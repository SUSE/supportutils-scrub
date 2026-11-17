import os
import sys
import re
import json
import time
import shutil
import signal
import pwd
from datetime import datetime

from supportutils_scrub.main import (
    SCRIPT_VERSION, EXIT_OK, EXIT_ERROR, EXIT_WARNING, EXIT_VERIFY_FAIL,
)
from supportutils_scrub.processor import (
    FileProcessor, scrubbed_output_name, append_scrubbed,
)
from supportutils_scrub.extractor import (
    extract_supportconfig, create_txz, walk_supportconfig,
    copy_folder_to_scrubbed, strip_archive_ext, is_archive_path,
    expand_nested_archives,
)
from supportutils_scrub.pcap_rewrite import rewrite_pcaps_with_tcprewrite, PcapRewriteError
from supportutils_scrub.verify import verify_scrubbed_folder
from supportutils_scrub.pipeline import (
    save_mappings_or_exit,
    warn_private_ip, init_scrubbers, extract_and_map_domains, extract_hostnames,
    extract_hostnames_from_adopted_paths,
    extract_usernames, extract_serials, extract_sids, rename_extraction_paths,
    scrub_name, dataset_paths, PhaseTimer, slowest_files_report,
    report_format_mismatches, split_names, chain_seed, build_chain,
    chain_mappings, drop_unscrubbed, is_pcap,
)
from supportutils_scrub.modes.file import scrub_loose_file
from supportutils_scrub.audit import (
    load_mappings_file, get_secure_tmp_base,
    print_enc_note, sha256_file, audit_record, write_audit_log, write_report,
)


def _scrub_tree(clean_folder_path, current_mappings, args, config, keyword_scrubber,
                logger, verbose_flag, include_ldap=True, timer=None, copied=True):
    """Pre-scan, build scrubbers, and scrub a directory tree in place.

    Shared by archive, folder, and file handlers so a mixed run keeps one
    consistent mapping. Returns the (possibly renamed) clean_folder_path,
    report_files, updated mappings, per-file hits, the verify mapping, and the
    hostname/domain dicts + tld_map (needed for output naming)."""
    expand_nested_archives(clean_folder_path, logger)
    if timer:
        timer.mark('unpack-nested')
    report_files = walk_supportconfig(clean_folder_path)

    domain_dict, tld_map = extract_and_map_domains(report_files, split_names(args.domain),
                                                   current_mappings)
    username_dict = extract_usernames(report_files, split_names(args.username),
                                      current_mappings)
    additional_hostnames = split_names(args.hostname)
    # collector-adoption bypass fix: node names carried by tree structure
    additional_hostnames.extend(
        extract_hostnames_from_adopted_paths(clean_folder_path, config=config))
    hostname_dict = extract_hostnames(report_files, additional_hostnames,
                                      current_mappings, config=config)

    renames = []
    clean_folder_path = rename_extraction_paths(clean_folder_path, hostname_dict,
                                                domain_dict=domain_dict,
                                                config=config, renames=renames)
    if renames and not getattr(args, 'quiet', False):
        print(f"[i] {len(renames)} path(s) renamed: a name carrying a hostname "
              "or a domain is obfuscated like the text is"
              + ("" if verbose_flag else " (--verbose lists them)"))
        if verbose_flag:
            for old, new in renames:
                print(f"        {old} -> {new}")
    report_files = walk_supportconfig(clean_folder_path)

    serial_dict = extract_serials(report_files, current_mappings, config=config)
    sid_dict = extract_sids(report_files, current_mappings)
    if timer:
        timer.mark('pre-scan')

    seed = chain_seed(current_mappings, hostname_dict, domain_dict, username_dict,
                      serial_dict, sid_dict, keyword_scrubber)
    report_file_hits = {}
    failed = []
    jobs = getattr(args, 'jobs', 1) or 1
    profile = getattr(args, 'profile', False)

    if jobs > 1 and len(report_files) > 1 and not profile:
        from supportutils_scrub.parallel import scrub_in_parallel
        logger.info(f"Scrubbing with {jobs} worker processes...")
        updated_mappings, report_file_hits, file_times = scrub_in_parallel(
            report_files, seed, config, jobs, logger,
            verbose=verbose_flag, include_ldap=include_ldap,
            decompress=getattr(args, 'unpacked', False), failed=failed)
        updated_mappings['tld_map'] = tld_map
    else:
        file_processor = FileProcessor(config, build_chain(seed, config, include_ldap=include_ldap),
                                       profile=profile,
                                       decompress=getattr(args, 'unpacked', False))
        logger.info("Scrubbing:")
        file_times = []
        for report_file in report_files:
            basename = os.path.basename(report_file)
            if not re.match(r"^sa\d{8}(\.xz)?$", basename) and not getattr(args, 'quiet', False):
                print(f"        {basename}")
            before = {s.name: len(s.mapping) for s in file_processor.scrubbers}
            t0 = time.perf_counter()
            if file_processor.process_file(report_file, logger, verbose_flag) is False:
                failed.append(report_file)
            file_times.append((basename, time.perf_counter() - t0))
            hits = [name for name, prev in before.items()
                    if len(file_processor[name].mapping) > prev]
            if hits:
                report_file_hits[os.path.basename(report_file)] = hits

        updated_mappings = chain_mappings(file_processor.scrubbers, current_mappings, tld_map)
        if profile:
            print(file_processor.format_profile())

    if timer:
        timer.mark('scrub')
    dropped_ok = drop_unscrubbed(failed, clean_folder_path, copied=copied)
    mismatches = report_format_mismatches(clean_folder_path)
    if verbose_flag and file_times:
        report = slowest_files_report(file_times)
        if report:
            print(report, file=sys.stderr)
    problems = {'failed': failed, 'dropped_ok': dropped_ok, 'mismatches': mismatches}
    return (clean_folder_path, report_files, updated_mappings, report_file_hits,
            updated_mappings, hostname_dict, domain_dict, tld_map,
            renames, problems)


def process_one_archive(archive_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    extract_base = get_secure_tmp_base() if getattr(args, 'secure_tmp', False) else None

    new_txz_file_path = None
    clean_folder_path = None
    verify_findings = []
    report_file_hits = {}
    tld_map = {}
    report_files = []

    _prev_sigint  = signal.getsignal(signal.SIGINT)
    _prev_sigterm = signal.getsignal(signal.SIGTERM)
    def _archive_cleanup_on_signal(signum, frame):
        try:
            # Stop pool workers first: os._exit skips executor shutdown, and
            # orphaned workers would keep scrubbing into the tree we delete.
            import multiprocessing
            for child in multiprocessing.active_children():
                try:
                    child.terminate()
                except Exception:
                    pass
            sys.stderr.write(f"\n[!] Interrupted — cleaning up {clean_folder_path}\n")
            sys.stderr.flush()
            if clean_folder_path and os.path.exists(clean_folder_path):
                shutil.rmtree(clean_folder_path, ignore_errors=True)
        except Exception:
            pass
        os._exit(1)
    signal.signal(signal.SIGINT,  _archive_cleanup_on_signal)
    signal.signal(signal.SIGTERM, _archive_cleanup_on_signal)

    timer = PhaseTimer(echo=verbose_flag)
    unpacked = getattr(args, 'unpacked', False)
    keep_folder = False
    problems = {}
    try:
        # Known before extraction starts (extract_tgz_archive names it the
        # same way): an interrupt mid-extraction must not leave a raw tree.
        clean_folder_path = os.path.join(
            extract_base or os.path.dirname(archive_path),
            append_scrubbed(strip_archive_ext(os.path.basename(archive_path))))
        try:
            report_files, clean_folder_path = extract_supportconfig(archive_path, logger, extract_base=extract_base)
        except Exception as e:
            print(f"[!] Error during extraction of {archive_path}: {e}")
            raise
        timer.mark('extract')
        if verbose_flag:
            try:
                total_mb = sum(os.path.getsize(p) for p in report_files) / (1024 * 1024)
            except OSError:
                total_mb = 0
            print(f"[i] debug: {len(report_files)} files, {total_mb:.0f} MB extracted, "
                  f"jobs={getattr(args, 'jobs', 1)} of {os.cpu_count()} CPUs, "
                  f"workdir={clean_folder_path}", file=sys.stderr)

        (clean_folder_path, report_files, updated_mappings, report_file_hits,
         combined_mappings_for_verify, hostname_dict, domain_dict, tld_map,
         renames, problems) = _scrub_tree(
            clean_folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag,
            timer=timer)

        archive_basename = os.path.basename(archive_path)
        archive_name_no_ext = strip_archive_ext(archive_basename)
        scrubbed_archive_name = scrub_name(archive_name_no_ext, hostname_dict, domain_dict=domain_dict)
        out_dir = getattr(args, 'output_dir', None) or os.path.dirname(os.path.abspath(archive_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        if unpacked:
            # --unpacked: the scrubbed folder is the output; no repack. Move it
            # out of tmpfs (--secure-tmp) or into --output-dir if needed.
            dest = os.path.join(out_dir, append_scrubbed(scrubbed_archive_name))
            if os.path.abspath(dest) != os.path.abspath(clean_folder_path):
                if os.path.exists(dest):
                    print(f"[!] Replacing existing output folder: {dest}")
                    shutil.rmtree(dest)
                shutil.move(clean_folder_path, dest)
                clean_folder_path = dest
            keep_folder = True
            timer.mark('move')
            print(f"[✓] Scrubbed folder written to: {clean_folder_path}")
        else:
            new_txz_file_path = os.path.join(out_dir, append_scrubbed(scrubbed_archive_name) + ".txz")
            create_txz(clean_folder_path, new_txz_file_path)
            timer.mark('repack')
            print(f"[✓] Scrubbed archive written to: {new_txz_file_path}")

        verify_findings = []
        if getattr(args, 'verify', False):
            verify_findings = verify_scrubbed_folder(
                clean_folder_path, combined_mappings_for_verify,
                config=config,
                check_allowlist=True, check_patterns=True,
                check_identity=False, jobs=getattr(args, 'jobs', 1))
            timer.mark('verify')
            if verify_findings:
                print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:")
                for f in verify_findings[:20]:
                    print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}")
                if len(verify_findings) > 20:
                    print(f"    ... and {len(verify_findings)-20} more (see --report for full details)")
            else:
                print("[✓] VERIFY: No sensitive data found in scrubbed output.")

    finally:
        signal.signal(signal.SIGINT,  _prev_sigint)
        signal.signal(signal.SIGTERM, _prev_sigterm)
        if not keep_folder and clean_folder_path and os.path.exists(clean_folder_path):
            try:
                shutil.rmtree(clean_folder_path)
            except Exception as e:
                print(f"[!] Could not remove temp folder {clean_folder_path}: {e}")
        if verbose_flag:
            print(timer.table(), file=sys.stderr)
        else:
            print(timer.summary(), file=sys.stderr)

    output_path = new_txz_file_path or clean_folder_path
    try:
        stat = os.stat(output_path)
        archive_owner = pwd.getpwuid(stat.st_uid).pw_name
        if new_txz_file_path:
            archive_size_mb = stat.st_size / (1024 * 1024)
        else:
            archive_size_mb = sum(
                os.path.getsize(p) for p in walk_supportconfig(output_path)) / (1024 * 1024)
    except Exception:
        archive_size_mb = 0
        archive_owner = "unknown"

    # updated_mappings was built above (serial or parallel branch).

    stats = {
        'archive_path': archive_path,
        'output_path': output_path,
        'files': len(report_files),
        'size_mb': archive_size_mb,
        'owner': archive_owner,
        'report_data': {
            'input':  archive_path,
            'output': output_path,
            'files_total': len(report_files),
            'file_hits': report_file_hits,
            'renames': [{'from': old, 'to': new} for old, new in renames],
        },
        'verify_findings': verify_findings,
        'problems': problems,
    }

    return updated_mappings, stats


def process_one_folder(folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Scrub a directory in place to <name>_scrubbed/ (original untouched)."""
    timer = PhaseTimer(echo=verbose_flag)
    report_files, clean_folder_path = copy_folder_to_scrubbed(folder_path)
    timer.mark('copy')
    (clean_folder_path, report_files, updated_mappings, report_file_hits,
     combined_mappings_for_verify, hostname_dict, domain_dict, tld_map,
     renames, problems) = _scrub_tree(
        clean_folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag,
        timer=timer, copied=clean_folder_path != folder_path.rstrip('/'))
    print(f"[✓] Scrubbed folder written to: {clean_folder_path}")

    verify_findings = []
    if getattr(args, 'verify', False):
        verify_findings = verify_scrubbed_folder(
            clean_folder_path, combined_mappings_for_verify,
            original_folder=folder_path, config=config,
            check_allowlist=True, check_patterns=True, check_identity=True,
            jobs=getattr(args, 'jobs', 1))
        if verify_findings:
            print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:")
            for f in verify_findings[:20]:
                print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}")
            if len(verify_findings) > 20:
                print(f"    ... and {len(verify_findings)-20} more (see --report for full details)")
        else:
            print("[✓] VERIFY: No sensitive data found in scrubbed output.")
    if getattr(args, 'verify', False):
        timer.mark('verify')
    if verbose_flag:
        print(timer.table(), file=sys.stderr)
    else:
        print(timer.summary(), file=sys.stderr)

    try:
        owner = pwd.getpwuid(os.stat(clean_folder_path).st_uid).pw_name
    except Exception:
        owner = "unknown"
    stats = {
        'archive_path': folder_path, 'output_path': clean_folder_path,
        'files': len(report_files), 'size_mb': 0, 'owner': owner,
        'report_data': {'input': folder_path, 'output': clean_folder_path,
                        'files_total': len(report_files), 'file_hits': report_file_hits},
        'verify_findings': verify_findings,
        'problems': problems,
    }
    return updated_mappings, stats


def process_one_file(file_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Scrub a loose file to <name>_scrubbed<ext> exactly as file mode does,
    on the run's shared mapping."""
    out_path, updated_mappings, _fp = scrub_loose_file(
        file_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)
    print(f"[✓] Scrubbed file written to: {out_path}")

    stats = {
        'archive_path': file_path, 'output_path': out_path, 'files': 1,
        'size_mb': (os.path.getsize(out_path) / (1024 * 1024)) if os.path.exists(out_path) else 0,
        'owner': 'unknown',
        'report_data': {'input': file_path, 'output': out_path, 'files_total': 1, 'file_hits': {}},
        'verify_findings': [],
    }
    return updated_mappings, stats


def _process_one_input(path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Dispatch a single input to the right handler by type (dir/archive/file)."""
    if os.path.isdir(path):
        return process_one_folder(path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)
    if is_archive_path(path):
        return process_one_archive(path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)
    if os.path.isfile(path):
        return process_one_file(path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)
    raise Exception(f"Unsupported input (not a folder, archive, or file): {path}")


def run_archive_mode(paths, args, logger):
    verbose_flag = args.verbose

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config = args._preloaded_config
    dataset_dir = config.dataset_dir
    warn_private_ip(config, file=sys.stderr if getattr(args, 'quiet', False) else None)

    if args.rewrite_pcap:
        if not args.pcap_in:
            print("[!] --rewrite-pcap needs --pcap-in PCAP(s)")
            sys.exit(2)
        if not args.mappings:
            print("[!] --rewrite-pcap requires --mappings to provide subnet data")
            sys.exit(2)
        mapping_src_path = args.mappings
        try:
            mappings_for_pcap = load_mappings_file(mapping_src_path)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[!] Failed to read mappings for pcap rewrite from {mapping_src_path}: {e}")
            sys.exit(2)
        try:
            rewrite_pcaps_with_tcprewrite(
                mappings_for_pcap, args.pcap_in, args.pcap_out_dir,
                tcprewrite=args.tcprewrite_path,
                print_cmd=args.print_tcprewrite,
                logger=logger,
            )
        except PcapRewriteError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(EXIT_WARNING)

    # det_key, keyword pseudonyms and the keyword file come from the same
    # place as in every other mode
    current_mappings, keyword_scrubber, _ip, _mac, _ipv6 = init_scrubbers(args, config, logger)
    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    all_stats = []

    # Captures go last: they are rewritten with the mapping every text
    # input of this run has built.
    pcaps = [p for p in paths if os.path.isfile(p) and is_pcap(p)]
    failed_archives = []
    for i, archive_path in enumerate(paths):
        if archive_path in pcaps:
            continue
        if len(paths) > 1:
            print(f"\n[{i+1}/{len(paths)}] Processing: {os.path.basename(archive_path)}")
        try:
            current_mappings, stats = _process_one_input(
                archive_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag
            )
            all_stats.append(stats)
        except Exception as e:
            print(f"[!] Failed to process {archive_path}: {e}", file=sys.stderr)
            failed_archives.append(archive_path)
            if len(paths) == 1:
                sys.exit(EXIT_ERROR)

    pcap_outputs, failed_pcaps = _rewrite_pcaps(pcaps, current_mappings, args, logger)

    problems = [s.get('problems') or {} for s in all_stats]
    unscrubbed = [f for p in problems for f in p.get('failed', [])]
    removal_failed = any(not p.get('dropped_ok', True) for p in problems)
    mismatches = sum(p.get('mismatches', 0) for p in problems)

    all_verify_findings = []
    for s in all_stats:
        all_verify_findings.extend(s.get('verify_findings', []))

    if all_verify_findings:
        verify_exit = EXIT_VERIFY_FAIL
    else:
        verify_exit = EXIT_OK

    hostname_dict_final = current_mappings.get('hostname', {})
    want_report = bool(getattr(args, 'report', False)) or bool(getattr(args, 'report_file', None))
    input_basename = os.path.basename(paths[0].rstrip('/')) if paths else ''
    dataset_path, audit_path, report_path = dataset_paths(
        dataset_dir, timestamp, hostname_dict_final, input_name=input_basename, report=want_report)
    if args.report_file:
        report_path = args.report_file

    if report_path:
        archives_report = [s['report_data'] for s in all_stats]
        write_report(report_path, archives_report, SCRIPT_VERSION,
                     verify_findings=all_verify_findings)

    saved_mapping_path = save_mappings_or_exit(args, dataset_path, current_mappings)
    if saved_mapping_path:
        print(f"[✓] Mapping file saved to:       {saved_mapping_path}")

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(current_mappings, indent=4))

    total_files_scrubbed = sum(s['files'] for s in all_stats)
    total_obfuscations = sum(
        len(current_mappings.get(k, {}))
        for k in ('user', 'ip', 'mac', 'domain', 'hostname', 'ipv6',
                   'keyword', 'subnet', 'ipv6_subnet', 'serial',
                   'email', 'password', 'cloud_token')
    )

    print("\n------------------------------------------------------------")
    if len(paths) > 1:
        print(f" Combined Obfuscation Summary ({len(paths)} archives)")
    else:
        print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Files obfuscated          : {total_files_scrubbed}")
    print(f"| Usernames obfuscated      : {len(current_mappings.get('user', {}))}")
    print(f"| IP addresses obfuscated   : {len(current_mappings.get('ip', {}))}")
    print(f"| IPv4 subnets obfuscated   : {len(current_mappings.get('subnet', {}))}")
    print(f"| MAC addresses obfuscated  : {len(current_mappings.get('mac', {}))}")
    print(f"| Domains obfuscated        : {len(current_mappings.get('domain', {}))}")
    print(f"| Hostnames obfuscated      : {len(current_mappings.get('hostname', {}))}")
    print(f"| IPv6 addresses obfuscated : {len(current_mappings.get('ipv6', {}))}")
    print(f"| IPv6 subnets obfuscated   : {len(current_mappings.get('ipv6_subnet', {}))}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(current_mappings.get('keyword', {}))}")
    print(f"| Serials/UUIDs obfuscated  : {len(current_mappings.get('serial', {}))}")
    print(f"| Emails obfuscated         : {len(current_mappings.get('email', {}))}")
    print(f"| Passwords obfuscated      : {len(current_mappings.get('password', {}))}")
    print(f"| Cloud tokens obfuscated   : {len(current_mappings.get('cloud_token', {}))}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    if len(all_stats) == 1:
        stats = all_stats[0]
        print(f"| Size                      : {stats['size_mb']:.2f} MB")
        print(f"| Owner                     : {stats['owner']}")
    for stats in all_stats:
        print(f"| Output archive            : {stats['output_path']}")
    for out in pcap_outputs:
        print(f"| Output pcap               : {out}")
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}")
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print(f"| Audit log                 : {audit_path}")
    if failed_archives:
        print(f"| FAILED archives           : {len(failed_archives)}")
        for fa in failed_archives:
            print(f"|   - {fa}")
    if unscrubbed:
        print(f"| Files NOT scrubbed        : {len(unscrubbed)}"
              + (" (removed from the output)" if not removal_failed else ""))
    if failed_pcaps:
        print(f"| FAILED pcaps (not written): {len(failed_pcaps)}")
        for fp in failed_pcaps:
            print(f"|   - {fp}")
    print("------------------------------------------------------------\n")

    record = audit_record('archive',
        inputs  = [{'path': os.path.abspath(p), 'sha256': sha256_file(p)} for p in paths],
        outputs = [{'path': s['output_path'], 'sha256': sha256_file(s['output_path'])} for s in all_stats]
                + [{'path': p, 'sha256': sha256_file(p)} for p in pcap_outputs],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)

    if failed_archives or removal_failed:
        sys.exit(EXIT_ERROR)
    if verify_exit == EXIT_VERIFY_FAIL:
        sys.exit(EXIT_VERIFY_FAIL)
    if unscrubbed or mismatches or failed_pcaps:
        sys.exit(EXIT_WARNING)


def _pcap_out_dir(args, pcap):
    # cli.py defaults --pcap-out-dir to '.', so '.' reads as "not given"
    given = getattr(args, 'pcap_out_dir', None)
    if given and given != '.':
        return given
    return getattr(args, 'output_dir', None) or os.path.dirname(os.path.abspath(pcap))


def _rewrite_pcaps(pcaps, mappings, args, logger):
    """Rewrite each capture with the mapping this run built. A capture that
    could not be rewritten (no tcprewrite, no IPv4 subnet to map, a tcprewrite
    error) gets no output at all. Returns (written paths, failed inputs)."""
    outputs, failed = [], []
    for pcap in pcaps:
        out_dir = _pcap_out_dir(args, pcap)
        base = os.path.basename(pcap)
        if not os.path.splitext(base)[1]:
            base += '.pcap'          # the name pcap_rewrite gives it
        written = os.path.join(out_dir, scrubbed_output_name(base))
        final = os.path.join(out_dir, scrubbed_output_name(
            scrub_name(base, mappings.get('hostname', {}),
                       domain_dict=mappings.get('domain', {}))))
        if os.path.abspath(pcap) in (os.path.abspath(written), os.path.abspath(final)):
            print(f"[!] {os.path.basename(pcap)}: already named _scrubbed; rename "
                  f"it, its rewrite would land on the input", file=sys.stderr)
            failed.append(pcap)
            continue
        # a stale output from an earlier run must not pass for this one
        for p in {written, final}:
            if os.path.lexists(p):
                os.remove(p)
        try:
            rewrite_pcaps_with_tcprewrite(
                mappings, [pcap], out_dir,
                tcprewrite=getattr(args, 'tcprewrite_path', None) or 'tcprewrite',
                print_cmd=getattr(args, 'print_tcprewrite', False), logger=logger)
            reason = None if os.path.exists(written) else "tcprewrite wrote nothing"
        except Exception as e:      # PcapRewriteError: no tcprewrite, or it failed
            reason = str(e) or type(e).__name__
        if reason:
            print(f"[!] {os.path.basename(pcap)}: not rewritten ({reason}); "
                  f"no scrubbed capture was written", file=sys.stderr)
            failed.append(pcap)
            continue
        if final != written:
            os.replace(written, final)
        outputs.append(final)
    return outputs, failed
