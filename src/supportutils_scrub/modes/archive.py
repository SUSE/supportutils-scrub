import os
import sys
import re
import json
import shutil
import signal
import pwd
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION, EXIT_OK, EXIT_ERROR, EXIT_VERIFY_FAIL
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.extractor import (
    extract_supportconfig, create_txz, walk_supportconfig,
    copy_folder_to_scrubbed, strip_archive_ext, is_archive_path,
)
from supportutils_scrub.pcap_rewrite import rewrite_pcaps_with_tcprewrite
from supportutils_scrub.verify import verify_scrubbed_folder
from supportutils_scrub.pipeline import (
    warn_private_ip, extract_and_map_domains, extract_hostnames,
    extract_usernames, extract_serials, rename_extraction_paths,
    scrub_name, dataset_paths,
)
from supportutils_scrub.audit import (
    load_mappings_file, get_secure_tmp_base, save_mappings,
    print_enc_note, sha256_file, audit_record, write_audit_log, write_report,
)


def _scrub_tree(clean_folder_path, current_mappings, args, config, keyword_scrubber,
                logger, verbose_flag, include_ldap=True):
    """Pre-scan, build scrubbers, and scrub a directory tree in place.

    Shared by archive, folder, and file handlers so a mixed run keeps one
    consistent mapping. Returns the (possibly renamed) clean_folder_path,
    report_files, updated mappings, per-file hits, the verify mapping, and the
    hostname/domain dicts + tld_map (needed for output naming)."""
    report_files = walk_supportconfig(clean_folder_path)

    additional_domains = re.split(r'[,\s;]+', args.domain) if args.domain else []
    domain_dict, tld_map = extract_and_map_domains(report_files, additional_domains, current_mappings)
    additional_usernames = re.split(r'[,\s;]+', args.username) if args.username else []
    username_dict = extract_usernames(report_files, additional_usernames, current_mappings)
    additional_hostnames = re.split(r'[,\s;]+', args.hostname) if args.hostname else []
    hostname_dict = extract_hostnames(report_files, additional_hostnames, current_mappings)

    clean_folder_path = rename_extraction_paths(clean_folder_path, hostname_dict, domain_dict=domain_dict)
    report_files = walk_supportconfig(clean_folder_path)

    serial_dict = extract_serials(report_files, current_mappings)
    serial_scrubber = SerialScrubber(mappings=current_mappings)
    serial_scrubber.serial_dict = serial_dict

    scrubbers = [
        IPScrubber(config, mappings=current_mappings),
        IPv6Scrubber(config, mappings=current_mappings),
        MACScrubber(config, mappings=current_mappings),
        keyword_scrubber,
        HostnameScrubber(hostname_dict), DomainScrubber(domain_dict),
    ]
    if include_ldap:
        scrubbers.append(LdapDnScrubber(mappings=current_mappings))
    scrubbers += [
        UsernameScrubber(username_dict), EmailScrubber(mappings=current_mappings),
        PasswordScrubber(mappings=current_mappings), CloudTokenScrubber(mappings=current_mappings),
        serial_scrubber,
    ]
    scrubbers = [s for s in scrubbers if s is not None]

    report_file_hits = {}
    jobs = getattr(args, 'jobs', 1) or 1
    profile = getattr(args, 'profile', False)

    if jobs > 1 and len(report_files) > 1 and not profile:
        from supportutils_scrub.parallel import scrub_in_parallel
        logger.info(f"Scrubbing with {jobs} worker processes...")
        frozen_seed = dict(current_mappings)
        frozen_seed['hostname'] = hostname_dict
        frozen_seed['domain'] = domain_dict
        frozen_seed['user'] = username_dict
        frozen_seed['serial'] = serial_dict
        frozen_seed['keyword'] = keyword_scrubber.keyword_dict if keyword_scrubber else {}
        updated_mappings, report_file_hits = scrub_in_parallel(
            report_files, frozen_seed, config, jobs, logger,
            verbose=verbose_flag, include_ldap=include_ldap)
        updated_mappings['tld_map'] = tld_map
        combined_mappings_for_verify = updated_mappings
    else:
        file_processor = FileProcessor(config, scrubbers, profile=profile)
        logger.info("Scrubbing:")
        for report_file in report_files:
            basename = os.path.basename(report_file)
            if not re.match(r"^sa\d{8}(\.xz)?$", basename) and not getattr(args, 'quiet', False):
                print(f"        {basename}")
            before = {s.name: len(s.mapping) for s in file_processor.scrubbers}
            file_processor.process_file(report_file, logger, verbose_flag)
            hits = [name for name, prev in before.items()
                    if len(file_processor[name].mapping) > prev]
            if hits:
                report_file_hits[os.path.basename(report_file)] = hits

        ip_s = file_processor['ip']
        ipv6_s = file_processor['ipv6']
        updated_mappings = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
        updated_mappings['subnet'] = ip_s.subnet_dict if ip_s else {}
        updated_mappings['state'] = ip_s.state if ip_s else {}
        updated_mappings['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
        updated_mappings['tld_map'] = tld_map
        combined_mappings_for_verify = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
        if profile:
            print(file_processor.format_profile())

    return (clean_folder_path, report_files, updated_mappings, report_file_hits,
            combined_mappings_for_verify, hostname_dict, domain_dict, tld_map)


def scrub_nested_archives_recursively(folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Scan folder_path for any sub-archives, recursively extract, scrub, and repack them."""
    import shutil
    from supportutils_scrub.extractor import is_archive_path, extract_supportconfig, create_txz

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if is_archive_path(file_path):
                logger.info(f"        [NESTED] Extracting and scrubbing: {file}")

                # 1. Extract the nested archive to a temporary directory
                temp_extract_dir = file_path + "_unpacked_temp"
                try:
                    sub_files, sub_clean_dir = extract_supportconfig(file_path, logger, extract_base=temp_extract_dir)

                    # 2. Recursively scrub the extracted sub-directory tree
                    sub_clean_dir, _, current_mappings, _, _, _, _, _ = _scrub_tree(
                        sub_clean_dir, current_mappings, args, config, keyword_scrubber,
                        logger, verbose_flag, include_ldap=False # Skip ldap check on nested for speed
                    )

                    # 3. Handle deeper nesting (e.g., nested inside nested)
                    current_mappings = scrub_nested_archives_recursively(
                        sub_clean_dir, current_mappings, args, config, keyword_scrubber, logger, verbose_flag
                    )

                    # 4. Re-compress the scrubbed folder back into the original filename (txz format)
                    os.remove(file_path)
                    create_txz(sub_clean_dir, file_path)

                except Exception as ex:
                    logger.error(f"Failed to scrub nested archive {file}: {ex}")
                finally:
                    if os.path.exists(temp_extract_dir):
                        shutil.rmtree(temp_extract_dir, ignore_errors=True)

    return current_mappings


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
            sys.stderr.write(f"\n[!] Interrupted — cleaning up {clean_folder_path}\n")
            sys.stderr.flush()
            if clean_folder_path and os.path.exists(clean_folder_path):
                shutil.rmtree(clean_folder_path, ignore_errors=True)
        except Exception:
            pass
        os._exit(1)
    signal.signal(signal.SIGINT,  _archive_cleanup_on_signal)
    signal.signal(signal.SIGTERM, _archive_cleanup_on_signal)

    try:
        try:
            report_files, clean_folder_path = extract_supportconfig(archive_path, logger, extract_base=extract_base)
        except Exception as e:
            print(f"[!] Error during extraction of {archive_path}: {e}")
            raise

        # Recursively scrub embedded archives first (SMLM 5.1/Podman support)
        current_mappings = scrub_nested_archives_recursively(
            clean_folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag
        )

        (clean_folder_path, report_files, updated_mappings, report_file_hits,
         combined_mappings_for_verify, hostname_dict, domain_dict, tld_map) = _scrub_tree(
            clean_folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)

        archive_basename = os.path.basename(archive_path)
        archive_name_no_ext = strip_archive_ext(archive_basename)
        scrubbed_archive_name = scrub_name(archive_name_no_ext, hostname_dict, domain_dict=domain_dict)
        out_dir = getattr(args, 'output_dir', None) or os.path.dirname(os.path.abspath(archive_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        new_txz_file_path = os.path.join(out_dir, scrubbed_archive_name + "_scrubbed.txz")

        create_txz(clean_folder_path, new_txz_file_path)
        print(f"[✓] Scrubbed archive written to: {new_txz_file_path}")

        verify_findings = []
        if getattr(args, 'verify', False):
            verify_findings = verify_scrubbed_folder(
                clean_folder_path, combined_mappings_for_verify,
                config=config,
                check_allowlist=True, check_patterns=True,
                check_identity=False)
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
        if clean_folder_path and os.path.exists(clean_folder_path):
            try:
                shutil.rmtree(clean_folder_path)
            except Exception as e:
                print(f"[!] Could not remove temp folder {clean_folder_path}: {e}")

    try:
        stat = os.stat(new_txz_file_path)
        archive_size_mb = stat.st_size / (1024 * 1024)
        archive_owner = pwd.getpwuid(stat.st_uid).pw_name
    except Exception:
        archive_size_mb = 0
        archive_owner = "unknown"

    # updated_mappings was built above (serial or parallel branch).

    stats = {
        'archive_path': archive_path,
        'output_path': new_txz_file_path,
        'files': len(report_files),
        'size_mb': archive_size_mb,
        'owner': archive_owner,
        'report_data': {
            'input':  archive_path,
            'output': new_txz_file_path,
            'files_total': len(report_files),
            'file_hits': report_file_hits,
        },
        'verify_findings': verify_findings,
    }

    return updated_mappings, stats


def process_one_folder(folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Scrub a directory in place to <name>_scrubbed/ (original untouched)."""
    report_files, clean_folder_path = copy_folder_to_scrubbed(folder_path)
    (clean_folder_path, report_files, updated_mappings, report_file_hits,
     combined_mappings_for_verify, hostname_dict, domain_dict, tld_map) = _scrub_tree(
        clean_folder_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag)
    print(f"[✓] Scrubbed folder written to: {clean_folder_path}")

    verify_findings = []
    if getattr(args, 'verify', False):
        verify_findings = verify_scrubbed_folder(
            clean_folder_path, combined_mappings_for_verify,
            original_folder=folder_path, config=config,
            check_allowlist=True, check_patterns=True, check_identity=True)
        if verify_findings:
            print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:")
            for f in verify_findings[:20]:
                print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}")
            if len(verify_findings) > 20:
                print(f"    ... and {len(verify_findings)-20} more (see --report for full details)")
        else:
            print("[✓] VERIFY: No sensitive data found in scrubbed output.")

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
    }
    return updated_mappings, stats


def process_one_file(file_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """Scrub a single plain file to <name>_scrubbed<ext>, reusing existing maps.

    No supportconfig structure to pre-scan, so it relies on the shared mapping
    built from other inputs plus the self-discovering scrubbers (ip/ipv6/mac/
    email/password/cloud_token/ldap)."""
    base = os.path.basename(file_path)
    root, ext = os.path.splitext(base)
    out_dir = getattr(args, 'output_dir', None) or os.path.dirname(os.path.abspath(file_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "{}_scrubbed{}".format(root, ext))
    shutil.copyfile(file_path, out_path)

    serial_scrubber = SerialScrubber(mappings=current_mappings)
    serial_scrubber.serial_dict = dict(current_mappings.get('serial', {}))
    scrubbers = [
        IPScrubber(config, mappings=current_mappings),
        IPv6Scrubber(config, mappings=current_mappings),
        MACScrubber(config, mappings=current_mappings),
        keyword_scrubber,
        HostnameScrubber(dict(current_mappings.get('hostname', {}))),
        DomainScrubber(dict(current_mappings.get('domain', {}))),
        LdapDnScrubber(mappings=current_mappings),
        UsernameScrubber(dict(current_mappings.get('user', {}))),
        EmailScrubber(mappings=current_mappings),
        PasswordScrubber(mappings=current_mappings),
        CloudTokenScrubber(mappings=current_mappings),
        serial_scrubber,
    ]
    scrubbers = [s for s in scrubbers if s is not None]
    fp = FileProcessor(config, scrubbers)
    logger.info(f"Scrubbing file: {base}")
    fp.process_file(out_path, logger, verbose_flag)
    print(f"[✓] Scrubbed file written to: {out_path}")

    ip_s = fp['ip']
    ipv6_s = fp['ipv6']
    updated_mappings = {s.name: dict(s.mapping) for s in fp.scrubbers}
    updated_mappings['subnet'] = ip_s.subnet_dict if ip_s else {}
    updated_mappings['state'] = ip_s.state if ip_s else {}
    updated_mappings['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    updated_mappings['tld_map'] = current_mappings.get('tld_map', {})

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
        rewrite_pcaps_with_tcprewrite(
            mappings_for_pcap, args.pcap_in, args.pcap_out_dir,
            tcprewrite=args.tcprewrite_path,
            print_cmd=args.print_tcprewrite,
            logger=logger,
        )

    initial_mappings = {}
    mapping_keywords = []
    if args.mappings:
        initial_mappings = load_mappings_file(args.mappings)
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
        mapping_keywords = list(initial_mappings.get('keyword', {}).keys())

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]
    combined_keywords = set(cmd_keywords).union(mapping_keywords)
    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined_keywords))
        if not keyword_scrubber.is_loaded():
            if args.keywords or args.keyword_file:
                print("[!] Keyword obfuscation disabled (no keywords loaded)")
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    current_mappings = initial_mappings
    all_stats = []

    failed_archives = []
    for i, archive_path in enumerate(paths):
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

    saved_mapping_path = save_mappings(args, dataset_path, current_mappings)
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
    print("------------------------------------------------------------\n")

    record = audit_record('archive',
        inputs  = [{'path': os.path.abspath(p), 'sha256': sha256_file(p)} for p in paths],
        outputs = [{'path': s['output_path'], 'sha256': sha256_file(s['output_path'])} for s in all_stats],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)

    if failed_archives:
        sys.exit(EXIT_ERROR)
    if verify_exit == EXIT_VERIFY_FAIL:
        sys.exit(EXIT_VERIFY_FAIL)
