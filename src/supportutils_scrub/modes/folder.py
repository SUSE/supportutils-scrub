import os
import sys
import re
import json
import shutil
import signal
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION, EXIT_VERIFY_FAIL
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.extractor import copy_folder_to_scrubbed, walk_supportconfig
from supportutils_scrub.verify import verify_scrubbed_folder
from supportutils_scrub.pipeline import (
    warn_private_ip, init_scrubbers, is_supportconfig_folder,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    extract_serials, rename_extraction_paths, dataset_paths,
)
from supportutils_scrub.audit import (
    save_mappings, print_enc_note, audit_record, write_audit_log, write_report,
)


def run_folder_mode(args, logger):
    verbose_flag = args.verbose

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    quiet = getattr(args, 'quiet', False)
    err = sys.stderr

    config = getattr(args, '_preloaded_config', None)
    if config is None:
        config = ConfigReader(DEFAULT_CONFIG_PATH).read_config(args.config)
    dataset_dir = config.dataset_dir

    if quiet:
        print(f"supportutils-scrub v{SCRIPT_VERSION} — scrubbing IPs, hostnames, domains, "
              f"usernames, MACs, IPv6, serials", file=err)
        warn_private_ip(config, file=err)
    else:
        warn_private_ip(config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        init_scrubbers(args, config, logger)
    if not quiet and args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if not quiet and keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        report_files, scrubbed_path = copy_folder_to_scrubbed(args.supportconfig_path[0])
        if not quiet:
            print(f"[✓] Folder copied to: {scrubbed_path}")
    except Exception as e:
        print(f"[!] Error copying folder: {e}")
        raise

    def _cleanup_on_signal(signum, frame):
        try:
            sys.stderr.write(f"\n[!] Interrupted — removing partial output {scrubbed_path}\n")
            sys.stderr.flush()
            if os.path.exists(scrubbed_path):
                shutil.rmtree(scrubbed_path, ignore_errors=True)
        except Exception:
            pass
        os._exit(1)
    signal.signal(signal.SIGINT,  _cleanup_on_signal)
    signal.signal(signal.SIGTERM, _cleanup_on_signal)

    is_sc = is_supportconfig_folder(report_files)
    scan_files = report_files if is_sc else []

    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict, tld_map = extract_and_map_domains(scan_files, additional_domains, mappings)

    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames(scan_files, additional_usernames, mappings)

    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames(scan_files, additional_hostnames, mappings)

    want_report = getattr(args, 'report', None) is not None
    input_basename = os.path.basename(args.supportconfig_path[0].rstrip('/'))
    dataset_path, audit_path, report_path = dataset_paths(
        dataset_dir, timestamp, hostname_dict, input_name=input_basename, report=want_report)
    if want_report and isinstance(args.report, str):
        report_path = args.report

    serial_scrubber = None
    if is_sc:
        scrubbed_path = rename_extraction_paths(scrubbed_path, hostname_dict)
        report_files = walk_supportconfig(scrubbed_path)
        serial_dict = extract_serials(report_files, mappings)
        serial_scrubber = SerialScrubber(mappings=mappings)
        serial_scrubber.serial_dict = serial_dict

    scrubbers = [
        ip_scrubber, ipv6_scrubber, mac_scrubber, keyword_scrubber,
        HostnameScrubber(hostname_dict), DomainScrubber(domain_dict),
        UsernameScrubber(username_dict), EmailScrubber(mappings=mappings),
        PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
        serial_scrubber,
    ]
    scrubbers = [s for s in scrubbers if s is not None]

    try:
        file_processor = FileProcessor(config, scrubbers)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    total_files = len(report_files)
    if not quiet:
        logger.info("Scrubbing:")
    _devnull = open(os.devnull, 'w') if quiet else None
    try:
        for file_idx, report_file in enumerate(report_files, 1):
            basename = os.path.basename(report_file)
            if quiet:
                err.write(f"\r  Scrubbing {file_idx}/{total_files} {basename:<60}")
                err.flush()
                _saved_stdout = sys.stdout
                sys.stdout = _devnull
            elif not re.match(r"^sa\d{8}(\.xz)?$", basename):
                print(f"        {basename}")
            try:
                file_processor.process_file(report_file, logger, verbose_flag)
            finally:
                if quiet:
                    sys.stdout = _saved_stdout
        if quiet:
            err.write(f"\r  Scrubbing {total_files}/{total_files} done.{' ' * 60}\n")
            err.flush()
    finally:
        if _devnull is not None:
            _devnull.close()

    ip_s = file_processor['ip']
    ipv6_s = file_processor['ipv6']

    dataset_dict = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
    dataset_dict['subnet'] = ip_s.subnet_dict if ip_s else {}
    dataset_dict['state'] = ip_s.state if ip_s else {}
    dataset_dict['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    dataset_dict['tld_map'] = tld_map

    saved_mapping_path = save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag and not quiet:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    counts = {s.name: len(s.mapping) for s in file_processor.scrubbers}
    subnet_count = len(dataset_dict.get('subnet', {}))
    ipv6_subnet_count = len(dataset_dict.get('ipv6_subnet', {}))
    total_files_scrubbed = len(report_files)
    total_obfuscations = sum(counts.values()) + subnet_count + ipv6_subnet_count

    out = sys.stderr if quiet else sys.stdout

    print("\n------------------------------------------------------------", file=out)
    print(" Obfuscation Summary", file=out)
    print("------------------------------------------------------------", file=out)
    print(f"| Files obfuscated          : {total_files_scrubbed}", file=out)
    print(f"| Usernames obfuscated      : {counts.get('user', 0)}", file=out)
    print(f"| IP addresses obfuscated   : {counts.get('ip', 0)}", file=out)
    print(f"| IPv4 subnets obfuscated   : {subnet_count}", file=out)
    print(f"| MAC addresses obfuscated  : {counts.get('mac', 0)}", file=out)
    print(f"| Domains obfuscated        : {counts.get('domain', 0)}", file=out)
    print(f"| Hostnames obfuscated      : {counts.get('hostname', 0)}", file=out)
    print(f"| IPv6 addresses obfuscated : {counts.get('ipv6', 0)}", file=out)
    print(f"| IPv6 subnets obfuscated   : {ipv6_subnet_count}", file=out)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {counts.get('keyword', 0)}", file=out)
    print(f"| Serials/UUIDs obfuscated  : {counts.get('serial', 0)}", file=out)
    print(f"| Emails obfuscated         : {counts.get('email', 0)}", file=out)
    print(f"| Passwords obfuscated      : {counts.get('password', 0)}", file=out)
    print(f"| Cloud tokens obfuscated   : {counts.get('cloud_token', 0)}", file=out)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=out)
    if not quiet:
        print(f"| Output folder             : {scrubbed_path}", file=out)
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}", file=out)
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=out)
    print(f"| Audit log                 : {audit_path}", file=out)
    print("------------------------------------------------------------\n", file=out)

    verify_findings = []
    if getattr(args, 'verify', False):
        original_path = args.supportconfig_path[0]
        combined_mappings_for_verify = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
        verify_findings = verify_scrubbed_folder(
            scrubbed_path, combined_mappings_for_verify,
            original_folder=original_path, config=config,
            check_allowlist=True, check_patterns=True,
            check_identity=True)
        vout = out
        if verify_findings:
            print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:", file=vout)
            for f in verify_findings[:20]:
                print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}", file=vout)
            if len(verify_findings) > 20:
                print(f"    ... and {len(verify_findings)-20} more (see --report for full details)", file=vout)
        else:
            print("[✓] VERIFY: No sensitive data found in scrubbed output.", file=vout)

    if quiet:
        print(scrubbed_path)

    if report_path:
        folder_report = [{'input': os.path.abspath(args.supportconfig_path[0]),
                          'output': os.path.abspath(scrubbed_path),
                          'files_total': len(report_files)}]
        write_report(report_path, folder_report, SCRIPT_VERSION,
                     verify_findings=verify_findings)

    record = audit_record('folder',
        inputs  = [{'path': os.path.abspath(args.supportconfig_path[0]), 'sha256': 'n/a (directory)'}],
        outputs = [{'path': os.path.abspath(scrubbed_path), 'sha256': 'n/a (directory)'}],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)

    if verify_findings:
        sys.exit(EXIT_VERIFY_FAIL)
