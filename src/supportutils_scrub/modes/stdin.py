import os
import sys
import re
import json
import time
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.pipeline import (
    warn_private_ip, init_scrubbers,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    dataset_paths,
)
from supportutils_scrub.audit import (
    save_mappings, print_enc_note, audit_record, write_audit_log,
)


def _build_processor(config, ip_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
                     domain_dict, username_dict, hostname_dict, mappings, logger):
    scrubbers = [
        ip_scrubber, ipv6_scrubber, mac_scrubber, keyword_scrubber,
        HostnameScrubber(hostname_dict), DomainScrubber(domain_dict),
        LdapDnScrubber(mappings=mappings),
        UsernameScrubber(username_dict), EmailScrubber(mappings=mappings),
        PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
    ]
    scrubbers = [s for s in scrubbers if s is not None]
    try:
        return FileProcessor(config, scrubbers)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)


def run_stdin_mode(args, logger):
    verbose_flag = args.verbose
    err = sys.stderr

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config = args._preloaded_config
    dataset_dir = config.dataset_dir
    dataset_path, audit_path, _ = dataset_paths(dataset_dir, timestamp)
    warn_private_ip(config, file=err)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ", file=err)
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)", file=err)

    _STREAM_BOOTSTRAP      = 500
    _STREAM_BOOTSTRAP_SECS = 3.0

    if getattr(args, 'stream', False):
        import select
        print(f"[i] Stream mode: collecting bootstrap (up to {_STREAM_BOOTSTRAP} lines "
              f"or {_STREAM_BOOTSTRAP_SECS:.0f}s)...", file=err)
        bootstrap_lines = []
        deadline = time.time() + _STREAM_BOOTSTRAP_SECS
        while len(bootstrap_lines) < _STREAM_BOOTSTRAP:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([sys.stdin], [], [], remaining)
            if not ready:
                break
            line = sys.stdin.readline()
            if not line:
                break
            bootstrap_lines.append(line)
        bootstrap_text = ''.join(bootstrap_lines)

        additional_domains   = list(re.split(r'[,\s;]+', args.domain)    if args.domain    else [])
        additional_domains   += DomainScrubber.extract_domains_from_text(bootstrap_text)
        additional_usernames = list(re.split(r'[,\s;]+', args.username)  if args.username  else [])
        additional_usernames += UsernameScrubber.extract_usernames_from_text(bootstrap_text)
        additional_hostnames = list(re.split(r'[,\s;]+', args.hostname)  if args.hostname  else [])
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(bootstrap_text)

        domain_dict, tld_map  = extract_and_map_domains([], additional_domains,   mappings)
        username_dict         = extract_usernames([],       additional_usernames,  mappings)
        hostname_dict         = extract_hostnames([],       additional_hostnames,  mappings)

        file_processor = _build_processor(
            config, ip_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
            domain_dict, username_dict, hostname_dict, mappings, logger)

        scrubbed_bootstrap = file_processor.process_text(bootstrap_text, logger, verbose_flag)
        sys.stdout.write(scrubbed_bootstrap)
        sys.stdout.flush()

        while True:
            line = sys.stdin.readline()
            if not line:
                break
            scrubbed_line = file_processor.process_text(line, logger, False)
            sys.stdout.write(scrubbed_line)
            sys.stdout.flush()

    else:
        text = sys.stdin.read()

        additional_domains   = list(re.split(r'[,\s;]+', args.domain)   if args.domain   else [])
        additional_domains   += DomainScrubber.extract_domains_from_text(text)
        additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
        additional_usernames += UsernameScrubber.extract_usernames_from_text(text)
        additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)

        domain_dict, tld_map  = extract_and_map_domains([], additional_domains,   mappings)
        username_dict         = extract_usernames([],       additional_usernames,  mappings)
        hostname_dict         = extract_hostnames([],       additional_hostnames,  mappings)

        file_processor = _build_processor(
            config, ip_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
            domain_dict, username_dict, hostname_dict, mappings, logger)

        scrubbed_text = file_processor.process_text(text, logger, verbose_flag)
        sys.stdout.write(scrubbed_text)

    ip_s = file_processor['ip']
    ipv6_s = file_processor['ipv6']

    dataset_dict = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
    dataset_dict['subnet'] = ip_s.subnet_dict if ip_s else {}
    dataset_dict['state'] = ip_s.state if ip_s else {}
    dataset_dict['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    dataset_dict['tld_map'] = tld_map

    saved_mapping_path = save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---", file=err)
        print(json.dumps(dataset_dict, indent=4), file=err)

    counts = {s.name: len(s.mapping) for s in file_processor.scrubbers}
    subnet_count = len(dataset_dict.get('subnet', {}))
    ipv6_subnet_count = len(dataset_dict.get('ipv6_subnet', {}))
    total_obfuscations = sum(counts.values()) + subnet_count + ipv6_subnet_count

    print("\n------------------------------------------------------------", file=err)
    print(" Obfuscation Summary", file=err)
    print("------------------------------------------------------------", file=err)
    print(f"| Usernames obfuscated      : {counts.get('user', 0)}", file=err)
    print(f"| IP addresses obfuscated   : {counts.get('ip', 0)}", file=err)
    print(f"| IPv4 subnets obfuscated   : {subnet_count}", file=err)
    print(f"| MAC addresses obfuscated  : {counts.get('mac', 0)}", file=err)
    print(f"| Domains obfuscated        : {counts.get('domain', 0)}", file=err)
    print(f"| Hostnames obfuscated      : {counts.get('hostname', 0)}", file=err)
    print(f"| IPv6 addresses obfuscated : {counts.get('ipv6', 0)}", file=err)
    print(f"| IPv6 subnets obfuscated   : {ipv6_subnet_count}", file=err)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {counts.get('keyword', 0)}", file=err)
    if file_processor['email']:
        print(f"| Emails obfuscated         : {counts.get('email', 0)}", file=err)
    if file_processor['password']:
        print(f"| Passwords obfuscated      : {counts.get('password', 0)}", file=err)
    if file_processor['cloud_token']:
        print(f"| Cloud tokens obfuscated   : {counts.get('cloud_token', 0)}", file=err)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=err)
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}", file=err)
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path, file=err)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=err)
    print(f"| Audit log                 : {audit_path}", file=err)
    print("------------------------------------------------------------\n", file=err)

    record = audit_record('stdin',
        inputs  = [{'path': 'stdin', 'sha256': 'n/a'}],
        outputs = [{'path': 'stdout', 'sha256': 'n/a'}],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)
