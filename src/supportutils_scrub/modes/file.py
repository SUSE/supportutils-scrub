import os
import sys
import re
import json
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.pipeline import (
    warn_private_ip, init_scrubbers,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    dataset_paths,
)
from supportutils_scrub.audit import (
    save_mappings, print_enc_note, sha256_file, audit_record, write_audit_log,
)


def run_file_mode(args, logger):
    verbose_flag = args.verbose
    input_path = args.supportconfig_path[0]
    output_path = input_path + '_scrubbed'

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config_reader_f = ConfigReader(DEFAULT_CONFIG_PATH)
    config_f = config_reader_f.read_config(args.config)
    dataset_dir = config_f.dataset_dir
    dataset_path, audit_path, _ = dataset_paths(dataset_dir, timestamp)

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)
    warn_private_ip(config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        print(f"[!] Cannot read {input_path}: {e}")
        sys.exit(1)

    additional_domains = list(re.split(r'[,\s;]+', args.domain) if args.domain else [])
    additional_domains += DomainScrubber.extract_domains_from_text(text)

    additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
    additional_usernames += UsernameScrubber.extract_usernames_from_text(text)

    additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])
    additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)

    domain_dict, tld_map = extract_and_map_domains([], additional_domains, mappings)
    username_dict = extract_usernames([], additional_usernames, mappings)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)

    scrubbers = [
        ip_scrubber, ipv6_scrubber, mac_scrubber, keyword_scrubber,
        HostnameScrubber(hostname_dict), DomainScrubber(domain_dict),
        UsernameScrubber(username_dict), EmailScrubber(mappings=mappings),
        PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
    ]
    scrubbers = [s for s in scrubbers if s is not None]

    try:
        file_processor = FileProcessor(config, scrubbers)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    scrubbed_text = file_processor.process_text(text, logger, verbose_flag)

    if scrubbed_text != text:
        header = (
            "#" + "-" * 93 + "\n"
            "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n"
            "#" + "-" * 93 + "\n\n"
        )
        final_content = header + scrubbed_text
    else:
        final_content = scrubbed_text

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_content)
    except Exception as e:
        print(f"[!] Cannot write {output_path}: {e}")
        sys.exit(1)

    print(f"[✓] Scrubbed file written to: {output_path}")

    ip_s = file_processor['ip']
    ipv6_s = file_processor['ipv6']

    dataset_dict = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
    dataset_dict['subnet'] = ip_s.subnet_dict if ip_s else {}
    dataset_dict['state'] = ip_s.state if ip_s else {}
    dataset_dict['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    dataset_dict['tld_map'] = tld_map

    saved_mapping_path = save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    counts = {s.name: len(s.mapping) for s in file_processor.scrubbers}
    subnet_count = len(dataset_dict.get('subnet', {}))
    ipv6_subnet_count = len(dataset_dict.get('ipv6_subnet', {}))
    total_obfuscations = sum(counts.values()) + subnet_count + ipv6_subnet_count

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Usernames obfuscated      : {counts.get('user', 0)}")
    print(f"| IP addresses obfuscated   : {counts.get('ip', 0)}")
    print(f"| IPv4 subnets obfuscated   : {subnet_count}")
    print(f"| MAC addresses obfuscated  : {counts.get('mac', 0)}")
    print(f"| Domains obfuscated        : {counts.get('domain', 0)}")
    print(f"| Hostnames obfuscated      : {counts.get('hostname', 0)}")
    print(f"| IPv6 addresses obfuscated : {counts.get('ipv6', 0)}")
    print(f"| IPv6 subnets obfuscated   : {ipv6_subnet_count}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {counts.get('keyword', 0)}")
    if file_processor['email']:
        print(f"| Emails obfuscated         : {counts.get('email', 0)}")
    if file_processor['password']:
        print(f"| Passwords obfuscated      : {counts.get('password', 0)}")
    if file_processor['cloud_token']:
        print(f"| Cloud tokens obfuscated   : {counts.get('cloud_token', 0)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Output file               : {output_path}")
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}")
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print(f"| Audit log                 : {audit_path}")
    print("------------------------------------------------------------\n")

    record = audit_record('file',
        inputs  = [{'path': os.path.abspath(input_path),  'sha256': sha256_file(input_path)}],
        outputs = [{'path': os.path.abspath(output_path), 'sha256': sha256_file(output_path)}],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)
