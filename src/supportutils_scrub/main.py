#!/usr/bin/env python3
import logging
import sys
import os
import re
import json
import argparse
import time
import pwd
import shutil
import subprocess
from datetime import datetime
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.extractor import extract_supportconfig, create_txz, copy_folder_to_scrubbed
from supportutils_scrub.translator import Translator
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.pcap_rewrite import rewrite_pcaps_with_tcprewrite

SCRIPT_VERSION = "1.1"
SCRIPT_DATE = "2025-08-14"

def print_header(file=None):
    if file is None:
        file = sys.stdout
    print("\n"+"=" * 77, file=file)
    print("          Obfuscation Utility - supportutils-scrub", file=file)
    print("                      Version : {:<12}".format(SCRIPT_VERSION), file=file)
    print("                 Release Date : {:<12}".format(SCRIPT_DATE), file=file)
    print(file=file)
    print(" supportutils-scrub is a python based tool that masks sensitive", file=file)
    print(" information from SUSE supportconfig tarballs. It replaces data such as", file=file)
    print(" IPv4, IPv6, domain names, usernames, hostnames, MAC addresses, and", file=file)
    print(" custom keywords in a consistent way throughout the archive.", file=file)
    print(" The mappings are saved in /var/tmp/obfuscation_mappings.json and can be", file=file)
    print(" reused to keep consistent results across multiple supportconfigs.", file=file)
    print("=" * 77 + "\n", file=file)

def print_footer(file=None):
    if file is None:
        file = sys.stdout
    print(" The obfuscated supportconfig has been successfully created. Please review", file=file)
    print(" its contents to ensure that all sensitive information has been properly", file=file)
    print(" obfuscated. If some values or keywords were not obfuscated automatically,", file=file)
    print(" you can manually add them using the keyword obfuscation option.", file=file)
    print("=" * 77 + "\n", file=file)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Obfuscate SUSE supportconfig archives by masking sensitive data."
    )

    parser.add_argument("supportconfig_path", nargs="?", help="Path to .txz archive, extracted folder, or '-' for stdin")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help="Path to config file (defaults provided)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--mappings", help="JSON file with prior obfuscation mappings")
    parser.add_argument("--username", help="Additional usernames to obfuscate")
    parser.add_argument("--domain", help="Additional domains to obfuscate")
    parser.add_argument("--hostname", help="Additional hostnames to obfuscate")
    parser.add_argument("--keyword-file", help="File containing keywords to obfuscate")
    parser.add_argument("--keywords", help="Additional keywords to obfuscate")
    parser.add_argument("--rewrite-pcap", action="store_true",
               help="Rewrite one or more pcap files using mappings (IPv4/IPv6 subnet-aware).")
    parser.add_argument("--pcap-in", nargs="+", metavar="PCAP",
               help="Input pcap(s) to rewrite (requires --rewrite-pcap).")
    parser.add_argument("--pcap-out-dir", default=".", metavar="DIR",
               help="Directory for rewritten pcaps (default: current dir).")
    parser.add_argument("--print-tcprewrite", action="store_true",
               help="Print the exact tcprewrite commands executed.")
    parser.add_argument("--tcprewrite-path", default="tcprewrite",
               help="Path to tcprewrite binary (default: 'tcprewrite').")


    return parser.parse_args()




def build_hierarchical_domain_map(all_domains, existing_mappings):
    """
    Builds a domain mapping dictionary that preserves parent-child relationships.
    """
    valid_domains = {d for d in all_domains if '.' in d}

    sorted_domains = sorted(list(valid_domains), key=lambda d: len(d.split('.')))

    domain_dict = existing_mappings.get('domain', {})
    base_domain_counter = len(domain_dict)
    sub_domain_counter = 0

    for domain in sorted_domains:
        if domain in domain_dict:
            continue

        parts = domain.split('.')
        parent_domain = '.'.join(parts[1:])

        if parent_domain in domain_dict:
            obfuscated_sub_part = f"sub_{sub_domain_counter}"
            sub_domain_counter += 1
            domain_dict[domain] = f"{obfuscated_sub_part}.{domain_dict[parent_domain]}"
        else:
            domain_dict[domain] = f"domain_{base_domain_counter}"
            base_domain_counter += 1

    return domain_dict


def extract_and_map_domains(report_files, additional_domains, mappings):
    """
    Extracts all unique domains from report files and builds the hierarchical map.
    """
    all_domains = set()

    for domain in additional_domains:
        DomainScrubber._add_domain_and_parents(domain, all_domains)

    files_to_scan = {
        'network.txt': ['# /etc/hosts', '# /etc/resolv.conf'],
        'nfs.txt': ['# /bin/egrep'],
        'ntp.txt': ['# /etc/ntp.conf', '# /etc/chrony.conf']
    }

    for file_path in report_files:
        basename = os.path.basename(file_path)
        if basename in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for section in files_to_scan[basename]:
                        domains_from_section = DomainScrubber.extract_domains_from_file_section(f, section)
                        all_domains.update(domains_from_section)
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")

    domain_map = build_hierarchical_domain_map(all_domains, mappings)
    return domain_map


def extract_hostnames(report_files, additional_hostnames, mappings):
    hostname_dict = mappings.get('hostname', {})
    hostname_counter = len(hostname_dict)
    all_hostnames = []

    for file in report_files:
        if 'network.txt' in file:
            hostnames_from_hosts = HostnameScrubber.extract_hostnames_from_hosts(file)
            hostnames_from_hostname = HostnameScrubber.extract_hostnames_from_hostname_section(file)
            all_hostnames.extend(hostnames_from_hosts)
            all_hostnames.extend(hostnames_from_hostname)

    all_hostnames.extend(additional_hostnames)

    for hostname in all_hostnames:
        if hostname not in hostname_dict:
            obfuscated_hostname = f"hostname_{hostname_counter}"
            hostname_dict[hostname] = obfuscated_hostname
            hostname_counter += 1

    return hostname_dict

def extract_usernames(report_files, additional_usernames, mappings):
    username_dict = mappings.get('user', {})
    username_counter = len(username_dict)
    all_usernames = []

    for file in report_files:
        if 'pam.txt' in file:
            section_starts = ['# /usr/bin/getent passwd', '# /etc/passwd']
            usernames = UsernameScrubber.extract_usernames_from_section(file, section_starts)
            all_usernames.extend(usernames)
        elif 'messages.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)
        elif 'security-apparmor.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)
        elif 'sssd.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)

    all_usernames.extend(additional_usernames)

    for username in all_usernames:
        if username not in username_dict:
            obfuscated_username = f"user_{username_counter}"
            username_dict[username] = obfuscated_username
            username_counter += 1

    return username_dict


def _init_scrubbers(args, config, logger):
    """
    Shared scrubber initialisation used by folder mode and stdin mode.
    Returns (mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber).
    Prints informational messages to *out* (default sys.stdout) or *err* (default sys.stderr).
    """
    mappings = {}
    mapping_keywords = []
    if args.mappings:
        try:
            with open(args.mappings, 'r') as f:
                mappings = json.load(f)
                mapping_keywords = list(mappings.get('keyword', {}).keys())
        except Exception as e:
            print(f"[!] Failed to load mapping from {args.mappings}", file=sys.stderr)
            sys.exit(1)

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]
    combined_keywords = set(cmd_keywords).union(mapping_keywords)

    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined_keywords))
        if not keyword_scrubber.is_loaded():
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    try:
        ip_scrubber = IPScrubber(config, mappings=mappings)
        mac_scrubber = MACScrubber(config, mappings=mappings)
        ipv6_scrubber = IPv6Scrubber(config, mappings=mappings)
    except Exception as e:
        logger.error(f"Error initializing scrubbers: {e}")
        sys.exit(1)

    return mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber


def run_folder_mode(args, logger):
    """
    Process a directory: copy to {dir}_scrubbed/, scrub files in-place, no repack.
    No supportconfig-specific pre-scan; additional --domain/--hostname/--username args still apply.
    """
    verbose_flag = args.verbose

    dataset_dir = '/var/tmp'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_path = os.path.join(dataset_dir, f"obfuscation_mappings_{timestamp}.json")

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        report_files, scrubbed_path = copy_folder_to_scrubbed(args.supportconfig_path)
        print(f"[✓] Folder copied to: {scrubbed_path}")
    except Exception as e:
        print(f"[!] Error copying folder: {e}")
        raise

    # Build dicts from args only (no supportconfig-specific pre-scan)
    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict = extract_and_map_domains([], additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)

    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames([], additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)

    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                       hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    total_ip_dict = {}
    total_domain_dict = {}
    total_user_dict = {}
    total_hostname_dict = {}
    total_keyword_dict = {}
    total_mac_dict = {}
    total_ipv6_dict = {}
    total_ipv4_subnet_dict = {}
    total_ipv6_subnet_dict = {}
    total_state = {}

    logger.info("Scrubbing:")
    for report_file in report_files:
        basename = os.path.basename(report_file)
        if not re.match(r"^sa\d{8}(\.xz)?$", basename):
            print(f"        {basename}")

        ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict = \
            file_processor.process_file(report_file, logger, verbose_flag)

        total_ip_dict.update(ip_dict)
        total_domain_dict.update(domain_dict)
        total_user_dict.update(username_dict)
        total_hostname_dict.update(hostname_dict)
        total_keyword_dict.update(keyword_dict)
        total_mac_dict.update(mac_dict)
        total_ipv6_dict.update(ipv6_dict)
        if hasattr(file_processor, '_ipv4_subnet_map'):
            total_ipv4_subnet_dict = file_processor._ipv4_subnet_map
        if hasattr(file_processor, '_ipv4_state'):
            total_state = file_processor._ipv4_state
        if hasattr(file_processor, '_ipv6_subnet_map'):
            total_ipv6_subnet_dict.update(file_processor._ipv6_subnet_map)

    dataset_dict = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'mac': total_mac_dict,
        'ipv6': total_ipv6_dict,
        'keyword': total_keyword_dict,
        'subnet': total_ipv4_subnet_dict,
        'state': total_state,
        'ipv6_subnet': total_ipv6_subnet_dict
    }

    Translator.save_datasets(dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    total_files_scrubbed = len(report_files)
    total_obfuscations = (
        len(total_user_dict) + len(total_ip_dict) + len(total_mac_dict)
        + len(total_domain_dict) + len(total_hostname_dict) + len(total_ipv6_dict)
        + len(total_keyword_dict) + len(total_ipv4_subnet_dict) + len(total_ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Files obfuscated          : {total_files_scrubbed}")
    print(f"| Usernames obfuscated      : {len(total_user_dict)}")
    print(f"| IP addresses obfuscated   : {len(total_ip_dict)}")
    print(f"| IPv4 subnets obfuscated   : {len(total_ipv4_subnet_dict)}")
    print(f"| MAC addresses obfuscated  : {len(total_mac_dict)}")
    print(f"| Domains obfuscated        : {len(total_domain_dict)}")
    print(f"| Hostnames obfuscated      : {len(total_hostname_dict)}")
    print(f"| IPv6 addresses obfuscated : {len(total_ipv6_dict)}")
    print(f"| IPv6 subnets obfuscated   : {len(total_ipv6_subnet_dict)}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(total_keyword_dict)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Output folder             : {scrubbed_path}")
    print(f"| Mapping file              : {dataset_path}")
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print("------------------------------------------------------------\n")


def run_stdin_mode(args, logger):
    """
    Read from stdin, write scrubbed text to stdout, header/summary to stderr.
    """
    verbose_flag = args.verbose
    err = sys.stderr

    print_header(file=err)

    dataset_dir = '/var/tmp'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_path = os.path.join(dataset_dir, f"obfuscation_mappings_{timestamp}.json")

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ", file=err)
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)", file=err)

    # No pre-scan; build dicts from args only
    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict = extract_and_map_domains([], additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)

    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames([], additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)

    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                       hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    text = sys.stdin.read()
    scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict = \
        file_processor.process_text(text, logger, verbose_flag)

    sys.stdout.write(scrubbed_text)

    ipv4_subnet_dict = file_processor._ipv4_subnet_map if hasattr(file_processor, '_ipv4_subnet_map') else {}
    ipv6_subnet_dict = file_processor._ipv6_subnet_map if hasattr(file_processor, '_ipv6_subnet_map') else {}
    state = file_processor._ipv4_state if hasattr(file_processor, '_ipv4_state') else {}

    dataset_dict = {
        'ip': ip_dict,
        'domain': domain_dict,
        'user': username_dict,
        'hostname': hostname_dict,
        'mac': mac_dict,
        'ipv6': ipv6_dict,
        'keyword': keyword_dict,
        'subnet': ipv4_subnet_dict,
        'state': state,
        'ipv6_subnet': ipv6_subnet_dict
    }

    Translator.save_datasets(dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---", file=err)
        print(json.dumps(dataset_dict, indent=4), file=err)

    total_obfuscations = (
        len(username_dict) + len(ip_dict) + len(mac_dict)
        + len(domain_dict) + len(hostname_dict) + len(ipv6_dict)
        + len(keyword_dict) + len(ipv4_subnet_dict) + len(ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------", file=err)
    print(" Obfuscation Summary", file=err)
    print("------------------------------------------------------------", file=err)
    print(f"| Usernames obfuscated      : {len(username_dict)}", file=err)
    print(f"| IP addresses obfuscated   : {len(ip_dict)}", file=err)
    print(f"| IPv4 subnets obfuscated   : {len(ipv4_subnet_dict)}", file=err)
    print(f"| MAC addresses obfuscated  : {len(mac_dict)}", file=err)
    print(f"| Domains obfuscated        : {len(domain_dict)}", file=err)
    print(f"| Hostnames obfuscated      : {len(hostname_dict)}", file=err)
    print(f"| IPv6 addresses obfuscated : {len(ipv6_dict)}", file=err)
    print(f"| IPv6 subnets obfuscated   : {len(ipv6_subnet_dict)}", file=err)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(keyword_dict)}", file=err)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=err)
    print(f"| Mapping file              : {dataset_path}", file=err)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=err)
    print("------------------------------------------------------------\n", file=err)

    print_footer(file=err)


def run_file_mode(args, logger):
    """
    Process a single plain file: write scrubbed copy to {path}_scrubbed, summary to stdout.
    """
    verbose_flag = args.verbose
    input_path = args.supportconfig_path
    output_path = input_path + '_scrubbed'

    dataset_dir = '/var/tmp'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_path = os.path.join(dataset_dir, f"obfuscation_mappings_{timestamp}.json")

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict = extract_and_map_domains([], additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)

    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames([], additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)

    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                       hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        print(f"[!] Cannot read {input_path}: {e}")
        sys.exit(1)

    scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict = \
        file_processor.process_text(text, logger, verbose_flag)

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

    ipv4_subnet_dict = file_processor._ipv4_subnet_map if hasattr(file_processor, '_ipv4_subnet_map') else {}
    ipv6_subnet_dict = file_processor._ipv6_subnet_map if hasattr(file_processor, '_ipv6_subnet_map') else {}
    state = file_processor._ipv4_state if hasattr(file_processor, '_ipv4_state') else {}

    dataset_dict = {
        'ip': ip_dict,
        'domain': domain_dict,
        'user': username_dict,
        'hostname': hostname_dict,
        'mac': mac_dict,
        'ipv6': ipv6_dict,
        'keyword': keyword_dict,
        'subnet': ipv4_subnet_dict,
        'state': state,
        'ipv6_subnet': ipv6_subnet_dict
    }

    Translator.save_datasets(dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    total_obfuscations = (
        len(username_dict) + len(ip_dict) + len(mac_dict)
        + len(domain_dict) + len(hostname_dict) + len(ipv6_dict)
        + len(keyword_dict) + len(ipv4_subnet_dict) + len(ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Usernames obfuscated      : {len(username_dict)}")
    print(f"| IP addresses obfuscated   : {len(ip_dict)}")
    print(f"| IPv4 subnets obfuscated   : {len(ipv4_subnet_dict)}")
    print(f"| MAC addresses obfuscated  : {len(mac_dict)}")
    print(f"| Domains obfuscated        : {len(domain_dict)}")
    print(f"| Hostnames obfuscated      : {len(hostname_dict)}")
    print(f"| IPv6 addresses obfuscated : {len(ipv6_dict)}")
    print(f"| IPv6 subnets obfuscated   : {len(ipv6_subnet_dict)}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(keyword_dict)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Output file               : {output_path}")
    print(f"| Mapping file              : {dataset_path}")
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print("------------------------------------------------------------\n")


def main():
    args = parse_args()
    verbose_flag = args.verbose
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose_flag else "normal")

    is_stdin = (not args.supportconfig_path and not sys.stdin.isatty()) \
               or args.supportconfig_path == '-'
    is_folder = bool(args.supportconfig_path) and os.path.isdir(args.supportconfig_path)
    is_file = (bool(args.supportconfig_path)
               and os.path.isfile(args.supportconfig_path)
               and not args.supportconfig_path.endswith(('.txz', '.tgz')))

    if is_stdin:
        run_stdin_mode(args, logger)
        return

    if is_file:
        print_header()
        run_file_mode(args, logger)
        print_footer()
        return

    if is_folder:
        print_header()
        run_folder_mode(args, logger)
        print_footer()
        return

    print_header()

    supportconfig_path = args.supportconfig_path
    config_path = args.config

    if args.rewrite_pcap and not args.supportconfig_path:
        if not args.mappings or not args.pcap_in:
            print("[!] For --rewrite-pcap without a supportconfig, provide --mappings and --pcap-in")
            sys.exit(2)
        mappings = json.load(open(args.mappings))
        rewrite_pcaps_with_tcprewrite(
            mappings, args.pcap_in, args.pcap_out_dir,
            tcprewrite=args.tcprewrite_path,
            print_cmd=args.print_tcprewrite,
            logger=logger,
        )
        return

    dataset_dir = '/var/tmp'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_name = f"obfuscation_mappings_{timestamp}.json"
    dataset_path = os.path.join(dataset_dir, unique_name)



    # Use the ConfigReader class to read the configuration
    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(config_path)

    if args.rewrite_pcap:
        if not args.pcap_in:
            print("[!] --rewrite-pcap needs --pcap-in PCAP(s)")
            sys.exit(2)
        mapping_src_path = args.mappings or dataset_path
        try:
            mappings_for_pcap = json.load(open(mapping_src_path))
        except Exception as e:
            print(f"[!] Failed to read mappings for pcap rewrite from {mapping_src_path}: {e}")
            sys.exit(2)

        rewrite_pcaps_with_tcprewrite(
            mappings_for_pcap, args.pcap_in, args.pcap_out_dir,
            tcprewrite=args.tcprewrite_path,
            print_cmd=args.print_tcprewrite,
            logger=logger,
        )

    # Load mappings from JSON file if provided
    mappings = {}
    mapping_keywords = []
    if args.mappings:
        try:
            with open(args.mappings, 'r') as f:
                mappings = json.load(f)
                print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
                # Extract keywords from mappings if available
                mapping_keywords = list(mappings.get('keyword', {}).keys())
        except Exception as e:
            print(f"[!] Failed to load mapping from {args.mappings}")
            sys.exit(1)

    # Parse command-line keywords
    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]


    # Combine keywords from command line, file, and mappings
    combined_keywords = set(cmd_keywords).union(mapping_keywords)

    # Initialize KeywordScrubber with file and combined keywords
    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined_keywords))
        if not keyword_scrubber.is_loaded():
            print("[!] Keyword obfuscation disabled (no keywords loaded)")
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    try:
        ip_scrubber = IPScrubber(config, mappings=mappings)
        mac_scrubber = MACScrubber(config, mappings=mappings)
        ipv6_scrubber = IPv6Scrubber(config, mappings=mappings)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    try:
        report_files, clean_folder_path = extract_supportconfig(supportconfig_path, logger)
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        raise

    # Populate the domains dictionary
    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict = extract_and_map_domains(report_files, additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)

    # Extract and build the username dictionary
    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames(report_files, additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)

    # Extract hostnames and build dictionary
    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames(report_files, additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    # Initialize FileProcessor
    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber, hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    # List of filenames to exclude from scrubbing
    exclude_files = []

    # Dictionaries to store obfuscation mappings
    total_ip_dict = {}
    total_domain_dict = {}
    total_user_dict = {}
    total_hostname_dict = {}
    total_keyword_dict = {}
    total_mac_dict = {}
    total_ipv6_dict = {}
    total_ipv4_subnet_dict = {}
    total_ipv6_subnet_dict = {}
    total_state = {}
    total_state6 = {}

    # Process supportconfig files
    logger.info("Scrubbing:")
    for report_file in report_files:
        if os.path.basename(report_file) in exclude_files:
            print(f"        {os.path.basename(report_file)} (Excluded)")
            continue
        basename=os.path.basename(report_file)
        if not re.match(r"^sa\d{8}(\.xz)?$", basename):
            print(f"        {basename}")

        # Use FileProcessor to process the file
        ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict = file_processor.process_file(report_file, logger, verbose_flag)

        # Aggregate the translation dictionaries
        total_ip_dict.update(ip_dict)
        total_domain_dict.update(domain_dict)
        total_user_dict.update(username_dict)
        total_hostname_dict.update(hostname_dict)
        total_keyword_dict.update(keyword_dict)
        total_mac_dict.update(mac_dict)
        total_ipv6_dict.update(ipv6_dict)
        total_ipv4_subnet_dict = {}
        total_ipv6_subnet_dict = {}

        if hasattr(file_processor, '_ipv4_subnet_map'):
            total_ipv4_subnet_dict = file_processor._ipv4_subnet_map
        if hasattr(file_processor, '_ipv4_state'):
            total_state = file_processor._ipv4_state
        if hasattr(file_processor, "_ipv6_subnet_map"):
           total_ipv6_subnet_dict.update(file_processor._ipv6_subnet_map)


    dataset_dict = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'mac': total_mac_dict,
        'ipv6': total_ipv6_dict,
        'keyword': total_keyword_dict,
        'subnet': total_ipv4_subnet_dict,
        'state': total_state,
        'ipv6_subnet': total_ipv6_subnet_dict
    }

    Translator.save_datasets(dataset_path, dataset_dict)

    base_name = os.path.splitext(args.supportconfig_path)[0]
    new_txz_file_path = base_name + "_scrubbed.txz"
    create_txz(clean_folder_path, new_txz_file_path)
    print(f"[✓] Scrubbed archive written to: {new_txz_file_path}")
    print(f"[✓] Mapping file saved to:       {dataset_path}")

    # Clean up: remove the extracted folder
    try:
        shutil.rmtree(clean_folder_path)
    except Exception as e:
        print(f"[!] Could not remove temp folder {clean_folder_path}: {e}")

    # Get size and owner of the scrubbed tarball
    try:
        stat = os.stat(new_txz_file_path)
        archive_size_mb = stat.st_size / (1024 * 1024)
        archive_owner = pwd.getpwuid(stat.st_uid).pw_name
    except Exception as e:
        archive_size_mb = 0
        archive_owner = "unknown"

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    total_files_scrubbed = len([
        f for f in report_files if os.path.basename(f) not in exclude_files
    ])

    total_obfuscations = (
        len(total_user_dict)
        + len(total_ip_dict)
        + len(total_mac_dict)
        + len(total_domain_dict)
        + len(total_hostname_dict)
        + len(total_ipv6_dict)
        + len(total_keyword_dict)
        + len(total_ipv4_subnet_dict)
        + len(total_ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Files obfuscated          : {total_files_scrubbed}")
    print(f"| Usernames obfuscated      : {len(total_user_dict)}")
    print(f"| IP addresses obfuscated   : {len(total_ip_dict)}")
    print(f"| IPv4 subnets obfuscated   : {len(total_ipv4_subnet_dict)}")
    print(f"| MAC addresses obfuscated  : {len(total_mac_dict)}")
    print(f"| Domains obfuscated        : {len(total_domain_dict)}")
    print(f"| Hostnames obfuscated      : {len(total_hostname_dict)}")
    print(f"| IPv6 addresses obfuscated : {len(total_ipv6_dict)}")
    print(f"| IPv6 subnets obfuscated   : {len(total_ipv6_subnet_dict)}")

    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(total_keyword_dict)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Size                      : {archive_size_mb:.2f} MB")
    print(f"| Owner                     : {archive_owner}")
    print(f"| Output archive            : {new_txz_file_path}")
    print(f"| Mapping file              : {dataset_path}")
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print("------------------------------------------------------------\n")

    print_footer()

if __name__ == "__main__":
    main()
