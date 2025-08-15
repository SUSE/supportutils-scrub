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
from datetime import datetime
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.extractor import extract_supportconfig
from supportutils_scrub.extractor import create_txz
from supportutils_scrub.translator import Translator
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.processor import FileProcessor

SCRIPT_VERSION = "1.1"
SCRIPT_DATE = "2025-08-14"

def print_header():
    print("\n"+"=" * 77)
    print("          Obfuscation Utility - supportutils-scrub")
    print("                      Version : {:<12}".format(SCRIPT_VERSION))
    print("                 Release Date : {:<12}".format(SCRIPT_DATE))
    print()
    print(" supportutils-scrub is a python based tool that masks sensitive")
    print(" information from SUSE supportconfig tarballs. It replaces data such as")
    print(" IPv4, IPv6, domain names, usernames, hostnames, MAC addresses, and")
    print(" custom keywords in a consistent way throughout the archive.")
    print(" The mappings are saved in /var/tmp/obfuscation_mappings.json and can be")
    print(" reused to keep consistent results across multiple supportconfigs.")
    print("=" * 77 + "\n")

def print_footer():
    print(" The obfuscated supportconfig has been successfully created. Please review")
    print(" its contents to ensure that all sensitive information has been properly")
    print(" obfuscated. If some values or keywords were not obfuscated automatically,")
    print(" you can manually add them using the keyword obfuscation option.")
    print("=" * 77 + "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Obfuscate SUSE supportconfig archives by masking sensitive data."
    )
    parser.add_argument("supportconfig_path", help="Path to .txz archive or extracted folder")
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


def main():
    args = parse_args()
    print_header()

    supportconfig_path = args.supportconfig_path
    config_path = args.config
    verbose_flag = args.verbose

    # Initialize the logger
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose_flag else "normal")

    dataset_dir = '/var/tmp'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_name = f"obfuscation_mappings_{timestamp}.json"
    dataset_path = os.path.join(dataset_dir, unique_name)

    # Use the ConfigReader class to read the configuration
    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(config_path)

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
        total_subnet_dict_v6 = {} 
        if hasattr(file_processor, '_ipv4_subnet_map'):
            total_subnet_dict = file_processor._ipv4_subnet_map
        if hasattr(file_processor, '_ipv4_state'):
            total_state = file_processor._ipv4_state
        if hasattr(file_processor, "_ipv6_subnet_map"):
            total_subnet_dict_v6.update(file_processor._ipv6_subnet_map)
        if hasattr(file_processor, "_ipv6_state"):
            total_state6 = file_processor._ipv6_state

    dataset_dict = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'mac': total_mac_dict,
        'ipv6': total_ipv6_dict,
        'keyword': total_keyword_dict,
        'subnet': total_subnet_dict,    
        'state': total_state,
        'subnet6': total_subnet_dict_v6,
        'state6': total_state6
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
        + len(total_subnet_dict)
        + len(total_subnet_dict_v6)
    )

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Files obfuscated          : {total_files_scrubbed}")
    print(f"| Usernames obfuscated      : {len(total_user_dict)}")
    print(f"| IP addresses obfuscated   : {len(total_ip_dict)}")
    print(f"| IPv4 subnets obfuscated   : {len(total_subnet_dict)}")
    print(f"| MAC addresses obfuscated  : {len(total_mac_dict)}")
    print(f"| Domains obfuscated        : {len(total_domain_dict)}")
    print(f"| Hostnames obfuscated      : {len(total_hostname_dict)}")
    print(f"| IPv6 addresses obfuscated : {len(total_ipv6_dict)}")
    print(f"| IPv6 subnets obfuscated   : {len(total_subnet_dict_v6)}")

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
