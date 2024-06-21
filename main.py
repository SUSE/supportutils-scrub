#!/usr/bin/env python3
# main.py

import sys
import os
import re
import json
import argparse
from config import DEFAULT_CONFIG_PATH
from config_reader import ConfigReader
from ip_scrubber import IPScrubber
from domain_scrubber import DomainScrubber
from username_scrubber import UsernameScrubber
from hostname_scrubber import HostnameScrubber
from keyword_scrubber import KeywordScrubber
from extractor import extract_supportconfig
from translator import Translator
from supportutils_scrub_logger import SupportutilsScrubLogger
from processor import FileProcessor


def extract_domains(report_files):
    domain_dict = {}
    domain_counter = 0

    # Extract domains from specific files
    for file in report_files:
        if 'sysconfig.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /etc/hosts')
        elif 'network.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /etc/resolv.conf')
        elif 'etc.conf' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '.snapshots/resolv.conf')
        elif 'nfs.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /bin/egrep')
        elif 'ntp.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /etc/ntp.conf')
        elif 'y2log.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /var/adm/autoinstall/cache/installedSystem.xml')
        else:
            continue

        # Update the domain dictionary with the extracted domains
        for domain in domains:
            if domain not in domain_dict:
                obfuscated_domain = f"masked_domain_{domain_counter}"
                domain_dict[domain] = obfuscated_domain
                domain_counter += 1
    return domain_dict

def extract_usernames(report_files):
    username_dict={}
    username_counter=0
    for file in report_files:
        if 'pam.txt' in file:
            usernames=UsernameScrubber.extract_usernames_from_section(file, '# /usr/bin/getent passwd')
        else:
            continue
        # Update the username dictionary with the extracted usernames
        for username in usernames:
            if username not in username_dict:
                obfuscated_username= f"user_{username_counter}"
                username_dict[username] = obfuscated_username
                username_counter += 1
    return username_dict



def main():
    parser = argparse.ArgumentParser(description='Process and scrub supportconfig files.')
    parser.add_argument('supportconfig_path', type=str, help='Path to the supportconfig file or directory.')
    parser.add_argument('--config', type=str, default='/etc/supportutils-scrub.conf',
                        help='Path to the configuration file. Default: /etc/supportutils-scrub.conf')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('--mappings', type=str, help='Path to a JSON file containing data mappings.')
    args = parser.parse_args()
    supportconfig_path = args.supportconfig_path
    config_path = args.config
    verbose_flag = args.verbose
    mappings_path = args.mappings 

    # You would load and use the mappings from mappings_path if provided
    if mappings_path:
        # Load and use the mappings
        print(f"Using mappings from: {mappings_path}")


    # Initialize the logger
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose_flag else "normal")

    # Use the ConfigReader class to read the configuration
    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(config_path)

    mappings = {}
    if args.mappings:
        with open(args.mappings, 'r') as f:
            mappings = json.load(f)
            
    #domain_dict = {}
    # Initialize scrubbers
    ip_scrubber = IPScrubber(config, mappings=mappings)
    hostname_scrubber = HostnameScrubber()

    # Conditional instantiation of KeywordScrubber
    if config.get('use_key_words_file', False):
        keyword_file_path = config['key_words_file']
        
        # Check if the keyword file exists and is not empty
        if os.path.exists(keyword_file_path) and os.path.getsize(keyword_file_path) > 0:
            keyword_scrubber = KeywordScrubber(keyword_file_path)
            keyword_scrubber.load_keywords()

            if not keyword_scrubber.is_loaded():
                logger.error("No keywords loaded. Check keyword file.")
                return
        else:
            logger.info("Keyword file is missing or empty. Skipping keyword scrubbing.")
            keyword_scrubber = None
    else:
        keyword_scrubber = None
        logger.info("Keyword scrubbing not enabled.")


    report_files = extract_supportconfig(supportconfig_path, logger)

    # Populate the domains dictuonary
    domain_dict = extract_domains(report_files)
    domain_scrubber = DomainScrubber(domain_dict)
    # Extract and build the username dictionary from pam.txt
    username_dict = extract_usernames(report_files)
    username_scrubber = UsernameScrubber(username_dict)

    # Initialize FileProcessor
    file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber, hostname_scrubber, keyword_scrubber)

    # List of filenames to exclude from scrubbing
    exclude_files = ["memory.txt", "env.txt", "open-files.txt"]

    # Extract Supportconfig and get the list of report files

    # Dictionaries to store obfuscation mappings
    total_ip_dict = {}
    total_domain_dict = {}
    total_user_dict = {}  
    total_hostname_dict = {}
    total_keyword_dict = {}    



    # Process supportcong files
    for report_file in report_files:
        if os.path.basename(report_file) in exclude_files:
            logger.info(f"\x1b[33mSkipping file: {report_file} (Excluded)\x1b[0m")
            continue

        # Use FileProcessor to process the file
        ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict = file_processor.process_file(report_file, logger, verbose_flag)

        # Aggregate the translation dictionaries
        total_ip_dict.update(ip_dict)
        total_domain_dict.update(domain_dict)
        total_user_dict.update(username_dict)
        total_hostname_dict.update(hostname_dict)
        total_keyword_dict.update(keyword_dict)

    dataset_dict = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'keyword': total_keyword_dict
    }

    dataset_path = '/usr/lib/supportconfig/obfuscation_dataset_mappings.json'
    Translator.save_datasets(dataset_path, dataset_dict)


    if verbose_flag:
        print(f"\nObfuscation dataset mappings saved at: {dataset_path}")
        print("Obfuscated mapping content:")
        print(json.dumps(dataset_dict, indent=4))
    else:
        logger.info(f"\033[1mObfuscation datasets mappings saved at: {dataset_path}\033[0m")

if __name__ == "__main__":
    main()

