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
from extractor import create_txz, extract_supportconfig
from translator import Translator
from supportutils_scrub_logger import SupportutilsScrubLogger
from processor import FileProcessor


def extract_domains(report_files, additional_domains):
    domain_dict = {}
    domain_counter = 0
    all_domains = []

    # Extract domains from specific files
    for file in report_files:
        if 'etc.txt' in file:
            domains = DomainScrubber.extract_domains_from_resolv_conf(file, '# /etc/resolv.conf')
            all_domains.extend(domains)
        elif 'network.txt' in file:
            domains = DomainScrubber.extract_domains_from_hosts(file, '# /etc/hosts')
            all_domains.extend(domains)
        elif 'nfs.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /bin/egrep')
            all_domains.extend(domains)
        elif 'ntp.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /etc/ntp.conf')
            all_domains.extend(domains)
        elif 'y2log.txt' in file:
            domains = DomainScrubber.extract_domains_from_section(file, '# /var/adm/autoinstall/cache/installedSystem.xml')
            all_domains.extend(domains)
        else:
            continue

        all_domains.extend(additional_domains)
        # Update the domain dictionary with the extracted domains
        for domain in all_domains:
            if domain not in domain_dict:
                obfuscated_domain = f"domain_{domain_counter}"
                domain_dict[domain] = obfuscated_domain
                domain_counter += 1
    
    return domain_dict


def extract_hostnames(report_files, additional_hostnames):
    hostname_dict = {}
    hostname_counter = 0
    all_hostnames = []
    
    # Extract hostnames from network.txt
    for file in report_files:
        if 'network.txt' in file:
            hostnames_from_hosts = HostnameScrubber.extract_hostnames_from_hosts(file)
            hostnames_from_hostname = HostnameScrubber.extract_hostnames_from_hostname_section(file)
            all_hostnames.extend(hostnames_from_hosts)
            all_hostnames.extend(hostnames_from_hostname)

    # Add additional hostnames
    all_hostnames.extend(additional_hostnames)

    # Update the hostname dictionary with the extracted hostnames
    for hostname in all_hostnames:
        if hostname not in hostname_dict:
            obfuscated_hostname = f"hostname_{hostname_counter}"
            hostname_dict[hostname] = obfuscated_hostname
            hostname_counter += 1

    return hostname_dict


def extract_usernames(report_files, additional_usernames):
    username_dict={}
    username_counter=0
    all_usernames = []

    for file in report_files:
        if 'pam.txt' in file:
            section_starts= ['# /usr/bin/getent passwd', '# /etc/passwd']
            usernames=UsernameScrubber.extract_usernames_from_section(file, section_starts)
            all_usernames.extend(usernames)
        elif 'messages.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file) 
            all_usernames.extend(usernames)           

        all_usernames.extend(additional_usernames)
        # Update the username dictionary with the extracted usernames
        for username in all_usernames:
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
    parser.add_argument('--username', type=str, help='Additional usernames to obfuscate (comma, semicolon, or space-separated)')
    parser.add_argument('--domain', type=str, help='Additional domains to obfuscate (comma, semicolon, or space-separated)')
    parser.add_argument('--hostname', type=str, help='List of hostnames separated by space, comma, or semicolon')


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
            
    ip_scrubber = IPScrubber(config, mappings=mappings)

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


    try:
        report_files, clean_folder_path = extract_supportconfig(supportconfig_path, logger)
        logger.info(f"Extraction completed. Clean folder path: {clean_folder_path}")
    except Exception as e:
        logger.error(f"Error during extraction: {e}")
        raise

    # Populate the domains dictuonary
    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict = extract_domains(report_files, additional_domains)
    domain_scrubber = DomainScrubber(domain_dict)

    # Extract and build the username dictionary from pam.txt
    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames(report_files, additional_usernames)
    username_scrubber = UsernameScrubber(username_dict)

    # Extract hostnames and build dictionary
    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames(report_files, additional_hostnames)
    hostname_scrubber = HostnameScrubber(hostname_dict)

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



    # Process supportconfig files
    logger.info("Scrubbing:")
    for report_file in report_files:
        if os.path.basename(report_file) in exclude_files:
            print(f"        {os.path.basename(report_file)} (Excluded)")
            continue
        print(f"        {os.path.basename(report_file)}")
    
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

    base_name = os.path.splitext(args.supportconfig_path)[0]
    new_txz_file_path = base_name + "_scrubbed.txz"
    create_txz(clean_folder_path, new_txz_file_path)
    logger.info(f"\033[1mNew scrubbed TXZ file created at: {new_txz_file_path}\033[0m")

    if verbose_flag:
        logger.info(f"\033[1mObfuscation datasets mappings saved at: {dataset_path}\033[0m")
        print("Obfuscated mapping content:")
        print(json.dumps(dataset_dict, indent=4))
    else:
        logger.info(f"\033[1mObfuscation datasets mappings saved at: {dataset_path}\033[0m")

if __name__ == "__main__":
    main()

