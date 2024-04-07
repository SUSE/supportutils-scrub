#!/usr/bin/env python3
# main.py

import sys
import os
import re
import json
from config import DEFAULT_CONFIG_PATH
from config_reader import ConfigReader
from ip_scrubber import IPScrubber
from domain_scrubber import DomainScrubber
from user_scrubber import UserScrubber
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


def main():
 
    # Parse command-line arguments
    args = sys.argv[1:]
    supportconfig_path = args[0] if args else None
    config_path = args[args.index("--config") + 1] if "--config" in args else "/etc/supportutils-scrub.conf"
    verbose_flag = "--verbose" in args

    # Initialize the logger
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose_flag else "normal")

    # Use the ConfigReader class to read the configuration
    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(config_path)

    domain_dict = {}
    # Initialize scrubbers
    ip_scrubber = IPScrubber(config)
    user_scrubber = UserScrubber()
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

    # Initialize FileProcessor
    file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, user_scrubber, hostname_scrubber, keyword_scrubber)

    # List of filenames to exclude from scrubbing
    exclude_files = ["memory.txt", "env.txt"]

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
        ip_dict, domain_dict, user_dict, hostname_dict, keyword_dict = file_processor.process_file(report_file, logger, verbose_flag)

        # Aggregate the translation dictionaries
        total_ip_dict.update(ip_dict)
        total_domain_dict.update(domain_dict)
        total_user_dict.update(user_dict)
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

