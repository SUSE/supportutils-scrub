# scrubber/main.py

import sys
import os
from config import DEFAULT_CONFIG_PATH
from config_reader import ConfigReader
from ip_scrubber import IPScrubber
from domain_scrubber import DomainScrubber
from user_scrubber import UserScrubber
from hostname_scrubber import HostnameScrubber
from extractor import extract_supportconfig
from translator import Translator
from supportutils_scrub_logger import SupportutilsScrubLogger

 
def process_file(file_path, config, ip_scrubber, domain_scrubber, user_scrubber, hostname_scrubber, logger, verbose_flag):
    """
    Process a supportconfig file, obfuscating sensitive information.

    Parameters:
    - file_path: Path to the supportconfig file.
    - config: Configuration dictionary.
    - ip_scrubber: Instance of IPScrubber.
    - domain_scrubber: Instance of DomainScrubber.
    - user_scrubber: Instance of UserScrubber.
    - hostname_scrubber: Instance of HostnameScrubber.
    - verbose_flag: Boolean indicating verbose output.

    Returns:
    - Tuple of dictionaries (ip_dict, domain_dict, user_dict, hostname_dict).
    """
    ip_dict = {}
    domain_dict = {}
    user_dict = {}
    hostname_dict = {}

    try:
        logger.info(f"Scrubbing file: {file_path}")
        with open(file_path, "r") as file:
            lines = file.readlines()

        # A switch to print a header if file was modified
        obfuscation_occurred = False

        for i, line in enumerate(lines):
            # Scrub IP addresses
            if config["obfuscate_ip"]:
                ip_list = IPScrubber.extract_ips(line)
                for ip in ip_list:
                    obfuscated_ip = ip_scrubber.scrub_ip(ip)  # Corrected method name
                    ip_dict[ip] = obfuscated_ip
                    line = line.replace(ip, obfuscated_ip)


            # Replace the line in the file with obfuscated content
            lines[i] = line

        # Write the changes back to the file
        with open(file_path, "w") as file:
            file.writelines(lines)

    except Exception as e:
        logger.error(f"Error processing file {file_path}: {str(e)}")

    return ip_dict, domain_dict, user_dict, hostname_dict


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

    ip_scrubber = IPScrubber()
    domain_scrubber = DomainScrubber()
    user_scrubber = UserScrubber()
    hostname_scrubber = HostnameScrubber()

    # List of filenames to exclude from scrubbing
    exclude_files = ["env.txt", "fs-btrfs.txt", "fs-diskio.txt"]

    # Extract Supportconfig and get the list of report files
    report_files = extract_supportconfig(supportconfig_path)

    for report_file in report_files:
        # Check if the current file should be excluded
        if os.path.basename(report_file) in exclude_files:
            logger.info(f"\x1b[33mSkipping file: {report_file} (Excluded)\x1b[0m")
            continue

        # Process with the report file
        ip_dict, domain_dict, user_dict, hostname_dict = process_file(
            report_file, config, ip_scrubber, domain_scrubber, user_scrubber, hostname_scrubber, logger, verbose_flag
        )

        # Print the translation dictionaries (for verbose output)
        if verbose_flag:
            logger.info("Translation Dictionaries:")
            logger.info(f"IP Dictionary: {ip_dict}")
            logger.info(f"Domain Dictionary: {domain_dict}")
            logger.info(f"User Dictionary: {user_dict}")
            logger.info(f"Hostname Dictionary: {hostname_dict}")
            logger.info("-" * 20)


    # Save translation dictionaries to JSON files
    Translator.save_translation('ip_translation.json', ip_dict)
    Translator.save_translation('domain_translation.json', domain_dict)
    Translator.save_translation('user_translation.json', user_dict)
    Translator.save_translation('hostname_translation.json', hostname_dict)

    if not verbose_flag:
        logger.info("Translation files saved.")

if __name__ == "__main__":
    main()

