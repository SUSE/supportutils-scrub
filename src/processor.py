# processor.py

import sys
import os
from config import DEFAULT_CONFIG_PATH
from config_reader import ConfigReader
from ip_scrubber import IPScrubber
from domain_scrubber import DomainScrubber
from hostname_scrubber import HostnameScrubber
from extractor import extract_supportconfig
from translator import Translator
from supportutils_scrub_logger import SupportutilsScrubLogger
from keyword_scrubber import KeywordScrubber
from username_scrubber import UsernameScrubber


class FileProcessor:
    def __init__(self, config, ip_scrubber: IPScrubber, domain_scrubber: DomainScrubber, username_scrubber: UsernameScrubber, hostname_scrubber: HostnameScrubber, keyword_scrubber: KeywordScrubber = None):
        self.config = config
        self.ip_scrubber = ip_scrubber
        self.domain_scrubber = domain_scrubber
        self.hostname_scrubber = hostname_scrubber
        self.keyword_scrubber = keyword_scrubber
        self.username_scrubber = username_scrubber

    def process_file(self, file_path, logger: SupportutilsScrubLogger, verbose_flag):
        """
        Process a supportconfig file, obfuscating sensitive information.

        Parameters:
        - file_path: Path to the supportconfig file.
        - config: Configuration file to enable various options.
        - ip_scrubber: Instance of IPScrubber.
        - domain_scrubber: Instance of DomainScrubber.
        - user_scrubber: Instance of UserScrubber.
        - hostname_scrubber: Instance of HostnameScrubber.
        - logger: Instance of SupportutilsScrubLogger. 
        - verbose_flag: Boolean indicating verbose output.

        Returns:
        - Tuple of dictionaries (ip_dict, domain_dict, user_dict, hostname_dict).
        """

        ip_dict = {}
        domain_dict = {}
        username_dict = {}
        hostname_dict = {}
        keyword_dict = {} 

        try:
            with open(file_path, "r") as file:
                lines = file.readlines()

           # A switch to print a header if file was modified
            obfuscation_occurred = False

            for i, line in enumerate(lines):
                
                # Scrub IP addresses
                if self.config["obfuscate_public_ip"]:
                    original_line = line
                    ip_list = IPScrubber.extract_ips(line)
                    for ip in ip_list:
                        obfuscated_ip = self.ip_scrubber.scrub_ip(ip)  
                        ip_dict[ip] = obfuscated_ip
                        line = line.replace(ip, obfuscated_ip)
                        if line != original_line:
                            obfuscation_occurred = True

                # Scrub keywords
                if self.config.get('use_key_words_file', False) and self.keyword_scrubber:
                    original_line = line
                    line, line_keyword_dict = self.keyword_scrubber.scrub(line)  
                    keyword_dict.update(line_keyword_dict) 
                    if line != original_line:
                        obfuscation_occurred = True

                # Scrub hostnames names
                if self.config["obfuscate_hostname"]:
                    original_line = line
                    scrubbed_line = self.hostname_scrubber.scrub(line)
                    line = scrubbed_line
                    hostname_dict.update(self.hostname_scrubber.hostname_dict)
                    if line != original_line:
                        obfuscation_occurred = True

                # Scrub domain names
                if self.config["obfuscate_domain"]:
                    original_line = line
                    scrubbed_line = self.domain_scrubber.scrub(line)
                    line = scrubbed_line
                    domain_dict.update(self.domain_scrubber.domain_dict)
                    if line != original_line:
                        obfuscation_occurred = True

                # Scrub usernames
                if self.config["obfuscate_username"]:
                    original_line = line
                    scrubbed_line = self.username_scrubber.scrub(line)
                    line = scrubbed_line
                    username_dict.update(self.username_scrubber.username_dict)
                    if line != original_line:
                        obfuscation_occurred = True


                # Replace the line in the file with obfuscated content
                lines[i] = line

            # Write the changes back to the file
            if obfuscation_occurred:
                with open(file_path, "w") as file:
                    file.write("#" + "-" * 93 + "\n")
                    file.write("# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n")
                    file.write("#" + "-" * 93 + "\n\n")
                    file.writelines(lines)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

        return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict
