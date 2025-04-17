# processor.py

import sys
import os
import lzma  
import re
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.extractor import extract_supportconfig
from supportutils_scrub.translator import Translator
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber

class FileProcessor:
    def __init__(self, config, ip_scrubber: IPScrubber, domain_scrubber: DomainScrubber, username_scrubber: UsernameScrubber, hostname_scrubber: HostnameScrubber, mac_scrubber: MACScrubber, ipv6_scrubber: IPv6Scrubber, keyword_scrubber: KeywordScrubber = None):
        self.config = config
        self.ip_scrubber = ip_scrubber
        self.domain_scrubber = domain_scrubber
        self.hostname_scrubber = hostname_scrubber
        self.keyword_scrubber = keyword_scrubber
        self.username_scrubber = username_scrubber
        self.mac_scrubber = mac_scrubber
        self.ipv6_scrubber = ipv6_scrubber

        # Initialize keyword scrubber if not already done
        if self.keyword_scrubber and not self.keyword_scrubber.is_loaded():
            self.keyword_scrubber.load_keywords()

    def process_file(self, file_path, logger: SupportutilsScrubLogger, verbose_flag):
        """
        Process a supportconfig file, obfuscating sensitive information.

        Returns:
        - Tuple of dictionaries (ip_dict, domain_dict, user_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict).
        """

        ip_dict = {}
        domain_dict = {}
        username_dict = {}
        hostname_dict = {}
        keyword_dict = {} 
        mac_dict = {}
        ipv6_dict = {}


        # A switch to print a header if file was modified
        obfuscation_occurred = False

        BINARY_SA_PATTERN = re.compile(r"^sa\d{8}(\.xz)?$")
        base_name = os.path.basename(file_path)

        if BINARY_SA_PATTERN.match(base_name):
            print(f"        {base_name} [binary] (skipped)")
            return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict

        is_sar_xz_file  = base_name.startswith("sar") and base_name.endswith(".xz")


        try:
            if is_sar_xz_file:
                file_handle = lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore")

            else:
                file_handle = open(file_path, mode="r", encoding="utf-8", errors="ignore")

            with file_handle as file:
                lines = file.readlines()



            for i, line in enumerate(lines):
                
                # Scrub IPv4 addresses
                if self.config["obfuscate_public_ip"]:
                    original_line = line
                    ip_list = IPScrubber.extract_ips(line)
                    for ip in ip_list:
                        obfuscated_ip = self.ip_scrubber.scrub_ip(ip)  
                        ip_dict[ip] = obfuscated_ip
                        line = line.replace(ip, obfuscated_ip)
                        if line != original_line:
                            obfuscation_occurred = True

                #Scrub IPv6 addresses
                if self.config["obfuscate_ipv6"]:
                    original_line = line
                    ipv6_list = IPv6Scrubber.extract_ipv6(line)
                    for ipv6 in ipv6_list:
                        obfuscated_ipv6 = self.ipv6_scrubber.scrub_ipv6(ipv6)  
                        ipv6_dict[ipv6] = obfuscated_ipv6
                        line = line.replace(ipv6, obfuscated_ipv6)
                        if line != original_line:
                            obfuscation_occurred = True

                # Scrub MAC addresses
                if self.config["obfuscate_mac"]:
                    original_line = line
                    mac_list = MACScrubber.extract_mac(line)
                    for mac in mac_list:
                        obfuscated_mac = self.mac_scrubber.scrub_mac(mac)  
                        mac_dict[mac] = obfuscated_mac
                        line = line.replace(mac, obfuscated_mac)
                        if line != original_line:
                            obfuscation_occurred = True                                            

                # Scrub keywords
                if self.keyword_scrubber:
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
                header = [
                    "#" + "-" * 93 + "\n",
                    "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n",
                    "#" + "-" * 93 + "\n\n",
                ]

                if is_sar_xz_file:
                    with lzma.open(file_path, mode="wt", encoding="utf-8") as out_f:
                        out_f.writelines(header + lines)

                else:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.writelines(header + lines)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

        return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict
