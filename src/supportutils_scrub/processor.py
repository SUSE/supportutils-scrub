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
        self.current_section = None
        self.current_interface = None
        self.in_network_config = False
        self.in_routing_table = False
        self._ipv4_subnet_map = {}
        self._ipv4_state = {}
        self._ipv6_subnet_map = {}
        self._ipv6_state = {}
        self.network_files = ['network.txt', 'network-*.txt', 'ip.txt', 'route.txt']
        self.special_sections = {
            '# /sbin/ip addr show': 'ip_config',
            '# /sbin/ip route show': 'routing',
            '# /usr/sbin/iptables': 'firewall',
            '# /etc/hosts': 'hosts',
            '# /proc/net/dev': 'network_stats',
            '# /usr/sbin/ethtool': 'ethtool'
        }
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

        obfuscation_occurred = False

        BINARY_SA_PATTERN = re.compile(r"^sa\d{8}(\.xz)?$")
        base_name = os.path.basename(file_path)

        if BINARY_SA_PATTERN.match(base_name):
            print(f"        {base_name} [binary] (removed)")
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"[!] Failed to remove binary file {file_path}: {e} " )
            return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict
        
        is_sar_xz_file  = base_name.startswith("sar") and base_name.endswith(".xz")

        try:
            if is_sar_xz_file:
                file_handle = lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore")
            else:
                file_handle = open(file_path, mode="r", encoding="utf-8", errors="ignore")

            with file_handle as file:
                original_text = file.read()
            
            scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict = \
                self._scrub_content(original_text, base_name, logger, verbose_flag)

            # Write the changes back to the file if any were made
            if scrubbed_text != original_text:
                obfuscation_occurred = True
                header = [
                    "#" + "-" * 93 + "\n",
                    "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n",
                    "#" + "-" * 93 + "\n\n",
                ]
                
                final_content = "".join(header) + scrubbed_text

                if is_sar_xz_file:
                    with lzma.open(file_path, mode="wt", encoding="utf-8") as out_f:
                        out_f.write(final_content)
                else:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(final_content)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

        return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict

    def _scrub_content(self, text, basename, logger, verbose_flag):
        """
        Apply all configured scrubbers to text.

        Returns:
        - Tuple (scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict)
        """
        ip_dict = {}
        domain_dict = {}
        username_dict = {}
        hostname_dict = {}
        keyword_dict = {}
        mac_dict = {}
        ipv6_dict = {}

        scrubbed_text = text

        # Scrub IPv4 addresses and subnets
        if self.config.get("obfuscate_public_ip") == 'yes' or self.config.get("obfuscate_private_ip") == 'yes':
            new_text, new_ip_map, new_subnet_map, state = self.ip_scrubber.scrub_text(scrubbed_text)
            ip_dict.update(new_ip_map)
            self._ipv4_subnet_map.update(new_subnet_map)
            self._ipv4_state = state
            scrubbed_text = new_text

        # Scrub IPv6 addresses
        if self.config.get("obfuscate_ipv6") == 'yes':
            try:
                scrubbed_text, new_ipv6_map, ipv6_subnet_map, state6 = self.ipv6_scrubber.scrub_text(scrubbed_text)
                ipv6_dict.update(new_ipv6_map)
                self._ipv6_subnet_map.update(ipv6_subnet_map)
                self._ipv6_state = state6
            except Exception as e:
                logger.error(f"IPv6 scrub failed for {basename}: {e}")

        # Scrub MAC addresses
        files_to_skip_mac_scrub = ['modules.txt', 'security-apparmor.txt', 'drbd.txt', 'security-audit.txt', 'fs-btrfs.txt']
        if basename not in files_to_skip_mac_scrub and self.config.get("obfuscate_mac") == 'yes':
            scrubbed_text = self.mac_scrubber.scrub(scrubbed_text)
            mac_dict.update(self.mac_scrubber.mac_dict)

        # Scrub keywords
        if self.keyword_scrubber:
            scrubbed_text, line_keyword_dict = self.keyword_scrubber.scrub(scrubbed_text)
            keyword_dict.update(line_keyword_dict)

        # Scrub hostnames
        if self.config.get("obfuscate_hostname") == 'yes':
            scrubbed_text = self.hostname_scrubber.scrub(scrubbed_text)
            hostname_dict.update(self.hostname_scrubber.hostname_dict)

        # Scrub domain names
        if self.config.get("obfuscate_domain") == 'yes':
            scrubbed_text = self.domain_scrubber.scrub(scrubbed_text)
            domain_dict.update(self.domain_scrubber.domain_dict)

        # Scrub usernames
        if self.config.get("obfuscate_username") == 'yes':
            scrubbed_text = self.username_scrubber.scrub(scrubbed_text)
            username_dict.update(self.username_scrubber.username_dict)

        return scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict

    def process_text(self, text, logger, verbose_flag):
        """
        Scrub a plain text string (e.g. from stdin).

        Returns the same tuple as _scrub_content().
        """
        return self._scrub_content(text, "stdin", logger, verbose_flag)
