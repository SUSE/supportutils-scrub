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
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber

class FileProcessor:
    def __init__(self, config, ip_scrubber: IPScrubber, domain_scrubber: DomainScrubber, username_scrubber: UsernameScrubber, hostname_scrubber: HostnameScrubber, mac_scrubber: MACScrubber, ipv6_scrubber: IPv6Scrubber, keyword_scrubber: KeywordScrubber = None, serial_scrubber: SerialScrubber = None, email_scrubber: EmailScrubber = None, password_scrubber: PasswordScrubber = None, cloud_token_scrubber: CloudTokenScrubber = None):
        self.config = config
        self.ip_scrubber = ip_scrubber
        self.domain_scrubber = domain_scrubber
        self.hostname_scrubber = hostname_scrubber
        self.keyword_scrubber = keyword_scrubber
        self.username_scrubber = username_scrubber
        self.mac_scrubber = mac_scrubber
        self.ipv6_scrubber = ipv6_scrubber
        self.serial_scrubber = serial_scrubber
        self.email_scrubber = email_scrubber
        self.password_scrubber = password_scrubber
        self.cloud_token_scrubber = cloud_token_scrubber
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
        ip_dict = {}
        domain_dict = {}
        username_dict = {}
        hostname_dict = {}
        keyword_dict = {}
        mac_dict = {}
        ipv6_dict = {}
        serial_dict = {}

        obfuscation_occurred = False

        BINARY_SA_PATTERN = re.compile(r"^sa\d{8}(\.xz)?$")
        BINARY_OBJ_PATTERN = re.compile(r"^.*\.obj$", re.IGNORECASE)
        base_name = os.path.basename(file_path)

        if BINARY_SA_PATTERN.match(base_name) or BINARY_OBJ_PATTERN.match(base_name):
            print(f"        {base_name} [binary] (removed)")
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"[!] Failed to remove binary file {file_path}: {e} " )
            return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict

        SAR_XZ_PATTERN   = re.compile(r'^sar\d{8}\.xz$')
        SAR_PLAIN_PATTERN = re.compile(r'^sar\d{8}$')
        is_sar_xz_file   = bool(SAR_XZ_PATTERN.match(base_name))
        is_sar_plain_file = bool(SAR_PLAIN_PATTERN.match(base_name))

        _SCRUB_INFO_HEADER = (
            "#" + "-" * 93 + "\n"
            "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n"
            "#" + "-" * 93 + "\n\n"
        )

        try:
            if is_sar_xz_file:
                with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()

                scrubbed_first_line, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict = \
                    self._scrub_content(first_line, base_name, logger, verbose_flag)

                if scrubbed_first_line != first_line:
                    obfuscation_occurred = True
                    # Re-open to read the rest now that we know a change is needed.
                    # Write as plain text to avoid expensive xz recompression.
                    with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                        f.readline()  
                        rest = f.read()
                    plain_path = file_path[:-3] 
                    with open(plain_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_first_line + rest)
                    os.remove(file_path)

            elif is_sar_plain_file:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()
                    rest = f.read()

                scrubbed_first_line, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict = \
                    self._scrub_content(first_line, base_name, logger, verbose_flag)

                if scrubbed_first_line != first_line:
                    obfuscation_occurred = True
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_first_line + rest)

            else:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as file:
                    original_text = file.read()

                scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict = \
                    self._scrub_content(original_text, base_name, logger, verbose_flag)

                if scrubbed_text != original_text:
                    obfuscation_occurred = True
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_text)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

        return ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict

    def _scrub_content(self, text, basename, logger, verbose_flag):
        ip_dict = {}
        domain_dict = {}
        username_dict = {}
        hostname_dict = {}
        keyword_dict = {}
        mac_dict = {}
        ipv6_dict = {}
        serial_dict = {}

        scrubbed_text = text

        if self.config.get("obfuscate_public_ip") == 'yes' or self.config.get("obfuscate_private_ip") == 'yes':
            new_text, new_ip_map, new_subnet_map, state = self.ip_scrubber.scrub_text(scrubbed_text)
            ip_dict.update(new_ip_map)
            self._ipv4_subnet_map.update(new_subnet_map)
            self._ipv4_state = state
            scrubbed_text = new_text

        if self.config.get("obfuscate_ipv6") == 'yes':
            try:
                scrubbed_text, new_ipv6_map, ipv6_subnet_map, state6 = self.ipv6_scrubber.scrub_text(scrubbed_text)
                ipv6_dict.update(new_ipv6_map)
                self._ipv6_subnet_map.update(ipv6_subnet_map)
                self._ipv6_state = state6
            except Exception as e:
                logger.error(f"IPv6 scrub failed for {basename}: {e}")

        files_to_skip_mac_scrub = ['modules.txt', 'security-apparmor.txt', 'drbd.txt', 'security-audit.txt', 'fs-btrfs.txt']
        if basename not in files_to_skip_mac_scrub and self.config.get("obfuscate_mac") == 'yes':
            scrubbed_text = self.mac_scrubber.scrub(scrubbed_text)
            mac_dict.update(self.mac_scrubber.mac_dict)

        if self.keyword_scrubber:
            scrubbed_text, line_keyword_dict = self.keyword_scrubber.scrub(scrubbed_text)
            keyword_dict.update(line_keyword_dict)

        if self.config.get("obfuscate_hostname") == 'yes':
            scrubbed_text = self.hostname_scrubber.scrub(scrubbed_text)
            hostname_dict.update(self.hostname_scrubber.hostname_dict)

        if self.config.get("obfuscate_domain") == 'yes':
            scrubbed_text = self.domain_scrubber.scrub(scrubbed_text)
            domain_dict.update(self.domain_scrubber.domain_dict)

        if self.config.get("obfuscate_username") == 'yes':
            scrubbed_text = self.username_scrubber.scrub(scrubbed_text)
            username_dict.update(self.username_scrubber.username_dict)

        if self.email_scrubber:
            scrubbed_text = self.email_scrubber.scrub(scrubbed_text)

        if self.password_scrubber:
            scrubbed_text = self.password_scrubber.scrub(scrubbed_text)

        if self.cloud_token_scrubber:
            scrubbed_text = self.cloud_token_scrubber.scrub(scrubbed_text)

        if self.serial_scrubber:
            scrubbed_text = self.serial_scrubber.scrub(scrubbed_text)
            serial_dict.update(self.serial_scrubber.serial_dict)

        return scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict

    def process_text(self, text, logger, verbose_flag):
        return self._scrub_content(text, "stdin", logger, verbose_flag)
