# ipv6_scrubber.py

import re
import ipaddress

class IPv6Scrubber:
    def __init__(self, config, mappings=None):
        self.ipv6_dict = {}
        self.config = config
        self.mappings = mappings.get('ipv6', {}) if mappings else {}

    def scrub_ipv6(self, ipv6):
        """
        Obfuscate an IPv6 address. Private IPv6 addresses are left intact, and public IPv6 addresses are replaced with fake IPv6 addresses.
        """
        if self.is_private_ipv6(ipv6):
            return ipv6
        obfuscated_ipv6 = self.map_original_ipv6_to_fake_ipv6(ipv6)
        return obfuscated_ipv6

    def is_private_ipv6(self, ipv6):
        """
        Check if it is a private IPv6 address.
        """
        # If the configuration is set to also obfuscate private IPv6 addresses, treat all IPv6 addresses as public
        if self.config.get('obfuscate_ipv6', 'no') == 'yes':
            return False
        
        private_ipv6_patterns = [
            re.compile(r"^fe80::"),  # Link-local unicast
            re.compile(r"^fc00::"),  # Unique local unicast
            re.compile(r"^fd00::"),  # Unique local unicast
            re.compile(r"^::1$")     # Loopback address
        ]
        return any(pattern.match(ipv6) for pattern in private_ipv6_patterns)

    def map_original_ipv6_to_fake_ipv6(self, original_ipv6):
        """
        Map the original IPv6 to its corresponding fake IPv6. If not present, generate a unique fake IPv6.
        """
        if original_ipv6 not in self.ipv6_dict:
            fake_ipv6 = self.generate_fake_ipv6()
            self.ipv6_dict[original_ipv6] = fake_ipv6
        return self.ipv6_dict[original_ipv6]

    def generate_fake_ipv6(self):
        """
        Generate a fake IPv6 address.
        """
        return "2001:0db8:85a3::{:x}:{:x}:{:x}".format(
            len(self.ipv6_dict),
            len(self.ipv6_dict) + 1,
            len(self.ipv6_dict) + 2
        )

    @staticmethod
    def extract_ipv6(text):
        """
        Extract IPv6 addresses from a given text.
        """
        # Use the detailed regex pattern for IPv6 addresses
        ipv6_pattern = (
            r"(?<![:\\.\\-a-z0-9])"
            r"((([0-9a-f]{1,4})(:[0-9a-f]{1,4}){7})|"
            r"(([0-9a-f]{1,4}(:[0-9a-f]{0,4}){0,5}))([^.])"
            r"::"
            r"(([0-9a-f]{1,4}(:[0-9a-f]{1,4}){0,5})?))"
            r"(/\d{1,3})?"
            r"(?![:\\a-z0-9])"
        )
        potential_ipv6s = re.findall(ipv6_pattern, text)

        # Filter out matches that are likely not valid IPv6 addresses
        valid_ipv6s = [ipv6[0] for ipv6 in potential_ipv6s if IPv6Scrubber.is_valid_ipv6(ipv6[0])]
        return valid_ipv6s

    @staticmethod
    def is_valid_ipv6(ipv6):
        """
        Check if the extracted string is a valid IPv6 address.
        """
        try:
            # Remove CIDR notation for validation
            ipv6_without_cidr = ipv6.split('/')[0]
            ipaddress.IPv6Address(ipv6_without_cidr)
            # Additional checks to filter out common false positives
            if ":" in ipv6_without_cidr and any(len(part) == 2 for part in ipv6_without_cidr.split(":")):
                return False
            return True
        except ValueError:
            return False
