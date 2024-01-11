# ip_scrubber.py

import re

class IPScrubber:
    def __init__(self, config):
        self.ip_dict = {}
        self.config = config

    def scrub_ip(self, ip):
        """
        Obfuscate an IP address. Private IPs are intact, and public IPs are replaced with fake IPs.
        """
        if self.is_private_ip(ip):
            return ip
        obfuscated_ip = self.map_original_ip_to_fake_ip(ip)
        return obfuscated_ip

    def is_private_ip(self, ip):
        """
        Check if it is a private IP address.
        """
        # If the configuration is set to also obfuscate private IPs, treat all IPs as public
        if self.config.get('obfuscate_private_ip', 'no') == 'yes':
            return False
        
        private_ip_patterns = [
            re.compile(r"^127\."),
            re.compile(r"^10\."),
            re.compile(r"^192\.168\."),
            re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.")
        ]
        return any(pattern.match(ip) for pattern in private_ip_patterns)

    def map_original_ip_to_fake_ip(self, original_ip):
        """
        Map the original IP to its corresponding fake IP. If not present, generate a unique fake IP.
        """
        if original_ip not in self.ip_dict:
            fake_ip = self.generate_fake_ip()
            self.ip_dict[original_ip] = fake_ip
        return self.ip_dict[original_ip]

    def generate_fake_ip(self):
        """
        Generate a fake IP address.
        """
        return "42.42.{}.{}".format(len(self.ip_dict) + 1, len(self.ip_dict) + 2)

    @staticmethod
    def extract_ips(text):
        """
        Extract IP addresses from a given text.
        """
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        return re.findall(ip_pattern, text)

