# mac_scrubber.py

import re
import logging

class MACScrubber:
    def __init__(self, config, mappings=None):
        self.mac_dict = {}
        self.config = config
        self.mappings = mappings.get('mac', {}) if mappings else {}

        # Log the configuration for debugging
        logging.info(f"MACScrubber initialized with config: {self.config}")

    def scrub_mac(self, mac):
        """
        Obfuscate a MAC address. If configuration is set to obfuscate MAC addresses, replace with fake MAC.
        """
        logging.info(f"Scrubbing MAC: {mac} with config: {self.config}")
        if self.config.get('obfuscate_mac', 'no') == 'yes':
            # Skip scrubbing for specific MAC addresses
            if mac.lower() in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                return mac
            obfuscated_mac = self.map_original_mac_to_fake_mac(mac)
            logging.info(f"Obfuscated MAC: {obfuscated_mac}")
            return obfuscated_mac
        else:
            return mac

    def map_original_mac_to_fake_mac(self, original_mac):
        """
        Map the original MAC to its corresponding fake MAC. If not present, generate a unique fake MAC.
        """
        if original_mac not in self.mac_dict:
            fake_mac = self.generate_fake_mac()
            self.mac_dict[original_mac] = fake_mac
        return self.mac_dict[original_mac]

    def generate_fake_mac(self):
        """
        Generate a fake MAC address.
        """
        fake_mac = "00:1A:2B:{:02X}:{:02X}:{:02X}".format(
            (len(self.mac_dict) + 1) % 256,
            (len(self.mac_dict) + 2) % 256,
            (len(self.mac_dict) + 3) % 256
        )
        logging.info(f"Generated fake MAC: {fake_mac}")
        return fake_mac

    @staticmethod
    def extract_mac(text):
        """
        Extract MAC addresses from a given text.
        """
        # Improved pattern to avoid large blocks of hexadecimal values
        mac_pattern = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
        lines = text.split('\n')
        macs = []
        for line in lines:
            # Avoid lines that are too long or have too many colons which likely aren't MAC addresses
            if len(line) <= 23 or line.count(':') == 5:
                macs.extend(re.findall(mac_pattern, line))
        return macs
