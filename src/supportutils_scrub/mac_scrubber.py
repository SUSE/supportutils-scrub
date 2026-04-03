# mac_scrubber.py

import re
from typing import Match
from supportutils_scrub.scrubber import Scrubber

class MACScrubber(Scrubber):
    name = 'mac'
    skip_files = frozenset(['modules.txt', 'security-apparmor.txt', 'drbd.txt', 'security-audit.txt', 'fs-btrfs.txt'])

    MAC_PATTERN = re.compile(
        r'(?<![0-9A-Fa-f:])'  
        r'((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})' 
        r'(?![0-9A-Fa-f:])',  
        re.IGNORECASE
    )
    
    EXCLUDED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    def __init__(self, config, mappings=None):
        self.mac_dict = {k.lower(): v for k, v in (mappings.get('mac', {}) if mappings else {}).items()}
        self.config = config

    @property
    def mapping(self):
        return self.mac_dict

    def _generate_fake_mac(self):
        count = len(self.mac_dict)

        b1 = (count >> 16) & 0xFF
        b2 = (count >> 8) & 0xFF
        b3 = count & 0xFF
        return f"00:1A:2B:{b1:02X}:{b2:02X}:{b3:02X}"

    def scrub(self, text: str) -> str:
        if not self.config.obfuscate_mac:
            return text

        def replacer(match: Match) -> str:
            original_mac = match.group(1).lower()

            if original_mac in self.EXCLUDED_MACS:
                return match.group(0)

            if original_mac in self.mac_dict:
                return self.mac_dict[original_mac]
            
            fake_mac = self._generate_fake_mac()
            self.mac_dict[original_mac] = fake_mac
            return fake_mac

        return self.MAC_PATTERN.sub(replacer, text)
