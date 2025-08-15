# mac_scrubber.py

import re
from typing import Match

class MACScrubber:
    """
    Handles the detection and replacement of MAC addresses efficiently.
    It uses a single, more precise compiled regex and a replacer function for a one-pass scrub.
    """

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

    def _generate_fake_mac(self):
        """Generates a new, unique fake MAC address."""
        count = len(self.mac_dict)

        b1 = (count >> 16) & 0xFF
        b2 = (count >> 8) & 0xFF
        b3 = count & 0xFF
        return f"00:1A:2B:{b1:02X}:{b2:02X}:{b3:02X}"

    def scrub(self, text: str) -> str:
        """
        Finds and replaces all non-excluded MAC addresses in a block of text
        using a single pass with re.sub and a callback function.
        The internal mac_dict is updated with any new mappings.
        """
        if self.config.get('obfuscate_mac', 'no') != 'yes':
            return text

        def replacer(match: Match) -> str:
            """
            This function is called for every MAC address found.
            It decides whether to replace it and what to replace it with.
            """
            original_mac = match.group(1).lower()

            if original_mac in self.EXCLUDED_MACS:
                return match.group(0) # Return the original string (preserving case).

            if original_mac in self.mac_dict:
                return self.mac_dict[original_mac]
            
            fake_mac = self._generate_fake_mac()
            self.mac_dict[original_mac] = fake_mac
            return fake_mac

        return self.MAC_PATTERN.sub(replacer, text)
