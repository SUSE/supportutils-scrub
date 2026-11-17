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
    # Longer colon runs that carry MACs inside: iptables "MAC=dst:src:type",
    # DHCP client-id "01:<mac>", DUID-LL "00:03:00:01:<mac>" and DUID-LLT
    # "00:01:00:01:<time>:<mac>". Any other run is left alone.
    LONG_RUN = re.compile(
        r'(?<![0-9A-Fa-f:])'
        r'((?:[0-9A-Fa-f]{2}:){6,13}[0-9A-Fa-f]{2})'
        r'(?![0-9A-Fa-f:])'
    )

    EXCLUDED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    def __init__(self, config, mappings=None, deterministic=False):
        self.mac_dict = {k.lower(): v for k, v in (mappings.get('mac', {}) if mappings else {}).items()}
        self.config = config
        self.deterministic = deterministic
        self._fakes = {v.upper() for v in self.mac_dict.values()}
        # --jobs workers avoid only the fakes they all start with; anything
        # learned in one worker would make the fake depend on file order.
        self._base_fakes = frozenset(self._fakes)

    @property
    def mapping(self):
        return self.mac_dict

    def _generate_fake_mac(self, original=None):
        # The fake OUI leaves 24 bits, so a hash collides after a few thousand
        # MACs: step to the next candidate until no other real MAC holds it.
        taken = self._base_fakes if self.deterministic else self._fakes
        i = 0
        while True:
            if self.deterministic and original is not None:
                from supportutils_scrub.det import dhash
                h = dhash(original if i == 0 else f"{original}#{i}", 3).upper()
                fake = f"00:1A:2B:{h[0:2]}:{h[2:4]}:{h[4:6]}"
            else:
                count = (len(self.mac_dict) + i) & 0xFFFFFF
                fake = f"00:1A:2B:{count >> 16:02X}:{(count >> 8) & 0xFF:02X}:{count & 0xFF:02X}"
            if fake not in taken:
                return fake
            i += 1

    def _fake_for(self, mac):
        mac = mac.lower()
        if mac in self.EXCLUDED_MACS:
            return None
        fake = self.mac_dict.get(mac)
        if fake is None:
            fake = self._generate_fake_mac(mac)
            self.mac_dict[mac] = fake
            self._fakes.add(fake)
        return fake

    def _embedded_offsets(self, m):
        o = m.group(1).lower().split(':')
        n = len(o)
        if n == 14 and m.string[max(0, m.start() - 4):m.start()] == 'MAC=':
            return (0, 6)
        if n == 7 and o[0] == '01':
            return (1,)
        if n == 10 and o[:4] == ['00', '03', '00', '01']:
            return (4,)
        if n == 14 and o[:4] == ['00', '01', '00', '01']:
            return (8,)
        return ()

    def _replace_run(self, m):
        octets = m.group(1).split(':')
        for off in self._embedded_offsets(m):
            fake = self._fake_for(':'.join(octets[off:off + 6]))
            if fake:
                octets[off:off + 6] = fake.split(':')
        return ':'.join(octets)

    def scrub(self, text: str) -> str:
        if not self.config.obfuscate_mac:
            return text

        def replacer(match: Match) -> str:
            return self._fake_for(match.group(1)) or match.group(0)

        text = self.MAC_PATTERN.sub(replacer, text)
        return self.LONG_RUN.sub(self._replace_run, text)
