# serial_scrubber.py
"""Scrubber for hardware serial numbers and system UUIDs found in dmidecode output."""
import re

# Placeholder values that are not real serials — skip these
_SKIP_VALUES = frozenset({
    '', 'not specified', 'not present', 'unknown', 'n/a', 'none',
    'to be filled by o.e.m.', 'default string', 'invalid',
    '0000000000', '00000000000000000000',
    'chassis serial number', 'system serial number',
    'base board serial number', 'not applicable',
})

_NULL_UUID_RE = re.compile(r'^0{8}-0{4}-0{4}-0{4}-0{12}$')
_UUID_RE      = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

# Matches labeled dmidecode fields that carry hardware identity values
_LABELED_RE = re.compile(
    r'^(?P<prefix>\s*(?:Serial\s+Number|Asset\s+Tag|Part\s+Number|UUID)\s*:\s*)(?P<value>\S[^\n]*)$',
    re.IGNORECASE | re.MULTILINE,
)


def _is_skip(value: str) -> bool:
    v = value.strip().lower()
    if v in _SKIP_VALUES:
        return True
    if _NULL_UUID_RE.match(value.strip()):
        return True
    return False


class SerialScrubber:
    """
    Scrubs hardware serial numbers and system UUIDs from supportconfig files.

    Usage:
      1. Call pre_scan(text) on targeted files (basic-environment.txt, boot.txt).
      2. Call scrub(text) on every file to replace found values.
    """

    def __init__(self, mappings: dict = None):
        self.serial_dict: dict = {}
        if mappings:
            self.serial_dict = dict(mappings.get('serial', {}))
        self._counter = len(self.serial_dict)

    def pre_scan(self, text: str) -> None:
        """Collect serial numbers and UUIDs from dmidecode-style labeled fields."""
        for m in _LABELED_RE.finditer(text):
            value = m.group('value').strip()
            if _is_skip(value):
                continue
            if value not in self.serial_dict:
                self.serial_dict[value] = self._make_fake(value, self._counter)
                self._counter += 1

    def _make_fake(self, value: str, idx: int) -> str:
        if _UUID_RE.match(value.strip()):
            return f'00000000-0000-0000-0000-{idx:012x}'
        return f'SERIAL_{idx}'

    def scrub(self, text: str) -> str:
        if not self.serial_dict:
            return text
        # Replace longest values first to avoid partial substitution
        for real, fake in sorted(self.serial_dict.items(), key=lambda x: len(x[0]), reverse=True):
            text = text.replace(real, fake)
        return text
