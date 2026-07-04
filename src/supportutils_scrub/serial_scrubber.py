# serial_scrubber.py
import re
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.trie_re import build_trie_pattern

_SKIP_VALUES = frozenset({
    '', 'not specified', 'not present', 'unknown', 'n/a', 'none',
    'to be filled by o.e.m.', 'default string', 'invalid',
    '0000000000', '00000000000000000000',
    'chassis serial number', 'system serial number',
    'base board serial number', 'not applicable',
    'not available', 'no asset information', '"not available"',
    '"no asset information"', '"none"',
})

_NULL_UUID_RE = re.compile(r'^0{8}-0{4}-0{4}-0{4}-0{12}$')
_UUID_RE      = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

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


class SerialScrubber(Scrubber):
    name = 'serial'
    """Scrubs hardware serial numbers and system UUIDs from supportconfig files"""

    def __init__(self, mappings: dict = None):
        self.serial_dict: dict = {}
        if mappings:
            self.serial_dict = dict(mappings.get('serial', {}))
        self._counter = len(self.serial_dict)
        self._re = None
        self._re_size = -1

    @property
    def mapping(self):
        return self.serial_dict

    def pre_scan(self, text: str) -> None:
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
        # Single trie-regex pass (greedy, so the longest serial wins at any
        # position) instead of one str.replace full pass per serial. Rebuilt
        # lazily because pre_scan keeps adding entries between scrubs.
        if self._re is None or self._re_size != len(self.serial_dict):
            self._re = re.compile(build_trie_pattern(self.serial_dict.keys()))
            self._re_size = len(self.serial_dict)
        return self._re.sub(lambda m: self.serial_dict[m.group(0)], text)
