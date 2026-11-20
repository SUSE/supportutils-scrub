# serial_scrubber.py
import re
from supportutils_scrub.fastsub import fold, gsub, iter_at, literals
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.trie_re import build_trie_pattern

_SKIP_VALUES = frozenset({
    '', 'not specified', 'not present', 'unknown', 'n/a', 'none',
    'to be filled by o.e.m.', 'default string', 'invalid',
    '0000000000', '00000000000000000000',
    'chassis serial number', 'system serial number',
    'base board serial number', 'not applicable',
    'not available', 'no asset information', '"not available"',
    '"no asset information"', '"none"', 'no dimm', 'no asset tag',
    'not provided', 'not set', 'not installed', 'not defined', 'undefined',
    'empty', 'oem', 'o.e.m.', '0123456789', '123456789',
})

_NULL_UUID_RE = re.compile(r'^0{8}-0{4}-0{4}-0{4}-0{12}$')
_UUID_RE      = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

# Serials are matched as SUBSTRINGS across the whole capture, so a short or
# punctuation-only DMI placeholder is catastrophic: "Serial Number: -" (a common
# empty-field placeholder) would turn every hyphen in the capture -- dates, RPM
# versions, iSCSI IQNs -- into SERIAL_N. A real serial / asset tag / part number is
# several alphanumeric characters, so require at least this many alphanumerics and
# reject values that carry no alphanumeric content at all.
_MIN_SERIAL_ALNUM = 4

_LABELED_RE = re.compile(
    r'^(?P<prefix>\s*(?:Serial\s+Number|Asset\s+Tag|Part\s+Number|UUID)\s*:\s*)(?P<value>\S[^\n]*)$',
    re.IGNORECASE | re.MULTILINE,
)

# what a label of _LABELED_RE begins with, lowercase
_LABEL_STARTS = ('serial', 'asset', 'part', 'uuid')


def _labeled(text):
    """The labelled values of text: the matches of _LABELED_RE, each started
    at the line its label is on.

    _LABELED_RE has nothing literal at its start (a line start, then any
    blank space), so `re` tries it at every character of a hardware listing.
    A match can only begin on a line whose first word starts a label, which
    a substring search finds; the pattern is then matched at those lines
    alone. (Run over the whole text, a match may start some blank lines
    earlier; its label, value and end are the same.)"""
    low = fold(text)
    if low is None:
        return _LABELED_RE.finditer(text)
    starts = set()
    for word in _LABEL_STARTS:
        i = low.find(word)
        while i != -1:
            line = text.rfind('\n', 0, i) + 1
            if line == i or text[line:i].isspace():
                starts.add(line)
            i = low.find(word, i + 1)
    return iter_at(_LABELED_RE, text, sorted(starts))


def _is_skip(value: str) -> bool:
    v = value.strip().lower()
    if v in _SKIP_VALUES:
        return True
    if _NULL_UUID_RE.match(value.strip()):
        return True
    # Placeholder / non-serial values ("-", ".", "0", "  "): too few alphanumeric
    # characters to be a real identifier, and dangerous to substring-replace.
    alnum = re.sub(r'[^A-Za-z0-9]', '', value)
    if len(alnum) < _MIN_SERIAL_ALNUM:
        return True
    # 00000000, FFFFFFFF: a blank field, and a run every UUID and hex dump has
    if len(set(alnum.lower())) == 1:
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
        for m in _labeled(text):
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
            trie = build_trie_pattern(self.serial_dict.keys())
            if not trie:
                return text
            self._re = re.compile(r'(?<![A-Za-z0-9])(?:' + trie + r')(?![A-Za-z0-9])')
            self._re_size = len(self.serial_dict)
            self._first = literals(self.serial_dict)
        return gsub(self._re, lambda m: self.serial_dict[m.group(0)], text,
                    first=self._first)
