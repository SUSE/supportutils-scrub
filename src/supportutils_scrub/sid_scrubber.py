# sid_scrubber.py
#
# Scrubs SAP System IDs (SIDs) -- e.g. "SEP" -- from supportconfig / crm_report
# data. A SID leaks pervasively: as the bare token, in /usr/sap/<SID>, /sapmnt/<SID>,
# SAP<SID> env/profile names, pacemaker resources (rsc_SAP_<SID>_D00) and the
# <sid>adm system user. supportutils-scrub historically did not scrub it, so a real
# customer SID survived into "scrubbed" output (found on SFSC01846075: SEP in 56+ files).
#
# Safety: a SID is only 3 chars, so scrubbing every 3-letter uppercase token would be
# catastrophic. We therefore DISCOVER SIDs only from strong, SAP-specific contexts and
# skip SAP's reserved words; then we substitute the discovered SID everywhere it appears.
import re
from supportutils_scrub.scrubber import Scrubber

_SID = r'[A-Z][A-Z0-9]{2}'

# SAP forbids these as SIDs (reserved). Several are also common all-caps tokens that
# would be false positives -- never treat them as a customer SID.
_RESERVED = frozenset({
    'ADD', 'ALL', 'AND', 'ANY', 'ASC', 'AUX', 'AVG', 'BIN', 'BIT', 'CDC', 'COM',
    'CON', 'DBA', 'DBM', 'DEV', 'EPS', 'FOR', 'GID', 'IBM', 'INT', 'KEY', 'LOG',
    'LPT', 'MAX', 'MIN', 'MON', 'NIX', 'NOT', 'NUL', 'OFF', 'OLD', 'OMS', 'OUT',
    'PAD', 'PRN', 'RAW', 'REF', 'ROW', 'SAP', 'SET', 'SGA', 'SHG', 'SID', 'SQL',
    'SUM', 'SYS', 'TMP', 'TOP', 'UID', 'USE', 'USR', 'VAR', 'ADM', 'ALT', 'TBD',
})

# Strong, SAP-specific discovery contexts. A 3-char token must appear in one of these
# to be treated as a real SID (deliberately conservative).
_DISCOVERY = [
    re.compile(r'/usr/sap/(' + _SID + r')(?![A-Za-z0-9])'),
    re.compile(r'/sapmnt/(' + _SID + r')(?![A-Za-z0-9])'),
    re.compile(r'SAPSYSTEMNAME\s*[=:]\s*(' + _SID + r')'),
    re.compile(r'\brsc_[A-Za-z]*SAP[A-Za-z]*_(' + _SID + r')_'),
    re.compile(r'\bSAP(' + _SID + r')_'),
    re.compile(r'\b(' + _SID + r')_(?:D|ASCS|ERS|SCS|HDB|J|W|G)\d\d\b'),
]


def _valid(sid: str) -> bool:
    return sid.upper() not in _RESERVED


class SIDScrubber(Scrubber):
    name = 'sid'

    def __init__(self, mappings: dict = None):
        self.sid_dict: dict = {}
        if mappings:
            self.sid_dict = dict(mappings.get('sid', {}))
        self._counter = len(self.sid_dict)

    @property
    def mapping(self):
        return self.sid_dict

    def _fake(self, idx: int) -> str:
        # Valid 3-char SIDs matching the project's placeholder style: HA1, HA2, ...
        return f'HA{idx + 1}' if idx < 9 else f'H{idx + 1:02d}'

    def _add(self, sid: str) -> None:
        sid = sid.upper()
        if not _valid(sid) or sid in self.sid_dict:
            return
        self.sid_dict[sid] = self._fake(self._counter)
        self._counter += 1

    def pre_scan(self, text: str) -> None:
        for rx in _DISCOVERY:
            for m in rx.finditer(text):
                self._add(m.group(1))

    def learn(self, text: str) -> None:   # parity with the parallel learn pre-pass
        self.pre_scan(text)

    def scrub(self, text: str) -> str:
        if not self.sid_dict:
            return text
        # Few SIDs per capture (1-3); sequential per-SID substitution is cheap and
        # keeps each replacement explicit. Underscore counts as a boundary, so the
        # standalone rule catches SEP, SEP_D00, /usr/sap/SEP and rsc_SAP_SEP_D00.
        for sid, fake in self.sid_dict.items():
            low, flow = sid.lower(), fake.lower()
            text = re.sub(r'SAP' + sid + r'(?![A-Za-z0-9])', 'SAP' + fake, text)
            text = re.sub(r'(?<![A-Za-z0-9])' + low + r'adm(?![A-Za-z0-9])',
                          flow + 'adm', text)
            text = re.sub(r'(?<![A-Za-z0-9])' + sid + r'(?![A-Za-z0-9])', fake, text)
        return text
