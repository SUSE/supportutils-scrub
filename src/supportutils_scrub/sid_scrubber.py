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
from supportutils_scrub.fastsub import gsub, giter, hint_spans, iter_spans, literals
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

# The last pattern starts with the SID itself, three characters with no
# literal to search for; each of its matches holds this, which starts with one.
_INSTANCE_HINT = (re.compile(r'_(?:D|ASCS|ERS|SCS|HDB|J|W|G)\d\d'),)


def _discoveries(text):
    for rx in _DISCOVERY[:-1]:
        for m in giter(rx, text):
            yield m
    for m in iter_spans(_DISCOVERY[-1], text, hint_spans(text, _INSTANCE_HINT)):
        yield m


# The SAP Diagnostics Agent (DAA by default) runs as its own SID with an SMDA<nn>
# instance. It is monitoring infrastructure, not the customer's system, and the
# agent read as a workload once its SID was renamed, so its SID and its <sid>adm
# user are never scrubbed: never learned, dropped from an older mapping when the
# capture shows the agent, and left alone in a text that shows it.
_AGENT = [
    re.compile(r'/usr/sap/(' + _SID + r')/SMDA\d\d(?![A-Za-z0-9])'),
    re.compile(r'(?<![A-Za-z0-9])(' + _SID + r')_SMDA\d\d(?![A-Za-z0-9])'),
]


def _agents(text: str) -> set:
    return {m.group(1) for rx in _AGENT for m in giter(rx, text)}


def _valid(sid: str) -> bool:
    return sid.upper() not in _RESERVED


class SIDScrubber(Scrubber):
    name = 'sid'

    def __init__(self, mappings: dict = None):
        self.sid_dict: dict = {}
        if mappings:
            self.sid_dict = dict(mappings.get('sid', {}))
        self._counter = len(self.sid_dict)
        self.agent_sids: set = set()
        self._compiled = {}     # tuple of SIDs -> (pattern, start literals)

    @property
    def mapping(self):
        return self.sid_dict

    def _fake(self, idx: int) -> str:
        # Valid 3-char SIDs matching the project's placeholder style: HA1, HA2, ...
        return f'HA{idx + 1}' if idx < 9 else f'H{idx + 1:02d}'

    def pre_scan(self, text: str) -> None:
        for sid in _agents(text):
            self.agent_sids.add(sid)
            self.sid_dict.pop(sid, None)
        found = [m.group(1).upper() for m in _discoveries(text)]
        found = [s for s in dict.fromkeys(found)
                 if _valid(s) and s not in self.agent_sids]
        # a fake is never a real SID nor one already handed out, or two
        # systems would read as one
        taken = (set(self.sid_dict) | set(self.sid_dict.values())
                 | self.agent_sids | set(found))
        for sid in found:
            if sid in self.sid_dict:
                continue
            fake = self._fake(self._counter)
            while fake in taken:
                self._counter += 1
                fake = self._fake(self._counter)
            self._counter += 1
            self.sid_dict[sid] = fake
            taken.add(fake)

    def learn(self, text: str) -> None:   # parity with the parallel learn pre-pass
        self.pre_scan(text)

    def scrub(self, text: str) -> str:
        if not self.sid_dict:
            return text
        # One pass, so a fake that is also a real SID (PRD -> HA1 next to a
        # real HA1) is never rewritten a second time. Underscore counts as a
        # boundary, so the standalone branch catches SEP, SEP_D00,
        # /usr/sap/SEP and rsc_SAP_SEP_D00.
        agents = _agents(text)
        sids = [s for s in self.sid_dict if s not in agents]
        if not sids:
            return text
        key = tuple(sids)
        if key not in self._compiled:
            alt = '|'.join(re.escape(s) for s in sorted(sids, key=len, reverse=True))
            rx = re.compile(r'SAP(?P<sap>' + alt + r')(?![A-Za-z0-9])'
                            r'|(?<![A-Za-z0-9])(?:(?P<adm>' + alt.lower() + r')adm'
                            r'|(?P<sid>' + alt + r'))(?![A-Za-z0-9])')
            # a match starts with SAP<SID> or with the SID in either case
            self._compiled[key] = (rx, literals(
                [s for s in sids] + ['sap' + s for s in sids]))
        rx, first = self._compiled[key]

        def _sub(m):
            if m.group('sap'):
                return 'SAP' + self.sid_dict[m.group('sap')]
            if m.group('adm'):
                return self.sid_dict[m.group('adm').upper()].lower() + 'adm'
            return self.sid_dict[m.group('sid')]
        return gsub(rx, _sub, text, first=first)
