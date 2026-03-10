# verify.py
"""Post-scrub verification: scan scrubbed files for any remaining real values."""
import os
import re

# (category_key, display_label, match_mode)
# match_mode:
#   'boundary'  – \bVALUE\b  (username, hostname: same logic as their scrubbers)
#   'ip'        – lookbehind/lookahead mirroring CIDR_RE  (avoids version-string false positives)
#   'substring' – plain 'value in line'  (domain, mac, ipv6, serial, keyword)
_CATEGORIES = [
    ('ip',       'IPv4 address',  'ip'),
    ('ipv6',     'IPv6 address',  'substring'),
    ('mac',      'MAC address',   'substring'),
    ('domain',   'domain',        'substring'),
    ('hostname', 'hostname',      'boundary'),
    ('user',     'username',      'boundary'),
    ('keyword',  'keyword',       'substring'),
    ('serial',   'serial/UUID',   'substring'),
]

# Real values shorter than this are skipped to reduce noise
_MIN_VALUE_LEN = 6

# Mirrors the lookbehind/lookahead in ip_scrubber.CIDR_RE so that IPs embedded
# in version strings (e.g. "nftables-1.4.4.2") are not flagged as leaks.
_IP_BOUNDARY = r'(?<![A-Za-z0-9.\-]){}(?![A-Za-z0-9.\-])'


def _build_terms(mappings: dict) -> list:
    """Return [(real_value, category_label, compiled_pattern | None), ...]."""
    terms = []
    for key, label, mode in _CATEGORIES:
        for real_val in mappings.get(key, {}):
            if len(real_val) < _MIN_VALUE_LEN:
                continue
            if mode == 'boundary':
                pat = re.compile(r'\b' + re.escape(real_val) + r'\b')
            elif mode == 'ip':
                pat = re.compile(_IP_BOUNDARY.format(re.escape(real_val)))
            else:
                pat = None   # substring – checked with 'in'
            terms.append((real_val, label, pat))
    return terms


def verify_scrubbed_folder(folder_path: str, mappings: dict) -> list:
    """
    Walk folder_path and check every text file for remaining real values from mappings.
    Returns list of findings: [{'file': str, 'line': int, 'category': str, 'value': str}]

    Match strategy per category:
      - hostname / username : word-boundary regex  (mirrors their scrubbers; avoids
                              flagging 'docker' inside 'dockerd')
      - IPv4 address        : CIDR-style boundary  (avoids flagging version strings
                              such as 'nftables-1.4.4.2')
      - everything else     : substring
    """
    terms = _build_terms(mappings)
    if not terms:
        return []

    findings = []
    for root, _, files in os.walk(folder_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, folder_path)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    for lineno, line in enumerate(f, 1):
                        for real_val, category, pat in terms:
                            if pat is not None:
                                found = bool(pat.search(line))
                            else:
                                found = real_val in line
                            if found:
                                findings.append({
                                    'file':     rel,
                                    'line':     lineno,
                                    'category': category,
                                    'value':    real_val,
                                })
            except Exception:
                pass
    return findings
