# verify.py
"""Post-scrub verification: scan scrubbed files for any remaining real values."""
import os

# Mapping categories and their display names
_CATEGORIES = [
    ('ip',       'IPv4 address'),
    ('ipv6',     'IPv6 address'),
    ('mac',      'MAC address'),
    ('domain',   'domain'),
    ('hostname', 'hostname'),
    ('user',     'username'),
    ('keyword',  'keyword'),
    ('serial',   'serial/UUID'),
]

# Skip real values shorter than this to avoid false positives
_MIN_VALUE_LEN = 6


def _build_terms(mappings: dict) -> list:
    """Return [(real_value, category_label), ...] for all mapping entries long enough to search."""
    terms = []
    for key, label in _CATEGORIES:
        for real_val in mappings.get(key, {}):
            if len(real_val) >= _MIN_VALUE_LEN:
                terms.append((real_val, label))
    return terms


def verify_scrubbed_folder(folder_path: str, mappings: dict) -> list:
    """
    Walk folder_path and check every text file for remaining real values from mappings.
    Returns list of findings: [{'file': str, 'line': int, 'category': str, 'value': str}]
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
                        for real_val, category in terms:
                            if real_val in line:
                                findings.append({
                                    'file':     rel,
                                    'line':     lineno,
                                    'category': category,
                                    'value':    real_val,
                                })
            except Exception:
                pass
    return findings
