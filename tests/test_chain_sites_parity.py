"""Every mode must scrub with the SAME chain.

There were five hand-built chains: modes/archive.py (twice), modes/folder.py,
modes/file.py and parallel._build_chain. When one drifted, a whole category
silently stopped being scrubbed on that entry point and the run still
reported success (the lone-plain-file path lost Serial and SID that way, a
loose file in a multi-input run lost the name pre-scan). Now they all call
pipeline.build_chain; this keeps them from growing a chain of their own.
"""

import os
import re

_SRC = os.path.join(os.path.dirname(__file__), "..", "src", "supportutils_scrub")
_SITES = ["modes/archive.py", "modes/folder.py", "modes/file.py", "parallel.py"]
_CLS = re.compile(r"\b([A-Z][A-Za-z0-9]*Scrubber)\(")


def test_every_chain_site_uses_the_shared_builder():
    own = {}
    for rel in _SITES:
        with open(os.path.join(_SRC, rel)) as fh:
            src = fh.read()
        assert "build_chain(" in src, f"{rel} does not use build_chain"
        found = set(_CLS.findall(src)) - {"IPScrubber"}   # the IPv4 pre-pass
        if found:
            own[rel] = sorted(found)
    assert not own, f"chain sites building scrubbers themselves: {own}"


_HOSTNAME_SITES = _SITES + ["pipeline.py", "modes/stdin.py"]


def _calls(src, name):
    """Every argument list of `name(...)`, nested parentheses included."""
    out = []
    marker = name + "("
    i = src.find(marker)
    while i >= 0:
        j = i + len(marker)
        depth = 1
        while j < len(src) and depth:
            depth += {"(": 1, ")": -1}.get(src[j], 0)
            j += 1
        out.append(src[i + len(marker):j - 1])
        i = src.find(marker, j)
    return out


def test_every_hostname_scrubber_is_given_the_config():
    """The same drift, one level down: the class was built everywhere, but
    only parallel.py handed it the config. Without it the preserve set is the
    built-ins alone, so the operator's hostname_preserve silently did nothing
    outside the parallel path, and the man page promised otherwise."""
    missing = {}
    for rel in _HOSTNAME_SITES:
        with open(os.path.join(_SRC, rel)) as fh:
            for call in _calls(fh.read(), "HostnameScrubber"):
                if "config" not in call:
                    missing.setdefault(rel, []).append(" ".join(call.split()))
    assert not missing, f"HostnameScrubber built without config: {missing}"
