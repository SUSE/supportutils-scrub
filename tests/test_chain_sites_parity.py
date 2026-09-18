"""Every place that builds a scrubber chain must build the SAME chain.

There are five: modes/archive.py (twice), modes/folder.py, modes/file.py and
parallel._build_chain. When one drifts, a whole category silently stops
being scrubbed on that entry point and the run still reports success. The
lone-plain-file path had lost Serial and SID that way.
"""

import os
import re

_SRC = os.path.join(os.path.dirname(__file__), "..", "src", "supportutils_scrub")
_SITES = ["modes/archive.py", "modes/folder.py", "modes/file.py", "parallel.py"]
_CLS = re.compile(r"\b([A-Z][A-Za-z0-9]*Scrubber)\(")
# folder and file mode take these four ready-made from pipeline.py's shared
# builder (the `mappings, keyword_scrubber, ip_scrubber, ...` unpack)
_SHARED = {"IPScrubber", "IPv6Scrubber", "MACScrubber", "KeywordScrubber"}
_SHARED_UNPACK = "keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber"


def _classes(rel):
    with open(os.path.join(_SRC, rel)) as fh:
        src = fh.read()
    got = set(_CLS.findall(src))
    if _SHARED_UNPACK in src:
        got |= _SHARED
    return got


def test_every_chain_site_constructs_the_same_scrubber_classes():
    sets = {rel: _classes(rel) for rel in _SITES}
    union = set().union(*sets.values())
    drift = {rel: sorted(union - got) for rel, got in sets.items()
             if union - got}
    assert not drift, f"chain sites missing scrubbers: {drift}"


_HOSTNAME_SITES = _SITES + ["modes/stdin.py"]


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
