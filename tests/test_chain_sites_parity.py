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
