"""walk_supportconfig returns files in a deterministic order.

os.walk yields directory entries in filesystem order, which differs between
two copies of the same tree. Fake values are allocated in the order they
are first seen, so the same capture scrubbed twice produced different
mappings depending on inode order. Sorted walks make the mapping a pure
function of the content."""

import os

from supportutils_scrub.extractor import walk_supportconfig


def test_walk_is_sorted_regardless_of_creation_order(tmp_path):
    for name in ("zeta.txt", "alpha.txt", "mid/b.txt", "mid/a.txt", "beta.txt"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    got = [os.path.relpath(f, tmp_path) for f in walk_supportconfig(str(tmp_path))]
    assert got == ["alpha.txt", "beta.txt", "zeta.txt", "mid/a.txt", "mid/b.txt"]
