"""The hierarchical domain map is a pure function of the set of domains.

Ties in the sort (same label count) used to fall back to set iteration
order, which depends on the per-process hash seed: the same capture got
'com' -> aaa in one run and 'lan' -> aaa in the next."""

import random

from supportutils_scrub.pipeline import build_hierarchical_domain_map

DOMAINS = ["internal.lan", "example.com", "corp.example.com", "gateway.internal.lan",
           "dbserver.corp.example.com", "appnode1.corp.example.com", "zeta.org", "alpha.net"]


def test_same_domains_any_order_same_map():
    maps = set()
    for seed in range(12):
        order = list(DOMAINS)
        random.Random(seed).shuffle(order)
        d, t = build_hierarchical_domain_map(order, {})
        maps.add((tuple(sorted(d.items())), tuple(sorted(t.items()))))
    assert len(maps) == 1
