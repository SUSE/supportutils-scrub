from ipaddress import IPv4Address, IPv4Network

from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.scrub_config import ScrubConfig


def _ip(private=True, public=True, mappings=None, **kw):
    cfg = ScrubConfig(obfuscate_private_ip=private, obfuscate_public_ip=public, **kw)
    return IPScrubber(cfg, mappings=mappings or {})


def test_sentence_dot_and_dash_ranges_are_scrubbed():
    s = _ip()
    out = s.scrub("Connected to 203.0.113.5.\n"
                  "range 203.0.113.10-203.0.113.20\n"
                  "--src-range 198.51.100.1-198.51.100.9\n")
    for real in ("203.0.113.5", "203.0.113.10", "203.0.113.20",
                 "198.51.100.1", "198.51.100.9"):
        assert real not in out
    assert f"{s.mapping['203.0.113.5']}.\n" in out
    assert f"{s.mapping['203.0.113.10']}-{s.mapping['203.0.113.20']}" in out


def test_reverse_dns_name_follows_forward_fake():
    s = _ip()
    out = s.scrub("198.51.100.22 is 22.100.51.198.in-addr.arpa.")
    fake = s.mapping['198.51.100.22']
    assert '.'.join(reversed(fake.split('.'))) + '.in-addr.arpa.' in out
    assert '22.100.51.198' not in out


def test_versions_and_continuations_are_left_alone():
    s = _ip()
    text = ("nftables-1.4.4.2 upower-1.90.7.13+git 1.2.3.4.5 1.2.3.4.el7 "
            "release 4.2.1.12 build 4.2.1.13")
    assert s.scrub(text) == text
    assert s.mapping == {}


def test_ips_in_paths_are_scrubbed():
    s = _ip()
    out = s.scrub("/var/lib/nfs/sm/198.51.100.21 "
                  "http://repo.example.com/mirror/198.51.100.22/x")
    assert "198.51.100.21" not in out and "198.51.100.22" not in out


def test_learn_then_scrub_allocates_nothing_new():
    text = ("203.0.113.5. 203.0.113.10-203.0.113.20 22.100.51.198.in-addr.arpa "
            "/srv/198.51.100.7 192.0.2.0/24")
    s = _ip()
    s.learn(text)
    learned = dict(s.mapping)
    s.scrub(text)
    assert s.mapping == learned


def test_net_larger_than_pool_never_leaves_the_pool():
    s = _ip()
    out = s.scrub("128.0.0.0/1 via 192.0.2.1\n"
                  "10.0.0.0/8 10.200.1.1 10.16.0.5 172.20.131.5\n"
                  "100.64.0.0/10 100.64.3.4")
    assert "192.0.2.1" not in out
    for real, fake in s.mapping.items():
        assert IPv4Address(fake) in s.category_pools[s._classify_ip(real)], (real, fake)
    assert len(set(s.mapping.values())) == len(s.mapping)


def test_bad_entries_from_an_old_mapping_are_dropped():
    s = _ip(mappings={'subnet': {'10.0.0.0/8': '100.80.0.0/12'},
                      'ip': {'10.200.1.1': '101.24.1.1'}})
    assert s.subnet_dict == {}
    assert IPv4Address(s._scrub_token('10.200.1.1', None)) in IPv4Network('100.80.0.0/12')


def test_failed_big_allocation_does_not_exhaust_small_ones():
    s = _ip(public_pool='198.18.0.0/22')       # four /24 slots
    s.scrub("192.0.2.0/24 198.51.100.0/24 203.0.113.0/24")
    s.scrub("198.51.0.0/23")                   # no aligned /23 left
    s.scrub("192.0.3.7")
    assert s.mapping['192.0.3.7'] == '198.18.3.7'


def test_exhausted_pool_fallback_never_shares_a_fake():
    s = _ip(public_pool='198.18.0.0/24')       # a single /24 slot
    s.scrub("198.51.15.7 198.51.30.7 198.51.45.7 198.51.60.7")
    fakes = list(s.mapping.values())
    assert len(set(fakes)) == 4
    assert all(IPv4Address(f) in IPv4Network('198.18.0.0/24') for f in fakes)


def test_slots_are_per_pool():
    s = _ip(mappings={'subnet': {'203.0.113.0/24': '198.16.0.0/24'}})
    assert s.scrub("10.1.1.1") == "100.80.0.1"


def test_public_ip_gate():
    s = _ip(private=True, public=False)
    out = s.scrub("8.8.8.8 10.1.1.1 192.0.2.0/24")
    assert "8.8.8.8" in out and "192.0.2.0/24" in out
    assert "10.1.1.1" not in out
    assert not any(k.startswith('192.0.2.') for k in s.subnet_dict)


def test_state_reflects_loaded_cursor_without_scrubbing():
    s = _ip(mappings={'state': {'pool_cursor_public': 4096}})
    assert s.state['pool_cursor_public'] == 4096
