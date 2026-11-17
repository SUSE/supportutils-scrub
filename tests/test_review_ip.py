from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from supportutils_scrub.det import dhash
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
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

    # a kept host fake keeps its /24 even though its subnet entry went
    s = _ip(mappings={'subnet': {'10.0.0.0/8': '100.80.0.0/12'},
                      'ip': {'10.0.0.5': '100.80.0.5'},
                      'state': {'pool_cursor_priv10': 0}})
    assert s.scrub("10.3.7.5") != "100.80.0.5"


def test_failed_big_allocation_does_not_exhaust_small_ones():
    s = _ip(public_pool='198.18.0.0/22')       # four /24 slots
    s.scrub("192.0.2.0/24 198.51.100.0/24 203.0.113.0/24")
    s._learn_cidrs(["198.51.0.0/23"])          # no aligned /23 left
    s.scrub("192.0.3.7")
    assert s.subnet_dict['192.0.3.0/24'] == '198.18.3.0/24'
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


def _v6(deterministic=False):
    cfg = ScrubConfig(obfuscate_ipv6=True, obfuscate_private_ip=False)
    return IPv6Scrubber(cfg, mappings={}, deterministic=deterministic)


def test_ipv6_det_fake_does_not_depend_on_what_was_seen_first():
    host = "2001:db8:1:2::5"
    a = _v6(deterministic=True)
    a.scrub("route 2001:db8:1::/48 via fe80::1")
    b = _v6(deterministic=True)
    c = _v6(deterministic=True)
    c.scrub("prefix 2001:db8:1:2::/64")
    assert a.scrub(host) == b.scrub(host) == c.scrub(host)


def test_ipv6_fakes_never_come_from_ula():
    for det in (False, True):
        s = _v6(deterministic=det)
        out = s.scrub("route 2001:db8:1::/48 host 2001:db8:5:6::7 keep fd00::1")
        assert "fd00::1" in out
        for fake in s.mapping.values():
            addr = IPv6Address(fake)
            assert addr in IPv6Network("3fff::/20") or addr in IPv6Network("2001:db8::/32")
            assert addr not in IPv6Network("fc00::/7")


def _mac(deterministic=False, mappings=None):
    return MACScrubber(ScrubConfig(obfuscate_mac=True), mappings=mappings or {},
                       deterministic=deterministic)


def test_macs_inside_longer_colon_runs_are_scrubbed():
    s = _mac()
    out = s.scrub("IN=eth0 MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00 SRC=\n"
                  "client-id 01:52:54:00:12:34:57\n"
                  "duid 00:03:00:01:52:54:00:12:34:58\n"
                  "duid 00:01:00:01:2a:3b:4c:5d:52:54:00:12:34:59\n").lower()
    for real in ("52:54:00:12:34:56", "52:54:00:ab:cd:ef", "52:54:00:12:34:57",
                 "52:54:00:12:34:58", "52:54:00:12:34:59"):
        assert real not in out
        assert s.mapping[real].lower() in out
    assert ":08:00 src=" in out
    assert "client-id 01:00:1a:2b:" in out
    assert "duid 00:03:00:01:00:1a:2b:" in out


def test_other_hex_runs_are_left_alone():
    text = ("fe80::5054:ff:fe12:3456 2001:db8:0:0:0:0:0:1 12:34:56 "
            "MD5:de:ad:be:ef:00:11:22:33:44:55:66:77:88:99:aa:bb "
            "01:02:03:04:05:06:07:08 02:52:54:00:12:34:56 "
            "MAC=52:54:00:12:34:56:08:00")
    s = _mac()
    assert s.scrub(text) == text
    assert s.mapping == {}


def test_mac_fake_collision_is_resolved():
    real = "52:54:00:12:34:56"
    h = dhash(real, 3).upper()
    taken = f"00:1A:2B:{h[0:2]}:{h[2:4]}:{h[4:6]}"
    s = _mac(deterministic=True, mappings={'mac': {'52:54:00:00:00:01': taken}})
    s.scrub(real)
    assert s.mapping[real] not in (taken, real)

    s = _mac(mappings={'mac': {'52:54:00:00:00:01': '00:1A:2B:00:00:01'}})
    s.scrub(real)
    assert s.mapping[real] != '00:1A:2B:00:00:01'
