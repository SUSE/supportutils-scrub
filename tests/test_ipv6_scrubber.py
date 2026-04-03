import pytest
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.scrub_config import ScrubConfig


def _make(enabled=True):
    cfg = ScrubConfig(obfuscate_ipv6=enabled)
    return IPv6Scrubber(cfg, mappings={})


class TestIPv6Scrub:
    def test_global_unicast_replaced(self):
        s = _make()
        result = s.scrub("addr 2001:0db8:85a3::8a2e:0370:7334 ok")
        assert "2001:0db8:85a3" not in result.lower()

    def test_disabled_passthrough(self):
        s = _make(enabled=False)
        addr = "2001:db8::1"
        assert addr in s.scrub(f"host {addr}")

    def test_loopback_preserved(self):
        s = _make()
        assert "::1" in s.scrub("localhost ::1")

    def test_same_addr_consistent(self):
        s = _make()
        text = "a 2001:db8::1 b 2001:db8::1"
        result = s.scrub(text)
        parts = result.split()
        assert parts[1] == parts[3]

    def test_mapping_populated(self):
        s = _make()
        s.scrub("host 2001:db8::1")
        assert len(s.mapping) >= 1

    def test_subnet_map_property(self):
        s = _make()
        s.scrub("net 2001:db8::/32")
        assert isinstance(s.subnet_map, dict)

    def test_state_property(self):
        s = _make()
        s.scrub("host 2001:db8::1")
        assert 'ipv6_pool_cursor' in s.state
