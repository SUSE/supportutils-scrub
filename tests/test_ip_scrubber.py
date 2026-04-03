import pytest
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.scrub_config import ScrubConfig


def _make(private=True):
    cfg = ScrubConfig(obfuscate_private_ip=private, obfuscate_public_ip=True)
    return IPScrubber(cfg, mappings={})


class TestPublicIP:
    def test_public_ip_replaced(self):
        s = _make()
        result = s.scrub("server 8.8.8.8 ok")
        assert "8.8.8.8" not in result
        assert "8.8.8.8" in s.mapping

    def test_multiple_ips_get_different_fakes(self):
        s = _make()
        result = s.scrub("dns 8.8.8.8 and 1.1.1.1")
        assert s.mapping["8.8.8.8"] != s.mapping["1.1.1.1"]

    def test_same_ip_same_fake(self):
        s = _make()
        result = s.scrub("a 8.8.8.8 b 8.8.8.8")
        fake = s.mapping["8.8.8.8"]
        assert result.count(fake) == 2

    def test_cidr_preserved(self):
        s = _make()
        result = s.scrub("net 10.0.0.0/24 here")
        assert "/24" in result


class TestPrivateIP:
    def test_private_skipped_by_default(self):
        s = _make(private=False)
        result = s.scrub("host 192.168.1.1 ok")
        assert "192.168.1.1" in result

    def test_private_replaced_when_enabled(self):
        s = _make(private=True)
        result = s.scrub("host 192.168.1.1 ok")
        assert "192.168.1.1" not in result

    def test_10_range(self):
        s = _make(private=True)
        result = s.scrub("gw 10.0.0.1")
        assert "10.0.0.1" not in result

    def test_172_range(self):
        s = _make(private=True)
        result = s.scrub("gw 172.16.5.1")
        assert "172.16.5.1" not in result


class TestSpecialIPs:
    def test_loopback_preserved(self):
        s = _make()
        assert "127.0.0.1" in s.scrub("localhost 127.0.0.1")

    def test_broadcast_preserved(self):
        s = _make()
        assert "255.255.255.255" in s.scrub("bcast 255.255.255.255")

    def test_zeros_preserved(self):
        s = _make()
        assert "0.0.0.0" in s.scrub("bind 0.0.0.0")


class TestVersionStringFalsePositives:
    """Regression: version strings like 0.8.9.0 must not be scrubbed."""

    def test_leading_zero_octet(self):
        s = _make()
        text = "libmodplug1 SUSE Linux Enterprise 12 0.8.9.0+git20170610"
        assert "0.8.9.0" in s.scrub(text)
        assert "0.8.9.0" not in s.mapping

    def test_version_prefix(self):
        s = _make()
        text = "version 3.2.1.0 installed"
        assert "3.2.1.0" in s.scrub(text)

    def test_real_ip_after_version(self):
        s = _make()
        text = "version 3.2.1.0 server 8.8.8.8"
        result = s.scrub(text)
        assert "3.2.1.0" in result
        assert "8.8.8.8" not in result


class TestSubnetAwareness:
    def test_same_subnet_ips_stay_together(self):
        s = _make(private=True)
        text = "gw 10.0.0.1/24 host 10.0.0.50"
        s.scrub(text)
        fake_gw = s.mapping.get("10.0.0.1")
        fake_host = s.mapping.get("10.0.0.50")
        if fake_gw and fake_host:
            # same /24 prefix
            assert fake_gw.rsplit('.', 1)[0] == fake_host.rsplit('.', 1)[0]

    def test_mapping_property(self):
        s = _make()
        s.scrub("test 8.8.8.8")
        assert isinstance(s.mapping, dict)
        assert len(s.mapping) >= 1

    def test_state_property(self):
        s = _make()
        s.scrub("test 8.8.8.8")
        assert isinstance(s.state, dict)
