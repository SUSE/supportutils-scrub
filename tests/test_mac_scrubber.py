import pytest
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.scrub_config import ScrubConfig


def _make(enabled=True):
    cfg = ScrubConfig(obfuscate_mac=enabled)
    return MACScrubber(cfg, mappings={})


class TestMACScrub:
    def test_mac_replaced(self):
        s = _make()
        result = s.scrub("eth0 AA:BB:CC:DD:EE:FF up")
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "aa:bb:cc:dd:ee:ff" in s.mapping

    def test_disabled_passthrough(self):
        s = _make(enabled=False)
        text = "eth0 AA:BB:CC:DD:EE:FF"
        assert "AA:BB:CC:DD:EE:FF" in s.scrub(text)

    def test_broadcast_preserved(self):
        s = _make()
        assert "ff:ff:ff:ff:ff:ff" in s.scrub("bcast ff:ff:ff:ff:ff:ff").lower()

    def test_zero_mac_preserved(self):
        s = _make()
        assert "00:00:00:00:00:00" in s.scrub("none 00:00:00:00:00:00")

    def test_consistent_replacement(self):
        s = _make()
        result = s.scrub("a AA:BB:CC:DD:EE:FF b AA:BB:CC:DD:EE:FF")
        fake = s.mapping["aa:bb:cc:dd:ee:ff"]
        assert result.count(fake) == 2

    def test_hyphen_separator(self):
        s = _make()
        result = s.scrub("id AA-BB-CC-DD-EE-FF")
        assert "AA-BB-CC-DD-EE-FF" not in result

    def test_skip_files(self):
        assert 'modules.txt' in MACScrubber.skip_files
        assert 'security-apparmor.txt' in MACScrubber.skip_files
