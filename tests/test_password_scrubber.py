import pytest
from supportutils_scrub.password_scrubber import PasswordScrubber


def _make():
    return PasswordScrubber(mappings={})


class TestPasswordScrub:
    def test_password_equals(self):
        s = _make()
        result = s.scrub('password=MySecret123')
        assert "MySecret123" not in result
        assert "scrubbed_pass_" in result

    def test_passwd_equals(self):
        s = _make()
        result = s.scrub('passwd = "longpassword"')
        assert "longpassword" not in result

    def test_short_password_not_matched(self):
        s = _make()
        result = s.scrub("password=short")
        # "short" is < 8 chars, regex requires 8+
        assert "short" in result

    def test_already_scrubbed_skipped(self):
        s = _make()
        text = "password=scrubbed_pass_1"
        assert s.scrub(text) == text

    def test_removed_marker_skipped(self):
        s = _make()
        text = "password=*REMOVED*"
        assert "*REMOVED" in s.scrub(text)

    def test_mapping_populated(self):
        s = _make()
        s.scrub("password=SuperSecret1")
        assert "SuperSecret1" in s.mapping
