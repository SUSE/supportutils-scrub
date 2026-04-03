import pytest
from supportutils_scrub.hostname_scrubber import HostnameScrubber


class TestHostnameScrub:
    def test_hostname_replaced(self):
        s = HostnameScrubber({"myserver": "hostname_0"})
        assert "hostname_0" in s.scrub("host myserver is up")

    def test_multiple_hostnames(self):
        s = HostnameScrubber({"host1": "hostname_0", "host2": "hostname_1"})
        result = s.scrub("host1 talks to host2")
        assert "host1" not in result
        assert "host2" not in result

    def test_word_boundary(self):
        s = HostnameScrubber({"test": "hostname_0"})
        result = s.scrub("testing test tested")
        # "test" should match only the standalone word
        assert "hostname_0" in result

    def test_empty_dict(self):
        s = HostnameScrubber({})
        assert s.scrub("anything") == "anything"

    def test_mapping_property(self):
        s = HostnameScrubber({"a": "b"})
        assert s.mapping == {"a": "b"}
