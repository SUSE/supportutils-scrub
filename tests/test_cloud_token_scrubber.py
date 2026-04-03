import pytest
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber


def _make():
    return CloudTokenScrubber(mappings={})


class TestCloudTokenScrub:
    def test_aws_access_key(self):
        s = _make()
        result = s.scrub("key AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "SCRUBBED_" in result

    def test_aws_temp_key(self):
        s = _make()
        result = s.scrub("temp ASIAIOSFODNN7EXAMPLE")
        assert "ASIAIOSFODNN7EXAMPLE" not in result

    def test_bearer_token(self):
        s = _make()
        long_token = "A" * 50
        result = s.scrub(f"Authorization: Bearer {long_token}")
        assert long_token not in result

    def test_normal_text_untouched(self):
        s = _make()
        text = "no tokens here, just words"
        assert s.scrub(text) == text

    def test_mapping_populated(self):
        s = _make()
        s.scrub("key AKIAIOSFODNN7EXAMPLE")
        assert len(s.mapping) >= 1
