import pytest
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber

# Build test keys at runtime to avoid triggering GitHub secret scanning
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_TEMP_KEY = "ASIA" + "IOSFODNN7EXAMPLE"


def _make():
    return CloudTokenScrubber(mappings={})


class TestCloudTokenScrub:
    def test_aws_access_key(self):
        s = _make()
        result = s.scrub(f"key {_AWS_KEY}")
        assert _AWS_KEY not in result
        assert "SCRUBBED_" in result

    def test_aws_temp_key(self):
        s = _make()
        result = s.scrub(f"temp {_AWS_TEMP_KEY}")
        assert _AWS_TEMP_KEY not in result

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
        s.scrub(f"key {_AWS_KEY}")
        assert len(s.mapping) >= 1
