import pytest
from supportutils_scrub.keyword_scrubber import KeywordScrubber


class TestKeywordScrub:
    def test_keyword_replaced(self):
        s = KeywordScrubber(cmd_keywords=["secretword"])
        result = s.scrub("the secretword is here")
        assert "secretword" not in result

    def test_case_insensitive(self):
        s = KeywordScrubber(cmd_keywords=["mytoken"])
        result = s.scrub("found MYTOKEN in config")
        assert "MYTOKEN" not in result

    def test_multiple_keywords(self):
        s = KeywordScrubber(cmd_keywords=["alpha", "bravo"])
        result = s.scrub("alpha and bravo")
        assert "alpha" not in result
        assert "bravo" not in result

    def test_returns_str(self):
        s = KeywordScrubber(cmd_keywords=["x"])
        result = s.scrub("x marks the spot")
        assert isinstance(result, str)

    def test_mapping_has_all_keywords(self):
        s = KeywordScrubber(cmd_keywords=["foo", "bar"])
        assert "foo" in s.mapping
        assert "bar" in s.mapping

    def test_is_loaded(self):
        s = KeywordScrubber(cmd_keywords=["a"])
        assert s.is_loaded()

    def test_empty_not_loaded(self):
        s = KeywordScrubber()
        assert not s.is_loaded()
