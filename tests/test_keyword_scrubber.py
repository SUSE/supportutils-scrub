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

    def test_deterministic_across_runs(self):
        a = KeywordScrubber(cmd_keywords=["alpha", "bravo"])
        b = KeywordScrubber(cmd_keywords=["alpha", "bravo"])
        assert a.mapping == b.mapping

    def test_distinct_keywords_distinct_fakes(self):
        s = KeywordScrubber(cmd_keywords=["alpha", "bravo", "charlie"])
        fakes = set(s.mapping.values())
        assert len(fakes) == 3

    def test_fake_uses_keyword_prefix(self):
        s = KeywordScrubber(cmd_keywords=["foo"])
        assert s.mapping["foo"].startswith("keyword_")

    def test_reload_from_mapping(self):
        mappings = {'keyword': {'alpha': 'keyword_1'}}
        s = KeywordScrubber(cmd_keywords=["bravo"], mappings=mappings)
        assert s.mapping["alpha"] == "keyword_1"
        assert s.mapping["bravo"] == "keyword_2"
