import pytest
from supportutils_scrub.domain_scrubber import DomainScrubber


class TestDomainScrub:
    def test_domain_replaced(self):
        s = DomainScrubber({"example.com": "domain_0.aaa"})
        result = s.scrub("host example.com ok")
        assert "example.com" not in result
        assert "domain_0.aaa" in result

    def test_case_insensitive(self):
        s = DomainScrubber({"example.com": "domain_0.aaa"})
        result = s.scrub("host Example.COM")
        assert "domain_0.aaa" in result

    def test_subdomain_inherits(self):
        mapping = {"example.com": "domain_0.aaa", "sub.example.com": "sub_0.domain_0.aaa"}
        s = DomainScrubber(mapping)
        result = s.scrub("host sub.example.com")
        assert "sub_0.domain_0.aaa" in result

    def test_no_partial_match(self):
        s = DomainScrubber({"test.com": "domain_0.aaa"})
        result = s.scrub("nottest.com")
        # should not match inside another domain
        assert "domain_0.aaa" not in result

    def test_empty_dict(self):
        s = DomainScrubber({})
        assert s.scrub("host example.com") == "host example.com"

    def test_mapping_property(self):
        s = DomainScrubber({"a.com": "fake.aaa"})
        assert "a.com" in s.mapping


class TestDomainExtraction:
    def test_extract_from_text(self):
        domains = DomainScrubber.extract_domains_from_text(
            "server ns1.example.com and mail.test.org")
        assert "example.com" in domains or "ns1.example.com" in domains
