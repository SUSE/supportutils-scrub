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


    def test_sssd_ldb_filename_replaced(self):
        s = DomainScrubber({"example-corp.com": "domain_1.com"})
        out = s.scrub("cache_example-corp.com.ldb")
        assert "example-corp.com" not in out
        assert "domain_1.com" in out

    def test_sssd_ccache_uppercase_replaced(self):
        s = DomainScrubber({"example-corp.com": "domain_1.com"})
        out = s.scrub("ccache_EXAMPLE-CORP.COM")
        assert "example-corp" not in out.lower()
        assert "domain_1.com" in out

    def test_timestamps_prefix_replaced(self):
        s = DomainScrubber({"example.com": "domain_0.aaa"})
        out = s.scrub("timestamps_example.com.ldb")
        assert "example.com" not in out
        assert "domain_0.aaa" in out

    def test_full_dc_form_replaced(self):
        s = DomainScrubber({"example-corp.com": "domain_1.com"})
        out = s.scrub("CN=Foo,DC=Example-corp,DC=com")
        assert "example-corp" not in out.lower()
        assert "DC=domain_1" in out

    def test_truncated_single_dc_replaced(self):
        s = DomainScrubber({"example-corp.com": "domain_1.com"})
        out = s.scrub("CN=Aggregate,CN=Schema,CN=Configuration,DC=Example-corp")
        assert "example-corp" not in out.lower()
        assert "DC=domain_1" in out

    def test_common_tld_dc_untouched(self):
        s = DomainScrubber({"example-corp.com": "domain_1.com"})
        assert s.scrub("DC=com") == "DC=com"
        assert s.scrub("DC=org") == "DC=org"

    def test_short_label_not_mapped_single_dc(self):
        s = DomainScrubber({"abc.com": "domain_2.com"})
        assert s.scrub("DC=abc") == "DC=abc"


class TestDomainExtraction:
    def test_extract_from_text(self):
        domains = DomainScrubber.extract_domains_from_text(
            "server ns1.example.com and mail.test.org")
        assert "example.com" in domains or "ns1.example.com" in domains
