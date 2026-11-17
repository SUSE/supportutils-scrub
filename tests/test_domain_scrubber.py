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


class TestFilenamesAreNotDomains:
    """Filenames whose extension collides with a country-code TLD were learned
    as domains and rewritten, which corrupts the PAM stack and the library
    listings a capture is read for."""

    def test_pam_module_not_learned(self):
        assert DomainScrubber.extract_domains_from_text(
            "auth     required     pam_unix.so try_first_pass") == []

    def test_pam_module_path_not_learned(self):
        assert DomainScrubber.extract_domains_from_text(
            "/lib64/security/pam_unix.so") == []

    def test_pam_stack_block_not_learned(self):
        block = (
            "auth     required     pam_env.so\n"
            "auth     required     pam_unix.so try_first_pass\n"
            "password requisite    pam_cracklib.so\n"
        )
        assert DomainScrubber.extract_domains_from_text(block) == []

    def test_shared_object_not_learned(self):
        assert DomainScrubber.extract_domains_from_text("libc.so") == []

    def test_libtool_archive_not_learned(self):
        assert DomainScrubber.extract_domains_from_text("libfoo.la") == []

    def test_python_script_not_learned(self):
        assert DomainScrubber.extract_domains_from_text(
            "Traceback: /usr/bin/omsutil.py line 3") == []

    def test_real_domain_still_learned(self):
        domains = DomainScrubber.extract_domains_from_text("host.example.co")
        assert "host.example.co" in domains
        assert "example.co" in domains

    def test_suse_domain_still_learned(self):
        assert "susecloud.net" in DomainScrubber.extract_domains_from_text(
            "updates from smt.susecloud.net")

    def test_srv_record_parent_still_learned(self):
        assert "example.com" in DomainScrubber.extract_domains_from_text(
            "_ldap._tcp.example.com")

    def test_trusted_source_unaffected(self):
        from supportutils_scrub.domain_scrubber import _is_valid_domain
        assert _is_valid_domain("unix.so", trusted=True) is True

    def test_trusted_hosts_line_learns_the_domain_not_a_hostname_piece(self):
        # An underscored host in /etc/hosts used to teach "db.corp.internal",
        # a truncated piece of the hostname. The domain itself is what matters
        # and still replaces; the hostname half is the hostname scrubber's.
        domains = DomainScrubber.extract_domains_from_text(
            "10.0.0.5 sap_db.corp.internal sap_db", trusted=True)
        assert domains == ["corp.internal"]

    def test_trusted_plain_host_line_unaffected(self):
        domains = DomainScrubber.extract_domains_from_text(
            "10.0.0.6 node1.corp.internal node1", trusted=True)
        assert "node1.corp.internal" in domains
        assert "corp.internal" in domains


class TestVendorDomains:
    def test_vendor_domains_are_never_mapped(self):
        from supportutils_scrub.pipeline import build_hierarchical_domain_map
        dmap, _ = build_hierarchical_domain_map(
            {"suse.com", "registry.suse.com", "www.suse.com", "example.com"}, {})
        assert set(dmap) == {"example.com"}

    def test_old_mapping_cannot_rename_vendor_urls(self):
        legacy = {"suse.com": "dom7.aae", "registry.suse.com": "sub_0.dom7.aae",
                  "example.com": "dom1.aaa"}
        out = DomainScrubber(legacy).scrub(
            "SUSE LLC <https://www.suse.com/> registry.suse.com/suse/toolbox "
            "mirror.example.com")
        assert "https://www.suse.com/" in out
        assert "registry.suse.com/suse/toolbox" in out
        assert "mirror.dom1.aaa" in out

    def test_lookalike_customer_domain_still_scrubbed(self):
        out = DomainScrubber({"notsuse.com": "dom1.aaa"}).scrub("notsuse.com")
        assert out == "dom1.aaa"


class TestVendorDomainFollowUps:
    def test_old_vendor_entry_is_not_saved_again(self):
        from supportutils_scrub.pipeline import build_hierarchical_domain_map
        old = {"domain": {"suse.com": "dom7.aae", "example.com": "dom1.aaa"}}
        dmap, _ = build_hierarchical_domain_map({"other.example.org"}, old)
        assert "suse.com" not in dmap
        assert dmap["example.com"] == "dom1.aaa"
        assert "dom7.aae" not in {v.split(".", 1)[-1] for v in dmap.values()}

    def test_seeding_a_vendor_domain_warns(self, caplog):
        from supportutils_scrub.pipeline import extract_and_map_domains
        with caplog.at_level("WARNING"):
            dmap, _ = extract_and_map_domains([], ["tenant.susecloud.net"], {})
        assert "tenant.susecloud.net" not in dmap
        assert "--keywords" in caplog.text

    def test_hosts_line_of_a_vendor_server_teaches_no_hostname(self, tmp_path):
        from supportutils_scrub.hostname_scrubber import HostnameScrubber
        f = tmp_path / "network.txt"
        f.write_text("# /etc/hosts\n"
                     "192.0.2.10 smt-ec2.susecloud.net smt-ec2\n"
                     "192.0.2.11 registry.suse.com\n"
                     "192.0.2.12 dbnode.example.com dbnode\n")
        assert HostnameScrubber.extract_hostnames_from_hosts(str(f)) == \
            ["dbnode", "dbnode"]

    def test_verify_still_checks_a_keyword_under_a_vendor_suffix(self):
        from supportutils_scrub.verify import _build_terms
        maps = {"keyword": {"acme-prod.susecloud.net": "keyword_1"},
                "domain": {"registry.suse.com": "sub_0.dom7.aae"}}
        combined_re, labels, substr = _build_terms(maps)
        terms = set(labels) | {t for t, _ in substr}
        assert "acme-prod.susecloud.net" in terms
        assert "registry.suse.com" not in terms
