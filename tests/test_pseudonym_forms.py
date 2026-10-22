"""The pseudonyms a new mapping hands out: host-1, user1, dom1.<tld>.

host-N because the kernel names SCSI adapters host0, host1 ... (thousands of
lines in an Azure capture); dom from 1 because Xen calls its control domain
dom0. A mapping that holds the older forms keeps them. A pseudonym is never a
name the mapping knows, and a pseudonym read back from scrubbed text is never
learned as a new real name."""
from supportutils_scrub.pipeline import (build_hierarchical_domain_map,
                                         extract_hostnames, extract_usernames)


def test_a_new_mapping_uses_the_short_forms():
    m = {}
    hosts = extract_hostnames([], ["alpha", "beta"], m)
    assert sorted(hosts.values()) == ["host-1", "host-2"]
    users = extract_usernames([], ["jdoe", "asmith"], m)
    assert sorted(users.values()) == ["user1", "user2"]
    doms, tld = build_hierarchical_domain_map({"corp.example", "a.corp.example"}, {})
    assert doms["corp.example"] == "dom1." + tld["example"]
    assert doms["a.corp.example"].endswith("." + doms["corp.example"])


def test_a_mapping_with_the_older_forms_keeps_them():
    m = {"hostname": {"alpha": "hostname_0"}, "user": {"jdoe": "user_0"}}
    hosts = extract_hostnames([], ["alpha", "beta"], m)
    assert hosts == {"alpha": "hostname_0", "beta": "hostname_1"}
    users = extract_usernames([], ["jdoe", "asmith"], m)
    assert users == {"jdoe": "user_0", "asmith": "user_1"}
    doms, _ = build_hierarchical_domain_map({"corp.example"}, {"domain": {"x.test": "domain_0.aaa"},
                                                               "tld_map": {"test": "aaa"}})
    assert doms["corp.example"].startswith("domain_1.")


def test_a_real_name_shaped_like_a_pseudonym_is_never_handed_out():
    m = {}
    hosts = extract_hostnames([], ["host-1", "alpha"], m)
    assert hosts["host-1"] != "host-1"
    assert "host-1" not in hosts.values()
    assert len(set(hosts.values())) == 2
    users = extract_usernames([], ["user1", "jdoe"], {})
    assert "user1" not in users.values() and len(set(users.values())) == 2


def test_a_real_name_spelled_like_a_pseudonym_is_still_mapped():
    # mapping beats skipping: a real account user1 must never survive as
    # if it were the pseudonym of another account (prep drops chain pairs)
    m = {"user": {"jdoe": "user1"}, "sid": {"PRD": "HA1"}}
    users = extract_usernames([], ["user1", "asmith"], m)
    assert users["user1"] not in ("user1",) and len(set(users.values())) == 3
    hosts = extract_hostnames([], ["ha1", "alpha"], dict(m))
    assert set(hosts) == {"ha1", "alpha"}


def test_one_case_never_mixes_forms():
    m = {"hostname": {"alpha": "hostname_0"}}
    users = extract_usernames([], ["jdoe"], m)
    assert users["jdoe"] == "user_0"


def test_sub_domains_continue_past_the_mapping():
    m = {"domain": {"corp.example": "dom1.aaa", "a.corp.example": "sub_0.dom1.aaa"},
         "tld_map": {"example": "aaa"}}
    doms, _ = build_hierarchical_domain_map({"corp.example", "b.corp.example"}, m)
    assert doms["b.corp.example"] != "sub_0.dom1.aaa"


def test_numbers_continue_past_what_the_mapping_holds():
    m = {"hostname": {"alpha": "host-1", "beta": "host-2"}}
    hosts = extract_hostnames([], ["gamma"], m)
    assert hosts["gamma"] == "host-3"
