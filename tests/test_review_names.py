"""Name learners and scrubbers: hostnames, usernames, serials, SIDs, domains,
keywords."""

import os

from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.pipeline import (build_hierarchical_domain_map,
                                         extract_hostnames,
                                         extract_hostnames_from_adopted_paths,
                                         extract_usernames)
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.sid_scrubber import SIDScrubber
from supportutils_scrub.trie_re import build_trie_pattern
from supportutils_scrub.username_scrubber import UsernameScrubber


def test_trailing_comma_does_not_learn_an_empty_name():
    hosts = extract_hostnames([], ["web01", ""], {})
    users = extract_usernames([], ["", "jdoe"], {})
    assert "" not in hosts and "" not in users
    assert build_trie_pattern(["", "web01"]) == build_trie_pattern(["web01"])
    out = HostnameScrubber(hosts).scrub("disk sda1 ok on web01")
    assert out == "disk sda1 ok on " + hosts["web01"]


def test_username_matches_case_and_underscore_forms():
    s = UsernameScrubber({"jdoe": "user1"})
    assert s.scrub("backup_jdoe.tar /home/jdoe_old EXAMPLE\\JDOE Jdoe jdoe2") == \
        "backup_user1.tar /home/user1_old EXAMPLE\\user1 user1 jdoe2"


def test_log_learner_takes_the_person_not_the_target():
    text = ("sshd[1]: pam_unix(sshd:session): session opened for user mary.major(uid=1001) by (uid=0)\n"
            "sudo:     jdoe : TTY=pts/0 ; PWD=/home ; USER=postgres ; COMMAND=/bin/ls\n"
            "sshd[2]: Accepted publickey for asmith from 192.0.2.7 port 22 ssh2\n"
            "audit: user=1000 logname=bwayne.\n")
    users = set(UsernameScrubber.extract_usernames_from_text(text))
    assert {"mary.major", "jdoe", "asmith", "bwayne"} <= users
    assert not users & {"mary", "postgres", "1000", "bwayne."}


def _network(tmp_path, body):
    p = tmp_path / "network.txt"
    p.write_text(body)
    return str(p)


def test_hosts_service_aliases_not_learned(tmp_path):
    f = _network(tmp_path, "#==[ Configuration File ]===#\n# /etc/hosts\n"
                 "192.0.2.10 ldap.example.com ldap\n192.0.2.11 mail proxy dbnode01\n"
                 "#==[ Command ]===#\n# /usr/bin/something\n192.0.2.12 notahost\n")
    assert HostnameScrubber.extract_hostnames_from_hosts(f) == ["dbnode01"]


def test_placeholder_serials_skipped_and_bounded():
    s = SerialScrubber()
    s.pre_scan("Serial Number: 00000000\nPart Number: NO DIMM\nSerial Number: ABC123XY\n")
    assert list(s.serial_dict) == ["ABC123XY"]
    s.serial_dict["00000000"] = "SERIAL_9"     # as an older mapping might hold
    out = s.scrub("4c4c4544-0000-0000-0000-00000000abcd 0x0000000000000000 ABC123XY")
    assert out == "4c4c4544-0000-0000-0000-00000000abcd 0x0000000000000000 SERIAL_0"


def test_host_named_after_product_is_scrubbed():
    s = HostnameScrubber({"uyuni-site7": "host-1", "uyuni-server-01": "host-2",
                          "server": "host-3"})
    assert s.scrub("ping uyuni-site7; uyuni-server-01 up; uyuni-server ok; server") == \
        "ping host-1; host-2 up; uyuni-server ok; host-3"


def test_sid_fakes_never_collide_with_real_sids():
    s = SIDScrubber()
    s.pre_scan("/usr/sap/PRD/D00\n/usr/sap/HA1/ASCS01\n")
    assert s.sid_dict["PRD"] != s.sid_dict["HA1"]
    assert not set(s.sid_dict.values()) & {"PRD", "HA1"}
    out = s.scrub("PRD and HA1 prdadm ha1adm SAPPRD")
    a, b = s.sid_dict["PRD"], s.sid_dict["HA1"]
    assert out == f"{a} and {b} {a.lower()}adm {b.lower()}adm SAP{a}"


def test_case_variant_reuses_the_pseudonym():
    hosts = extract_hostnames([], ["WEB01"], {"hostname": {"web01": "host-1"}})
    assert hosts == {"web01": "host-1"}
    users = extract_usernames([], ["JDoe"], {"user": {"jdoe": "user1"}})
    assert users == {"jdoe": "user1"}


def test_adopted_fqdn_shares_the_short_pseudonym(tmp_path):
    node = tmp_path / "crm_report" / "web01.example.com"
    os.makedirs(node)
    (node / "cib.xml").write_text("")
    hosts = extract_hostnames([], extract_hostnames_from_adopted_paths(str(tmp_path)), {})
    assert hosts["web01.example.com"] == hosts["web01"]


def test_dn_needs_a_trailing_boundary_and_takes_spaces():
    s = DomainScrubber({"example.com": "dom1.aaa", "abc.org": "dom2.aab"})
    # the label pass still renames a known first label; the suffix is intact
    assert s.scrub("DC=example,DC=community") == "DC=dom1,DC=community"
    assert s.scrub("dc=abc, dc=org") == "DC=dom2,DC=aab"


def test_new_domain_never_reuses_a_stored_first_label():
    m = {"domain": {"alpha.com": "dom1.aaa"}, "tld_map": {"com": "aaa"}}
    doms, _ = build_hierarchical_domain_map({"bravo.org"}, m)
    assert doms["bravo.org"].split(".")[0] != "dom1"


def test_public_suffix_is_not_learned():
    found = DomainScrubber.extract_domains_from_text("www.example.co.uk", trusted=True)
    assert "example.co.uk" in found and "co.uk" not in found
    parents = set()
    DomainScrubber._add_domain_and_parents("example.co.uk", parents)
    assert parents == {"example.co.uk"}


def test_keyword_pseudonyms_stable_across_runs():
    s = KeywordScrubber(cmd_keywords=["acme", "newword"],
                        mappings={"keyword": {"Acme": "keyword_1"}})
    assert s.keyword_dict == {"acme": "keyword_1", "newword": "keyword_2"}
    assert s.scrub("ACME newword") == "keyword_1 keyword_2"


def test_keyword_fake_skips_numbers_a_mapping_already_uses():
    from supportutils_scrub.keyword_scrubber import KeywordScrubber
    k = KeywordScrubber(cmd_keywords=['newcorp'],
                        mappings={'keyword': {'acme': 'keyword_2', 'globex': 'keyword_1'}})
    k2 = KeywordScrubber(cmd_keywords=['newcorp'],
                         mappings={'keyword': {'acme': 'keyword_3'}})
    assert k2.mapping['newcorp'] != 'keyword_3'
    assert len(set(k.mapping.values())) == 3
