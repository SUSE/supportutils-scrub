import base64
import gzip
from types import SimpleNamespace

from supportutils_scrub.verify import verify_scrubbed_folder, _build_terms, _mapping_hits

PRIVATE_ON = SimpleNamespace(obfuscate_private_ip=True, obfuscate_mac=True)


def _verify(tmp_path, files, maps=None, config=None, **kw):
    d = tmp_path / "scrubbed"
    for name, text in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text)
    kw.setdefault("check_identity", False)
    return verify_scrubbed_folder(str(d), maps or {}, config=config, jobs=1, **kw)


def _values(findings, category=None):
    return {f["value"] for f in findings if category is None or f["category"] == category}


def test_ip_at_sentence_end_and_in_a_range_is_found(tmp_path):
    f = _verify(tmp_path, {"a.txt": "Connection from 10.20.30.40.\n"
                                     "range 10.20.30.50-10.20.30.60\n"},
                {"ip": {"10.20.30.40": "100.80.0.40"}}, config=PRIVATE_ON)
    assert "10.20.30.40" in _values(f, "IPv4 address")
    assert {"10.20.30.50", "10.20.30.60"} <= _values(f, "unlisted IPv4")


def test_versions_and_oids_are_not_ips(tmp_path):
    f = _verify(tmp_path, {"a.txt": "nftables-1.4.4.2\nupower 1.90.7.13+git\n"
                                     "oid 1.3.6.1.4.1.311\nrelease 4.2.1.12\n"
                                     "rev 1.2.3.4\nkernel 4.12.14.122-37\n"},
                config=PRIVATE_ON)
    assert not _values(f, "unlisted IPv4"), f


def test_mac_inside_a_longer_run_is_found(tmp_path):
    f = _verify(tmp_path, {"fw.txt": (
        "IN=eth0 MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00 SRC=x\n"
        "client-id 01:52:54:00:aa:bb:cc\n"
        "duid 00:03:00:01:52:54:00:dd:ee:ff\n"
        "Modulus:\n    00:c3:a4:5b:11:22:33:44:55:66:77:88:99:aa:bb:\n")},
        config=PRIVATE_ON)
    assert _values(f, "unlisted MAC") == {
        "52:54:00:12:34:56", "52:54:00:ab:cd:ef",
        "52:54:00:aa:bb:cc", "52:54:00:dd:ee:ff"}


def test_mac_not_reported_where_the_scrubber_leaves_macs_on_purpose(tmp_path):
    files = {"modules.txt": "sig:\t\t3B:2A:01:00:FF:7C\n"}
    assert not _verify(tmp_path, files, config=PRIVATE_ON)
    off = SimpleNamespace(obfuscate_private_ip=False, obfuscate_mac=False)
    assert not _verify(tmp_path, {"net.txt": "link/ether 52:54:00:12:34:56\n"}, config=off)


def test_secret_forms_the_password_scrubber_does_not_know(tmp_path):
    lines = [
        '{"password": "Sup3rS3cretValue"}',
        '<password>Sup3rS3cretValue</password>',
        'db_password=Sup3rS3cretValue',
        'MYSQL_ROOT_PASSWORD=Sup3rS3cretValue',
        'SECRET_KEY=Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh',
        'bindpw Sup3rS3cretValue',
        'ldapsearch -x -D cn=admin -w Sup3rS3cretValue',
        '{"SecretAccessKey": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}',
        '{"Token": "IQoJb3JpZ2luX2VjEXAMPLE"}',
        'password=hunter2',
        'password="two words"',
        'system_token=0123456789abcdef',
        'username=SCC_0123456789abcdef',
        '-----BEGIN RSA PRIVATE KEY-----',
    ]
    f = _verify(tmp_path, {"conf.txt": "\n".join(lines) + "\n"})
    assert {x["line"] for x in f} == set(range(1, len(lines) + 1)), f


def test_clean_output_is_quiet(tmp_path):
    blob = base64.b64encode(b"user1:SCRUBBED_SECRET_3").decode()
    lines = [
        'pam_unix(passwd:chauthtok): password changed for user1',
        'passwd: password changed.',
        'PasswordAuthentication no',
        'PWD=/root',
        'password=$DB_PASS',
        'password=********',
        'password = *REMOVED BY SUPPORTCONFIG*',
        'password=scrubbed_pass_1 auth_token=SCRUBBED_TOKEN_2',
        'SECRET_KEY=SCRUBBED_SECRET_4',
        '-----BEGIN CERTIFICATE-----',
        f'Authorization: Basic {blob}',
        'repo https://user1:SCRUBBED_SECRET_3@git.dom1.example/r.git',
        'member: CN=Users,DC=dom1,DC=example',
        'server: CN=cn_3,OU=Servers,DC=dom1,DC=test',
        'Subject: C=DE, ST=Bavaria, L=Nuernberg, O=Example, CN=www.example.com',
        'principal host-1@DOM1.EXAMPLE',
    ]
    f = _verify(tmp_path, {"messages.txt": "\n".join(lines) + "\n"})
    assert not f, f


def test_dn_with_a_name_left_in_it_is_found(tmp_path):
    f = _verify(tmp_path, {"a.txt": "dn: CN=cn_1 Smith,OU=ou_2,DC=dom1,DC=example\n"})
    assert _values(f, "LDAP DN")


def test_kerberos_realm_with_a_dash(tmp_path):
    f = _verify(tmp_path, {"krb5.txt": "default_principal admin@AD-CORP.EXAMPLE.COM\n"})
    assert "admin@AD-CORP.EXAMPLE.COM" in _values(f, "Kerberos principal")


def test_every_mapping_section_and_short_values_are_checked(tmp_path):
    maps = {"password": {"Sup3rS3cretValue": "scrubbed_pass_1", "changed": "scrubbed_pass_2"},
            "email": {"jdoe@corp.example": "email_1@scrubbed.local"},
            "ldap_dn": {"john": "cn_1"},
            "sid": {"PRD": "HA1"},
            "keyword": {"ACME": "keyword_1"},
            "hostname": {"db01": "host-1", "admin": "host-2"},
            "user": {"jdoe": "user1"}}
    f = _verify(tmp_path, {"a.txt": "x Sup3rS3cretValue\nmail jdoe@corp.example\n"
                                     "CN=John Smith\n/usr/sap/PRD prdadm SAPPRD_\n"
                                     "ACME db01 jdoe_backup\npassword changed by admin\n"},
                maps)
    assert {"Sup3rS3cretValue", "jdoe@corp.example", "John", "PRD", "prdadm",
            "SAPPRD", "ACME", "db01", "jdoe"} <= _values(f)
    assert {x["line"] for x in f} == {1, 2, 3, 4, 5}, f


def test_sar_text_file_compressed_file_and_file_names_are_checked(tmp_path):
    maps = {"hostname": {"dbnode01": "host-1"}}
    f = _verify(tmp_path, {"sar20261117": "Linux 6.4 (dbnode01) 11/17/26\n",
                           "old.log.gz": gzip.compress(b"dbnode01 boot\n"),
                           "dbnode01/notes.txt": "nothing\n"}, maps)
    assert {"sar20261117", "old.log.gz", "dbnode01"} <= {x["file"] for x in f}, f


def test_unreadable_file_is_reported(tmp_path):
    f = _verify(tmp_path, {"cut.log.gz": gzip.compress(b"line\n" * 1000)[:-30]})
    assert [x for x in f if x["category"] == "unreadable file"], f


def test_ipv6_fake_is_not_taken_for_a_real_key(tmp_path):
    maps = {"ipv6": {"2001:db8::1": "2001:db8:0:1::1", "2001:db8:5::7": "2001:db8::10"}}
    f = _verify(tmp_path, {"a.txt": "addr 2001:db8::10/64\naddr 2001:db8:0:1::1\n"}, maps)
    assert not f, f
    f = _verify(tmp_path, {"b.txt": "addr 2001:db8:5::7/64\n"}, maps)
    assert _values(f, "IPv6 address") == {"2001:db8:5::7"}


def test_identity_does_not_skip_hosts_named_fd(tmp_path):
    orig = tmp_path / "orig"
    orig.mkdir()
    (orig / "basic-environment.txt").write_text("Linux fdserver01 6.4.0 x86_64\n")
    f = _verify(tmp_path, {"a.txt": "up on fdserver01\n"},
                original_folder=str(orig), check_identity=True)
    assert "fdserver01" in _values(f, "system identity")


def test_trie_terms_match_like_single_terms():
    maps = {"hostname": {f"node{i:04d}x": f"host-{i}" for i in range(2000)},
            "ip": {f"203.0.113.{i}": f"198.16.0.{i}" for i in range(1, 200)}}
    term_res, labels = _build_terms(maps)
    line = "node0042x node00420x 203.0.113.17 203.0.113.170 x203.0.113.18"
    assert set(_mapping_hits(line, term_res, labels)) == {
        ("hostname", "node0042x"), ("IPv4 address", "203.0.113.17"),
        ("IPv4 address", "203.0.113.170")}


def test_public_ips_kept_on_purpose_are_not_findings():
    from supportutils_scrub.verify import _build_safe_ipv4_nets, _is_safe_ipv4
    nets = _build_safe_ipv4_nets(obfuscate_private_ip=True, obfuscate_public_ip=False)
    assert _is_safe_ipv4("8.8.8.8", nets)
    assert not _is_safe_ipv4("10.1.2.3", nets)
    assert not _is_safe_ipv4("192.168.1.1", nets)
    nets = _build_safe_ipv4_nets()
    assert not _is_safe_ipv4("8.8.8.8", nets)
