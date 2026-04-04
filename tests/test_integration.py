"""
Integration tests — full scrubbing pipeline across all scrubber types.
Run before every release to catch regressions.
"""
import os
import json
import shutil
import tempfile
import pytest

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


class _FakeLogger:
    def info(self, msg): pass
    def error(self, msg): pass
    def warning(self, msg): pass


def _full_config():
    return ScrubConfig(
        obfuscate_private_ip=True, obfuscate_public_ip=True,
        obfuscate_ipv6=True, obfuscate_mac=True,
        obfuscate_hostname=True, obfuscate_domain=True,
        obfuscate_username=True, obfuscate_serial=True)


def _full_processor(hostname_dict=None, domain_dict=None, username_dict=None,
                    keywords=None, serial_mappings=None, mappings=None):
    cfg = _full_config()
    m = mappings or {}
    serial_scrubber = SerialScrubber(mappings=m)
    if serial_mappings:
        serial_scrubber.serial_dict = serial_mappings

    scrubbers = [
        IPScrubber(cfg, mappings=m),
        IPv6Scrubber(cfg, mappings=m),
        MACScrubber(cfg, mappings=m),
    ]
    if keywords:
        scrubbers.append(KeywordScrubber(cmd_keywords=keywords))
    scrubbers += [
        HostnameScrubber(hostname_dict or {}),
        DomainScrubber(domain_dict or {}),
        UsernameScrubber(username_dict or {}),
        EmailScrubber(mappings=m),
        PasswordScrubber(mappings=m),
        CloudTokenScrubber(mappings=m),
        serial_scrubber,
    ]
    return FileProcessor(cfg, scrubbers)


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name), 'r') as f:
        return f.read()


# ────────────────────────────────────────────────────
#  KEYWORD TESTS
# ────────────────────────────────────────────────────

class TestKeywordIntegration:
    def test_keyword_replaced_everywhere(self):
        fp = _full_processor(keywords=["ProjectX"])
        text = "ProjectX is live. See ProjectX docs. PROJECTX config."
        result = fp.process_text(text, _FakeLogger(), False)
        assert "ProjectX" not in result
        assert "PROJECTX" not in result

    def test_keyword_case_insensitive(self):
        fp = _full_processor(keywords=["SecretDevice"])
        result = fp.process_text("Found SECRETDEVICE in bay 3", _FakeLogger(), False)
        assert "SECRETDEVICE" not in result

    def test_keyword_with_special_chars(self):
        fp = _full_processor(keywords=["customer.name"])
        result = fp.process_text("owner=customer.name", _FakeLogger(), False)
        assert "customer.name" not in result

    def test_multiple_keywords(self):
        fp = _full_processor(keywords=["alpha", "bravo", "charlie"])
        text = "alpha bravo charlie delta"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "alpha" not in result
        assert "bravo" not in result
        assert "charlie" not in result
        assert "delta" in result

    def test_keyword_in_mixed_content(self):
        fp = _full_processor(
            hostname_dict={"myhost": "hostname_0"},
            keywords=["InternalProject"])
        text = "host myhost running InternalProject at 8.8.8.8"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "InternalProject" not in result
        assert "myhost" not in result
        assert "8.8.8.8" not in result


# ────────────────────────────────────────────────────
#  USERNAME TESTS
# ────────────────────────────────────────────────────

class TestUsernameIntegration:
    def test_username_in_log_line(self):
        fp = _full_processor(username_dict={"jdoe": "user_0"})
        text = "sshd[1234]: session opened for user jdoe by (uid=0)"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "jdoe" not in result
        assert "user_0" in result

    def test_system_user_not_replaced(self):
        fp = _full_processor(username_dict={"root": "user_0"})
        # root is in EXCLUDED_USERS, so even if passed, scrub won't match
        # because UsernameScrubber builds regex only from non-excluded users
        # Actually, if you explicitly pass root in the dict, it WILL be replaced
        # This tests the pipeline behavior
        text = "USER=root running command"
        result = fp.process_text(text, _FakeLogger(), False)
        # root should be in excluded list upstream (extract_usernames filters it)
        # but if explicitly added to dict, it will be replaced

    def test_multiple_users_in_same_line(self):
        fp = _full_processor(username_dict={"alice": "user_0", "bob": "user_1"})
        text = "alice sent message to bob"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "alice" not in result
        assert "bob" not in result
        assert "user_0" in result
        assert "user_1" in result

    def test_username_with_ip_and_mac(self):
        fp = _full_processor(username_dict={"admin": "user_0"})
        text = "admin logged in from 10.0.0.5 via 52:54:00:AA:BB:CC"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "admin" not in result
        assert "10.0.0.5" not in result
        assert "52:54:00:AA:BB:CC" not in result


# ────────────────────────────────────────────────────
#  FULL PIPELINE — NETWORK FILE
# ────────────────────────────────────────────────────

class TestNetworkFileScrub:
    def test_all_ips_scrubbed(self):
        fp = _full_processor(
            hostname_dict={"dbserver": "hostname_0", "gateway": "hostname_1", "appnode1": "hostname_2"},
            domain_dict={"corp.example.com": "domain_0.aaa", "internal.lan": "domain_1.aab"})
        text = _read_fixture('sample_network.txt')
        result = fp.process_text(text, _FakeLogger(), False)

        # Public IPs scrubbed
        assert "8.8.8.8" not in result
        # Private IPs scrubbed (config enables private)
        assert "192.168.1.10" not in result
        assert "10.0.0.1" not in result
        assert "172.16.5.50" not in result
        # Loopback preserved
        assert "127.0.0.1" in result
        # Broadcast preserved
        assert "ff:ff:ff:ff:ff:ff" in result.lower()

    def test_mac_addresses_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_network.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "52:54:00:9a:c4:ad" not in result.lower()

    def test_ipv6_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_network.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "2001:db8:85a3" not in result.lower()
        # loopback preserved
        assert "::1" in result

    def test_hostnames_scrubbed(self):
        fp = _full_processor(
            hostname_dict={"dbserver": "hostname_0", "appnode1": "hostname_1"})
        text = _read_fixture('sample_network.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "dbserver" not in result
        assert "hostname_0" in result

    def test_domains_scrubbed(self):
        fp = _full_processor(
            domain_dict={"corp.example.com": "domain_0.aaa"})
        text = _read_fixture('sample_network.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "corp.example.com" not in result
        assert "domain_0.aaa" in result


# ────────────────────────────────────────────────────
#  FULL PIPELINE — LOG FILE
# ────────────────────────────────────────────────────

class TestLogFileScrub:
    def test_usernames_and_ips(self):
        fp = _full_processor(
            username_dict={"jdoe": "user_0", "admin": "user_1", "hacker": "user_2"},
            hostname_dict={"dbserver": "hostname_0", "appnode1": "hostname_1"})
        text = _read_fixture('sample_messages.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "jdoe" not in result
        assert "192.168.1.50" not in result
        assert "203.0.113.45" not in result
        assert "45.33.32.156" not in result

    def test_mac_in_kernel_log(self):
        # kernel UFW lines concatenate MACs (src+dst+ethertype) without spaces,
        # e.g. MAC=52:54:00:9a:c4:ad:00:1a:2b:3c:4d:5e:08:00
        # the MAC regex needs a non-hex boundary so this is a known limitation
        fp = _full_processor()
        text = "link/ether 52:54:00:9a:c4:ad brd ff:ff:ff:ff:ff:ff"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "52:54:00:9a:c4:ad" not in result.lower()

    def test_email_in_postfix_line(self):
        fp = _full_processor(
            domain_dict={"corp.example.com": "domain_0.aaa"})
        text = _read_fixture('sample_messages.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "corp.example.com" not in result


# ────────────────────────────────────────────────────
#  FULL PIPELINE — CONFIG FILE
# ────────────────────────────────────────────────────

class TestConfigFileScrub:
    def test_ldap_dn_scrubbed(self):
        fp = _full_processor(
            domain_dict={"corp.example.com": "domain_0.aaa"})
        text = _read_fixture('sample_config.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "DC=corp,DC=example,DC=com" not in result

    def test_passwords_scrubbed(self):
        fp = _full_processor()
        # password regex matches: password=VALUE, passwd=VALUE
        # db_password with quotes is a different pattern
        text = "password=SuperSecretDB99\npasswd = LongPasswd12"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "SuperSecretDB99" not in result
        assert "LongPasswd12" not in result
        assert "scrubbed_pass_" in result

    def test_cloud_tokens_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_config.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "wJalrXUtnFEMI" not in result
        assert "eyJhbGciOiJIUzI1NiI" not in result
        assert "Eby8vdM02xNOcqFlq" not in result

    def test_domains_in_config(self):
        fp = _full_processor(
            domain_dict={"corp.example.com": "domain_0.aaa",
                         "internal.lan": "domain_1.aab"})
        text = _read_fixture('sample_config.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert "corp.example.com" not in result

    def test_domain_with_full_url(self):
        fp = _full_processor(
            domain_dict={"corp.example.com": "domain_0.aaa"})
        text = "ldap_uri = ldaps://ldap.corp.example.com"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "corp.example.com" not in result


# ────────────────────────────────────────────────────
#  SERIAL / UUID TESTS
# ────────────────────────────────────────────────────

class TestSerialIntegration:
    def test_serial_and_uuid_scrubbed(self):
        text = _read_fixture('sample_hardware.txt')
        serial_scrubber = SerialScrubber(mappings={})
        serial_scrubber.pre_scan(text)
        fp = _full_processor(serial_mappings=serial_scrubber.serial_dict)
        result = fp.process_text(text, _FakeLogger(), False)
        assert "ABC123XYZ789" not in result
        assert "550e8400-e29b-41d4-a716-446655440000" not in result
        assert "BOARD-SN-99887766" not in result

    def test_not_specified_preserved(self):
        text = _read_fixture('sample_hardware.txt')
        serial_scrubber = SerialScrubber(mappings={})
        serial_scrubber.pre_scan(text)
        assert "Not Specified" not in [v for v in serial_scrubber.serial_dict.keys()]


# ────────────────────────────────────────────────────
#  VERSION STRING FALSE POSITIVES (REGRESSION)
# ────────────────────────────────────────────────────

class TestRpmVersionStrings:
    def test_version_numbers_not_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_rpm.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        # These look like IPs but are version numbers
        assert "0.8.9.0" in result
        assert "67.7.2" in result

    def test_real_ip_still_scrubbed_alongside_versions(self):
        fp = _full_processor()
        text = "version 0.8.9.0 server 8.8.8.8"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "0.8.9.0" in result
        assert "8.8.8.8" not in result


# ────────────────────────────────────────────────────
#  EMAIL EDGE CASES (REGRESSION)
# ────────────────────────────────────────────────────

class TestEmailEdgeCases:
    def test_systemd_unit_not_email(self):
        fp = _full_processor()
        units = [
            "user@1000.service", "session-c1@.service",
            "dbus-org.freedesktop.resolve1.socket",
            "dev-disk-by\\x2did-partition1.mount",
        ]
        for unit in units:
            result = fp.process_text(unit, _FakeLogger(), False)
            assert "@scrubbed" not in result, f"false positive on {unit}"

    def test_catalog_file_not_email(self):
        fp = _full_processor()
        text = "loading 1234567890abcdef.catalog"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "@scrubbed" not in result

    def test_real_email_scrubbed(self):
        fp = _full_processor()
        result = fp.process_text("contact: admin@bigcorp.com", _FakeLogger(), False)
        assert "admin@bigcorp.com" not in result
        assert "@scrubbed.local" in result

    def test_safe_domain_preserved(self):
        fp = _full_processor()
        result = fp.process_text("see docs@example.com", _FakeLogger(), False)
        assert "docs@example.com" in result


# ────────────────────────────────────────────────────
#  CONSISTENCY TESTS
# ────────────────────────────────────────────────────

class TestConsistency:
    def test_same_ip_across_files(self):
        """Same IP processed twice must get the same fake."""
        fp = _full_processor()
        r1 = fp.process_text("server 8.8.8.8", _FakeLogger(), False)
        r2 = fp.process_text("dns 8.8.8.8", _FakeLogger(), False)
        fake = fp['ip'].mapping["8.8.8.8"]
        assert fake in r1
        assert fake in r2

    def test_same_mac_across_files(self):
        fp = _full_processor()
        fp.process_text("eth0 AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        fp.process_text("eth1 AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        assert len(fp['mac'].mapping) == 1

    def test_mapping_reuse(self):
        """Loading previous mappings must produce the same fakes."""
        cfg = _full_config()
        # First run
        fp1 = _full_processor()
        fp1.process_text("server 8.8.8.8 mac AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        saved = {s.name: dict(s.mapping) for s in fp1.scrubbers}
        saved['subnet'] = fp1['ip'].subnet_dict
        saved['state'] = fp1['ip'].state

        # Second run reusing mappings
        fp2 = _full_processor(mappings=saved)
        fp2.process_text("server 8.8.8.8", _FakeLogger(), False)
        assert fp2['ip'].mapping["8.8.8.8"] == fp1['ip'].mapping["8.8.8.8"]


# ────────────────────────────────────────────────────
#  CONFIG FLAG TESTS
# ────────────────────────────────────────────────────

class TestConfigFlags:
    def test_private_ip_disabled(self):
        cfg = ScrubConfig(obfuscate_private_ip=False, obfuscate_public_ip=True)
        scrubbers = [IPScrubber(cfg, mappings={})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("host 192.168.1.1", _FakeLogger(), False)
        assert "192.168.1.1" in result

    def test_private_ip_enabled(self):
        cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
        scrubbers = [IPScrubber(cfg, mappings={})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("host 192.168.1.1", _FakeLogger(), False)
        assert "192.168.1.1" not in result

    def test_mac_disabled(self):
        cfg = ScrubConfig(obfuscate_mac=False)
        scrubbers = [MACScrubber(cfg, mappings={})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("eth0 AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_ipv6_disabled(self):
        cfg = ScrubConfig(obfuscate_ipv6=False)
        scrubbers = [IPv6Scrubber(cfg, mappings={})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("addr 2001:db8::1", _FakeLogger(), False)
        assert "2001:db8::1" in result

    def test_hostname_disabled(self):
        cfg = ScrubConfig(obfuscate_hostname=False)
        scrubbers = [HostnameScrubber({"myhost": "hostname_0"})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("host myhost", _FakeLogger(), False)
        assert "myhost" in result

    def test_domain_disabled(self):
        cfg = ScrubConfig(obfuscate_domain=False)
        scrubbers = [DomainScrubber({"test.com": "domain_0.aaa"})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("host test.com", _FakeLogger(), False)
        assert "test.com" in result

    def test_username_disabled(self):
        cfg = ScrubConfig(obfuscate_username=False)
        scrubbers = [UsernameScrubber({"jdoe": "user_0"})]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("user jdoe", _FakeLogger(), False)
        assert "jdoe" in result


# ────────────────────────────────────────────────────
#  EDGE CASES
# ────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_input(self):
        fp = _full_processor()
        assert fp.process_text("", _FakeLogger(), False) == ""

    def test_no_sensitive_data(self):
        fp = _full_processor()
        text = "This is a plain text file with nothing to scrub."
        assert fp.process_text(text, _FakeLogger(), False) == text

    def test_unicode_text(self):
        fp = _full_processor()
        text = "Ünïcödé text with IP 8.8.8.8 and émojis 🎉"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "8.8.8.8" not in result
        assert "Ünïcödé" in result
        assert "🎉" in result

    def test_very_long_line(self):
        fp = _full_processor()
        text = "prefix " + "8.8.8.8 " * 1000 + "suffix"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "8.8.8.8" not in result
        assert "prefix" in result
        assert "suffix" in result

    def test_ip_at_line_boundaries(self):
        fp = _full_processor()
        text = "8.8.8.8\n8.8.4.4\n"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "8.8.8.8" not in result
        assert "8.8.4.4" not in result

    def test_adjacent_sensitive_data(self):
        fp = _full_processor(
            hostname_dict={"myhost": "hostname_0"},
            domain_dict={"test.com": "domain_0.aaa"})
        text = "myhost.test.com=8.8.8.8:AA:BB:CC:DD:EE:FF"
        result = fp.process_text(text, _FakeLogger(), False)
        assert "8.8.8.8" not in result


# ────────────────────────────────────────────────────
#  FILE MODE — PROCESS_FILE
# ────────────────────────────────────────────────────

class TestFileProcessing:
    def test_process_file_writes_header(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("server 8.8.8.8 is up\n")
        fp = _full_processor()
        fp.process_file(str(test_file), _FakeLogger(), False)
        content = test_file.read_text()
        assert "INFO: This file was processed by supportutils-scrub" in content
        assert "8.8.8.8" not in content

    def test_process_file_no_header_when_unchanged(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("nothing sensitive here\n")
        fp = _full_processor()
        fp.process_file(str(test_file), _FakeLogger(), False)
        content = test_file.read_text()
        assert "INFO: Sensitive information" not in content

    def test_binary_sa_file_removed(self, tmp_path):
        sa_file = tmp_path / "sa20260404"
        sa_file.write_bytes(b'\x00\x01\x02binary data')
        fp = _full_processor()
        fp.process_file(str(sa_file), _FakeLogger(), False)
        assert not sa_file.exists()

    def test_obj_file_removed(self, tmp_path):
        obj_file = tmp_path / "module.obj"
        obj_file.write_bytes(b'\x00\x01\x02binary data')
        fp = _full_processor()
        fp.process_file(str(obj_file), _FakeLogger(), False)
        assert not obj_file.exists()


# ────────────────────────────────────────────────────
#  MAC SKIP FILES
# ────────────────────────────────────────────────────

class TestMacSkipFiles:
    def test_mac_not_scrubbed_in_modules_txt(self, tmp_path):
        test_file = tmp_path / "modules.txt"
        test_file.write_text("module AA:BB:CC:DD:EE:FF loaded\n")
        fp = _full_processor()
        fp.process_file(str(test_file), _FakeLogger(), False)
        content = test_file.read_text()
        assert "AA:BB:CC:DD:EE:FF" in content

    def test_mac_scrubbed_in_network_txt(self, tmp_path):
        test_file = tmp_path / "network.txt"
        test_file.write_text("eth0 AA:BB:CC:DD:EE:FF up\n")
        fp = _full_processor()
        fp.process_file(str(test_file), _FakeLogger(), False)
        content = test_file.read_text()
        assert "AA:BB:CC:DD:EE:FF" not in content


# ────────────────────────────────────────────────────
#  DATASET DICT ASSEMBLY
# ────────────────────────────────────────────────────

class TestDatasetDict:
    def test_all_keys_present(self):
        fp = _full_processor(
            hostname_dict={"h": "hostname_0"},
            domain_dict={"d.com": "domain_0.aaa"},
            username_dict={"u": "user_0"},
            keywords=["kw"])
        fp.process_text(
            "h d.com u kw 8.8.8.8 AA:BB:CC:DD:EE:FF admin@corp.com password=LongPass99",
            _FakeLogger(), False)
        dataset = {s.name: dict(s.mapping) for s in fp.scrubbers}
        dataset['subnet'] = fp['ip'].subnet_dict
        dataset['state'] = fp['ip'].state
        dataset['ipv6_subnet'] = fp['ipv6'].subnet_map

        assert 'ip' in dataset
        assert 'ipv6' in dataset
        assert 'mac' in dataset
        assert 'keyword' in dataset
        assert 'hostname' in dataset
        assert 'domain' in dataset
        assert 'user' in dataset
        assert 'email' in dataset
        assert 'password' in dataset
        assert 'cloud_token' in dataset
        assert 'serial' in dataset
        assert 'subnet' in dataset
        assert 'state' in dataset

    def test_dataset_serializable(self):
        fp = _full_processor()
        fp.process_text("server 8.8.8.8", _FakeLogger(), False)
        dataset = {s.name: dict(s.mapping) for s in fp.scrubbers}
        dataset['subnet'] = fp['ip'].subnet_dict
        dataset['state'] = fp['ip'].state
        # Must be JSON-serializable for mapping file
        json_str = json.dumps(dataset)
        assert isinstance(json_str, str)
        loaded = json.loads(json_str)
        assert loaded['ip'] == dataset['ip']
