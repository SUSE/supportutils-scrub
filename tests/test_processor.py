import pytest
import logging
from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber


class _FakeLogger:
    def info(self, msg): pass
    def error(self, msg): pass
    def warning(self, msg): pass


def _full_processor(**overrides):
    defaults = dict(
        obfuscate_private_ip=True, obfuscate_public_ip=True,
        obfuscate_ipv6=True, obfuscate_mac=True,
        obfuscate_hostname=True, obfuscate_domain=True,
        obfuscate_username=True)
    defaults.update(overrides)
    cfg = ScrubConfig(**defaults)
    scrubbers = [
        IPScrubber(cfg, mappings={}),
        IPv6Scrubber(cfg, mappings={}),
        MACScrubber(cfg, mappings={}),
        HostnameScrubber({"myhost": "hostname_0"}),
        DomainScrubber({"corp.local": "domain_0.aaa"}),
        UsernameScrubber({"jdoe": "user_0"}),
        EmailScrubber(mappings={}),
        PasswordScrubber(mappings={}),
        CloudTokenScrubber(mappings={}),
    ]
    return FileProcessor(cfg, scrubbers)


class TestProcessorPipeline:
    def test_all_types_scrubbed(self):
        fp = _full_processor()
        text = (
            "server 8.8.8.8 mac AA:BB:CC:DD:EE:FF\n"
            "host myhost.corp.local user jdoe\n"
            "email admin@company.com password=LongSecret1\n"
        )
        result = fp.process_text(text, _FakeLogger(), False)
        assert "8.8.8.8" not in result
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert "myhost" not in result
        assert "jdoe" not in result
        assert "admin@company.com" not in result
        assert "LongSecret1" not in result

    def test_scrubber_order_preserved(self):
        fp = _full_processor()
        names = [s.name for s in fp.scrubbers]
        assert names.index('ip') < names.index('mac')
        assert names.index('mac') < names.index('hostname')

    def test_getitem_lookup(self):
        fp = _full_processor()
        assert fp['ip'] is not None
        assert fp['ip'].name == 'ip'
        assert fp['nonexistent'] is None

    def test_config_gate_disables_scrubber(self):
        fp = _full_processor(obfuscate_mac=False)
        result = fp.process_text("mac AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_mac_skip_files(self):
        fp = _full_processor()
        # _scrub_content with basename in skip_files should skip MAC
        result = fp._scrub_content("mac AA:BB:CC:DD:EE:FF", "modules.txt", _FakeLogger())
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_mac_not_skipped_for_normal_file(self):
        fp = _full_processor()
        result = fp._scrub_content("mac AA:BB:CC:DD:EE:FF", "network.txt", _FakeLogger())
        assert "AA:BB:CC:DD:EE:FF" not in result

    def test_keyword_scrubber_in_list(self):
        cfg = ScrubConfig()
        scrubbers = [KeywordScrubber(cmd_keywords=["secret"])]
        fp = FileProcessor(cfg, scrubbers)
        result = fp.process_text("the secret is out", _FakeLogger(), False)
        assert "secret" not in result


class TestProcessorMappings:
    def test_mappings_accessible_after_scrub(self):
        fp = _full_processor()
        fp.process_text("server 8.8.8.8 mac AA:BB:CC:DD:EE:FF", _FakeLogger(), False)
        assert len(fp['ip'].mapping) >= 1
        assert len(fp['mac'].mapping) >= 1

    def test_dataset_dict_buildable(self):
        fp = _full_processor()
        fp.process_text("server 8.8.8.8", _FakeLogger(), False)
        dataset = {s.name: dict(s.mapping) for s in fp.scrubbers}
        assert 'ip' in dataset
        assert len(dataset['ip']) >= 1
