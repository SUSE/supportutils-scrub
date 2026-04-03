"""Verify every scrubber honors the Scrubber ABC contract."""
import pytest
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.scrub_config import ScrubConfig
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


_CFG = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                   obfuscate_ipv6=True, obfuscate_mac=True)

ALL_SCRUBBERS = [
    lambda: IPScrubber(_CFG, mappings={}),
    lambda: IPv6Scrubber(_CFG, mappings={}),
    lambda: MACScrubber(_CFG, mappings={}),
    lambda: DomainScrubber({"example.com": "domain_0.aaa"}),
    lambda: HostnameScrubber({"myhost": "hostname_0"}),
    lambda: UsernameScrubber({"jdoe": "user_0"}),
    lambda: KeywordScrubber(cmd_keywords=["secret"]),
    lambda: SerialScrubber(mappings={}),
    lambda: EmailScrubber(mappings={}),
    lambda: PasswordScrubber(mappings={}),
    lambda: CloudTokenScrubber(mappings={}),
]


@pytest.mark.parametrize("factory", ALL_SCRUBBERS,
                         ids=lambda f: f().__class__.__name__)
class TestScrubberContract:
    def test_is_subclass(self, factory):
        s = factory()
        assert isinstance(s, Scrubber)

    def test_has_name(self, factory):
        s = factory()
        assert isinstance(s.name, str)
        assert len(s.name) > 0

    def test_scrub_returns_str(self, factory):
        s = factory()
        result = s.scrub("some text 8.8.8.8 AA:BB:CC:DD:EE:FF")
        assert isinstance(result, str)

    def test_mapping_returns_dict(self, factory):
        s = factory()
        s.scrub("some text")
        assert isinstance(s.mapping, dict)

    def test_scrub_empty_string(self, factory):
        s = factory()
        result = s.scrub("")
        assert isinstance(result, str)

    def test_scrub_no_matches(self, factory):
        s = factory()
        text = "plain text no sensitive data"
        result = s.scrub(text)
        assert isinstance(result, str)

    def test_skip_files_is_frozenset(self, factory):
        s = factory()
        assert isinstance(s.skip_files, frozenset)
