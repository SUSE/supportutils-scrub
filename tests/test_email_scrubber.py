import pytest
from supportutils_scrub.email_scrubber import EmailScrubber


def _make():
    return EmailScrubber(mappings={})


class TestEmailScrub:
    def test_email_replaced(self):
        s = _make()
        result = s.scrub("contact admin@company.com please")
        assert "admin@company.com" not in result
        assert "@scrubbed.local" in result

    def test_safe_domain_preserved(self):
        s = _make()
        result = s.scrub("test user@example.com here")
        assert "user@example.com" in result

    def test_catalog_suffix_skipped(self):
        """Regression: .catalog files look like emails but aren't."""
        s = _make()
        text = "file 1234567890abcdef.catalog loaded"
        result = s.scrub(text)
        assert ".catalog" in result
        assert "@scrubbed" not in result

    def test_systemd_unit_skipped(self):
        s = _make()
        for suffix in ['.service', '.socket', '.timer', '.target', '.mount']:
            text = f"unit foo@bar{suffix} active"
            result = s.scrub(text)
            assert suffix in result

    def test_consistent_replacement(self):
        s = _make()
        text = "from bob@corp.com to bob@corp.com"
        result = s.scrub(text)
        parts = [p for p in result.split() if "@scrubbed" in p]
        assert len(parts) == 2
        assert parts[0] == parts[1]

    def test_mapping_populated(self):
        s = _make()
        s.scrub("mail alice@test.org")
        assert "alice@test.org" in s.mapping
