import pytest
from supportutils_scrub.serial_scrubber import SerialScrubber


def _make():
    return SerialScrubber(mappings={})


class TestSerialScrub:
    def test_serial_number_replaced(self):
        s = _make()
        s.pre_scan("Serial Number: ABC12345XYZ")
        result = s.scrub("Serial Number: ABC12345XYZ")
        assert "ABC12345XYZ" not in result

    def test_uuid_replaced(self):
        s = _make()
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        s.pre_scan(f"UUID: {uuid}")
        result = s.scrub(f"UUID: {uuid}")
        assert uuid not in result

    def test_not_specified_skipped(self):
        s = _make()
        s.pre_scan("Serial Number: Not Specified")
        assert len(s.mapping) == 0

    def test_null_uuid_skipped(self):
        s = _make()
        s.pre_scan("UUID: 00000000-0000-0000-0000-000000000000")
        assert len(s.mapping) == 0

    def test_mapping_property(self):
        s = _make()
        s.pre_scan("Serial Number: REAL123")
        assert isinstance(s.mapping, dict)

    def test_dash_placeholder_skipped(self):
        # DMI empty-field placeholder: "Serial Number: -" must NOT become a serial,
        # or every hyphen in the capture gets substring-replaced.
        s = _make()
        s.pre_scan("Serial Number: -")
        s.pre_scan("Asset Tag: -")
        assert len(s.mapping) == 0

    def test_dash_placeholder_does_not_corrupt_hyphens(self):
        s = _make()
        s.pre_scan("Serial Number: -")
        text = ("2026-07-16T00:47 kernel-default-6.4.0-150600 "
                "iqn.2009-04.com.example:target")
        assert s.scrub(text) == text          # nothing altered

    def test_short_or_punctuation_values_skipped(self):
        for placeholder in ("-", ".", "0", "AB", "12", "--", "   ", "N/A"):
            s = _make()
            s.pre_scan(f"Serial Number: {placeholder}")
            assert len(s.mapping) == 0, placeholder

    def test_real_serial_still_scrubbed(self):
        # the guard must not suppress genuine serials (>= 4 alphanumerics)
        s = _make()
        s.pre_scan("Part Number: ABC-123-XYZ")
        assert s.scrub("Part Number: ABC-123-XYZ") != "Part Number: ABC-123-XYZ"
