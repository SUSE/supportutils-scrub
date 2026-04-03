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
