"""A plain binary file must never be rewritten as text.

Folder mode probed for binary content only inside the compressed branch, so
a file whose name carries no compression extension went straight to the text
path: it was read with errors='ignore', which drops every byte that is not
valid UTF-8, and written back with the scrub banner in front. A packet
capture came out of that with its magic gone and a fifth of its bytes
missing, and no tool would open it again. The same held for any core dump,
database or disk image a case happens to carry.

No em dashes, by project convention.
"""

import os

import pytest

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor, looks_binary, _SCRUB_INFO_HEADER
from supportutils_scrub.ip_scrubber import IPScrubber


class _FakeLogger:
    def __init__(self):
        self.errors = []

    def info(self, msg):
        pass

    def warning(self, msg):
        pass

    def error(self, msg):
        self.errors.append(msg)


def _scrub(path):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
    logger = _FakeLogger()
    FileProcessor(cfg, [IPScrubber(cfg, mappings={})]).process_file(str(path), logger, False)
    return logger


#: a little-endian pcap header (magic d4c3b2a1, v2.4, LINKTYPE_ETHERNET)
#: followed by one packet record carrying an IPv4 address in its payload
PCAP_HEAD = (b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 +
             b"\xff\xff\x00\x00\x01\x00\x00\x00")
#: a packet whose payload carries ASCII the scrubbers match, which is what a
#: real capture looks like: a TFTP request naming a path that embeds the
#: server address, next to raw bytes that are not valid UTF-8
PCAP_REC = (b"\x00\x11\x22\x33\x50\x00\x00\x00\x50\x00\x00\x00" +
            b"\xff\xfe\x00\x01\x08\x00\x45\x00" +
            b"\x00\x01(tftp,10.179.147.203)/SLE15_SP7/core.elf\x00octet\x00" +
            b"\x00\xd4\xc3\xb2\xa1\xfe\xff")


def _pcap_bytes():
    return PCAP_HEAD + PCAP_REC * 4


class TestBinaryIsLeftAlone:
    @pytest.mark.parametrize("name", ["capture.pcap", "boot.pcapng", "core.1234",
                                      "state.db", "disk.img"])
    def test_a_binary_file_is_not_rewritten_as_text(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(_pcap_bytes())
        before = path.read_bytes()

        _scrub(path)

        after = path.read_bytes()
        assert after == before, f"{name} was rewritten"
        assert not after.startswith(_SCRUB_INFO_HEADER.encode()), "banner prepended"

    def test_the_capture_still_opens_after_a_scrub(self, tmp_path):
        """The bytes a reader keys on: magic first, size unchanged."""
        path = tmp_path / "working-boot.pcap"
        path.write_bytes(_pcap_bytes())
        size = path.stat().st_size

        _scrub(path)

        assert path.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"
        assert path.stat().st_size == size

    def test_a_big_endian_capture_is_recognised_too(self, tmp_path):
        path = tmp_path / "other.pcap"
        path.write_bytes(b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04" + b"\x00" * 200)
        before = path.read_bytes()

        _scrub(path)

        assert path.read_bytes() == before

    def test_the_file_is_reported_so_it_is_never_a_silent_leave(self, tmp_path):
        path = tmp_path / "capture.pcap"
        path.write_bytes(_pcap_bytes())

        logger = _scrub(path)

        assert any("capture.pcap" in m for m in logger.errors), logger.errors

    def test_dry_run_does_not_touch_it_either(self, tmp_path):
        path = tmp_path / "capture.pcap"
        path.write_bytes(_pcap_bytes())
        before = path.read_bytes()

        cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
        FileProcessor(cfg, [IPScrubber(cfg, mappings={})]).process_file(
            str(path), _FakeLogger(), False, dry_run=True)

        assert path.read_bytes() == before


class TestTextIsStillScrubbed:
    def test_a_plain_log_is_scrubbed_and_gets_the_banner(self, tmp_path):
        path = tmp_path / "messages"
        path.write_text("Sep  9 07:38:28 host sshd: accepted from 8.8.8.8\n")

        _scrub(path)

        body = path.read_text()
        assert "8.8.8.8" not in body
        assert body.startswith(_SCRUB_INFO_HEADER[:4])

    def test_a_long_text_file_with_no_nul_bytes_is_still_text(self, tmp_path):
        path = tmp_path / "big.txt"
        path.write_text(("10.0.0.1 line of a log\n" * 5000))

        _scrub(path)

        assert "10.0.0.1" not in path.read_text()

    def test_utf8_text_is_not_mistaken_for_binary(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("hostname aaa, IP 8.8.8.8, note: Grusse aus Munchen\n")

        _scrub(path)

        assert "8.8.8.8" not in path.read_text()


def test_the_probe_itself_agrees(tmp_path):
    b = tmp_path / "x.pcap"
    b.write_bytes(_pcap_bytes())
    t = tmp_path / "x.txt"
    t.write_text("plain text, no NUL here\n")
    assert looks_binary(str(b)) is True
    assert looks_binary(str(t)) is False
