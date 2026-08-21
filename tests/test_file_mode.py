"""Lone-file invocation (modes/file.py). The scrub runs in place on a copy
carrying the output name, so compressed payloads stream through the segment
machinery instead of being decompressed into one string — a small .xz can
hide a multi-GB log (28:1 seen in the field)."""

import lzma
import os
from types import SimpleNamespace

import pytest

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub import processor as processor_mod
from supportutils_scrub.modes import file as file_mode
from supportutils_scrub.processor import _SCRUB_INFO_HEADER, compression_magic_ok


class _Logger:
    def info(self, msg):
        pass

    def warning(self, msg):
        pass

    def error(self, msg):
        pass


def _args(path, tmp_path, **kw):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / 'datasets'))
    ns = SimpleNamespace(
        verbose=False, supportconfig_path=[str(path)], mappings=None,
        keywords=None, keyword_file=None, domain=None, username=None,
        hostname=None, unpacked=False, no_mappings=True,
        _preloaded_config=cfg)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _run(path, tmp_path, **kw):
    file_mode.run_file_mode(_args(path, tmp_path, **kw), _Logger())


def test_plain_file(tmp_path):
    path = tmp_path / "notes.log"
    path.write_text("client 8.8.8.8 connected\n")

    _run(path, tmp_path)

    out = tmp_path / "notes_scrubbed.log"
    body = out.read_text()
    assert body.startswith(_SCRUB_INFO_HEADER)
    assert "8.8.8.8" not in body
    assert path.read_text() == "client 8.8.8.8 connected\n"


def test_compressed_multi_segment_round_trip(tmp_path, monkeypatch):
    # _SEG_BYTES is imported by value in modes/file.py, so both bindings are
    # shrunk to force the multi-segment paths (pre-scan and scrub).
    monkeypatch.setattr(processor_mod, '_SEG_BYTES', 256)
    monkeypatch.setattr(file_mode, '_SEG_BYTES', 256)

    lines = "".join(f"198.51.{i % 4}.{(i % 250) + 1} - - \"GET /page/{i}\"\n"
                    for i in range(300))
    path = tmp_path / "access_log.xz"
    with lzma.open(path, 'wt') as f:
        f.write(lines)
    before = path.read_bytes()

    _run(path, tmp_path)

    out = tmp_path / "access_log_scrubbed.xz"
    assert compression_magic_ok(str(out), '.xz')
    with lzma.open(out, 'rt') as f:
        body = f.read()
    assert body.startswith(_SCRUB_INFO_HEADER)
    assert "198.51." not in body
    assert path.read_bytes() == before


def test_syslog_hostname_learned_across_segments(tmp_path, monkeypatch):
    # Three RFC 5424 mentions of one host, each in a different segment: the
    # >=3-occurrences threshold must count across the whole document, or the
    # hostname ships unscrubbed.
    monkeypatch.setattr(processor_mod, '_SEG_BYTES', 256)
    monkeypatch.setattr(file_mode, '_SEG_BYTES', 256)

    filler = "nothing sensitive on this line of the log at all\n" * 10
    mention = "2026-08-07T12:00:00+02:00 buildhost77 systemd[1]: Started unit\n"
    path = tmp_path / "messages.xz"
    with lzma.open(path, 'wt') as f:
        f.write(filler + mention + filler + mention + filler + mention + filler)

    _run(path, tmp_path)

    with lzma.open(tmp_path / "messages_scrubbed.xz", 'rt') as f:
        assert "buildhost77" not in f.read()


def test_binary_payload_refused(tmp_path):
    path = tmp_path / "blob.xz"
    with lzma.open(path, 'wb') as f:
        f.write(b'\x00\x01\x02binary payload\x00')

    with pytest.raises(SystemExit) as e:
        _run(path, tmp_path)

    assert e.value.code == 1
    assert not (tmp_path / "blob_scrubbed.xz").exists()


def test_damaged_beyond_salvage_leaves_no_output(tmp_path):
    # Valid magic, garbage stream: nothing decompresses, so no scrubbed
    # rewrite is possible and no _scrubbed file may remain.
    path = tmp_path / "broken.xz"
    path.write_bytes(b'\xfd7zXZ\x00' + b'\x13\x37' * 200)

    with pytest.raises(SystemExit) as e:
        _run(path, tmp_path)

    assert e.value.code == 1
    assert not (tmp_path / "broken_scrubbed.xz").exists()
    assert path.exists()


def test_misleading_extension_scrubbed_as_plain(tmp_path):
    path = tmp_path / "rotated.log.xz"
    path.write_text("plain text with 8.8.8.8 despite the name\n")

    _run(path, tmp_path)

    out = tmp_path / "rotated_scrubbed.log"
    assert out.exists()
    assert "8.8.8.8" not in out.read_text()
    assert not (tmp_path / "rotated_scrubbed.log.xz").exists()


def test_unpacked_writes_plain_output(tmp_path):
    path = tmp_path / "boot.log.xz"
    with lzma.open(path, 'wt') as f:
        f.write("kernel says hello to 8.8.8.8\n")

    _run(path, tmp_path, unpacked=True)

    out = tmp_path / "boot_scrubbed.log"
    assert out.exists()
    assert "8.8.8.8" not in out.read_text()
    assert not (tmp_path / "boot_scrubbed.log.xz").exists()


def test_already_scrubbed_name_rescrubs_in_place(tmp_path):
    # Output name equals input name: no copy is made and nothing may crash.
    path = tmp_path / "notes_scrubbed.log"
    path.write_text("client 8.8.8.8 connected\n")

    _run(path, tmp_path)

    body = path.read_text()
    assert "8.8.8.8" not in body


def test_unpacked_in_place_refused(tmp_path):
    # Converting in place would delete the input; refused, input untouched.
    path = tmp_path / "boot_scrubbed.log.xz"
    with lzma.open(path, 'wt') as f:
        f.write("kernel says hello to 8.8.8.8\n")
    before = path.read_bytes()

    with pytest.raises(SystemExit) as e:
        _run(path, tmp_path, unpacked=True)

    assert e.value.code == 1
    assert path.read_bytes() == before


def test_lone_sap_log_loses_its_sid_like_it_would_inside_a_bundle(tmp_path):
    """The file entry point had no Serial/SID scrubber: the same SAP log
    scrubbed alone kept its SID while inside a bundle it lost it."""
    path = tmp_path / "sapstartsrv.log"
    path.write_text("starting SAPPRD instance for /usr/sap/PRD/SYS by prdadm\n")

    _run(path, tmp_path)

    body = (tmp_path / "sapstartsrv_scrubbed.log").read_text()
    assert "PRD" not in body
    assert "prdadm" not in body
