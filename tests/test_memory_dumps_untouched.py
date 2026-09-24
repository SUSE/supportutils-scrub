"""Kernel dumps, application cores and the archives that carry them are
never scrubbed, rewritten or deleted.

A dump holds memory, not text: a text scrub either destroys it or, at best,
leaves it and reports it as an error. The nested-archive pass used to unpack
every tar it found and then remove it, so a getappcore bundle (opencore.ini
plus root/core.<pid>) or a kdump tar inside a supportconfig came out
expanded with its tarball gone, and an archive that failed to unpack (a
truncated 200 GB upload) was deleted outright.

No em dashes, by project convention.
"""

import hashlib
import io
import os
import tarfile
from types import SimpleNamespace

import pytest

from supportutils_scrub import extractor
from supportutils_scrub import parallel
from supportutils_scrub import processor
from supportutils_scrub.modes import folder as folder_mode
from supportutils_scrub.scrub_config import ScrubConfig


class _Logger:
    def __init__(self):
        self.infos, self.warnings, self.errors = [], [], []

    def info(self, msg):
        self.infos.append(msg)

    def warning(self, msg):
        self.warnings.append(msg)

    def error(self, msg):
        self.errors.append(msg)


#: text a scrub would rewrite if it ever read a dump as text
_TEXT_BAIT = b"peer 198.51.100.77 said hello to 203.0.113.9\n" * 40


def _elf_core(order="little", e_type=4):
    """An ELF header (64-bit, the given byte order and e_type) plus bytes
    that are not text, then text a scrubber would match."""
    data = 1 if order == "little" else 2
    ident = b"\x7fELF" + bytes([2, data, 1, 0]) + b"\x00" * 8
    head = ident + e_type.to_bytes(2, order) + (62).to_bytes(2, order)
    return head + b"\x00\xff\xfe" * 32 + _TEXT_BAIT


def _makedumpfile():
    """The flattened makedumpfile header, then padding and text bait."""
    return b"makedumpfile\x00\x00\x00\x00" + b"\x00\x00\x00\x01" * 4 + b"\x00" * 64 + _TEXT_BAIT


def _kdump_compressed():
    """The compressed kdump header: KDUMP plus three spaces."""
    return b"KDUMP   " + b"\x06\x00\x00\x00" + b"\x00" * 64 + _TEXT_BAIT


def _tar_bytes(members, mode="w"):
    """A tar (mode w, w:bz2, w:gz, ...) holding members [(name, bytes)]."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 1700000000
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _case_tree(tmp_path):
    """A case folder with a core, a vmcore, a getappcore bundle and an
    unrelated nested tar of logs."""
    src = tmp_path / "case_tree"
    src.mkdir()
    (src / "core.1234").write_bytes(_elf_core())
    (src / "vmcore").write_bytes(_makedumpfile())
    (src / "bundle.tbz").write_bytes(_tar_bytes([
        ("opencore.ini", b"[core]\nhost = 198.51.100.77\n"),
        ("root/core.1234", _elf_core()),
    ], mode="w:bz2"))
    (src / "logs.tar").write_bytes(_tar_bytes([
        ("messages", b"Sep  9 07:38:28 sshd: accepted from 198.51.100.77\n"),
    ]))
    (src / "notes.txt").write_text("contact 198.51.100.77 about it\n")
    return src


_KEPT = ("core.1234", "vmcore", "bundle.tbz")


def _args(src, tmp_path, jobs):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    return SimpleNamespace(verbose=False, supportconfig_path=[str(src)],
                           mappings=None, keywords=None, keyword_file=None,
                           domain=None, username=None, hostname=None,
                           unpacked=False, no_mappings=False, quiet=True,
                           jobs=jobs, report=False, report_file=None, profile=False,
                           verify=False, encrypt_mappings=False, secure_tmp=None,
                           config=None, _preloaded_config=cfg, _enc_passphrase=None)


def _run_folder_mode(tmp_path, capture, jobs):
    src = _case_tree(tmp_path)
    before = {name: _sha(src / name) for name in _KEPT}
    logger = _Logger()
    folder_mode.run_folder_mode(_args(src, tmp_path, jobs), logger)
    out = capture.readouterr().out.strip().splitlines()[-1]
    assert os.path.isdir(out), out
    return out, before, logger


def _assert_kept_and_logs_expanded(out, before):
    for name in _KEPT:
        path = os.path.join(out, name)
        assert os.path.isfile(path), f"{name} is gone from the output"
        assert _sha(path) == before[name], f"{name} was rewritten"
    # the bundle is left whole, not unpacked beside itself
    assert not os.path.exists(os.path.join(out, "bundle"))
    # an unrelated nested tar is still expanded and removed, and scrubbed
    assert not os.path.exists(os.path.join(out, "logs.tar"))
    messages = open(os.path.join(out, "logs", "messages")).read()
    assert "198.51.100.77" not in messages
    assert "198.51.100.77" not in open(os.path.join(out, "notes.txt")).read()


class TestFolderMode:
    def test_dumps_cores_and_their_archive_come_out_byte_identical(self, tmp_path, capsys):
        out, before, logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        _assert_kept_and_logs_expanded(out, before)

    def test_no_error_line_names_them(self, tmp_path, capsys):
        _out, _before, logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        for name in _KEPT:
            assert not [m for m in logger.errors if name in m], logger.errors

    def test_each_leave_is_reported_at_info(self, tmp_path, capsys):
        _out, _before, logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        infos = "\n".join(logger.infos)
        assert "core.1234: memory dump, left unchanged (never scrubbed)" in infos
        assert "vmcore: memory dump, left unchanged (never scrubbed)" in infos
        assert "bundle.tbz: carries a memory dump; left whole, never scrubbed" in infos

    def test_parallel_run_never_chunks_a_dump_or_an_archive_as_text(
            self, tmp_path, capsys, monkeypatch):
        # production runs with --jobs; real dumps are far above the chunking
        # threshold, so shrink it and make the chunk path reachable. The
        # workers log through their own logger, so this one checks bytes.
        monkeypatch.setattr(parallel, "_CHUNK_THRESHOLD", 64)
        monkeypatch.setattr(parallel, "_CHUNK_MIN", 32)
        out, before, _logger = _run_folder_mode(tmp_path, capsys, jobs=2)
        _assert_kept_and_logs_expanded(out, before)


class TestMemoryDumpProbe:
    @pytest.mark.parametrize("payload", [
        _elf_core("little"), _elf_core("big"), _makedumpfile(), _kdump_compressed(),
    ], ids=["elf-core-le", "elf-core-be", "makedumpfile", "kdump-compressed"])
    def test_dump_heads_are_recognised(self, tmp_path, payload):
        path = tmp_path / "anything.txt"
        path.write_bytes(payload)
        assert processor.is_memory_dump(str(path)) is True

    @pytest.mark.parametrize("payload", [
        _elf_core("little", e_type=2),        # an executable is not a dump
        _elf_core("big", e_type=3),           # nor is a shared object
        b"\x7fELF",                           # too short to carry e_type
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 40,   # a pcap
        b"KDUMP  \n" + b"x" * 40,             # two spaces is not the header
        b"plain text 198.51.100.77\n",
        b"",
    ], ids=["elf-exec", "elf-dyn", "elf-short", "pcap", "kdump-near-miss", "text", "empty"])
    def test_other_heads_are_not(self, tmp_path, payload):
        path = tmp_path / "file"
        path.write_bytes(payload)
        assert processor.is_memory_dump(str(path)) is False

    def test_a_missing_file_is_not_a_dump(self, tmp_path):
        assert processor.is_memory_dump(str(tmp_path / "nope")) is False

    def test_a_dump_under_a_text_name_is_left_unchanged(self, tmp_path):
        path = tmp_path / "messages.txt"
        path.write_bytes(_elf_core())
        before = path.read_bytes()
        logger = _Logger()
        cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
        from supportutils_scrub.ip_scrubber import IPScrubber
        ok = processor.FileProcessor(cfg, [IPScrubber(cfg, mappings={})]).process_file(
            str(path), logger, False)
        assert ok is True
        assert path.read_bytes() == before
        assert logger.errors == []
        assert logger.infos == ["messages.txt: memory dump, left unchanged (never scrubbed)"]


class TestDumpMemberNames:
    @pytest.mark.parametrize("name", [
        "vmcore", "var/crash/127.0.0.1-2026-09-24/vmcore", "vmcore.flat",
        "vmcore-incomplete", "core", "core.1234", "root/core.1234", "core.1234.gz",
        "opencore.ini", "x/opencore.ini",
    ])
    def test_dump_members(self, name):
        assert processor.is_dump_member_name(name) is True

    @pytest.mark.parametrize("name", [
        "vmcore-dmesg.txt", "var/crash/x/vmcore-dmesg.txt", "cores", "corefile",
        "score.1234", "opencore.ini.bak", "messages", "",
    ])
    def test_other_members(self, name):
        assert processor.is_dump_member_name(name) is False


class TestExpandNestedArchives:
    def test_a_kdump_tar_is_left_whole(self, tmp_path):
        arc = tmp_path / "crash.tar.gz"
        arc.write_bytes(_tar_bytes([
            ("127.0.0.1-2026-09-24/vmcore-dmesg.txt", b"dmesg text\n"),
            ("127.0.0.1-2026-09-24/vmcore", _makedumpfile()),
        ], mode="w:gz"))
        before = _sha(arc)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar.gz"]
        assert logger.infos == ["crash.tar.gz: carries a memory dump; left whole, never scrubbed"]
        assert logger.errors == []

    def test_a_kept_archive_is_listed_once_not_once_per_depth(self, tmp_path, monkeypatch):
        (tmp_path / "bundle.tbz").write_bytes(_tar_bytes([
            ("opencore.ini", b"[core]\n"), ("root/core.1234", _elf_core())], mode="w:bz2"))
        calls = []
        real = extractor.archive_dump_member
        monkeypatch.setattr(extractor, "archive_dump_member",
                            lambda p, *a, **k: calls.append(p) or real(p, *a, **k))
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert len(calls) == 1
        assert len(logger.infos) == 1

    def test_a_truncated_archive_holding_a_dump_is_kept(self, tmp_path):
        # the dump's header is readable, its data is cut short: the listing
        # sees it before the damage, so the upload is never deleted
        full = _tar_bytes([("vmcore", _makedumpfile() * 50)])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:2048])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert arc.exists() and _sha(arc) == before
        assert os.listdir(tmp_path) == ["upload.tar"]
        assert logger.infos == ["upload.tar: carries a memory dump; left whole, never scrubbed"]
        assert logger.errors == []

    def test_a_failed_unpack_keeps_an_archive_whose_dump_the_listing_missed(
            self, tmp_path, monkeypatch):
        # the listing stops after a member cap; the dump sits past it and the
        # archive is damaged, so the unpack fails: kept, and named in the error
        monkeypatch.setattr(processor, "_DUMP_LISTING_CAP", 1)
        full = _tar_bytes([("readme", b"notes\n"), ("vmcore", _makedumpfile() * 50)])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:4096])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert arc.exists() and _sha(arc) == before
        assert len(logger.errors) == 1, logger.errors
        assert "upload.tar" in logger.errors[0] and "vmcore" in logger.errors[0]
        assert "left in place" in logger.errors[0]

    def test_an_intact_archive_whose_dump_the_listing_missed_is_still_kept(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(processor, "_DUMP_LISTING_CAP", 1)
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("readme", b"notes\n"), ("vmcore", _makedumpfile())]))
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar"]
        assert logger.errors == []

    def test_a_failed_unpack_without_a_dump_is_still_removed(self, tmp_path):
        full = _tar_bytes([("messages", b"198.51.100.77 log line\n" * 400)])
        arc = tmp_path / "logs.tar"
        arc.write_bytes(full[:2048])
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert not arc.exists()
        assert len(logger.errors) == 1 and "logs.tar" in logger.errors[0]

    def test_an_archive_without_a_dump_is_expanded_and_removed(self, tmp_path):
        (tmp_path / "logs.tar.gz").write_bytes(_tar_bytes([
            ("messages", b"a log line\n"), ("sub/scores.txt", b"text\n")], mode="w:gz"))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert not (tmp_path / "logs.tar.gz").exists()
        assert (tmp_path / "logs" / "messages").read_bytes() == b"a log line\n"
