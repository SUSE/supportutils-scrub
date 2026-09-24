"""Kernel dumps and application cores are never scrubbed, rewritten or
deleted, and the text beside them is still scrubbed.

A dump holds memory, not text: a text scrub either destroys it or, at best,
leaves it and reports it as an error. A nested archive that carries one (a
getappcore bundle: opencore.ini plus root/core.<pid>; a kdump tar: vmcore
plus vmcore-dmesg.txt) is unpacked like any other, so its text members are
scrubbed; the dump comes out byte-identical, and the archive is removed
only after a complete, verified extraction. One that cannot be unpacked is
kept in place and named in an error, never deleted with the dump in it.

No em dashes, by project convention.
"""

import bz2
import gzip
import hashlib
import io
import lzma
import os
import random
import shutil
import subprocess
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


_KDUMP_DIR = "2026-09-24-10_00"


def _case_tree(tmp_path):
    """A case folder with a loose core and vmcore, a getappcore bundle, a
    kdump tar, an unrelated nested tar of logs and a note."""
    src = tmp_path / "case_tree"
    src.mkdir()
    (src / "core.1234").write_bytes(_elf_core())
    (src / "vmcore").write_bytes(_makedumpfile())
    (src / "bundle.tbz").write_bytes(_tar_bytes([
        ("opencore.ini", b"[core]\nhost = 198.51.100.77\n"),
        ("root/core.1234", _elf_core()),
    ], mode="w:bz2"))
    (src / "crash.tar.gz").write_bytes(_tar_bytes([
        (f"{_KDUMP_DIR}/vmcore-dmesg.txt", b"[ 12.5] eth0: link up, peer 198.51.100.77\n"),
        (f"{_KDUMP_DIR}/vmcore", _makedumpfile()),
    ], mode="w:gz"))
    (src / "logs.tar").write_bytes(_tar_bytes([
        ("messages", b"Sep  9 07:38:28 sshd: accepted from 198.51.100.77\n"),
    ]))
    (src / "notes.txt").write_text("contact 198.51.100.77 about it\n")
    return src


#: output path -> the bytes it must hold, unchanged
_DUMPS = {
    "core.1234": _elf_core(),
    "vmcore": _makedumpfile(),
    "bundle/root/core.1234": _elf_core(),
    f"crash/{_KDUMP_DIR}/vmcore": _makedumpfile(),
}
#: text members that must come out scrubbed
_TEXTS = ("bundle/opencore.ini", f"crash/{_KDUMP_DIR}/vmcore-dmesg.txt",
          "logs/messages", "notes.txt")


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


def _run_folder_mode(tmp_path, capture, jobs, tree=_case_tree):
    src = tree(tmp_path)
    logger = _Logger()
    folder_mode.run_folder_mode(_args(src, tmp_path, jobs), logger)
    out = capture.readouterr().out.strip().splitlines()[-1]
    assert os.path.isdir(out), out
    return out, logger


def _assert_dumps_intact_and_text_scrubbed(out):
    for rel, payload in _DUMPS.items():
        path = os.path.join(out, rel)
        assert os.path.isfile(path), f"{rel} is missing from the output"
        assert _sha(path) == hashlib.sha256(payload).hexdigest(), f"{rel} was rewritten"
    for rel in _TEXTS:
        body = open(os.path.join(out, rel), "rb").read()
        assert b"198.51.100.77" not in body, f"{rel} was not scrubbed"
    # every nested archive was unpacked completely and then removed
    for arc in ("bundle.tbz", "crash.tar.gz", "logs.tar"):
        assert not os.path.exists(os.path.join(out, arc)), f"{arc} survived"


class TestFolderMode:
    def test_dumps_come_out_byte_identical_and_the_text_beside_them_scrubbed(
            self, tmp_path, capsys):
        out, _logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        _assert_dumps_intact_and_text_scrubbed(out)

    def test_no_error_line_names_a_dump_or_its_archive(self, tmp_path, capsys):
        _out, logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        for name in ("core.1234", "vmcore", "bundle", "crash", "opencore.ini"):
            assert not [m for m in logger.errors if name in m], logger.errors

    def test_each_dump_is_reported_at_info(self, tmp_path, capsys):
        _out, logger = _run_folder_mode(tmp_path, capsys, jobs=1)
        assert logger.infos.count("core.1234: memory dump, left unchanged (never scrubbed)") == 2
        assert logger.infos.count("vmcore: memory dump, left unchanged (never scrubbed)") == 2
        assert "Unpacked nested archive: bundle.tbz" in logger.infos
        assert "Unpacked nested archive: crash.tar.gz" in logger.infos

    def test_parallel_run_never_chunks_a_dump_as_text(self, tmp_path, capsys, monkeypatch):
        # production runs with --jobs; real dumps are far above the chunking
        # threshold, so shrink it and make the chunk path reachable. The
        # workers log through their own logger, so this one checks bytes.
        monkeypatch.setattr(parallel, "_CHUNK_THRESHOLD", 64)
        monkeypatch.setattr(parallel, "_CHUNK_MIN", 32)
        out, _logger = _run_folder_mode(tmp_path, capsys, jobs=2)
        _assert_dumps_intact_and_text_scrubbed(out)


_RNG_BYTES = random.Random(0).randbytes(256 * 1024)


def _compressed_tree(tmp_path):
    """Compressed payloads above a (patched-down) staging threshold: a
    kernel dump, an application core, a binary capture and a text log."""
    src = tmp_path / "compressed_tree"
    src.mkdir()
    (src / "vmcore.xz").write_bytes(lzma.compress(_makedumpfile() + _RNG_BYTES + _TEXT_BAIT))
    (src / "core.4321.gz").write_bytes(gzip.compress(_elf_core() + _RNG_BYTES, mtime=0))
    (src / "capture.pcap.gz").write_bytes(gzip.compress(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + _RNG_BYTES + _TEXT_BAIT, mtime=0))
    rng = random.Random(1)
    log = "".join(f"line {i} peer 198.51.100.77 id {rng.random()}\n" for i in range(4000))
    (src / "messages.xz").write_bytes(lzma.compress(log.encode()))
    (src / "notes.txt").write_text("contact 198.51.100.77\n")
    return src


_COMPRESSED_BINARIES = ("vmcore.xz", "core.4321.gz", "capture.pcap.gz")


class TestCompressedDumps:
    def test_parallel_run_never_stages_a_compressed_dump_or_binary(
            self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(parallel, "_COMPRESSED_CHUNK_THRESHOLD", 1024)
        staged = []
        real_stage = parallel._stage_compressed
        monkeypatch.setattr(parallel, "_stage_compressed",
                            lambda p, comp, lg: staged.append(os.path.basename(p))
                            or real_stage(p, comp, lg))
        src = _compressed_tree(tmp_path)
        before = {n: _sha(src / n) for n in _COMPRESSED_BINARIES}
        for n in _COMPRESSED_BINARIES + ("messages.xz",):
            assert os.path.getsize(src / n) > 1024, n
        out, _logger = _run_folder_mode(tmp_path, capsys, jobs=2, tree=lambda _t: src)
        for n in _COMPRESSED_BINARIES:
            assert n not in staged
            assert _sha(os.path.join(out, n)) == before[n], f"{n} was rewritten"
        # a compressed text log is still staged, scrubbed and recompressed
        assert "messages.xz" in staged
        text = lzma.decompress(open(os.path.join(out, "messages.xz"), "rb").read())
        assert b"198.51.100.77" not in text and b"line 3999 peer" in text

    def test_serial_run_reports_a_compressed_dump_at_info(self, tmp_path, capsys):
        src = _compressed_tree(tmp_path)
        before = {n: _sha(src / n) for n in _COMPRESSED_BINARIES}
        out, logger = _run_folder_mode(tmp_path, capsys, jobs=1, tree=lambda _t: src)
        for n in _COMPRESSED_BINARIES:
            assert _sha(os.path.join(out, n)) == before[n], f"{n} was rewritten"
        assert "vmcore.xz: memory dump, left unchanged (never scrubbed)" in logger.infos
        assert "core.4321.gz: memory dump, left unchanged (never scrubbed)" in logger.infos
        assert not [m for m in logger.errors if "vmcore.xz" in m or "core.4321" in m], \
            logger.errors
        # a binary that is not a dump is still reported as before
        assert [m for m in logger.errors if m.startswith("capture.pcap.gz: gz payload is not text")]

    @pytest.mark.parametrize("payload,expected", [
        (_makedumpfile() + _RNG_BYTES, False),
        (b"\x00" + b"text\n" * 400, False),
        (b"plain text 198.51.100.77\n" * 400, True),
    ], ids=["dump", "binary", "text"])
    def test_only_a_compressed_text_payload_is_stageable(self, tmp_path, monkeypatch,
                                                         payload, expected):
        monkeypatch.setattr(parallel, "_COMPRESSED_CHUNK_THRESHOLD", 16)
        path = tmp_path / "payload.gz"
        path.write_bytes(gzip.compress(payload, mtime=0))
        assert (parallel._stageable_compressed(str(path)) is not None) is expected


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
        b"makedumpfile: saving to /var/crash/vmcore\n",   # a log line, no NUL
        b"KDUMP   enabled on this node since boot\n",     # a log line, no NUL
        b"plain text 198.51.100.77\n",
        b"",
    ], ids=["elf-exec", "elf-dyn", "elf-short", "pcap", "kdump-near-miss",
            "makedumpfile-log-line", "kdump-log-line", "text", "empty"])
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

    def test_a_log_line_naming_the_dump_tool_is_still_scrubbed(self, tmp_path):
        path = tmp_path / "kdump.log"
        path.write_text("makedumpfile: saving to 198.51.100.77:/var/crash\n")
        ok, _logger = _process(path)
        assert ok is True
        assert "198.51.100.77" not in path.read_text()


def _process(path):
    logger = _Logger()
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
    from supportutils_scrub.ip_scrubber import IPScrubber
    ok = processor.FileProcessor(cfg, [IPScrubber(cfg, mappings={})]).process_file(
        str(path), logger, False)
    return ok, logger


class TestArchivesReachingTheTreeWalk:
    """Only an archive that could not be unpacked reaches process_file."""

    def test_a_damaged_archive_that_carries_a_dump_is_reported_at_info(self, tmp_path):
        path = tmp_path / "upload.tar"
        path.write_bytes(_tar_bytes([("vmcore", _makedumpfile() * 50)])[:2048])
        before = path.read_bytes()
        ok, logger = _process(path)
        assert ok is True and path.read_bytes() == before
        assert logger.infos == ["upload.tar: archive carrying a memory dump, left whole "
                                "(never scrubbed)"]
        assert logger.errors == []

    def test_an_archive_without_a_dump_still_gets_the_binary_line(self, tmp_path):
        path = tmp_path / "logs.tar"
        path.write_bytes(_tar_bytes([("messages", b"198.51.100.77 log line\n")]))
        before = path.read_bytes()
        ok, logger = _process(path)
        assert ok is True and path.read_bytes() == before
        assert len(logger.errors) == 1
        assert logger.errors[0].startswith("logs.tar: binary content, not text")


def _stream_verdicts(members):
    """{member name: is_dump_member} over a tar read as a stream."""
    buf = io.BytesIO(_tar_bytes(members))
    out = {}
    with tarfile.open(fileobj=buf, mode="r|*") as tar:
        for member in tar:
            out[member.name] = processor.is_dump_member(tar, member)
    return out


class TestDumpMembers:
    """A member is a dump by its content; only opencore.ini counts by name."""

    @pytest.mark.parametrize("name,payload", [
        ("vmcore", _makedumpfile()),
        ("var/crash/127.0.0.1-2026-09-24/vmcore", _kdump_compressed()),
        ("vmcore.flat", _makedumpfile()),
        ("vmcore-incomplete", _elf_core()),
        ("core", _elf_core()),
        ("core.1234", _elf_core("big")),
        ("root/core.1234", _elf_core()),
        ("corefile", _elf_core()),
        ("opencore.ini", b"[core]\n"),
        ("x/opencore.ini", b""),
    ], ids=["vmcore-flat", "vmcore-kdump", "vmcore.flat", "vmcore-incomplete-elf",
            "core", "core.1234-be", "root-core.1234", "corefile", "opencore.ini",
            "opencore.ini-empty"])
    def test_dump_members(self, name, payload):
        assert _stream_verdicts([(name, payload)]) == {name: True}

    @pytest.mark.parametrize("name,payload", [
        ("core.txt", b"core notes 198.51.100.77\n"),
        ("core.py", b"import os\n"),
        ("core.xml", b"<core/>\n"),
        ("core.1234", b"not a core at all\n"),
        ("core.1234", _elf_core(e_type=2)),        # an executable is no core
        ("core", _makedumpfile()),                 # a core is an ELF core only
        ("vmcore", b"plain text body 198.51.100.77\n"),
        ("vmcore", b"makedumpfile: saving to /var/crash\n"),
        ("vmcore.log", b"KDUMP   enabled on this node\n"),
        ("vmcore-dmesg.txt", b"[    0.000000] Linux version\n"),
        ("vmcore.1", b""),
        ("messages", _elf_core()),                 # not a dump name: not read
        ("score.1234", _elf_core()),
        ("opencore.ini.bak", b"[core]\n"),
    ], ids=["core.txt", "core.py", "core.xml", "core.1234-text", "core.1234-elf-exec",
            "core-makedumpfile", "vmcore-text", "vmcore-makedumpfile-log-line",
            "vmcore-kdump-log-line", "vmcore-dmesg.txt", "vmcore.1-empty",
            "messages-elf-core", "score.1234", "opencore.ini.bak"])
    def test_other_members(self, name, payload):
        assert _stream_verdicts([(name, payload)]) == {name: False}

    def test_a_directory_named_core_is_not_a_dump(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("pkg/core")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r|*") as tar:
            assert [processor.is_dump_member(tar, m) for m in tar] == [False]

    def test_the_stream_listing_reads_each_member_in_turn(self):
        verdicts = _stream_verdicts([
            ("core.txt", b"text\n"), ("vmcore-dmesg.txt", b"text\n"),
            ("vmcore", _makedumpfile())])
        assert verdicts == {"core.txt": False, "vmcore-dmesg.txt": False, "vmcore": True}


def _zstd(data):
    try:
        import zstandard
        return zstandard.ZstdCompressor().compress(data)
    except ImportError:
        pass
    exe = shutil.which("zstd")
    if not exe:
        pytest.skip("no zstd compressor here")
    return subprocess.run([exe, "-c", "-q"], input=data, stdout=subprocess.PIPE,
                          check=True).stdout


def _lz4(data):
    try:
        import lz4.frame
        return lz4.frame.compress(data)
    except ImportError:
        pass
    exe = shutil.which("lz4")
    if not exe:
        pytest.skip("no lz4 compressor here")
    return subprocess.run([exe, "-c", "-q"], input=data, stdout=subprocess.PIPE,
                          check=True).stdout


_SYSTEMD_CORE = "core.bash.1000.0123456789abcdef0123456789abcdef.4321.1700000000000000"


class TestCompressedDumpMembers:
    """A dump member stored compressed is judged by its decompressed head."""

    @pytest.mark.parametrize("name,make", [
        ("vmcore.gz", lambda: gzip.compress(_makedumpfile(), mtime=0)),
        ("vmcore.xz", lambda: lzma.compress(_makedumpfile() + _RNG_BYTES)),
        ("vmcore.bz2", lambda: bz2.compress(_kdump_compressed())),
        ("core.1234.xz", lambda: lzma.compress(_elf_core())),
        # a whole 900 KB bz2 block must be in before bz2 emits a byte
        ("core.1234.bz2", lambda: bz2.compress(_elf_core() + random.Random(2).randbytes(2 << 20))),
        (_SYSTEMD_CORE + ".zst", lambda: _zstd(_elf_core() + _RNG_BYTES)),
        (_SYSTEMD_CORE + ".xz", lambda: lzma.compress(_elf_core())),
        (_SYSTEMD_CORE + ".lz4", lambda: _lz4(_elf_core())),
    ], ids=["vmcore.gz", "vmcore.xz", "vmcore.bz2-kdump", "core.xz", "core.bz2-big-block",
            "systemd-zst", "systemd-xz", "systemd-lz4"])
    def test_compressed_dumps(self, name, make):
        assert _stream_verdicts([(name, make())]) == {name: True}

    @pytest.mark.parametrize("name,make", [
        ("vmcore.gz", lambda: gzip.compress(b"plain text 198.51.100.77\n", mtime=0)),
        ("vmcore-dmesg.txt.gz", lambda: gzip.compress(b"[ 0.0] Linux\n", mtime=0)),
        ("core.txt.gz", lambda: gzip.compress(b"core notes\n", mtime=0)),
        ("core.1234.xz", lambda: lzma.compress(_elf_core(e_type=2))),
        ("vmcore.gz", lambda: gzip.compress(b"makedumpfile: saving\n", mtime=0)),
        # a bomb: 64 MB of NUL bytes, decompressed only as far as the head
        ("vmcore.gz", lambda: gzip.compress(b"\x00" * (64 << 20), mtime=0)),
    ], ids=["vmcore.gz-text", "dmesg.gz", "core.txt.gz", "core.xz-elf-exec",
            "vmcore.gz-log-line", "vmcore.gz-zeros"])
    def test_compressed_non_dumps(self, name, make):
        assert _stream_verdicts([(name, make())]) == {name: False}

    def test_the_external_zstd_tool_is_used_when_no_module_is(self, monkeypatch):
        if not shutil.which("zstd"):
            pytest.skip("no zstd tool here")
        monkeypatch.setattr(processor, "_python_decompressor", lambda suffix: None)
        name = _SYSTEMD_CORE + ".zst"
        assert _stream_verdicts([(name, _zstd(_elf_core() + _RNG_BYTES))]) == {name: True}
        assert _stream_verdicts([("core.9.zst", _zstd(b"text\n" * 1000))]) == {"core.9.zst": False}


def _verdicts3(members, mode="r|*"):
    """{member name: dump_member_verdict} over a tar (a stream by default)."""
    buf = io.BytesIO(_tar_bytes(members))
    out = {}
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for member in tar:
            out[member.name] = processor.dump_member_verdict(tar, member)
    return out


def _no_decompressors(monkeypatch):
    """What the production image has for zstd and lz4: nothing."""
    monkeypatch.setattr(processor, "_python_decompressor", lambda suffix: None)
    monkeypatch.setattr(processor, "_EXTERNAL_MEMBER_DECOMPRESSORS", {})


def _xz_with_dict(data, dict_code):
    """An xz stream whose block header declares the LZMA2 dictionary
    dict_code (40 is 4 GiB), block header CRC recomputed."""
    import struct
    import zlib
    raw = bytearray(lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32))
    hdr = 12
    size = (raw[hdr] + 1) * 4
    flags = raw[hdr + 1]
    pos = hdr + 2

    def varint(pos):
        while raw[pos] & 0x80:
            pos += 1
        return pos + 1
    if flags & 0x40:
        pos = varint(pos)
    if flags & 0x80:
        pos = varint(pos)
    assert raw[pos] == 0x21 and raw[pos + 1] == 1       # LZMA2, one property byte
    raw[pos + 2] = dict_code
    crc = zlib.crc32(bytes(raw[hdr:hdr + size - 4]))
    raw[hdr + size - 4:hdr + size] = struct.pack("<I", crc)
    return bytes(raw)


class TestMemberVerdicts:
    """The probe answers DUMP, NOT_A_DUMP or UNKNOWN, and never raises."""

    def test_a_stream_that_does_not_decode_is_unknown(self):
        assert _verdicts3([("vmcore.xz", b"not an xz stream at all")]) == \
            {"vmcore.xz": processor.UNKNOWN}

    def test_no_decompressor_here_is_unknown(self, monkeypatch):
        core = _zstd(_elf_core() + _RNG_BYTES)
        text = _zstd(b"plain text\n" * 100)
        _no_decompressors(monkeypatch)
        name = _SYSTEMD_CORE + ".zst"
        assert _verdicts3([(name, core), ("core.9.zst", text)]) == \
            {name: processor.UNKNOWN, "core.9.zst": processor.UNKNOWN}

    def test_a_huge_declared_dictionary_is_unknown_not_a_memory_error(self):
        name = "vmcore.xz"
        data = _xz_with_dict(_makedumpfile(), 40)
        assert _verdicts3([(name, data)]) == {name: processor.UNKNOWN}

    def test_a_memory_error_in_the_probe_is_unknown(self, monkeypatch):
        class _Greedy:
            eof = False

            def decompress(self, data, n):
                raise MemoryError()
        monkeypatch.setattr(processor, "_python_decompressor", lambda suffix: _Greedy())
        data = gzip.compress(_makedumpfile(), mtime=0)
        assert _verdicts3([("vmcore.gz", data)]) == {"vmcore.gz": processor.UNKNOWN}

    def test_the_stream_listing_never_raises_a_memory_error(self, tmp_path, monkeypatch):
        def greedy(tar, member):
            raise MemoryError()
        monkeypatch.setattr(processor, "is_dump_member", greedy)
        path = tmp_path / "x.tar"
        path.write_bytes(_tar_bytes([("vmcore", _makedumpfile())]))
        assert processor.archive_dump_member(str(path)) is None

    def test_an_uncompressed_dump_under_a_compressed_name_is_a_dump(self, monkeypatch):
        _no_decompressors(monkeypatch)
        assert _verdicts3([("vmcore.gz", _makedumpfile()), ("core.7.zst", _elf_core())]) == \
            {"vmcore.gz": processor.DUMP, "core.7.zst": processor.DUMP}

    @pytest.mark.parametrize("name,payload", [
        ("core.txt.gz", gzip.compress(b"core notes 198.51.100.77\n" * 20, mtime=0)),
        ("vmcore.gz", gzip.compress(b"hi\n", mtime=0)),        # shorter than a head
        ("vmcore.xz", lzma.compress(b"plain text\n" * 20)),
        ("vmcore", b"hello"),
    ], ids=["core.txt.gz", "vmcore.gz-short", "vmcore.xz-text", "vmcore-short-text"])
    def test_a_decodable_text_payload_is_not_a_dump(self, name, payload):
        assert _verdicts3([(name, payload)]) == {name: processor.NOT_A_DUMP}

    @pytest.mark.parametrize("cut,expected", [
        (b"makedump", "unknown"),    # a dump signature cut short
        (b"\x7fELF\x02\x01", "unknown"),
        (b"hello wo", "not-a-dump"),
    ], ids=["makedumpfile-cut", "elf-cut", "text-cut"])
    def test_a_member_cut_inside_its_head(self, tmp_path, cut, expected):
        full = _tar_bytes([("vmcore", cut + b"x" * 5000)])
        path = tmp_path / "cut.tar"
        path.write_bytes(full[:512 + len(cut)])
        with tarfile.open(path, "r:*") as tar:
            try:
                tar.getmembers()
            except tarfile.ReadError:
                pass
            member = tar.members[0]
            assert processor.dump_member_verdict(tar, member) == expected

    def test_a_short_read_keeps_the_bytes_before_the_damage(self, tmp_path):
        data = bytes(range(256)) * 40                           # 10240 bytes
        full = _tar_bytes([("vmcore.xz", data)])
        path = tmp_path / "cut.tar"
        path.write_bytes(full[:512 + 5000])
        with tarfile.open(path, "r:*") as tar:
            try:
                tar.getmembers()
            except tarfile.ReadError:
                pass
            raw = tar.extractfile(tar.members[0]).raw
            assert b"".join(processor._member_blocks(raw, 1 << 20)) == data[:5000]

    def test_the_external_tool_is_fed_from_memory_and_reaped(self):
        if not shutil.which("zstd"):
            pytest.skip("no zstd tool here")
        import threading
        before = threading.active_count()
        head, complete = processor._external_decompressed_head(
            ".zst", _zstd(b"short text\n"), 20)
        assert (head, complete) == (b"short text\n", True)
        head, complete = processor._external_decompressed_head(
            ".zst", _zstd(_elf_core() + _RNG_BYTES), 20)
        assert len(head) == 20 and processor._is_elf_core_head(head)
        assert threading.active_count() == before


class TestExpandNestedArchives:
    def test_a_kdump_tar_is_unpacked_and_its_dump_comes_out_byte_identical(self, tmp_path):
        (tmp_path / "crash.tar.gz").write_bytes(_tar_bytes([
            ("2026-09-24/vmcore-dmesg.txt", b"dmesg text\n"),
            ("2026-09-24/vmcore", _makedumpfile()),
        ], mode="w:gz"))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert os.listdir(tmp_path) == ["crash"]
        assert (tmp_path / "crash" / "2026-09-24" / "vmcore").read_bytes() == _makedumpfile()
        assert (tmp_path / "crash" / "2026-09-24" / "vmcore-dmesg.txt").is_file()
        assert logger.errors == []

    def test_a_bundle_with_an_elf_core_is_unpacked_and_the_core_is_intact(self, tmp_path):
        (tmp_path / "app.tar.xz").write_bytes(_tar_bytes([
            ("opencore.ini", b"[core]\n"), ("root/core.1234", _elf_core())], mode="w:xz"))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert os.listdir(tmp_path) == ["app"]
        assert (tmp_path / "app" / "root" / "core.1234").read_bytes() == _elf_core()

    def test_a_truncated_archive_holding_a_dump_is_kept_and_named(self, tmp_path):
        # the dump's header is readable, its data is cut short: the upload is
        # never deleted, and it is tried once, not once per depth pass
        arc = tmp_path / "upload.tar"
        arc.write_bytes(_tar_bytes([("vmcore", _makedumpfile() * 50)])[:2048])
        before = _sha(arc)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger, max_depth=5) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["upload.tar"]
        assert len(logger.errors) == 1, logger.errors
        assert "upload.tar" in logger.errors[0] and "(vmcore)" in logger.errors[0]
        assert "left in place" in logger.errors[0]

    def test_a_damaged_archive_with_its_dump_after_other_members_is_kept(self, tmp_path):
        full = _tar_bytes([("readme", b"notes\n"), ("vmcore", _makedumpfile() * 50)])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:4096])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["upload.tar"]
        assert len(logger.errors) == 1 and "(vmcore)" in logger.errors[0], logger.errors

    def test_a_damaged_gz_archive_holding_a_dump_is_kept(self, tmp_path):
        filler = bytes(range(256)) * 400          # does not compress away
        full = _tar_bytes([("readme", b"notes\n"), ("vmcore", _makedumpfile() + filler)],
                          mode="w:gz")
        arc = tmp_path / "upload.tar.gz"
        arc.write_bytes(full[:len(full) // 2])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["upload.tar.gz"]
        assert len(logger.errors) == 1 and "(vmcore)" in logger.errors[0], logger.errors

    def test_a_failed_extraction_keeps_the_archive_and_leaves_no_partial_folder(
            self, tmp_path, monkeypatch):
        # the disk fills while the dump is written out (a 200 GB vmcore)
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("dmesg.txt", b"text\n"), ("vmcore", _makedumpfile())]))
        before = _sha(arc)
        real_extract = tarfile.TarFile.extract

        def extract(self, member, path="", **kw):
            if os.path.basename(getattr(member, "name", member)) == "vmcore":
                raise OSError(28, "No space left on device")
            return real_extract(self, member, path, **kw)
        monkeypatch.setattr(tarfile.TarFile, "extract", extract)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar"]
        assert len(logger.errors) == 1 and "No space left" in logger.errors[0]
        assert "partial extraction removed" in logger.errors[0]

    def test_a_folder_that_cannot_be_made_keeps_a_dump_carrying_archive(
            self, tmp_path, monkeypatch):
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("dmesg.txt", b"text\n"), ("vmcore", _makedumpfile())]))
        before = _sha(arc)
        real_makedirs = os.makedirs

        def makedirs(path, *a, **kw):
            if os.path.basename(path) == "crash":
                raise OSError(28, "No space left on device")
            return real_makedirs(path, *a, **kw)
        monkeypatch.setattr(extractor.os, "makedirs", makedirs)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar"]
        assert len(logger.errors) == 1 and "(vmcore)" in logger.errors[0], logger.errors
        assert "No space left" in logger.errors[0]
        assert "partial extraction removed" not in logger.errors[0]

    @pytest.mark.parametrize("name", ["/var/crash/2026-09-24/vmcore", "../vmcore",
                                      "a/../../core.1234"],
                             ids=["absolute", "dotdot", "nested-dotdot"])
    def test_a_dump_stored_under_an_unsafe_path_keeps_the_archive(self, tmp_path, name):
        payload = _elf_core() if "core.1234" in name else _makedumpfile()
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("dmesg.txt", b"text\n"), (name, payload)]))
        before = _sha(arc)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar"]
        assert len(logger.errors) == 1, logger.errors
        assert f"({name})" in logger.errors[0] and "unsafe path" in logger.errors[0]
        assert "partial extraction removed" in logger.errors[0]

    def test_a_text_member_under_an_unsafe_path_is_still_just_skipped(self, tmp_path):
        (tmp_path / "logs.tar").write_bytes(_tar_bytes([
            ("../escape.txt", b"text\n"), ("/etc/passwd", b"root:x:0:0\n"),
            ("messages", b"a log line\n")]))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert sorted(os.listdir(tmp_path)) == ["logs"]
        assert os.listdir(tmp_path / "logs") == ["messages"]
        assert logger.errors == []

    def test_a_damaged_archive_holding_only_a_compressed_dump_is_kept(self, tmp_path):
        full = _tar_bytes([("vmcore.xz", lzma.compress(_makedumpfile() + _RNG_BYTES))])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:len(full) // 2])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["upload.tar"]
        assert len(logger.errors) == 1 and "(vmcore.xz)" in logger.errors[0], logger.errors

    def test_a_short_extraction_is_not_trusted(self, tmp_path, monkeypatch):
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("dmesg.txt", b"text\n"), ("vmcore", _makedumpfile())]))
        before = _sha(arc)
        real_extract = tarfile.TarFile.extract

        def extract(self, member, path="", **kw):
            real_extract(self, member, path, **kw)
            if member.name == "vmcore":
                os.truncate(os.path.join(path, member.name), 10)
        monkeypatch.setattr(tarfile.TarFile, "extract", extract)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before
        assert os.listdir(tmp_path) == ["crash.tar"]
        assert len(logger.errors) == 1 and "(vmcore)" in logger.errors[0], logger.errors

    def test_a_damaged_archive_holding_a_raw_dump_under_a_gz_name_is_kept(self, tmp_path):
        full = _tar_bytes([("vmcore.gz", _makedumpfile() * 50)])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:2048])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before and os.listdir(tmp_path) == ["upload.tar"]
        assert len(logger.errors) == 1 and "memory dump (vmcore.gz)" in logger.errors[0]

    def test_a_damaged_archive_whose_member_does_not_decode_is_kept(self, tmp_path):
        full = _tar_bytes([("vmcore.xz", b"not an xz stream at all" * 200)])
        arc = tmp_path / "upload.tar"
        arc.write_bytes(full[:2048])
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before and os.listdir(tmp_path) == ["upload.tar"]
        assert len(logger.errors) == 1, logger.errors
        assert "(vmcore.xz: could not inspect)" in logger.errors[0]

    def test_without_a_decompressor_an_unsafe_path_zst_core_keeps_the_archive(
            self, tmp_path, monkeypatch):
        name = "/var/lib/systemd/coredump/" + _SYSTEMD_CORE + ".zst"
        arc = tmp_path / "cores.tar"
        arc.write_bytes(_tar_bytes([("readme", b"text\n"),
                                    (name, _zstd(_elf_core() + _RNG_BYTES))]))
        _no_decompressors(monkeypatch)
        before = _sha(arc)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before and os.listdir(tmp_path) == ["cores.tar"]
        assert len(logger.errors) == 1, logger.errors
        assert f"({name}: could not inspect)" in logger.errors[0]
        assert "unsafe path" in logger.errors[0]

    def test_without_a_decompressor_a_damaged_archive_of_a_zst_core_is_kept(
            self, tmp_path, monkeypatch):
        full = _tar_bytes([(_SYSTEMD_CORE + ".zst", _zstd(_elf_core() + _RNG_BYTES))])
        arc = tmp_path / "cores.tar"
        arc.write_bytes(full[:len(full) // 2])
        _no_decompressors(monkeypatch)
        before = _sha(arc)
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert _sha(arc) == before and os.listdir(tmp_path) == ["cores.tar"]
        assert len(logger.errors) == 1 and "could not inspect" in logger.errors[0]

    def test_a_damaged_archive_of_a_decodable_text_core_txt_gz_is_removed(self, tmp_path):
        full = _tar_bytes([("core.txt.gz", gzip.compress(b"notes\n" * 50000, mtime=0)),
                           ("messages", b"x" * 8000)])
        with tarfile.open(fileobj=io.BytesIO(full)) as tar:
            cut = tar.getmember("messages").offset_data + 1000
        arc = tmp_path / "notes.tar"
        arc.write_bytes(full[:cut])                 # damaged inside messages
        logger = _Logger()
        extractor.expand_nested_archives(str(tmp_path), logger)
        assert not arc.exists()
        assert len(logger.errors) == 1 and "removed" in logger.errors[0]

    @pytest.mark.parametrize("order", ["dump-then-text", "text-then-dump"])
    def test_a_second_member_at_the_path_of_a_dump_keeps_the_archive(self, tmp_path, order):
        members = [("vmcore", _makedumpfile()), ("vmcore", b"hello")]
        if order == "text-then-dump":
            members.reverse()
        arc = tmp_path / "crash.tar"
        arc.write_bytes(_tar_bytes([("dmesg.txt", b"text\n")] + members))
        before = _sha(arc)
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 0
        assert _sha(arc) == before and os.listdir(tmp_path) == ["crash.tar"]
        assert len(logger.errors) == 1 and "stored twice" in logger.errors[0], logger.errors

    def test_two_text_copies_at_one_path_still_unpack(self, tmp_path):
        (tmp_path / "logs.tar").write_bytes(_tar_bytes([
            ("messages", b"first\n"), ("messages", b"second\n")]))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert (tmp_path / "logs" / "messages").read_bytes() == b"second\n"
        assert logger.errors == []

    def test_a_tar_holding_core_txt_is_expanded(self, tmp_path):
        (tmp_path / "notes.tar").write_bytes(_tar_bytes([
            ("core.txt", b"core notes 198.51.100.77\n"), ("core.py", b"import os\n")]))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert not (tmp_path / "notes.tar").exists()
        assert (tmp_path / "notes" / "core.txt").is_file()
        assert logger.errors == []

    def test_a_tar_holding_a_text_vmcore_is_expanded(self, tmp_path):
        (tmp_path / "crash.tar").write_bytes(_tar_bytes([
            ("vmcore", b"plain text body 198.51.100.77\n"),
            ("vmcore-dmesg.txt", b"[    0.000000] Linux version\n")]))
        logger = _Logger()
        assert extractor.expand_nested_archives(str(tmp_path), logger) == 1
        assert not (tmp_path / "crash.tar").exists()
        assert (tmp_path / "crash" / "vmcore").is_file()

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


def test_one_archive_suffix_list_for_every_module():
    assert extractor._NESTED_ARCHIVE_SUFFIXES is processor._ARCHIVE_NAME_SUFFIXES
    assert extractor._ARCHIVE_SUFFIXES is processor._TAR_SUFFIXES
