"""Single-file compressed logs (.gz/.xz/.bz2): a name must never lie about its
content. Regression tests for rotated logs coming back as plain text under a
.xz name, which made every consumer that follows the extension skip them."""

import bz2
import gzip
import lzma
import os

import pytest

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub import processor as processor_mod
from supportutils_scrub.processor import (
    FileProcessor, compression_magic_ok, find_format_mismatches,
    read_compressed_text, _SCRUB_INFO_HEADER,
)
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


FORMATS = [('.gz', gzip.open), ('.xz', lzma.open), ('.bz2', bz2.open)]


def _processor(**kw):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
    return FileProcessor(cfg, [IPScrubber(cfg, mappings={})], **kw)


def _scrub(path, **kw):
    logger = _FakeLogger()
    _processor(**kw).process_file(str(path), logger, False)
    return logger


@pytest.mark.parametrize("ext,opener", FORMATS)
def test_round_trip_stays_a_valid_stream(tmp_path, ext, opener):
    path = tmp_path / f"access_log-20260704{ext}"
    with opener(path, 'wt') as f:
        f.write("8.8.8.8 - - [04/Jul/2026] \"GET / HTTP/1.1\" 200\n")

    _scrub(path)

    assert compression_magic_ok(str(path), ext)
    with opener(path, 'rt') as f:
        body = f.read()
    assert "8.8.8.8" not in body
    assert body.startswith("#---")


@pytest.mark.parametrize("ext,opener", FORMATS)
def test_nothing_to_scrub_is_not_rewritten(tmp_path, ext, opener):
    path = tmp_path / f"cobbler.log-20260705{ext}"
    with opener(path, 'wt') as f:
        f.write("started, nothing sensitive here\n")
    before = path.read_bytes()

    _scrub(path)

    assert path.read_bytes() == before


def test_plain_text_under_xz_name_is_scrubbed_and_renamed(tmp_path):
    path = tmp_path / "master-20260705.xz"
    path.write_text("8.8.8.8 salt minion connected\n")

    logger = _scrub(path)

    plain = tmp_path / "master-20260705"
    assert not path.exists()
    assert "8.8.8.8" not in plain.read_text()
    assert any("not a xz stream" in e for e in logger.errors)


def test_misnamed_binary_is_left_alone_and_reported(tmp_path):
    # a zstd stream under an .xz name: not xz, not text either
    path = tmp_path / "logging.xz"
    payload = b"\x28\xb5\x2f\xfd\x00\x58" + bytes(range(200))
    path.write_bytes(payload)

    logger = _scrub(path)

    assert path.read_bytes() == payload
    assert any("nor text" in e for e in logger.errors)
    assert [ext for _p, ext in find_format_mismatches(str(tmp_path))] == ['.xz']


def test_misnamed_file_keeps_its_name_when_the_plain_name_is_taken(tmp_path):
    path = tmp_path / "reposync.log.gz"
    path.write_text("8.8.8.8 repo sync\n")
    (tmp_path / "reposync.log").write_text("other file\n")

    _scrub(path)

    assert "8.8.8.8" not in path.read_text()
    assert (tmp_path / "reposync.log").read_text() == "other file\n"


def test_binary_payload_is_left_alone(tmp_path):
    payload = b"\x00\x01\x02" + b"8.8.8.8" + bytes(range(128, 200))
    path = tmp_path / "core.xz"
    with lzma.open(path, 'wb') as f:
        f.write(payload)

    logger = _scrub(path)

    with lzma.open(path, 'rb') as f:
        assert f.read() == payload
    assert any("not text" in e for e in logger.errors)


@pytest.mark.parametrize("ext,opener", [('.gz', gzip.open), ('.xz', lzma.open)])
def test_truncated_stream_is_salvaged_into_a_valid_stream(tmp_path, ext, opener):
    path = tmp_path / f"ssl_request_log-20260705{ext}"
    with opener(path, 'wt') as f:
        f.write("8.8.8.8 request line\n" * 50000)
    data = path.read_bytes()
    path.write_bytes(data[:len(data) // 2])

    logger = _scrub(path)

    assert compression_magic_ok(str(path), ext)
    with opener(path, 'rt') as f:
        body = f.read()
    assert body.count("\n") > 100          # the readable prefix survived
    assert "8.8.8.8" not in body
    assert any("ends before its end-of-stream" in e for e in logger.errors)


def test_non_utf8_bytes_survive_the_round_trip(tmp_path):
    path = tmp_path / "messages.xz"
    with lzma.open(path, 'wb') as f:
        f.write("caf\xe9 8.8.8.8\n".encode('latin-1'))

    _scrub(path)

    with lzma.open(path, 'rb') as f:
        assert b"\xe9" in f.read()


def test_unpacked_writes_plain_and_drops_the_extension(tmp_path):
    path = tmp_path / "traces.gz"
    with gzip.open(path, 'wt') as f:
        f.write("8.8.8.8 trace\n")

    _scrub(path, decompress=True)

    assert not path.exists()
    assert "8.8.8.8" not in (tmp_path / "traces").read_text()


def test_dry_run_touches_nothing(tmp_path):
    path = tmp_path / "access_log.xz"
    with lzma.open(path, 'wt') as f:
        f.write("8.8.8.8 hit\n")
    misnamed = tmp_path / "plain.xz"
    misnamed.write_text("8.8.8.8 hit\n")
    before = (path.read_bytes(), misnamed.read_bytes())

    logger = _FakeLogger()
    fp = _processor()
    fp.process_file(str(path), logger, False, dry_run=True)
    fp.process_file(str(misnamed), logger, False, dry_run=True)

    assert (path.read_bytes(), misnamed.read_bytes()) == before
    assert fp['ip'].mapping          # mappings still learned


class TestTreePostcondition:
    def test_scrubbed_tree_has_no_format_mismatch(self, tmp_path):
        logs = tmp_path / "logs"
        logs.mkdir()
        for name, opener in (("access_log-20260704.xz", lzma.open),
                             ("localhost_access_log.txt-20260705.xz", lzma.open),
                             ("reposync.log-20260710.gz", gzip.open),
                             ("boot.log.bz2", bz2.open)):
            with opener(logs / name, 'wt') as f:
                f.write("8.8.8.8 - - request\n")
        (logs / "messages").write_text("8.8.8.8 syslog\n")

        fp = _processor()
        logger = _FakeLogger()
        for root, _dirs, files in os.walk(logs):
            for name in files:
                fp.process_file(os.path.join(root, name), logger, False)

        assert find_format_mismatches(str(tmp_path)) == []

    def test_mismatch_is_detected(self, tmp_path):
        (tmp_path / "access_log.xz").write_text("plain text\n")
        with lzma.open(tmp_path / "good.xz", 'wt') as f:
            f.write("real stream\n")

        bad = find_format_mismatches(str(tmp_path))

        assert [(os.path.basename(p), ext) for p, ext in bad] == [("access_log.xz", ".xz")]

    def test_tar_archives_are_not_treated_as_single_file_logs(self, tmp_path):
        # a .tar.gz payload is a tar stream, not text: not our business here
        (tmp_path / "spacewalk-debug.tar.bz2").write_bytes(b"BZh9 whatever")
        (tmp_path / "bundle.tgz").write_bytes(b"not gzip at all")

        assert find_format_mismatches(str(tmp_path)) == []


class TestSegmentedStreaming:
    """Payloads larger than one segment stream through the scrubbers in
    line-aligned pieces (a 120 MB salt .xz decompressing to 3.3 GB once took
    a worker to 17 GB). Segment size is shrunk here so a few KB exercises the
    multi-segment path."""

    LINES = "".join(f"198.51.{i % 4}.{(i % 250) + 1} - - \"GET /page/{i}\"\n"
                    for i in range(300))

    @pytest.fixture(autouse=True)
    def _small_segments(self, monkeypatch):
        monkeypatch.setattr(processor_mod, '_SEG_BYTES', 256)

    @pytest.mark.parametrize("ext,opener", FORMATS)
    def test_round_trip_matches_the_whole_text_scrub(self, tmp_path, ext, opener):
        path = tmp_path / f"access_log{ext}"
        with opener(path, 'wt') as f:
            f.write(self.LINES)

        _scrub(path)

        assert compression_magic_ok(str(path), ext)
        with opener(path, 'rt') as f:
            body = f.read()
        assert "198.51." not in body
        expected = _processor()._scrub_content(self.LINES, "access_log",
                                               _FakeLogger())
        assert body == _SCRUB_INFO_HEADER + expected

    @pytest.mark.parametrize("ext,opener", FORMATS)
    def test_nothing_to_scrub_is_not_rewritten(self, tmp_path, ext, opener):
        path = tmp_path / f"quiet.log{ext}"
        with opener(path, 'wt') as f:
            f.write("nothing sensitive on this line\n" * 200)
        before = path.read_bytes()

        _scrub(path)

        assert path.read_bytes() == before

    def test_ip_prelearn_gives_whole_file_semantics(self, tmp_path):
        # A bare IP in the FIRST segment must map by the subnet declared only
        # in the LAST segment — the IP learn pre-pass is what makes
        # segment-wise replacement match whole-text two-pass semantics.
        # /16 on purpose: a /24 would coincide with default_infer_prefixlen
        # and pass even without the pre-learn.
        content = ("client 203.0.113.77 connected\n"
                   + "nothing to see on this line\n" * 200
                   + "route 203.0.0.0/16 via gateway\n")
        path = tmp_path / "net.xz"
        with lzma.open(path, 'wt') as f:
            f.write(content)

        _scrub(path)

        with lzma.open(path, 'rt') as f:
            body = f.read()
        expected = _processor()._scrub_content(content, "net", _FakeLogger())
        assert body == _SCRUB_INFO_HEADER + expected

    def test_single_line_longer_than_a_segment(self, tmp_path):
        line = "8.8.8.8 " + "x" * 5000 + "\n"
        path = tmp_path / "oneline.xz"
        with lzma.open(path, 'wt') as f:
            f.write(line)

        _scrub(path)

        with lzma.open(path, 'rt') as f:
            body = f.read()
        assert "8.8.8.8" not in body
        assert "x" * 5000 in body

    def test_dry_run_learns_without_writing(self, tmp_path):
        path = tmp_path / "big.xz"
        with lzma.open(path, 'wt') as f:
            f.write(self.LINES)
        before = path.read_bytes()

        fp = _processor()
        fp.process_file(str(path), _FakeLogger(), False, dry_run=True)

        assert path.read_bytes() == before
        assert fp['ip'].mapping

    def test_unpacked_writes_plain_with_header(self, tmp_path):
        path = tmp_path / "big.gz"
        with gzip.open(path, 'wt') as f:
            f.write(self.LINES)

        _scrub(path, decompress=True)

        assert not path.exists()
        body = (tmp_path / "big").read_text()
        assert body.startswith("#---")
        assert "198.51." not in body

    @pytest.mark.parametrize("ext,opener", [('.gz', gzip.open), ('.xz', lzma.open)])
    def test_truncated_stream_is_still_salvaged(self, tmp_path, ext, opener):
        path = tmp_path / f"cut{ext}"
        with opener(path, 'wt') as f:
            f.write("8.8.8.8 request line\n" * 50000)
        data = path.read_bytes()
        path.write_bytes(data[:len(data) // 2])

        logger = _scrub(path)

        assert compression_magic_ok(str(path), ext)
        with opener(path, 'rt') as f:
            body = f.read()
        assert body.count("\n") > 100
        assert "8.8.8.8" not in body
        assert any("ends before its end-of-stream" in e for e in logger.errors)

    def test_no_scrubtmp_left_behind(self, tmp_path):
        path = tmp_path / "big.xz"
        with lzma.open(path, 'wt') as f:
            f.write(self.LINES)

        _scrub(path)

        assert [p.name for p in tmp_path.iterdir()] == ["big.xz"]


class TestMemoryErrorIsNotTruncation:
    def test_read_compressed_text_reraises(self, tmp_path):
        path = tmp_path / "a.xz"
        with lzma.open(path, 'wt') as f:
            f.write("healthy stream\n")

        class _Boom:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                raise MemoryError

        with pytest.raises(MemoryError):
            read_compressed_text(str(path), '.xz', lambda p, m: _Boom())


class TestReadCompressedText:
    def test_status_ok(self, tmp_path):
        path = tmp_path / "a.xz"
        with lzma.open(path, 'wt') as f:
            f.write("hello\n")
        assert read_compressed_text(str(path), '.xz', lzma.open) == ("hello\n", 'ok')

    def test_status_not_a_stream(self, tmp_path):
        path = tmp_path / "a.xz"
        path.write_text("hello\n")
        assert read_compressed_text(str(path), '.xz', lzma.open) == (None, 'not-a-stream')

    def test_status_binary(self, tmp_path):
        path = tmp_path / "a.gz"
        with gzip.open(path, 'wb') as f:
            f.write(b"\x00\x01\x02")
        assert read_compressed_text(str(path), '.gz', gzip.open) == (None, 'binary')

    def test_empty_file_is_not_a_stream(self, tmp_path):
        path = tmp_path / "a.bz2"
        path.write_bytes(b"")
        assert read_compressed_text(str(path), '.bz2', bz2.open) == (None, 'not-a-stream')
