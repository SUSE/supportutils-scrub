"""A big compressed log is scrubbed across workers like any other big file.

Measured before: `_is_chunkable` excluded every .gz/.xz/.bz2 by name, so a
multi-GB rotated log was ONE task on ONE core whatever --jobs said; at ~2
MB/s per core a 3.3 GB payload took 27 minutes and was the p99 of every
scrub. The payload is now staged to a plain temporary file, chunked and
scrubbed by the pool, and the result is written back in the format its name
promises (or plain, under --unpacked), validated before it replaces the
original. Nothing of the staging survives.
"""

import logging
import lzma
import os

from supportutils_scrub import parallel
from supportutils_scrub.processor import _SCRUB_INFO_HEADER, compression_magic_ok
from supportutils_scrub.scrub_config import ScrubConfig

from test_parallel_scheduling import _Inline

LINES = 3000


def _payload():
    return "".join(f"2026-08-21T10:00:{i % 60:02d}+02:00 host1 sshd: client "
                   f"203.0.113.{i % 250} and 8.8.8.8 connected\n"
                   for i in range(LINES))


def _case(tmp_path, name="messages-20260820.xz", sibling=False):
    p = tmp_path / name
    with lzma.open(p, "wt") as fh:
        fh.write(_payload())
    if sibling:
        (tmp_path / name[:-3]).write_text("an older plain copy\n")
    return p


def _run(tmp_path, files, monkeypatch, jobs=2, decompress=False):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    monkeypatch.setattr(parallel, "_COMPRESSED_CHUNK_THRESHOLD", 1024)
    monkeypatch.setattr(parallel, "_CHUNK_MIN", 4096)
    _Inline.submitted.clear()
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    return parallel.scrub_in_parallel([str(f) for f in files], {}, cfg, jobs,
                                      logging.getLogger("t"),
                                      decompress=decompress)


def test_big_compressed_log_is_chunked_and_stays_a_valid_stream(tmp_path, monkeypatch):
    p = _case(tmp_path)
    _run(tmp_path, [p], monkeypatch)
    assert _Inline.submitted.count("_scrub_chunk") >= 2
    assert compression_magic_ok(str(p), ".xz")
    with lzma.open(p, "rt") as fh:
        body = fh.read()
    assert body.startswith(_SCRUB_INFO_HEADER)
    assert "8.8.8.8" not in body and body.count("\n") >= LINES
    assert not [f for f in os.listdir(tmp_path) if "scrubplain" in f or "scrubpart" in f]


def test_unpacked_writes_the_chunked_result_plain(tmp_path, monkeypatch):
    p = _case(tmp_path)
    _run(tmp_path, [p], monkeypatch, decompress=True)
    plain = tmp_path / "messages-20260820"
    assert plain.exists() and not p.exists()
    body = plain.read_text()
    assert body.startswith(_SCRUB_INFO_HEADER) and "8.8.8.8" not in body


def test_unpacked_keeps_the_stream_when_a_plain_sibling_exists(tmp_path, monkeypatch):
    p = _case(tmp_path, sibling=True)
    _run(tmp_path, [p], monkeypatch, decompress=True)
    assert p.exists() and compression_magic_ok(str(p), ".xz")
    assert (tmp_path / "messages-20260820").read_text() == "an older plain copy\n"


def test_small_compressed_logs_take_the_streaming_path(tmp_path, monkeypatch):
    p = _case(tmp_path)
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    _Inline.submitted.clear()
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    parallel.scrub_in_parallel([str(p)], {}, cfg, 2, logging.getLogger("t"))
    assert "_scrub_chunk" not in _Inline.submitted      # below the threshold
    with lzma.open(p, "rt") as fh:
        assert "8.8.8.8" not in fh.read()
