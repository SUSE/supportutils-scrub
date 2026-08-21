"""Archive extraction through a multi-threaded decompressor, and pre-scans
that read in segments.

Extraction ran through Python's single-threaded lzma (22 s p99) while the
repack already used `xz -T0`; the pre-scan read whole multi-hundred-MB logs
into the parent's memory. The streaming extractor must produce the tree the
Python extractor produces, byte for byte, with the same wrapper stripping
and the same traversal guard.
"""

import os
import shutil
import tarfile

import pytest

from supportutils_scrub import extractor
from supportutils_scrub import pipeline
from supportutils_scrub.extractor import extract_tgz_archive


def _tree(root):
    out = {}
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def _wrapped_xz(tmp_path):
    src = tmp_path / "src" / "scc_host_260101"
    (src / "etc").mkdir(parents=True)
    (src / "basic-environment.txt").write_text("x" * 100)
    (src / "etc" / "hosts").write_text("10.0.0.1 host\n")
    arc = tmp_path / "scc_host_260101.txz"
    with tarfile.open(arc, "w:xz") as tar:
        tar.add(src, arcname="scc_host_260101")
    return str(arc)


def _multiroot_xz(tmp_path):
    src = tmp_path / "m"
    for rel in ("spacewalk-debug/httpd-logs/access_log", "conf/rhn.conf"):
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("payload " + rel)
    arc = tmp_path / "bundle.txz"
    with tarfile.open(arc, "w:xz") as tar:
        for rel in ("spacewalk-debug", "conf"):
            tar.add(src / rel, arcname=rel)
    return str(arc)


@pytest.mark.skipif(not shutil.which("xz"), reason="xz binary needed")
@pytest.mark.parametrize("make", [_wrapped_xz, _multiroot_xz])
def test_streaming_extraction_matches_the_python_extractor(tmp_path, monkeypatch, make):
    arc = make(tmp_path)
    py_out = tmp_path / "py"; py_out.mkdir()
    st_out = tmp_path / "st"; st_out.mkdir()
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", False)
    extract_tgz_archive(arc, logger=None, extract_base=str(py_out), mode="r:xz")
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", True)
    used = {}
    real = extractor._decompressor_cmd
    monkeypatch.setattr(extractor, "_decompressor_cmd",
                        lambda mode: used.setdefault("cmd", real(mode)))
    extract_tgz_archive(arc, logger=None, extract_base=str(st_out), mode="r:xz")
    assert used["cmd"] and used["cmd"][0] == "xz"
    assert _tree(st_out) == _tree(py_out)


@pytest.mark.skipif(not shutil.which("xz"), reason="xz binary needed")
def test_streaming_extraction_blocks_traversal(tmp_path, monkeypatch):
    arc = tmp_path / "evil.txz"
    inner = tmp_path / "inner.txt"; inner.write_text("boom")
    with tarfile.open(arc, "w:xz") as tar:
        tar.add(inner, arcname="../../escaped.txt")
        tar.add(inner, arcname="ok/inner.txt")
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", True)
    out = tmp_path / "out"; out.mkdir()
    extract_tgz_archive(str(arc), logger=None, extract_base=str(out), mode="r:xz")
    assert not (tmp_path / "escaped.txt").exists()
    assert not (tmp_path.parent / "escaped.txt").exists()
    assert (out / "evil_scrubbed" / "ok" / "inner.txt").read_text() == "boom"


def test_sid_pre_scan_reads_in_segments_and_still_finds_a_late_sid(tmp_path, monkeypatch):
    log = tmp_path / "pacemaker.log"
    with open(log, "w") as fh:
        fh.write("filler line without anything interesting\n" * 200000)
        fh.write("rsc_SAP_PRD_HDB00 started on node1\n")
    monkeypatch.setattr(pipeline, "_PRESCAN_SEG_BYTES", 1 << 20)
    seen = []
    real = pipeline._iter_line_segments
    monkeypatch.setattr(pipeline, "_iter_line_segments",
                        lambda read, n: (seen.append(n) or real(read, n)))
    sids = pipeline.extract_sids([str(log)], {})
    assert "PRD" in sids
    assert seen and seen[0] == 1 << 20
