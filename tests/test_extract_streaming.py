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


# One decode pass instead of two, and the bzip2 decoder that is parallel on
# any stream. The plain forms below are what the faster ones must equal.

def _plain_common_top_level(members):
    tops = set()
    for m in members:
        name = (m.name or "").strip("/")
        if not name:
            continue
        if "/" not in name:
            if m.isdir():
                tops.add(name)
                continue
            return None
        tops.add(name.split("/", 1)[0])
    return tops.pop() if len(tops) == 1 else None


def _member(name, kind=tarfile.REGTYPE):
    m = tarfile.TarInfo(name)
    m.type = kind
    return m


_SHAPES = {
    "wrapped": [("w", tarfile.DIRTYPE), ("w/a.txt",), ("w/etc/hosts",)],
    "wrapped, no folder entry": [("w/a.txt",), ("w/etc/hosts",)],
    "two roots": [("a/x.txt",), ("b/y.txt",)],
    "root file first": [("readme.txt",), ("w/a.txt",)],
    "root file last": [("w/a.txt",), ("w/b.txt",), ("readme.txt",)],
    "second root last": [("w", tarfile.DIRTYPE), ("w/a.txt",), ("v/b.txt",)],
    "dot slash": [("./w/a.txt",), ("./w/b.txt",)],
    "only folders": [("w", tarfile.DIRTYPE), ("w/sub", tarfile.DIRTYPE)],
    "empty": [],
}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_the_wrapper_decision_is_the_plain_one(shape):
    members = [_member(*m) for m in _SHAPES[shape]]
    assert extractor._common_top_level(members) == _plain_common_top_level(members)


def _archive(tmp_path, shape, mode="w:xz", ext=".txz"):
    arc = tmp_path / ("bundle" + ext)
    with tarfile.open(arc, mode) as tar:
        for m in _SHAPES[shape]:
            info = _member(*m)
            if info.isdir():
                info.mode = 0o755
                tar.addfile(info)
            else:
                data = ("payload of " + m[0]).encode()
                info.size = len(data)
                import io
                tar.addfile(info, io.BytesIO(data))
    return str(arc)


@pytest.mark.skipif(not shutil.which("xz"), reason="xz binary needed")
@pytest.mark.parametrize("shape,passes", [("wrapped", 1), ("wrapped, no folder entry", 1),
                                          ("root file first", 1), ("only folders", 1),
                                          ("two roots", 2), ("root file last", 2),
                                          ("second root last", 2)])
def test_one_decode_pass_unless_the_archive_has_no_single_wrapper(tmp_path, monkeypatch,
                                                                  shape, passes):
    arc = _archive(tmp_path, shape)
    py_out = tmp_path / "py"; py_out.mkdir()
    st_out = tmp_path / "st"; st_out.mkdir()
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", False)
    extract_tgz_archive(arc, logger=None, extract_base=str(py_out), mode="r:xz")
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", True)
    opened = []
    real = extractor._stream_members
    monkeypatch.setattr(extractor, "_stream_members",
                        lambda path, cmd: (opened.append(cmd[0]) or real(path, cmd)))
    extract_tgz_archive(arc, logger=None, extract_base=str(st_out), mode="r:xz")
    assert opened == ["xz"] * passes
    assert _tree(st_out) == _tree(py_out)
    assert sorted(os.listdir(st_out)) == sorted(os.listdir(py_out))


@pytest.mark.parametrize("tool,mode,ext,wmode", [("lbzip2", "r:bz2", ".tbz", "w:bz2"),
                                                 ("pbzip2", "r:bz2", ".tbz", "w:bz2"),
                                                 ("pigz", "r:gz", ".tgz", "w:gz")])
def test_each_external_decompressor_gives_the_python_tree(tmp_path, monkeypatch, tool, mode,
                                                          ext, wmode):
    if not shutil.which(tool):
        pytest.skip(f"{tool} not installed")
    arc = _archive(tmp_path, "wrapped", wmode, ext)
    py_out = tmp_path / "py"; py_out.mkdir()
    st_out = tmp_path / "st"; st_out.mkdir()
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", False)
    extract_tgz_archive(arc, logger=None, extract_base=str(py_out), mode=mode)
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", True)
    which = shutil.which
    monkeypatch.setattr(extractor.shutil, "which", lambda b: which(b) if b == tool else None)
    assert extractor._decompressor_cmd(mode)[0] == tool
    extract_tgz_archive(arc, logger=None, extract_base=str(st_out), mode=mode)
    assert _tree(st_out) == _tree(py_out) and _tree(st_out)


def test_bzip2_archives_prefer_the_decoder_that_is_parallel_on_any_stream(monkeypatch):
    monkeypatch.setattr(extractor.shutil, "which", lambda b: "/usr/bin/" + b)
    assert extractor._decompressor_cmd("r:bz2")[0] == "lbzip2"
    monkeypatch.setattr(extractor.shutil, "which",
                        lambda b: None if b == "lbzip2" else "/usr/bin/" + b)
    assert extractor._decompressor_cmd("r:bz2")[0] == "pbzip2"
    monkeypatch.setattr(extractor.shutil, "which", lambda b: None)
    assert extractor._decompressor_cmd("r:bz2") is None


def _plain_tar(tmp_path):
    arc = tmp_path / "plain.tar"
    with tarfile.open(arc, "w") as tar:
        for name in ("w/a.txt", "w/b.txt", "w/c.txt"):
            info = _member(name)
            info.size = 2000
            import io
            tar.addfile(info, io.BytesIO(b"x" * 2000))
    return str(arc)


def test_a_decoder_that_fails_between_two_members_is_an_error(tmp_path):
    """tarfile takes a stream that ends between two members for the end of
    the archive; only the decoder's exit status says it was cut short."""
    arc = _plain_tar(tmp_path)
    cut = ["sh", "-c", "head -c 2560; exit 3"]          # exactly one member
    with pytest.raises(RuntimeError, match="status 3"):
        assert [m.name for _t, m in extractor._stream_members(arc, cut)] == ["w/a.txt"]
    names = [m.name for _t, m in extractor._stream_members(arc, ["cat"])]
    assert names == ["w/a.txt", "w/b.txt", "w/c.txt"]


def test_a_reader_that_stops_early_raises_nothing(tmp_path):
    arc = _plain_tar(tmp_path)
    stream = extractor._stream_members(arc, ["cat"])
    assert next(stream)[1].name == "w/a.txt"
    stream.close()


def test_a_failed_decoder_falls_back_to_the_python_extractor(tmp_path, monkeypatch):
    arc = _archive(tmp_path, "wrapped")
    monkeypatch.setattr(extractor, "_decompressor_cmd", lambda mode: ["sh", "-c", "exit 5"])
    out = tmp_path / "out"; out.mkdir()
    extract_tgz_archive(arc, logger=None, extract_base=str(out), mode="r:xz")
    assert sorted(_tree(out)) == ["bundle_scrubbed/a.txt", "bundle_scrubbed/etc/hosts"]
