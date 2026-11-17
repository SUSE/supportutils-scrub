"""processor/extractor review findings: text that only looks odd is still
scrubbed, what is written back keeps its bytes, and what an archive carries
beside regular files never stops or leaks the run."""

import gzip
import io
import lzma
import os
import shutil
import subprocess
import tarfile

import pytest

from supportutils_scrub import extractor
from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor, is_binary_head
from supportutils_scrub.ip_scrubber import IPScrubber

IP = b"198.51.100.77"


class _Logger:
    def __init__(self):
        self.infos, self.errors = [], []

    def info(self, msg):
        self.infos.append(msg)

    def warning(self, msg):
        self.errors.append(msg)

    def error(self, msg):
        self.errors.append(msg)


def _fp(**kw):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
    return FileProcessor(cfg, [IPScrubber(cfg, mappings={})], **kw)


def _scrub(path, **kw):
    logger = _Logger()
    ok = _fp(**kw).process_file(str(path), logger, False)
    return ok, logger


def test_zero_blocks_in_a_log_do_not_make_it_binary(tmp_path):
    body = b"boot " + IP + b"\n" + b"\x00" * 4096 + b"\nresumed " + IP + b"\n"
    plain = tmp_path / "boot.log"
    plain.write_bytes(body)
    packed = tmp_path / "messages.gz"
    packed.write_bytes(gzip.compress(body))

    assert _scrub(plain)[0] and _scrub(packed)[0]

    for out in (plain.read_bytes(), gzip.decompress(packed.read_bytes())):
        assert IP not in out
        assert b"\x00" * 4096 in out


def test_binary_heads_are_still_binary():
    assert is_binary_head(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"x" * 100)
    assert is_binary_head(b"\x00\x01\x02\x03peer 198.51.100.77\n" + b"\x00" * 1000)
    assert is_binary_head(b"\xff\xfeh\x00i\x00")
    assert not is_binary_head(b"plain text\n" + b"\x00" * 1000 + b"more\n")


def test_a_plain_rewrite_keeps_latin1_bytes_and_line_ends(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(b"caf\xe9 " + IP + b"\r\nprogress 10%\r20%\r\n")

    _scrub(path)

    out = path.read_bytes()
    assert IP not in out
    assert out.endswith(b"\r\nprogress 10%\r20%\r\n") and b"caf\xe9 " in out


def test_sar_xz_keeps_its_name_and_never_touches_a_plain_sibling(tmp_path):
    path = tmp_path / "sar20250101.xz"
    path.write_bytes(lzma.compress(b"Linux 6.4 (h) 01/01/25\n" + b"rest " + IP + b"\n"))
    sibling = tmp_path / "sar20250101"
    sibling.write_bytes(b"PLAIN SIBLING\n")

    assert _scrub(path)[0]

    assert sibling.read_bytes() == b"PLAIN SIBLING\n"
    out = lzma.decompress(path.read_bytes())
    assert IP not in out and b"rest " in out


class _Boom:
    name = "boom"
    skip_files = ()

    def __init__(self, exc):
        self.exc = exc

    def scrub(self, text):
        raise self.exc


def test_a_failing_scrubber_leaves_the_file_unwritten_and_returns_false(tmp_path):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True)
    for exc in (MemoryError(), ValueError("bug")):
        for name, data in (("messages", IP + b"\n"), ("big.log.gz", gzip.compress(IP + b"\n"))):
            path = tmp_path / name
            path.write_bytes(data)
            fp = FileProcessor(cfg, [IPScrubber(cfg, mappings={}), _Boom(exc)])
            assert fp.process_file(str(path), _Logger(), False) is False
            assert path.read_bytes() == data


def test_gzip_header_never_keeps_the_original_name(tmp_path):
    for body in (b"nothing to scrub\n", IP + b"\n"):
        buf = io.BytesIO()
        with gzip.GzipFile(filename="db01.example.com_boot.log", mode="wb", fileobj=buf) as g:
            g.write(body)
        path = tmp_path / "host-1_boot.log.gz"
        path.write_bytes(buf.getvalue())
        os.chmod(path, 0o600)

        assert _scrub(path)[0]

        data = path.read_bytes()
        assert data[3] & 0x18 == 0
        assert b"example.com" not in data
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert gzip.decompress(data).endswith(body if IP not in body else b"\n")


def test_salvage_keeps_every_complete_member_before_the_damage(tmp_path):
    import bz2
    from supportutils_scrub.processor import _salvage_decompressed
    for ext, comp in ((".gz", gzip.compress), (".bz2", bz2.compress)):
        third = comp(b"third\n" * 100)
        path = tmp_path / ("multi.log" + ext)
        path.write_bytes(comp(b"first\n") + comp(b"second\n") + third[:len(third) // 2])
        assert _salvage_decompressed(str(path), ext).startswith(b"first\nsecond\n")


def _add(tar, name, data=b"", **kw):
    info = tarfile.TarInfo(name)
    for k, v in kw.items():
        setattr(info, k, v)
    if info.isreg():
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    else:
        tar.addfile(info)


@pytest.mark.parametrize("external", [True, False])
def test_top_level_extract_skips_fifos_copies_hardlinks_and_drops_modes(
        tmp_path, monkeypatch, external):
    monkeypatch.setattr(extractor, "_EXTERNAL_DECOMPRESS", external)
    arc = tmp_path / "scc_x.txz"
    with tarfile.open(arc, "w:xz") as t:
        _add(t, "scc_x", type=tarfile.DIRTYPE, mode=0o555)
        _add(t, "scc_x/net.txt", IP + b"\n", mode=0o444)
        _add(t, "scc_x/fifo", type=tarfile.FIFOTYPE, mode=0o644)
        _add(t, "scc_x/hl.txt", type=tarfile.LNKTYPE, linkname="scc_x/net.txt")
    logger = _Logger()

    files, folder = extractor.extract_tgz_archive(str(arc), logger, mode="r:xz")

    assert sorted(os.path.basename(f) for f in files) == ["hl.txt", "net.txt"]
    assert any("1 archive member" in m for m in logger.errors)
    for f in files:
        assert _scrub(f)[0]
        assert IP not in open(f, "rb").read()


def test_process_file_leaves_a_fifo_alone(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert _scrub(fifo)[0]


def test_nested_read_only_dir_and_tar_zst_are_unpacked(tmp_path):
    if not shutil.which("zstd"):
        pytest.skip("no zstd tool here")
    with tarfile.open(tmp_path / "bundle.tar.gz", "w:gz") as t:
        _add(t, "conf", type=tarfile.DIRTYPE, mode=0o555)
        _add(t, "conf/hosts", IP + b" db01.example.com\n", mode=0o644)
    with tarfile.open(tmp_path / "plain.tar", "w") as t:
        _add(t, "inner/net.txt", IP + b"\n", mode=0o644)
    subprocess.run(["zstd", "-q", "--rm", str(tmp_path / "plain.tar"),
                    "-o", str(tmp_path / "logs.tar.zst")], check=True)

    assert extractor.expand_nested_archives(str(tmp_path), _Logger()) == 2

    assert sorted(os.listdir(tmp_path)) == ["bundle", "logs"]
    assert (tmp_path / "logs" / "inner" / "net.txt").read_bytes() == IP + b"\n"
    assert _scrub(tmp_path / "bundle" / "conf" / "hosts")[0]


def test_nested_tar_zst_without_a_decompressor_is_removed(tmp_path, monkeypatch):
    from supportutils_scrub import processor
    monkeypatch.setattr(processor.shutil, "which", lambda name: None)
    monkeypatch.setattr(extractor, "_zstd_open", processor._ZstdPipe)
    (tmp_path / "logs.tar.zst").write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 32)
    logger = _Logger()

    assert extractor.expand_nested_archives(str(tmp_path), logger) == 0

    assert os.listdir(tmp_path) == []
    assert any("logs.tar.zst" in m and "removed" in m for m in logger.errors)


def test_a_single_zst_log_is_scrubbed_and_stays_zst(tmp_path):
    if not shutil.which("zstd"):
        pytest.skip("no zstd tool here")
    path = tmp_path / "boot.log.zst"
    path.write_bytes(subprocess.run(["zstd", "-qc"], input=IP + b"\n",
                                    stdout=subprocess.PIPE, check=True).stdout)

    assert _scrub(path)[0]

    out = subprocess.run(["zstd", "-dqc", str(path)], stdout=subprocess.PIPE,
                         check=True).stdout
    assert IP not in out and out.endswith(b"\n")


def test_create_txz_leaves_nothing_on_failure_and_records_no_owner(tmp_path):
    src = tmp_path / "scc_y_scrubbed"
    src.mkdir()
    (src / "a.txt").write_text("a\n")
    out = tmp_path / "scc_y_scrubbed.txz"

    extractor.create_txz(str(src), str(out))
    with tarfile.open(out) as t:
        assert {(m.uid, m.gid, m.uname, m.gname) for m in t.getmembers()} == {(0, 0, "", "")}

    out.unlink()
    with pytest.raises(OSError):
        extractor.create_txz(str(src / "missing"), str(out))
    assert not out.exists() and not (tmp_path / "scc_y_scrubbed.txz.tmp").exists()


def test_safe_path_allows_names_that_only_start_with_dots(tmp_path):
    assert extractor._is_safe_path(str(tmp_path), "..foo")
    assert not extractor._is_safe_path(str(tmp_path), "../foo")
