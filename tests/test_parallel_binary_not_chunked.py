"""Under --jobs, a big binary file is never split and scrubbed as text.

The pool splits every file above the chunking threshold (32 MB) at line
boundaries and scrubs the pieces as text in the workers; that path never
went through process_file, so it never probed for binary content. A dump
part that carries no header of its own, a big packet capture, a database
file: each came back decoded with errors='ignore', rewritten as text and
banner-prefixed. A file whose head holds NUL bytes now stays whole and goes
to process_file, which leaves a binary unchanged and reports it.

No em dashes, by project convention.
"""

import hashlib
import os
from types import SimpleNamespace

from supportutils_scrub import parallel
from supportutils_scrub.modes import folder as folder_mode
from supportutils_scrub.scrub_config import ScrubConfig


class _Logger:
    def __init__(self):
        self.infos, self.errors = [], []

    def info(self, msg):
        self.infos.append(msg)

    def warning(self, msg):
        pass

    def error(self, msg):
        self.errors.append(msg)


_SIZE = 40 * 1024 * 1024
_BAIT = b"peer 198.51.100.77 said hello\n"
#: a line the scrubbers pass over quickly, so 40 MB stays a few seconds
_LINE = b"a" * 160 + b"\n"


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _binary_part(path):
    """40 MB, sparse: NUL bytes in the head, text bait at both ends (a text
    scrub would rewrite it) and a hole in between."""
    with open(path, "wb") as f:
        f.write(b"\x00\x01\x02\x03" + _BAIT)
        f.seek(_SIZE - len(_BAIT))
        f.write(_BAIT)


def _text_log(path):
    """40 MB of plain text with the bait at both ends."""
    body = _LINE * ((_SIZE // len(_LINE)) + 1)
    with open(path, "wb") as f:
        f.write(_BAIT + body[:_SIZE - 2 * len(_BAIT)] + _BAIT)


def _args(src, tmp_path):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    return SimpleNamespace(verbose=False, supportconfig_path=[str(src)],
                           mappings=None, keywords=None, keyword_file=None,
                           domain=None, username=None, hostname=None,
                           unpacked=False, no_mappings=False, quiet=True,
                           jobs=2, report=False, report_file=None, profile=False,
                           verify=False, encrypt_mappings=False, secure_tmp=None,
                           config=None, _preloaded_config=cfg, _enc_passphrase=None)


def _run(tmp_path, capsys, monkeypatch, make):
    """Folder mode with --jobs 2 over one 40 MB file and a small note (the
    pool is used only for more than one file). Returns (src, out, chunked)."""
    src = tmp_path / "case_tree"
    src.mkdir()
    name = make(src)
    (src / "notes.txt").write_text("contact 198.51.100.77\n")
    chunked = []
    real_bounds = parallel._chunk_bounds
    monkeypatch.setattr(parallel, "_chunk_bounds",
                        lambda p, jobs: chunked.append(os.path.basename(p))
                        or real_bounds(p, jobs))
    folder_mode.run_folder_mode(_args(src, tmp_path), _Logger())
    out = capsys.readouterr().out.strip().splitlines()[-1]
    return src, os.path.join(out, name), chunked


def test_a_big_binary_is_never_chunked_and_stays_byte_identical(
        tmp_path, capsys, monkeypatch):
    def make(src):
        _binary_part(src / "split.part2")
        return "split.part2"
    src, part, chunked = _run(tmp_path, capsys, monkeypatch, make)
    assert "split.part2" not in chunked
    assert os.path.getsize(part) == _SIZE
    assert _sha(part) == _sha(src / "split.part2"), "the binary was rewritten"


def test_a_big_text_log_is_still_chunked_and_scrubbed(tmp_path, capsys, monkeypatch):
    def make(src):
        _text_log(src / "messages")
        return "messages"
    _src, log, chunked = _run(tmp_path, capsys, monkeypatch, make)
    assert "messages" in chunked, chunked
    with open(log, "rb") as f:
        head = f.read(4096)
        f.seek(-4096, os.SEEK_END)
        tail = f.read()
    assert b"198.51.100.77" not in head and b"198.51.100.77" not in tail
    assert b"a" * 160 in head


def test_the_rule_itself(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "_CHUNK_THRESHOLD", 1024)
    binary = tmp_path / "db.sqlite"
    binary.write_bytes(b"SQLite format 3\x00" + b"x\n" * 2000)
    text = tmp_path / "big.log"
    text.write_bytes(b"a log line\n" * 400)
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 10)
    assert parallel._is_chunkable(str(binary)) is False
    assert parallel._is_chunkable(str(text)) is True
    assert parallel._is_chunkable(str(small)) is False
