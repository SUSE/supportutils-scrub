"""Journal files and login records leave the scrubbed output.

They are binary, so the scrub cannot rewrite them, and they hold the very
names and addresses it removes from every text file beside them. Like
binary sa data they are removed; everything else binary is still left as it
is and reported.
"""

import lzma
import os

import pytest

from supportutils_scrub.pipeline import build_chain
from supportutils_scrub.processor import FileProcessor, is_private_binary
from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger

JOURNAL = b'LPKSHHRH' + b'\x00' * 16 + b'\x01\x02\x00_HOSTNAME=realnode01\x00_UID=1000\x00' * 40
RECORDS = (b'\x07\x00\x00\x00' + b'\x11\x22\x00\x00' + b'pts/0' + b'\x00' * 27 + b'ts/0'
           + b'jdoe' + b'\x00' * 28 + b'203.0.113.77' + b'\x00' * 244) * 6


def _tree(tmp_path):
    d = tmp_path / 'var' / 'log'
    (d / 'journal' / 'abc').mkdir(parents=True)
    files = {
        'journal/abc/system.journal': JOURNAL,
        'journal/abc/user-1000@x-1.journal~': JOURNAL,
        'journal/abc/user-1000_scrubbed.journal': JOURNAL,     # named by an older run
        'wtmp': RECORDS, 'btmp': RECORDS, 'utmp': RECORDS,
        'wtmp-20260804.xz': lzma.compress(RECORDS),
        'wtmp.1': RECORDS,
        'empty-btmp/btmp': b'',
        'wtmp.txt': b'this is text about wtmp, 203.0.113.77\n',
        'lastlog': b'\x00' * 2000 + b'pts/1\x00' + b'\x00' * 500 + b'\x01\x00\x02\x00\x03\x00\x04\x00\x05',
        'data.bin': b'\x00\x01\x02\x03\x00\x05\x00\x07\x00' * 300,
        'messages': b'kernel: eth0 up 203.0.113.77\n',
    }
    for rel, data in files.items():
        path = d / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return d, files


def _all_files(d):
    return sorted(os.path.relpath(os.path.join(root, f), str(d))
                  for root, _dirs, fs in os.walk(str(d)) for f in fs)


GONE = {'journal/abc/system.journal', 'journal/abc/user-1000@x-1.journal~',
        'journal/abc/user-1000_scrubbed.journal', 'wtmp', 'btmp', 'utmp',
        'wtmp-20260804.xz', 'wtmp.1', 'lastlog'}


def test_what_counts_as_a_journal_or_a_login_record():
    assert is_private_binary(JOURNAL, 'anything.bin')
    assert is_private_binary(RECORDS, 'wtmp') and is_private_binary(RECORDS, 'btmp-20260101')
    assert is_private_binary(RECORDS, 'utmp.1') and is_private_binary(RECORDS, 'wtmp_scrubbed')
    assert is_private_binary(b'\x00' * 4096, 'lastlog') and is_private_binary(RECORDS, 'lastlog.1')
    assert not is_private_binary(RECORDS, 'wtmpfile') and not is_private_binary(RECORDS, 'data.bin')
    assert not is_private_binary(b'plain text\n', 'wtmp') and not is_private_binary(b'', 'btmp')


def test_journals_and_login_records_are_removed_one_file_at_a_time(tmp_path):
    d, files = _tree(tmp_path)
    cfg = ScrubConfig()
    fp = FileProcessor(cfg, build_chain({}, cfg))
    logger = SupportutilsScrubLogger(log_level="normal")
    before = _all_files(d)
    for rel in before:                              # the dry run removes nothing
        assert fp.process_file(str(d / rel), logger, False, dry_run=True)
    assert _all_files(d) == before
    for rel in before:
        assert fp.process_file(str(d / rel), logger, False), rel
    assert set(before) - set(_all_files(d)) == GONE
    # what is left: text scrubbed, other binaries byte for byte
    assert b'203.0.113.77' not in (d / 'wtmp.txt').read_bytes()
    assert b'203.0.113.77' not in (d / 'messages').read_bytes()
    assert (d / 'data.bin').read_bytes() == files['data.bin']
    assert (d / 'empty-btmp' / 'btmp').read_bytes() == b''


def test_journals_and_login_records_are_removed_under_jobs(tmp_path):
    from supportutils_scrub.parallel import scrub_in_parallel
    d, files = _tree(tmp_path)
    cfg = ScrubConfig()
    before = _all_files(d)
    failed = []
    scrub_in_parallel([str(d / rel) for rel in before], {}, cfg, 3,
                      SupportutilsScrubLogger(log_level="normal"), failed=failed)
    assert not failed
    assert set(before) - set(_all_files(d)) == GONE
    assert (d / 'data.bin').read_bytes() == files['data.bin']
    assert b'203.0.113.77' not in (d / 'messages').read_bytes()
