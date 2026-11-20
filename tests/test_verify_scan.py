"""The verify scan: fast, and blind to nothing.

Two things are held here. The piece-wise scan must report exactly what the
line-by-line scan reports (same findings, same order). And a real value must
be found wherever it is left: in a plain file, a compressed one, a tar still
packed in the tree, a binary file, a file or member name, and across every
boundary the scan cuts its input at.
"""

import bz2
import gzip
import io
import json
import lzma
import os
import random
import subprocess
import sys
import tarfile

import pytest

from supportutils_scrub import fastsub, verify as V
from supportutils_scrub.scrub_config import ScrubConfig

MAPS = {
    'ip': {'203.0.113.77': '198.16.0.5', '8.8.4.4': '198.16.0.6', '45.33.1.2': '198.16.0.7'},
    'ipv6': {'2a00:1450:4001:81b::200e': '2001:db8::1'},
    'mac': {'52:54:00:ab:cd:ef': '00:1A:2B:00:00:01'},
    'domain': {'corp.example-bank.com': 'dom1.aaa', 'example-bank.com': 'dom2.aaa'},
    'hostname': {'realnode01': 'host-1', 'DBsrv': 'host-2'},
    'user': {'jdoe': 'user1', 'a-bob': 'user2', 'bob': 'user3', 'svc.backup': 'user4'},
    'keyword': {'projectx': 'keyword_1'},
    'serial': {'CZ1234ABCD': 'SERIAL_0'},
    'sid': {'PRD': 'HA1'},
    'ldap_dn': {'John Smith': 'cn_1', 'Finance': 'ou_1'},
    'email': dict({'user%d@corp.example-bank.com' % i: 'email_%d@scrubbed.local' % i
                   for i in range(40)},
                  **{'a.b@x.example-bank.com': 'email_90@scrubbed.local',
                     'boss@example-bank.com': 'email_91@scrubbed.local',
                     # one address is the beginning of another
                     'boss@example-bank.co': 'email_92@scrubbed.local'}),
    'password': {'S3cr3tValue9': 'scrubbed_pass_1'},
    'auth': {'loginname77': 'SCRUBBED_LOGIN_1'},
    'cloud_token': {'AKIAIOSFODNN7EXAMPLE': 'SCRUBBED_AWS_KEY_1'},
}

LINES = [
    'addr 203.0.113.77 up', 'dns 8.8.4.4.', 'range 45.33.1.2-45.33.1.9', 'version 8.8.4.4',
    'v 1.2.3.4', 'pkg-8.8.4.4-1.x86_64', 'ptr 77.113.0.203.in-addr.arpa', 'fake 198.16.0.5',
    'v6 2A00:1450:4001:81B::200E/64', 'mac 52:54:00:AB:CD:EF', 'mac 52-54-00-ab-cd-ef',
    'MAC=52:54:00:ab:cd:ef:00:11:22:33:44:55:08:00', 'fake 00:1a:2b:00:00:01',
    'host REALNODE01.corp.example-bank.com', 'x_realnode01_y', 'dbsrv!', 'realnode012',
    'user jdoe logged in', 'xjdoe', 'a-bob and bob', 'Bob', 'svc.backup', '/home/jdoe_old',
    'ProjectX rocks', 'serial cz1234abcd', 'SAPPRD_00 prdadm PRD PRDX', 'john smith',
    'CN=John Smith,OU=Finance,DC=corp,DC=example-bank,DC=com', 'cn=cn_1,ou=ou_1,dc=dom1,dc=aaa',
    'mail User7@Corp.Example-Bank.com.', 'xxuser39@corp.example-bank.comyy', 'a.b@x.example-bank.com',
    'boss@example-bank.com user1@corp.example-bank.com', 'someone@else.org', 'x@y.service',
    'email_3@scrubbed.local', 'krb jdoe@CORP.EXAMPLE-BANK.COM',
    'password=S3cr3tValue9', 'password=hunter2', 'token: 3000', 'api_key: scrubbed_pass_2',
    'key AKIAIOSFODNN7EXAMPLE', 'loginname77', 'Authorization: Basic dXNlcjpwYXNz',
    '-----BEGIN RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEA', 'SCRUBBED_KEY_0123456789ab',
    'bindpw topsecret1', 'nothing here', '', 'date 2026-01-29-11-50-20 x',
]
FILLER = 'Jan 01 12:00:00 node kernel: [  123.456] usb 1-1: nothing of note in this line at all\n'


def _ctx(maps=MAPS, identity=('ident-token-99',), **kw):
    ctx = {'folder_path': '.', 'mappings': maps, 'check_allowlist': True, 'check_mac': True,
           'check_patterns': True, 'safe_nets': V._build_safe_ipv4_nets(False, True),
           'identity_lower': {t: t.lower() for t in identity}}
    ctx.update(kw)
    return V._prepare_ctx(ctx)


def _texts(seed=7, n=80):
    dense = '\n'.join(LINES) + '\n'
    sparse = ''.join(FILLER * 30 + line + '\n' for line in LINES) + FILLER * 30
    yield 'dense', dense
    yield 'dense-upper', dense.upper()
    yield 'sparse', sparse
    yield 'no-final-newline', sparse.rstrip('\n')
    yield 'non-ascii', sparse.replace('nothing', 'n\u00f6thing \u20ac', 5)
    yield 'irregular', sparse.replace('usb', 'u\u017fb \u212a \u0130 \u0131', 5) + 'J\u0131DOE jdoe \u212aey=x\n'
    yield 'identity', sparse + 'the Ident-Token-99 twice ident-token-99\n'
    yield 'empty', ''
    yield 'address-first', 'boss@example-bank.com starts the text\n' + FILLER * 20
    rnd = random.Random(seed)
    import re
    words = [w for line in LINES for w in re.split(r'(\s+|[=:,@/])', line) if w]
    words += ['\n', '\n', ' ', '.', '-', '_', '@', ':', '=', 'x', '9']
    for i in range(n):
        text = ''.join(rnd.choice(words) + rnd.choice(['', '', ' ', '\n'])
                       for _ in range(rnd.randint(5, 150)))
        if i % 3 == 0:
            text = FILLER * rnd.randint(10, 40) + text + '\n' + FILLER * rnd.randint(10, 40)
        yield 'random-%d' % i, text


def _in_order(items):
    """(line, category, value) in the order the findings come out."""
    return [it[1:] for it in sorted(items, key=lambda it: it[0])]


def test_the_piece_scan_reports_what_the_line_by_line_scan_reports():
    ctx = _ctx()
    for label, text in _texts():
        for check_mac in (True, False):
            fast = V._scan_piece(text, ctx, 5, None, check_mac)
            fastsub.forget()
            slow = V._scan_piece_by_line(text, ctx, 5, None, check_mac)
            assert _in_order(fast[0]) == _in_order(slow[0]), label
            assert fast[1:] == slow[1:], label


def test_each_term_list_is_found_as_its_one_pattern_finds_it():
    ctx = _ctx()
    assert any(t._at is not None for t in ctx['matchers'])       # the address list
    for label, text in _texts(seed=8):
        low = fastsub._fold(text)
        for terms in ctx['matchers']:
            assert terms.find(text, low) == [m.span() for m in terms.rx.finditer(text)], \
                (label, terms.mode)


def test_a_term_ending_in_a_line_end_is_matched_line_by_line():
    maps = dict(MAPS, password={'tail-secret\n': 'scrubbed_pass_9', 'two\nlines': 'x'})
    ctx = _ctx(maps)
    text = FILLER * 3 + 'key tail-secret\nkey tail-secretx\ntwo\nlines\n'
    fast = V._scan_piece(text, ctx, 0, None, True)
    slow = V._scan_piece_by_line(text, ctx, 0, None, True)
    assert _in_order(fast[0]) == _in_order(slow[0])
    assert [it[3] for it in fast[0] if it[2] == 'password'] == ['tail-secret\n']


def _verify(path, maps=MAPS, jobs=1, **kw):
    return V.verify_scrubbed_folder(str(path), maps, config=ScrubConfig(), jobs=jobs, **kw)


def _cats(findings):
    return sorted({(f['file'], f['category']) for f in findings})


LEAK = b'clean line\nuser jdoe logged in from 203.0.113.77\nclean line\n'


def _tar_bytes(members, mode='w'):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_a_real_value_is_found_wherever_it_is_left(tmp_path):
    d = tmp_path / 'tree'
    (d / 'sub').mkdir(parents=True)
    (d / 'plain.txt').write_bytes(LEAK)
    (d / 'log.gz').write_bytes(gzip.compress(LEAK))
    (d / 'log.xz').write_bytes(lzma.compress(LEAK))
    (d / 'log.bz2').write_bytes(bz2.compress(LEAK))
    (d / 'wtmp').write_bytes(b'\x00' * 300 + b'jdoe\x00\x00pts/0\x00203.0.113.77\x00' + b'\x07\x00' * 200)
    (d / 'wtmp.xz').write_bytes(lzma.compress(b'\x00' * 300 + b'jdoe\x00\x00203.0.113.77\x00' + b'\x07\x00' * 99))
    (d / 'inner.tar').write_bytes(_tar_bytes([('a/plain.txt', LEAK), ('a/log.gz', gzip.compress(LEAK))]))
    (d / 'inner.tgz').write_bytes(_tar_bytes([('b/plain.txt', LEAK)], 'w:gz'))
    (d / 'inner.txz').write_bytes(_tar_bytes(
        [('c/deep.tar', _tar_bytes([('d/plain.txt', LEAK)])), ('c/wtmp', b'\x00\x01\x00jdoe\x00' * 50),
         ('realnode01/x.txt', b'fine\n')], 'w:xz'))
    (d / 'sub' / 'realnode01.txt').write_bytes(b'fine\n')
    (d / 'jdoe').mkdir()
    (d / 'clean.txt').write_bytes(b'user user1 from 198.16.0.5\n')
    found = _verify(d)
    got = _cats(found)
    for where in ('plain.txt', 'log.gz', 'log.xz', 'log.bz2', 'inner.tar!/a/plain.txt',
                  'inner.tar!/a/log.gz', 'inner.tgz!/b/plain.txt',
                  'inner.txz!/c/deep.tar!/d/plain.txt'):
        assert (where, 'username') in got and (where, 'IPv4 address') in got, where
    for where in ('wtmp', 'wtmp.xz'):
        assert (where, 'username in binary file') in got, where
        assert (where, 'IPv4 address in binary file') in got, where
    assert ('inner.txz!/c/wtmp', 'username in binary file') in got
    assert ('sub/realnode01.txt', 'hostname in file name') in got
    assert ('jdoe', 'username in file name') in got
    assert ('inner.txz!/realnode01/x.txt', 'hostname in file name') in got
    assert not [f for f in found if f['file'] == 'clean.txt']
    binary = [f for f in found if f['file'] == 'wtmp' and f['category'] == 'username in binary file']
    assert binary == [{'file': 'wtmp', 'line': 0, 'category': 'username in binary file',
                       'value': 'jdoe', 'count': 1}]
    # the same tree, one file at a time and across a pool: the same findings
    assert _verify(d, jobs=3) == found


def test_a_value_is_found_across_every_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(V, '_PIECE', 4096)
    monkeypatch.setattr(V, '_SPLIT_ABOVE', 20000)
    monkeypatch.setattr(V, '_BIN_BLOCK', 4096)
    d = tmp_path / 'tree'
    d.mkdir()
    rnd = random.Random(3)
    lines = []
    for i in range(3000):
        lines.append('line %d %s' % (i, rnd.choice(LINES)))
    text = '\n'.join(lines) + '\n'
    (d / 'big.log').write_text(text)
    (d / 'big.log.gz').write_bytes(gzip.compress(text.encode()))
    (d / 'crlf.log').write_bytes(text.replace('\n', '\r\n').encode())
    (d / 'cr.log').write_bytes(text.replace('\n', '\r').encode())
    blob = b''.join(b'\x00\x01' * rnd.randint(1, 900) + rnd.choice(LINES).encode() + b'\x00'
                    for _ in range(400))
    (d / 'journal.bin').write_bytes(blob)
    # bigger than the size above which a binary file is cut into ranges
    (d / 'packed.tar').write_bytes(_tar_bytes([('logs/big.log', text.encode())]))
    (d / 'packed.txz').write_bytes(_tar_bytes([('logs/a.log', LEAK), ('logs/b.bin', blob)], 'w:xz'))
    serial = _verify(d)
    packed = {f['file'] for f in serial if '!/' in f['file']}
    assert packed == {'packed.tar!/logs/big.log', 'packed.txz!/logs/a.log', 'packed.txz!/logs/b.bin'}
    one_piece = []
    monkeypatch.setattr(V, '_PIECE', 1 << 30)
    monkeypatch.setattr(V, '_BIN_BLOCK', 1 << 30)
    one_piece = _verify(d)
    assert serial == one_piece
    monkeypatch.setattr(V, '_PIECE', 4096)
    monkeypatch.setattr(V, '_BIN_BLOCK', 4096)
    assert _verify(d, jobs=3) == serial
    by_file = {}
    for f in serial:
        by_file.setdefault(f['file'], []).append((f['line'], f['category'], f['value']))
    assert by_file['big.log'] == by_file['big.log.gz'] == by_file['crlf.log'] == by_file['cr.log']
    assert any(c == 'private key' for _, c, _ in by_file['big.log'])


def test_a_key_header_is_a_finding_unless_the_next_line_was_replaced(tmp_path, monkeypatch):
    d = tmp_path / 'tree'
    d.mkdir()
    head = '-----BEGIN RSA PRIVATE KEY-----\n'
    (d / 'kept.pem').write_text(FILLER * 5 + head + 'MIIEowIBAAKCAQEA\n')
    (d / 'gone.pem').write_text(FILLER * 5 + head + 'SCRUBBED_KEY_0123456789ab\n')
    (d / 'last.pem').write_text(FILLER * 5 + head)
    for piece in (1 << 20, len(FILLER) * 5 + len(head)):      # the header ends a piece
        monkeypatch.setattr(V, '_PIECE', piece)
        found = [(f['file'], f['line'], f['category']) for f in _verify(d)
                 if f['category'] == 'private key']
        assert found == [('kept.pem', 6, 'private key'), ('last.pem', 6, 'private key')], piece


def test_a_big_file_of_zero_bytes_costs_nothing_and_a_value_after_it_is_found(tmp_path):
    d = tmp_path / 'tree'
    d.mkdir()
    with open(str(d / 'lastlog'), 'wb') as f:
        f.truncate(300 * 1024 * 1024)                  # sparse: no blocks on disk
        f.seek(0, 2)
        f.write(b'\x00jdoe\x00pts/1\x00')
    found = _verify(d, jobs=2)
    assert [(f['category'], f['value'], f['count']) for f in found] == \
        [('username in binary file', 'jdoe', 1)]


def test_verify_output_checks_a_tree_this_tool_did_not_scrub(tmp_path):
    """The other tool left the accounts in: the mapping of a run of this
    tool on the same original says so, whoever did the scrubbing."""
    d = tmp_path / 'theirs_scrubbed'
    d.mkdir()
    (d / 'messages.txt').write_text('Accepted publickey for jdoe from 100.64.3.9\n' * 3)
    (d / 'inner.txz').write_bytes(_tar_bytes([('etc/passwd', b'jdoe:x:1000:100::/home/jdoe:/bin/bash\n')], 'w:xz'))
    clean = tmp_path / 'ours_scrubbed'
    clean.mkdir()
    (clean / 'messages.txt').write_text('Accepted publickey for user1 from 198.16.0.5\n')
    mapping = tmp_path / 'map.json'
    mapping.write_text(json.dumps(MAPS))
    script = os.path.join(os.path.dirname(__file__), '..', 'bin', 'supportutils-scrub')

    def run(*args):
        return subprocess.run([sys.executable, script, '--quiet', '--mappings', str(mapping)]
                              + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
    r = run('--verify-output', str(d), '--verify-mapping-only')
    assert r.returncode == 3, r.stderr
    assert 'username' in r.stdout and '100.64.3.9' not in r.stdout
    r = run('--verify-output', str(d))
    assert r.returncode == 3 and 'unlisted IPv4' in r.stdout      # not one of this tool's fakes
    r = run('--verify-output', str(d / 'inner.txz'), '--verify-mapping-only')
    assert r.returncode == 3 and 'username' in r.stdout
    r = run('--verify-output', str(clean))
    assert r.returncode == 0, r.stdout + r.stderr
    r = run('--verify-output', str(tmp_path / 'nothing-there'))
    assert r.returncode == 2


def test_a_long_term_list_is_found_as_its_one_pattern_finds_it():
    """Hundreds of terms have no few literals to search for: the pattern is
    then run without its lookbehind, which is applied by hand."""
    rnd = random.Random(11)
    abc = 'abcdefghijklmnopqrstuvwxyz'
    users = ['%s%su%d' % (rnd.choice(abc), rnd.choice(abc), i) for i in range(400)] + ['jdoe', 'bob', 'a-bob']
    ips = ['%d.%d.%d.%d' % (rnd.randint(1, 223), rnd.randint(0, 255), rnd.randint(0, 255), i % 250 + 1)
           for i in range(400)]
    hosts = ['%s%sNode%d' % (rnd.choice(abc).upper(), rnd.choice(abc), i) for i in range(300)]
    maps = {'user': {u: 'user%d' % i for i, u in enumerate(users)},
            'ip': {ip: '198.16.0.%d' % (i % 250) for i, ip in enumerate(ips)},
            'hostname': {h: 'host-%d' % i for i, h in enumerate(hosts)}}
    ctx = _ctx(maps)
    assert all(t._first is None for t in ctx['matchers'])
    pieces = users[:40] + ips[:40] + hosts[:40] + [h.upper() for h in hosts[:20]] + [
        'x', '9', '.', '-', '_', ' ', ' ', '\n', 'jdoe', 'xjdoe', 'bob2', '1.', '.1', 'a-', 'ver ',
        'xa-bob ', 'a-bob', ' bob ']
    for i in range(150):
        text = ''.join(rnd.choice(pieces) + rnd.choice(['', '', ' ']) for _ in range(rnd.randint(5, 200)))
        low = fastsub._fold(text)
        for terms in ctx['matchers']:
            assert terms.find(text, low) == [m.span() for m in terms.rx.finditer(text)], (i, terms.mode)
        fast = V._scan_piece(text, ctx, 0, None, True)
        fastsub.forget()
        assert _in_order(fast[0]) == _in_order(V._scan_piece_by_line(text, ctx, 0, None, True)[0])


def test_pieces_never_split_a_line_end():
    def pieces(blocks, size=8):
        it = iter(blocks)
        return list(V._pieces(lambda n: next(it, b''), size))
    for blocks in ([b'abc\rdef\r', b'\nghi\r\n'], [b'a\r', b'\nb\r', b'c\r\n'], [b'one\n', b'two'],
                   [b'no line end ', b'at all'], [b'x\r', b'y\r', b'z']):
        whole = V._normal_newlines(b''.join(blocks).decode())
        got = ''.join(V._normal_newlines(p.decode()) for p in pieces(blocks))
        assert got == whole, blocks


def test_ranges_of_one_file_merge_into_what_one_scan_gives():
    ctx = _ctx()
    head = '-----BEGIN RSA PRIVATE KEY-----\n'
    body = ''.join(line + '\n' for line in LINES)
    for first_of_second in ('MIIEowIBAAKCAQEA\n', 'SCRUBBED_KEY_0123456789ab\n'):
        halves = [body + head, first_of_second + body]
        whole = V._TextScan(ctx, True)
        whole.feed(''.join(halves).encode())
        parts = []
        for half in halves:
            scan = V._TextScan(ctx, True)
            scan.feed(half.encode())
            parts.append((scan.items, scan.lines, scan.pem, scan.first_line_replaced, None))
        assert V._merge_text_ranges('f', parts) == V._file_findings('f', whole, {}, None)
    kept = V._merge_text_ranges('f', parts[:1])
    assert kept[-1]['category'] == 'private key'           # nothing follows: still a finding


def test_a_damaged_archive_keeps_what_was_read_and_says_it_was_not_read_through(tmp_path, monkeypatch):
    d = tmp_path / 'tree'
    d.mkdir()
    rnd = random.Random(5)
    noise = bytes(rnd.getrandbits(8) for _ in range(200000))      # does not compress
    whole = _tar_bytes([('first.txt', LEAK), ('noise.bin', noise), ('last.txt', LEAK)], 'w:xz')
    (d / 'cut.txz').write_bytes(whole[:len(whole) // 2])
    (d / 'outer.tar').write_bytes(_tar_bytes([('inner/cut.txz', whole[:len(whole) // 2]),
                                               ('after.txt', LEAK)]))
    (d / 'notatar.tar').write_bytes(b'just text with jdoe in it\n')
    for jobs, block in ((1, 8 << 20), (3, 8 << 20), (3, 4096)):
        # the last: every archive here counts as big and is handed to the pool
        monkeypatch.setattr(V, '_BIN_BLOCK', block)
        got = _cats(_verify(d, jobs=jobs))
        assert ('cut.txz!/first.txt', 'username') in got
        assert ('cut.txz', 'unreadable file') in got
        assert ('outer.tar!/inner/cut.txz!/first.txt', 'username') in got
        assert ('outer.tar!/inner/cut.txz', 'unreadable file') in got
        assert ('outer.tar!/after.txt', 'username') in got
        # not a tar at all: its bytes are searched like any file's
        assert ('notatar.tar', 'username in binary file') in got
