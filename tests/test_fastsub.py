"""fastsub only decides WHERE a pattern is run, never what it matches: every
route has to give exactly what the plain pattern gives on the whole text.

Each test here compares the two on text built to hit the edges: literals in
either case, matches that cross a line end, texts with and without non-ASCII
characters, literals so frequent that the gate gives up, and seeded random
text full of near misses.
"""

import importlib
import os
import random
import re

import pytest

from supportutils_scrub import fastsub
from supportutils_scrub.scrub_config import ScrubConfig

_MODULES = ('password_scrubber', 'auth_scrubber', 'cloud_token_scrubber',
            'email_scrubber', 'serial_scrubber', 'ldap_dn_scrubber',
            'sid_scrubber', 'mac_scrubber', 'ip_scrubber', 'ipv6_scrubber',
            'username_scrubber', 'domain_scrubber', 'hostname_scrubber')

_PATTERN = type(re.compile(''))


def _all_patterns():
    found = {}
    for name in _MODULES:
        mod = importlib.import_module('supportutils_scrub.' + name)
        spaces = [(name, vars(mod))]
        spaces += [(name + '.' + k, vars(v)) for k, v in vars(mod).items()
                   if isinstance(v, type) and v.__module__ == mod.__name__]
        for prefix, space in spaces:
            for key, value in space.items():
                items = value if isinstance(value, (list, tuple)) else [value]
                for i, item in enumerate(items):
                    if isinstance(item, _PATTERN):
                        found['%s.%s[%d]' % (prefix, key, i)] = item
    return found


PATTERNS = _all_patterns()

_KEY40 = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2'
LINES = [
    # secrets
    'password=hunter2', 'Password: "two words"', 'db_password = x9', 'MYSQL_ROOT_PASSWORD=abc',
    'token: 3000', 'TOKEN=abcdef', 'api_key: ZZZ', 'secret_key="s3"', 'wpa_passphrase=wifi',
    '<password>pw1</password>', '<Secret>pw2</Secret>',
    '<nvpair id="x" name="passwd" value="longsecret1"/>',
    '<nvpair name="passwd"\n   value="longsecret2"/>',
    'cmd --password=cli1 --user x', 'cmd --passphrase "two words" x', 'cmd --pass $PASS',
    'ldapsearch -x -w bindsecret -b dc=example,dc=com', 'bindpw secretbind', '  rootpw {SSHA}abcDEF',
    'mount -o credentials=/etc/samba/cred', 'mount -o credentials=secretval,uid=0',
    'pam_unix(passwd:chauthtok): ok', 'passwd: password changed for x', 'password=*REMOVED*',
    # http and url credentials
    'Authorization: Basic dXNlcjpwYXNz', 'Proxy-Authorization: Bearer abc.def-ghi',
    'authorization:\n  Basic dXNlcjpwYXNz', 'curl https://jdoe:pw@host.example.com/x',
    'ftp://anonymous@ftp.example.org/pub', 'Digest username="bob", realm="r"',
    'login SCC_0123456789abcdef01 ok',
    '# /etc/zypp/credentials.d/SCCcredentials\nusername=SCC_abc\npassword=x\n#==[ next ]=====#',
    # cloud tokens
    'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123', 'key AKIAIOSFODNN7EXAMPLE',
    'key ASIAIOSFODNN7EXAMPLE', 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'SessionToken":\n "' + _KEY40 + '"', 'AccountKey=abcdefghijklmnopqrstuvwxyz0123456789==',
    'https://x.blob.core.windows.net/c?sv=2020-08-04&sig=abcdefghijklmnopqrstuvwxyz%2B',
    '"private_key": "-----BEGIN PRIVATE KEY-----\\nabc"',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKC\n-----END RSA PRIVATE KEY-----',
    'Bearer ' + _KEY40, 'X-Auth-Token: ' + _KEY40, 'token = ' + _KEY40,
    '<identity>eyJhbGciOiJIUzI1NiJ9abcdefghij', 'identity: eyJhbGciOiJIUzI1NiJ9abcdefghij',
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhA0123456789abcd jdoe@laptop',
    # mail, directory names
    'mail from john.doe@corp.example.com.', 'unit x@y.service', 'root@localhost', 'A.B@Example.COM',
    'CN=John Smith,OU=People,DC=corp,DC=example,DC=com', 'cn=admin+ou=ops, dc=corp, dc=example',
    # SAP
    '/usr/sap/SEP/D00/work', 'rsc_SAPHana_SEP_HDB00', 'SAPSEP_00', 'sepadm 1234', 'SEP_ASCS01',
    'SAPSYSTEMNAME = SEP', '/sapmnt/SEP/profile', 'DAA_SMDA98_host', '/usr/sap/DAA/SMDA98',
    # addresses
    'addr 10.1.2.3 up', 'net 192.168.1.0/24 dev', 'dns 8.8.8.8.', 'range 1.2.3.4-1.2.3.9/24',
    'version 1.2.3.4', '4.3.2.1.in-addr.arpa', '3.2.1.IN-ADDR.ARPA', 'kernel 5.14.21.150400.24',
    'last 203.0.113.7', 'v6 2001:db8::1', 'll fe80::1%eth0', 'v6 2a00:1450:4001:81b::200e/64',
    'at 12:34:56 done', '[AF_INET6]2a00:1450::1:443', 'full 2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    'port 2600:1f18:1:2:3:4:5:41ee:443', 'mapped ::ffff:192.0.2.1', 'x::y', '1:2:3:4:5:6:7:8',
    'mac 00:1b:21:aa:bb:cc', 'mac 00-1B-21-AA-BB-CD', 'IN= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC',
    'client-id 01:00:1b:21:aa:bb:cc', 'bcast ff:ff:ff:ff:ff:ff', 'duid 00:03:00:01:00:1b:21:aa:bb:cc',
    'date 2026-01-29-11-50-20 x', 'aa:bb:cc:dd', 'xx:00:1b:21:aa:bb:cc:yy',
    # hardware labels
    'Serial Number: ABC12345', '   UUID: 4c4c4544-0042-3510-8051-b4c04f4d4e32',
    '\n\n  Asset Tag: XYZ9876', 'Serial\n Number: SPLIT123', 'x Serial Number: NOTATSTART',
    'Part Number: -', 'uuid: none', 'Serial Number:\n   NEXTLINE77',
    # log lines
    'session opened for user jdoe(uid=1000) by (uid=0)', 'sudo:   jdoe : TTY=pts/0',
    'Accepted publickey for jdoe from 10.0.0.9', 'pam_unix(sshd:auth): check pass; user unknown [jdoe]',
    'Jan 01 12:34:56 host kernel: something happened here', 'package-1.2.3-150400.1.x86_64 installed',
    'user=jdoe logname=root', 'acct="jdoe" exe="/usr/sbin/sshd"', 'nfs: server filer01 not responding',
]
FILLER = 'Jan 01 12:00:00 node kernel: [  123.456] usb 1-1: nothing of note in this line at all\n'


def _tag(m):
    return '[' + m.group(0)[::-1] + ']'


def _texts():
    dense = '\n'.join(LINES) + '\n'
    sparse = ''.join(FILLER * 40 + line + '\n' for line in LINES) + FILLER * 40
    yield 'dense', dense
    yield 'dense-upper', dense.upper()
    yield 'sparse', sparse
    yield 'sparse-no-final-newline', sparse.rstrip('\n')
    yield 'sparse-crlf', sparse.replace('\n', '\r\n')
    yield 'sparse-non-ascii', sparse.replace('nothing', 'n\u00f6thing \u20ac', 3)
    yield 'sparse-surrogate', sparse.replace('nothing', 'n\udcffthing', 2)
    yield 'sparse-irregular', sparse.replace('usb', 'u\u017fb \u212a \u0130 \u0131', 2)
    yield 'empty', ''
    yield 'one-line', LINES[0]


def _random_texts(n, seed):
    rnd = random.Random(seed)
    words = [w for line in LINES for w in re.split(r'(\s+|[=:"/<>,@])', line) if w]
    words += ['\n', '\n', ' ', ' ', '=', ':', '"', "'", '.', '-', '/', '_', '0', '9', 'a', 'F']
    for i in range(n):
        parts = []
        for _ in range(rnd.randint(5, 120)):
            w = rnd.choice(words)
            flip = rnd.random()
            parts.append(w.upper() if flip < .1 else w.lower() if flip < .2 else w)
            if rnd.random() < .5:
                parts.append(rnd.choice(' \n'))
        text = ''.join(parts)
        if i % 3 == 0:                   # few hits in a lot of text
            text = FILLER * rnd.randint(20, 60) + text + '\n' + FILLER * rnd.randint(20, 60)
        yield 'random-%d' % i, text


@pytest.mark.parametrize('name', sorted(PATTERNS))
def test_gated_substitution_equals_the_plain_one(name):
    rx = PATTERNS[name]
    for label, text in list(_texts()) + list(_random_texts(60, 1)):
        fastsub.forget()
        assert fastsub.gsub(rx, _tag, text) == rx.sub(_tag, text), (name, label)
        got = [(m.span(), m.groups()) for m in fastsub.giter(rx, text)]
        assert got == [(m.span(), m.groups()) for m in rx.finditer(text)], (name, label)


def test_the_gates_are_in_use_and_not_all_falling_back():
    from supportutils_scrub import password_scrubber as pw, cloud_token_scrubber as ct
    sparse = FILLER * 200 + 'password=hunter2\n' + FILLER * 200
    p = fastsub.plan(pw._PASSWORD_RE)
    assert 'pass' in p.first and 'token' in p.first and p.one_line
    assert fastsub._route(pw._PASSWORD_RE, sparse, p.first, p.required, p.one_line)[0] == 'at'
    assert fastsub._route(pw._PASSWORD_RE, FILLER * 400, p.first, p.required, p.one_line)[0] == 'none'
    p = fastsub.plan(pw._BLANK_SECRET_RE)
    assert p.first is None and set(p.required) == {'bindpw', 'rootpw'} and p.one_line
    assert fastsub._route(pw._BLANK_SECRET_RE, FILLER * 99 + 'rootpw x\n', None,
                          p.required, True)[0] == 'spans'
    assert not fastsub.plan(pw._ATTR_PAIR_RE).one_line       # [^>]*? crosses lines
    assert not fastsub.plan(ct._AWS_SECRET_RE).one_line      # \s* crosses lines
    assert 'bearer' in fastsub.plan(ct._BEARER_RE).first


@pytest.mark.parametrize('pattern,one_line', [
    (r'ab+c', True), (r'a\s*=', False), (r'a[^"]+"', False), (r'a[^\s"]+"', True),
    (r'a.c', True), (r'(?s)a.c', False), (r'a(?=\s*x)', False), (r'a(?!\s)', True),
    (r'a(?=b|$)', False), (r'(?m)a(?=b|$)', True), (r'a$', False), (r'(?m)^a$', True),
    (r'a\Z', False), (r'a\D', False), (r'a\W', False), (r'a\S', True), (r'a\nb', False),
    (r'(?<=\n)ab', True),
])
def test_what_counts_as_staying_on_one_line(pattern, one_line):
    assert fastsub.plan(re.compile(pattern)).one_line is one_line


@pytest.mark.parametrize('pattern,first,required', [
    (r'(?i)(?:foo|bar)\s*=', ('bar', 'foo'), ('bar', 'foo')),
    (r'\bxy[0-9]+', ('xy',), ('xy',)),
    (r'(?:pre-)?token=', ('pre-token=', 'token='), ('token=',)),
    (r'[ab]cd', ('acd', 'bcd'), ('acd', 'bcd')),
    (r'\d+://x', None, ('://x',)),
    (r'[0-9a-f]+', None, None),
    (r'(?:x)?', None, None),             # can match nothing at all
    (r'caf\u00e9', ('caf',), ('caf',)),  # a literal stops at a non-ASCII character
    (r'password|passwd|passphrase', ('pass',), ('pass',)),
])
def test_literals_read_from_a_pattern(pattern, first, required):
    p = fastsub.plan(re.compile(pattern))
    assert (p.first, p.required) == (first, required)


def test_the_lowercase_copy_says_what_an_ignore_case_pattern_sees():
    assert fastsub.fold('ABC d') == 'abc d'
    assert fastsub.fold('\u00c4BC \udcff') == '\u00e4bc \udcff'
    # the four characters `re` takes for an ASCII letter become that letter
    assert fastsub.fold('\u0130\u0131\u017f\u212a \u00c9') == 'iisk \u00e9'
    rx = re.compile(r'(?i)sink=\S+')
    text = FILLER * 50 + '\u017fin\u212a=1 sink=2\n'
    assert fastsub.gsub(rx, 'X', text) == rx.sub('X', text) == FILLER * 50 + 'X X\n'


def test_the_lowercase_copy_follows_the_edits():
    rx = re.compile(r'(?i)name=\S+')
    text = FILLER * 80 + 'NAME=Caf\u00e9 x\n' + FILLER * 80
    fastsub.forget()
    out = fastsub.gsub(rx, lambda m: 'Name=HIDDEN', text)
    assert out == rx.sub('Name=HIDDEN', text)
    assert fastsub._fold_memo[0] is out and fastsub._fold_memo[1] == out.lower()
    # a replacement that is not ASCII is not carried: the copy is made anew
    out2 = fastsub.gsub(rx, lambda m: 'Name=\u00c9', out)
    assert fastsub.fold(out2) == out2.lower()


def test_start_literals_for_a_word_list():
    assert fastsub.literals(['Web01', 'web012', 'DB']) == ('db', 'web01')
    assert fastsub.literals(['m\u00fcller']) is None and fastsub.literals([]) is None
    many = ['c5%05d' % i for i in range(300)] + ['i0%04d' % i for i in range(200)]
    assert fastsub.literals(many) == ('c500', 'i000', 'i001')
    assert fastsub.literals([chr(97 + i % 26) + chr(97 + i // 26) for i in range(300)]) is None


# --- whole passes: with the pre-filter and with it switched off -------------

def _scrubbers():
    from supportutils_scrub.ip_scrubber import IPScrubber
    from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
    from supportutils_scrub.mac_scrubber import MACScrubber
    cfg = ScrubConfig(obfuscate_private_ip=True)
    return [('supportutils_scrub.ip_scrubber', lambda: IPScrubber(cfg, mappings={})),
            ('supportutils_scrub.ipv6_scrubber', lambda: IPv6Scrubber(cfg, mappings={})),
            ('supportutils_scrub.mac_scrubber', lambda: MACScrubber(cfg, mappings={}))]


@pytest.mark.parametrize('index', [0, 1, 2], ids=['ip', 'ipv6', 'mac'])
def test_a_pre_filtered_pass_equals_the_pass_over_the_whole_text(index, monkeypatch):
    modname, make = _scrubbers()[index]
    mod = importlib.import_module(modname)
    texts = list(_texts()) + list(_random_texts(150, 2))
    hinted = []
    for _label, text in texts:
        s = make()
        hinted.append((s.scrub(text), dict(s.mapping)))
    monkeypatch.setattr(mod, 'hint_spans', lambda text, hints: None)
    for (label, text), (out, mapping) in zip(texts, hinted):
        s = make()
        assert (s.scrub(text), dict(s.mapping)) == (out, mapping), label


def test_ip_discovery_equals_discovery_over_the_whole_text(monkeypatch):
    from supportutils_scrub import ip_scrubber
    texts = list(_texts()) + list(_random_texts(150, 3))
    make = _scrubbers()[0][1]
    hinted = [make().discover(text) for _label, text in texts]
    monkeypatch.setattr(ip_scrubber, 'hint_spans', lambda text, hints: None)
    for (label, text), got in zip(texts, hinted):
        assert make().discover(text) == got, label


def test_usernames_on_the_lowercase_copy_equal_the_case_insensitive_pattern():
    from supportutils_scrub.username_scrubber import UsernameScrubber
    names = {'jdoe': 'user1', 'a-bob': 'user2', 'bob': 'user3', 'Bobby': 'user4',
             'svc.backup': 'user5', 'x1': 'user6', 'web_admin': 'user7'}
    s = UsernameScrubber(dict(names))
    assert s._re_low is not None
    rnd = random.Random(4)
    pieces = list(names) + [n.upper() for n in names] + [
        'xa-bob', 'a-bobx', 'bobb', '-bob', 'bob-', '_bob_', 'jdoe2', '2jdoe', '.', '-', '_',
        ' ', '\n', '/', 'x', '1', 'svc', 'backup', '\u00e9', '\udcfe']
    for i in range(400):
        text = ''.join(rnd.choice(pieces) for _ in range(rnd.randint(1, 60)))
        plain = s._re.sub(lambda m: s._lookup[m.group(0).lower()], text)
        fastsub.forget()
        assert s.scrub(text) == plain, repr(text)
    irregular = 'jdoe \u0131 bob \u017f'
    assert s.scrub(irregular) == s._re.sub(lambda m: s._lookup[m.group(0).lower()], irregular)
    assert UsernameScrubber({'m\u00fcller': 'user1'})._re_low is None


def test_labelled_serials_equal_the_pattern_over_the_whole_text():
    from supportutils_scrub import serial_scrubber as ser
    for label, text in list(_texts()) + list(_random_texts(150, 5)):
        fastsub.forget()
        got = [(m.group('value'), m.end()) for m in ser._labeled(text)]
        assert got == [(m.group('value'), m.end()) for m in ser._LABELED_RE.finditer(text)], label


def test_sid_discovery_equals_the_patterns_over_the_whole_text():
    from supportutils_scrub import sid_scrubber as sid
    for label, text in list(_texts()) + list(_random_texts(150, 6)):
        fastsub.forget()
        plain = [m.group(1) for rx in sid._DISCOVERY for m in rx.finditer(text)]
        assert [m.group(1) for m in sid._discoveries(text)] == plain, label


# --- the subnet allocator: same choices as the loop it replaced -------------

def _alloc_one_net_at_a_time(self, cat_key, prefixlen):
    """The allocation loop as it was: candidates tried net by net."""
    from ipaddress import IPv4Network
    pool = self.category_pools[cat_key]
    used = self._used_slots[cat_key]
    if (cat_key, prefixlen) in self._exhausted_pools:
        raise RuntimeError('exhausted')
    step = 2 ** (32 - prefixlen)
    start = int(pool.network_address)
    end = int(pool.broadcast_address) + 1
    cursor = self._pool_cursor.get(cat_key, 0)
    for _ in range((end - start) // step):
        base = start + ((cursor // step) * step)
        if base >= end:
            cursor = 0
            base = start
        slot_start = (base - start) // 256
        slot_count = max(1, step // 256)
        if not any(s in used for s in range(slot_start, slot_start + slot_count)):
            used.update(range(slot_start, slot_start + slot_count))
            self._pool_cursor[cat_key] = (base - start) + step
            return IPv4Network((base, prefixlen))
        cursor += step
    self._exhausted_pools.add((cat_key, prefixlen))
    raise RuntimeError('exhausted')


@pytest.mark.parametrize('seed', range(8))
def test_subnet_allocation_picks_what_the_net_by_net_loop_picked(seed):
    from supportutils_scrub.ip_scrubber import IPScrubber
    rnd = random.Random(seed)
    cfg = ScrubConfig(public_pool='198.18.0.0/%d' % rnd.choice([20, 21, 22]))
    new, old = IPScrubber(cfg, mappings={}), IPScrubber(cfg, mappings={})
    for _ in range(400):
        prefixlen = rnd.choice([32, 30, 28, 27, 25, 24, 24, 24, 23, 22, 21])
        if rnd.random() < .1:            # a cursor left anywhere by an older mapping
            new._pool_cursor['public'] = old._pool_cursor['public'] = rnd.randrange(0, 5000)
        results = []
        for scrubber, alloc in ((new, new._alloc_fake_subnet_from_pool),
                                (old, lambda c, p: _alloc_one_net_at_a_time(old, c, p))):
            try:
                results.append(str(alloc('public', prefixlen)))
            except RuntimeError:
                results.append('exhausted')
        assert results[0] == results[1]
        assert new._pool_cursor == old._pool_cursor and new._used_slots == old._used_slots


# --- copy and compression ---------------------------------------------------

def test_a_cloned_or_copied_file_is_its_own_file(tmp_path):
    from supportutils_scrub.extractor import _clone_or_copy
    src, dst = tmp_path / 'a.log', tmp_path / 'b.log'
    src.write_bytes(b'one\n' * 5000)
    os.chmod(str(src), 0o640)
    _clone_or_copy(str(src), str(dst))
    assert dst.read_bytes() == src.read_bytes()
    assert os.stat(str(dst)).st_mode & 0o777 == 0o640
    dst.write_bytes(b'changed\n')
    assert src.read_bytes() == b'one\n' * 5000


@pytest.mark.parametrize('ext', ['.gz', '.xz', '.bz2'])
def test_a_rewritten_compressed_log_reads_back_and_names_no_file(tmp_path, ext):
    from supportutils_scrub import processor
    path = str(tmp_path / ('messages-20260101' + ext))
    opener = processor.compressed_opener(os.path.basename(path))[1]
    out, fh = processor.open_compressed_out(path, ext, opener)
    out.write(b'line\n' * 1000)
    out.close()
    if fh:
        fh.close()
    with opener(path, 'rb') as f:
        assert f.read() == b'line\n' * 1000
    assert processor.compression_magic_ok(path, ext)
    assert b'messages' not in open(path, 'rb').read()


def test_a_fifo_in_the_folder_does_not_hang_the_copy(tmp_path):
    import threading
    from supportutils_scrub.extractor import copy_folder_to_scrubbed
    src = tmp_path / 'case'
    src.mkdir()
    (src / 'a.txt').write_text('text\n')
    os.mkfifo(str(src / 'pipe'))
    done = []
    t = threading.Thread(target=lambda: done.append(copy_folder_to_scrubbed(str(src))),
                         daemon=True)
    t.start()
    t.join(20)
    assert done, "the copy is still waiting on the FIFO"
    assert (tmp_path / 'case_scrubbed' / 'a.txt').read_text() == 'text\n'


def test_the_shared_lowercase_copy_is_dropped_after_each_text():
    from supportutils_scrub.pipeline import build_chain
    from supportutils_scrub.processor import FileProcessor
    fp = FileProcessor(ScrubConfig(), build_chain({}, ScrubConfig()))
    text = FILLER * 100 + 'password=hunter2 mail a.b@corp.example.com\n'
    assert 'hunter2' not in fp._scrub_content(text, 'x.txt', None)
    assert fastsub._fold_memo[:2] == [None, None]


def test_only_four_characters_pass_for_an_ascii_letter_when_case_is_ignored():
    """fastsub.fold rests on this, for the `re` of the Python running it:
    as a literal and inside a class, no other non-ASCII character matches
    an ASCII letter or digit, and no other one changes length in lower()."""
    letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    # each letter followed by '!': kept apart, so `re` matches them as
    # literals and does not merge them into one class
    literal = re.compile('(?i)' + '|'.join('(%s)!' % ch for ch in letters))
    in_class = re.compile('(?i)[A-Za-z0-9]')
    expected = dict(fastsub._IRREGULAR)
    for code in range(128, 0x110000):
        ch = chr(code)
        m = literal.fullmatch(ch + '!')
        as_literal = letters[m.lastindex - 1] if m else None
        assert as_literal == expected.get(ch), hex(code)
        assert bool(in_class.fullmatch(ch)) == (ch in expected), hex(code)
        assert len(ch.lower()) == 1 or ch == '\u0130', hex(code)
        folded = fastsub._fold(ch + 'x')
        assert len(folded) == 2 and (folded[0] in letters) == (ch in expected), hex(code)


def test_a_name_written_with_a_dotless_i_or_a_long_s_is_replaced_not_a_crash():
    """`re` matches these for the i, s and k of a name when it ignores
    case; the replacement used to be looked up by lower(), which does not
    turn them into that letter, and the pass failed on the file."""
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    from supportutils_scrub.username_scrubber import UsernameScrubber
    from supportutils_scrub.domain_scrubber import DomainScrubber
    spellings = ('kiosk', 'KIOSK', 'k\u0131osk', 'K\u0130OSK', 'kio\u017fk', '\u212aiosk')
    user = UsernameScrubber({'kiosk': 'user1'})
    host = HostnameScrubber({'kiosk': 'host-1'})
    domain = DomainScrubber({'kiosk.example-bank.com': 'dom1.aaa'})
    for word in spellings:
        for pad in ('', FILLER * 60):                 # short text, and one that is remembered
            fastsub.forget()
            assert user.scrub(pad + 'login %s ok\n' % word) == pad + 'login user1 ok\n', word
            fastsub.forget()
            assert host.scrub(pad + 'on %s now\n' % word) == pad + 'on host-1 now\n', word
            fastsub.forget()
            assert domain.scrub(pad + 'at %s.example-bank.com.\n' % word) == pad + 'at dom1.aaa.\n', word
    assert fastsub.key('K\u0130O\u017f\u212a') == 'kiosk'
