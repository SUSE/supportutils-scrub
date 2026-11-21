"""Learning the names (--preload and every pre-scan) reads the logs before
anything is scrubbed, and on a set of large logs it was slow: a pattern
tried at every character of gigabytes of text, and a step of Python for
each of millions of repeated matches. The faster forms only decide WHERE
the unchanged patterns are tried, so each is compared here with the plain
form it replaced, on text built to hit the edges and on seeded random text.
"""

import random
import re

import pytest

from supportutils_scrub import domain_scrubber as D
from supportutils_scrub import hostname_scrubber as H
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber


# --- the plain forms, as they were -----------------------------------------

def _plain_domains(text, trusted=False):
    found = set()
    for m in D.DOMAIN_RE.finditer(text):
        fqdn = D._norm(m.group(1))
        if not D._is_valid_domain(fqdn, trusted):
            continue
        found.add(fqdn)
        parts = fqdn.split('.')
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if D._is_valid_domain(parent, trusted):
                found.add(parent)
    for m in D._DC_RE.finditer(text):
        domain = D._dc_to_domain(m.group(1))
        if D._is_valid_domain(domain, trusted):
            DomainScrubber._add_domain_and_parents(domain, found)
    return D._sort_specific_first(found, trusted)


def _plain_valid(d, trusted=False):
    d = D._norm(d)
    if "." not in d:
        return False
    if d in D._SINGLE_LABEL_BAN or d in D._PUBLIC_SUFFIXES:
        return False
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", d):
        return False
    parts = d.split(".")
    if any(len(p) == 0 for p in parts):
        return False
    for p in parts:
        if len(p) > 63:
            return False
        if p.startswith("-") or p.endswith("-"):
            return False
        if not re.fullmatch(r"[a-zA-Z0-9-]+", p):
            return False
    if not trusted and parts[-1].lower() not in D._VALID_TLDS:
        return False
    if not trusted and len(parts) == 2 and parts[-1].lower() in D._EXTENSION_TLDS:
        return False
    return True


_PLAIN_SYSLOG = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+([\w][\w-]*)\b',
                           re.MULTILINE)


def _plain_users(text):
    lower = text.lower()
    seen, lines = set(), []
    for trigger in UsernameScrubber._LOG_TRIGGERS:
        pos = lower.find(trigger)
        while pos != -1:
            start = lower.rfind('\n', 0, pos) + 1
            if start not in seen:
                seen.add(start)
                end = lower.find('\n', pos)
                lines.append(text[start:end if end != -1 else len(text)])
            pos = lower.find(trigger, pos + 1)
    order = []
    for line in lines:
        for pat in UsernameScrubber._LOG_PATTERNS:
            for m in pat.finditer(line):
                name = m.group(1).rstrip('.')
                if not UsernameScrubber._is_excluded(name):
                    order.append(name)
    return order


# --- text -------------------------------------------------------------------

_WORDS = [
    'db01.corp.example.com', 'EXAMPLE.ORG', 'mail.example.co.uk', 'a.b.c.d.example.net',
    'pam_unix.so', 'libfoo.so', 'script.py', 'www.example.so', '_ldap._tcp.example.com',
    'x_y.example.com', '-lead.example.com', 'trail-.example.com', 'example.com.',
    '..example.com', 'example..com', '10.1.2.3', '1.2.3', '0.00', '12.34',
    '07:20:01.123456', '2026-11-16T07:20:01.123456+01:00', 'node1', 'host-a',
    'kernel-default-6.4.0-150600.23.x86_64', 'foo.bar', 'local', 'co.uk', 'x.local',
    'DC=corp,DC=example,DC=com', 'dc=a, dc=example, dc=org', 'DC=solo',
    'uſer.example.com', 'example.uK', 'İstanbul.example.com',
    'mıx.example.org', 'café.example.com', 'naïve', 'über.de',
    'user=jdoe', 'logname=amiller', 'USER=root', 'user = bwayne', 'acct="ckent"',
    'session opened for user dprince(uid=1001)', 'session opened for user root by',
    'sudo:   pparker : TTY=pts/0', 'sudo[4711]: tstark : command',
    'Accepted publickey for srogers from', 'pam_unix(sshd:auth): check pass; [nromanoff]',
    'RESOURCE/USER/dom/bbanner', 'nce/user/x/thor.odinson',
    'password check failed for user (lskywalker)', 'nfs: server filer01.example.com not responding',
    'a' * 70 + '.example.com', 'x' * 300, '=', ':', '[', ']', '(', ')', '/', ',', '"',
]
_STAMPS = ['2026-11-16T07:20:01.123456+01:00 ', '2026-11-16T07:20:02+01:00  ',
           'Nov 16 07:20:01 ', '(2026-11-16  7:20:01): ', '', '2026-11-16T07:20:03Z\n',
           '1999-01-01T00:00:00 ']


def _random_text(seed, lines=400, ascii_only=False):
    rnd = random.Random(seed)
    words = [w for w in _WORDS if not ascii_only or all(ord(c) < 128 for c in w)]
    out = []
    for _ in range(lines):
        row = rnd.choice(_STAMPS) + rnd.choice(('node1', 'host-a', 'db', 'x', ''))
        for _ in range(rnd.randrange(0, 9)):
            row += rnd.choice((' ', ' ', '\t', '', '=', ':', '.', '-', '_', '[')) + rnd.choice(words)
        out.append(row)
    return rnd.choice(('\n', '\n', '\r\n')).join(out) + rnd.choice(('', '\n'))


_SEEDS = range(40)


# --- domains ----------------------------------------------------------------

@pytest.mark.parametrize('seed', _SEEDS)
@pytest.mark.parametrize('trusted', (False, True))
def test_domains_from_runs_equal_the_pattern_on_the_whole_text(seed, trusted):
    text = _random_text(seed, ascii_only=seed % 2 == 0)
    assert DomainScrubber.extract_domains_from_text(text, trusted) == _plain_domains(text, trusted)


@pytest.mark.parametrize('seed', _SEEDS)
@pytest.mark.parametrize('tld_only', (False, True))
def test_runs_give_every_match_in_first_seen_order(seed, tld_only, monkeypatch):
    # a small window, so the text is cut many times
    monkeypatch.setattr(D, '_RUN_WINDOW', 257)
    text = _random_text(seed, ascii_only=seed % 3 == 0)
    plain = list(dict.fromkeys(D.DOMAIN_RE.findall(text)))
    got = []
    for run in D._dotted_runs(text, tld_only):
        got += D.DOMAIN_RE.findall(run)
    got = list(dict.fromkeys(got))
    if tld_only:
        # a run with no letter after a dot is left out, and with it only
        # matches no untrusted text can give; the ones that count keep
        # their order (it is the order they reach the result set in)
        def counts(found):
            return [m for m in found if D._is_valid_domain(m)]
        assert counts(got) == counts(plain)
    else:
        assert got == plain


def test_a_window_is_never_cut_inside_a_name(monkeypatch):
    monkeypatch.setattr(D, '_RUN_WINDOW', 8)
    text = 'x ' * 3 + 'long-name.corp.example.com' + ' y' * 3 + '\nnext.example.org\n' + 'no newline at the end.example.net'
    assert DomainScrubber.extract_domains_from_text(text) == _plain_domains(text)


def test_validity_is_the_same_with_the_tld_test_first():
    rnd = random.Random(7)
    labels = ['example', 'com', 'so', 'py', 'la', 'co', 'uk', 'local', 'rz', '', '-a', 'a-', 'a_b',
              '10', '255', 'x' * 64, 'x' * 63, 'EXAMPLE', 'Com', 'internal', 'www', 'café']
    for _ in range(20000):
        d = '.'.join(rnd.choice(labels) for _ in range(rnd.randrange(1, 6)))
        d = rnd.choice(('', ' ', '.')) + d + rnd.choice(('', '.', ' ', '\n'))
        for trusted in (False, True):
            assert D._is_valid_domain(d, trusted) == _plain_valid(d, trusted), (d, trusted)


def test_the_run_alphabet_is_what_the_domain_pattern_can_take():
    # every character a DOMAIN_RE match or its lookarounds can test, and
    # only those, belongs to a run
    inside = re.compile(r'[A-Za-z0-9_.-]', re.IGNORECASE)
    for code in range(0x110000):
        ch = chr(code)
        assert bool(D._RUN_RE.fullmatch(ch)) == bool(inside.fullmatch(ch)), hex(code)
        if code < 128 and ch != ' ':       # the space is what the others become
            assert (D._RUN_SPLIT[code] == code) == bool(inside.fullmatch(ch)), hex(code)
    assert D._RUN_SPLIT[32] == 32 and not inside.fullmatch(' ')


# --- hosts ------------------------------------------------------------------

@pytest.mark.parametrize('seed', _SEEDS)
def test_syslog_hosts_equal_the_line_start_pattern(seed):
    text = _random_text(seed)
    assert H._syslog_hosts(text) == _PLAIN_SYSLOG.findall(text)


@pytest.mark.parametrize('text', [
    '', '\n', '2026-11-16T07:20:01+01:00 nodeA msg',
    '2026-11-16T07:20:01+01:00 nodeA msg\n2026-11-16T07:20:02+01:00 nodeB msg\n',
    '\n2026-11-16T07:20:01+01:00 nodeA msg',
    'x 2026-11-16T07:20:01+01:00 nodeA msg\n',
    # the white space after the stamp runs over the line end: the next line
    # is taken as the host and is not a line of its own
    '2026-11-16T07:20:01+01:00\n2026-11-16T07:20:02+01:00 nodeB\n2026-11-16T07:20:03+01:00 nodeC\n',
    '2026-11-16T07:20:01+01:00 \n\n2026-11-16T07:20:02+01:00 nodeB\r\n2026-11-16T07:20:03+01:00 nodeC',
])
def test_syslog_hosts_on_the_edges(text):
    assert H._syslog_hosts(text) == _PLAIN_SYSLOG.findall(text)


def test_host_counts_add_up_over_segments():
    seg = '2026-11-16T07:20:01+01:00 nodeA one\n2026-11-16T07:20:02+01:00 nodeB two\n'
    counts = {}
    assert H.HostnameScrubber.extract_hostnames_from_text(seg, syslog_counts=counts) == []
    H.HostnameScrubber.extract_hostnames_from_text(seg + seg, syslog_counts=counts)
    assert counts == {'nodeA': 3, 'nodeB': 3}
    assert sorted(H.HostnameScrubber.extract_hostnames_from_text(seg * 3)) == ['nodeA', 'nodeB']


# --- users ------------------------------------------------------------------

@pytest.mark.parametrize('seed', _SEEDS)
def test_users_come_out_the_same_and_in_the_same_order(seed, monkeypatch):
    text = _random_text(seed)
    order = []
    real = UsernameScrubber._is_excluded

    def spy(name):
        excluded = real(name)
        if not excluded:
            order.append(name)
        return excluded
    monkeypatch.setattr(UsernameScrubber, '_is_excluded', staticmethod(spy))
    got = UsernameScrubber.extract_usernames_from_text(text)
    monkeypatch.setattr(UsernameScrubber, '_is_excluded', staticmethod(real))
    plain = _plain_users(text)
    assert order == plain                  # the order names reach the set
    assert sorted(got) == sorted(set(plain))


def test_every_pattern_has_its_needs_and_a_match_holds_one():
    assert len(UsernameScrubber._LOG_NEEDS) == len(UsernameScrubber._LOG_PATTERNS)
    hit = [0] * len(UsernameScrubber._LOG_PATTERNS)
    for seed in _SEEDS:
        for line in _random_text(seed).splitlines():
            for i, (pat, needs) in enumerate(zip(UsernameScrubber._LOG_PATTERNS,
                                                 UsernameScrubber._LOG_NEEDS)):
                for m in pat.finditer(line):
                    hit[i] += 1
                    assert needs is None or any(n in m.group(0) for n in needs), (pat.pattern, m.group(0))
    assert all(hit), hit                   # the text exercised every pattern


# --- SAP system IDs ----------------------------------------------------------

from supportutils_scrub import sid_scrubber as S   # noqa: E402

_SAP_WORDS = [
    '/usr/sap/PRD', '/usr/sap/PRD/HDB00', '/usr/sap/QA1x', '/usr/sap/DAA/SMDA98', '/sapmnt/DEV',
    '/sapmnt/TS2/profile', 'SAPSYSTEMNAME = ABC', 'SAPSYSTEMNAME:\tXY9', 'SAPSYSTEMNAME=\nNL1',
    'rsc_SAPHana_PRD_HDB00', 'rsc_SAPHanaTopology_QA1_HDB10', 'rsc_SAP_DEV_ASCS01', 'xrsc_SAP_BAD_D00',
    'cln_rsc_SAPHana_NO1_HDB00', 'SAPPRD_00', 'xSAPBAD_00', '_SAPBAD_', 'PRD_HDB00', 'QA1_D01',
    'DEV_ASCS01x', 'TS2_ERS29', 'x_TS9_W77', '/TS8_J00', 'ABC_G12/', 'AB_D00', 'abc_D00', 'PRD_HDB0',
    'PRD_HDB١٢', 'caféSAPUNI_', 'éPRD_D00', 'PRD_D00é', 'sap', 'SAP', 'saphana',
    '=', ':', ' ', '-', '.', '(', ')', '[', ']', ',', 'id=', 'notice:', 'x' * 200,
]


def _sap_text(seed, lines=300, ascii_only=False):
    rnd = random.Random(seed)
    words = [w for w in _SAP_WORDS if not ascii_only or all(ord(c) < 128 for c in w)]
    out = []
    for _ in range(lines):
        row = rnd.choice(_STAMPS)
        for _ in range(rnd.randrange(0, 8)):
            row += rnd.choice((' ', ' ', '', '=', ':', '.', '-', '_', '/', '[')) + rnd.choice(words)
        out.append(row)
    return '\n'.join(out) + rnd.choice(('', '\n'))


def _plain_discovered(text):
    out = []
    for rx in S._DISCOVERY:
        out += list(dict.fromkeys(m.group(1) for m in rx.finditer(text)))
    return out


@pytest.mark.parametrize('seed', _SEEDS)
def test_sids_by_findall_equal_the_discovery_patterns(seed):
    text = _sap_text(seed, ascii_only=seed % 2 == 0)
    assert S._discovered(text) == _plain_discovered(text)


@pytest.mark.parametrize('seed', _SEEDS)
def test_each_scan_pattern_matches_where_its_discovery_pattern_does(seed):
    # the same SID at the same place, match for match (the last one starts
    # at the "_" after the SID instead of at the SID)
    text = _sap_text(seed, lines=500)
    assert len(S._SCAN) == len(S._DISCOVERY)
    for rx, scan in zip(S._DISCOVERY, S._SCAN):
        want = [(m.start(1), m.group(1), m.end()) for m in rx.finditer(text)]
        got = [(m.start(1), m.group(1), m.end()) for m in scan.finditer(text)]
        assert got == want, rx.pattern


@pytest.mark.parametrize('seed', range(10))
def test_the_pre_scan_learns_the_same_sids_in_the_same_order(seed, monkeypatch):
    text = _sap_text(seed, lines=600)
    new = S.SIDScrubber(mappings={})
    new.pre_scan(text)
    old = S.SIDScrubber(mappings={})
    monkeypatch.setattr(S, '_discovered', lambda t: [
        m.group(1) for rx in S._DISCOVERY for m in rx.finditer(t)])
    old.pre_scan(text)
    assert list(new.sid_dict.items()) == list(old.sid_dict.items())
    assert new.sid_dict                     # the text does hold SIDs


@pytest.mark.parametrize('seed', _SEEDS)
def test_the_agent_scan_finds_the_agent_patterns_matches(seed):
    rnd = random.Random(seed)
    words = _SAP_WORDS + ['DAA_SMDA98', '/usr/sap/DA1/SMDA97', 'xDA2_SMDA96', 'DA3_SMDA9', 'DA4_SMDA95x',
                          '-DA5_SMDA94', 'DA6_SMDA93_DA7_SMDA92', '\u00e9DA8_SMDA91', 'DA9_SMDA\u0661\u0662']
    text = '\n'.join(' '.join(rnd.choice(words) for _ in range(rnd.randrange(1, 8))) for _ in range(300))
    assert len(S._AGENT_SCAN) == len(S._AGENT)
    for rx, scan in zip(S._AGENT, S._AGENT_SCAN):
        want = [(m.start(1), m.group(1), m.end()) for m in rx.finditer(text)]
        got = [(m.start(1), m.group(1), m.end()) for m in scan.finditer(text)]
        assert got == want, rx.pattern
    assert S._agents(text) == {m.group(1) for rx in S._AGENT for m in rx.finditer(text)}
    assert 'DAA' in S._agents(text) or 'DAA_SMDA98' not in text
