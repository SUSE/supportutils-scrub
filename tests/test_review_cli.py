import io
import json
import os
import sys
from types import SimpleNamespace

import pytest

from supportutils_scrub import audit, cli
from supportutils_scrub.audit import _redacted_argv
from supportutils_scrub.translator import Translator
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.scrub_config import ScrubConfig


@pytest.fixture
def conf(tmp_path):
    # never the host's /etc conf: it may turn on encrypt_mappings and prompt
    c = tmp_path / 'empty.conf'
    c.write_text('')
    return ['--config', str(c)]


def _main(monkeypatch, argv):
    monkeypatch.setattr(sys, 'argv', ['supportutils-scrub'] + argv)
    monkeypatch.delenv('SUPPORTUTILS_SCRUB_OPTS', raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main()
    return e.value.code


@pytest.mark.parametrize('val,want', [('true', True), ('On', True), ('1', True),
                                      ('false', False), ('OFF', False), ('0', False)])
def test_boolean_spellings(val, want):
    assert ScrubConfig.from_dict({'obfuscate_mac': val}).obfuscate_mac is want


def test_unknown_boolean_keeps_default(capsys):
    assert ScrubConfig.from_dict({'obfuscate_mac': 'maybe'}).obfuscate_mac is True
    assert 'obfuscate_mac' in capsys.readouterr().err


def test_section_header_and_bad_line_do_not_drop_later_keys(tmp_path, capsys):
    conf = tmp_path / 'scrub.conf'
    conf.write_text('[main]\nobfuscate_domain = no   # keep off\n'
                    'garbage line\nobfuscate_mac = false\n')
    cfg = ConfigReader('/nonexistent').read_config(str(conf))
    assert cfg.obfuscate_domain is False
    assert cfg.obfuscate_mac is False
    assert 'garbage line' in capsys.readouterr().err


def test_explicit_missing_config_is_an_error(monkeypatch, tmp_path):
    assert _main(monkeypatch, ['--config', str(tmp_path / 'typo.conf'),
                               str(tmp_path)]) == 2


def test_option_prefixes_are_rejected(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['supportutils-scrub', '--host',
                                      'node1.example.com', 'x.txz'])
    with pytest.raises(SystemExit):
        cli.parse_args()


def test_audit_argv_redacts_both_forms():
    assert _redacted_argv(['--hostname=node1.example.com', '--domain',
                           'example.com', 'x.txz']) == \
        ['--hostname=<redacted>', '--domain', '<redacted>', 'x.txz']


def test_encrypt_without_cryptography_stops_before_scrubbing(monkeypatch, tmp_path, conf):
    monkeypatch.setitem(sys.modules, 'cryptography', None)
    assert _main(monkeypatch, conf + ['--encrypt-mappings', str(tmp_path)]) == 2


def _save_args(**kw):
    return SimpleNamespace(**{"no_mappings": False, "_enc_passphrase": None, **kw})


def test_failed_encryption_never_writes_plaintext(monkeypatch, tmp_path):
    def boom(*a):
        raise RuntimeError('no')
    monkeypatch.setattr(Translator, 'save_datasets_encrypted', boom)
    dest = tmp_path / 'm.json'
    with pytest.raises(RuntimeError):
        audit.save_mappings(_save_args(_enc_passphrase='x' * 8), str(dest), {'ip': {}})
    assert not dest.exists()


def test_failed_plain_save_raises(tmp_path):
    (tmp_path / 'f').write_text('')
    with pytest.raises(OSError):
        audit.save_mappings(_save_args(), str(tmp_path / 'f' / 'm.json'), {})


def test_mapping_is_created_private(tmp_path):
    old = os.umask(0)
    try:
        Translator.save_datasets(str(tmp_path / 'new.json'), {})
        existing = tmp_path / 'old.json'
        existing.write_text('{}')
        existing.chmod(0o644)
        Translator.save_datasets(str(existing), {})
    finally:
        os.umask(old)
    assert (tmp_path / 'new.json').stat().st_mode & 0o777 == 0o600
    assert existing.stat().st_mode & 0o777 == 0o600


def test_pcap_only_run_with_piped_stdin_rewrites_the_pcap(monkeypatch, tmp_path, conf):
    import io
    m = tmp_path / 'm.json'
    m.write_text('{}')
    calls = []
    monkeypatch.setattr(cli, 'rewrite_pcaps_with_tcprewrite',
                        lambda *a, **k: calls.append(a))
    monkeypatch.setattr(sys, 'stdin', io.StringIO(''))
    monkeypatch.setattr(sys, 'argv', ['supportutils-scrub', *conf, '--rewrite-pcap', '--quiet',
                                      '--mappings', str(m), '--pcap-in', 'a.pcap'])
    monkeypatch.delenv('SUPPORTUTILS_SCRUB_OPTS', raising=False)
    cli.main()
    assert calls and calls[0][1] == ['a.pcap']


def test_pcap_rewrite_with_a_folder_is_refused(monkeypatch, tmp_path, conf, capsys):
    assert _main(monkeypatch, conf + [str(tmp_path), '--rewrite-pcap',
                                      '--pcap-in', 'a.pcap']) == 2
    assert 'not supported' in capsys.readouterr().err


def test_missing_tcprewrite_is_a_clear_error_and_leaves_no_output(tmp_path):
    from supportutils_scrub.pcap_rewrite import (PcapRewriteError,
                                                 rewrite_pcaps_with_tcprewrite)
    pcap = tmp_path / 'a.pcap'
    pcap.write_bytes(b'')
    out = tmp_path / 'out'
    with pytest.raises(PcapRewriteError, match='tcprewrite not found'):
        rewrite_pcaps_with_tcprewrite(
            {'subnet': {'198.51.100.0/24': '198.18.0.0/24'}}, [str(pcap)],
            str(out), tcprewrite=str(tmp_path / 'no-tcprewrite'))
    assert os.listdir(out) == []


def test_addresses_mapped_outside_a_subnet_get_host_rules():
    from supportutils_scrub.pcap_rewrite import _host_pairs
    pairs = _host_pairs({'203.0.113.5': '198.18.1.5', '198.51.100.7': '198.18.0.7',
                         '2001:db8::1': '2001:db8::2'},
                        [('198.51.100.0/24', '198.18.0.0/24')])
    assert pairs == [('203.0.113.5/32', '198.18.1.5/32')]


class _Logger:
    def __getattr__(self, name):
        return lambda *a, **k: None


def _stdin_args(tmp_path, mapping=None, **kw):
    m = None
    if mapping is not None:
        m = tmp_path / 'in.json'
        m.write_text(json.dumps(mapping))
    ns = SimpleNamespace(
        verbose=False, mappings=str(m) if m else None, keywords=None,
        keyword_file=None, domain=None, username=None, hostname=None,
        no_mappings=False, _enc_passphrase=None, stream=False,
        _preloaded_config=ScrubConfig(dataset_dir=str(tmp_path / 'ds')))
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _feed(monkeypatch, data, close=True):
    r, w = os.pipe()
    os.write(w, data)
    if close:
        os.close(w)
    monkeypatch.setattr(sys, 'stdin', os.fdopen(r, 'r'))
    return w


def _saved(tmp_path):
    import glob
    [p] = glob.glob(str(tmp_path / 'ds' / '*mappings.json'))
    return json.load(open(p))


def test_stdin_applies_and_keeps_sid_mapping(monkeypatch, tmp_path, capsysbinary):
    from supportutils_scrub.modes import stdin as stdin_mode
    _feed(monkeypatch, b'SAPSYSTEMNAME = QAB\nbad byte \xff here\n')
    stdin_mode.run_stdin_mode(_stdin_args(tmp_path, {'sid': {'QAB': 'HA1'}}), _Logger())
    out = capsysbinary.readouterr().out
    assert b'SAPSYSTEMNAME = HA1' in out and b'\xff' in out
    assert _saved(tmp_path)['sid'] == {'QAB': 'HA1'}


def test_stream_bootstrap_gets_the_whole_burst(monkeypatch, tmp_path, capsysbinary):
    import threading
    from supportutils_scrub.modes import stdin as stdin_mode
    monkeypatch.setattr(stdin_mode, '_STREAM_BOOTSTRAP_SECS', 0.2)
    seen = []
    orig = stdin_mode._prepare
    monkeypatch.setattr(stdin_mode, '_prepare',
                        lambda a, c, text, *r: seen.append(text) or orig(a, c, text, *r))
    w = _feed(monkeypatch, b'one\ntwo\nthree\n', close=False)
    threading.Timer(0.6, os.close, [w]).start()
    stdin_mode.run_stdin_mode(_stdin_args(tmp_path, stream=True), _Logger())
    assert seen == ['one\ntwo\nthree\n']


@pytest.mark.parametrize('exc,code', [(KeyboardInterrupt, 130), (BrokenPipeError, None)])
def test_interrupted_stdin_still_saves_the_mapping(monkeypatch, tmp_path, exc, code,
                                                   capsysbinary):
    from supportutils_scrub.modes import stdin as stdin_mode

    def stop(text):
        raise exc
    monkeypatch.setattr(stdin_mode, '_emit', stop)
    _feed(monkeypatch, b'SAPSYSTEMNAME = QAB\n')
    if code:
        with pytest.raises(SystemExit) as e:
            stdin_mode.run_stdin_mode(_stdin_args(tmp_path), _Logger())
        assert e.value.code == code
    else:
        stdin_mode.run_stdin_mode(_stdin_args(tmp_path), _Logger())
    assert 'QAB' in _saved(tmp_path)['sid']


@pytest.mark.parametrize('crm', [False, True])
def test_preload_of_an_archive_learns_no_extraction_folder_name(tmp_path, crm):
    import tarfile
    from test_preload import _node, _args, _Logger as _PLogger
    from supportutils_scrub.modes import preload as preload_mode
    a = _node(tmp_path, 'nodea', ['nodea'])
    if crm:   # a crm_report: cib.xml at the top marks the dir as a node
        (a / 'cib.xml').write_text('<cib/>')
    arc = tmp_path / 'scc_nodea_260821.txz'
    with tarfile.open(arc, 'w:xz') as t:
        t.add(a, arcname=a.name)
    mapping = tmp_path / 'shared.json'
    preload_mode.run_preload_mode(_args([arc], mapping, tmp_path), _PLogger())
    assert not [h for h in json.load(open(mapping))['hostname'] if 'scrubbed' in h]


def test_preload_keeps_an_encrypted_mapping_encrypted(monkeypatch, tmp_path):
    import getpass
    from test_preload import _node, _args, _Logger as _PLogger
    from supportutils_scrub.modes import preload as preload_mode
    pw = 'example-passphrase'
    Translator.save_datasets_encrypted(str(tmp_path / 'case.json'), {}, pw)
    enc = tmp_path / 'case.json.enc'
    monkeypatch.setattr(getpass, 'getpass', lambda *a: pw)
    a = _node(tmp_path, 'nodea', ['nodea', 'peer1'])
    preload_mode.run_preload_mode(_args([a], enc, tmp_path, _enc_passphrase=pw),
                                  _PLogger())
    assert not (tmp_path / 'case.json').exists()
    assert 'peer1' in audit.load_mappings_file(str(enc))['hostname']


def test_relative_mapping_path_is_saved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Translator.save_datasets('rel.json', {})
    assert (tmp_path / 'rel.json').exists()


def test_stdin_stops_output_when_a_scrubber_fails(monkeypatch, tmp_path, capsysbinary):
    from supportutils_scrub.modes import stdin as stdin_mode
    from supportutils_scrub.processor import FileProcessor, ScrubError

    def boom(self, *a, **k):
        raise ScrubError("ip scrub failed")
    monkeypatch.setattr(FileProcessor, 'process_text', boom)
    _feed(monkeypatch, b'peer 203.0.113.7 ok\n')
    with pytest.raises(SystemExit) as e:
        stdin_mode.run_stdin_mode(_stdin_args(tmp_path), _Logger())
    assert e.value.code == 1
    assert b'203.0.113.7' not in capsysbinary.readouterr().out


@pytest.mark.parametrize('order', ['pcap_first', 'pcap_last', 'pcap_alone'])
def test_a_positional_pcap_goes_to_archive_mode(monkeypatch, tmp_path, conf, order):
    from supportutils_scrub.modes import archive
    pcap = tmp_path / 'network.cap'
    pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 20)
    sc = tmp_path / 'scc_node1_260101_1200'
    sc.mkdir()
    paths = {'pcap_first': [str(pcap), str(sc)], 'pcap_last': [str(sc), str(pcap)],
             'pcap_alone': [str(pcap)]}[order]
    seen = []
    monkeypatch.setattr(archive, 'run_archive_mode',
                        lambda p, *a, **k: (seen.append(p), sys.exit(0)))
    monkeypatch.setattr(sys, 'stdin', io.StringIO(''))
    assert _main(monkeypatch, conf + paths) == 0
    assert seen == [paths]
