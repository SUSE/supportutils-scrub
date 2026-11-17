import os
import sys
from types import SimpleNamespace

import pytest

from supportutils_scrub import audit, cli
from supportutils_scrub.audit import _redacted_argv
from supportutils_scrub.translator import Translator
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.scrub_config import ScrubConfig


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


def test_encrypt_without_cryptography_stops_before_scrubbing(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, 'cryptography', None)
    assert _main(monkeypatch, ['--encrypt-mappings', str(tmp_path)]) == 2


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


def test_relative_mapping_path_is_saved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Translator.save_datasets('rel.json', {})
    assert (tmp_path / 'rel.json').exists()
