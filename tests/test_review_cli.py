import sys

import pytest

from supportutils_scrub import cli
from supportutils_scrub.audit import _redacted_argv
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
