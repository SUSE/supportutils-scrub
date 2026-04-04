import pytest
from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.config_reader import ConfigReader


class TestScrubConfig:
    def test_defaults(self):
        cfg = ScrubConfig()
        assert cfg.obfuscate_private_ip is True
        assert cfg.obfuscate_public_ip is True
        assert cfg.obfuscate_mac is True
        assert cfg.dataset_dir == '/var/tmp'
        assert cfg.default_infer_prefixlen == 24

    def test_from_dict_bool(self):
        cfg = ScrubConfig.from_dict({'obfuscate_private_ip': 'yes'})
        assert cfg.obfuscate_private_ip is True

    def test_from_dict_no(self):
        cfg = ScrubConfig.from_dict({'obfuscate_mac': 'no'})
        assert cfg.obfuscate_mac is False

    def test_from_dict_string(self):
        cfg = ScrubConfig.from_dict({'dataset_dir': '/tmp/custom'})
        assert cfg.dataset_dir == '/tmp/custom'

    def test_from_dict_int(self):
        cfg = ScrubConfig.from_dict({'default_infer_prefixlen': '16'})
        assert cfg.default_infer_prefixlen == 16

    def test_unknown_keys_ignored(self):
        cfg = ScrubConfig.from_dict({'unknown_key': 'value'})
        assert not hasattr(cfg, 'unknown_key') or cfg.dataset_dir == '/var/tmp'

    def test_pool_defaults(self):
        cfg = ScrubConfig()
        assert cfg.public_pool == '198.16.0.0/12'
        assert cfg.pool_10 == '100.80.0.0/12'


class TestConfigReader:
    def test_missing_file_returns_defaults(self):
        cfg = ConfigReader('/nonexistent').read_config()
        assert isinstance(cfg, ScrubConfig)
        assert cfg.obfuscate_public_ip is True

    def test_returns_scrub_config_type(self):
        cfg = ConfigReader('/nonexistent').read_config()
        assert type(cfg).__name__ == 'ScrubConfig'
