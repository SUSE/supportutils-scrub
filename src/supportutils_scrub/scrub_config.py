# scrub_config.py
from dataclasses import dataclass, field


def _yes(val) -> bool:
    return str(val).strip().lower() == 'yes'


@dataclass
class ScrubConfig:
    obfuscate_private_ip: bool = True
    obfuscate_public_ip: bool = True
    obfuscate_domain: bool = True
    obfuscate_username: bool = True
    obfuscate_hostname: bool = True
    obfuscate_mac: bool = True
    obfuscate_ipv6: bool = True
    obfuscate_serial: bool = True
    dataset_dir: str = '/var/tmp'
    secure_tmp: bool = False
    encrypt_mappings: bool = False
    verbose: bool = True
    log_level: str = 'verbose'
    use_key_words_file: bool = True
    key_words_file: str = '/var/lib/supportutils-scrub-keywords.txt'
    public_pool: str = '198.16.0.0/12'
    pool_10: str = '100.80.0.0/12'
    pool_172: str = '100.96.0.0/12'
    pool_192_168: str = '100.112.0.0/12'
    pool_169_254: str = '100.79.0.0/16'
    default_infer_prefixlen: int = 24

    @classmethod
    def from_dict(cls, d: dict) -> 'ScrubConfig':
        bool_fields = {
            'obfuscate_private_ip', 'obfuscate_public_ip', 'obfuscate_domain',
            'obfuscate_username', 'obfuscate_hostname', 'obfuscate_mac',
            'obfuscate_ipv6', 'obfuscate_serial', 'secure_tmp',
            'encrypt_mappings', 'verbose', 'use_key_words_file',
        }
        kwargs = {}
        for key, val in d.items():
            if key in bool_fields:
                kwargs[key] = _yes(val)
            elif key == 'default_infer_prefixlen':
                kwargs[key] = int(val)
            elif hasattr(cls, key):
                kwargs[key] = val
        return cls(**kwargs)

