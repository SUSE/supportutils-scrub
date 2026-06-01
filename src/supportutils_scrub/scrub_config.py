# scrub_config.py


def _yes(val):
    return str(val).strip().lower() == 'yes'


class ScrubConfig:
    def __init__(
        self,
        obfuscate_private_ip=True,
        obfuscate_public_ip=True,
        obfuscate_domain=True,
        obfuscate_username=True,
        obfuscate_hostname=True,
        obfuscate_mac=True,
        obfuscate_ipv6=True,
        obfuscate_serial=True,
        dataset_dir='/var/tmp',
        secure_tmp=False,
        encrypt_mappings=False,
        verbose=True,
        log_level='verbose',
        use_key_words_file=True,
        key_words_file='/var/lib/supportutils-scrub-keywords.txt',
        public_pool='198.16.0.0/12',
        pool_10='100.80.0.0/12',
        pool_172='100.96.0.0/12',
        pool_192_168='100.112.0.0/12',
        pool_169_254='100.79.0.0/16',
        default_infer_prefixlen=24,
    ):
        self.obfuscate_private_ip = obfuscate_private_ip
        self.obfuscate_public_ip = obfuscate_public_ip
        self.obfuscate_domain = obfuscate_domain
        self.obfuscate_username = obfuscate_username
        self.obfuscate_hostname = obfuscate_hostname
        self.obfuscate_mac = obfuscate_mac
        self.obfuscate_ipv6 = obfuscate_ipv6
        self.obfuscate_serial = obfuscate_serial
        self.dataset_dir = dataset_dir
        self.secure_tmp = secure_tmp
        self.encrypt_mappings = encrypt_mappings
        self.verbose = verbose
        self.log_level = log_level
        self.use_key_words_file = use_key_words_file
        self.key_words_file = key_words_file
        self.public_pool = public_pool
        self.pool_10 = pool_10
        self.pool_172 = pool_172
        self.pool_192_168 = pool_192_168
        self.pool_169_254 = pool_169_254
        self.default_infer_prefixlen = default_infer_prefixlen

    @classmethod
    def from_dict(cls, d):
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

