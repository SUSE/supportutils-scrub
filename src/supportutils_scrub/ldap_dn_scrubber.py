import re
from typing import Dict, Optional
from supportutils_scrub.scrubber import Scrubber

_LDAP_SAFE_VALUES = {
    'aggregate', 'schema', 'configuration', 'sites', 'subnets', 'servers',
    'services', 'partitions', 'builtin', 'users', 'computers', 'system',
    'container', 'config', 'domain', 'default', 'deleted objects',
    'lostandfound', 'ntds quotas', 'ntds settings', 'ntds site settings',
    'adminsdholder', 'foreign security principals', 'keys', 'program data',
    'managed service accounts', 'tpm devices', 'well-known security principals',
    'certificate publishers', 'enterprise admins', 'domain admins',
    'schema admins', 'domain controllers', 'rid manager$', 'display specifiers',
    'enterprise read-only domain controllers', 'read-only domain controllers',
    'extended-rights', 'file replication service', 'dfsr-globalsettings',
    'group policy container', 'policies', 'adrm', 'dns', 'microsoftdns',
    'directory service', 'site settings', 'rpc services', 'windows nt',
    'top', 'organizationalunit', 'person', 'user', 'group', 'computer',
}

_AZURE_REGIONS = {
    'east-us', 'east-us-2', 'west-us', 'west-us-2', 'west-us-3',
    'central-us', 'north-central-us', 'south-central-us', 'west-central-us',
    'north-europe', 'west-europe', 'uk-south', 'uk-west', 'france-central',
    'germany-west-central', 'switzerland-north', 'norway-east', 'sweden-central',
    'east-asia', 'southeast-asia', 'japan-east', 'japan-west', 'korea-central',
    'australia-east', 'australia-southeast', 'canada-central', 'canada-east',
    'brazil-south', 'south-africa-north', 'uae-north', 'india-central',
    'azure-west-europe', 'azure-east-us', 'azure-north-europe',
}

_FAKE_VALUE_RE = re.compile(
    r'^(?:hostname_\d+|user_\d+|domain_\d+|cn_\d+|ou_\d+|keyword_\d+)'
    r'(?:\.[a-z]{2,})?$',
    re.IGNORECASE,
)

_CN_OU_RE = re.compile(r'(?i)\b(CN|OU)=([^,\s]+)')


def _is_safe_ad_value(val: str) -> bool:
    v = val.lower().strip()
    if v in _LDAP_SAFE_VALUES or v in _AZURE_REGIONS:
        return True
    if v.endswith('$') and v[:-1] in _LDAP_SAFE_VALUES:
        return True
    return False


class LdapDnScrubber(Scrubber):
    """Anonymize CN=/OU= values in LDAP DN strings.

    DC= is handled upstream by DomainScrubber; this scrubber only rewrites
    CN= and OU= values that are neither safe AD schema terms nor already fake.
    """

    name = 'ldap_dn'

    def __init__(self, mappings: Optional[Dict] = None):
        stored = (mappings or {}).get('ldap_dn', {}) or {}
        self.ldap_dict: Dict[str, str] = {k.lower(): v for k, v in stored.items()}
        self._counter = len(self.ldap_dict)

    @property
    def mapping(self):
        return self.ldap_dict

    def _fake_for(self, real_val: str, typ: str) -> str:
        key = real_val.lower()
        if key in self.ldap_dict:
            return self.ldap_dict[key]
        self._counter += 1
        fake = f"{typ.lower()}_{self._counter}"
        self.ldap_dict[key] = fake
        return fake

    def scrub(self, text: str) -> str:
        if not text or ('CN=' not in text and 'cn=' not in text
                        and 'OU=' not in text and 'ou=' not in text):
            return text

        def _repl(m):
            typ, val = m.group(1), m.group(2)
            if _is_safe_ad_value(val) or _FAKE_VALUE_RE.match(val):
                return m.group(0)
            return f"{typ}={self._fake_for(val, typ)}"

        return _CN_OU_RE.sub(_repl, text)
