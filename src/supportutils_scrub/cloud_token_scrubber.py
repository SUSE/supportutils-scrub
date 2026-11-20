# cloud_token_scrubber.py

import re
from supportutils_scrub.fastsub import gsub
from supportutils_scrub.scrubber import Scrubber, is_pseudonym


_JWT_RE = re.compile(
    r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'
)

_AWS_ACCESS_KEY_RE = re.compile(r'(AKIA[0-9A-Z]{16})')
_AWS_TEMP_KEY_RE = re.compile(r'(ASIA[0-9A-Z]{16})')
_AWS_SECRET_RE = re.compile(
    r'(?i)((?:aws_secret_access_key|SecretAccessKey|aws_session_token|SessionToken)'
    r'["\']?\s*[:=]\s*["\']?)([A-Za-z0-9+/=_-]{20,})'
)

_AZURE_CONNSTR_RE = re.compile(
    r'(?i)((?:AccountKey|SharedAccessKey)\s*=\s*)([A-Za-z0-9+/=]{20,})'
)
_AZURE_SAS_RE = re.compile(
    r'([?&](?:sig|sv|se|sp|spr|srt|ss)=)([A-Za-z0-9%+/=]{20,})'
)

_GCP_PRIVKEY_RE = re.compile(
    r'("private_key"\s*:\s*")(-----BEGIN[^"]+)"'
)

# The body of a PEM private key; the BEGIN/END lines stay so the key type is
# still visible. Certificates are public and left alone. A block split across
# two --jobs chunks of a very large file is not matched.
_PEM_PRIVKEY_RE = re.compile(
    r'(-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----)(\s*)([\s\S]*?)(\s*)(-----END \2-----)'
)

_BEARER_RE = re.compile(
    r'(?i)((?:Bearer|X-Auth-Token)\s+|(?:Authorization|token)\s*[:=]\s*(?:Bearer\s+)?["\']?)'
    r'([A-Za-z0-9._+/=-]{40,})'
)

_IDENTITY_TAG_RE = re.compile(
    r'(<identity>|identity:\s*)(eyJ[A-Za-z0-9_+/=-]{20,})'
)

# Public key comments (user@host) identify accounts and foreign hosts that
# the hostname scrubber can't learn from this system's /etc/hosts.
_SSH_PUBKEY_RE = re.compile(
    r'\b((?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{40,})'
    r'[ \t]+(?!SCRUBBED_)([^\s"\']+)'
)


class CloudTokenScrubber(Scrubber):
    name = 'cloud_token'
    """
    Detects and replaces cloud provider tokens, keys, and credentials
    from AWS, Azure, and GCE/GCP.
    """

    def __init__(self, mappings=None, deterministic=False):
        self.token_dict = dict(mappings.get('cloud_token', {})) if mappings else {}
        self._counter = len(self.token_dict)
        self.deterministic = deterministic

    @property
    def mapping(self):
        return self.token_dict

    def _get_fake(self, real_value, prefix='TOKEN'):
        """Return a consistent fake token for a real one."""
        if real_value in self.token_dict:
            return self.token_dict[real_value]
        if self.deterministic:
            from supportutils_scrub.det import dhash
            fake = f"SCRUBBED_{prefix}_{dhash(real_value)}"
        else:
            self._counter += 1
            fake = f"SCRUBBED_{prefix}_{self._counter}"
        self.token_dict[real_value] = fake
        return fake

    def _replace_pem(self, m):
        body = m.group(4)
        if not body or is_pseudonym(body):
            return m.group(0)
        return (m.group(1) + m.group(3) + self._get_fake(body, 'PRIVKEY')
                + m.group(5) + m.group(6))

    def scrub(self, text):
        """Replace cloud tokens in text. Returns scrubbed text.

        Each pattern is gated by a cheap substring check so we don't run nine
        regexes over every file — most files contain none of these markers.
        """
        # The lowered copy is only needed for the gate checks; drop it before
        # the subs run so peak memory is not one full extra copy of the text.
        tl = text.lower()
        has_jwt = 'eyj' in tl
        has_aws_secret = any(k in tl for k in ('aws_secret_access_key',
                                               'secretaccesskey',
                                               'aws_session_token',
                                               'sessiontoken'))
        has_account_key = 'accountkey' in tl or 'sharedaccesskey' in tl
        has_sas = 'sig=' in tl or 'sv=' in tl or 'srt=' in tl
        has_bearer = ('bearer' in tl or 'authorization' in tl
                      or 'x-auth-token' in tl or 'token' in tl)
        del tl

        if has_jwt:
            text = gsub(_JWT_RE, 
                lambda m: self._get_fake(m.group(1), 'JWT'), text)
            text = gsub(_IDENTITY_TAG_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'JWT'), text)

        if 'AKIA' in text:
            text = gsub(_AWS_ACCESS_KEY_RE, 
                lambda m: self._get_fake(m.group(1), 'AWS_KEY'), text)

        if 'ASIA' in text:
            text = gsub(_AWS_TEMP_KEY_RE, 
                lambda m: self._get_fake(m.group(1), 'AWS_TEMP'), text)

        if has_aws_secret:
            text = gsub(_AWS_SECRET_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AWS_SECRET'), text)

        if has_account_key:
            text = gsub(_AZURE_CONNSTR_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_KEY'), text)

        if has_sas:
            text = gsub(_AZURE_SAS_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_SAS'), text)

        if '"private_key"' in text:
            text = gsub(_GCP_PRIVKEY_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'GCP_PRIVKEY') + '"', text)

        if 'PRIVATE KEY-----' in text:
            text = gsub(_PEM_PRIVKEY_RE, self._replace_pem, text)

        if has_bearer:
            text = gsub(_BEARER_RE, 
                lambda m: m.group(1) + self._get_fake(m.group(2), 'BEARER'), text)

        if 'ssh-rsa' in text or 'ssh-ed25519' in text or 'ecdsa-sha2-' in text or 'ssh-dss' in text:
            text = gsub(_SSH_PUBKEY_RE, 
                lambda m: m.group(1) + ' ' + self._get_fake(m.group(2), 'SSH_COMMENT'), text)

        return text
