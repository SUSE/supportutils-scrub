# cloud_token_scrubber.py

import re
from supportutils_scrub.scrubber import Scrubber


_JWT_RE = re.compile(
    r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'
)

_AWS_ACCESS_KEY_RE = re.compile(r'(AKIA[0-9A-Z]{16})')
_AWS_TEMP_KEY_RE = re.compile(r'(ASIA[0-9A-Z]{16})')
_AWS_SECRET_RE = re.compile(
    r'(?i)((?:aws_secret_access_key|SecretAccessKey|aws_session_token|SessionToken)'
    r'\s*[:=]\s*["\']?)([A-Za-z0-9+/=_-]{20,})'
)

_AZURE_CONNSTR_RE = re.compile(
    r'(AccountKey\s*=\s*)([A-Za-z0-9+/=]{20,})'
)
_AZURE_SAS_RE = re.compile(
    r'([?&](?:sig|sv|se|sp|spr|srt|ss)=)([A-Za-z0-9%+/=]{20,})'
)

_GCP_PRIVKEY_RE = re.compile(
    r'("private_key"\s*:\s*")(-----BEGIN[^"]+-----)"'
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

    def scrub(self, text):
        """Replace cloud tokens in text. Returns scrubbed text.

        Each pattern is gated by a cheap substring check so we don't run nine
        regexes over every file — most files contain none of these markers.
        """
        tl = text.lower()

        if 'eyj' in tl:
            text = _JWT_RE.sub(
                lambda m: self._get_fake(m.group(1), 'JWT'), text)
            text = _IDENTITY_TAG_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'JWT'), text)

        if 'AKIA' in text:
            text = _AWS_ACCESS_KEY_RE.sub(
                lambda m: self._get_fake(m.group(1), 'AWS_KEY'), text)

        if 'ASIA' in text:
            text = _AWS_TEMP_KEY_RE.sub(
                lambda m: self._get_fake(m.group(1), 'AWS_TEMP'), text)

        if any(k in tl for k in ('aws_secret_access_key', 'secretaccesskey',
                                 'aws_session_token', 'sessiontoken')):
            text = _AWS_SECRET_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AWS_SECRET'), text)

        if 'accountkey' in tl:
            text = _AZURE_CONNSTR_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_KEY'), text)

        if 'sig=' in tl or 'sv=' in tl or 'srt=' in tl:
            text = _AZURE_SAS_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_SAS'), text)

        if '"private_key"' in text:
            text = _GCP_PRIVKEY_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'GCP_PRIVKEY') + '"', text)

        if 'bearer' in tl or 'authorization' in tl or 'x-auth-token' in tl or 'token' in tl:
            text = _BEARER_RE.sub(
                lambda m: m.group(1) + self._get_fake(m.group(2), 'BEARER'), text)

        if 'ssh-rsa' in text or 'ssh-ed25519' in text or 'ecdsa-sha2-' in text or 'ssh-dss' in text:
            text = _SSH_PUBKEY_RE.sub(
                lambda m: m.group(1) + ' ' + self._get_fake(m.group(2), 'SSH_COMMENT'), text)

        return text
