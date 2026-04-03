# cloud_token_scrubber.py

import re


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


class CloudTokenScrubber:
    """
    Detects and replaces cloud provider tokens, keys, and credentials
    from AWS, Azure, and GCE/GCP.
    """

    def __init__(self, mappings=None):
        self.token_dict = dict(mappings.get('cloud_token', {})) if mappings else {}
        self._counter = len(self.token_dict)

    def _get_fake(self, real_value, prefix='TOKEN'):
        """Return a consistent fake token for a real one."""
        if real_value in self.token_dict:
            return self.token_dict[real_value]
        self._counter += 1
        fake = f"SCRUBBED_{prefix}_{self._counter}"
        self.token_dict[real_value] = fake
        return fake

    def scrub(self, text):
        """Replace cloud tokens in text. Returns scrubbed text."""

        text = _JWT_RE.sub(
            lambda m: self._get_fake(m.group(1), 'JWT'), text)

        text = _IDENTITY_TAG_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'JWT'), text)

        text = _AWS_ACCESS_KEY_RE.sub(
            lambda m: self._get_fake(m.group(1), 'AWS_KEY'), text)

        text = _AWS_TEMP_KEY_RE.sub(
            lambda m: self._get_fake(m.group(1), 'AWS_TEMP'), text)

        text = _AWS_SECRET_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'AWS_SECRET'), text)

        text = _AZURE_CONNSTR_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_KEY'), text)

        text = _AZURE_SAS_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'AZURE_SAS'), text)

        text = _GCP_PRIVKEY_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'GCP_PRIVKEY') + '"', text)

        text = _BEARER_RE.sub(
            lambda m: m.group(1) + self._get_fake(m.group(2), 'BEARER'), text)

        return text
