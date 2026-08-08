# auth_scrubber.py
#
# HTTP credentials. Two shapes carry them into a capture and neither was
# recognised by the other scrubbers:
#
#     Authorization: Basic <base64 of "user:password">
#     scheme://user:password@host/path
#
# The base64 form is the dangerous one. It matches no token pattern (it is
# just base64), it decodes to a live credential, and a reverse-proxy access
# log records it on every single request, so one log file can carry thousands
# of copies of a working password or API token.
#
# Both shapes are scrubbed PART BY PART instead of being replaced wholesale,
# because the structure is diagnostic while the value never is. Whether the
# password field is empty, and whether a URL carries a username at all, are
# precisely the facts needed to explain a failing authentication sequence.
# So "user:" keeps its visibly-empty password and "user:pw" does not:
#
#     base64("user:")    -> base64("SCRUBBED_LOGIN_1:")
#     base64("user:pw")  -> base64("SCRUBBED_LOGIN_1:SCRUBBED_SECRET_1")
#     https://user@host  -> https://SCRUBBED_LOGIN_1@host
#
# A blanket replacement would remove the credential and the diagnosis with it.

import base64
import binascii
import re

from supportutils_scrub.scrubber import Scrubber


# Anchored on the header name, so a bare "Basic <word>" in prose is never
# touched. The optional quotes are what matters here: JSON access logs write
# {"authorization":"Basic ..."}, and a pattern expecting `Authorization:`
# never matches it because the quote sits between the name and the colon.
_AUTH_VALUE_RE = re.compile(
    r'(?i)((?:proxy-)?authorization"?\s*[:=]\s*"?)'
    r'(basic|bearer)([ \t]+)'
    r'([A-Za-z0-9+/._~-]+={0,2})'
)

# RFC 3986 userinfo. The user and password classes exclude '/' and '@', so the
# match cannot run past the authority into a path or query containing '@'.
_URL_CRED_RE = re.compile(
    r'(?i)\b([a-z][a-z0-9+.-]*://)'
    r'([^\s/:@"\'<>]+)'
    r'(?::([^\s/@"\'<>]*))?'
    r'@'
)

# Conventional, non-secret logins that identify a protocol rather than a
# person. Skipped only when no password accompanies them.
_PUBLIC_LOGINS = frozenset({'git', 'anonymous', 'ftp'})

# Values already replaced by this or another scrubber; re-scrubbing them would
# allocate a second pseudonym for a pseudonym.
_ALREADY_SCRUBBED = ('SCRUBBED_', 'scrubbed_', 'email_')


class AuthScrubber(Scrubber):
    name = 'auth'
    """Replaces HTTP Basic/Bearer credentials and URL userinfo."""

    def __init__(self, mappings=None, deterministic=False,
                 email_scrubber=None, username_scrubber=None):
        self.auth_dict = dict(mappings.get('auth', {})) if mappings else {}
        self._counter = len(self.auth_dict)
        self.deterministic = deterministic
        # Delegates keep an identity consistent with the same identity written
        # in clear elsewhere in the capture. The address inside a Basic header
        # and the address in a repo config must land on one pseudonym, or an
        # engineer cannot tell they are the same account.
        self._email = email_scrubber
        self._user = username_scrubber

    @property
    def mapping(self):
        return self.auth_dict

    def _get_fake(self, real_value, prefix):
        """Return a consistent fake value for a real one."""
        if real_value in self.auth_dict:
            return self.auth_dict[real_value]
        if self.deterministic:
            from supportutils_scrub.det import dhash
            fake = f"SCRUBBED_{prefix}_{dhash(real_value)}"
        else:
            self._counter += 1
            fake = f"SCRUBBED_{prefix}_{self._counter}"
        self.auth_dict[real_value] = fake
        return fake

    def _scrub_login(self, user):
        """Pseudonymise a credential username, reusing a sibling scrubber's
        mapping when that scrubber already knows the identity."""
        if not user or user.startswith(_ALREADY_SCRUBBED):
            return user
        if self._email is not None and '@' in user:
            fake = self._email.scrub(user)
            if fake != user:
                return fake
        if self._user is not None:
            fake = self._user.scrub(user)
            if fake != user:
                return fake
        return self._get_fake(user, 'LOGIN')

    def _scrub_secret(self, secret):
        if secret.startswith(_ALREADY_SCRUBBED):
            return secret
        return self._get_fake(secret, 'SECRET')

    def _basic(self, blob):
        """Re-encode a Basic credential with both halves scrubbed.

        Fails closed: anything that does not decode to a printable
        "user:password" pair is replaced wholesale, because an undecodable
        blob sitting in an Authorization header is far more likely to be a
        credential we could not parse than a false positive.
        """
        if blob.startswith(_ALREADY_SCRUBBED):
            return blob
        try:
            decoded = base64.b64decode(blob, validate=True).decode('utf-8')
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return self._get_fake(blob, 'BASIC')
        if ':' not in decoded or not decoded.isprintable():
            return self._get_fake(blob, 'BASIC')

        user, _, secret = decoded.partition(':')
        # An empty password stays empty. That trailing colon is the entire
        # diagnosis when a client sends a username with no password and the
        # server answers 401 (or, after enough of them, 403).
        clean = self._scrub_login(user) + ':'
        if secret:
            clean += self._scrub_secret(secret)
        return base64.b64encode(clean.encode('utf-8')).decode('ascii')

    def _replace_header(self, m):
        prefix, scheme, gap, blob = m.group(1), m.group(2), m.group(3), m.group(4)
        if scheme.lower() == 'basic':
            return prefix + scheme + gap + self._basic(blob)
        if blob.startswith(_ALREADY_SCRUBBED):
            return m.group(0)
        return prefix + scheme + gap + self._get_fake(blob, 'BEARER')

    def _replace_url(self, m):
        scheme, user, secret = m.group(1), m.group(2), m.group(3)
        if user.startswith(_ALREADY_SCRUBBED):
            return m.group(0)
        if secret is None and user.lower() in _PUBLIC_LOGINS:
            return m.group(0)
        out = scheme + self._scrub_login(user)
        if secret is not None:
            # "user:@host" keeps its empty password for the same reason the
            # Basic form does.
            out += ':' + (self._scrub_secret(secret) if secret else '')
        return out + '@'

    def scrub(self, text):
        """Replace HTTP credentials in text. Returns scrubbed text.

        Both patterns are gated by a cheap substring check: most files contain
        neither an Authorization header nor a URL.
        """
        if 'authorization' in text.lower():
            text = _AUTH_VALUE_RE.sub(self._replace_header, text)
        if '://' in text:
            text = _URL_CRED_RE.sub(self._replace_url, text)
        return text
