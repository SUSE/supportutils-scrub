# password_scrubber.py
"""Obfuscate password values in config files (e.g. password=secret123)."""

import re

# Only match full keywords "password" and "passwd" — NOT "pass" (too many false positives).
# Require = as delimiter (not :) to avoid matching PAM log lines like
# "pam_unix(sshd:auth): authentication failure" or "password: required".
# Value must be alphanumeric/hex-like (no shell commands, no punctuation-heavy strings).
_PASSWORD_RE = re.compile(
    r'(?i)(\b(?:password|passwd)\s*=\s*["\']?)'     # keyword + = delimiter
    r'(?!\*REMOVED)'                                  # skip supportconfig-redacted
    r'(?!scrubbed_pass_)'                             # skip already-scrubbed
    r'([A-Za-z0-9+/=_.-]{8,})'                       # credential-like value (8+ chars, no spaces)
)


class PasswordScrubber:
    """
    Finds and replaces password values consistently.
    Preserves the key= prefix, only replaces the value.
    """

    def __init__(self, mappings=None):
        self.password_dict = dict(mappings.get('password', {})) if mappings else {}
        self._counter = len(self.password_dict)

    def _get_fake_password(self, real_value):
        """Return a consistent fake password for a real one."""
        if real_value in self.password_dict:
            return self.password_dict[real_value]
        self._counter += 1
        fake = f"scrubbed_pass_{self._counter}"
        self.password_dict[real_value] = fake
        return fake

    def scrub(self, text):
        """Replace password values in text. Returns scrubbed text."""
        def _replace(m):
            prefix = m.group(1)   # e.g. "password="
            value = m.group(2)    # e.g. "ce99185f0ff046d3"
            return prefix + self._get_fake_password(value)

        return _PASSWORD_RE.sub(_replace, text)
