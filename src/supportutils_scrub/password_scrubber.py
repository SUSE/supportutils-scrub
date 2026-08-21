# password_scrubber.py
import re
from supportutils_scrub.scrubber import Scrubber

#: Names whose VALUE is a credential wherever it appears. Kept to secrets:
#: an account or an application id is an identifier and is handled by the
#: username and keyword paths, and over-scrubbing a configuration makes it
#: unreadable, which is its own kind of damage.
_SECRET_NAMES = r'password|passwd|secret|token|apikey|api_key|passphrase'

#: key=value and key: value, the shape a configuration file uses. The value
#: charset used to be letters, digits, + and /, so a secret carrying a tilde
#: or a dot was only partly replaced and the rest of it shipped.
_PASSWORD_RE = re.compile(
    r'(?i)(\b(?:' + _SECRET_NAMES + r')\s*[:=]\s*)'
    r'(["\']?)'
    r'(?!\*REMOVED)'
    r'(?!scrubbed_pass_)'
    r'([^\s"\'<>]{8,})'
)

#: name="passwd" value="..." , which is how a cluster configuration carries
#: the credentials its fencing agents authenticate with. Neither form above
#: matches it: the name is followed by a quote, not by a separator, so a
#: fencing password survived a full scrub run untouched.
_ATTR_PAIR_RE = re.compile(
    r'(?i)(name\s*=\s*(["\'])(?:' + _SECRET_NAMES + r')\2'
    r'[^>]*?value\s*=\s*)(["\'])'
    r'(?!\*REMOVED)'
    r'(?!scrubbed_pass_)'
    r'([^"\'<>]{6,})'
    r'\3'
)

# Command-line secrets. Values passed as CLI options survive into ps/history
# dumps and OCR'd terminal screenshots, and the config-style pattern above
# never matches them (no ':'/'=' after the keyword in "--passphrase VALUE").
# Quoted values may contain spaces; unquoted values stop at whitespace and
# closing punctuation. A value that is itself a flag (--password --stdin),
# a placeholder (***, *REMOVED*, <password>), a shell variable ($PASS) or an
# already-scrubbed token is left alone. The bare "-p" short option is NOT
# matched: attached letters are usually a flag cluster (ss -plnt, tar -pxvf).
_CLI_SECRET_RE = re.compile(
    r'(?i)(?P<prefix>--(?:passphrase|password|passwd|pass)[= ]|\bcredentials=)'
    r'(?:(?P<q>["\'])(?P<qval>[^"\']{2,}?)(?P=q)'
    r'|(?P<val>[^\s"\';,)]{2,}))'
)

_PLACEHOLDER_LEAD = ('*', '<', '$', '-')


class PasswordScrubber(Scrubber):
    name = 'password'
    """Finds and replaces password values """

    def __init__(self, mappings=None, deterministic=False):
        self.password_dict = dict(mappings.get('password', {})) if mappings else {}
        self._counter = len(self.password_dict)
        self.deterministic = deterministic

    @property
    def mapping(self):
        return self.password_dict

    def _get_fake_password(self, real_value):
        """Returns fake password for a real one."""
        if real_value in self.password_dict:
            return self.password_dict[real_value]
        if self.deterministic:
            from supportutils_scrub.det import dhash
            fake = f"scrubbed_pass_{dhash(real_value)}"
        else:
            self._counter += 1
            fake = f"scrubbed_pass_{self._counter}"
        self.password_dict[real_value] = fake
        return fake

    def scrub(self, text):
        """Replaces password values in text. Returns scrubbed text."""
        def _replace(m):
            prefix, quote, value = m.group(1), m.group(2), m.group(3)
            return prefix + quote + self._get_fake_password(value)

        def _replace_attr(m):
            prefix, quote, value = m.group(1), m.group(3), m.group(4)
            return prefix + quote + self._get_fake_password(value) + quote

        def _replace_cli(m):
            value = m.group('qval') or m.group('val')
            if value.startswith(_PLACEHOLDER_LEAD) or value.startswith('scrubbed_pass_'):
                return m.group(0)
            quote = m.group('q') or ''
            return m.group('prefix') + quote + self._get_fake_password(value) + quote

        text = _ATTR_PAIR_RE.sub(_replace_attr, text)
        text = _PASSWORD_RE.sub(_replace, text)
        return _CLI_SECRET_RE.sub(_replace_cli, text)
