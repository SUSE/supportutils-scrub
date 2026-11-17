# password_scrubber.py
import re
from supportutils_scrub.scrubber import Scrubber, is_pseudonym

#: Names whose VALUE is a credential wherever it appears. Kept to secrets:
#: an account or an application id is an identifier and is handled by the
#: username and keyword paths, and over-scrubbing a configuration makes it
#: unreadable, which is its own kind of damage. Any word prefix counts
#: (db_password, MYSQL_ROOT_PASSWORD, system_token, wpa_passphrase), which is
#: why the patterns carry no leading \b.
_SECRET_NAMES = (r'password|passwd|passphrase|secret_key|secret|token|apikey'
                 r'|api_key|bindpw|rootpw|authtok|psk')

#: key=value and key: value, the shape a configuration file uses, with the key
#: optionally quoted the way JSON writes it. A quoted value is taken whole,
#: spaces included. An unquoted one stops at whitespace and at the , ; ) } ]
#: that end it in a mount option list or a JSON/YAML flow, so
#: "password=x,uid=1000" keeps its uid.
_PASSWORD_RE = re.compile(
    r'(?i)(?P<prefix>(?P<name>' + _SECRET_NAMES + r')["\']?[ \t]*(?P<sep>[:=])[ \t]*)'
    r'(?:(?P<q>["\'])(?P<qval>.+?)(?P=q)'
    r'|(?P<val>[^\s"\'<>,;)}\]{[(][^\s"\'<>,;)}\]]*))'
)

#: <password>value</password>
_XML_SECRET_RE = re.compile(
    r'(?i)(<(\w*(?:' + _SECRET_NAMES + r'))>)([^<\n]+)(</\2>)'
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
    r'(?i)(?P<prefix>--(?:passphrase|password|passwd|pass|bindpw)[= ]|\bcredentials=)'
    r'(?:(?P<q>["\'])(?P<qval>[^"\']{2,}?)(?P=q)'
    r'|(?P<val>[^\s"\';,)]{2,}))'
)

# -w is the bind password only for the ldap tools; grep -w and ping -w are not.
_LDAP_W_RE = re.compile(
    r'(?P<prefix>\bldap\w*(?:[ \t][^\n]*?)?[ \t]-w[ \t]+)'
    r'(?:(?P<q>["\'])(?P<qval>.+?)(?P=q)|(?P<val>[^\s"\']+))'
)

# slapd.conf and nslcd.conf separate the value with blanks: "bindpw value".
_BLANK_SECRET_RE = re.compile(
    r'(?im)(?P<prefix>^[ \t]*(?:bindpw|rootpw)[ \t]+)'
    r'(?:(?P<q>["\'])(?P<qval>.+?)(?P=q)|(?P<val>\S+))'
)

_PLACEHOLDER_LEAD = ('*', '<', '$', '-')

_VAR_RE = re.compile(r'\$\{?\w+\}?')
_NOT_SECRET = frozenset({'none', 'null', 'nil', 'yes', 'no', 'true', 'false',
                         'bearer', 'basic'})


def _is_placeholder(value):
    """True for a value that is not a secret: a boolean or null, ***, the
    *REMOVED BY SUPPORTCONFIG* marker, <password>, $VAR, or a pseudonym.
    Bearer/Basic are left for the token scrubbers to take the whole header."""
    return (value.lower() in _NOT_SECRET or not value.strip('*')
            or value.startswith('*REMOVED')
            or (value.startswith('<') and value.endswith('>'))
            or _VAR_RE.fullmatch(value) is not None or is_pseudonym(value))


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
            value = m.group('qval') or m.group('val')
            if _is_placeholder(value):
                return m.group(0)
            # "passwd: password changed" is the passwd program talking, and
            # "pam_unix(passwd:chauthtok)" or "(gdm-password:auth)" is a PAM
            # service:type pair. Neither is a key.
            if m.group('val') and m.group('sep') == ':' and (
                    m.group('name').lower() == 'passwd'
                    or m.string.startswith(')', m.end())):
                return m.group(0)
            quote = m.group('q') or ''
            return m.group('prefix') + quote + self._get_fake_password(value) + quote

        def _replace_xml(m):
            if _is_placeholder(m.group(3)):
                return m.group(0)
            return m.group(1) + self._get_fake_password(m.group(3)) + m.group(4)

        def _replace_attr(m):
            prefix, quote, value = m.group(1), m.group(3), m.group(4)
            return prefix + quote + self._get_fake_password(value) + quote

        def _replace_cli(m):
            value = m.group('qval') or m.group('val')
            if value.startswith(_PLACEHOLDER_LEAD) or _is_placeholder(value):
                return m.group(0)
            # credentials=/etc/samba/cred.txt names the file, not the secret.
            if m.group('prefix').lower() == 'credentials=' and value.startswith('/'):
                return m.group(0)
            quote = m.group('q') or ''
            return m.group('prefix') + quote + self._get_fake_password(value) + quote

        text = _ATTR_PAIR_RE.sub(_replace_attr, text)
        text = _XML_SECRET_RE.sub(_replace_xml, text)
        text = _PASSWORD_RE.sub(_replace, text)
        text = _BLANK_SECRET_RE.sub(_replace_cli, text)
        if 'ldap' in text:
            text = _LDAP_W_RE.sub(_replace_cli, text)
        return _CLI_SECRET_RE.sub(_replace_cli, text)
