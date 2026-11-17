# verify.py
import base64
import os
import re
import ipaddress

from supportutils_scrub.processor import compressed_opener, compression_magic_ok
from supportutils_scrub.domain_scrubber import is_preserved_domain, _VALID_TLDS
from supportutils_scrub.ldap_dn_scrubber import _is_safe_ad_value
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.scrubber import is_pseudonym
from supportutils_scrub.trie_re import build_trie_pattern
from supportutils_scrub.username_scrubber import UsernameScrubber

# (mapping section, label, match mode, minimum length). The minimum follows
# what each scrubber itself replaces: keywords at any length, names from 3.
_CATEGORIES = [
    ('ip',          'IPv4 address',  'ip',          6),
    ('ipv6',        'IPv6 address',  'ipv6',        6),
    ('mac',         'MAC address',   'mac',         6),
    ('domain',      'domain',        'domain',      4),
    ('hostname',    'hostname',      'word_i',      3),
    ('user',        'username',      'word',        3),
    ('keyword',     'keyword',       'substring_i', 1),
    ('serial',      'serial/UUID',   'substring_i', 6),
    ('sid',         'SAP SID',       'sid',         3),
    ('ldap_dn',     'LDAP name',     'word_i',      3),
    ('email',       'email address', 'substring_i', 6),
    ('password',    'password',      'secret',      6),
    ('auth',        'credential',    'secret',      6),
    ('cloud_token', 'cloud token',   'secret',      6),
]

# Names verify alone ignores; the SUSE domains the scrubber leaves alone are
# checked with is_preserved_domain.
_SAFE_DOMAIN_VALUES = {
    'microsoft.com', 'microsoft.net',   # upstream vendor
    'windowsupdate.com', 'windows.com',
    'digicert.com', 'verisign.com',      # certificate authorities
    'globalsign.com', 'comodo.com',
}

# ---------------------------------------------------------------------------
# 1. IP allowlist — structural guarantee
# ---------------------------------------------------------------------------
# After scrubbing, every IPv4 in the output must be in one of these safe ranges.
# Anything else is flagged as a potential leak.
# Deliberately not the scrubber's pattern: verify must see what the scrubber
# misses. A sentence dot, an underscore and a dash range ("a-b") end an
# address; a package name before a dash ("nftables-1.4.4.2"), a further dotted
# number (an OID) or "+" after it (a version) do not.
_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
_IPV4 = rf'{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}'
_IP_LEFT = r'(?<![A-Za-z0-9.])(?<![A-Za-z]-)'
_IP_RIGHT = rf'(?![A-Za-z0-9+]|\.\d|-(?!{_IPV4}))'
_IP_RE = re.compile(rf'{_IP_LEFT}({_IPV4}){_IP_RIGHT}')

_SAFE_IPV4_ALWAYS = [
    # Fake pools used by ip_scrubber
    ipaddress.IPv4Network('198.16.0.0/12'),      # public pool
    ipaddress.IPv4Network('100.79.0.0/16'),       # link-local pool
    ipaddress.IPv4Network('100.80.0.0/12'),       # 10.x pool
    ipaddress.IPv4Network('100.96.0.0/12'),       # 172.16.x pool
    ipaddress.IPv4Network('100.112.0.0/12'),      # 192.168.x pool
    # Well-known safe addresses
    ipaddress.IPv4Network('127.0.0.0/8'),         # loopback
    ipaddress.IPv4Network('0.0.0.0/32'),          # unspecified
    ipaddress.IPv4Network('255.255.255.255/32'),  # broadcast
    ipaddress.IPv4Network('224.0.0.0/4'),         # multicast
    # All subnet masks (255.x.x.x are never real host IPs)
    ipaddress.IPv4Network('255.0.0.0/8'),
    # IANA special-purpose / documentation ranges
    ipaddress.IPv4Network('192.0.0.0/24'),        # IANA IPv4 special purpose
    ipaddress.IPv4Network('192.0.2.0/24'),        # TEST-NET-1
    ipaddress.IPv4Network('198.51.100.0/24'),     # TEST-NET-2
    ipaddress.IPv4Network('203.0.113.0/24'),      # TEST-NET-3
]

# Private/link-local ranges — safe when obfuscate_private_ip is disabled
_SAFE_IPV4_PRIVATE = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('169.254.0.0/16'),
]


def _build_safe_ipv4_nets(obfuscate_private_ip=False, obfuscate_public_ip=True):
    """Build the safe IPv4 list, including private ranges if they are not being scrubbed."""
    nets = list(_SAFE_IPV4_ALWAYS)
    if not obfuscate_private_ip:
        nets.extend(_SAFE_IPV4_PRIVATE)
    if not obfuscate_public_ip:
        # everything outside the private ranges is left as it is on purpose
        public = [ipaddress.IPv4Network('0.0.0.0/0')]
        for priv in _SAFE_IPV4_PRIVATE:
            public = [p for net in public
                      for p in (net.address_exclude(priv) if priv.subnet_of(net) else [net])]
        nets.extend(public)
    return nets


def _is_safe_ipv4(ip_str, safe_nets):
    """Return True if the IPv4 address is in a known-safe range."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return True  # not a valid IP, ignore
    return any(addr in net for net in safe_nets)


# Mirrors the suppression in ip_scrubber.scrub_text so verify agrees with scrub.
_VERSION_CONTEXT_RE = re.compile(r'(?:\b|_)(?:ver(?:sion)?|rev|build|release)[\s:="\']*$', re.IGNORECASE)


def _looks_like_version_context(line, match_start):
    """True if the IP at match_start is preceded by version-like context."""
    snippet = line[max(0, match_start - 20):match_start].rstrip()
    return bool(_VERSION_CONTEXT_RE.search(snippet))


# ---------------------------------------------------------------------------
# 2. MAC OUI allowlist
# ---------------------------------------------------------------------------
# A run of hex octets with one separator. Six octets are a MAC; a few longer
# runs carry one at a known offset: a DHCP client-id (01:<mac>), a DUID-LL
# (00:03:00:01:<mac>), a DUID-LLT (00:01:00:01:<time>:<mac>) and the iptables
# MAC= field (<dst mac>:<src mac>:<ethertype>). Other runs (fingerprints, key
# dumps) are not MACs.
_HEX_RUN_RE = re.compile(
    r'(?<![0-9A-Fa-f:])'
    r'([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\2[0-9A-Fa-f]{2}){4,})'
    r'(?![0-9A-Fa-f:]|-[0-9A-Fa-f])'
)


def _find_macs(line):
    for m in _HEX_RUN_RE.finditer(line):
        octets = m.group(1).split(m.group(2))
        n = len(octets)
        if n == 6:
            yield m.group(1)
            continue
        if m.group(2) != ':':
            continue
        head = [o.lower() for o in octets[:4]]
        if n == 7 and head[0] == '01':
            yield ':'.join(octets[1:])
        elif n == 10 and head == ['00', '03', '00', '01']:
            yield ':'.join(octets[4:])
        elif n == 14 and head == ['00', '01', '00', '01']:
            yield ':'.join(octets[8:])
        elif n == 14 and line[max(0, m.start() - 4):m.start()] == 'MAC=':
            yield ':'.join(octets[:6])
            yield ':'.join(octets[6:12])


_FAKE_MAC_OUI = '00:1a:2b'  # fake OUI used by mac_scrubber


_SAFE_MACS = {'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'}


def _is_safe_mac(mac_str):
    """Return True if the MAC uses the fake OUI prefix or is a known safe value."""
    normalized = mac_str.lower().replace('-', ':')
    return normalized.startswith(_FAKE_MAC_OUI) or normalized in _SAFE_MACS


# ---------------------------------------------------------------------------
# 3. Pattern scanning independent of mappings
# ---------------------------------------------------------------------------
# Require local part starts and ends with alnum (no leading dots/underscores)
_EMAIL_RE = re.compile(
    r'(?<![A-Za-z0-9._%+-])'
    r'([A-Za-z0-9][A-Za-z0-9._%+-]*[A-Za-z0-9]@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})'
    r'(?![A-Za-z0-9._%+-])'
)

# Well-known safe email-like patterns (not real addresses / not customer data)
_SAFE_EMAIL_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'localhost', 'localhost.localdomain',
    'microfocus.com',                            # vendor legacy
    'kernel.org', 'linux.it', 'vger.kernel.org',# kernel upstream
    'gnu.org', 'fsf.org', 'gcc.gnu.org',        # GNU/FSF
    'redhat.com', 'fedoraproject.org',           # upstream
    'debian.org', 'ubuntu.com', 'canonical.com', # upstream
    'apache.org', 'mozilla.org',                 # upstream
    'sourceforge.net', 'github.com', 'gitlab.com',
    'googlegroups.com', 'lists.sf.net',
}

# Short pseudo-TLDs from locale/gettext data (e.g. en@quot.mo)
_FAKE_EMAIL_TLDS = {'mo', 'po', 'gmo'}

# Systemd unit suffixes — name@instance.service is not an email
_SYSTEMD_SUFFIXES = ('.service', '.socket', '.timer', '.target', '.mount',
                     '.slice', '.scope', '.path', '.device', '.conf', '.tmp',
                     '.catalog')

# NFS/system default pseudo-domains
_SAFE_EMAIL_DOMAINS.update({
    'defaultv4iddomain.com',   # NFS idmapd default
    'localdomain',
    'scrubbed.local',          # our own fake email domain
})

# Independent of the password scrubber: any key whose name ends in a secret
# word (db_password, MYSQL_ROOT_PASSWORD, SecretAccessKey, system_token, ...),
# quoted or not, with a value of any length.
_SECRET_NAME = (r'[\w.-]*(?:pass(?:word|wd|phrase)?|pwd|pw|secret|secret[_-]?key'
                r'|token|authtok|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)')
_SECRET_VALUE = (r'(?:"(?P<dq>[^"\n]*)"|\'(?P<sq>[^\'\n]*)\''
                 r'|(?P<u>[^\s"\'`,;<>(){}\[\]]+))')

_SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'), 'private key'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS access key'),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'), 'JWT token'),
    (re.compile(rf'(?i)(?<![\w.-])["\']?{_SECRET_NAME}["\']?\s*(?P<sep>[:=])\s*{_SECRET_VALUE}'),
     'password value'),
    (re.compile(rf'(?i)<{_SECRET_NAME}>(?P<u>[^<\n]+)</'), 'password value'),
    (re.compile(rf'(?i)name\s*=\s*(["\']){_SECRET_NAME}\1[^>]*?value\s*=\s*(["\'])(?P<u>[^"\'<>]*)\2'),
     'password value'),
    (re.compile(r'(?i)(?<![\w.-])(?:bindpw|rootpw)\s+(?P<u>\S+)'), 'password value'),
    (re.compile(r'(?i)\bldap\w*(?:\s[^\n]*?)?\s-w\s+(?P<u>\S+)'), 'password value'),
    # /etc/zypp/credentials.d: the SCC login is a credential in its own right
    (re.compile(r'(?i)\busername\s*=\s*(?P<u>SCC_[0-9a-f]+)'), 'SCC credential'),
]
_SECRET_HINTS = ('pass', 'pw', 'secret', 'token', 'key', 'authtok', 'credential',
                 '-----begin', 'akia', 'eyj', 'scc_', ' -w ')
_SECRET_PLACEHOLDER_RE = re.compile(
    r'(?i)\*.*|\$.*|%.*|<.*|\{\{.*|/.*|none|null|nil|n/a|yes|no|true|false|on|off|x+|-+')


def _secret_value(m):
    gd = m.groupdict()
    for k in ('dq', 'sq', 'u'):
        if gd.get(k) is not None:
            return gd[k]
    return None


def _is_real_secret(val, sep=None):
    v = val.strip().strip('"\'')
    if not v or _SECRET_PLACEHOLDER_RE.fullmatch(v) or is_pseudonym(v):
        return False
    # "passwd: password changed", "pam_unix(passwd:chauthtok)": prose
    if sep == ':' and v.isalpha() and v.islower():
        return False
    return True


def _find_secrets(line):
    for pat, label in _SECRET_PATTERNS:
        for m in pat.finditer(line):
            val = _secret_value(m)
            if val is not None and not _is_real_secret(val, m.groupdict().get('sep')):
                continue
            yield label, m.group(0).strip()[:80]


# An HTTP Basic credential that survived scrubbing. The scrubbed form is still
# valid base64 of "login:secret", so the test cannot be "does it decode" — it
# is whether both halves are pseudonyms a scrubber allocates.
# The trailing lookahead stops the base64 class from matching the leading
# letters of a wholesale replacement such as "Basic SCRUBBED_BASIC_1".
_BASIC_CRED_RE = re.compile(
    r'(?i)(?:proxy-)?authorization"?\s*[:=]\s*"?basic[ \t]+'
    r'([A-Za-z0-9+/]+={0,2})(?![A-Za-z0-9+/=_-])'
)


def _basic_is_credential(blob):
    """True when a Basic blob still carries a real login.

    Anything that does not decode to printable "login:secret" is left alone:
    the scrubber replaces undecodable blobs wholesale, so a non-decoding value
    here is noise rather than a leak, and flagging it would fire on every file.
    """
    try:
        decoded = base64.b64decode(blob, validate=True).decode('utf-8')
    except Exception:
        return False
    if ':' not in decoded or not decoded.isprintable():
        return False
    login, _, secret = decoded.partition(':')
    return not (is_pseudonym(login) and is_pseudonym(secret))


# LDAP / Kerberos patterns. Values may hold spaces ("CN=John Smith"); a DN
# needs a DC= part, which keeps certificate subjects (CN, O, C) out.
_LDAP_DN_RE = re.compile(
    r'(?<![A-Za-z])(?:CN|OU|DC|O|L|ST|C)=[^,=\n]+(?:,\s*(?:CN|OU|DC|O|L|ST|C)=[^,=\n]+){2,}',
    re.IGNORECASE)
_DN_PART_RE = re.compile(r'(?i)(?<![A-Za-z])(CN|OU|DC)=([^,=\n]+)')
_SAFE_DC_VALUES = {'example', 'local', 'localdomain', 'test', 'invalid'}


def _dn_is_leak(dn):
    if 'sysdb' in dn.lower():
        return False
    parts = _DN_PART_RE.findall(dn)
    if not any(t.upper() == 'DC' for t, _ in parts):
        return False
    for typ, val in parts:
        val = val.strip().strip('"\'>)')
        if typ.upper() == 'DC':
            val = re.match(r'[\w-]*', val).group(0).lower()
            if val in _VALID_TLDS or val in _SAFE_DC_VALUES:
                continue
        elif _is_safe_ad_value(val):
            continue
        if not val or is_pseudonym(val) or is_preserved_domain(val):
            continue
        return True
    return False


# Require local part >= 3 alphanumeric chars, realm looks like an FQDN
# (at least one dot). Avoids binary garbage like "HEH@HHEHP" that happens
# to look like user@REALM but has no domain structure.
_KERBEROS_RE = re.compile(
    r'(?<![A-Za-z0-9@])([A-Za-z][A-Za-z0-9]{2,})@([A-Z][A-Z0-9-]*(?:\.[A-Z][A-Z0-9-]*)+)', re.ASCII)

# URL with potentially real hostnames
_URL_RE = re.compile(r'https?://([A-Za-z0-9.-]+)')


# ---------------------------------------------------------------------------
# 4. Reverse identity extraction
# ---------------------------------------------------------------------------

def _extract_identity_from_original(original_folder):
    """
    Parse key supportconfig files from the ORIGINAL (unscrubbed) folder to build
    a set of identity tokens: hostname, FQDN, IPs, MACs, DNS servers, NTP servers,
    NFS servers, serial numbers, domain names.
    Returns a set of strings to check for in the scrubbed output.
    """
    identity = set()
    if not original_folder or not os.path.isdir(original_folder):
        return identity

    # basic-environment.txt: hostname, FQDN
    _parse_basic_environment(original_folder, identity)
    # network.txt: IPs, MACs, DNS, domains
    _parse_network_txt(original_folder, identity)
    # hardware.txt: serial numbers
    _parse_hardware_txt(original_folder, identity)

    # Filter out tokens that would cause false positives
    # - Must be 8+ chars to avoid generic words (Name, Domain, Service, etc.)
    # - Must not be a common English word or field label
    _generic_words = {
        'name', 'domain', 'service', 'server', 'system', 'network', 'default',
        'address', 'version', 'type', 'none', 'true', 'false', 'enabled',
        'disabled', 'unknown', 'localhost', 'specified', 'available',
        'not specified', 'to be filled', 'not available', 'tracking',
        'internet', 'ethernet', 'loopback', 'broadcast', 'multicast',
        'protocol', 'interface', 'hardware', 'software', 'firmware',
        'configuration', 'information', 'description', 'manufacturer',
        'product name', 'serial number', 'asset tag',
    }
    # IPs/MACs that are safe and should not be tracked as identity
    _safe_identity_prefixes = (
        '127.', '0.0.', '255.', '224.', '::1', 'fe80:', 'ff0',  # loopback, broadcast, multicast, link-local, IPv6 multicast
        '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.',
        '192.168.', '169.254.',  # private, link-local
    )
    # Local/mDNS domains that are not sensitive customer data
    _safe_identity_suffixes = ('.box', '.local', '.localdomain', '.arpa')
    filtered = set()
    for t in identity:
        # Strip surrounding quotes
        t = t.strip("'\"")
        if len(t) < 8:
            continue
        tl = t.lower()
        if tl in _generic_words:
            continue
        if t.isdigit():
            continue
        # Skip safe/private IPs and link-local/ULA IPv6
        if any(t.startswith(p) for p in _safe_identity_prefixes) or _ULA_RE.match(t):
            continue
        # Skip local/mDNS/ARPA domains
        if any(t.lower().endswith(s) for s in _safe_identity_suffixes):
            continue
        # Skip vendor/infrastructure domains
        if t.lower() in _SAFE_DOMAIN_VALUES or is_preserved_domain(t):
            continue
        filtered.add(t)
    return filtered


_ULA_RE = re.compile(r'(?i)fd[0-9a-f]{2}:')


def _safe_read(filepath):
    """Read a file returning empty string on error."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''


def _parse_basic_environment(folder, identity):
    path = os.path.join(folder, 'basic-environment.txt')
    text = _safe_read(path)
    if not text:
        return
    # Hostname from "Linux <hostname> <kernel>" line
    for m in re.finditer(r'^Linux\s+(\S+)\s+', text, re.MULTILINE):
        hostname = m.group(1)
        identity.add(hostname)
        if '.' in hostname:
            identity.add(hostname.split('.')[0])  # short name
    # /etc/hostname section
    in_section = False
    for line in text.splitlines():
        if '# /etc/hostname' in line:
            in_section = True
            continue
        if in_section and line.startswith('#'):
            in_section = False
            continue
        if in_section:
            stripped = line.strip()
            if stripped:
                identity.add(stripped)


def _parse_network_txt(folder, identity):
    path = os.path.join(folder, 'network.txt')
    text = _safe_read(path)
    if not text:
        return
    # Extract IPs from ip addr output
    for m in re.finditer(r'inet6?\s+([0-9a-fA-F:.]+)(?:/\d+)?', text):
        identity.add(m.group(1))
    # Extract MACs from link/ether
    for m in re.finditer(r'link/ether\s+([0-9a-fA-F:]{17})', text):
        identity.add(m.group(1))
    # DNS servers from /etc/resolv.conf (only in resolv.conf section)
    in_resolv = False
    for line in text.splitlines():
        if '# /etc/resolv.conf' in line or '# resolv.conf' in line:
            in_resolv = True
            continue
        if in_resolv and line.startswith('#') and line.strip() != '#':
            in_resolv = False
        if in_resolv:
            m = re.match(r'^\s*nameserver\s+(\S+)', line)
            if m:
                identity.add(m.group(1))
            # search/domain only at line start (not inside /etc/services entries)
            m = re.match(r'^\s*(?:search|domain)\s+(.+)', line)
            if m:
                for domain in m.group(1).split():
                    # skip port/protocol patterns and bracketed names
                    if re.match(r'^\d+/(tcp|udp)$', domain):
                        continue
                    if domain.startswith('[') or domain.startswith('#'):
                        continue
                    identity.add(domain)


def _parse_hardware_txt(folder, identity):
    path = os.path.join(folder, 'hardware.txt')
    text = _safe_read(path)
    if not text:
        return
    # dmidecode serial numbers
    for m in re.finditer(r'Serial Number:\s+(\S+)', text):
        val = m.group(1)
        if val.lower() not in ('not', 'none', 'n/a', 'to', 'be', 'filled'):
            identity.add(val)
    # UUID
    for m in re.finditer(r'UUID:\s+(\S+)', text):
        identity.add(m.group(1))


# ---------------------------------------------------------------------------
# Core: build terms from mappings
# ---------------------------------------------------------------------------

# Fakes that are not word pseudonyms: the MAC scrubber's OUI, zeroed UUIDs.
_FAKE_HW_RE = re.compile(r'(?i)00:1a:2b:|00000000-0000-')

# Names too common to search for at 3 characters; the username scrubber never
# replaces the system words either.
_GENERIC_NAMES = (UsernameScrubber.COMMON_WORDS | UsernameScrubber.EXCLUDED_USERS
                  | {'localhost', 'linux', 'host', 'node', 'server', 'domain',
                     'name', 'none', 'null', 'true', 'false'})

_ALNUM_L, _ALNUM_R = r'(?<![A-Za-z0-9])', r'(?![A-Za-z0-9])'

# mode -> (left boundary, right boundary, case-insensitive)
_MODES = {
    'ip':          (_IP_LEFT, _IP_RIGHT, False),
    'ipv6':        (r'(?<![0-9A-Fa-f:])', r'(?![0-9A-Fa-f]|:[0-9A-Fa-f])', True),
    'mac':         (r'(?<![0-9A-Fa-f])', r'(?![0-9A-Fa-f])', True),
    'domain':      (r'(?<![A-Za-z0-9-])', r'(?![A-Za-z0-9-])', True),
    'word':        (_ALNUM_L, _ALNUM_R, False),
    'word_i':      (_ALNUM_L, _ALNUM_R, True),
    'sid':         (_ALNUM_L, _ALNUM_R, False),
    'secret':      (_ALNUM_L, _ALNUM_R, False),
    'substring_i': ('', '', True),
}


def _build_terms(mappings: dict):
    """Return ([(regex, case_insensitive)], {term: label}) for the mapping check.

    One trie regex per match mode: a flat alternation with per-term
    lookarounds took minutes on a large file with a few thousand terms.
    """
    fakes = set()
    for key, _, _, _ in _CATEGORIES:
        fakes.update(v for v in (mappings.get(key) or {}).values() if isinstance(v, str))

    by_mode = {}
    labels = {}
    for key, label, mode, min_len in _CATEGORIES:
        ci = _MODES[mode][2]
        for real_val in mappings.get(key) or {}:
            if not isinstance(real_val, str) or len(real_val) < min_len:
                continue
            low = real_val.lower()
            if low in _SAFE_DOMAIN_VALUES:
                continue
            # only a domain entry: a keyword or user that merely ends in
            # .suse.de is still the operator's and still verified
            if key == 'domain' and is_preserved_domain(real_val):
                continue
            if real_val in fakes or is_pseudonym(real_val) or _FAKE_HW_RE.match(real_val):
                continue
            if mode in ('word', 'word_i') and low in _GENERIC_NAMES:
                continue
            # a lowercase word in the password map is prose the scrubber caught
            if mode == 'secret' and real_val.isalpha() and (real_val.islower() or real_val.isupper()):
                continue
            terms = [real_val]
            if mode == 'sid':
                terms += ['SAP' + real_val, low + 'adm']
            for t in terms:
                t = t.lower() if ci else t
                by_mode.setdefault(mode, set()).add(t)
                labels.setdefault(t, label)

    term_res = []
    for mode, terms in by_mode.items():
        left, right, ci = _MODES[mode]
        rx = left + '(?:' + build_trie_pattern(terms) + ')' + right
        term_res.append((re.compile(rx, re.IGNORECASE if ci else 0), ci))
    return term_res, labels


def _mapping_hits(text, term_res, labels):
    for rx, ci in term_res:
        for m in rx.finditer(text):
            val = m.group(0)
            label = labels.get(val.lower() if ci else val)
            # Scrub leaves dotted quads in version context alone;
            # agree with that instead of flagging them.
            if label == 'IPv4 address' and _looks_like_version_context(text, m.start()):
                continue
            yield label, val


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _scan_one_file(fpath_fname, scan_ctx):
    fpath, fname = fpath_fname
    rel = os.path.relpath(fpath, scan_ctx['folder_path'])
    file_findings = []
    comp = compressed_opener(fname)
    # A name that lies about its content must still be scanned: reading it
    # through the decompressor would raise and silently skip the file.
    if comp and not compression_magic_ok(fpath, comp[0]):
        comp = None
    _open = comp[1] if comp else open
    lineno = 0

    def add(category, value):
        file_findings.append({'file': rel, 'line': lineno,
                              'category': category, 'value': value})

    check_mac = scan_ctx['check_allowlist'] and scan_ctx['check_mac'] \
        and fname not in MACScrubber.skip_files
    try:
        with _open(fpath, 'rt', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):

                for label, val in _mapping_hits(line, scan_ctx['term_res'], scan_ctx['labels']):
                    add(label, val)

                if scan_ctx['check_allowlist'] and '.' in line:
                    for m in _IP_RE.finditer(line):
                        ip_str = m.group(1)
                        if _is_safe_ipv4(ip_str, scan_ctx['safe_nets']):
                            continue
                        if _looks_like_version_context(line, m.start()):
                            continue
                        add('unlisted IPv4', ip_str)

                if check_mac and (':' in line or '-' in line):
                    for mac_str in _find_macs(line):
                        if not _is_safe_mac(mac_str):
                            add('unlisted MAC', mac_str)

                if scan_ctx['check_patterns']:
                    if '@' in line:
                        for m in _EMAIL_RE.finditer(line):
                            email = m.group(1)
                            if any(email.endswith(s) for s in _SYSTEMD_SUFFIXES):
                                continue
                            local, domain = email.split('@', 1)
                            domain = domain.lower()
                            tld = domain.rsplit('.', 1)[-1] if '.' in domain else domain
                            if domain not in _SAFE_EMAIL_DOMAINS \
                                    and not is_preserved_domain(domain) \
                                    and tld not in _FAKE_EMAIL_TLDS \
                                    and not is_pseudonym(local):
                                add('email address', email)

                        for m in _KERBEROS_RE.finditer(line):
                            realm = m.group(2)
                            if is_pseudonym(realm) or is_preserved_domain(realm):
                                continue
                            add('Kerberos principal', m.group(0))

                    low = line.lower()
                    if any(h in low for h in _SECRET_HINTS):
                        for label, snippet in _find_secrets(line):
                            add(label, snippet)

                    if 'asic' in line and 'uthorization' in line:
                        for m in _BASIC_CRED_RE.finditer(line):
                            if _basic_is_credential(m.group(1)):
                                add('HTTP Basic credential', line.strip()[:80])

                    if 'dc=' in low:
                        for m in _LDAP_DN_RE.finditer(line):
                            if _dn_is_leak(m.group(0)):
                                add('LDAP DN', m.group(0).strip()[:80])

                if scan_ctx['identity_lower']:
                    line_lower = line.lower()
                    for token, token_low in scan_ctx['identity_lower'].items():
                        if token_low in line_lower:
                            add('system identity', token)

    except Exception as e:
        # a file verify cannot read to the end is not a file it has verified
        add('unreadable file', f'{type(e).__name__}: {e}'[:80])
    return file_findings


def _scan_batch(payload):
    batch, scan_ctx = payload
    out = []
    for item in batch:
        out.extend(_scan_one_file(item, scan_ctx))
    return out


def _verify_batches(file_list, n):
    """Split (path, name) items into size-balanced buckets."""
    def _size(item):
        try:
            return os.path.getsize(item[0])
        except OSError:
            return 0
    buckets = [[] for _ in range(max(1, n))]
    loads = [0] * len(buckets)
    for item in sorted(file_list, key=_size, reverse=True):
        i = loads.index(min(loads))
        buckets[i].append(item)
        loads[i] += _size(item)
    return [b for b in buckets if b]


def verify_scrubbed_folder(folder_path, mappings, original_folder=None,
                           config=None,
                           check_allowlist=True, check_patterns=True,
                           check_identity=True, jobs=None):
    """
    Walk folder_path and check every text file for remaining sensitive data.

    Verification layers:
      1. Mapping-based   — check that known real values from mappings are gone
      2. IP allowlist    — every IPv4 must be in a known-safe range
      3. MAC allowlist   — every MAC must use the fake OUI (00:1A:2B)
      4. Pattern scan    — detect emails, secrets, keys, LDAP DNs, Kerberos principals
      5. Identity check  — if original_folder provided, extract system identity
                           and verify none of those tokens remain

    Args:
        config: dict from config_reader; used to check obfuscate_private_ip setting.
                When private IP obfuscation is disabled, private IPs are safe.

    Returns list of findings:
        [{'file': str, 'line': int, 'category': str, 'value': str}, ...]
    """
    findings = []

    # Build IP allowlist based on config
    obfuscate_private, obfuscate_public = False, True
    if config:
        obfuscate_private = config.obfuscate_private_ip
        obfuscate_public = getattr(config, 'obfuscate_public_ip', True)
    safe_nets = _build_safe_ipv4_nets(obfuscate_private_ip=obfuscate_private,
                                      obfuscate_public_ip=obfuscate_public)

    # --- Layer 1: mapping-based (one trie regex per match mode) ---
    term_res, labels = _build_terms(mappings)

    # --- Layer 5: identity tokens from original ---
    identity_tokens = set()
    if check_identity and original_folder:
        identity_tokens = _extract_identity_from_original(original_folder)
        # Remove tokens that are already in mappings (avoid double-reporting)
        all_mapped = set()
        for key in ('ip', 'ipv6', 'mac', 'domain', 'hostname', 'user', 'serial', 'keyword'):
            all_mapped.update(mappings.get(key, {}).keys())
        identity_tokens -= all_mapped

    # Binary sar data is deleted by the scrub; the sarDATE text files are
    # scanned, their header line names the host.
    _skip_binary_re = re.compile(r'^sa\d{8}(\.xz)?$')

    # Pre-lowercase identity tokens once
    identity_lower = {t: t.lower() for t in identity_tokens} if identity_tokens else {}

    file_list = []
    for root, dirs, files in os.walk(folder_path):
        # a real name left in a file or directory name leaks as well
        for name in dirs + files:
            rel = os.path.relpath(os.path.join(root, name), folder_path)
            for label, val in _mapping_hits(name, term_res, labels):
                findings.append({'file': rel, 'line': 0,
                                 'category': f'{label} in file name', 'value': val})
        for fname in files:
            fpath = os.path.join(root, fname)
            if _skip_binary_re.match(fname) or os.path.islink(fpath) \
                    or not os.path.isfile(fpath):
                continue
            file_list.append((fpath, fname))

    import sys
    from concurrent.futures import ProcessPoolExecutor, as_completed

    scan_ctx = {
        'folder_path': folder_path,
        'term_res': term_res,
        'labels': labels,
        'check_allowlist': check_allowlist,
        'check_mac': getattr(config, 'obfuscate_mac', True) if config else True,
        'check_patterns': check_patterns,
        'safe_nets': safe_nets,
        'identity_lower': identity_lower,
    }

    total_files = len(file_list)
    workers = max(1, jobs) if jobs else min(8, os.cpu_count() or 4)

    if workers == 1 or total_files <= 1:
        done = 0
        for item in file_list:
            findings.extend(_scan_one_file(item, scan_ctx))
            done += 1
            sys.stderr.write(f"\r  Verifying {done}/{total_files}")
            sys.stderr.flush()
    else:
        # The scan is CPU-bound regex work, so processes, not threads: a
        # thread pool serializes on the GIL and pins a single core no matter
        # how many threads it spawns. Size-balanced batches keep the pickled
        # scan context per task cheap and still give coarse progress.
        done = 0
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_scan_batch, (batch, scan_ctx)): len(batch)
                       for batch in _verify_batches(file_list, workers * 4)}
            for future in as_completed(futures):
                done += futures[future]
                sys.stderr.write(f"\r  Verifying {done}/{total_files}")
                sys.stderr.flush()
                findings.extend(future.result())

    sys.stderr.write(f"\r  Verifying {total_files}/{total_files} done.{' ' * 60}\n")
    sys.stderr.flush()

    # Deduplicate: same file+line+category+value
    seen = set()
    unique = []
    for f in findings:
        key = (f['file'], f['line'], f['category'], f['value'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
