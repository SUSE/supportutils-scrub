# verify.py
import base64
import os
import re
import ipaddress

import tarfile
from supportutils_scrub import fastsub
from supportutils_scrub.processor import (
    single_file_compression, compression_magic_ok, _iter_line_segments,
    looks_binary, is_binary_head, is_memory_dump, is_archive_name, _TEXT_PROBE,
    _ZstdPipe, _ZST_TAR_SUFFIXES,
)
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
    (re.compile(rf'(?i)(?<![\w.-])["\']?(?P<name>{_SECRET_NAME})["\']?\s*(?P<sep>[:=])\s*{_SECRET_VALUE}'),
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
            name = (m.groupdict().get('name') or '').lower()
            # corosync "token: 3000" is a timeout; zypper's ?credentials=NAME
            # names a credentials file
            if name.endswith('token') and val and val.strip('"\'').isdigit():
                continue
            if name == 'credentials' and m.start() and line[m.start() - 1] in '?&':
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


def _collect_terms(mappings: dict):
    """({mode: set of terms}, {term: label}): what the mapping check looks for."""
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
    return by_mode, labels


class _Terms:
    """The terms of one match mode.

    `rx` is the mode's one pattern: left boundary, a trie of the terms,
    right boundary. find() returns exactly the spans rx.finditer returns,
    without walking the text with it where it can be avoided: a pattern that
    starts with a lookbehind, or is case-insensitive, is tried by `re` at
    every character, and a mapping holds thousands of terms."""

    def __init__(self, mode, terms):
        self.mode = mode
        self.terms = terms
        left, right, self.ci = _MODES[mode]
        self._rx = None
        # A term holding a line end can never sit inside one line, except
        # as the line's very end: such a list is matched line by line, as
        # it always was.
        self.by_line = any('\n' in t or '\r' in t for t in terms)
        plain = all(ord(ch) < 128 for t in terms for ch in t)
        self._left = re.compile(left) if left else None
        self._tail = None           # compiled when first needed, see _scan
        self._plain = plain
        self._first = fastsub.literals(terms) if plain else None
        # Addresses, matched anywhere in the text (no boundaries): every one
        # holds an '@', which is rare. Around each '@' the text is compared
        # with the terms that have theirs at the same place, by a slice and
        # a set lookup, so the pattern for ten thousand addresses is never
        # even compiled.
        self._at = None
        if plain and not left and not right and not self.by_line:
            with_at = [t for t in terms if '@' in t]
            rest = [t for t in terms if '@' not in t]
            rest_first = fastsub.literals(rest) if rest else ()
            if len(with_at) >= 32 and rest_first is not None:
                # offset of the '@' -> what stands before it in some term
                # -> lengths of those terms, longest first
                self._at = set(with_at)
                self._at_local = {}
                for t in with_at:
                    k = t.index('@')
                    self._at_local.setdefault(k, {}).setdefault(t[:k], set()).add(len(t))
                self._at_local = sorted(
                    (k, {local: sorted(sizes, reverse=True) for local, sizes in by_local.items()})
                    for k, by_local in self._at_local.items())
                self._rest_first = rest_first
                self._rest_rx = re.compile(
                    '(?:' + build_trie_pattern(rest) + ')',
                    re.IGNORECASE if self.ci else 0) if rest else None

    @property
    def rx(self):
        if self._rx is None:
            left, right, ci = _MODES[self.mode]
            self._rx = re.compile(left + '(?:' + build_trie_pattern(self.terms) + ')' + right,
                                  re.IGNORECASE if ci else 0)
        return self._rx

    def _around_at(self, text, low):
        """find() for a list of addresses, or None when '@' is too frequent."""
        hay = low if self.ci else text
        # one '@' costs a slice per place a term has its own; beyond one in
        # 256 characters the pattern over the whole text is the cheaper way
        if fastsub._count(low, ('@',), len(low) >> 8) < 0 or \
                (self._rest_first and fastsub._count(low, self._rest_first, len(low) >> 5) < 0):
            return None
        found = []                           # every occurrence of a term
        terms = self._at
        for i in fastsub._positions(low, ('@',)):
            for k, by_local in self._at_local:
                start = i - k
                if start < 0:
                    break                    # the offsets only grow from here
                sizes = by_local.get(hay[start:i])
                if sizes:
                    for size in sizes:
                        if hay[start:start + size] in terms:
                            found.append((start, start + size))
        if self._rest_rx is not None:
            match = self._rest_rx.match
            for pos in fastsub._positions(low, self._rest_first):
                m = match(text, pos)
                if m is not None:
                    found.append(m.span())
        # what one pattern for all of them does: the leftmost, the longest
        # of those starting there, and on from its end
        found.sort(key=lambda se: (se[0], -se[1]))
        spans = []
        end = 0
        for s, e in found:
            if s >= end:
                spans.append((s, e))
                end = e
        return spans

    def _candidates(self, low):
        """Sorted positions a match can start at, or None when there are
        too many for that to pay off."""
        if self._first is None:
            return None
        n = fastsub._count(low, self._first, len(low) >> 5)
        if n < 0:
            return None
        return fastsub._positions(low, self._first) if n else []

    def _scan(self, hay):
        """find() by the pattern without its lookbehind and without
        IGNORECASE (hay is the lowercase copy for a case-insensitive mode):
        it starts with the terms' first characters, so `re` skips every
        position holding none of them. The lookbehind is applied here."""
        if self._tail is None:
            _left, right, _ci = _MODES[self.mode]
            self._tail = re.compile('(?:' + build_trie_pattern(self.terms) + ')' + right)
        spans = []
        i = 0
        search = self._tail.search
        left = self._left.match if self._left is not None else None
        while True:
            m = search(hay, i)
            if m is None:
                return spans
            s = m.start()
            if left is not None and left(hay, s) is None:
                i = s + 1                 # what the lookbehind does in rx
                continue
            i = m.end()
            spans.append((s, i))

    def find(self, text, low):
        """[(start, end)] of every match of rx in text, in order. low is
        fastsub.fold(text), or None."""
        if self.by_line:
            spans = []
            start = 0
            size = len(text)
            while start < size:
                nl = text.find('\n', start)
                end = size if nl == -1 else nl + 1
                spans.extend((start + m.start(), start + m.end())
                             for m in self.rx.finditer(text[start:end]))
                start = end
            return spans
        if low is not None:
            if self._at is not None:
                spans = self._around_at(text, low)
                if spans is not None:
                    return spans
            cand = self._candidates(low)
            if cand is not None:
                return [m.span() for m in fastsub.iter_at(self.rx, text, cand)]
            if self._plain:
                return self._scan(low if self.ci else text)
        return [m.span() for m in self.rx.finditer(text)]


def _build_matchers(mappings: dict):
    """([_Terms per match mode], {term: label}) for the mapping check."""
    by_mode, labels = _collect_terms(mappings)
    return [_Terms(mode, terms) for mode, terms in by_mode.items()], labels


def _build_terms(mappings: dict):
    """Return ([(regex, case_insensitive)], {term: label}) for the mapping check.

    One trie regex per match mode: a flat alternation with per-term
    lookarounds took minutes on a large file with a few thousand terms.
    """
    matchers, labels = _build_matchers(mappings)
    return [(t.rx, t.ci) for t in matchers], labels


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

# How the scan works. The checks themselves are the per-line code they always
# were (_line_findings). What changed is where they run: a file is read in
# line-aligned pieces, a piece is searched as a whole for the few things a
# check needs to fire at all (a dotted number, a run of hex octets, an '@', a
# secret word, a mapping term), and only the lines that hold one are handed
# to the per-line code. A piece the lowercase copy cannot stand in for is
# scanned line by line, as before.

_PIECE = 8 * 1024 * 1024           # text is scanned in pieces of about this size
_SPLIT_ABOVE = 32 * 1024 * 1024    # a plain file above this goes to the pool in ranges
_BIN_BLOCK = 8 * 1024 * 1024
_BIN_OVERLAP = 64 * 1024           # how far a binary range looks for a place to end

# where a finding sorts within its line: the order the checks run in
_R_MAP, _R_IP, _R_MAC, _R_EMAIL, _R_KRB, _R_PEM, _R_SECRET, _R_BASIC, _R_DN, _R_IDENT = range(10)

# Each starts with a literal, so `re` jumps to it. An IPv4 holds two octets
# between dots; a run _HEX_RUN_RE accepts holds four octets between five of
# the same separator.
_QUAD_HINT = re.compile(r'\.\d{1,3}\.\d{1,3}\.')
_MAC_HINTS = (re.compile(r':(?:[0-9A-Fa-f]{2}:){4}'), re.compile(r'-(?:[0-9A-Fa-f]{2}-){4}'))


def _normal_newlines(text):
    """Line ends as a text-mode read gives them: \r\n and a lone \r are \n."""
    if '\r' in text:
        return text.replace('\r\n', '\n').replace('\r', '\n')
    return text


def _line_findings(line, lineno, ctx, check_mac, out):
    """The checks that need no mapping, on one line. Appends (key, line
    number, category, value) to out; returns a private key header found on
    this line (it is a leak only if the line after it was not replaced)."""
    def add(rank, category, value):
        out.append(((lineno, rank, len(out)), lineno, category, value))

    pem = None
    if ctx['check_allowlist'] and '.' in line:
        for m in _IP_RE.finditer(line):
            ip_str = m.group(1)
            if _is_safe_ipv4(ip_str, ctx['safe_nets']):
                continue
            if line[m.end():m.end() + 13].lower() == '.in-addr.arpa' and \
                    _is_safe_ipv4('.'.join(reversed(ip_str.split('.'))),
                                  ctx['safe_nets']):
                continue
            if _looks_like_version_context(line, m.start()):
                continue
            add(_R_IP, 'unlisted IPv4', ip_str)

    if check_mac and (':' in line or '-' in line):
        for mac_str in _find_macs(line):
            if not _is_safe_mac(mac_str):
                add(_R_MAC, 'unlisted MAC', mac_str)

    if ctx['check_patterns']:
        if '@' in line:
            for m in _EMAIL_RE.finditer(line):
                email = m.group(1)
                if any(email.endswith(sfx) for sfx in _SYSTEMD_SUFFIXES):
                    continue
                local, domain = email.split('@', 1)
                domain = domain.lower()
                tld = domain.rsplit('.', 1)[-1] if '.' in domain else domain
                if domain not in _SAFE_EMAIL_DOMAINS \
                        and not is_preserved_domain(domain) \
                        and tld not in _FAKE_EMAIL_TLDS \
                        and not is_pseudonym(local):
                    add(_R_EMAIL, 'email address', email)

            for m in _KERBEROS_RE.finditer(line):
                realm = m.group(2)
                if is_pseudonym(realm) or is_preserved_domain(realm):
                    continue
                add(_R_KRB, 'Kerberos principal', m.group(0))

        low = line.lower()
        if any(h in low for h in _SECRET_HINTS):
            for label, snippet in _find_secrets(line):
                if label == 'private key':
                    pem = snippet
                else:
                    add(_R_SECRET, label, snippet)

        if 'asic' in line and 'uthorization' in line:
            for m in _BASIC_CRED_RE.finditer(line):
                if _basic_is_credential(m.group(1)):
                    add(_R_BASIC, 'HTTP Basic credential', line.strip()[:80])

        if 'dc=' in low:
            for m in _LDAP_DN_RE.finditer(line):
                if _dn_is_leak(m.group(0)):
                    add(_R_DN, 'LDAP DN', m.group(0).strip()[:80])
    return pem


def _pem_item(pem, next_lineno):
    """The finding for a key header whose body was not replaced. It is
    reported for the header's line and sorts where the line after it is
    looked at."""
    lineno, snippet = pem
    return ((next_lineno, _R_PEM, 0), lineno, 'private key', snippet)


def _scan_piece_by_line(text, ctx, base, pem, check_mac):
    """One piece, every check on every line. The reference the fast path
    has to agree with, and its fallback."""
    out = []
    labels = ctx['labels']
    ident = ctx['identity_lower']
    lineno = base
    start, size = 0, len(text)
    while start < size:
        nl = text.find('\n', start)
        end = size if nl == -1 else nl + 1
        line = text[start:end]
        start = end
        lineno += 1
        for mi, terms in enumerate(ctx['matchers']):
            for m in terms.rx.finditer(line):
                val = m.group(0)
                label = labels.get(val.lower() if terms.ci else val)
                if label == 'IPv4 address' and _looks_like_version_context(line, m.start()):
                    continue
                out.append(((lineno, _R_MAP, mi, m.start()), lineno, label, val))
        if pem is not None:
            if not is_pseudonym(line.strip()):
                out.append(_pem_item(pem, lineno))
            pem = None
        found = _line_findings(line, lineno, ctx, check_mac, out)
        if found is not None:
            pem = (lineno, found)
        if ident:
            line_lower = line.lower()
            for ti, (token, token_low) in enumerate(ident.items()):
                if token_low in line_lower:
                    out.append(((lineno, _R_IDENT, ti), lineno, 'system identity', token))
    return out, lineno - base, pem


def _scan_piece(text, ctx, base, pem, check_mac):
    """Findings of one piece of text that starts and ends at a line end.

    base: lines of the file before this piece. pem: (line number, snippet)
    of a private key header on the last line before it, or None. Returns
    ([(key, line number, category, value)], lines in the piece, pem)."""
    low = fastsub.fold(text)
    if low is None:
        return _scan_piece_by_line(text, ctx, base, pem, check_mac)
    out = []
    size = len(text)
    labels = ctx['labels']
    find, rfind, count = text.find, text.rfind, text.count

    # line number of a position, counted on from the last one asked for
    at = [0, base + 1]

    def line_of(pos):
        """(start of the line holding pos, its number)"""
        start = rfind('\n', 0, pos) + 1
        if start < at[0]:
            at[0], at[1] = 0, base + 1
        at[1] += count('\n', at[0], start)
        at[0] = start
        return start, at[1]

    # 1. mapping terms
    for mi, terms in enumerate(ctx['matchers']):
        for s, e in terms.find(text, low):
            val = text[s:e]
            label = labels.get(val.lower() if terms.ci else val)
            start, lineno = line_of(s)
            if label == 'IPv4 address' and _VERSION_CONTEXT_RE.search(
                    text[max(start, s - 20):s].rstrip()):
                continue
            out.append(((lineno, _R_MAP, mi, s - start), lineno, label, val))

    # 2. the lines one of the other checks can fire on
    hits = []
    if ctx['check_allowlist']:
        hits.extend(m.start() for m in _QUAD_HINT.finditer(text))
    if check_mac:
        for hint in _MAC_HINTS:
            hits.extend(m.start() for m in hint.finditer(text))
    if ctx['check_patterns']:
        hits.extend(fastsub._positions(text, ('@', 'uthorization')))
        hits.extend(fastsub._positions(low, _SECRET_HINTS + ('dc=',)))
    hits.sort()

    if pem is not None and size:
        nl = find('\n')
        if not is_pseudonym(text[:size if nl == -1 else nl + 1].strip()):
            out.append(_pem_item(pem, base + 1))
        pem = None

    end = 0
    for pos in hits:
        if pos < end:
            continue
        start, lineno = line_of(pos)
        nl = find('\n', pos)
        end = size if nl == -1 else nl + 1
        found = _line_findings(text[start:end], lineno, ctx, check_mac, out)
        if found is not None:
            if end >= size:
                pem = (lineno, found)        # the next line is in the next piece
            else:
                nl = find('\n', end)
                if not is_pseudonym(text[end:size if nl == -1 else nl + 1].strip()):
                    out.append(_pem_item((lineno, found), lineno + 1))

    # 3. identity tokens of the original
    for ti, (token, token_low) in enumerate(ctx['identity_lower'].items()):
        last = -1
        for pos in fastsub._positions(low, (token_low,)):
            start, lineno = line_of(pos)
            if start != last:
                last = start
                out.append(((lineno, _R_IDENT, ti), lineno, 'system identity', token))

    lines = count('\n') + (1 if size and not text.endswith('\n') else 0)
    return out, lines, pem


def _pieces(read, size=_PIECE):
    """Bytes from read(n) in pieces that end at a line end, of about size."""
    carry = b''
    while True:
        block = read(size)
        if not block:
            break
        buf = carry + block if carry else block
        cut = buf.rfind(b'\n')
        if cut == -1:
            # no \n: a lone \r ends a line too, unless it is the last byte
            # read (the \n of a \r\n may be the next one)
            cut = buf.rfind(b'\r', 0, len(buf) - 1)
        if cut == -1:
            carry = buf
            continue
        yield buf[:cut + 1]
        carry = buf[cut + 1:]
    if carry:
        yield carry


class _TextScan:
    """The scan of one text, fed piece by piece."""

    def __init__(self, ctx, check_mac):
        self.ctx, self.check_mac = ctx, check_mac
        self.items = []
        self.lines = 0
        self.pem = None
        self.first_line_replaced = None      # is_pseudonym() of the first line

    def feed(self, data):
        text = _normal_newlines(data.decode('utf-8', 'ignore'))
        if not text:
            return
        if self.first_line_replaced is None:
            nl = text.find('\n')
            self.first_line_replaced = is_pseudonym(
                text[:len(text) if nl == -1 else nl + 1].strip())
        try:
            out, n, self.pem = _scan_piece(text, self.ctx, self.lines, self.pem,
                                           self.check_mac)
        finally:
            fastsub.forget()
        self.items.extend(out)
        self.lines += n


def _binary_pieces(read):
    """The bytes of a binary stream in pieces that end at a line end or,
    where 8 MiB hold none, at a zero byte; failing both, anywhere."""
    carry = b''
    while True:
        block = read(_BIN_BLOCK)
        if not block:
            break
        buf = carry + block if carry else block
        cut = buf.rfind(b'\n')
        if cut == -1:
            cut = buf.rfind(b'\0')
        if cut == -1:
            cut = len(buf) - 1
        yield buf[:cut + 1]
        carry = buf[cut + 1:]
    if carry:
        yield carry


def _binary_hits(read, ctx, check_mac, counts):
    """What the checks find in a binary stream, counted per (category, value).

    A journal or a wtmp is not rewritten by the scrub, so whatever real
    value it holds is still there. Its bytes are decoded like text (what
    does not decode is dropped) and go through the same checks, piece by
    piece, with a zero byte ending a line as a line end does: such a file
    is fields of text between zero bytes. A line number would mean nothing,
    so a value is reported once with the number of times it was seen. A piece of nothing but zero bytes
    (a sparse lastlog is gigabytes of them) is not decoded at all."""
    for piece in _binary_pieces(read):
        if piece.count(0) == len(piece):
            continue
        text = _normal_newlines(piece.decode('utf-8', 'ignore')).replace('\0', '\n')
        try:
            items, _lines, _pem = _scan_piece(text, ctx, 0, None, check_mac)
        finally:
            fastsub.forget()
        for _key, _lineno, category, value in items:
            key = (category, value)
            counts[key] = counts.get(key, 0) + 1


class _Range:
    """read(n) over bytes [start, end) of a file."""

    def __init__(self, f, start, end):
        self._f, self._left = f, end - start
        f.seek(start)

    def read(self, n):
        data = self._f.read(min(n, self._left)) if self._left > 0 else b''
        self._left -= len(data)
        return data


class _Prepended:
    """read(n) that gives back the bytes already read from f, then f's."""

    def __init__(self, head, f):
        self._head, self._f = head, f

    def read(self, n):
        if self._head:
            data, self._head = self._head, b''
            return data
        return self._f.read(n)


def _is_binary_file(path, fname, comp):
    """A file the scrub does not rewrite as text: a dump, an archive, or a
    plain file whose head is not text."""
    if comp:
        return False
    return is_memory_dump(path) or is_archive_name(fname) or looks_binary(path)


_NEST_MAX = 4                      # archives inside archives, this deep
_HAND_OVER_MAX = 64 * 1024 * 1024  # a bigger member is scanned where the archive is read
_IN_FLIGHT_MAX = 256 * 1024 * 1024 # member bytes handed to the pool and not scanned yet


def _scan_tar(rel, tar, ctx, depth, out, hand_over=None):
    """The members of an open tar, read as a stream: each regular file is
    scanned like a file of the tree and reported as <archive>!/<member>. A
    real name left in a member's path is a finding as well. Findings go to
    out as they are made, so what was read before a damaged spot is kept.

    hand_over(mrel, name, data, depth): given the bytes of a member, returns
    something that stands in out for that member's findings until they are
    there (the pool scans the members of a big archive side by side)."""
    seen_parts = set()
    for member in tar:
        mrel = rel + '!/' + member.name
        for part in member.name.split('/'):
            if part and part not in seen_parts:
                seen_parts.add(part)
                for label, val in _name_hits(part, ctx):
                    out.append({'file': mrel, 'line': 0,
                                'category': f'{label} in file name', 'value': val})
        if member.isfile():
            name = os.path.basename(member.name)
            if hand_over is not None and member.size <= _HAND_OVER_MAX:
                out.append(hand_over(mrel, name, tar.extractfile(member).read(), depth))
            else:
                out.extend(_scan_stream(mrel, name, tar.extractfile(member), ctx, depth))


def _unreadable(rel, e):
    return {'file': rel, 'line': 0, 'category': 'unreadable file',
            'value': f'{type(e).__name__}: {e}'[:80]}


def _scan_stream(rel, fname, f, ctx, depth):
    """Every finding of one archive member, read from the stream f."""
    check_mac = ctx['check_allowlist'] and ctx['check_mac'] \
        and fname not in MACScrubber.skip_files
    scan = _TextScan(ctx, check_mac)
    counts = {}
    if is_archive_name(fname) and depth < _NEST_MAX:
        nested = []
        try:
            if fname.lower().endswith(_ZST_TAR_SUFFIXES):
                raise OSError("a .tar.zst inside an archive is not read")
            with tarfile.open(fileobj=f, mode='r|*') as tar:
                _scan_tar(rel, tar, ctx, depth + 1, nested)
        except Exception as e:
            # the stream cannot be read again as plain bytes: say so
            nested.append(_unreadable(rel, e))
        return nested
    try:
        comp = single_file_compression(fname)
        if comp and comp[1] is _ZstdPipe:
            raise OSError("no zstd reader for an archive member")
        src = comp[1](f, 'rb') if comp else f
        head = src.read(_TEXT_PROBE)
        read = _Prepended(head, src).read
        if is_binary_head(head):
            _binary_hits(read, ctx, check_mac, counts)
        else:
            for piece in _pieces(read):
                scan.feed(piece)
    except Exception as e:
        # what verify could not read to the end it has not verified
        return _file_findings(rel, scan, counts, f'{type(e).__name__}: {e}'[:80])
    return _file_findings(rel, scan, counts, None)


def _scan_archive_file(rel, fpath, fname, ctx, hand_over=None):
    """A tar archive in the tree, by its members; None when it is not one
    after all (nothing in it could be read as a tar). An archive that
    breaks off part way keeps the findings of the members before the
    damage and is reported as not read to its end."""
    out = []
    opened = False
    try:
        if fname.lower().endswith(_ZST_TAR_SUFFIXES):
            with single_file_compression('x.zst')[1](fpath, 'rb') as z, \
                    tarfile.open(fileobj=z, mode='r|') as tar:
                opened = True
                _scan_tar(rel, tar, ctx, 1, out, hand_over)
        else:
            with tarfile.open(fpath, 'r|*') as tar:
                opened = True
                _scan_tar(rel, tar, ctx, 1, out, hand_over)
    except Exception as e:
        if not opened and isinstance(e, tarfile.ReadError):
            return None
        out.append(_unreadable(rel, e))
    return out


def _scan_one_file(fpath_fname, scan_ctx):
    """Every finding of one file, in the order of its lines."""
    fpath, fname = fpath_fname
    rel = os.path.relpath(fpath, scan_ctx['folder_path'])
    if is_archive_name(fname):
        # A scrubbed tree holds its archives unpacked. One that is still
        # packed (kept whole for the dump it carries, or the output of
        # another tool) is read member by member: as a file it is compressed
        # bytes in which nothing would ever be found.
        found = _scan_archive_file(rel, fpath, fname, scan_ctx)
        if found is not None:
            return found
    comp = single_file_compression(fname)
    # A name that lies about its content must still be scanned: reading it
    # through the decompressor would raise and silently skip the file.
    if comp and not compression_magic_ok(fpath, comp[0]):
        comp = None
    check_mac = scan_ctx['check_allowlist'] and scan_ctx['check_mac'] \
        and fname not in MACScrubber.skip_files
    scan = _TextScan(scan_ctx, check_mac)
    counts = {}
    error = None
    try:
        if _is_binary_file(fpath, fname, comp):
            with open(fpath, 'rb') as f:
                _binary_hits(f.read, scan_ctx, check_mac, counts)
        else:
            with (comp[1] if comp else open)(fpath, 'rb') as f:
                head = f.read(_TEXT_PROBE) if comp else b''
                read = _Prepended(head, f).read
                if comp and is_binary_head(head):
                    # a compressed wtmp, dump or image: its bytes, not lines
                    _binary_hits(read, scan_ctx, check_mac, counts)
                else:
                    for piece in _pieces(read):
                        scan.feed(piece)
    except Exception as e:
        # a file verify cannot read to the end is not a file it has verified
        error = f'{type(e).__name__}: {e}'[:80]
    return _file_findings(rel, scan, counts, error)


def _file_findings(rel, scan, counts, error):
    items = list(scan.items)
    if scan.pem is not None:
        items.append(_pem_item(scan.pem, scan.lines + 1))
    items.sort(key=lambda it: it[0])
    out = [{'file': rel, 'line': lineno, 'category': category, 'value': value}
           for _key, lineno, category, value in items]
    for (category, value), n in sorted(counts.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
        out.append({'file': rel, 'line': 0, 'category': f'{category} in binary file',
                    'value': value, 'count': n})
    if error is not None:
        out.append({'file': rel, 'line': scan.lines, 'category': 'unreadable file',
                    'value': error})
    return out


# --- the pool ---------------------------------------------------------------

# What a scan needs, by the path of the file it was written to. The parent
# fills it before the pool starts, so a forked worker has it already; a
# worker started any other way loads the file once.
_CTX = {}


def _name_hits(name, ctx):
    """_mapping_hits for a file or directory name."""
    labels = ctx['labels']
    low = fastsub._fold(name)
    for terms in ctx['matchers']:
        for s, e in terms.find(name, low):
            val = name[s:e]
            label = labels.get(val.lower() if terms.ci else val)
            if label == 'IPv4 address' and _looks_like_version_context(name, s):
                continue
            yield label, val


def _prepare_ctx(ctx):
    """Add what is built from the mapping. Returns ctx."""
    ctx['matchers'], ctx['labels'] = _build_matchers(ctx['mappings'])
    return ctx


def _worker_ctx(ctx_path):
    ctx = _CTX.get(ctx_path)
    if ctx is None:
        import pickle
        with open(ctx_path, 'rb') as f:
            ctx = _CTX[ctx_path] = _prepare_ctx(pickle.load(f))
    return ctx


def _scan_batch(payload):
    ctx_path, batch = payload
    ctx = _worker_ctx(ctx_path)
    return [_scan_one_file(item, ctx) for item in batch]


def _scan_member(payload):
    """One archive member the parent read out of its archive."""
    import io
    ctx_path, mrel, name, data, depth = payload
    return _scan_stream(mrel, name, io.BytesIO(data), _worker_ctx(ctx_path), depth)


def _scan_text_range(payload):
    """One line-aligned byte range of a big plain file. Line numbers count
    from the range's start; the parent adds what came before."""
    ctx_path, fpath, fname, start, end = payload
    ctx = _worker_ctx(ctx_path)
    check_mac = ctx['check_allowlist'] and ctx['check_mac'] \
        and fname not in MACScrubber.skip_files
    scan = _TextScan(ctx, check_mac)
    error = None
    try:
        with open(fpath, 'rb') as f:
            for piece in _pieces(_Range(f, start, end).read):
                scan.feed(piece)
    except Exception as e:
        error = f'{type(e).__name__}: {e}'[:80]
    return scan.items, scan.lines, scan.pem, scan.first_line_replaced, error


def _scan_binary_range(payload):
    ctx_path, fpath, fname, start, end = payload
    ctx = _worker_ctx(ctx_path)
    check_mac = ctx['check_allowlist'] and ctx['check_mac'] \
        and fname not in MACScrubber.skip_files
    counts = {}
    try:
        with open(fpath, 'rb') as f:
            _binary_hits(_Range(f, start, end).read, ctx, check_mac, counts)
    except Exception as e:
        return counts, f'{type(e).__name__}: {e}'[:80]
    return counts, None


def _line_ranges(path, workers):
    """(start, end) byte ranges of a file, each ending at a \n."""
    size = os.path.getsize(path)
    target = max(_PIECE, size // (workers * 2) + 1)
    ranges = []
    with open(path, 'rb') as f:
        pos = 0
        while pos < size:
            end = min(pos + target, size)
            if end < size:
                f.seek(end)
                f.readline()
                end = f.tell()
            ranges.append((pos, end))
            pos = end
    return ranges


def _binary_ranges(path, size, workers):
    """(start, end) byte ranges of a binary file, each ending where a piece
    may end: after a line end or a zero byte found within 64 KiB."""
    step = max(_BIN_BLOCK, size // (workers * 2) + 1)
    ranges = []
    with open(path, 'rb') as f:
        pos = 0
        while pos < size:
            end = min(pos + step, size)
            if end < size:
                f.seek(end)
                look = f.read(_BIN_OVERLAP)
                cut = look.find(b'\n')
                if cut == -1:
                    cut = look.find(b'\0')
                end += cut + 1 if cut != -1 else len(look)
            ranges.append((pos, end))
            pos = end
    return ranges


def _merge_text_ranges(rel, parts):
    """The findings of a file scanned in ranges, as one scan would give them."""
    scan = _TextScan(None, False)
    error = None
    for items, lines, pem, first_replaced, err in parts:
        if scan.pem is not None and lines:
            if not first_replaced:
                scan.items.append(_pem_item(scan.pem, scan.lines + 1))
            scan.pem = None
        base = scan.lines
        for key, lineno, category, value in items:
            scan.items.append(((key[0] + base,) + key[1:], lineno + base, category, value))
        if pem is not None:
            scan.pem = (pem[0] + base, pem[1])
        scan.lines += lines
        error = error or err
    return _file_findings(rel, scan, {}, error)


def _batches(file_list, n):
    """Split (path, name) items into size-balanced buckets, the biggest
    files first."""
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


_verify_batches = _batches


def verify_scrubbed_folder(folder_path, mappings, original_folder=None,
                           config=None,
                           check_allowlist=True, check_patterns=True,
                           check_identity=True, jobs=None):
    """
    Walk folder_path and check every file for remaining sensitive data.

    Verification layers:
      1. Mapping-based   — check that known real values from mappings are gone
      2. IP allowlist    — every IPv4 must be in a known-safe range
      3. MAC allowlist   — every MAC must use the fake OUI (00:1A:2B)
      4. Pattern scan    — detect emails, secrets, keys, LDAP DNs, Kerberos principals
      5. Identity check  — if original_folder provided, extract system identity
                           and verify none of those tokens remain

    A binary file (a journal, wtmp, a dump, an image) is not read as lines:
    its bytes are searched for the mapping's real values, and each value
    found is one finding, "<kind> in binary file", with a count.

    Args:
        config: dict from config_reader; used to check obfuscate_private_ip setting.
                When private IP obfuscation is disabled, private IPs are safe.

    Returns list of findings:
        [{'file': str, 'line': int, 'category': str, 'value': str}, ...]
    in the order of the files and, within a file, of its lines.
    """
    import pickle
    import sys
    import tempfile
    from concurrent.futures import ProcessPoolExecutor

    findings = []

    # Build IP allowlist based on config
    obfuscate_private, obfuscate_public = False, True
    if config:
        obfuscate_private = config.obfuscate_private_ip
        obfuscate_public = getattr(config, 'obfuscate_public_ip', True)
    safe_nets = _build_safe_ipv4_nets(obfuscate_private_ip=obfuscate_private,
                                      obfuscate_public_ip=obfuscate_public)

    # --- Layer 5: identity tokens from original ---
    identity_tokens = set()
    if check_identity and original_folder:
        identity_tokens = _extract_identity_from_original(original_folder)
        # Remove tokens that are already in mappings (avoid double-reporting)
        all_mapped = set()
        for key in ('ip', 'ipv6', 'mac', 'domain', 'hostname', 'user', 'serial', 'keyword'):
            all_mapped.update(mappings.get(key, {}).keys())
        identity_tokens -= all_mapped

    # only what the mapping check reads: the rest of a mapping (pool
    # cursors, the pseudonym key) has no business in a worker
    plain_ctx = {
        'folder_path': folder_path,
        'mappings': {key: dict(mappings.get(key) or {}) for key, _, _, _ in _CATEGORIES},
        'check_allowlist': check_allowlist,
        'check_mac': getattr(config, 'obfuscate_mac', True) if config else True,
        'check_patterns': check_patterns,
        'safe_nets': safe_nets,
        # sorted: the order findings on one line come out in
        'identity_lower': {t: t.lower() for t in sorted(identity_tokens)},
    }
    scan_ctx = _prepare_ctx(dict(plain_ctx))

    # Binary sar data is deleted by the scrub; the sarDATE text files are
    # scanned, their header line names the host.
    _skip_binary_re = re.compile(r'^sa\d{8}(\.xz)?$')

    file_list = []
    if os.path.isfile(folder_path):
        # one file (a scrubbed archive, a single log) instead of a tree
        file_list.append((folder_path, os.path.basename(folder_path)))
        for label, val in _name_hits(os.path.basename(folder_path), scan_ctx):
            findings.append({'file': os.path.basename(folder_path), 'line': 0,
                             'category': f'{label} in file name', 'value': val})
        plain_ctx['folder_path'] = scan_ctx['folder_path'] = folder_path = \
            os.path.dirname(os.path.abspath(folder_path))
    for root, dirs, files in os.walk(folder_path) if not file_list else ():
        # a real name left in a file or directory name leaks as well
        for name in dirs + files:
            rel = os.path.relpath(os.path.join(root, name), folder_path)
            for label, val in _name_hits(name, scan_ctx):
                findings.append({'file': rel, 'line': 0,
                                 'category': f'{label} in file name', 'value': val})
        for fname in files:
            fpath = os.path.join(root, fname)
            if _skip_binary_re.match(fname) or os.path.islink(fpath) \
                    or not os.path.isfile(fpath):
                continue
            file_list.append((fpath, fname))

    total_files = len(file_list)
    workers = max(1, jobs) if jobs else min(8, os.cpu_count() or 4)
    per_file = {}                       # path -> its findings

    def progress(done):
        sys.stderr.write(f"\r  Verifying {done}/{total_files}")
        sys.stderr.flush()

    if workers == 1 or total_files <= 1:
        for done, item in enumerate(file_list, 1):
            per_file[item[0]] = _scan_one_file(item, scan_ctx)
            progress(done)
    else:
        # The scan is CPU-bound, so processes. A big file is split: a plain
        # text one into line-aligned ranges, a binary one into byte ranges,
        # so one multi-GB file no longer pins a single worker.
        fd, ctx_path = tempfile.mkstemp(prefix='supportutils-scrub-verify-', suffix='.pkl')
        _CTX[ctx_path] = scan_ctx
        try:
            # mkstemp = mode 0600; the file holds the mapping's real values
            with os.fdopen(fd, 'wb') as f:
                pickle.dump(plain_ctx, f, protocol=pickle.HIGHEST_PROTOCOL)
            small, text_parts, bin_parts, archives = [], {}, {}, []
            with ProcessPoolExecutor(max_workers=workers) as pool:
                for item in file_list:
                    fpath, fname = item
                    try:
                        size = os.path.getsize(fpath)
                    except OSError:
                        size = 0
                    comp = single_file_compression(fname)
                    if is_archive_name(fname) and size > 2 * _BIN_BLOCK:
                        # A big archive is read here, member by member, and
                        # its members are scanned across the pool. (As byte
                        # ranges it would be compressed data nothing is
                        # ever found in.)
                        archives.append(item)
                    elif size <= 2 * _BIN_BLOCK or is_archive_name(fname) \
                            or (comp and compression_magic_ok(fpath, comp[0])):
                        small.append(item)
                    elif _is_binary_file(fpath, fname, None):
                        bin_parts[fpath] = [
                            pool.submit(_scan_binary_range, (ctx_path, fpath, fname, start, end))
                            for start, end in _binary_ranges(fpath, size, workers)]
                    elif size <= _SPLIT_ABOVE:
                        small.append(item)
                    else:
                        text_parts[fpath] = [
                            pool.submit(_scan_text_range, (ctx_path, fpath, fname, start, end))
                            for start, end in _line_ranges(fpath, workers)]
                batch_futures = [(batch, pool.submit(_scan_batch, (ctx_path, batch)))
                                 for batch in _batches(small, workers * 8)]
                done = 0
                for fpath, fname in archives:
                    rel = os.path.relpath(fpath, folder_path)
                    in_flight = []                  # (future, bytes) not known done

                    def hand_over(mrel, name, data, depth):
                        # no more member bytes in the pool's queue than
                        # _IN_FLIGHT_MAX: wait for the oldest first
                        while in_flight and sum(n for _f, n in in_flight) > _IN_FLIGHT_MAX:
                            in_flight.pop(0)[0].result()
                        future = pool.submit(_scan_member, (ctx_path, mrel, name, data, depth))
                        in_flight.append((future, len(data)))
                        return future

                    found = _scan_archive_file(rel, fpath, fname, scan_ctx, hand_over)
                    if found is None:               # not a tar after all
                        found = _scan_one_file((fpath, fname), scan_ctx)
                    merged = []
                    for item in found:
                        if isinstance(item, dict):
                            merged.append(item)
                        else:
                            merged.extend(item.result())
                    per_file[fpath] = merged
                    done += 1
                    progress(done)
                for fpath, futures in text_parts.items():
                    rel = os.path.relpath(fpath, folder_path)
                    per_file[fpath] = _merge_text_ranges(rel, [f.result() for f in futures])
                    done += 1
                    progress(done)
                for fpath, futures in bin_parts.items():
                    rel = os.path.relpath(fpath, folder_path)
                    counts, error = {}, None
                    for f in futures:
                        part, err = f.result()
                        error = error or err
                        for key, n in part.items():
                            counts[key] = counts.get(key, 0) + n
                    per_file[fpath] = _file_findings(rel, _TextScan(None, False), counts, error)
                    done += 1
                    progress(done)
                for batch, future in batch_futures:
                    for item, found in zip(batch, future.result()):
                        per_file[item[0]] = found
                    done += len(batch)
                    progress(done)
        finally:
            _CTX.pop(ctx_path, None)
            try:
                os.unlink(ctx_path)
            except OSError:
                pass

    for fpath, _fname in file_list:
        findings.extend(per_file.get(fpath, ()))

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
