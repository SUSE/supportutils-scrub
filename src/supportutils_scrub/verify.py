# verify.py
"""Post-scrub verification: scan scrubbed files for any remaining real values."""
import os
import re
import ipaddress

# ---------------------------------------------------------------------------
# Original mapping-based categories
# ---------------------------------------------------------------------------
# (category_key, display_label, match_mode)
# match_mode:
#   'boundary'  – \bVALUE\b  (username, hostname: same logic as their scrubbers)
#   'ip'        – lookbehind/lookahead mirroring CIDR_RE  (avoids version-string false positives)
#   'substring' – plain 'value in line'  (domain, mac, ipv6, serial, keyword)
_CATEGORIES = [
    ('ip',       'IPv4 address',  'ip'),
    ('ipv6',     'IPv6 address',  'substring'),
    ('mac',      'MAC address',   'substring'),
    ('domain',   'domain',        'substring'),
    ('hostname', 'hostname',      'boundary'),
    ('user',     'username',      'boundary'),
    ('keyword',  'keyword',       'substring'),
    ('serial',   'serial/UUID',   'substring'),
]

# Real values shorter than this are skipped to reduce noise
_MIN_VALUE_LEN = 6

# Domains to never flag as leaks (vendor/infrastructure, not customer data)
_SAFE_DOMAIN_VALUES = {
    'susecloud.net',
    'suse.org', 'suse.com', 'suse.de', 'suse.net',
    'opensuse.org',
    'microsoft.com', 'microsoft.net',   # upstream vendor
    'windowsupdate.com', 'windows.com',
    'digicert.com', 'verisign.com',      # certificate authorities
    'globalsign.com', 'comodo.com',
}

# Mirrors the lookbehind/lookahead in ip_scrubber.CIDR_RE so that IPs embedded
# in version strings (e.g. "nftables-1.4.4.2") are not flagged as leaks.
_IP_BOUNDARY = r'(?<![A-Za-z0-9.\-]){}(?![A-Za-z0-9.\-])'

# ---------------------------------------------------------------------------
# 1. IP allowlist — structural guarantee
# ---------------------------------------------------------------------------
# After scrubbing, every IPv4 in the output must be in one of these safe ranges.
# Anything else is flagged as a potential leak.
_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
_IP_RE = re.compile(
    rf'(?<![A-Za-z0-9.\-])'
    rf'({_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET})'
    rf'(?![A-Za-z0-9.\-])'
)

_SAFE_IPV4_ALWAYS = [
    # Fake pools used by ip_scrubber
    ipaddress.IPv4Network('198.18.0.0/15'),      # public pool
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


def _build_safe_ipv4_nets(obfuscate_private_ip=False):
    """Build the safe IPv4 list, including private ranges if they are not being scrubbed."""
    nets = list(_SAFE_IPV4_ALWAYS)
    if not obfuscate_private_ip:
        nets.extend(_SAFE_IPV4_PRIVATE)
    return nets


def _is_safe_ipv4(ip_str, safe_nets):
    """Return True if the IPv4 address is in a known-safe range."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return True  # not a valid IP, ignore
    # IPs with first octet <= 2 are almost never real network addresses —
    # they are typically version strings (e.g. 2.12.0.4, 1.0.8.177)
    if addr.packed[0] <= 2:
        return True
    return any(addr in net for net in safe_nets)


# ---------------------------------------------------------------------------
# 2. MAC OUI allowlist
# ---------------------------------------------------------------------------
_MAC_RE = re.compile(
    r'(?<![0-9A-Fa-f:])'
    r'((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})'
    r'(?![0-9A-Fa-f:])',
    re.IGNORECASE
)
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
    'suse.com', 'suse.de', 'suse.net',           # vendor
    'novell.com', 'microfocus.com',             # vendor legacy
    'kernel.org', 'linux.it', 'vger.kernel.org',# kernel upstream
    'gnu.org', 'fsf.org', 'gcc.gnu.org',        # GNU/FSF
    'redhat.com', 'fedoraproject.org',           # upstream
    'debian.org', 'ubuntu.com', 'canonical.com', # upstream
    'apache.org', 'mozilla.org',                 # upstream
    'sourceforge.net', 'github.com', 'gitlab.com',
    'googlegroups.com', 'lists.sf.net',
    'opensuse.org', 'opensuse.com',              # community
    'suse.org',                                   # vendor community
}

# Short pseudo-TLDs from locale/gettext data (e.g. en@quot.mo)
_FAKE_EMAIL_TLDS = {'mo', 'po', 'gmo'}

# Systemd unit suffixes — name@instance.service is not an email
_SYSTEMD_SUFFIXES = ('.service', '.socket', '.timer', '.target', '.mount',
                     '.slice', '.scope', '.path', '.device', '.conf', '.tmp')

# NFS/system default pseudo-domains
_SAFE_EMAIL_DOMAINS.update({
    'defaultv4iddomain.com',   # NFS idmapd default
    'localdomain',
    'scrubbed.local',          # our own fake email domain
    'susecloud.net',           # SUSE public cloud infrastructure
})

_SECRET_PATTERNS = [
    # PEM-encoded keys and certificates
    (re.compile(r'-----BEGIN\s+(RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'), 'private key'),
    (re.compile(r'-----BEGIN CERTIFICATE-----'), 'certificate'),
    # API keys / tokens (generic high-entropy after keyword)
    (re.compile(r'(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{20,})', re.IGNORECASE), 'api key/token'),
    # AWS access key IDs
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS access key'),
    # JWT tokens
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'), 'JWT token'),
    # Generic password assignments — only "password" and "passwd" with = delimiter
    # Skip values already redacted by supportconfig or our scrubber
    (re.compile(r'(?i)\b(?:password|passwd)\s*=\s*["\']?(?!\*REMOVED)(?!scrubbed_pass_)([A-Za-z0-9+/]{8,})'), 'password value'),
]

# LDAP / Kerberos patterns
_LDAP_DN_RE = re.compile(r'(?:CN|OU|DC|O|L|ST|C)=[^,\s]{2,}(?:,\s*(?:CN|OU|DC|O|L|ST|C)=[^,\s]{2,}){2,}', re.IGNORECASE)
# Require local part >= 3 alphanumeric chars (no dots/special), realm all-uppercase
# letters/digits only. Avoids binary garbage and shell completion patterns.
_KERBEROS_RE = re.compile(r'(?<![A-Za-z0-9@])([A-Za-z][A-Za-z0-9]{2,})@([A-Z][A-Z0-9]{3,}(?:\.[A-Z][A-Z0-9]{1,})*)', re.ASCII)

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
        '127.', '0.0.', '255.', '224.', '::1', 'fe80:', 'fd', 'ff0',  # loopback, broadcast, multicast, link-local, ULA, IPv6 multicast
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
        if any(t.startswith(p) for p in _safe_identity_prefixes):
            continue
        # Skip local/mDNS/ARPA domains
        if any(t.lower().endswith(s) for s in _safe_identity_suffixes):
            continue
        # Skip vendor/infrastructure domains
        if t.lower() in _SAFE_DOMAIN_VALUES:
            continue
        filtered.add(t)
    return filtered


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
# Core: build terms from mappings (original approach)
# ---------------------------------------------------------------------------

# Skip our own fake replacement values in mapping keys
_FAKE_VALUE_RE = re.compile(
    r'^(?:hostname_\d+|user_\d+|domain_\d+|email_\d+@scrubbed\.local'
    r'|scrubbed_pass_\d+|SCRUBBED_\w+_\d+|SERIAL_\d+'
    r'|00:1[Aa]:2[Bb]:[0-9A-Fa-f:]+|00000000-0000-)'
)


def _build_terms(mappings: dict) -> list:
    """Return [(real_value, category_label, compiled_pattern | None), ...]."""
    # Collect all fake values so we skip them if they appear as keys
    all_fake_values = set()
    for cat_key in ('ip', 'ipv6', 'mac', 'domain', 'hostname', 'user',
                    'keyword', 'serial', 'email', 'password', 'cloud_token'):
        for fake_val in mappings.get(cat_key, {}).values():
            all_fake_values.add(fake_val)

    terms = []
    for key, label, mode in _CATEGORIES:
        for real_val in mappings.get(key, {}):
            if len(real_val) < _MIN_VALUE_LEN:
                continue
            if real_val.lower() in _SAFE_DOMAIN_VALUES:
                continue
            # Skip fake values that ended up as keys (e.g. from chained mappings)
            if real_val in all_fake_values or _FAKE_VALUE_RE.match(real_val):
                continue
            if mode == 'boundary':
                pat = re.compile(r'\b' + re.escape(real_val) + r'\b')
            elif mode == 'ip':
                pat = re.compile(_IP_BOUNDARY.format(re.escape(real_val)))
            else:
                pat = None   # substring – checked with 'in'
            terms.append((real_val, label, pat))
    return terms


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_scrubbed_folder(folder_path, mappings, original_folder=None,
                           config=None,
                           check_allowlist=True, check_patterns=True,
                           check_identity=True):
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
    obfuscate_private = False
    if config:
        obfuscate_private = config.get('obfuscate_private_ip', 'no').lower() == 'yes'
    safe_nets = _build_safe_ipv4_nets(obfuscate_private_ip=obfuscate_private)

    # --- Layer 1: mapping-based (original approach) ---
    terms = _build_terms(mappings)

    # --- Layer 5: identity tokens from original ---
    identity_tokens = set()
    if check_identity and original_folder:
        identity_tokens = _extract_identity_from_original(original_folder)
        # Remove tokens that are already in mappings (avoid double-reporting)
        all_mapped = set()
        for key in ('ip', 'ipv6', 'mac', 'domain', 'hostname', 'user', 'serial', 'keyword'):
            all_mapped.update(mappings.get(key, {}).keys())
        identity_tokens -= all_mapped

    # Files that are safe to skip for pattern scanning (binary sar data is already deleted)
    _skip_binary_re = re.compile(r'^sa\d{8}(\.xz)?$')
    # Also skip sar text files — they contain only numeric performance data, no sensitive info
    _skip_sar_re = re.compile(r'^sar\d{8}$')

    # Pre-compute cheap string hints for secret patterns to avoid regex on every line
    _secret_hints = ['-----BEGIN', 'api_key', 'apikey', 'api-key', 'secret_key', 'secret-key',
                     'access_token', 'access-token', 'auth_token', 'auth-token',
                     'AKIA', 'eyJ', 'password', 'passwd', 'pass=', 'pass:']

    # Pre-lowercase identity tokens once
    identity_lower = {t: t.lower() for t in identity_tokens} if identity_tokens else {}

    file_list = []
    for root, _, files in os.walk(folder_path):
        for fname in files:
            if not _skip_binary_re.match(fname) and not _skip_sar_re.match(fname):
                file_list.append((os.path.join(root, fname), fname))

    import sys
    total_files = len(file_list)
    for file_idx, (fpath, fname) in enumerate(file_list):
        rel = os.path.relpath(fpath, folder_path)
        # Progress indicator (every 20 files)
        if file_idx % 20 == 0:
            sys.stderr.write(f"\r  Verifying... {file_idx}/{total_files} files")
            sys.stderr.flush()
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for lineno, line in enumerate(f, 1):

                    # Layer 1: mapping-based
                    if terms:
                        for real_val, category, pat in terms:
                            if pat is not None:
                                found = bool(pat.search(line))
                            else:
                                found = real_val in line
                            if found:
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': category, 'value': real_val,
                                })

                    # Layer 2: IP allowlist — cheap pre-check: line must contain a digit
                    if check_allowlist and '.' in line:
                        for m in _IP_RE.finditer(line):
                            ip_str = m.group(1)
                            if not _is_safe_ipv4(ip_str, safe_nets):
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': 'unlisted IPv4',
                                    'value': ip_str,
                                })

                    # Layer 3: MAC allowlist — cheap pre-check: line must contain ':'
                    if check_allowlist and ':' in line:
                        for m in _MAC_RE.finditer(line):
                            mac_str = m.group(1)
                            if not _is_safe_mac(mac_str):
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': 'unlisted MAC',
                                    'value': mac_str,
                                })

                    # Layer 4: pattern scanning
                    if check_patterns:
                        # Emails — cheap pre-check: line must contain '@'
                        if '@' in line:
                            for m in _EMAIL_RE.finditer(line):
                                email = m.group(1)
                                # Skip systemd template units (user@1000.service)
                                if any(email.endswith(s) for s in _SYSTEMD_SUFFIXES):
                                    continue
                                domain = email.split('@')[1].lower()
                                tld = domain.rsplit('.', 1)[-1] if '.' in domain else domain
                                if domain not in _SAFE_EMAIL_DOMAINS \
                                        and tld not in _FAKE_EMAIL_TLDS:
                                    findings.append({
                                        'file': rel, 'line': lineno,
                                        'category': 'email address',
                                        'value': email,
                                    })

                            # Kerberos principals — also requires '@'
                            for m in _KERBEROS_RE.finditer(line):
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': 'Kerberos principal',
                                    'value': m.group(0),
                                })

                        # Secrets / keys / tokens — cheap hint check first
                        # Skip lines containing already-scrubbed values
                        if 'SCRUBBED_' not in line:
                            for hint in _secret_hints:
                                if hint in line:
                                    for pat, label in _SECRET_PATTERNS:
                                        if pat.search(line):
                                            snippet = line.strip()[:80]
                                            findings.append({
                                                'file': rel, 'line': lineno,
                                                'category': label,
                                                'value': snippet,
                                            })
                                    break  # only need one hint to trigger

                        # LDAP DNs — cheap pre-check
                        if '=' in line and ('CN=' in line or 'DC=' in line
                                            or 'OU=' in line or 'cn=' in line
                                            or 'dc=' in line or 'ou=' in line):
                            for m in _LDAP_DN_RE.finditer(line):
                                dn_val = m.group(0)
                                # Skip example/placeholder DNs
                                if 'example' in dn_val.lower():
                                    continue
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': 'LDAP DN',
                                    'value': dn_val[:80],
                                })

                    # Layer 5: identity tokens from original
                    if identity_lower:
                        line_lower = line.lower()
                        for token, token_low in identity_lower.items():
                            if token_low in line_lower:
                                findings.append({
                                    'file': rel, 'line': lineno,
                                    'category': 'system identity',
                                    'value': token,
                                })

        except Exception:
            pass

    sys.stderr.write(f"\r  Verifying... {total_files}/{total_files} files\n")
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
