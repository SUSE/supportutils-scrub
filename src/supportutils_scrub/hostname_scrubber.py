# hostname_scrubber.py

import re
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.trie_re import build_trie_pattern

# Loopback names that never identify anyone.
LOOPBACK_HOSTNAMES = {
    "localhost", "ipv6-localhost", "ipv6-loopback",
    "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes",
    "ipv6-allrouters", "ipv6-allhosts",
    "ip6-localhost", "ip6-loopback",
    "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
    "ip6-allrouters", "ip6-allhosts",
}

# Hostnames that identify a PRODUCT, not a customer. Containerized SUSE
# Multi-Linux Manager / Uyuni creates its podman containers with these
# literal names on every installation (mgradm defaults), so they appear as
# real hostnames in container captures. Obfuscating them destroys the
# product context of paths and logs while protecting nothing: every
# deployment in the world shares them.
PRODUCT_DEFAULT_HOSTNAMES = {
    # the product name itself: a host literally named 'uyuni' would, once
    # learned, corrupt every uyuni-* package and path name via the token
    # boundary match
    "uyuni",
    # mgradm server-side containers
    "uyuni-server", "uyuni-db", "uyuni-hub-xmlrpc", "uyuni-hub",
    # proxy pod containers
    "uyuni-proxy", "uyuni-proxy-httpd", "uyuni-proxy-salt-broker",
    "uyuni-proxy-squid", "uyuni-proxy-ssh", "uyuni-proxy-tftpd",
}

# Never scrubbed, PERIOD: excluded from automatic learning AND filtered out
# of any hostname mapping at scrub time, so entries carried in from legacy
# mapping files (or passed as additional hostnames) cannot resurrect them.
# The config key `hostname_preserve` (comma-separated) EXTENDS this set;
# nothing can remove the built-ins.
WELL_KNOWN_HOSTNAMES = LOOPBACK_HOSTNAMES | PRODUCT_DEFAULT_HOSTNAMES


def preserved_hostnames(config=None):
    """The full preserve set: built-ins plus the config's hostname_preserve
    extension, lowercased."""
    extra = ""
    if config is not None:
        extra = getattr(config, "hostname_preserve", "") or ""
    names = {n.strip().lower() for n in extra.split(",") if n.strip()}
    return {n.lower() for n in WELL_KNOWN_HOSTNAMES} | names


class HostnameScrubber(Scrubber):
    name = 'hostname'

    def __init__(self, hostname_dict, config=None):
        # Enforce the preserve set at SCRUB time, not only at learn time: a
        # legacy mapping file may already contain e.g. uyuni-server from a
        # run before the product-name rule existed, and shared mappings are
        # reused across re-scrubs. Dropped here, such an entry neither
        # rewrites text nor reappears in the mapping written back out.
        preserved = preserved_hostnames(config)
        hostname_dict = {k: v for k, v in (hostname_dict or {}).items()
                         if k.lower() not in preserved}
        self.hostname_dict = hostname_dict
        self._re = None
        self._lookup = {}
        if hostname_dict:
            # Boundaries: \b is not enough — underscore must count as a
            # boundary or the hostname survives inside SAP instance profile
            # tokens (DAA_SMDA98_<host>) and scc_<host>_<date> path names,
            # and a leading digit must too (HANA traces glue a timestamp
            # straight onto the hostname). The trailing lookahead keeps
            # digits so sibling hosts (web01 vs web012) stay distinct.
            # Case-insensitive: NetBIOS/SAP contexts uppercase the hostname.
            self._lookup = {k.lower(): v for k, v in hostname_dict.items()}
            self._re = re.compile(r'(?<![A-Za-z])(?:'
                                  + build_trie_pattern(self._lookup.keys())
                                  + r')(?![A-Za-z0-9])', re.IGNORECASE)

    @property
    def mapping(self):
        return self.hostname_dict

    # Preserved strings are protected against CORRUPTION too, not only
    # direct replacement: a learned hostname that happens to be a substring
    # with a token boundary (a customer host literally named "server" would
    # turn "uyuni-server" into "uyuni-hostname_N") must not touch them.
    # Occurrences are masked with sentinels before substitution and restored
    # after. The mask pattern is compiled once per process.
    _PRESERVE_RE = None

    @classmethod
    def _preserve_re(cls):
        if cls._PRESERVE_RE is None:
            names = sorted(PRODUCT_DEFAULT_HOSTNAMES, key=len, reverse=True)
            cls._PRESERVE_RE = re.compile(
                r'(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(n) for n in names)
                + r')(?![A-Za-z0-9])', re.IGNORECASE)
        return cls._PRESERVE_RE

    def scrub(self, text):
        if not self._re:
            return text
        pre = self._preserve_re()
        saved = []
        if pre.search(text):
            def _mask(m):
                saved.append(m.group(0))
                return f"\x00PRESERVED{len(saved) - 1}\x00"
            text = pre.sub(_mask, text)
        text = self._re.sub(lambda m: self._lookup[m.group(0).lower()], text)
        for i, original in enumerate(saved):
            text = text.replace(f"\x00PRESERVED{i}\x00", original)
        return text
    


    @staticmethod
    def extract_hostnames_from_hosts(file_path):
        hostnames = []
        excluded_hostnames = WELL_KNOWN_HOSTNAMES
        with open(file_path, 'r') as file:
            in_hosts_section = False
            for line in file:
                if line.startswith('# /etc/hosts'):
                    in_hosts_section = True
                    continue
                if line.startswith('# /etc/host.conf'):
                    break
                if in_hosts_section:
                    if line.strip() == "" or line.startswith('#'):
                        continue
                    if '#' in line:
                        line = line.split('#')[0]

                    fields = re.split(r'\s+', line.strip())
                    for field in fields[1:]:
                        short_name = field.split('.')[0]
                        if len(short_name) < 4:
                            continue
                        if short_name not in excluded_hostnames:
                            hostnames.append(short_name)

        return hostnames

    @staticmethod
    def extract_hostnames_from_hostname_section(file_path):
        hostnames = []
        excluded_hostnames = WELL_KNOWN_HOSTNAMES
        with open(file_path, 'r') as file:
            in_hostname_section = False
            for line in file:
                if line.startswith('# /bin/hostname'):
                    in_hostname_section = True
                    continue
                if in_hostname_section:
                    if line.strip() == "" or line.startswith('#'):
                        continue

                    hostname = line.strip()
                    short_name = hostname.split('.')[0]
                    if short_name not in excluded_hostnames:
                        hostnames.append(short_name)
                    
                    break  
        return hostnames

    @staticmethod
    def extract_hostnames_from_text(text):
        """Extract hostnames from NFS server lines and RFC 5424 syslog timestamps."""
        excluded = WELL_KNOWN_HOSTNAMES
        hostnames = set()

        for m in re.finditer(r'nfs: server ([\w][\w.-]*)', text):
            short = m.group(1).split('.')[0]
            if len(short) >= 3 and short not in excluded:
                hostnames.add(short)

        counts = {}
        for m in re.finditer(
            r'^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+([\w][\w-]*)\b', text, re.MULTILINE
        ):
            h = m.group(1)
            if len(h) >= 3 and h not in excluded:
                counts[h] = counts.get(h, 0) + 1
        for h, count in counts.items():
            if count >= 3:
                hostnames.add(h)

        return list(hostnames)
