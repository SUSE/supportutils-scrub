# hostname_scrubber.py

import re
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.trie_re import build_trie_pattern
from supportutils_scrub.domain_scrubber import is_preserved_domain

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
# The cloud instance-metadata service, which every instance of a given cloud
# shares. GCE writes "169.254.169.254 metadata.google.internal metadata" into
# /etc/hosts, so the bare word is harvested as a hostname, and from there it
# renames public_cloud/metadata.txt to hostname_N.txt: the file loses the name
# every reader and every tool knows it by, and nothing is protected, because
# the name identifies a service rather than a customer.
#
# This set is OR'd into WELL_KNOWN_HOSTNAMES only. It must NOT join
# PRODUCT_DEFAULT_HOSTNAMES: that set is also the scrub regex's protected
# branch, which matches case-insensitively and would then protect the
# 'metadata' inside a customer host named metadata-01 from being scrubbed.
CLOUD_METADATA_HOSTNAMES = {
    "metadata", "metadata.google.internal",
}

# Addresses that only ever serve instance metadata. Every name on such a line
# is an alias of that service, so nothing on it is learned.
METADATA_ADDRESSES = {"169.254.169.254", "fd00:ec2::254"}

# Service aliases (/etc/hosts: "192.0.2.10 ldap.example.com ldap"). They name
# a role every site has, not a host, and once learned they rewrite ldap_uri,
# /var/spool/mail and http_proxy and rename ldap.txt. Never learned from the
# hosts file or the cluster; the counterpart of UsernameScrubber.COMMON_WORDS.
SERVICE_WORDS = {
    "ldap", "ldaps", "mail", "mailhost", "smtp", "imap", "imaps", "pop",
    "pop3", "proxy", "ntp", "dns", "www", "ftp", "http", "https", "backup",
    "db", "sql", "nfs", "kdc", "kerberos", "gateway", "router", "loghost",
    "syslog", "relay", "mirror", "repo", "time", "timehost", "print",
    "printer", "vpn", "radius", "samba", "cifs", "iscsi", "ipa", "puppet",
}

WELL_KNOWN_HOSTNAMES = (LOOPBACK_HOSTNAMES | PRODUCT_DEFAULT_HOSTNAMES
                        | CLOUD_METADATA_HOSTNAMES)


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
        trie = build_trie_pattern(k.lower() for k in hostname_dict)
        if trie:
            # Boundaries: \b is not enough — underscore must count as a
            # boundary or the hostname survives inside SAP instance profile
            # tokens (DAA_SMDA98_<host>) and scc_<host>_<date> path names,
            # and a leading digit must too (HANA traces glue a timestamp
            # straight onto the hostname). The trailing lookahead keeps
            # digits so sibling hosts (web01 vs web012) stay distinct.
            # Case-insensitive: NetBIOS/SAP contexts uppercase the hostname.
            #
            # Product strings (uyuni-server) are matched in the same pass as a
            # second branch, so a learned host named 'server' cannot corrupt
            # them, while a learned uyuni-site7 still wins over the bare
            # product prefix because its branch is tried first.
            self._lookup = {k.lower(): v for k, v in hostname_dict.items()}
            preserve = '|'.join(re.escape(n) for n in
                                sorted(PRODUCT_DEFAULT_HOSTNAMES, key=len, reverse=True))
            self._re = re.compile(r'(?P<h>(?<![A-Za-z])(?:' + trie
                                  + r')(?![A-Za-z0-9]))|(?<![A-Za-z0-9])(?:'
                                  + preserve + r')(?![A-Za-z0-9])', re.IGNORECASE)

    @property
    def mapping(self):
        return self.hostname_dict

    def scrub(self, text):
        if not self._re:
            return text

        def _sub(m):
            h = m.group('h')
            return m.group(0) if h is None else self._lookup[h.lower()]
        return self._re.sub(_sub, text)


    @staticmethod
    def extract_hostnames_from_hosts(file_path):
        hostnames = []
        # Lowercased: /etc/hosts is written by hand and by cloud agents, and
        # 'Metadata' must be excluded exactly as 'metadata' is.
        excluded_hostnames = {n.lower() for n in WELL_KNOWN_HOSTNAMES}
        with open(file_path, 'r') as file:
            in_hosts_section = False
            for line in file:
                if line.startswith('# /etc/hosts'):
                    in_hosts_section = True
                    continue
                if line.startswith('# /etc/host.conf') or (
                        in_hosts_section and line.startswith('#==[')):
                    break
                if in_hosts_section:
                    if line.strip() == "" or line.startswith('#'):
                        continue
                    if '#' in line:
                        line = line.split('#')[0]

                    fields = re.split(r'\s+', line.strip())
                    if fields and fields[0].lower() in METADATA_ADDRESSES:
                        # every name on this line is an alias of the cloud's
                        # metadata service, not a host anyone owns
                        continue
                    if any('.' in f and is_preserved_domain(f) for f in fields[1:]):
                        # smt-ec2.susecloud.net smt-ec2, registry.suse.com:
                        # a SUSE server pinned here, its aliases are SUSE's too
                        continue
                    for field in fields[1:]:
                        short_name = field.split('.')[0]
                        if len(short_name) < 4:
                            continue
                        if short_name.lower() not in excluded_hostnames | SERVICE_WORDS:
                            hostnames.append(short_name)

        return hostnames

    @staticmethod
    def extract_hostnames_from_hostname_section(file_path):
        hostnames = []
        excluded_hostnames = {n.lower() for n in WELL_KNOWN_HOSTNAMES}
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
                    if short_name.lower() not in excluded_hostnames:
                        hostnames.append(short_name)
                    
                    break  
        return hostnames

    @staticmethod
    def extract_hostnames_from_cluster(file_path):
        """Hostnames the CLUSTER names, from its own record of its membership.

        Hostnames are otherwise learned from a node's own identity files, so a
        clustered system leaks its peers: a member that was never captured
        appears in no captured node's /etc/hosts, is never learned, and its
        real name survives wherever the captured nodes' configuration mentions
        it. Measured on a support corpus: 4 of 38 clustered cases, 15 names.

        Four places a cluster states who belongs to it, all narrow on purpose:
        the CIB node table, the status output's node list, the bracketed
        online/offline lines, and the corosync nodelist. Anything that could
        equally be a resource id, an address or a cluster name is left alone;
        over-harvesting would replace text that is not a host and make the
        scrubbed capture harder to read than the leak it prevents.
        """
        excluded = WELL_KNOWN_HOSTNAMES
        found = []

        def take(name):
            short = (name or "").strip().split(".")[0]
            if len(short) < 4 or short in excluded or short.lower() in SERVICE_WORDS:
                return
            if re.fullmatch(r"[0-9a-fA-F:.]+", short):
                return                       # an address, not a name
            if not re.fullmatch(r"[A-Za-z][\w-]*", short):
                return
            found.append(short)

        try:
            with open(file_path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return []

        # the CIB's own node table
        for m in re.finditer(r'<node\b[^>]*\buname="([^"]+)"', text):
            take(m.group(1))
        # status output. The bullet is required: the same tool prints "Node
        # List:" and "Node Attributes:" as section headings, and a pattern
        # reading "Node <word>:" harvested List and Attributes from a real
        # capture. The parenthesised form carries a node id instead.
        for m in re.finditer(r"^\s*\*\s*Node\s+([A-Za-z][\w.-]*)\s*:",
                             text, re.MULTILINE):
            take(m.group(1))
        for m in re.finditer(r"^\s*Node\s+([A-Za-z][\w.-]*)\s+\(\d+\)",
                             text, re.MULTILINE):
            take(m.group(1))
        # bracketed membership lines, bulleted in current output and bare in
        # older versions
        for m in re.finditer(r"^\s*\*?\s*(?:Online|OFFLINE|Standby)\s*:\s*"
                             r"\[([^\]]*)\]", text, re.MULTILINE):
            for word in m.group(1).split():
                take(word)
        # corosync nodelist, scoped: `name:` outside it means many things
        block = re.search(r"nodelist\s*\{(.*?)\n\}", text, re.S)
        if block:
            for m in re.finditer(r"^\s*(?:ring\d+_addr|name)\s*:\s*(\S+)",
                                 block.group(1), re.MULTILINE):
                take(m.group(1))

        return list(dict.fromkeys(found))

    @staticmethod
    def extract_hostnames_from_text(text, syslog_counts=None):
        """Extract hostnames from NFS server lines and RFC 5424 syslog timestamps.

        When one document is scanned in segments, pass the same dict as
        syslog_counts on every call: occurrence counts accumulate there instead
        of being thresholded per segment (a host mentioned three times across
        two segments would otherwise be missed), and the caller collects the
        result via syslog_hosts_from_counts() after the last segment."""
        excluded = WELL_KNOWN_HOSTNAMES
        hostnames = set()

        for m in re.finditer(r'nfs: server ([\w][\w.-]*)', text):
            short = m.group(1).split('.')[0]
            if len(short) >= 3 and short not in excluded:
                hostnames.add(short)

        counts = {} if syslog_counts is None else syslog_counts
        for m in re.finditer(
            r'^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+([\w][\w-]*)\b', text, re.MULTILINE
        ):
            h = m.group(1)
            if len(h) >= 3 and h not in excluded:
                counts[h] = counts.get(h, 0) + 1
        if syslog_counts is None:
            hostnames |= HostnameScrubber.syslog_hosts_from_counts(counts)

        return list(hostnames)

    @staticmethod
    def syslog_hosts_from_counts(counts):
        """Hosts seen in enough RFC 5424 lines to count as this system's."""
        return {h for h, count in counts.items() if count >= 3}
