# ip_scrubber.py

import re
from ipaddress import IPv4Address, IPv4Network, ip_network
from supportutils_scrub.fastsub import hint_spans, iter_spans, sub_spans
from supportutils_scrub.scrubber import Scrubber

OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
QUAD = rf'{OCTET}\.{OCTET}\.{OCTET}\.{OCTET}'
# A trailing '.' ends a sentence; '.x' continues a version, OID or hostname.
_AFTER = r'(?![A-Za-z0-9\-+])(?!\.[A-Za-z0-9])'
CIDR_RE = re.compile(
    rf'(?<![A-Za-z0-9.\-])'
    rf'(?P<ip>{QUAD})'
    # "a.b.c.d-e.f.g.h" ranges (iptables --src-range, dhcp pools)
    rf'(?:-(?P<ip2>{QUAD}))?'
    rf'{_AFTER}'
    r'(?:/(?P<pfx>\d{1,2}))?'
)

# Like CIDR_RE but the /prefix is mandatory — for the subnet-learning pre-pass,
# so it only yields actual CIDR subnets instead of iterating every bare IP.
CIDR_SUBNET_RE = re.compile(
    rf'(?<![A-Za-z0-9.\-])'
    rf'(?P<ip>{QUAD})'
    rf'{_AFTER}'
    r'/(?P<pfx>\d{1,2})'
)

# 3 or 4 reversed octets of a PTR name, scrubbed as the forward address.
REV_RE = re.compile(
    rf'(?<![A-Za-z0-9.\-])(?P<rev>(?:{OCTET}\.){{2,3}}{OCTET})'
    r'(?=\.in-addr\.arpa(?![A-Za-z0-9\-]))',
    re.IGNORECASE)

# Every address, range, subnet and reversed PTR name holds two octets between
# dots. The hint starts with a literal, so `re` jumps from dot to dot.
_QUAD_HINTS = (re.compile(r'\.\d{1,3}\.\d{1,3}\.'),)

SPECIALS = {
    "0.0.0.0", "127.0.0.1", "127.0.0.0", "127.255.255.255", "255.255.255.255",
}
# Contiguous-ones netmasks (255.255.254.0, ...) identify nothing, and 255/8
# never holds real hosts. Scrubbing them only desyncs "addr/mask" forms.
SPECIALS.update(str(IPv4Network((0, p)).netmask) for p in range(8, 33))

# "...version: " context before a dotted number means it's a version, not an IP.
_VERSION_CTX_RE = re.compile(r'(?:\b|_)(?:ver(?:sion)?|rev|build|release)[\s:="\']*$',
                             re.IGNORECASE)


class IPScrubber(Scrubber):
    name = 'ip'

    def __init__(self, config, mappings=None):
        mappings = mappings or {}
        self.ip_dict = mappings.get('ip', {})
        self.config = config
        self.subnet_dict = dict(mappings.get('subnet', {}))
        self.category_pools = {
            'public':      IPv4Network(self.config.public_pool),
            'priv10':      IPv4Network(self.config.pool_10),
            'priv172':     IPv4Network(self.config.pool_172),
            'priv192_168': IPv4Network(self.config.pool_192_168),
            'linklocal':   IPv4Network(self.config.pool_169_254),
        }
        self._exhausted_pools = set()   # (category, prefixlen)
        self._pool_cursor = {}
        for key in self.category_pools:
            cursor_key = f'pool_cursor_{key}'
            self._pool_cursor[key] = int(mappings.get('state', {}).get(cursor_key, 0))

        self._sanitize_ip_map()

        self._real_to_fake = {}
        # prefix index: {prefixlen: {network_addr_int: fake_net}} + masks, so a
        # lookup is O(distinct prefix lengths) instead of O(all subnets).
        self._prefix_index = {}
        self._prefix_masks = []
        self._index_dirty = True
        # /24 slots taken, per pool: slot numbers are pool-relative.
        self._used_slots = {cat: set() for cat in self.category_pools}
        self._taken = None   # fake IPs in use, built on the first fallback
        # Addresses that are never replaced (loopback, multicast, netmasks,
        # a range the config leaves alone). Most addresses in a log are
        # private ones repeated on every line, and without this each
        # repeat is parsed and classified again.
        self._untouched = set()
        for k, v in list(self.subnet_dict.items()):
            try:
                real_net = IPv4Network(k)
                fake_net = IPv4Network(v)
            except ValueError:
                del self.subnet_dict[k]
                continue
            cat = self._classify_ip(str(real_net.network_address))
            pool = self.category_pools[cat]
            # Older runs clamped nets larger than the pool, so their hosts
            # spilled out of it. Never reuse such an entry.
            if fake_net.prefixlen != real_net.prefixlen or not fake_net.subnet_of(pool):
                del self.subnet_dict[k]
                continue
            self._real_to_fake[real_net] = fake_net
            slot_start = (int(fake_net.network_address) - int(pool.network_address)) // 256
            slot_count = max(1, fake_net.num_addresses // 256)
            self._used_slots[cat].update(range(slot_start, slot_start + slot_count))
        # A kept fake whose subnet entry was dropped still owns its /24.
        for k, v in self.ip_dict.items():
            cat = self._classify_ip(k)
            pool_start = int(self.category_pools[cat].network_address)
            self._used_slots[cat].add((int(IPv4Address(v)) - pool_start) // 256)

    def _sanitize_ip_map(self):
        for k, v in list(self.ip_dict.items()):
            try:
                ok = (k not in SPECIALS and
                      IPv4Address(v) in self.category_pools[self._classify_ip(k)])
            except ValueError:
                ok = False
            if not ok:
                del self.ip_dict[k]

    def _classify_ip(self, ip: str) -> str:
        """Classify an IP into a pool category."""
        try:
            parts = ip.split('.')
            a = int(parts[0])
            b = int(parts[1]) if len(parts) > 1 else 0

            if a == 169 and b == 254:
                return 'linklocal'

            if a == 10:
                return 'priv10'
            if a == 172 and 16 <= b <= 31:
                return 'priv172'
            if a == 192 and b == 168:
                return 'priv192_168'

            return 'public'
        except:
            return 'public'

    _PRIVATE_NETS = [
        IPv4Network('10.0.0.0/8'),
        IPv4Network('172.16.0.0/12'),
        IPv4Network('192.168.0.0/16'),
        IPv4Network('127.0.0.0/8'),
        IPv4Network('169.254.0.0/16'),
    ]

    def _is_private(self, ip_str):
        """Return True if IP is RFC1918 private, loopback, or link-local."""
        try:
            ip = IPv4Address(ip_str)
            return any(ip in net for net in self._PRIVATE_NETS)
        except:
            return False

    def _wants(self, ip_str):
        """The config gate: is this an address we were asked to obfuscate?"""
        if ip_str.startswith('0.'):
            return False
        if self._is_private(ip_str):
            return self.config.obfuscate_private_ip
        return self.config.obfuscate_public_ip

    def _alloc_fake_subnet_from_pool(self, cat_key: str, prefixlen: int) -> IPv4Network:
        """Allocate a fake subnet from the specified pool, using a /24 slot for overlap checking."""
        pool = self.category_pools[cat_key]
        used = self._used_slots[cat_key]

        # Once a (category, prefixlen) pool is full it stays full (subnets are
        # never freed). Short-circuit so we don't rescan every slot per IP.
        if (cat_key, prefixlen) in self._exhausted_pools:
            raise RuntimeError(f"Pool {pool} exhausted for /{prefixlen}")

        step  = 2 ** (32 - prefixlen)
        start = int(pool.network_address)
        end   = int(pool.broadcast_address) + 1

        cursor = self._pool_cursor.get(cat_key, 0)
        slot_count = max(1, step // 256)
        travelled = 0
        while travelled < end - start:
            base = start + ((cursor // step) * step)
            if base >= end:
                cursor = 0
                base = start
            slot_start = (base - start) // 256
            if not any(s in used for s in range(slot_start, slot_start + slot_count)):
                used.update(range(slot_start, slot_start + slot_count))
                self._pool_cursor[cat_key] = (base - start) + step
                return IPv4Network((base, prefixlen))
            # Overlap is tracked per /24, so a taken /24 is taken for every
            # smaller net inside it: the next candidate that can be free is
            # the first one of the next /24 (the same one stepping net by
            # net reaches, after up to 256 checks of the same slot).
            skip = max(step, 256 - (base - start) % 256)
            cursor = (base - start) + skip
            travelled += skip

        self._exhausted_pools.add((cat_key, prefixlen))
        raise RuntimeError(f"Pool {pool} exhausted for /{prefixlen}")

    def _ensure_fake_subnet(self, real_net: IPv4Network):
        if real_net in self._real_to_fake:
            return
        if not self._wants(str(real_net.network_address)):
            return
        cat = self._classify_ip(str(real_net.network_address))
        # A real net larger than its pool has no faithful fake: leave it
        # unlearned and its hosts get mapped per inferred subnet.
        if real_net.prefixlen < self.category_pools[cat].prefixlen:
            return
        fake_net = self._alloc_fake_subnet_from_pool(cat, real_net.prefixlen)
        self._real_to_fake[real_net] = fake_net
        self.subnet_dict[str(real_net)] = str(fake_net)
        self._index_dirty = True

    def _discover_cidrs(self, text, spans=None):
        seen = set()
        for m in iter_spans(CIDR_SUBNET_RE, text, spans):
            ip, pfx = m.group('ip'), int(m.group('pfx'))
            key = f"{ip}/{pfx}"
            if key in seen or pfx in (0, 32) or pfx > 32:
                continue
            ip_obj = IPv4Address(ip)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip in SPECIALS:
                continue
            if self._wants(ip):
                seen.add(key)
                yield key

    def _learn_cidrs(self, cidrs):
        for cidr in cidrs:
            try:
                self._ensure_fake_subnet(ip_network(cidr, strict=False))
            except (ValueError, RuntimeError):
                pass

    def _rebuild_index(self):
        idx = {}
        for real_net, fake_net in self._real_to_fake.items():
            idx.setdefault(real_net.prefixlen, {})[int(real_net.network_address)] = fake_net
        self._prefix_index = idx
        self._prefix_masks = [
            (plen, (~0 << (32 - plen)) & 0xFFFFFFFF)
            for plen in sorted(idx.keys(), reverse=True)
        ]
        self._index_dirty = False

    def _map_in_subnets(self, ip_str):
        """Map an IP to its fake equivalent by offset within its known subnet.

        Most-specific-first via a prefix index: for each distinct prefix length
        we mask the IP and do a dict lookup, so this is O(#prefix lengths) per
        IP rather than O(#subnets).
        """
        try:
            ip_int = int(IPv4Address(ip_str))
        except Exception:
            return None

        if self._index_dirty:
            self._rebuild_index()

        for plen, mask in self._prefix_masks:
            net_int = ip_int & mask
            fake_net = self._prefix_index[plen].get(net_int)
            if fake_net is not None:
                off = ip_int - net_int
                return str(IPv4Address(int(fake_net.network_address) + off))
        return None

    def _scrub_token(self, ip_str, pfx_str):
        suffix = f"/{pfx_str}" if pfx_str else ""
        cached = self.ip_dict.get(ip_str)
        if cached is not None:
            return cached + suffix
        if ip_str in self._untouched:
            return ip_str + suffix
        try:
            ip_obj = IPv4Address(ip_str)
        except ValueError:
            return ip_str + suffix
        if (ip_obj.is_loopback or ip_obj.is_multicast or ip_str in SPECIALS
                or not self._wants(ip_str)):
            self._untouched.add(ip_str)
            return ip_str + suffix
        if pfx_str == '0':
            return ip_str + suffix

        fake = self._map_in_subnets(ip_str)
        if fake is None:
            pool = self.category_pools[self._classify_ip(ip_str)]
            pfx = max(self.config.default_infer_prefixlen, pool.prefixlen)
            try:
                self._ensure_fake_subnet(ip_network(f"{ip_str}/{pfx}", strict=False))
                fake = self._map_in_subnets(ip_str)
            except RuntimeError:
                fake = self._fallback_fake(ip_str, pool)
        if fake is None:
            return ip_str + suffix
        self.ip_dict[ip_str] = fake
        if self._taken is not None:
            self._taken.add(fake)
        return fake + suffix

    def _fallback_fake(self, ip_str, pool):
        # No free /24 is left in the pool, so fakes have to share slots. Probe
        # from a hashed slot to an address no other real IP was given.
        # ponytail: a host of an already-mapped subnet seen later can still
        # land on one of these; only a bigger pool fixes that.
        import hashlib
        if self._taken is None:
            self._taken = set(self.ip_dict.values())
        net_part, host = ip_str.rsplit('.', 1)
        h = int(hashlib.md5(net_part.encode()).hexdigest()[:8], 16)
        pool_start = int(pool.network_address)
        pool_slots = pool.num_addresses // 256
        for i in range(pool.num_addresses):
            slot = (h + (int(host) + i) // 256) % pool_slots
            fake = str(IPv4Address(pool_start + slot * 256 + (int(host) + i) % 256))
            if fake not in self._taken:
                return fake
        return None

    def _iter_matches(self, text, spans=None):
        """CIDR_RE matches that are addresses, not versions. Shared by scrub
        and discover so both make identical decisions."""
        for m in iter_spans(CIDR_RE, text, spans):
            start = m.start()
            if not _VERSION_CTX_RE.search(text[max(0, start - 20):start].rstrip()):
                yield m

    @staticmethod
    def _rev_forward(m):
        rev = m.group('rev').split('.')
        return '.'.join(rev[::-1] + ['0'] * (4 - len(rev)))

    def _replace_rev(self, m):
        n = m.group('rev').count('.') + 1
        fake = self._scrub_token(self._rev_forward(m), None).split('.')[:n]
        return '.'.join(fake[::-1])

    def _replace_match(self, m):
        if not m.group('ip2'):
            return self._scrub_token(m.group('ip'), m.group('pfx'))
        return (self._scrub_token(m.group('ip'), None) + '-' +
                self._scrub_token(m.group('ip2'), m.group('pfx')))

    def scrub_text(self, text):
        """Two-pass scrub: learn subnets, then replace IPs subnet-aware."""
        spans = hint_spans(text, _QUAD_HINTS)
        if spans is not None and not spans:
            return text, self.ip_dict, self.subnet_dict, self.state
        self._learn_cidrs(self._discover_cidrs(text, spans))
        if 'in-addr' in text or 'IN-ADDR' in text:
            if spans is None:
                text = REV_RE.sub(self._replace_rev, text)
            else:
                new = sub_spans(REV_RE, self._replace_rev, text, spans)
                if new is not text:
                    text, spans = new, hint_spans(new, _QUAD_HINTS)
        out = []
        pos = 0
        for m in self._iter_matches(text, spans):
            out.append(text[pos:m.start()])
            out.append(self._replace_match(m))
            pos = m.end()
        out.append(text[pos:])
        return ''.join(out), self.ip_dict, self.subnet_dict, self.state

    def discover(self, text):
        """Read-only discovery half of learn(): returns (cidrs, tokens).

        cidrs are 'ip/pfx' strings and tokens are (ip, pfx) pairs, each in
        first-seen order and deduplicated. Filtering is shared with
        scrub_text; nothing touches allocation state, so this can run in
        parallel workers and be replayed in the parent."""
        spans = hint_spans(text, _QUAD_HINTS)
        if spans is not None and not spans:
            return [], []
        cidrs = list(self._discover_cidrs(text, spans))
        tokens = []
        seen = set()

        def add(tok):
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)

        if 'in-addr' in text or 'IN-ADDR' in text:
            for m in iter_spans(REV_RE, text, spans):
                add((self._rev_forward(m), None))
        for m in self._iter_matches(text, spans):
            if m.group('ip2'):
                add((m.group('ip'), None))
                add((m.group('ip2'), m.group('pfx')))
            else:
                add((m.group('ip'), m.group('pfx')))
        return cidrs, tokens

    def replay(self, cidrs, tokens):
        """Allocation half of learn(): apply one file's discover() output.

        Repeated (ip, pfx) pairs are pure cache hits in _scrub_token, so the
        dedup in discover() does not change the resulting maps."""
        self._learn_cidrs(cidrs)
        for ip, pfx in tokens:
            self._scrub_token(ip, pfx)

    def learn(self, text):
        """Discover IPs/subnets and allocate fakes without rebuilding the string.
        Same per-match filters and allocation decisions as scrub_text, so the
        maps it builds are identical — but with no output-string cost."""
        cidrs, tokens = self.discover(text)
        self.replay(cidrs, tokens)

    @property
    def mapping(self):
        return self.ip_dict

    @property
    def state(self):
        return {f'pool_cursor_{k}': v for k, v in self._pool_cursor.items()}

    def scrub(self, text):
        new_text, _, _, _ = self.scrub_text(text)
        return new_text

    @staticmethod
    def extract_ips(text):
        ip_pattern = r"(?<![\w\-\.])((?:\d{1,3}\.){3}\d{1,3})(?![\w\-\.])"
        return re.findall(ip_pattern, text)
