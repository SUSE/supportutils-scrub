# ip_scrubber.py

import re
from ipaddress import IPv4Address, IPv4Network, ip_network
from supportutils_scrub.scrubber import Scrubber

OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
CIDR_RE = re.compile(
    rf'(?<![A-Za-z0-9.\-])'
    rf'(?P<ip>{OCTET}\.{OCTET}\.{OCTET}\.{OCTET})'
    rf'(?![A-Za-z0-9.\-])'
    r'(?:/(?P<pfx>\d{1,2}))?'
)

SPECIALS = {
    "0.0.0.0", "127.0.0.1", "127.0.0.0", "127.255.255.255", "255.255.255.255",
    "255.255.255.0", "255.255.0.0", "255.0.0.0"
}


class IPScrubber(Scrubber):
    name = 'ip'

    def __init__(self, config, mappings=None):

        self.ip_dict = mappings.get('ip', {}) if mappings else {}
        self.config = config       
        self.subnet_dict = dict(mappings.get('subnet', {}))
        self.category_pools = {
            'public':      IPv4Network(self.config.public_pool),
            'priv10':      IPv4Network(self.config.pool_10),
            'priv172':     IPv4Network(self.config.pool_172),
            'priv192_168': IPv4Network(self.config.pool_192_168),
            'linklocal':   IPv4Network(self.config.pool_169_254),
        }
        self._pool_cursor = {}
        for key in self.category_pools:
            cursor_key = f'pool_cursor_{key}'
            self._pool_cursor[key] = int(mappings.get('state', {}).get(cursor_key, 0))
        
        self._sanitize_ip_map()

        self._last_state = {}
        self._real_to_fake = {}
        self._used_slots = set()  
        for k, v in self.subnet_dict.items():
            try:
                real_net = IPv4Network(k)
                fake_net = IPv4Network(v)
                self._real_to_fake[real_net] = fake_net
                for cat_key, pool in self.category_pools.items():
                    pool_start = int(pool.network_address)
                    pool_end = int(pool.broadcast_address) + 1
                    fake_start = int(fake_net.network_address)
                    if pool_start <= fake_start < pool_end:
                        slot_start = (fake_start - pool_start) // 256
                        slot_count = max(1, fake_net.num_addresses // 256)
                        for s in range(slot_start, slot_start + slot_count):
                            self._used_slots.add(s)
                        break
            except:
                pass
        self._sorted_subnets = sorted(
            self._real_to_fake.items(), key=lambda kv: kv[0].prefixlen, reverse=True
        )


    def _sanitize_ip_map(self):
        for k in list(self.ip_dict.keys()):
            if k in SPECIALS:
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

    def _should_obfuscate_private(self):
        return self.config.obfuscate_private_ip

    def _alloc_fake_subnet_from_pool(self, cat_key: str, prefixlen: int) -> IPv4Network:
        """Allocate a fake subnet from the specified pool, using a /24 slot for overlap checking."""
        pool = self.category_pools[cat_key]

        if prefixlen < pool.prefixlen:
            prefixlen = pool.prefixlen

        step  = 2 ** (32 - prefixlen)
        start = int(pool.network_address)
        end   = int(pool.broadcast_address) + 1

        cursor = self._pool_cursor.get(cat_key, 0)
        for _ in range((end - start) // step):
            base = start + ((cursor // step) * step)
            if base >= end:
                cursor = 0
                base = start
            # Check /24-slot bitmap for overlap
            slot_start = (base - start) // 256
            slot_count = max(1, step // 256)
            if not any(s in self._used_slots for s in range(slot_start, slot_start + slot_count)):
                for s in range(slot_start, slot_start + slot_count):
                    self._used_slots.add(s)
                self._pool_cursor[cat_key] = (base - start) + step
                return IPv4Network((base, prefixlen))
            cursor += step

        raise RuntimeError(f"Pool {pool} exhausted for /{prefixlen}")


    def _ensure_fake_subnet(self, real_net: IPv4Network):
        if real_net in self._real_to_fake:
            return
        cat = self._classify_ip(str(real_net.network_address))
        if self._is_private(str(real_net.network_address)) and not self._should_obfuscate_private():
            return
        fake_net = self._alloc_fake_subnet_from_pool(cat, real_net.prefixlen)
        self._real_to_fake[real_net] = fake_net
        self.subnet_dict[str(real_net)] = str(fake_net)
        self._sorted_subnets = None  # invalidate cache


    def _prepare_subnets(self, text):
        """learn all CIDR subnets from text to enable subnet-aware mapping."""
        for m in CIDR_RE.finditer(text):
            ip = m.group('ip')
            pfx = m.group('pfx')
            
            if not pfx:
                continue

            pfx = int(pfx)

            if pfx in (0, 32):
                continue

            try:
                ip_obj = IPv4Address(ip)
            except ValueError:
                continue

            if ip.startswith('0.'):
                continue
            if ip_obj.is_loopback or ip_obj.is_multicast or ip in SPECIALS:
                continue

            try:
                real_net = ip_network(f"{ip}/{pfx}", strict=False)

                is_private = self._is_private(ip)
                if is_private and not self._should_obfuscate_private():
                    continue

                self._ensure_fake_subnet(real_net)
            except (ValueError, RuntimeError):
                pass
        self._sorted_subnets = sorted(
            self._real_to_fake.items(), key=lambda kv: kv[0].prefixlen, reverse=True
        )

    def _map_in_subnets(self, ip_str):
        """Map an IP to its fake equivalent by offset within its known subnet."""
        from ipaddress import IPv4Address
        try:
            ip = IPv4Address(ip_str)
        except:
            return None

        if self._sorted_subnets is None:
            self._sorted_subnets = sorted(
                self._real_to_fake.items(), key=lambda kv: kv[0].prefixlen, reverse=True
            )

        for real_net, fake_net in self._sorted_subnets:
            if ip in real_net:
                off = int(ip) - int(real_net.network_address)
                return str(IPv4Address(int(fake_net.network_address) + off))
        return None


    
    def _scrub_token(self, ip_str, pfx_str):
        try:
            ip_obj = IPv4Address(ip_str)
        except ValueError:
            return ip_str + (f"/{pfx_str}" if pfx_str else "")

        if ip_obj.is_loopback or ip_obj.is_multicast:
            return ip_str + (f"/{pfx_str}" if pfx_str else "")
        
        if ip_str in SPECIALS:
            return ip_str + (f"/{pfx_str}" if pfx_str else "")

        if pfx_str == '0':  
            return ip_str + "/0"
        
        is_private = self._is_private(ip_str)
        if is_private and not self._should_obfuscate_private():
            return ip_str + (f"/{pfx_str}" if pfx_str else "")
        
        mapped = self._map_in_subnets(ip_str)
        if mapped:
            self.ip_dict[ip_str] = mapped
            return mapped + (f"/{pfx_str}" if pfx_str else "")

        real_net, fake_net = self._ensure_logical_subnet_for_ip(ip_str)
        if real_net and fake_net:
            off = int(ip_obj) - int(real_net.network_address)
            mapped_ip = str(IPv4Address(int(fake_net.network_address) + off))
            self.ip_dict[ip_str] = mapped_ip
            return mapped_ip + (f"/{pfx_str}" if pfx_str else "")

        if ip_str in self.ip_dict:
            return self.ip_dict[ip_str] + (f"/{pfx_str}" if pfx_str else "")

        return ip_str + (f"/{pfx_str}" if pfx_str else "")
        

    def _ensure_logical_subnet_for_ip(self, ip_str):
        ip = IPv4Address(ip_str)
        for real_net in sorted(self._real_to_fake.keys(), key=lambda n: n.prefixlen, reverse=True):
            if ip in real_net:
                return real_net, self._real_to_fake[real_net]

        default_pfx = self.config.default_infer_prefixlen
        real_net = ip_network(f"{ip}/{default_pfx}", strict=False)

        if self._is_private(str(real_net.network_address)) and not self._should_obfuscate_private():
            return None, None

        try:
            self._ensure_fake_subnet(real_net)
        except RuntimeError:
            import hashlib
            pool = self.category_pools.get(self._classify_ip(ip_str))
            pool_start = int(pool.network_address)
            pool_slots = pool.num_addresses // 256  
            host_byte = int(ip_str.split('.')[-1])  
            net_part = ip_str.rsplit('.', 1)[0]
            h = int(hashlib.md5(net_part.encode()).hexdigest()[:8], 16)
            fake_base = pool_start + ((h % pool_slots) * 256)
            fake_ip = str(IPv4Address(fake_base + host_byte))
            self.ip_dict[ip_str] = fake_ip
            return None, None
        return real_net, self._real_to_fake.get(real_net)

    


    def scrub_text(self, text):
        """Two-pass scrub: learn subnets, then replace IPs subnet-aware."""
        self._prepare_subnets(text)
        
        def repl(m):
            ip = m.group('ip')
            pfx = m.group('pfx')

            if ip.startswith('0.'):
                return m.group(0)

            start = m.start()
            snippet = text[max(0, start-20):start].lower()
            if re.search(r'(?:\b|_)ver(?:sion)?[\s:="\']*$', snippet.rstrip()):
                return m.group(0)
            if snippet.endswith('/') and not snippet.endswith('://'):
                return m.group(0)

            return self._scrub_token(ip, pfx)
        
        new_text = CIDR_RE.sub(repl, text)
        self._last_state = {f'pool_cursor_{k}': v for k, v in self._pool_cursor.items()}

        return new_text, self.ip_dict, self.subnet_dict, self._last_state

    @property
    def mapping(self):
        return self.ip_dict

    @property
    def state(self):
        return self._last_state

    def scrub(self, text):
        new_text, _, _, _ = self.scrub_text(text)
        return new_text

    def scrub_ip(self, ip):
        """Legacy single-IP scrub without subnet."""
        if ip in SPECIALS or ip.startswith('0.'):
            return ip
        
        is_private = self._is_private(ip)
        if is_private and not self._should_obfuscate_private():
            return ip
        
        mapped = self._map_in_subnets(ip)
        if mapped:
            return mapped
        
        if ip not in self.ip_dict:
            cat = self._classify_ip(ip)
            pool = self.category_pools[cat]
            
            n = len([k for k in self.ip_dict.keys() if self._classify_ip(k) == cat])
            base = str(pool.network_address).rsplit('.', 2)[0]
            self.ip_dict[ip] = f"{base}.{(n // 256) % 256}.{(n % 256) or 1}"
        
        return self.ip_dict[ip]

    @staticmethod
    def extract_ips(text):
        ip_pattern = r"(?<![\w\-\.])((?:\d{1,3}\.){3}\d{1,3})(?![\w\-\.])"
        return re.findall(ip_pattern, text)
    
    def tcprewrite_rules(self):
        pairs = []
        for real_net, fake_net in sorted(self._real_to_fake.items(),
                                        key=lambda kv: kv[0].prefixlen,
                                        reverse=True):
            if real_net.prefixlen == 32:
                continue
            nw = real_net.network_address
            if nw.is_loopback or nw.is_multicast:
                continue
            pairs.append((str(real_net), str(fake_net)))
        return pairs
