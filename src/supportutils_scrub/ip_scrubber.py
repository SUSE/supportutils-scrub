# ip_scrubber.py

import re
from ipaddress import IPv4Address, IPv4Network, ip_network

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


class IPScrubber:
    def __init__(self, config, mappings=None):

        # Load the existing mappings or initialize an empty dictionary
        self.ip_dict = mappings.get('ip', {}) if mappings else {}
        self.config = config       
        self.subnet_dict = dict(mappings.get('subnet', {}))
        self.category_pools = {
            'public':      IPv4Network(self.config.get('public_pool', '198.18.0.0/15')),   
            'priv10':      IPv4Network(self.config.get('pool_10',       '100.80.0.0/12')),  
            'priv172':     IPv4Network(self.config.get('pool_172',      '100.96.0.0/12')),  
            'priv192_168': IPv4Network(self.config.get('pool_192_168',  '100.112.0.0/12')), 
            'linklocal':   IPv4Network(self.config.get('pool_169_254',  '100.79.0.0/16')),  
        }
        self._pool_cursor = {}
        for key in self.category_pools:
            cursor_key = f'pool_cursor_{key}'
            self._pool_cursor[key] = int(mappings.get('state', {}).get(cursor_key, 0))
        
        self._sanitize_ip_map()
        
        self._real_to_fake = {}
        for k, v in self.subnet_dict.items():
            try:
                self._real_to_fake[IPv4Network(k)] = IPv4Network(v)
            except:
                pass  


    def _sanitize_ip_map(self):
        """Remove any bad mappings like 0.0.0.0 from previous runs"""
        for k in list(self.ip_dict.keys()):
            if k in SPECIALS:
                del self.ip_dict[k]

    def _classify_ip(self, ip: str) -> str:
        """
        Classify an IP to determine which visual category it belongs to.
        This is the key to visual pattern recognition!
        """
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

    def _is_private(self, ip_str):
        """Check if IP is private"""
        try:
            ip = IPv4Address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return False

    def _should_obfuscate_private(self):
        """Determine if private IPs should be obfuscated"""
        mode = str(self.config.get('obfuscate_private_ip', 'no')).lower()
        return mode == 'yes'  

    def _alloc_fake_subnet_from_pool(self, cat_key: str, prefixlen: int) -> IPv4Network:
        """
        Allocate a fake subnet from the specified pool.
        Maintains the same prefix length as the original subnet.
        Only checks conflicts against same-size fake subnets so that a large
        allocated fake (e.g. /16) does not block all /24 slots inside it.
        """
        pool = self.category_pools[cat_key]

        if prefixlen < pool.prefixlen:
            prefixlen = pool.prefixlen

        step  = 2 ** (32 - prefixlen)
        start = int(pool.network_address)
        end   = int(pool.broadcast_address) + 1

        # Only compare against fake subnets of the same prefix length to avoid
        # a single large fake subnet (e.g. /16) exhausting all smaller slots.
        same_size_fakes = {n for n in self._real_to_fake.values() if n.prefixlen == prefixlen}

        cursor = self._pool_cursor.get(cat_key, 0)
        for _ in range((end - start) // step):
            base = start + ((cursor // step) * step)
            if base >= end:
                cursor = 0
                base = start
            cand = IPv4Network((base, prefixlen))
            if not any(cand.overlaps(n) for n in same_size_fakes):
                self._pool_cursor[cat_key] = (base - start) + step
                return cand
            cursor += step

        raise RuntimeError(f"Pool {pool} exhausted for /{prefixlen}")


    def _ensure_fake_subnet(self, real_net: IPv4Network):
        """Ensure we have a fake subnet allocated for this real subnet"""
        if real_net in self._real_to_fake:
            return
        cat = self._classify_ip(str(real_net.network_address))
        if self._is_private(str(real_net.network_address)) and not self._should_obfuscate_private():
            return
        fake_net = self._alloc_fake_subnet_from_pool(cat, real_net.prefixlen)
        self._real_to_fake[real_net] = fake_net
        self.subnet_dict[str(real_net)] = str(fake_net)


    def _prepare_subnets(self, text):
        """
        First pass: Learn all subnets from IP/prefix notations.
        This enables subnet-aware mapping in the second pass.
        """
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

            if ip_obj.is_loopback or ip_obj.is_multicast or ip in SPECIALS:
                continue  
            
            try:
                real_net = ip_network(f"{ip}/{pfx}", strict=False)
                
                is_private = self._is_private(ip)
                if is_private and not self._should_obfuscate_private():
                    continue  
                
                self._ensure_fake_subnet(real_net)
            except ValueError:
                pass

    def _map_in_subnets(self, ip_str):
        """
        Map an IP by finding which subnet it belongs to
        and using the same offset in the fake subnet.
        This preserves network/broadcast addresses and relative positions!
        """
        from ipaddress import IPv4Address
        try:
            ip = IPv4Address(ip_str)
        except:
            return None      
          
        for real_net, fake_net in sorted(self._real_to_fake.items(),
                                        key=lambda kv: kv[0].prefixlen,
                                        reverse=True):
            if ip in real_net:
                off = int(ip) - int(real_net.network_address)
                return str(IPv4Address(int(fake_net.network_address) + off))
        return None


    
    def _scrub_token(self, ip_str, pfx_str):
        """
        Scrub a single IP or IP/prefix token.
        This is called for each regex match.
        """
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
            return mapped + (f"/{pfx_str}" if pfx_str else "")

        # If no known subnet yet then create logical subnet and map by offset
        real_net, fake_net = self._ensure_logical_subnet_for_ip(ip_str)
        if real_net and fake_net:
            off = int(ip_obj) - int(real_net.network_address)
            mapped_ip = str(IPv4Address(int(fake_net.network_address) + off))
            self.ip_dict[ip_str] = mapped_ip
            return mapped_ip + (f"/{pfx_str}" if pfx_str else "")

        return ip_str + (f"/{pfx_str}" if pfx_str else "")
        

    def _ensure_logical_subnet_for_ip(self, ip_str):
        ip = IPv4Address(ip_str)
        for real_net in sorted(self._real_to_fake.keys(), key=lambda n: n.prefixlen, reverse=True):
            if ip in real_net:
                return real_net, self._real_to_fake[real_net]

        default_pfx = int(self.config.get('default_infer_prefixlen', 24))
        real_net = ip_network(f"{ip}/{default_pfx}", strict=False)

        if self._is_private(str(real_net.network_address)) and not self._should_obfuscate_private():
            return None, None

        self._ensure_fake_subnet(real_net)
        return real_net, self._real_to_fake.get(real_net)

    


    def scrub_text(self, text):
        """
        Main entry point: scrub all IPs in a text.
        Two-pass approach:
        1. Learn subnets
        2. Replace IPs with subnet awareness
        """
        self._prepare_subnets(text)
        
        def repl(m):
            ip = m.group('ip')
            pfx = m.group('pfx')

            start = m.start()
            snippet = text[max(0, start-20):start].lower()
            if 'version' in snippet or snippet.rstrip().endswith('ver'):
                return m.group(0)  

            return self._scrub_token(ip, pfx)
        
        new_text = CIDR_RE.sub(repl, text)
        state = {f'pool_cursor_{k}': v for k, v in self._pool_cursor.items()}
        
        return new_text, self.ip_dict, self.subnet_dict, state


    def scrub_ip(self, ip):
        """
        Legacy method for backward compatibility.
        Single IP scrubbing without subnet context.
        """
        if ip in SPECIALS:
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
        """Extract IP addresses from text (for compatibility)"""
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
