# ipv6_scrubber.py 


import re
import ipaddress
from typing import Dict, Tuple, List, Iterable, Match, Optional

CANDIDATE_V6 = re.compile(r"(?<![A-Za-z0-9:_-])([0-9A-Fa-f:.:]+)(?:/(\d{1,3}))?(?![A-Za-z0-9:_-])")

UNSPECIFIED = ipaddress.IPv6Network("::/128")
LOOPBACK    = ipaddress.IPv6Network("::1/128")
MULTICAST   = ipaddress.IPv6Network("ff00::/8")
LINK_LOCAL  = ipaddress.IPv6Network("fe80::/10")
ULA         = ipaddress.IPv6Network("fc00::/7")

FAKE_POOL_DB8   = ipaddress.IPv6Network("2001:db8::/32")  
FAKE_POOL_ULA = ipaddress.IPv6Network("fd00::/8") 
GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")


class IPv6Scrubber:
    """
    Subnet-aware IPv6 obfuscator.

    Public methods:
      - scrub_text(text) -> (new_text, ipv6_map, ipv6_subnet_map, state)
      - extract_ipv6(text) -> List[str]
      - scrub_ipv6(ip_str) -> str (legacy per-address)
    """

    def __init__(self, config: Dict, mappings: Optional[Dict] = None) -> None:
        self.config = config or {}

        self.ipv6_map: Dict[str, str] = dict((mappings or {}).get('ipv6', {}))
        self._subnet_map: Dict[ipaddress.IPv6Network, ipaddress.IPv6Network] = {}
        for k, v in ((mappings or {}).get('ipv6_subnet', {}) or {}).items():
            try:
                self._subnet_map[ipaddress.IPv6Network(k)] = ipaddress.IPv6Network(v)
            except Exception:
                pass

        state = (mappings or {}).get('state', {})
        self._pool_cursor: int = int(state.get('ipv6_pool_cursor', 0))

    def _flag(self, key: str, default: str = 'yes') -> bool:
        return str(self.config.get(key, default)).strip().lower() == 'yes'

    def _should_obfuscate(self) -> bool:
        return self._flag('obfuscate_ipv6', 'yes')

    def _skip_scope(self, ip: ipaddress.IPv6Address) -> bool:
        if ip in UNSPECIFIED or ip in LOOPBACK or ip in MULTICAST:
            return True

        if (ip in LINK_LOCAL) and not self._flag('obfuscate_ipv6_linklocal', 'no'):
            return True
        if (ip in ULA) and not self._flag('obfuscate_ipv6_ula', 'no'):
            return True

        if (ip in GLOBAL_UNICAST):
            return False
        if (ip in ULA) and self._flag('obfuscate_ipv6_ula', 'no'):
            return False
        if (ip in LINK_LOCAL) and self._flag('obfuscate_ipv6_linklocal', 'no'):
            return False

        return True

    
    def _pick_pool(self, prefixlen: int) -> ipaddress.IPv6Network:

        return FAKE_POOL_ULA if prefixlen <= 48 else FAKE_POOL_DB8

    def _alloc_fake_subnet(self, prefixlen: int) -> ipaddress.IPv6Network:
        pool = self._pick_pool(prefixlen)

        if prefixlen < pool.prefixlen:
            prefixlen = pool.prefixlen

        step  = 1 << (128 - prefixlen)
        start = int(pool.network_address)
        end   = int(pool.broadcast_address) + 1

        cur = self._pool_cursor
        tried = 0
        while tried < ((end - start) // step):
            base = start + ((cur // step) * step)
            if base >= end:
                cur = 0
                base = start
            cand = ipaddress.IPv6Network((base, prefixlen))
            if not any(cand.overlaps(n) for n in self._subnet_map.values()):
                self._pool_cursor = (base - start) + step
                return cand
            cur += step
            tried += 1

        raise RuntimeError(f"IPv6 fake pool {pool} exhausted for /{prefixlen}")


    def _get_or_create_fake_subnet(self, real_net: ipaddress.IPv6Network) -> ipaddress.IPv6Network:
        if real_net in self._subnet_map:
            return self._subnet_map[real_net]
        fake = self._alloc_fake_subnet(real_net.prefixlen)
        self._subnet_map[real_net] = fake
        return fake

    def _choose_mapping_prefix(self, ip: ipaddress.IPv6Address, explicit_pfx: Optional[int]) -> int:
        """
        Prefer explicit prefix from the text, but never anchor broader than /48.
        Otherwise default to /64 (typical host subnets).
        """
        if explicit_pfx is not None and 0 <= explicit_pfx <= 128:
            return max(48, explicit_pfx) 
        return 64

    def _map_in_known_subnets(self, ip: ipaddress.IPv6Address) -> Optional[str]:
        """If the IP sits inside any already-mapped real subnet, return mapped IP."""
        for real, fake in sorted(self._subnet_map.items(), key=lambda kv: kv[0].prefixlen, reverse=True):
            if ip in real:
                offset = int(ip) - int(real.network_address)
                return str(ipaddress.IPv6Address(int(fake.network_address) + offset))
        return None

    def scrub_text(self, text: str):
        """
        One-pass IPv6 obfuscation over free text.
        Returns: (new_text, ipv6_map, ipv6_subnet_map, state)
        - ipv6_map:        dict real->fake (strings)
        - ipv6_subnet_map: dict real->fake (strings)
        - state:           { 'ipv6_pool_cursor': int }
        """
        if not self._should_obfuscate() or not text:
            # Return existing maps asare for consistency
            return text, dict(self.ipv6_map), {str(k): str(v) for k, v in self._subnet_map.items()}, { 'ipv6_pool_cursor': self._pool_cursor }

        def repl(m: Match) -> str:
            token = m.group(0)
            pfx_s = m.group(2)
            try:
                iface = ipaddress.IPv6Interface(token) if pfx_s else ipaddress.IPv6Interface(f"{token}/128")
                ip = iface.ip
                explicit_pfx = iface.network.prefixlen if pfx_s else None
            except Exception:
                return token  # not a valid IPv6 token

            if self._skip_scope(ip):
                return token

            # If seen before, reuse mapping (preserving any /pfx shown in text)
            if str(ip) in self.ipv6_map:
                fake_ip = self.ipv6_map[str(ip)]
                return f"{fake_ip}/{explicit_pfx}" if explicit_pfx is not None else fake_ip

            # Try mapped subnets first
            mapped = self._map_in_known_subnets(ip)
            if mapped:
                self.ipv6_map[str(ip)] = mapped
                return f"{mapped}/{explicit_pfx}" if explicit_pfx is not None else mapped

            # Create or reuse subnet mapping placed at chosen prefix
            anchor_pfx = self._choose_mapping_prefix(ip, explicit_pfx)
            real_subnet = ipaddress.IPv6Network((int(ip) & ~((1 << (128 - anchor_pfx)) - 1), anchor_pfx))
            fake_subnet = self._get_or_create_fake_subnet(real_subnet)

            host_off = int(ip) - int(real_subnet.network_address)
            fake_ip = ipaddress.IPv6Address(int(fake_subnet.network_address) + host_off)
            fake_s = str(fake_ip)

            self.ipv6_map[str(ip)] = fake_s
            return f"{fake_s}/{explicit_pfx}" if explicit_pfx is not None else fake_s

        new_text = CANDIDATE_V6.sub(repl, text)
        state = {'ipv6_pool_cursor': self._pool_cursor}
        subnet_map_str = {str(k): str(v) for k, v in self._subnet_map.items()}
        return new_text, dict(self.ipv6_map), subnet_map_str, state

    @staticmethod
    def extract_ipv6(text: str) -> List[str]:
        """Extract valid IPv6 literals (without validation side-effects)."""
        if not text:
            return []
        found: List[str] = []
        for m in CANDIDATE_V6.finditer(text):
            token = m.group(0)
            try:
                ipaddress.IPv6Interface(token)
            except Exception:
                try:
                    ipaddress.IPv6Address(m.group(1))
                except Exception:
                    continue
            found.append(token)
        return found

    def scrub_ipv6(self, token: str) -> str:
        """
        Scrub a single IPv6 token (with or without /prefix). Returns the obfuscated token.
        Honors the same scope and config rules as scrub_text().
        """
        if not self._should_obfuscate() or not token:
            return token
        try:
            iface = ipaddress.IPv6Interface(token) if '/' in token else ipaddress.IPv6Interface(f"{token}/128")
            ip = iface.ip
            explicit_pfx = iface.network.prefixlen if '/' in token else None
        except Exception:
            return token

        if self._skip_scope(ip):
            return token

        if str(ip) in self.ipv6_map:
            fake_ip = self.ipv6_map[str(ip)]
            return f"{fake_ip}/{explicit_pfx}" if explicit_pfx is not None else fake_ip

        mapped = self._map_in_known_subnets(ip)
        if mapped:
            self.ipv6_map[str(ip)] = mapped
            return f"{mapped}/{explicit_pfx}" if explicit_pfx is not None else mapped

        anchor_pfx = self._choose_mapping_prefix(ip, explicit_pfx)
        real_subnet = ipaddress.IPv6Network((int(ip) & ~((1 << (128 - anchor_pfx)) - 1), anchor_pfx))
        fake_subnet = self._get_or_create_fake_subnet(real_subnet)
        host_off = int(ip) - int(real_subnet.network_address)
        fake_ip = ipaddress.IPv6Address(int(fake_subnet.network_address) + host_off)
        fake_s = str(fake_ip)
        self.ipv6_map[str(ip)] = fake_s
        return f"{fake_s}/{explicit_pfx}" if explicit_pfx is not None else fake_s

    def ipv6_tcprewrite_rules(self) -> List[Tuple[str, str]]:
        """
        Return subnet mapping pairs suitable for tcprewrite-like tools.
        (Note: tcprewrite's v6 options vary by version; this method simply
        exposes real/fake subnet pairs.)
        """
        pairs: List[Tuple[str, str]] = []
        for real, fake in sorted(self._subnet_map.items(), key=lambda kv: kv[0].prefixlen, reverse=True):
            pairs.append((str(real), str(fake)))
        return pairs
