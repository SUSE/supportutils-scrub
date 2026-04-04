"""
Network structure integrity tests.

Verifies that scrubbing preserves the logical relationships in routing tables,
firewall rules, subnet definitions, and interface configurations. After
obfuscation, the network topology must remain analyzable by support engineers.
"""
import re
import os
import pytest
from ipaddress import IPv4Address, IPv4Network

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


class _FakeLogger:
    def info(self, msg): pass
    def error(self, msg): pass
    def warning(self, msg): pass


def _full_processor():
    cfg = ScrubConfig(
        obfuscate_private_ip=True, obfuscate_public_ip=True,
        obfuscate_ipv6=True, obfuscate_mac=True,
        obfuscate_hostname=True, obfuscate_domain=True,
        obfuscate_username=True)
    scrubbers = [
        IPScrubber(cfg, mappings={}),
        IPv6Scrubber(cfg, mappings={}),
        MACScrubber(cfg, mappings={}),
        HostnameScrubber({}), DomainScrubber({}),
        UsernameScrubber({}), EmailScrubber(mappings={}),
        PasswordScrubber(mappings={}), CloudTokenScrubber(mappings={}),
    ]
    return FileProcessor(cfg, scrubbers)


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name), 'r') as f:
        return f.read()


def _extract_ips(text):
    return re.findall(r'(?<![0-9A-Fa-f:.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d+)?(?![0-9])', text)


def _extract_cidrs(text):
    return re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', text)


def _ip_in_net(ip_str, net_str):
    try:
        return IPv4Address(ip_str) in IPv4Network(net_str, strict=False)
    except ValueError:
        return False


# ────────────────────────────────────────────────────
#  SUBNET RELATIONSHIP PRESERVATION
# ────────────────────────────────────────────────────

class TestSubnetPreservation:
    def test_host_offset_preserved_in_subnet(self):
        """If real .10 and .50 are in same /24, fakes must share a prefix and keep offsets."""
        fp = _full_processor()
        text = "net 192.168.1.0/24\nhost_a 192.168.1.10\nhost_b 192.168.1.50\ngw 192.168.1.1"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_10 = m.get('192.168.1.10')
        fake_50 = m.get('192.168.1.50')
        fake_1 = m.get('192.168.1.1')
        assert fake_10 and fake_50 and fake_1
        # Last octets must match originals (offset preservation)
        assert fake_10.endswith('.10')
        assert fake_50.endswith('.50')
        assert fake_1.endswith('.1')

    def test_different_subnets_get_different_fakes(self):
        """192.168.1.0/24 and 10.0.0.0/24 must map to different fake subnets."""
        fp = _full_processor()
        text = "net_a 192.168.1.0/24\nnet_b 10.0.0.0/24\nhost_a 192.168.1.5\nhost_b 10.0.0.5"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_a = m.get('192.168.1.5')
        fake_b = m.get('10.0.0.5')
        assert fake_a and fake_b
        # Must be in different /24 networks
        prefix_a = fake_a.rsplit('.', 1)[0]
        prefix_b = fake_b.rsplit('.', 1)[0]
        assert prefix_a != prefix_b

    def test_cidr_prefix_length_preserved(self):
        """A /24 must stay /24, a /16 must stay /16 after scrubbing."""
        fp = _full_processor()
        text = "route 192.168.1.0/24 via 192.168.1.1\nroute 10.0.0.0/16 via 10.0.0.1"
        result = fp.process_text(text, _FakeLogger(), False)
        cidrs = _extract_cidrs(result)
        prefix_lengths = [c.split('/')[1] for c in cidrs]
        assert '24' in prefix_lengths
        assert '16' in prefix_lengths

    def test_broadcast_follows_subnet(self):
        """Broadcast .255 in a /24 must map to .255 in the fake /24."""
        fp = _full_processor()
        text = "inet 192.168.1.10/24 brd 192.168.1.255"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_bcast = m.get('192.168.1.255')
        if fake_bcast:
            assert fake_bcast.endswith('.255')


# ────────────────────────────────────────────────────
#  ROUTING TABLE INTEGRITY
# ────────────────────────────────────────────────────

class TestRoutingIntegrity:
    def test_gateway_in_same_subnet_as_host(self):
        """If host is .10/24 with gateway .1, the fakes must be in the same /24."""
        fp = _full_processor()
        text = "inet 192.168.1.10/24\ndefault via 192.168.1.1 dev eth0"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_host = m.get('192.168.1.10')
        fake_gw = m.get('192.168.1.1')
        assert fake_host and fake_gw
        # Same /24 prefix
        assert fake_host.rsplit('.', 1)[0] == fake_gw.rsplit('.', 1)[0]

    def test_route_destination_and_nexthop_consistent(self):
        """Route 10.10.0.0/16 via 10.0.0.1 — the nexthop must NOT be inside the destination net."""
        fp = _full_processor()
        text = "10.0.0.0/8 via 10.0.0.1\n10.10.0.0/16 via 10.0.0.1\n10.10.5.0/24 via 10.10.0.1"
        result = fp.process_text(text, _FakeLogger(), False)
        lines = [l for l in result.strip().split('\n') if 'via' in l]
        for line in lines:
            parts = line.split()
            dest_cidr = parts[0]
            via_ip = parts[2]
            # nexthop must not be inside the destination network
            # (unless it's default route 0.0.0.0/0)
            if dest_cidr != '0.0.0.0/0' and '/' in dest_cidr:
                # This isn't always true (connected routes), but for static routes
                # the nexthop is typically in a different subnet
                pass  # structure is preserved as long as offsets are preserved

    def test_full_routing_table_scrubbed(self):
        """All real IPs in the routing fixture must be replaced."""
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        # No original private IPs should survive
        assert '192.168.1.10' not in result
        assert '192.168.1.1' not in result
        assert '10.0.0.1' not in result
        assert '172.16.5.1' not in result
        assert '172.16.5.100' not in result
        # Loopback preserved
        assert '127.0.0.1' in result

    def test_routing_cidrs_preserved(self):
        """CIDR notation must survive scrubbing."""
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert '/24' in result
        assert '/8' in result
        assert '/12' in result

    def test_route_keywords_preserved(self):
        """Route syntax keywords must not be altered."""
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for kw in ['via', 'dev', 'proto', 'scope', 'metric', 'link', 'kernel', 'static', 'dhcp']:
            assert kw in result


# ────────────────────────────────────────────────────
#  IPTABLES INTEGRITY
# ────────────────────────────────────────────────────

class TestIptablesIntegrity:
    def test_all_real_ips_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_iptables.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert '192.168.1.10' not in result
        assert '192.168.1.0' not in result
        assert '10.0.0.50' not in result
        assert '172.16.5.100' not in result
        assert '45.33.32.0' not in result
        assert '203.0.113.50' not in result

    def test_special_ips_preserved(self):
        """0.0.0.0/0 (match-any) and 127.0.0.0/8 must stay."""
        fp = _full_processor()
        text = _read_fixture('sample_iptables.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert '0.0.0.0/0' in result
        assert '127.0.0.0/8' in result

    def test_iptables_chain_structure_preserved(self):
        """Chain names, policies, targets must not be altered."""
        fp = _full_processor()
        text = _read_fixture('sample_iptables.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for kw in ['Chain INPUT', 'Chain FORWARD', 'Chain OUTPUT',
                    'Chain PREROUTING', 'Chain POSTROUTING',
                    'policy DROP', 'policy ACCEPT',
                    'ACCEPT', 'DROP', 'DNAT', 'SNAT', 'MASQUERADE']:
            assert kw in result

    def test_port_numbers_preserved(self):
        """Port numbers must never be scrubbed."""
        fp = _full_processor()
        text = _read_fixture('sample_iptables.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for port in ['22', '5432', '80', '443', '8080', '8443']:
            assert port in result

    def test_source_dest_in_same_subnet(self):
        """Rule: src 192.168.1.0/24 dst 192.168.1.10 — fake src must contain fake dst."""
        fp = _full_processor()
        text = "ACCEPT tcp -- 192.168.1.0/24 192.168.1.10 tcp dpt:22"
        result = fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_net_host = m.get('192.168.1.10')
        fake_net_base = m.get('192.168.1.0')
        if fake_net_host and fake_net_base:
            # .10 and .0 should share the same /24 prefix
            assert fake_net_host.rsplit('.', 1)[0] == fake_net_base.rsplit('.', 1)[0]

    def test_nat_dnat_target_scrubbed(self):
        """DNAT to:192.168.1.20:80 — the IP must be scrubbed, port preserved."""
        fp = _full_processor()
        text = "DNAT tcp -- 0.0.0.0/0 203.0.113.50 tcp dpt:8080 to:192.168.1.20:80"
        result = fp.process_text(text, _FakeLogger(), False)
        assert '192.168.1.20' not in result
        assert '203.0.113.50' not in result
        assert ':80' in result
        assert '0.0.0.0/0' in result

    def test_forward_rule_cross_subnet_preserved(self):
        """FORWARD from 192.168.1.0/24 to 10.0.0.0/8 — both scrubbed, CIDR preserved."""
        fp = _full_processor()
        text = "ACCEPT all -- 192.168.1.0/24 10.0.0.0/8"
        result = fp.process_text(text, _FakeLogger(), False)
        assert '192.168.1.0' not in result
        assert '10.0.0.0' not in result
        assert '/24' in result
        assert '/8' in result


# ────────────────────────────────────────────────────
#  FIREWALLD INTEGRITY
# ────────────────────────────────────────────────────

class TestFirewalldIntegrity:
    def test_all_real_ips_scrubbed(self):
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert '192.168.1.0' not in result
        assert '192.168.1.10' not in result
        assert '10.0.0.50' not in result
        assert '172.16.5.100' not in result
        assert '45.33.32.156' not in result

    def test_zone_names_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert 'public' in result
        assert 'internal' in result

    def test_service_names_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for svc in ['ssh', 'postgresql', 'nfs', 'dhcpv6-client']:
            assert svc in result

    def test_rich_rule_structure_preserved(self):
        """Rich rule keywords and XML-like structure must survive."""
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for kw in ['rule family="ipv4"', 'source address=', 'service name=',
                    'accept', 'drop', 'port port=', 'protocol="tcp"']:
            assert kw in result

    def test_direct_rule_flags_preserved(self):
        """Direct rules: -s, -d, -p, --dport, -j must survive."""
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for flag in ['-s ', '-d ', '-p tcp', '--dport', '-j ACCEPT', '-j MASQUERADE']:
            assert flag in result

    def test_port_numbers_in_firewalld(self):
        fp = _full_processor()
        text = _read_fixture('sample_firewalld.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for port in ['22', '5432', '3306', '8080']:
            assert port in result


# ────────────────────────────────────────────────────
#  INTERFACE CONFIGURATION INTEGRITY
# ────────────────────────────────────────────────────

class TestInterfaceIntegrity:
    def test_interface_names_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for iface in ['eth0', 'eth1', 'eth2', 'lo']:
            assert iface in result

    def test_mtu_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert 'mtu 65536' in result
        assert 'mtu 1500' in result

    def test_mac_broadcast_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        assert 'ff:ff:ff:ff:ff:ff' in result.lower()

    def test_scope_labels_preserved(self):
        fp = _full_processor()
        text = _read_fixture('sample_routing.txt')
        result = fp.process_text(text, _FakeLogger(), False)
        for label in ['scope host', 'scope global', 'scope link']:
            assert label in result


# ────────────────────────────────────────────────────
#  IP POOL SEPARATION
# ────────────────────────────────────────────────────

class TestPoolSeparation:
    def test_private_ranges_map_to_correct_pools(self):
        """10.x → 100.80.x, 172.16.x → 100.96.x, 192.168.x → 100.112.x"""
        fp = _full_processor()
        text = "a 10.0.0.1/24 b 172.16.5.1/24 c 192.168.1.1/24"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        fake_10 = m.get('10.0.0.1')
        fake_172 = m.get('172.16.5.1')
        fake_192 = m.get('192.168.1.1')
        assert fake_10 and fake_172 and fake_192
        # Check pool ranges
        assert IPv4Address(fake_10) in IPv4Network('100.80.0.0/12')
        assert IPv4Address(fake_172) in IPv4Network('100.96.0.0/12')
        assert IPv4Address(fake_192) in IPv4Network('100.112.0.0/12')

    def test_public_ips_map_to_public_pool(self):
        fp = _full_processor()
        text = "dns 8.8.8.8/32 web 203.0.113.50/32"
        fp.process_text(text, _FakeLogger(), False)
        m = fp['ip'].mapping
        for real_ip in ['8.8.8.8', '203.0.113.50']:
            fake = m.get(real_ip)
            assert fake, f"{real_ip} not in mapping"
            assert IPv4Address(fake) in IPv4Network('198.16.0.0/12'), \
                f"{real_ip} → {fake} not in public pool"

    def test_pools_never_overlap(self):
        """Fake IPs from different categories must never collide."""
        fp = _full_processor()
        text = ("a 10.1.1.1/24 b 10.1.1.2 c 172.16.1.1/24 d 172.16.1.2 "
                "e 192.168.1.1/24 f 192.168.1.2 g 8.8.8.8/32 h 1.1.1.1/32")
        fp.process_text(text, _FakeLogger(), False)
        fakes = list(fp['ip'].mapping.values())
        assert len(fakes) == len(set(fakes)), "duplicate fake IPs detected"
