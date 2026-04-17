import pytest
from supportutils_scrub.verify import (
    _is_safe_ipv4,
    _looks_like_version_context,
    _build_safe_ipv4_nets,
    _IP_RE,
)


class TestSafeIPv4:
    def test_real_cloudflare_not_safe(self):
        nets = _build_safe_ipv4_nets(obfuscate_private_ip=True)
        assert not _is_safe_ipv4("1.1.1.1", nets)

    def test_real_akamai_not_safe(self):
        nets = _build_safe_ipv4_nets(obfuscate_private_ip=True)
        assert not _is_safe_ipv4("2.16.1.2", nets)

    def test_fake_public_pool_safe(self):
        nets = _build_safe_ipv4_nets(obfuscate_private_ip=True)
        assert _is_safe_ipv4("198.16.1.2", nets)

    def test_loopback_safe(self):
        nets = _build_safe_ipv4_nets(obfuscate_private_ip=True)
        assert _is_safe_ipv4("127.0.0.1", nets)

    def test_private_safe_when_not_scrubbing(self):
        nets = _build_safe_ipv4_nets(obfuscate_private_ip=False)
        assert _is_safe_ipv4("10.0.0.1", nets)


class TestVersionContext:
    def test_version_keyword_suppresses(self):
        line = "kernel version 2.25.1.0"
        m = next(_IP_RE.finditer(line))
        assert _looks_like_version_context(line, m.start())

    def test_ver_keyword_suppresses(self):
        line = "ver: 1.0.8.177"
        m = next(_IP_RE.finditer(line))
        assert _looks_like_version_context(line, m.start())

    def test_nameserver_not_version(self):
        line = "nameserver 1.1.1.1"
        m = next(_IP_RE.finditer(line))
        assert not _looks_like_version_context(line, m.start())

    def test_release_keyword_suppresses(self):
        line = "release 16.0.0.4"
        m = next(_IP_RE.finditer(line))
        assert _looks_like_version_context(line, m.start())

    def test_plain_ip_not_version(self):
        line = "gateway 8.8.8.8"
        m = next(_IP_RE.finditer(line))
        assert not _looks_like_version_context(line, m.start())
