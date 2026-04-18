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


class TestIPBoundary:
    def test_rpm_version_with_plus_not_matched(self):
        line = "upower-lang 1.90.7.13+git.4f1ef04-160000.2.2"
        assert list(_IP_RE.finditer(line)) == []

    def test_rpm_version_space_separated_with_plus(self):
        line = "tuned 2.25.1.0+git.889387b-16000"
        assert list(_IP_RE.finditer(line)) == []

    def test_real_ip_before_slash_still_matches(self):
        line = "gateway 192.168.1.1/24"
        hits = [m.group(1) for m in _IP_RE.finditer(line)]
        assert "192.168.1.1" in hits


class TestKerberosRegex:
    def test_binary_garbage_rejected(self):
        from supportutils_scrub.verify import _KERBEROS_RE
        for junk in ("HtAHEH@HHEHP", "HEH@HUHP", "HEH@HEHE", "HtPhH@HHHH"):
            assert _KERBEROS_RE.search(junk) is None, junk

    def test_real_principal_matches(self):
        from supportutils_scrub.verify import _KERBEROS_RE
        for real in ("admin@EXAMPLE.COM", "krbtgt@AD.EXAMPLE.LOCAL"):
            assert _KERBEROS_RE.search(real) is not None, real
