import pytest
from supportutils_scrub.hostname_scrubber import HostnameScrubber


class TestHostnameScrub:
    def test_hostname_replaced(self):
        s = HostnameScrubber({"myserver": "hostname_0"})
        assert "hostname_0" in s.scrub("host myserver is up")

    def test_multiple_hostnames(self):
        s = HostnameScrubber({"host1": "hostname_0", "host2": "hostname_1"})
        result = s.scrub("host1 talks to host2")
        assert "host1" not in result
        assert "host2" not in result

    def test_word_boundary(self):
        s = HostnameScrubber({"test": "hostname_0"})
        result = s.scrub("testing test tested")
        # "test" should match only the standalone word
        assert "hostname_0" in result

    def test_empty_dict(self):
        s = HostnameScrubber({})
        assert s.scrub("anything") == "anything"

    def test_mapping_property(self):
        s = HostnameScrubber({"a": "b"})
        assert s.mapping == {"a": "b"}


def test_product_default_hostnames_never_learned(tmp_path):
    """uyuni-server / uyuni-db etc. are the mgradm container defaults on
    EVERY Multi-Linux Manager installation: real hostnames in a container
    capture, but product identity, not customer identity. They must never
    be auto-learned as scrub targets (an operator can still pass them
    explicitly via additional hostnames)."""
    from supportutils_scrub.hostname_scrubber import (HostnameScrubber,
                                                      WELL_KNOWN_HOSTNAMES)
    assert {"uyuni-server", "uyuni-db", "uyuni-proxy"} <= WELL_KNOWN_HOSTNAMES

    f = tmp_path / "network.txt"
    f.write_text(
        "# /etc/hosts\n"
        "127.0.0.1 localhost\n"
        "10.0.0.5 uyuni-server uyuni-server.mgr.internal\n"
        "10.0.0.6 uyuni-db\n"
        "10.0.0.7 susemgr01 susemgr01.customer.example\n"
        "# /etc/host.conf\n")
    learned = HostnameScrubber.extract_hostnames_from_hosts(str(f))
    assert "susemgr01" in learned                 # real customer host: learned
    assert "uyuni-server" not in learned          # product default: kept
    assert "uyuni-db" not in learned
    assert "localhost" not in learned


def test_product_default_not_learned_from_text():
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    text = ("2026-07-14T02:05:01+00:00 uyuni-server systemd[1]: started\n"
            "2026-07-14T02:05:02+00:00 uyuni-server taskomatic: run\n"
            "2026-07-14T02:05:03+00:00 uyuni-server taskomatic: done\n"
            "2026-07-14T02:06:01+00:00 custhost42 sshd[9]: session\n"
            "2026-07-14T02:06:02+00:00 custhost42 sshd[9]: session\n"
            "2026-07-14T02:06:03+00:00 custhost42 sshd[9]: session\n")
    learned = HostnameScrubber.extract_hostnames_from_text(text)
    assert "custhost42" in learned
    assert "uyuni-server" not in learned


def test_preserved_strings_never_scrubbed_even_from_legacy_mapping():
    """The absolute guarantee: uyuni-server/db/proxy and friends are never
    rewritten, even when a legacy shared-mapping file already contains them
    as scrub targets (mappings are reused across re-scrubs)."""
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    legacy = {"uyuni-server": "hostname_10", "uyuni-db": "hostname_11",
              "custhost42": "hostname_12"}
    s = HostnameScrubber(legacy)
    out = s.scrub("uyuni-server-container-80056a0c on custhost42 with uyuni-db")
    assert "uyuni-server-container-80056a0c" in out     # untouched
    assert "uyuni-db" in out
    assert "custhost42" not in out                      # real host still scrubbed
    assert "hostname_12" in out
    # and the dropped entries do not reappear in the mapping written out
    assert "uyuni-server" not in s.mapping
    assert "custhost42" in s.mapping


def test_preserved_strings_not_corrupted_by_substring_hosts():
    """A learned hostname that is a boundary-substring of a preserved string
    (host literally named 'server') must not corrupt 'uyuni-server'."""
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    s = HostnameScrubber({"server": "hostname_0", "uyuni": "hostname_1"})
    out = s.scrub("uyuni-server started; server rebooted; uyuni node up; "
                  "uyuni-common-libs installed")
    assert "uyuni-server started" in out                # preserved intact
    assert "hostname_0 rebooted" in out                 # bare 'server' scrubbed
    assert "uyuni node up" in out                       # product name preserved
    assert "uyuni-common-libs installed" in out         # package names intact


def test_preserved_strings_case_insensitive():
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    s = HostnameScrubber({"UYUNI-SERVER": "hostname_9"})
    assert s.scrub("UYUNI-SERVER and Uyuni-Server") == \
        "UYUNI-SERVER and Uyuni-Server"


def test_hostname_preserve_config_extends_set():
    from supportutils_scrub.hostname_scrubber import (HostnameScrubber,
                                                      preserved_hostnames)

    class _Cfg:
        hostname_preserve = "mycorp-gateway, Another-Name"

    names = preserved_hostnames(_Cfg())
    assert "mycorp-gateway" in names and "another-name" in names
    assert "uyuni-server" in names                      # built-ins always kept
    s = HostnameScrubber({"mycorp-gateway": "hostname_5"}, config=_Cfg())
    assert s.scrub("mycorp-gateway up") == "mycorp-gateway up"
