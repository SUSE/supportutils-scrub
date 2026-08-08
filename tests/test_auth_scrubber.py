import base64

import pytest

from supportutils_scrub.auth_scrubber import AuthScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber

# Built at runtime so no string in this file looks like a checked-in secret.
_LOGIN = "a.tester@corp.invalid"
_SECRET = "s3cr3t" + "T0kenValue"


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _decode(text):
    """Pull the Basic blob out of a scrubbed line and decode it."""
    blob = text.split("Basic ")[1].split('"')[0].split()[0]
    return base64.b64decode(blob).decode()


def _make(**kw):
    return AuthScrubber(mappings={}, **kw)


class TestBasicHeader:
    def test_full_credential_is_removed(self):
        s = _make()
        out = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        assert _SECRET not in out
        assert _LOGIN not in out
        assert _b64(_LOGIN + ":" + _SECRET) not in out

    def test_json_access_log_form(self):
        """The form a reverse-proxy access log writes; the quote between the
        key and the colon is what older patterns tripped on."""
        s = _make()
        line = '{"status":200,"authorization":"Basic %s"}' % _b64(_LOGIN + ":" + _SECRET)
        out = s.scrub(line)
        assert _SECRET not in out
        assert out.startswith('{"status":200,')

    def test_proxy_authorization(self):
        s = _make()
        out = s.scrub(f"Proxy-Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        assert _SECRET not in out

    def test_empty_password_stays_empty(self):
        """The trailing colon is diagnostic: it is how an engineer sees a
        client sending a username with no password. It must survive."""
        s = _make()
        out = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':')}")
        assert _LOGIN not in out
        assert _decode(out).endswith(":")
        assert len(_decode(out).split(":")) == 2

    def test_non_empty_password_stays_non_empty(self):
        s = _make()
        out = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        login, _, secret = _decode(out).partition(":")
        assert login and secret

    def test_empty_and_full_remain_distinguishable(self):
        """The whole point: the two states must not collapse onto one value."""
        s = _make()
        empty = s.scrub(f'"authorization":"Basic {_b64(_LOGIN + ":")}"')
        full = s.scrub(f'"authorization":"Basic {_b64(_LOGIN + ":" + _SECRET)}"')
        assert empty != full
        assert _decode(empty) != _decode(full)

    def test_same_credential_maps_consistently(self):
        s = _make()
        line = f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}"
        assert s.scrub(line) == s.scrub(line)

    def test_output_is_still_a_parseable_basic_header(self):
        """Downstream log tooling keeps working: the value is still base64 of
        a login:secret pair, just not a real one."""
        s = _make()
        out = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        assert ":" in _decode(out)

    def test_undecodable_blob_fails_closed(self):
        """Not parseable as a credential, but it sits in an auth header, so it
        is replaced rather than passed through."""
        s = _make()
        out = s.scrub("Authorization: Basic ////////////")
        assert "////////////" not in out
        assert "SCRUBBED_" in out

    def test_already_scrubbed_value_is_left_alone(self):
        s = _make()
        once = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        assert s.scrub(once) == once

    def test_bearer_in_json_form(self):
        s = _make()
        token = "B" * 40
        out = s.scrub('{"authorization":"Bearer %s"}' % token)
        assert token not in out

    def test_www_authenticate_challenge_untouched(self):
        """A challenge carries no credential."""
        s = _make()
        line = 'WWW-Authenticate: Basic realm="artifactory"'
        assert s.scrub(line) == line

    def test_prose_is_untouched(self):
        s = _make()
        line = "Basic INSTALLATION steps are described below"
        assert s.scrub(line) == line


class TestUrlUserinfo:
    def test_user_and_password_removed(self):
        s = _make()
        out = s.scrub("baseurl=https://tuser:hunter2pw@repo.corp.invalid/x/")
        assert "hunter2pw" not in out
        assert "tuser" not in out
        assert "@repo.corp.invalid/x/" in out

    def test_bare_username_is_pseudonymised_not_deleted(self):
        """Whether the URL carries a username at all is the diagnosis in a
        credential-precedence failure, so the '@' must stay."""
        s = _make()
        out = s.scrub("baseurl=https://tuser@repo.corp.invalid/x/")
        assert "tuser" not in out
        assert "@repo.corp.invalid/x/" in out
        assert out.count("@") == 1

    def test_url_without_userinfo_untouched(self):
        s = _make()
        line = "baseurl=https://repo.corp.invalid/x/"
        assert s.scrub(line) == line

    def test_public_login_untouched(self):
        s = _make()
        line = "git clone https://git@github.com/foo/bar"
        assert s.scrub(line) == line

    def test_at_in_path_does_not_extend_the_match(self):
        s = _make()
        line = "https://repo.corp.invalid/api/v1/user@example/list"
        assert s.scrub(line) == line

    def test_empty_password_in_url_stays_empty(self):
        s = _make()
        out = s.scrub("https://tuser:@repo.corp.invalid/x/")
        assert "tuser" not in out
        assert ":@repo.corp.invalid" in out


class TestDelegation:
    def test_login_matches_the_email_scrubber(self):
        """The address inside the header and the same address in clear text
        must land on one pseudonym, or they cannot be correlated."""
        em = EmailScrubber(mappings={})
        s = _make(email_scrubber=em)
        plain = em.scrub(f"contact: {_LOGIN}")
        out = s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        pseudonym = em.mapping[_LOGIN]
        assert pseudonym in plain
        assert _decode(out).startswith(pseudonym)

    def test_login_matches_the_username_scrubber(self):
        us = UsernameScrubber({"tuser": "scrubbed_user_7"})
        s = _make(username_scrubber=us)
        out = s.scrub(f"Authorization: Basic {_b64('tuser:' + _SECRET)}")
        assert _decode(out).startswith("scrubbed_user_7")

    def test_falls_back_without_delegates(self):
        s = _make()
        out = s.scrub(f"Authorization: Basic {_b64('tuser:' + _SECRET)}")
        assert "tuser" not in out
        assert _decode(out).startswith("SCRUBBED_LOGIN_")


class TestMapping:
    def test_mapping_is_exposed_for_persistence(self):
        s = _make()
        s.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        assert s.mapping
        assert _SECRET in s.mapping

    def test_mapping_is_reloaded(self):
        first = _make()
        line = f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}"
        out = first.scrub(line)
        second = AuthScrubber(mappings={"auth": first.mapping})
        assert second.scrub(line) == out

    def test_deterministic_mode_is_process_stable(self):
        line = f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}"
        a = AuthScrubber(mappings={}, deterministic=True)
        b = AuthScrubber(mappings={}, deterministic=True)
        assert a.scrub(line) == b.scrub(line)


class TestChainOrder:
    """The auth scrubber runs immediately before the email scrubber, and the
    two interact in both directions. Unit tests pass either way, so these
    guard the wiring rather than the classes."""

    @staticmethod
    def _chain(text):
        em = EmailScrubber(mappings={})
        au = AuthScrubber(mappings={}, email_scrubber=em)
        return em.scrub(au.scrub(text))

    def test_email_does_not_reswallow_a_url_login(self):
        """"SCRUBBED_LOGIN_1@host" matches EMAIL_RE exactly. If email were
        allowed to take it, the login and the host would collapse into one
        pseudonym and the host would never reach the domain scrubber."""
        out = self._chain("baseurl=https://tuser@repo.corp.invalid/x/")
        assert "tuser" not in out
        assert "@repo.corp.invalid/x/" in out

    def test_email_does_not_reswallow_a_url_secret(self):
        out = self._chain("baseurl=https://tuser:hunter2pw@repo.corp.invalid/x/")
        assert "hunter2pw" not in out
        assert "@repo.corp.invalid/x/" in out

    def test_url_host_is_left_for_the_domain_scrubber(self):
        out = self._chain("https://tuser@repo.corp.invalid/x/")
        assert "repo.corp.invalid" in out

    def test_header_login_still_matches_plain_text(self):
        em = EmailScrubber(mappings={})
        au = AuthScrubber(mappings={}, email_scrubber=em)
        header = au.scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        plain = em.scrub(f"owner: {_LOGIN}")
        assert em.mapping[_LOGIN] in plain
        assert _decode(header).startswith(em.mapping[_LOGIN])


class TestVerifyCatchesLeaks:
    """The detector must fail on an unscrubbed credential and pass on a
    scrubbed one, otherwise it cannot be used as proof."""

    def test_detector_flags_a_real_credential(self):
        from supportutils_scrub.verify import _BASIC_CRED_RE, _basic_is_credential
        line = f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}"
        m = _BASIC_CRED_RE.search(line)
        assert m and _basic_is_credential(m.group(1))

    def test_detector_passes_scrubbed_output(self):
        from supportutils_scrub.verify import _BASIC_CRED_RE, _basic_is_credential
        out = _make().scrub(f"Authorization: Basic {_b64(_LOGIN + ':' + _SECRET)}")
        m = _BASIC_CRED_RE.search(out)
        assert m and not _basic_is_credential(m.group(1))

    def test_detector_passes_wholesale_replacement(self):
        from supportutils_scrub.verify import _BASIC_CRED_RE, _basic_is_credential
        out = _make().scrub("Authorization: Basic ////////////")
        m = _BASIC_CRED_RE.search(out)
        assert m is None or not _basic_is_credential(m.group(1))
