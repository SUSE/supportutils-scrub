"""The serial and parallel chains must scrub the same categories.

`--jobs N` builds its own chain in parallel._build_chain. When the two lists
drift, the parallel path silently stops scrubbing a category and nothing fails
— the run succeeds and the output looks scrubbed. That is how SID scrubbing
was lost on the default path, so the composition is asserted here rather than
left to review.
"""

from supportutils_scrub.parallel import _build_chain
from supportutils_scrub.scrub_config import ScrubConfig

# Every category the serial chains in modes/{archive,folder,file,stdin}.py
# install. Kept as names so this test does not care about construction order.
_EXPECTED = {
    'ip', 'ipv6', 'mac', 'auth', 'email', 'hostname', 'domain',
    'user', 'password', 'cloud_token', 'serial', 'sid',
}


def _names(**kw):
    frozen = {k: {} for k in ('hostname', 'domain', 'user', 'serial', 'sid',
                              'keyword', 'email', 'password', 'cloud_token',
                              'auth')}
    frozen.update(kw)
    chain = _build_chain(frozen, ScrubConfig(), deterministic=True,
                         include_ldap=True)
    return [s.name for s in chain]


def test_parallel_chain_covers_every_serial_category():
    missing = _EXPECTED - set(_names())
    assert not missing, f"parallel chain does not scrub: {sorted(missing)}"


def test_sid_is_in_the_parallel_chain():
    """Regression: constructed, configured, then never appended."""
    assert 'sid' in _names()


def test_auth_runs_before_email():
    """URL userinfo (user@host) matches an email address exactly, so auth has
    to consume it first."""
    names = _names()
    assert names.index('auth') < names.index('email')


def test_no_duplicate_scrubbers():
    names = _names()
    assert len(names) == len(set(names)), names
