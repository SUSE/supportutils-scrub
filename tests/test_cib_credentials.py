"""Fencing credentials inside a cluster configuration.

A cluster's fencing agents authenticate to a hypervisor, a BMC or a cloud
API, and the credentials sit in the configuration as ordinary parameters.
The existing password scrubber matches `passwd=` and `passwd:`; a CIB writes
`name="passwd" value="..."`, which matches neither, so the secret passes
through untouched.

Demonstrated against the deployed scrubber before this was written: a
fence_azure_arm password and its service principal id survived a full run
verbatim. Measured on the corpus, 3 of 21 raw cluster configurations carry
such parameters and one carries an unredacted secret.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from supportutils_scrub.password_scrubber import PasswordScrubber

SECRET = "Qx7~vB2mK9pLd4RtZ0aWcE1sYn6Uf8Hj3Gk5"


def _s():
    return PasswordScrubber(mappings={})


def test_the_cib_parameter_form_is_scrubbed():
    text = ('<nvpair id="a2" name="passwd" value="%s"/>' % SECRET)
    out = _s().scrub(text)
    assert SECRET not in out
    assert "scrubbed_pass_" in out


def test_single_quoted_and_spaced_forms_too():
    for text in ("<nvpair name='password' value='%s'/>" % SECRET,
                 '<nvpair name = "passwd"  value = "%s" />' % SECRET):
        assert SECRET not in _s().scrub(text), text


def test_the_configure_show_form_is_scrubbed():
    """crm configure show writes the same parameters as key=value pairs."""
    text = 'params ipaddr=10.0.0.5 login=app passwd="%s" ssl=1' % SECRET
    assert SECRET not in _s().scrub(text)


def test_symbols_in_a_secret_do_not_save_it():
    """The old value pattern accepted only letters, digits, + and /, so a
    secret with a tilde or a dot was only partly matched."""
    text = 'passwd=%s' % SECRET
    out = _s().scrub(text)
    assert SECRET not in out and "vB2mK9pLd4RtZ0" not in out


def test_other_parameters_are_left_alone():
    """Over-scrubbing a configuration makes it unreadable; only the
    credential-bearing names are touched."""
    text = ('<nvpair name="resourceGroup" value="rg-prod-01"/>'
            '<nvpair name="pcmk_host_list" value="node1 node2"/>')
    assert _s().scrub(text) == text


def test_an_already_scrubbed_value_is_not_scrubbed_twice():
    text = '<nvpair name="passwd" value="scrubbed_pass_1"/>'
    assert _s().scrub(text) == text


def test_the_same_secret_maps_consistently():
    s = _s()
    a = s.scrub('passwd="%s"' % SECRET)
    b = s.scrub('<nvpair name="passwd" value="%s"/>' % SECRET)
    tok_a = a.split('"')[1]
    assert tok_a in b
