"""SID scrubber: discover SAP System IDs from strong contexts and substitute them
everywhere, without touching random 3-letter uppercase tokens."""
from supportutils_scrub.sid_scrubber import SIDScrubber


def _scrub(text):
    s = SIDScrubber()
    s.pre_scan(text)
    return s, s.scrub(text)


def test_discovers_from_usr_sap_and_scrubs_all_forms():
    text = (
        "/usr/sap/SEP/SYS/profile\n"
        "SAPSYSTEMNAME=SEP\n"
        "resource rsc_SAP_SEP_D00 monitor\n"
        "profile SEP_D00_host\n"
        "dir /sapmnt/SEP\n"
        "user sepadm home /home/sepadm\n"
        "env SAPSEP_something\n"
        "bare token SEP here\n"
    )
    s, out = _scrub(text)
    assert s.sid_dict == {'SEP': 'HA1'}
    # every SID form is gone
    assert 'SEP' not in out
    assert 'sepadm' not in out
    # and replaced coherently
    assert '/usr/sap/HA1/' in out
    assert 'rsc_SAP_HA1_D00' in out
    assert 'HA1_D00_host' in out
    assert '/sapmnt/HA1' in out
    assert 'ha1adm' in out
    assert 'SAPHA1_something' in out


def test_reserved_words_are_never_treated_as_sid():
    # SAP / SYS / TMP are reserved; a path using them must NOT be scrubbed
    text = "/usr/sap/SYS/exe\n/usr/sap/tmp\nSAPSYSTEMNAME=SAP\n"
    s, out = _scrub(text)
    assert s.sid_dict == {}
    assert out == text


def test_does_not_touch_random_uppercase_tokens():
    # No SAP context anywhere -> nothing discovered, nothing changed
    text = "CPU TCP ABC XYZ load average; the DEV team saw a GID mismatch on RAW disks\n"
    s, out = _scrub(text)
    assert s.sid_dict == {}
    assert out == text


def test_multiple_sids_get_distinct_fakes():
    text = "/usr/sap/SEP/x\n/usr/sap/QAS/y\nrsc_SAP_PRD_D01 up\n"
    s, out = _scrub(text)
    assert set(s.sid_dict) == {'SEP', 'QAS', 'PRD'}
    assert len(set(s.sid_dict.values())) == 3          # all distinct
    for real in ('SEP', 'QAS', 'PRD'):
        assert real not in out


def test_standalone_sid_needs_a_discovery_context_first():
    # A bare 3-letter token with NO strong context is left alone...
    assert _scrub("the SEP value\n")[0].sid_dict == {}
    # ...but once discovered via /usr/sap, every bare occurrence is scrubbed
    s, out = _scrub("/usr/sap/SEP\nlater the SEP value recurs\n")
    assert 'SEP' not in out and out.count('HA1') == 2


def test_sidadm_alone_does_not_invent_a_sid():
    # 'sysadm'/'gradm' style words must not be mistaken for <sid>adm
    text = "sysadm logged in; gradm policy loaded\n"
    s, out = _scrub(text)
    assert s.sid_dict == {}
    assert out == text
