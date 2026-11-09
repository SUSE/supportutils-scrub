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


# The SAP Diagnostics Agent runs as its own SID with an SMDA<nn> instance; it is
# monitoring infrastructure, so its SID and its <sid>adm user stay as they are.
AGENT_PS = ("daaadm 14123 13988 1.1 /usr/sap/DAA/SMDA98/exe/jstart -appTrc -nodeId=0 "
            "pf=/usr/sap/DAA/SYS/profile/DAA_SMDA98_host1\n"
            "prdadm 4069 1 hdbindexserver -port 30040 /usr/sap/PRD/HDB00\n")


def test_the_diagnostics_agent_and_its_user_are_never_scrubbed():
    s, out = _scrub(AGENT_PS + "SAPDAA_98.service loaded active running\n")
    assert s.sid_dict == {'PRD': 'HA1'}
    assert '/usr/sap/DAA/SMDA98/exe/jstart' in out and 'DAA_SMDA98_host1' in out
    assert 'daaadm' in out and 'SAPDAA_98' in out
    # the system's own SID is still scrubbed
    assert 'prdadm' not in out and 'ha1adm' in out and '/usr/sap/HA1/HDB00' in out


def test_an_agent_seen_in_a_later_file_is_dropped_from_what_was_learned(tmp_path):
    from supportutils_scrub.pipeline import extract_sids
    first = tmp_path / 'systemd.txt'
    first.write_text("SAPDAA_98.service loaded active running\nSAPPRD_00.service\n")
    later = tmp_path / 'open-files.txt'
    later.write_text("jstart 14123 daaadm /usr/sap/DAA/SMDA98/exe/jstart\n")
    assert extract_sids([str(first), str(later)], {}) == {'PRD': 'HA2'}


def test_an_older_mapping_cannot_rename_the_agent():
    s = SIDScrubber(mappings={'sid': {'DAA': 'HA1', 'PRD': 'HA2'}})
    s.pre_scan(AGENT_PS)
    assert s.sid_dict == {'PRD': 'HA2'}
    # and a text scrubbed with the old table alone leaves the agent it shows
    old = SIDScrubber(mappings={'sid': {'DAA': 'HA1', 'PRD': 'HA2'}})
    out = old.scrub(AGENT_PS)
    assert 'daaadm' in out and '/usr/sap/DAA/SMDA98' in out and 'ha2adm' in out
