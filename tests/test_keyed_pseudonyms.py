"""Pseudonyms in parallel mode are a KEYED hash of the real value.

Unkeyed, anyone holding scrubbed output could enumerate candidates (an
IPv4 is 2^32, hostnames are a dictionary), hash them, and read the mapping
back. The key is generated per fresh run, stored in the mapping file (mode
0600) so a --mappings resume reproduces the same fakes, and never appears in
any output. A legacy mapping without a key keeps its unkeyed fakes, so the
cases already scrubbed with it stay consistent on re-sync.
"""

import os
import sys

from supportutils_scrub import det
from supportutils_scrub import audit


def setup_function(_):
    det.set_key(None)


def test_a_key_changes_the_digest_and_is_stable():
    plain = det.dhash("hana-prod-01")
    det.set_key("00" * 16)
    keyed = det.dhash("hana-prod-01")
    assert keyed != plain
    assert det.dhash("hana-prod-01") == keyed


def test_a_fresh_mapping_gets_a_key():
    m = {}
    det.ensure_key(m)
    assert len(m["det_key"]) == 32 and m["det_key"] != "00" * 16
    assert det.current_key() == m["det_key"]


def test_a_resumed_mapping_reuses_its_key():
    m = {"det_key": "ab" * 16, "hostname": {"x": "hostname_1"}}
    det.ensure_key(m)
    assert det.current_key() == "ab" * 16


def test_a_legacy_mapping_without_a_key_stays_unkeyed():
    m = {"hostname": {"x": "hostname_1"}}          # written before keys
    det.ensure_key(m)
    assert det.current_key() is None
    assert "det_key" not in m


def test_audit_redacts_seeded_values_from_the_argv_record(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["supportutils-scrub", "--hostname",
                                      "hana-prod-01,hana-prod-02", "--keywords",
                                      "AcmeCorp", "--jobs", "4", "case.txz"])
    import types
    rec = audit.audit_record("archive", [], [], None, types.SimpleNamespace(),
                             "t")
    args = " ".join(rec["cli_args"])
    assert "hana-prod-01" not in args and "AcmeCorp" not in args
    assert "--jobs 4" in args and "case.txz" in args
