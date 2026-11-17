"""Orchestration across modes: one chain, one mapping, nothing raw shipped."""

import json
import logging
import os
from types import SimpleNamespace

import pytest

from supportutils_scrub import det, parallel, pipeline
from supportutils_scrub.modes import archive as archive_mode
from supportutils_scrub.modes import file as file_mode
from supportutils_scrub.modes import folder as folder_mode
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.scrub_config import ScrubConfig

from test_parallel_scheduling import _Inline


class _Logger:
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass


def _args(paths, tmp_path, **kw):
    cfg = kw.pop('cfg', None) or ScrubConfig(
        obfuscate_private_ip=True, obfuscate_public_ip=True,
        dataset_dir=str(tmp_path / "ds"), use_key_words_file=False)
    ns = SimpleNamespace(
        verbose=False, supportconfig_path=[str(p) for p in paths], mappings=None,
        keywords=None, keyword_file=None, domain=None, username=None,
        hostname=None, unpacked=False, no_mappings=False, quiet=False, jobs=1,
        report=False, report_file=None, profile=False, verify=False,
        rewrite_pcap=False, output_dir=None, secure_tmp=None, config=None,
        _preloaded_config=cfg, _enc_passphrase=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _saved_mapping(tmp_path):
    ds = tmp_path / "ds"
    [name] = [n for n in os.listdir(ds) if n.endswith("_mappings.json")]
    return json.loads((ds / name).read_text())


def _mappings_file(tmp_path, data):
    p = tmp_path / "in_mappings.json"
    p.write_text(json.dumps(data))
    return str(p)


def test_jobs_run_keys_its_fakes_and_saves_the_key(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    parallel._CTX.clear()
    src = tmp_path / "logs"
    src.mkdir()
    (src / "a.txt").write_text("password=Hunter2Example\n")
    (src / "b.txt").write_text("nothing\n")
    det.set_key(None)
    archive_mode.run_archive_mode([str(src)], _args([src], tmp_path, jobs=2),
                                  _Logger())
    parallel._CTX.clear()
    key = _saved_mapping(tmp_path).get(det.KEY_FIELD)
    assert key and key == det.current_key()
    det.set_key(None)


def test_parallel_merge_keeps_det_key_and_loaded_cursors(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    f = tmp_path / "x.txt"
    f.write_text("nothing here\n")
    seed = {det.KEY_FIELD: "00" * 16, 'state': {'ipv6_pool_cursor': 7}}
    det.ensure_key(seed)
    merged, _h, _t = parallel.scrub_in_parallel(
        [str(f)], seed, ScrubConfig(), 2, logging.getLogger("t"))
    det.set_key(None)
    assert merged[det.KEY_FIELD] == "00" * 16
    assert merged['state']['ipv6_pool_cursor'] == 7


def test_a_file_that_could_not_be_scrubbed_is_removed_and_exit_is_2(tmp_path, monkeypatch):
    src = tmp_path / "logs"
    src.mkdir()
    (src / "good.txt").write_text("client 8.8.8.8\n")
    (src / "bad.txt").write_text("client 8.8.4.4\n")
    real = FileProcessor.process_file

    def flaky(self, path, *a, **kw):
        return False if path.endswith("bad.txt") else real(self, path, *a, **kw)
    monkeypatch.setattr(FileProcessor, "process_file", flaky)

    with pytest.raises(SystemExit) as e:
        folder_mode.run_folder_mode(_args([src], tmp_path), _Logger())
    assert e.value.code == 2
    out = tmp_path / "logs_scrubbed"
    assert (out / "good.txt").exists() and not (out / "bad.txt").exists()
    assert (src / "bad.txt").exists()


def test_parallel_reports_files_it_could_not_scrub(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    monkeypatch.setattr(FileProcessor, "process_file", lambda *a, **kw: False)
    parallel._CTX.clear()
    f = tmp_path / "x.txt"
    f.write_text("client 8.8.8.8\n")
    failed = []
    parallel.scrub_in_parallel([str(f)], {}, ScrubConfig(), 2,
                               logging.getLogger("t"), failed=failed)
    parallel._CTX.clear()
    assert failed == [str(f)]


def test_chunked_file_keeps_crlf_and_non_utf8_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    monkeypatch.setattr(parallel, "_CHUNK_THRESHOLD", 1024)
    monkeypatch.setattr(parallel, "_CHUNK_MIN", 512)
    parallel._CTX.clear()
    f = tmp_path / "big.log"
    f.write_bytes(b"caf\xe9 client 8.8.8.8 ok\r\n" * 200)
    cfg = ScrubConfig(obfuscate_public_ip=True)
    parallel.scrub_in_parallel([str(f)], {}, cfg, 2, logging.getLogger("t"))
    parallel._CTX.clear()
    body = f.read_bytes()
    assert b"8.8.8.8" not in body
    assert body.count(b"caf\xe9 client ") == 200 and body.count(b"\r\n") == 200


def test_loose_files_in_one_run_learn_names_and_take_seeds(tmp_path):
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("mounted nfssrv7.example.com:/export on webnode9\n")
    b.write_text("webnode9 restarted\n")
    archive_mode.run_archive_mode([str(a), str(b)],
                                  _args([a, b], tmp_path, hostname="webnode9"), _Logger())
    for out in ("a_scrubbed.log", "b_scrubbed.log"):
        body = (tmp_path / out).read_text()
        assert "webnode9" not in body and "nfssrv7" not in body


def test_file_mode_honours_output_dir(tmp_path):
    f = tmp_path / "notes.log"
    f.write_text("client 8.8.8.8\n")
    out = tmp_path / "out"
    file_mode.run_file_mode(_args([f], tmp_path, output_dir=str(out)), _Logger())
    assert (out / "notes_scrubbed.log").exists()
    assert not (tmp_path / "notes_scrubbed.log").exists()


def test_binary_lone_file_is_refused_before_any_copy(tmp_path):
    f = tmp_path / "blob.dat"
    f.write_bytes(b"\x00\x01 8.8.8.8 \x00")
    with pytest.raises(SystemExit) as e:
        file_mode.run_file_mode(_args([f], tmp_path), _Logger())
    assert e.value.code == 1
    assert not (tmp_path / "blob_scrubbed.dat").exists()


def test_plain_folder_learns_cluster_members_and_applies_mapping_serials(tmp_path):
    src = tmp_path / "report"
    (src / "nodea").mkdir(parents=True)
    (src / "nodea" / "cib.xml").write_text('<node id="1" uname="peernode4"/>\n')
    (src / "nodea" / "ha-log.txt").write_text(
        "peernode4 joined; board serial ABCD1234EFGH\n")
    mp = _mappings_file(tmp_path, {'serial': {'ABCD1234EFGH': 'SERIAL_9'}})
    folder_mode.run_folder_mode(_args([src], tmp_path, mappings=mp), _Logger())
    [out] = [p for p in tmp_path.iterdir() if p.name.endswith("_scrubbed")]
    body = "".join(p.read_text() for p in out.rglob("ha-log.txt"))
    assert "peernode4" not in body and "ABCD1234EFGH" not in body
    assert _saved_mapping(tmp_path)['serial'] == {'ABCD1234EFGH': 'SERIAL_9'}


def test_loaded_keywords_keep_their_pseudonyms(tmp_path):
    mp = _mappings_file(tmp_path, {'keyword': {'projzeta': 'keyword_7'}})
    args = _args([], tmp_path, mappings=mp, keywords="projalpha")
    _m, kw, *_ = pipeline.init_scrubbers(args, args._preloaded_config, _Logger())
    assert kw.keyword_dict == {'projzeta': 'keyword_7', 'projalpha': 'keyword_2'}


def test_config_keyword_file_is_used(tmp_path):
    kwf = tmp_path / "kw.txt"
    kwf.write_text("projomega\n")
    cfg = ScrubConfig(use_key_words_file=True, key_words_file=str(kwf))
    args = _args([], tmp_path, cfg=cfg)
    _m, kw, *_ = pipeline.init_scrubbers(args, cfg, _Logger())
    assert 'projomega' in kw.keyword_dict


def test_obfuscate_serial_no_drops_the_serial_scrubber():
    names = [s.name for s in pipeline.build_chain({}, ScrubConfig(obfuscate_serial=False))]
    assert 'serial' not in names and 'sid' in names


def test_case_twins_renamed_to_one_hostname_both_survive(tmp_path):
    (tmp_path / "testhost.log").write_text("lower\n")
    (tmp_path / "TESTHOST.log").write_text("upper\n")
    pipeline.rename_extraction_paths(str(tmp_path), {"testhost": "host-1"}, rename_top=False)
    bodies = sorted(p.read_text() for p in tmp_path.iterdir())
    assert bodies == ["lower\n", "upper\n"]
    assert "host-1.log" in os.listdir(tmp_path)


def test_saved_state_keeps_loaded_cursors_when_nothing_was_allocated():
    loaded = {'state': {'pool_cursor_public': 5, 'ipv6_pool_cursor': 3}}
    chain = pipeline.build_chain(loaded, ScrubConfig())
    state = pipeline.chain_mappings(chain, loaded)['state']
    assert state['pool_cursor_public'] == 5 and state['ipv6_pool_cursor'] == 3


_PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20


def _stub_tcprewrite(tmp_path):
    # writes its own arguments as the "rewritten" capture
    stub = tmp_path / "bin" / "tcprewrite"
    stub.parent.mkdir()
    stub.write_text('#!/bin/sh\nfor a; do case "$prev" in -o) out=$a;; esac; prev=$a; done\n'
                    'echo "$@" > "$out"\n')
    stub.chmod(0o755)
    return str(stub)


def _pcap_case(tmp_path):
    cap, log = tmp_path / "network.cap", tmp_path / "a.log"
    cap.write_bytes(_PCAP)
    log.write_text("peer 198.51.100.7/24 up\n")
    return cap, log


def test_pcap_next_to_text_is_rewritten_with_the_final_mapping(tmp_path):
    cap, log = _pcap_case(tmp_path)
    args = _args([cap, log], tmp_path, tcprewrite_path=_stub_tcprewrite(tmp_path),
                 print_tcprewrite=False)
    archive_mode.run_archive_mode([str(cap), str(log)], args, _Logger())
    out = (tmp_path / "network_scrubbed.cap").read_text()
    assert "198.51.100.0/24:" in out and str(cap) in out


def test_pcap_without_tcprewrite_ships_nothing_and_exits_2(tmp_path):
    cap, log = _pcap_case(tmp_path)
    args = _args([cap, log], tmp_path, tcprewrite_path=str(tmp_path / "no-such-tool"),
                 print_tcprewrite=False)
    with pytest.raises(SystemExit) as e:
        archive_mode.run_archive_mode([str(cap), str(log)], args, _Logger())
    assert e.value.code == 2
    assert not (tmp_path / "network_scrubbed.cap").exists()


def test_interrupt_never_removes_an_input_scrubbed_in_place(tmp_path, monkeypatch):
    mine, other = tmp_path / "mine_scrubbed", tmp_path / "other"
    for d in (mine, other):
        d.mkdir()
        (d / "x.txt").write_text("client 8.8.8.8\n")
    handlers = []
    monkeypatch.setattr(folder_mode.signal, "signal", lambda sig, h: handlers.append(h))
    monkeypatch.setattr(folder_mode.os, "_exit", lambda code: None)
    folder_mode.run_folder_mode(_args([mine, other], tmp_path), _Logger())
    handlers[-1](2, None)
    assert (mine / "x.txt").exists()
    assert not (tmp_path / "other_scrubbed").exists()
