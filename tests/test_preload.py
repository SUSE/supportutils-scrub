"""--preload: learn every capture's names before any capture is scrubbed.

A case is scrubbed one capture at a time with a shared mapping, so the
first capture is scrubbed knowing only its own names. A peer that only the
second capture names (its hosts file, its cluster records, a loose log)
survives into the first capture's scrubbed output. The preload pass walks
every input, learns hostnames, domains, users, serials and SIDs, writes the
shared mapping, and touches no file. The per-capture scrubs then start with
the complete name set.
"""

import json
import os
import tarfile
from types import SimpleNamespace

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.modes import preload as preload_mode


class _Logger:
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass


def _node(tmp_path, name, hosts, extra=None):
    d = tmp_path / f"scc_{name}_260821"
    d.mkdir()
    (d / "basic-environment.txt").write_text("# /bin/uname -a\nLinux x\n")
    (d / "network.txt").write_text("# /etc/hosts\n127.0.0.1 localhost\n"
                                   + "".join(f"10.0.0.{i} {h}\n" for i, h in
                                             enumerate(hosts, 10))
                                   + "# /etc/host.conf\n")
    for fname, text in (extra or {}).items():
        (d / fname).write_text(text)
    return d


def _args(paths, mapping, tmp_path, **kw):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    ns = SimpleNamespace(verbose=False, supportconfig_path=[str(p) for p in paths],
                         mappings=str(mapping), keywords=None, keyword_file=None,
                         domain=None, username=None, hostname=None, unpacked=False,
                         no_mappings=False, quiet=True, preload=True,
                         _preloaded_config=cfg, _enc_passphrase=None,
                         encrypt_mappings=False, secure_tmp=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _snapshot(root):
    out = {}
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            out[p] = (os.path.getmtime(p), open(p, "rb").read())
    return out


def test_preload_learns_names_from_every_capture_and_touches_nothing(tmp_path):
    a = _node(tmp_path, "nodea", ["nodea"])
    b = _node(tmp_path, "nodeb", ["nodea", "nodeb"],
              {"ha.txt": "  * Online: [ nodea nodeb nodec ]\n"})
    mapping = tmp_path / "shared.json"
    before = _snapshot(tmp_path)

    preload_mode.run_preload_mode(_args([a, b], mapping, tmp_path), _Logger())

    m = json.load(open(mapping))
    assert {"nodea", "nodeb", "nodec"} <= set(m["hostname"])
    assert m.get("det_key")
    assert _snapshot(tmp_path) == before | {str(mapping): _snapshot(tmp_path)[str(mapping)]}


def test_preload_is_idempotent_and_keeps_existing_fakes(tmp_path):
    a = _node(tmp_path, "nodea", ["nodea"])
    mapping = tmp_path / "shared.json"
    preload_mode.run_preload_mode(_args([a], mapping, tmp_path), _Logger())
    first = json.load(open(mapping))
    b = _node(tmp_path, "nodeb", ["nodeb"])
    preload_mode.run_preload_mode(_args([a, b], mapping, tmp_path), _Logger())
    second = json.load(open(mapping))
    assert second["hostname"]["nodea"] == first["hostname"]["nodea"]
    assert second["det_key"] == first["det_key"]
    assert "nodeb" in second["hostname"]


def test_preload_reads_archives_too(tmp_path):
    a = _node(tmp_path, "nodea", ["nodea", "peer-in-archive"])
    arc = tmp_path / "scc_nodea_260821.txz"
    with tarfile.open(arc, "w:xz") as t:
        t.add(a, arcname=a.name)
    mapping = tmp_path / "shared.json"
    preload_mode.run_preload_mode(_args([arc], mapping, tmp_path), _Logger())
    m = json.load(open(mapping))
    assert "peer-in-archive" in m["hostname"]
    assert not [p for p in tmp_path.iterdir() if "scrubbed" in p.name]


def test_preload_reads_loose_files(tmp_path):
    loose = tmp_path / "customer-notes.log"
    loose.write_text("".join(f"2026-08-21T10:00:0{i}+02:00 standalone-host kernel: boot\n"
                            for i in range(3)))   # the syslog extractor wants three lines
    mapping = tmp_path / "shared.json"
    preload_mode.run_preload_mode(_args([loose], mapping, tmp_path), _Logger())
    m = json.load(open(mapping))
    assert "standalone-host" in m["hostname"]
