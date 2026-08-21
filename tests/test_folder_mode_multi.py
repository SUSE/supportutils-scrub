"""Folder mode over several directories in ONE run: one pool, one mapping.

A multi-node case used to be scrubbed one capture at a time (one tool run
each, mapping carried over). Running captures concurrently as separate
processes is unsafe: each would allocate fake IPv4/MAC/IPv6 values from the
same pools with no coordination and the last mapping written would win. One
run over all trees keeps the discover/replay coordination and keeps every
worker busy across captures.
"""

import json
import os
from types import SimpleNamespace

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.modes import folder as folder_mode


class _Logger:
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass


def _node(tmp_path, name, ip):
    d = tmp_path / f"scc_{name}_260821"
    d.mkdir()
    (d / "basic-environment.txt").write_text("# /bin/uname -a\nLinux x\n")
    (d / "network.txt").write_text(f"# /etc/hosts\n127.0.0.1 localhost\n{ip} {name}\n# /etc/host.conf\n")
    (d / "messages.txt").write_text(f"peer 198.51.100.77 talked to {ip} twice; {ip}\n")
    return d


def _args(paths, tmp_path, **kw):
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    ns = SimpleNamespace(verbose=False, supportconfig_path=[str(p) for p in paths],
                         mappings=None, keywords=None, keyword_file=None,
                         domain=None, username=None, hostname=None,
                         unpacked=False, no_mappings=False, quiet=True,
                         jobs=2, report=False, report_file=None, profile=False,
                         verify=False, encrypt_mappings=False, secure_tmp=None,
                         config=None, _preloaded_config=cfg, _enc_passphrase=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_two_directories_one_run_one_mapping(tmp_path, capsys):
    a = _node(tmp_path, "nodea", "10.10.1.5")
    b = _node(tmp_path, "nodeb", "10.10.1.6")
    folder_mode.run_folder_mode(_args([a, b], tmp_path), _Logger())
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) >= 2                           # one line per input, in order
    sa, sb = out[-2], out[-1]                      # (node dirs are renamed)
    assert os.path.isdir(sa) and os.path.isdir(sb) and sa != sb
    ma = open(os.path.join(sa, "messages.txt")).read()
    mb = open(os.path.join(sb, "messages.txt")).read()
    assert "198.51.100.77" not in ma and "198.51.100.77" not in mb
    # the shared peer address got ONE fake, the same in both trees
    fake_a = [w for w in ma.split() if w.count(".") == 3][0]
    assert fake_a in mb
    # and nodeb's hostname is known to nodea's tree (learned before scrubbing)
    assert "nodeb" not in ma and "nodea" not in mb
    ds = [f for f in os.listdir(tmp_path / "ds") if f.endswith("_mappings.json")]
    assert len(ds) == 1                            # one mapping for the run
