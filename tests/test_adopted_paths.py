"""Collector-adoption bypass: node names carried only by directory structure
must reach hostname_dict (crm_report node dirs, nested scc_ trees, nested
uname lines). Field shape: an adopted node dir kept the real customer FQDN
in its name while sibling content was scrubbed."""

import os

from supportutils_scrub.pipeline import (
    extract_hostnames, extract_hostnames_from_adopted_paths,
    rename_extraction_paths)


def _mk(p, content=""):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(content)


def test_crm_report_node_dir_harvested(tmp_path):
    root = tmp_path / "bundle"
    _mk(str(root / "crm_report" / "node2.customer.example" / "sysinfo.txt"),
        "Platform: Linux\n")
    names = extract_hostnames_from_adopted_paths(str(root))
    assert "node2.customer.example" in names
    assert "node2" in names                       # short form too


def test_nested_scc_dir_and_uname_harvested(tmp_path):
    root = tmp_path / "bundle"
    cap = root / "scc_mlmhost.customer.example_260701_1200"
    _mk(str(cap / "basic-environment.txt"),
        "# /bin/uname -a\nLinux mlmhost.customer.example 5.14.21 #1 SMP x86_64\n")
    names = extract_hostnames_from_adopted_paths(str(root))
    assert "mlmhost.customer.example" in names
    assert "mlmhost" in names


def test_end_to_end_rename_covers_adopted_dir(tmp_path):
    # the exact reported failure: adopted node dir named by real FQDN,
    # absent from any network.txt -> dir must still be renamed
    root = tmp_path / "bundle"
    _mk(str(root / "crm_report" / "node2.customer.example" / "sysinfo.txt"))
    harvested = extract_hostnames_from_adopted_paths(str(root))
    hostname_dict = extract_hostnames([], harvested, {})
    renamed = rename_extraction_paths(str(root), hostname_dict, rename_top=False)
    leftovers = []
    for base, dirs, files in os.walk(renamed):
        for n in dirs + files:
            if "customer.example" in n or "node2" in n:
                leftovers.append(os.path.join(base, n))
    assert not leftovers, leftovers


def test_junk_names_not_harvested(tmp_path):
    root = tmp_path / "bundle"
    # pengine subdir INSIDE a node dir must not be treated as a hostname;
    # marker-less dirs are never harvested
    _mk(str(root / "crm_report" / "node1" / "sysinfo.txt"))
    os.makedirs(str(root / "crm_report" / "node1" / "pengine"))
    _mk(str(root / "some" / "random" / "dir" / "notes.txt"))
    names = extract_hostnames_from_adopted_paths(str(root))
    assert "pengine" not in names
    assert "dir" not in names and "random" not in names
    assert "node1" in names


def test_preserved_product_names_skipped(tmp_path):
    from supportutils_scrub.hostname_scrubber import preserved_hostnames
    pres = sorted(preserved_hostnames())
    if not pres:
        return
    root = tmp_path / "bundle"
    _mk(str(root / "crm_report" / pres[0] / "sysinfo.txt"))
    names = extract_hostnames_from_adopted_paths(str(root))
    assert pres[0] not in names
