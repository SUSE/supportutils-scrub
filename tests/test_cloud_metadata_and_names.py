"""A name is renamed by exactly what rewrites the text, and the cloud
metadata alias is not a hostname.

The field case: a public-cloud supportconfig came back without
public_cloud/metadata.txt. The file was there, renamed to hostname_0.txt,
because /etc/hosts on a cloud instance carries

    169.254.169.254 metadata.google.internal metadata

and the bare alias was harvested as a hostname. Nothing in the output said a
rename had happened, so the file read as missing.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.pipeline import (extract_hostnames,
                                         rename_extraction_paths, scrub_name)


class _Cfg:
    """The one field preserved_hostnames() reads."""

    def __init__(self, preserve=""):
        self.hostname_preserve = preserve


def _hosts_file(tmp_path, body):
    p = tmp_path / "network.txt"
    p.write_text("# /etc/hosts\n" + body + "\n# /etc/host.conf\n")
    return str(p)


# ---- the alias is not a hostname ------------------------------------------

def test_the_cloud_metadata_alias_is_never_learned(tmp_path):
    f = _hosts_file(tmp_path, "169.254.169.254 metadata.google.internal metadata\n"
                              "10.0.0.11 avt-cb-ugd001.example.internal avt-cb-ugd001")
    names = HostnameScrubber.extract_hostnames_from_hosts(f)
    assert "metadata" not in names
    assert "avt-cb-ugd001" in names


def test_the_alias_is_not_learned_whatever_its_case(tmp_path):
    f = _hosts_file(tmp_path, "169.254.169.254 Metadata.Google.Internal Metadata")
    assert HostnameScrubber.extract_hostnames_from_hosts(f) == []


def test_every_name_on_the_metadata_address_line_is_left_alone(tmp_path):
    """The address serves one thing, so nothing on its line names a host."""
    f = _hosts_file(tmp_path, "169.254.169.254 metadata.google.internal computeMetadata")
    assert HostnameScrubber.extract_hostnames_from_hosts(f) == []


def test_a_customer_host_that_merely_starts_with_metadata_is_still_scrubbed(tmp_path):
    """The alias goes in the never-learned set, NOT in the set that builds the
    corruption mask: a mask entry would protect the first eight characters of
    metadata-01 and leak the host."""
    f = _hosts_file(tmp_path, "10.0.0.12 metadata-01.example.internal metadata-01")
    names = HostnameScrubber.extract_hostnames_from_hosts(f)
    assert "metadata-01" in names
    scrubbed = HostnameScrubber({"metadata-01": "hostname_3"}).scrub(
        "metadata-01 went down")
    assert scrubbed == "hostname_3 went down"
    assert scrub_name("metadata-01.log", {"metadata-01": "hostname_3"}) == \
        "hostname_3.log"


def test_a_stale_mapping_file_cannot_bring_the_alias_back(tmp_path):
    f = _hosts_file(tmp_path, "10.0.0.11 host-a")
    mappings = {"hostname": {"metadata": "hostname_0", "host-a": "hostname_1"}}
    out = extract_hostnames([f], [], mappings)
    assert "metadata" not in out
    assert out["host-a"] == "hostname_1"


def test_seeding_the_alias_by_hand_does_not_map_it(tmp_path):
    """--hostname metadata reaches the same merge loop the harvest does."""
    out = extract_hostnames([], ["metadata", "realhost"], {"hostname": {}})
    assert "metadata" not in out
    assert "realhost" in out


# ---- a name gets exactly the rules the text gets ---------------------------

def test_a_short_hostname_no_longer_eats_a_product_file_name():
    """Plain str.replace turned network.txt into nethostname_9.txt for a host
    called work, because it had no word boundaries. The text scrubber never
    did that, and now the rename uses the text scrubber."""
    hd = {"work": "hostname_9"}
    assert scrub_name("network.txt", hd) == "network.txt"
    assert scrub_name("messages.txt", {"mess": "hostname_9"}) == "messages.txt"
    assert scrub_name("work.txt", hd) == "hostname_9.txt"


def test_a_name_in_another_case_is_renamed_like_the_text_is():
    """MYHOST_logs kept a name the file contents no longer used."""
    assert scrub_name("MYHOST_logs", {"myhost": "hostname_2"}) == "hostname_2_logs"


def test_a_domain_is_not_matched_inside_a_longer_label():
    assert scrub_name("notexample.com.txt", {}, domain_dict={"example.com": "domain_0.aaa"}) \
        == "notexample.com.txt"


def test_the_preserve_list_from_the_config_reaches_the_rename(tmp_path):
    """hostname_preserve promised 'never obfuscated'. It was honoured in the
    parallel path only, so in a default run it renamed the file anyway."""
    cfg = _Cfg("buildhost")
    tree = tmp_path / "sc"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "buildhost.txt").write_text("x")
    hd = extract_hostnames([], ["buildhost", "realhost"], {"hostname": {}},
                           config=cfg)
    assert "buildhost" not in hd
    renames = []
    rename_extraction_paths(str(tree), {"buildhost": "hostname_5"},
                            rename_top=False, config=cfg, renames=renames)
    assert renames == []
    assert (tree / "sub" / "buildhost.txt").exists()


# ---- what happened is reported --------------------------------------------

def test_a_rename_is_reported_with_both_names(tmp_path):
    tree = tmp_path / "sc"
    (tree / "public_cloud").mkdir(parents=True)
    (tree / "public_cloud" / "myhost-notes.txt").write_text("x")
    renames = []
    rename_extraction_paths(str(tree), {"myhost": "hostname_0"},
                            rename_top=False, renames=renames)
    assert renames == [(os.path.join("public_cloud", "myhost-notes.txt"),
                        os.path.join("public_cloud", "hostname_0-notes.txt"))]


# ---- the tree keeps its shape ---------------------------------------------

def test_an_empty_directory_survives_the_round_trip(tmp_path):
    import tarfile
    from supportutils_scrub.extractor import extract_supportconfig

    src = tmp_path / "scc_host_260915_1447"
    (src / "public_cloud" / "regcache").mkdir(parents=True)
    (src / "public_cloud" / "metadata.txt").write_text("x\n")
    (src / "basic-environment.txt").write_text("# /bin/hostname\nhost\n")
    archive = tmp_path / "scc_host_260915_1447.txz"
    with tarfile.open(archive, "w:xz") as tar:
        tar.add(str(src), arcname=src.name)

    import logging
    files = extract_supportconfig(str(archive), logging.getLogger(__name__))
    assert files, "nothing extracted"
    root = str(tmp_path / (src.name + "_scrubbed"))
    assert os.path.isdir(os.path.join(root, "public_cloud", "regcache"))
    assert os.path.isfile(os.path.join(root, "public_cloud", "metadata.txt"))
    # the wrapper names the output folder; recreating it as a member would
    # leave an empty scc_host_date/ sitting inside that folder
    assert not os.path.exists(os.path.join(root, src.name))
