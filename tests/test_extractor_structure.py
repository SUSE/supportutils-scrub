# Directory-structure preservation on archive extraction.
#
# Regression: extraction assumed the FIRST member's first path component was
# a single wrapper folder and basename-flattened every member that did not
# match it. A multi-root archive (a debug bundle packed without a wrapper:
# spacewalk-debug/..., conf/..., logs) lost its whole directory tree, which
# broke every consumer that navigates by path. The rules under test:
#
#   1. single common wrapper       -> stripped (classic supportconfig shape)
#   2. multiple top-level roots    -> every path preserved verbatim
#   3. file at the archive root    -> nothing stripped at all
#   4. unsafe members              -> still blocked

import os
import tarfile

from supportutils_scrub.extractor import (_common_top_level,
                                          _member_relative_path,
                                          extract_tgz_archive)


class _FakeMember:
    def __init__(self, name, isdir=False):
        self.name = name
        self._isdir = isdir

    def isdir(self):
        return self._isdir


def test_common_top_single_wrapper():
    members = [_FakeMember("scc_host_260101/", isdir=True),
               _FakeMember("scc_host_260101/basic-environment.txt"),
               _FakeMember("scc_host_260101/etc/hosts")]
    assert _common_top_level(members) == "scc_host_260101"


def test_common_top_multi_root_is_none():
    members = [_FakeMember("spacewalk-debug/rhn-logs/rhn/x.log"),
               _FakeMember("conf/rhn.conf")]
    assert _common_top_level(members) is None


def test_common_top_root_file_is_none():
    members = [_FakeMember("scc_host_260101/etc/hosts"),
               _FakeMember("README")]                    # file at root
    assert _common_top_level(members) is None


def test_member_relative_path_never_flattens():
    m = _FakeMember("spacewalk-debug/rhn-logs/rhn/rhn_taskomatic_daemon.log")
    assert _member_relative_path(m, None) == m.name       # preserved verbatim
    assert _member_relative_path(m, "spacewalk-debug") == \
        "rhn-logs/rhn/rhn_taskomatic_daemon.log"          # wrapper stripped


def _make_archive(tmp_path, layout, name="bundle.tgz"):
    src = tmp_path / "src"
    for rel in layout:
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("payload for " + rel)
    arc = tmp_path / name
    with tarfile.open(arc, "w:gz") as tar:
        for rel in layout:
            tar.add(src / rel, arcname=rel)
    return str(arc)


def test_extract_multiroot_preserves_tree(tmp_path):
    arc = _make_archive(tmp_path, [
        "spacewalk-debug/rhn-logs/rhn/rhn_taskomatic_daemon.log",
        "spacewalk-debug/httpd-logs/access_log",
        "conf/rhn.conf",
    ])
    files = extract_tgz_archive(arc, logger=None, mode="r:gz")
    flat = files[0] if files and isinstance(files[0], list) else files
    rels = sorted(os.path.relpath(f, os.path.dirname(arc)) for f in flat)
    assert rels == [
        "bundle_scrubbed/conf/rhn.conf",
        "bundle_scrubbed/spacewalk-debug/httpd-logs/access_log",
        "bundle_scrubbed/spacewalk-debug/rhn-logs/rhn/rhn_taskomatic_daemon.log",
    ]


def test_extract_wrapped_still_strips_wrapper(tmp_path):
    src = tmp_path / "src" / "scc_host_260101"
    (src / "etc").mkdir(parents=True)
    (src / "basic-environment.txt").write_text("x")
    (src / "etc" / "hosts").write_text("y")
    arc = tmp_path / "scc_host_260101.tgz"
    with tarfile.open(arc, "w:gz") as tar:
        tar.add(src, arcname="scc_host_260101")
    files = extract_tgz_archive(str(arc), logger=None, mode="r:gz")
    flat = files[0] if files and isinstance(files[0], list) else files
    rels = sorted(os.path.relpath(f, tmp_path) for f in flat)
    assert rels == [
        "scc_host_260101_scrubbed/basic-environment.txt",
        "scc_host_260101_scrubbed/etc/hosts",
    ]


def test_extract_blocks_traversal(tmp_path):
    arc = tmp_path / "evil.tgz"
    inside = tmp_path / "inside.txt"
    inside.write_text("ok")
    with tarfile.open(arc, "w:gz") as tar:
        tar.add(inside, arcname="good/inside.txt")
        tar.add(inside, arcname="good/../../escape.txt")
    files = extract_tgz_archive(str(arc), logger=None, mode="r:gz")
    flat = files[0] if files and isinstance(files[0], list) else files
    assert not (tmp_path.parent / "escape.txt").exists()
    assert any(f.endswith("inside.txt") for f in flat)
