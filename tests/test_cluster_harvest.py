"""Cluster membership is a hostname source.

Hostnames are learned from a node's own identity files: /etc/hosts and the
hostname section of network.txt. A clustered system therefore leaks its
PEERS: a cluster member that was never captured appears in no captured
node's hosts file, so it is never learned, and its real name survives into
the scrubbed output wherever the captured nodes' cluster configuration
mentions it.

Measured on a real corpus before this was written: of 56 drawable cluster
views in scrub-mode cases, 24 carried at least one unreplaced name. On one
case the mapping held 11 names while two cluster members, present only in
the other nodes' configuration, were absent from it entirely.

The cluster states its own membership in several places, and those are the
sources this adds.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from supportutils_scrub.hostname_scrubber import HostnameScrubber as H

HA_TXT = """#==[ Command ]======================================#
# /usr/sbin/crm_mon -A -1
Cluster Summary:
  * Stack: corosync
  * Current DC: acweulx1696 (version 2.1.5) - partition with quorum

Node List:
  * Node acweulx1696: online
  * Node acweulx1705: online
  * Node acweulx1723: standby

#==[ Command ]======================================#
# /usr/sbin/cibadmin -Q
<cib crm_feature_set="3.16.1" update-origin="acweulx1696">
  <configuration>
    <nodes>
      <node id="1" uname="acweulx1696"/>
      <node id="2" uname="acweulx1705"/>
      <node id="3" uname="acweulx1723"/>
    </nodes>
  </configuration>
</cib>

#==[ Configuration File ]===========================#
# /etc/corosync/corosync.conf
nodelist {
    node {
        ring0_addr: acweulx1696
        nodeid: 1
    }
    node {
        ring0_addr: acweulx1705
        nodeid: 2
    }
}
"""


def _w(tmp, text, name="ha.txt"):
    p = os.path.join(tmp, name)
    with open(p, "w") as fh:
        fh.write(text)
    return p


def test_every_cluster_member_is_learned(tmp_path):
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), HA_TXT)))
    assert {"acweulx1696", "acweulx1705", "acweulx1723"} <= got


def test_a_peer_named_only_in_the_configuration_is_learned(tmp_path):
    """The exact shape of the leak: the capturing node is in its own hosts
    file, the other two are not, and only the cluster config names them."""
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), HA_TXT)))
    assert "acweulx1705" in got and "acweulx1723" in got


def test_the_online_bracket_form_is_read(tmp_path):
    text = ("Online: [ nodealpha nodebeta ]\n"
            "OFFLINE: [ nodegamma ]\n")
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert got == {"nodealpha", "nodebeta", "nodegamma"}


def test_short_names_are_returned_like_the_other_extractors(tmp_path):
    text = '<node id="1" uname="nodealpha.example.com"/>\n'
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert "nodealpha" in got
    assert "nodealpha.example.com" not in got


def test_well_known_names_are_never_harvested(tmp_path):
    """The same exclusion set the other extractors use, not a second opinion
    about what counts as a real host."""
    text = "Online: [ localhost ip6-localhost ]\n"
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert got == set()


def test_addresses_and_ids_are_not_mistaken_for_names(tmp_path):
    """ring0_addr is often an address, and a resource id is not a host."""
    text = ("nodelist {\n  node {\n    ring0_addr: 10.0.0.5\n"
            "    nodeid: 1\n  }\n}\n"
            "primitive rsc_ip_HDB ocf:heartbeat:IPaddr2\n"
            "  params ip=10.0.0.9\n")
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert got == set()


def test_a_name_outside_a_nodelist_block_is_not_taken(tmp_path):
    """`name:` appears all over a cluster configuration; only the one inside
    the corosync nodelist identifies a host."""
    text = ("totem {\n  cluster_name: production\n}\n"
            "nodelist {\n  node {\n    name: nodealpha\n  }\n}\n")
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert got == {"nodealpha"}


def test_an_unreadable_file_yields_nothing(tmp_path):
    assert H.extract_hostnames_from_cluster(
        os.path.join(str(tmp_path), "absent.txt")) == []


# ---- shapes taken from a real capture, which the first draft got wrong ----

REAL_SHAPE = """Cluster Summary:
  * Current DC: peerhosta (version 2.1.7) - partition with quorum

Node List:
  * Node peerhostb: online:
  * Node peerhostc: online:

Node Attributes:
  * Node: peerhostb:

  * Online: [ peerhostb peerhostc peerhosta ]
  * OFFLINE: [ peerhostd ]
"""


def test_the_status_headings_are_not_hostnames(tmp_path):
    """Found on a real capture: crm_mon prints "Node List:" and "Node
    Attributes:" as section headings, and a pattern reading "Node <word>:"
    harvested List and Attributes as if they were hosts. Replacing those two
    words throughout a capture would have been worse than the leak."""
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), REAL_SHAPE)))
    assert "List" not in got and "Attributes" not in got


def test_the_bulleted_membership_line_is_read(tmp_path):
    """The bracket form carries a bullet in real output; the first draft
    anchored at the start of the line and matched none of them."""
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), REAL_SHAPE)))
    assert {"peerhosta", "peerhostb", "peerhostc", "peerhostd"} <= got


def test_the_parenthesised_node_form_still_works(tmp_path):
    text = "Node peerhosta (1): online\n"
    got = set(H.extract_hostnames_from_cluster(_w(str(tmp_path), text)))
    assert got == {"peerhosta"}
