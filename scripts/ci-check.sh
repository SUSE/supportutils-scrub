#!/bin/bash
# One check of the tree it is run from, the same on a laptop, in a container
# and in the pipeline: build the RPM as the spec describes it, install it, scrub
# a small made-up capture with the installed tool and look for what must be
# gone, then run the unit tests with the system Python.
#
#   scripts/ci-check.sh            everything
#   scripts/ci-check.sh --no-rpm   tests and the scrub from the tree (no root needed)
#
# Needs: python3, tar, gzip; for the RPM part rpm-build and root. pytest is
# taken from the system when it is there, otherwise installed into a
# throw-away virtual environment.
set -u
cd "$(dirname "$0")/.."
RPM=1; [ "${1:-}" = "--no-rpm" ] && RPM=0
FAIL=0
say()  { printf '%s\n' "== $*"; }
bad()  { printf '%s\n' "FAILED: $*"; FAIL=1; }
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

[ -r /etc/os-release ] && . /etc/os-release
say "${PRETTY_NAME:-unknown system}, $(python3 --version 2>&1)"
VERSION=$(sed -n 's/^Version:[[:space:]]*//p' specs/supportutils-scrub.spec)
grep -q "SCRIPT_VERSION = \"$VERSION\"" src/supportutils_scrub/main.py \
    || bad "spec says $VERSION, main.py says something else"
head -4 specs/supportutils-scrub.changes | grep -q "Update to version $VERSION" \
    || bad "the newest changes entry is not for $VERSION"

TOOL="python3 $PWD/bin/supportutils-scrub"
if [ "$RPM" = 1 ]; then
    TOP=$(rpm --eval %_topdir)
    mkdir -p "$TOP/SOURCES"
    tar czf "$TOP/SOURCES/supportutils-scrub-$VERSION.tar.gz" --exclude=.git \
        --transform "s,^\.,supportutils-scrub-$VERSION," .
    if rpmbuild -bb specs/supportutils-scrub.spec > "$WORK/rpmbuild.log" 2>&1; then
        say "rpmbuild ok"
    else
        tail -15 "$WORK/rpmbuild.log"; bad "rpmbuild"
    fi
    rpm -e supportutils-scrub > /dev/null 2>&1
    rpm -i "$TOP"/RPMS/noarch/supportutils-scrub-"$VERSION"-*.rpm || bad "rpm install"
    say "installed $(rpm -q supportutils-scrub); requires: $(rpm -qR supportutils-scrub | grep -v rpmlib | tr '\n' ' ')"
    TOOL=supportutils-scrub
fi

# --- a made-up capture: every value below must be gone from the output ------
C="$WORK/scc_node1_260101_1200"; mkdir -p "$C"
cat > "$C/basic-environment.txt" <<'EOT'
#==[ Command ]======================================#
# /bin/hostname -f
node1.corp.example-ci.com
EOT
cat > "$C/network.txt" <<'EOT'
#==[ Configuration File ]===========================#
# /etc/hosts
203.0.113.10 node1.corp.example-ci.com node1
203.0.113.11 node2.corp.example-ci.com node2
#==[ Command ]======================================#
# /sbin/ip addr
    link/ether 52:54:00:ab:cd:ef brd ff:ff:ff:ff:ff:ff
    inet 203.0.113.10/24 scope global eth0
    inet6 2001:db8:77::10/64 scope global
EOT
cat > "$C/pam.txt" <<'EOT'
#==[ Configuration File ]===========================#
# /etc/passwd
root:x:0:0:root:/root:/bin/bash
ciuser:x:1000:100:CI User:/home/ciuser:/bin/bash
EOT
cat > "$C/messages.txt" <<'EOT'
#==[ Log File ]=====================================#
# /var/log/messages
2026-01-01T12:00:00.123456+01:00 node1 sshd[1]: Accepted publickey for ciuser from 203.0.113.99 port 22
2026-01-01T12:00:01.123456+01:00 node1 app[2]: mail to ciuser@example-ci.com password=Secret123x
2026-01-01T12:00:02.123456+01:00 node1 pacemaker: rsc_SAPHana_CI9_HDB00 on node2 /usr/sap/CI9/HDB00
EOT
# a SID is learned from the SAP and cluster files and then replaced everywhere
cat > "$C/ha.txt" <<'EOT'
#==[ Command ]======================================#
# /usr/sbin/crm configure show
primitive rsc_SAPHana_CI9_HDB00 ocf:suse:SAPHana params SID=CI9 InstanceNumber=00
EOT
tar cJf "$WORK/scc_node1_260101_1200.txz" -C "$WORK" scc_node1_260101_1200
SECRETS='node1|node2|example-ci|203\.0\.113\.|52:54:00:ab:cd:ef|2001:db8:77|ciuser|Secret123x|CI9'

run_scrub() {   # <label> <args...>: scrub the archive in a fresh folder, then look for leftovers
    label=$1; shift
    d="$WORK/run_$label"; mkdir -p "$d"; cp "$WORK/scc_node1_260101_1200.txz" "$d/"
    ( cd "$d" && $TOOL --quiet "$@" scc_node1_260101_1200.txz > out.log 2> err.log )
    rc=$?
    [ "$rc" = 0 ] || { tail -5 "$d/err.log"; bad "scrub ($label) exit $rc"; return; }
    left=$(cd "$d" && find . -mindepth 1 -maxdepth 1 ! -name 'scc_node1_260101_1200.txz' ! -name '*.log' \
           -exec sh -c 'for p; do if [ -d "$p" ]; then grep -rlE "$0" "$p"; else tar xJf "$p" -O 2>/dev/null | grep -cE "$0" | grep -v "^0$"; fi; done' "$SECRETS" {} + | wc -l)
    [ "$left" = 0 ] && say "scrub ($label): nothing left" || bad "scrub ($label): $left file(s) still hold a value"
}
run_scrub archive
run_scrub unpacked --unpacked
run_scrub jobs --unpacked --jobs 4
M="$WORK/map.json"
( cd "$WORK" && $TOOL --preload --quiet --mappings "$M" scc_node1_260101_1200.txz > pre.log 2>&1 ) \
    && python3 -c "import json,sys; m=json.load(open('$M')); sys.exit(0 if m.get('hostname') and m.get('user') and m.get('sid') else 1)" \
    && say "preload learned hosts, users and the SID" || bad "preload"
( cd "$WORK/run_unpacked" && out=$(ls -d */ | head -1) && $TOOL --verify-output "$out" --mappings "$M" --verify-mapping-only > verify.log 2>&1 ) \
    && say "verify-output: clean" || bad "verify-output found a mapped value in the scrubbed tree (or failed)"

# --- unit tests ---------------------------------------------------------------
PY=python3
if ! python3 -c 'import pytest' 2>/dev/null; then
    python3 -m venv "$WORK/venv" > /dev/null 2>&1 && "$WORK/venv/bin/pip" install -q pytest > "$WORK/pip.log" 2>&1 \
        && PY="$WORK/venv/bin/python" || { tail -3 "$WORK/pip.log"; bad "no pytest and none could be installed"; }
fi
$PY -m pytest -q -p no:cacheprovider tests > "$WORK/pytest.log" 2>&1 || { grep -E '^(FAILED|ERROR)' "$WORK/pytest.log" | head -20; bad "unit tests"; }
say "unit tests: $(tail -1 "$WORK/pytest.log")"

[ "$FAIL" = 0 ] && say "ALL CHECKS PASSED" || say "CHECKS FAILED"
exit $FAIL
