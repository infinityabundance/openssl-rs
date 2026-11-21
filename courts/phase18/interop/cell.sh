#!/usr/bin/env bash
#
# cell.sh — O7: run one cell of the four-cell interoperability matrix.
#
#   bash courts/phase18/interop/cell.sh BA
#
# Cells: AA (client A, server A), BB, BA (client B against server A), AB.
# A is the reference-OpenSSL build, B the openssl-rs build, both from the same
# unmodified 9.9p1 source (O4).
#
# The harness launches the local build's binaries by path, so a cross cell
# cannot be produced by setting TEST_SSH_SSH alone: the outer Makefile pins
# TEST_SSH_SSH to $(BUILDDIR)/ssh. Instead each cell gets its own copy of the
# tree in which every executable is replaced by a wrapper that execs the cell's
# chosen build with that build's own LD_LIBRARY_PATH. There is no single shared
# LD_LIBRARY_PATH, so a client and a server from different cells each map their
# own libcrypto -- the condition O5 checks, and the reason a shared value would
# silently collapse the matrix into two cells.
#
# Client-side: ssh, sftp, scp, ssh-agent, ssh-add, ssh-keyscan.
# Server-side: sshd, sshd-session, sftp-server, ssh-keygen (host keys).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CELL="${1:-}"
case "$CELL" in
    AA|BB|BA|AB) ;;
    *) echo "usage: cell.sh AA|BB|BA|AB" >&2; exit 2;;
esac

WORK="${O7_WORK:-$ROOT/court/tmp/o4}"
AUTH="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
B_PREFIX="${B_PREFIX:-$WORK/b-prefix}"
TOOLS="${TOOLS_PREFIX:-$ROOT/court/tmp/o3/prefix}"
RECEIPT="${O7_RECEIPT:-$ROOT/courts/phase18/interop/RECEIPT-o7-$CELL.json}"

client_cell="${CELL:0:1}"
server_cell="${CELL:1:1}"
declare -A TREE=( [A]="$WORK/tree-A" [B]="$WORK/tree-B" )
declare -A LIB=( [A]="$AUTH/lib" [B]="$B_PREFIX/lib" )

CTREE="${TREE[$server_cell]}"
[ -x "$CTREE/ssh" ] || { echo "cell: no built tree for $server_cell" >&2; exit 2; }

CELLDIR="$WORK/cell-$CELL"
rm -rf "$CELLDIR"
cp -a "$CTREE" "$CELLDIR" || { echo "cell: copy failed" >&2; exit 2; }
# The copy carries the source tree's previous regress state -- known_hosts,
# generated host keys, copies of test data. Carrying it forward makes a cell fail
# on its own history instead of on the other cell's library (observed: dbclient
# reporting a host-key mismatch from a stale $OBJ/.ssh/known_hosts), so the
# regress state is cleared before the cell runs.
( cd "$CELLDIR" && make regressclean >/dev/null 2>&1 ) || true

wrap() {  # <name> <tree> <lib>
    local name="$1"
    local tree="$2"
    local lib="$3"
    [ -x "$tree/$name" ] || return 0
    # printf, not a heredoc: the wrapper must end up containing a literal "$@",
    # and a heredoc both expands and eats the escaping. The first version wrote
    # "\$@" into the wrapper, so every argument was dropped.
    printf '#!/bin/sh\nLD_LIBRARY_PATH=%s exec %s "$@"\n' \
        "$lib" "$tree/$name" > "$CELLDIR/$name"
    chmod +x "$CELLDIR/$name"
}

for b in ssh sftp scp ssh-agent ssh-add ssh-keyscan ssh-keygen; do
    wrap "$b" "${TREE[$client_cell]}" "${LIB[$client_cell]}"
done
for b in sshd sshd-session sftp-server ssh-keygen; do
    wrap "$b" "${TREE[$server_cell]}" "${LIB[$server_cell]}"
done

export PATH="$TOOLS/bin:$TOOLS/sbin:$PATH"

# A cell is only a matrix cell if the two sides really run different libraries.
# The wrappers say so, but the wrappers are the thing under suspicion, so the
# probe from O5 re-asks the question from inside the processes.
probe_mapping() {
    local probe="$WORK/map_probe.so"
    [ -f "$probe" ] || cc -O2 -fPIC -shared \
        "$ROOT/courts/phase18/interop/map_probe.c" -o "$probe" || return 1
    local out="$WORK/cell-$CELL.mapping.log"
    : > "$out"
    local key="$WORK/cell-$CELL.probe.key"
    "$CELLDIR/ssh-keygen" -q -t ed25519 -N '' -f "$key" >/dev/null 2>&1 || true
    printf 'Port 22499\nHostKey %s\nPidFile %s.pid\nUsePAM no\n' "$key" "$key" > "$key.conf"
    MAP_PROBE_OUT="$out" LD_PRELOAD="$probe" "$CELLDIR/ssh" -V >/dev/null 2>&1 || true
    MAP_PROBE_OUT="$out" LD_PRELOAD="$probe" "$CELLDIR/sshd" -t -f "$key.conf" >/dev/null 2>&1 || true
    awk '{print $6}' "$out" | sort -u | tr '\n' ' '
}

mapped="$(probe_mapping || true)"
echo "mapped libcrypto in this cell: ${mapped:-<none>}"
# The expected set is the distinct libraries of the two chosen builds: one entry
# for a same-library cell, two for a cross cell. Set equality is the check, so a
# cross cell that collapsed onto one library fails just as a same-library cell
# that picked up a foreign one does.
expected="$(printf '%s\n%s\n' "${LIB[$client_cell]}/libcrypto.so.3" \
              "${LIB[$server_cell]}/libcrypto.so.3" | sort -u | tr '\n' ' ')"
mapped_sorted="$(printf '%s' "$mapped" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')"
if [ "$mapped_sorted" = "$expected" ]; then
    mapped_status=ok
else
    mapped_status=unexpected
    echo "cell: mapped ${mapped_sorted:-<none>}, expected $expected" >&2
fi
if [ "${O7_PROBE_ONLY:-0}" = 1 ]; then
    printf '{"cell": "%s", "client": "%s", "server": "%s", "expected": "%s", "mapped": "%s", "status": "%s"}\n' \
        "$CELL" "$client_cell" "$server_cell" "$expected" "$mapped_sorted" "$mapped_status" \
        > "$WORK/cell-$CELL.mapping.json"
    echo "mapping: $WORK/cell-$CELL.mapping.json"
    [ "$mapped_status" = ok ] || exit 1
    exit 0
fi

echo "=== cell $CELL: client $client_cell, server $server_cell ==="
# BUILDDIR must be the cell's own directory: configure wrote an absolute
# BUILDDIR into the Makefile, so a copy still points at the tree it came from and
# the harness would launch *that* tree's binaries -- the wrappers would never be
# reached and a "cross" cell would silently be a same-cell run. The first version
# of this script did exactly that; the override is the fix.
( cd "$CELLDIR" \
  && TEST_SSH_PORT="${O7_PORT:-22422}" make -k tests BUILDDIR="$CELLDIR" \
       > "$WORK/cell-$CELL.log" 2>&1 )
rc=$?
echo "make -k tests exit=$rc"

# The wrappers must have done their job: the log's failures, and a spot check
# that the client and server wrappers name different libraries.
grep -E "^failed " "$WORK/cell-$CELL.log" | sed 's/^/  /' || true

client_dso="$(sha256sum "${LIB[$client_cell]}/libcrypto.so.3" | cut -d' ' -f1)"
server_dso="$(sha256sum "${LIB[$server_cell]}/libcrypto.so.3" | cut -d' ' -f1)"
cat > "$RECEIPT" <<EOF
{
  "schema": "openssl-rs/interop-cell-receipt/1",
  "item": "O7 of docs/ETP-TODO.md",
  "cell": "$CELL",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "client": {"build": "$client_cell", "libcrypto_sha256": "$client_dso"},
  "server": {"build": "$server_cell", "libcrypto_sha256": "$server_dso"},
  "separate_library_paths": $([ "$client_cell" != "$server_cell" ] && echo true || echo false),
  "mapped_libraries": "$(printf '%s' "$mapped" | sed 's/\\/\\\\/g')",
  "mapping_status": "$mapped_status",
  "make_k_tests_exit": $rc,
  "log": "$WORK/cell-$CELL.log",
  "failed_scripts": "$(grep -cE '^failed ' "$WORK/cell-$CELL.log" || true)"
}
EOF
echo "receipt: $RECEIPT"
exit $((rc == 0 ? 0 : 1))
