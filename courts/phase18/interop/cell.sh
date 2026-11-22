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
# `regressclean` does not remove the copied `.ssh` directory or any known_hosts
# file, and those carry the *source* tree's server key: dbclient then rejects the
# cell's own server with "host key mismatch" (observed, and stable across runs
# because the copied key is stable). They are removed explicitly.
rm -rf "$CELLDIR/regress/.ssh" "$CELLDIR/regress/known_hosts" \
       "$CELLDIR/regress/known_hosts2" "$CELLDIR/regress/.putty" 2>/dev/null || true

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

# Venue aids, now tracked and built here rather than borrowed from a work
# directory:
#   * a child subreaper, because container PID 1 does not reap orphans and a
#     zombie ssh-agent stalls `agent-subprocess` (the 96-script run depended on
#     this and it was previously untracked);
#   * the authority `openssl` CLI on PATH, which `ssh2putty.sh` calls by name.
AIDS="$WORK/cell-aids"
mkdir -p "$AIDS"
cc -O2 "$ROOT/courts/phase18/interop/subreaper.c" -o "$AIDS/subreaper" \
    || { echo "cell: building the subreaper failed" >&2; exit 2; }
# Invoke the shim through `sh` so the wrapper does not depend on the tracked
# file's execute bit surviving a checkout or a copy: the first attempt at this
# produced a wrapper that failed with "Permission denied" (rc 126), and
# ssh2putty.sh ignored the failure and wrote an empty key cache.
printf '#!/bin/sh\nOSR_AUTHORITY_PREFIX=%s exec sh %s "$@"\n' \
    "$AUTH" "$ROOT/courts/phase18/interop/openssl-shim.sh" > "$AIDS/openssl"
chmod +x "$AIDS/openssl"

export PATH="$TOOLS/bin:$TOOLS/sbin:$AIDS:$PATH"

# A cell is only a matrix cell if the two sides really run different libraries.
# The wrappers say so, but the wrappers are the thing under suspicion, so the
# probe from O5 re-asks the question from inside the processes.
# A cell is only a matrix cell if the *client process* runs the client build's
# library and the *server process* runs the server build's library. Checking the
# set of libraries that appear anywhere in the cell cannot distinguish a correct
# cell from one where both sides picked up the same library, so each side is
# probed separately and compared with its own expectation.
PROBE_SO="$WORK/map_probe.so"
[ -f "$PROBE_SO" ] || cc -O2 -fPIC -shared \
    "$ROOT/courts/phase18/interop/map_probe.c" -o "$PROBE_SO"

probe_side() {  # binary outfile [conf] -> mapped path
    local bin="$1"
    local out="$2"
    local conf="${3:-}"
    : > "$out"
    if [ -n "$conf" ]; then
        MAP_PROBE_OUT="$out" LD_PRELOAD="$PROBE_SO" "$bin" -t -f "$conf" >/dev/null 2>&1 || true
    else
        MAP_PROBE_OUT="$out" LD_PRELOAD="$PROBE_SO" "$bin" -V >/dev/null 2>&1 || true
    fi
    awk '/libcrypto\.so/ {print $6}' "$out" | head -n 1
}

key="$WORK/cell-$CELL.probe.key"
"$CELLDIR/ssh-keygen" -q -t ed25519 -N '' -f "$key" >/dev/null 2>&1 || true
printf 'Port 22499\nHostKey %s\nPidFile %s.pid\nPasswordAuthentication no\n' \
    "$key" "$key" > "$key.conf"

client_mapped="$(probe_side "$CELLDIR/ssh" "$WORK/cell-$CELL.client.maps")"
server_mapped="$(probe_side "$CELLDIR/sshd" "$WORK/cell-$CELL.server.maps" "$key.conf")"

client_ok=no; server_ok=no
[ "$client_mapped" = "${LIB[$client_cell]}/libcrypto.so.3" ] && client_ok=yes
[ "$server_mapped" = "${LIB[$server_cell]}/libcrypto.so.3" ] && server_ok=yes
if [ "$client_ok" = yes ] && [ "$server_ok" = yes ]; then
    mapped_status=ok
else
    mapped_status=unexpected
    echo "cell: client mapped '${client_mapped:-<none>}' (expected ${LIB[$client_cell]}/libcrypto.so.3)," \
         "server mapped '${server_mapped:-<none>}' (expected ${LIB[$server_cell]}/libcrypto.so.3)" >&2
fi

if [ "${O7_PROBE_ONLY:-0}" = 1 ]; then
    printf '{"cell": "%s", "client": "%s", "server": "%s", "client_mapped": "%s", "server_mapped": "%s", "client_expected": "%s", "server_expected": "%s", "status": "%s"}\n' \
        "$CELL" "$client_cell" "$server_cell" "$client_mapped" "$server_mapped" \
        "${LIB[$client_cell]}/libcrypto.so.3" "${LIB[$server_cell]}/libcrypto.so.3" "$mapped_status" \
        > "$WORK/cell-$CELL.mapping.json"
    echo "mapping: $WORK/cell-$CELL.mapping.json"
    [ "$mapped_status" = ok ] || exit 1
    exit 0
fi
# The mapping is a precondition of the run, not a note about it: an unexpected
# mapping aborts the cell before the harness can produce a result that would be
# attributed to the wrong cell.
if [ "$mapped_status" != ok ]; then
    echo "cell: refusing to run $CELL with an unexpected library mapping" >&2
    exit 3
fi

echo "=== cell $CELL: client $client_cell, server $server_cell ==="
# Deterministic script selection: `t-exec` iterates `$?` (the prerequisites newer
# than the target), so which scripts run depends on file mtimes. The same target
# ran 73 scripts on one tree and 96 on another. Touching every regression script
# before the run makes the selection maximal and repeatable instead of a function
# of when the tree was last used.
find "$CELLDIR/regress" -maxdepth 1 -name '*.sh' -exec touch {} + 2>/dev/null || true

# BUILDDIR must be the cell's own directory: configure wrote an absolute
# BUILDDIR into the Makefile, so a copy still points at the tree it came from and
# the harness would launch *that* tree's binaries -- the wrappers would never be
# reached and a "cross" cell would silently be a same-cell run. The first version
# of this script did exactly that; the override is the fix.
( cd "$CELLDIR" \
  && TEST_SSH_PORT="${O7_PORT:-22422}" SKIP_LTESTS="sftp-cmds" \
       "$AIDS/subreaper" make -k tests BUILDDIR="$CELLDIR" \
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
  "scripts": "same set as O9 (SKIP_LTESTS=sftp-cmds)",
  "client_mapped": "$client_mapped",
  "server_mapped": "$server_mapped",
  "mapping_status": "$mapped_status",
  "make_k_tests_exit": $rc,
  "log": "$WORK/cell-$CELL.log",
  "failed_scripts": "$(grep -cE '^failed ' "$WORK/cell-$CELL.log" || true)"
}
EOF
echo "receipt: $RECEIPT"
exit $((rc == 0 ? 0 : 1))
