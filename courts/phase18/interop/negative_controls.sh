#!/usr/bin/env bash
#
# negative_controls.sh — O10: the interop harness must fail when the world is
# wrong. A harness that reports `ok` for a broken world is not evidence.
#
# The controls drive the real harness (`make t-exec LTESTS=<script>`) in a
# throwaway copy of a built tree, so each one runs exactly the path the matrix
# runs. Each mutation is a wrapper around `ssh` or `sshd` (the harness invokes
# them by path from the build directory) or a genuinely absent tool; the harness
# is never asked to notice something it cannot see.
#
# A control counts only if (a) the harness announced the script and (b) the run
# failed. A non-zero exit with no `run test` line is a setup error and is
# reported NOT_TRIGGERED, because that would make the control vacuous — the
# first version of this script did exactly that and was rewritten.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${O10_WORK:-$ROOT/court/tmp/o10}"
TOOLS="${TOOLS_PREFIX:-$ROOT/court/tmp/o3/prefix}"
SRC_TREE="${O10_TREE:-$ROOT/court/tmp/o4/tree-A}"
RECEIPT="${O10_RECEIPT:-$ROOT/courts/phase18/interop/RECEIPT-o10.json}"

die() { echo "negative_controls: $*" >&2; exit 2; }
[ -x "$SRC_TREE/sshd" ] || die "no built tree (run build_trees.sh)"

mkdir -p "$WORK"
fail=0
rows=""

new_cell() {
    local name="$1"
    local dir="$WORK/$name"
    rm -rf "$dir"
    cp -a "$SRC_TREE" "$dir" || return 1
    echo "$dir"
}

wrap() {  # dir name body
    local dir="$1"
    local name="$2"
    local body="$3"
    if [ ! -f "$dir/$name.real" ]; then mv "$dir/$name" "$dir/$name.real"; fi
    printf '#!/bin/sh\n%s\n' "$body" > "$dir/$name"
    chmod +x "$dir/$name"
}

run() {  # dir script log -> exit status
    # BUILDDIR must be the copy: configure wrote an absolute BUILDDIR into the
    # Makefile, so without this the harness would run the original tree's
    # binaries and every mutation would be invisible.
    ( cd "$1" && PATH="$TOOLS/bin:$TOOLS/sbin:$PATH" \
        make -k t-exec "LTESTS=$2" BUILDDIR="$1" ) > "$3" 2>&1
}

verdict() {  # rc log script -> TRIGGERED|NOT_TRIGGERED|VACUOUS
    if ! grep -qE "^run test $3\.sh" "$2" 2>/dev/null; then
        echo VACUOUS
    elif [ "$1" -ne 0 ]; then
        echo TRIGGERED
    else
        echo NOT_TRIGGERED
    fi
}

record() {  # control expectation verdict
    printf '%-32s expected %-10s %s\n' "$1" "$2" "$3"
    [ "$3" = TRIGGERED ] || fail=$((fail + 1))
    rows+="${rows:+,}
    {\"control\": \"$1\", \"expected\": \"$2\", \"verdict\": \"$3\"}"
}

echo "=== 1. wrong client binary ==="
d="$(new_cell c1)"; wrap "$d" ssh 'exit 127'
rc=0; run "$d" connect "$WORK/c1.log" || rc=$?
record "wrong client binary" failed "$(verdict $rc "$WORK/c1.log" connect)"

echo "=== 2. wrong crypto library ==="
d="$(new_cell c2)"; mkdir -p "$d/badlib"; : > "$d/badlib/libcrypto.so.3"
wrap "$d" ssh "LD_LIBRARY_PATH=$d/badlib exec $d/ssh.real \"\$@\""
rc=0; run "$d" connect "$WORK/c2.log" || rc=$?
record "wrong crypto library" failed "$(verdict $rc "$WORK/c2.log" connect)"

echo "=== 3. failed authentication ==="
d="$(new_cell c3)"; wrap "$d" sshd "exec $d/sshd.real -o DenyUsers='*' \"\$@\""
rc=0; run "$d" connect "$WORK/c3.log" || rc=$?
record "failed authentication" failed "$(verdict $rc "$WORK/c3.log" connect)"

echo "=== 4. dead server ==="
d="$(new_cell c4)"
wrap "$d" sshd 'exit 1'
rc=0; run "$d" connect "$WORK/c4.log" || rc=$?
record "dead server" failed "$(verdict $rc "$WORK/c4.log" connect)"

echo "=== 5. unsupported algorithm ==="
d="$(new_cell c5)"
wrap "$d" sshd "exec $d/sshd.real -o KexAlgorithms=diffie-hellman-group14-sha1 \"\$@\""
wrap "$d" ssh "exec $d/ssh.real -o KexAlgorithms=curve25519-sha256 \"\$@\""
rc=0; run "$d" connect "$WORK/c5.log" || rc=$?
record "unsupported algorithm" failed "$(verdict $rc "$WORK/c5.log" connect)"

echo "=== 6. missing third-party tool ==="
d="$(new_cell c6)"
mv "$TOOLS/bin/dbclient" "$TOOLS/bin/dbclient.hidden"
rc=0; run "$d" dropbear-ciphers "$WORK/c6.log" || rc=$?
mv "$TOOLS/bin/dbclient.hidden" "$TOOLS/bin/dbclient"
# The harness's own handling of a missing tool is a SKIP with exit 0, and its
# reason string ("dropbear interop tests not enabled") does not name the missing
# binary. That is acceptable upstream behaviour, but it means exit status alone
# can never distinguish "skipped" from "passed" -- so the control requires a
# SKIPPED line and the absence of any ok line, and the receipt records that the
# exit code is not evidence here.
if [ "$(grep -cE '^run test dropbear-ciphers\.sh' "$WORK/c6.log" 2>/dev/null || true)" -eq 0 ]; then
    v=NOT_TRIGGERED; note=harness-never-started
elif [ "$(grep -cE '^ok ' "$WORK/c6.log" 2>/dev/null || true)" -ne 0 ]; then
    v=NOT_TRIGGERED; note=passed-without-tool
elif grep -qE '^SKIPPED' "$WORK/c6.log"; then
    v=TRIGGERED; note=skipped-exit-0
else
    v=NOT_TRIGGERED; note=neither-skip-nor-fail
fi
echo "  ($note; exit $rc)"
record "missing third-party tool" "no ok, skip or fail" "$v"

echo "=== 7. timeout / signal kill ==="
d="$(new_cell c7)"
wrap "$d" sshd "$d/sshd.real \"\$@\" & p=\$!; sleep 0.5; kill -9 \$p 2>/dev/null; wait \$p 2>/dev/null; exit 1"
rc=0; run "$d" connect "$WORK/c7.log" || rc=$?
record "timeout / signal kill" failed "$(verdict $rc "$WORK/c7.log" connect)"

cat > "$RECEIPT" <<EOF
{
  "schema": "openssl-rs/interop-negative-controls-receipt/1",
  "item": "O10 of docs/ETP-TODO.md",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "subject_tree": "$SRC_TREE",
  "mechanism": "make -k t-exec LTESTS=<script> in a throwaway copy, with ssh or sshd replaced by a wrapper that is wrong in one specific way",
  "principle": "a control that does not trigger fails this script, and a control whose harness never started is reported VACUOUS rather than counted",
  "controls": [$rows
  ],
  "not_triggered": $fail
}
EOF
echo
echo "controls not triggered: $fail"
echo "receipt: $RECEIPT"
exit $((fail == 0 ? 0 : 1))
