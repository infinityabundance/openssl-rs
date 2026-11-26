#!/bin/sh
# run_audit.sh — binary branch audit at the PFP-29 artefact digest.
#
# Two runs, both bound to the digest with --expect-sha256:
#
#   1. the tool's default 9-target inventory, for the record: at this digest it
#      refuses `mont_mul_into` (the PFP-6 refactor inlined it), so the default
#      inventory is 8/9 and exits 1.  That refusal is evidence, not an error to
#      hide, and it is why PFP-29 carries its own inventory.
#   2. the PFP-29 inventory (default 9 minus the inlined `mont_mul_into`, plus
#      the SOS kernel, the ladder carrier, the DH driver, the wNAF verify core
#      and the ML-KEM kernels).  It must resolve every target and exit 0.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-29/run_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-29
DSO=/work/court/tmp/pfp29/a/distribution/libcrypto.so.3
EXPECT=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae

fail() { printf 'PFP29-AUDIT STOP: %s\n' "$*" >&2; exit 1; }

[ -f "$DSO" ] || fail "missing DSO $DSO"
got=$(sha256sum "$DSO" | awk '{print $1}')
[ "$got" = "$EXPECT" ] || fail "DSO digest $got"

mkdir -p "$EV/raw"

echo "=== default inventory (expected to refuse mont_mul_into) ==="
set +e
python3 courts/phase18/timing/binary_branch_audit.py \
    --expect-sha256 "$EXPECT" "$DSO" \
    >"$EV/raw/audit-default.md" 2>"$EV/raw/audit-default.stderr"
d_rc=$?
set -e
[ "$d_rc" = 1 ] || fail "default inventory exit $d_rc, expected 1 (mont_mul_into refusal)"
grep -q 'REFUSED target="Montgomery multiply (core)" symbol="mont_mul_into" reason=missing' \
    "$EV/raw/audit-default.stderr" || fail "default inventory did not name the expected refusal"

echo "=== PFP-29 inventory (must resolve every target) ==="
python3 courts/phase18/timing/binary_branch_audit.py \
    --expect-sha256 "$EXPECT" \
    --targets-file "$EV/targets-pfp29.json" "$DSO" \
    >"$EV/raw/audit-pfp29.md" 2>"$EV/raw/audit-pfp29.stderr" \
    || fail "PFP-29 inventory refused a target (see raw/audit-pfp29.stderr)"

grep -q 'expected targets: 29' "$EV/raw/audit-pfp29.md" || fail "unexpected target count"
grep -q 'failed: 0' "$EV/raw/audit-pfp29.md" || fail "audit reports a failure"
grep -q 'resolved uniquely and disassembled: 29' "$EV/raw/audit-pfp29.md" \
    || fail "not every target resolved"

{
    echo "dso_path=$DSO"
    echo "dso_sha256=$got"
    echo "default_inventory_exit=$d_rc"
    echo "pfp29_inventory_exit=0"
    echo "objdump=$(objdump --version | head -1)"
} >"$EV/raw/audit-meta.env"
cat "$EV/raw/audit-pfp29.stderr"
echo "PASS: audit at $EXPECT (default 8/9 with a named refusal; PFP-29 29/29)"
