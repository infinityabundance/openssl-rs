#!/bin/sh
# run_audit.sh — PFP-31: the LLVM-suffix witness and the canary control.
#
# Three audits, each bound with --expect-sha256:
#
#   1. PFP-31 inventory on the real candidate 5e75b694.  The report resolves
#      31/31, including the two LLVM-suffixed copies, and FAILS the declared
#      comparison-result contract at the one secret-derived conditional jump.
#   2. the same inventory on the canary 7a039dee, which replaces the mask select
#      with a branch on the comparison result.  It must fail and name the
#      introduced conditional jump.
#   3. the PFP-29 inventory on the real candidate, to show the extension left
#      the previous audit's result unchanged (29/29, exit 0).
#
#   bash docker/openssl-rs-court.sh exec sh \
#     evidence/performance-frontier/campaigns/PFP-31/run_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-31
DSO=/work/court/tmp/pfp29/a/distribution/libcrypto.so.3
CANARY=/work/court/tmp/pfp31/k/distribution/libcrypto.so.3
EXPECT=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_CANARY=7a039deed0565a1c1507bbe584f75c54c9f59a434dd855937da2e556ab16da60
TOOL=courts/phase18/timing/binary_branch_audit.py

fail() { printf 'PFP31-AUDIT STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$DSO" ] || fail "missing $DSO"
[ -f "$CANARY" ] || fail "missing $CANARY (run build_canary.sh)"
[ "$(sha "$DSO")" = "$EXPECT" ] || fail "candidate digest $(sha "$DSO")"
[ "$(sha "$CANARY")" = "$EXPECT_CANARY" ] || fail "canary digest $(sha "$CANARY")"
[ "$(sha "$DSO")" != "$(sha "$CANARY")" ] || fail "canary is the candidate"

mkdir -p "$EV/raw"

echo "=== real candidate: PFP-31 inventory (expect exit 1) ==="
set +e
python3 "$TOOL" --expect-sha256 "$EXPECT" \
    --targets-file "$EV/targets-pfp31.json" "$DSO" \
    >"$EV/raw/audit-real.md" 2>"$EV/raw/audit-real.stderr"
r_real=$?
set -e
[ "$r_real" = 1 ] || fail "real audit exit $r_real, expected 1 (contract violation)"
grep -q 'reason=secret-derived-conditional-jump' "$EV/raw/audit-real.stderr" \
    || fail "real audit did not name a secret-derived conditional jump"
grep -q 'resolved uniquely and disassembled: 31' "$EV/raw/audit-real.md" \
    || fail "real audit did not resolve all 31 targets"

echo "=== canary: PFP-31 inventory (expect exit 1) ==="
set +e
python3 "$TOOL" --expect-sha256 "$EXPECT_CANARY" \
    --targets-file "$EV/targets-pfp31.json" "$CANARY" \
    >"$EV/raw/audit-canary.md" 2>"$EV/raw/audit-canary.stderr"
r_canary=$?
set -e
[ "$r_canary" = 1 ] || fail "canary audit exit $r_canary, expected 1"
grep -q 'reason=secret-derived-conditional-jump' "$EV/raw/audit-canary.stderr" \
    || fail "canary audit did not name a secret-derived conditional jump"
canary_jump=$(sed -n 's/.*detail=\(0x[0-9a-f]*\) .*/\1/p' \
    "$EV/raw/audit-canary.stderr" | head -1)
real_jump=$(sed -n 's/.*detail=\(0x[0-9a-f]*\) .*/\1/p' \
    "$EV/raw/audit-real.stderr" | head -1)
[ -n "$canary_jump" ] || fail "canary audit named no jump address"
[ -n "$real_jump" ] || fail "real audit named no jump address"
[ "$canary_jump" != "$real_jump" ] || fail "canary and real name the same address"

echo "=== real candidate: PFP-29 inventory (regression check, expect 0) ==="
set +e
python3 "$TOOL" --expect-sha256 "$EXPECT" \
    --targets-file /work/evidence/performance-frontier/campaigns/PFP-29/targets-pfp29.json \
    "$DSO" >"$EV/raw/audit-pfp29-recheck.md" 2>"$EV/raw/audit-pfp29-recheck.stderr"
r_p29=$?
set -e
[ "$r_p29" = 0 ] || fail "PFP-29 inventory now exits $r_p29, expected 0"
grep -q 'resolved uniquely and disassembled: 29' "$EV/raw/audit-pfp29-recheck.md" \
    || fail "PFP-29 re-check did not resolve 29/29"

{
    printf 'real_dso_sha256 %s\n' "$(sha "$DSO")"
    printf 'canary_dso_sha256 %s\n' "$(sha "$CANARY")"
    printf 'tool_sha256 %s\n' "$(sha "$TOOL")"
    printf 'tool_lines %s\n' "$(wc -l <"$TOOL")"
    printf 'objdump %s\n' "$(objdump --version | head -1)"
    printf 'real_audit_exit %s\n' "$r_real"
    printf 'real_jump %s\n' "$real_jump"
    printf 'canary_audit_exit %s\n' "$r_canary"
    printf 'canary_jump %s\n' "$canary_jump"
    printf 'pfp29_inventory_exit %s\n' "$r_p29"
} | tee "$EV/raw/audit-summary.txt"

sed -n 's/^REFUSED .*/&/p' "$EV/raw/audit-real.stderr"
sed -n 's/^REFUSED .*/&/p' "$EV/raw/audit-canary.stderr"
echo "audit: done"
