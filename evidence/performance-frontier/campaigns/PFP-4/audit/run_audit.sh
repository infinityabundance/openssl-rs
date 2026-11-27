#!/bin/sh
# run_audit.sh — PFP-4 binary branch audit over the new order-inverse carriers.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-4/audit/run_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-4/audit
DSO=/work/court/tmp/pfp4-a/distribution/libcrypto.so.3
EXPECT=4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77

fail() { printf 'PFP4-AUDIT STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$DSO" ] || fail "missing DSO $DSO"
[ "$(sha "$DSO")" = "$EXPECT" ] || fail "DSO digest $(sha "$DSO")"

mkdir -p "$EV/raw"

echo "=== shared auditor, PFP-4 carrier inventory ==="
python3 courts/phase18/timing/binary_branch_audit.py \
    --expect-sha256 "$EXPECT" \
    --targets-file "$EV/targets-pfp4.json" "$DSO" \
    >"$EV/raw/audit-pfp4.md" 2>"$EV/raw/audit-pfp4.stderr" \
    || fail "shared auditor refused a target (see raw/audit-pfp4.stderr)"
cat "$EV/raw/audit-pfp4.stderr"

# `to_canonical` is instantiated for four types (three P256Field kernels and
# P256Scalar), so the auditor's exact-identifier rule refuses it as ambiguous.
# `ossl_ec_group_do_inverse_ord` is an ABI-exported plain C symbol, outside that
# rule. Disassemble both bodies explicitly by their symbol-table addresses.
for pair in "P256Scalar12to_canonical:to-canonical" \
            "ossl_ec_group_do_inverse_ord:do-inverse-ord"; do
    pat=${pair%%:*}
    tag=${pair##*:}
    echo "=== $pat (exact address range) ==="
    ADDR=$(nm "$DSO" | awk -v p="$pat" '$3 ~ p "$" {print $1; exit}')
    [ -n "$ADDR" ] || fail "$pat symbol missing"
    SIZE=$(nm -S "$DSO" | awk -v p="$pat" '$4 ~ p "$" {print $2; exit}')
    [ -n "$SIZE" ] || fail "$pat size missing"
    START=$((0x$ADDR))
    END=$((START + 0x$SIZE))
    objdump -d --no-show-raw-insn "$DSO" \
        --start-address="$START" --stop-address="$END" \
        >"$EV/raw/$tag.asm"
    printf 'symbol=%s addr=0x%s size=0x%s start=0x%x end=0x%x\n' \
        "$pat" "$ADDR" "$SIZE" "$START" "$END" >"$EV/raw/$tag.meta"
    awk '/\t(j[a-z]+|cmov[a-z]+|set[a-z]+)\t/ {print}' \
        "$EV/raw/$tag.asm" >"$EV/raw/$tag.rows" || true
    cat "$EV/raw/$tag.rows"
done

{
    echo "dso_path=$DSO"
    echo "dso_sha256=$EXPECT"
    echo "shared_inventory_exit=0"
    echo "targets_inventory=$EV/targets-pfp4.json sha256=$(sha "$EV/targets-pfp4.json")"
    echo "auditor=courts/phase18/timing/binary_branch_audit.py sha256=$(sha courts/phase18/timing/binary_branch_audit.py)"
    echo "objdump=$(objdump --version | head -1)"
} >"$EV/raw/audit-meta.env"

echo "PASS: PFP-4 branch audit ran at $EXPECT"
