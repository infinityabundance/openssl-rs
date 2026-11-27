#!/bin/sh
# run_audit.sh — PFP-3 branch audit after the branch-free admission.
#
# Same two instruments as ../audit/run_audit.sh, unchanged:
#   1. the shared auditor with the PFP-31 31-target inventory (must exit 0);
#   2. capture_carriers.py, which imports that auditor's own disassembler,
#      byte-coverage check and condition-provenance classifier and resolves the
#      five generic fixed-base instantiations plus wNAF by exact v0 component.
#
# The only change is the subject: the post-fix DSO ecbefb7d… built from
# f8d5c4b33 with src/ec/p256/fixed_base.rs modified.  There is no hard-coded
# "+0x1938 must be a je" assertion: that instruction was the defect.  The
# post-fix gate instead refuses if the old secret branch pattern (a `je` whose
# flag setter is `test $0x1,%cl`, the low bit of the ct_ge mask) is still
# present in the inlined fixed-base region, and it prints every jcc row of the
# wNAF carrier so the classification can be adjudicated against the source.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/audit-postfix/run_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/audit-postfix
DSO=/work/court/tmp/pfp3-ctgrind-postfix/a/libcrypto.so.3
EXPECT=ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053

fail() { printf 'PFP3-AUDIT-POSTFIX STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$DSO" ] || fail "missing DSO $DSO"
[ "$(sha "$DSO")" = "$EXPECT" ] || fail "DSO digest $(sha "$DSO")"

mkdir -p "$EV/raw"

echo "=== shared auditor, PFP-3 inventory ==="
python3 courts/phase18/timing/binary_branch_audit.py \
    --expect-sha256 "$EXPECT" \
    --targets-file "$EV/targets-pfp3.json" "$DSO" \
    >"$EV/raw/audit-pfp3.md" 2>"$EV/raw/audit-pfp3.stderr" \
    || fail "shared auditor refused a target (see raw/audit-pfp3.stderr)"
cat "$EV/raw/audit-pfp3.stderr"

echo "=== exact-symbol carrier audit (generic instantiations) ==="
python3 "$EV/capture_carriers.py" \
    --dso "$DSO" --expect-sha256 "$EXPECT" \
    --out-json "$EV/raw/carriers.json" --out-md "$EV/raw/carriers.md" \
    | tee "$EV/raw/carriers.stdout"

# The defect was a `je` on the ct_ge admission mask, whose flag setter was
# `test $0x1,%cl`.  After folding the mask into the scalar, that pattern must
# not reach a conditional transfer in the inlined fixed-base region.
python3 - "$EV/raw/carriers.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
key = "Fixed-base entry and admission (inlined into wNAF)"
arms = [v for k, v in doc["carriers"].items() if k == key]
if len(arms) != 1:
    print("audit-carriers: the wNAF carrier is missing", file=sys.stderr)
    raise SystemExit(1)
rows = arms[0]["jcc_rows"]
bad = [r for r in rows if (r.get("setter") or "").endswith("test $0x1,%cl")]
if bad:
    print("audit-carriers: the ct_ge admission branch pattern is still present:", file=sys.stderr)
    for r in bad:
        print(r, file=sys.stderr)
    raise SystemExit(1)
print(f"wNAF carrier jcc rows: {len(rows)}; admission-mask jcc pattern: 0")
PY

{
    echo "dso_path=$DSO"
    echo "dso_sha256=$EXPECT"
    echo "shared_inventory_exit=0"
    echo "targets_inventory=$EV/targets-pfp3.json sha256=$(sha "$EV/targets-pfp3.json")"
    echo "auditor=courts/phase18/timing/binary_branch_audit.py sha256=$(sha courts/phase18/timing/binary_branch_audit.py)"
    echo "carrier_driver=$EV/capture_carriers.py sha256=$(sha "$EV/capture_carriers.py")"
    echo "objdump=$(objdump --version | head -1)"
} >"$EV/raw/audit-meta.env"

echo "PASS: post-fix audit ran at $EXPECT (shared inventory resolved; admission-mask jcc absent)"
