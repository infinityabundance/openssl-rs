#!/bin/sh
# run_audit.sh — PFP-3 binary branch audit at DSO 04611380.
#
# Two instruments, both bound to the digest with --expect-sha256:
#
#   1. the shared auditor, unchanged, with the PFP-31 31-target inventory.  It
#      must resolve every target and exit 0.  `ossl_ec_wNAF_mul` in that
#      inventory is the ABI function into which the fixed-base admission and
#      `try_fixed_base_mul` are inlined, so its rows are the inlined carriers.
#   2. capture_carriers.py, which imports the auditor's own disassembler,
#      byte-coverage check and provenance classifier, and audits the five
#      generic fixed-base instantiations the short-name rule cannot name
#      (rcb_add, table_mul, to_affine, build_table, advance) plus wNAF by exact
#      v0 component.  Admission requires a unique exact symbol, a non-zero
#      extent and a complete disassembly — the same fail-closed contract.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/audit/run_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/audit
DSO=/work/court/tmp/pfp3-ctgrind/a/libcrypto.so.3
EXPECT=04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4

fail() { printf 'PFP3-AUDIT STOP: %s\n' "$*" >&2; exit 1; }
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

# The ctgrind context was a secret-derived je at wNAF+0x1938.  The carrier
# audit must contain that exact jcc row; if it does not, the two instruments do
# not agree about the artefact and the audit is void.
python3 - "$EV/raw/carriers.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
w = doc["carriers"]["Fixed-base entry and admission (inlined into wNAF)"]
rows = [r for r in w["jcc_rows"] if r["off"] == "+0x1938"]
if len(rows) != 1 or rows[0]["jcc"] != "je":
    print("audit-carriers: the ctgrind jcc at wNAF+0x1938 is not reproduced", file=sys.stderr)
    raise SystemExit(1)
print("wNAF+0x1938 jcc reproduced:", rows[0])
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

echo "PASS: audit ran at $EXPECT (shared inventory resolved; carriers captured)"
