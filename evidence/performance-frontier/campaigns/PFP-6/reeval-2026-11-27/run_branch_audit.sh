#!/bin/sh
# run_branch_audit.sh — branch/division/cmov audit of the production default A
# at the new digest. The PFP-5 targets (`run_mont_ladder`, `mont_mul_sos_into`)
# are used unchanged; the DSO digest is the new artefact's.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/run_branch_audit.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
A="$OUT/a/distribution/libcrypto.so.3"
EXPECT_A=661384603e0b661af384997676d8e88843f2b307b6abf73f56d472b03d888630

[ "$(sha256sum "$A" | awk '{print $1}')" = "$EXPECT_A" ] || {
    echo "FATAL: A digest" >&2
    exit 1
}
mkdir -p "$EV/audit"
cp /work/evidence/performance-frontier/campaigns/PFP-5/harness/branch-targets.json \
    "$EV/audit/branch-targets.json"
python3 /work/courts/phase18/timing/binary_branch_audit.py \
    --targets-file "$EV/audit/branch-targets.json" \
    --expect-sha256 "$EXPECT_A" "$A" >"$EV/audit/branch-audit.md" \
    2>"$EV/audit/branch-audit.err"
cat "$EV/audit/branch-audit.err"
echo "branch audit: done"
