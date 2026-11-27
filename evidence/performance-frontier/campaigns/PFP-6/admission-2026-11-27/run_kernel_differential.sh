#!/bin/sh
# run_kernel_differential.sh — correctness gate 1: the per-kernel differential at
# the admission source, before anything else.
#
#   pfp6_each_kernel_satisfies_the_congruence  (SOS, CIOS, SQR congruence)
#   pfp6_cios_matches_the_reference            (CIOS vs SOS exhaustive + sampled)
#   pfp6_dedicated_squaring_matches_the_reference
#   pfp6_geometry_fails_closed
#
# The counts are printed by the tests; --nocapture records them.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_kernel_differential.sh
set -u

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
T="$OUT/test-target"

mkdir -p "$EV/correctness"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- pfp6 --nocapture --test-threads=4 \
    >"$EV/correctness/pfp6.log" 2>&1
rc=$?
grep -E 'PFP-6 (kernel congruence|CIOS differential|squaring differential)|^test result:|running [0-9]+ tests' \
    "$EV/correctness/pfp6.log" || true
echo "pfp6_exit=$rc"
exit "$rc"
