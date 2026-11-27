#!/bin/sh
# run_kernel_differential.sh — M-A1 correctness gate 1: the per-width
# differential of the compile-time kernels against the generic slice kernel,
# before timing.
#
#   ma1_specialised_widths_match_the_generic_kernel
#   ma1_unspecialised_widths_use_the_generic_kernel
#   pfp6_cios_matches_the_reference   (the generic reference is unchanged)
#
# Counts are printed by the tests; --nocapture records them.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/M-A1/run_kernel_differential.sh
set -u

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/M-A1
OUT=/work/court/tmp/ma1
T="$OUT/test-target"

mkdir -p "$EV/correctness"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- ma1 --nocapture --test-threads=4 \
    >"$EV/correctness/ma1.log" 2>&1
rc1=$?
grep -E 'M-A1 (width|specialised differential|fallback widths)|^test result:' \
    "$EV/correctness/ma1.log" || true

CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- pfp6_cios_matches_the_reference --nocapture --test-threads=4 \
    >"$EV/correctness/pfp6_reference.log" 2>&1
rc2=$?
grep -E 'PFP-6 CIOS differential|^test result:' "$EV/correctness/pfp6_reference.log" || true

echo "ma1_exit=$rc1 pfp6_reference_exit=$rc2"
[ "$rc1" = 0 ] && [ "$rc2" = 0 ]
