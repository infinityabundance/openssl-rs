#!/bin/sh
# run_tests.sh — PFP-48 correctness under the VARIANT build flag.
#
#   1. the in-crate PFP-6 CIOS/SOS differential sets, compiled with
#      RUSTFLAGS="-C target-feature=+bmi2" (i.e. the variant codegen);
#   2. the full library suite with the same flag.
#
# The DSO-level ABI transcript and DH court are in run_diff.sh.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 \
#     bash docker/openssl-rs-court.sh exec env CARGO_PROFILE_TEST_DEBUG=0 \
#       sh evidence/performance-frontier/campaigns/PFP-48/run_tests.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-48
RAW="$EV/tests"
T=/work/court/tmp/pfp48/testtarget
FLAGS="-C target-feature=+bmi2"
mkdir -p "$RAW"

run() {
    CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$T" \
        RUSTFLAGS="$FLAGS" cargo "$@"
}

echo "=== focused PFP-6 differential sets (RUSTFLAGS='$FLAGS') ==="
run test --lib --offline pfp6_ -- --test-threads=4 --nocapture \
    2>&1 | tee "$RAW/differential-tests.txt"

echo "=== full library suite (RUSTFLAGS='$FLAGS') ==="
run test --lib --offline -- --test-threads=4 --skip test_sigstore_bundle \
    2>&1 | tee "$RAW/full-suite.txt"

echo "=== focused summary ==="
grep -E "^PFP-6 |test result:" "$RAW/differential-tests.txt" || true
echo "=== full-suite summary ==="
grep -E "^test result:" "$RAW/full-suite.txt" | tail -n 1 || true
echo "=== tests: done ==="
