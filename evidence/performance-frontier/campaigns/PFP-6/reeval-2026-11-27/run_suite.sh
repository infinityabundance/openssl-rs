#!/bin/sh
# run_suite.sh — full library suite at the re-evaluation source.
#
# The debug test profile with debuginfo=2 exceeds the court's 4 GiB
# RLIMIT_DATA, so the same debug profile is built with line debug info
# suppressed (CARGO_PROFILE_TEST_DEBUG=0). Assertions are unaffected
# (opt-level stays 0). The target directory is removed afterwards.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/run_suite.sh
set -u

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
T=/work/court/tmp/pfp6-reeval/suite-target
rm -rf "$T"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- --test-threads=4 >"$EV/suite.log" 2>&1
rc=$?
grep -E '^(test result:|running [0-9]+ tests)' "$EV/suite.log" | tail -n 5
echo "suite_exit=$rc"
rm -rf "$T"
exit "$rc"
