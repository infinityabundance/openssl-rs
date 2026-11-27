#!/bin/sh
# run_gates.sh — correctness gates 3–5: `cargo test --lib -- bn`, the full
# library suite, fmt and clippy, reusing the test target built by
# run_kernel_differential.sh.
#
# The debug test profile with debuginfo=2 exceeds the court's 4 GiB RLIMIT_DATA,
# so the same debug profile is built with line debug info suppressed
# (CARGO_PROFILE_TEST_DEBUG=0). Assertions are unaffected (opt-level stays 0).
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_gates.sh
set -u

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
T="$OUT/test-target"

mkdir -p "$EV/correctness"

echo "=== cargo test --lib -- bn ==="
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- bn --test-threads=4 \
    >"$EV/correctness/bn.log" 2>&1
bn_rc=$?
grep -E '^test result:|running [0-9]+ tests' "$EV/correctness/bn.log" | tail -n 4
echo "bn_exit=$bn_rc"

echo "=== full library suite ==="
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    CARGO_TARGET_DIR="$T" \
    cargo test --lib --offline -- --test-threads=4 \
    >"$EV/correctness/suite.log" 2>&1
suite_rc=$?
grep -E '^test result:|running [0-9]+ tests' "$EV/correctness/suite.log" | tail -n 4
echo "suite_exit=$suite_rc"

echo "=== cargo fmt --all -- --check ==="
cargo fmt --all -- --check >"$EV/correctness/fmt.log" 2>&1
fmt_rc=$?
echo "fmt_exit=$fmt_rc"

echo "=== cargo clippy --all-targets -- -D warnings ==="
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    cargo clippy --all-targets --offline -- -D warnings \
    >"$EV/correctness/clippy.log" 2>&1
clippy_rc=$?
tail -n 3 "$EV/correctness/clippy.log"
echo "clippy_exit=$clippy_rc"

rm -rf "$T"
{
    echo "bn_exit=$bn_rc"
    echo "suite_exit=$suite_rc"
    echo "fmt_exit=$fmt_rc"
    echo "clippy_exit=$clippy_rc"
} >"$EV/correctness/gates.env"
cat "$EV/correctness/gates.env"

[ "$bn_rc" = 0 ] && [ "$suite_rc" = 0 ] && [ "$fmt_rc" = 0 ] && [ "$clippy_rc" = 0 ]
