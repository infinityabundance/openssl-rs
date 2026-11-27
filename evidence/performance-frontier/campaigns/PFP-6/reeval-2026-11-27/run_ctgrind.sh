#!/bin/sh
# run_ctgrind.sh — source-bound ctgrind with the secret exponent tainted, at
# the re-evaluation source. This is the PFP-5 window test, unchanged:
#
#   valgrind → debug test binary (NOT the release DSO)
#
# It is a source-level control-flow/address check, not a DSO-bound result and
# not a constant-time proof. The target directory is removed after the run.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/run_ctgrind.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
T="$OUT/ctgrind-target"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$EV/ctgrind"
rm -rf "$T"
# debuginfo=2 exceeded the 4 GiB per-process RLIMIT_DATA in this court.  A
# smaller unit is used: the same debug profile and test assertions, with line
# debug info suppressed.  This is recorded; it affects the binary's debug
# sections, not the emitted control flow the instrument reads.
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$JOBS" \
    CARGO_TARGET_DIR="$T" cargo test --lib --offline --no-run 2>&1 | tail -n 5

BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: test binary not found" >&2; exit 1; }
echo "test_binary=$BIN sha256=$(sha256sum "$BIN" | awk '{print $1}')"

valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
    --log-file="$EV/ctgrind/ct-window.log" \
    "$BIN" --exact bn::arith::tests::ctgrind_secret_exponent_window \
    --nocapture --test-threads=1 >"$EV/ctgrind/ct-window.out" 2>&1 || rc=$?
rc="${rc:-0}"
echo "valgrind_exit=$rc"
grep -E 'ERROR SUMMARY|Invalid|Conditional jump|uninitialised' "$EV/ctgrind/ct-window.log" || true
grep -E 'test result|running 1 test' "$EV/ctgrind/ct-window.out" || true
{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "arith_rs_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "valgrind_exit=$rc"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0 (debuginfo=2 exceeded RLIMIT_DATA)"
    echo "note=debug test binary; source-bound, not DSO-bound; not a constant-time proof"
} >"$EV/ctgrind/meta.txt"

rm -rf "$T"
echo "ctgrind: done"
