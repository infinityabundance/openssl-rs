#!/bin/sh
# run_ctgrind.sh — M-A1: ctgrind at the candidate source with the secret
# exponent tainted, plus the built-in negative control.
#
# Test: bn::arith::tests::ctgrind_secret_exponent_window. It marks the staged
# exponent's limb bytes undefined and runs the five-bit-window ladder; memcheck
# must report no conditional jump and no secret-derived address inside
# run_mont_ladder_window / select_window_digit. The modulus is four limbs, so the
# ladder reaches the width-4 compile-time kernel (the smallest specialised one).
# CTGRIND_CONTROL=1 adds a deliberate branch on a marked exponent limb, which
# memcheck must report — the instrument's sensitivity check.
#
# Coverage limit, stated: one specialised width is exercised dynamically. The
# branch audit (run_branch_audit.sh) enumerates all eight inlined widths in the
# same carrier, and the DSO-bound probe (run_dso_probe.sh) runs the real export.
# This is not a constant-time proof.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/M-A1/run_ctgrind.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/M-A1
OUT=/work/court/tmp/ma1
T="$OUT/ct-target"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$EV/ctgrind"
rm -rf "$T"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$JOBS" \
    CARGO_TARGET_DIR="$T" cargo test --lib --offline --no-run 2>&1 | tail -n 3

BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: test binary not found" >&2; exit 1; }

run_case() { # tag env
    tag=$1
    log="$EV/ctgrind/$tag.log"
    out="$EV/ctgrind/$tag.out"
    rc=0
    env $2 valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=24 --log-file="$log" \
        "$BIN" --exact bn::arith::tests::ctgrind_secret_exponent_window \
        --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/ctgrind/summary.txt"
}

: >"$EV/ctgrind/summary.txt"
run_case exponent_taint ""
run_case negative_control "CTGRIND_CONTROL=1"

{
    for f in "$EV/ctgrind"/*.log; do
        echo "--- $(basename "$f")"
        grep -E 'Conditional jump|Use of uninitialised|depends on uninitialised|Uninitialised value was created|Address .* is ' "$f" || echo "origins: none"
    done
} >"$EV/ctgrind/origins.txt"
cat "$EV/ctgrind/origins.txt"

{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "arith_rs_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "dso_cand_sha256=$(sha256sum "$OUT/cand/distribution/libcrypto.so.3" | awk '{print $1}')"
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0"
    echo "note=debug test binary; source-bound, not DSO-bound; not a constant-time proof"
} >"$EV/ctgrind/meta.txt"

errs=$(sed -n 's/^exponent_taint errors=\([0-9]*\).*/\1/p' "$EV/ctgrind/summary.txt")
ctl=$(sed -n 's/^negative_control errors=\([0-9]*\).*/\1/p' "$EV/ctgrind/summary.txt")
[ "${errs:-x}" = 0 ] || { echo "STOP: exponent-taint run reported ${errs:-?} errors" >&2; exit 1; }
[ "${ctl:-0}" -gt 0 ] || { echo "STOP: negative control did not fire" >&2; exit 1; }

rm -rf "$T"
echo "ctgrind: done"
