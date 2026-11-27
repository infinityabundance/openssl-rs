#!/bin/sh
# run_ctgrind.sh — PFP-46: ctgrind on the runtime-BMI2 dispatch.
#
# Test: bn::arith::tests::ctgrind_secret_exponent_window. The modulus is four
# limbs, so the ladder reaches the width-4 kernel; on a CPU whose BMI2 feature
# `is_x86_feature_detected!` sees, that is the `mont_mul_cios_bmi2_4` wrapper.
# A tiny cpuid probe under the same valgrind run records whether valgrind itself
# reports BMI2, so the receipt states which path was actually exercised.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 \
#     bash docker/openssl-rs-court.sh exec \
#       sh evidence/performance-frontier/campaigns/PFP-46/run_ctgrind.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-46/ctgrind
OUT=/work/court/tmp/pfp46
T="$OUT/ct-target"
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4
mkdir -p "$EV"

rm -rf "$T"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$JOBS" \
    CARGO_TARGET_DIR="$T" cargo test --lib --offline --no-run 2>&1 | tail -n 3

BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: test binary not found" >&2; exit 1; }

# Does valgrind's emulated CPU expose BMI2 (leaf 7 EBX bit 8)? This decides
# which dispatch arm the ctgrind run reached.
cat >"$OUT/cpuid_bmi2.c" <<'EOF'
#include <stdio.h>
int main(void) {
    unsigned a = 7, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    printf("bmi2=%u\n", (b >> 8) & 1u);
    return 0;
}
EOF
cc -O0 -o "$OUT/cpuid_bmi2" "$OUT/cpuid_bmi2.c"
valgrind --tool=memcheck --log-file="$EV/cpuid-valgrind.log" \
    "$OUT/cpuid_bmi2" >"$EV/cpuid-bmi2.txt" 2>&1 || true
cat "$EV/cpuid-bmi2.txt" | tee -a "$EV/summary.txt"

run_case() { # tag env
    tag=$1
    log="$EV/$tag.log"
    out="$EV/$tag.out"
    rc=0
    env $2 valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=24 --log-file="$log" \
        "$BIN" --exact bn::arith::tests::ctgrind_secret_exponent_window \
        --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/summary.txt"
}

run_case exponent_taint ""
run_case negative_control "CTGRIND_CONTROL=1"

{
    for f in "$EV"/*.log; do
        echo "--- $(basename "$f")"
        grep -E 'Conditional jump|Use of uninitialised|depends on uninitialised|Uninitialised value was created|Address .* is ' "$f" || echo "origins: none"
    done
} >"$EV/origins.txt"
cat "$EV/origins.txt"

{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "arith_rs_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0"
    echo "valgrind=$(valgrind --version)"
    echo "note=debug test binary; source-bound, not DSO-bound; not a constant-time proof"
} >"$EV/meta.txt"

errs=$(sed -n 's/^exponent_taint errors=\([0-9]*\).*/\1/p' "$EV/summary.txt")
ctl=$(sed -n 's/^negative_control errors=\([0-9]*\).*/\1/p' "$EV/summary.txt")
[ "${errs:-x}" = 0 ] || { echo "STOP: exponent-taint run reported ${errs:-?} errors" >&2; exit 1; }
[ "${ctl:-0}" -gt 0 ] || { echo "STOP: negative control did not fire" >&2; exit 1; }

rm -rf "$T"
echo "ctgrind: done"
