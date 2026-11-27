#!/bin/sh
# run_ctgrind_tools.sh — PFP-46 ctgrind in the pinned tools image.
#
# The active forensic court image (`openssl-rs-court:1`) has no valgrind; the
# campaign's timing-tools image `openssl-rs-court-tools:1` does (valgrind
# 3.19.0). This script runs the SAME court-built debug test binary under that
# image, capped, with the checkout bind-mounted read-write at /work.
#
# The cpuid probe records whether valgrind's emulated CPU exposes BMI2, i.e.
# which dispatch arm the taint run reached.
set -eu
cd /work
EV=/work/evidence/performance-frontier/campaigns/PFP-46/ctgrind
BIN=/work/court/tmp/pfp46/ct-target/debug/deps/openssl_rs-b4da7ea231465a25
PROBE=/work/court/tmp/pfp46/cpuid_bmi2
mkdir -p "$EV"
: >"$EV/summary.txt"

valgrind --tool=memcheck --log-file="$EV/cpuid-valgrind.log" "$PROBE" \
    >"$EV/cpuid-bmi2.txt" 2>&1 || true
cat "$EV/cpuid-bmi2.txt" | tee -a "$EV/summary.txt"

run_case() {
    tag=$1
    ctl=$2
    log="$EV/$tag.log"
    out="$EV/$tag.out"
    rc=0
    if [ "$ctl" = "control" ]; then
        CTGRIND_CONTROL=1 valgrind --tool=memcheck --error-exitcode=99 \
            --leak-check=no --num-callers=24 --log-file="$log" "$BIN" \
            --exact bn::arith::tests::ctgrind_secret_exponent_window \
            --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    else
        valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
            --num-callers=24 --log-file="$log" "$BIN" \
            --exact bn::arith::tests::ctgrind_secret_exponent_window \
            --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    fi
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/summary.txt"
}

run_case exponent_taint ""
run_case negative_control control

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
    echo "venue=openssl-rs-court-tools:1 (base court image has no valgrind)"
    echo "note=debug test binary; source-bound, not DSO-bound; not a constant-time proof"
} >"$EV/meta.txt"
cat "$EV/meta.txt"
echo "ctgrind-tools: done"
