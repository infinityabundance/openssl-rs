#!/bin/sh
# run_ctgrind_wp.sh — PFP8-WIDTH-POLICY: ctgrind at the new digest with the
# private exponent tainted, on the **shortened** (policy-width) schedule, plus
# the established modulus-width window case and a negative control for each.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash courts/performance-frontier/pfp8/run_ctgrind_wp.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8/width-policy
OUT=/work/court/tmp/pfp8-wp
T="$OUT/ct-target"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$EV/ctgrind"
rm -rf "$EV/ctgrind"/*.log "$EV/ctgrind"/*.out "$EV/ctgrind"/summary.txt
rm -rf "$T"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$JOBS" \
    CARGO_TARGET_DIR="$T" cargo test --lib --offline --no-run 2>&1 | tail -n 3

BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: test binary not found" >&2; exit 1; }

run_case() { # tag test env
    tag=$1
    test=$2
    log="$EV/ctgrind/$tag.log"
    out="$EV/ctgrind/$tag.out"
    rc=0
    env $3 valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=24 --log-file="$log" \
        "$BIN" --exact "bn::arith::tests::$test" \
        --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s test=%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "$test" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/ctgrind/summary.txt"
}

: >"$EV/ctgrind/summary.txt"
run_case policy_taint ctgrind_secret_exponent_policy_width ""
run_case policy_control ctgrind_secret_exponent_policy_width "CTGRIND_POLICY_CONTROL=1"
run_case window_taint ctgrind_secret_exponent_window ""

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
    echo "dqso_sha256=$(sha256sum /work/court/tmp/ma1/cand/distribution/libcrypto.so.3 | awk '{print $1}')"
    echo "dso_cand_sha256=$(sha256sum /work/court/tmp/pfp8-wp-build/cand/distribution/libcrypto.so.3 | awk '{print $1}')"
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0"
    echo "note=debug test binary; source-bound, not DSO-bound; not a constant-time proof"
} >"$EV/ctgrind/meta.txt"

for tag in policy_taint window_taint; do
    errs=$(sed -n "s/^$tag .* errors=\([0-9]*\).*/\1/p" "$EV/ctgrind/summary.txt")
    [ "${errs:-x}" = 0 ] || { echo "STOP: $tag reported ${errs:-?} errors" >&2; exit 1; }
done
ctl=$(sed -n 's/^policy_control .* errors=\([0-9]*\).*/\1/p' "$EV/ctgrind/summary.txt")
[ "${ctl:-0}" -gt 0 ] || { echo "STOP: the policy negative control did not fire" >&2; exit 1; }

rm -rf "$T"
echo "ctgrind: done"
