#!/bin/sh
# run_ctgrind.sh — PFP-45: ctgrind on the secret-dividend reduction, plus the
# built-in branch-on-secret negative control.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=1 \
#     sh evidence/performance-frontier/campaigns/PFP-45/run_ctgrind.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-45
OUT=/work/court/tmp/pfp45
T="$OUT/ct-target"

mkdir -p "$EV/ctgrind"
rm -rf "$T"
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
    CARGO_TARGET_DIR="$T" cargo test --lib --offline --no-run 2>&1 | tail -n 3

BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: test binary not found" >&2; exit 1; }

run_case() { # tag extra-env
    tag=$1
    log="$EV/ctgrind/$tag.log"
    out="$EV/ctgrind/$tag.out"
    rc=0
    env $2 valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=24 --log-file="$log" \
        "$BIN" --exact bn::limbs::tests::ctgrind_rem_consttime_secret_dividend \
        --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/ctgrind/summary.txt"
}

: >"$EV/ctgrind/summary.txt"
run_case dividend_taint ""
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
    echo "limbs_sha256=$(sha256sum src/bn/limbs.rs | awk '{print $1}')"
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0"
    echo "note=source-bound, not DSO-bound; a schedule observation, not a proof"
} >"$EV/ctgrind/meta.txt"

errs=$(sed -n 's/^dividend_taint errors=\([0-9]*\).*/\1/p' "$EV/ctgrind/summary.txt")
ctl=$(sed -n 's/^negative_control errors=\([0-9]*\).*/\1/p' "$EV/ctgrind/summary.txt")
[ "${errs:-x}" = 0 ] || { echo "STOP: dividend-taint run reported ${errs:-?} errors" >&2; exit 1; }
[ "${ctl:-0}" -gt 0 ] || { echo "STOP: negative control did not fire" >&2; exit 1; }

rm -rf "$T"
echo "ctgrind: done"
