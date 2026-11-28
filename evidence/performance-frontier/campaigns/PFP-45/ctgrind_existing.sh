#!/bin/sh
# ctgrind_existing.sh — run the PFP-45 ctgrind case against an already-built
# test binary, for a venue that has valgrind but not the cargo registry.
#
#   docker exec <court-with-valgrind> sh \
#     evidence/performance-frontier/campaigns/PFP-45/ctgrind_existing.sh <test-binary>
set -eu
cd /work
BIN=${1:?usage: ctgrind_existing.sh <test-binary>}
EV=/work/evidence/performance-frontier/campaigns/PFP-45/ctgrind
mkdir -p "$EV"

run_case() { # tag extra-env
    tag=$1
    log="$EV/$tag.log"
    out="$EV/$tag.out"
    rc=0
    env $2 valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=24 --log-file="$log" \
        "$BIN" --exact bn::limbs::tests::ctgrind_rem_consttime_secret_dividend \
        --nocapture --test-threads=1 >"$out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' \
        "$tag" "${errs:-0}" "${ctxs:-0}" "$rc" | tee -a "$EV/summary.txt"
}

: >"$EV/summary.txt"
run_case dividend_taint ""
run_case negative_control "CTGRIND_CONTROL=1"

{
    for f in "$EV"/*.log; do
        echo "--- $(basename "$f")"
        grep -E 'Conditional jump|Use of uninitialised|depends on uninitialised|Uninitialised value was created|Address .* is ' "$f" || echo "origins: none"
    done
} >"$EV/origins.txt"
cat "$EV/origins.txt"

{
    echo "test_binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"
    echo "limbs_sha256=$(sha256sum src/bn/limbs.rs | awk '{print $1}')"
    echo "test_profile=debug, CARGO_PROFILE_TEST_DEBUG=0"
    echo "valgrind=$(valgrind --version)"
    echo "note=source-bound, not DSO-bound; a schedule observation, not a proof"
} >"$EV/meta.txt"

errs=$(sed -n 's/^dividend_taint errors=\([0-9]*\).*/\1/p' "$EV/summary.txt")
ctl=$(sed -n 's/^negative_control errors=\([0-9]*\).*/\1/p' "$EV/summary.txt")
[ "${errs:-x}" = 0 ] || { echo "STOP: dividend-taint run reported ${errs:-?} errors" >&2; exit 1; }
[ "${ctl:-0}" -gt 0 ] || { echo "STOP: negative control did not fire" >&2; exit 1; }
echo "ctgrind: done"
