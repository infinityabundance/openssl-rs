#!/bin/sh
# profile_composition.sh — callgrind profile of the production default (A) at
# the PFP-5 window composition. One operation per workload, `--only`, so the
# call counts are per exponentiation.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/profile_composition.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
RSA_DER=/work/courts/phase18/timing/fixtures/rsa2048.der
FIX=/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures
A="$OUT/a/distribution/libcrypto.so.3"

mkdir -p "$EV/profile"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    /work/courts/performance-frontier/pfp5/bench_pfp5.c -ldl -lm \
    -o "$OUT/instrument/bench_pfp5"

COMMON=(--lib "$A" --rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

for w in modexp2048 modexp8192; do
    echo "=== $w ==="
    valgrind --tool=callgrind --callgrind-out-file="$EV/profile/$w.cg" \
        --quiet "$OUT/instrument/bench_pfp5" "${COMMON[@]}" --prepared --only "$w" \
        >"$EV/profile/$w.stdout" 2>"$EV/profile/$w.stderr" || true
    grep -E '^(RESULT|CHECK)' "$EV/profile/$w.stdout" | cut -c1-80 || true
    callgrind_annotate --inclusive=no --threshold=95 "$EV/profile/$w.cg" \
        >"$EV/profile/$w.annotate" 2>/dev/null || true
    grep -E 'PROGRAM TOTALS|mont_mul_sos_into|run_mont_ladder' "$EV/profile/$w.annotate" || true
done
echo PROFILE_OK
