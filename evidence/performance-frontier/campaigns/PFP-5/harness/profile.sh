#!/usr/bin/env bash
# PFP-5 profiling: one operation of each workload under callgrind.
set -euo pipefail
ROOT=/work
BUILD=/work/court/tmp/pfp5/build
PROF=/work/court/tmp/pfp5/profile
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$PROF/cg"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm -o "$PROF/bench_pfp5"

COMMON=(--lib "$DSO" --rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

for w in modexp2048 modexp8192 rsa2048 dh-ffdhe2048 dh-modp2048; do
    echo "=== $w ==="
    valgrind --tool=callgrind --callgrind-out-file="$PROF/cg/$w.out" \
        --quiet "$PROF/bench_pfp5" "${COMMON[@]}" --prepared --only "$w" \
        >"$PROF/cg/$w.stdout" 2>"$PROF/cg/$w.stderr" || true
    grep -E '^(RESULT|CHECK)' "$PROF/cg/$w.stdout" | cut -c1-80 || true
    callgrind_annotate --inclusive=no --threshold=90 "$PROF/cg/$w.out" \
        >"$PROF/cg/$w.annotate" 2>/dev/null || true
    grep -E 'PROGRAM TOTALS|bn::|mont|redc|ladder|mod_exp' "$PROF/cg/$w.annotate" | head -25 || true
done
echo PROFILE_OK
