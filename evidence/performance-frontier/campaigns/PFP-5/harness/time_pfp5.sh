#!/usr/bin/env bash
# PFP-5 timing: candidate vs authority, 15 process-level repetitions,
# one process per library per repetition, pinned to CPU 1.
set -euo pipefail
ROOT=/work
BUILD=/work/court/tmp/pfp5/build
PROF=/work/court/tmp/pfp5/profile
OUT="$PROF/timing"
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

REPS=15
CPU="${PFP5_PIN_CPU:-1}"
mkdir -p "$OUT"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm -o "$PROF/bench_pfp5"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

sha256sum "$DSO" "$AUTH" "$PROF/bench_pfp5" >"$OUT/identity.sha256"

for ((i = 0; i < REPS; i++)); do
    if (( i % 2 == 0 )); then
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$DSO" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-candidate.out"
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$AUTH" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-authority.out"
    else
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$AUTH" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-authority.out"
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$DSO" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-candidate.out"
    fi
    echo "rep $i done"
done
echo TIMING_OK
