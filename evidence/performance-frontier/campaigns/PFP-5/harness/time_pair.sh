#!/usr/bin/env bash
# Paired before/after timing: base (HEAD, digest 4e6ec312) vs candidate
# (digest 842efa27), 15 process-level repetitions, pinned to CPU 1.
set -euo pipefail
ROOT=/work
PROF=/work/court/tmp/pfp5/profile
OUT="$PROF/timing-pair"
BASE=/work/court/tmp/pfp5/base-build/distribution/libcrypto.so.3
CAND=/work/court/tmp/pfp5/build/distribution/libcrypto.so.3
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
REPS=15
CPU="${PFP5_PIN_CPU:-1}"
mkdir -p "$OUT"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

sha256sum "$BASE" "$CAND" "$AUTH" "$PROF/bench_pfp5" >"$OUT/identity.sha256"
for ((i = 0; i < REPS; i++)); do
    if (( i % 2 == 0 )); then
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$BASE" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-base.out"
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$CAND" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-candidate.out"
    else
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$CAND" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-candidate.out"
        taskset -c "$CPU" "$PROF/bench_pfp5" --lib "$BASE" "${COMMON[@]}" --prepared \
            >"$OUT/rep-$(printf %02d "$i")-base.out"
    fi
    echo "pair $i done"
done
echo PAIR_OK
