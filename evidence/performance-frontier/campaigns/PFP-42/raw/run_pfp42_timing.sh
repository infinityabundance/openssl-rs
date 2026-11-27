#!/bin/sh
# run_pfp42_timing.sh — paired before/after latency on the campaign instruments.
#
#   DH keygen / DH shared secret: bench_pfp8 (named group, policy ladder width).
#   modexp-2048 / modexp-8192 / RSA-2048: bench_pfp5 population (prepared mode).
#
# One process per arm per repetition, arm order alternated, taskset -c 1.
# REPS5 / REPS8 override the repetition counts.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

RAW=/work/evidence/performance-frontier/campaigns/PFP-42/raw
OUT=/work/court/tmp/pfp42
ROOT=/work
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
BEFORE="$OUT/before/distribution/libcrypto.so.3"
AFTER="$OUT/after/distribution/libcrypto.so.3"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
REPS5=${REPS5:-5}
REPS8=${REPS8:-15}
CPU=${PFP42_CPU:-1}
T="$RAW/timing"
mkdir -p "$T"

cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm -o "$OUT/bench_pfp5"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp8/bench_pfp8.c" -ldl -o "$OUT/bench_pfp8"
. "$ROOT/evidence/performance-frontier/campaigns/PFP-8/raw/operands.env"

rm -f "$T"/*.out

# --- bench_pfp8: keygen + two shared-secret geometries ---
rep=1
while [ "$rep" -le "$REPS8" ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="before after"; else order="after before"; fi
    for arm in $order; do
        case "$arm" in before) dso=$BEFORE ;; after) dso=$AFTER ;; esac
        n=$(printf %02d "$rep")
        taskset -c "$CPU" "$OUT/bench_pfp8" --lib "$dso" --op keygen --nid 1126 \
            --iters 10 --runs 1 >"$T/p8-keygen-$arm-r$n.out" 2>&1
        taskset -c "$CPU" "$OUT/bench_pfp8" --lib "$dso" --op compute --nid 1126 \
            --priv "$PRIV225" --peer "$PEER225" --iters 10 --runs 1 \
            >"$T/p8-compute2048-$arm-r$n.out" 2>&1
        taskset -c "$CPU" "$OUT/bench_pfp8" --lib "$dso" --op compute --nid 1127 \
            --priv "$PRIV225" --peer "$PEER225" --iters 10 --runs 1 \
            >"$T/p8-compute3072-$arm-r$n.out" 2>&1
    done
    rep=$((rep + 1))
done
echo "pfp8 reps done: $REPS8"

# --- bench_pfp5: modexp-2048 / modexp-8192 / RSA-2048 (full prepared population) ---
COMMON="--rsa-der $RSA_DER --dh-ffdhe2048 $FIX/ffdhe2048.hex --dh-ffdhe3072 $FIX/ffdhe3072.hex --dh-modp2048 $FIX/modp2048.hex"
rep=1
while [ "$rep" -le "$REPS5" ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="before after"; else order="after before"; fi
    for arm in $order; do
        case "$arm" in before) dso=$BEFORE ;; after) dso=$AFTER ;; esac
        n=$(printf %02d "$rep")
        taskset -c "$CPU" "$OUT/bench_pfp5" --lib "$dso" $COMMON --prepared \
            >"$T/p5-$arm-r$n.out" 2>&1
    done
    echo "pfp5 rep $rep/$REPS5 done"
    rep=$((rep + 1))
done

{
    echo "before_dso_sha256=$(sha256sum "$BEFORE" | awk '{print $1}')"
    echo "after_dso_sha256=$(sha256sum "$AFTER" | awk '{print $1}')"
    echo "bench_pfp5_sha256=$(sha256sum "$OUT/bench_pfp5" | awk '{print $1}')"
    echo "bench_pfp8_sha256=$(sha256sum "$OUT/bench_pfp8" | awk '{print $1}')"
    echo "reps5=$REPS5 reps8=$REPS8 taskset=-c$CPU"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "cc=$(cc --version | head -1)"
} >"$T/run-meta.env"
cat "$T/run-meta.env"
python3 "$RAW/analyse_pfp42.py" "$T"
