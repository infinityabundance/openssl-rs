#!/bin/sh
# run_timing.sh — PFP-48 paired before/after latency on the campaign instruments.
#
# before = the frozen source built with no RUSTFLAGS (portable `mul`/`setb`/`adc`);
# after  = the SAME source built with the whole crate under
#          RUSTFLAGS="-C target-feature=+bmi2", so the kernel inlines into the
#          feature context with no #[target_feature] wrapper call.
#
# Workloads (the five PFP-48 asks for):
#   DH keygen / DH shared secret ffdhe2048 : bench_pfp8 (named group).
#   modexp-2048 / modexp-8192 / RSA-2048   : bench_pfp5 population (--prepared).
# One process per arm per repetition, arm order alternated, taskset -c 1.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

RAW=/work/evidence/performance-frontier/campaigns/PFP-48/timing
OUT=/work/court/tmp/pfp48
ROOT=/work
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
BEFORE="$OUT/portable/libcrypto.so.3"
AFTER="$OUT/bmi2/libcrypto.so.3"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
REPS5=${REPS5:-5}
REPS8=${REPS8:-15}
CPU=${PFP48_CPU:-1}
T="$RAW/raw"
mkdir -p "$T"

cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm -o "$OUT/bench_pfp5"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp8/bench_pfp8.c" -ldl -o "$OUT/bench_pfp8"
. "$ROOT/evidence/performance-frontier/campaigns/PFP-8/raw/operands.env"

rm -f "$T"/*.out

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
    done
    rep=$((rep + 1))
done
echo "pfp8 reps done: $REPS8"

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
python3 "$RAW/analyse_timing.py" "$T"
