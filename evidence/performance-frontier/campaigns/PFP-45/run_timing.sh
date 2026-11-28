#!/bin/sh
# run_timing.sh — PFP-45 before/after timing on the out-of-policy 2400-bit DH
# preset and the in-policy 225-bit preset, authority included.
#
# One process per arm per workload per repetition, order rotated, taskset -c 1.
# bench_pfp8 `keygen-fixed` sets the private key and calls DH_generate_key.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-45
OUT=/work/court/tmp/pfp45
ROOT=/work
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
BEFORE="$OUT/before/distribution/libcrypto.so.3"
AFTER="$OUT/after/distribution/libcrypto.so.3"
CPU=${PFP45_CPU:-1}
REPS=${PFP45_REPS:-15}
ITERS=${PFP45_ITERS:-10}

# shellcheck disable=SC1091
. "$ROOT/evidence/performance-frontier/campaigns/PFP-8/raw/operands.env"
PRIV2400=$(python3 -c 'print("ab" * 300)')

mkdir -p "$EV/raw/timing" "$OUT"
cc -O2 -g -Wall -Wextra \
    -I "$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include" \
    "$ROOT/courts/performance-frontier/pfp8/bench_pfp8.c" -ldl -o "$OUT/bench_pfp8"
rm -f "$EV/raw/timing"/*.out "$EV/raw/timing"/*.err

run_one() { # tag dso workload
    tag=$1; dso=$2; workload=$3
    case "$workload" in
        out2400)  priv=$PRIV2400 ;;
        in225)    priv=$PRIV225 ;;
        *) return 1 ;;
    esac
    taskset -c "$CPU" "$OUT/bench_pfp8" --lib "$dso" --op keygen-fixed --nid 1126 \
        --priv "$priv" --iters "$ITERS" --runs 1 \
        >"$EV/raw/timing/$tag-$workload-r$(printf %02d "$REP").out" \
        2>"$EV/raw/timing/$tag-$workload-r$(printf %02d "$REP").err"
}

REP=1
while [ "$REP" -le "$REPS" ]; do
    if [ $((REP % 2)) -eq 1 ]; then order="before after auth"; else order="auth after before"; fi
    for tag in $order; do
        case "$tag" in
            before) dso=$BEFORE ;;
            after)  dso=$AFTER ;;
            auth)   dso=$AUTH ;;
        esac
        for w in out2400 in225; do
            run_one "$tag" "$dso" "$w"
        done
    done
    REP=$((REP + 1))
done

{
    echo "before_dso_sha256=$(sha256sum "$BEFORE" | awk '{print $1}')"
    echo "after_dso_sha256=$(sha256sum "$AFTER" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "harness_source_sha256=$(sha256sum /work/courts/performance-frontier/pfp8/bench_pfp8.c | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp8" | awk '{print $1}')"
    echo "reps=$REPS iters=$ITERS taskset=-c$CPU"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$EV/raw/timing/run-meta.env"
cat "$EV/raw/timing/run-meta.env"
python3 "$EV/analyse_timing.py" "$EV/raw/timing" | tee "$EV/raw/timing/summary.txt"
echo TIMING_OK
