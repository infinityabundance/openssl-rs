#!/bin/sh
# run_timing_wp.sh — PFP8-WIDTH-POLICY paired timing at one digest.
#
# Arms: cand (this batch, policy-width ladder), prev (the PFP-8/M-A1 DSO
# 88c0c7e0, identical source without this change) and auth (OpenSSL 3.6.4).
# Workloads: real named-group key generation and the shared secret with the
# group's declared key length, on two groups (ffdhe2048 4 limbs, ffdhe3072
# 5 limbs), plus the full-width 2039-bit exponent (the policy falls back) and
# ffdhe3072 key generation. One process per arm per workload per repetition,
# order rotated, `taskset -c 1`, 15 repetitions, 10 calls per process.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash courts/performance-frontier/pfp8/run_timing_wp.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8/width-policy
OUT=${PFP8WP_OUT:-/work/court/tmp/pfp8-wp}
CAND=${PFP8WP_CAND:-/work/court/tmp/pfp8-wp-build/cand/distribution/libcrypto.so.3}
PREV=${PFP8WP_PREV:-/work/court/tmp/ma1/cand/distribution/libcrypto.so.3}
AUTH=${PFP8WP_AUTH:-/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}
CPU=${PFP8WP_CPU:-1}
REPS=${PFP8WP_REPS:-15}

. "$EV/raw/operands-wp.env"
mkdir -p "$EV/timing/raw"
rm -f "$EV/timing/raw"/*.out "$EV/timing/raw"/*.err

run_one() { # tag dso workload
    tag=$1; dso=$2; workload=$3
    case "$workload" in
        keygen)       set -- --op keygen --nid 1126 ;;
        keygen3072)   set -- --op keygen --nid 1127 ;;
        compute225)   set -- --op compute --nid 1126 --priv "$PRIV225" --peer "$PEER225" ;;
        compute2048)  set -- --op compute --nid 1126 --priv "$PRIV2048" --peer "$PEER2048" ;;
        compute275)   set -- --op compute --nid 1127 --priv "$PRIV275" --peer "$PEER275" ;;
    esac
    taskset -c "$CPU" "$OUT/bench_pfp8_wp" --lib "$dso" "$@" \
        --iters 10 --runs 1 >"$EV/timing/raw/$tag-$workload-r$(printf %02d "$REP").out" \
        2>"$EV/timing/raw/$tag-$workload-r$(printf %02d "$REP").err"
}

REP=1
while [ "$REP" -le "$REPS" ]; do
    if [ $((REP % 2)) -eq 1 ]; then order="cand auth prev"; else order="prev auth cand"; fi
    for tag in $order; do
        case "$tag" in
            cand) dso=$CAND ;;
            prev) dso=$PREV ;;
            auth) dso=$AUTH ;;
        esac
        for w in keygen keygen3072 compute225 compute2048 compute275; do
            run_one "$tag" "$dso" "$w"
        done
    done
    echo "rep $REP/$REPS done"
    REP=$((REP + 1))
done

{
    echo "cand_dso_sha256=$(sha256sum "$CAND" | awk '{print $1}')"
    echo "prev_dso_sha256=$(sha256sum "$PREV" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "harness_source_sha256=$(sha256sum /work/courts/performance-frontier/pfp8/bench_pfp8.c | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp8_wp" | awk '{print $1}')"
    echo "operands_sha256=$(sha256sum "$EV/raw/operands-wp.env" | awk '{print $1}')"
    echo "reps=$REPS taskset=-c$CPU iters=10"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$EV/timing/raw/run-meta.env"
cat "$EV/timing/raw/run-meta.env"

python3 /work/courts/performance-frontier/pfp8/analyse_timing_wp.py
echo TIMING_OK
