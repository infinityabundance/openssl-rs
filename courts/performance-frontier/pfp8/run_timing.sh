#!/bin/sh
# run_timing.sh — PFP-8 paired timing at one digest.
#
# Arms: cand (current HEAD, DSO 88c0c7e0), prev (PFP-6 admitted DSO 6d002db2)
# and auth (OpenSSL 3.6.4).  Workloads: real named-group key generation
# (ffdhe2048), the shared secret with the 2048-bit benchmark exponent, and the
# shared secret with the RFC 7919 225-bit key length.  One process per arm per
# workload per repetition, order rotated, `taskset -c 1`, 15 repetitions.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8
OUT=${PFP8_OUT:-/work/court/tmp/pfp8}
CAND=${PFP8_CAND:-/work/court/tmp/ma1/cand/distribution/libcrypto.so.3}
PREV=${PFP8_PREV:-/work/court/tmp/ma1/prev/distribution/libcrypto.so.3}
AUTH=${PFP8_AUTH:-/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}
CPU=${PFP8_CPU:-1}
REPS=${PFP8_REPS:-15}

. "$EV/raw/operands.env"
mkdir -p "$EV/timing/raw"
rm -f "$EV/timing/raw"/*.out "$EV/timing/raw"/*.err

run_one() { # tag dso workload
    tag=$1; dso=$2; workload=$3
    case "$workload" in
        keygen)  set -- --op keygen --nid 1126 ;;
        compute) set -- --op compute --nid 1126 --priv "$PRIV2048" --peer "$PEER2048" ;;
        compute225) set -- --op compute --nid 1126 --priv "$PRIV225" --peer "$PEER225" ;;
    esac
    taskset -c "$CPU" "$OUT/bench_pfp8" --lib "$dso" "$@" \
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
        for w in keygen compute compute225; do
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
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp8" | awk '{print $1}')"
    echo "reps=$REPS taskset=-c$CPU"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$EV/timing/raw/run-meta.env"
cat "$EV/timing/raw/run-meta.env"

python3 /work/courts/performance-frontier/pfp8/analyse_timing.py
echo TIMING_OK
