#!/bin/sh
# run_timing.sh — PFP-12 paired AEAD/SHA-2 timing, two message regimes.
#
# Arms: cand (this tree's DSO) and auth (pinned OpenSSL 3.6.4). One process per
# arm per operation per repetition; order rotated; taskset -c 1; 15
# repetitions. A process is one independent replication.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-12
OUT=${PFP12_OUT:-/work/court/tmp/pfp12}
CAND=$OUT/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
CPU=${PFP12_CPU:-1}
REPS=${PFP12_REPS:-15}
B=$OUT/bench_pfp12

mkdir -p "$OUT/timing"
rm -f "$OUT/timing"/*.out "$OUT/timing"/*.err

run_one() { # tag dso rep
    tag=$1; dso=$2; rep=$3
    for spec in \
        "aes128gcm-64|--iters 3000" \
        "aes128gcm-16k|--iters 8" \
        "aes256gcm-64|--iters 3000" \
        "aes256gcm-16k|--iters 8" \
        "chachapoly-64|--iters 3000" \
        "chachapoly-16k|--iters 8" \
        "sha256-16k|--iters 64" \
        "sha512-16k|--iters 64"
    do
        name=${spec%%|*}
        args=${spec#*|}
        # shellcheck disable=SC2086
        taskset -c "$CPU" "$B" --lib "$dso" --op "$name" $args --runs 5 \
            >"$OUT/timing/$tag-$name-r$(printf %02d "$rep").out" \
            2>"$OUT/timing/$tag-$name-r$(printf %02d "$rep").err"
    done
}

rep=1
while [ "$rep" -le "$REPS" ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="cand auth"; else order="auth cand"; fi
    for tag in $order; do
        case "$tag" in
            cand) dso=$CAND ;;
            auth) dso=$AUTH ;;
        esac
        run_one "$tag" "$dso" "$rep"
    done
    echo "rep $rep/$REPS done"
    rep=$((rep + 1))
done

{
    echo "cand_dso_sha256=$(sha256sum "$CAND" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "harness_source_sha256=$(sha256sum "$EV/bench_pfp12.c" | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$B" | awk '{print $1}')"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "reps=$REPS taskset=-c$CPU"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$OUT/timing/run-meta.env"
cat "$OUT/timing/run-meta.env"

python3 "$EV/analyse_timing.py" --dir "$OUT/timing" --out "$EV/raw/timing.json"
echo TIMING_OK
