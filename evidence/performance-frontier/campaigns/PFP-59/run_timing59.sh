#!/bin/sh
# run_timing59.sh — PFP-59 paired timing, before vs after vs authority.
#
# Same instrument before and after: PFP-11's unmodified bench_pfp11.c for
# P-384/P-521 and bench_p256.c for P-256. One process per arm/operation/
# repetition; order rotated; taskset -c 1; 15 repetitions. A process is one
# independent replication.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/court/tmp/pfp59
REPS=${PFP59_REPS:-15}
CPU=${PFP59_CPU:-1}
INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B11=$OUT/bench_pfp11
B256=$OUT/bench_p256
TIM=$OUT/timing
mkdir -p "$TIM"
rm -f "$TIM"/*.out "$TIM"/*.err

cc -O2 -Wall -Wextra -Werror -I"$INC" -o "$B256" \
    /work/evidence/performance-frontier/campaigns/PFP-11/bench_p256.c -ldl

run_one() { # tag dso rep
    tag=$1; dso=$2; rep=$3
    for spec in \
        "ecdsa-sign-p384|p11|--op ecdsa-sign --curve p384 --iters 20" \
        "ecdsa-verify-p384|p11|--op ecdsa-verify --curve p384 --iters 20" \
        "ecdsa-sign-p521|p11|--op ecdsa-sign --curve p521 --iters 10" \
        "ecdsa-verify-p521|p11|--op ecdsa-verify --curve p521 --iters 10" \
        "ecdsa256|p256|--iters 100"
    do
        name=${spec%%|*}
        rest=${spec#*|}
        which=${rest%%|*}
        args=${rest#*|}
        bin=$B11
        [ "$which" = p256 ] && bin=$B256
        # shellcheck disable=SC2086
        taskset -c "$CPU" "$bin" --lib "$dso" $args --runs 5 \
            >"$TIM/$tag-$name-r$(printf %02d "$rep").out" \
            2>"$TIM/$tag-$name-r$(printf %02d "$rep").err"
    done
}

rep=1
while [ "$rep" -le "$REPS" ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="before after auth"; else order="auth after before"; fi
    for tag in $order; do
        case "$tag" in
            before) dso=$OUT/before/libcrypto.so.3 ;;
            after)  dso=$OUT/after/libcrypto.so.3 ;;
            auth)   dso=$AUTH ;;
        esac
        run_one "$tag" "$dso" "$rep"
    done
    echo "rep $rep/$REPS done"
    rep=$((rep + 1))
done

{
    echo "before_dso_sha256=$(sha256sum "$OUT/before/libcrypto.so.3" | awk '{print $1}')"
    echo "after_dso_sha256=$(sha256sum "$OUT/after/libcrypto.so.3" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "bench_pfp11_sha256=$(sha256sum "$B11" | awk '{print $1}')"
    echo "bench_p256_sha256=$(sha256sum "$B256" | awk '{print $1}')"
    echo "harness_pfp11_source_sha256=$(sha256sum /work/evidence/performance-frontier/campaigns/PFP-11/bench_pfp11.c | awk '{print $1}')"
    echo "harness_p256_source_sha256=$(sha256sum /work/evidence/performance-frontier/campaigns/PFP-11/bench_p256.c | awk '{print $1}')"
    echo "reps=$REPS taskset=-c$CPU"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$TIM/run-meta.env"
cat "$TIM/run-meta.env"
echo "TIMING_OK"
