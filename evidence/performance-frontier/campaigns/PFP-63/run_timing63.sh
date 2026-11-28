#!/bin/sh
# run_timing63.sh — PFP-63 paired AEAD timing, two regimes, three campaigns.
#
# Every campaign uses the same instrument binary, the same pinned CPU, the same
# rotated order and the same 15 independent process replications. A ratio is always
# cand/auth (the pinned OpenSSL 3.6.4), so >1 means the candidate is slower.
#
#   before  the pre-change DSO (baseline reproduced)
#   after   this tree's DSO (AES-NI + PCLMULQDQ)
#   off     this tree's DSO with both CPUID bits cleared (the portable, leaking path)
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp63
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B=$OUT/bench_pfp63
EV=/work/evidence/performance-frontier/campaigns/PFP-63
CPU=${PFP63_CPU:-1}
REPS=${PFP63_REPS:-15}
OPSPEC="aes128gcm-64,aes128gcm-16k,aes256gcm-64,aes256gcm-16k"

run_campaign() { # label dso cap
    label=$1
    dso=$2
    cap=${3:-}
    T=$OUT/timing-$label
    mkdir -p "$T"
    rm -f "$T"/*.out "$T"/*.err

    rep=1
    while [ "$rep" -le "$REPS" ]; do
        if [ $((rep % 2)) -eq 1 ]; then order="cand auth"; else order="auth cand"; fi
        for tag in $order; do
            if [ "$tag" = cand ]; then d=$dso; else d=$AUTH; fi
            for spec in \
                "aes128gcm-64|--iters 3000" \
                "aes128gcm-16k|--iters 8" \
                "aes256gcm-64|--iters 3000" \
                "aes256gcm-16k|--iters 8"
            do
                name=${spec%%|*}
                args=${spec#*|}
                r=$(printf %02d "$rep")
                if [ "$tag" = cand ] && [ -n "$cap" ]; then
                    # shellcheck disable=SC2086
                    OPENSSL_ia32cap="$cap" taskset -c "$CPU" "$B" --lib "$d" \
                        --op "$name" $args --runs 5 >"$T/$tag-$name-r$r.out" \
                        2>"$T/$tag-$name-r$r.err"
                else
                    # shellcheck disable=SC2086
                    taskset -c "$CPU" "$B" --lib "$d" \
                        --op "$name" $args --runs 5 >"$T/$tag-$name-r$r.out" \
                        2>"$T/$tag-$name-r$r.err"
                fi
            done
        done
        rep=$((rep + 1))
    done

    {
        echo "campaign=$label"
        echo "cand_dso_sha256=$(sha256sum "$dso" | awk '{print $1}')"
        echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
        echo "harness_source_sha256=$(sha256sum /work/evidence/performance-frontier/campaigns/PFP-12/bench_pfp12.c | awk '{print $1}')"
        echo "harness_binary_sha256=$(sha256sum "$B" | awk '{print $1}')"
        echo "source_commit=$(git -C /work rev-parse HEAD)"
        echo "ia32cap_override=$cap"
        echo "reps=$REPS taskset=-c$CPU"
        echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    } >"$T/run-meta.env"
    cat "$T/run-meta.env"

    python3 "$EV/analyse_timing.py" --dir "$T" --ops "$OPSPEC" \
        --out "$OUT/raw/timing-$label.json" | tee "$OUT/raw/timing-$label.txt"
}

run_campaign before "$OUT/before/libcrypto.so.3"
run_campaign after "$OUT/after/libcrypto.so.3"
run_campaign off "$OUT/after/libcrypto.so.3" '~0x2000002'
echo TIMING63_OK
