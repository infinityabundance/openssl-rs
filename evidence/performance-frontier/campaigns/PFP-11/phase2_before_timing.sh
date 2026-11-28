#!/bin/sh
# phase2_before_timing.sh — PFP-11 phase 2 three-arm timing at one digest.
#
# arms: head  = pristine HEAD 56a4c0f7 (phase-1 candidate dbf3d0a4)
#       cand  = phase-2 candidate (Mersenne fast arm)
#       auth  = pinned OpenSSL 3.6.4
# ops:  P-521 ecdsa sign/verify (bench_pfp11), P-256 ecdsa sign (bench_p256).
set -eu
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-11
OUT=${PFP11P2B_OUT:-/work/court/tmp/pfp11-phase2b}
HEAD=/work/court/tmp/pfp11-head56/libcrypto.so.3
CAND=/work/court/tmp/pfp11/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B11=/work/court/tmp/pfp11/bench_pfp11
B5=/work/court/tmp/pfp11-phase2/instrument/bench_p256
CPU=${PFP11P2B_CPU:-1}
REPS=${PFP11P2B_REPS:-11}

mkdir -p "$OUT/timing-p521" "$OUT/timing-p256"
rm -f "$OUT/timing-p521"/*.out "$OUT/timing-p256"/*.out 2>/dev/null || true

run_p521() { # tag dso rep
    tag=$1; dso=$2; rep=$3
    for spec in \
        "ecdsa-sign-p521|--op ecdsa-sign --curve p521 --iters 10" \
        "ecdsa-verify-p521|--op ecdsa-verify --curve p521 --iters 10"
    do
        name=${spec%%|*}
        args=${spec#*|}
        # shellcheck disable=SC2086
        taskset -c "$CPU" "$B11" --lib "$dso" $args --runs 5 \
            >"$OUT/timing-p521/$tag-$name-r$(printf %02d "$rep").out" 2>/dev/null
    done
}

run_p256() { # tag dso rep
    tag=$1; dso=$2; rep=$3
    taskset -c "$CPU" "$B5" --lib "$dso" --iters 20 --runs 5 \
        >"$OUT/timing-p256/$tag-ecdsa256-r$(printf %02d "$rep").out" 2>/dev/null
}

rep=1
while [ "$rep" -le "$REPS" ]; do
    case $((rep % 3)) in
        1) order="head cand auth" ;;
        2) order="cand auth head" ;;
        0) order="auth head cand" ;;
    esac
    for tag in $order; do
        case "$tag" in
            head) dso=$HEAD ;;
            cand) dso=$CAND ;;
            auth) dso=$AUTH ;;
        esac
        run_p521 "$tag" "$dso" "$rep"
        run_p256 "$tag" "$dso" "$rep"
    done
    echo "rep $rep/$REPS done"
    rep=$((rep + 1))
done

{
    echo "head_dso_sha256=$(sha256sum "$HEAD" | awk '{print $1}')"
    echo "cand_dso_sha256=$(sha256sum "$CAND" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "worktree_build_inputs=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | wc -l)"
    echo "reps=$REPS taskset=-c$CPU"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$OUT/run-meta.env"
cat "$OUT/run-meta.env"

python3 "$EV/phase2_compare.py" --p521 "$OUT/timing-p521" --p256 "$OUT/timing-p256" \
    --out "$EV/raw/phase2-three-arm.json"
echo PHASE2_THREE_ARM_OK
