#!/bin/sh
# phase2_timing.sh — PFP-11 phase 2 paired timing at one digest.
#
# P-521: ecdsa-sign and ecdsa-verify, candidate vs pinned authority, 11 paired
# process-level repetitions, `taskset -c 1`, order rotated. P-256: the
# `ecdsa256` control (sign) through the PFP-5 harness, same pairing, to show the
# new arm did not touch the plain-field curve.
set -eu
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-11
OUT=${PFP11P2_OUT:-/work/court/tmp/pfp11-phase2}
CAND=/work/court/tmp/pfp11/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B11=/work/court/tmp/pfp11/bench_pfp11
B5="$OUT/instrument/bench_p256"
CPU=${PFP11P2_CPU:-1}
REPS=${PFP11P2_REPS:-11}

mkdir -p "$OUT/timing-p521" "$OUT/timing-p256" "$OUT/instrument"
rm -f "$OUT/timing-p521"/*.out "$OUT/timing-p256"/*.out 2>/dev/null || true
cc -O2 -Wall -Wextra -Werror \
    "$EV/bench_p256.c" -ldl -o "$B5"

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
    if [ $((rep % 2)) -eq 1 ]; then order="cand auth"; else order="auth cand"; fi
    for tag in $order; do
        case "$tag" in
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
    echo "cand_dso_sha256=$(sha256sum "$CAND" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "harness_p521_sha256=$(sha256sum "$B11" | awk '{print $1}')"
    echo "harness_p256_sha256=$(sha256sum "$B5" | awk '{print $1}')"
    echo "harness_p256_source_sha256=$(sha256sum "$EV/bench_p256.c" | awk '{print $1}')"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "worktree_build_inputs=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | wc -l)"
    echo "reps=$REPS taskset=-c$CPU"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
} >"$OUT/run-meta.env"
cat "$OUT/run-meta.env"

python3 "$EV/analyse_timing.py" --dir "$OUT/timing-p521" --out "$EV/raw/phase2-timing.json"
python3 "$EV/phase2_p256_analyse.py" --dir "$OUT/timing-p256" --out "$EV/raw/phase2-timing-p256.json"
echo PHASE2_TIMING_OK
