#!/bin/sh
# run_timing.sh — PFP-6 re-evaluation: paired timing of the four variants.
#
# One process per DSO per repetition, order rotated across the four arms so no
# arm is always first or last. Same harness as PFP-5 (bench_pfp5.c, unmodified),
# same fixtures, `--prepared`, `taskset -c 1`, 15 repetitions. Each process
# reports five batch medians per workload; the analysis takes the median of the
# paired per-repetition ratios with a 20,000-resample percentile bootstrap,
# exactly as PFP-5's analyse_pair.py did.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/run_timing.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
ROOT=/work
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
REPS=15
CPU="${PFP6_PIN_CPU:-1}"

EXPECT_A=661384603e0b661af384997676d8e88843f2b307b6abf73f56d472b03d888630
EXPECT_B=5c0e0d90e9caf95f140fe98d386bab18e27072e78038a0ba3827706b4b900484
EXPECT_C=ca0ae5387d81f42de6dd2207d0794840eb38b8cab1d4015d91d4aa4239569159
EXPECT_D=a24c0aa2e9e09e1335445421c744809585bb680915b16108546f9b5f20ab1197

fail() { printf 'PFP6 REEVAL STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

A="$OUT/a/distribution/libcrypto.so.3"
B="$OUT/b/distribution/libcrypto.so.3"
C="$OUT/c/distribution/libcrypto.so.3"
D="$OUT/d/distribution/libcrypto.so.3"
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "B digest"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "C digest"
[ "$(sha "$D")" = "$EXPECT_D" ] || fail "D digest"

mkdir -p "$OUT/instrument" "$EV/timing/raw"
rm -f "$EV/timing/raw"/*.out
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm \
    -o "$OUT/instrument/bench_pfp5"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

rep=1
while [ "$rep" -le "$REPS" ]; do
    case $((rep % 4)) in
        1) order="a b c d" ;;
        2) order="b c d a" ;;
        3) order="c d a b" ;;
        0) order="d a b c" ;;
    esac
    for tag in $order; do
        case $tag in
            a) dso=$A ;;
            b) dso=$B ;;
            c) dso=$C ;;
            d) dso=$D ;;
        esac
        f="$EV/timing/raw/$tag-r$(printf %02d "$rep").out"
        taskset -c "$CPU" "$OUT/instrument/bench_pfp5" --lib "$dso" \
            "${COMMON[@]}" --prepared >"$f" 2>"$f.err" \
            || fail "$tag/r$rep: harness failed"
        grep -q '^RESULT ' "$f" || fail "$tag/r$rep: no RESULT lines"
        rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
        [ "$rp" = "$(realpath "$dso")" ] || fail "$tag/r$rep: mapped $rp"
    done
    echo "rep $rep/$REPS done"
    rep=$((rep + 1))
done

{
    echo "dso_a_sha256=$(sha "$A")"
    echo "dso_b_sha256=$(sha "$B")"
    echo "dso_c_sha256=$(sha "$C")"
    echo "dso_d_sha256=$(sha "$D")"
    echo "harness_source_sha256=$(sha "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c")"
    echo "harness_binary_sha256=$(sha "$OUT/instrument/bench_pfp5")"
    echo "reps=$REPS taskset=-c$CPU mode=prepared"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
} >"$EV/timing/raw/run-meta.env"
cat "$EV/timing/raw/run-meta.env"
echo "timing: done"
