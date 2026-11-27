#!/bin/sh
# run_timing.sh — PFP-6 admission: paired whole-operation timing of the admitted
# CIOS default, the SOS reference twin and the production authority.
#
# Same harness, fixtures and conventions as PFP-5/PFP-6: bench_pfp5.c, one
# process per arm per repetition, order rotated across the three arms, 15
# repetitions, `taskset -c 1`, `--prepared`.  The analysis takes the median of
# the paired per-repetition ratios with a 20,000-resample percentile bootstrap.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_timing.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
ROOT=/work
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"
REPS=15
CPU="${PFP6_PIN_CPU:-1}"

EXPECT_CAND=6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39
EXPECT_REF=f3d716028e9022e769bcd05fd4fe84cb1bd5e680c32744933b0c27974d80fb3c
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2

fail() { printf 'PFP6 ADMISSION STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

CAND="$OUT/cand/distribution/libcrypto.so.3"
REF="$OUT/ref/distribution/libcrypto.so.3"
[ "$(sha "$CAND")" = "$EXPECT_CAND" ] || fail "cand digest"
[ "$(sha "$REF")" = "$EXPECT_REF" ] || fail "ref digest"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority digest"

mkdir -p "$OUT/instrument" "$EV/timing/raw"
rm -f "$EV/timing/raw"/*.out "$EV/timing/raw"/*.err
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm \
    -o "$OUT/instrument/bench_pfp5"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

# --- population, declared before execution --------------------------------
cat >"$EV/population.json" <<EOF
{
  "declared_by": "evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_timing.sh (written before execution)",
  "mode": "prepared",
  "repetitions": $REPS,
  "cpu": $CPU,
  "taskset": "taskset -c $CPU",
  "harness": {
    "path": "courts/performance-frontier/pfp5/bench_pfp5.c",
    "sha256": "$(sha "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c")",
    "note": "the PFP-5/PFP-1 workload driver, unmodified"
  },
  "workloads": [
    "modexp2048", "dh-synth2048", "dh-synth3072", "dh-ffdhe2048",
    "dh-ffdhe3072", "dh-modp2048", "rsa2048", "ecdsa256", "modexp8192"
  ],
  "fixtures": {
    "rsa2048.der": "$(sha "$RSA_DER")",
    "ffdhe2048.hex": "$(sha "$FIX/ffdhe2048.hex")",
    "ffdhe3072.hex": "$(sha "$FIX/ffdhe3072.hex")",
    "modp2048.hex": "$(sha "$FIX/modp2048.hex")"
  },
  "arms": {
    "cand": "$(sha "$CAND")",
    "ref": "$(sha "$REF")",
    "auth": "$(sha "$AUTH")"
  },
  "statistic": "median of the $REPS paired per-repetition ratios; 95% percentile bootstrap, 20000 resamples, seed 0x50465036",
  "frozen_before_execution": true
}
EOF
echo "population_sha256=$(sha "$EV/population.json")"

rep=1
while [ "$rep" -le "$REPS" ]; do
    case $((rep % 3)) in
        1) order="cand ref auth" ;;
        2) order="ref auth cand" ;;
        0) order="auth cand ref" ;;
    esac
    for tag in $order; do
        case $tag in
            cand) dso=$CAND ;;
            ref) dso=$REF ;;
            auth) dso=$AUTH ;;
        esac
        f="$EV/timing/raw/$tag-r$(printf %02d "$rep").out"
        taskset -c "$CPU" "$OUT/instrument/bench_pfp5" --lib "$dso" \
            "${COMMON[@]}" --prepared >"$f" 2>"$f.err" \
            || fail "$tag/r$rep: harness failed"
        grep -q '^RESULT ' "$f" || fail "$tag/r$rep: no RESULT lines"
        rp=$(sed -n 's/^LOADED realpath=\([^ ]*\).*/\1/p' "$f")
        [ "$rp" = "$(realpath "$dso")" ] || fail "$tag/r$rep: mapped $rp"
    done
    echo "rep $rep/$REPS done"
    rep=$((rep + 1))
done

{
    echo "dso_cand_sha256=$(sha "$CAND")"
    echo "dso_ref_sha256=$(sha "$REF")"
    echo "authority_sha256=$(sha "$AUTH")"
    echo "harness_source_sha256=$(sha "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c")"
    echo "harness_binary_sha256=$(sha "$OUT/instrument/bench_pfp5")"
    echo "reps=$REPS taskset=-c$CPU mode=prepared"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
} >"$EV/timing/raw/run-meta.env"
cat "$EV/timing/raw/run-meta.env"
echo "timing: done"
