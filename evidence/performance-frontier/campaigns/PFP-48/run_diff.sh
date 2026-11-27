#!/bin/sh
# run_diff.sh — PFP-48 correctness at the C ABI, against the VARIANT DSO.
#   1. the PFP-5 ABI transcript: authority vs baseline (old witness) vs variant;
#   2. the PFP-8 30-row DH preset-private keygen matrix: variant vs authority,
#      with the baseline as the old-arm witness (old==new).
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-48/run_diff.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-48
RAW="$EV/differential"
OUT=/work/court/tmp/pfp48
ROOT=/work
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
BEFORE="$OUT/portable/libcrypto.so.3"   # baseline encoding (old-arm witness)
CAND="$OUT/bmi2/libcrypto.so.3"         # whole-DSO +bmi2 variant (candidate)
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$RAW" "$ROOT/court/tmp/pfp8"

# --- 1. ABI transcript ---
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/pfp5_diff.c" -ldl -o "$OUT/pfp5_diff"
COMMON="--rsa-der $RSA_DER --dh-ffdhe2048 $FIX/ffdhe2048.hex --dh-modp2048 $FIX/modp2048.hex"
"$OUT/pfp5_diff" --lib "$AUTH"   $COMMON >"$RAW/diff-authority.txt"
"$OUT/pfp5_diff" --lib "$BEFORE" $COMMON >"$RAW/diff-before.txt"
"$OUT/pfp5_diff" --lib "$CAND"   $COMMON >"$RAW/diff-variant.txt"
for arm in before variant; do
    if diff -u "$RAW/diff-authority.txt" "$RAW/diff-$arm.txt" >"$RAW/diff-$arm.patch"; then
        echo "ABI $arm: $(wc -l <"$RAW/diff-$arm.txt") lines IDENTICAL to authority"
    else
        echo "ABI $arm: MISMATCH"
        head -40 "$RAW/diff-$arm.patch"
    fi
done
echo "ABI authority lines: $(wc -l <"$RAW/diff-authority.txt")"
echo "ABI MX=$(grep -c '^MX ' "$RAW/diff-variant.txt") RSA=$(grep -c '^RSA ' "$RAW/diff-variant.txt") DH=$(grep -c '^DH ' "$RAW/diff-variant.txt")"

# --- 2. DH keygen matrix (variant vs authority; baseline as the old-arm witness) ---
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.c" -ldl \
    -o "$ROOT/court/tmp/pfp8/keygen_matrix"
python3 "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.py" \
    --cand "$CAND" --old "$BEFORE" \
    --out "$RAW/keygen-matrix.json" --txt "$RAW/keygen-matrix.txt" \
    >"$RAW/keygen-matrix.out" 2>&1 || true
cat "$RAW/keygen-matrix.out"

{
    echo "harness_source_sha256=$(sha256sum "$ROOT/courts/performance-frontier/pfp5/pfp5_diff.c" | awk '{print $1}')"
    echo "authority_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "dso_before_sha256=$(sha256sum "$BEFORE" | awk '{print $1}')"
    echo "dso_variant_sha256=$(sha256sum "$CAND" | awk '{print $1}')"
} >"$RAW/identity.txt"
cat "$RAW/identity.txt"
echo "abi differential + DH court: done"
