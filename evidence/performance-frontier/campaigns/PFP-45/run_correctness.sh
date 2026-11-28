#!/bin/sh
# run_correctness.sh — PFP-45 correctness at the C ABI and on the DH preset court.
#   1. the PFP-5 161-line ABI transcript, authority vs before vs after;
#   2. the PFP-8 30-row DH preset-private keygen matrix, after vs authority,
#      with the before DSO as an old-arm witness.
#
#   bash docker/openssl-rs-court.sh exec sh \
#     evidence/performance-frontier/campaigns/PFP-45/run_correctness.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

RAW=/work/evidence/performance-frontier/campaigns/PFP-45/raw
OUT=/work/court/tmp/pfp45
ROOT=/work
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
BEFORE="$OUT/before/distribution/libcrypto.so.3"
AFTER="$OUT/after/distribution/libcrypto.so.3"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$OUT" "$RAW" "$ROOT/court/tmp/pfp8"

# --- 1. ABI transcript ---
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp5/pfp5_diff.c" -ldl -o "$OUT/pfp5_diff"
COMMON="--rsa-der $RSA_DER --dh-ffdhe2048 $FIX/ffdhe2048.hex --dh-modp2048 $FIX/modp2048.hex"
"$OUT/pfp5_diff" --lib "$AUTH"   $COMMON >"$RAW/diff-authority.txt"
"$OUT/pfp5_diff" --lib "$BEFORE" $COMMON >"$RAW/diff-before.txt"
"$OUT/pfp5_diff" --lib "$AFTER"  $COMMON >"$RAW/diff-after.txt"
for arm in before after; do
    if diff -u "$RAW/diff-authority.txt" "$RAW/diff-$arm.txt" >"$RAW/diff-$arm.patch"; then
        echo "ABI $arm: $(wc -l <"$RAW/diff-$arm.txt") lines IDENTICAL to authority"
    else
        echo "ABI $arm: MISMATCH"
        head -40 "$RAW/diff-$arm.patch"
    fi
done
echo "ABI authority lines: $(wc -l <"$RAW/diff-authority.txt")"
echo "ABI MX=$(grep -c '^MX ' "$RAW/diff-after.txt") RSA=$(grep -c '^RSA ' "$RAW/diff-after.txt") DH=$(grep -c '^DH ' "$RAW/diff-after.txt")"

# --- 2. DH keygen matrix ---
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.c" -ldl \
    -o "$ROOT/court/tmp/pfp8/keygen_matrix"
python3 "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.py" \
    --cand "$AFTER" --old "$BEFORE" \
    --out "$RAW/keygen-matrix.json" --txt "$RAW/keygen-matrix.txt" \
    >"$RAW/keygen-matrix.out" 2>&1
tail -n 6 "$RAW/keygen-matrix.out"
