#!/bin/sh
# run_diff.sh — PFP-46 correctness at the C ABI:
#   1. the PFP-5 161-line ABI transcript, authority vs before vs after;
#   2. the PFP-8 30-row DH preset-private keygen matrix, after vs authority,
#      with before as the old-arm witness (old==new).
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-46/run_diff.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-46
RAW="$EV/differential/raw"
OUT=/work/court/tmp/pfp46
ROOT=/work
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
BEFORE="$OUT/portable/libcrypto.so.3"
AFTER="$OUT/after/libcrypto.so.3"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$RAW" "$ROOT/court/tmp/pfp8"

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

# --- 2. DH keygen matrix (after vs authority; before as the old-arm witness) ---
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.c" -ldl \
    -o "$ROOT/court/tmp/pfp8/keygen_matrix"
python3 "$ROOT/courts/performance-frontier/pfp8/keygen_matrix.py" \
    --cand "$AFTER" --old "$BEFORE" \
    --out "$RAW/keygen-matrix.json" --txt "$RAW/keygen-matrix.txt" \
    >"$RAW/keygen-matrix.out" 2>&1
cat "$RAW/keygen-matrix.out"
tail -n 1 "$RAW/keygen-matrix.out"

{
    echo "harness_source_sha256=$(sha256sum "$ROOT/courts/performance-frontier/pfp5/pfp5_diff.c" | awk '{print $1}')"
    echo "authority_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    echo "dso_before_sha256=$(sha256sum "$BEFORE" | awk '{print $1}')"
    echo "dso_after_sha256=$(sha256sum "$AFTER" | awk '{print $1}')"
} >"$RAW/identity.txt"
cat "$RAW/identity.txt"
echo "abi differential + DH court: done"
