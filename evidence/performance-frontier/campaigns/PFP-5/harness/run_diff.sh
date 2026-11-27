#!/usr/bin/env bash
# PFP-5 authority differential: candidate DSO vs OpenSSL 3.6.4 production.
set -euo pipefail
ROOT=/work
BUILD=/work/court/tmp/pfp5/build
PROF=/work/court/tmp/pfp5/profile
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$PROF/diff"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp5/pfp5_diff.c" -ldl -o "$PROF/pfp5_diff"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

echo "=== candidate ==="
"$PROF/pfp5_diff" --lib "$DSO" "${COMMON[@]}" >"$PROF/diff/candidate.txt"
echo "=== authority ==="
"$PROF/pfp5_diff" --lib "$AUTH" "${COMMON[@]}" >"$PROF/diff/authority.txt"

echo "candidate lines: $(wc -l <"$PROF/diff/candidate.txt")"
echo "authority lines: $(wc -l <"$PROF/diff/authority.txt")"
if diff -u "$PROF/diff/authority.txt" "$PROF/diff/candidate.txt" >"$PROF/diff/diff.txt"; then
    echo "DIFF_RESULT=IDENTICAL"
else
    echo "DIFF_RESULT=MISMATCH"
    head -40 "$PROF/diff/diff.txt"
fi
grep -c '^MX ' "$PROF/diff/candidate.txt" | sed 's/^/MX cases: /'
grep -c '^RSA ' "$PROF/diff/candidate.txt" | sed 's/^/RSA lines: /'
grep -c '^DH ' "$PROF/diff/candidate.txt" | sed 's/^/DH lines: /'
grep '^DONE' "$PROF/diff/candidate.txt"
