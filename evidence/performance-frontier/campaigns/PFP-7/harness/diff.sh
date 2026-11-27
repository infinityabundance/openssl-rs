#!/usr/bin/env bash
# PFP-7 deterministic differential: candidate DSO vs the 3.6.4 authority.
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
DIR=/work/court/tmp/pfp7/diff
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
mkdir -p "$DIR"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/evidence/performance-frontier/campaigns/PFP-7/harness/pfp7_diff.c" \
   -ldl -o "$DIR/pfp7_diff"
sha256sum "$DSO" "$AUTH" >"$DIR/identity.sha256"
"$DIR/pfp7_diff" --lib "$DSO" --rsa-der "$RSA_DER" >"$DIR/candidate.txt"
"$DIR/pfp7_diff" --lib "$AUTH" --rsa-der "$RSA_DER" >"$DIR/authority.txt"
echo "candidate lines: $(wc -l <"$DIR/candidate.txt") authority lines: $(wc -l <"$DIR/authority.txt")"
if diff -u "$DIR/authority.txt" "$DIR/candidate.txt" >"$DIR/diff.txt"; then
    echo "DIFF_RESULT=IDENTICAL"
else
    echo "DIFF_RESULT=MISMATCH"; head -20 "$DIR/diff.txt"
fi
grep -c '^dec-pkcs1-mal-.* rc=0 ' "$DIR/candidate.txt" | sed 's/^/zero-length synthetic answers: /'
grep -c '^sign-' "$DIR/candidate.txt" | sed 's/^/sign lines: /'
grep -c '^dec-' "$DIR/candidate.txt" | sed 's/^/dec lines: /'
