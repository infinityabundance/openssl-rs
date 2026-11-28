#!/bin/sh
# run_diff.sh — PFP-12 cross-library differential and KAT, both arms.
#
# For each operation the complete AEAD result (ciphertext + tag), the open
# result and the tamper rejection are printed by `--once` and compared
# byte-for-byte between the candidate and the pinned authority. `--kat` adds
# the NIST GCM known-answer cases and the empty/partial AAD boundary cases.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-12
OUT=${PFP12_OUT:-/work/court/tmp/pfp12}
CAND=$OUT/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B=$OUT/bench_pfp12
D=$OUT/diff

mkdir -p "$D"
rm -f "$D"/*.out "$D"/*.err

for op in aes128gcm-64 aes128gcm-16k aes256gcm-64 aes256gcm-16k \
          chachapoly-64 chachapoly-16k sha256-16k sha512-16k; do
    "$B" --lib "$CAND" --once --op "$op" >"$D/cand-$op.out" 2>"$D/cand-$op.err"
    "$B" --lib "$AUTH" --once --op "$op" >"$D/auth-$op.out" 2>"$D/auth-$op.err"
done
"$B" --lib "$CAND" --kat >"$D/cand-kat.out" 2>"$D/cand-kat.err"
"$B" --lib "$AUTH" --kat >"$D/auth-kat.out" 2>"$D/auth-kat.err"

python3 "$EV/compare_diff.py" --dir "$D" --out "$EV/raw/diff.json"
