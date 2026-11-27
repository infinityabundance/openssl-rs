#!/bin/sh
# run_abi_diff.sh — byte-identical ABI transcript for every variant against the
# authority (PFP-5's pfp5_diff.c, unmodified; the 161-line transcript).
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/run_abi_diff.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
RSA_DER=/work/courts/phase18/timing/fixtures/rsa2048.der
FIX=/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures

mkdir -p "$EV/differential/raw"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    /work/courts/performance-frontier/pfp5/pfp5_diff.c -ldl \
    -o "$OUT/instrument/pfp5_diff"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

"$OUT/instrument/pfp5_diff" --lib "$AUTH" "${COMMON[@]}" \
    >"$EV/differential/raw/authority.txt"

: >"$EV/differential/raw/summary.txt"
for tag in a b c d; do
    dso="$OUT/$tag/distribution/libcrypto.so.3"
    out="$EV/differential/raw/$tag.txt"
    "$OUT/instrument/pfp5_diff" --lib "$dso" "${COMMON[@]}" >"$out"
    lines=$(wc -l <"$out")
    auth_lines=$(wc -l <"$EV/differential/raw/authority.txt")
    if cmp -s "$EV/differential/raw/authority.txt" "$out"; then
        result=IDENTICAL
    else
        result=MISMATCH
    fi
    mx=$(grep -c '^MX ' "$out" || true)
    rsa=$(grep -c '^RSA ' "$out" || true)
    dh=$(grep -c '^DH ' "$out" || true)
    printf '%s lines=%s authority_lines=%s result=%s MX=%s RSA=%s DH=%s\n' \
        "$tag" "$lines" "$auth_lines" "$result" "$mx" "$rsa" "$dh" \
        | tee -a "$EV/differential/raw/summary.txt"
done

{
    echo "harness_source_sha256=$(sha256sum /work/courts/performance-frontier/pfp5/pfp5_diff.c | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/instrument/pfp5_diff" | awk '{print $1}')"
    echo "authority_sha256=$(sha256sum "$AUTH" | awk '{print $1}')"
    for tag in a b c d; do
        echo "dso_${tag}_sha256=$(sha256sum "$OUT/$tag/distribution/libcrypto.so.3" | awk '{print $1}')"
    done
} >"$EV/differential/raw/identity.txt"
cat "$EV/differential/raw/identity.txt"
echo "abi differential: done"
