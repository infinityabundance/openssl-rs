#!/bin/sh
# run_diff.sh — PFP-6 admission: the 161-line ABI transcript of the admitted
# CIOS default and the SOS reference twin against the production authority.
#
# The harness is PFP-5's pfp5_diff.c, unmodified.  It covers BN_mod_exp_mont_consttime
# over 256/1024/2048/3072/8192-bit moduli, RSA CRT blinded, CRT unblinded
# (RSA_blinding_off) and non-CRT, and FFDHE2048 / MODP2048 DH.  The transcript
# must be byte-identical to the authority's.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/run_diff.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
RSA_DER=/work/courts/phase18/timing/fixtures/rsa2048.der
FIX=/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures

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

mkdir -p "$EV/differential/raw"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
    /work/courts/performance-frontier/pfp5/pfp5_diff.c -ldl \
    -o "$OUT/pfp5_diff"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

"$OUT/pfp5_diff" --lib "$AUTH" "${COMMON[@]}" >"$EV/differential/raw/authority.txt"

: >"$EV/differential/raw/summary.txt"
for tag in cand ref; do
    case $tag in cand) dso=$CAND;; ref) dso=$REF;; esac
    out="$EV/differential/raw/$tag.txt"
    "$OUT/pfp5_diff" --lib "$dso" "${COMMON[@]}" >"$out"
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

grep -q 'result=IDENTICAL' "$EV/differential/raw/summary.txt" || fail "transcript mismatch"
[ "$(grep -c 'lines=161 ' "$EV/differential/raw/summary.txt")" = 2 ] \
    || fail "expected two 161-line transcripts"

{
    echo "harness_source_sha256=$(sha /work/courts/performance-frontier/pfp5/pfp5_diff.c)"
    echo "harness_binary_sha256=$(sha "$OUT/pfp5_diff")"
    echo "authority_sha256=$(sha "$AUTH")"
    echo "dso_cand_sha256=$(sha "$CAND")"
    echo "dso_ref_sha256=$(sha "$REF")"
} >"$EV/differential/raw/identity.txt"
cat "$EV/differential/raw/identity.txt"
echo "abi differential: done"
