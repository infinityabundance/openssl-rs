#!/bin/sh
# run_diff63.sh — PFP-63 cross-library differential and KAT, three arms.
#
# Arms: before (pre-change DSO), after (this tree), off (this tree with the AES and
# PCLMULQDQ CPUID clear-masks applied through OPENSSL_ia32cap's `~` support). Each is
# compared byte-for-byte with the pinned authority on the complete AEAD result
# (ciphertext + tag), the open result and the tamper rejection, plus the hard-coded
# NIST GCM KATs. A single differing line is a STOP.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp63
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B=$OUT/bench_pfp63
EV=/work/evidence/performance-frontier/campaigns/PFP-63
OPS="aes128gcm-64 aes128gcm-16k aes256gcm-64 aes256gcm-16k"

run_arm() { # name dso cap
    name=$1
    dso=$2
    cap=${3:-}
    D=$OUT/diff-$name
    mkdir -p "$D"
    rm -f "$D"/*.out "$D"/*.err
    for op in $OPS; do
        if [ -n "$cap" ]; then
            OPENSSL_ia32cap="$cap" "$B" --lib "$dso" --once --op "$op" \
                >"$D/cand-$op.out" 2>"$D/cand-$op.err"
        else
            "$B" --lib "$dso" --once --op "$op" \
                >"$D/cand-$op.out" 2>"$D/cand-$op.err"
        fi
        "$B" --lib "$AUTH" --once --op "$op" >"$D/auth-$op.out" 2>"$D/auth-$op.err"
    done
    if [ -n "$cap" ]; then
        OPENSSL_ia32cap="$cap" "$B" --lib "$dso" --kat >"$D/cand-kat.out" 2>"$D/cand-kat.err"
    else
        "$B" --lib "$dso" --kat >"$D/cand-kat.out" 2>"$D/cand-kat.err"
    fi
    "$B" --lib "$AUTH" --kat >"$D/auth-kat.out" 2>"$D/auth-kat.err"
    python3 "$EV/compare_diff.py" --dir "$D" --out "$OUT/raw/diff-$name.json" \
        | tee "$OUT/raw/diff-$name.txt"
}

run_arm before "$OUT/before/libcrypto.so.3"
run_arm after "$OUT/after/libcrypto.so.3"
# Bit 25 = AES-NI (CPUID.1.ECX), bit 1 = PCLMULQDQ (CPUID.1.ECX): force both off.
run_arm off "$OUT/after/libcrypto.so.3" '~0x2000002'
# The individual arms, so each fallback is shown reachable on its own.
run_arm off-aes "$OUT/after/libcrypto.so.3" '~0x2000000'
run_arm off-pclmul "$OUT/after/libcrypto.so.3" '~0x2'
echo DIFF63_OK
