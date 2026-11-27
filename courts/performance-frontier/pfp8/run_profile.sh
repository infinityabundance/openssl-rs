#!/bin/sh
# run_profile.sh — PFP-8: key-generation and shared-secret profile at the
# current digest, named group versus explicitly-loaded group, candidate versus
# the OpenSSL 3.6.4 authority.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash courts/performance-frontier/pfp8/run_profile.sh
#
# The DSOs are arguments so the same script profiles the incumbent and a later
# candidate without editing it:
#   CAND=<candidate libcrypto.so.3> AUTH=<authority libcrypto.so.3>
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8
OUT=${PFP8_OUT:-/work/court/tmp/pfp8}
CAND=${PFP8_CAND:-/work/court/tmp/ma1/cand/distribution/libcrypto.so.3}
AUTH=${PFP8_AUTH:-/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
FIX=/work/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures

mkdir -p "$OUT" "$EV/raw"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   /work/courts/performance-frontier/pfp8/bench_pfp8.c -ldl -o "$OUT/bench_pfp8"

# Deterministic operands, identical to the PFP-5/PFP-0 construction:
#   private exponent seed 0x50524900 + bits, top bit clear, odd
#   peer value        seed 0x50454500 + bits, top bit clear, odd
# plus the RFC 7919 key-length exponent (225 bits for the 2048-bit groups).
python3 - "$EV/raw/operands.env" <<'PY'
import sys

def make(n, seed, top_set=False, odd=True):
    s = seed
    out = bytearray()
    for _ in range(n):
        s ^= (s >> 12) & 0xFFFFFFFFFFFFFFFF
        s ^= (s << 25) & 0xFFFFFFFFFFFFFFFF
        s ^= (s >> 27) & 0xFFFFFFFFFFFFFFFF
        out.append((s >> 56) & 0xFF)
    if top_set:
        out[0] |= 0x80
    else:
        out[0] &= 0x7F
    if odd:
        out[-1] |= 1
    else:
        out[-1] &= 0xFE
    return out

priv2048 = make(256, 0x50524900 + 2048)
peer2048 = make(256, 0x50454500 + 2048)
priv225 = make(29, 0x50524900 + 225)
priv225[0] &= 0x01          # 225 bits
peer225 = make(29, 0x50454500 + 225)
peer225[0] &= 0x01
with open(sys.argv[1], "w") as f:
    f.write("PRIV2048=%s\n" % priv2048.hex())
    f.write("PEER2048=%s\n" % peer2048.hex())
    f.write("PRIV225=%s\n" % priv225.hex())
    f.write("PEER225=%s\n" % peer225.hex())
PY
. "$EV/raw/operands.env"

groups="ffdhe2048:1126 ffdhe3072:1127 modp2048:1213"

run() { # lib tag op extra...
    lib=$1; tag=$2; op=$3; shift 3
    "$OUT/bench_pfp8" --lib "$lib" --op "$op" "$@" \
        >"$EV/raw/profile-$tag-$op.out" 2>"$EV/raw/profile-$tag-$op.err" || true
    grep -E '^(CHECK|RESULT)' "$EV/raw/profile-$tag-$op.out" | cut -c1-160 || true
}

echo '=== named keygen (real RNG), 5 runs ==='
for g in $groups; do
    name=${g%%:*}; nid=${g##*:}
    echo "--- $name ---"
    run "$CAND" "$name-cand" keygen --nid "$nid" --iters 20 --runs 5
    run "$AUTH" "$name-auth" keygen --nid "$nid" --iters 20 --runs 5
done

echo '=== named keygen-fixed (225-bit exponent), one check ==='
for g in $groups; do
    name=${g%%:*}; nid=${g##*:}
    echo "--- $name ---"
    run "$CAND" "$name-cand" keygen-fixed --nid "$nid" --priv "$PRIV225" --iters 5 --runs 1
    run "$AUTH" "$name-auth" keygen-fixed --nid "$nid" --priv "$PRIV225" --iters 5 --runs 1
    run "$CAND" "$name-cand-exp" keygen-fixed --params "$FIX/$name.hex" --priv "$PRIV225" --iters 5 --runs 1
done

echo '=== named compute (2048-bit exponent) ==='
for g in $groups; do
    name=${g%%:*}; nid=${g##*:}
    echo "--- $name ---"
    run "$CAND" "$name-cand" compute --nid "$nid" --priv "$PRIV2048" --peer "$PEER2048" --iters 20 --runs 5
    run "$AUTH" "$name-auth" compute --nid "$nid" --priv "$PRIV2048" --peer "$PEER2048" --iters 20 --runs 5
    run "$CAND" "$name-cand-exp" compute --params "$FIX/$name.hex" --priv "$PRIV2048" --peer "$PEER2048" --iters 20 --runs 5
done

echo '=== named compute (225-bit exponent, the RFC 7919 key length) ==='
for g in $groups; do
    name=${g%%:*}; nid=${g##*:}
    echo "--- $name ---"
    run "$CAND" "$name-cand225" compute --nid "$nid" --priv "$PRIV225" --peer "$PEER225" --iters 20 --runs 5
    run "$AUTH" "$name-auth225" compute --nid "$nid" --priv "$PRIV225" --peer "$PEER225" --iters 20 --runs 5
done

echo PROFILE_OK
