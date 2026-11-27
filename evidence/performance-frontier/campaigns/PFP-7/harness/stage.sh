#!/usr/bin/env bash
# PFP-7 stage measurements: latency (N=1), throughput (N=large) and callgrind
# steady-state profile, candidate and authority, pinned to one core.
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
PROF=${PROF:-/work/court/tmp/pfp7/stage}
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
CPU="${PFP7_PIN_CPU:-1}"

mkdir -p "$PROF"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/evidence/performance-frontier/campaigns/PFP-7/harness/pfp7_rsa.c" \
   -ldl -o "$PROF/pfp7_rsa"

sha256sum "$DSO" "$AUTH" >"$PROF/identity.sha256"

run() { # lib tag mode iters
    taskset -c "$CPU" "$PROF/pfp7_rsa" --lib "$1" --rsa-der "$RSA_DER" \
        --mode "$3" --iters "$4" | sed "s/^RESULT/RESULT $2/"
}

for libtag in candidate authority; do
    if [ "$libtag" = candidate ]; then lib="$DSO"; else lib="$AUTH"; fi
    { for mode in priv-nopad priv-pkcs1 dec-pkcs1 dec-oaep noblind half vrfy inverse; do
          run "$lib" "$libtag" "$mode" 1
          run "$lib" "$libtag" "$mode" 200
      done ; } >"$PROF/$libtag.wall.txt" 2>"$PROF/$libtag.wall.err"
    grep '^RESULT' "$PROF/$libtag.wall.txt" || true
done

echo "=== callgrind steady state (candidate, priv-nopad N=60) ==="
valgrind --tool=callgrind --callgrind-out-file="$PROF/cg-priv.out" --quiet \
    "$PROF/pfp7_rsa" --lib "$DSO" --rsa-der "$RSA_DER" --mode priv-nopad --iters 60 \
    >"$PROF/cg-priv.stdout" 2>"$PROF/cg-priv.stderr" || true
callgrind_annotate --inclusive=no --threshold=99 "$PROF/cg-priv.out" \
    >"$PROF/cg-priv.annotate" 2>/dev/null || true
callgrind_annotate --inclusive=yes --threshold=99.99 "$PROF/cg-priv.out" \
    >"$PROF/cg-priv.inclusive.annotate" 2>/dev/null || true
sed -n '/PROGRAM TOTALS/,+14p' "$PROF/cg-priv.annotate"

echo "=== callgrind one CRT half (candidate, half N=1) ==="
valgrind --tool=callgrind --callgrind-out-file="$PROF/cg-half.out" --quiet \
    "$PROF/pfp7_rsa" --lib "$DSO" --rsa-der "$RSA_DER" --mode half --iters 1 \
    >"$PROF/cg-half.stdout" 2>"$PROF/cg-half.stderr" || true
callgrind_annotate --inclusive=no --threshold=99 "$PROF/cg-half.out" \
    >"$PROF/cg-half.annotate" 2>/dev/null || true
sed -n '/PROGRAM TOTALS/,+10p' "$PROF/cg-half.annotate"
echo STAGE_OK
