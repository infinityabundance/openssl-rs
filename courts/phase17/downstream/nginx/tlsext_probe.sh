#!/bin/sh
#
# openssl-rs — Phase 17 downstream (nginx): contrast the candidate and the authority on the two
# setters nginx treats as booleans. nginx disables SNI / session tickets when they return 0;
# real OpenSSL returns 1. This isolates the cause of the two runtime warnings nginx emits.
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/nginx/tlsext_probe.sh
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/nginx}
SRC=/work/courts/phase17/downstream/nginx/tlsext_probe.c

mkdir -p "$WORK"

echo "=== candidate ($CANDIDATE) ==="
gcc -I"$CANDIDATE/include" -o "$WORK/tlsext_cand" "$SRC" \
    -L"$CANDIDATE/lib" -Wl,-rpath,"$CANDIDATE/lib" -lssl -lcrypto
"$WORK/tlsext_cand"

echo "=== authority ($AUTHORITY) ==="
gcc -I"$AUTHORITY/include" -o "$WORK/tlsext_auth" "$SRC" \
    -L"$AUTHORITY/lib" -Wl,-rpath,"$AUTHORITY/lib" -lssl -lcrypto
LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$WORK/tlsext_auth"
