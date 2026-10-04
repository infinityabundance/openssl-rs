#!/bin/sh
#
# openssl-rs — Phase 17 downstream (HAProxy): build and run sni_arg_probe.c against both libraries.
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/haproxy/sni_arg_probe.sh
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/haproxy}
SRC=/work/courts/phase17/downstream/haproxy/sni_arg_probe.c

mkdir -p "$WORK/sni"
cd "$WORK/sni"

OSSL="$AUTHORITY/bin/openssl"
aossl() { timeout 30 env LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"; }

# Self-contained cert/key pair (client does not verify, so the signer is irrelevant here).
aossl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out crt.pem -days 7 \
    -subj "/CN=localhost" >/dev/null 2>&1

build() {
    _lib=$1; _out=$2
    # --no-as-needed: the probe calls only libssl symbols, so gcc would otherwise drop -lcrypto
    # and the loader would pull libcrypto.so.3 from its transitive runpath (system 3.0.x) instead
    # of the prefix under test. Forcing both keeps the test on a single, matched library pair.
    cc -O2 -I"$_lib/include" -o "$_out" "$SRC" \
        -L"$_lib/lib" -Wl,-rpath,"$_lib/lib" -Wl,--no-as-needed -lssl -lcrypto
}

echo "=== build ==="
build "$CANDIDATE" sni_cand
build "$AUTHORITY" sni_auth

show() {
    _b=$1
    echo "--- $_b ---"
    ldd "$_b" | grep -E 'libssl|libcrypto'
    set +e
    "$_b" crt.pem key.pem
    echo "exit=$?"
    set -e
}

echo "=== candidate-linked probe (expect arg_matches=1; defect => 0) ==="
show "$WORK/sni/sni_cand"
echo "=== authority-linked probe (control, expect arg_matches=1) ==="
show "$WORK/sni/sni_auth"
