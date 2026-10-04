#!/bin/sh
#
# openssl-rs — Phase 17 downstream: prove a REAL TLS 1.3 exchange with the candidate-linked curl.
#
# Hostility: the TLS *server* is the admitted AUTHORITY's `openssl s_server` (real upstream
# OpenSSL 3.6.4), not the candidate. The client is the unmodified curl built by build.sh, linked
# against the candidate libssl/libcrypto. A full chain is verified: a CA and a server certificate
# with `subjectAltName = IP:127.0.0.1`, trusted by the client through `--cacert`.
#
# Two authority-only environment quirks are confined to the authority commands step by step:
#   * `LD_LIBRARY_PATH=$AUTHORITY/lib` — the shipped CLI otherwise resolves the system
#     (Debian 3.0.x) libssl/libcrypto and dies on missing OPENSSL_3.4.0+ version nodes.
#     It must NOT leak into the candidate curl, whose own RUNPATH is the thing under test.
#   * `OPENSSL_CONF=/dev/null` — the authority prefix ships no `ssl/openssl.cnf`, and `req`
#     fatals trying to read its compiled-in default config path.
#
# Run (court container up, build.sh already run):
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/curl/live_tls_probe.sh
#
# Environment overrides: CANDIDATE, AUTHORITY, WORK, PORT.
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/curl}
PORT=${PORT:-8443}
CURL=${CURL:-$WORK/curl-8.22.0/src/curl}

if [ ! -x "$CURL" ]; then
    echo "live_tls_probe.sh: '$CURL' not found; run build.sh first" >&2
    exit 2
fi

LIVE=$WORK/live
rm -rf "$LIVE"
mkdir -p "$LIVE"
cd "$LIVE"

OSSL="$AUTHORITY/bin/openssl"

# Authority CLI only: its bundled libs, and no default config (the prefix ships none).
run_ossl() {
    LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"
}

echo "=== authority server ==="
run_ossl version

# CA + server certificate, server cert carries SAN IP:127.0.0.1.
run_ossl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7 \
    -subj "/CN=phase17-curl test CA" -addext "basicConstraints=critical,CA:TRUE" \
    >/dev/null 2>&1
run_ossl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > server.ext
run_ossl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 7 -extfile server.ext >/dev/null 2>&1

# Authority TLS 1.3 server. `-www` answers a GET with a small status page.
LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null \
    "$OSSL" s_server -accept "$PORT" -cert server.crt -key server.key \
    -tls1_3 -www > s_server.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

# Give s_server a moment to bind; a plain sleep keeps the connection for curl.
sleep 2

echo "=== candidate-linked curl (no authority environment) ==="
echo "--- ldd (candidate libssl/libcrypto) ---"
ldd "$CURL" | grep -E 'libssl|libcrypto'
echo "--- curl -V ---"
"$CURL" -V

echo "=== live HTTPS fetch (TLS 1.3, authority s_server) ==="
set +e
"$CURL" -v --cacert ca.crt --tlsv1.3 --tls-max 1.3 \
    -o body.html -w 'http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\n' \
    "https://127.0.0.1:$PORT/"
RC=$?
set -e
echo "curl_exit=$RC"
echo "--- response body (first 3 lines) ---"
head -3 body.html 2>/dev/null || true

kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
trap - EXIT INT TERM

[ "$RC" -eq 0 ] || { echo "live_tls_probe.sh: curl FAILED (exit $RC)" >&2; exit 1; }
echo "live_tls_probe.sh: OK"
