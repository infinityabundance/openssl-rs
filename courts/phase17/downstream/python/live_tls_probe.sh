#!/bin/sh
#
# openssl-rs — Phase 17 downstream: prove a REAL TLS 1.3 exchange with candidate-linked CPython.
#
# Hostility: the TLS *server* is the admitted AUTHORITY's `openssl s_server` (real upstream
# OpenSSL 3.6.4), not the candidate. The client is the unmodified CPython built by build.sh,
# linked against the candidate libssl/libcrypto. A full chain is verified: a CA and a server
# certificate with `subjectAltName = IP:127.0.0.1`, trusted by the client through
# `SSLContext.load_verify_locations`. A negative control (an unrelated CA) must be rejected,
# proving verification is enforced rather than skipped.
#
# Run (court container up, build.sh already run):
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/python/live_tls_probe.sh
#
# Environment overrides: CANDIDATE, AUTHORITY, WORK, PORT.
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/python}
PORT=${PORT:-8444}
PY=${PY:-$WORK/Python-3.12.15/python}

if [ ! -x "$PY" ]; then
    echo "live_tls_probe.sh: '$PY' not found; run build.sh first" >&2
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

# CA + server certificate (SAN IP:127.0.0.1), plus an unrelated CA for the negative control.
run_ossl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7 \
    -subj "/CN=phase17-python test CA" -addext "basicConstraints=critical,CA:TRUE" \
    >/dev/null 2>&1
run_ossl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > server.ext
run_ossl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 7 -extfile server.ext >/dev/null 2>&1

run_ossl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other-ca.crt -days 7 \
    -subj "/CN=phase17-python unrelated CA" -addext "basicConstraints=critical,CA:TRUE" \
    >/dev/null 2>&1

# Authority TLS 1.3 server. `-www` answers a GET with a small status page.
LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null \
    "$OSSL" s_server -accept "$PORT" -cert server.crt -key server.key \
    -tls1_3 -www > s_server.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

# Give s_server a moment to bind; a plain sleep keeps the connection for the client.
sleep 2

echo "=== candidate-linked CPython (no authority environment) ==="
echo "--- ldd ($PY) ---"
ldd "$PY" | grep -E 'libssl|libcrypto' || true

echo "=== live HTTPS fetch (TLS 1.3, authority s_server) ==="
set +e
"$PY" /work/courts/phase17/downstream/python/tls_client.py "$PORT" ca.crt other-ca.crt
RC=$?
set -e
echo "tls_client_exit=$RC"

# Concurrency: many simultaneous candidate-linked CPython clients against the authority s_server.
echo "=== 16 concurrent TLS clients ==="
CONC=$LIVE/conc
rm -rf "$CONC"; mkdir -p "$CONC"
i=1
PY_PIDS=
while [ "$i" -le 16 ]; do
    ( "$PY" /work/courts/phase17/downstream/python/tls_client.py "$PORT" ca.crt other-ca.crt \
        > "$CONC/out.$i" 2>&1; echo $? > "$CONC/rc.$i" ) &
    PY_PIDS="$PY_PIDS $!"
    i=$((i + 1))
done
# shellcheck disable=SC2086
wait $PY_PIDS || true
CONC_OK=0
for f in "$CONC"/rc.*; do [ "$(cat "$f")" = "0" ] && CONC_OK=$((CONC_OK + 1)); done
echo "concurrent_ok=$CONC_OK/16"

kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
trap - EXIT INT TERM

[ "$RC" -eq 0 ] || { echo "live_tls_probe.sh: FAILED (exit $RC)" >&2; exit 1; }
echo "live_tls_probe.sh: OK"
