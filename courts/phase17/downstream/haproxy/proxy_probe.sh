#!/bin/sh
#
# openssl-rs — Phase 17 downstream: prove a REAL TLS 1.3 *load balancer / terminator* using the
# candidate-linked HAProxy, in front of a plain-HTTP backend.
#
# HAProxy from build.sh terminates TLS 1.3 on `127.0.0.1:$PORT` and proxies to a plain-HTTP
# `python3 -m http.server` on `127.0.0.1:$BACKEND_PORT`. The TLS exchange is observed from two
# independent clients:
#
#   (a) the admitted AUTHORITY's `openssl s_client` (real upstream OpenSSL 3.6.4) — the reference
#       client, which does not use the candidate at all;
#   (b) the candidate-linked curl from courts/phase17/downstream/curl/ — a second, independent
#       consumer of the candidate's server-side TLS.
#
# It also exercises `haproxy -c` (config check, plus a deliberately broken config as a control),
# the runtime stats socket (backend health), and 16 concurrent verified fetches.
#
# Authority-only environment quirks are confined to the authority commands, exactly as in the
# curl/nginx courts:
#   * LD_LIBRARY_PATH=$AUTHORITY/lib — the shipped CLI otherwise resolves the system (Debian
#     3.0.x) libssl/libcrypto and dies on missing OPENSSL_3.4.0+ version nodes. It must NOT leak
#     into HAProxy or the candidate curl, whose RUNPATHs are the thing under test.
#   * OPENSSL_CONF=/dev/null — the authority prefix ships no ssl/openssl.cnf.
#
# The s_client probes are wrapped in `timeout`, and every curl in `--max-time`, because the
# candidate intermittently stalls a connection; a 124 or a curl timeout is a defect to capture,
# not a reason for the probe to hang.
#
# Run (court container up, build.sh already run):
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/haproxy/proxy_probe.sh
#
# Environment overrides: CANDIDATE, AUTHORITY, WORK, PORT, BACKEND_PORT, CURL, HAPROXY.
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/haproxy}
HAPROXY_BIN=${HAPROXY:-$WORK/haproxy-3.0.29/haproxy}
CURL=${CURL:-/court/curl/curl-8.22.0/src/curl}
PORT=${PORT:-18445}
BACKEND_PORT=${BACKEND_PORT:-18081}

if [ ! -x "$HAPROXY_BIN" ]; then
    echo "proxy_probe.sh: '$HAPROXY_BIN' not found; run build.sh first" >&2
    exit 2
fi
if [ ! -x "$CURL" ]; then
    echo "proxy_probe.sh: candidate curl '$CURL' not found;" >&2
    echo "  run courts/phase17/downstream/curl/build.sh first" >&2
    exit 2
fi

PROBE=$WORK/probe

# kill_ours: SIGKILL leftovers (from an aborted run) by /proc/PID/comm.
kill_ours() {
    for p in /proc/[0-9]*; do
        c=$(cat "$p/comm" 2>/dev/null || true)
        case "$c" in
            haproxy|python3) kill -9 "${p#/proc/}" 2>/dev/null || true ;;
        esac
    done
}

# is_port_free PORT: true unless /proc/net/tcp holds a LISTEN socket on that v4 port. The
# court container is long-lived and previous slices leave servers behind; without this check a
# squatter on the chosen port answers in place of HAProxy and silently fakes a result.
is_port_free() {
    _h=$(printf '%04X' "$1")
    awk -v h=":$_h" 'BEGIN{free=1} $2 ~ h"$" && $4=="0A" {free=0} END{exit free?0:1}' /proc/net/tcp
}

for _p in "$PORT" "$BACKEND_PORT"; do
    if ! is_port_free "$_p"; then
        echo "proxy_probe.sh: port $_p is already in use; refusing to run (a squatter would" >&2
        echo "  answer in HAProxy's place). Free it or override PORT/BACKEND_PORT." >&2
        exit 2
    fi
done

rm -rf "$PROBE"
mkdir -p "$PROBE/docroot" "$PROBE/run"
kill_ours

OSSL="$AUTHORITY/bin/openssl"
# aossl_to SECONDS ARGS...: authority CLI under a wall-clock bound, with its own libs/config.
aossl_to() {
    _t=$1; shift
    timeout "$_t" env LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"
}

# --- fixed docroot (served by the plain-HTTP backend) ------------------------
printf 'phase17-haproxy-ok\n' > "$PROBE/docroot/index.html"
dd if=/dev/zero bs=1024 count=64 2>/dev/null | tr '\0' 'A' > "$PROBE/docroot/big.txt"

# --- CA + server certificate (SAN IP:127.0.0.1), signed by the authority openssl -----------
echo "=== authority signer ==="
timeout 20 env LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" version
aossl_to 30 req -x509 -newkey rsa:2048 -nodes -keyout "$PROBE/ca.key" -out "$PROBE/ca.crt" -days 7 \
    -subj "/CN=phase17-haproxy test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
aossl_to 30 req -newkey rsa:2048 -nodes -keyout "$PROBE/server.key" -out "$PROBE/server.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > "$PROBE/server.ext"
aossl_to 30 x509 -req -in "$PROBE/server.csr" -CA "$PROBE/ca.crt" -CAkey "$PROBE/ca.key" \
    -CAcreateserial -out "$PROBE/server.crt" -days 7 -extfile "$PROBE/server.ext" >/dev/null 2>&1
aossl_to 20 x509 -in "$PROBE/server.crt" -noout -subject -ext subjectAltName
# HAProxy's `crt` wants one PEM carrying the key (and, here, the leaf cert; the CA is not needed).
cat "$PROBE/server.crt" "$PROBE/server.key" > "$PROBE/server.pem"

# --- HAProxy configuration: TLS 1.3 termination in front of the plain HTTP backend ----------
cat > "$PROBE/haproxy.cfg" <<EOF
global
    maxconn 200
    log stdout format raw local0 info
    stats socket $PROBE/run/admin.sock mode 600 level admin

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-request 10s

frontend fe_tls
    bind 127.0.0.1:$PORT ssl crt $PROBE/server.pem ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3
    default_backend be_http

backend be_http
    balance roundrobin
    option httpchk GET /index.html
    http-check expect status 200
    server s1 127.0.0.1:$BACKEND_PORT check inter 500ms fall 2 rise 2
EOF

echo "=== (c0) haproxy -c -f (config check) ==="
"$HAPROXY_BIN" -c -f "$PROBE/haproxy.cfg"

echo "=== (c0b) config-check control: a broken config must be rejected ==="
sed 's/^frontend fe_tls/frontend fe_tls\n    this_is_not_a_keyword 1/' "$PROBE/haproxy.cfg" > "$PROBE/broken.cfg"
set +e
"$HAPROXY_BIN" -c -f "$PROBE/broken.cfg" > "$PROBE/broken.out" 2>&1
BROKEN_RC=$?
set -e
echo "broken_config_exit=$BROKEN_RC (non-zero expected)"
grep -m1 -iE 'error|alert|unknown' "$PROBE/broken.out" || true

# --- start the plain-HTTP backend (python stdlib) ----------------------------
echo "=== start plain-HTTP backend ==="
python3 -m http.server "$BACKEND_PORT" --bind 127.0.0.1 --directory "$PROBE/docroot" \
    > "$PROBE/backend.log" 2>&1 &
BACKEND_PID=$!
# --- start HAProxy (foreground, owned by this shell) ------------------------
echo "=== start haproxy (candidate-linked) ==="
"$HAPROXY_BIN" -db -f "$PROBE/haproxy.cfg" -p "$PROBE/run/haproxy.pid" \
    > "$PROBE/haproxy.log" 2>&1 &
HAPROXY_PID=$!

# HAProxy binds first, then daemonizes: if the bind failed it exits before doing any TLS. Detect
# that immediately instead of letting the readiness loop time out.
sleep 0.5
if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
    HRC=0; wait "$HAPROXY_PID" 2>/dev/null || HRC=$?
    echo "proxy_probe.sh: haproxy exited at startup (exit=$HRC); log:" >&2
    sed -n '1,20p' "$PROBE/haproxy.log" >&2
    exit 3
fi

cleanup() {
    kill -TERM "$HAPROXY_PID" 2>/dev/null || true
    kill -TERM "$BACKEND_PID" 2>/dev/null || true
    sleep 0.3
    kill -9 "$HAPROXY_PID" "$BACKEND_PID" 2>/dev/null || true
    kill_ours
}
trap cleanup EXIT INT TERM

# Wait for the listener to answer a verified HTTPS request through the backend.
i=0
while [ "$i" -lt 60 ]; do
    if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
        HRC=0; wait "$HAPROXY_PID" 2>/dev/null || HRC=$?
        echo "proxy_probe.sh: haproxy DIED during readiness (exit=$HRC; 139=SIGSEGV, 134=SIGABRT)" >&2
        sed -n '1,20p' "$PROBE/haproxy.log" >&2
        exit 3
    fi
    if [ "$("$CURL" -s --max-time 5 --cacert "$PROBE/ca.crt" -o /dev/null -w '%{http_code}' \
            "https://127.0.0.1:$PORT/index.html" 2>/dev/null)" = "200" ]; then break; fi
    i=$((i + 1)); sleep 0.1
done
echo "haproxy_pid=$HAPROXY_PID backend_pid=$BACKEND_PID ready_attempts=$i/60"

# --- (a) authority openssl s_client ------------------------------------------
echo "=== (a) authority openssl s_client ==="
printf 'GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' > "$PROBE/req.txt"

echo "--- (a1) -brief: TLS version + verification ---"
set +e
aossl_to 10 s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -CAfile "$PROBE/ca.crt" -servername 127.0.0.1 -verify_ip 127.0.0.1 -verify_return_error \
    -brief < "$PROBE/req.txt" > "$PROBE/a1.out" 2> "$PROBE/a1.err"
A1_RC=$?
set -e
echo "a1_exit=$A1_RC"
grep -E "Protocol version|Ciphersuite|Verification|Peer certificate" "$PROBE/a1.err" || true

echo "--- (a2) -quiet: decrypted HTTP response ---"
set +e
aossl_to 8 s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -CAfile "$PROBE/ca.crt" -servername 127.0.0.1 -verify_ip 127.0.0.1 -verify_return_error \
    -quiet < "$PROBE/req.txt" > "$PROBE/a2.out" 2> "$PROBE/a2.err"
A2_RC=$?
set -e
echo "a2_exit=$A2_RC (124 = server never closed the connection)"
grep -E "HTTP/1|phase17-haproxy-ok" "$PROBE/a2.out" || true
A_PROTO=$(grep -cE "Protocol version: TLSv1.3" "$PROBE/a1.err" || true)
A_OK=$(grep -cE "Verification: OK" "$PROBE/a1.err" || true)
A_HTTP=$(grep -c "200 OK" "$PROBE/a2.out" || true)

# --- (b) candidate-linked curl ----------------------------------------------
echo "=== (b) candidate-linked curl (TLS 1.3 + verify + HTTP 200 through the proxy) ==="
echo "--- ldd (candidate libssl/libcrypto) ---"
ldd "$CURL" | grep -E 'libssl|libcrypto'
set +e
"$CURL" -v --max-time 15 --cacert "$PROBE/ca.crt" --tlsv1.3 --tls-max 1.3 \
    -o "$PROBE/body.html" -w 'http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\n' \
    "https://127.0.0.1:$PORT/index.html" > "$PROBE/curl.out" 2> "$PROBE/curl.err"
B_RC=$?
set -e
echo "curl_exit=$B_RC"
grep -E "SSL connection using|subjectAltName|SSL certificate verified|< HTTP" "$PROBE/curl.err" || true
cat "$PROBE/curl.out"
echo "body: $(cat "$PROBE/body.html" 2>/dev/null || true)"

echo "=== (b2) candidate curl, UNRELATED CA (must FAIL verification) ==="
aossl_to 30 req -x509 -newkey rsa:2048 -nodes -keyout "$PROBE/other.key" -out "$PROBE/other-ca.crt" \
    -days 7 -subj "/CN=phase17-haproxy unrelated CA" -addext "basicConstraints=critical,CA:TRUE" \
    >/dev/null 2>&1
set +e
"$CURL" -sS --max-time 15 --cacert "$PROBE/other-ca.crt" --tlsv1.3 --tls-max 1.3 \
    -o /dev/null -w 'neg_http_code=%{http_code}\nneg_ssl_verify_result=%{ssl_verify_result}\n' \
    "https://127.0.0.1:$PORT/index.html" 2> "$PROBE/curl_neg.err"
NEGRC=$?
set -e
echo "curl_negative_exit=$NEGRC"
grep -E 'neg_http_code|neg_ssl_verify_result' "$PROBE/curl_neg.err" 2>/dev/null || cat "$PROBE/curl_neg.err"

# --- (c) runtime stats socket: backend health --------------------------------
echo "=== (c1) runtime stats socket: backend server state ==="
python3 - "$PROBE/run/admin.sock" <<'PY' || true
import socket, sys, csv, io
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b"show stat\n")
data = b""
while True:
    b = s.recv(65536)
    if not b:
        break
    data += b
s.close()
lines = data.decode(errors="replace").splitlines()
# HAProxy's `show stat` header line is prefixed with `# `; strip it so DictReader sees clean keys.
if lines and lines[0].startswith("# "):
    lines[0] = lines[0][2:]
rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
for r in rows:
    if r.get("pxname") in ("be_http",) and r.get("svname") in ("s1", "BACKEND"):
        print("  %s/%s status=%s check=%s" % (r["pxname"], r["svname"], r.get("status", ""), r.get("check_status", "")))
PY

# --- (c2) concurrent verified fetches ----------------------------------------
echo "=== (c2) 16 concurrent verified fetches through the proxy ==="
CONC=$PROBE/conc
rm -rf "$CONC"; mkdir -p "$CONC"
T0=$(date +%s)
CURL_PIDS=
i=1
while [ "$i" -le 16 ]; do
    (
        "$CURL" -sS --max-time 20 --cacert "$PROBE/ca.crt" --tlsv1.3 --tls-max 1.3 \
            -o "$CONC/body.$i" -w '%{http_code}\n' \
            "https://127.0.0.1:$PORT/index.html" > "$CONC/code.$i" 2> "$CONC/err.$i"
    ) &
    CURL_PIDS="$CURL_PIDS $!"
    i=$((i + 1))
done
# Wait only for the curls (a bare `wait` would also wait for the foreground haproxy).
# shellcheck disable=SC2086
wait $CURL_PIDS || true
T1=$(date +%s)
CONC_OK=0
for f in "$CONC"/code.*; do [ "$(cat "$f")" = "200" ] && CONC_OK=$((CONC_OK + 1)); done
echo "concurrent_200s=$CONC_OK/16 elapsed=$((T1 - T0))s"
grep -h . "$CONC"/err.* 2>/dev/null | sort -u | sed 's/^/  err: /' || true

# --- server error inventory --------------------------------------------------
echo "=== haproxy log inventory (stderr/stdout) ==="
grep -m1 -E 'HAProxy version|OpenSSL version' "$PROBE/haproxy.log" || true
grep -cE 'SSL handshake|handshake failure|Connection reset|error' "$PROBE/haproxy.log" || true
grep -E 'error|alert' "$PROBE/haproxy.log" | sort -u | head -10 || true

echo "=== summary ==="
echo "A_tls13_handshake=$A_PROTO A_verification_ok=$A_OK A_http200=$A_HTTP a2_close_hang=$([ "$A2_RC" = 124 ] && echo yes || echo no)"
echo "B_curl_exit=$B_RC B_http_code=$(sed -n 's/^http_code=//p' "$PROBE/curl.out") B_neg_exit=$NEGRC B_broken_cfg_exit=$BROKEN_RC"
echo "C_concurrent_200s=$CONC_OK/16"
echo "proxy_probe.sh: done"
