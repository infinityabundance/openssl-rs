#!/bin/sh
#
# openssl-rs — Phase 17 downstream: prove a REAL TLS 1.3 *server* using the candidate-linked nginx.
#
# The server under test is the unmodified nginx from build.sh, linked against the candidate
# libssl/libcrypto. The TLS exchange is observed from two independent clients:
#
#   (a) the admitted AUTHORITY's `openssl s_client` (real upstream OpenSSL 3.6.4) — the reference
#       client, which does not use the candidate at all;
#   (b) the candidate-linked curl from courts/phase17/downstream/curl/ — a second, independent
#       consumer of the candidate's server-side TLS.
#
# It then exercises the server behaviours a court cares about: `nginx -t`, HTTP keep-alive, TLS
# session resumption, a `worker_processes` change applied by `-s reload`, and concurrent clients.
#
# Two authority-only environment quirks are confined to the authority commands, exactly as in the
# curl court:
#   * LD_LIBRARY_PATH=$AUTHORITY/lib — the shipped CLI otherwise resolves the system (Debian
#     3.0.x) libssl/libcrypto and dies on missing OPENSSL_3.4.0+ version nodes. It must NOT leak
#     into nginx or the candidate curl, whose RUNPATHs are the thing under test.
#   * OPENSSL_CONF=/dev/null — the authority prefix ships no ssl/openssl.cnf.
#
# The s_client probes are wrapped in `timeout`, and every curl in `--max-time`, because the
# candidate intermittently stalls a connection; a 124 or a curl timeout is a defect to capture,
# not a reason for the probe to hang.
#
# Run (court container up, nginx build.sh already run):
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/nginx/serve_probe.sh
#
# Environment overrides: CANDIDATE, AUTHORITY, WORK, PORT, CURL, NGINX.
#
set -eu

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
WORK=${WORK:-/court/nginx}
PORT=${PORT:-9443}
CURL=${CURL:-/court/curl/curl-8.22.0/src/curl}
# nginx itself reads an environment variable named NGINX (a listener fd); consuming the override
# into a differently named shell variable and unsetting NGINX keeps it out of nginx's env.
NGINX_BIN=${NGINX:-$WORK/nginx-1.26.3/objs/nginx}
unset NGINX

if [ ! -x "$NGINX_BIN" ]; then
    echo "serve_probe.sh: '$NGINX_BIN' not found; run build.sh first" >&2
    exit 2
fi
if [ ! -x "$CURL" ]; then
    echo "serve_probe.sh: candidate curl '$CURL' not found;" >&2
    echo "  run courts/phase17/downstream/curl/build.sh first" >&2
    exit 2
fi

SERVE=$WORK/serve

# kill_ours: SIGKILL any leftover nginx (from an aborted run). nginx workers are non-dumpable,
# so /proc/PID/exe is unreadable and the match must be on comm instead.
kill_ours() {
    for p in /proc/[0-9]*; do
        [ "$(cat "$p/comm" 2>/dev/null)" = "nginx" ] && kill -9 "${p#/proc/}" 2>/dev/null || true
    done
}
# count_children PID: direct children, read from /proc (the court image has no pgrep).
count_children() {
    _m=$1; _n=0
    for d in /proc/[0-9]*; do
        _s=$(cat "$d/stat" 2>/dev/null) || continue
        _rest=${_s#*) }
        # shellcheck disable=SC2086
        set -- $_rest
        [ "${2:-}" = "$_m" ] && _n=$((_n + 1))
    done
    echo "$_n"
}
# list_children PID: each direct child's pid and title (shows a lingering "shutting down" worker).
list_children() {
    _m=$1
    for d in /proc/[0-9]*; do
        _s=$(cat "$d/stat" 2>/dev/null) || continue
        _rest=${_s#*) }
        # shellcheck disable=SC2086
        set -- $_rest
        if [ "${2:-}" = "$_m" ]; then
            printf '  child %s %s\n' "${d#/proc/}" "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)"
        fi
    done
}

rm -rf "$SERVE"
mkdir -p "$SERVE/docroot" "$SERVE/logs" "$SERVE/run" "$SERVE/conf"
kill_ours

OSSL="$AUTHORITY/bin/openssl"
run_ossl() { LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"; }
# aossl_to SECONDS ARGS...: authority CLI under a wall-clock bound.
aossl_to() {
    _t=$1; shift
    timeout "$_t" env LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"
}

# --- fixed docroot -----------------------------------------------------------
printf 'phase17-nginx-ok\n' > "$SERVE/docroot/index.html"
dd if=/dev/zero bs=1024 count=64 2>/dev/null | tr '\0' 'A' > "$SERVE/docroot/big.txt"

# --- CA + server certificate (SAN IP:127.0.0.1), signed by the authority openssl -----------
echo "=== authority signer ==="
run_ossl version
run_ossl req -x509 -newkey rsa:2048 -nodes -keyout "$SERVE/ca.key" -out "$SERVE/ca.crt" -days 7 \
    -subj "/CN=phase17-nginx test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
run_ossl req -newkey rsa:2048 -nodes -keyout "$SERVE/server.key" -out "$SERVE/server.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > "$SERVE/server.ext"
run_ossl x509 -req -in "$SERVE/server.csr" -CA "$SERVE/ca.crt" -CAkey "$SERVE/ca.key" \
    -CAcreateserial -out "$SERVE/server.crt" -days 7 -extfile "$SERVE/server.ext" >/dev/null 2>&1
run_ossl x509 -in "$SERVE/server.crt" -noout -subject -ext subjectAltName

# --- nginx configuration: HTTPS only, TLS 1.3 only ---------------------------
# client_header_timeout is shortened from its 60s default (it is the timer nginx arms around
# the HTTP SSL handshake) so that an intermittent handshake stall surfaces in 5s, not 60s.
write_conf() {
    cat > "$SERVE/conf/nginx.conf" <<EOF
worker_processes $1;
pid $SERVE/run/nginx.pid;
error_log $SERVE/logs/error.log info;

events {
    worker_connections 128;
}

http {
    access_log $SERVE/logs/access.log;
    default_type text/plain;
    sendfile off;

    server {
        listen 127.0.0.1:$PORT ssl;
        server_name 127.0.0.1;

        ssl_certificate     $SERVE/server.crt;
        ssl_certificate_key $SERVE/server.key;
        ssl_protocols       TLSv1.3;
        client_header_timeout 5s;
        ssl_session_cache   shared:SSL:1m;
        ssl_session_timeout 5m;

        root $SERVE/docroot;
        location / { }
    }
}
EOF
}
write_conf "${WORKERS:-2}"

echo "=== nginx -t ==="
"$NGINX_BIN" -t -p "$SERVE" -c "$SERVE/conf/nginx.conf"

# --- start (daemon off, owned by this shell) ---------------------------------
echo "=== start nginx ==="
"$NGINX_BIN" -p "$SERVE" -c "$SERVE/conf/nginx.conf" -g 'daemon off;' \
    > "$SERVE/nginx.stdout" 2> "$SERVE/nginx.stderr" &
MASTER=$!
cleanup() {
    "$NGINX_BIN" -p "$SERVE" -c "$SERVE/conf/nginx.conf" -s stop 2>/dev/null || true
    sleep 0.3
    kill -9 "$MASTER" 2>/dev/null || true
    kill_ours
}
trap cleanup EXIT INT TERM

# Wait for the listener to answer a verified HTTPS request.
i=0
while [ "$i" -lt 60 ]; do
    if [ "$("$CURL" -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/index.html" 2>/dev/null)" = "200" ]; then break; fi
    i=$((i + 1)); sleep 0.1
done
sed -n '1,4p' "$SERVE/nginx.stderr" || true
echo "master pid=$MASTER workers=$(count_children "$MASTER")"

# --- (a) authority s_client --------------------------------------------------
echo "=== (a) authority openssl s_client ==="
printf 'GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' > "$SERVE/req.txt"

echo "--- (a1) -brief: TLS version + verification ---"
set +e
aossl_to 10 s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -CAfile "$SERVE/ca.crt" -servername 127.0.0.1 -verify_ip 127.0.0.1 -verify_return_error \
    -brief < "$SERVE/req.txt" > "$SERVE/a1.out" 2> "$SERVE/a1.err"
A1_RC=$?
set -e
echo "a1_exit=$A1_RC"
grep -E "Protocol version|Ciphersuite|Verification|Peer certificate" "$SERVE/a1.err" || true

echo "--- (a2) -quiet: decrypted HTTP response (response says Connection: close) ---"
set +e
aossl_to 6 s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -CAfile "$SERVE/ca.crt" -servername 127.0.0.1 -verify_ip 127.0.0.1 -verify_return_error \
    -quiet < "$SERVE/req.txt" > "$SERVE/a2.out" 2> "$SERVE/a2.err"
A2_RC=$?
set -e
echo "a2_exit=$A2_RC (124 = server never closed the connection)"
grep -E "HTTP/1|phase17-nginx-ok" "$SERVE/a2.out" || true
A_PROTO=$(grep -cE "Protocol version: TLSv1.3" "$SERVE/a1.err" || true)
A_OK=$(grep -cE "Verification: OK" "$SERVE/a1.err" || true)
A_HTTP=$(grep -c "200 OK" "$SERVE/a2.out" || true)

# --- (b) candidate-linked curl ----------------------------------------------
echo "=== (b) candidate-linked curl (TLS 1.3 + verify + HTTP 200) ==="
echo "--- ldd (candidate libssl/libcrypto) ---"
ldd "$CURL" | grep -E 'libssl|libcrypto'
set +e
"$CURL" -v --max-time 15 --cacert "$SERVE/ca.crt" --tlsv1.3 --tls-max 1.3 \
    -o "$SERVE/body.html" -w 'http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\n' \
    "https://127.0.0.1:$PORT/index.html" > "$SERVE/curl.out" 2> "$SERVE/curl.err"
B_RC=$?
set -e
echo "curl_exit=$B_RC"
grep -E "SSL connection using|subjectAltName|SSL certificate verified|< HTTP" "$SERVE/curl.err" || true
cat "$SERVE/curl.out"
echo "body: $(cat "$SERVE/body.html")"

# --- (c1) HTTP keep-alive / connection reuse ---------------------------------
echo "=== (c1) keep-alive: two requests on one connection ==="
"$CURL" -sS --max-time 15 --cacert "$SERVE/ca.crt" --tlsv1.3 --tls-max 1.3 \
    -o /dev/null -o /dev/null -w 'ka_http=%{http_code} ka_num_connects=%{num_connects}\n' \
    "https://127.0.0.1:$PORT/index.html" "https://127.0.0.1:$PORT/big.txt" \
    > "$SERVE/ka.out" 2>/dev/null || true
cat "$SERVE/ka.out"

# --- (c2) TLS session resumption --------------------------------------------
echo "=== (c2) TLS 1.3 session resumption (sess_out / sess_in) ==="
# -ign_eof keeps s_client alive to receive the post-handshake session ticket, then exit when the
# server closes. A server that never closes (a defect) is bounded by the timeout.
aossl_to 10 s_client -connect "127.0.0.1:$PORT" -tls1_3 -CAfile "$SERVE/ca.crt" \
    -servername 127.0.0.1 -sess_out "$SERVE/sess.pem" -ign_eof < "$SERVE/req.txt" \
    >/dev/null 2>&1 || true
if [ -s "$SERVE/sess.pem" ]; then
    echo "session saved: yes ($(wc -c < "$SERVE/sess.pem") bytes)"
    aossl_to 10 s_client -connect "127.0.0.1:$PORT" -tls1_3 -CAfile "$SERVE/ca.crt" \
        -servername 127.0.0.1 -sess_in "$SERVE/sess.pem" -ign_eof < "$SERVE/req.txt" \
        > "$SERVE/reuse.out" 2> "$SERVE/reuse.err" || true
    echo "reused session lines: $(grep -acE 'Reused, TLSv1.3' "$SERVE/reuse.out" "$SERVE/reuse.err" || true)"
else
    echo "session saved: NO — no ticket was issued, resumption is impossible"
fi

# --- (c3) worker_processes change + reload ----------------------------------
echo "=== (c3) worker_processes 2 -> 3 via nginx -s reload ==="
OLD_WORKERS=$(count_children "$MASTER")
write_conf 3
"$NGINX_BIN" -t -q -p "$SERVE" -c "$SERVE/conf/nginx.conf"
"$NGINX_BIN" -p "$SERVE" -c "$SERVE/conf/nginx.conf" -s reload
sleep 1
NEW_MASTER=$(cat "$SERVE/run/nginx.pid")
NEW_WORKERS=$(count_children "$NEW_MASTER")
echo "workers before=$OLD_WORKERS after=$NEW_WORKERS master_before=$MASTER master_after=$NEW_MASTER"
sleep 3
echo "children 3s after reload: $(count_children "$NEW_MASTER")"
list_children "$NEW_MASTER"
"$CURL" -sS --max-time 15 --cacert "$SERVE/ca.crt" --tlsv1.3 --tls-max 1.3 \
    -o /dev/null -w 'post_reload_http=%{http_code}\n' "https://127.0.0.1:$PORT/index.html" || true

# --- (c4) concurrent clients (last: a stall here can wedge graceful shutdown) ----
echo "=== (c4) 16 concurrent verified fetches ==="
CONC=$SERVE/conc
rm -rf "$CONC"; mkdir -p "$CONC"
T0=$(date +%s)
CURL_PIDS=
i=1
while [ "$i" -le 16 ]; do
    (
        "$CURL" -sS --max-time 20 --cacert "$SERVE/ca.crt" --tlsv1.3 --tls-max 1.3 \
            -o "$CONC/body.$i" -w '%{http_code}\n' \
            "https://127.0.0.1:$PORT/index.html" > "$CONC/code.$i" 2> "$CONC/err.$i"
    ) &
    CURL_PIDS="$CURL_PIDS $!"
    i=$((i + 1))
done
# Wait only for the curls: a bare `wait` would also wait for the `daemon off` nginx master.
# shellcheck disable=SC2086
wait $CURL_PIDS || true
T1=$(date +%s)
CONC_OK=0
for f in "$CONC"/code.*; do [ "$(cat "$f")" = "200" ] && CONC_OK=$((CONC_OK + 1)); done
echo "concurrent_200s=$CONC_OK/16 elapsed=$((T1 - T0))s"
grep -h . "$CONC"/err.* 2>/dev/null | sort -u | sed 's/^/  err: /' || true

# --- server error inventory --------------------------------------------------
echo "=== nginx error.log inventory ==="
echo "SNI warnings:            $(grep -c 'tlsext support, therefore SNI' "$SERVE/logs/error.log" || true)"
echo "Session-ticket warnings: $(grep -c 'Session Tickets are not available' "$SERVE/logs/error.log" || true)"
echo "SSL_read failures:       $(grep -c 'SSL_read() failed' "$SERVE/logs/error.log" || true)"
echo "SSL handshake timeouts:  $(grep -c 'while SSL handshaking' "$SERVE/logs/error.log" || true)"
echo "--- distinct SSL_read messages ---"
grep -o 'SSL_read() failed (SSL: [^)]*)' "$SERVE/logs/error.log" | sort -u || true

echo "=== summary ==="
echo "A_tls13_handshake=$A_PROTO A_verification_ok=$A_OK A_http200=$A_HTTP a2_close_hang=$([ "$A2_RC" = 124 ] && echo yes || echo no)"
echo "B_curl_exit=$B_RC B_http_code=$(sed -n 's/^http_code=//p' "$SERVE/curl.out")"
echo "C_concurrent_200s=$CONC_OK/16 C_reload_workers=$OLD_WORKERS->$NEW_WORKERS"
echo "serve_probe.sh: done"
