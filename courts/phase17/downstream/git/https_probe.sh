#!/bin/sh
#
# openssl-rs — Phase 17 downstream: Git push + pull over https end-to-end, with every
# TLS endpoint on the candidate.
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/https_probe.sh
#
# Topology (all OpenSSL on both ends is the candidate's libssl/libcrypto):
#
#   git client (candidate-linked git-remote-https -> candidate libcurl -> candidate
#     libssl/libcrypto)
#        |  https://127.0.0.1:8443
#        v
#   nginx (courts/phase17/downstream/nginx build; candidate libssl/libcrypto)
#        |  FastCGI over a unix socket
#        v
#   fcgiwrap -> git-http-backend (candidate-linked git) -> bare repository
#
# fcgiwrap/spawn-fcgi are only glue between nginx and the CGI backend; they carry no TLS.
#
# Certificate generation is *fixture setup*, not part of the proof: the candidate's
# `openssl req` CLI is not landed (a Phase 16 boundary), so the CA and server certificate
# are minted with the admitted AUTHORITY's real upstream 3.6.4 CLI, exactly as the sibling
# curl live probe does. The TLS endpoints themselves — nginx on the server, git-remote-https
# -> libcurl on the client — are the candidate's libssl/libcrypto, and the client verifies
# the chain against its own CA (the negative arm then shows an unrelated CA is rejected).
#
set -eu

SRC=${SRC:-/court/git/git-2.56.0}
CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
AUTHORITY=${AUTHORITY:-/work/forensics/authorities/prefix/openssl-3.6.4-production}
NGINX=${NGINX:-/court/nginx/nginx-1.26.3/objs/nginx}
BASE=${BASE:-/court/git/https}
PORT=${PORT:-8443}
GIT="$SRC/git"
BACKEND="$SRC/git-http-backend"
OSSL="$AUTHORITY/bin/openssl"

for f in "$GIT" "$BACKEND" "$NGINX" "$OSSL"; do
    [ -x "$f" ] || { echo "https_probe.sh: missing executable $f" >&2; exit 2; }
done
command -v fcgiwrap >/dev/null || { echo "https_probe.sh: fcgiwrap missing" >&2; exit 2; }

# Authority CLI only, confined to fixture generation: its bundled libs (the shipped CLI
# else resolves the system 3.0.x and dies on missing OPENSSL_3.4.0+ version nodes) and no
# default config (the authority prefix ships none). This must NOT leak into the candidate
# git/nginx, whose own resolution is the thing under test.
run_ossl() { LD_LIBRARY_PATH="$AUTHORITY/lib" OPENSSL_CONF=/dev/null "$OSSL" "$@"; }

echo "https_probe.sh: git = $("$GIT" version --build-options | head -1)"
echo "https_probe.sh: fixture certs via authority CLI = $(run_ossl version 2>/dev/null)"

rm -rf "$BASE"
mkdir -p "$BASE"/{repos,body,proxy,fcgi,uwsgi,scgi,home,nginx-prefix}
chmod 755 "$BASE"

# --- 1. CA + server certificate (fixture setup via the authority CLI) -------
cd "$BASE"
run_ossl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 \
    -subj "/CN=openssl-rs-phase17-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
run_ossl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > san.ext
run_ossl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 2 -extfile san.ext >/dev/null 2>&1
# An unrelated CA for the negative arm.
run_ossl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 2 \
    -subj "/CN=unrelated-ca" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
[ -f server.crt ] || { echo "https_probe.sh: cert generation failed" >&2; exit 1; }
echo "https_probe.sh: generated CA + server cert (authority CLI, fixture only)"

# --- 2. nginx: TLS termination, FastCGI to git-http-backend -----------------
cat > "$BASE/nginx.conf" <<EOF
user root;
worker_processes 1;
pid $BASE/nginx.pid;
error_log $BASE/nginx-error.log info;
events { worker_connections 64; }
http {
    client_body_temp_path $BASE/body;
    proxy_temp_path $BASE/proxy;
    fastcgi_temp_path $BASE/fcgi;
    uwsgi_temp_path $BASE/uwsgi;
    scgi_temp_path $BASE/scgi;
    access_log $BASE/access.log;
    server {
        listen 127.0.0.1:$PORT ssl;
        server_name localhost;
        ssl_certificate $BASE/server.crt;
        ssl_certificate_key $BASE/server.key;
        ssl_protocols TLSv1.3 TLSv1.2;
        location / {
            fastcgi_param QUERY_STRING \$query_string;
            fastcgi_param REQUEST_METHOD \$request_method;
            fastcgi_param CONTENT_TYPE \$content_type;
            fastcgi_param CONTENT_LENGTH \$content_length;
            fastcgi_param SERVER_PROTOCOL \$server_protocol;
            fastcgi_param REMOTE_ADDR \$remote_addr;
            fastcgi_param SERVER_SOFTWARE nginx;
            fastcgi_param GATEWAY_INTERFACE CGI/1.1;
            fastcgi_param SCRIPT_FILENAME $BACKEND;
            fastcgi_param SCRIPT_NAME /git-http-backend;
            fastcgi_param PATH_INFO \$uri;
            fastcgi_param GIT_PROJECT_ROOT $BASE/repos;
            fastcgi_param GIT_HTTP_EXPORT_ALL "";
            fastcgi_param REMOTE_USER \$remote_user;
            fastcgi_pass unix:$BASE/fcgi.sock;
        }
    }
}
EOF

fcgiwrap -f -c 2 -s "unix:$BASE/fcgi.sock" >"$BASE/fcgiwrap.log" 2>&1 &
FCGI_PID=$!
"$NGINX" -p "$BASE/nginx-prefix" -c "$BASE/nginx.conf" -g 'daemon off;' \
    >"$BASE/nginx.log" 2>&1 &
NGINX_PID=$!
trap 'kill $NGINX_PID $FCGI_PID 2>/dev/null || true; sleep 1; kill -9 $NGINX_PID $FCGI_PID 2>/dev/null || true' EXIT

# Wait for the listener (and the unix socket) to come up.
i=0
while [ $i -lt 50 ]; do
    if [ -S "$BASE/fcgi.sock" ] && run_ossl s_client -connect "127.0.0.1:$PORT" \
        -servername localhost -CAfile "$BASE/ca.crt" </dev/null >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1)); sleep 0.2
done
[ $i -lt 50 ] || { echo "https_probe.sh: TLS listener did not come up"; cat "$BASE/nginx-error.log"; exit 1; }
echo "https_probe.sh: nginx TLS listener up on 127.0.0.1:$PORT"

# --- 3. bare repository served over Smart HTTP ------------------------------
"$GIT" init -q --bare --template="$SRC/templates/blt" "$BASE/repos/repo.git"
"$GIT" -C "$BASE/repos/repo.git" symbolic-ref HEAD refs/heads/main
"$GIT" -C "$BASE/repos/repo.git" config http.receivepack true

export GIT_CONFIG_NOSYSTEM=1
export HOME="$BASE/home"
export GIT_EXEC_PATH="$SRC"
export GIT_TEMPLATE_DIR="$SRC/templates/blt"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
export GIT_SSL_CAINFO="$BASE/ca.crt"
URL="https://127.0.0.1:$PORT/repo.git"

# --- 3a. push (client -> server) --------------------------------------------
"$GIT" init -q --template="$SRC/templates/blt" "$BASE/work"
cd "$BASE/work"
echo one > file.txt
"$GIT" add file.txt
"$GIT" commit -q -m "one"
WORK_HEAD=$("$GIT" rev-parse HEAD)
echo "https_probe.sh: local commit $WORK_HEAD"

GIT_TRACE_CURL=1 "$GIT" push "$URL" HEAD:refs/heads/main >"$BASE/push.log" 2>&1 \
    || { echo "https_probe.sh: PUSH FAILED"; cat "$BASE/push.log"; exit 1; }
echo "https_probe.sh: push ok"
grep -E 'SSL connection using|using HTTP|Connected to .* port' "$BASE/push.log" | head -4 || true
echo "https_probe.sh: server-side TLS (nginx error log) ---"
grep -E 'SSL_do_handshake|TLSv1.3|SSL' "$BASE/nginx-error.log" | head -3 || true

# --- 3b. clone + pull (server -> client) ------------------------------------
cd "$BASE"
"$GIT" clone -q "$URL" clone
CLONE_HEAD=$(git -C "$BASE/clone" rev-parse HEAD)
echo "https_probe.sh: clone HEAD $CLONE_HEAD"
[ "$CLONE_HEAD" = "$WORK_HEAD" ] || { echo "https_probe.sh: CLONE HEAD MISMATCH"; exit 1; }

cd "$BASE/work"
echo two >> file.txt
"$GIT" commit -q -am "two"
NEW_HEAD=$("$GIT" rev-parse HEAD)
"$GIT" push -q "$URL" HEAD:refs/heads/main
cd "$BASE/clone"
"$GIT" pull -q origin main
PULLED=$("$GIT" rev-parse HEAD)
echo "https_probe.sh: pull HEAD $PULLED"
[ "$PULLED" = "$NEW_HEAD" ] || { echo "https_probe.sh: PULL HEAD MISMATCH"; exit 1; }
echo "https_probe.sh: push+clone+pull over https all succeeded"

# --- 4. negative arm: unrelated CA must be rejected -------------------------
cd "$BASE"
if GIT_SSL_CAINFO="$BASE/other.crt" "$GIT" clone -q "$URL" clone_bad \
        >"$BASE/clone_bad.log" 2>&1; then
    echo "https_probe.sh: NEGATIVE ARM FAILED (unrelated CA was accepted)"; exit 1
fi
echo "https_probe.sh: negative arm ok (unrelated CA rejected):"
grep -iE 'SSL certificate problem|unable to get local issuer|certificate verify failed' \
    "$BASE/clone_bad.log" | head -2 || true

# --- 5. link evidence -------------------------------------------------------
echo "https_probe.sh: --- client git-remote-https ---"
ldd "$SRC/git-remote-https" | grep -E 'curl|libssl|libcrypto'
echo "https_probe.sh: --- server nginx ---"
ldd "$NGINX" | grep -E 'libssl|libcrypto'
echo "https_probe.sh: HTTPS PUSH/PULL PASS"
