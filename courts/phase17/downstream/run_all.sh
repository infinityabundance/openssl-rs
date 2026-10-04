#!/bin/sh
#
# openssl-rs -- Phase 17 downstream: the driver that (re)produces the machine-owned records.
#
# This is how `courts/phase17/downstream/<program>/result.json` and
# `forensics/atlas/downstream-corpus.json` are produced. It runs each program's harness inside
# the court container, captures the transcript, parses the measured fields with `lib/record.py`,
# aggregates with `lib/build_corpus.py`, and regenerates the prose with
# `forensics/tools/gen_downstream_evidence.py`.
#
# It does NOT run in the normal gate path -- the harnesses include multi-minute builds and live
# TLS servers. `RT-DOWNSTREAM-CORPUS` validates the *recorded* corpus and its freshness; running
# this driver is how that corpus is refreshed (and only a real re-measurement may change it).
#
# Run from the repository root, court container up:
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh --build
#
# `--build` runs each program's build.sh first if the binary is missing; without it the driver
# records whatever is already built (the container's /court prefix survives between execs, so a
# normal refresh is fast). A harness that fails is recorded as its own evidence, not hidden: this
# script sets `set -u`, never `set -e`.
set -u

ROOT=${ROOT:-/work}
DL=$ROOT/courts/phase17/downstream
LOGS=${LOGS:-/court/phase17-downstream}
BUILD=0
[ "${1:-}" = "--build" ] && BUILD=1

mkdir -p "$LOGS"

# runlog LOG COMMAND...: run under /bin/sh -c, capture combined output, never abort the driver.
runlog() {
    log=$1; shift
    echo "[run_all] $log"
    sh -c "$*" >"$LOGS/$log" 2>&1 || echo "[run_all]   (exit $?) -> $LOGS/$log"
}

# build_if_missing BINARY BUILDSCRIPT EXTRA-ENV: run build.sh only when BINARY is absent.
build_if_missing() {
    bin=$1; script=$2; env=$3
    [ "$BUILD" = 1 ] || return 0
    [ -x "$bin" ] && return 0
    runlog "$(basename "$(dirname "$script")").build" "env $env sh $script"
}

# --- curl (TLS client) ------------------------------------------------------
build_if_missing /court/curl/curl-8.22.0/src/curl "$DL/curl/build.sh" \
    "WORK=/court/curl CANDIDATE=$ROOT/artifacts/phase2/install"
CURL=/court/curl/curl-8.22.0/src/curl
runlog curl.version "$CURL -V"
runlog curl.ldd "ldd $CURL"
runlog curl.probe "sh $DL/curl/live_tls_probe.sh"

# --- nginx (TLS server) -----------------------------------------------------
build_if_missing /court/nginx/nginx-1.26.3/objs/nginx "$DL/nginx/build.sh" \
    "WORK=/court/nginx CANDIDATE=$ROOT/artifacts/phase2/install"
NGINX=/court/nginx/nginx-1.26.3/objs/nginx
runlog nginx.version "$NGINX -V 2>&1"
runlog nginx.ldd "ldd $NGINX"
runlog nginx.probe "sh $DL/nginx/serve_probe.sh"

# --- haproxy (TLS terminator in front of a plain-HTTP backend) --------------
build_if_missing /court/haproxy/haproxy-3.0.29/haproxy "$DL/haproxy/build.sh" \
    "WORK=/court/haproxy CANDIDATE=$ROOT/artifacts/phase2/install"
HAPROXY=/court/haproxy/haproxy-3.0.29/haproxy
runlog haproxy.version "$HAPROXY -vv"
runlog haproxy.ldd "ldd $HAPROXY"
runlog haproxy.probe "sh $DL/haproxy/proxy_probe.sh"

# --- CPython (ssl + hashlib consumer) ---------------------------------------
build_if_missing /court/python/Python-3.12.15/python "$DL/python/build.sh" \
    "WORK=/court/python CANDIDATE=$ROOT/artifacts/phase2/install"
PY=/court/python/Python-3.12.15/python
runlog python.version "$PY -VV; $PY -c 'import ssl;print(ssl.OPENSSL_VERSION)'"
runlog python.ldd "SSLSO=\$(find /court/python/Python-3.12.15 -name '_ssl*.so' -print -quit); echo \$SSLSO; ldd \$SSLSO"
runlog python.probe "$PY $DL/python/probe.py"
runlog python.live "sh $DL/python/live_tls_probe.sh"
runlog python.tests "sh $DL/python/run_test_ssl.sh"

# --- git (sha1/sha256 + https) ----------------------------------------------
build_if_missing /court/git/git-2.56.0/git "$DL/git/build.sh" \
    "WORK=/court/git CANDIDATE=$ROOT/artifacts/phase2/install"
GIT=/court/git/git-2.56.0/git
runlog git.version "$GIT version --build-options"
runlog git.ldd "ldd $GIT"
runlog git.hash "sh $DL/git/hash_check.sh"
runlog git.https "sh $DL/git/https_probe.sh"
runlog git.tests "sh $DL/git/run_tests.sh"

# --- OpenSSH (libcrypto-only consumer) --------------------------------------
build_if_missing /court/openssh/openssh-10.5p1/ssh "$DL/openssh/build.sh" \
    "WORK=/court/openssh CANDIDATE=$ROOT/artifacts/phase2/install"
SSH=/court/openssh/openssh-10.5p1/ssh
runlog openssh.version "$SSH -V 2>&1"
runlog openssh.ldd "ldd /court/openssh/openssh-10.5p1/sshd"
runlog openssh.probe "sh $DL/openssh/probe.sh"
runlog openssh.keyformat "sh $DL/openssh/keyformat_probe.sh"
runlog openssh.tests "sh $DL/openssh/regress_unit.sh"

# --- parse measured logs into per-program result.json -----------------------
python3 "$DL/lib/record.py" --all --logs "$LOGS" --out "$DL"
# --- aggregate + regenerate the prose from the records ----------------------
python3 "$DL/lib/build_corpus.py" --out forensics/atlas/downstream-corpus.json
python3 "$ROOT/forensics/tools/gen_downstream_evidence.py"

echo "[run_all] done: records in $DL/<program>/result.json, logs in $LOGS"
