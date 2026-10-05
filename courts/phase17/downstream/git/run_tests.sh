#!/bin/sh
#
# openssl-rs — Phase 17 downstream: run a bounded subset of Git's OWN test suite
# against the candidate-linked git built by build.sh.
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/run_tests.sh
#
# The core plumbing tests exercise object encoding and hashing (t0000 hard-codes object
# IDs; t1006/t1007 exercise cat-file/hash-object), and t0001/t0002 exercise repository
# setup. The http tests are attempted too:
#   * t5540 (WebDAV http-push) self-skips because this Git is built without expat
#     (`--without-http-push`-style; the court image ships no libexpat headers).  It is a
#     plain-HTTP path with no OpenSSL use, so nothing TLS is lost by skipping it.
#   * t5551 (smart HTTP fetch) needs an Apache httpd *and a non-root uid*.  When this
#     script runs as root and can provision both (apt apache2, a uid-1000 account), it
#     reruns t5551 as uid 1000, which is the environment the test insists on.
#
set -eu

SRC=${SRC:-/court/git/git-2.56.0}
LOGDIR=${LOGDIR:-/court/git-tests}
CORE=${CORE:-"t0000-basic t0001-init t0002-gitfile t1006-cat-file t1007-hash-object"}
HTTP=${HTTP:-"t5540-http-push-webdav t5551-http-fetch-smart"}
JUDGE_UID=${JUDGE_UID:-1000}

if [ ! -x "$SRC/git" ]; then
    echo "run_tests.sh: $SRC/git is missing; run build.sh first" >&2
    exit 2
fi

mkdir -p "$LOGDIR"
cd "$SRC"

if [ ! -x "$SRC/t/helper/test-tool" ]; then
    echo "run_tests.sh: t/helper/test-tool missing; building it" >&2
    make -j"${JOBS:-8}" t/helper/test-tool \
        OPENSSL_SHA1=YesPlease OPENSSL_SHA256=YesPlease >"$LOGDIR/build-test-tool.log" 2>&1
fi

report () {
    t=$1 rc=$2
    ok=$(grep -c '^ok ' "$LOGDIR/$t.log" 2>/dev/null || true)
    # `not ok ... # TODO known breakage` is an *expected* failure: the harness reports it,
    # still exits 0, and counts it separately.  Only genuine `not ok` lines count here.
    notok=$(grep '^not ok ' "$LOGDIR/$t.log" 2>/dev/null | grep -vc '# TODO' || true)
    todo=$(grep '^not ok ' "$LOGDIR/$t.log" 2>/dev/null | grep -c '# TODO' || true)
    skipped=$(grep -c '^ok .*# skip' "$LOGDIR/$t.log" 2>/dev/null || true)
    skipall=$(grep -m1 '# SKIP ' "$LOGDIR/$t.log" 2>/dev/null || true)
    if [ -n "$skipall" ] && [ "$ok" -eq 0 ]; then
        printf '%-28s SKIP  %s\n' "$t" "${skipall#*# SKIP }"
        return
    fi
    if [ "$rc" -eq 0 ] && [ "$notok" -eq 0 ]; then
        printf '%-28s PASS  ok=%s not-ok=%s todo=%s skipped=%s\n' "$t" "$ok" "$notok" "$todo" "$skipped"
    else
        printf '%-28s FAIL  exit=%s ok=%s not-ok=%s todo=%s skipped=%s\n' "$t" "$rc" "$ok" "$notok" "$todo" "$skipped"
        grep -E '^not ok ' "$LOGDIR/$t.log" | grep -v '# TODO' | head -20 || true
    fi
}

run_one () {
    t=$1
    shift
    if ( cd t && ./"$t".sh --verbose "$@" ) >"$LOGDIR/$t.log" 2>&1; then rc=0; else rc=$?; fi
    report "$t" "$rc"
}

run_one_as_judge () {
    t=$1
    if setpriv --reuid="$JUDGE_UID" --regid="$JUDGE_UID" --clear-groups \
          env -i HOME=/home/judge PATH=/usr/sbin:/usr/bin:/bin TERM=dumb TZ=UTC \
          sh -c "cd '$SRC/t' && ./$t.sh --verbose" >"$LOGDIR/$t.log" 2>&1; then rc=0; else rc=$?; fi
    report "$t" "$rc"
}

echo "run_tests.sh: git = $("$SRC/git" --version)"
echo "run_tests.sh: --- core tests ---"
for t in $CORE; do run_one "$t"; done

echo "run_tests.sh: --- http/curl tests ---"
run_one t5540-http-push-webdav

# t5551 must not run as root.  Provision Apache + a uid-1000 account and rerun it there.
if [ "$(id -u)" = 0 ] && command -v setpriv >/dev/null 2>&1 && command -v useradd >/dev/null 2>&1; then
    if ! command -v apache2 >/dev/null 2>&1; then
        echo "run_tests.sh: installing apache2 (HTTPD test prerequisite)"
        apt-get update >/dev/null 2>&1 \
            && apt-get install -y --no-install-recommends apache2 >/dev/null 2>&1 || true
    fi
    if command -v apache2 >/dev/null 2>&1; then
        id "$JUDGE_UID" >/dev/null 2>&1 || useradd -u "$JUDGE_UID" -m -d /home/judge -s /bin/sh judge
        chown -R "$JUDGE_UID:$JUDGE_UID" "$SRC/t"
        run_one_as_judge t5551-http-fetch-smart
    else
        echo "run_tests.sh: apache2 unavailable; t5551 will self-skip"
        run_one t5551-http-fetch-smart
    fi
else
    run_one t5551-http-fetch-smart
fi

echo "run_tests.sh: logs in $LOGDIR"
