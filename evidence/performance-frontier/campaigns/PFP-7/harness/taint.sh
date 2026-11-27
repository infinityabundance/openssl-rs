#!/usr/bin/env bash
# PFP-7 ctgrind at the candidate source: the RSA private operation with d,
# dmp1, dmq1, p and q tainted, plus the negative control that must fire.
set -euo pipefail
ROOT=/work
T=${TARGET:-/work/court/tmp/pfp7/test-target}
DIR=/work/court/tmp/pfp7/taint
mkdir -p "$DIR"
BIN=$(find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x -name 'openssl_rs-*' | head -n 1)
[ -n "$BIN" ] || { echo "FATAL: no test binary"; exit 1; }
echo "binary sha256: $(sha256sum "$BIN" | awk '{print $1}')"

run() { # tag env test
    tag=$1; envs=$2; test=$3
    rc=0
    env $envs valgrind --tool=memcheck --error-exitcode=99 --leak-check=no \
        --num-callers=20 --log-file="$DIR/$tag.log" \
        "$BIN" --exact "rsa::ossl::tests::$test" --nocapture --test-threads=1 \
        >"$DIR/$tag.out" 2>&1 || rc=$?
    errs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$DIR/$tag.log")
    ctxs=$(sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$DIR/$tag.log")
    printf '%s errors=%s contexts=%s valgrind_exit=%s\n' "$tag" "${errs:-?}" "${ctxs:-?}" "$rc"
    # Which functions appear in the origin/error stacks?
    grep -oE 'openssl_rs::[a-z_:A-Za-z0-9]+' "$DIR/$tag.log" | sort | uniq -c | sort -rn | head -8
}

run rsa-crt-exponents "" ctgrind_rsa_crt_secret_exponents
run rsa-crt-moduli "" ctgrind_rsa_crt_secret_moduli
run rsa-crt-moduli-control "CTGRIND_CONTROL=1" ctgrind_rsa_crt_secret_moduli
echo TAINT_OK
