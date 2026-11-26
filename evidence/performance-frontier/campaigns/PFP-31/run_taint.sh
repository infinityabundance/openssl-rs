#!/bin/sh
# run_taint.sh — PFP-31: per-parameter-set ctgrind and the rejection-outcome
# comparison.
#
# For ML-KEM-512, -768 and -1024 on candidate DSO 5e75b694 and authority
# 611e511d:
#
#   1. control        nothing tainted, valid ciphertext: must report 0 errors;
#   2. taint          the 64-byte keygen seed marked undefined at the
#                     EVP_PKEY_fromdata boundary, three repetitions each;
#   3. valid vs invalid under the same taint: decapsulate the valid ciphertext
#                     and a one-bit-flipped one, and compare the memcheck
#                     surface.  This is the rejection-outcome comparison; the
#                     shared-secret bytes are redacted in tainted mode, so
#                     nothing reads a secret after the taint.
#   4. authority      the same taint on the 3.6.4 authority, for the
#                     conversion-difference observation.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-31/run_taint.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-31
OUT=/work/court/tmp/pfp31
BIN="$OUT/instrument/pfp31_mlkem"
A="$OUT/../pfp29/a/distribution/libcrypto.so.3"
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
EXPECT_A=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
PARAMS="512 768 1024"
REPEATS=3

fail() { printf 'PFP31-TAINT STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
summary() { sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$1"; }
contexts() { sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$1"; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate digest $(sha "$A")"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority digest $(sha "$AUTH")"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV"/raw/control-*.out "$EV"/raw/taint-*.out "$EV"/raw/m-*.out \
      "$EV"/raw/auth-taint-*.out "$EV"/raw/*.stdout "$EV"/attrib/*

echo "=== compile the harness (links no libcrypto) ==="
cc -O1 -g -Wall -Wextra -Wno-unused-parameter -o "$BIN" "$EV/pfp31_mlkem.c" -ldl
{
    printf 'harness_source_sha256 %s\n' "$(sha "$EV/pfp31_mlkem.c")"
    printf 'harness_binary_sha256 %s\n' "$(sha "$BIN")"
    printf 'candidate_sha256 %s\n' "$(sha "$A")"
    printf 'authority_sha256 %s\n' "$(sha "$AUTH")"
    printf 'valgrind %s\n' "$(valgrind --version)"
} | tee "$EV/raw/taint-meta.txt"

verify_loaded() { # stdout expected_dso label
    f=$1; dso=$2; label=$3
    rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
    entries=$(sed -n 's/^MAPS .* entries=\([0-9]*\)/\1/p' "$f")
    foreign=$(sed -n 's/^FOREIGN libcrypto=\([0-9]*\).*/\1/p' "$f")
    [ -n "$rp" ] || fail "$label: no LOADED line"
    [ "$rp" = "$(realpath "$dso")" ] || fail "$label: mapped $rp"
    [ "${entries:-0}" -ge 1 ] || fail "$label: no maps entry"
    [ "${foreign:-x}" = 0 ] || fail "$label: foreign libcrypto ($foreign)"
}

: >"$EV/raw/taint-summary.tsv"
printf 'param\trun\terrors\tcontexts\tdecap_contexts\torigin_sites\n' \
    >>"$EV/raw/taint-summary.tsv"

record() { # param run log
    p=$1; run=$2; log=$3
    n=$(summary "$log"); c=$(contexts "$log")
    dc=$(grep -c 'at 0x[0-9A-F]*: openssl_rs::ml_kem::key::decap ' "$log" || true)
    sites=$(grep -h -A1 'Conditional jump or move' "$log" \
        | sed -n 's/.*at 0x[0-9A-F]*: \(.*\)$/\1/p' \
        | sed 's/ (in .*)//' | sort | uniq -c \
        | sed 's/^ *\([0-9]*\) /\1x /' | tr '\n' ';')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$run" "${n:-0}" "${c:-0}" \
        "${dc:-0}" "$sites" >>"$EV/raw/taint-summary.tsv"
}

for p in $PARAMS; do
    echo "=== control ML-KEM-$p (defined, valid) ==="
    valgrind --tool=memcheck --num-callers=24 \
        --log-file="$EV/raw/control-$p.out" \
        "$BIN" --lib "$A" --mode control --param "$p" \
        >"$EV/raw/control-$p.stdout" 2>&1 || true
    verify_loaded "$EV/raw/control-$p.stdout" "$A" "control/$p"
    grep -q "^RESULT mode=control param=$p ok=1" "$EV/raw/control-$p.stdout" \
        || fail "control/$p did not succeed"
    [ "$(summary "$EV/raw/control-$p.out")" = 0 ] \
        || fail "control/$p reported $(summary "$EV/raw/control-$p.out") errors"
    record "$p" control "$EV/raw/control-$p.out"

    rep=1
    while [ "$rep" -le "$REPEATS" ]; do
        echo "=== taint ML-KEM-$p r$rep ==="
        valgrind --tool=memcheck --num-callers=24 \
            --log-file="$EV/raw/taint-$p-r$rep.out" \
            "$BIN" --lib "$A" --mode taint --param "$p" \
            >"$EV/raw/taint-$p-r$rep.stdout" 2>&1 || true
        verify_loaded "$EV/raw/taint-$p-r$rep.stdout" "$A" "taint/$p/r$rep"
        grep -q '^TAINT name=kem-seed bytes=64' "$EV/raw/taint-$p-r$rep.stdout" \
            || fail "taint/$p/r$rep: nothing tainted"
        grep -q "^RESULT mode=taint param=$p ok=1" \
            "$EV/raw/taint-$p-r$rep.stdout" \
            || fail "taint/$p/r$rep: operation did not succeed"
        record "$p" "taint-r$rep" "$EV/raw/taint-$p-r$rep.out"
        rep=$((rep + 1))
    done

    for c in valid bit-00; do
        echo "=== taint ML-KEM-$p case $c ==="
        valgrind --tool=memcheck --num-callers=24 \
            --log-file="$EV/raw/m-$p-$c.out" \
            "$BIN" --lib "$A" --mode malformed --param "$p" --case "$c" --taint \
            >"$EV/raw/m-$p-$c.stdout" 2>&1 || true
        verify_loaded "$EV/raw/m-$p-$c.stdout" "$A" "m/$p/$c"
        grep -q "^CASE param=$p id=$c " "$EV/raw/m-$p-$c.stdout" \
            || fail "m/$p/$c: case row missing"
        record "$p" "case-$c" "$EV/raw/m-$p-$c.out"
    done

    echo "=== authority taint ML-KEM-$p ==="
    valgrind --tool=memcheck --num-callers=24 \
        --log-file="$EV/raw/auth-taint-$p.out" \
        "$BIN" --lib "$AUTH" --mode taint --param "$p" \
        >"$EV/raw/auth-taint-$p.stdout" 2>&1 || true
    verify_loaded "$EV/raw/auth-taint-$p.stdout" "$AUTH" "auth/$p"
    grep -q "^RESULT mode=taint param=$p ok=1" \
        "$EV/raw/auth-taint-$p.stdout" || fail "auth/$p did not succeed"
    record "$p" authority-taint "$EV/raw/auth-taint-$p.out"
done

echo "=== attribution (campaign five-way parser) ==="
python3 "$EV/../PFP-29/attrib_pfp29.py" "$EV/attrib" "$EV"/raw/taint-*.out \
    "$EV"/raw/m-*.out "$EV"/raw/auth-taint-*.out >"$EV/raw/attrib-summary.jsonl"

echo "=== rejection-outcome comparison (valid vs one-bit-flipped) ==="
: >"$EV/raw/rejection-comparison.tsv"
printf 'param\tvalid_errors\tinvalid_errors\tvalid_contexts\tinvalid_contexts\tdelta_errors\tsites_identical\n' \
    >>"$EV/raw/rejection-comparison.tsv"
for p in $PARAMS; do
    ve=$(summary "$EV/raw/m-$p-valid.out")
    ie=$(summary "$EV/raw/m-$p-bit-00.out")
    vc=$(contexts "$EV/raw/m-$p-valid.out")
    ic=$(contexts "$EV/raw/m-$p-bit-00.out")
    vs=$(grep -h -A1 'Conditional jump or move' "$EV/raw/m-$p-valid.out" \
        | sed -n 's/.*at 0x[0-9A-F]*: \(.*\)$/\1/p' | sort)
    is=$(grep -h -A1 'Conditional jump or move' "$EV/raw/m-$p-bit-00.out" \
        | sed -n 's/.*at 0x[0-9A-F]*: \(.*\)$/\1/p' | sort)
    same=no
    [ "$vs" = "$is" ] && same=yes
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$ve" "$ie" "$vc" "$ic" \
        "$((ie - ve))" "$same" >>"$EV/raw/rejection-comparison.tsv"
done

cat "$EV/raw/taint-summary.tsv"
cat "$EV/raw/rejection-comparison.tsv"
echo "taint: done"
