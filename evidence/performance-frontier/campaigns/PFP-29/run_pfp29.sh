#!/bin/sh
# run_pfp29.sh — PFP-29 one whole-path checkpoint at DSO 5e75b694.
#
# Per path, one process per memcheck run, one tainted secret each:
#
#   ecdsa-sign, ecdsa-verify (public, untainted), ecdh, rsa-crt, rsa-nocrt,
#   rsa-crt-pkcs1, dh, mlkem-decaps
#
# Then: a negative control (0 errors), a positive sensitivity control on the
# pre-PFP-20 DSO (the instrument must still see the engine path), per-path wall
# timing, the five-way attribution, and the artefact differential against the
# 3.6.4 authority 611e511d (signatures cross-verified both directions; shared
# secrets compared byte-for-byte).
#
# Every process prints the file it mapped and the runner compares
# realpath/dev/ino/size with stat(2); a mismatch, a foreign libcrypto mapping, a
# failed RESULT line, a changed DSO digest, or a non-empty negative control is a
# STOP (exit 1).
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-29/run_pfp29.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-29
OUT=/work/court/tmp/pfp29
BIN="$OUT/instrument/pfp29_paths"
A="$OUT/a/distribution/libcrypto.so.3"
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
PRE=/work/court/tmp/pfp2-fix/distribution/libcrypto.so.3
FIX="$EV/raw/rsa-fixture.txt"
EXPECT_A=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
EXPECT_PRE=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
MODES="ecdsa-sign ecdsa-sign-default ecdsa-verify ecdh rsa-crt rsa-nocrt rsa-crt-pkcs1 dh mlkem-decaps"
TIMING_MODES="ecdsa-sign ecdsa-sign-default ecdsa-verify ecdh rsa-crt rsa-nocrt dh mlkem-decaps"
REPEATS=3

fail() {
    printf 'PFP29 STOP: %s\n' "$*" >&2
    exit 1
}

sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate digest $(sha "$A")"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority digest $(sha "$AUTH")"
[ -f "$FIX" ] || fail "RSA fixture missing: $FIX"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV"/raw/*.out "$EV"/raw/*.stdout "$EV"/raw/*.tsv \
      "$EV"/raw/differential-*.txt "$EV"/raw/timing-*.stdout "$EV"/attrib/*

echo "=== compile the harness (links no libcrypto) ==="
cc -O1 -g -Wall -Wextra -o "$BIN" "$EV/pfp29_paths.c" -ldl
cc -O1 -g -Wall -Wextra -o "$OUT/instrument/pfp29_fixtures" "$EV/pfp29_fixtures.c" -ldl
{
    printf 'harness_source_sha256 %s\n' "$(sha "$EV/pfp29_paths.c")"
    printf 'harness_binary_sha256 %s\n' "$(sha "$BIN")"
    printf 'fixture_source_sha256 %s\n' "$(sha "$EV/pfp29_fixtures.c")"
    printf 'rsa_fixture_sha256 %s\n' "$(sha "$FIX")"
} | tee "$EV/raw/harness.sha256"

verify_loaded() { # stdout expected_dso label
    f=$1
    dso=$2
    label=$3
    rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
    dev=$(sed -n 's/^LOADED .* dev=\([0-9]*\) .*/\1/p' "$f")
    ino=$(sed -n 's/^LOADED .* ino=\([0-9]*\) .*/\1/p' "$f")
    size=$(sed -n 's/^LOADED .* size=\([0-9]*\).*/\1/p' "$f")
    entries=$(sed -n 's/^MAPS .* entries=\([0-9]*\).*/\1/p' "$f")
    foreign=$(sed -n 's/^FOREIGN libcrypto=\([0-9]*\).*/\1/p' "$f")
    [ -n "$rp" ] || fail "$label: no LOADED line"
    erp=$(realpath "$dso")
    edev=$(stat -c %d "$erp"); eino=$(stat -c %i "$erp"); esize=$(stat -c %s "$erp")
    [ "$rp" = "$erp" ] || fail "$label: mapped $rp, expected $erp"
    [ "$dev" = "$edev" ] || fail "$label: dev $dev != $edev"
    [ "$ino" = "$eino" ] || fail "$label: ino $ino != $eino"
    [ "$size" = "$esize" ] || fail "$label: size $size != $esize"
    [ "${entries:-0}" -ge 1 ] || fail "$label: no /proc/self/maps entry"
    [ "${foreign:-x}" = "0" ] || fail "$label: foreign libcrypto mapping ($foreign)"
}

summary() { sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$1"; }
contexts() { sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$1"; }

# --- negative control ------------------------------------------------------
echo "=== negative control: everything defined, once ==="
valgrind --tool=memcheck --num-callers=24 --log-file="$EV/raw/a-control.out" \
    "$BIN" --lib "$A" --mode control --rsa-fixture "$FIX" \
    >"$EV/raw/a-control.stdout" 2>&1 || true
verify_loaded "$EV/raw/a-control.stdout" "$A" "control"
grep -q '^RESULT mode=control ok=1' "$EV/raw/a-control.stdout" \
    || fail "control: operation did not succeed"
n=$(summary "$EV/raw/a-control.out"); c=$(contexts "$EV/raw/a-control.out")
[ "${n:-x}" = 0 ] || fail "negative control reported ${n:-?} errors"
printf 'control\t0\t%s\t%s\n' "${n:-0}" "${c:-0}" >"$EV/raw/valgrind.tsv"

# --- per-path taint --------------------------------------------------------
: >>"$EV/raw/valgrind.tsv"
for mode in $MODES; do
    rep=1
    while [ "$rep" -le "$REPEATS" ]; do
        label="a/$mode/r$rep"
        echo "=== $label ==="
        valgrind --tool=memcheck --num-callers=24 \
            --log-file="$EV/raw/a-$mode-r$rep.out" \
            "$BIN" --lib "$A" --mode "$mode" --rsa-fixture "$FIX" \
            >"$EV/raw/a-$mode-r$rep.stdout" 2>&1 || true
        verify_loaded "$EV/raw/a-$mode-r$rep.stdout" "$A" "$label"
        grep -q "^RESULT mode=$mode ok=1" "$EV/raw/a-$mode-r$rep.stdout" \
            || fail "$label: operation did not succeed"
        if [ "$mode" != ecdsa-verify ]; then
            grep -q '^TAINT ' "$EV/raw/a-$mode-r$rep.stdout" \
                || fail "$label: nothing was tainted"
        fi
        n=$(summary "$EV/raw/a-$mode-r$rep.out")
        c=$(contexts "$EV/raw/a-$mode-r$rep.out")
        printf '%s\t%s\t%s\t%s\n' "$mode" "$rep" "${n:-0}" "${c:-0}" \
            >>"$EV/raw/valgrind.tsv"
        rep=$((rep + 1))
    done
done

# --- positive sensitivity control -----------------------------------------
# The pre-PFP-20 artefact still branches on the secret coordinate in
# store_coordinate.  If this harness cannot see it, its silence on A is void.
echo "=== sensitivity control (pre-PFP-20 artefact) ==="
[ "$(sha "$PRE")" = "$EXPECT_PRE" ] || fail "sensitivity control digest $(sha "$PRE")"
valgrind --tool=memcheck --num-callers=24 --log-file="$EV/raw/pre-ecdh-r1.out" \
    "$BIN" --lib "$PRE" --mode ecdh --rsa-fixture "$FIX" \
    >"$EV/raw/pre-ecdh-r1.stdout" 2>&1 || true
verify_loaded "$EV/raw/pre-ecdh-r1.stdout" "$PRE" "pre/ecdh"
grep -q '^RESULT mode=ecdh ok=1' "$EV/raw/pre-ecdh-r1.stdout" \
    || fail "sensitivity control: operation did not succeed"

echo "=== attribution (PFP-29 five-way) ==="
python3 "$EV/attrib_pfp29.py" "$EV/attrib" "$EV/raw"/*.out \
    >"$EV/raw/attrib-summary.jsonl"

eop() { sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$1" | head -1; }
pe=$(eop "$EV/attrib/pre-ecdh-r1.summary.json")
[ "${pe:-0}" -ge 1 ] || fail "sensitivity control: engine_on_path=0"

# --- timing (defined, no valgrind) ----------------------------------------
echo "=== per-path wall timing ==="
: >"$EV/raw/timing.tsv"
for mode in $TIMING_MODES; do
    rep=1
    while [ "$rep" -le 7 ]; do
        "$BIN" --lib "$A" --mode "$mode" --rsa-fixture "$FIX" --iters 20 \
            >"$EV/raw/timing-$mode-$rep.stdout" 2>&1
        verify_loaded "$EV/raw/timing-$mode-$rep.stdout" "$A" \
            "$mode/timing/$rep"
        grep -q '^RESULT .* ok=1' "$EV/raw/timing-$mode-$rep.stdout" \
            || fail "$mode/timing/$rep: operation failed"
        ns=$(sed -n 's/^TIME .* ns_per_op=\([0-9.]*\).*/\1/p' \
                "$EV/raw/timing-$mode-$rep.stdout")
        printf '%s\t%s\t%s\n' "$mode" "$rep" "$ns" >>"$EV/raw/timing.tsv"
        rep=$((rep + 1))
    done
done

# --- differential, same fixture, fixed inputs -----------------------------
echo "=== artefact differential (candidate vs authority 611e511d) ==="
"$BIN" --lib "$A" --mode emit --rsa-fixture "$FIX" --sig-out "$OUT/cand.sig" \
    >"$EV/raw/differential-cand.txt" 2>&1
grep -q '^RESULT mode=emit ok=1' "$EV/raw/differential-cand.txt" \
    || fail "candidate emit failed"
verify_loaded "$EV/raw/differential-cand.txt" "$A" "cand/emit"
"$BIN" --lib "$AUTH" --mode emit --rsa-fixture "$FIX" --sig-out "$OUT/auth.sig" \
    >"$EV/raw/differential-auth.txt" 2>&1
grep -q '^RESULT mode=emit ok=1' "$EV/raw/differential-auth.txt" \
    || fail "authority emit failed"
verify_loaded "$EV/raw/differential-auth.txt" "$AUTH" "auth/emit"

# every observable must be byte-identical
for k in ECDSA_R ECDSA_S ECDH_SS RSA_PT DH_SS MLKEM_CT MLKEM_ENCAP_SS MLKEM_DECAP_SS; do
    cv=$(sed -n "s/^$k //p" "$EV/raw/differential-cand.txt")
    av=$(sed -n "s/^$k //p" "$EV/raw/differential-auth.txt")
    [ -n "$cv" ] || fail "differential: candidate has no $k"
    [ "$cv" = "$av" ] || fail "differential mismatch on $k"
done

# signatures cross-verified in both directions
"$BIN" --lib "$A" --mode verify-sig --sig-in "$OUT/auth.sig" \
    >"$EV/raw/verify-cand-of-auth.txt" 2>&1
grep -q '^RESULT mode=verify-sig ok=1' "$EV/raw/verify-cand-of-auth.txt" \
    || fail "candidate could not verify the authority's signature"
verify_loaded "$EV/raw/verify-cand-of-auth.txt" "$A" "cand/verify"
"$BIN" --lib "$AUTH" --mode verify-sig --sig-in "$OUT/cand.sig" \
    >"$EV/raw/verify-auth-of-cand.txt" 2>&1
grep -q '^RESULT mode=verify-sig ok=1' "$EV/raw/verify-auth-of-cand.txt" \
    || fail "authority could not verify the candidate's signature"
verify_loaded "$EV/raw/verify-auth-of-cand.txt" "$AUTH" "auth/verify"

# --- 64-case seeded differential sweep ------------------------------------
echo "=== 64-case seeded differential sweep (same seed, same cases) ==="
rm -rf "$OUT/sweep"
mkdir -p "$OUT/sweep/cand" "$OUT/sweep/auth"
"$BIN" --lib "$A" --mode sweep --rsa-fixture "$FIX" --sig-dir "$OUT/sweep/cand" \
    >"$EV/raw/sweep-cand.txt" 2>&1
grep -q '^RESULT mode=sweep ok=1' "$EV/raw/sweep-cand.txt" || fail "candidate sweep failed"
verify_loaded "$EV/raw/sweep-cand.txt" "$A" "cand/sweep"
"$BIN" --lib "$AUTH" --mode sweep --rsa-fixture "$FIX" --sig-dir "$OUT/sweep/auth" \
    >"$EV/raw/sweep-auth.txt" 2>&1
grep -q '^RESULT mode=sweep ok=1' "$EV/raw/sweep-auth.txt" || fail "authority sweep failed"
verify_loaded "$EV/raw/sweep-auth.txt" "$AUTH" "auth/sweep"

grep -E '^(ECDSA|ECDH|RSA|DH|KEM_CT|KEM_SS) ' "$EV/raw/sweep-cand.txt" \
    >"$EV/raw/sweep-cand.obs"
grep -E '^(ECDSA|ECDH|RSA|DH|KEM_CT|KEM_SS) ' "$EV/raw/sweep-auth.txt" \
    >"$EV/raw/sweep-auth.obs"
[ "$(wc -l <"$EV/raw/sweep-cand.obs")" = 384 ] \
    || fail "sweep: expected 384 observable rows (64 cases x 6 paths)"
cmp -s "$EV/raw/sweep-cand.obs" "$EV/raw/sweep-auth.obs" \
    || fail "sweep: observable mismatch between candidate and authority"

"$BIN" --lib "$A" --mode verify-sweep --sig-dir "$OUT/sweep/auth" \
    >"$EV/raw/sweep-verify-cand-of-auth.txt" 2>&1
grep -q '^VERIFY_SWEEP ok=64 cases=64' "$EV/raw/sweep-verify-cand-of-auth.txt" \
    || fail "candidate verified fewer than 64 authority signatures"
verify_loaded "$EV/raw/sweep-verify-cand-of-auth.txt" "$A" "cand/verify-sweep"
"$BIN" --lib "$AUTH" --mode verify-sweep --sig-dir "$OUT/sweep/cand" \
    >"$EV/raw/sweep-verify-auth-of-cand.txt" 2>&1
grep -q '^VERIFY_SWEEP ok=64 cases=64' "$EV/raw/sweep-verify-auth-of-cand.txt" \
    || fail "authority verified fewer than 64 candidate signatures"
verify_loaded "$EV/raw/sweep-verify-auth-of-cand.txt" "$AUTH" "auth/verify-sweep"

# --- digests after execution ----------------------------------------------
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate changed during the run"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority changed during the run"

{
    echo "candidate_path=$A"
    echo "candidate_sha256=$(sha "$A")"
    echo "authority_path=$AUTH"
    echo "authority_sha256=$(sha "$AUTH")"
    echo "sensitivity_path=$PRE"
    echo "sensitivity_sha256=$(sha "$PRE")"
    echo "harness_source_sha256=$(sha "$EV/pfp29_paths.c")"
    echo "harness_binary_sha256=$(sha "$BIN")"
    echo "fixture_sha256=$(sha "$FIX")"
    echo "differential_seed=0x5046503239505032"
    echo "differential_cases=64"
    echo "harness_cc=$(cc --version | head -1)"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$EV/raw/run-meta.env"

python3 "$EV/record_pfp29.py" --dir "$EV" >"$EV/raw/record.txt"
cat "$EV/raw/record.txt"
echo "PASS: PFP-29 whole-path run completed at $EXPECT_A"
