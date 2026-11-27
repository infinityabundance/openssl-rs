#!/bin/sh
# run_ctgrind.sh — PFP-4 DSO-level ctgrind on the signing path with the private
# scalar and the library's own nonce draw tainted.
#
# Populations:
#   control      no taint; every operation once (negative control; 0 errors)
#   sign         private scalar `d` limbs tainted, ECDSA_do_sign
#   sign-nonce   `d` tainted AND the RAND_METHOD's output marked undefined, so
#                the hash-to-nonce chain, the generated k, and the order
#                inverse's input are all secret-derived
#
# The same populations run on the PFP-3 candidate (generic order inverse) as
# "before".  The sensitivity control is the pre-PFP-20 artefact 83f67826 under
# `mul-g-fixed`, which must still report engine code on the P-256 ladder, so a
# zero on the new carrier is not vacuous.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-4/ctgrind/run_ctgrind.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-4/ctgrind
OUT=/work/court/tmp/pfp4-ctgrind
BIN="$OUT/instrument/pfp4_dso_ct"
A=/work/court/tmp/pfp4-a/distribution/libcrypto.so.3
B=/work/court/tmp/pfp3-d/distribution/libcrypto.so.3
C=/work/court/tmp/pfp2-fix/distribution/libcrypto.so.3
EXPECT_A=4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77
EXPECT_B=ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053
EXPECT_C=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
MODES="control sign sign-nonce"

fail() { printf 'PFP4-CTGRIND STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$A" ] || fail "candidate DSO missing: $A"
[ -f "$B" ] || fail "before DSO missing: $B"
[ -f "$C" ] || fail "sensitivity DSO missing: $C"
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate digest $(sha "$A")"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "before digest $(sha "$B")"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity digest $(sha "$C")"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV/raw"/*.out "$EV/raw"/*.stdout "$EV/raw"/*.tsv \
      "$EV/raw"/attrib-summary.jsonl "$EV"/attrib/*

echo "=== compile the harness (links no libcrypto) ==="
cc -O1 -g -Wall -Wextra -o "$BIN" "$EV/pfp4_dso_ct.c" -ldl
HSHA=$(sha "$BIN")
printf 'harness_source_sha256 %s\nharness_binary_sha256 %s\n' \
    "$(sha "$EV/pfp4_dso_ct.c")" "$HSHA" | tee "$EV/raw/harness.sha256"

verify_loaded() { # stdout expected_dso label
    f=$1; dso=$2; label=$3
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

summary()  { sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$1"; }
contexts() { sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$1"; }

REPEATS=3
: >"$EV/raw/valgrind-exits.tsv"
for subject in candidate before; do
    if [ "$subject" = candidate ]; then dso="$A"; else dso="$B"; fi
    for mode in $MODES; do
        if [ "$mode" = control ]; then reps=1; else reps=$REPEATS; fi
        rep=1
        while [ "$rep" -le "$reps" ]; do
            label="$subject/$mode/r$rep"
            printf '=== %s ===\n' "$label"
            valgrind --tool=memcheck --num-callers=24 \
                --log-file="$EV/raw/$subject-$mode-r$rep.out" \
                "$BIN" --lib "$dso" --mode "$mode" \
                >"$EV/raw/$subject-$mode-r$rep.stdout" 2>&1 || true
            verify_loaded "$EV/raw/$subject-$mode-r$rep.stdout" "$dso" "$label"
            grep -q "^RESULT mode=$mode ok=1" \
                "$EV/raw/$subject-$mode-r$rep.stdout" \
                || fail "$label: operation did not succeed"
            if [ "$mode" != control ]; then
                grep -q 'marked=1' "$EV/raw/$subject-$mode-r$rep.stdout" \
                    || fail "$label: no secret was marked"
            fi
            n=$(summary "$EV/raw/$subject-$mode-r$rep.out")
            c=$(contexts "$EV/raw/$subject-$mode-r$rep.out")
            printf '%s\t%s\t%s\t%s\t%s\n' "$subject" "$mode" "$rep" \
                "${n:-0}" "${c:-0}" >>"$EV/raw/valgrind-exits.tsv"
            if [ "$mode" = control ] && [ "${n:-x}" != 0 ]; then
                fail "$label: negative control reported ${n:-?} errors"
            fi
            rep=$((rep + 1))
        done
    done
done

# --- sensitivity control: the instrument still sees engine code --------------
for rep in 1 2 3; do
    printf '=== sensitivity/mul-g-fixed/r%s ===\n' "$rep"
    valgrind --tool=memcheck --num-callers=24 \
        --log-file="$EV/raw/sensitivity-mul-g-fixed-r$rep.out" \
        "$BIN" --lib "$C" --mode mul-g-fixed \
        >"$EV/raw/sensitivity-mul-g-fixed-r$rep.stdout" 2>&1 || true
    verify_loaded "$EV/raw/sensitivity-mul-g-fixed-r$rep.stdout" "$C" \
        "sensitivity/mul-g-fixed/r$rep"
    grep -q '^RESULT mode=mul-g-fixed ok=1' \
        "$EV/raw/sensitivity-mul-g-fixed-r$rep.stdout" \
        || fail "sensitivity/mul-g-fixed/r$rep: operation did not succeed"
    n=$(summary "$EV/raw/sensitivity-mul-g-fixed-r$rep.out")
    c=$(contexts "$EV/raw/sensitivity-mul-g-fixed-r$rep.out")
    printf 'sensitivity\tmul-g-fixed\t%s\t%s\t%s\n' "$rep" "${n:-0}" \
        "${c:-0}" >>"$EV/raw/valgrind-exits.tsv"
done

echo "=== attribution (PFP-2 classifier, unchanged) ==="
python3 /work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/repro-2026-11-26/attribute.py \
    "$EV/attrib" "$EV/raw"/*.out >"$EV/raw/attrib-summary.jsonl"

for rep in 1 2 3; do
    f="$EV/attrib/sensitivity-mul-g-fixed-r$rep.summary.json"
    [ -f "$f" ] || fail "sensitivity control: missing $f"
    eop=$(sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$f" | head -1)
    [ "${eop:-0}" -ge 1 ] || fail "sensitivity control r$rep: engine_on_path=0"
done

# The new carrier must have no context whose *origin* is P-256 engine code.
# A positive origin is a secret-dependent operation in the engine and a STOP.
: >"$EV/raw/engine-origins.tsv"
printf 'subject\tmode\trep\tcontexts\tengine_on_path\torigin_in_engine\n' \
    >"$EV/raw/engine-origins.tsv"
for subject in candidate before; do
    for mode in sign sign-nonce; do
        for rep in 1 2 3; do
            f="$EV/attrib/$subject-$mode-r$rep.summary.json"
            [ -f "$f" ] || fail "missing $f"
            ctx=$(sed -n 's/.*"contexts": \([0-9]*\).*/\1/p' "$f" | head -1)
            eop=$(sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$f" | head -1)
            oie=$(sed -n 's/.*"origin_in_engine": \([0-9]*\).*/\1/p' "$f" | head -1)
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$subject" "$mode" "$rep" \
                "${ctx:-0}" "${eop:-0}" "${oie:-0}" \
                >>"$EV/raw/engine-origins.tsv"
            if [ "$subject" = candidate ] && [ "${oie:-0}" -ne 0 ]; then
                fail "$subject/$mode/r$rep: $oie context(s) originate in the P-256 engine"
            fi
        done
    done
done

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate A changed during the run"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "before B changed during the run"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity C changed during the run"

{
    echo "candidate_path=$A"
    echo "candidate_sha256=$(sha "$A")"
    echo "before_path=$B"
    echo "before_sha256=$(sha "$B")"
    echo "sensitivity_path=$C"
    echo "sensitivity_sha256=$(sha "$C")"
    echo "harness_source_sha256=$(sha "$EV/pfp4_dso_ct.c")"
    echo "harness_binary_sha256=$HSHA"
    echo "harness_cc=$(cc --version | head -1)"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-unknown}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$EV/raw/run-meta.env"

echo "=== engine-origin table ==="
cat "$EV/raw/engine-origins.tsv"
echo "PASS: PFP-4 ctgrind completed (candidate $EXPECT_A)"
