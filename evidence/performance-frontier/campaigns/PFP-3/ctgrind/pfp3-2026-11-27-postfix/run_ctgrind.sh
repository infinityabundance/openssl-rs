#!/bin/sh
# run_ctgrind.sh — PFP-3 DSO-level ctgrind on the fixed-base arm.
#
# The harness is the PFP-21 source with exactly one added population,
# `mul-g-fixed`, which calls EC_POINT_mul(group, r, k, NULL, NULL, ctx) — the
# form the PFP-3 admission arm is entered from.  Every other population, the
# limb-value taint that is verified against each BIGNUM's own export, the
# LOADED/MAPS/FOREIGN identity proof, the negative control and the attribution
# script are the PFP-21 ones, unchanged.
#
# The candidate is the post-fix PFP-3 DSO rebuilt from the same clean commit
# f8d5c4b33 with the branch-free admission; the sensitivity control is the
# pre-PFP-20 artefact, unchanged.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/ctgrind/pfp3-2026-11-27-postfix/run_ctgrind.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/ctgrind/pfp3-2026-11-27-postfix
OUT=/work/court/tmp/pfp3-ctgrind-postfix
BIN="$OUT/instrument/pfp3_dso_ct"
A="$OUT/a/libcrypto.so.3"
C=/work/court/tmp/pfp2-fix/distribution/libcrypto.so.3
EXPECT_A=ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053
EXPECT_C=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
MODES="control mul-g mul-p mul-g-fixed mul-g-bytes sign sign-ex sign-ex-k"

fail() { printf 'PFP3-CTGRIND STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$A" ] || fail "candidate DSO missing: $A"
[ -f "$C" ] || fail "sensitivity DSO missing: $C"
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate digest $(sha "$A")"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity digest $(sha "$C")"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV/raw"/*.out "$EV/raw"/*.stdout "$EV/raw"/*.tsv \
      "$EV/raw"/attrib-summary.jsonl "$EV/attrib"/*

echo "=== compile the harness (links no libcrypto) ==="
cc -O1 -g -Wall -Wextra -o "$BIN" "$EV/pfp3_dso_ct.c" -ldl
HSHA=$(sha "$BIN")
printf 'harness_source_sha256 %s\nharness_binary_sha256 %s\n' \
    "$(sha "$EV/pfp3_dso_ct.c")" "$HSHA" | tee "$EV/raw/harness.sha256"

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
for mode in $MODES; do
    if [ "$mode" = control ]; then reps=1; else reps=$REPEATS; fi
    rep=1
    while [ "$rep" -le "$reps" ]; do
        label="a/$mode/r$rep"
        printf '=== %s ===\n' "$label"
        valgrind --tool=memcheck --num-callers=24 \
            --log-file="$EV/raw/a-$mode-r$rep.out" \
            "$BIN" --lib "$A" --mode "$mode" \
            >"$EV/raw/a-$mode-r$rep.stdout" 2>&1 || true
        verify_loaded "$EV/raw/a-$mode-r$rep.stdout" "$A" "$label"
        grep -q "^RESULT mode=$mode ok=1" "$EV/raw/a-$mode-r$rep.stdout" \
            || fail "$label: operation did not succeed"
        grep -q 'marked=1' "$EV/raw/a-$mode-r$rep.stdout" \
            || { [ "$mode" = control ] || fail "$label: no secret was marked"; }
        n=$(summary "$EV/raw/a-$mode-r$rep.out")
        c=$(contexts "$EV/raw/a-$mode-r$rep.out")
        printf 'a\t%s\t%s\t%s\t%s\n' "$mode" "$rep" "${n:-0}" "${c:-0}" \
            >>"$EV/raw/valgrind-exits.tsv"
        if [ "$mode" = control ] && [ "${n:-x}" != 0 ]; then
            fail "$label: negative control reported ${n:-?} errors"
        fi
        rep=$((rep + 1))
    done
done

# --- sensitivity control: the same call shape must reach engine code --------
for rep in 1 2 3; do
    printf '=== c/mul-g-fixed/r%s (sensitivity control) ===\n' "$rep"
    valgrind --tool=memcheck --num-callers=24 \
        --log-file="$EV/raw/c-mul-g-fixed-r$rep.out" \
        "$BIN" --lib "$C" --mode mul-g-fixed \
        >"$EV/raw/c-mul-g-fixed-r$rep.stdout" 2>&1 || true
    verify_loaded "$EV/raw/c-mul-g-fixed-r$rep.stdout" "$C" "c/mul-g-fixed/r$rep"
    grep -q '^RESULT mode=mul-g-fixed ok=1' "$EV/raw/c-mul-g-fixed-r$rep.stdout" \
        || fail "c/mul-g-fixed/r$rep: operation did not succeed"
    n=$(summary "$EV/raw/c-mul-g-fixed-r$rep.out")
    c=$(contexts "$EV/raw/c-mul-g-fixed-r$rep.out")
    printf 'c\tmul-g-fixed\t%s\t%s\t%s\n' "$rep" "${n:-0}" "${c:-0}" \
        >>"$EV/raw/valgrind-exits.tsv"
done

echo "=== attribution (PFP-21 classifier, unchanged) ==="
python3 /work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/repro-2026-11-26/attribute.py \
    "$EV/attrib" "$EV/raw"/*.out >"$EV/raw/attrib-summary.jsonl"

for rep in 1 2 3; do
    f="$EV/attrib/c-mul-g-fixed-r$rep.summary.json"
    [ -f "$f" ] || fail "sensitivity control: missing $f"
    eop=$(sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$f" | head -1)
    [ "${eop:-0}" -ge 1 ] || fail "sensitivity control r$rep: engine_on_path=0"
done

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate A changed during the run"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity C changed during the run"

{
    echo "candidate_path=$A"
    echo "candidate_sha256=$(sha "$A")"
    echo "sensitivity_path=$C"
    echo "sensitivity_sha256=$(sha "$C")"
    echo "harness_source_sha256=$(sha "$EV/pfp3_dso_ct.c")"
    echo "harness_binary_sha256=$HSHA"
    echo "harness_cc=$(cc --version | head -1)"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-unknown}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$EV/raw/run-meta.env"

python3 "$EV/record_ctgrind.py" --dir "$EV" >"$EV/raw/record.txt"
cat "$EV/raw/record.txt"
echo "PASS: PFP-3 post-fix ctgrind completed (A $EXPECT_A; sensitivity C $EXPECT_C)"
