#!/bin/sh
# run_ctgrind.sh — PFP-27: DSO-level ctgrind on the artefact that contains the
# CIOS kernel, using the PFP-21 harness SOURCE UNCHANGED.
#
#   A = 5e75b694…, staging HEAD, LADDER_SCHEDULE = Sos (production default)
#   B = 12023efe…, the same source with LADDER_SCHEDULE = Cios (the only input
#       difference; see artefact-audit/build_dsos.sh)
#
# Both artefacts contain the same operations.  The population that forces the
# CIOS path is `sign` (ECDSA_do_sign -> ecdsa_sign_setup -> Fermat inverse ->
# BN_mod_exp_mont_consttime -> run_mont_ladder -> mont_mul_ladder_into).  That
# it was actually taken is proven by callgrind: the executed-instruction totals
# for `sign` differ between A and B, and for no other measured mode do they.
#
# The sensitivity control (83f67826, pre-PFP-20) must still produce
# engine_on_path >= 1 contexts, exactly as in PFP-21.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g CARGO_BUILD_JOBS=4 \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-6/ctgrind/pfp27-2026-11-26/run_ctgrind.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp27
EV=/work/evidence/performance-frontier/campaigns/PFP-6/ctgrind/pfp27-2026-11-26
HARNESS_SRC=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/pfp21_dso_ct.c
ATTRIB=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/repro-2026-11-26/attribute.py
BIN="$OUT/instrument/pfp27_dso_ct"
A="$OUT/a/distribution/libcrypto.so.3"
B="$OUT/b/distribution/libcrypto.so.3"
C=/work/court/tmp/pfp2-fix/distribution/libcrypto.so.3
EXPECT_A=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_B=12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8
EXPECT_C=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
MODES="control mul-g mul-p mul-g-bytes sign sign-ex sign-ex-k"
CG_MODES="mul-g sign sign-ex-k"

fail() { printf 'PFP27 STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest $(sha "$A")"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "B digest $(sha "$B")"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity digest $(sha "$C")"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV/raw"/*.out "$EV/raw"/*.stdout "$EV/raw"/*.cglog \
      "$EV/raw"/*.tsv "$EV/attrib"/*

echo "=== compile the PFP-21 harness unchanged ==="
cc -O1 -g -Wall -Wextra -o "$BIN" "$HARNESS_SRC" -ldl
HSHA=$(sha "$BIN")
printf 'harness_source %s\nharness_source_sha256 %s\nharness_binary_sha256 %s\n' \
    "$HARNESS_SRC" "$(sha "$HARNESS_SRC")" "$HSHA" | tee "$EV/raw/harness.sha256"

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
for tag in a b; do
    if [ "$tag" = a ]; then dso=$A; else dso=$B; fi
    for mode in $MODES; do
        if [ "$mode" = control ]; then reps=1; else reps=$REPEATS; fi
        rep=1
        while [ "$rep" -le "$reps" ]; do
            label="$tag/$mode/r$rep"
            printf '=== %s ===\n' "$label"
            valgrind --tool=memcheck --num-callers=24 \
                --log-file="$EV/raw/$tag-$mode-r$rep.out" \
                "$BIN" --lib "$dso" --mode "$mode" \
                >"$EV/raw/$tag-$mode-r$rep.stdout" 2>&1 || true
            verify_loaded "$EV/raw/$tag-$mode-r$rep.stdout" "$dso" "$label"
            grep -q "^RESULT mode=$mode ok=1" "$EV/raw/$tag-$mode-r$rep.stdout" \
                || fail "$label: operation did not succeed"
            n=$(summary "$EV/raw/$tag-$mode-r$rep.out")
            c=$(contexts "$EV/raw/$tag-$mode-r$rep.out")
            printf '%s\t%s\t%s\t%s\t%s\n' "$tag" "$mode" "$rep" \
                "${n:-0}" "${c:-0}" >>"$EV/raw/valgrind-exits.tsv"
            if [ "$mode" = control ] && [ "${n:-x}" != 0 ]; then
                fail "$label: negative control reported ${n:-?} errors"
            fi
            rep=$((rep + 1))
        done
    done
done

# --- sensitivity control: pre-PFP-20 engine branch must still fire ---------
for rep in 1 2 3; do
    printf '=== c/mul-g/r%s (sensitivity control) ===\n' "$rep"
    valgrind --tool=memcheck --num-callers=24 \
        --log-file="$EV/raw/c-mul-g-r$rep.out" \
        "$BIN" --lib "$C" --mode mul-g \
        >"$EV/raw/c-mul-g-r$rep.stdout" 2>&1 || true
    verify_loaded "$EV/raw/c-mul-g-r$rep.stdout" "$C" "c/mul-g/r$rep"
    grep -q '^RESULT mode=mul-g ok=1' "$EV/raw/c-mul-g-r$rep.stdout" \
        || fail "c/mul-g/r$rep: operation did not succeed"
    n=$(summary "$EV/raw/c-mul-g-r$rep.out")
    c=$(contexts "$EV/raw/c-mul-g-r$rep.out")
    printf 'c\tmul-g\t%s\t%s\t%s\n' "$rep" "${n:-0}" "${c:-0}" \
        >>"$EV/raw/valgrind-exits.tsv"
done

echo "=== attribution (campaign classifier, unchanged) ==="
python3 "$ATTRIB" "$EV/attrib" "$EV/raw"/*.out >"$EV/raw/attrib-summary.jsonl"

for rep in 1 2 3; do
    f="$EV/attrib/c-mul-g-r$rep.summary.json"
    [ -f "$f" ] || fail "sensitivity control: missing $f"
    eop=$(sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$f" | head -1)
    [ "${eop:-0}" -ge 1 ] || fail "sensitivity control r$rep: engine_on_path=0"
done

# --- reachability: does the schedule selection change executed instructions?
echo "=== callgrind instruction counts (A vs B) ==="
: >"$EV/raw/callgrind.tsv"
for tag in a b; do
    if [ "$tag" = a ]; then dso=$A; else dso=$B; fi
    for mode in $CG_MODES; do
        for iters in 0 64; do
            valgrind --tool=callgrind \
                --callgrind-out-file="$EV/raw/cg-$tag-$mode-$iters.cglog" \
                "$BIN" --lib "$dso" --mode "$mode" --iters "$iters" \
                >"$EV/raw/cg-$tag-$mode-$iters.stdout" 2>&1
            verify_loaded "$EV/raw/cg-$tag-$mode-$iters.stdout" "$dso" \
                "$tag/$mode/cg/$iters"
            ir=$(sed -n 's/^summary: \([0-9]*\)$/\1/p' \
                     "$EV/raw/cg-$tag-$mode-$iters.cglog" | tail -1)
            [ -n "$ir" ] || ir=$(sed -n 's/^totals: \([0-9]*\)$/\1/p' \
                     "$EV/raw/cg-$tag-$mode-$iters.cglog" | tail -1)
            [ -n "$ir" ] || fail "$tag/$mode/$iters: no callgrind total"
            printf '%s\t%s\t%s\t%s\n' "$tag" "$mode" "$iters" "$ir" \
                >>"$EV/raw/callgrind.tsv"
        done
    done
done

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate A changed during the run"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "candidate B changed during the run"

{
    echo "dso_a_path=$A"; echo "dso_a_sha256=$(sha "$A")"
    echo "dso_b_path=$B"; echo "dso_b_sha256=$(sha "$B")"
    echo "sensitivity_path=$C"; echo "sensitivity_sha256=$(sha "$C")"
    echo "harness_source_sha256=$(sha "$HARNESS_SRC")"
    echo "harness_binary_sha256=$HSHA"
    echo "harness_cc=$(cc --version | head -1)"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"; echo "machine=$(uname -m)"
} >"$EV/raw/run-meta.env"

echo "PASS: PFP-27 ctgrind completed (A $EXPECT_A, B $EXPECT_B)"
