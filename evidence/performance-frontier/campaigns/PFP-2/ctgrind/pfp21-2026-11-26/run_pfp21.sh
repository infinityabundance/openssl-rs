#!/bin/sh
# run_pfp21.sh — PFP-21 DSO-level ctgrind, negative control, mutation control.
#
# Runs the same harness against two population DSOs, one process per subject:
#
#   A = 553e1b8c…, the audited PFP-20 candidate (rebuilt byte-identically)
#   B = 86bc63a6…, the same source with default_kernel_id() selecting the
#       generic Solinas kernel instead of Mont: the mutation control
#
# Every process prints the file it actually mapped and the runner compares
# realpath/dev/ino/size with stat(2); a mismatch, a foreign libcrypto mapping, a
# failed operation line, a changed DSO digest or a non-empty negative control is
# a STOP (exit 1).  Memcheck errors are *expected* for the tainted populations;
# the negative control must read zero.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/run_pfp21.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26
OUT=/work/court/tmp/pfp21
BIN="$OUT/instrument/pfp21_dso_ct"
A="$OUT/a/distribution/libcrypto.so.3"
B="$OUT/b/distribution/libcrypto.so.3"
EXPECT_A=553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4
EXPECT_B=86bc63a6746e2e7bad628f7e7e6df477c3355759582e0611109af3e08156765e
MODES="control mul-g mul-p mul-g-bytes sign sign-ex sign-ex-k"

fail() {
    printf 'PFP21 STOP: %s\n' "$*" >&2
    exit 1
}

sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate A digest $(sha "$A")"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "control B digest $(sha "$B")"

mkdir -p "$EV/raw" "$EV/attrib" "$OUT/instrument"
rm -f "$EV/raw"/*.out "$EV/raw"/*.cglog "$EV/raw"/*.stdout "$EV/raw"/*.cglog \
      "$EV/raw/timing.tsv" "$EV/raw/callgrind.tsv" "$EV/raw/valgrind-exits.tsv" \
      "$EV/attrib"/*

echo "=== compile the harness (links no libcrypto) ==="
cc -O1 -g -Wall -Wextra -o "$BIN" "$EV/pfp21_dso_ct.c" -ldl
HSHA=$(sha "$BIN")
printf 'harness_source_sha256 %s\nharness_binary_sha256 %s\n' \
    "$(sha "$EV/pfp21_dso_ct.c")" "$HSHA" | tee "$EV/raw/harness.sha256"

# Prove the mapping, not the name.  A path alone is not identity.
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

# --- sensitivity control: an artefact the instrument must flag -------------
# 83f67826 is the pre-PFP-20 candidate: its write-back normalise branches on the
# secret coordinate, and the recorded history attributes 4 engine-on-path
# contexts to it.  If this harness on this artefact cannot reproduce that, the
# instrument is not sensitive to the engine path and the A result is void.
C=/work/court/tmp/pfp2-fix/distribution/libcrypto.so.3
EXPECT_C=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
[ -f "$C" ] || fail "sensitivity control DSO missing: $C"
[ "$(sha "$C")" = "$EXPECT_C" ] || fail "sensitivity control digest $(sha "$C")"
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
printf 'c %s %s\n' "$(sha "$C")" "$(stat -c %s "$C")" \
    >"$EV/raw/sensitivity-digest.txt"

echo "=== attribution (campaign classifier) ==="
python3 "$EV/../repro-2026-11-26/attribute.py" "$EV/attrib" "$EV/raw"/*.out \
    >"$EV/raw/attrib-summary.jsonl"

# The sensitivity control must fire: if the instrument cannot attribute a
# context to a stack containing engine frames on the artefact that still had
# the write-back branch, then its silence on A means nothing.
for rep in 1 2 3; do
    f="$EV/attrib/c-mul-g-r$rep.summary.json"
    [ -f "$f" ] || fail "sensitivity control: missing $f"
    eop=$(sed -n 's/.*"engine_on_path": \([0-9]*\).*/\1/p' "$f" | head -1)
    [ "${eop:-0}" -ge 1 ] || fail "sensitivity control r$rep: engine_on_path=0"
done

# --- mutation control: wall time, 9 repetitions, 200 operations each ------
echo "=== mutation control: wall time ==="
: >"$EV/raw/timing.tsv"
for tag in a b; do
    if [ "$tag" = a ]; then dso=$A; else dso=$B; fi
    for mode in mul-g sign; do
        rep=1
        while [ "$rep" -le 9 ]; do
            "$BIN" --lib "$dso" --mode "$mode" --iters 200 \
                >"$EV/raw/timing-$tag-$mode-$rep.stdout" 2>&1
            verify_loaded "$EV/raw/timing-$tag-$mode-$rep.stdout" "$dso" \
                "$tag/$mode/timing/$rep"
            grep -q '^RESULT .* ok=1' "$EV/raw/timing-$tag-$mode-$rep.stdout" \
                || fail "$tag/$mode/timing/$rep: operation failed"
            ns=$(sed -n 's/^TIME .* ns_per_op=\([0-9.]*\).*/\1/p' \
                    "$EV/raw/timing-$tag-$mode-$rep.stdout")
            printf '%s\t%s\t%s\t%s\n' "$tag" "$mode" "$rep" "$ns" \
                >>"$EV/raw/timing.tsv"
            rep=$((rep + 1))
        done
    done
done

# --- mutation control: instruction counts (deterministic) -----------------
echo "=== mutation control: callgrind instruction counts ==="
: >"$EV/raw/callgrind.tsv"
for tag in a b; do
    if [ "$tag" = a ]; then dso=$A; else dso=$B; fi
    for mode in mul-g sign; do
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

# --- digests after execution ----------------------------------------------
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate A changed during the run"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "control B changed during the run"

{
    echo "candidate_a_path=$A"
    echo "candidate_a_sha256=$(sha "$A")"
    echo "control_b_path=$B"
    echo "control_b_sha256=$(sha "$B")"
    echo "harness_source_sha256=$(sha "$EV/pfp21_dso_ct.c")"
    echo "harness_binary_sha256=$HSHA"
    echo "harness_cc=$(cc --version | head -1)"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
} >"$EV/raw/run-meta.env"

python3 "$EV/record_pfp21.py" --dir "$EV" >"$EV/raw/record.txt"
cat "$EV/raw/record.txt"
echo "PASS: PFP-21 DSO-level run completed (A $EXPECT_A, B $EXPECT_B)"
