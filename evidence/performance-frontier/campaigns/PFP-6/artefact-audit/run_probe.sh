#!/bin/sh
# run_probe.sh — PFP-27 kernel-taint population and negative control.
#
# The PFP-21 harness cannot route a tainted value into the exponentiation
# ladder through any exported entry point in its mode set, so the admitted
# ctgrind run (run_ctgrind.sh) has zero kernel-taint coverage by construction.
# This probe supplies it directly and, with the canary DSO, proves the
# instrument sees this kernel.
#
#   A = 5e75b694…  Sos default        B = 12023efe…  Cios default
#   K = 97e960f3…  Cios + a deliberate branch on the CIOS `keep` flag
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-6/artefact-audit/run_probe.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp27
EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
ATTRIB=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/repro-2026-11-26/attribute.py
PROBE_SRC="$EV/pfp27_ladder_probe.c"
BIN="$OUT/instrument/pfp27_ladder_probe"
A="$OUT/a/distribution/libcrypto.so.3"
B="$OUT/b/distribution/libcrypto.so.3"
K="$OUT/k/distribution/libcrypto.so.3"
EXPECT_A=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_B=12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8
EXPECT_K=97e960f31e8d345bd0ad529f8f5f84df7bebb4b731ce41e0e72a3aa392420309

fail() { printf 'PFP27 STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest $(sha "$A")"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "B digest $(sha "$B")"
[ "$(sha "$K")" = "$EXPECT_K" ] || fail "canary digest $(sha "$K")"

mkdir -p "$EV/probe/raw" "$EV/probe/attrib" "$OUT/instrument"
rm -f "$EV/probe/raw"/* "$EV/probe/attrib"/*

echo "=== compile the probe ==="
cc -O2 -g -Wall -Wextra -o "$BIN" "$PROBE_SRC" -ldl
HSHA=$(sha "$BIN")
printf 'probe_source_sha256 %s\nprobe_binary_sha256 %s\n' \
    "$(sha "$PROBE_SRC")" "$HSHA" | tee "$EV/probe/raw/probe.sha256"

verify_loaded() { # stdout expected_dso label
    f=$1; dso=$2; label=$3
    rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
    ino=$(sed -n 's/^LOADED .* ino=\([0-9]*\) .*/\1/p' "$f")
    foreign=$(sed -n 's/^FOREIGN libcrypto=\([0-9]*\).*/\1/p' "$f")
    erp=$(realpath "$dso")
    eino=$(stat -c %i "$erp")
    [ "$rp" = "$erp" ] || fail "$label: mapped $rp, expected $erp"
    [ "$ino" = "$eino" ] || fail "$label: ino $ino != $eino"
    [ "${foreign:-x}" = "0" ] || fail "$label: foreign libcrypto ($foreign)"
}

summary()  { sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$1"; }
contexts() { sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$1"; }

: >"$EV/probe/raw/valgrind-exits.tsv"
for tag in a b k; do
    case $tag in a) dso=$A;; b) dso=$B;; k) dso=$K;; esac
    for mode in control ladder; do
        reps=1
        [ "$mode" = ladder ] && reps=3
        rep=1
        while [ "$rep" -le "$reps" ]; do
            label="$tag/$mode/r$rep"
            printf '=== %s ===\n' "$label"
            valgrind --tool=memcheck --num-callers=24 \
                --log-file="$EV/probe/raw/$tag-$mode-r$rep.out" \
                "$BIN" --lib "$dso" --mode "$mode" \
                >"$EV/probe/raw/$tag-$mode-r$rep.stdout" 2>&1 || true
            verify_loaded "$EV/probe/raw/$tag-$mode-r$rep.stdout" "$dso" "$label"
            grep -q "^RESULT mode=$mode ok=1" "$EV/probe/raw/$tag-$mode-r$rep.stdout" \
                || fail "$label: operation did not succeed"
            n=$(summary "$EV/probe/raw/$tag-$mode-r$rep.out")
            c=$(contexts "$EV/probe/raw/$tag-$mode-r$rep.out")
            printf '%s\t%s\t%s\t%s\t%s\n' "$tag" "$mode" "$rep" \
                "${n:-0}" "${c:-0}" >>"$EV/probe/raw/valgrind-exits.tsv"
            if [ "$mode" = control ] && [ "${n:-x}" != 0 ]; then
                fail "$label: negative control reported ${n:-?} errors"
            fi
            rep=$((rep + 1))
        done
    done
done

echo "=== attribution (campaign classifier, unchanged) ==="
python3 "$ATTRIB" "$EV/probe/attrib" "$EV/probe/raw"/*.out \
    >"$EV/probe/raw/attrib-summary.jsonl"

# --- assertions ----------------------------------------------------------
# 1. The real artefacts must show no context anywhere in the CIOS or SOS
#    kernel carrier: this is the kernel-taint result.
for tag in a b; do
    for rep in 1 2 3; do
        f="$EV/probe/attrib/$tag-ladder-r$rep.tsv"
        [ -f "$f" ] || fail "missing $f"
        if grep -q 'mont_mul_ladder_into\|mont_mul_sos_into' "$f"; then
            fail "$tag-ladder-r$rep: secret-derived context inside a kernel carrier"
        fi
    done
done

# 2. The canary must fire, and the firing context must be inside the carrier.
for rep in 1 2 3; do
    f="$EV/probe/attrib/k-ladder-r$rep.tsv"
    [ -f "$f" ] || fail "missing $f"
    grep -q 'mont_mul_ladder_into' "$f" \
        || fail "canary r$rep: no context inside mont_mul_ladder_into"
done

{
    echo "dso_a_sha256=$(sha "$A")"
    echo "dso_b_sha256=$(sha "$B")"
    echo "canary_sha256=$(sha "$K")"
    echo "probe_source_sha256=$(sha "$PROBE_SRC")"
    echo "probe_binary_sha256=$HSHA"
    echo "valgrind=$(valgrind --version)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
} >"$EV/probe/raw/run-meta.env"

echo "PASS: PFP-27 kernel-taint probe completed (A silent, canary fires)"
