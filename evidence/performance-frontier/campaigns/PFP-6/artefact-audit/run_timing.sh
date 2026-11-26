#!/bin/sh
# run_timing.sh — PFP-27: benchmark the Rust ladder through the DSO.
#
# Two DSOs that differ only in the compile-time `MontSchedule` default
# (A = Sos, B = Cios), one harness, one CPU, interleaved repetitions:
#
#   A = 5e75b694…   B = 12023efe…
#   taskset -c 1 ./instrument/pfp27_ladder_probe --lib <dso> --mode time --iters N
#
# The measured operation is BN_mod_exp_mont_consttime on a P-256-order modulus
# with a 4-limb base, which runs the fixed ladder 256 times and therefore calls
# the schedule's multiply 257 times and the SOS squaring 256 times per
# operation.  The measured ratio is therefore the ladder operation's ratio; the
# kernel's own instruction counts are extracted separately (kernel_ir.py).
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-6/artefact-audit/run_timing.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp27
EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
CG=/work/evidence/performance-frontier/campaigns/PFP-6/ctgrind/pfp27-2026-11-26/raw
PROBE_SRC="$EV/pfp27_ladder_probe.c"
BIN="$OUT/instrument/pfp27_ladder_probe"
A="$OUT/a/distribution/libcrypto.so.3"
B="$OUT/b/distribution/libcrypto.so.3"
EXPECT_A=5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae
EXPECT_B=12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8
ITERS=2000
REPS=15

fail() { printf 'PFP27 STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest"
[ "$(sha "$B")" = "$EXPECT_B" ] || fail "B digest"

mkdir -p "$EV/timing/raw" "$OUT/instrument"
rm -f "$EV/timing/raw"/*
cc -O2 -g -Wall -Wextra -o "$BIN" "$PROBE_SRC" -ldl

: >"$EV/timing/raw/timing.tsv"
rep=1
while [ "$rep" -le "$REPS" ]; do
    # Alternate the order so a monotone drift cannot masquerade as a schedule
    # difference.
    if [ $((rep % 2)) -eq 1 ]; then order="a b"; else order="b a"; fi
    for tag in $order; do
        if [ "$tag" = a ]; then dso=$A; else dso=$B; fi
        f="$EV/timing/raw/$tag-r$rep.stdout"
        taskset -c 1 "$BIN" --lib "$dso" --mode time --iters "$ITERS" >"$f" 2>&1 \
            || fail "$tag/r$rep: probe failed"
        grep -q "^RESULT mode=time ok=1" "$f" || fail "$tag/r$rep: operation failed"
        rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
        [ "$rp" = "$(realpath "$dso")" ] || fail "$tag/r$rep: mapped $rp"
        ns=$(sed -n 's/^TIME .* ns_per_op=\([0-9.]*\).*/\1/p' "$f")
        [ -n "$ns" ] || fail "$tag/r$rep: no TIME line"
        printf '%s\t%s\t%s\t%s\t%s\n' "$rep" "$order" "$tag" "$ITERS" "$ns" \
            >>"$EV/timing/raw/timing.tsv"
    done
    rep=$((rep + 1))
done

{
    echo "dso_a_sha256=$(sha "$A")"
    echo "dso_b_sha256=$(sha "$B")"
    echo "probe_source_sha256=$(sha "$PROBE_SRC")"
    echo "probe_binary_sha256=$(sha "$BIN")"
    echo "iters=$ITERS reps=$REPS taskset=-c1"
    echo "cc=$(cc --version | head -1)"
    echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "court_image=${PFP0_COURT_IMAGE:-openssl-rs-court-tools:1}"
} >"$EV/timing/raw/run-meta.env"

# Deterministic kernel instruction counts from the same callgrind runs.
python3 "$EV/kernel_ir.py" "$CG/cg-a-sign-64.cglog" "$CG/cg-b-sign-64.cglog" \
    >"$EV/timing/raw/kernel-ir.json"

python3 "$EV/analyse_timing.py" "$EV/timing/raw/timing.tsv" \
    >"$EV/timing/raw/timing-summary.json"
cat "$EV/timing/raw/timing-summary.json"
echo "timing: done"
