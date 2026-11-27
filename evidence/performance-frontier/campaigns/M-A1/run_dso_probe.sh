#!/bin/sh
# run_dso_probe.sh — M-A1: DSO-bound kernel-taint probe at the candidate digest,
# using PFP-27's pfp27_ladder_probe.c UNMODIFIED. The probe taints the base of
# BN_mod_exp_mont_consttime on a four-limb modulus, which the width-4 CIOS kernel
# multiplies on every ladder call; a memcheck context inside the carrier is a
# STOP. It complements the source-bound exponent taint in run_ctgrind.sh.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/M-A1/run_dso_probe.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/M-A1
OUT=/work/court/tmp/ma1
PROBE_SRC=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit/pfp27_ladder_probe.c
BIN="$OUT/pfp27_ladder_probe"
A="$OUT/cand/distribution/libcrypto.so.3"
P="$OUT/prev/distribution/libcrypto.so.3"
EXPECT_A=88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87
EXPECT_P=6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39

fail() { printf 'M-A1 STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "cand digest"
[ "$(sha "$P")" = "$EXPECT_P" ] || fail "prev digest"

mkdir -p "$EV/dso-probe/raw"
rm -f "$EV/dso-probe/raw"/*
cc -O2 -g -Wall -Wextra -o "$BIN" "$PROBE_SRC" -ldl
printf 'probe_source_sha256 %s\nprobe_binary_sha256 %s\n' \
    "$(sha "$PROBE_SRC")" "$(sha "$BIN")" | tee "$EV/dso-probe/raw/probe.sha256"

summary()  { sed -n 's/^==[0-9]*== ERROR SUMMARY: \([0-9]*\) errors.*/\1/p' "$1"; }
contexts() { sed -n 's/^==[0-9]*== ERROR SUMMARY: [0-9]* errors from \([0-9]*\) contexts.*/\1/p' "$1"; }

: >"$EV/dso-probe/raw/valgrind.tsv"
for tag in cand prev; do
    case $tag in cand) dso=$A;; prev) dso=$P;; esac
    for mode in control ladder; do
        reps=1
        [ "$mode" = ladder ] && reps=3
        rep=1
        while [ "$rep" -le "$reps" ]; do
            label="$tag/$mode/r$rep"
            valgrind --tool=memcheck --num-callers=24 \
                --log-file="$EV/dso-probe/raw/$tag-$mode-r$rep.out" \
                "$BIN" --lib "$dso" --mode "$mode" \
                >"$EV/dso-probe/raw/$tag-$mode-r$rep.stdout" 2>&1 || true
            rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$EV/dso-probe/raw/$tag-$mode-r$rep.stdout")
            [ "$rp" = "$(realpath "$dso")" ] || fail "$label: mapped $rp"
            grep -q "^RESULT mode=$mode ok=1" "$EV/dso-probe/raw/$tag-$mode-r$rep.stdout" \
                || fail "$label: operation did not succeed"
            n=$(summary "$EV/dso-probe/raw/$tag-$mode-r$rep.out")
            c=$(contexts "$EV/dso-probe/raw/$tag-$mode-r$rep.out")
            printf '%s\t%s\n' "$label" "${c:-0}" >>"$EV/dso-probe/raw/valgrind.tsv"
            [ "${n:-x}" = 0 ] || fail "$label: ${n:-?} memcheck errors (control and taint must both be silent)"
            rep=$((rep + 1))
        done
    done
done

cat "$EV/dso-probe/raw/valgrind.tsv"
{
    echo "dso_cand_sha256=$(sha "$A")"
    echo "dso_prev_sha256=$(sha "$P")"
    echo "probe_source_sha256=$(sha "$PROBE_SRC")"
    echo "probe_binary_sha256=$(sha "$BIN")"
    echo "valgrind=$(valgrind --version)"
} >"$EV/dso-probe/raw/run-meta.env"

echo "PASS: DSO-bound base-taint probe silent on cand and prev"
