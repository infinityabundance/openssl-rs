#!/bin/sh
# run_mutation.sh — PFP-3 artefact-level mutation control.
#
# A = candidate 04611380 (comb admitted)
# B = the same source with the admission switch off (ladder fallback)
#
# Both DSOs are exercised by the same harness.  The differential harness
# (`mul-g`, the fixed-base call form) must return the authority's point on
# 4,096 scalars for BOTH — so B is a correct fallback, and any difference is a
# path difference, not a correctness difference.  The same fixed-base population
# under callgrind and wall timing must then show a material difference: A (the
# comb) executes materially fewer instructions and less wall time than B (the
# ladder).  If A had silently fallen back, A's measurement would equal B's.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/mutation/run_mutation.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/mutation
OUT=/work/court/tmp/pfp3-mut
A=/work/court/tmp/pfp3-ctgrind/a/libcrypto.so.3
B="$OUT/distribution/libcrypto.so.3"
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
AUTH_INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
DIFF_SRC=/work/evidence/performance-frontier/campaigns/PFP-3/dso-differential/pfp2_dso_differential.c
CT_BIN=/work/court/tmp/pfp3-ctgrind/instrument/pfp3_dso_ct
SEED=0x5046503250485032
COUNT=4096
EXPECT_A=04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4

fail() { printf 'PFP3-MUTATION STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$A" ] || fail "missing A $A"
[ -f "$B" ] || fail "missing B $B"
[ -f "$AUTH" ] || fail "missing authority"
[ -f "$CT_BIN" ] || fail "missing ctgrind harness $CT_BIN"
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest $(sha "$A")"
B_SHA="$(sha "$B")"
[ "$B_SHA" != "$EXPECT_A" ] || fail "B is the candidate digest"
B_SHA_EXPECT="$(sed -n 's/^mutation_b_sha256=//p' "$EV/raw/dso-digests.txt")"
[ "$B_SHA" = "$B_SHA_EXPECT" ] || fail "B digest $B_SHA != $B_SHA_EXPECT"

mkdir -p "$EV/raw" "$OUT/instrument"

echo "=== differential harness: mul-g on A, B, authority (4096) ==="
cc -O2 -g -Wall -Wextra -Wno-deprecated-declarations -I "$AUTH_INC" \
   "$DIFF_SRC" -ldl -o "$OUT/instrument/pfp2_dso_differential"
for tag in a b auth; do
    if [ "$tag" = a ]; then dso="$A"; elif [ "$tag" = b ]; then dso="$B"; else dso="$AUTH"; fi
    "$OUT/instrument/pfp2_dso_differential" --lib "$dso" --seed "$SEED" \
        --mode mul-g --count "$COUNT" >"$EV/raw/diff-$tag.out" 2>"$EV/raw/diff-$tag.err" \
        || fail "differential $tag failed"
    grep '^POINT ' "$EV/raw/diff-$tag.out" >"$EV/raw/$tag.points"
    [ "$(wc -l <"$EV/raw/$tag.points")" -eq "$COUNT" ] || fail "$tag: not $COUNT points"
done
cmp -s "$EV/raw/a.points" "$EV/raw/auth.points" || fail "A disagrees with authority"
cmp -s "$EV/raw/b.points" "$EV/raw/auth.points" || fail "B disagrees with authority"
echo "A and B both match the authority on $COUNT mul-g points"

echo "=== callgrind instruction counts (fixed-base population) ==="
: >"$EV/raw/callgrind.tsv"
for tag in a b; do
    if [ "$tag" = a ]; then dso="$A"; else dso="$B"; fi
    for iters in 0 64; do
        valgrind --tool=callgrind \
            --callgrind-out-file="$EV/raw/cg-$tag-$iters.cglog" \
            "$CT_BIN" --lib "$dso" --mode mul-g-fixed --iters "$iters" \
            >"$EV/raw/cg-$tag-$iters.stdout" 2>&1
        grep -q '^RESULT mode=mul-g-fixed ok=1' "$EV/raw/cg-$tag-$iters.stdout" \
            || fail "callgrind $tag/$iters: operation failed"
        ir=$(sed -n 's/^summary: \([0-9]*\)$/\1/p' "$EV/raw/cg-$tag-$iters.cglog" | tail -1)
        [ -n "$ir" ] || ir=$(sed -n 's/^totals: \([0-9]*\)$/\1/p' "$EV/raw/cg-$tag-$iters.cglog" | tail -1)
        [ -n "$ir" ] || fail "callgrind $tag/$iters: no total"
        printf '%s\t%s\t%s\n' "$tag" "$iters" "$ir" >>"$EV/raw/callgrind.tsv"
    done
done

echo "=== wall time, 9 repetitions x 200 operations ==="
: >"$EV/raw/wall.tsv"
for tag in a b; do
    if [ "$tag" = a ]; then dso="$A"; else dso="$B"; fi
    rep=1
    while [ "$rep" -le 9 ]; do
        "$CT_BIN" --lib "$dso" --mode mul-g-fixed --iters 200 \
            >"$EV/raw/wall-$tag-$rep.stdout" 2>&1
        grep -q '^RESULT mode=mul-g-fixed ok=1' "$EV/raw/wall-$tag-$rep.stdout" \
            || fail "wall $tag/$rep: operation failed"
        ns=$(sed -n 's/^TIME .* ns_per_op=\([0-9.]*\).*/\1/p' "$EV/raw/wall-$tag-$rep.stdout")
        printf '%s\t%s\t%s\n' "$tag" "$rep" "$ns" >>"$EV/raw/wall.tsv"
        rep=$((rep + 1))
    done
done

python3 - "$EV/raw" "$EXPECT_A" "$B_SHA" <<'PY'
import json, statistics, sys
raw, a_sha, b_sha = sys.argv[1], sys.argv[2], sys.argv[3]
cg = {}
for line in open(f"{raw}/callgrind.tsv"):
    tag, iters, ir = line.split("\t")
    cg[(tag, int(iters))] = int(ir)
ir_op = {t: (cg[(t, 64)] - cg[(t, 0)]) / 64.0 for t in ("a", "b")}
wall = {"a": [], "b": []}
for line in open(f"{raw}/wall.tsv"):
    tag, rep, ns = line.split("\t")
    wall[tag].append(float(ns))
med = {t: statistics.median(v) for t, v in wall.items()}
doc = {
    "candidate_a_sha256": a_sha,
    "mutation_b_sha256": b_sha,
    "differential_mul_g": {"count": 4096, "a_mismatches": 0, "b_mismatches": 0},
    "callgrind_ir_per_op": ir_op,
    "ir_ratio_b_over_a": ir_op["b"] / ir_op["a"],
    "wall_ns_per_op_median": med,
    "wall_ratio_b_over_a": med["b"] / med["a"],
    "wall_reps": 9,
    "wall_iters": 200,
}
open(f"{raw}/mutation-record.json", "w").write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
print(json.dumps(doc, indent=2, sort_keys=True))
PY

echo "PASS: mutation control completed (A $EXPECT_A, B $B_SHA)"
