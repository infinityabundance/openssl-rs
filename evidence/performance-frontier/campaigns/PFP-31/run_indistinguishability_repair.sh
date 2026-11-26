#!/bin/sh
# run_indistinguishability_repair.sh — PFP-31 repair: the same malformed
# population as run_indistinguishability.sh, retargeted at the repaired DSO
# 43a23e9b and writing to repair-raw/ so the original finding's rows are kept.
#
# One dlopen()ed DSO per process, exported entry points only.  The population is
# built inside the harness and is identical for both subjects:
#
#   valid, len-1, len+1, 64 one-bit flips, all-zero, all-ones, 8 seeded random
#   = 77 cases per parameter set.
#
# For each case the harness prints (return code, output length, shared secret).
# Every CASE row must be byte-identical between candidate and authority; a
# mismatch in rc or outlen is a compatibility finding and is named by case id.
#
#   bash docker/openssl-rs-court.sh exec sh \
#     evidence/performance-frontier/campaigns/PFP-31/run_indistinguishability.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-31
OUT=/work/court/tmp/pfp31
BIN="$OUT/instrument/pfp31_mlkem"
A=/work/court/tmp/pfp31/repair/r/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
EXPECT_A=43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
PARAMS="512 768 1024"
CASES=77

fail() { printf 'PFP31-INDIST STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "candidate digest $(sha "$A")"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority digest $(sha "$AUTH")"
[ -x "$BIN" ] || fail "harness not built: run run_taint.sh first"

mkdir -p "$EV/repair-raw"
: >"$EV/repair-raw/indistinguishability.tsv"
printf 'param\tcases\tdiffering_rows\trc_mismatches\toutlen_mismatches\tss_mismatches\tverdict\n' \
    >>"$EV/repair-raw/indistinguishability.tsv"

for p in $PARAMS; do
    echo "=== ML-KEM-$p candidate ==="
    "$BIN" --lib "$A" --mode malformed --param "$p" \
        >"$EV/repair-raw/malformed-cand-$p.txt" 2>&1
    echo "=== ML-KEM-$p authority ==="
    "$BIN" --lib "$AUTH" --mode malformed --param "$p" \
        >"$EV/repair-raw/malformed-auth-$p.txt" 2>&1

    nc=$(grep -c '^CASE' "$EV/repair-raw/malformed-cand-$p.txt")
    na=$(grep -c '^CASE' "$EV/repair-raw/malformed-auth-$p.txt")
    [ "$nc" = "$CASES" ] || fail "candidate ML-KEM-$p: $nc cases"
    [ "$na" = "$CASES" ] || fail "authority ML-KEM-$p: $na cases"

    # The base ciphertext and encapsulated secret must match too, or the rows
    # would be comparing different inputs.
    cb=$(grep '^BASE ' "$EV/repair-raw/malformed-cand-$p.txt")
    ab=$(grep '^BASE ' "$EV/repair-raw/malformed-auth-$p.txt")
    [ "$cb" = "$ab" ] || fail "ML-KEM-$p: base ciphertext/secret differ"

    diff "$EV/repair-raw/malformed-cand-$p.txt" "$EV/repair-raw/malformed-auth-$p.txt" \
        >"$EV/repair-raw/malformed-diff-$p.txt" 2>&1 || true
    python3 - "$EV/repair-raw/malformed-cand-$p.txt" \
        "$EV/repair-raw/malformed-auth-$p.txt" >"$EV/repair-raw/malformed-counts-$p.txt" <<'PY'
import sys

def rows(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        f = line.split()
        if not f or f[0] != "CASE":
            continue
        out[f[2]] = (f[3], f[4], f[5])
    return out

c = rows(sys.argv[1])
a = rows(sys.argv[2])
diff = [k for k in c if c.get(k) != a.get(k)]
rc = sum(1 for k in diff if c[k][0] != a[k][0])
ol = sum(1 for k in diff if c[k][1] != a[k][1])
ss = sum(1 for k in diff if c[k][2] != a[k][2])
print(len(diff), rc, ol, ss)
PY
    set -- $(cat "$EV/repair-raw/malformed-counts-$p.txt")
    rows=$1; rcm=$2; om=$3; sm=$4
    verdict=identical
    [ "${rows:-0}" = 0 ] || verdict="DIFFERING: see repair-raw/malformed-diff-$p.txt"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$CASES" "${rows:-0}" \
        "$rcm" "$om" "$sm" "$verdict" >>"$EV/repair-raw/indistinguishability.tsv"
done

# The population's own shape, so the record states what was compared.
{
    p=768
    echo "case-class    count"
    for cls in valid len-1 len+1 bit zero ones rand; do
        n=$(awk -v c="$cls" '/^CASE/ { id=$3; sub("id=", "", id);
            if (index(id, c) == 1) n++ } END { print n + 0 }' \
            "$EV/repair-raw/malformed-cand-$p.txt")
        printf '%-12s %s\n' "$cls" "$n"
    done
} | tee "$EV/repair-raw/population-shape.txt"

cat "$EV/repair-raw/indistinguishability.tsv"
echo "indistinguishability: done"
