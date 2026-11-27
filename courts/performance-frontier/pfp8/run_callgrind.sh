#!/bin/sh
# run_callgrind.sh — PFP-8 profile: one key generation and one shared secret
# per process, callgrind instruction attribution at the current digest.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8
OUT=${PFP8_OUT:-/work/court/tmp/pfp8}
CAND=${PFP8_CAND:-/work/court/tmp/ma1/cand/distribution/libcrypto.so.3}
. "$EV/raw/operands.env"

mkdir -p "$OUT/cg"
run() { # name lib op args...
    name=$1; lib=$2; op=$3; shift 3
    valgrind --tool=callgrind --callgrind-out-file="$OUT/cg/$name.out" \
        --quiet "$OUT/bench_pfp8" --lib "$lib" --op "$op" \
        --iters 1 --runs 1 "$@" \
        >"$OUT/cg/$name.stdout" 2>"$OUT/cg/$name.stderr" || true
    grep -E '^(CHECK|RESULT)' "$OUT/cg/$name.stdout" | cut -c1-100 || true
    callgrind_annotate --inclusive=no --threshold=95 "$OUT/cg/$name.out" \
        >"$OUT/cg/$name.annotate" 2>/dev/null || true
}

run keygen-named "$CAND" keygen --nid 1126
run compute-named "$CAND" compute --nid 1126 --priv "$PRIV2048" --peer "$PEER2048"
run compute-named-225 "$CAND" compute --nid 1126 --priv "$PRIV225" --peer "$PEER225"

for n in keygen-named compute-named compute-named-225; do
    echo "=== $n ==="
    grep -E 'PROGRAM TOTALS|mont_mul|mont_sqr|run_mont_ladder|select_window|mod_exp|ffc_generate|generate_private|DH_|ossl_dh|bn::limbs|bn::arith|rand' \
        "$OUT/cg/$n.annotate" | head -40 || true
done
echo CALLGRIND_OK
