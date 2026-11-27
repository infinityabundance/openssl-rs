#!/usr/bin/env bash
# PFP-7 profiling: one process per workload under callgrind, plus perf stat.
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
PROF=${PROF:-/work/court/tmp/pfp7/profile}
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance/fixtures"

mkdir -p "$PROF/cg" "$PROF/perf"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp5/bench_pfp5.c" -ldl -lm -o "$PROF/bench_pfp7"

COMMON=(--lib "$DSO" --rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

echo "=== perf stat rsa2048 (10 batches x 20 calls, pinned) ==="
perf stat -e cycles,instructions,branches,branch-misses,stalled-cycles-frontend,stalled-cycles-backend \
    taskset -c 1 "$PROF/bench_pfp7" "${COMMON[@]}" --prepared --only rsa2048 \
    >"$PROF/perf/rsa2048.stdout" 2>"$PROF/perf/rsa2048.perf" || true
cat "$PROF/perf/rsa2048.perf" || true
grep -E '^(RESULT|CHECK)' "$PROF/perf/rsa2048.stdout" | cut -c1-100 || true

for w in rsa2048; do
    echo "=== callgrind $w ==="
    valgrind --tool=callgrind --callgrind-out-file="$PROF/cg/$w.out" \
        --quiet "$PROF/bench_pfp7" "${COMMON[@]}" --prepared --only "$w" \
        >"$PROF/cg/$w.stdout" 2>"$PROF/cg/$w.stderr" || true
    grep -E '^(RESULT|CHECK)' "$PROF/cg/$w.stdout" | cut -c1-80 || true
    callgrind_annotate --inclusive=yes --threshold=99.9 "$PROF/cg/$w.out" \
        >"$PROF/cg/$w.inclusive.annotate" 2>/dev/null || true
    callgrind_annotate --inclusive=no --threshold=90 "$PROF/cg/$w.out" \
        >"$PROF/cg/$w.annotate" 2>/dev/null || true
    grep -E 'PROGRAM TOTALS' "$PROF/cg/$w.annotate" || true
done
echo PROFILE_OK
