#!/bin/sh
# run_attribution.sh — PFP-12 callgrind attribution, candidate and authority.
#
# Instruction counts (not cycles), one operation per process. Two iteration
# counts are profiled per (arm, operation) and differenced by the analyser, so
# the one-time provider/namemap/loader startup cancels exactly and the reported
# shares describe steady-state per-operation instructions.
#
# Must run in the timing-tools court (valgrind).
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-12
OUT=${PFP12_OUT:-/work/court/tmp/pfp12}
CAND=$OUT/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B=$OUT/bench_pfp12
A=$OUT/attr

mkdir -p "$A"
rm -f "$A"/*.cg "$A"/*.self "$A"/*.out "$A"/*.err

run_profile() { # arm dso op tag iters
    arm=$1; dso=$2; op=$3; tag=$4; iters=$5
    valgrind --tool=callgrind --quiet \
        --callgrind-out-file="$A/$arm-$op-$tag.cg" \
        "$B" --lib "$dso" --op "$op" --iters "$iters" --runs 1 \
        >"$A/$arm-$op-$tag.out" 2>"$A/$arm-$op-$tag.err" || {
            echo "ATTRIB_FAIL $arm $op $tag" >&2
            exit 1
        }
    callgrind_annotate --inclusive=no --auto=no --threshold=99.9 \
        "$A/$arm-$op-$tag.cg" >"$A/$arm-$op-$tag.self" 2>"$A/$arm-$op-$tag.self.err" || true
}

for pair in "cand|$CAND" "auth|$AUTH"; do
    arm=${pair%%|*}
    dso=${pair#*|}
    for op in aes128gcm-64 aes128gcm-16k aes256gcm-64 aes256gcm-16k \
              chachapoly-64 chachapoly-16k sha256-16k sha512-16k; do
        case "$op" in
            *-64) small=250; big=1000 ;;
            *) small=16; big=64 ;;
        esac
        run_profile "$arm" "$dso" "$op" small "$small"
        run_profile "$arm" "$dso" "$op" big "$big"
    done
done

python3 "$EV/analyse_attribution.py" --dir "$A" --out "$EV/raw/attribution.json"
echo ATTRIB_OK
