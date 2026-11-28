#!/bin/sh
# run_callgrind.sh — PFP-11 instruction attribution at one digest.
#
# One callgrind run per operation on the exact candidate DSO built by
# build_candidate.sh. `--inclusive=no` (self cost) is the disjoint partition;
# `--inclusive=yes` is kept for the field-multiply/inversion subtree shares.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=${PFP11_OUT:-/work/court/tmp/pfp11}
CG="$OUT/cg"
B=$OUT/bench_pfp11
CAND=$OUT/distribution/libcrypto.so.3
mkdir -p "$CG"
rm -f "$CG"/*.out "$CG"/*.self.txt "$CG"/*.incl.txt

run() { # name args
    name=$1
    shift
    echo "=== $name ==="
    taskset -c 1 valgrind --tool=callgrind --quiet \
        --callgrind-out-file="$CG/$name.out" \
        "$B" --lib "$CAND" "$@" >/dev/null
    callgrind_annotate --inclusive=no --threshold=100 "$CG/$name.out" \
        >"$CG/$name.self.txt" 2>/dev/null
    callgrind_annotate --inclusive=yes --threshold=100 "$CG/$name.out" \
        >"$CG/$name.incl.txt" 2>/dev/null
}

run ecdsa-sign-p384   --op ecdsa-sign   --curve p384 --iters 10 --runs 1
run ecdsa-verify-p384 --op ecdsa-verify --curve p384 --iters 10 --runs 1
run ecdsa-sign-p521   --op ecdsa-sign   --curve p521 --iters 10 --runs 1
run ecdsa-verify-p521 --op ecdsa-verify --curve p521 --iters 10 --runs 1
run x25519-derive     --op x25519-derive --iters 20 --runs 1
run ed25519-sign      --op ed25519-sign  --iters 20 --runs 1
run ed25519-verify    --op ed25519-verify --iters 20 --runs 1

echo CALLGRIND_OK
