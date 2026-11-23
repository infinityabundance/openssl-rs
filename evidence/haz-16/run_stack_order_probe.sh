#!/usr/bin/env bash
#
# run_stack_order_probe.sh — HAZ-16 stack destruction-order evidence.
#
# Builds the candidate release DSO from the current tree, compiles
# `pop_free_order_probe.c`, and runs the same operation against the pinned
# authority DSO and against the candidate DSO. The transcript covers:
#
#   * destruction order for the public `OPENSSL_sk_pop_free`;
#   * the same stack through an end-popping loop (the rejected reversal);
#   * the same stack through a front-removal loop (the rejected O(n^2) shape);
#   * destroy-path wall time at several sizes.
#
# Runs inside the court. Output is written to $HAZ16_WORK/RESULTS.txt.
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#   OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
#     bash docker/openssl-rs-court.sh exec \
#       bash evidence/haz-16/run_stack_order_probe.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

WORK="${HAZ16_WORK:-$ROOT/court/tmp/haz16}"
BUILD="$WORK/build"
AUTH="${AUTH_DSO:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3}"
CAND="$WORK/libcrypto.so.3"
PROBE="$WORK/probe"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4
PIN="${HAZ16_PIN_CPU:-1}"
RUN=(taskset -c "$PIN")

[ -f "$AUTH" ] || { echo "missing authority DSO: $AUTH" >&2; exit 1; }
mkdir -p "$WORK"

if [ "${HAZ16_REBUILD:-1}" = 1 ] || [ ! -f "$BUILD/target/release/libopenssl_rs.a" ]; then
    rm -rf "$BUILD"
    mkdir -p "$BUILD"
    (
        cd "$ROOT"
        env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
            cargo build --release --lib --offline
    )
fi

cc -shared -Wl,--whole-archive "$BUILD/target/release/libopenssl_rs.a" \
   -Wl,--no-whole-archive -Wl,-soname,libcrypto.so.3 -o "$CAND"
cc -O2 -std=c11 -Wall -Wextra -o "$PROBE" \
   "$ROOT/evidence/haz-16/pop_free_order_probe.c" -ldl

{
    echo "# HAZ-16 stack destruction-order probe"
    echo "source_head $(git -C "$ROOT" rev-parse HEAD)"
    echo "rustc $(rustc --version)"
    echo "cc $(cc --version | head -n 1)"
    echo "authority_dso $AUTH"
    echo "authority_sha256 $(sha256sum "$AUTH" | cut -d' ' -f1)"
    echo "candidate_dso $CAND"
    echo "candidate_sha256 $(sha256sum "$CAND" | cut -d' ' -f1)"
    echo

    echo "## destruction order"
    "${RUN[@]}" "$PROBE" "$AUTH" order pop_free
    "${RUN[@]}" "$PROBE" "$CAND" order pop_free
    "${RUN[@]}" "$PROBE" "$CAND" order pop
    "${RUN[@]}" "$PROBE" "$CAND" order shift
    echo

    echo "## destroy-path wall time (nanoseconds, one process per sample, pinned to CPU $PIN)"
    for n in 4000 8000 16000 32000 64000; do
        "${RUN[@]}" "$PROBE" "$AUTH" time pop_free "$n" 7
    done
    for n in 4000 8000 16000 32000 64000; do
        "${RUN[@]}" "$PROBE" "$CAND" time pop_free "$n" 7
    done
    echo "## end-popping shape (linear, reversed order)"
    for n in 4000 8000 16000 32000 64000; do
        "${RUN[@]}" "$PROBE" "$CAND" time pop "$n" 7
    done
    echo "## front-removal shape (quadratic)"
    for n in 2000 4000 8000 16000; do
        "${RUN[@]}" "$PROBE" "$CAND" time shift "$n" 7
    done
} | tee "$WORK/RESULTS.txt"
