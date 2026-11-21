#!/usr/bin/env bash
#
# run_bench_api.sh — T21: benchmark the same workloads through the crate's
# libcrypto.so.3 and the pinned OpenSSL 3.6.4 authority, one library per
# process.
#
# Run INSIDE the court (docker/openssl-rs-court.sh) from the repository root:
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec \
#       env CARGO_BUILD_JOBS=4 REBUILD_CANDIDATE=1 \
#       bash courts/phase18/timing/run_bench_api.sh
#
# The candidate archive must have been built with
#   CARGO_BUILD_JOBS=4 cargo build --release --lib
# (REBUILD_CANDIDATE=1 only relinks the DSO from that archive; it never rebuilds
# the crate). The authority is the pinned prefix at
# forensics/authorities/prefix/openssl-3.6.4-production.
#
# Outputs (under court/tmp/t21 unless T21_WORK says otherwise):
#   candidate.out / authority.out   RESULT, CHECK and LIB lines
#   candidate.alloc.out             ALLOC lines (LD_PRELOAD allocation probe)
#
# The script exits non-zero if the two processes disagree on any CHECK line, or
# if both processes report having loaded the same library.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
AUTH_PREFIX="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
AUTH_LIB="$AUTH_PREFIX/lib"
AUTH_INC="$AUTH_PREFIX/include"
AUTH_BIN="$AUTH_PREFIX/bin/openssl"
AUTH_DSO="$AUTH_LIB/libcrypto.so.3"

WORK="${T21_WORK:-$ROOT/court/tmp/t21}"
FIX_DIR="$ROOT/courts/phase18/timing/fixtures"
RSA_DER="${RSA_DER:-$FIX_DIR/rsa2048.der}"
ARCHIVE="$ROOT/target/release/libopenssl_rs.a"
CAND_DSO="${CANDIDATE_DSO:-$WORK/libcrypto.so.3}"

mkdir -p "$WORK" "$FIX_DIR"

if [ ! -f "$AUTH_DSO" ]; then
    echo "run_bench_api: missing authority $AUTH_DSO" >&2
    exit 2
fi
if [ ! -f "$AUTH_INC/openssl/bn.h" ]; then
    echo "run_bench_api: missing authority headers $AUTH_INC" >&2
    exit 2
fi
if [ ! -f "$ARCHIVE" ]; then
    echo "run_bench_api: missing $ARCHIVE" >&2
    echo "  build it inside the court with: CARGO_BUILD_JOBS=4 cargo build --release --lib" >&2
    exit 2
fi

if [ "${REBUILD_CANDIDATE:-0}" = 1 ] || [ ! -f "$CAND_DSO" ]; then
    echo "=== linking candidate measurement DSO from the crate archive ==="
    cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
       -Wl,-soname,libcrypto.so.3 -o "$CAND_DSO"
fi

echo "=== building harness and allocation probe ==="
cc -O2 -g -I "$AUTH_INC" \
   "$ROOT/courts/phase18/timing/bench_api.c" -ldl -lm -o "$WORK/bench_api"
cc -O2 -fPIC -shared "$ROOT/courts/phase18/timing/alloc_probe.c" -ldl \
   -o "$WORK/alloc_probe.so"

if [ ! -f "$RSA_DER" ]; then
    echo "=== generating the fixed RSA-2048 test key fixture ==="
    LD_LIBRARY_PATH="$AUTH_LIB" "$AUTH_BIN" genpkey -algorithm RSA \
       -pkeyopt rsa_keygen_bits:2048 -out "$WORK/rsa2048.pem"
    LD_LIBRARY_PATH="$AUTH_LIB" "$AUTH_BIN" rsa -in "$WORK/rsa2048.pem" \
       -traditional -outform DER -out "$RSA_DER"
fi

PIN=()
if command -v taskset >/dev/null 2>&1; then
    PIN=(taskset -c "${T21_PIN:-1}")
fi

run_one() {
    local dso="$1" out="$2"

    LD_LIBRARY_PATH="$(dirname "$dso")" "${PIN[@]}" "$WORK/bench_api" \
        --lib "$dso" --rsa-der "$RSA_DER" > "$out"
}

echo "=== candidate: $CAND_DSO ==="
run_one "$CAND_DSO" "$WORK/candidate.out"
echo "=== authority: $AUTH_DSO ==="
run_one "$AUTH_DSO" "$WORK/authority.out"
echo "=== candidate allocation counts ==="
LD_PRELOAD="$WORK/alloc_probe.so" LD_LIBRARY_PATH="$(dirname "$CAND_DSO")" \
    "${PIN[@]}" "$WORK/bench_api" --lib "$CAND_DSO" --rsa-der "$RSA_DER" \
    --alloc > "$WORK/candidate.alloc.out"

CAND_LOADED="$(sed -n 's/^LIB //p' "$WORK/candidate.out" | head -n 1)"
AUTH_LOADED="$(sed -n 's/^LIB //p' "$WORK/authority.out" | head -n 1)"
echo "candidate loaded: $CAND_LOADED"
echo "authority loaded: $AUTH_LOADED"
if [ "$CAND_LOADED" = "$AUTH_LOADED" ]; then
    echo "run_bench_api: both processes loaded the same DSO" >&2
    exit 1
fi
case "$CAND_LOADED" in
    */libcrypto.so.3) ;;
    *) echo "run_bench_api: candidate LIB is not libcrypto.so.3" >&2; exit 1 ;;
esac
case "$AUTH_LOADED" in
    */libcrypto.so.3) ;;
    *) echo "run_bench_api: authority LIB is not libcrypto.so.3" >&2; exit 1 ;;
esac

grep '^CHECK ' "$WORK/candidate.out" | sed 's/^CHECK //' > "$WORK/candidate.check"
grep '^CHECK ' "$WORK/authority.out" | sed 's/^CHECK //' > "$WORK/authority.check"
if ! diff -u "$WORK/authority.check" "$WORK/candidate.check"; then
    echo "run_bench_api: CORRECTNESS MISMATCH (candidate vs authority)" >&2
    exit 1
fi
echo "correctness: $(wc -l < "$WORK/candidate.check") checks agree byte-for-byte"

grep '^RESULT ' "$WORK/candidate.out" | sed 's/^RESULT //' > "$WORK/candidate.res"
grep '^RESULT ' "$WORK/authority.out" | sed 's/^RESULT //' > "$WORK/authority.res"
if [ "$(wc -l < "$WORK/candidate.res")" -ne "$(wc -l < "$WORK/authority.res")" ]; then
    echo "run_bench_api: result-line count differs between processes" >&2
    exit 1
fi

echo
printf '%-12s %14s %14s %8s  %-8s %-17s\n' \
       operation candidate_us authority_us ratio n-spread
paste "$WORK/candidate.res" "$WORK/authority.res" | awk '
{
    # Each half: name median_us min_us max_us spread iters runs
    split($2, cmed, "="); split($5, csp, "=");
    split($9, rmed, "="); split($12, rsp, "=");
    ratio = (rmed[2] + 0 > 0) ? (cmed[2] + 0) / (rmed[2] + 0) : 0;
    printf "%-12s %14.3f %14.3f %7.2fx  %-8s %s / %s\n",
           $1, cmed[2] + 0, rmed[2] + 0, ratio, $7, csp[2], rsp[2];
}'

echo
echo "allocation counts (candidate only; per call):"
grep '^ALLOC ' "$WORK/candidate.alloc.out" | sed 's/^ALLOC //' || true

echo
echo "raw outputs: $WORK/candidate.out $WORK/authority.out $WORK/candidate.alloc.out"
