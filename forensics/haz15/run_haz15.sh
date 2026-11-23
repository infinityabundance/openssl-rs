#!/usr/bin/env bash
#
# run_haz15.sh - HAZ-15 differential campaign.
#
# Runs INSIDE the court (docker/openssl-rs-court.sh).  It builds the candidate
# from the current working tree into a fresh target directory, links a
# measurement DSO, compiles the dlopen harness against no libcrypto, and drives
# one fixed RSA key in two shapes (external: no d, RSA_FLAG_EXT_PKEY; internal:
# d present) through RSA_private_decrypt(PKCS#1 v1.5) against the pinned
# OpenSSL 3.6.4 authority and against the candidate.
#
# Nothing here compiles on the host.  Invocation from the repository root:
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#   OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
#     bash docker/openssl-rs-court.sh exec \
#       env CARGO_BUILD_JOBS=4 bash forensics/haz15/run_haz15.sh <out-dir>
#
# <out-dir> defaults to court/tmp/haz15.  The script writes authority.jsonl and
# candidate.jsonl there and prints both.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

AUTH_DSO="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
BUILD="${HAZ15_BUILD_DIR:-$ROOT/court/tmp/haz15-build}"
OUT="${1:-${HAZ15_OUT:-$ROOT/court/tmp/haz15}}"

fail() {
    printf 'haz15: FAILED: %s\n' "$*" >&2
    exit 2
}

trap 'fail "command failed at line $LINENO"' ERR

[ -f "$AUTH_DSO" ] || fail "missing authority DSO $AUTH_DSO"

MEM_AVAILABLE_KB="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
[ "$MEM_AVAILABLE_KB" -ge 2097152 ] || \
    fail "less than 2 GiB available ($MEM_AVAILABLE_KB KiB); refusing to build"

HEAD="$(git -C "$ROOT" rev-parse HEAD)"
DIRTY="$(git -C "$ROOT" status --porcelain -- src Cargo.toml Cargo.lock build.rs rust-toolchain.toml)"
mkdir -p "$BUILD" "$OUT"

echo "=== source identity ==="
echo "head=$HEAD"
echo "build_relevant_dirty=${DIRTY:-clean}"
echo "mem_available_kb=$MEM_AVAILABLE_KB"

echo "=== release build (fresh target dir, jobs=$JOBS) ==="
(
    cd "$ROOT"
    env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
        cargo build --release --lib --offline
) >"$BUILD/build.log" 2>&1 || fail "cargo build failed; see $BUILD/build.log"

ARCHIVE="$BUILD/target/release/libopenssl_rs.a"
[ -f "$ARCHIVE" ] || fail "cargo did not produce $ARCHIVE"

echo "=== link measurement DSO ==="
cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   -Wl,-soname,libcrypto.so.3 -o "$BUILD/candidate.so"

echo "=== compile harness ==="
cc -O2 -std=c11 -Wall -Wextra -o "$BUILD/haz15_harness" \
   "$ROOT/forensics/haz15/haz15_harness.c" -ldl

echo "=== authority ==="
"$BUILD/haz15_harness" "$AUTH_DSO" authority | tee "$OUT/authority.jsonl"

echo "=== candidate ==="
"$BUILD/haz15_harness" "$BUILD/candidate.so" candidate | tee "$OUT/candidate.jsonl"

echo "=== digests ==="
sha256sum "$AUTH_DSO" "$BUILD/candidate.so"
