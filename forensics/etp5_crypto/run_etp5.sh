#!/usr/bin/env bash
#
# run_etp5.sh - ETP-T5 cryptographic differential campaign.
#
# Runs INSIDE the court (docker/openssl-rs-court.sh).  It builds the candidate
# from the current source tree into a fresh target directory, links the
# distribution-shaped DSO, compiles the C harness against the pinned authority
# headers, regenerates or verifies the tracked vector populations, and runs the
# Python driver against both the candidate and the pinned authority.
#
# Nothing here compiles on the host.  Invocation from the repository root:
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#   OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
#     bash docker/openssl-rs-court.sh exec \
#       env CARGO_BUILD_JOBS=4 bash forensics/etp5_crypto/run_etp5.sh
#
# Exit status: 0 when the campaign ran and every difference was classified;
# 1 when the reference cross checks failed or a case is UNKNOWN; 2 on a setup
# or build failure.  A nonzero status never rewrites a result as a pass.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

AUTH_PREFIX="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production"
AUTH_DSO="$AUTH_PREFIX/lib/libcrypto.so.3"
AUTH_INC="$AUTH_PREFIX/include"

BUILD="${ETP5_BUILD_DIR:-$ROOT/court/tmp/etp5-build}"
WORK="${ETP5_WORK:-$ROOT/court/tmp/etp5-work}"
EVIDENCE="$ROOT/evidence/etp-t5"
VECDIR="$ROOT/forensics/etp5_crypto/vectors"

fail() {
    printf 'etp5: FAILED: %s\n' "$*" >&2
    exit 2
}

trap 'fail "command failed at line $LINENO"' ERR

[ -f "$AUTH_DSO" ] || fail "missing authority DSO $AUTH_DSO"
[ -f "$AUTH_INC/openssl/ecdsa.h" ] || fail "missing authority headers"

MEM_AVAILABLE_KB="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
[ "$MEM_AVAILABLE_KB" -ge 2097152 ] || \
    fail "less than 2 GiB available ($MEM_AVAILABLE_KB KiB); refusing to build"

HEAD="$(git -C "$ROOT" rev-parse HEAD)"
DIRTY="$(git -C "$ROOT" status --porcelain -- src Cargo.toml Cargo.lock build.rs rust-toolchain.toml)"
[ -z "$DIRTY" ] || fail "build-relevant worktree is dirty: $DIRTY"

mkdir -p "$BUILD" "$WORK" "$EVIDENCE" "$VECDIR"

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
   -Wl,-soname,libcrypto.so.3 -o "$BUILD/measurement.so"

echo "=== link distribution-shaped DSO ==="
python3 "$ROOT/forensics/tools/implemented_surface.py" \
    --archive "$ARCHIVE" --out "$BUILD/implemented-surface.json" \
    >"$BUILD/implemented-surface.log" 2>&1 || fail "implemented_surface failed"
python3 "$ROOT/courts/performance-frontier/baseline/emit_shell.py" \
    --surface "$BUILD/implemented-surface.json" --out "$BUILD/shell" \
    --authority openssl-3.6.4-production \
    --record "$BUILD/shell-generation.json" \
    >"$BUILD/shell.log" 2>&1 || fail "emit_shell failed"
rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$BUILD/shell/libcrypto.shell.o" \
    "$BUILD/shell/libcrypto.shell.rs" \
    >"$BUILD/shell-rustc.log" 2>&1 || fail "shell object failed"
cc -shared -o "$BUILD/libcrypto.so.3" \
   -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   "$BUILD/shell/libcrypto.shell.o" \
   -Wl,--version-script="$ROOT/artifacts/phase2/libcrypto.ld" \
   -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
   -lpthread -ldl -lm -lrt -lutil >"$BUILD/link.log" 2>&1 || \
   fail "distribution DSO link failed; see $BUILD/link.log"

echo "=== build harness ==="
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/forensics/etp5_crypto/etp5_harness.c" \
   -ldl -lm -o "$BUILD/etp5_harness" 2>"$BUILD/harness-build.log" || \
   fail "harness build failed; see $BUILD/harness-build.log"

echo "=== vectors ==="
if [ ! -f "$VECDIR/rsa_key.json" ]; then
    python3 "$ROOT/forensics/etp5_crypto/make_vectors.py"
fi
python3 "$ROOT/forensics/etp5_crypto/make_vectors.py" --check

echo "=== classifier self test ==="
python3 "$ROOT/forensics/etp5_crypto/driver.py" --self-test

python3 "$ROOT/forensics/etp5_crypto/driver.py" --transport-control \
    --candidate "$BUILD/libcrypto.so.3" --harness "$BUILD/etp5_harness" \
    --workdir "$WORK"

echo "=== differential campaign ==="
set +e
python3 "$ROOT/forensics/etp5_crypto/driver.py" \
    --candidate "$BUILD/libcrypto.so.3" \
    --authority "$AUTH_DSO" \
    --harness "$BUILD/etp5_harness" \
    --vectors "$VECDIR" \
    --workdir "$WORK" \
    --out "$EVIDENCE/RESULTS.json" \
    --source-head "$HEAD" \
    --source-dirty "$DIRTY" \
    --court-image "${ETP5_COURT_IMAGE:-openssl-rs-court-tools:1}" \
    --rustc "$(rustc --version)" \
    --cc "$(cc --version | head -n 1)"
STATUS=$?
set -e

python3 -m json.tool "$EVIDENCE/RESULTS.json" >/dev/null || \
    fail "RESULTS.json is not valid JSON"

echo "=== result ==="
echo "results=$EVIDENCE/RESULTS.json"
echo "candidate_dso_sha256=$(sha256sum "$BUILD/libcrypto.so.3" | cut -d' ' -f1)"
echo "authority_dso_sha256=$(sha256sum "$AUTH_DSO" | cut -d' ' -f1)"
exit "$STATUS"
