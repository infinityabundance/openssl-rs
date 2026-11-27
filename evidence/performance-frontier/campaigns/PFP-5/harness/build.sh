#!/usr/bin/env bash
# PFP-5 build: release library -> distribution-shaped libcrypto.so.3.
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp5/build}
JOBS=${CARGO_BUILD_JOBS:-4}

rm -rf "$BUILD/target"
mkdir -p "$BUILD/target" "$BUILD/measurement" "$BUILD/distribution" "$BUILD/shell"

echo "=== release build ==="
cd "$ROOT"
env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
    cargo build --release --lib --offline 2>&1 | tail -n 5

ARCHIVE="$BUILD/target/release/libopenssl_rs.a"
cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   -Wl,-soname,libcrypto.so.3 -o "$BUILD/measurement/libcrypto.so.3"

python3 "$ROOT/forensics/tools/implemented_surface.py" \
    --archive "$ARCHIVE" --out "$BUILD/implemented-surface.json" \
    >"$BUILD/implemented-surface.log" 2>&1

python3 "$ROOT/courts/performance-frontier/baseline/emit_shell.py" \
    --surface "$BUILD/implemented-surface.json" --out "$BUILD/shell" \
    --authority openssl-3.6.4-production --record "$BUILD/shell-generation.json" \
    >"$BUILD/shell.log" 2>&1

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$BUILD/shell/libcrypto.shell.o" \
    "$BUILD/shell/libcrypto.shell.rs"

cc -shared -o "$BUILD/distribution/libcrypto.so.3" \
   -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   "$BUILD/shell/libcrypto.shell.o" \
   -Wl,--version-script="$ROOT/artifacts/phase2/libcrypto.ld" \
   -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
   -lpthread -ldl -lm -lrt -lutil

sha256sum "$BUILD/distribution/libcrypto.so.3"
echo "BUILD_OK"
