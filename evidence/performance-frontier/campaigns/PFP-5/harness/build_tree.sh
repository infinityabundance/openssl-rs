#!/usr/bin/env bash
# Build a distribution-shaped libcrypto.so.3 from an arbitrary source tree.
# Usage: TREE=<dir> BUILD=<dir> bash build_tree.sh
set -euo pipefail
TREE="${TREE:?}"
BUILD="${BUILD:?}"
JOBS=${CARGO_BUILD_JOBS:-4}
SHELLOBJ="${SHELLOBJ:-}"

rm -rf "$BUILD/target"
mkdir -p "$BUILD/target" "$BUILD/distribution" "$BUILD/shell"
cd "$TREE"
env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
    cargo build --release --lib --offline 2>&1 | tail -n 3
ARCHIVE="$BUILD/target/release/libopenssl_rs.a"

if [ -n "$SHELLOBJ" ] && [ -f "$SHELLOBJ" ]; then
    OBJ="$SHELLOBJ"
    VSCRIPT=/work/artifacts/phase2/libcrypto.ld
else
    python3 "$TREE/forensics/tools/implemented_surface.py" \
        --archive "$ARCHIVE" --out "$BUILD/implemented-surface.json" \
        >"$BUILD/implemented-surface.log" 2>&1
    python3 "$TREE/courts/performance-frontier/baseline/emit_shell.py" \
        --surface "$BUILD/implemented-surface.json" --out "$BUILD/shell" \
        --authority openssl-3.6.4-production --record "$BUILD/shell-generation.json" \
        >"$BUILD/shell.log" 2>&1
    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$BUILD/shell/libcrypto.shell.o" \
        "$BUILD/shell/libcrypto.shell.rs"
    OBJ="$BUILD/shell/libcrypto.shell.o"
    VSCRIPT="$TREE/artifacts/phase2/libcrypto.ld"
fi

cc -shared -o "$BUILD/distribution/libcrypto.so.3" \
   -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   "$OBJ" -Wl,--version-script="$VSCRIPT" \
   -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
   -lpthread -ldl -lm -lrt -lutil
sha256sum "$ARCHIVE" "$BUILD/distribution/libcrypto.so.3"
echo BASE_BUILD_OK
