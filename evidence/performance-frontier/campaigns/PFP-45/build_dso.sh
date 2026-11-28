#!/bin/sh
# build_dso.sh — PFP-45: build the worktree's release lib and link the
# distribution-shaped libcrypto.so.3 for one arm.
#
#   bash docker/openssl-rs-court.sh exec sh \
#     evidence/performance-frontier/campaigns/PFP-45/build_dso.sh before
#
# The arm name selects the output directory only; the source is the current
# worktree. Call it once before the source edit and once after, so the two DSOs
# differ only by the PFP-45 change.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

TAG=${1:?usage: build_dso.sh <arm-tag>}
EV=/work/evidence/performance-frontier/campaigns/PFP-45
OUT=/work/court/tmp/pfp45
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
TARGET="$OUT/$TAG-target"
DIST="$OUT/$TAG/distribution"

mkdir -p "$OUT" "$DIST/shell" "$EV/raw"
[ -f "$SHELL_RS" ] && [ -f "$VERSION_SCRIPT" ] || {
    echo "FATAL: missing shell/version script" >&2
    exit 1
}

{
    echo "arm=$TAG"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "dirty=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | tr '\n' ';')"
    echo "arith_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "limbs_sha256=$(sha256sum src/bn/limbs.rs | awk '{print $1}')"
    echo "mont_sha256=$(sha256sum src/bn/mont.rs | awk '{print $1}')"
    echo "dh_key_sha256=$(sha256sum src/dh/key.rs | awk '{print $1}')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
    echo "profile=release overflow-checks=true"
} >"$EV/raw/$TAG.build-inputs.env"

echo "=== $TAG: cargo build --release --lib --offline (JOBS=1) ==="
rm -rf "$TARGET"
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$TARGET" \
    cargo build --release --lib --offline 2>&1 | tail -n 3

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$DIST/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$DIST/libcrypto.so.3" \
    -Wl,--whole-archive "$TARGET/release/libopenssl_rs.a" \
    -Wl,--no-whole-archive \
    "$DIST/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

{
    echo "archive_sha256=$(sha256sum "$TARGET/release/libopenssl_rs.a" | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$DIST/libcrypto.so.3" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$DIST/libcrypto.so.3")"
    echo "dso_build_id=$(readelf -n "$DIST/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
} | tee "$EV/raw/$TAG.dso.env"

rm -rf "$TARGET"
