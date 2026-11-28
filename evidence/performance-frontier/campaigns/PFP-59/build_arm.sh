#!/bin/sh
# build_arm.sh — build one PFP-59 arm (before or after) as a distribution DSO.
#
#   build_arm.sh before   HEAD source from `git archive`, built in /court
#   build_arm.sh after    the current working tree, built in /work
#
# Both arms use the crate's own phase-2 shell and version script, so the only
# difference is the source identity. Nothing is linked against libcrypto.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

TAG="$1"
OUT=/court/tmp/pfp59
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4

case "$TAG" in
    before)
        SRC=$OUT/before-src
        TARGET=$OUT/before-target
        mkdir -p "$SRC"
        rm -rf "$SRC"/* "$SRC"/.[!.]* 2>/dev/null || true
        git -C /work archive HEAD | tar -x -C "$SRC"
        ;;
    after)
        SRC=/work
        TARGET=/work/target
        ;;
    *)
        echo "usage: build_arm.sh before|after" >&2
        exit 2
        ;;
esac

mkdir -p "$OUT/$TAG"
{
    echo "arm=$TAG"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "worktree_dirty_inputs=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | wc -l)"
    echo "solinas_sha256=$(sha256sum "$SRC/src/bn/solinas.rs" 2>/dev/null | awk '{print $1}')"
    echo "p384_sha256=$(sha256sum "$SRC/src/ec/p384.rs" 2>/dev/null | awk '{print $1}')"
    echo "mont_sha256=$(sha256sum "$SRC/src/bn/mont.rs" | awk '{print $1}')"
    echo "ec_mont_sha256=$(sha256sum "$SRC/src/ec/mont.rs" | awk '{print $1}')"
    echo "ec_lib_sha256=$(sha256sum "$SRC/src/ec/lib.rs" | awk '{print $1}')"
    echo "profile=release jobs=$JOBS debug=0"
} | tee "$OUT/$TAG/build-identity.txt"

echo "=== cargo build --release --lib (JOBS=$JOBS) ==="
cd "$SRC"
CARGO_BUILD_JOBS="$JOBS" CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_TARGET_DIR="$TARGET" \
    cargo build --release --lib --offline 2>&1 | tail -n 5

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/$TAG/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$OUT/$TAG/libcrypto.so.3" \
    -Wl,--whole-archive "$TARGET/release/libopenssl_rs.a" -Wl,--no-whole-archive \
    "$OUT/$TAG/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

{
    echo "archive_sha256=$(sha256sum "$TARGET/release/libopenssl_rs.a" | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$OUT/$TAG/libcrypto.so.3" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$OUT/$TAG/libcrypto.so.3")"
    echo "dso_build_id=$(readelf -n "$OUT/$TAG/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
} | tee "$OUT/$TAG/artefact-identity.txt"
echo "BUILD_OK $TAG"
