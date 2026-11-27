#!/bin/sh
# build_one.sh — build one PFP-42 DSO variant from the /work checkout and record
# its identity. Run inside the court:
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=1 \
#     sh evidence/performance-frontier/campaigns/PFP-42/raw/build_one.sh <tag> [--fresh]
#
# The target directory is reused across tags unless --fresh is given, so the
# after-change build recompiles only the changed crate.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

TAG=${1:?usage: build_one.sh <tag> [--fresh]}
FRESH=${2:-}
EV=/work/evidence/performance-frontier/campaigns/PFP-42/raw
OUT=/work/court/tmp/pfp42
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 2 ] || JOBS=2
T="$OUT/target"

mkdir -p "$OUT/$TAG/shell" "$OUT/$TAG/distribution" "$EV"
for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done
if [ "$FRESH" = "--fresh" ]; then rm -rf "$T"; fi

{
    echo "tag=$TAG"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "dirty_src=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | tr '\n' ';')"
    echo "arith_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "src_fingerprint=$(find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
} >"$EV/$TAG.env"

echo "=== $TAG: cargo build --release --lib --offline (JOBS=$JOBS) ==="
CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$T" \
    cargo build --release --lib --offline 2>&1 | tail -n 3

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/$TAG/shell/libcrypto.shell.o" \
    "$SHELL_RS"
cc -shared -o "$OUT/$TAG/distribution/libcrypto.so.3" \
    -Wl,--whole-archive "$T/release/libopenssl_rs.a" \
    -Wl,--no-whole-archive \
    "$OUT/$TAG/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

{
    echo "archive_sha256=$(sha256sum "$T/release/libopenssl_rs.a" | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$OUT/$TAG/distribution/libcrypto.so.3" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$OUT/$TAG/distribution/libcrypto.so.3")"
} >>"$EV/$TAG.env"
cat "$EV/$TAG.env"
