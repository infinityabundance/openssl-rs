#!/bin/sh
# build.sh — PFP-51: build the release libcrypto DSO once per invocation, from
# the exact source identity the branch-audit record will name.
#
# The link recipe is the one PFP-46/PFP-48 used (the release distribution shell):
# the crate's staticlib archive, linked whole into a shared object with the
# committed shell object and version script. No source is modified.
#
# PFP-51 needs two independent builds in separate target directories; the caller
# runs this script once per tag with a fresh CARGO_TARGET_DIR. The target dir is
# removed between runs to stay inside the court's disk budget, so the two builds
# never share rustc fingerprints.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 \
#     bash docker/openssl-rs-court.sh exec env CARGO_PROFILE_TEST_DEBUG=0 \
#       sh evidence/performance-frontier/campaigns/PFP-51/build.sh <tag>
set -eu
cd /work
. /work/forensics/tools/require_court.sh

TAG=$1
EV=/work/evidence/performance-frontier/campaigns/PFP-51
OUT="$EV/raw"
BASE=/work/court/tmp/pfp51
T="$BASE/$TAG/target"
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
mkdir -p "$OUT" "$BASE/$TAG/shell"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

{
    echo "tag=$TAG"
    echo "date=$(date -u +%FT%TZ)"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "dirty_build_relevant=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs artifacts/phase2/shell artifacts/phase2/libcrypto.ld | tr '\n' ';')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
    echo "target_triple=$(rustc -vV | sed -n 's/^host: //p')"
    echo "profile=release"
    echo "rustflags="
    echo "cargo_build_jobs=1"
    echo "shell_rs_sha256=$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    echo "version_script_sha256=$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
} >"$OUT/build-inputs-$TAG.txt"

echo "=== $TAG: cargo build --release --lib --offline ==="
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$T" \
    cargo build --release --lib --offline 2>&1 | tail -n 2

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$BASE/$TAG/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$BASE/$TAG/libcrypto.so.3" \
    -Wl,--whole-archive "$T/release/libopenssl_rs.a" -Wl,--no-whole-archive \
    "$BASE/$TAG/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

DSO="$BASE/$TAG/libcrypto.so.3"
{
    echo "archive_sha256=$(sha256sum "$T/release/libopenssl_rs.a" | awk '{print $1}')"
    echo "dso_path=$DSO"
    echo "dso_sha256=$(sha256sum "$DSO" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$DSO")"
    echo "build_id=$(readelf -n "$DSO" | sed -n 's/.*Build ID: //p')"
    echo "objdump=$(objdump --version | head -1)"
} >>"$OUT/build-inputs-$TAG.txt"

echo "=== $TAG: dso_sha256=$(sha256sum "$DSO" | awk '{print $1}') ==="
