#!/bin/sh
# build_candidate.sh — PFP-12 candidate DSO from the exact working tree.
#
# Builds the release staticlib with the crate's own recipe and links the
# distribution-shaped libcrypto.so.3 (phase-2 shell + version script), as
# PFP-6/M-A1/PFP-11 did. Also compiles the PFP-12 harness. Everything is inside
# the court container; the harness is linked only against -ldl.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp12
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT/distribution" "$OUT/shell" "$OUT/raw"

{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "worktree_build_inputs=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | wc -l)"
    echo "aes_sha256=$(sha256sum src/aes.rs | awk '{print $1}')"
    echo "gcm_sha256=$(sha256sum src/modes/gcm.rs | awk '{print $1}')"
    echo "chacha_sha256=$(sha256sum src/chacha.rs | awk '{print $1}')"
    echo "poly1305_sha256=$(sha256sum src/mac/poly1305.rs | awk '{print $1}')"
    echo "sha2_sha256=$(sha256sum src/digest/sha2.rs | awk '{print $1}')"
    echo "profile=release jobs=$JOBS"
} | tee "$OUT/raw/build-identity.txt"

echo "=== cargo build --release --lib --offline (JOBS=$JOBS) ==="
CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR=/work/target \
    cargo build --release --lib --offline 2>&1 | tail -n 5

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$OUT/distribution/libcrypto.so.3" \
    -Wl,--whole-archive /work/target/release/libopenssl_rs.a -Wl,--no-whole-archive \
    "$OUT/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

cc -O2 -Wall -Wextra -Werror -I"$INC" \
    -o "$OUT/bench_pfp12" \
    /work/evidence/performance-frontier/campaigns/PFP-12/bench_pfp12.c -ldl

{
    echo "archive_sha256=$(sha256sum /work/target/release/libopenssl_rs.a | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$OUT/distribution/libcrypto.so.3" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$OUT/distribution/libcrypto.so.3")"
    echo "dso_build_id=$(readelf -n "$OUT/distribution/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
    echo "harness_source_sha256=$(sha256sum /work/evidence/performance-frontier/campaigns/PFP-12/bench_pfp12.c | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp12" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum /work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3 | awk '{print $1}')"
} | tee "$OUT/raw/artefact-identity.txt"
echo BUILD_OK
