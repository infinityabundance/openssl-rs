#!/bin/sh
# build_after.sh — PFP-63 "after" candidate DSO from the exact working tree.
#
# Same recipe as PFP-12's build_candidate.sh: the release staticlib linked into the
# distribution-shaped libcrypto.so.3 (phase-2 shell + version script). The timing
# instrument is the *same binary* PFP-12 used (`bench_pfp12`, identical source), so
# "same instrument" is literal. Everything runs inside the court container.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp63
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
INC=/work/forensics/authorities/prefix/openssl-3.6.4-production/include
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT/after" "$OUT/shell" "$OUT/raw"

{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "worktree_build_inputs=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | wc -l)"
    echo "aes_sha256=$(sha256sum src/aes.rs | awk '{print $1}')"
    echo "gcm_sha256=$(sha256sum src/modes/gcm.rs | awk '{print $1}')"
    echo "profile=release jobs=$JOBS"
} | tee "$OUT/raw/build-identity-after.txt"

echo "=== cargo build --release --lib --offline (JOBS=$JOBS) ==="
CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR=/work/target \
    cargo build --release --lib --offline 2>&1 | tail -n 5

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$OUT/after/libcrypto.so.3" \
    -Wl,--whole-archive /work/target/release/libopenssl_rs.a -Wl,--no-whole-archive \
    "$OUT/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

# The PFP-12 instrument binary is reused if present; otherwise it is rebuilt from the
# identical source. Either way the source hash is recorded.
BENCH_SRC=/work/evidence/performance-frontier/campaigns/PFP-12/bench_pfp12.c
if [ -x /work/court/tmp/pfp12/bench_pfp12 ]; then
    cp /work/court/tmp/pfp12/bench_pfp12 "$OUT/bench_pfp63"
else
    cc -O2 -Wall -Wextra -Werror -I"$INC" -o "$OUT/bench_pfp63" "$BENCH_SRC" -ldl
fi

{
    echo "archive_sha256=$(sha256sum /work/target/release/libopenssl_rs.a | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$OUT/after/libcrypto.so.3" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$OUT/after/libcrypto.so.3")"
    echo "dso_build_id=$(readelf -n "$OUT/after/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
    echo "before_dso_sha256=$(sha256sum "$OUT/before/libcrypto.so.3" | awk '{print $1}')"
    echo "harness_source_sha256=$(sha256sum "$BENCH_SRC" | awk '{print $1}')"
    echo "harness_binary_sha256=$(sha256sum "$OUT/bench_pfp63" | awk '{print $1}')"
    echo "authority_dso_sha256=$(sha256sum /work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3 | awk '{print $1}')"
} | tee "$OUT/raw/artefact-identity-after.txt"
echo BUILD_OK
