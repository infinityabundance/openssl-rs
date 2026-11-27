#!/bin/sh
# build.sh — PFP-41: build the release lib DSO at the frozen source, record its
# digest, and enumerate the Montgomery-kernel symbols. No source is modified.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=1 \
#     CARGO_PROFILE_TEST_DEBUG=0 sh evidence/performance-frontier/campaigns/PFP-41/build.sh
set -eu
cd /work

EV=/work/evidence/performance-frontier/campaigns/PFP-41
OUT="$EV/raw"
WORK=/work/court/tmp/pfp41
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
mkdir -p "$OUT/disasm" "$WORK/shell"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

{
    printf 'date %s\n' "$(date -u +%FT%TZ)"
    printf 'source_commit %s\n' "$(git -C /work rev-parse HEAD)"
    printf 'source_src_tree %s\n' "$(git -C /work rev-parse HEAD:src)"
    printf 'build_relevant_dirty_begin\n%s\nbuild_relevant_dirty_end\n' \
        "$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs)"
    printf 'arith_rs_sha256 %s\n' "$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum Cargo.lock | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=1\n'
    printf 'shell_source_sha256 %s\n' "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script_sha256 %s\n' "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
} | tee "$OUT/build-inputs.txt"

echo "=== cargo build --release --lib --offline (JOBS=1) ==="
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
    cargo build --release --lib --offline 2>&1 | tail -n 5

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$WORK/shell/libcrypto.shell.o" "$SHELL_RS"

cc -shared -o "$WORK/libcrypto.so.3" \
    -Wl,--whole-archive /work/target/release/libopenssl_rs.a -Wl,--no-whole-archive \
    "$WORK/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

{
    printf 'archive_sha256 %s\n' "$(sha256sum /work/target/release/libopenssl_rs.a | awk '{print $1}')"
    printf 'dso_path %s\n' "$WORK/libcrypto.so.3"
    printf 'dso_sha256 %s\n' "$(sha256sum "$WORK/libcrypto.so.3" | awk '{print $1}')"
    printf 'dso_size %s\n' "$(stat -c %s "$WORK/libcrypto.so.3")"
    printf 'build_id %s\n' "$(readelf -n "$WORK/libcrypto.so.3" | sed -n 's/.*Build ID: //p')"
} | tee "$OUT/dso-identity.txt"

# Mangled + demangled symbol enumeration for the Montgomery kernels and their
# call sites (the ladder). Both forms are kept so objdump --disassemble can be
# fed the exact mangled name while the reader sees the Rust path.
nm --defined-only "$WORK/libcrypto.so.3" | grep -Ei 'mont|run_mont_ladder|smpl|p256' \
    | sort > "$OUT/symbols-mont-mangled.txt" || true
nm -C --defined-only "$WORK/libcrypto.so.3" | grep -Ei 'mont_mul|run_mont_ladder|mont_sqr|p256' \
    | sort > "$OUT/symbols-mont-demangled.txt" || true

echo "=== mont symbols (demangled) ==="
cat "$OUT/symbols-mont-demangled.txt"
echo "=== build: done ==="
