#!/bin/sh
# build_after.sh — PFP-46: build the release DSO from the working tree (the
# runtime-BMI2 dispatch change) and record its identity + the kernel census.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 \
#     bash docker/openssl-rs-court.sh exec env CARGO_PROFILE_TEST_DEBUG=0 \
#       sh evidence/performance-frontier/campaigns/PFP-46/build_after.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-46
OUT="$EV/raw/after"
BASE=/work/court/tmp/pfp46
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
T="$BASE/after/target"
mkdir -p "$OUT" "$BASE/after/shell"

{
    echo "date=$(date -u +%FT%TZ)"
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "dirty_src=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | tr '\n' ';')"
    echo "arith_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
    echo "profile=release"
} >"$OUT/build-inputs.txt"

CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$T" \
    cargo build --release --lib --offline 2>&1 | tail -n 3

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$BASE/after/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$BASE/after/libcrypto.so.3" \
    -Wl,--whole-archive "$T/release/libopenssl_rs.a" -Wl,--no-whole-archive \
    "$BASE/after/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

DSO="$BASE/after/libcrypto.so.3"
{
    echo "archive_sha256=$(sha256sum "$T/release/libopenssl_rs.a" | awk '{print $1}')"
    echo "dso_sha256=$(sha256sum "$DSO" | awk '{print $1}')"
    echo "dso_size=$(stat -c %s "$DSO")"
} >>"$OUT/build-inputs.txt"

ADDR=$(nm -C --defined-only "$DSO" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $1; exit}')
SIZE=$(nm -S --defined-only -C "$DSO" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $2; exit}')
echo "mont_mul_ladder_into addr=0x$ADDR size=0x$SIZE" | tee -a "$OUT/build-inputs.txt"
objdump -d --no-show-raw-insn --start-address=0x$ADDR \
    --stop-address=$((0x$ADDR + 0x$SIZE)) "$DSO" \
    >"$OUT/mont_mul_ladder_into.dis"

echo "=== BMI2 wrapper symbols ===" | tee -a "$OUT/build-inputs.txt"
nm -S --defined-only -C "$DSO" | grep -E 'mont_mul_cios_bmi2_' | sort \
    | tee -a "$OUT/build-inputs.txt" || true

echo "=== opcode census (whole DSO .text via the kernel + wrappers) ===" | tee -a "$OUT/build-inputs.txt"
for sym in mont_mul_ladder_into; do
    printf '%s: ' "$sym"
    for op in mulq mulx adcx adox; do
        printf '%s=%s ' "$op" "$(grep -cE "^\s+[0-9a-f]+:\s+$op" "$OUT/mont_mul_ladder_into.dis" || true)"
    done
    echo
done | tee -a "$OUT/build-inputs.txt"

# Disassemble each wrapper so the BMI2 encoding is inspectable per width.
mkdir -p "$OUT/disasm"
nm -S --defined-only -C "$DSO" | awk '/mont_mul_cios_bmi2_[0-9]+$/{name=$4; for(i=5;i<=NF;i++) name=name" "$i; print $1, $2, name}' >"$OUT/wrappers.txt"
while read -r addr size name; do
    [ -n "$addr" ] || continue
    short=$(printf '%s' "$name" | sed 's/.*:://')
    objdump -d --no-show-raw-insn --start-address=0x$addr \
        --stop-address=$((0x$addr + 0x$size)) "$DSO" \
        >"$OUT/disasm/${short}.dis"
    printf '%-36s insns=%s mulx=%s ' "$short" \
        "$(grep -cE '^\s+[0-9a-f]+:\s' "$OUT/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+mulx' "$OUT/disasm/${short}.dis" || true)"
    printf 'mulq=%s adcx=%s adox=%s\n' \
        "$(grep -cE '^\s+[0-9a-f]+:\s+mulq' "$OUT/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+adcx' "$OUT/disasm/${short}.dis" || true)" \
        "$(grep -cE '^\s+[0-9a-f]+:\s+adox' "$OUT/disasm/${short}.dis" || true)"
done <"$OUT/wrappers.txt" | tee -a "$OUT/build-inputs.txt"

echo "=== after build: done ==="
