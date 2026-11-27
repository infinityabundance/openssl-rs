#!/bin/sh
# native_probe.sh — PFP-41 supplementary: does LLVM synthesise the ADX idiom
# (mulx/adcx/adox) for the same CIOS kernel when the target enables BMI2+ADX?
#
# Separate CARGO_TARGET_DIR; production source unchanged; the baseline DSO in
# court/tmp/pfp41 is not touched.
set -eu
cd /work
OUT=/work/evidence/performance-frontier/campaigns/PFP-41/raw/disasm
WORK=/work/court/tmp/pfp41-native
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
mkdir -p "$WORK/shell" "$OUT"

CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_TARGET_DIR="$WORK/target" \
  RUSTFLAGS="-C target-cpu=native" \
  cargo build --release --lib --offline 2>&1 | tail -n 3

rustc --edition 2021 --emit=obj --crate-type lib -O \
  --crate-name libcrypto_shell -o "$WORK/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$WORK/libcrypto.so.3" \
  -Wl,--whole-archive "$WORK/target/release/libopenssl_rs.a" -Wl,--no-whole-archive \
  "$WORK/shell/libcrypto.shell.o" \
  -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
  -lpthread -ldl -lm -lrt -lutil

printf 'native_dso_sha256 %s\n' "$(sha256sum "$WORK/libcrypto.so.3" | awk '{print $1}')" \
  | tee "$OUT/native-probe-identity.txt"
ADDR=$(nm -C --defined-only "$WORK/libcrypto.so.3" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $1; exit}')
SIZE=$(nm -S --defined-only -C "$WORK/libcrypto.so.3" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $2; exit}')
echo "mont_mul_ladder_into addr=0x$ADDR size=0x$SIZE" | tee -a "$OUT/native-probe-identity.txt"
objdump -d --no-show-raw-insn --start-address=0x$ADDR \
  --stop-address=$((0x$ADDR + 0x$SIZE)) "$WORK/libcrypto.so.3" \
  > "$OUT/native_mont_mul_ladder_into.dis"
echo "=== native kernel opcode census ===" | tee -a "$OUT/native-probe-identity.txt"
for op in mulx adcx adox mulq mul; do
  printf '%-6s %s\n' "$op" "$(grep -cE "^\s+[0-9a-f]+:\s+$op" "$OUT/native_mont_mul_ladder_into.dis")"
done | tee -a "$OUT/native-probe-identity.txt"
echo "=== done ==="
