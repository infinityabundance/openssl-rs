#!/usr/bin/env bash
# openssl-rs — build the Phase 2 distribution DSOs *under AddressSanitizer*.
#
# This is the ASan sibling of `forensics/tools/build_phase2.sh`. That script builds
# the normal distribution shell the Phase 17 downstream courts and the FRF depend
# on, and it must not be disturbed. This one builds the SAME object graph — the
# crate's instrumented staticlib, the (empty at Phase 18) scaffold shell objects and
# the legacy provider module — but every first-party compilation is instrumented:
#
#   * the Rust crate and `std` are built by rustc with
#     `-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=1` and
#     `-Zbuild-std`, through a `CC` wrapper that appends `-fsanitize=address
#     -fno-omit-frame-pointer -g` to the C adapters `build.rs` compiles;
#   * the DSOs are linked from that instrumented archive.
#
# A DSO built this way *references* the ASan runtime (`__asan_*` are undefined)
# rather than carrying a private static copy, so one runtime is shared by every
# DSO and the consumer, and `LD_PRELOAD` of the dynamic runtime first in the
# process initialises it. The consumers are NOT instrumented; they load the
# instrumented candidate DSOs, which is the point (the defect surface under test
# is the candidate, not the consumer).
#
# It installs into a dedicated prefix so the normal `artifacts/phase2/install`
# (which the FRF/courts depend on) is never overwritten:
#
#     PREFIX=${PREFIX:-/asan/install}
#
# Run inside the ASan venue only (nothing runs on the host):
#
#     bash docker/openssl-rs-asan.sh exec bash forensics/tools/build_phase2_asan.sh
#
# It reuses the instrumented archive the ASan closure harness already built
# (`/asan/target/<triple>/release/libopenssl_rs.a`); if it is absent it builds it
# with the same environment `forensics/tools/asan_closure.py` uses.
set -euo pipefail

cd /work

# Court-hygiene for the wrong venue: ASan cannot run under the court's RLIMIT_DATA,
# and this script must not be run on the host (docs/REPRODUCIBILITY.md §1).
if [ ! -f /.dockerenv ] || [ ! -d /asan ]; then
  echo "build_phase2_asan: REFUSED — run inside the ASan venue (docker/openssl-rs-asan.sh)" >&2
  exit 2
fi

NIGHTLY="${ASAN_NIGHTLY:-nightly-2026-10-05}"
TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-linux-gnu}"
PREFIX="${PREFIX:-/asan/install}"
ARCHIVE="${ARCHIVE:-/asan/target/$TARGET_TRIPLE/release/libopenssl_rs.a}"
OBJ=/asan/obj/phase2
OUT=/asan/obj/phase2/out
CC_WRAPPER=/asan/bin/asan-cc

mkdir -p "$OBJ" "$OUT" "$PREFIX/lib/ossl-modules" "$PREFIX/include" "$PREFIX/bin"

# --- 1. the instrumented crate archive ---------------------------------------
if [ ! -f "$ARCHIVE" ]; then
  echo "=== [1/3] build the ASan-instrumented crate (rlib + staticlib) ==="
  mkdir -p /asan/bin
  printf '#!/bin/sh\nexec clang -fsanitize=address -fno-omit-frame-pointer -g "$@"\n' > "$CC_WRAPPER"
  chmod +x "$CC_WRAPPER"
  RUSTUP_TOOLCHAIN="$NIGHTLY" \
  RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=1" \
  CARGO_TARGET_DIR=/asan/target \
  CC="$CC_WRAPPER" AR=ar \
    cargo "+$NIGHTLY" build -Zbuild-std --release --lib --target "$TARGET_TRIPLE"
else
  echo "=== [1/3] reuse existing ASan crate archive: $ARCHIVE ==="
fi

# --- 2. compile the scaffold shell objects (empty at Phase 18) ----------------
echo
echo "=== [2/3] compile the scaffold shell objects ==="
cd /work/artifacts/phase2
rustc "+$NIGHTLY" --edition 2021 --emit=obj --crate-type lib -O -C panic=abort \
  --crate-name libssl_shell -o "$OBJ/libssl.shell.o" shell/libssl.shell.rs
rustc "+$NIGHTLY" --edition 2021 --emit=obj --crate-type lib -O \
  --crate-name libcrypto_shell -o "$OBJ/libcrypto.shell.o" shell/libcrypto.shell.rs

# --- 3. link the instrumented DSOs into the dedicated prefix -----------------
echo
echo "=== [3/3] link instrumented DSOs into $PREFIX ==="
for lib in libcrypto libssl; do
  echo "--- $lib.so.3 (ASan) ---"
  if [ "$lib" = "libssl" ]; then
    inputs="-Wl,--whole-archive $ARCHIVE -Wl,--no-whole-archive $OBJ/$lib.shell.o"
    ldflags="-Wl,--allow-multiple-definition"
    depflags="-Wl,--no-as-needed -L$PREFIX/lib -lcrypto -Wl,--as-needed"
  else
    inputs="-Wl,--whole-archive $ARCHIVE -Wl,--no-whole-archive $OBJ/$lib.shell.o"
    ldflags=""
    depflags="-Wl,--as-needed"
  fi
  # Plain `cc -shared` (no -fsanitize): every container object is already
  # instrumented, so the DSO carries undefined __asan_* symbols that the preloaded
  # runtime resolves. Embedding a private static runtime per DSO is what we avoid.
  # The output goes to `$OUT`, NEVER to `$PWD` (which is `artifacts/phase2`, where
  # the normal distribution DSOs live); the normal install is not touched.
  cc -shared -o "$OUT/$lib.so.3" $inputs \
    -Wl,--version-script="$PWD/$lib.ld" \
    -Wl,-soname,"$lib.so.3" \
    $ldflags $depflags \
    -lpthread -ldl -lm -lrt -lutil
  cp "$OUT/$lib.so.3" "$PREFIX/lib/$lib.so.3"
  ln -sf "$lib.so.3" "$PREFIX/lib/$lib.so"
  echo "  $(stat -c %s "$OUT/$lib.so.3") bytes; NEEDED: $(readelf -d "$OUT/$lib.so.3" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')"
  echo "  undefined ASan refs: $(nm --undefined-only "$OUT/$lib.so.3" 2>/dev/null | grep -c __asan || true)"
done

# --- provider module (legacy.so) ---------------------------------------------
echo "--- legacy.so (ASan) ---"
rustc "+$NIGHTLY" --edition 2021 --emit=obj --crate-type lib -O -C panic=abort \
  --crate-name legacy_shell -o "$OBJ/legacy.shell.o" shell/legacy.shell.rs
printf '%s\n' '{' '    global: OSSL_provider_init;' '    local: *;' '};' > "$OUT/legacy.ld"
cc -shared -o "$OUT/legacy.so" \
  -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive "$OBJ/legacy.shell.o" \
  -Wl,--version-script="$OUT/legacy.ld" \
  -Wl,--no-as-needed -L"$PREFIX/lib" -lcrypto -lpthread -ldl -lm -lrt -lutil
cp "$OUT/legacy.so" "$PREFIX/lib/ossl-modules/legacy.so"

# --- static archives (unused by the downstream probes; kept for layout parity) -
cp "$ARCHIVE" "$OBJ/libcrypto.a"
ar rcs "$OBJ/libcrypto.a" "$OBJ/libcrypto.shell.o" 2>/dev/null || true
cp "$ARCHIVE" "$OBJ/libssl.a"
ar rcs "$OBJ/libssl.a" "$OBJ/libssl.shell.o" 2>/dev/null || true
cp "$OBJ/libcrypto.a" "$PREFIX/lib/libcrypto.a"
cp "$OBJ/libssl.a" "$PREFIX/lib/libssl.a"

# --- install layout (headers + pkg-config + provider module) ------------------
cp -a include/. "$PREFIX/include/"
cp pkgconfig/libcrypto.pc pkgconfig/libssl.pc "$PREFIX/lib/pkgconfig/" 2>/dev/null || {
  mkdir -p "$PREFIX/lib/pkgconfig"
  cp pkgconfig/libcrypto.pc pkgconfig/libssl.pc "$PREFIX/lib/pkgconfig/"
}

echo
echo "build_phase2_asan: installed ASan distribution prefix -> $PREFIX"
echo "  libssl.so.3/libcrypto.so.3 reference the ASan runtime; preload"
echo "  $(clang -print-file-name=libclang_rt.asan-x86_64.so) before a consumer."
ls -l "$PREFIX/lib/libcrypto.so.3" "$PREFIX/lib/libssl.so.3" "$PREFIX/lib/ossl-modules/legacy.so"
