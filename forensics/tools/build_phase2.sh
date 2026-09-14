#!/usr/bin/env bash
# openssl-rs — build the Phase 2 distribution / ABI shell and run its courts.
#
# Runs inside the forensic court container; nothing executes on the host.
#
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_phase2.sh
#
# The shell is SCAFFOLDED by construction (docs/CUSTODIAN_CONTRACT.md §5): every
# unimplemented symbol aborts when called. Passing these courts is NOT parity.
#
# Two things changed when Phase 3 began, and both matter:
#
#   * The crate is built FIRST, and its static archive is linked into
#     libcrypto.so.3. Implemented symbols therefore come from the implementation,
#     not from a scaffold, and the shell generator excludes them (it reads
#     forensics/atlas/implemented-surface.json, derived from that archive).
#
#   * The scaffolds are compiled with `--emit=obj` rather than as a second Rust
#     `staticlib`. A second staticlib would bundle a second copy of `core`/`std`
#     and the link would fail with thousands of duplicate definitions; a bare
#     object contributes only the shell's own symbols and lets the crate archive
#     provide the one Rust runtime this DSO gets.
set -euo pipefail

# Nothing runs on the host (docs/REPRODUCIBILITY.md §1). Enforced, not assumed.
. "$(dirname "$0")/require_court.sh"

cd /work

OBJ=/work/court/phase2
CRATE=/work/target/release/libopenssl_rs.a
mkdir -p "$OBJ"

# GNU ar in this image loads the LLVM gold plugin and emits one harmless
# "failed to create LTO module" diagnostic per Rust object it scans. Those lines
# are noise, but they arrive on stderr -- exactly where a genuine archive failure
# would also arrive. So capture stderr and re-emit it only when ar fails: the
# exit status still decides, and no diagnostic is discarded on the failure path.
ar_quiet() {
  local err rc=0
  err="$(ar "$@" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$err" >&2
    return "$rc"
  fi
}

echo "=== [1/4] build the implementation crate (rlib + staticlib) ==="
cargo build --release

echo
echo "=== [2/4] derive the implemented surface, then generate the shell ==="
# The order is the point: the scaffold set is computed from what the crate
# actually defines, so no generator keeps a second opinion about what is done.
python3 forensics/tools/implemented_surface.py
python3 forensics/tools/phase2_shell.py

echo
echo "=== [3/4] build the distribution artifacts ==="
cd /work/artifacts/phase2
for lib in libcrypto libssl; do
  echo "--- $lib.so.3 ---"

  # Compile the scaffold set to a single relocatable object.
  #
  # `libcrypto`'s scaffolds are `std` flavour because the crate archive is in the
  # same link. `libssl`'s are `no_std` and reference only `write(2)`/`abort(3)`,
  # because libssl.so.3 is linked WITHOUT the crate archive: giving it a private
  # copy of libcrypto's implementation would also give it a private copy of
  # libcrypto's observable *state* (the ERR queue is thread-local), and an
  # application would then observe two divergent OpenSSLs in one process.
  if [ "$lib" = "libssl" ]; then
    rustc --edition 2021 --emit=obj --crate-type lib -O -C panic=abort \
      --crate-name "${lib}_shell" -o "$OBJ/$lib.shell.o" "shell/$lib.shell.rs"
    inputs="$OBJ/$lib.shell.o"
    # --no-as-needed is what actually creates DT_NEEDED libcrypto.so.3: nothing
    # in a scaffold *calls* libcrypto yet, so without it the linker drops the
    # dependency -- and the authority declares it (docs/CUSTODIAN_CONTRACT.md §2).
    depflags="-Wl,--no-as-needed -L$PWD -lcrypto -Wl,--as-needed"
  else
    rustc --edition 2021 --emit=obj --crate-type lib -O \
      --crate-name "${lib}_shell" -o "$OBJ/$lib.shell.o" "shell/$lib.shell.rs"
    # --whole-archive on the crate archive: implemented `#[no_mangle]` entry
    # points are referenced by nothing, so the linker would otherwise discard
    # them. The version script's `local: *;` keeps the Rust runtime's thousands
    # of symbols from being exported.
    inputs="-Wl,--whole-archive $CRATE -Wl,--no-whole-archive $OBJ/$lib.shell.o"
    depflags="-Wl,--as-needed"
  fi

  cc -shared -o "$lib.so.3" $inputs \
    -Wl,--version-script="$PWD/$lib.ld" \
    -Wl,-soname,"$lib.so.3" \
    $depflags \
    -lpthread -ldl -lm -lrt -lutil
  echo "  built $(stat -c %s "$lib.so.3") bytes, NEEDED: $(readelf -d "$lib.so.3" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')"
done

# --- static archives ----------------------------------------------------------
# The authority ships libcrypto.a / libssl.a. Ours are the same object graph in
# archive form: the crate archive plus that library's scaffolds. libcrypto.a
# therefore carries the Rust runtime (as any Rust staticlib does) and libssl.a
# does not, matching how the shared objects are split.
echo "--- static archives ---"
cp "$CRATE" "$OBJ/libcrypto.a"
ar_quiet rcs "$OBJ/libcrypto.a" "$OBJ/libcrypto.shell.o"
ar_quiet rcs "$OBJ/libssl.a" "$OBJ/libssl.shell.o"

# --- provider module (legacy.so) ---------------------------------------------
# The authority's module exports exactly OSSL_provider_init and declares
# NEEDED libcrypto.so.3. The module is a separate Rust program with its own
# runtime, so a staticlib IS correct here (nothing else is in its link), and the
# version script keeps that runtime from being exported.
#
# --no-as-needed plus -lcrypto is what creates the dependency: without it the
# linker drops the library (nothing is referenced) and the module would load
# WITHOUT the dependency the authority declares, which a provider-loading court
# would catch.
echo "--- legacy.so ---"
rustc --edition 2021 --crate-type staticlib -O --crate-name legacy_shell \
  -o legacy.shell.a shell/legacy.shell.rs
printf '%s\n' '{' '    global: OSSL_provider_init;' '    local: *;' '};' > legacy.ld
cc -shared -o legacy.so -Wl,--whole-archive legacy.shell.a -Wl,--no-whole-archive \
  -Wl,--version-script="$PWD/legacy.ld" \
  -Wl,--no-as-needed -L"$PWD" -lcrypto -lpthread -ldl -lm -lrt -lutil

# --- executables --------------------------------------------------------------
echo "--- openssl executable ---"
rustc --edition 2021 -O --crate-name openssl_shell -o openssl shell/openssl.shell.rs
cp shell/c_rehash.sh c_rehash && chmod +x c_rehash

# --- install layout -----------------------------------------------------------
# Mirrors the authority's install tree: bin/, include/openssl/, lib/ with the
# SOs, their development symlinks, the static archives, the provider module and
# pkg-config metadata. The layout is itself an observable contract (a consumer's
# build system, pkg-config and `dlopen("legacy")` all depend on it).
echo "--- install layout ---"
rm -rf install
mkdir -p install/bin install/lib/ossl-modules install/lib/pkgconfig install/include
cp -a include/. install/include/
cp libcrypto.so.3 libssl.so.3 install/lib/
cp libcrypto.so libssl.so install/lib/
cp "$OBJ/libcrypto.a" install/lib/libcrypto.a
cp "$OBJ/libssl.a" install/lib/libssl.a
cp legacy.so install/lib/ossl-modules/legacy.so
cp pkgconfig/libcrypto.pc pkgconfig/libssl.pc install/lib/pkgconfig/
cp openssl c_rehash install/bin/
chmod +x install/bin/openssl install/bin/c_rehash
cd /work

echo
echo "=== [4/4] run the Phase 2 courts ==="
python3 forensics/tools/phase2_courts.py

echo
echo "phase 2 shell built."
