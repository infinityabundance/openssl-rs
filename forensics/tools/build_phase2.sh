#!/usr/bin/env bash
# openssl-rs — build the Phase 2 distribution / ABI shell and run its courts.
#
# Runs inside the forensic court container; nothing executes on the host.
#
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_phase2.sh
#
# The shell is SCAFFOLDED by construction (docs/CUSTODIAN_CONTRACT.md §5): every
# symbol aborts when called. Passing these courts is NOT parity.
set -euo pipefail

cd /work

echo "=== [1/3] generate the shell (headers, version scripts, scaffolds, pkg-config) ==="
python3 forensics/tools/phase2_shell.py

echo
echo "=== [2/3] build the distribution artifacts ==="
cd /work/artifacts/phase2
for lib in libcrypto libssl; do
  echo "--- $lib.so.3 ---"
  # TWO-STAGE BUILD, because rustc cannot do this in one.
  #
  # For `--crate-type cdylib` on linux-gnu, rustc injects its OWN anonymous
  # version script (to hide non-exported symbols). GNU ld refuses to combine an
  # anonymous version tag with named version tags:
  #
  #   /usr/bin/ld.bfd: anonymous version tag cannot be combined with other
  #   version tags
  #
  # rustc's default bundled linker (rust-lld) takes the opposite failure mode:
  # it silently IGNORES the version assignment ("attempt to reassign symbol ...
  # of VER_NDX_GLOBAL to version ...") and emits an unversioned library that
  # still exports every name. Either default produces a DSO that looks right and
  # resolves wrongly.
  #
  # So: build a staticlib, then link it ourselves with GNU ld, using
  # --whole-archive to keep every scaffolded symbol (nothing references them)
  # and -Wl,--version-script for the version nodes.
  rustc --edition 2021 --crate-type staticlib -O --crate-name "${lib}_shell" \
    -o "$lib.shell.a" "shell/$lib.shell.rs"
  # libssl must carry the authority-observed dependency on libcrypto:
  #
  #   authority libssl.so.3: DT_NEEDED [libcrypto.so.3, libc.so.6]
  #
  # Without --no-as-needed the linker drops it (nothing is referenced) and the
  # candidate links WITHOUT a dependency that is part of the contract: ELF
  # symbol resolution order and transitive loading are observable. Same
  # technique already used for legacy.so.
  #
  # --as-needed is then restored so that toolchain runtime libraries our stubs
  # do not actually reference are not dragged in.
  if [ "$lib" = "libssl" ]; then
    depflags="-Wl,--no-as-needed -L$PWD -lcrypto -Wl,--as-needed"
  else
    depflags="-Wl,--as-needed"
  fi
  cc -shared -o "$lib.so.3" \
    -Wl,--whole-archive "$lib.shell.a" -Wl,--no-whole-archive \
    -Wl,--version-script="$PWD/$lib.ld" \
    -Wl,-soname,"$lib.so.3" \
    $depflags \
    -lpthread -ldl -lm -lrt -lutil
  echo "  built $(stat -c %s "$lib.so.3") bytes, NEEDED: $(readelf -d "$lib.so.3" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')"
done

# --- provider module (legacy.so) ---------------------------------------------
# The authority's module exports exactly OSSL_provider_init and declares
# NEEDED libcrypto.so.3. --no-as-needed plus -lcrypto is what actually creates
# that dependency: without it the linker drops the library (nothing is
# referenced) and the module would load WITHOUT the dependency the authority
# declares, which a provider-loading court would catch.
echo "--- legacy.so ---"
rustc --edition 2021 --crate-type staticlib -O --crate-name legacy_shell \
  -o legacy.shell.a shell/legacy.shell.rs
cc -shared -o legacy.so -Wl,--whole-archive legacy.shell.a -Wl,--no-whole-archive \
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
cp libcrypto.so.3 libssl.so.3 legacy.so install/lib/
cp libcrypto.so libssl.so install/lib/
cp libcrypto.shell.a install/lib/libcrypto.a
cp libssl.shell.a install/lib/libssl.a
mv install/lib/legacy.so install/lib/ossl-modules/legacy.so
cp pkgconfig/libcrypto.pc pkgconfig/libssl.pc install/lib/pkgconfig/
cp openssl c_rehash install/bin/
chmod +x install/bin/openssl install/bin/c_rehash
cd /work

echo
echo "=== [3/3] run the Phase 2 courts ==="
python3 forensics/tools/phase2_courts.py

echo
echo "phase 2 shell built."
