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
  cc -shared -o "$lib.so.3" \
    -Wl,--whole-archive "$lib.shell.a" -Wl,--no-whole-archive \
    -Wl,--version-script="$PWD/$lib.ld" \
    -Wl,-soname,"$lib.so.3" \
    -lpthread -ldl -lm -lrt -lutil
  echo "  built $(stat -c %s "$lib.so.3") bytes"
done
cd /work

echo
echo "=== [3/3] run the Phase 2 courts ==="
python3 forensics/tools/phase2_courts.py

echo
echo "phase 2 shell built."
