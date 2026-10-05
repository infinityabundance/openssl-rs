#!/bin/sh
# openssl-rs ASan venue entrypoint.
#
# Records the execution environment every sanitizer run inherits, so a receipt
# can bind the toolchain, the cgroup caps and the symbolizer path
# (docs/REPRODUCIBILITY.md). Then execs the requested command.
#
# Refuses to run if a non-authority `openssl` CLI is reachable, exactly as the
# court entrypoint does: a sanitizer probe resolving against a wrong-version
# runtime would produce contaminated evidence, and such a run must fail loudly.
set -eu

if command -v openssl >/dev/null 2>&1; then
  echo "FATAL: non-authority 'openssl' binary is on PATH: $(command -v openssl)" >&2
  echo "       The ASan venue must not expose a system OpenSSL CLI." >&2
  exit 90
fi

# Pin the symbolizer so ASan reports name file:line even if PATH is rewritten by
# a caller. `llvm-symbolizer` is asserted at image build time.
if command -v llvm-symbolizer >/dev/null 2>&1; then
  export ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer)"
fi

mkdir -p /asan
{
  echo "venue=openssl-rs-asan"
  echo "asan_toolchain:"
  echo "  nightly=${ASAN_NIGHTLY:-unknown}"
  echo "  rustc=$(rustc +"${ASAN_NIGHTLY:-nightly}" --version 2>/dev/null)"
  echo "  cargo=$(cargo +"${ASAN_NIGHTLY:-nightly}" --version 2>/dev/null)"
  echo "  cc=$(cc --version 2>/dev/null | head -1)"
  echo "  clang=$(clang --version 2>/dev/null | head -1)"
  echo "  llvm_symbolizer=$(llvm-symbolizer --version 2>/dev/null | head -1)"
  echo "  ld=$(ld --version 2>/dev/null | head -1)"
  echo "  nm=$(nm --version 2>/dev/null | head -1)"
  echo "  python=$(python3 --version 2>/dev/null)"
  echo "asan_options=${ASAN_OPTIONS:-}"
} > /asan/toolchain.txt 2>/dev/null || true

exec "$@"
