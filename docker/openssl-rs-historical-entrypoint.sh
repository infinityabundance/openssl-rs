#!/bin/sh
# openssl-rs historical-venue entrypoint.
#
# Records the execution environment every historical acquisition/build inherits, so a
# build receipt can bind the toolchain, the platform and the image
# (docs/REPRODUCIBILITY.md). Then execs the requested command.
#
# Refuses to run if a non-authority `openssl` CLI is reachable, exactly as the court
# entrypoint does: a build that silently linked against a distribution OpenSSL would
# produce contaminated evidence, and such a run must fail loudly.
set -eu

if command -v openssl >/dev/null 2>&1; then
  echo "FATAL: non-authority 'openssl' binary is on PATH: $(command -v openssl)" >&2
  echo "       The historical venue must not expose a system OpenSSL CLI." >&2
  exit 90
fi

mkdir -p /historical
{
  echo "venue=openssl-rs-historical"
  echo "historical_toolchain:"
  echo "  cc=$(cc --version 2>/dev/null | head -1)"
  echo "  gcc=$(gcc --version 2>/dev/null | head -1)"
  echo "  ld=$(ld --version 2>/dev/null | head -1)"
  echo "  make=$(make --version 2>/dev/null | head -1)"
  echo "  perl=$(perl -e 'print $]' 2>/dev/null)"
  echo "  python=$(python3 --version 2>/dev/null)"
  echo "  qemu=$(qemu-x86_64-static --version 2>/dev/null | head -1)"
} > /historical/toolchain.txt 2>/dev/null || true

exec "$@"
