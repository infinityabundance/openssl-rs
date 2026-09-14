#!/bin/sh
# openssl-rs court entrypoint.
#
# Records the execution environment every court run inherits, so that receipts
# can bind the court's toolchain and resource caps (docs/REPRODUCIBILITY.md).
# Then execs the requested command.
#
# Refuses to run if a non-authority `openssl` CLI is reachable: that would make
# accidental use of a wrong-version authority possible, and such a run must fail
# loudly rather than produce contaminated evidence.
set -eu

if command -v openssl >/dev/null 2>&1; then
  echo "FATAL: non-authority 'openssl' binary is on PATH: $(command -v openssl)" >&2
  echo "       The court image must not expose a system OpenSSL CLI." >&2
  exit 90
fi

mkdir -p /court
{
  echo "court=openssl-rs-court"
  echo "court_toolchain:"
  echo "  cc=$(cc --version 2>/dev/null | head -1)"
  echo "  clang=$(clang --version 2>/dev/null | head -1)"
  echo "  ld=$(ld --version 2>/dev/null | head -1)"
  echo "  nm=$(nm --version 2>/dev/null | head -1)"
  echo "  readelf=$(readelf --version 2>/dev/null | head -1)"
  echo "  python=$(python3 --version 2>/dev/null)"
  echo "  perl=$(perl -e 'print $]' 2>/dev/null)"
  echo "  rustc=$(rustc --version 2>/dev/null)"
  echo "  cargo=$(cargo --version 2>/dev/null)"
} > /court/toolchain.txt 2>/dev/null || true
cat /court/non-authority-openssl.txt >> /court/toolchain.txt 2>/dev/null || true

exec "$@"
