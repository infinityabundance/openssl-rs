#!/usr/bin/env bash
# ETP-6 offline verifier.
#
# Runs with no network and reads only paths below this directory.  The archive
# that carries this script was produced by forensics/tools/etp6_package.py from
# the named commit; nothing here reaches back to the development repository.
#
#   ./verify.sh              steps 1-5 (reproducibility is NOT_RUN, deferred)
#   ./verify.sh --full       also run the two-build reproducibility step
#   ./verify.sh --only ID    one step, used by the mutation tests
#   ./verify.sh --list       list the steps
#
# Exit status: 0 only when every required selected step is PASS.  A NOT_RUN is
# never a pass.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE" || { echo "verify: cannot enter $HERE" >&2; exit 2; }

PY=${ETP6_PYTHON:-python3}
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "verify: python3 is required but was not found" >&2
  exit 2
fi

# The verifier performs no network I/O.  These settings do not add a sandbox;
# they make an accidental network attempt fail fast instead of reaching out.
export NO_PROXY='*'
export no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy 2>/dev/null || true

# The verifier must not write into the unpacked tree; bytecode caches would be
# files the manifest does not name.  Use the system temporary directory.
export PYTHONDONTWRITEBYTECODE=1

exec "$PY" forensics/tools/etp6_verify.py "$@"
