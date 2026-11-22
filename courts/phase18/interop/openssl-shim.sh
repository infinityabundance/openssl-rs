#!/bin/sh
# openssl-shim.sh — the authority `openssl` CLI, on PATH for the harness.
#
# `regress/ssh2putty.sh` invokes `openssl` by name. Without it on PATH, the putty
# tests that convert keys silently skip or fail. The authority's CLI needs its own
# library path, so the shim (not the bare binary) is what goes on PATH.
#
# The 96-script matrix run used an untracked copy of this; it is tracked here so
# the reproduction does not depend on a work directory.
#
# Usage: place a symlink or copy named `openssl` that execs this script, with
# OSR_AUTHORITY_PREFIX set, or call it directly as `openssl-shim.sh`.
set -eu
: "${OSR_AUTHORITY_PREFIX:?set OSR_AUTHORITY_PREFIX to the pinned authority prefix}"
LD_LIBRARY_PATH="$OSR_AUTHORITY_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    exec "$OSR_AUTHORITY_PREFIX/bin/openssl" "$@"
