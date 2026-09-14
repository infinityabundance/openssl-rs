#!/bin/sh
# openssl-rs FRF candidate reference: OpenSSL 3.6.4 (production authority),
# as built inside the court container under the profile
# linux-x86_64-default-shared-legacy-notests.
#
# Why a wrapper rather than the ELF binary directly: the authority is built
# out-of-tree and installed under its own prefix, so its `openssl` executable
# resolves libcrypto/libssl from that prefix. Executing it without binding
# LD_LIBRARY_PATH would silently resolve the *contaminating system OpenSSL*
# (docs/AUTHORITY_POLICY.md §4.1) and the observation would be worthless. The
# wrapper binds the prefix and is itself hashed by FRF admission.
#
# The real dependencies (the ELF binary and both libraries) are declared in the
# court manifest's `execution_context`, so they are snapshotted and
# content-addressed at observation time. This wrapper is not hiding them.
#
# `OPENSSL_CONF=/dev/null` disables configuration loading: configuration is a
# separate observable surface (its own court), and inheriting an ambient config
# would make the observation non-reproducible.
set -eu
PREFIX=/work/forensics/authorities/prefix/openssl-3.6.4-production
LD_LIBRARY_PATH="$PREFIX/lib"
OPENSSL_MODULES="$PREFIX/lib/ossl-modules"
OPENSSL_CONF=/dev/null
export LD_LIBRARY_PATH OPENSSL_MODULES OPENSSL_CONF
exec "$PREFIX/bin/openssl" "$@"
