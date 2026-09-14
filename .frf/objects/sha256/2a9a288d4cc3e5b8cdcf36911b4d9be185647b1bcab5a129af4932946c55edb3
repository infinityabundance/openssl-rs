#!/bin/sh
# openssl-rs FRF authority reference: OpenSSL 3.6.3 (historical authority), as
# built inside the court container under the profile
# linux-x86_64-default-shared-legacy-notests.
#
# 3.6.3 is the HISTORICAL authority: it is what extant downstream archaeology
# (bind9-rs) observed, and it is the "before" side of the 3.6.3 -> 3.6.4
# oracle-vs-oracle trajectory required by docs/SECURITY_DIVERGENCE_POLICY.md.
# It is never the production target.
#
# See refs/openssl-3.6.4.sh for why this is a wrapper and not the ELF binary
# directly (LD_LIBRARY_PATH binding, to prevent contaminating the observation
# with the system OpenSSL).
set -eu
PREFIX=/work/forensics/authorities/prefix/openssl-3.6.3-historical
LD_LIBRARY_PATH="$PREFIX/lib"
OPENSSL_MODULES="$PREFIX/lib/ossl-modules"
OPENSSL_CONF=/dev/null
export LD_LIBRARY_PATH OPENSSL_MODULES OPENSSL_CONF
exec "$PREFIX/bin/openssl" "$@"
