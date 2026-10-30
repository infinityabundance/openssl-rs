#!/bin/sh
# Run the minimized reproducer against one OpenSSL install prefix.
set -eu
: "${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the prefix under test}"
LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ./repro
