#!/bin/sh
# Compile the minimized reproducer against one OpenSSL install prefix.
set -eu
: "${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the prefix under test}"
cc -Wall -Wextra -I"$OPENSSL_PREFIX/include" -o repro repro.c \
   -L"$OPENSSL_PREFIX/lib" -lssl -lcrypto -Wl,-rpath,"$OPENSSL_PREFIX/lib"
