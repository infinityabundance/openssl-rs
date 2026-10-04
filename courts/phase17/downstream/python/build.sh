#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build UNMODIFIED CPython against the candidate shell.
#
# This is the proof-of-concept slice for CPython as a Phase 17 downstream court. A real,
# unmodified upstream CPython is configured and built against the *shipped distribution
# surface* of the candidate (`artifacts/phase2/install/{include,lib}`), not the crate and
# not the authority. The only inputs are the pinned tarball (URL + sha256 below) and the
# candidate install prefix.
#
# Everything runs inside Docker. With the court container up:
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/python/build.sh
#
# Toolchain required (all present in openssl-rs-court:1): gcc, GNU make, perl, /bin/sh,
# pkg-config and zlib headers. CPython's release tarball ships a generated `configure`, so
# no autotools/libtool/cmake are needed. **No extra Dockerfile is required for this slice.**
#
# Why these configure flags:
#   --with-openssl=<prefix>      link the candidate's libssl/libcrypto, not a system one
#   --with-openssl-rpath=auto    bake the candidate lib dir into the extension modules' rpath
#   CPPFLAGS/LDFLAGS/-rpath      belt-and-suspenders: applies the include/lib/rpath to every
#                                compile and link, including the `_ssl`/`_hashlib` extension
#                                modules (whose own RUNPATH matters, since DT_RUNPATH does
#                                not apply to indirect dependencies)
#   --without-ensurepip          no bundled pip/setuptools build
#   CFLAGS=-O2                   faster than the -O3 default; behaviour is identical here
#
# NOT MODIFIED: the CPython source tree is used exactly as released; only the build flags
# differ.
#
# The build is deliberately left in-tree: `$SRC/python` is the real interpreter with the
# full `Lib/` stdlib, so `test_ssl` runs from the build directory with no install step.
#
set -eu

CPYTHON_VERSION=3.12.15
CPYTHON_URL=https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz
# Pin computed from the python.org artifact on 2026-10-04 (python.org publishes no
# .sha256 sidecar for this release; it publishes .spdx.json/.sigstore instead).
CPYTHON_SHA256=c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/python}
INSTALL=${INSTALL:-$WORK/install}
JOBS=${JOBS:-8}

if [ ! -f "$CANDIDATE/lib/libssl.so.3" ] || [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libssl.so.3/libcrypto.so.3" >&2
    exit 2
fi
if [ ! -f "$CANDIDATE/include/openssl/ssl.h" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold include/openssl/ssl.h" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"

if [ ! -f "Python-$CPYTHON_VERSION.tar.xz" ]; then
    echo "build.sh: fetching $CPYTHON_URL"
    curl -fsSL -o "Python-$CPYTHON_VERSION.tar.xz" "$CPYTHON_URL"
fi

echo "$CPYTHON_SHA256  Python-$CPYTHON_VERSION.tar.xz" | sha256sum -c -
echo "build.sh: sha256 ok for Python-$CPYTHON_VERSION.tar.xz"

echo "build.sh: stage=extract"
cd "$WORK"
rm -rf "Python-$CPYTHON_VERSION"
tar xf "dl/Python-$CPYTHON_VERSION.tar.xz"

SRC="$WORK/Python-$CPYTHON_VERSION"
cd "$SRC"

CPPFLAGS="-I$CANDIDATE/include"
LDFLAGS="-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib"
CFLAGS="-O2"
export CPPFLAGS LDFLAGS CFLAGS

echo "build.sh: stage=configure"
./configure \
    --prefix="$INSTALL" \
    --with-openssl="$CANDIDATE" \
    --with-openssl-rpath=auto \
    --without-ensurepip \
    > "$WORK/configure.log" 2>&1

echo "build.sh: configured; openssl detection:"
grep -iE 'checking for openssl|openssl.*(version|found)|SSL' "$WORK/configure.log" | tail -20 || true

echo "build.sh: stage=make"
make -j"$JOBS" > "$WORK/make.log" 2>&1

echo "build.sh: stage=built"
"$SRC/python" -VV

echo "build.sh: --- ldd ($SRC/python) ---"
ldd "$SRC/python" | grep -E 'libssl|libcrypto' || echo "build.sh: WARNING: no libssl/libcrypto in ldd of interpreter"
echo "build.sh: --- ldd (_ssl extension) ---"
SSLSO=$(find "$SRC" -name '_ssl*.so' -print -quit)
echo "build.sh: _ssl = $SSLSO"
ldd "$SSLSO" | grep -E 'libssl|libcrypto' || echo "build.sh: WARNING: no libssl/libcrypto in ldd of _ssl"

echo "build.sh: OK"
