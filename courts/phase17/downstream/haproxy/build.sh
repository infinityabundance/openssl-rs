#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build an UNMODIFIED HAProxy against the candidate shell.
#
# HAProxy is the *load balancer / TLS terminator* slice of the Phase 17 downstream court: unlike
# curl (a TLS client) or nginx (a TLS server), HAProxy terminates TLS in front of a separate
# plain-HTTP backend and proxies across it, so it exercises the candidate's libssl/libcrypto in a
# front-end listener whose only job is the handshake plus re-encryption policy.
#
# The only inputs are the pinned tarball (URL + sha256 below) and the candidate distribution
# surface (`artifacts/phase2/install/{include,lib}`). Everything runs inside the court container:
#
#   bash docker/openssl-rs-court.sh up
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/haproxy/build.sh
#
# Toolchain: the existing `openssl-rs-court:1` image suffices. HAProxy has no `configure`; it is
# built with its own `make` and needs only a C compiler, GNU make, /bin/sh, zlib headers (present)
# and the candidate headers/libs. PCRE2 *headers* are deliberately absent from the image, so the
# build is left without PCRE and HAProxy falls back to the libc POSIX regex
# (`src/regex.c`: `#else ... regexec(...)`); regex ACLs are irrelevant to TLS termination, and
# wiring PCRE in would add a dependency that has nothing to do with the candidate. No extra
# Dockerfile is required for this slice.
#
# Why these make flags:
#   TARGET=linux-glibc  the court's userspace
#   USE_OPENSSL=1       link the candidate's libssl/libcrypto (this is the whole point)
#   SSL_INC=<cand>/include, SSL_LIB=<cand>/lib
#                       HAProxy's own switches for a non-system OpenSSL prefix (Makefile lines
#                       ~609-632): SSL_CFLAGS/SSL_LDFLAGS become -I<cand>/include and
#                       -L<cand>/lib -lssl -lcrypto, i.e. a SHARED link to the candidate.
#   USE_ZLIB=1          zlib headers are present; keeps the build close to a stock one
#   LDFLAGS=-Wl,-rpath,<cand>/lib
#                       bake an rpath so the running `haproxy` resolves libssl.so.3/libcrypto.so.3
#                       from the candidate prefix (HAProxy passes $(LDFLAGS) on the final link,
#                       Makefile line ~1041)
#
# NOT MODIFIED: the HAProxy source tree is used exactly as released; only the build flags differ.
#
set -eu

HAPROXY_VERSION=3.0.29
HAPROXY_URL=https://www.haproxy.org/download/3.0/src/haproxy-3.0.29.tar.gz
HAPROXY_SHA256=225dbddbab9eb0abc0ff3db39ded1e07f20028105a36f4c36fc2f85bf86835d1

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/haproxy}

if [ ! -f "$CANDIDATE/lib/libssl.so.3" ] || [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libssl.so.3/libcrypto.so.3" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"

if [ ! -f "haproxy-$HAPROXY_VERSION.tar.gz" ]; then
    echo "build.sh: fetching $HAPROXY_URL"
    curl -fsSL -o "haproxy-$HAPROXY_VERSION.tar.gz" "$HAPROXY_URL"
fi

echo "$HAPROXY_SHA256  haproxy-$HAPROXY_VERSION.tar.gz" | sha256sum -c -
echo "build.sh: sha256 ok for haproxy-$HAPROXY_VERSION.tar.gz"

cd "$WORK"
rm -rf "haproxy-$HAPROXY_VERSION"
tar xf "dl/haproxy-$HAPROXY_VERSION.tar.gz"

SRC="$WORK/haproxy-$HAPROXY_VERSION"
cd "$SRC"

# HAProxy has no configure step; `make` both configures and builds. The release tarball ships the
# generated version/SSL metadata, so no autotools/perl build step is needed.
make -j"$(nproc)" \
    TARGET=linux-glibc \
    USE_OPENSSL=1 \
    USE_ZLIB=1 \
    SSL_INC="$CANDIDATE/include" \
    SSL_LIB="$CANDIDATE/lib" \
    LDFLAGS="-Wl,-rpath,$CANDIDATE/lib" \
    > "$WORK/make.log" 2>&1

echo "build.sh: built $SRC/haproxy"

echo "build.sh: --- haproxy -vv (must show the candidate's OpenSSL) ---"
"$SRC/haproxy" -vv

echo "build.sh: --- ldd (must resolve libssl/libcrypto from the candidate prefix) ---"
ldd "$SRC/haproxy"

echo "build.sh: --- readelf RUNPATH ---"
readelf -d "$SRC/haproxy" | grep -E 'RUNPATH|RPATH|NEEDED.*(ssl|crypto)'
