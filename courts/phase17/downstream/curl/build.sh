#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build an UNMODIFIED curl against the candidate shell.
#
# This is the proof-of-concept slice for the Phase 17 downstream court: a real, unmodified
# upstream release is configured and built against the *shipped distribution surface* of the
# candidate (`artifacts/phase2/install/{include,lib}`), not the crate and not the authority.
# The only inputs are the pinned tarball (URL + sha256 below) and the candidate install prefix.
#
# Everything runs inside Docker. With the court container:
#
#   bash docker/openssl-rs-court.sh build          # once, if the image is missing
#   bash docker/openssl-rs-court.sh up
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/curl/build.sh
#
# Toolchain required (all present in openssl-rs-court:1): a C compiler, GNU make, /bin/sh,
# pkg-config and zlib headers. curl's release tarball ships a generated `configure`, so no
# autotools/libtool/cmake are needed.
#
# Why these configure flags:
#   --with-openssl=<prefix>  link the candidate's libssl/libcrypto, not the system's
#   CPPFLAGS/LDFLAGS/-rpath  point the compiler/linker/runtime at the candidate install
#   --disable-shared         build a static libcurl into the `curl` tool, so the only shared
#                            objects in `ldd` are the candidate libssl/libcrypto (+ libc)
#   the --disable-*/--without-* set removes optional protocols/deps not installed in the
#                            court, keeping the build small and self-contained
#
# NOT MODIFIED: the curl source tree is used exactly as released; only the build flags differ.
#
set -eu

CURL_VERSION=8.22.0
CURL_URL=https://curl.se/download/curl-8.22.0.tar.gz
CURL_SHA256=d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/curl}
INSTALL=${INSTALL:-$WORK/install}

if [ ! -f "$CANDIDATE/lib/libssl.so.3" ] || [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libssl.so.3/libcrypto.so.3" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"

if [ ! -f "curl-$CURL_VERSION.tar.gz" ]; then
    echo "build.sh: fetching $CURL_URL"
    curl -fsSL -o "curl-$CURL_VERSION.tar.gz" "$CURL_URL"
fi

echo "$CURL_SHA256  curl-$CURL_VERSION.tar.gz" | sha256sum -c -
echo "build.sh: sha256 ok for curl-$CURL_VERSION.tar.gz"

cd "$WORK"
rm -rf "curl-$CURL_VERSION"
tar xf "dl/curl-$CURL_VERSION.tar.gz"

SRC="$WORK/curl-$CURL_VERSION"
cd "$SRC"

# Write the compiler flags the way curl's configure wants them (the candidate's pkg-config
# metadata records a /usr/local prefix, which does not match the tree it ships in, so the
# prefix is given explicitly here rather than via PKG_CONFIG_PATH).
CPPFLAGS="-I$CANDIDATE/include"
LDFLAGS="-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib"
export CPPFLAGS LDFLAGS

./configure \
    --prefix="$INSTALL" \
    --with-openssl="$CANDIDATE" \
    --disable-shared --disable-ldap --disable-ldaps --disable-rtsp \
    --disable-dict --disable-telnet --disable-tftp --disable-pop3 \
    --disable-imap --disable-smtp --disable-gopher --disable-mqtt \
    --without-libpsl --without-brotli --without-zstd --without-nghttp2 \
    --without-libidn2 --without-librtmp --without-libssh2 \
    --disable-manual --disable-threaded-resolver \
    > "$WORK/configure.log" 2>&1

echo "build.sh: configured"
grep -E "  SSL:|  curl version:|OpenSSL with QUIC|built with one SSL backend" "$WORK/configure.log" || true

make -j"$(nproc)" > "$WORK/make.log" 2>&1
echo "build.sh: built $SRC/src/curl"

"$SRC/src/curl" -V

echo "build.sh: --- ldd (must show candidate libssl/libcrypto) ---"
ldd "$SRC/src/curl"
