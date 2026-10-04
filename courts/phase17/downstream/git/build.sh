#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build UNMODIFIED Git against the candidate shell.
#
# This is the Git proof slice for the Phase 17 downstream court. A real, unmodified
# upstream Git release is configured and built against the *shipped distribution surface*
# of the candidate (`artifacts/phase2/install/{include,lib}`), not the crate and not the
# authority. Git's OpenSSL use is two-fold:
#
#   * SHA-1 / SHA-256 object hashing, which Git routes through OpenSSL when
#     OPENSSL_SHA1=YesPlease / OPENSSL_SHA256=YesPlease are set (the default is Git's
#     own in-tree `block-sha1` / SHA-256 code and SHA-1 collision detection).
#   * the https:// transport, via libcurl. We first build a *shared* libcurl against
#     the same candidate (reusing the exact pinned curl tarball that the sibling
#     courts/phase17/downstream/curl slice uses; that slice deliberately builds curl
#     statically into the `curl` tool and installs no libcurl, so a shared one is
#     produced here) and point Git's `--with-curl` at it.
#
# Everything runs inside Docker. With the court container up:
#
#   bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/build.sh
#
# Toolchain required (all present in openssl-rs-court:1): gcc, GNU make, /bin/sh, perl,
# pkg-config and zlib headers. Both curl's and Git's release tarballs ship a generated
# `configure`, so no autotools/libtool/cmake are needed.
#
# Why these configure/build flags:
#   --with-openssl=$CANDIDATE   set OPENSSLDIR so configure probes the candidate's
#                               libcrypto for SHA1_Init and libssl is never taken from
#                               the system (the court deliberately has libssl3 3.0.x as a
#                               known contaminant via Debian's libcurl4).
#   OPENSSL_SHA1=YesPlease      compile git's SHA-1 through OpenSSL (-DSHA1_OPENSSL) and
#   OPENSSL_SHA256=YesPlease    compile git's SHA-256 through OpenSSL (-DSHA256_OPENSSL);
#                               both add $(LIB_4_CRYPTO) = candidate -lcrypto to the link.
#   --with-curl=$DEPS           set CURLDIR to the candidate-linked shared libcurl; Git
#                               derives -L/-rpath from CURLDIR but the actual -lcurl comes
#                               from CURL_LDFLAGS (normally populated from curl-config,
#                               which the deliberately curl-dev-free court does not have),
#                               so CURL_LDFLAGS=-lcurl is passed explicitly.
#   CPPFLAGS/LDFLAGS/-rpath     belt-and-suspenders: the candidate include/lib dirs and an
#                               rpath on every binary, so the helpers resolve the
#                               candidate libcrypto/libcurl at runtime.
#   NO_TCLTK=1 NO_GETTEXT=1     skip gitk/git-gui (no Tcl) and translations (no msgfmt);
#                               neither is needed to run t/ and neither is TLS related.
#
# NOT MODIFIED: the Git and curl source trees are used exactly as released; only the
# build flags differ.
#
set -eu

# Git release, pinned. sha256 published in the signed kernel.org
# <https://mirrors.edge.kernel.org/pub/software/scm/git/sha256sums.asc>.
GIT_VERSION=2.56.0
GIT_URL=https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz
GIT_SHA256=26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3

# curl release, pinned to the same version/sha as courts/phase17/downstream/curl.
CURL_VERSION=8.22.0
CURL_URL=https://curl.se/download/curl-8.22.0.tar.gz
CURL_SHA256=d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/git}
DEPS=${DEPS:-$WORK/deps}
INSTALL=${INSTALL:-$WORK/install}
JOBS=${JOBS:-8}

if [ ! -f "$CANDIDATE/lib/libssl.so.3" ] || [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libssl.so.3/libcrypto.so.3" >&2
    exit 2
fi
if [ ! -f "$CANDIDATE/include/openssl/sha.h" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold include/openssl/sha.h" >&2
    exit 2
fi

mkdir -p "$WORK/dl"

# --- 1. shared libcurl against the candidate --------------------------------
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
cd "curl-$CURL_VERSION"

CPPFLAGS="-I$CANDIDATE/include"
LDFLAGS="-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib"
export CPPFLAGS LDFLAGS

./configure \
    --prefix="$DEPS" \
    --with-openssl="$CANDIDATE" \
    --enable-shared --disable-static \
    --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet \
    --disable-tftp --disable-pop3 --disable-imap --disable-smtp --disable-gopher \
    --disable-mqtt --without-libpsl --without-brotli --without-zstd --without-nghttp2 \
    --without-libidn2 --without-librtmp --without-libssh2 \
    --disable-manual --disable-threaded-resolver \
    > "$WORK/curl-configure.log" 2>&1

echo "build.sh: curl configured (shared)"
grep -E "  SSL:|libcurl version:|built with one SSL backend" "$WORK/curl-configure.log" || true

make -j"$JOBS" > "$WORK/curl-make.log" 2>&1
make install > "$WORK/curl-install.log" 2>&1
echo "build.sh: built + installed shared libcurl into $DEPS"
ldd "$DEPS/lib/libcurl.so" | grep -E 'libssl|libcrypto' || echo "build.sh: WARNING: libcurl does not link libssl/libcrypto"

# --- 2. Git against the candidate -------------------------------------------
cd "$WORK/dl"
if [ ! -f "git-$GIT_VERSION.tar.xz" ]; then
    echo "build.sh: fetching $GIT_URL"
    curl -fsSL -o "git-$GIT_VERSION.tar.xz" "$GIT_URL"
fi
echo "$GIT_SHA256  git-$GIT_VERSION.tar.xz" | sha256sum -c -
echo "build.sh: sha256 ok for git-$GIT_VERSION.tar.xz"

cd "$WORK"
rm -rf "git-$GIT_VERSION"
tar xf "dl/git-$GIT_VERSION.tar.xz"

SRC="$WORK/git-$GIT_VERSION"
cd "$SRC"

# The curl prefix's bin/curl-config is deliberately NOT put on PATH: configure would then
# bake the shared library's transitive -l list into CURL_LDFLAGS, while leaving it off
# makes Git link exactly -lcurl from CURLDIR and let the loader follow DT_NEEDED.
CPPFLAGS="-I$CANDIDATE/include -I$DEPS/include"
LDFLAGS="-L$CANDIDATE/lib -L$DEPS/lib -Wl,-rpath,$CANDIDATE/lib -Wl,-rpath,$DEPS/lib"
export CPPFLAGS LDFLAGS

./configure \
    --prefix="$INSTALL" \
    --with-openssl="$CANDIDATE" \
    --with-curl="$DEPS" \
    > "$WORK/configure.log" 2>&1

echo "build.sh: configured"
grep -E "Setting (OPENSSLDIR|CURLDIR)|NO_OPENSSL|NO_CURL|NO_EXPAT|checking whether to use OpenSSL|checking for curl" \
    "$WORK/configure.log" || true

make -j"$JOBS" \
    OPENSSL_SHA1=YesPlease OPENSSL_SHA256=YesPlease \
    CURL_LDFLAGS=-lcurl NO_TCLTK=1 NO_GETTEXT=1 \
    > "$WORK/make.log" 2>&1

echo "build.sh: built $SRC/git"
"$SRC/git" --version

echo "build.sh: --- ldd (git: SHA-1/SHA-256 via the candidate's libcrypto) ---"
ldd "$SRC/git" | grep -E 'libssl|libcrypto' || echo "build.sh: WARNING: git does not link libssl/libcrypto"
echo "build.sh: --- ldd (git-remote-https: https via candidate-linked libcurl) ---"
ldd "$SRC/git-remote-https"

echo "build.sh: OK"
