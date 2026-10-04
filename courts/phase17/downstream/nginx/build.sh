#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build an UNMODIFIED nginx against the candidate shell.
#
# This is the TLS-*server* proof slice for the Phase 17 downstream court. The client slice
# (courts/phase17/downstream/curl) proved the candidate can *consume* TLS; this proves it can
# *terminate* TLS as a real https server. The only inputs are the pinned tarball (URL + sha256
# below) and the candidate distribution surface (`artifacts/phase2/install/{include,lib}`).
#
# Everything runs inside Docker. With the court container:
#
#   bash docker/openssl-rs-court.sh build          # once, if the image is missing
#   bash docker/openssl-rs-court.sh up
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/nginx/build.sh
#
# Toolchain required (all present in openssl-rs-court:1): a C compiler, GNU make, /bin/sh,
# and zlib. nginx's release tarball ships a generated `configure`, so no autotools are needed.
#
# Why these configure flags:
#   --with-http_ssl_module  the module under test, built against the candidate libssl/libcrypto
#   --with-cc-opt=...       put the candidate's headers on the include path for nginx's feature
#                           tests *and* the real compile (nginx has no --openssl-prefix switch
#                           for a prebuilt tree — see NOTE below)
#   --with-ld-opt=...       put the candidate's lib/*.so on the link path and bake an rpath so
#                           the running `nginx` resolves libssl.so.3/libcrypto.so.3 from the
#                           candidate prefix
#   --without-http_rewrite_module
#                           nginx's rewrite module hard-depends on PCRE; the court image ships
#                           only the pcre2 *runtime* (no headers), and PCRE is irrelevant to TLS.
#                           Dropping it is the minimal way to satisfy "no PCRE if avoidable".
#   --without-http_gzip_module
#                           drops the one remaining optional dependency (zlib) so the only
#                           shared objects in `ldd objs/nginx` are the candidate's + libc.
#
# NOTE on --with-openssl=<path>: that option does NOT link a prebuilt prefix. It points nginx at
# an OpenSSL *source tree*, which nginx then builds into `<path>/.openssl/` and statically embeds
# (auto/lib/openssl/conf, the `OPENSSL != NONE` branch). Pointing it at the candidate *install*
# prefix (`include/`, `lib/`) fails, because there is no `./config` there. Linking the candidate's
# shared libssl.so.3/libcrypto.so.3 is done with --with-cc-opt/--with-ld-opt and no --with-openssl,
# which takes nginx's `else` branch (probe with `-lssl -lcrypto` + the supplied flags).
#
# NOT MODIFIED: the nginx source tree is used exactly as released; only the build flags differ.
#
set -eu

NGINX_VERSION=1.26.3
NGINX_URL=https://nginx.org/download/nginx-1.26.3.tar.gz
NGINX_SHA256=69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/nginx}
INSTALL=${INSTALL:-$WORK/install}

if [ ! -f "$CANDIDATE/lib/libssl.so.3" ] || [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libssl.so.3/libcrypto.so.3" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"

if [ ! -f "nginx-$NGINX_VERSION.tar.gz" ]; then
    echo "build.sh: fetching $NGINX_URL"
    curl -fsSL -o "nginx-$NGINX_VERSION.tar.gz" "$NGINX_URL"
fi

echo "$NGINX_SHA256  nginx-$NGINX_VERSION.tar.gz" | sha256sum -c -
echo "build.sh: sha256 ok for nginx-$NGINX_VERSION.tar.gz"

cd "$WORK"
rm -rf "nginx-$NGINX_VERSION"
tar xf "dl/nginx-$NGINX_VERSION.tar.gz"

SRC="$WORK/nginx-$NGINX_VERSION"
cd "$SRC"

./configure \
    --prefix="$INSTALL" \
    --sbin-path="$INSTALL/sbin/nginx" \
    --conf-path="$INSTALL/conf/nginx.conf" \
    --with-http_ssl_module \
    --without-http_rewrite_module \
    --without-http_gzip_module \
    --with-cc-opt="-I$CANDIDATE/include" \
    --with-ld-opt="-L$CANDIDATE/lib -Wl,-rpath,$CANDIDATE/lib" \
    > "$WORK/configure.log" 2>&1

echo "build.sh: configured"
sed -n '1,40p' "$WORK/configure.log"

make -j"$(nproc)" > "$WORK/make.log" 2>&1
echo "build.sh: built $SRC/objs/nginx"

echo "build.sh: --- nginx -V (configure line records the candidate paths) ---"
"$SRC/objs/nginx" -V

echo "build.sh: --- ldd (must resolve libssl/libcrypto from the candidate prefix) ---"
ldd "$SRC/objs/nginx"
