#!/bin/sh
#
# openssl-rs — Phase 17 downstream: build an UNMODIFIED portable OpenSSH against
# the candidate shell.
#
# OpenSSH is a *libcrypto-only* consumer: it uses OpenSSL for primitives
# (EVP ciphers/digests, HMAC, KDF, BN, EC, RSA, Ed25519), never for TLS, so it
# never links libssl. This slice therefore exercises a different corner of the
# candidate than the TLS courts (curl/nginx/HAProxy).
#
# Everything runs inside Docker. With the court container:
#
#   bash docker/openssl-rs-court.sh build          # once, if the image is missing
#   bash docker/openssl-rs-court.sh up
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/openssh/build.sh
#
# Toolchain required (all present in openssl-rs-court:1): gcc, GNU make, /bin/sh,
# zlib headers, and the candidate install prefix. No autotools/bsdmake needed:
# the portable release tarball ships a generated `configure`, and the portable
# top-level Makefile's `tests`/`unit` targets drive the bundled regress suite
# through GNU make.
#
# Why these configure flags:
#   --with-ssl-dir=<candidate>  the one flag that matters: it puts
#                               -I<candidate>/include on CPPFLAGS and
#                               -L<candidate>/lib plus the platform rpath option
#                               (-Wl,-rpath,<candidate>/lib) on LDFLAGS, and it
#                               picks <candidate>/bin/openssl as OPENSSL_BIN so
#                               the regress suite uses the candidate CLI too.
#   --with-privsep-path=...     privilege-separation chroot, inside the scratch
#                               prefix so the probe can own it
#   --sysconfdir=...            keep sshd_config/ssh_config under the scratch prefix
#   (PAM/SELinux/Kerberos/ldns stay off: their headers are deliberately absent
#    from the minimal court image, and none of them touch the crypto path.)
#
# NOT MODIFIED: the OpenSSH source tree is used exactly as released; only the
# build flags differ.
set -eu

OPENSSH_VERSION=10.5p1
OPENSSH_URL=https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz
OPENSSH_SHA256=d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/court/openssh}
# NOTE: the prefix is kept in PREFIX, not INSTALL: autoconf's Makefile uses
# $(INSTALL) for the install(1) program, and an INSTALL variable inherited from
# the environment would silently override it (`make install` then tries to run
# the prefix directory as a program). Callers may still pass INSTALL= for
# compatibility with the other downstream build.sh scripts.
PREFIX=${PREFIX:-${INSTALL:-$WORK/install}}
unset INSTALL

if [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build.sh: candidate install prefix '$CANDIDATE' does not hold libcrypto.so.3" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"

if [ ! -f "openssh-$OPENSSH_VERSION.tar.gz" ]; then
    echo "build.sh: fetching $OPENSSH_URL"
    curl -fsSL -o "openssh-$OPENSSH_VERSION.tar.gz" "$OPENSSH_URL"
fi

echo "$OPENSSH_SHA256  openssh-$OPENSSH_VERSION.tar.gz" | sha256sum -c -
echo "build.sh: sha256 ok for openssh-$OPENSSH_VERSION.tar.gz"

cd "$WORK"
rm -rf "openssh-$OPENSSH_VERSION"
tar xf "dl/openssh-$OPENSSH_VERSION.tar.gz"

SRC="$WORK/openssh-$OPENSSH_VERSION"
cd "$SRC"

# On Linux the released configure leaves rpath_opt empty, so --with-ssl-dir alone
# only adds -L<candidate>/lib for the *link*: the configure-time "OpenSSL library
# version" probe (and every linked binary) then loads the system libcrypto
# (3.0.x) at run time and the header/library consistency check fails. Supplying
# the rpath explicitly makes the candidate the run-time libcrypto everywhere.
export LDFLAGS="-Wl,-rpath,$CANDIDATE/lib ${LDFLAGS:-}"

./configure \
    --prefix="$PREFIX" \
    --sysconfdir="$PREFIX/etc" \
    --with-ssl-dir="$CANDIDATE" \
    --with-privsep-user=sshd \
    --with-privsep-path="$PREFIX/var/empty" \
    > "$WORK/configure.log" 2>&1

echo "build.sh: configured; OpenSSL line(s) from configure:"
grep -iE "OpenSSL|ssl-dir|rpath" "$WORK/configure.log" | head -20 || true

make -j"$(nproc)" > "$WORK/make.log" 2>&1
echo "build.sh: built $SRC/{ssh,sshd,ssh-keygen,ssh-agent,ssh-add}"

# OpenSSH 10.x splits sshd into a listener plus a per-connection `sshd-session`
# helper that it exec()s from <prefix>/libexec. Without `make install` that helper
# is absent and sshd refuses every connection, so install into the scratch prefix.
make install > "$WORK/install.log" 2>&1
echo "build.sh: installed to $PREFIX (sbin/sshd, bin/ssh, libexec/sshd-session)"
ls "$PREFIX/sbin/sshd" "$PREFIX/libexec/sshd-session" >/dev/null

echo "build.sh: --- ssh -V (must report OpenSSL 3.6.4, the candidate) ---"
"$SRC/ssh" -V

echo "build.sh: --- ldd (libcrypto MUST resolve from the candidate prefix; no libssl) ---"
for b in ssh sshd ssh-keygen ssh-agent ssh-add; do
    echo "### $b"
    ldd "$SRC/$b" | grep -E "libcrypto|libssl|libz|libc\." || true
done
