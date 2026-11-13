#!/bin/sh
#
# openssl-rs — build an UNMODIFIED portable OpenSSH against the candidate
# install, as the consumer identity the OpenSSH closure analyses.
#
# This is the tracked relink recipe for the closure artefacts.  Earlier batches
# recorded the digest of an untracked `court/freeze-*/build-openssh-*.sh`
# (court/ is git-ignored), so the recipe that produced the analysed binaries
# could not be reproduced from the repository.  The recipe lives here, in a
# tracked path, so the artefact identity is reproducible.
#
# Everything runs inside the court container:
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/forensics/tools/build_openssh_closure.sh client-b76
#
# usage: build_openssh_closure.sh <role-tag>
#
# The role tag is an identity label for the tree that receives the build
# (court/tmp/openssh-closure/<role-tag>/openssh-<version>), not a different
# recipe: `ssh` and `sshd` are built from one unmodified source with one flag
# set.  Separate trees are used because `make` in a shared tree would rebuild
# between the two runs.
#
# Pinned source: OpenSSH 9.9p1 portable release tarball, sha256 recorded in
# forensics/downstream/build-link-atlas.json:
#   source:https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz#b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02
# The digest is verified before extraction; a mismatch aborts.
#
# Flags are the Phase 17 downstream ones (courts/phase17/downstream/openssh/
# build.sh): --with-ssl-dir puts the candidate on the include/link line and
# LDFLAGS pins the candidate lib directory on the run path, because the
# released Linux configure leaves rpath_opt empty.
set -eu

OPENSSH_VERSION=${OPENSSH_VERSION:-9.9p1}
OPENSSH_SHA256=${OPENSSH_SHA256:-b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02}
OPENSSH_URL=${OPENSSH_URL:-https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$OPENSSH_VERSION.tar.gz}

CANDIDATE=${CANDIDATE:-/work/artifacts/phase2/install}
WORK=${WORK:-/work/court/tmp/openssh-closure}
TAG=${1:?usage: build_openssh_closure.sh <role-tag>}

if [ ! -f "$CANDIDATE/lib/libcrypto.so.3" ]; then
    echo "build_openssh_closure.sh: '$CANDIDATE' does not hold libcrypto.so.3" >&2
    exit 2
fi

mkdir -p "$WORK/dl"
cd "$WORK/dl"
if [ ! -f "openssh-$OPENSSH_VERSION.tar.gz" ]; then
    echo "build_openssh_closure.sh: fetching $OPENSSH_URL"
    curl -fsSL -o "openssh-$OPENSSH_VERSION.tar.gz" "$OPENSSH_URL"
fi
echo "$OPENSSH_SHA256  openssh-$OPENSSH_VERSION.tar.gz" | sha256sum -c -

ROOT="$WORK/$TAG"
rm -rf "$ROOT"
mkdir -p "$ROOT"
cd "$ROOT"
tar xf "$WORK/dl/openssh-$OPENSSH_VERSION.tar.gz"
SRC="$ROOT/openssh-$OPENSSH_VERSION"
PREFIX="$ROOT/install"

cd "$SRC"
export LDFLAGS="-Wl,-rpath,$CANDIDATE/lib ${LDFLAGS:-}"
./configure \
    --prefix="$PREFIX" \
    --sysconfdir="$PREFIX/etc" \
    --with-ssl-dir="$CANDIDATE" \
    --with-privsep-user=sshd \
    --with-privsep-path="$PREFIX/var/empty" \
    > "$ROOT/configure.log" 2>&1
grep -iE "OpenSSL|ssl-dir|rpath" "$ROOT/configure.log" | head -20 || true

make -j"$(nproc)" > "$ROOT/make.log" 2>&1
make install > "$ROOT/install.log" 2>&1

echo "build_openssh_closure.sh: --- ssh -V ---"
"$SRC/ssh" -V
echo "build_openssh_closure.sh: --- ldd ---"
for b in ssh sshd ssh-keygen; do
    echo "### $b"
    ldd "$SRC/$b" | grep -E "libcrypto|libssl" || true
done
echo "build_openssh_closure.sh: --- digests ---"
for b in ssh sshd sshd-session; do
    if [ -f "$SRC/$b" ]; then sha256sum "$SRC/$b"; fi
done
echo "build_openssh_closure.sh: source=$SRC prefix=$PREFIX"
