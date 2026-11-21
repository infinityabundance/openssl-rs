#!/usr/bin/env bash
#
# build_tools.sh — O3: build the third-party SSH implementations and configure
# OpenSSH so the interop harness can see them.
#
# Run from the repository root:
#   PREFIX=$PWD/court/tmp/o3/prefix O3_WORK=$PWD/court/tmp/o2 \
#     bash courts/phase18/interop/build_tools.sh
#
# It expects the pinned archives in $O3_WORK (fetch_pinned.sh /
# verify_pins.py --fetch puts them there) and refuses to build from anything
# whose digest is not the manifest's.
#
# Two findings this script exists to make reproducible:
#
#  1. OpenSSH's `regress/test-exec.sh` does *not* detect these tools. It
#     defaults to /usr/local/bin/{plink,puttygen,dropbear,dbclient,dropbearkey,
#     dropbearconvert} and only overrides them from TEST_SSH_* variables, which
#     `configure` fills from ACL_PATH_PROG results — and the `interop-tests`
#     target of the generated Makefile is what passes them into the harness.
#     So the detectable surface is (a) `config.log`'s `checking for <tool>`
#     lines and (b) the TEST_SSH_* block of the generated Makefile. Neither is
#     assumed here: verify_detection.sh asserts both.
#  2. Dropbear installs the server binary to `sbindir` and the client tools to
#     `bindir`. A PATH containing only `bin` produces
#     `checking for dropbear ... no` while dbclient/dropbearkey/dropbearconvert
#     are found, which is exactly the kind of silent partial detection this
#     item is meant to catch. Both directories are on PATH below.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${O3_WORK:-$ROOT/court/tmp/o2}"
PREFIX="${PREFIX:-$ROOT/court/tmp/o3/prefix}"
AUTH="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
SSH_BUILD="${SSH_BUILD:-$ROOT/court/tmp/o3/openssh-9.9p1}"

die() { echo "build_tools: $*" >&2; exit 1; }

echo "=== verifying the pinned archives ==="
python3 "$ROOT/courts/phase18/interop/verify_pins.py" --work "$WORK" --fetch \
    --receipt "${O3_PIN_RECEIPT:-$WORK/pins-before-build.json}" \
    || die "a pinned archive is missing or does not match its digest"

CMAKE_DIR="$WORK/cmake-3.31.4-linux-x86_64"
if [ ! -x "$CMAKE_DIR/bin/cmake" ]; then
    echo "=== unpacking cmake ==="
    tar xzf "$WORK/cmake-3.31.4-linux-x86_64.tar.gz" -C "$WORK"
fi
export PATH="$CMAKE_DIR/bin:$PATH"

echo "=== building PuTTY 0.85 (plink, puttygen) ==="
if [ ! -d "$WORK/putty-0.85" ]; then
    tar xzf "$WORK/putty-0.85.tar.gz" -C "$WORK"
fi
cmake -S "$WORK/putty-0.85" -B "$WORK/putty-build" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$WORK/putty-build" -j4 >/dev/null
mkdir -p "$PREFIX/bin"
cp "$WORK/putty-build/plink" "$WORK/putty-build/puttygen" "$PREFIX/bin/"

echo "=== building Dropbear 2026.94 (dropbear, dbclient, dropbearkey, dropbearconvert) ==="
if [ ! -d "$WORK/dropbear-2026.94" ]; then
    tar xjf "$WORK/dropbear-2026.94.tar.bz2" -C "$WORK"
fi
if [ ! -f "$WORK/dropbear-2026.94/Makefile" ]; then
    ( cd "$WORK/dropbear-2026.94" \
      && ./configure --prefix="$PREFIX" --disable-zlib --disable-syslog >/dev/null )
fi
make -C "$WORK/dropbear-2026.94" -j4 >/dev/null
make -C "$WORK/dropbear-2026.94" install >/dev/null

echo "=== configuring OpenSSH 9.9p1 against the pinned authority ==="
if [ ! -d "$WORK/openssh-9.9p1" ]; then
    tar xzf "$WORK/openssh-9.9p1.tar.gz" -C "$WORK"
fi
# Both directories: `dropbear` is installed to sbin/ (finding 2 above).
export PATH="$PREFIX/bin:$PREFIX/sbin:$PATH"
( cd "$WORK/openssh-9.9p1" \
  && ./configure --prefix="$SSH_BUILD" --with-ssl-dir="$AUTH" \
       --without-openssl-header-check --without-pam --without-selinux \
       --without-libedit --without-ldns )

echo "=== detection must be observable, not assumed ==="
bash "$ROOT/courts/phase18/interop/verify_detection.sh"
