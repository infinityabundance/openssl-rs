#!/usr/bin/env bash
# openssl-rs — install the pinned z3 solver used by BINSEC -checkct.
#
# The tools image ships z3 4.8.12 at /usr/bin/z3 and does not provide the
# pinned 4.13.0 tree. BINSEC resolves `-smt-solver z3` from PATH, so the
# wrapper must be pointed at this tree explicitly:
#
#   BINSEC_Z3=/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin/z3 \
#     bash courts/phase18/timing/binsec_checkct.sh <cfg> <elf>
#
# Usage (inside the court; nothing here runs on the host):
#
#   bash forensics/tools/install_z3_pinned.sh
#   bash forensics/tools/install_z3_pinned.sh --check
#   bash forensics/tools/install_z3_pinned.sh --dest /opt/z3-solver
#
# Pins (both digests were observed in the installing session and are checked
# before the tree is made visible to BINSEC):
#
#   version  Z3 4.13.0 - 64 bit
#   asset    z3-4.13.0-x64-glibc-2.35.zip
#   archive  sha256 884e3a411fa11b125522fc35eba3391b772517c047f8064fb4b656d92a73b38c
#   binary   sha256 0be0492eb59745e31e77a510ce50c8b940617b87647757bdb1ba6c856301f712
#
# Exit status: 0 installed and verified (or --check passed); 1 verification
# failure; 2 usage or prerequisite failure; 97 outside the court.

set -euo pipefail

. "$(dirname "$0")/require_court.sh"

Z3_VERSION=4.13.0
ASSET=z3-4.13.0-x64-glibc-2.35.zip
URL="https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/${ASSET}"
ZIP_SHA256=884e3a411fa11b125522fc35eba3391b772517c047f8064fb4b656d92a73b38c
BIN_SHA256=0be0492eb59745e31e77a510ce50c8b940617b87647757bdb1ba6c856301f712

ROOT=/opt/z3-solver
MODE=install

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE=check; shift ;;
    --dest) ROOT=$2; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "usage: $0 [--check] [--dest DIR]" >&2; exit 2 ;;
  esac
done

DEST="$ROOT/z3-${Z3_VERSION}-x64-glibc-2.35"
BIN="$DEST/bin/z3"

fail() { echo "install_z3_pinned: REFUSED: $*" >&2; exit 1; }

verify_tree() {
  [ -x "$BIN" ] || fail "solver not executable: $BIN"
  local digest version
  digest=$(sha256sum "$BIN" | cut -d' ' -f1)
  [ "$digest" = "$BIN_SHA256" ] || \
    fail "binary digest mismatch: expected=$BIN_SHA256 observed=$digest ($BIN)"
  version=$("$BIN" --version 2>&1 | head -n 1)
  [ "$version" = "Z3 version ${Z3_VERSION} - 64 bit" ] || \
    fail "unexpected version string from $BIN: '$version'"
  echo "Z3_PINNED_OK path=$BIN version='$version' binary_sha256=$digest"
}

if [ "$MODE" = check ]; then
  verify_tree
  exit 0
fi

for tool in curl unzip sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "install_z3_pinned: downloading $URL" >&2
curl -fsSL -o "$tmp/$ASSET" "$URL" || fail "download failed: $URL"

observed=$(sha256sum "$tmp/$ASSET" | cut -d' ' -f1)
[ "$observed" = "$ZIP_SHA256" ] || \
  fail "archive digest mismatch: expected=$ZIP_SHA256 observed=$observed"
echo "install_z3_pinned: archive sha256 verified: $observed" >&2

unzip -q "$tmp/$ASSET" -d "$tmp/unpacked" || fail "cannot extract $ASSET"
src="$tmp/unpacked/z3-${Z3_VERSION}-x64-glibc-2.35"
[ -x "$src/bin/z3" ] || fail "archive does not contain bin/z3"

observed=$(sha256sum "$src/bin/z3" | cut -d' ' -f1)
[ "$observed" = "$BIN_SHA256" ] || \
  fail "extracted binary digest mismatch: expected=$BIN_SHA256 observed=$observed"

mkdir -p "$ROOT"
rm -rf "$DEST.new"
mv "$src" "$DEST.new"
rm -rf "$DEST"
mv "$DEST.new" "$DEST"

verify_tree
