#!/bin/sh
# build_pfp4.sh — build the PFP-4 distribution DSO from the working tree.
#
# The candidate is the uncommitted `staging` working tree (the campaign is
# forbidden to commit). Identity is therefore recorded as the git HEAD plus the
# sha256 fingerprint of every `src/**/*.rs` file, including untracked ones, taken
# before and after the build; a change during the build is a failure.
#
# Recipe is the PFP-2/PFP-3 distribution recipe, unchanged:
#   cargo build --release --lib --offline            (CARGO_BUILD_JOBS=4)
#   rustc -O --emit=obj --crate-type lib              (Phase-2 shell)
#   cc -shared --whole-archive libopenssl_rs.a ... --version-script -soname
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#       sh evidence/performance-frontier/campaigns/PFP-4/build/build_pfp4.sh a
set -eu

LABEL="${1:-a}"
cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

SRC=/work
OUT=/work/court/tmp/pfp4-"$LABEL"
EV=/work/evidence/performance-frontier/campaigns/PFP-4/build
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV" "$EV/raw"

[ -f "$SHELL_RS" ] || { echo "FATAL: missing $SHELL_RS" >&2; exit 1; }
[ -f "$VERSION_SCRIPT" ] || { echo "FATAL: missing $VERSION_SCRIPT" >&2; exit 1; }

fingerprint() { ( cd "$SRC" && find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum ); }
fingerprint >"$OUT/src-before.sha256"
SRC_FP="$(sha256sum "$OUT/src-before.sha256" | awk '{print $1}')"
HEAD_SHA="$(git -C "$SRC" rev-parse HEAD)"
SRC_TREE="$(git -C "$SRC" rev-parse HEAD:src)"
DIRTY="$(git -C "$SRC" status --porcelain -- src Cargo.toml Cargo.lock)"

RUSTC_V="$(rustc --version)"
CARGO_V="$(cargo --version)"
CC_V="$(cc --version | head -n 1)"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
LOCK_SHA="$(sha256sum "$SRC/Cargo.lock" | awk '{print $1}')"

rm -rf "$OUT/target"
echo "=== cargo build --release --lib --offline (JOBS=$JOBS) [$LABEL] ==="
( cd "$SRC" && CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/target" \
    cargo build --release --lib --offline )
ARCHIVE="$OUT/target/release/libopenssl_rs.a"
[ -f "$ARCHIVE" ] || { echo "FATAL: missing $ARCHIVE" >&2; exit 1; }
ARCHIVE_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"

echo "=== distribution link [$LABEL] ==="
mkdir -p "$OUT/shell" "$OUT/distribution"
rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/shell/libcrypto.shell.o" "$SHELL_RS"
cc -shared -o "$OUT/distribution/libcrypto.so.3" \
    -Wl,--whole-archive "$ARCHIVE" \
    -Wl,--no-whole-archive "$OUT/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil
DSO="$OUT/distribution/libcrypto.so.3"
DSO_SHA="$(sha256sum "$DSO" | awk '{print $1}')"
DSO_SIZE="$(stat -c %s "$DSO")"
BUILD_ID="$(readelf -n "$DSO" | sed -n 's/^ *Build ID: //p')"

fingerprint >"$OUT/src-after.sha256"
cmp -s "$OUT/src-before.sha256" "$OUT/src-after.sha256" || {
    echo "FATAL: source fingerprint changed during the build" >&2; exit 90; }

{
    printf 'label %s\n' "$LABEL"
    printf 'git_head %s\n' "$HEAD_SHA"
    printf 'head_src_tree %s\n' "$SRC_TREE"
    printf 'working_tree_dirty_paths\n%s\n' "$DIRTY"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src-before.sha256")"
    printf 'cargo_lock_sha256 %s\n' "$LOCK_SHA"
    printf 'rustc %s\n' "$RUSTC_V"
    printf 'cargo %s\n' "$CARGO_V"
    printf 'cc %s\n' "$CC_V"
    printf 'target_triple %s\n' "$TRIPLE"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source %s sha256=%s\n' "$SHELL_RS" "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script %s sha256=%s\n' "$VERSION_SCRIPT" "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    printf 'archive_sha256 %s\n' "$ARCHIVE_SHA"
    printf 'dso %s\n' "$DSO"
    printf 'dso_sha256 %s\n' "$DSO_SHA"
    printf 'dso_size %s\n' "$DSO_SIZE"
    printf 'dso_build_id %s\n' "$BUILD_ID"
} | tee "$EV/raw/build-inputs-$LABEL.txt"
