#!/bin/sh
# rebuild.sh — PFP-23 second independent clean rebuild of the PFP-20 candidate.
#
# Reproduces DSO 553e1b8c from the declared source commit c1d25e10d into a
# fresh CARGO_TARGET_DIR, with the same recipe the PFP-21 build used:
#
#   cargo build --release --lib --offline      (CARGO_BUILD_JOBS=4)
#   rustc -O --emit=obj --crate-type lib       (distribution shell)
#   cc -shared, --whole-archive the archive, --version-script, -soname
#
# The source is a detached git worktree of the declared commit, so the guard in
# make_build_identity.py (HEAD:src == declared:src, clean build-relevant paths)
# is satisfied from the commit itself rather than from a substituted file.
#
# Everything is recorded: source-tree fingerprint, Cargo.lock digest, toolchain,
# host triple, profile, flags, linker, and every link input.  A digest mismatch
# is a failure, never a warning.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#       sh evidence/performance-frontier/campaigns/PFP-2/repro-553e1b8c/rebuild.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

SRC=/work/court/tmp/pfp23-src
OUT=/work/court/tmp/pfp23
EV=/work/evidence/performance-frontier/campaigns/PFP-2/repro-553e1b8c
SHELL_RS=/work/court/tmp/pfp2-fix/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld

SOURCE_COMMIT=c1d25e10d16bc197e03446619a5330842b411c5c
EXPECT_DSO=553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4
EXPECT_ARCHIVE=b7c22e863b4508423b4c4a7be8efad7790aff14a8ecf366c24ca59e8788ad3f9
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/raw"

[ -d "$SRC" ] || { echo "FATAL: missing worktree $SRC" >&2; exit 1; }
[ -f "$SHELL_RS" ] || { echo "FATAL: missing $SHELL_RS" >&2; exit 1; }
[ -f "$VERSION_SCRIPT" ] || { echo "FATAL: missing $VERSION_SCRIPT" >&2; exit 1; }

# --- declared identity, verified before anything is built -------------------
HEAD_SHA="$(git -C "$SRC" rev-parse HEAD)"
HEAD_SRC="$(git -C "$SRC" rev-parse HEAD:src)"
DECL_SRC="$(git -C /work rev-parse "$SOURCE_COMMIT:src")"
DIRTY="$(git -C "$SRC" status --porcelain)"
[ "$HEAD_SHA" = "$SOURCE_COMMIT" ] || { echo "FATAL: worktree HEAD $HEAD_SHA != $SOURCE_COMMIT" >&2; exit 1; }
[ "$HEAD_SRC" = "$DECL_SRC" ] || { echo "FATAL: worktree src tree $HEAD_SRC != $DECL_SRC" >&2; exit 1; }
[ -z "$DIRTY" ] || { echo "FATAL: worktree is dirty" >&2; printf '%s\n' "$DIRTY" >&2; exit 1; }

fingerprint() { ( cd "$SRC" && find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum ); }
fingerprint >"$OUT/src-before.sha256"
SRC_FP="$(sha256sum "$OUT/src-before.sha256" | awk '{print $1}')"

LOCK_SHA="$(sha256sum "$SRC/Cargo.lock" | awk '{print $1}')"
RUSTC_V="$(rustc --version)"
CARGO_V="$(cargo --version)"
CC_V="$(cc --version | head -n 1)"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"

# --- fresh target directory, release library -------------------------------
rm -rf "$OUT/target"
echo "=== cargo build --release --lib --offline (JOBS=$JOBS) ==="
( cd "$SRC" && CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/target" \
    cargo build --release --lib --offline )
ARCHIVE="$OUT/target/release/libopenssl_rs.a"
[ -f "$ARCHIVE" ] || { echo "FATAL: missing $ARCHIVE" >&2; exit 1; }
ARCHIVE_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"

# --- distribution link, the PFP-21 recipe ----------------------------------
echo "=== distribution link ==="
mkdir -p "$OUT/shell" "$OUT/distribution"
rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/shell/libcrypto.shell.o" \
    "$SHELL_RS"
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
if ! cmp -s "$OUT/src-before.sha256" "$OUT/src-after.sha256"; then
    echo "FATAL: source fingerprint changed during the build" >&2
    exit 90
fi

{
    printf 'source_commit %s\n' "$SOURCE_COMMIT"
    printf 'worktree %s\n' "$SRC"
    printf 'head_src_tree %s\n' "$HEAD_SRC"
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
    printf 'archive %s sha256=%s\n' "$ARCHIVE" "$ARCHIVE_SHA"
    printf 'dso %s sha256=%s size=%s build_id=%s\n' "$DSO" "$DSO_SHA" "$DSO_SIZE" "$BUILD_ID"
    printf 'expected_dso %s\n' "$EXPECT_DSO"
    printf 'expected_archive %s\n' "$EXPECT_ARCHIVE"
    printf 'archive_matches_previous %s\n' "$([ "$ARCHIVE_SHA" = "$EXPECT_ARCHIVE" ] && echo yes || echo no)"
    printf 'dso_matches_previous %s\n' "$([ "$DSO_SHA" = "$EXPECT_DSO" ] && echo yes || echo no)"
} | tee "$EV/raw/build-inputs.txt"

if [ "$ARCHIVE_SHA" != "$EXPECT_ARCHIVE" ]; then
    echo "FATAL: archive digest $ARCHIVE_SHA != $EXPECT_ARCHIVE" >&2
    exit 1
fi
if [ "$DSO_SHA" != "$EXPECT_DSO" ]; then
    echo "FATAL: DSO digest $DSO_SHA != $EXPECT_DSO" >&2
    exit 1
fi
if ! cmp -s "$DSO" /work/court/tmp/pfp21/a/distribution/libcrypto.so.3; then
    echo "FATAL: rebuilt DSO is not byte-identical to the PFP-21 build" >&2
    exit 1
fi
echo "PASS: second clean rebuild reproduces $EXPECT_DSO byte-for-byte"
