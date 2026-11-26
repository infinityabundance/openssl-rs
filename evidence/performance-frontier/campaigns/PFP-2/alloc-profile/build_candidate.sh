#!/bin/sh
# build_candidate.sh — build the PFP-24 candidate DSO from the working tree.
#
# The PFP-24 changes are made in the working tree and are not committed by the
# agent that makes them, so the build identity is recorded from `git status`
# and the source fingerprint rather than asserted from a declared commit. The
# recipe is the PFP-21/PFP-23 one, unchanged:
#
#   cargo build --release --lib --offline      (CARGO_BUILD_JOBS=4)
#   rustc -O --emit=obj --crate-type lib       (distribution shell)
#   cc -shared, --whole-archive the archive, --version-script, -soname
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#       sh evidence/performance-frontier/campaigns/PFP-2/alloc-profile/build_candidate.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT="${PFP24_OUT:-/work/court/tmp/pfp24}"
SRC="${PFP24_SRC:-/work}"
SHELL_RS=/work/court/tmp/pfp2-fix/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT"

[ -f "$SHELL_RS" ] || { echo "FATAL: missing $SHELL_RS" >&2; exit 1; }
[ -f "$VERSION_SCRIPT" ] || { echo "FATAL: missing $VERSION_SCRIPT" >&2; exit 1; }

fingerprint() { ( cd "$SRC" && find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum ); }

fingerprint >"$OUT/src-before.sha256"
SRC_FP="$(sha256sum "$OUT/src-before.sha256" | awk '{print $1}')"

echo "=== cargo build --release --lib --offline (JOBS=$JOBS, src=$SRC) ==="
( cd "$SRC" && CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/target" \
    cargo build --release --lib --offline )
ARCHIVE="$OUT/target/release/libopenssl_rs.a"
[ -f "$ARCHIVE" ] || { echo "FATAL: missing $ARCHIVE" >&2; exit 1; }

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

fingerprint >"$OUT/src-after.sha256"
cmp -s "$OUT/src-before.sha256" "$OUT/src-after.sha256" \
    || { echo "FATAL: source fingerprint changed during the build" >&2; exit 90; }

{
    printf 'source_tree %s\n' "$SRC"
    printf 'head %s\n' "$(git -C "$SRC" rev-parse HEAD)"
    printf 'head_branch %s\n' "$(git -C "$SRC" rev-parse --abbrev-ref HEAD)"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src-before.sha256")"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum "$SRC/Cargo.lock" | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source %s sha256=%s\n' "$SHELL_RS" "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script %s sha256=%s\n' "$VERSION_SCRIPT" "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    printf 'archive %s sha256=%s\n' "$ARCHIVE" "$(sha256sum "$ARCHIVE" | awk '{print $1}')"
    printf 'dso %s sha256=%s size=%s build_id=%s\n' "$DSO" "$DSO_SHA" \
        "$(stat -c %s "$DSO")" "$(readelf -n "$DSO" | sed -n 's/^ *Build ID: //p')"
    printf 'worktree_status_file raw/worktree-status.txt\n'
} | tee "$OUT/build-identity.txt"

git -C "$SRC" status --porcelain -- src Cargo.toml Cargo.lock build.rs \
    >"$OUT/worktree-status.txt" 2>/dev/null || true
echo "PASS: built $DSO ($DSO_SHA)"
