#!/bin/sh
# build_repair.sh — PFP-31 repair: build the release DSO from the *repaired*
# working tree, twice, in fresh target dirs, and prove the two agree.
#
# R  = the repaired working tree (/work), production defaults.
# R2 = the same source built again in a second fresh CARGO_TARGET_DIR.
#
# The working tree is dirty by design (the repair is the change under test);
# this script records the exact src fingerprint and the git diff it built, and
# re-checks the fingerprint after the build so the recorded digest is bound to
# the source that was compiled.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-31/build_repair.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-31
OUT=/work/court/tmp/pfp31/repair
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/repair-raw"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

SOURCE_COMMIT="$(git -C /work rev-parse HEAD)"
fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }
fingerprint >"$OUT/src.before.sha256"
SRC_FP="$(sha256sum "$OUT/src.before.sha256" | awk '{print $1}')"
git -C /work diff -- src Cargo.toml Cargo.lock build.rs >"$OUT/src.diff"

link() { # dir
    d=$1
    mkdir -p "$OUT/$d/shell" "$OUT/$d/distribution"
    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$OUT/$d/shell/libcrypto.shell.o" \
        "$SHELL_RS"
    cc -shared -o "$OUT/$d/distribution/libcrypto.so.3" \
        -Wl,--whole-archive "$OUT/$d/target/release/libopenssl_rs.a" \
        -Wl,--no-whole-archive "$OUT/$d/shell/libcrypto.shell.o" \
        -Wl,--version-script="$VERSION_SCRIPT" \
        -Wl,-soname,libcrypto.so.3 \
        -lpthread -ldl -lm -lrt -lutil
}

build() { # dir label
    d=$1
    label=$2
    echo "=== $label: cargo build --release --lib --offline (JOBS=$JOBS) ==="
    rm -rf "$OUT/$d/target"
    CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/$d/target" \
        cargo build --release --lib --offline
    link "$d"
}

build r R
build r2 R2

fingerprint >"$OUT/src.after.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256" || {
    echo "FATAL: src fingerprint changed during the build" >&2
    diff "$OUT/src.before.sha256" "$OUT/src.after.sha256" >&2 || true
    exit 90
}

{
    printf 'source_commit %s\n' "$SOURCE_COMMIT"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src.before.sha256")"
    printf 'src_diff_sha256 %s\n' "$(sha256sum "$OUT/src.diff" | awk '{print $1}')"
    printf 'constant_time_sha256 %s\n' "$(sha256sum src/runtime/constant_time.rs | awk '{print $1}')"
    printf 'ml_kem_key_sha256 %s\n' "$(sha256sum src/ml_kem/key.rs | awk '{print $1}')"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum Cargo.lock | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source %s sha256=%s\n' "$SHELL_RS" "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script %s sha256=%s\n' "$VERSION_SCRIPT" "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    for d in r r2; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s archive_sha256=%s dso_sha256=%s size=%s build_id=%s\n' \
            "$d" "$(sha256sum "$OUT/$d/target/release/libopenssl_rs.a" | awk '{print $1}')" \
            "$(sha256sum "$p" | awk '{print $1}')" "$(stat -c %s "$p")" \
            "$(readelf -n "$p" | sed -n 's/^ *Build ID: //p')"
    done
    printf 'r2_matches_r %s\n' "$(cmp -s "$OUT/r/distribution/libcrypto.so.3" "$OUT/r2/distribution/libcrypto.so.3" && echo yes || echo no)"
} | tee "$EV/repair-raw/build-inputs.txt"

cmp -s "$OUT/r/distribution/libcrypto.so.3" "$OUT/r2/distribution/libcrypto.so.3" || {
    echo "FATAL: R2 does not reproduce R" >&2
    exit 1
}
echo "build: done"
