#!/bin/sh
# build_dso.sh — PFP-29: build the release library and the distribution-shaped DSO
# at the frozen source head, twice, and prove the two builds agree byte-for-byte.
#
# A   = staging HEAD, production defaults (LADDER_SCHEDULE = Sos).
# A2  = the same source built again in a fresh CARGO_TARGET_DIR.
#
# Recipe: identical to PFP-21/PFP-23/PFP-27.
#   cargo build --release --lib --offline   (CARGO_BUILD_JOBS=4)
#   rustc -O --emit=obj the Phase 2 shell
#   cc -shared --whole-archive <archive> + shell object + version script
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-29/build_dso.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-29
OUT=/work/court/tmp/pfp29
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/raw"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

SOURCE_COMMIT="$(git -C /work rev-parse HEAD)"
SRC_TREE="$(git -C /work rev-parse HEAD:src)"
DIRTY="$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs)"
[ -z "$DIRTY" ] || { echo "FATAL: build-relevant paths are dirty" >&2; printf '%s\n' "$DIRTY" >&2; exit 1; }

fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }
fingerprint >"$OUT/src.before.sha256"
SRC_FP="$(sha256sum "$OUT/src.before.sha256" | awk '{print $1}')"

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

build a A
build a2 A2

fingerprint >"$OUT/src.after.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256" || {
    echo "FATAL: src fingerprint changed during the build" >&2
    diff "$OUT/src.before.sha256" "$OUT/src.after.sha256" >&2 || true
    exit 90
}
echo "restore: src fingerprint identical ($(wc -l <"$OUT/src.after.sha256") files)"

{
    printf 'source_commit %s\n' "$SOURCE_COMMIT"
    printf 'source_src_tree %s\n' "$SRC_TREE"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src.before.sha256")"
    printf 'arith_rs_sha256 %s\n' "$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum Cargo.lock | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source %s sha256=%s\n' "$SHELL_RS" "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script %s sha256=%s\n' "$VERSION_SCRIPT" "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    for d in a a2; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s archive_sha256=%s dso_sha256=%s size=%s build_id=%s\n' \
            "$d" "$(sha256sum "$OUT/$d/target/release/libopenssl_rs.a" | awk '{print $1}')" \
            "$(sha256sum "$p" | awk '{print $1}')" "$(stat -c %s "$p")" \
            "$(readelf -n "$p" | sed -n 's/^ *Build ID: //p')"
    done
    printf 'a2_matches_a %s\n' "$(cmp -s "$OUT/a/distribution/libcrypto.so.3" "$OUT/a2/distribution/libcrypto.so.3" && echo yes || echo no)"
} | tee "$EV/raw/build-inputs.txt"

cmp -s "$OUT/a/distribution/libcrypto.so.3" "$OUT/a2/distribution/libcrypto.so.3" || {
    echo "FATAL: A2 does not reproduce A" >&2
    exit 1
}
echo "build: done"
