#!/bin/sh
# build.sh — PFP-8 identity: build the frozen source twice in fresh target
# directories and record the archive and DSO digests.  No source is modified.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash courts/performance-frontier/pfp8/build.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-8
OUT=/work/court/tmp/pfp8-build
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/build"
for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

{
    echo "source_commit=$(git -C /work rev-parse HEAD)"
    echo "src_tree=$(git -C /work rev-parse HEAD:src)"
    echo "dirty=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | tr '\n' ';')"
    echo "arith_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
    echo "src_fingerprint=$(find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cc=$(cc --version | head -1)"
} >"$EV/build/source.env"

link() { # variant targetdir
    d=$1
    t=$2
    mkdir -p "$OUT/$d/shell" "$OUT/$d/distribution"
    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$OUT/$d/shell/libcrypto.shell.o" \
        "$SHELL_RS"
    cc -shared -o "$OUT/$d/distribution/libcrypto.so.3" \
        -Wl,--whole-archive "$t/release/libopenssl_rs.a" \
        -Wl,--no-whole-archive \
        "$OUT/$d/shell/libcrypto.shell.o" \
        -Wl,--version-script="$VERSION_SCRIPT" \
        -Wl,-soname,libcrypto.so.3 \
        -lpthread -ldl -lm -lrt -lutil
    printf '%s archive_sha256=%s dso_sha256=%s size=%s build_id=%s\n' \
        "$d" "$(sha256sum "$t/release/libopenssl_rs.a" | awk '{print $1}')" \
        "$(sha256sum "$OUT/$d/distribution/libcrypto.so.3" | awk '{print $1}')" \
        "$(stat -c %s "$OUT/$d/distribution/libcrypto.so.3")" \
        "$(readelf -n "$OUT/$d/distribution/libcrypto.so.3" | sed -n 's/.*Build ID: //p')" \
        >>"$EV/build/variants.txt"
}

build() {
    d=$1
    t="$OUT/$d/target"
    echo "=== $d: cargo build --release --lib --offline (JOBS=$JOBS) ==="
    rm -rf "$t"
    CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$t" \
        cargo build --release --lib --offline 2>&1 | tail -n 3
    link "$d" "$t"
    rm -rf "$t"
}

: >"$EV/build/variants.txt"
build cand
build cand2
cat "$EV/build/variants.txt"

c1=$(sed -n 's/^cand .*dso_sha256=\([0-9a-f]*\) .*/\1/p' "$EV/build/variants.txt")
c2=$(sed -n 's/^cand2 .*dso_sha256=\([0-9a-f]*\) .*/\1/p' "$EV/build/variants.txt")
[ -n "$c1" ] && [ "$c1" = "$c2" ] || { echo "FATAL: rebuild digest mismatch" >&2; exit 1; }
echo "REPRODUCIBLE dso_sha256=$c1"
