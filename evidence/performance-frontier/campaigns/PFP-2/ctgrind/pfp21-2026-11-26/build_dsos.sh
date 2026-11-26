#!/bin/sh
# build_dsos.sh — build the two PFP-21 population DSOs.
#
#   A = the exact PFP-20 candidate source (staging c1d25e10d): the tree that
#       produced the audited DSO 553e1b8c.  Run from HEAD c1d25e10d's successor
#       20972901d, whose only src difference from c1d25e10d is src/bn/arith.rs
#       (the PFP-6 integration), so that one file is swapped for the duration of
#       the build and restored unconditionally.
#   B = the same source with ONE line changed: default_kernel_id() selects
#       KernelId::Solinas (the generic reduction kernel) instead of
#       KernelId::Mont.  That single build input is the mutation.
#
# The source tree is fingerprinted before and after; a restore that does not
# reproduce the original fingerprint aborts the run.  Nothing here runs on the
# host: invoke inside the court.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/build_dsos.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp21
EV=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26
ARITH_CAND=/work/court/tmp/pfp20/arith.head.rs       # c1d25e10d src/bn/arith.rs
ARITH_CAND_SHA=edf456e6b38ee48c43bf42e2b7c167906d2675a2b18820358f9dcc04779dafdc
ARITH_HEAD_SHA=06005795079c9957ba2b35c6816c423b507f427705842284aa9c23d0e0759a1c
P256_SHA=75a2dd1de88139b9b050b09f0dbcb1b694c7e7185240c6d519baac999019b0c5
SHELL_RS=/work/court/tmp/pfp2-fix/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld

mkdir -p "$OUT/a" "$OUT/b" "$EV/raw"

fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }

echo "=== source fingerprint before ==="
fingerprint >"$OUT/src.before.sha256"
sha256sum "$ARITH_CAND"

[ "$(sha256sum src/bn/arith.rs | awk '{print $1}')" = "$ARITH_HEAD_SHA" ] || {
    echo "FATAL: src/bn/arith.rs is not the expected HEAD copy" >&2
    exit 1
}
[ "$(sha256sum src/ec/p256.rs | awk '{print $1}')" = "$P256_SHA" ] || {
    echo "FATAL: src/ec/p256.rs is not the expected HEAD copy" >&2
    exit 1
}

cp src/bn/arith.rs "$OUT/arith.restore.rs"
cp src/ec/p256.rs "$OUT/p256.restore.rs"

restore() {
    cp "$OUT/arith.restore.rs" src/bn/arith.rs
    cp "$OUT/p256.restore.rs" src/ec/p256.rs
    fingerprint >"$OUT/src.after.sha256"
    if cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256"; then
        echo "restore: src fingerprint identical ($(wc -l <"$OUT/src.after.sha256") files)"
    else
        echo "FATAL: src fingerprint changed during the build" >&2
        diff "$OUT/src.before.sha256" "$OUT/src.after.sha256" >&2 || true
        exit 90
    fi
}
trap restore EXIT HUP INT TERM

link() { # dir
    d=$1
    mkdir -p "$OUT/$d/distribution" "$OUT/$d/shell"
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

# --- A: candidate source (c1d25e10d) --------------------------------------
cp "$ARITH_CAND" src/bn/arith.rs
[ "$(sha256sum src/bn/arith.rs | awk '{print $1}')" = "$ARITH_CAND_SHA" ]
echo "=== A: cargo build (candidate source) ==="
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$OUT/a/target" \
    cargo build --release --lib --offline
link a

# --- B: candidate source + the single kernel-selection line ---------------
line_before=$(grep -n 'let id = KernelId::Mont;' src/ec/p256.rs | cut -d: -f1)
[ -n "$line_before" ] || { echo "FATAL: kernel selection line not found" >&2; exit 1; }
sed -i 's/^    let id = KernelId::Mont;$/    let id = KernelId::Solinas;/' \
    src/ec/p256.rs
n=$(grep -c 'let id = KernelId::Solinas;' src/ec/p256.rs)
[ "$n" = "1" ] || { echo "FATAL: kernel patch applied $n times" >&2; exit 1; }
P256_B_SHA=$(sha256sum src/ec/p256.rs | awk '{print $1}')
diff -u "$OUT/p256.restore.rs" src/ec/p256.rs >"$EV/raw/kernel-difference.diff" || true
echo "=== B: cargo build (generic kernel forced) ==="
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$OUT/b/target" \
    cargo build --release --lib --offline
link b

# --- restore and record ----------------------------------------------------
cp "$OUT/arith.restore.rs" src/bn/arith.rs
cp "$OUT/p256.restore.rs" src/ec/p256.rs
fingerprint >"$OUT/src.after.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256" || {
    echo "FATAL: src fingerprint changed during the build" >&2
    exit 90
}
echo "restore: src fingerprint identical"

{
    printf 'source_commit c1d25e10d16bc197e03446619a5330842b411c5c\n'
    printf 'source_note HEAD 20972901d with src/bn/arith.rs restored to c1d25e10d; fp identical after\n'
    for d in a b; do
        p="$OUT/$d/distribution/libcrypto.so.3"
        printf '%s %s %s\n' "$d" "$(sha256sum "$p" | awk '{print $1}')" \
            "$(stat -c %s "$p")"
    done
    printf 'p256_a %s\n' "$P256_SHA"
    printf 'p256_b %s\n' "${P256_B_SHA:-unset}"
    printf 'difference single_line src/ec/p256.rs default_kernel_id Mont->Solinas\n'
} | tee "$EV/raw/dso-digests.txt"

sha256sum "$OUT/a/distribution/libcrypto.so.3" "$OUT/b/distribution/libcrypto.so.3"
echo "build: done"
