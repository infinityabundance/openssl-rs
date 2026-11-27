#!/bin/sh
# build.sh — M-A1 fixed-width CIOS specialisation: build the candidate and the
# previous (generic slice-kernel) build, twice each where reproducibility is
# claimed.
#
#   cand   current worktree: const-generic CIOS kernels for 4/6/9/16/32/48/64/128
#          limbs, dispatched from `mont_mul_ladder_into`; generic kernel fallback.
#   cand2  cand rebuilt in a fresh CARGO_TARGET_DIR (reproducibility).
#   prev   `git show HEAD:src/bn/arith.rs` (the generic slice kernel, CIOS
#          schedule, no specialisation) in an otherwise identical tree, rebuilt in
#          a fresh CARGO_TARGET_DIR. This is the paired "previous build".
#
# The worktree arith.rs is saved before `prev` is built and restored afterwards,
# and the restore is checked byte for byte. Only `cand` is a candidate.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/M-A1/build.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/M-A1
OUT=/work/court/tmp/ma1
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/raw"
for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

grep -q '^const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;$' src/bn/arith.rs || {
    echo "FATAL: source is not the CIOS default" >&2
    exit 1
}

SOURCE_COMMIT="$(git -C /work rev-parse HEAD)"
SRC_TREE="$(git -C /work rev-parse HEAD:src)"
DIRTY="$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs)"
ARITH_SHA="$(sha256sum src/bn/arith.rs | awk '{print $1}')"

fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }
fingerprint >"$OUT/src.before.sha256"
SRC_FP="$(sha256sum "$OUT/src.before.sha256" | awk '{print $1}')"

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
        >>"$OUT/variants.txt"
}

build() { # variant
    d=$1
    t="$OUT/$d/target"
    echo "=== $d: cargo build --release --lib --offline (JOBS=$JOBS) ==="
    rm -rf "$t"
    CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$t" \
        cargo build --release --lib --offline 2>&1 | tail -n 3
    link "$d" "$t"
    rm -rf "$t"
    echo "=== $d: target removed, DSO retained ==="
}

restore() {
    if [ "${PATCHED:-0}" = 1 ]; then
        cp "$OUT/arith.cand.rs" src/bn/arith.rs
        PATCHED=0
    fi
}
trap restore EXIT HUP INT TERM
cp src/bn/arith.rs "$OUT/arith.cand.rs"

: >"$OUT/variants.txt"

# --- candidate and its reproducibility twin --------------------------------
build cand
build cand2

# --- previous build: HEAD's generic slice kernel, same tree otherwise ------
git -C /work show HEAD:src/bn/arith.rs > "$OUT/arith.prev.rs"
cp "$OUT/arith.prev.rs" src/bn/arith.rs
PATCHED=1
diff -u "$OUT/arith.prev.rs" "$OUT/arith.cand.rs" >"$EV/raw/source-difference.diff" || true
build prev
restore
cmp -s "$OUT/arith.cand.rs" src/bn/arith.rs || {
    echo "FATAL: source was not restored to the candidate" >&2
    exit 90
}
fingerprint >"$OUT/src.after.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256" || {
    echo "FATAL: src fingerprint changed during the build" >&2
    exit 91
}

# --- record -----------------------------------------------------------------
{
    printf 'source_commit %s\n' "$SOURCE_COMMIT"
    printf 'source_src_tree %s\n' "$SRC_TREE"
    printf 'build_relevant_clean %s\n' "$( [ -z "$DIRTY" ] && echo true || echo false )"
    printf 'dirty_paths_begin\n%s\ndirty_paths_end\n' "$DIRTY"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src.before.sha256")"
    printf 'arith_rs_sha256_cand %s\n' "$ARITH_SHA"
    printf 'arith_rs_sha256_prev %s\n' "$(sha256sum "$OUT/arith.prev.rs" | awk '{print $1}')"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum Cargo.lock | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source sha256=%s\n' "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script sha256=%s\n' "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    printf 'cand2_matches_cand %s\n' "$(cmp -s "$OUT/cand/distribution/libcrypto.so.3" "$OUT/cand2/distribution/libcrypto.so.3" && echo yes || echo no)"
    printf 'prev_is_pfp6_admitted %s\n' "$( [ "$(sha256sum "$OUT/prev/distribution/libcrypto.so.3" | awk '{print $1}')" = 6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39 ] && echo yes || echo no)"
} | tee "$EV/raw/build-inputs.txt"
cat "$OUT/variants.txt" | tee "$EV/raw/variants.txt"

cmp -s "$OUT/cand/distribution/libcrypto.so.3" "$OUT/cand2/distribution/libcrypto.so.3" || {
    echo "FATAL: cand2 does not reproduce cand" >&2
    exit 1
}
echo "build: done (cand reproduces; candidate restored)"
