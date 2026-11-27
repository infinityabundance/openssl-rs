#!/bin/sh
# build_variants.sh — PFP-6 re-evaluation at the PFP-5 composition.
#
# Final source S = staging 76652a46d + the documentation correction to
# src/bn/arith.rs (no behaviour change).  Four experimental DSOs are built from
# S by one- or two-line compile-time changes, and each variant is restored:
#
#   A  final source, production defaults (window + SOS multiply-for-square)
#   A2 A built again in a fresh CARGO_TARGET_DIR (reproducibility)
#   B  A with the squarings in run_mont_ladder_window using mont_sqr_into
#   C  A with LADDER_SCHEDULE = Cios (CIOS used for the squaring role too)
#   D  C plus the dedicated-squaring change (2x2 check)
#
# Only A is a candidate for admission. B/C/D exist to measure the squaring
# role; the source is restored and the fingerprint re-checked after each.
#
# Build recipe is PFP-5/PFP-27's: cargo build --release --lib --offline,
# rustc -O shell object, cc -shared --whole-archive + version script.
#
# Each target directory is removed after its DSO is linked, because this host
# has ~5 GiB free; the DSO and archive hashes are recorded before removal.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27/build_variants.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/reeval-2026-11-27
OUT=/work/court/tmp/pfp6-reeval
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/raw" "$EV/raw/disasm"
for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

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
    printf '%s archive_sha256=%s dso_sha256=%s size=%s\n' \
        "$d" "$(sha256sum "$t/release/libopenssl_rs.a" | awk '{print $1}')" \
        "$(sha256sum "$OUT/$d/distribution/libcrypto.so.3" | awk '{print $1}')" \
        "$(stat -c %s "$OUT/$d/distribution/libcrypto.so.3")" \
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
        cp "$OUT/arith.restore.rs" src/bn/arith.rs
        PATCHED=0
    fi
}
trap restore EXIT HUP INT TERM
cp src/bn/arith.rs "$OUT/arith.restore.rs"

: >"$OUT/variants.txt"

# --- A and A2: final source, production defaults ---------------------------
build a
build a2

# --- patch helper ----------------------------------------------------------
patch_sqr() {
    python3 - "$@" <<'PY'
import pathlib, sys
p = pathlib.Path("src/bn/arith.rs")
s = p.read_text()
old = """        for _ in 0..shift {
            if !mont_mul_ladder_into(
                &acc[..],
                &acc[..],
                &mut scratch[..],
                md,
                n0,
                &mut t[..],
                &mut diff[..],
            ) {
                return None;
            }
            core::mem::swap(acc, scratch);
        }"""
new = """        for _ in 0..shift {
            if !mont_sqr_into(&acc[..], &mut scratch[..], md, n0, &mut t[..], &mut diff[..]) {
                return None;
            }
            core::mem::swap(acc, scratch);
        }"""
assert s.count(old) == 1, s.count(old)
p.write_text(s.replace(old, new))
PY
}

patch_schedule() {
    python3 - <<'PY'
import pathlib
p = pathlib.Path("src/bn/arith.rs")
s = p.read_text()
old = "const LADDER_SCHEDULE: MontSchedule = MontSchedule::Sos;"
new = "const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;"
assert s.count(old) == 1, s.count(old)
p.write_text(s.replace(old, new))
PY
}

# --- B: dedicated squaring ------------------------------------------------
patch_sqr
PATCHED=1
diff -u "$OUT/arith.restore.rs" src/bn/arith.rs >"$EV/raw/squaring-difference.diff" || true
build b
restore
fingerprint >"$OUT/src.after-b.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after-b.sha256" || { echo "FATAL: restore after B" >&2; exit 90; }

# --- C: CIOS for every Montgomery operation --------------------------------
patch_schedule
PATCHED=1
diff -u "$OUT/arith.restore.rs" src/bn/arith.rs >"$EV/raw/schedule-difference.diff" || true
build c
restore
fingerprint >"$OUT/src.after-c.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after-c.sha256" || { echo "FATAL: restore after C" >&2; exit 90; }

# --- D: CIOS plus dedicated squaring (2x2) ---------------------------------
patch_schedule
patch_sqr
PATCHED=1
diff -u "$OUT/arith.restore.rs" src/bn/arith.rs >"$EV/raw/cios-dedicated-difference.diff" || true
build d
restore
fingerprint >"$OUT/src.after-d.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after-d.sha256" || { echo "FATAL: restore after D" >&2; exit 90; }

fingerprint >"$OUT/src.after.sha256"
cmp -s "$OUT/src.before.sha256" "$OUT/src.after.sha256" || {
    echo "FATAL: src fingerprint changed during the build" >&2
    exit 91
}

# --- record ---------------------------------------------------------------
{
    printf 'source_commit %s\n' "$SOURCE_COMMIT"
    printf 'source_src_tree %s\n' "$SRC_TREE"
    printf 'build_relevant_clean %s\n' "$( [ -z "$DIRTY" ] && echo true || echo false )"
    printf 'dirty_paths_begin\n%s\ndirty_paths_end\n' "$DIRTY"
    printf 'source_tree_fingerprint %s\n' "$SRC_FP"
    printf 'source_files %s\n' "$(wc -l <"$OUT/src.before.sha256")"
    printf 'arith_rs_sha256 %s\n' "$ARITH_SHA"
    printf 'cargo_lock_sha256 %s\n' "$(sha256sum Cargo.lock | awk '{print $1}')"
    printf 'rustc %s\n' "$(rustc --version)"
    printf 'cargo %s\n' "$(cargo --version)"
    printf 'cc %s\n' "$(cc --version | head -n 1)"
    printf 'target_triple %s\n' "$(rustc -vV | sed -n 's/^host: //p')"
    printf 'profile release\n'
    printf 'flags cargo build --release --lib --offline; CARGO_BUILD_JOBS=%s\n' "$JOBS"
    printf 'shell_source sha256=%s\n' "$(sha256sum "$SHELL_RS" | awk '{print $1}')"
    printf 'version_script sha256=%s\n' "$(sha256sum "$VERSION_SCRIPT" | awk '{print $1}')"
    printf 'a2_matches_a %s\n' "$(cmp -s "$OUT/a/distribution/libcrypto.so.3" "$OUT/a2/distribution/libcrypto.so.3" && echo yes || echo no)"
} | tee "$EV/raw/build-inputs.txt"
cat "$OUT/variants.txt" | tee "$EV/raw/variants.txt"

cmp -s "$OUT/a/distribution/libcrypto.so.3" "$OUT/a2/distribution/libcrypto.so.3" || {
    echo "FATAL: A2 does not reproduce A" >&2
    exit 1
}
echo "build: done"
