#!/bin/sh
# build.sh — PFP-6 CIOS admission: build the admitted default and its SOS twin.
#
# Source S = staging HEAD with exactly one functional change: the named constant
# LADDER_SCHEDULE in src/bn/arith.rs selects MontSchedule::Cios.  The SOS
# reference path is retained (mont_mul_fallible / MontSchedule::Sos) and is built
# here as a one-line twin for the paired timing and the ABI differential.
#
#   cand   current source, LADDER_SCHEDULE = Cios   (the admitted candidate)
#   cand2  cand rebuilt in a fresh CARGO_TARGET_DIR (reproducibility)
#   ref    current source with the constant patched to Sos (reference twin)
#
# The source is restored to the CIOS default after the twin is built, and the
# restore is checked byte for byte.  Only `cand` is a candidate for admission.
#
#   bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#     bash evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27/build.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
OUT=/work/court/tmp/pfp6-admission
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

# --- admitted default and its reproducibility twin -------------------------
build cand
build cand2

# --- SOS reference twin: one-line constant change, restored afterwards -----
python3 - <<'PY'
import pathlib
p = pathlib.Path("src/bn/arith.rs")
s = p.read_text()
old = "const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;"
new = "const LADDER_SCHEDULE: MontSchedule = MontSchedule::Sos;"
assert s.count(old) == 1, s.count(old)
p.write_text(s.replace(old, new))
PY
PATCHED=1
diff -u "$OUT/arith.cand.rs" src/bn/arith.rs >"$EV/raw/schedule-difference.diff" || true
build ref
restore
cmp -s "$OUT/arith.cand.rs" src/bn/arith.rs || {
    echo "FATAL: source was not restored to the CIOS default" >&2
    exit 90
}
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
    printf 'cand2_matches_cand %s\n' "$(cmp -s "$OUT/cand/distribution/libcrypto.so.3" "$OUT/cand2/distribution/libcrypto.so.3" && echo yes || echo no)"
} | tee "$EV/raw/build-inputs.txt"
cat "$OUT/variants.txt" | tee "$EV/raw/variants.txt"

cmp -s "$OUT/cand/distribution/libcrypto.so.3" "$OUT/cand2/distribution/libcrypto.so.3" || {
    echo "FATAL: cand2 does not reproduce cand" >&2
    exit 1
}
echo "build: done (cand reproduces; source restored to Cios)"
