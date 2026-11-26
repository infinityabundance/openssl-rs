#!/bin/sh
# build_canary.sh — PFP-31 negative control: a branch on the rejection result
# in `ml_kem::key::decap` instead of the constant-time mask select.
#
# The canary is built from a *copy* of HEAD under court/tmp, never from the
# working tree: `/work/src` is neither edited nor rebuilt here, and its
# fingerprint is re-checked before and after. The canary DSO is a separate
# artefact under court/tmp/pfp31/k/distribution and is never the candidate.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g CARGO_BUILD_JOBS=4 \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-31/build_canary.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-31
OUT=/work/court/tmp/pfp31
SRC="$OUT/canary-src"
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

mkdir -p "$OUT" "$EV/raw"

fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }
fingerprint >"$OUT/src.before-canary.sha256"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

# A clean copy of the build-relevant tree. `git archive` is the tracked HEAD,
# so no working-tree file (and nothing in the working `src/`) can leak in.
rm -rf "$SRC"
mkdir -p "$SRC"
git -C /work archive HEAD -- \
    Cargo.toml Cargo.lock build.rs rust-toolchain.toml README.md \
    docs src courts/phase8 \
    forensics/authorities/AUTHORITIES.json \
    forensics/multitrack/default-authority.json \
    forensics/multitrack/abi-facades.json \
    | tar -x -C "$SRC"

python3 - "$SRC" <<'PY'
import io
import sys

root = sys.argv[1]
path = f"{root}/src/ml_kem/key.rs"
text = io.open(path, encoding="utf-8").read()

old = """        let mask = constant_time_eq_int_8(
            0,
            CRYPTO_memcmp(ctext.cast(), tmp_ctext.cast(), (*vinfo).ctext_bytes),
        );
        for i in 0..ML_KEM_SHARED_SECRET_BYTES {
            *secret.add(i) = constant_time_select_8(mask, kr[i], failure_key[i]);
        }
"""
new = """        let mask = constant_time_eq_int_8(
            0,
            CRYPTO_memcmp(ctext.cast(), tmp_ctext.cast(), (*vinfo).ctext_bytes),
        );
        // CANARY (PFP-31 negative control): a branch on the comparison result
        // instead of the constant-time select. Two distinct `#[inline(never)]`
        // sinks keep the optimiser from if-converting it into a data select.
        if mask != 0 {
            canary_take_kr(secret, kr.as_ptr());
        } else {
            canary_take_failure_key(secret, failure_key.as_ptr());
        }
"""

sinks = """// CANARY (PFP-31 negative control): model the two arms as distinct opaque
// copies. They produce identical bytes; only the control transfer differs.
#[inline(never)]
unsafe fn canary_take_kr(out: *mut u8, src: *const u8) {
    // SAFETY: canary-only; both buffers are ML_KEM_SHARED_SECRET_BYTES long.
    unsafe {
        for i in 0..ML_KEM_SHARED_SECRET_BYTES {
            *out.add(i) = *src.add(i);
        }
    }
}

#[inline(never)]
unsafe fn canary_take_failure_key(out: *mut u8, src: *const u8) {
    // SAFETY: canary-only; both buffers are ML_KEM_SHARED_SECRET_BYTES long.
    unsafe {
        for i in (0..ML_KEM_SHARED_SECRET_BYTES).rev() {
            *out.add(i) = *src.add(i);
        }
    }
}

/// `decap(secret, ctext, tmp_ctext, tmp, mdctx, key)` — `ml_kem.c:1837-1890`, Algorithm 18.
"""

if text.count(old) != 1:
    sys.stderr.write("FATAL: canary site not found exactly once\n")
    sys.exit(1)
anchor = ("/// `decap(secret, ctext, tmp_ctext, tmp, mdctx, key)` — "
          "`ml_kem.c:1837-1890`, Algorithm 18.\n")
if text.count(anchor) != 1:
    sys.stderr.write("FATAL: canary sink anchor not found exactly once\n")
    sys.exit(1)
text = text.replace(old, new)
text = text.replace(anchor, sinks, 1)
io.open(path, "w", encoding="utf-8").write(text)
PY

grep -q 'CANARY (PFP-31 negative control)' "$SRC/src/ml_kem/key.rs" || {
    echo "FATAL: canary not applied" >&2; exit 1; }
diff -u /work/src/ml_kem/key.rs "$SRC/src/ml_kem/key.rs" \
    >"$EV/raw/canary-difference.diff" || true

mkdir -p "$OUT/k/target" "$OUT/k/shell" "$OUT/k/distribution"
echo "=== K: cargo build --release --lib --offline in the copy (JOBS=$JOBS) ==="
(
    cd "$SRC"
    CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/k/target" \
        cargo build --release --lib --offline
)

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/k/shell/libcrypto.shell.o" \
    "$SHELL_RS"
cc -shared -o "$OUT/k/distribution/libcrypto.so.3" \
    -Wl,--whole-archive "$OUT/k/target/release/libopenssl_rs.a" \
    -Wl,--no-whole-archive "$OUT/k/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

fingerprint >"$OUT/src.after-canary.sha256"
cmp -s "$OUT/src.before-canary.sha256" "$OUT/src.after-canary.sha256" || {
    echo "FATAL: working src fingerprint changed during the canary build" >&2
    exit 90
}
echo "working tree: src fingerprint identical (never edited)"

p="$OUT/k/distribution/libcrypto.so.3"
{
    printf 'canary dso_sha256=%s size=%s\n' \
        "$(sha256sum "$p" | awk '{print $1}')" "$(stat -c %s "$p")"
    printf 'canary source: git archive HEAD extracted to court/tmp/pfp31/canary-src\n'
    printf 'canary edit: ml_kem/key.rs implicit-rejection mask select -> branch on mask\n'
} | tee "$EV/raw/canary-digest.txt"
echo "canary: done"
