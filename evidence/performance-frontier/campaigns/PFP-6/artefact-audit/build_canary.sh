#!/bin/sh
# build_canary.sh — PFP-27 negative control: a deliberately branchy CIOS kernel.
#
# K = the DSO- B source (LADDER_SCHEDULE = Cios) with exactly one further edit:
# the final masked conditional subtraction in `mont_mul_cios_into` is replaced
# by a branch on the secret-derived `keep` flag.  That is the defect class the
# PFP-2 leak belonged to, and the instrument must fire on it (AGENTS.md §16).
#
# The canary is a test-only artefact.  It is never proposed, never the candidate,
# and every source edit is restored with the src fingerprint re-checked.
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g CARGO_BUILD_JOBS=4 \
#     bash docker/openssl-rs-court.sh exec bash \
#       evidence/performance-frontier/campaigns/PFP-6/artefact-audit/build_canary.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
OUT=/work/court/tmp/pfp27
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

fingerprint() { find src -name '*.rs' -print0 | sort -z | xargs -0 sha256sum; }
fingerprint >"$OUT/src.before-canary.sha256"

cp src/bn/arith.rs "$OUT/arith.restore-canary.rs"
restore() {
    cp "$OUT/arith.restore-canary.rs" src/bn/arith.rs
    fingerprint >"$OUT/src.after-canary.sha256"
    cmp -s "$OUT/src.before-canary.sha256" "$OUT/src.after-canary.sha256" || {
        echo "FATAL: src fingerprint changed during the canary build" >&2
        exit 90
    }
    echo "restore: src fingerprint identical"
}
trap restore EXIT HUP INT TERM

sed -i 's/^const LADDER_SCHEDULE: MontSchedule = MontSchedule::Sos;$/const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;/' src/bn/arith.rs

python3 - <<'PY'
import io, sys
p = 'src/bn/arith.rs'
s = io.open(p, encoding='utf-8').read()
old = """    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    for j in 0..n {
        out[j] = constant_time_select(mask as usize, diff[j] as usize, acc[j] as usize) as Limb;
    }
"""
new = """    let keep = high | (borrow ^ 1);
    // CANARY (PFP-27 negative control): a branch on the secret-derived flag.
    // Two distinct `#[inline(never)]` sinks keep the optimiser from
    // if-converting the branch into a conditional move.
    if keep != 0 {
        canary_take_diff(out, diff, n);
    } else {
        canary_take_acc(out, acc, n);
    }
"""
sinks = """
// CANARY (PFP-27 negative control): the two arms are distinct opaque callees.
#[inline(never)]
fn canary_take_diff(out: &mut [Limb], src: &[Limb], n: usize) {
    for j in 0..n {
        out[j] = src[j];
    }
}

#[inline(never)]
fn canary_take_acc(out: &mut [Limb], src: &[Limb], n: usize) {
    for j in 0..n {
        out[j] = src[j];
    }
}

fn mont_mul_cios_into(
"""
if s.count(old) != 1:
    sys.stderr.write('FATAL: canary site not found exactly once\n')
    sys.exit(1)
if s.count('fn mont_mul_cios_into(\n') != 1:
    sys.stderr.write('FATAL: canary sink anchor not found exactly once\n')
    sys.exit(1)
s = s.replace(old, new)
s = s.replace('fn mont_mul_cios_into(\n', sinks, 1)
io.open(p, 'w', encoding='utf-8').write(s)
PY

grep -q 'CANARY (PFP-27 negative control)' src/bn/arith.rs || {
    echo "FATAL: canary not applied" >&2; exit 1; }

diff -u "$OUT/arith.restore-canary.rs" src/bn/arith.rs >"$EV/raw/canary-difference.diff" || true

mkdir -p "$OUT/k/target" "$OUT/k/shell" "$OUT/k/distribution"
echo "=== K: cargo build --release --lib --offline (JOBS=$JOBS) ==="
CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$OUT/k/target" \
    cargo build --release --lib --offline

rustc --edition 2021 --emit=obj --crate-type lib -O \
    --crate-name libcrypto_shell -o "$OUT/k/shell/libcrypto.shell.o" \
    "$SHELL_RS"
cc -shared -o "$OUT/k/distribution/libcrypto.so.3" \
    -Wl,--whole-archive "$OUT/k/target/release/libopenssl_rs.a" \
    -Wl,--no-whole-archive "$OUT/k/shell/libcrypto.shell.o" \
    -Wl,--version-script="$VERSION_SCRIPT" \
    -Wl,-soname,libcrypto.so.3 \
    -lpthread -ldl -lm -lrt -lutil

restore
trap - EXIT HUP INT TERM

p="$OUT/k/distribution/libcrypto.so.3"
{
    printf 'canary dso_sha256=%s size=%s\n' \
        "$(sha256sum "$p" | awk '{print $1}')" "$(stat -c %s "$p")"
    printf 'canary edit mont_mul_cios_into final masked subtraction -> branch on keep\n'
} | tee "$EV/raw/canary-digest.txt"
echo "canary: done"
