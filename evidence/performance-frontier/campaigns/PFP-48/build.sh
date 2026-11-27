#!/bin/sh
# build.sh — PFP-48: build the SAME frozen source twice, as the campaign's
# release-DSO path does, and keep both artefacts.
#
#   baseline = no RUSTFLAGS (the portable x86-64 encoding)
#   variant  = RUSTFLAGS="-C target-feature=+bmi2" applied to the WHOLE crate,
#              so mont_mul_cios_fixed is compiled inside a BMI2 feature context
#              and inlines without any #[target_feature] wrapper call.
#
# No source is modified. Evidence: raw/build-inputs-*.txt, raw/disasm/.
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 \
#     bash docker/openssl-rs-court.sh exec env CARGO_PROFILE_TEST_DEBUG=0 \
#       sh evidence/performance-frontier/campaigns/PFP-48/build.sh
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-48
OUT="$EV/raw"
BASE=/work/court/tmp/pfp48
SHELL_RS=/work/artifacts/phase2/shell/libcrypto.shell.rs
VERSION_SCRIPT=/work/artifacts/phase2/libcrypto.ld
mkdir -p "$OUT/disasm" "$BASE"

for f in "$SHELL_RS" "$VERSION_SCRIPT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 1; }
done

build_variant() {
    tag=$1; extra=$2
    T="$BASE/$tag/target"
    mkdir -p "$BASE/$tag/shell"

    {
        echo "tag=$tag"
        echo "date=$(date -u +%FT%TZ)"
        echo "source_commit=$(git -C /work rev-parse HEAD)"
        echo "src_tree=$(git -C /work rev-parse HEAD:src)"
        echo "arith_sha256=$(sha256sum src/bn/arith.rs | awk '{print $1}')"
        echo "dirty_src=$(git -C /work status --porcelain -- src Cargo.toml Cargo.lock build.rs | tr '\n' ';')"
        echo "rustc=$(rustc --version)"
        echo "cargo=$(cargo --version)"
        echo "cc=$(cc --version | head -1)"
        echo "target_triple=$(rustc -vV | sed -n 's/^host: //p')"
        echo "profile=release"
        echo "rustflags=$extra"
    } >"$OUT/build-inputs-$tag.txt"

    echo "=== $tag: cargo build --release --lib --offline (RUSTFLAGS='$extra') ==="
    CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR="$T" \
        RUSTFLAGS="$extra" \
        cargo build --release --lib --offline 2>&1 | tail -n 3

    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$BASE/$tag/shell/libcrypto.shell.o" "$SHELL_RS"
    cc -shared -o "$BASE/$tag/libcrypto.so.3" \
        -Wl,--whole-archive "$T/release/libopenssl_rs.a" -Wl,--no-whole-archive \
        "$BASE/$tag/shell/libcrypto.shell.o" \
        -Wl,--version-script="$VERSION_SCRIPT" -Wl,-soname,libcrypto.so.3 \
        -lpthread -ldl -lm -lrt -lutil

    DSO="$BASE/$tag/libcrypto.so.3"
    {
        echo "archive_sha256=$(sha256sum "$T/release/libopenssl_rs.a" | awk '{print $1}')"
        echo "dso_path=$DSO"
        echo "dso_sha256=$(sha256sum "$DSO" | awk '{print $1}')"
        echo "dso_size=$(stat -c %s "$DSO")"
        echo "build_id=$(readelf -n "$DSO" | sed -n 's/.*Build ID: //p')"
    } >>"$OUT/build-inputs-$tag.txt"

    ADDR=$(nm -C --defined-only "$DSO" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $1; exit}')
    SIZE=$(nm -S --defined-only -C "$DSO" | awk '/openssl_rs::bn::arith::mont_mul_ladder_into$/{print $2; exit}')
    echo "mont_mul_ladder_into addr=0x$ADDR size=0x$SIZE" | tee -a "$OUT/build-inputs-$tag.txt"
    objdump -d --no-show-raw-insn --start-address=0x$ADDR \
        --stop-address=$((0x$ADDR + 0x$SIZE)) "$DSO" \
        >"$OUT/disasm/${tag}_mont_mul_ladder_into.dis"
}

build_variant portable ""
build_variant bmi2 "-C target-feature=+bmi2"

echo "=== whole-symbol opcode census (mont_mul_ladder_into) ===" | tee "$OUT/opcodes.txt"
for tag in portable bmi2; do
    f="$OUT/disasm/${tag}_mont_mul_ladder_into.dis"
    printf '%s: ' "$tag" | tee -a "$OUT/opcodes.txt"
    for op in mulq mulx adcx adox imul; do
        printf '%s=%s ' "$op" "$(grep -cE "^\s+[0-9a-f]+:\s+$op" "$f" || true)" | tee -a "$OUT/opcodes.txt"
    done
    echo | tee -a "$OUT/opcodes.txt"
done

echo "=== wrapper / out-of-line kernel symbols ===" | tee "$OUT/symbols.txt"
{
    echo "-- mont kernel symbols (demangled) --"
    nm -S --defined-only -C "$BASE/portable/libcrypto.so.3" \
        | grep -E 'mont_mul_cios_fixed|mont_mul_cios_bmi2|mont_mul_ladder_into' || true
    echo "-- variant --"
    nm -S --defined-only -C "$BASE/bmi2/libcrypto.so.3" \
        | grep -E 'mont_mul_cios_fixed|mont_mul_cios_bmi2|mont_mul_ladder_into' || true
    echo "-- variant: any call instruction inside mont_mul_ladder_into --"
    grep -E "^\s+[0-9a-f]+:\s+call" "$OUT/disasm/bmi2_mont_mul_ladder_into.dis" \
        | sed 's/^\s*//' | sort | uniq -c || true
} | tee -a "$OUT/symbols.txt"

echo "=== per-product static counts (count_pfp48.py) ===" | tee "$OUT/counts.txt"
python3 "$EV/count_pfp48.py" "$BASE/portable/libcrypto.so.3" portable | tee -a "$OUT/counts.txt"
python3 "$EV/count_pfp48.py" "$BASE/bmi2/libcrypto.so.3" bmi2 | tee -a "$OUT/counts.txt"

echo "=== build: done ==="
