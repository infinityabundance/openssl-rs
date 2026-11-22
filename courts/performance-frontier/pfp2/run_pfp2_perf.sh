#!/usr/bin/env bash
#
# run_pfp2_perf.sh — PFP-2 kernel comparison and end-to-end mutation control.
#
# Two instruments, both inside the court:
#
#   1. in-process kernel measurement (`ec::p256::tests::pfp2_kernel_measurement`)
#      measures mul, sqr, add, sub and reduce for MONT, SOLINAS and ARCH on a
#      fixed operand population, and the end-to-end P-256 ladder with each kernel
#      forced. One process per repetition, 15 repetitions, kernel order rotated
#      by the repetition.
#
#   2. `bench_pfp2` measures ECDSA signing and `EC_POINT_mul` through the
#      distribution DSO built from the working tree and from the before-control
#      source (`git archive a3f7b277c`, the PFP-2 base commit). The paired
#      candidate/before ratio is the mutation control: the before-control's
#      P-256 ladder is the generic fixed-width workspace with the Knuth
#      reduction, so the delta is the engine's contribution.
#
# The statistic is the PFP-0 one: 15 repetitions fixed before execution, one
# process per arm per repetition, median of five batch means, median of the
# paired ratios, percentile bootstrap interval (20 000 resamples, seed
# 0x50465030). No row is excluded.
#
# OOM note: the release test binary's LLVM peak exceeded the 6g court cap once
# (`rustc-LLVM ERROR: out of memory`). The court was recreated at the §6.1
# computed cap of 8g and the build runs with CARGO_BUILD_JOBS=1, which bounds
# rustc's parallel codegen. Both facts are recorded in the receipt.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

CAMPAIGN="$ROOT/evidence/performance-frontier/campaigns/PFP-2"
WORK="${PFP2_WORK:-$CAMPAIGN/performance}"
BUILD="${PFP2_BUILD_DIR:-$ROOT/court/tmp/pfp2-build}"
BEFORE_COMMIT="${PFP2_BEFORE_COMMIT:-a3f7b277cf09ea2cb28c853fded090580f3e80cd}"
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4
REPS=15
ORDER_SEED=0x50465030
PIN_CPU="${PFP2_PIN_CPU:-1}"

AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
VERSION_SCRIPT="$ROOT/artifacts/phase2/libcrypto.ld"

fail() {
    mkdir -p "$WORK"
    printf 'BLOCKED: %s\n' "$*" >"$WORK/BLOCKED"
    printf 'run_pfp2_perf: BLOCKED: %s\n' "$*" >&2
    exit 1
}
trap 'fail "command failed at line $LINENO"' ERR

# §6.1 memory guard: refuse to start a build without headroom.
avail_kb="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
[ "${avail_kb:-0}" -ge 25165824 ] || fail "MemAvailable ${avail_kb} KiB is below the 24 GiB floor"

rm -rf "$WORK/raw" "$WORK/results.json" "$WORK/BLOCKED"
mkdir -p "$WORK/raw"

[ -f "$AUTH_INC/openssl/bn.h" ] || fail "missing authority headers"
[ -f "$VERSION_SCRIPT" ] || fail "missing $VERSION_SCRIPT"

# --- build both DSOs ------------------------------------------------------

build_side() { # source-dir target-dir output-dir
    local src=$1 target=$2 outdir=$3
    mkdir -p "$outdir"
    (
        cd "$src"
        env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$target" \
            cargo build --release --lib --offline
    ) >"$outdir/build.log" 2>&1 || { tail -n 30 "$outdir/build.log" >&2; fail "build in $src"; }
    local archive="$target/release/libopenssl_rs.a"
    [ -f "$archive" ] || fail "no archive from $src"
    python3 "$ROOT/forensics/tools/implemented_surface.py" \
        --archive "$archive" --out "$outdir/implemented-surface.json" \
        >"$outdir/implemented-surface.log" 2>&1
    python3 "$ROOT/courts/performance-frontier/baseline/emit_shell.py" \
        --surface "$outdir/implemented-surface.json" --out "$outdir/shell" \
        --authority openssl-3.6.4-production --record "$outdir/shell-generation.json" \
        >"$outdir/shell.log" 2>&1
    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$outdir/shell/libcrypto.shell.o" \
        "$outdir/shell/libcrypto.shell.rs"
    cc -shared -o "$outdir/libcrypto.so.3" \
       -Wl,--whole-archive "$archive" -Wl,--no-whole-archive \
       "$outdir/shell/libcrypto.shell.o" \
       -Wl,--version-script="$VERSION_SCRIPT" \
       -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
       -lpthread -ldl -lm -lrt -lutil
    sha256sum "$outdir/libcrypto.so.3" >"$outdir/libcrypto.so.3.sha256"
}

if [ "${PFP2_SKIP_BUILD:-0}" != 1 ] || [ ! -f "$BUILD/candidate/libcrypto.so.3" ]; then
    rm -rf "$BUILD"
    mkdir -p "$BUILD/before-src"
    git -C "$ROOT" archive "$BEFORE_COMMIT" | tar -x -C "$BUILD/before-src"
    build_side "$ROOT" "$BUILD/candidate-target" "$BUILD/candidate"
    build_side "$BUILD/before-src" "$BUILD/before-target" "$BUILD/before"
fi

DSO_CAND="$BUILD/candidate/libcrypto.so.3"
DSO_BEFORE="$BUILD/before/libcrypto.so.3"
HARNESS="$BUILD/bench_pfp2"
[ -f "$DSO_CAND" ] || fail "missing candidate DSO"
[ -f "$DSO_BEFORE" ] || fail "missing before-control DSO"

cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp2/bench_pfp2.c" -ldl -lm -o "$HARNESS"

# --- identity and venue ---------------------------------------------------

git -C "$ROOT" rev-parse HEAD >"$WORK/raw/source-head.txt"
git -C "$ROOT" status --porcelain >"$WORK/raw/worktree-status.txt" || true
git -C "$ROOT" rev-parse "$BEFORE_COMMIT" >"$WORK/raw/before-commit.txt"
{
    sha256sum "$ROOT/src/ec/p256.rs" "$ROOT/src/ec/p256/tests.rs" \
             "$ROOT/src/ec/mult.rs" "$ROOT/src/ec/smpl.rs" \
             "$ROOT/courts/performance-frontier/pfp2/bench_pfp2.c" \
             "$ROOT/courts/performance-frontier/pfp2/analyse_pfp2.py"
} >"$WORK/raw/patch-files.sha256"
sha256sum "$DSO_CAND" >"$WORK/raw/candidate-dso.sha256"
sha256sum "$DSO_BEFORE" >"$WORK/raw/before-dso.sha256"
sha256sum "$HARNESS" >"$WORK/raw/harness.sha256"

{
    echo "campaign=PFP-2"
    echo "inside_court=true"
    echo "court_image=${OPENSSL_RS_COURT_IMAGE:-unknown}"
    echo "container_hostname=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
    echo "nproc=$(nproc)"
    echo "cpu_model=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
    echo "build_jobs=$JOBS"
    echo "taskset_cpu=$PIN_CPU"
    echo "cgroup_memory_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
    echo "cgroup_cpu_max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)"
    echo "mem_available_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
    echo "pmu=cpu event source absent (recorded by PFP-0); no hardware counters"
} >"$WORK/venue.txt"

# --- balanced order, fixed before measurement -----------------------------

python3 - "$REPS" "$ORDER_SEED" >"$WORK/raw/run-order.tsv" <<'PY'
import random, sys
reps, seed = int(sys.argv[1]), int(sys.argv[2], 0)
rng = random.Random(seed)
firsts = ["candidate"] * (reps // 2 + reps % 2) + ["before"] * (reps // 2)
rng.shuffle(firsts)
for i, first in enumerate(firsts):
    second = "before" if first == "candidate" else "candidate"
    print(f"{i:02d}\t{first}\t{second}")
PY

printf 'label\tarm\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tstatus\n' \
    >"$WORK/raw/identity-check.tsv"

dso_sha() { sha256sum "$1" | cut -d' ' -f1; }
CAND_SHA="$(dso_sha "$DSO_CAND")"
BEFORE_SHA="$(dso_sha "$DSO_BEFORE")"

verify_loaded() { # file arm dso
    local file=$1 arm=$2 dso=$3 rp dev ino size entries
    read -r rp dev ino size entries < <(
        awk '/^LOADED / {
                 for (i = 2; i <= NF; i++) {
                     split($i, a, "=");
                     if (a[1] == "realpath") r = a[2];
                     else if (a[1] == "dev") d = a[2];
                     else if (a[1] == "ino") n = a[2];
                     else if (a[1] == "size") s = a[2];
                 }
             }
             /^MAPS / {
                 for (i = 2; i <= NF; i++) { split($i, a, "="); if (a[1] == "entries") e = a[2]; }
             }
             END { print r, d, n, s, e }' "$file"
    )
    local real expected_sha
    real="$(realpath "$dso")"
    expected_sha="$(dso_sha "$dso")"
    read -r e_dev e_ino e_size < <(stat -c '%d %i %s' "$real")
    [ -n "${rp:-}" ] || fail "$arm: no LOADED line"
    [ "$rp" = "$real" ] || fail "$arm: mapped $rp, expected $real"
    [ "$dev" = "$e_dev" ] || fail "$arm: device $dev != $e_dev"
    [ "$ino" = "$e_ino" ] || fail "$arm: inode $ino != $e_ino"
    [ "$size" = "$e_size" ] || fail "$arm: size $size != $e_size"
    [ "${entries:-0}" -ge 1 ] || fail "$arm: no /proc/self/maps entry"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tok\n' \
        "$arm" "$arm" "$expected_sha" "$real" "$rp" "$e_dev" "$dev" "$e_ino" "$ino" \
        "$e_size" "$size" >>"$WORK/raw/identity-check.tsv"
}

run_dso() { # arm dso label
    local arm=$1 dso=$2 label=$3
    local out="$WORK/raw/dso-$label-$arm.out"
    LD_LIBRARY_PATH="$(dirname "$dso")" taskset -c "$PIN_CPU" \
        "$HARNESS" --lib "$dso" --iters 8 --runs 5 >"$out"
    verify_loaded "$out" "$arm" "$dso"
}

run_kernels() { # label
    local label=$1
    local out="$WORK/raw/kernels-$label.out"
    local tsv="$WORK/raw/kernels-$label.tsv"
    : >"$tsv"
    (
        cd "$ROOT"
        env CARGO_BUILD_JOBS="$JOBS" PFP2_MEASURE=1 PFP2_MEASURE_REP="${label#rep-}" \
            PFP2_MEASURE_OUT="$tsv" \
            cargo test --release --lib --offline \
                ec::p256::tests::pfp2_kernel_measurement -- --exact --nocapture
    ) >"$out" 2>&1
    grep -q '^RESULT' "$out" || fail "$label: kernel measurement produced no RESULT line"
}

# --- warm-up (excluded) ---------------------------------------------------

echo "=== warm-up (excluded) ==="
run_kernels warmup
run_dso candidate "$DSO_CAND" warmup
run_dso before "$DSO_BEFORE" warmup

# --- measured repetitions -------------------------------------------------

echo "=== measured repetitions ($REPS) ==="
while IFS=$'\t' read -r rep first second; do
    echo "--- repetition $rep: $first then $second"
    run_kernels "rep-$rep"
    run_dso "$first" "$( [ "$first" = candidate ] && echo "$DSO_CAND" || echo "$DSO_BEFORE" )" "rep-$rep"
    run_dso "$second" "$( [ "$second" = candidate ] && echo "$DSO_CAND" || echo "$DSO_BEFORE" )" "rep-$rep"
    diff -u <(grep '^CHECK ' "$WORK/raw/dso-rep-$rep-candidate.out" | sort) \
            <(grep '^CHECK ' "$WORK/raw/dso-rep-$rep-before.out" | sort) \
        >"$WORK/raw/dso-rep-$rep-checks.diff" \
        || fail "rep-$rep: CHECK lines differ between the arms"
done <"$WORK/raw/run-order.tsv"

# --- analysis -------------------------------------------------------------

echo "=== analyse ==="
python3 "$ROOT/courts/performance-frontier/pfp2/analyse_pfp2.py" \
    --work "$WORK" --reps "$REPS" --out "$WORK/results.json" \
    >"$WORK/raw/analysis.stdout"
python3 -m json.tool "$WORK/results.json" >/dev/null

echo "PASS: PFP-2 performance campaign completed; results in $WORK/results.json"
