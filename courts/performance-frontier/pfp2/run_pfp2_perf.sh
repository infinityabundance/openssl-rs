#!/usr/bin/env bash
#
# run_pfp2_perf.sh — PFP-2 kernel comparison, end-to-end measurement and
# mutation control.
#
# Three instruments, all inside the court:
#
#   1. in-process kernel measurement (`ec::p256::tests::pfp2_kernel_measurement`)
#      measures mul, sqr, add, sub and reduce for MONT, SOLINAS and ARCH on a
#      fixed operand population, and the end-to-end P-256 ladder with each kernel
#      forced. One process per repetition, 15 repetitions, kernel order rotated
#      by the repetition.
#
#   2. `bench_pfp2` measures the PFP-0 `ecdsa256` workload (the same fixed key,
#      digest, iteration count and CHECK line as `bench_api.c`) and a `p256-mul`
#      ladder workload, through one distribution DSO per process. The candidate
#      is built four ways from the same source: the unforced default, and one
#      DSO per kernel with `OPENSSL_RS_PFP2_MEASURE_KERNEL` fixed at compile
#      time. The authority is the admitted OpenSSL 3.6.4 production DSO, so the
#      candidate/authority ratio is directly comparable with the PFP-0
#      `ecdsa256` row.
#
#   3. the before-control (`git archive a3f7b277c`, the PFP-2 base commit) is
#      the pre-engine generic fixed-width ladder, so candidate/before is the
#      mutation control: forcing the generic implementation must undo the win.
#
# The statistic is the PFP-0 one: 15 repetitions fixed before execution, one
# process per arm per repetition, median of five batch means, paired ratios by
# repetition, median of the paired ratios, percentile bootstrap interval (20 000
# resamples, seed 0x50465030), exact sign test. No row is excluded.
#
# Evidence population: every repetition must produce one ecdsa256 and one
# p256-mul RESULT line for every arm, and every arm's CHECK lines must be
# non-empty and identical to the authority's. A missing, duplicate or extra
# identifier makes the campaign BLOCKED.
#
# OOM note: the release test binary's LLVM peak exceeded a 6g court cap
# (`rustc-LLVM ERROR: out of memory`). The court runs at the §6.1 computed cap
# (8g here) and every build uses CARGO_BUILD_JOBS=1, which bounds rustc's
# parallel codegen. The runner refuses to start below 24 GiB available.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

AUTH_PREFIX="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
AUTH_INC="$AUTH_PREFIX/include"
AUTH_DSO="$AUTH_PREFIX/lib/libcrypto.so.3"

CAMPAIGN="$ROOT/evidence/performance-frontier/campaigns/PFP-2"
WORK="${PFP2_WORK:-$CAMPAIGN/performance}"
BUILD="${PFP2_BUILD_DIR:-$ROOT/court/tmp/pfp2-build}"
BEFORE_COMMIT="${PFP2_BEFORE_COMMIT:-a3f7b277cf09ea2cb28c853fded090580f3e80cd}"
JOBS="${CARGO_BUILD_JOBS:-1}"
[ "$JOBS" -le 4 ] || JOBS=4
REPS=15
ORDER_SEED=0x50465030
PIN_CPU="${PFP2_PIN_CPU:-1}"
VARIANTS=(default mont solinas arch before)

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
mkdir -p "$WORK/raw" "$BUILD"

[ -f "$AUTH_INC/openssl/bn.h" ] || fail "missing authority headers"
[ -f "$AUTH_DSO" ] || fail "missing authority DSO"
[ -f "$VERSION_SCRIPT" ] || fail "missing $VERSION_SCRIPT"

# --- build the harness and the allocation probe ------------------------------

cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp2/bench_pfp2.c" -ldl -lm \
   -o "$BUILD/bench_pfp2"
cc -O2 -fPIC -shared "$ROOT/courts/phase18/timing/alloc_probe.c" -ldl \
   -o "$BUILD/alloc_probe.so"
HARNESS="$BUILD/bench_pfp2"

# --- link one distribution DSO from a static archive -------------------------

link_dso() { # archive outdir
    local archive=$1 outdir=$2
    mkdir -p "$outdir"
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

# --- build the candidate variants --------------------------------------------
#
# The kernel variants differ only in `option_env!`, which cargo does not track as
# a fingerprint input. `cargo clean -p openssl-rs` between variants removes the
# crate's own artifacts (dependencies stay cached) so each compile sees its own
# value. The source is never edited.

CAND_TARGET="$BUILD/candidate-target"
build_variant() { # name force
    local name=$1 force=$2
    local outdir="$BUILD/$name"
    if [ "$name" != default ]; then
        env CARGO_TARGET_DIR="$CAND_TARGET" \
            cargo clean -p openssl-rs --release >"$outdir.clean.log" 2>&1 || true
    fi
    (
        cd "$ROOT"
        env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$CAND_TARGET" \
            OPENSSL_RS_PFP2_MEASURE_KERNEL="$force" \
            cargo build --release --lib --offline
    ) >"$outdir.build.log" 2>&1 || { tail -n 30 "$outdir.build.log" >&2; fail "build $name"; }
    link_dso "$CAND_TARGET/release/libopenssl_rs.a" "$outdir"
}

build_variant default ""
build_variant mont MONT
build_variant solinas SOLINAS
build_variant arch ARCH

# --- build the before-control (the pre-engine generic ladder) ----------------

mkdir -p "$BUILD/before-src"
git -C "$ROOT" archive "$BEFORE_COMMIT" | tar -x -C "$BUILD/before-src"
(
    cd "$BUILD/before-src"
    env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/before-target" \
        cargo build --release --lib --offline
) >"$BUILD/before.build.log" 2>&1 || { tail -n 30 "$BUILD/before.build.log" >&2; fail "build before"; }
link_dso "$BUILD/before-target/release/libopenssl_rs.a" "$BUILD/before"

# --- identity and venue ------------------------------------------------------

git -C "$ROOT" rev-parse HEAD >"$WORK/raw/source-head.txt"
git -C "$ROOT" status --porcelain >"$WORK/raw/worktree-status.txt" || true
git -C "$ROOT" diff >"$WORK/raw/worktree.diff"
sha256sum "$WORK/raw/worktree.diff" >"$WORK/raw/worktree-diff.sha256"
sha256sum "$ROOT/src/ec/p256.rs" "$ROOT/src/ec/p256/tests.rs" \
         "$ROOT/src/ec/mult.rs" "$ROOT/src/ec/smpl.rs" \
         "$ROOT/courts/performance-frontier/pfp2/bench_pfp2.c" \
         "$ROOT/courts/performance-frontier/pfp2/analyse_pfp2.py" \
         >"$WORK/raw/patch-files.sha256"
git -C "$ROOT" rev-parse "$BEFORE_COMMIT" >"$WORK/raw/before-commit.txt"

for arm in "${VARIANTS[@]}"; do
    sha256sum "$BUILD/$arm/libcrypto.so.3" >"$WORK/raw/$arm-dso.sha256"
done
sha256sum "$AUTH_DSO" >"$WORK/raw/authority-dso.sha256"
sha256sum "$HARNESS" >"$WORK/raw/harness.sha256"
sha256sum "$BUILD/alloc_probe.so" >"$WORK/raw/alloc-probe.sha256"

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
    echo "authority_dso=$AUTH_DSO"
    echo "authority_sha256=$(sha256sum "$AUTH_DSO" | cut -d' ' -f1)"
} >"$WORK/venue.txt"

# --- balanced order, fixed before measurement --------------------------------

python3 - "$REPS" "$ORDER_SEED" "${#VARIANTS[@]}" >"$WORK/raw/run-order.tsv" <<'PY'
import random, sys
reps, seed, width = int(sys.argv[1]), int(sys.argv[2], 0), int(sys.argv[3])
rng = random.Random(seed)
firsts = ["authority"] * (reps // 2 + reps % 2) + ["candidate"] * (reps // 2)
rng.shuffle(firsts)
for i, first in enumerate(firsts):
    print(f"{i:02d}\t{first}\t{i % width}")
PY

printf 'arm\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tstatus\n' \
    >"$WORK/raw/identity-check.tsv"

dso_sha() { sha256sum "$1" | cut -d' ' -f1; }
arm_dso() {
    case "$1" in
        authority) echo "$AUTH_DSO" ;;
        *) echo "$BUILD/$1/libcrypto.so.3" ;;
    esac
}

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
    local real
    real="$(realpath "$dso")"
    read -r e_dev e_ino e_size < <(stat -c '%d %i %s' "$real")
    [ -n "${rp:-}" ] || fail "$arm: no LOADED line in $file"
    [ "$rp" = "$real" ] || fail "$arm: mapped $rp, expected $real"
    [ "$dev" = "$e_dev" ] || fail "$arm: device $dev != $e_dev"
    [ "$ino" = "$e_ino" ] || fail "$arm: inode $ino != $e_ino"
    [ "$size" = "$e_size" ] || fail "$arm: size $size != $e_size"
    [ "${entries:-0}" -ge 1 ] || fail "$arm: no /proc/self/maps entry"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tok\n' \
        "$arm" "$(dso_sha "$dso")" "$real" "$rp" "$e_dev" "$dev" "$e_ino" "$ino" \
        "$e_size" "$size" >>"$WORK/raw/identity-check.tsv"
}

run_dso() { # arm tag
    local arm=$1 tag=$2 dso out
    dso="$(arm_dso "$arm")"
    for wl in ecdsa mul; do
        out="$WORK/raw/dso-$tag-$arm-$wl.out"
        if [ "$wl" = ecdsa ]; then
            LD_LIBRARY_PATH="$(dirname "$dso")" taskset -c "$PIN_CPU" \
                "$HARNESS" --lib "$dso" --ecdsa --iters 500 --runs 5 >"$out"
        else
            LD_LIBRARY_PATH="$(dirname "$dso")" taskset -c "$PIN_CPU" \
                "$HARNESS" --lib "$dso" --mul --iters 200 --runs 5 >"$out"
        fi
        verify_loaded "$out" "$arm" "$dso"
    done
}

run_alloc() { # arm
    local arm=$1 dso out
    dso="$(arm_dso "$arm")"
    out="$WORK/raw/alloc-$arm.out"
    LD_PRELOAD="$BUILD/alloc_probe.so" LD_LIBRARY_PATH="$(dirname "$dso")" \
        taskset -c "$PIN_CPU" "$HARNESS" --lib "$dso" --ecdsa --alloc \
        --iters 5 --runs 1 >"$out"
    verify_loaded "$out" "$arm" "$dso"
    grep -q '^ALLOC ecdsa256 allocs_per_op=[0-9]' "$out" \
        || fail "$arm: allocation probe produced no numeric count"
}

run_kernels() { # tag rep
    local tag=$1 rep=$2 out="$WORK/raw/kernels-$1.out"
    : >"$WORK/raw/kernels-$1.tsv"
    (
        cd "$ROOT"
        env -u OPENSSL_RS_PFP2_MEASURE_KERNEL CARGO_BUILD_JOBS="$JOBS" \
            PFP2_MEASURE=1 PFP2_MEASURE_REP="$rep" \
            PFP2_MEASURE_OUT="$WORK/raw/kernels-$1.tsv" \
            cargo test --release --lib --offline \
                ec::p256::tests::pfp2_kernel_measurement -- --exact --nocapture
    ) >"$out" 2>&1
    grep -q '^RESULT' "$out" || fail "$tag: kernel measurement produced no RESULT line"
}

# --- warm-up (excluded from every statistic) ---------------------------------

echo "=== warm-up (excluded) ==="
run_kernels warmup 0
for arm in "${VARIANTS[@]}" authority; do
    run_dso "$arm" warmup
done

# --- measured repetitions ----------------------------------------------------

echo "=== measured repetitions ($REPS) ==="
while IFS=$'\t' read -r rep first rotation; do
    echo "--- repetition $rep: first=$first rotation=$rotation"
    ordered=()
    for k in 0 1 2 3 4; do
        ordered+=("${VARIANTS[$(( (rotation + k) % ${#VARIANTS[@]} ))]}")
    done
    if [ "$first" = authority ]; then
        run_dso authority "rep-$rep"
        for arm in "${ordered[@]}"; do run_dso "$arm" "rep-$rep"; done
    else
        for arm in "${ordered[@]}"; do run_dso "$arm" "rep-$rep"; done
        run_dso authority "rep-$rep"
    fi
    # Every arm's CHECK population must be non-empty and byte-identical to the
    # authority's, for both workloads.
    for arm in "${VARIANTS[@]}"; do
        for wl in ecdsa mul; do
            auth_out="$WORK/raw/dso-rep-$rep-authority-$wl.out"
            cand_out="$WORK/raw/dso-rep-$rep-$arm-$wl.out"
            grep -q '^CHECK ' "$cand_out" || fail "rep-$rep $arm $wl: empty CHECK population"
            diff -u <(grep '^CHECK ' "$auth_out") \
                    <(grep '^CHECK ' "$cand_out") \
                >"$WORK/raw/dso-rep-$rep-$arm-$wl-checks.diff" \
                || fail "rep-$rep $arm $wl: CHECK lines differ from the authority"
        done
    done
    run_kernels "rep-$rep" "$rep"
done <"$WORK/raw/run-order.tsv"

# --- allocation probe --------------------------------------------------------

echo "=== allocation probe ==="
for arm in default before; do run_alloc "$arm"; done

# --- analysis ----------------------------------------------------------------

echo "=== analyse ==="
python3 "$ROOT/courts/performance-frontier/pfp2/analyse_pfp2.py" \
    --work "$WORK" --reps "$REPS" --out "$WORK/results.json" \
    >"$WORK/raw/analysis.stdout"
python3 -m json.tool "$WORK/results.json" >/dev/null

echo "PASS: PFP-2 campaign completed; results in $WORK/results.json"
