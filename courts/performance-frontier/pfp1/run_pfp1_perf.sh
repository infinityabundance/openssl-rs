#!/usr/bin/env bash
#
# run_pfp1_perf.sh — PFP-1: setup-inclusive versus prepared-key latency.
#
# Implements the PFP-0 statistic on the within-candidate paired comparison:
#
#   * the candidate DSO is the distribution-shaped build of the working tree;
#   * one process per mode per repetition, 15 repetitions fixed before the run;
#   * the mode order within a repetition is a balanced pseudo-random sequence
#     from the fixed seed 0x50465030, written to raw/run-order.tsv;
#   * `--prepared` reuses a prepared Montgomery domain where the workload has
#     one; `--setup` removes that reuse (a NULL context for modexp, a fresh
#     DH/RSA object whose first operation builds the contexts for DH/RSA);
#   * each process must prove which DSO it mapped;
#   * every process must contain exactly the frozen WORKLOADS.json identifiers;
#   * CHECK lines are compared between the two arms of every repetition.
#
# This is a supplementary PFP-1 instrument, not a PFP-0 re-run: the population
# is unchanged, and no PFP-0 evidence is read or written.
#
# Runs INSIDE the court. Nothing compiles on the host.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

WORK="${PFP1_WORK:-$ROOT/evidence/performance-frontier/campaigns/PFP-1/performance}"
BUILD="${PFP1_BUILD_DIR:-$ROOT/court/tmp/pfp1-build}"
WORKLOADS="$ROOT/forensics/performance/WORKLOADS.json"
FIX_SRC="$ROOT/src/bn/dh_data.rs"
RSA_DER="${RSA_DER:-$ROOT/courts/phase18/timing/fixtures/rsa2048.der}"

REPS=15
ORDER_SEED=0x50465030
PIN_CPU="${PFP1_PIN_CPU:-1}"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

DSO="$BUILD/distribution/libcrypto.so.3"
HARNESS="$BUILD/bench_pfp1"

fail() {
    mkdir -p "$WORK"
    printf 'BLOCKED: %s\n' "$*" >"$WORK/BLOCKED"
    printf 'run_pfp1_perf: BLOCKED: %s\n' "$*" >&2
    exit 1
}
trap 'fail "command failed at line $LINENO"' ERR

[ -f "$RSA_DER" ] || fail "missing RSA fixture $RSA_DER"
[ -f "$WORKLOADS" ] || fail "missing $WORKLOADS"

rm -rf "$WORK/raw" "$WORK/fixtures" "$WORK/results.json" "$WORK/BLOCKED"
mkdir -p "$WORK/raw" "$WORK/fixtures"

if [ "${PFP1_SKIP_BUILD:-0}" != 1 ] || [ ! -f "$DSO" ]; then
    rm -rf "$BUILD"
    mkdir -p "$BUILD/target" "$BUILD/measurement" "$BUILD/distribution" "$BUILD/shell"
    echo "=== release build (fresh target dir, jobs=$JOBS) ==="
    (
        cd "$ROOT"
        env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
            cargo build --release --lib --offline
    ) >"$BUILD/build.log" 2>&1 || { tail -n 40 "$BUILD/build.log" >&2; fail "cargo build failed"; }
    ARCHIVE="$BUILD/target/release/libopenssl_rs.a"
    [ -f "$ARCHIVE" ] || fail "cargo did not produce $ARCHIVE"
    cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
       -Wl,-soname,libcrypto.so.3 -o "$BUILD/measurement/libcrypto.so.3"
    python3 "$ROOT/forensics/tools/implemented_surface.py" \
        --archive "$ARCHIVE" --out "$BUILD/implemented-surface.json" \
        >"$BUILD/implemented-surface.log" 2>&1
    python3 "$ROOT/courts/performance-frontier/baseline/emit_shell.py" \
        --surface "$BUILD/implemented-surface.json" --out "$BUILD/shell" \
        --authority openssl-3.6.4-production --record "$BUILD/shell-generation.json" \
        >"$BUILD/shell.log" 2>&1
    rustc --edition 2021 --emit=obj --crate-type lib -O \
        --crate-name libcrypto_shell -o "$BUILD/shell/libcrypto.shell.o" \
        "$BUILD/shell/libcrypto.shell.rs"
    cc -shared -o "$DSO" \
       -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
       "$BUILD/shell/libcrypto.shell.o" \
       -Wl,--version-script="$ROOT/artifacts/phase2/libcrypto.ld" \
       -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
       -lpthread -ldl -lm -lrt -lutil
fi
[ -f "$DSO" ] || fail "missing candidate DSO $DSO"

AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
[ -f "$AUTH_INC/openssl/bn.h" ] || fail "missing authority headers $AUTH_INC"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/performance-frontier/pfp1/bench_pfp1.c" -ldl -lm -o "$HARNESS"

echo "=== derive DH group fixtures from tracked bytes ==="
python3 "$ROOT/courts/performance-frontier/baseline/extract_dh_fixtures.py" \
    --source "$FIX_SRC" --out "$WORK/fixtures" >"$WORK/fixtures/dh-fixtures.stdout"
[ -s "$WORK/fixtures/ffdhe2048.hex" ] || fail "missing ffdhe2048 fixture"
[ -s "$WORK/fixtures/ffdhe3072.hex" ] || fail "missing ffdhe3072 fixture"
[ -s "$WORK/fixtures/modp2048.hex" ] || fail "missing modp2048 fixture"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$WORK/fixtures/ffdhe2048.hex"
        --dh-ffdhe3072 "$WORK/fixtures/ffdhe3072.hex"
        --dh-modp2048 "$WORK/fixtures/modp2048.hex")

mapfile -t EXPECTED < <(
    python3 - "$WORKLOADS" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for item in sorted(doc["workloads"], key=lambda w: w["id"]):
    print(item["id"])
PY
)

# --- identity -------------------------------------------------------------

git -C "$ROOT" rev-parse HEAD >"$WORK/raw/source-head.txt"
git -C "$ROOT" status --porcelain >"$WORK/raw/worktree-status.txt" || true
{
    sha256sum "$ROOT/src/bn/mont.rs" "$ROOT/src/bn/arith.rs" \
             "$ROOT/src/rsa/ossl.rs" "$ROOT/courts/performance-frontier/pfp1/bench_pfp1.c" \
             "$ROOT/courts/performance-frontier/pfp1/analyse_pfp1.py"
} >"$WORK/raw/patch-files.sha256"
sha256sum "$DSO" >"$WORK/raw/candidate-dso.sha256"
sha256sum "$HARNESS" >"$WORK/raw/harness.sha256"

{
    echo "campaign=PFP-1"
    echo "inside_court=true"
    echo "court_image=${PFP1_COURT_IMAGE:-unknown}"
    echo "container_hostname=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
    echo "nproc=$(nproc)"
    echo "cpu_model=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
    echo "taskset_cpu=$PIN_CPU"
    echo "cgroup_memory_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
    echo "cgroup_cpu_max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)"
    echo "mem_available_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
} >"$WORK/venue.txt"

# --- balanced mode order, fixed before measurement ------------------------

python3 - "$REPS" "$ORDER_SEED" >"$WORK/raw/run-order.tsv" <<'PY'
import random, sys
reps, seed = int(sys.argv[1]), int(sys.argv[2], 0)
rng = random.Random(seed)
firsts = ["setup"] * (reps // 2 + reps % 2) + ["prepared"] * (reps // 2)
rng.shuffle(firsts)
for i, first in enumerate(firsts):
    second = "prepared" if first == "setup" else "setup"
    print(f"{i:02d}\t{first}\t{second}")
PY

printf 'label\tmode\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\texpected_size\treported_size\tstatus\n' \
    >"$WORK/raw/identity-check.tsv"

DSO_SHA="$(sha256sum "$DSO" | cut -d' ' -f1)"
DSO_REAL="$(realpath "$DSO")"
read -r DSO_DEV DSO_INO DSO_SIZE < <(stat -c '%d %i %s' "$DSO_REAL")
CURRENT_LABEL=""

verify_loaded() { # file mode
    local file=$1 mode=$2 rp dev ino size entries
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
                 for (i = 2; i <= NF; i++) {
                     split($i, a, "=");
                     if (a[1] == "entries") e = a[2];
                 }
             }
             END { print r, d, n, s, e }' "$file"
    )
    [ -n "${rp:-}" ] || fail "$CURRENT_LABEL/$mode: no LOADED line"
    [ "$rp" = "$DSO_REAL" ] || fail "$CURRENT_LABEL/$mode: mapped $rp, expected $DSO_REAL"
    [ "$dev" = "$DSO_DEV" ] || fail "$CURRENT_LABEL/$mode: device $dev != on-disk $DSO_DEV"
    [ "$ino" = "$DSO_INO" ] || fail "$CURRENT_LABEL/$mode: inode $ino != on-disk $DSO_INO"
    [ "$size" = "$DSO_SIZE" ] || fail "$CURRENT_LABEL/$mode: size $size != on-disk $DSO_SIZE"
    [ "${entries:-0}" -ge 1 ] || fail "$CURRENT_LABEL/$mode: no /proc/self/maps entry"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$CURRENT_LABEL" "$mode" "$DSO_SHA" "$DSO_REAL" "$rp" \
        "$DSO_DEV" "$dev" "$DSO_INO" "$ino" "$DSO_SIZE" "$size" ok \
        >>"$WORK/raw/identity-check.tsv"
}

verify_population() { # file mode
    local file=$1 mode=$2
    local -a got
    mapfile -t got < <(awk '$1 == "RESULT" {print $2}' "$file" | sort)
    if [ "${#got[@]}" -ne "${#EXPECTED[@]}" ]; then
        fail "$CURRENT_LABEL/$mode: population has ${#got[@]} lines, expected ${#EXPECTED[@]}"
    fi
    diff -u <(printf '%s\n' "${EXPECTED[@]}") <(printf '%s\n' "${got[@]}") \
        >"$WORK/raw/population-$CURRENT_LABEL-$mode.diff" \
        || fail "$CURRENT_LABEL/$mode: workload identifiers differ from WORKLOADS.json"
}

run_one() { # mode label
    local mode=$1 label=$2
    local out="$WORK/raw/$label-$mode.out"
    CURRENT_LABEL="$label"
    LD_LIBRARY_PATH="$(dirname "$DSO")" taskset -c "$PIN_CPU" \
        "$HARNESS" --lib "$DSO" "${COMMON[@]}" "--$mode" >"$out"
    verify_loaded "$out" "$mode"
    verify_population "$out" "$mode"
}

# --- warm-up (excluded) ---------------------------------------------------

echo "=== warm-up pair (excluded) ==="
run_one setup warmup
run_one prepared warmup

# --- measured repetitions -------------------------------------------------

echo "=== measured repetitions ($REPS, balanced mode order) ==="
while IFS=$'\t' read -r rep first second; do
    echo "--- repetition $rep: $first then $second"
    run_one "$first" "rep-$rep"
    run_one "$second" "rep-$rep"
    grep '^CHECK ' "$WORK/raw/rep-$rep-setup.out" | sort \
        >"$WORK/raw/rep-$rep-setup.check"
    grep '^CHECK ' "$WORK/raw/rep-$rep-prepared.out" | sort \
        >"$WORK/raw/rep-$rep-prepared.check"
    diff -u "$WORK/raw/rep-$rep-setup.check" \
            "$WORK/raw/rep-$rep-prepared.check" \
        >"$WORK/raw/rep-$rep-checks.diff" \
        || fail "rep-$rep: CHECK lines differ between setup and prepared"
done <"$WORK/raw/run-order.tsv"

# --- analysis -------------------------------------------------------------

echo "=== analyse ==="
python3 "$ROOT/courts/performance-frontier/pfp1/analyse_pfp1.py" \
    --work "$WORK" --workloads "$WORKLOADS" --out "$WORK/results.json" \
    >"$WORK/raw/analysis.stdout"
python3 -m json.tool "$WORK/results.json" >/dev/null

echo "PASS: PFP-1 performance campaign completed; results in $WORK/results.json"
