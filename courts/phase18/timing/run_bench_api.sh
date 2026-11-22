#!/usr/bin/env bash
#
# run_bench_api.sh — PFP-0: reconstruct the cross-library performance baseline.
#
# Implements the preregistered protocol in docs/PERFORMANCE-METHODOLOGY.md:
#
#   * the candidate is built from the frozen, clean source tree into a fresh
#     CARGO_TARGET_DIR, then linked twice: the distribution-shaped DSO (shell
#     object + version script) is the one benchmarked, and the plain
#     measurement DSO is kept only for identity comparison;
#   * each repetition is one process per subject, and the candidate/authority
#     order within each repetition is a balanced pseudo-random sequence fixed
#     before execution and recorded in raw/run-order.tsv;
#   * the same allocation probe is preloaded for both subjects, with the same
#     workload population and the same accounting;
#   * every process must prove which file it mapped (LOADED device/inode from
#     /proc/self/maps against stat(2) on the expected on-disk DSO);
#   * result-line identities are matched against forensics/performance/
#     WORKLOADS.json, not by line count;
#   * ECDSA signatures are exchanged between the two libraries in both
#     directions at repetitions 0, 3, 6, 9, 12 and 14;
#   * real FFDHE/MODP group fixtures are derived from tracked bytes; the
#     synthetic modulus remains as a separately labelled row.
#
# Runs INSIDE the court (docker/openssl-rs-court.sh). Nothing compiles on the
# host. Usage from the repository root:
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#   OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
#     bash docker/openssl-rs-court.sh exec \
#       env CARGO_BUILD_JOBS=4 PFP0_COURT_IMAGE=openssl-rs-court-tools:1 \
#       bash courts/phase18/timing/run_bench_api.sh
#
# Outputs under evidence/performance-frontier/campaigns/PFP-0/ (override with
# PFP0_WORK): raw/*.out, raw/run-order.tsv, raw/identity-check.tsv,
# build-identity.json, venue.txt, raw/pmu-*.txt, results.json.
#
# Exit status: 0 only when build, identity, population, correctness,
# cross-verification and analysis all succeed. A resource-exhausted or failed
# run writes a BLOCKED marker; it is never reported as a pass.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$ROOT/forensics/tools/require_court.sh"

AUTH_PREFIX="${AUTH_PREFIX:-$ROOT/forensics/authorities/prefix/openssl-3.6.4-production}"
AUTH_LIB="$AUTH_PREFIX/lib"
AUTH_INC="$AUTH_PREFIX/include"
AUTH_DSO="$AUTH_LIB/libcrypto.so.3"

WORK="${PFP0_WORK:-$ROOT/evidence/performance-frontier/campaigns/PFP-0}"
BUILD="${PFP0_BUILD_DIR:-$ROOT/court/tmp/pfp0-build}"
WORKLOADS="$ROOT/forensics/performance/WORKLOADS.json"
FIX_SRC="$ROOT/src/bn/dh_data.rs"
RSA_DER="${RSA_DER:-$ROOT/courts/phase18/timing/fixtures/rsa2048.der}"

REPS=15
ORDER_SEED=0x50465030
CROSS_REPS="00 03 06 09 12 14"
PIN_CPU="${PFP0_PIN_CPU:-1}"
JOBS="${CARGO_BUILD_JOBS:-4}"
[ "$JOBS" -le 4 ] || JOBS=4

CAND_DSO="$BUILD/distribution/libcrypto.so.3"
MEAS_DSO="$BUILD/measurement/libcrypto.so.3"

fail() {
    mkdir -p "$WORK"
    printf 'BLOCKED: %s\n' "$*" >"$WORK/BLOCKED"
    printf 'run_bench_api: BLOCKED: %s\n' "$*" >&2
    exit 1
}
trap 'fail "command failed at line $LINENO"' ERR

[ -f "$AUTH_DSO" ] || fail "missing authority $AUTH_DSO"
[ -f "$AUTH_INC/openssl/bn.h" ] || fail "missing authority headers $AUTH_INC"
[ -f "$RSA_DER" ] || fail "missing RSA fixture $RSA_DER"
[ -f "$WORKLOADS" ] || fail "missing $WORKLOADS"

if [ -e "$WORK/results.json" ] || [ -e "$WORK/raw/run-order.tsv" ]; then
    if [ "${PFP0_FORCE:-0}" != 1 ]; then
        fail "campaign output already exists; set PFP0_FORCE=1 for a new attempt"
    fi
    rm -rf "$WORK/raw" "$WORK/fixtures" "$WORK/results.json" "$WORK/BLOCKED"
fi
rm -rf "$BUILD"
mkdir -p "$WORK/raw" "$WORK/fixtures" "$BUILD/measurement" \
         "$BUILD/distribution" "$BUILD/shell" "$BUILD/target"

# --- preregistration, before any measurement ------------------------------

python3 - "$WORK/preregistration.json" "$REPS" "$ORDER_SEED" "$CROSS_REPS" <<'PY'
import json, sys
path, reps, seed, cross = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].split()
doc = {
    "schema": "openssl-rs/performance/preregistration/v1",
    "campaign": "PFP-0",
    "protocol_document": "docs/PERFORMANCE-METHODOLOGY.md",
    "repetitions": reps,
    "unit_of_replication": "one process per subject per repetition",
    "ordering": {
        "kind": "balanced pseudo-random within each repetition",
        "seed": seed,
        "candidate_first_blocks": reps // 2 + reps % 2,
        "authority_first_blocks": reps // 2,
        "realised_file": "raw/run-order.tsv",
    },
    "warmup": "one unrecorded pair before repetition 00; excluded from statistics",
    "stopping_rule": "fixed repetition count; no early stop and no replacement",
    "statistic": "median of paired per-repetition ratios candidate_us/authority_us",
    "uncertainty": "percentile bootstrap, 20000 resamples, seed 0x50465030",
    "multiplicity": "Holm-Bonferroni across the declared workload family (alpha=0.05)",
    "cross_verification_repetitions": cross,
    "exclusions": "none may be introduced after execution",
    "exhaustion_policy": "a failed or resource-exhausted run is BLOCKED, never PASS",
}
open(path, "w").write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY

python3 - "$REPS" "$ORDER_SEED" >"$WORK/raw/run-order.tsv" <<'PY'
import random, sys
reps, seed = int(sys.argv[1]), int(sys.argv[2], 0)
rng = random.Random(seed)
firsts = ["candidate"] * (reps // 2 + reps % 2) + ["authority"] * (reps // 2)
rng.shuffle(firsts)
for i, first in enumerate(firsts):
    second = "authority" if first == "candidate" else "candidate"
    print(f"{i:02d}\t{first}\t{second}")
PY

# --- build from the frozen tree -------------------------------------------

git -C "$ROOT" rev-parse HEAD >"$WORK/raw/source-head.txt"
git -C "$ROOT" status --porcelain >"$WORK/raw/worktree-status.txt" || true
BUILD_DIRTY="$(git -C "$ROOT" status --porcelain -- src Cargo.toml Cargo.lock \
                 build.rs rust-toolchain.toml)"
[ -z "$BUILD_DIRTY" ] || fail "build-relevant worktree is dirty: $BUILD_DIRTY"

echo "=== release build (fresh target dir, jobs=$JOBS) ==="
if ! (
    cd "$ROOT"
    env CARGO_BUILD_JOBS="$JOBS" CARGO_TARGET_DIR="$BUILD/target" \
        cargo build --release --lib --offline
) >"$BUILD/build.log" 2>&1; then
    tail -n 40 "$BUILD/build.log" >&2
    fail "cargo build failed"
fi
ARCHIVE="$BUILD/target/release/libopenssl_rs.a"
[ -f "$ARCHIVE" ] || fail "cargo did not produce $ARCHIVE"
cp "$BUILD/build.log" "$WORK/raw/build.log"

echo "=== link measurement DSO ==="
cc -shared -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   -Wl,-soname,libcrypto.so.3 -o "$MEAS_DSO"

echo "=== link distribution-shaped DSO ==="
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
cc -shared -o "$CAND_DSO" \
   -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive \
   "$BUILD/shell/libcrypto.shell.o" \
   -Wl,--version-script="$ROOT/artifacts/phase2/libcrypto.ld" \
   -Wl,-soname,libcrypto.so.3 -Wl,--as-needed \
   -lpthread -ldl -lm -lrt -lutil
[ -f "$CAND_DSO" ] || fail "distribution DSO was not linked"
cp "$BUILD/implemented-surface.log" "$WORK/raw/implemented-surface.log"
cp "$BUILD/shell.log" "$WORK/raw/shell.log"
cp "$BUILD/shell-generation.json" "$WORK/raw/shell-generation.json"

echo "=== build harness and probe ==="
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/courts/phase18/timing/bench_api.c" -ldl -lm -o "$BUILD/bench_api"
cc -O2 -fPIC -shared "$ROOT/courts/phase18/timing/alloc_probe.c" -ldl \
   -o "$BUILD/alloc_probe.so"
cc -O2 "$ROOT/courts/phase18/timing/pmu_probe.c" -o "$BUILD/pmu_probe"

echo "=== derive DH group fixtures from tracked bytes ==="
python3 "$ROOT/courts/performance-frontier/baseline/extract_dh_fixtures.py" \
    --source "$FIX_SRC" --out "$WORK/fixtures" >"$WORK/fixtures/dh-fixtures.stdout"
[ -s "$WORK/fixtures/ffdhe2048.hex" ] || fail "missing ffdhe2048 fixture"
[ -s "$WORK/fixtures/ffdhe3072.hex" ] || fail "missing ffdhe3072 fixture"
[ -s "$WORK/fixtures/modp2048.hex" ] || fail "missing modp2048 fixture"

echo "=== record build identity ==="
python3 "$ROOT/courts/performance-frontier/baseline/build_identity.py" \
    --repo "$ROOT" --out "$WORK/build-identity.json" \
    --archive "$ARCHIVE" --measurement-dso "$MEAS_DSO" \
    --distribution-dso "$CAND_DSO" --authority-dso "$AUTH_DSO" \
    --harness "$ROOT/courts/phase18/timing/bench_api.c" \
    --harness "$ROOT/courts/phase18/timing/alloc_probe.c" \
    --harness "$ROOT/courts/phase18/timing/run_bench_api.sh" \
    --harness "$ROOT/courts/performance-frontier/baseline/extract_dh_fixtures.py" \
    --harness "$ROOT/courts/performance-frontier/baseline/analyse_bench_api.py" \
    --harness "$ROOT/courts/performance-frontier/baseline/build_identity.py" \
    --harness "$ROOT/courts/performance-frontier/baseline/emit_shell.py" \
    --fixture-manifest "$WORK/fixtures/dh-fixtures.json" \
    --shell-record "$BUILD/shell-generation.json" \
    --court-image "${PFP0_COURT_IMAGE:-unknown}"

# --- venue and PMU --------------------------------------------------------

{
    echo "campaign=PFP-0"
    echo "inside_court=true"
    echo "court_image=${PFP0_COURT_IMAGE:-unknown}"
    echo "container_hostname=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "machine=$(uname -m)"
    echo "nproc=$(nproc)"
    echo "cpu_model=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
    echo "cpu_flags=$(sed -n 's/^flags[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
    echo "taskset_cpu=$PIN_CPU"
    echo "cgroup_memory_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
    echo "cgroup_memory_current=$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo unknown)"
    echo "cgroup_cpu_max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)"
    echo "mem_available_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
    echo "self_cgroup=$(cat /proc/self/cgroup | tr '\n' ';')"
} >"$WORK/venue.txt"

"$BUILD/pmu_probe" >"$WORK/raw/pmu-probe.txt"
{
    if [ -e /sys/bus/event_source/devices/cpu ]; then
        echo "cpu_event_source=present"
    else
        echo "cpu_event_source=absent"
    fi
    echo "perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"
    echo "event_sources=$(ls /sys/bus/event_source/devices | tr '\n' ' ')"
    echo "--- perf stat -e cycles true ---"
    perf stat -e cycles true 2>&1 || true
    echo "--- perf stat -e task-clock true ---"
    perf stat -e task-clock true 2>&1 || true
} >"$WORK/raw/pmu-perf.txt"

# --- run helpers ----------------------------------------------------------

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

CAND_SHA="$(sha256sum "$CAND_DSO" | cut -d' ' -f1)"
AUTH_SHA="$(sha256sum "$AUTH_DSO" | cut -d' ' -f1)"
printf 'label\tsubject\tdso_sha256\texpected_realpath\treported_realpath\texpected_dev\treported_dev\texpected_ino\treported_ino\tmaps_entries\tstatus\n' \
    >"$WORK/raw/identity-check.tsv"
printf 'label\tsubject\tstart_ns\tend_ns\n' >"$WORK/raw/run-log.tsv"

CURRENT_LABEL=""

verify_loaded() { # file subject dso
    local file=$1 subject=$2 dso=$3 rp dev ino size entries
    local erp edev eino esize lib libres

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
    [ -n "${rp:-}" ] || fail "$CURRENT_LABEL/$subject: no LOADED line"
    erp="$(realpath "$dso")"
    read -r edev eino esize < <(stat -c '%d %i %s' "$erp")
    [ "$rp" = "$erp" ] || fail "$CURRENT_LABEL/$subject: mapped $rp, expected $erp"
    [ "$dev" = "$edev" ] || fail "$CURRENT_LABEL/$subject: device $dev != on-disk $edev"
    [ "$ino" = "$eino" ] || fail "$CURRENT_LABEL/$subject: inode $ino != on-disk $eino"
    [ "$size" = "$esize" ] || fail "$CURRENT_LABEL/$subject: size $size != on-disk $esize"
    [ "${entries:-0}" -ge 1 ] || fail "$CURRENT_LABEL/$subject: no /proc/self/maps entry"
    lib="$(sed -n 's/^LIB //p' "$file" | head -n 1)"
    libres="$(realpath "$lib")"
    [ "$libres" = "$erp" ] || fail "$CURRENT_LABEL/$subject: LIB $libres != $erp"

    if [ "$subject" = candidate ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$CURRENT_LABEL" "$subject" "$CAND_SHA" "$erp" "$rp" \
            "$edev" "$dev" "$eino" "$ino" "$entries" ok \
            >>"$WORK/raw/identity-check.tsv"
    else
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$CURRENT_LABEL" "$subject" "$AUTH_SHA" "$erp" "$rp" \
            "$edev" "$dev" "$eino" "$ino" "$entries" ok \
            >>"$WORK/raw/identity-check.tsv"
    fi
}

verify_population() { # file prefix
    local file=$1 prefix=$2
    local -a got
    mapfile -t got < <(awk -v p="$prefix" '$1 == p {print $2}' "$file" | sort)
    if [ "${#got[@]}" -ne "${#EXPECTED[@]}" ]; then
        fail "$CURRENT_LABEL: $prefix population has ${#got[@]} lines, expected ${#EXPECTED[@]}"
    fi
    if ! diff -u <(printf '%s\n' "${EXPECTED[@]}") <(printf '%s\n' "${got[@]}") \
            >"$WORK/raw/population-$CURRENT_LABEL-$prefix.diff"; then
        fail "$CURRENT_LABEL: $prefix workload identifiers differ from WORKLOADS.json"
    fi
}

run_one() { # subject dso out mode
    local subject=$1 dso=$2 out=$3 mode=$4 start end
    start="$(date -u +%s%N)"
    if [ "$mode" = alloc ]; then
        LD_PRELOAD="$BUILD/alloc_probe.so" LD_LIBRARY_PATH="$(dirname "$dso")" \
            taskset -c "$PIN_CPU" "$BUILD/bench_api" --lib "$dso" \
            "${COMMON[@]}" --alloc >"$out"
    else
        LD_LIBRARY_PATH="$(dirname "$dso")" taskset -c "$PIN_CPU" \
            "$BUILD/bench_api" --lib "$dso" "${COMMON[@]}" >"$out"
    fi
    end="$(date -u +%s%N)"
    printf '%s\t%s\t%s\t%s\n' "$CURRENT_LABEL" "$subject" "$start" "$end" \
        >>"$WORK/raw/run-log.tsv"
    verify_loaded "$out" "$subject" "$dso"
    if [ "$mode" = alloc ]; then
        verify_population "$out" ALLOC
    else
        verify_population "$out" RESULT
    fi
}

compare_checks() { # rep
    local rep=$1
    local c="$WORK/raw/rep-$rep-candidate.out"
    local a="$WORK/raw/rep-$rep-authority.out"
    grep '^CHECK ' "$c" | sort >"$WORK/raw/rep-$rep-candidate.check"
    grep '^CHECK ' "$a" | sort >"$WORK/raw/rep-$rep-authority.check"
    [ "$(wc -l <"$WORK/raw/rep-$rep-candidate.check")" -eq "${#EXPECTED[@]}" ] \
        || fail "rep-$rep: candidate produced the wrong number of CHECK lines"
    [ "$(wc -l <"$WORK/raw/rep-$rep-authority.check")" -eq "${#EXPECTED[@]}" ] \
        || fail "rep-$rep: authority produced the wrong number of CHECK lines"
    if ! diff -u "$WORK/raw/rep-$rep-authority.check" \
                 "$WORK/raw/rep-$rep-candidate.check" \
            >"$WORK/raw/rep-$rep-checks.diff"; then
        fail "rep-$rep: CHECK lines differ between candidate and authority"
    fi
}

cross_subject() { # rep signer
    local rep=$1 signer=$2 verifier dso_signer dso_verifier sig sign_out verify_out
    local ok pub_sign pub_verify
    if [ "$signer" = candidate ]; then
        verifier=authority; dso_signer="$CAND_DSO"; dso_verifier="$AUTH_DSO"
    else
        verifier=candidate; dso_signer="$AUTH_DSO"; dso_verifier="$CAND_DSO"
    fi
    sig="$WORK/raw/cross-$rep-$signer.sig"
    sign_out="$WORK/raw/cross-$rep-$signer-sign.out"
    verify_out="$WORK/raw/cross-$rep-$signer-$verifier-verify.out"

    CURRENT_LABEL="cross-$rep-$signer"
    LD_LIBRARY_PATH="$(dirname "$dso_signer")" "$BUILD/bench_api" \
        --lib "$dso_signer" --cross-sign "$sig" >"$sign_out"
    verify_loaded "$sign_out" "$signer" "$dso_signer"

    CURRENT_LABEL="cross-$rep-$signer"
    LD_LIBRARY_PATH="$(dirname "$dso_verifier")" "$BUILD/bench_api" \
        --lib "$dso_verifier" --cross-verify "$sig" >"$verify_out"
    verify_loaded "$verify_out" "$verifier" "$dso_verifier"

    ok="$(sed -n 's/^CROSS verify .* ok=\([01]\).*/\1/p' "$verify_out")"
    pub_sign="$(sed -n 's/^CROSS sign .* pub=\([0-9a-f]*\).*/\1/p' "$sign_out")"
    pub_verify="$(sed -n 's/^CROSS verify .* pub=\([0-9a-f]*\).*/\1/p' "$verify_out")"
    [ "$ok" = 1 ] || fail "cross-$rep: $signer signature rejected by $verifier"
    [ "$pub_sign" = "$pub_verify" ] || fail "cross-$rep: public keys differ"
    printf '%s\t%s\t%s\t%s\t%s\n' "$rep" "$signer" "$verifier" "$ok" "$pub_verify" \
        >>"$WORK/cross-verification.tsv"
}

# --- warm-up (excluded) ---------------------------------------------------

echo "=== warm-up pair (excluded) ==="
CURRENT_LABEL=warmup
run_one candidate "$CAND_DSO" "$WORK/raw/rep-warmup-candidate.out" timing
run_one authority "$AUTH_DSO" "$WORK/raw/rep-warmup-authority.out" timing
compare_checks warmup

# --- measured repetitions -------------------------------------------------

echo "=== measured repetitions ($REPS, balanced randomized order) ==="
printf 'repetition\tsigner\tverifier\tverified\tpublic_key\n' \
    >"$WORK/cross-verification.tsv"

while IFS=$'\t' read -r rep first second; do
    CURRENT_LABEL="rep-$rep"
    echo "--- repetition $rep: $first then $second"
    for subject in "$first" "$second"; do
        if [ "$subject" = candidate ]; then
            dso="$CAND_DSO"
        else
            dso="$AUTH_DSO"
        fi
        run_one "$subject" "$dso" "$WORK/raw/rep-$rep-$subject.out" timing
    done
    compare_checks "$rep"
    case " $CROSS_REPS " in
        *" $rep "*)
            cross_subject "$rep" candidate
            cross_subject "$rep" authority
            ;;
    esac
done <"$WORK/raw/run-order.tsv"

# --- allocation instrument, both subjects ---------------------------------

echo "=== allocation probe: both subjects ==="
CURRENT_LABEL=alloc
run_one candidate "$CAND_DSO" "$WORK/raw/alloc-candidate.out" alloc
run_one authority "$AUTH_DSO" "$WORK/raw/alloc-authority.out" alloc

# --- analysis -------------------------------------------------------------

echo "=== analyse ==="
python3 "$ROOT/courts/performance-frontier/baseline/analyse_bench_api.py" \
    --work "$WORK" --workloads "$WORKLOADS" --out "$WORK/results.json"

echo "PASS: PFP-0 campaign completed; results in $WORK/results.json"
