#!/usr/bin/env bash
# run_pmu_substitutes.sh — T17: prove what timing instrumentation this host has.
#
# This host exposes no hardware PMU: there is no /sys/bus/event_source/devices/cpu
# and `perf stat -e cycles` cannot be satisfied.  This runner records that
# conclusion together with the two substitutes that *do* work:
#
#   1. perf software events (task-clock, context-switches, page-faults,
#      minor-faults) on a real crate timing harness (bench_bn);
#   2. a serialised RDTSC harness (tsc_clock) calibrated against CLOCK_MONOTONIC,
#      with its resolution measured and its limits stated in the source/README.
#
# It must run inside the tools court image (perf + valgrind tooling), never on the
# host.  No hardware-counter claim is made anywhere below.
#
#   OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
#     bash docker/openssl-rs-court.sh exec bash courts/phase18/timing/run_pmu_substitutes.sh
#
# Optional first argument: output directory.  Default court/tmp/t1718/t17.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../../.." && pwd)"
OUT="${1:-${ROOT}/court/tmp/t1718/t17}"
PREFIX="${ROOT}/artifacts/phase2/install"
CC="${CC:-cc}"

mkdir -p "${OUT}"

section() { printf '\n===== %s =====\n' "$*"; }

section "host identity"
uname -a
if [ -r /proc/cpuinfo ]; then
    grep -m1 '^model name' /proc/cpuinfo || true
    grep -m1 '^vendor_id' /proc/cpuinfo || true
fi

section "/sys/bus/event_source/devices (the PMU event sources the kernel registered)"
ls -1 /sys/bus/event_source/devices 2>&1 || true
if [ -e /sys/bus/event_source/devices/cpu ]; then
    echo "cpu event source: PRESENT"
else
    echo "cpu event source: ABSENT"
fi

section "perf_event_paranoid"
cat /proc/sys/kernel/perf_event_paranoid 2>&1 || true

section "selected /proc/cpuinfo flags (presence/absence)"
if [ -r /proc/cpuinfo ]; then
    FLAGS="$(grep -m1 '^flags' /proc/cpuinfo || true)"
    for f in hypervisor arch_perfmon tsc rdtscp constant_tsc nonstop_tsc tsc_reliable tsc_known_freq; do
        if printf '%s\n' "${FLAGS}" | tr ' ' '\n' | grep -qx "$f"; then
            echo "$f: PRESENT"
        else
            echo "$f: ABSENT"
        fi
    done
    if grep -q ' hypervisor ' /proc/cpuinfo; then
        echo "guest (hypervisor flag): YES"
    else
        echo "guest (hypervisor flag): NO"
    fi
fi

section "CPUID probe"
"${CC}" -O2 -Wall -o "${OUT}/pmu_probe" "${HERE}/pmu_probe.c"
"${OUT}/pmu_probe" | tee "${OUT}/cpuid.txt"

section "PMU MSR probe (are the counters real, not just masked?)"
# CPUID can be masked while counters exist, so this programs a counter and
# checks whether the configuration is retained and the counter advances.
# The court has no /dev/cpu and no privilege, so this runs only when the caller
# has already provided one; otherwise the command to run outside is printed.
PMU_PROBE="${HERE}/pmu_msr_probe.c"
if [ -r /dev/cpu/0/msr ]; then
    "${CC}" -O2 -Wall -o "${OUT}/pmu_msr_probe" "${PMU_PROBE}"
    "${OUT}/pmu_msr_probe" 0 | tee "${OUT}/pmu-msr-probe.txt"
    echo "pmu_msr_probe_exit=${PIPESTATUS:-$?}"
else
    echo "/dev/cpu/0/msr is not readable in this venue; run outside the court:"
    echo "  cc -O2 -o pmu_msr_probe ${PMU_PROBE}"
    echo "  docker run --rm --privileged -v /dev/cpu:/dev/cpu \\"
    echo "    -v \$PWD/pmu_msr_probe:/pmu_msr_probe:ro debian:bookworm-slim /pmu_msr_probe 0"
fi

section "perf stat -e cycles (expected to fail: no PMU)"
set +e
perf stat -e cycles true >"${OUT}/perf-cycles.txt" 2>&1
rc=$?
set -e
cat "${OUT}/perf-cycles.txt"
echo "perf_cycles_exit=${rc}"
if grep -q '<not supported>' "${OUT}/perf-cycles.txt"; then
    echo "cycles_event: NOT SUPPORTED (no PMU exposed)"
fi

section "build the crate timing harnesses"
"${CC}" -O2 -g -I"${PREFIX}/include" "${HERE}/bench_bn.c" \
    -L "${PREFIX}/lib" -lcrypto -lm \
    -Wl,-rpath,"${PREFIX}/lib" -o "${OUT}/bench_bn"
"${CC}" -O2 -g -I"${PREFIX}/include" "${HERE}/tsc_clock.c" \
    -L "${PREFIX}/lib" -lcrypto \
    -Wl,-rpath,"${PREFIX}/lib" -o "${OUT}/tsc_clock"

section "perf software events on bench_bn (this is the path that works)"
# bench_bn runs 50x2048-bit, 20x3072-bit, 4x8192-bit and 50x RSA-2048 CRT
# exponentiations, so the event counts are large enough to be meaningful.
perf stat -e task-clock,context-switches,page-faults,minor-faults \
    "${OUT}/bench_bn" 2>&1 | tee "${OUT}/perf-software-events.txt"

section "hardware PMU events (runs only if the vCPU exposes a PMU)"
# CPUID.0AH is the deciding evidence: version 0 / 0 counters means the
# hypervisor exposes no architectural PMU, and no capability can recover it.
pmu_version=$(sed -n 's/.*version=\([0-9]*\).*/\1/p' "${OUT}/cpuid.txt" | head -1)
if [ "${pmu_version:-0}" -ge 1 ]; then
    perf stat -e cycles,instructions,branches,branch-misses,cache-misses \
        "${OUT}/bench_bn" 2>&1 | tee "${OUT}/perf-hardware-events.txt"
    echo "pmu: PRESENT (CPUID.0AH version ${pmu_version}) -- hardware counters recorded above"
else
    echo "pmu: ABSENT (CPUID.0AH version ${pmu_version:-0}) -- no architectural PMU"
    # The kernel's msr PMU still exposes hardware MSR counters even when the
    # architectural PMU is absent.  tsc is a real hardware counter; smi shows
    # whether system-management interrupts perturbed the measurement.  It must
    # be counted system-wide (-a) and pinned (-C) to the CPU running the work.
    if [ -d /sys/bus/event_source/devices/msr/events ]; then
        msr_cpu=${OPENSSL_RS_PMU_CPU:-1}
        echo "msr pmu: PRESENT -- counting msr/tsc/ and msr/smi/ on cpu ${msr_cpu}"
        perf stat -C "${msr_cpu}" -a -e msr/tsc/,msr/smi/ \
            taskset -c "${msr_cpu}" "${OUT}/bench_bn" \
            2>&1 | tee "${OUT}/perf-msr-tsc.txt"
        echo "msr pmu: hardware TSC counted; NOT retired core cycles, because"
        echo "  CPUID.0AH reports no architectural counters in this guest"
    else
        echo "msr pmu: ABSENT -- falling back to userspace rdtsc only"
    fi
fi

section "TSC measurement (serialised lfence;rdtsc / rdtscp;lfence)"
if command -v taskset >/dev/null 2>&1; then
    taskset -c 1 "${OUT}/tsc_clock" | tee "${OUT}/tsc.txt"
else
    "${OUT}/tsc_clock" | tee "${OUT}/tsc.txt"
fi

section "done"
echo "artefacts in ${OUT}"
