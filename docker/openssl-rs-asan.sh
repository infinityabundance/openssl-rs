#!/usr/bin/env bash
# openssl-rs — AddressSanitizer venue lifecycle.
#
# A dedicated sanitizer execution environment. It exists because the forensic
# court's OOM protection sets a hard per-process RLIMIT_DATA
# (OPENSSL_RS_COURT_DATA, default 4 GiB), and AddressSanitizer reserves a
# terabyte-scale sparse virtual shadow before it runs anything. That cap is
# KEPT for the hostile courts — it is what keeps a runaway court off the host —
# so ASan gets its own venue rather than the court being weakened. See
# docs/DECISIONS.md D105, docs/UNSAFE.md §4 and artifacts/phase18/asan.json.
#
# The envelope bounds every *real* resource, exactly as the court does:
#
#   --memory=<4-8g>        hard memory cap for the container cgroup
#   --memory-reservation   soft limit, defaulting to the hard cap so the container
#                          reclaims its own pages before the host feels them
#                          (OPENSSL_RS_ASAN_MEMRES overrides)
#   --memory-swap=<same>   swap pinned equal to memory, so the container cannot
#                          grow by swapping: exceeding the cap is an in-container
#                          OOM kill rather than host memory pressure
#   --memory-swappiness=0  bias the kernel away from swapping sanitiser pages (the
#                          kernel discards it on cgroup v2, where docker runs)
#   --oom-score-adj=500    if the *host* runs out of memory, prefer to kill this
#                          disposable venue over the user's editor; 0 disables
#                          (OPENSSL_RS_ASAN_OOM_SCORE_ADJ)
#   --pids-limit=2048      fork-bomb containment
#   --cpus=<min(8, nproc)> bounded CPU, clamped to the machine's CPU count
#                          because docker refuses a `--cpus` above that
#   --restart=no           a killed run stays dead; it never silently restarts
#   a wall-clock timeout   applied to every `exec` (OPENSSL_RS_ASAN_TIMEOUT_S,
#                          default 7200), so no sanitizer run can hang forever
#   --security-opt no-new-privileges   kept, exactly as the court keeps it
#   network policy         the court's: the default docker bridge, no extra
#                          grants, no published ports, no host network
#
# The memory cap is clamped to the host's MemTotal (announced, never silent) and the
# three venues share one collective budget against the host's RAM:
# docker/openssl-rs-resource-guard.sh, sourced below, also backs `status`/`verify`
# with the container's cgroup OOM evidence (memory.current, memory.max,
# memory.events' oom/oom_kill) so a runtime kill is explainable after the fact.
#
# The ONE difference from the court is deliberate and named: no per-process
# RLIMIT_DATA. ASan's shadow is PROT_NONE, MAP_NORESERVE virtual address space
# that the cgroup does not count against memory.current, so its absence does not
# weaken the bound on *resident* memory — the cgroup memory cap still applies.
#
# The container is disposable: `down` removes it and its /asan scratch space.
# The repository is bind-mounted read-write at /work so the harness can write
# evidence.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_ASAN_IMAGE:-openssl-rs-asan:1}"
NAME="${OPENSSL_RS_ASAN_NAME:-openssl-rs-asan}"

# Shared host-side budget / OOM helpers (see the header).
# shellcheck source=docker/openssl-rs-resource-guard.sh
. "${PROJECT_DIR}/docker/openssl-rs-resource-guard.sh"

MEM="${OPENSSL_RS_ASAN_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_ASAN_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_ASAN_PIDS:-2048}"
TIMEOUT_S="${OPENSSL_RS_ASAN_TIMEOUT_S:-7200}"

is_positive_int() {
  case "${1}" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ "${1}" -gt 0 ]
}

# Docker rejects a `--cpus` above the machine's CPU count, so the requested
# value is clamped to what is actually available (same clamp as the court).
CPUS_REQUEST="${OPENSSL_RS_ASAN_CPUS:-8}"
if ! is_positive_int "${CPUS_REQUEST}"; then
  echo "openssl-rs-asan: OPENSSL_RS_ASAN_CPUS must be a positive integer (got '${CPUS_REQUEST}')" >&2
  exit 2
fi
CPUS="${CPUS_REQUEST}"
HOST_CPUS="$(nproc 2>/dev/null || echo '')"
if is_positive_int "${HOST_CPUS}" && [ "${CPUS}" -gt "${HOST_CPUS}" ]; then
  echo "openssl-rs-asan: note: --cpus=${CPUS} requested, but this machine has ${HOST_CPUS} CPUs; clamping to ${HOST_CPUS}" >&2
  CPUS="${HOST_CPUS}"
fi

if ! is_positive_int "${TIMEOUT_S}"; then
  echo "openssl-rs-asan: OPENSSL_RS_ASAN_TIMEOUT_S must be a positive integer (got '${TIMEOUT_S}')" >&2
  exit 2
fi

# Clamp the hard memory cap to the host (announced, same pattern as the CPU clamp)
# and default the soft limit to it. Both must parse as a docker memory size.
MEM="$(guard_clamp_mem_to_host openssl-rs-asan "${MEM}")"
MEMRES="${OPENSSL_RS_ASAN_MEMRES:-${MEM}}"
if ! guard_mem_to_bytes "${MEMRES}" >/dev/null 2>&1; then
  echo "openssl-rs-asan: OPENSSL_RS_ASAN_MEMRES must be a memory size like 8g (got '${MEMRES}')" >&2
  exit 2
fi

# OOM score adjustment for the container's processes; 0 disables the raise.
OOM_SCORE_ADJ="${OPENSSL_RS_ASAN_OOM_SCORE_ADJ:-500}"
case "${OOM_SCORE_ADJ}" in
  '' | *[!0-9-]*) echo "openssl-rs-asan: OPENSSL_RS_ASAN_OOM_SCORE_ADJ must be an integer in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2; exit 2 ;;
esac
if [ "${OOM_SCORE_ADJ}" -lt -1000 ] || [ "${OOM_SCORE_ADJ}" -gt 1000 ]; then
  echo "openssl-rs-asan: OPENSSL_RS_ASAN_OOM_SCORE_ADJ must be in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2
  exit 2
fi
OOM_SCORE_ADJ_OPT=""
if [ "${OOM_SCORE_ADJ}" -ne 0 ]; then
  OOM_SCORE_ADJ_OPT="--oom-score-adj=${OOM_SCORE_ADJ}"
fi

usage() {
  cat <<EOF
usage: openssl-rs-asan.sh <command>

  build         build the ASan venue image from docker/openssl-rs-asan.Dockerfile
  up            (re)create and start the venue container with resource caps
  down          stop and remove the venue container
  status        show container state and effective resource caps
  verify        assert the venue is up, capped, has no RLIMIT_DATA, and has
                no system openssl CLI
  exec CMD...   run CMD inside the venue, from /work, under the wall-clock bound
  shell         interactive shell inside the venue

env overrides:
  OPENSSL_RS_ASAN_IMAGE      default ${IMAGE}
  OPENSSL_RS_ASAN_NAME       default ${NAME}
  OPENSSL_RS_ASAN_MEM        default ${MEM}, clamped to the host's MemTotal
  OPENSSL_RS_ASAN_MEMRES     default ${MEMRES}, the soft limit
  OPENSSL_RS_ASAN_MEMSWAP    default ${MEMSWAP}
  OPENSSL_RS_ASAN_PIDS       default ${PIDS}
  OPENSSL_RS_ASAN_CPUS       default 8, clamped to the machine's CPU count
  OPENSSL_RS_ASAN_OOM_SCORE_ADJ  default ${OOM_SCORE_ADJ}; 0 disables the raise
  OPENSSL_RS_ASAN_TIMEOUT_S  default ${TIMEOUT_S}, the wall-clock bound per exec

shared with the other venues (docker/openssl-rs-resource-guard.sh):
  OPENSSL_RS_CONTAINER_BUDGET    collective cap, default the host's MemTotal
  OPENSSL_RS_CONTAINER_HEADROOM  MemAvailable warning headroom, default 2g
  OPENSSL_RS_CONTAINER_PREFIX    counted name prefix, default openssl-rs-

Every 'exec' runs under the container's cgroup memory cap, PID cap, CPU cap and
the wall-clock bound. It deliberately does NOT set RLIMIT_DATA: ASan needs a
large sparse virtual shadow, and the cgroup still bounds real physical memory.
EOF
}

do_build() {
  docker build -f "${PROJECT_DIR}/docker/openssl-rs-asan.Dockerfile" -t "${IMAGE}" "${PROJECT_DIR}/docker"
}

do_up() {
  if docker inspect "${NAME}" >/dev/null 2>&1; then
    echo "ASan venue container '${NAME}' already exists; run 'down' first" >&2
    exit 2
  fi
  # Collective budget: refuse before creating if this container plus the running
  # openssl-rs-* siblings would declare more than the host can be asked to hold.
  guard_check_container_budget openssl-rs-asan "${NAME}" "${MEM}"
  # Network policy: no --network / --publish / --net flags, so the container gets
  # the same default bridge the court gets and nothing more.
  docker run -d \
    --name "${NAME}" \
    --memory="${MEM}" \
    --memory-reservation="${MEMRES}" \
    --memory-swap="${MEMSWAP}" \
    --memory-swappiness=0 \
    ${OOM_SCORE_ADJ_OPT} \
    --pids-limit="${PIDS}" \
    --cpus="${CPUS}" \
    --restart=no \
    --security-opt no-new-privileges \
    -v "${PROJECT_DIR}:/work" \
    -w /work \
    "${IMAGE}" sleep infinity
}

do_down() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
}

do_status() {
  docker inspect "${NAME}" \
    --format 'name={{.Name}} image={{.Config.Image}} running={{.State.Running}} memory={{.HostConfig.Memory}} memory_reservation={{.HostConfig.MemoryReservation}} memory_swap={{.HostConfig.MemorySwap}} memory_swappiness={{.HostConfig.MemorySwappiness}} oom_score_adj={{.HostConfig.OomScoreAdj}} pids={{.HostConfig.PidsLimit}} nanocpus={{.HostConfig.NanoCpus}} privileged={{.HostConfig.Privileged}}'
  guard_report_oom "${NAME}"
}

do_exec() {
  # No `ulimit -d` here, on purpose: see the header. The wall-clock `timeout`
  # wraps the whole tree the command spawns.
  docker exec -i "${NAME}" timeout --signal=KILL "${TIMEOUT_S}" "$@"
}

do_verify() {
  do_status
  do_exec sh -c '
    echo "cgroup memory.current: $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo n/a)"
    echo "cgroup memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
    echo "cgroup pids.max:   $(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo n/a)"
    echo "cgroup memory.events:"; cat /sys/fs/cgroup/memory.events 2>/dev/null || echo "  n/a"
    echo "nproc:             $(nproc)"
    echo "RLIMIT_DATA:       $(ulimit -d)  (expected: unlimited)"
    echo "RLIMIT_AS:         $(ulimit -v)  (expected: unlimited)"
    echo "ASAN_SYMBOLIZER_PATH: ${ASAN_SYMBOLIZER_PATH:-unset}"
    if command -v openssl >/dev/null 2>&1; then
      echo "system openssl CLI: PRESENT (FAIL) at $(command -v openssl)"
      exit 1
    else
      echo "system openssl CLI: absent (ok)"
    fi
    echo "toolchain record:"; cat /asan/toolchain.txt 2>/dev/null || true
  '
}

case "${1:-}" in
  build)  do_build ;;
  up)     do_up ;;
  down)   do_down ;;
  status) do_status ;;
  verify) do_verify ;;
  exec)   shift; do_exec "$@" ;;
  shell)  do_exec sh ;;
  *)      usage; exit 1 ;;
esac
