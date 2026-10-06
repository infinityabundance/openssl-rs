#!/usr/bin/env bash
# openssl-rs — historical-authority build venue lifecycle.
#
# WHY THIS EXISTS AS A THIRD VENUE
# --------------------------------
# The forensic court (`openssl-rs-court`, Debian bookworm, GCC 12, Perl 5.36) is the venue
# for the candidate, the atlas and the admitted production/historical authorities. Its base
# image is pinned by digest and its toolchain is recorded in receipts, so it must not change.
#
# Building an old OpenSSL release needs an era-appropriate toolchain, and some releases a
# modern compiler rejects outright. Rather than change the court's base (which would
# invalidate recorded evidence) or build on the host (forbidden), historical acquisition and
# building run here: a separately pinned Debian bullseye image with GCC 10 / Perl 5.32 and
# QEMU user-mode emulation. See docker/openssl-rs-historical.Dockerfile.
#
# The resource envelope is the court's, applied here for the same reason and over the same
# shared budget guard:
#
#   --memory=8g / --memory-reservation=8g   hard cap plus an equal soft limit, so the venue
#                                reclaims its own pages before the host feels them (override
#                                the soft limit with OPENSSL_RS_HISTORICAL_MEMRES)
#   --memory-swap=8g             swap pinned equal to memory: exceeding the cap is an
#                                in-container OOM kill, not host pressure
#   --memory-swappiness=0        bias the kernel away from swapping build pages (the kernel
#                                discards it on cgroup v2, where docker runs)
#   --oom-score-adj=500          if the *host* runs out of memory, prefer to kill this
#                                disposable venue over the user's editor; 0 disables
#                                (OPENSSL_RS_HISTORICAL_OOM_SCORE_ADJ)
#   --pids-limit=2048            fork-bomb containment
#   --cpus=8, clamped to nproc   bounded CPU: docker refuses a `--cpus` above the machine's
#                                count, and a clamp is announced, never silent
#   --restart=no                 a killed build stays dead
#   a per-process RLIMIT_DATA    applied to every `exec`, as the court does
#
# The memory cap is clamped to the host's MemTotal, and every openssl-rs-* venue shares one
# collective budget against the host's RAM: docker/openssl-rs-resource-guard.sh, sourced
# below, also backs `status`/`verify` with the container's cgroup OOM evidence.
#
# Nothing here executes on the host.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_HISTORICAL_IMAGE:-openssl-rs-historical:1}"
NAME="${OPENSSL_RS_HISTORICAL_NAME:-openssl-rs-historical}"

# Shared host-side budget / OOM helpers (see the header).
# shellcheck source=docker/openssl-rs-resource-guard.sh
. "${PROJECT_DIR}/docker/openssl-rs-resource-guard.sh"

MEM="${OPENSSL_RS_HISTORICAL_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_HISTORICAL_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_HISTORICAL_PIDS:-2048}"
DATA="${OPENSSL_RS_HISTORICAL_DATA:-4194304}"

is_positive_int() {
  case "${1}" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ "${1}" -gt 0 ]
}

# Docker rejects a `--cpus` above the machine's CPU count, so the requested value is
# clamped to what is actually available (same announced clamp as the other venues).
CPUS_REQUEST="${OPENSSL_RS_HISTORICAL_CPUS:-8}"
if ! is_positive_int "${CPUS_REQUEST}"; then
  echo "openssl-rs-historical: OPENSSL_RS_HISTORICAL_CPUS must be a positive integer (got '${CPUS_REQUEST}')" >&2
  exit 2
fi
CPUS="${CPUS_REQUEST}"
HOST_CPUS="$(nproc 2>/dev/null || echo '')"
if is_positive_int "${HOST_CPUS}" && [ "${CPUS}" -gt "${HOST_CPUS}" ]; then
  echo "openssl-rs-historical: note: --cpus=${CPUS} requested, but this machine has ${HOST_CPUS} CPUs; clamping to ${HOST_CPUS}" >&2
  CPUS="${HOST_CPUS}"
fi

# Clamp the hard memory cap to the host (announced) and default the soft limit to it.
MEM="$(guard_clamp_mem_to_host openssl-rs-historical "${MEM}")"
MEMRES="${OPENSSL_RS_HISTORICAL_MEMRES:-${MEM}}"
if ! guard_mem_to_bytes "${MEMRES}" >/dev/null 2>&1; then
  echo "openssl-rs-historical: OPENSSL_RS_HISTORICAL_MEMRES must be a memory size like 8g (got '${MEMRES}')" >&2
  exit 2
fi

# OOM score adjustment for the container's processes; 0 disables the raise.
OOM_SCORE_ADJ="${OPENSSL_RS_HISTORICAL_OOM_SCORE_ADJ:-500}"
case "${OOM_SCORE_ADJ}" in
  '' | *[!0-9-]*) echo "openssl-rs-historical: OPENSSL_RS_HISTORICAL_OOM_SCORE_ADJ must be an integer in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2; exit 2 ;;
esac
if [ "${OOM_SCORE_ADJ}" -lt -1000 ] || [ "${OOM_SCORE_ADJ}" -gt 1000 ]; then
  echo "openssl-rs-historical: OPENSSL_RS_HISTORICAL_OOM_SCORE_ADJ must be in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2
  exit 2
fi
OOM_SCORE_ADJ_OPT=""
if [ "${OOM_SCORE_ADJ}" -ne 0 ]; then
  OOM_SCORE_ADJ_OPT="--oom-score-adj=${OOM_SCORE_ADJ}"
fi

usage() {
  cat <<EOF
usage: openssl-rs-historical.sh <command>

  build         build the historical venue image from docker/openssl-rs-historical.Dockerfile
  up            (re)create and start the venue with resource caps
  down          stop and remove the venue container
  status        show container state and effective resource caps
  verify        assert the venue is up, capped, and free of a system openssl CLI
  exec CMD...   run CMD inside the venue, from /work, under RLIMIT_DATA
  shell         interactive shell inside the venue

env overrides:
  OPENSSL_RS_HISTORICAL_IMAGE       default ${IMAGE}
  OPENSSL_RS_HISTORICAL_NAME        default ${NAME}
  OPENSSL_RS_HISTORICAL_MEM         default ${MEM}, clamped to the host's MemTotal
  OPENSSL_RS_HISTORICAL_MEMRES      default ${MEMRES}, the soft limit
  OPENSSL_RS_HISTORICAL_MEMSWAP     default ${MEMSWAP}
  OPENSSL_RS_HISTORICAL_PIDS        default ${PIDS}
  OPENSSL_RS_HISTORICAL_CPUS        default 8, clamped to the machine's CPU count
  OPENSSL_RS_HISTORICAL_OOM_SCORE_ADJ  default ${OOM_SCORE_ADJ}; 0 disables the raise
  OPENSSL_RS_HISTORICAL_DATA        default ${DATA} KiB, the per-process RLIMIT_DATA for exec

shared with the other venues (docker/openssl-rs-resource-guard.sh):
  OPENSSL_RS_CONTAINER_BUDGET       collective cap, default the host's MemTotal
  OPENSSL_RS_CONTAINER_HEADROOM     MemAvailable warning headroom, default 2g
  OPENSSL_RS_CONTAINER_PREFIX       counted name prefix, default openssl-rs-
EOF
}

do_build() {
  docker build -f "${PROJECT_DIR}/docker/openssl-rs-historical.Dockerfile" -t "${IMAGE}" "${PROJECT_DIR}/docker"
}

do_up() {
  if docker inspect "${NAME}" >/dev/null 2>&1; then
    echo "historical venue container '${NAME}' already exists; run 'down' first" >&2
    exit 2
  fi
  # Collective budget: refuse before creating if this container plus the running
  # openssl-rs-* siblings would declare more than the host can be asked to hold.
  guard_check_container_budget openssl-rs-historical "${NAME}" "${MEM}"
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
    --format 'name={{.Name}} image={{.Config.Image}} running={{.State.Running}} memory={{.HostConfig.Memory}} memory_reservation={{.HostConfig.MemoryReservation}} memory_swap={{.HostConfig.MemorySwap}} memory_swappiness={{.HostConfig.MemorySwappiness}} oom_score_adj={{.HostConfig.OomScoreAdj}} pids={{.HostConfig.PidsLimit}} nanocpus={{.HostConfig.NanoCpus}}'
  guard_report_oom "${NAME}"
}

do_exec() {
  # `exec` is not needed: the shell is the process under the limit and it waits for the
  # command, so the limit covers the whole tree it spawns.
  docker exec -i "${NAME}" sh -c 'ulimit -d "$1" 2>/dev/null || { echo "openssl-rs-historical: cannot set RLIMIT_DATA to $1" >&2; exit 3; }; shift; exec "$@"' sh "${DATA}" "$@"
}

do_verify() {
  do_status
  do_exec sh -c '
    echo "cgroup memory.current: $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo n/a)"
    echo "cgroup memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
    echo "cgroup pids.max:   $(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo n/a)"
    echo "cgroup memory.events:"; cat /sys/fs/cgroup/memory.events 2>/dev/null || echo "  n/a"
    echo "nproc:             $(nproc)"
    echo "RLIMIT_DATA:       $(ulimit -d)"
    if command -v openssl >/dev/null 2>&1; then
      echo "system openssl CLI: PRESENT (FAIL) at $(command -v openssl)"
      exit 1
    else
      echo "system openssl CLI: absent (ok)"
    fi
    echo "toolchain record:"; cat /historical/toolchain.txt 2>/dev/null || true
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
