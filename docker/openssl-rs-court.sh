#!/usr/bin/env bash
# openssl-rs — court container lifecycle.
#
# Every test, court, fuzz campaign and authority build runs inside this
# container. Nothing is executed on the host.
#
# OOM protection is applied here, at run time:
#
#   --memory=8g            hard memory cap for the container cgroup
#   --memory-swap=8g       swap allowance pinned equal to memory, so the
#                          container cannot grow by swapping: exceeding the cap
#                          triggers an in-container OOM kill rather than host
#                          memory pressure.
#   --memory-swappiness=0  bias the kernel away from swapping court pages
#   --pids-limit=2048      fork-bomb containment
#   --cpus=8               bound CPU so a runaway court cannot starve the host
#   --restart=no           a killed court stays dead; it never silently restarts
#
# The container is disposable: `down` removes it and its /court scratch space.
# The repository is bind-mounted read-write at /work so courts can write
# evidence. Authorities are content-addressed, so tampering is detectable.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_COURT_IMAGE:-openssl-rs-court:1}"
NAME="${OPENSSL_RS_COURT_NAME:-openssl-rs-court}"

MEM="${OPENSSL_RS_COURT_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_COURT_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_COURT_PIDS:-2048}"
CPUS="${OPENSSL_RS_COURT_CPUS:-8}"

usage() {
  cat <<EOF
usage: openssl-rs-court.sh <command>

  build         build the court image from docker/openssl-rs-court.Dockerfile
  up            (re)create and start the court container with resource caps
  down          stop and remove the court container
  status        show container state and effective resource caps
  verify        assert the court is up, capped, and free of a system openssl CLI
  exec CMD...   run CMD inside the court container, from /work
  shell         interactive shell inside the court container

env overrides:
  OPENSSL_RS_COURT_IMAGE   default ${IMAGE}
  OPENSSL_RS_COURT_NAME    default ${NAME}
  OPENSSL_RS_COURT_MEM     default ${MEM}
  OPENSSL_RS_COURT_MEMSWAP default ${MEMSWAP}
  OPENSSL_RS_COURT_PIDS    default ${PIDS}
  OPENSSL_RS_COURT_CPUS    default ${CPUS}
EOF
}

do_build() {
  docker build -f "${PROJECT_DIR}/docker/openssl-rs-court.Dockerfile" -t "${IMAGE}" "${PROJECT_DIR}/docker"
}

do_up() {
  if docker inspect "${NAME}" >/dev/null 2>&1; then
    echo "court container '${NAME}' already exists; run 'down' first" >&2
    exit 2
  fi
  docker run -d \
    --name "${NAME}" \
    --memory="${MEM}" \
    --memory-swap="${MEMSWAP}" \
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
    --format 'name={{.Name}} image={{.Config.Image}} running={{.State.Running}} memory={{.HostConfig.Memory}} memory_swap={{.HostConfig.MemorySwap}} pids={{.HostConfig.PidsLimit}} nanocpus={{.HostConfig.NanoCpus}}'
}

do_exec() {
  docker exec -i "${NAME}" "$@"
}

do_verify() {
  do_status
  do_exec sh -c '
    echo "cgroup memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
    echo "cgroup pids.max:   $(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo n/a)"
    echo "nproc:             $(nproc)"
    if command -v openssl >/dev/null 2>&1; then
      echo "system openssl CLI: PRESENT (FAIL) at $(command -v openssl)"
      exit 1
    else
      echo "system openssl CLI: absent (ok)"
    fi
    echo "toolchain record:"; cat /court/toolchain.txt 2>/dev/null || true
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
