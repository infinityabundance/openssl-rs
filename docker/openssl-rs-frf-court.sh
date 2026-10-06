#!/usr/bin/env bash
# openssl-rs — FRF/Gemel tooling container lifecycle.
#
# WHY THIS EXISTS AS A SECOND CONTAINER
# -------------------------------------
# The forensic court (`openssl-rs-court`, Debian bookworm, glibc 2.36) is the
# venue for authority builds, the atlas and the implementation crate. Its base
# image is pinned by digest and its toolchain is recorded in receipts, so it must
# not change.
#
# The FRF and Gemel binaries were built on the host against glibc 2.39 and
# therefore cannot run on bookworm. Rather than change the court's base (which
# would invalidate recorded evidence) or execute authority binaries on the host
# (forbidden), FRF/Gemel run here: a minimal Debian trixie container with the
# same hard OOM/CPU/PID caps. The authority binaries are built for bookworm and
# run forward-compatibly on trixie.
#
# The resource envelope is the court's, applied here for the same reason:
#
#   --memory=8g / --memory-reservation=8g   hard cap plus an equal soft limit, so
#                                the container reclaims its own pages before the
#                                host feels them (override the soft limit with
#                                OPENSSL_RS_FRF_MEMRES)
#   --memory-swap=8g             swap pinned equal to memory: exceeding the cap is
#                                an in-container OOM kill, not host pressure
#   --memory-swappiness=0        bias the kernel away from swapping tool pages (the
#                                kernel discards it on cgroup v2, where docker runs)
#   --oom-score-adj=500          if the *host* runs out of memory, prefer to kill
#                                this disposable container over the user's editor;
#                                0 disables (OPENSSL_RS_FRF_OOM_SCORE_ADJ)
#   --pids-limit=2048            fork-bomb containment
#   --cpus=8, clamped to nproc   bounded CPU: docker refuses a `--cpus` above the
#                                machine's count, and a clamp is announced, never
#                                silent
#   --restart=no                 a killed container stays dead
#
# The memory cap is clamped to the host's MemTotal, and the three venues share one
# collective budget against the host's RAM: see docker/openssl-rs-resource-guard.sh,
# sourced below. It also backs `status`/`verify` with the container's cgroup OOM
# evidence (memory.current, memory.max, memory.events' oom/oom_kill).
#
# Nothing here executes on the host.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_FRF_IMAGE:-debian:trixie-slim}"
NAME="${OPENSSL_RS_FRF_NAME:-openssl-rs-frf-court}"

# Shared host-side budget / OOM helpers (see the header).
# shellcheck source=docker/openssl-rs-resource-guard.sh
. "${PROJECT_DIR}/docker/openssl-rs-resource-guard.sh"

MEM="${OPENSSL_RS_FRF_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_FRF_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_FRF_PIDS:-2048}"
CPUS="${OPENSSL_RS_FRF_CPUS:-8}"

# Clamp the hard memory cap to the host (announced, like the CPU clamp the other
# venues apply) and default the soft limit to it. Both must parse as a docker
# memory size, or this fails loudly rather than dropping a cap.
MEM="$(guard_clamp_mem_to_host openssl-rs-frf-court "${MEM}")"
MEMRES="${OPENSSL_RS_FRF_MEMRES:-${MEM}}"
if ! guard_mem_to_bytes "${MEMRES}" >/dev/null 2>&1; then
  echo "openssl-rs-frf-court: OPENSSL_RS_FRF_MEMRES must be a memory size like 8g (got '${MEMRES}')" >&2
  exit 2
fi

# OOM score adjustment for the container's processes; 0 disables the raise.
OOM_SCORE_ADJ="${OPENSSL_RS_FRF_OOM_SCORE_ADJ:-500}"
case "${OOM_SCORE_ADJ}" in
  '' | *[!0-9-]*) echo "openssl-rs-frf-court: OPENSSL_RS_FRF_OOM_SCORE_ADJ must be an integer in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2; exit 2 ;;
esac
if [ "${OOM_SCORE_ADJ}" -lt -1000 ] || [ "${OOM_SCORE_ADJ}" -gt 1000 ]; then
  echo "openssl-rs-frf-court: OPENSSL_RS_FRF_OOM_SCORE_ADJ must be in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2
  exit 2
fi
OOM_SCORE_ADJ_OPT=""
if [ "${OOM_SCORE_ADJ}" -ne 0 ]; then
  OOM_SCORE_ADJ_OPT="--oom-score-adj=${OOM_SCORE_ADJ}"
fi

# Pinned base digest (recorded in receipts that cite the FRF venue).
BASE_DIGEST="debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"

# Host-built tool binaries, copied in read-only at start (never on the host's
# behalf; they run inside the container).
FRF_BIN="${OPENSSL_RS_FRF_BIN:-/mnt/1tb_kingston/frf/target/release/frf}"
GEMEL_BIN="${OPENSSL_RS_GEMEL_BIN:-/mnt/1tb_kingston/gemel/target/debug/gemel}"

usage() {
  cat <<EOF
usage: openssl-rs-frf-court.sh <command>
  up      create and start the tooling container with resource caps
  down    stop and remove it
  status  show state and effective caps, plus the cgroup OOM evidence
  verify  assert caps and that frf/gemel run
  exec CMD...
env: OPENSSL_RS_FRF_IMAGE, OPENSSL_RS_FRF_NAME,
     OPENSSL_RS_FRF_{MEM,MEMRES,MEMSWAP,PIDS,CPUS,OOM_SCORE_ADJ},
     OPENSSL_RS_FRF_BIN, OPENSSL_RS_GEMEL_BIN
shared: OPENSSL_RS_CONTAINER_BUDGET (default host MemTotal),
        OPENSSL_RS_CONTAINER_HEADROOM (default 2g),
        OPENSSL_RS_CONTAINER_PREFIX (default openssl-rs-)
EOF
}

do_up() {
  docker inspect "${NAME}" >/dev/null 2>&1 && { echo "'${NAME}' exists; run down first" >&2; exit 2; }
  # Collective budget: refuse before creating if this container plus the running
  # openssl-rs-* siblings would declare more than the host can be asked to hold.
  guard_check_container_budget openssl-rs-frf-court "${NAME}" "${MEM}"
  docker run -d --name "${NAME}" \
    --memory="${MEM}" --memory-reservation="${MEMRES}" \
    --memory-swap="${MEMSWAP}" --memory-swappiness=0 \
    ${OOM_SCORE_ADJ_OPT} \
    --pids-limit="${PIDS}" --cpus="${CPUS}" --restart=no \
    --security-opt no-new-privileges \
    -v "${PROJECT_DIR}:/work" -w /work \
    "${IMAGE}" sleep infinity
  docker cp "${FRF_BIN}" "${NAME}:/usr/local/bin/frf"
  docker cp "${GEMEL_BIN}" "${NAME}:/usr/local/bin/gemel"
  docker exec "${NAME}" chmod +x /usr/local/bin/frf /usr/local/bin/gemel
}

do_down() { docker rm -f "${NAME}" >/dev/null 2>&1 || true; }

do_status() {
  docker inspect "${NAME}" --format 'name={{.Name}} image={{.Config.Image}} running={{.State.Running}} memory={{.HostConfig.Memory}} memory_reservation={{.HostConfig.MemoryReservation}} memory_swap={{.HostConfig.MemorySwap}} memory_swappiness={{.HostConfig.MemorySwappiness}} oom_score_adj={{.HostConfig.OomScoreAdj}} pids={{.HostConfig.PidsLimit}} nanocpus={{.HostConfig.NanoCpus}}'
  echo "base digest (pinned): ${BASE_DIGEST}"
  guard_report_oom "${NAME}"
}

do_verify() {
  do_status
  docker exec "${NAME}" sh -c '
    echo "cgroup memory.current: $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo n/a)"
    echo "cgroup memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
    echo "cgroup pids.max:   $(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo n/a)"
    echo "cgroup memory.events:"; cat /sys/fs/cgroup/memory.events 2>/dev/null || echo "  n/a"
    echo "glibc: $(ldd --version | head -1)"
    echo "frf:   $(frf --version 2>&1)"
    echo "gemel: $(gemel --version 2>&1)"
  '
}

case "${1:-}" in
  up)     do_up ;;
  down)   do_down ;;
  status) do_status ;;
  verify) do_verify ;;
  exec)   shift; docker exec -i "${NAME}" "$@" ;;
  *)      usage; exit 1 ;;
esac
