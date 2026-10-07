#!/usr/bin/env bash
# openssl-rs — court container lifecycle.
#
# Every test, court, fuzz campaign and authority build runs inside this
# container. Nothing is executed on the host.
#
# OOM protection is applied here, at run time:
#
#   --memory=8g                  hard memory cap for the container cgroup
#   --memory-reservation=<MEM>   soft limit. It defaults to the same 8g as the
#                                hard cap, so the container is as eager to reclaim
#                                its own pages as it is to be capped; it is
#                                overridable with OPENSSL_RS_COURT_MEMRES when a
#                                session genuinely needs a lower reclaim threshold.
#   --memory-swap=8g             swap allowance pinned equal to memory, so the
#                                container cannot grow by swapping: exceeding the
#                                cap triggers an in-container OOM kill rather than
#                                host memory pressure.
#   --memory-swappiness=0        bias the kernel away from swapping court pages. On
#                                a cgroup v2 host (what docker uses today) the kernel
#                                has no per-cgroup swappiness and discards the flag;
#                                it is passed anyway so the documented contract holds
#                                and because --memory-swap=mem already pins the swap.
#   --oom-score-adj=500          raise the container processes' OOM score, so if the
#                                *host* is ever the one out of memory the kernel
#                                prefers to kill this disposable container over the
#                                user's editor and rust-analyzer. 0 disables the raise.
#                                Trade-off: the court is disposable by design (`down`
#                                removes it and its /court scratch space); the
#                                interactive host work is not.
#   --pids-limit=2048            fork-bomb containment
#   --cpus=<min(8, nproc)>       bound CPU so a runaway court cannot starve the host.
#                                The cap is clamped to the machine's CPU count because
#                                docker refuses a `--cpus` greater than that ("range of
#                                CPUs is from 0.01 to N"), which is how a 4-CPU CI
#                                runner failed to start the court at all. A clamp is
#                                announced, never silent.
#   --restart=no                 a killed court stays dead; it never silently restarts
#
# The memory cap is clamped to the host's MemTotal the same announced way, and a
# collective budget keeps the three venues from declaring more between them than the
# host has. Both live in docker/openssl-rs-resource-guard.sh, sourced below; it also
# backs `status`/`verify` with the container's cgroup OOM evidence (memory.current,
# memory.max, memory.events' oom/oom_kill) so a future runtime kill is explainable
# rather than mysterious.
#
# The container is disposable: `down` removes it and its /court scratch space.
# The repository is bind-mounted read-write at /work so courts can write
# evidence. Authorities are content-addressed, so tampering is detectable.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_COURT_IMAGE:-openssl-rs-court:1}"
NAME="${OPENSSL_RS_COURT_NAME:-openssl-rs-court}"

# Shared host-side budget / OOM helpers. Sourced so the three venues all see the
# same running openssl-rs-* set and the budget cannot drift between them.
# shellcheck source=docker/openssl-rs-resource-guard.sh
. "${PROJECT_DIR}/docker/openssl-rs-resource-guard.sh"

MEM="${OPENSSL_RS_COURT_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_COURT_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_COURT_PIDS:-2048}"
# Per-process allocation cap applied to every `exec`, on top of the container's
# cgroup memory cap. The cgroup limit is a *ceiling for the container*, so a
# runaway court can still drive the whole container to it and leave the machine
# thrashing; RLIMIT_DATA bounds each individual process, which is the granularity
# a runaway probe or an accidental unbounded allocation actually has. The value is
# deliberately generous (a release build of this crate peaks well under 1 GiB) so
# that the linker's file-backed mappings, which do not count, and a multi-threaded
# test harness, which does, both have room. It is in kibibytes because the POSIX
# shell's `ulimit` takes a plain number and no suffix, and a silently rejected
# suffix would leave the cap unset — which is why `do_exec` fails loudly rather
# than continuing without it.
DATA="${OPENSSL_RS_COURT_DATA:-4194304}"

is_positive_int() {
  case "${1}" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ "${1}" -gt 0 ]
}

# The cap exists to stop a runaway court starving the host. Docker rejects a
# `--cpus` above the machine's CPU count, so the requested value is clamped to
# what is actually available. See the header note.
CPUS_REQUEST="${OPENSSL_RS_COURT_CPUS:-8}"
if ! is_positive_int "${CPUS_REQUEST}"; then
  echo "openssl-rs-court: OPENSSL_RS_COURT_CPUS must be a positive integer (got '${CPUS_REQUEST}')" >&2
  exit 2
fi
CPUS="${CPUS_REQUEST}"
HOST_CPUS="$(nproc 2>/dev/null || echo '')"
if is_positive_int "${HOST_CPUS}" && [ "${CPUS}" -gt "${HOST_CPUS}" ]; then
  echo "openssl-rs-court: note: --cpus=${CPUS} requested, but this machine has ${HOST_CPUS} CPUs; clamping to ${HOST_CPUS}" >&2
  CPUS="${HOST_CPUS}"
fi

# The hard memory cap is clamped to the host's RAM (same announced pattern as the
# CPU clamp), and the soft limit defaults to the clamped hard cap so the container
# reclaims its own pages before the host ever feels it. Both must parse as a docker
# memory size; a value that will not is fatal rather than silently dropped.
MEM="$(guard_clamp_mem_to_host openssl-rs-court "${MEM}")"
MEMRES="${OPENSSL_RS_COURT_MEMRES:-${MEM}}"
if ! guard_mem_to_bytes "${MEMRES}" >/dev/null 2>&1; then
  echo "openssl-rs-court: OPENSSL_RS_COURT_MEMRES must be a memory size like 8g (got '${MEMRES}')" >&2
  exit 2
fi

# OOM score adjustment for the container's processes. 500 sits well above the
# user's editor and rust-analyzer (usually 0) but inside the kernel's -1000..1000
# range, so a host-wide OOM prefers this disposable container. 0 disables the raise
# entirely, in which case the flag is omitted and docker's default applies.
OOM_SCORE_ADJ="${OPENSSL_RS_COURT_OOM_SCORE_ADJ:-500}"
case "${OOM_SCORE_ADJ}" in
  '' | *[!0-9-]*) echo "openssl-rs-court: OPENSSL_RS_COURT_OOM_SCORE_ADJ must be an integer in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2; exit 2 ;;
esac
if [ "${OOM_SCORE_ADJ}" -lt -1000 ] || [ "${OOM_SCORE_ADJ}" -gt 1000 ]; then
  echo "openssl-rs-court: OPENSSL_RS_COURT_OOM_SCORE_ADJ must be in -1000..1000 (got '${OOM_SCORE_ADJ}')" >&2
  exit 2
fi
OOM_SCORE_ADJ_OPT=""
if [ "${OOM_SCORE_ADJ}" -ne 0 ]; then
  OOM_SCORE_ADJ_OPT="--oom-score-adj=${OOM_SCORE_ADJ}"
fi

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
  OPENSSL_RS_COURT_IMAGE           default ${IMAGE}
  OPENSSL_RS_COURT_NAME            default ${NAME}
  OPENSSL_RS_COURT_MEM             default ${MEM}, clamped to the host's MemTotal
  OPENSSL_RS_COURT_MEMRES          default ${MEMRES}, the soft limit
  OPENSSL_RS_COURT_MEMSWAP         default ${MEMSWAP}
  OPENSSL_RS_COURT_PIDS            default ${PIDS}
  OPENSSL_RS_COURT_CPUS            default 8, clamped to the machine's CPU count
  OPENSSL_RS_COURT_OOM_SCORE_ADJ   default ${OOM_SCORE_ADJ}; 0 disables the raise
  OPENSSL_RS_COURT_DATA            default ${DATA} KiB, the per-process RLIMIT_DATA for exec

shared with the other venues (docker/openssl-rs-resource-guard.sh):
  OPENSSL_RS_CONTAINER_BUDGET      collective cap for all openssl-rs-* containers,
                                   default the host's MemTotal; `up` refuses when the
                                   running set plus the request would exceed it
  OPENSSL_RS_CONTAINER_HEADROOM    headroom for the MemAvailable warning, default 2g
  OPENSSL_RS_CONTAINER_PREFIX      counted container-name prefix, default openssl-rs-

Every 'exec' runs under both caps: the container's cgroup memory limit and a
per-process RLIMIT_DATA. Neither is optional, and neither depends on the caller
remembering to ask for it.
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
  # Collective budget: refuse before creating anything if this container plus the
  # already-running openssl-rs-* siblings would declare more than the host can be
  # asked to hold. See docker/openssl-rs-resource-guard.sh.
  guard_check_container_budget openssl-rs-court "${NAME}" "${MEM}"
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
  # `exec` is not needed here: the shell is the process under the limit and it
  # waits for the command, so the limit covers the whole tree it spawns.
  #
  # Before running anything, drop build artifacts the *host* wrote into the
  # bind-mounted `target/`. The editor's rust-analyzer runs `cargo check` on the
  # host, linked against the host's glibc, while this image is pinned to an
  # older one; a dev-profile build in the court can then reuse a host-built
  # build script and die with "GLIBC_2.3x not found", which is a toolchain
  # collision that looks exactly like a defect in the crate. Only host-owned
  # debris is removed, only from the dev profile, and only when this shell is
  # root (as the court is): the release artifacts the distribution shell is
  # built from are always the court's own and are never touched. Isolating the
  # court's target directory instead was rejected because it changes the
  # archive path recorded in `forensics/atlas/implemented-surface.json`, and
  # evidence is not reshaped to suit the tooling. See docs/DECISIONS.md D62.
  #
  # The three `-e` flags record the admitted venue for the Phase-24 Docker-only
  # execution guard (forensics/tools/phase24_guard.py): the guard admits only a
  # container whose marker (/.dockerenv) is present *and* whose environment records
  # PHASE24_CONTAINER=1 with the admitted image and platform the committed manifest
  # (forensics/downstream/container.json) names. `docker exec -e` sets them for the
  # exec'd process and everything it spawns, so a host invocation -- which has no
  # marker -- is refused rather than proceeding. See docs/DECISIONS.md D550.
  docker exec -i \
    -e PHASE24_CONTAINER=1 \
    -e PHASE24_IMAGE="${IMAGE}" \
    -e PHASE24_PLATFORM=linux \
    "${NAME}" sh -c 'ulimit -d "$1" 2>/dev/null || { echo "openssl-rs-court: cannot set RLIMIT_DATA to $1" >&2; exit 3; }; shift;
    if [ "$(id -u)" = 0 ] && { [ -d /work/target/flycheck0 ] \
       || { [ -d /work/target/debug ] \
            && find /work/target/debug -mindepth 1 ! -user 0 -print -quit 2>/dev/null | grep -q .; }; }; then
      rm -rf /work/target/debug /work/target/flycheck0
    fi
    exec "$@"' sh "${DATA}" "$@"
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
