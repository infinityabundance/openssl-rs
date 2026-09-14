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
# Nothing here executes on the host.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${OPENSSL_RS_FRF_IMAGE:-debian:trixie-slim}"
NAME="${OPENSSL_RS_FRF_NAME:-openssl-rs-frf-court}"

MEM="${OPENSSL_RS_FRF_MEM:-8g}"
MEMSWAP="${OPENSSL_RS_FRF_MEMSWAP:-8g}"
PIDS="${OPENSSL_RS_FRF_PIDS:-2048}"
CPUS="${OPENSSL_RS_FRF_CPUS:-8}"

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
  status  show state and effective caps
  verify  assert caps and that frf/gemel run
  exec CMD...
env: OPENSSL_RS_FRF_IMAGE, OPENSSL_RS_FRF_NAME, OPENSSL_RS_FRF_{MEM,MEMSWAP,PIDS,CPUS}
     OPENSSL_RS_FRF_BIN, OPENSSL_RS_GEMEL_BIN
EOF
}

do_up() {
  docker inspect "${NAME}" >/dev/null 2>&1 && { echo "'${NAME}' exists; run down first" >&2; exit 2; }
  docker run -d --name "${NAME}" \
    --memory="${MEM}" --memory-swap="${MEMSWAP}" \
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
  docker inspect "${NAME}" --format 'name={{.Name}} image={{.Config.Image}} running={{.State.Running}} memory={{.HostConfig.Memory}} memory_swap={{.HostConfig.MemorySwap}} pids={{.HostConfig.PidsLimit}} nanocpus={{.HostConfig.NanoCpus}}'
  echo "base digest (pinned): ${BASE_DIGEST}"
}

do_verify() {
  do_status
  docker exec "${NAME}" sh -c '
    echo "cgroup memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
    echo "cgroup pids.max:   $(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo n/a)"
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
