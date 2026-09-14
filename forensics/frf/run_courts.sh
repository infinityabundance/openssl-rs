#!/usr/bin/env bash
# openssl-rs — run the FRF trajectory courts and emit receipts.
#
# Runs inside the FRF tooling container (docker/openssl-rs-frf-court.sh), never
# on the host: the courts execute the authority binaries, and no authority
# binary is ever executed on the host.
#
#     bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
#
# This script performs the mechanical half of the FRF loop:
#
#   authority admit -> court run -> receipt emit
#
# The judgement half is deliberately NOT automated:
#
#   residual dispose -> claim compile
#
# A disposition is a judgement that requires a reason, and FRF refuses `open` as
# a settable disposition and refuses to compile a claim while any residual is
# open, unknown or harness. Automating it would produce dispositions nobody made.
# The exact commands used for the Phase 1 disposition and claim are recorded in
# forensics/frf/README.md.
#
# The store is recreated from clean because authority admission and run ids are
# content-addressed: re-running over an existing store would not be a fresh
# observation.
set -euo pipefail

# Nothing runs on the host (docs/REPRODUCIBILITY.md §1). Enforced, not assumed.
. "$(dirname "$0")/../tools/require_court.sh"

cd /work
ROOT="${FRF_ROOT:-.frf}"
COURTS="openssl-cli-version openssl-cli-dgst openssl-cli-inventory"

echo "=== [1/3] admit authorities ==="
rm -rf "$ROOT"
frf --root "$ROOT" authority admit forensics/frf/refs/openssl-3.6.3.sh --name openssl --version 3.6.3
frf --root "$ROOT" authority admit forensics/frf/refs/openssl-3.6.4.sh --name openssl --version 3.6.4
frf --root "$ROOT" authority admit forensics/frf/refs/authority-cli-inventory.sh --name openssl-cli --version 3.6.3
frf --root "$ROOT" authority admit forensics/frf/refs/authority-abi-report.sh --name openssl-abi --version 3.6.4

echo
echo "=== [2/3] run the 3.6.3 -> 3.6.4 trajectory courts ==="
RUNS=/tmp/openssl-rs-frf-runs.txt
: > "$RUNS"
for c in $COURTS; do
  echo "--- court $c ---"
  out=$(frf --root "$ROOT" court run "forensics/frf/courts/$c/manifest.yaml" 2>&1)
  printf '%s\n' "$out"
  # `frf court run` prints the bare run id as its final line.
  printf '%s\n' "$out" | tail -1 >> "$RUNS"
done

echo
echo "=== [3/3] emit receipts ==="
while IFS= read -r run; do
  [ -n "$run" ] || continue
  frf --root "$ROOT" receipt emit "$run" 2>&1 | tail -1
done < "$RUNS"

echo
echo "run ids recorded in $RUNS"
echo
echo "remaining (judgement) steps, see forensics/frf/README.md:"
echo "  frf --root $ROOT residual dispose <residual> --disposition oracle_version --reason '...'"
echo "  frf --root $ROOT claim compile <receipt>... "
