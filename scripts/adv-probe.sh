#!/usr/bin/env bash
# Run every allocator-injection adversarial probe, one probe per process.
#
# The probe tests install the process-global `CRYPTO_set_mem_functions` hook, which persists for
# the life of the process and is a one-way state change. They are therefore `#[ignore]`d in the
# routine suite -- a green `cargo test --lib` never means they ran -- and each must execute alone:
# one `cargo test` invocation, `--exact`, `--test-threads=1`.
#
# The probes are self-verifying: a missing gate, a refused hook installation, a missing intended
# refusal, or a dead negative-control canary makes the test panic. This script fails on any
# non-zero exit **and** on an invocation that did not actually execute exactly one test (a typo in
# a filter would otherwise look like a pass).
#
# Usage:
#   bash scripts/adv-probe.sh
#
# Environment:
#   CARGO_BUILD_JOBS   build parallelism (default 4, for host/CI OOM safety)
#
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export OPENSSL_RS_ADV_PROBE=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"

probes=(
  "ssl::statem::statem_clnt::adv_probe::tls12_process_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_clnt::adv_probe::tls13_process_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_clnt::adv_probe::canary_refusal_instrument_fires"
  "ssl::statem::statem_srvr::adv_probe::tls12_construct_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_srvr::adv_probe::canary_double_release_is_detected"
  "ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_refused_keeps_old_owner"
  "ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_reentrancy_reads_member"
  "ssl::ssl_lib::adv_realloc_probe::canary_realloc_refusal_instrument_fires"
  "ssl::ssl_lib::adv_realloc_probe::canary_reenter_observer_fires"
)

failures=0
for probe in "${probes[@]}"; do
  echo "=== adv-probe: ${probe}"
  log="$(mktemp)"
  # One process per probe: a separate cargo invocation with an exact filter.
  if cargo test --lib -- \
      --ignored --exact "${probe}" --test-threads=1 --nocapture 2>&1 | tee "${log}"; then
    if grep -qE 'test result: ok\. 1 passed' "${log}"; then
      echo "--- PASS: ${probe}"
    else
      echo "--- FAIL: ${probe} did not execute exactly one test" >&2
      failures=$((failures + 1))
    fi
  else
    echo "--- FAIL: ${probe} (non-zero exit)" >&2
    failures=$((failures + 1))
  fi
  rm -f "${log}"
done

if [ "${failures}" -ne 0 ]; then
  echo "adv-probe: ${failures} probe(s) failed" >&2
  exit 1
fi
echo "adv-probe: all ${#probes[@]} probes passed"
