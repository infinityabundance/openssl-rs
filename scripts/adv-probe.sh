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
  "runtime::bio::ownership_adv_probe::refused_bio_block_alloc_returns_null"
  "runtime::bio::ownership_adv_probe::refused_mem_context_alloc_releases_the_partial_bio"
  "runtime::bio::ownership_adv_probe::refused_buf_mem_alloc_releases_the_partial_bio"
  "runtime::bio::ownership_adv_probe::mem_bio_create_and_free_releases_each_block_once"
  "ssl::statem::statem_clnt::adv_probe::tls12_process_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_clnt::adv_probe::tls13_process_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_clnt::adv_probe::canary_refusal_instrument_fires"
  "ssl::statem::statem_srvr::adv_probe::tls12_construct_refused_ticket_alloc_leaves_ext_tick_empty"
  "ssl::statem::statem_srvr::adv_probe::canary_double_release_is_detected"
  "ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_refused_keeps_old_owner"
  "ssl::ssl_rsa::adv_probe::self_aliasing_serverinfo_is_teed_before_realloc"
  "ssl::ssl_sess::adv_probe::self_aliasing_session_setters_copy_before_clearing"
  "ssl::s3_lib::adv_probe::self_aliasing_sni_control_copies_before_clearing"
  "asn1::utl::adv_probe::refused_encoding_malloc_leaves_a_null_member_and_safe_restore"
  "ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_reentrancy_reads_member"
  "ssl::ssl_lib::adv_realloc_probe::canary_realloc_refusal_instrument_fires"
  "ssl::ssl_lib::adv_realloc_probe::canary_reenter_observer_fires"
  "ssl::adv_alloc::adv_probe::cleansed_free_instrument_detects_residue"
  "cms::cms_env::tests::adv_probe_decrypted_key_release_cleanses_before_free"
  "dsa::object::adv_probe::dsa_new_refused_alloc_returns_null_without_free"
  "dsa::object::adv_probe::dsa_method_init_failure_runs_partial_cleanup"
  "dh::object::adv_probe::dh_new_refused_alloc_returns_null_without_free"
  "dh::object::adv_probe::dh_method_init_failure_runs_partial_cleanup"
  "ec::ecx_backend::adv_probe::ecx_key_dup_refused_alloc_returns_null_without_free"
  "ssl::d1_lib::adv_probe::dtls_state_refusal_and_lifecycle"
  "pkcs12::p12_key::adv_probe::unipass_drop_cleanses_before_release"
  "provider::kdf::tests::adv_probe::argon2_matrix_release_cleanses_the_whole_block"
  "provider::kdf::tests::adv_probe::sskdf_defaulted_kmac_cleanse_uses_the_allocation_length"
  "provider::kdf::tests::adv_probe::pbkdf1_derived_key_is_cleansed_before_release"
  "provider::activate::adv_probe::opbits_realloc_publishes_after_old_pair"
  "store::store_lib::adv_probe::refused_store_ctx_alloc_after_provider_open_preserves_the_cached_loader"
  "store::store_lib::adv_probe::refused_loader_params_refuses_the_attach_without_publishing_a_null_loader"
  "store::store_lib::adv_probe::canary_published_null_loader_store_faults_on_close_and_load"
  "store::store_lib::adv_probe::canary_double_release_is_detected"
  "runtime::bio::bss_conn::tests::retry_advance_invalidates_the_closed_descriptor"
  "ml_dsa::tests::keygen_without_retain_seed_releases_a_secure_seed_through_the_secure_heap"
  "provider::ml_dsa_kmgmt::adv_probe::refused_propq_allocation_cleanses_the_gen_entropy"
  "provider::ml_dsa_sig::adv_probe::refused_signature_copy_cleanses_the_dupctx_entropy"
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
