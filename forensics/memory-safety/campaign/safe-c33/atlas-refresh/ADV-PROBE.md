# ADV-PROBE — allocator-injection adversarial probes

Status: **green** (routine + probed gates) on the candidate below.

## Committed candidate + independent CI evidence

The original record below (branch `stage/p25/adv-harden`, working tree) is the
**development-time** evidence and is preserved unrewritten. The stronger,
independent evidence is the **committed** candidate and its CI run:

- Integration HEAD: `5f320e2f6` on `integrate/safe-c33` (the adversarial-probe
  work merged via `517f52df5`; the routine suite reports **1196 passed, 9
  ignored** and `scripts/adv-probe.sh` reports **9/9 passed** at this HEAD).
- The dedicated `adversarial` CI job completed successfully at this tip; the
  `lints (clippy)` job also passed. This is the source identity to cite for the
  probe evidence going forward; re-run `bash scripts/adv-probe.sh` and record a
  new block here whenever a callback/allocator edge changes.

This record is deliberately **separate from the routine `cargo test --lib` count**. The probes
install the process-global `CRYPTO_set_mem_functions` hook and are `#[ignore]`d, so the routine
suite reports them as `ignored`; a green routine run never implies they executed. Only the probed
runs below establish that the adversarial regressions ran.

## Candidate identity

- Branch: `stage/p25/adv-harden` (parent `integrate/safe-c33`)
- HEAD: `112ecd5f63a90acb6b05426b4bc0e235e4ff2626`
- Working tree: **uncommitted** (this task forbids commits). The candidate is HEAD plus:

```
 .github/workflows/ci.yml      |  24 +++++
 src/ssl/adv_alloc.rs          | 150 +++++++++++++++++++++++++--
 src/ssl/ssl_lib.rs            | 348 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++-
 src/ssl/statem/statem_clnt.rs |  60 ++++++----
 src/ssl/statem/statem_srvr.rs |  27 ++---
 5 files changed, 563 insertions(+), 46 deletions(-)
 scripts/adv-probe.sh          | new file (untracked in this record's diff)
```

The rebuilt candidate is the only implementation these results describe; re-run on the sealed
commit before citing them as evidence for that SHA.

## Commands and results

All commands ran inside the court container
(`bash docker/openssl-rs-court.sh exec bash -c 'cd /work && ...'`), one heavy command at a time,
with `CARGO_BUILD_JOBS=4`.

### Routine gate (probes must be ignored, not false passes)

```
cargo fmt --all -- --check                     # rc 0
cargo clippy --all-targets -- -D warnings      # rc 0
cargo test --lib -- --test-threads=4           # rc 0
test result: ok. 1196 passed; 0 failed; 9 ignored; 0 measured; 0 filtered out
```

The 9 ignored tests are exactly the allocator-injection probes below (4 pre-existing, 5 added).
The 1196 passed includes 4 new deterministic `CertKey.serverinfo` realloc tests, so the routine
*passed* count is preserved at the baseline 1196 while the probes no longer count as passes.

### Probed gate 1 — the literal `--test-threads=1` command

```
OPENSSL_RS_ADV_PROBE=1 CARGO_BUILD_JOBS=4 cargo test --lib -- --test-threads=1
test result: ok. 1196 passed; 0 failed; 9 ignored; 0 measured; 0 filtered out
```

This is the point of the change: even with the gate set, an `#[ignore]`d probe is **not executed**
by a plain run. The `ignored` count is the machine-readable proof that the green run did not
execute the probes.

### Probed gate 2 — execute the probes

```
OPENSSL_RS_ADV_PROBE=1 CARGO_BUILD_JOBS=4 cargo test --lib -- --ignored --test-threads=1
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 1196 filtered out
```

(`--ignored` is required because the probes are `#[ignore]`d.)

### Probed gate 3 — one process per probe (isolation-authoritative)

```
bash scripts/adv-probe.sh
adv-probe: all 9 probes passed
SCRIPT_RC=0
```

The script invokes each probe in a **separate `cargo test` process** with
`--ignored --exact <name> --test-threads=1 --nocapture`, and fails if the invocation exits
non-zero **or** did not execute exactly one test (`test result: ok. 1 passed`).

## Per-test result

| # | Probe (module path) | Process-isolated run |
|---|---------------------|----------------------|
| 1 | `ssl::statem::statem_clnt::adv_probe::tls12_process_refused_ticket_alloc_leaves_ext_tick_empty` | PASS |
| 2 | `ssl::statem::statem_clnt::adv_probe::tls13_process_refused_ticket_alloc_leaves_ext_tick_empty` | PASS |
| 3 | `ssl::statem::statem_clnt::adv_probe::canary_refusal_instrument_fires` | PASS |
| 4 | `ssl::statem::statem_srvr::adv_probe::tls12_construct_refused_ticket_alloc_leaves_ext_tick_empty` | PASS |
| 5 | `ssl::statem::statem_srvr::adv_probe::canary_double_release_is_detected` | PASS |
| 6 | `ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_refused_keeps_old_owner` | PASS |
| 7 | `ssl::ssl_lib::adv_realloc_probe::serverinfo_realloc_reentrancy_reads_member` | PASS |
| 8 | `ssl::ssl_lib::adv_realloc_probe::canary_realloc_refusal_instrument_fires` | PASS |
| 9 | `ssl::ssl_lib::adv_realloc_probe::canary_reenter_observer_fires` | PASS |

Deterministic (not ignored, run in the routine suite) `CertKey.serverinfo` coverage added in
`ssl_lib.rs::adv_member_tests`:

| Test | Covers |
|------|--------|
| `serverinfo_realloc_growth_updates_member_and_preserves_contents` | successful growth; member/reader agree; incumbent bytes preserved |
| `serverinfo_realloc_growth_then_destruction_releases_once` | destruction after growth |
| `serverinfo_realloc_from_empty_allocates_and_destruction_releases_once` | `realloc(NULL, n)` first-install arm |
| `canary_realloc_member_predicate_detects_stale_length` | negative control: stale length is rejected |

## Targeted boundary court (converted staged/duplicated contexts)

Seven probes extend the same process-global harness to the DSA, DH, ECX, DTLS state,
PKCS#12 password and provider operation-bit boundaries. `adv_alloc::arm_any(size)`
refuses the next request of exactly that size at **any** `(file, line)` coordinate; the
existing site-specific `arm(size)` is unchanged and still backs the SSL ticket probes.
The recorded `site` bit is the request's real coordinate, so a size-only match stays
auditable. A one-shot `arm_cleansed_free(len)` inspects the first `len` bytes of the next
forwarded release before freeing it. With the nine original SSL probes, the targeted
court now totals **18** probes.

| Probe | Establishes | Does **not** establish |
|-------|-------------|------------------------|
| `dsa::object::adv_probe::dsa_new_refused_alloc_returns_null_without_free` | A refused `Dsa`-sized `CRYPTO_zalloc` makes `ossl_dsa_new(NULL)` answer NULL; exactly one refused request, none forwarded, no release of a block that never existed; the unarmed success path still allocates and releases once. | Other constructor failure arms (lock/ex-data/method `init`), arbitrary reentrancy, or any cryptographic property. |
| `dsa::object::adv_probe::dsa_method_init_failure_runs_partial_cleanup` | After a **successful** `Dsa` context allocation, a method whose `init` answers 0 makes `ossl_dsa_new(NULL)` answer NULL; the same block reaches `finish` once, exactly one `Dsa`-sized allocation is forwarded, and the sole release is that block's address; the saved default method is restored before every assertion and `DSA_new`/`DSA_free` still work. | Lock-null and ex-data-failure arms (unreachable/non-injectable, see scope note), method tables the constructor does not own, reentrancy, or crypto correctness. |
| `dh::object::adv_probe::dh_new_refused_alloc_returns_null_without_free` | The same refusal/cleanup contract for `ossl_dh_new_ex(NULL)` and the staged `Dh` block. | As above. |
| `dh::object::adv_probe::dh_method_init_failure_runs_partial_cleanup` | The same later-initialisation partial-cleanup contract for `ossl_dh_new_ex(NULL)`: `finish` once on the object `init` refused, one forwarded `Dh` allocation, one release of that block, restored default method, and a working `DH_new`/`DH_free` path. | As above. |
| `ec::ecx_backend::adv_probe::ecx_key_dup_refused_alloc_returns_null_without_free` | `ossl_ecx_key_dup(k, 0)` answers NULL when its `ECX_KEY` zalloc is refused, with no release; the inert source key (`keylen`/`type_` set, `propq`/`privkey` NULL) releases once. | Duplication of a fully populated key, the `propq`/private-scalar failure arms, `realloc`/callback reentrancy, or crypto correctness. |
| `ssl::adv_alloc::adv_probe::cleansed_free_instrument_detects_residue` | The cleansed-free detector accepts a zeroed block, flags residue, and `assert_not_cleansed()` panics with the precise reason; a dead check is not a pass. | That any specific release path cleanses its secret storage. |
| `ssl::d1_lib::adv_probe::dtls_state_refusal_and_lifecycle` | A refused `Dtls1State`-sized `CRYPTO_zalloc` makes `dtls1_new_state(true)` answer NULL with exactly one refused request and no release; on the success path `dtls1_free` releases the state once, clears the `Ssl.d1` field, and the enclosing zeroed `Ssl` block is released once. | `DTLSv1_listen` cookie-stage behaviour, the unmodelled queue/sequence fields, or reentrant access to `d1`. |
| `pkcs12::p12_key::adv_probe::unipass_drop_cleanses_before_release` | `OwnedUniPass::drop` zeros the `len` password bytes through `CRYPTO_clear_free` **before** the hooked release forwards them; the seized block is released exactly once. | That every PKCS#12 password conversion path is cleansed (only the owner's `Drop` is exercised), or KDF correctness. |
| `provider::activate::adv_probe::opbits_realloc_publishes_after_old_pair` | `ossl_provider_set_operation_bit(&mut p, 3)` regrows `(NULL, 0)` to one byte; during the intercepted realloc the member pair is still the old `(NULL, 0)`, and only after return are the new block, size 1 and bit `1 << 3` visible. | A reentrant call that takes the same `opbits_lock`: the lock is non-reentrant, so that call would deadlock. Also does not cover concurrent readers/writers or other realloc sizes. |

**Constructor-failure scope (recorded, not hidden).** Allocation refusal was already covered by the `*_new_refused_alloc_*` probes. The two `*_method_init_failure_*` probes cover the **later** arm: the context allocation succeeds, and `meth->init` then answers 0, so the constructor's `err:` path must run the partial cleanup. The lock-null arm is not reachable in this crate (`CRYPTO_THREAD_lock_new` is `Box`-based, so it cannot be made to answer NULL by the allocator hook), and `CRYPTO_new_ex_data` failure is not injectable through the CRYPTO hook; neither arm is claimed here.

**Provider publication-ordering scope (recorded, not hidden).** The provider probe
establishes **publication ordering only**. A genuine reentrant call into
`ossl_provider_set_operation_bit` (or `ossl_provider_test_operation_bit`) while the write
lock is held is not attempted, because `opbits_lock` is a non-reentrant read/write lock
and the reentrant call would deadlock rather than observe a partially published pair.
The probe therefore exercises the allocator-boundary observation, not an application
callback that reenters the provider.

**Scope of the claim.** These probes exercise the allocator-refusal path of the
boundary, plus the later method-`init` failure after a successful context
allocation for DSA and DH. They do not model an application callback that
reenters and mutates the object, do not cover every constructor failure point,
and do not substitute for the functional/differential courts. `arm_any` is a
test-only negative-control instrument and never links into a release build.

## Hard-fail and self-verification semantics

Every probe now calls `adv_alloc::require_installed()` and `adv_alloc::assert_instrument_live()`
before its measured window:

- Gate missing (e.g. an accidental `--ignored` run without `OPENSSL_RS_ADV_PROBE=1`) → `panic!`.
- `CRYPTO_set_mem_functions` refused (not running alone) → `panic!` (previously a silent skip).
- Recording hook does not observe a known `CRYPTO_malloc`/`CRYPTO_free` pair → `panic!`
  (a dead detector cannot produce a green probe).
- The intended refusal/double-release/reentrancy observation is asserted as before; the canaries
  assert the corresponding instrument is live.

## Negative-control verification of the runner

The runner was tested against a deliberately broken canary: the double-release canary's assertion
was temporarily inverted, `bash scripts/adv-probe.sh` was run, and it exited **1** with:

```
--- FAIL: ssl::statem::statem_srvr::adv_probe::canary_double_release_is_detected (non-zero exit)
adv-probe: 1 probe(s) failed
SCRIPT_RC=1
```

The inversion was reverted, `cargo fmt --all -- --check` passed, and the script returned `SCRIPT_RC=0`
with all 9 probes PASS.

## CI

`.github/workflows/ci.yml` has a dedicated `adversarial` job (separate from `lint`/`static`), which
acquires the authority source (needed to compile the test target), then runs
`bash scripts/adv-probe.sh`. The script sets `OPENSSL_RS_ADV_PROBE=1`, runs one process per probe,
and fails hard. The job is cheap and runs on every push and pull request.

## Residual notes

**Reentrancy scope (do not overstate).** `serverinfo_realloc_reentrancy_reads_member`
proves **publication ordering** only: a synthetic allocator observer invoked
during `CRYPTO_realloc` sees the original pointer/length, and the new pair
after success. It does **not** prove soundness under an arbitrary application
callback that reenters and mutates or releases the same object; no Rust borrow
is held across that call, but the broader callback/alias boundary remains a
§21 obligation to state and discharge explicitly per affected API.

- Isolation is per probe **process**, not per test thread; `--test-threads=1` alone is not
  sufficient because the allocator hook is process-global.
- The probes are test-only (`#[cfg(test)]`); nothing here links into a release build.
- Results above are for the uncommitted working tree; re-run at any sealed SHA before citing them
  as that SHA's evidence.
