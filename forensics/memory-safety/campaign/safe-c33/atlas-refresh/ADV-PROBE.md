# ADV-PROBE — allocator-injection adversarial probes

Status: **green** (routine + probed gates) on the candidate below.

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

- Isolation is per probe **process**, not per test thread; `--test-threads=1` alone is not
  sufficient because the allocator hook is process-global.
- The probes are test-only (`#[cfg(test)]`); nothing here links into a release build.
- Results above are for the uncommitted working tree; re-run at any sealed SHA before citing them
  as that SHA's evidence.
