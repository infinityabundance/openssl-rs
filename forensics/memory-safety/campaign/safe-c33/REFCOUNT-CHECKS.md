# Refcount independent check package — RC-1

**Boundary:** `RC-1`, `src/runtime/refcount.rs`.
**State after this package:** `INDEPENDENTLY_CHECKED` (bounded evidence, no global
proof). **Not** `SAFETY_DISCHARGED` and **not** `SAFE_COMPATIBLE`.
**Check type:** independent verification of the *protocol state machine*, run by a
verification subagent in the court container; no conversion code was changed except
the crate-private test seam described in §3.

## 1. Source and build identity

| item | value |
|---|---|
| branch | `integrate/safe-c33` |
| source HEAD | `56ba894594ed3df0fdf117a15747d205b4f0ecd9` |
| working tree | uncommitted check package: `Cargo.toml`, `Cargo.lock`, `src/runtime/refcount.rs`, this file, and `REFCOUNT-BOUNDARY.md` |
| working-tree diff | `sha256:a3e07d0458865d61cdb3988e67f59a2d916ad8a7cd0f670d278bc988d7046a0c` (`git diff \| sha256sum`, tracked files) |
| `src/runtime/refcount.rs` | `sha256:063c5ab907cce57ae1c93d67be770575ffbd384e3b297534eaba1bb2b7991ae8` |
| `Cargo.toml` | `sha256:21dc5024678cc35d893f6749f2f692d4fa468aa626fd2fd7bc1b30003ed3b765` |
| `Cargo.lock` | `sha256:bbec0bde8505f5adedfdc5e3ec68d3d5b80cc72b90510e41169fad9133264554` |
| `REFCOUNT-BOUNDARY.md` | `sha256:902bd90957fc6b7ab88e1b7c990fe968623f4a8baac637734a3a574a0db3a41d` |
| venue | `openssl-rs-court:1` (Docker), `x86_64`, `rustc 1.98.1`, dev profile |
| toolchain record | `/court/toolchain.txt` in the court image |

These hashes pin the *checked* candidate. They are not a commit; the orchestrator
must commit the package and re-record the commit identity at merge time.

## 2. What was checked

The protocol, not its callers:

- `up_ref(&A) -> c_int`: positive-count increment with the authority's `1` answer;
  refusal at zero, `REF_DESTROYING`, and `i32::MAX` without changing the count.
- `down_ref(&A) -> DownRef`: `Remaining` for a non-final release; `Last` exactly
  once, claiming `1 -> REF_DESTROYING`; `Retired` for a zero/sentinel observation.
- The `REF_DESTROYING` sentinel never coincides with a live positive count.
- At most one `Last` per modelled execution; no increment may succeed after the
  sentinel is installed; the count may never be negative except the sentinel.
- Logical conservation: modelled initial references + successful increments equal
  successful releases plus the final live count (the sentinel counts as zero live
  references).
- A `Last` is only legal when no other modelled reference is outstanding.
- A re-entrant (non-owning) release must observe `Retired`, never `Last`.

Checked in two independent instruments over the *same algorithm*:

1. **Loom model checking** of the real `up_ref`/`down_ref` bodies through a
   crate-private `RefAtomic` seam. Loom `0.7.2` atomics are substituted only in the
   `cfg(loom)` test build; product and ordinary-test builds instantiate the same
   generic functions for `core::sync::atomic::AtomicI32`.
2. **Exhaustive bounded interleaving model** in
   `src/runtime/refcount.rs::exhaustive_model_tests`. It mirrors the state machine
   over plain integers and a deterministic step scheduler that enumerates every
   ordering of every actor's atomic micro-steps (`load` and `commit`), with CAS
   retry on failure. The mirror is used for the exhaustive enumeration and the
   mutant controls; the Loom harness is what runs the real generic functions.

## 3. Instrument configuration

- `Cargo.toml` adds `[target.'cfg(loom)'.dev-dependencies] loom = "0.7"` and
  `unexpected_cfgs = { level = "warn", check-cfg = ["cfg(loom)"] }`.
- Resolution fetched `loom 0.7.2` and its dependency closure from crates.io in the
  court container. The dependency is linked only when the test build sets
  `--cfg loom`; ordinary builds and ordinary test runs never see it.
- The production seam is `pub(crate) trait RefAtomic` with
  `load_ref`/`compare_exchange_ref`; the only non-Loom implementor is
  `core::sync::atomic::AtomicI32`. The `#[cfg(all(test, loom))]` module adds the
  Loom implementor. No product signature, layout, exported symbol or call site
  changed beyond the generic parameter inference.
- Loom models: 2 workers + a base reference; a last-release/increment race; two
  releases of a one-reference count; `i32::MAX`.
- Exhaustive model bounds: four scenarios, at most three actors, two operations per
  actor, `MAX_STEPS = 128` (a reached bound is reported as `StepBoundExceeded` and
  did not occur for the real protocol). The three-actor base scenario enumerates
  226 executions; smaller scenarios enumerate the orderings of their step
  sequences. No state deduplication is used (duplicate paths only add evidence).

## 4. Exact commands and results

All commands ran in the court container from `/work`, with `CARGO_BUILD_JOBS=4`.

| command | result |
|---|---|
| `cargo fmt --all -- --check` | clean (`FMT-OK`) |
| `cargo clippy --all-targets -- -D warnings` | clean (`Finished dev profile`) |
| `cargo test --lib -- --test-threads=4` | `1346 passed; 0 failed; 22 ignored` |
| `cargo test --lib runtime::refcount -- --test-threads=4` | `21 passed; 0 failed` |
| `RUSTFLAGS="--cfg loom" cargo test --lib runtime::refcount::loom_tests -- --test-threads=1` | `4 passed; 0 failed` |

The 22 ignored tests are the pre-existing allocator probes (run one per process by
`scripts/adv-probe.sh`); none was added or removed. The test count grew by the six
new exhaustive-model tests; the four Loom tests exist only under `cfg(loom)`.

**Adjudication re-run (fresh compile).** After adjudication flagged a possible
cached Loom artifact, `src/runtime/refcount.rs` was `touch`ed and the Loom command
re-run. Cargo emitted `Compiling openssl-rs v0.0.27 (/work)` and the result remained
`4 passed; 0 failed`. The touch changed no file content, so the §1 hashes are
unchanged. The commit SHA is deliberately not recorded yet: it will be pinned by
the follow-up docs commit that lands this package, which must re-confirm these
hashes.

### Loom tests (real protocol, modelled atomics)

| test | result |
|---|---|
| `runtime::refcount::loom_tests::loom_base_reference_yields_one_last` | pass |
| `runtime::refcount::loom_tests::loom_last_release_race_never_resurrects` | pass |
| `runtime::refcount::loom_tests::loom_sentinel_absorbs_a_second_release` | pass |
| `runtime::refcount::loom_tests::loom_up_ref_refuses_i32_max` | pass |

### Exhaustive model tests

| test | result |
|---|---|
| `runtime::refcount::exhaustive_model_tests::exhaustive_real_protocol_has_no_violations` | pass (all four scenarios, zero violations) |
| `runtime::refcount::exhaustive_model_tests::exhaustive_scheduler_explores_racing_interleavings` | pass (the three-actor scenario branches into 226 executions) |
| `runtime::refcount::exhaustive_model_tests::mutant_non_atomic_rmw_is_detected` | pass (mutant detected) |
| `runtime::refcount::exhaustive_model_tests::mutant_unchecked_up_is_detected` | pass (mutant detected) |
| `runtime::refcount::exhaustive_model_tests::mutant_zero_free_is_detected` | pass (mutant detected) |

## 5. Negative controls

Each mutant is selected through the *same* `explore(scenario, proto)` harness that
the real protocol passes. The harness reports a violation only through the named
invariant classes; there is no mutant-specific detector.

| mutant | mechanism | scenario | detected violation | result |
|---|---|---|---|---|
| (a) `Proto::NonAtomicRmw` | loads the count, then writes `n ± 1` without verifying the value is still `n` | `base-plus-two-workers` | `LastWithOutstandingRefs` — a lost update lets a worker's release claim `Last` while the base reference is still outstanding; the same runs also report conservation/final-count divergence | detected |
| (b) `Proto::UncheckedUp` | increments without the zero/sentinel guard (wrapping add) | `last-release-race` (and `i32-max-refusal`) | `Resurrection` — a winning release installs the sentinel and the racing increment still succeeds; at `i32::MAX` the wrap also yields `UpProducedNonPositive` | detected |
| (c) `Proto::ZeroFree` | returns `Last` on any zero/negative count instead of claiming `REF_DESTROYING` | `reentrant-double-down` | `MultipleLast` / `ReentrantDownClaimedLast` — the owner's release leaves count `0`, and the re-entrant release frees a second time | detected |

The real protocol (`Proto::Real`) produces no violation in any of the four
scenarios, including the re-entrant scenario. Thus the controls demonstrate that
the harness fails when the protocol is replaced by each mutant, rather than merely
asserting properties that every implementation satisfies.

## 6. What was not checked

- **No global or unbounded proof.** Loom explores its configured models under its
  own bounds; the exhaustive model is bounded to at most three actors, two
  operations per actor, and 128 micro-steps. Neither covers all thread counts,
  operation lengths, or weak-memory behaviours.
- **No C-ABI caller validation.** `up_ref`/`down_ref` remain `unsafe fn`: liveness,
  provenance, alignment, per-reference single release and the destructor-runner
  obligation are caller contracts. The exported `*_free` wrappers and their call
  sites were **not** re-audited here. A safe caller cannot reach the functions, but
  a C caller can violate the contract; that judgment is a separate adjudication
  and is why this package does not claim `SAFETY_DISCHARGED`.
- **No differential compatibility court.** These tests exercise the candidate's own
  module. No authority binary was replayed against the races, and no claim is made
  about publication/ordering of surrounding object state beyond the existing lock
  discipline.
- **No Miri, TSan, ASan, or dudect run for this boundary.** Loom is a model checker
  for the modelled atomics; it is not a substitute for a sanitizer campaign.
- **No per-site `SAFETY` audit.** The caller inventory and the `// SAFETY:`
  assertions in `src/runtime/refcount.rs` and the consumer families remain reviewed
  prose, not machine-checked obligations.
- **Mirror fidelity is bounded by construction.** The exhaustive model is a mirror
  written by the checker. The Loom harness mitigates this by running the real
  generic function bodies; the mirror's role is the exhaustive enumeration and the
  three negative controls.
- **Step bound not exercised as a pass.** `StepBoundExceeded` is a reported
  violation, not a silent skip; it did not occur for `Proto::Real`. A future model
  that reaches the bound would fail rather than pass.

## 7. Evidence pointers

- `src/runtime/refcount.rs` — `RefAtomic` seam; `#[cfg(all(test, loom))]
  mod loom_tests`; `#[cfg(test)] mod exhaustive_model_tests`.
- `Cargo.toml` — Loom dev-dependency and `unexpected_cfgs` check-cfg.
- `Cargo.lock` — resolved `loom 0.7.2`.
- `REFCOUNT-BOUNDARY.md` §5–§7 — conversion boundary, caller inventory and the
  updated graduation state.
- Court commands and outputs are reproduced in §4; the working-tree hashes in §1
  identify the exact candidate checked.
