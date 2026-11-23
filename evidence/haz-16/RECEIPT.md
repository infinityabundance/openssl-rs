# HAZ-16 receipt — FFI failure atomicity

**Item:** `HAZ-16` / `OBL-PANIC-ATOMICITY`.
**Base candidate:** `staging` at `5d38094cc` (clean worktree at the start of the
item).
**This receipt:** describes the source change and the evidence added in the
batch that carries it. The orchestrator commits the batch; the evidence commit
settles the identity.

## 1. Scope

This is a bounded batch, not a universal atomicity claim.

- Enumerated: 883 scripts, 6,511 exported `extern "C"` functions, 1,485
  `guard_ffi`-wrapped, 823 mutation candidates.
- Covered: 79 entries in the nine security-relevant object-owner files
  (`OPENSSL_STACK`, `OPENSSL_LHASH`, `BIO`, `BIGNUM`, `BN_CTX`, `BN_GENCB`,
  `BN_BLINDING`, `CRYPTO_EX_DATA`, `ASN1_OBJECT`/`OBJ_NAME`).
- Repaired: 3 `PARTIAL_EXPOSED` entries.
- Recorded but not repaired: 3 `CRYPTO_EX_DATA` callback-driven rows.
- Not audited: 744 mutation candidates outside the covered owners.

The population, method and per-entry basis are in
`docs/FFI-FAILURE-ATOMICITY.md` and `CLASSIFICATION.json`.

## 2. Authority contract

- **Authority:** OpenSSL 3.6.4 at the pinned source tree; the affected code is
  `crypto/bn/bn_blind.c` (`BN_BLINDING_update`, `BN_BLINDING_create_param`) and
  `crypto/stack/stack.c` (`OPENSSL_sk_pop_free`).
- **ABI:** unchanged. No exported symbol, signature, `#[repr(C)]` layout or
  `CRYPTO_*` allocator coordinate is touched. `Blinding` remains opaque and
  `BigNum` is unchanged.
- **Target:** the crate's supported 64-bit target; no target-specific code is
  involved.
- **Lifecycle:** the three entries take live objects under their existing
  `# Safety` contracts; the repairs change only what happens after a fallible
  step or a caught panic.

## 3. Ownership before / after

| entry | before | after |
|---|---|---|
| `BN_BLINDING_update` | two in-place squarings; the counter advanced before them | squares computed into `TempBn`; pair and counter published together, counter rolled back on failure |
| `BN_BLINDING_create_param` | `a`, `e`, `m_ctx`, `bn_mod_exp` published before the inverse/exponentiation/Montgomery steps | locals only until every fallible step succeeds; `a`, `ai`, `e`, `m_ctx`, `bn_mod_exp` published together |
| `OPENSSL_sk_pop_free` | element array iterated in place, stack released after the loop | each element removed before its destructor; the stack keeps only unreleased elements if the loop is interrupted |

New helper types:

- `TempBn` — owns a `BIGNUM` until publication and `BN_clear_free`s it on every
  exit, including unwind. The blinding factor and its inverse are secret.
- `publish_member` — swaps a completed value into a member and cleanses the
  replaced value; total, and therefore the commit point.

## 4. Unsafe changes

| category | count |
|---|---:|
| unsafe operations eliminated | 0 |
| unsafe operations relocated | 0 |
| unsafe operations introduced | 1 (the `unsafe fn publish_member`, with a documented contract; its body is two `BN_swap`/assignment arms and one `BN_clear_free`) |
| `SAFETY:` comments added | every new unsafe call site |

`create_param_impl` is a new `unsafe fn` with a `# Safety` contract; it performs
no new raw-pointer operation that the previous inline body did not already
perform, but the contract is now stated once. No exported function gained a
safe-looking wrapper.

## 5. Compatibility delta

- Success paths: byte-for-byte return values and object contents unchanged; the
  existing round-trip, counter and accessor tests pass unchanged.
- Failure paths (deliberate, recorded):
  - `BN_BLINDING_update` does not advance the counter when the update did not
    commit. The authority advances it on its error path.
  - `BN_BLINDING_create_param` with a non-null `b` leaves `b` unchanged when it
    fails. The authority returns a partly initialised `b`.
  - `OPENSSL_sk_pop_free` keeps only unreleased elements if it is interrupted;
    the authority leaves released elements in the array.
- `OPENSSL_sk_pop_free` is O(n²) rather than O(n) in element count; destruction
  order is unchanged.
- `BN_BLINDING_update` allocates two temporary `BIGNUM`s per squaring update and
  `BN_BLINDING_create_param` allocates two per call (plus one duplicate of a
  caller-supplied exponent). These are Rust-allocator `BIGNUM`s, **not**
  `CRYPTO_*`-seam allocations, so an installed memory hook does not observe them;
  the replaced factors are cleansed. The delta is recorded because allocation
  surveys (T21/T29) count Rust allocations too.
- No ABI change; no new exported symbol; no allocator-seam coordinate change.

## 6. Demonstrated findings (pre-fix)

The test-only hooks inject a panic at the pre-fix mutation point, `guard_ffi`
catches it, and the object is then used as a legal caller would.

| entry | what the caller observed after the caught panic |
|---|---|
| `BN_BLINDING_update` | both later `convert`/`invert` calls returned 1 and the round trip did not cancel |
| `BN_BLINDING_create_param` | the caller's context held the new draw with the old inverse; every later round trip returned 1 and did not cancel |
| `OPENSSL_sk_pop_free` | `sk_num` returned 2 and `sk_value(0)` returned the already-released element; a retry would have released it twice |

Verbatim revert-control failures:

```
thread '...a_panic_between_the_blinding_squares...' panicked at src/bn/blinding.rs:
injected defect: panic between the blinding squares
thread '...a_panic_between_the_blinding_squares...' panicked at src/bn/blinding.rs:
assertion failed: unsafe { round_trip_cancels(b, m, d, ctx, keep, expect) }
```

```
thread '...a_panic_after_the_blinding_draw...' panicked at src/bn/blinding.rs:
injected defect: panic after the blinding draw
thread '...a_panic_after_the_blinding_draw...' panicked at src/bn/blinding.rs:
assertion failed: unsafe { round_trip_cancels(b, m, d, ctx, keep, expect) }
```

```
thread '...a_panic_during_pop_free...' panicked at src/runtime/stack.rs:
injected defect: panic after an element was released
thread '...a_panic_during_pop_free...' panicked at src/runtime/stack.rs:
assertion `left == right` failed: only the unprocessed element remains
  left: 2
 right: 1
```

## 7. Tests added

| test | proves |
|---|---|
| `bn::blinding::tests::a_panic_between_the_blinding_squares_leaves_the_factor_pair_usable` | the update is failure-atomic; the pair still cancels; a retry succeeds |
| `bn::blinding::tests::a_panic_after_the_blinding_draw_does_not_publish_the_new_factor` | the draw is not published before its inverse |
| `bn::blinding::tests::create_param_on_an_existing_context_still_publishes_a_cancelling_pair` | the success path of the rewritten `create_param` |
| `runtime::stack::tests::a_panic_during_pop_free_leaves_only_unreleased_elements_reachable` | a released element is never reachable; a retry releases the remainder once |
| `runtime::stack::tests::pop_free_releases_each_element_once_on_the_success_path` | the success path is unchanged |

The pre-existing `the_blinding_round_trip_cancels_after_the_private_exponentiation`
remains the broad success-path control for the blinding path.

## 8. Gates (verbatim)

Court: `openssl-rs-court-tools:1`, container cap 8g/8g, `CARGO_BUILD_JOBS=4`,
`--test-threads` as shown. Host `available` at the final gate was 27 GiB (≥ 24
GiB threshold; the prescribed 6g is stricter than `min(8g, available − 16g)`).
No build ran on the host.

```
cargo fmt --all -- --check
FMT_EXIT=0
```

```
cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.87s
```

```
cargo test --lib -- --test-threads=1
test result: ok. 2430 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 372.22s
```

```
cargo test --lib -- --test-threads=4
test result: ok. 2430 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 150.28s
```

Baseline was 2425 passed / 0 failed / 54 ignored; the five added tests account
for the increase to 2430. No test was removed or newly ignored.

## 9. Obligations

- **Discharged:** the three named entries now state and satisfy a failure-atomic
  publication contract; their `PARTIAL_EXPOSED` pre-fix findings are
  demonstrated and their revert controls are recorded.
- **Retained:**
  - `OBL-PANIC-ATOMICITY` stays open. The covered population is 79 of 823
    mutation candidates; the remaining 744 are `NOT_AUDITED`.
  - The three `CRYPTO_EX_DATA` `PARTIAL_EXPOSED` rows remain.
  - Caller output buffers are not covered.
  - `evp`/`rsa`/`ec`/`x509` do not use `guard_ffi`; their panic behaviour is an
    abort at Rust's `extern "C"` boundary and is not analysed here.
- **Newly introduced:** none. The new `unsafe fn` has a written contract and
  every new unsafe call site has a `SAFETY:` comment.

## 10. Residuals and what would close them

1. Classify the remaining 744 mutation candidates (same method; they are
   consumers rather than object owners, and `evp`/`rsa`/`ec`/`x509` need the
   separate abort-vs-caught analysis).
2. Decide whether the `CRYPTO_EX_DATA` rows get a transactional slot protocol;
   that needs a compatibility measurement for application callbacks.
3. Run Miri over the repaired blinding and stack paths, and an independent
   reviewer over this batch, before any `SAFETY_DISCHARGED` language is used.
4. No `REL-OPENSSH-B85C` effect: `OBL-PANIC-ATOMICITY` still constrains it.
