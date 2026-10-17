# Refcount boundary RC-1 — `runtime::refcount`

**Source identity:** `integrate/safe-c33` at
`66192b437f6deda27a5b2c190a6a9d9a9c6aa2d7` (working tree at audit time).
**Boundary ID:** `RC-1`. **Instrument:** bounded deterministic concurrency
tests plus the existing consumer re-entrancy tests. **Status:** `ESTABLISHED`
(bounded, independently checkable). **Not** `SAFETY_DISCHARGED`; **not**
`SAFE_COMPATIBLE`. No dependency-closure or consumer-compatibility claim is
made here.

## 1. The object and the contract

`src/runtime/refcount.rs` implements one atomic count shared by four consumer
families. The count is the object's existing `AtomicI32` field; the sentinel
`REF_DESTROYING = i32::MIN` is stored in that same field and changes no
`#[repr(C)]` layout or exported signature.

### Shared preconditions (both operations)

- The `AtomicI32` is the live object's `references` field, correctly aligned
  and sized for the authority's `int`.
- The object's storage is live and not retiring for the duration of the call. The protocol
  cannot validate provenance or liveness; a pointer to released storage is C-invalid input
  and is outside the contract.
- The count is accessed only through this protocol. A foreign write to the
  field is outside the contract.
- For `up_ref`, a live reference to the object exists. It may be held by the calling
  thread or, as `SSL_dup` does, by the caller on whose behalf the increment is taken; the
  authority permits incrementing any live, non-retiring object, and this protocol imposes
  no separate per-thread token requirement. The caller acquires exactly one new reference.
- For `down_ref`, the caller releases exactly one reference it acquired, and that reference
  is released exactly once.

### `up_ref(&AtomicI32) -> c_int`

| answer | meaning | postcondition |
|---|---|---|
| `1` | a reference was acquired | count increased by exactly one; caller owns the new reference |
| `0` | refused | count unchanged; no reference acquired; count was zero, negative, `REF_DESTROYING`, or `i32::MAX` |

The positive-count answer and ordering are the authority's
`memory_order_relaxed` increment. A refused call never resurrects a retired or
destroying object.

### `down_ref(&AtomicI32) -> DownRef`

| outcome | meaning | who may run the destructor |
|---|---|---|
| `Remaining` | one reference released; at least one other owner remains | nobody |
| `Last` | the caller released the final reference; count is now `REF_DESTROYING` | this caller, exactly once |
| `Retired` | the release was not applied (count was zero, negative, or destroying) | nobody |

`Last` is a one-shot ownership transfer: only the caller that received it may
run the destructor body, and only after that body completes may the storage be
released. `Retired` is the defined no-op for a re-entrant `*_free` that runs
while the destructor body is in progress. After `Last`, the count remains
`REF_DESTROYING` for as long as the storage is readable: `up_ref` answers `0`
and `down_ref` answers `Retired`. The sentinel must not be read after the
block is released.

## 2. Caller inventory

There are **9 direct call sites** across the **four converted families**
(`Ssl`, `SslCtx`, `SslSession`, `X509Store`). Every other public
`*_up_ref`/`*_free` path is **not** claimed to funnel through these functions;
the crate has independent refcount implementations (see the out-of-scope list
below).

| file:line | function | object / field | operation |
|---|---|---|---|
| `src/ssl/ssl_lib.rs:3102` | `SSL_CTX_up_ref` | `SslCtx.references` | `up_ref` |
| `src/ssl/ssl_lib.rs:3126` | `SSL_CTX_free` | `SslCtx.references` | `down_ref` |
| `src/ssl/ssl_lib.rs:3475` | `SSL_up_ref` | `Ssl.references` | `up_ref` |
| `src/ssl/ssl_lib.rs:3490` | `SSL_free` | `Ssl.references` | `down_ref` |
| `src/ssl/ssl_lib.rs:12148` | `SSL_dup` | `Ssl.references` | `up_ref` (returns the same connection) |
| `src/ssl/ssl_sess.rs:594` | `SSL_SESSION_up_ref` | `SslSession.references` | `up_ref` |
| `src/ssl/ssl_sess.rs:532` | `SSL_SESSION_free` | `SslSession.references` | `down_ref` |
| `src/x509/x509_lu.rs:1959` | `X509_STORE_up_ref` | `X509Store.references` | `up_ref` |
| `src/x509/x509_lu.rs:1896` | `X509_STORE_free` | `X509Store.references` | `down_ref` |

Callers of the public wrappers (for example `SSL_new`, `SSL_set_SSL_CTX`,
`SSL_CTX_add_session`, `SSL_get1_session`, `SSL_set_session`,
`ssl_update_cache`, `lookup_sess_in_cache`) inherit the obligations above.
They do not add call sites to RC-1.

### Out of scope: other refcount implementations

The following paths were checked by grep during this review. They are outside
RC-1 and retain their own contracts.

| path | mechanism at this revision | relation to RC-1 |
|---|---|---|
| `src/evp/cipher.rs` | `EvpCipher.refcnt: AtomicI32`, direct `fetch_add`/`fetch_sub` guarded by `origin`; `EVP_CIPHER_up_ref`/`EVP_CIPHER_free` | independent method refcount |
| `src/store/store_meth.rs` | `OsslStoreLoader.refcnt: AtomicI32`, direct `fetch_add`/`fetch_sub`; `OSSL_STORE_LOADER_up_ref`/`_free` | independent method refcount |
| `src/ml_dsa/key.rs` | no refcount of its own; `ossl_ml_dsa_key_dup` calls `EVP_MD_up_ref` | caller of the `EvpMd` mechanism, not an RC-1 call site |
| `src/evp/digest.rs` | `EvpMd.refcnt: AtomicI32`, direct `fetch_add`/`fetch_sub` guarded by `origin` | the implementation reached from `ml_dsa/key.rs` |
| `src/asn1/utl.rs` | `CryptoRefCount` helpers | independent |
| `src/engine/eng_lib.rs` | `struct_ref` helpers | independent |
| `src/dso/mod.rs` | `references: AtomicI32` | independent |

## 3. Concurrency analysis

All mutations are compare-and-swap loops. There are no lost updates, and the
last-reference claim is the single CAS `1 -> REF_DESTROYING` (`AcqRel`). The
non-final release is `CAS(n -> n-1)` with release ordering; the initial read
is `Acquire`. `up_ref` uses `CAS(n -> n+1)` with relaxed ordering, matching the
authority's `atomic_fetch_add_explicit(..., memory_order_relaxed)`.

These tests are **protocol-level** evidence: the object is live, but a thread
need not already hold a reference before calling `up_ref`, and the tests do not
establish that arbitrary callers conform to the C contract. The racing test is
a sampler: it requires whichever outcome occurs to satisfy its invariant, not
that both outcomes occur in one run.

### 3.1 Unique last release (`many_threads_last_release_is_unique`)

With `N` initial references and exactly `N` release calls, each successful
release removes exactly one reference and the sentinel transition removes the
final one. At most one CAS `1 -> sentinel` can succeed: after it succeeds no
operation writes a positive count again. A loser that read a stale `1`
re-reads and observes the sentinel, so it cannot also claim `Last`. Because
the calls and references are matched one-for-one, no correct holder observes
`Retired`; the test requires `Last == 1`, `Remaining == N-1`,
`Retired == 0`, final count `REF_DESTROYING`, and a later release `Retired`.

### 3.2 Conservation under repeated acquire/release

(`concurrent_increments_and_decrements_conserve_ownership`)

One base reference is held for the whole test, so the count is at least one
throughout and the last release is unreachable inside the workers. Each
worker's `up_ref` must answer `1`; its matching `down_ref` must answer
`Remaining`, because the worker's own reference is still counted when it
releases. CAS retry handles contention, so no increment or decrement is lost.
After the workers join, the count is exactly one; the base release is the
unique `Last`, followed by `Retired`.

### 3.3 No resurrection (`up_ref_racing_last_release_never_resurrects`)

Consider the two linearization points on the same atomic: `up_ref`'s
`CAS(n -> n+1)` and `down_ref`'s `CAS(1 -> sentinel)`.

- If the release wins, the sentinel is installed. A later `up_ref` either
  loads the sentinel directly or its CAS `1 -> 2` fails and retries into the
  sentinel. It answers `0`. The sentinel is absorbing: `up_ref` never writes
  when `n <= 0`, `down_ref` returns `Retired` on it, and the only writer of a
  positive value (`up_ref`) refuses from it. There is no ABA path back to a
  live count.
- If the increment wins, the release's CAS `1 -> sentinel` fails. Its retry
  observes `n >= 2`, performs `CAS(n -> n-1)`, and answers `Remaining`; it can
  never answer `Last` on that reference.
- Therefore `down == Last` implies `up == 0`, and `up == 1` implies
  `down == Remaining`; in the latter case releasing the increment's reference
  is the unique `Last`.

The test is a sampler: it runs 2000 `Barrier`-synchronised rounds, asserts the
conditional invariant in every round (never a particular interleaving), checks
that each `up_ref` answer is in `{0, 1}`, and checks that the two outcome
classes account for all rounds. It does **not** require both branches to occur
in a run. It also asserts that a destroying object refuses a subsequent
`up_ref` and retires a subsequent `down_ref`.

### 3.4 Ordering scope

The count invariant above depends on RMW atomicity, not on the chosen memory
order. The orderings match the authority: relaxed increment, release
decrement, and acquire on the last-reference claim (the authority's conditional
acquire fence). This boundary makes **no** claim that `up_ref` publishes other
object state; callers' existing locking discipline remains responsible for
that, as in the authority.

## 4. `i32::MAX` and the §17 divergence

`up_ref` uses `checked_add(1)`. At `i32::MAX` it answers `0` and leaves the
count at `i32::MAX`.

The authority's C11/GNU atomic profile instead wraps: `fetch_add` on a signed
atomic is defined by C11 7.17.7.5 to use two's-complement representation
("there are no undefined results"), so the count becomes `i32::MIN` and the
public wrapper answers `0` because the new value is not greater than one. The
court measurement (`cc 12.2.0`, `-fsanitize=undefined`) confirms that a plain
`INT_MAX + 1` is diagnosed but `atomic_fetch_add_explicit` and
`__atomic_fetch_add` wrap to `-2147483648` without a diagnostic.

The observable public answer is therefore the same (`0`). The deliberate
divergence is internal: this module refuses without corrupting the count,
because in this candidate `i32::MIN` is the destroying sentinel and a wrapped
count would permanently refuse `up_ref` and turn every subsequent `down_ref`
into `Retired`. Classification (§17): implementation-defined authority
wraparound plus a safety improvement, not reproduction of UB. The
`OPENSSL_THREADS`-absent non-atomic fallback (`refcnt->val++`) would be UB on
overflow, but that profile is not the one this gate serves.

Related deliberate divergences, already recorded in the module:

- **Zero:** the authority increments `0 -> 1` and then reports failure; this
  protocol reports failure and leaves the count at zero.
- **Over-free:** the authority drives the count negative (the atomic
  arithmetic is defined; the second teardown it enables is UB) and its
  `REF_ASSERT_ISNT(i < 0)` diagnostic is compiled out under `NDEBUG`. This
  protocol returns `Retired` and performs no teardown.

## 5. Evidence

Environment: court container, `x86_64`, `rustc 1.98.1`, dev profile,
`CARGO_BUILD_JOBS=4`.

| instrument | result |
|---|---|
| `cargo fmt --all -- --check` | clean (no output) |
| `cargo clippy --all-targets -- -D warnings` | clean (`Finished dev profile`) |
| `cargo test --lib -- --test-threads=4` | `test result: ok. 1222 passed; 0 failed; 18 ignored` |
| `cargo test --lib runtime::refcount::tests -- --test-threads=4` | `9 passed; 0 failed` |
| `bash scripts/adv-probe.sh` | `adv-probe: all 18 probes passed` |

The suite grew by the four tests added here; no test was removed or newly
ignored. The 18 ignored tests are the pre-existing allocator probes, run one
per process by `adv-probe.sh`.

### Test-to-invariant map

| test | invariant |
|---|---|
| `ref_destroying_never_matches_a_live_count` | the sentinel is disjoint from every live count |
| `down_ref_claims_last_reference_then_retires` | `Last` occurs once, installs the sentinel, then `Retired` |
| `up_ref_refuses_zero_and_destroying` | no resurrection; count unchanged on refusal |
| `up_ref_refuses_overflow_without_changing_count` | checked add at `i32::MAX`; no wrap into the sentinel |
| `up_ref_preserves_positive_count_answer` | positive-count answer and increment match the authority |
| `up_ref_down_ref_outcome_classes_are_reachable` | deterministic witness of both outcome classes: `up=1`, `Remaining`, `Last`, sentinel, `up=0`, `Retired` |
| `many_threads_last_release_is_unique` | exactly one `Last`, `N-1` `Remaining`, no spurious `Retired`, sentinel remains |
| `concurrent_increments_and_decrements_conserve_ownership` | no lost increments/decrements; no `Retired` while the base reference is held; base release is the unique `Last` |
| `up_ref_racing_last_release_never_resurrects` | race outcomes are exactly {release wins ⇒ increment refused, sentinel absorbing} or {increment wins ⇒ release non-final, next release `Last`} |
| `ssl_lib::tests::ctx_free_reentrancy_is_defined_noop` | re-entrant `SSL_CTX_free` from a destructor callback is a no-op |
| `ssl_lib::tests::ssl_free_reentrancy_is_defined_noop` | re-entrant `SSL_free` from a destructor callback is a no-op |
| `ssl_sess::tests::session_free_reentrancy_is_defined_noop` | re-entrant `SSL_SESSION_free` from ex-data is a no-op |
| `x509_lu::tests::store_free_reentrancy_is_defined_noop` | re-entrant `X509_STORE_free` from ex-data is a no-op |
| `x509_lu::tests::store_free_from_lookup_free_hook_is_defined_noop` | re-entrant `X509_STORE_free` from the lookup free hook sees the sentinel and is a no-op |
| `x509_lu::tests::store_refcount_is_atomic_under_concurrent_up_ref` | the consumer's `up_ref` path loses no concurrent increments |

## 6. What is not proven

- **No model checking or exhaustive interleaving proof.** No Loom, no Miri,
  no TSan/ASan run for this boundary. The tests are bounded (8 threads;
  1000 iterations; 2000 barrier rounds) and sample scheduler interleavings;
  they do not enumerate them. The linearization arguments in §3 are prose
  proofs, not machine-checked ones.
- **No independent review yet.** The package is `ESTABLISHED` under the §21
  lifecycle; it has not reached `INDEPENDENTLY_CHECKED` or `DISCHARGED`.
- **Ordering adequacy is not proved.** Relaxed is sufficient for the count
  invariant and matches the authority, but no claim is made about publication
  of surrounding object state beyond the existing caller lock discipline.
- **The sentinel is a Rust-only state.** It is `pub(crate)`, lives in the
  existing count field, is never returned across the C ABI, and does not
  change layout. A consumer that reads the opaque structure's internal count
  through a private layout assumption is outside the contract.
- **Liveness, not per-thread ownership.** `up_ref` and `down_ref` cannot
  validate provenance, alignment or liveness. The obligation is that the
  object is live and not retiring; `up_ref` may increment on behalf of a
  caller that already holds the reference (`SSL_dup`), so no per-thread token
  is required. A `down_ref` without a matching acquired reference is an
  over-release and may start destruction early; an `up_ref` on freed storage
  is invalid before the call.
- **Only the free path's re-entrancy is protected.** A callback that calls
  `*_up_ref` during destruction receives `0`; a callback that calls `*_free`
  receives `Retired`. The protocol does not make arbitrary concurrent use of
  an object whose last reference is being released safe, and does not protect
  every callback family beyond the ex-data and lookup-free paths exercised by
  the consumer tests.
- **No claim for other refcount implementations.** `ASN.1`, `ENGINE`, `DSO`
  and the numerous object-local counts are separate mechanisms with their own
  boundaries.
- **No compatibility claim.** The tests exercise the candidate's own module;
  no differential court replayed these races against the authority binary.

## 7. Residual obligations

Retained: the four consumer families must continue to synchronise object
state independently of the count (authority lock discipline); callers must
release each reference exactly once; the storage must remain live until the
destructor runner completes.

Introduced: none. The only new code is test code, and the §17 wording was
corrected to classify the authority's atomic wraparound as defined rather than
UB (the divergence itself is unchanged).
