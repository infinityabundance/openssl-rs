# Refcount boundary RC-1 — `runtime::refcount`

**Source identity:** `integrate/safe-c33` at
`544222da4` (RC-1 discharge batch; audit began at `c74f87d1b`).
**Boundary ID:** `RC-1`. **Conversion instrument:** bounded deterministic
concurrency tests plus the existing consumer re-entrancy tests. **Independent
check:** Loom model checking of the real generic protocol plus an exhaustive
bounded interleaving model with three mutant negative controls; see
`REFCOUNT-CHECKS.md`. **Caller audit:** every production call site in
`RC1-CALLERS.md` is ESTABLISHED or explicitly N/A, with source witnesses.
**Status:** `SAFETY_DISCHARGED` (adjudicated after the engine-table lifetime and
certificate-duplication blockers were fixed; see §7). Scope: the protocol and
its callers in this crate. **Not** `SAFE_COMPATIBLE`: no dependency-closure or
consumer-compatibility claim is made here. The exported wrappers' ownership
precondition is the C-ABI caller contract, which §7 accepts as an external
contract and which `RC1-CALLERS.md` records per site.

## 1. The object and the contract

`src/runtime/refcount.rs` implements one atomic count shared by the consumer
families listed in §2. The count is the object's existing `AtomicI32` field;
the sentinel `REF_DESTROYING = i32::MIN` is stored in that same field and
changes no `#[repr(C)]` layout or exported signature.

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

### The Rust API is `unsafe` (the ownership obligation is at the call site)

`up_ref` and `down_ref` are `pub(crate) unsafe fn`. Safe crate code cannot call
them, so the previous soundness defect — a safe `*_free` wrapper in safe code
could release a reference it did not own, or `*_up_ref` could acquire on behalf
of nobody — is no longer expressible through these functions. Every call is an
`unsafe { ... }` expression carrying a `// SAFETY:` comment naming the reference
owned or the owner acted for.

`down_ref`'s caller must establish:

- it owns exactly one reference to the object whose count this is;
- the object's storage is live and remains live until the call returns;
- no other caller releases this same reference;
- when the result is `Last`, it is the unique destructor runner and must not
  use the object afterwards (running the destructor body and releasing the
  block are its single responsibility).

`up_ref`'s caller must establish:

- a published positive count exists: the object's constructor has published a count
  of at least one and that publication is visible to the call (a count still being
  initialised, or one already retired, is not a live object);
- it holds a reference, or acts on behalf of an owner whose reference will not be
  released for the duration of the call (as `SSL_dup` does for its caller);
- the object's storage is live for the duration of the call.

`unsafe fn` transfers these proof obligations; it does not discharge them.
The compiler rejects any in-tree safe caller, so what remains is an explicit,
reviewable assertion at each ownership boundary rather than an implicit one.

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

At this revision the shared protocol serves the **four original converted
families** plus the families that have adopted it since. There are **62 direct
`runtime::refcount` calls** in production code; the ENGINE family routes a
further **12 calls** through the shared `engine::eng_lib::{up_ref, down_ref}`
wrapper. That wrapper is one auditable boundary whose callers all hold the
engine's structural reference. The module's own tests are additional call
sites and carry a module-level `SAFETY` note.

### 2.1 The four original families

| family | file | operation |
|---|---|---|
| `SslCtx` | `src/ssl/ssl_lib.rs` | `SSL_CTX_up_ref`, `SSL_CTX_free` |
| `Ssl` | `src/ssl/ssl_lib.rs` | `SSL_up_ref`, `SSL_free`, `SSL_dup` |
| `SslSession` | `src/ssl/ssl_sess.rs` | `SSL_SESSION_up_ref`, `SSL_SESSION_free` |
| `X509Store` | `src/x509/x509_lu.rs` | `X509_STORE_up_ref`, `X509_STORE_free` |

### 2.2 Families added to RC-1

| family / object | file(s) | operation(s) |
|---|---|---|
| ASN.1 refcounted items (`X509`, `X509_CRL`, `X509_REQ`) | `src/asn1/utl.rs`, `src/x509/x509_set.rs`, `src/x509/x_crl.rs` | `*_do_lock` up/down; `X509_up_ref`, `X509_CRL_up_ref` |
| `Engine` | `src/engine/eng_lib.rs`, `eng_init.rs`, `eng_list.rs`, `tb_asnmth.rs` | helper up/down, `engine_free_util`, list add/fetch, `ENGINE_up_ref`, `ENGINE_by_id` |
| `Dso` | `src/dso/mod.rs` | `DSO_up_ref`, `DSO_free` |
| `Bio` | `src/runtime/bio/mod.rs` | `BIO_up_ref`, `BIO_free` |
| `Dh` | `src/dh/object.rs` | `DH_up_ref`, `DH_free` |
| `Dsa` | `src/dsa/object.rs` | `DSA_up_ref`, `DSA_free` |
| `Rsa` | `src/rsa/object.rs` | `RSA_up_ref`, `RSA_free` |
| `EcKey` | `src/ec/key.rs` | `EC_KEY_up_ref`, `EC_KEY_free` |
| `EvpAsymCipher` | `src/evp/asymcipher.rs` | `EVP_ASYM_CIPHER_up_ref`, `_free` |
| `EvpCipher` | `src/evp/cipher.rs` | `EVP_CIPHER_up_ref`, `_free` |
| `EvpMd` | `src/evp/digest.rs` | `EVP_MD_up_ref`, `_free` |
| `EvpKeyExch` | `src/evp/exchange.rs` | `EVP_KEYEXCH_up_ref`, `_free` |
| `EvpKdf` | `src/evp/kdf.rs` | `EVP_KDF_up_ref`, `_free` |
| `EvpKem` | `src/evp/kem.rs` | `EVP_KEM_up_ref`, `_free` |
| `EvpKeyMgmt` | `src/evp/keymgmt.rs` | `EVP_KEYMGMT_up_ref`, `_free` |
| `EvpMac` | `src/evp/mac.rs` | `EVP_MAC_up_ref`, `_free` |
| `EvpPkey` | `src/evp/pkey.rs` | `EVP_PKEY_up_ref`, `_free` |
| `EvpRand`, `EvpRandCtx` | `src/evp/rand.rs` | `EVP_RAND_up_ref`/`_free`, `EVP_RAND_CTX_up_ref`/`_free` |
| `EvpSignature` | `src/evp/signature.rs` | `EVP_SIGNATURE_up_ref`, `_free` |
| `EvpSkeyMgmt`, `EvpSkey` | `src/evp/skeymgmt.rs` | `EVP_SKEYMGMT_up_ref`/`_free`, `EVP_SKEY_up_ref`/`_free` |
| `OsslStoreLoader` (provider loaders only) | `src/store/store_meth.rs` | `OSSL_STORE_LOADER_up_ref`, `_free` |
| `OsslDecoder` | `src/decoder_meth.rs` | `OSSL_DECODER_up_ref`, `_free` |
| `OsslEncoder` | `src/encoder_meth.rs` | `OSSL_ENCODER_up_ref`, `_free` |

Callers of the public wrappers (for example `SSL_new`, `SSL_set_SSL_CTX`,
`SSL_CTX_add_session`, `SSL_get1_session`, `SSL_set_session`,
`ssl_update_cache`, `lookup_sess_in_cache`) inherit the obligations above.
They do not add call sites to RC-1.

### Out of scope: other refcount implementations

The following paths were checked by grep at this revision. They are outside
RC-1 and retain their own contracts.

| path | mechanism at this revision | relation to RC-1 |
|---|---|---|
| `src/ssl/ssl_cert_comp.rs` | local `up_ref`/`down_ref` over `OsslCompCert.references` | independent record count |
| `src/ec/ecx_key.rs` | direct `fetch_add`/`fetch_sub` over `EcxKey.references` | independent key count |
| `src/ec/mult.rs` | direct `fetch_add`/`fetch_sub` over the pre-computation count | independent |
| `src/provider/mod.rs`, `src/provider/activate.rs`, `src/provider/keymgmt.rs`, `src/provider/mac_legacy_kmgmt.rs` | direct provider/data counts | independent provider mechanism |
| `src/runtime/bio/core_bio.rs` | direct `ref_cnt` count | independent core-BIO count |
| `src/context/core_bio.rs`, `src/provider/child.rs` | C callback pointers (`c_bio_up_ref`, `c_prov_up_ref`) | the callback object's contract |
| `src/runtime/rcu.rs` | `users` reader count | not an object reference count |

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

## 4. `i32::MAX`, the zero-count divergence, and §17 classification

### 4.1 `CRYPTO_UP_REF` on a zero count — §17 classification

The authority's `CRYPTO_UP_REF` is an unconditional `fetch_add(1)`: a count
at zero is incremented to one and the public wrapper then reports failure only
because the new value is not greater than one. The failed call therefore
leaves a **positive** count behind. That is the mechanism by which a count
that was never published, or whose last reference was already released, can be
resurrected and a later `CRYPTO_DOWN_REF` can run a second destructor.

This crate reports failure **without changing the count** and requires
`up_ref`'s caller to establish a published positive count (§1).

- **Compatibility:** the public failure answer is preserved — `0` from this
  module, translated to `-1` by the ASN.1 lock path — so a caller that tests
  the answer sees the authority's result.
- **Divergence:** the internal count differs after a failed call (`0` here,
  `1` in the authority). No in-tree caller reads the count after a refusal or
  assumes the increment happened.
- **§17 category:** elimination of a known vulnerability mechanism (premature
  destruction / second teardown), not reproduction of authority behaviour.
  The authority's arithmetic is defined; the use-after-free it enables is not
  reproduced.
- **State effect:** none. RC-1 remains `ESTABLISHED`, not `SAFETY_DISCHARGED`.

### 4.2 `i32::MAX`

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

### 4.3 Over-free

The authority drives the count negative (the atomic arithmetic is defined; the
second teardown it enables is UB) and its `REF_ASSERT_ISNT(i < 0)` diagnostic
is compiled out under `NDEBUG`. This protocol returns `Retired` and performs
no teardown.

## 5. Evidence

Environment: court container, `x86_64`, `rustc 1.98.1`, dev profile,
`CARGO_BUILD_JOBS=4`.

| instrument | result |
|---|---|
| `cargo fmt --all -- --check` | clean (no output) |
| `cargo clippy --all-targets -- -D warnings` | clean (`Finished dev profile`) |
| `cargo check --all-targets` | clean; no safe caller remains (`E0133` would reject one) |
| `cargo test --lib -- --test-threads=4` | `test result: ok. 1338 passed; 0 failed; 22 ignored` |
| `cargo test --lib runtime::refcount::tests -- --test-threads=4` | `9 passed; 0 failed` |
| `bash scripts/adv-probe.sh` | `adv-probe: all 22 probes passed` |

The suite grew; no test was removed or newly ignored. The 22 ignored tests
are the pre-existing allocator probes, run one per process by `adv-probe.sh`.
The compiler check is the structural evidence that no safe in-tree caller of
the refcount API remains. These figures are the conversion-time record; the
independent check re-ran the gates at `56ba89459` (see §5.1), so the suite
count differs from this audit's snapshot without any test being removed.

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

### Independent check (2026-10-18)

The verification package is `REFCOUNT-CHECKS.md`. It runs the *real* generic
protocol bodies over Loom `0.7.2` atomics (`cfg(loom)`) and an exhaustive bounded
interleaving model with three negative controls. Full commands, identities and
residual gaps are in that file; the headline results are:

| instrument | result |
|---|---|
| Loom, four models (base reference, last-release race, sentinel absorption, `i32::MAX`) | `4 passed; 0 failed` |
| Exhaustive model, four scenarios, all micro-step interleavings | real protocol: zero violations; three-actor scenario: 226 executions |
| Mutant (a) non-atomic RMW | detected by `LastWithOutstandingRefs` |
| Mutant (b) unchecked increment without the sentinel guard | detected by `Resurrection` |
| Mutant (c) free on any zero/negative | detected by `MultipleLast` |
| `cargo fmt --all -- --check` / `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --lib -- --test-threads=4` | `1346 passed; 0 failed; 22 ignored` |

## 6. What is not proven

- **Bounded model checking, not a global proof.** Loom now checks the real
  protocol over modelled atomics, and the exhaustive model enumerates every
  micro-step interleaving of its small scenarios. Both are bounded: Loom explores
  its configured models only, and the exhaustive model covers at most three
  actors, two operations per actor, and 128 micro-steps. The conversion tests
  still sample 8 threads / 1000 iterations / 2000 barrier rounds. No Miri, TSan
  or ASan run was performed for this boundary, and the linearization arguments in
  §3 remain prose proofs rather than unbounded machine-checked ones.
- **Independent check exists, with open caller obligations.** The protocol state
  machine is `INDEPENDENTLY_CHECKED`; the caller inventory, each `// SAFETY:`
  assertion and the exported `*_free` wrappers were not re-audited by the check
  package. §7 retains those obligations, which is why the boundary is not
  `SAFETY_DISCHARGED`.
- **`unsafe fn` does not prove the caller's ownership.** Each `// SAFETY:`
  comment is an assertion. The per-site argument — which reference is owned,
  or which owner is acted for — is reviewed prose, not a machine-checked proof;
  a wrong assertion remains a soundness bug the compiler cannot catch. The check
  package did not audit these sites; they must be audited before
  `SAFETY_DISCHARGED`.
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
  is required. The unsafe signature now makes an over-release or a
  use-after-release an explicit caller violation rather than something a safe
  function could cause; the protocol's `Retired` answer is a defined no-op for
  a re-entrant free, not permission to release a reference that was never
  owned.
- **Only the free path's re-entrancy is protected.** A callback that calls
  `*_up_ref` during destruction receives `0`; a callback that calls `*_free`
  receives `Retired`. The protocol does not make arbitrary concurrent use of
  an object whose last reference is being released safe, and does not protect
  every callback family beyond the ex-data and lookup-free paths exercised by
  the consumer tests.
- **No compatibility claim.** The tests exercise the candidate's own module;
  no differential court replayed these races against the authority binary.

## 7. Residual obligations

Retained:

- every consumer family must continue to synchronise object state
  independently of the count (authority lock discipline);
- each caller must release each reference exactly once;
- storage must remain live until the destructor runner completes;
- callers of the internal `engine::eng_lib::{up_ref, down_ref}` wrapper must
  hold the structural reference they pass to it;
- `SSL_dup`'s `up_ref` acts for the caller's existing reference, which the
  caller must hold at the call.

Introduced:

- every production call site now carries a `SAFETY` assertion; these were
audited per site in `RC1-CALLERS.md` (75 ESTABLISHED, 0 UNATTRIBUTED, 1 N/A);
- the API is `unsafe`, so any future safe wrapper must repeat the contract at
  its own boundary rather than exposing a safe-looking call.

## 8. Discharge record

**Adjudication:** `SAFETY_DISCHARGED`, source `544222da4`.

§7 criteria, as adjudicated by an independent reviewer:

1. **Contracts.** `up_ref`/`down_ref` are `unsafe fn` with complete validity
   contracts (published positive count, live storage, exactly one owned
   reference for down-ref, unique `Last` destructor runner, checked
   `i32::MAX`). No unsafe operation in scope lacks a contract.
2. **Precondition establishment.** All 76 production call expressions are
   accounted for in `RC1-CALLERS.md`: 75 ESTABLISHED with a frame or ABI
   witness and 1 explicitly N/A (a test-only `do_lock` arm). Exported
   wrappers state the C-ABI caller contract; §7 accepts an external ABI
   contract. The two former blockers were fixed rather than documented:
   engine operation tables are unregistered from all nine tables under the
   held lock before the list reference is dropped (§17 divergence from the
   authority's latent dangling-table UB), and `ssl_cert_dup` /
   `cert_copy_security` check every up-ref and roll back on refusal.
3. **Safe interface.** No safe Rust function can reach `up_ref`/`down_ref`;
   the compiler enforces the unsafe boundary (`cargo check --all-targets`).

Independent evidence: `REFCOUNT-CHECKS.md` (loom 4/4 on a forced fresh
compile, exhaustive bounded model of up to three actors — 226 interleavings in
the base+2 case — and three mutants each detected).

Retained, non-blocking obligations: the C-ABI caller owns the reference it
frees; object state synchronisation remains the consumer's lock discipline;
the authority's cached-`funct`-without-a-reference arm on a refused init is a
retained authority hazard (reachable only through the crate's added
`i32::MAX` refusal); the model is bounded; no Miri/ASan/differential replay of
the races exists. These are enumerated residuals, not unknowns.

Graduation: **RC-1 is `SAFETY_DISCHARGED`**. It is **not** `SAFE_COMPATIBLE`:
no consumer dependency-closure or current-candidate compatibility claim is made
here.
