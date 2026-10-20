# OB-3 checks — `runtime::bio::owned::{OwnedCtx, RawCtx}` transition model, executable zero-state sweep, focused ASan

**Scope.** This receipt covers OB-3 evidence only: (A) a bounded, test-only
model of the `OwnedCtx`/`RawCtx` transition rules with four negative controls
and production-correspondence tests; (B) an **executable all-zero sweep** of all
130 shared `CtxDestroy` impls together with the cross-reference of the
zero-validity obligation to `DESTRUCTOR-CONTRACTS.md`'s 199 `ESTABLISHED` rows;
and (C) focused AddressSanitizer runs over the production context paths,
including the digest copy test whose method lifetime this batch fixed. It records
evidence; **it does not set a graduation state**. The adjudicator decides.

**Source identity.** Branch `integrate/safe-c33`; the batch is committed on
HEAD `2df614290d26e8d58f5176134cf51ef1ec784abd`, plus the uncommitted OB-3
fixes and the verification additions below. **The hashes in §1 describe the
working tree at commit time, not that HEAD.** Authority for every referenced C
behaviour: `forensics/authorities/src/openssl-3.6.4/` (as cited by the
production sites). All commands ran in the court container
(`docker/openssl-rs-court.sh`) except the ASan runs, which ran in the ASan venue
(`docker/openssl-rs-asan.sh`). No commit, branch or push was made.

**Owner-type boundary under test.** The shared
`runtime::bio::owned::{OwnedCtx, RawCtx}` and its shared `CtxDestroy`
implementations. Module-local `OwnedCtx`/`RawCtx`/`CtxDestroy` copies (`ec/lib.rs`,
`ssl/ssl_lib.rs`, `evp/bio_ok.rs`, the provider families) are out of OB-3, as
recorded in `OB3-CALLERS.md`.

## 1. Changed artefacts and hashes (SHA-256)

These hashes describe the **working tree at commit time on HEAD `2df614290`**,
not that HEAD and not the state before the OB-3 fixes.

| artefact | SHA-256 |
|---|---|
| `src/runtime/bio/owned.rs` (test-only drop probe + model include) | `31012c5d6117580593d7473f4cba26f9815f1b1afc0f9b11947fe776bed41e8d` |
| `src/runtime/bio/owned_ctx_model.rs` (new, test-only) | `4ad24f9d205b3ccc8b4ec8fb36f4babeac22c2f7f5ff77cdcb8544be7b2c946f` |
| `src/runtime/bio/zero_state.rs` (new, test-only zero-state sweep macro) | `1c82e0b868951c9579a2f4cff74ccc493653bff156e47f153ca15e9ba9d1d9be` |
| `src/runtime/bio/mod.rs` (test-only module gate) | `39f34a34de60c0f23eef8e56601037c564c93ccb2599eeb7fe333a746b045434` |
| `src/context/mod.rs` (OB-3 fix) | `f290e01048d7392c38cab20e3d9aeaef1453d6a701767052a00516916d951050` |
| `src/evp/digest.rs` (OB-3 coordinates + ASan UAF test fix) | `a809e7933ac06e7900e53189050eb1253f86d0a1f5ac50f0a6e41f2b7876947d` |
| `src/evp/pkey.rs` (OB-3 attribute release + test) | `0c29f561988d6278e66b16d346df5f1065bf75717e14bcdf45f0238edd131efb` |
| `src/evp/pkey_ctx.rs` (OB-3 coordinates) | `41f72f16249e4798d5cf00aa728740dd4ee344a6304df0fccae2482420a5ac70` |
| `src/evp/pkey_asn1.rs` (release-coordinate correction) | `97f675e04530ce64dfc060fe91969173331f9dae697daa9a4eb6cd661772d634` |
| `src/engine/eng_table.rs` (release-coordinate correction) | `2b0b38806cf5d1ee5f9e3f41818de80e547011d37986805d1ac2e547f70ccdd2` |
| `src/ec/ecdsa.rs` (release-coordinate correction) | `2663df2ae8ce8d1674d758b982fd3535419800591677074848d2d22206018ed8` |
| `src/selftest/indicator.rs` (release-coordinate correction) | `aea757e5d8873a792ab2f68fc9107206b9031d1c22dc4981d38307a79a55b059` |
| `src/selftest/mod.rs` (release-coordinate correction) | `801dfedaacd8bc62bcc296ddd73f4722f484244633f913f038ff5a5cf1b20456` |
| `src/provider/child.rs` (release-coordinate correction) | `e82b723c6ca0ffbfc5945ada3f85f8d545c729958047f12b15f6a026e062e5be` |
| `DESTRUCTOR-CONTRACTS.md` (working-tree edit) | `57b4531496e272f753c4286bd46c32ea16475d5329c7afe20cbc199fba53c9b9` |
| `OB3-CALLERS.md` | `610e672db5991782cd7f5aeec01bfaf2c0f121e64089fdd41a51d00fd1952b7f` |
| `OB3-CHECKS.md` (this receipt; its final hash is recorded in the batch report because inserting it would change the file) | — |

The production `OwnedCtx`/`RawCtx` transition bodies (`zalloc`/`malloc`,
`assume_init`, `into_raw`, `from_raw(_at)`, both `Drop`s) are unchanged. This
batch **does** correct authority coordinates in `evp/pkey_asn1.rs`,
`engine/eng_table.rs`, `ec/ecdsa.rs`, `selftest/indicator.rs`,
`selftest/mod.rs` and `provider/child.rs`, and it changes `digest.rs`'
constructor-failure coordinate. `owned.rs` gains only two `#[cfg(test)]` probe
statements (one at the top of each `Drop`) and the `#[cfg(test)]` model include;
no non-test build contains either.

`zero_state.rs` is likewise `#[cfg(test)]`-only. Each of the 112 source files
that owns a shared impl gains one appended item,
`#[cfg(test)] crate::runtime::bio::zero_state::zero_state_sweep!(...)`, carrying
the file's `Type => test_fn` pairs (130 in total). The macro expands to one
`#[test]` per type; no production item changed in those 112 files.

## 2. Model (Part A)

`src/runtime/bio/owned_ctx_model.rs` is compiled only under `#[cfg(test)]`
through `owned.rs`. States and operations:

- **States:** `Raw` (allocated, not yet a valid `T`), `Owned` (valid `T`),
  `Transferred` (the raw pointer was given to C), `Released`.
- **Starts:** `malloc` and `zalloc` both produce `Raw` (the two origins are kept
  distinct in the state).
- **Operations:** `assume_init` (`Raw -> Owned` only), `into_raw`
  (`Raw|Owned -> Transferred`), `from_raw` (`Transferred -> Owned` in the real
  rules), `Drop` (`Raw|Owned -> Released`).

The model checks:

| id | invariant | enforcement |
|---|---|---|
| (a) | the full destructor (`destroy_body` **and** block release) runs only from `Owned` | `DestructorFromRaw` violation |
| (b) | `RawCtx::Drop` releases only the block, never `destroy_body` | same violation; the raw drop has no body call |
| (c) | every terminal `Drop` path has exactly one block release | `MissingBlockRelease` / `MultipleReleases` |
| (d) | `into_raw` suppresses `Drop`; the `from_raw` reclaim is the only matching release | `IntoRawReleased`; `from_raw` refused outside `Transferred` |
| (e) | no transition from `Released` | every operation from `Released` is refused |
| (f) | `assume_init` cannot be reached twice | `AssumeInitTwice`, plus refusal from `Owned` |

A `Transferred` state with no reclaim is the exported-ownership boundary: the C
caller owns the block, and a failure to reclaim is an application leak, not a
second release. The model therefore requires the reclaim's `Drop` to be the
single release but does not force every finite prefix to end in `Released`.

**Bounds.** Two origins × the product of `Phase` (4) and the bounded counters
`destroys`, `releases`, `assume_inits` (each 0..=2; the invariants only
distinguish 0, 1 and "more than one") is at most 144 states. The real-rules
exploration reached **2 start states, 64 transitions, 46 refusals** and no
violation. The exploration aborts at `MAX_TRANSITIONS = 100_000`; the real-rules
run is also asserted to stay below that bound.

**Model and correspondence tests.** 14 tests pass:

- `exhaustive_real_rules_satisfy_every_invariant`
- `exhaustive_real_rules_stay_inside_the_declared_bound`
- `a_released_state_admits_no_transition` (e)
- `assume_init_is_admitted_only_from_raw` (f)
- `into_raw_transfers_and_the_reclaim_is_the_matching_release` (c)/(d)
- four mutant-detection tests (below)
- six production-correspondence tests (below)

### Production bodies the model mirrors

`src/runtime/bio/owned.rs:159` (`OwnedCtx::into_raw`):

```rust
pub(crate) fn into_raw(self) -> *mut T {
    let p = self.ptr.as_ptr();
    core::mem::forget(self);
    p
}
```

`src/runtime/bio/owned.rs:201` (`OwnedCtx::Drop`):

```rust
fn drop(&mut self) {
    #[cfg(test)]
    drop_probe::LAST.with(|last| last.set(Some(drop_probe::Call::Owned)));
    // SAFETY: `self.ptr` is the block this handle allocated (or `from_raw` reclaimed) and this
    // is its single release; `Drop` runs once, and `destroy_body` is the authority's own
    // `*_free` body.
    unsafe {
        T::destroy_body(self.ptr.as_ptr());
        CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), self.file.as_ptr(), self.line);
    }
}
```

`src/runtime/bio/owned.rs:307` (`RawCtx::into_raw`) is the same `mem::forget`
transfer on the `MaybeUninit<T>` pointer. `src/runtime/bio/owned.rs:320`
(`RawCtx::assume_init`) consumes the `RawCtx` with `mem::forget(self)` and
constructs the `OwnedCtx` from the same pointer and release coordinates.
`src/runtime/bio/owned.rs:332` (`RawCtx::Drop`) calls `CRYPTO_free` only.

### Correspondence tests (new)

The six tests observe the production bodies with a test-only thread-local
`drop_probe` (which `Drop` ran) and a thread-local `destroy_body` counter:

| test | rule |
|---|---|
| `acquisition_starts_raw_and_raw_drop_releases_the_block_alone` | `malloc`/`zalloc -> Raw`; `RawCtx::Drop` never runs the body |
| `assume_init_moves_to_owned_and_drop_runs_the_body_once` | `assume_init -> Owned`; `OwnedCtx::Drop` runs the body once |
| `raw_into_raw_suppresses_drop_and_from_raw_reclaims_once` | `into_raw` suppresses `RawCtx::Drop`; `from_raw`+`Drop` runs the body once |
| `owned_into_raw_suppresses_the_full_destructor` | `into_raw` suppresses the full `OwnedCtx` destructor |
| `from_raw_null_is_no_owner` | `from_raw(NULL) -> None` |
| (existing `adv_partial_init_tests`) | raw drop has no body; owned drop has one; negative-control canary is live |

## 3. Mutants (negative controls)

Each mutant is a deliberately broken rule; the real rules remain violation-free.

| mutant | modelled defect | result |
|---|---|---|
| (i) `DestroyFromRaw` | `RawCtx::Drop` runs `destroy_body` | **56 transitions, 2 `DestructorFromRaw`** |
| (ii) `DoubleBlockRelease` | `Drop` releases the block twice | **64 transitions, 6 `MultipleReleases`** |
| (iii) `FromRawUntransferred` | `from_raw` admits `Raw`/`Released` | **184 transitions, 30 `FromRawNotTransferred`** |
| (iv) `IntoRawReleases` | `into_raw` releases instead of transferring | **112 transitions, 8 `IntoRawReleased`** |

Mutant (iii) covers both a never-validated `Raw` block and a resurrected
`Released` block. Mutant (i) is the exact defect the real `RawCtx::Drop` avoids:
`RawCtx` never forms a reference to `T` and never calls `destroy_body`.

## 4. Zero-validity cross-reference

`DESTRUCTOR-CONTRACTS.md` records **199 audited implementations: 199
`ESTABLISHED`, 0 `CONTRACTED`, 0 `DISCHARGED`**. Of those, §2's 136
`CtxDestroy` rows correspond to the 130 production shared-trait impls in
`OB3-CALLERS.md` plus the 6 module-local `ec/lib.rs`/`ssl/ssl_lib.rs` impls.
The "zero witness" column of each row is the source evidence that an all-zero
block is a valid value for which the destructor body is sound.

The model **assumes** `T: CtxDestroy` implementer obligation (b) ("an all-zero
block is a valid `Self`, and `destroy_body` and every owner operation are sound
for it"). It does not prove obligation (b) for any production type; the
all-zero sweep below is the independent runtime check, and nothing here promotes
the impls beyond evidence.

**Executable all-zero sweep — 130/130 shared impls.**

`src/runtime/bio/zero_state.rs` (test-only) defines `zero_state_sweep!`, invoked
once at the end of each of the 112 files that owns shared impls. It expands to
one `#[test]` per `Type => test_fn` pair. Each test:

1. allocates `size_of::<T>()` zeroed bytes with `CRYPTO_zalloc`;
2. calls `T::destroy_body` on that all-zero value; and
3. releases the block with `CRYPTO_free`.

No constructor and no owner `Drop` runs, so this is exactly obligation (b), not
the `OwnedCtx`/`RawCtx` machinery. **Coverage 130/130; 130 passed, 0 failed.**
No shared impl was found non-zero-valid, so no `destroy_body` was changed in
this batch.

The previously recorded fresh-constructor tests remain supplementary evidence
for constructor/reset paths (they are not all-zero executions):

| type | test | what it executes |
|---|---|---|
| `EvpMdCtx` | `evp::digest::tests::a_fresh_context_is_all_zeros_and_says_so` | `EVP_MD_CTX_new` all-zero state, then `EVP_MD_CTX_free` |
| `X509StoreCtx` | `x509::x509_vfy::tests::a_new_context_is_zeroed` | zeroed `X509_STORE_CTX_new`, cleanup twice, free |
| `EvpCipherCtx` | `evp::cipher_ctx::tests::a_fresh_context_answers_every_accessors_empty_arm` | fresh constructor state (note `iv_len = -1`, so not the all-zero state), `Drop` guard |
| `OsslDecoderInstance` | `decoder_lib::tests::a_fresh_context_has_an_empty_chain_and_round_trips_its_setters` | `OSSL_DECODER_CTX_new` + free |
| `OsslEncoderInstance` | `encoder_lib::tests::a_fresh_context_has_no_encoders` | `OSSL_ENCODER_CTX_new` + free |
| `EvpPkeyCtx` | `evp::pkey_ctx::tests::an_owned_ctx` callers | safe `OwnedCtx::zalloc_at` zero state + `EVP_PKEY_CTX_free` |

**Excluded from the sweep (8 impls outside the 130):**

| impl(s) | owning file(s) | reason |
|---|---|---|
| `EcGroup`, `EcPoint` | `src/ec/lib.rs` | implement the module-local `CtxDestroy` (`ec/lib.rs:123`), a different trait |
| `Cert`, `SslCtx`, `Ssl`, `DanetlsRecord` | `src/ssl/ssl_lib.rs` | implement the module-local `CtxDestroy` (`ssl/ssl_lib.rs:567`) |
| `ProbeCtx` | `src/runtime/bio/owned.rs:413`, `src/runtime/bio/owned_ctx_model.rs:457` | test-only probe types, already inside `#[cfg(test)]` |

The 130 shared impls, 6 module-local impls and 2 test-only ProbeCtx impls are the 138 `unsafe impl CtxDestroy` sites in
`src/`. The deterministic all-zero negative controls for `EcGroup`/`EcPoint`
(`ec/lib.rs:3116`) and `ProvAesSivCtx`/`ProvAesGcmSivCtx`
(`provider/cipher.rs:22833`) are module-local families and remain outside OB-3.

`EvpPkey`'s new `attributes` release is exercised by
`evp::pkey::tests::an_attribute_is_released_exactly_once_with_the_key`; it is a
constructed-state release test, not a zero-validity witness.

## 5. Focused ASan (Part C)

**Venue.** `docker/openssl-rs-asan.sh`, container `openssl-rs-asan`.
Toolchain: `rustc 1.101.0-nightly (282215592 2026-10-04)`,
`cargo 1.101.0-nightly (f3865b2a4 2026-09-29)`, Debian clang 14.0.6,
`llvm-symbolizer` present, no system `openssl` CLI. Build:

```
RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=1"
CC=/asan/bin/asan-cc AR=ar
ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:symbolize=1"
CARGO_TARGET_DIR=/work/target/asan-ob3 CARGO_BUILD_JOBS=4
cargo +nightly-2026-10-05 test -Zbuild-std --lib --target x86_64-unknown-linux-gnu
```

`/work/target/asan-ob3` is on the host bind mount, not the container's 26 GiB
overlay (which is 99% full).

**Instrumentation evidence.** Test binary
`/work/target/asan-ob3/x86_64-unknown-linux-gnu/debug/build/openssl-rs/e5ce922b5aa27603/out/openssl_rs-e5ce922b5aa27603`,
size `125,861,872` bytes, SHA-256
`ec9aa560a0d83d34fc37fdbb4d54fe4413916b4eac76aa62a5de854acb5d95bb`,
`nm` finds **515** `__asan*` symbols. The venue canary
(`/asan/bin/asan_canary`, built from `forensics/tools/asan_canary.c`) produced
`heap-use-after-free` at `asan_canary.c:31`, so the instrument fires in this
venue.

| focused filter | exercised production path | result |
|---|---|---|
| `runtime::bio::owned` | `OwnedCtx`/`RawCtx` alloc, `assume_init`, `into_raw`, `from_raw`, both `Drop`s, model + correspondence | **18 passed**, no ASan report |
| `evp::pkey::tests::an_attribute_is_released_exactly_once_with_the_key` | `EVP_PKEY_free` → `sk_X509_ATTRIBUTE_pop_free` → `X509_ATTRIBUTE_free` | **1 passed**, no ASan report |
| `evp::pkey_ctx` | `EVP_PKEY_CTX` allocation/free, op-cache and propquery teardown | **12 passed**, no ASan report |
| `context::tests` | `OSSL_LIB_CTX_new`/`OSSL_LIB_CTX_free`, slot lifecycle | **4 passed**, no ASan report |
| `zero_state_sweep` | all 130 shared `CtxDestroy` bodies on an all-zero block | **130 passed**, no ASan report |
| `evp::digest::tests` (no skip) | `EVP_MD_CTX_new`/copy/free, `EvpMd` release, legacy `md_data` | **26 passed**, no ASan report |

`ASAN_OPTIONS` for every row was
`allocator_may_return_null=1:detect_leaks=0:symbolize=1`.

**`evp::digest` ASan status (one venue policy, one fixed defect):**

1. The deliberate `SIZE_MAX` allocation in
   `a_legacy_copy_allocation_failure_does_not_run_cleanup` needs
   `allocator_may_return_null=1`; without it ASan aborts with
   `allocation-size-too-big` before the crate can observe the NULL. This is a
   venue policy for an intentionally huge request, not an OB-3 defect.
2. The heap-use-after-free previously reported by
   `a_refused_copy_leaves_the_destination_unchanged` is **fixed**. The test set
   `(*src).digest = fake` and then freed `fake` before `EVP_MD_CTX_free(src)`,
   so the reset read the dangling method at `cleanup_old_md_data`
   (`digest.rs:1729`). The test now releases `src` and `dst` before
   `EVP_MD_free(fake)`, which preserves its intent (the refused copy leaves
   `dst.flags` and `dst.digest` untouched) and makes the context outlive its
   method. The full `evp::digest` module now runs clean under ASan, so the
   earlier STOP on a module-wide digest claim is cleared.

## 6. Ordinary gate (court container)

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --all-targets -- -D warnings` | pass |
| `cargo test --lib -- --test-threads=4` | **1536 passed; 0 failed; 22 ignored** |
| `scripts/adv-probe.sh` (one process per probe) | **22/22 passed** |

No test was newly ignored and none was removed. The OB-2 receipt recorded 1391
library tests; the uncommitted OB-3 fixes add 1 `EvpPkey` attribute-release test
and the model/correspondence tests reached 1406. This batch adds the 130
executable zero-state tests, for 1536. The ordinary suite and the adversarial
probes were run with `CARGO_TARGET_DIR=/work/target/ob3-gate`, on the host bind
mount; `CARGO_BUILD_JOBS=4` and `--test-threads=4` were used for both.

**ASan evidence identity.** The ASan runs in §5 were made on the
working tree before the 2026-10-18 coordinate-only corrections. Their test
binary hash is retained as `ec9aa560...`; it is **not** a hash of the final tree.
They remain evidence for the ownership transitions, not for the final
coordinates. The executable gate for the final tree is §6 (including the 22
adversarial probes).

## 7. Honest limits

- The model is a **finite abstraction**: 2 origins × 4 phases × bounded
  counters, 64 real-rule transitions. It does not model pointers, allocator
  identity, `CRYPTO_set_mem_functions` hooks, provenance, concurrency, panic
  unwinding, or compiler optimisations.
- Zero-validity is now **executed** for all 130 shared impls: each
  `destroy_body` runs on an all-zero block, ordinarily and under ASan. It is
  still not model-checked, and ASan cannot detect an invalid Rust *value* (for
  example an invalid enum discriminant) that no memory access exposes; that
  remains a Miri/contract-review question. The model still assumes
  `T: CtxDestroy` obligation (b) rather than proving it for any type.
- Miri (Stacked Borrows and Tree Borrows) ran on the focused owner-transition
  and `EvpMd` zero-state tests, one at a time, and passed; §8.3 records the
  exact commands, results and the scope limitation (it is not a whole-crate
  Miri run and does not cover the C ABI or allocator hooks).
- No differential court against the authority was run for these transitions.
- ASan covered only the focused filters above, not the whole crate or
  downstream consumers. Leak detection was disabled (`detect_leaks=0`);
  `allocator_may_return_null=1` was required for the digest module's deliberate
  `SIZE_MAX` request.
- The `drop_probe` and the model are `#[cfg(test)]`-only. The production
  `Drop`/`into_raw`/`assume_init` bodies are unchanged.
- This receipt records evidence only. **It does not set an OB-3 graduation
  state**; `SAFE_COMPATIBLE` and `SAFETY_DISCHARGED` remain the adjudicator's
  decisions under `AGENTS.md` §7.

## 8. Independent re-audit (2026-10-18)

Read-only independent pass over HEAD `2df614290` plus the uncommitted OB-3 tree. No
`src/` edit, no commit and no push. The previous document's assertions were not
accepted; coordinates and fields were re-derived from source.

### 8.1 Production caller sample

48 production coordinates were re-derived (6 `assume_init`, 10 `from_raw`, 8 `from_raw_at`, 4 `malloc`, 4 `malloc_at`, 8 `into_raw`, 8 `set_release_line`). Operation/provenance witnesses: **no unreproducible production row**. Release coordinates are `LINE_FREE_STACK_FAIL`, `83`, `LINE_FREE_CTX`, `L_PCGBL_FREE`, `135`, `LINE_FREE_HASH_PUSH`, `LINE_FREE_OBJECT_DUP`, `2704`; the five named constants are symbolic release sites and the three numeric literals are direct coordinates. The earlier automated check that reported five missing release coordinates was rejecting symbolic constants, not a source defect. The follow-up re-derivation of **every** production reclaim (121 rows) is `OB3-CALLERS.md` §9: 76 `VERIFIED`, 45 `UNVERIFIED` with reasons.

### 8.2 External ABI entries

A whole-tree scan of files importing the shared `runtime::bio::owned` owners
found C-ABI definitions (`extern "C"`) whose bodies use a shared transition.
187 entries were found; the three that initially lacked a same-file structural
witness are now **discharged** by a constructor/release pairing read from source
and checked against the authority:

| ABI entry | constructor / allocation | publication | matching release |
|---|---|---|---|
| `EVP_KEYEXCH_free` (`src/evp/exchange.rs:490`) | `evp_keyexch_new` (`:339`) `CRYPTO_zalloc(size, exchange.c, 34)` | `evp_keyexch_from_algorithm` returns `exchange` (the `into_raw` is `evp_keyexch_new`'s return) | `OwnedCtx::from_raw_at(exchange, exchange.c, 173)` at `:505`; authority `exchange.c:173` `OPENSSL_free(exchange)` |
| `EVP_PKEY_asn1_new` (`src/evp/pkey_asn1.rs:598`) | `OwnedCtx::<EvpPkeyAsn1Method>::zalloc()` at `:608` (`ameth_lib.c:227`) | `ameth.into_raw()` at `:641` | `EVP_PKEY_asn1_free` (`:699`) gates on `ASN1_PKEY_DYNAMIC`, calls `destroy_body` at `:711` (member frees `ameth_lib.c:277`/`:278`) and `CRYPTO_free(ameth, …, LINE_FREE_AMETH)` at `:712` (`ameth_lib.c:279`) |
| `OSSL_STORE_LOADER_new` (`src/store/store_register.rs:251`) | `OwnedCtx::<OsslStoreLoader>::zalloc()` at `:265` (`store_register.c:46`) | `res.into_raw()` at `:275` | `OSSL_STORE_LOADER_free` (`src/store/store_meth.rs:211`) calls `OwnedCtx::<OsslStoreLoader>::from_raw(loader)` at `:232`; the legacy loader has `prov == NULL`, so this is the unique release (`store_meth.c:39`) |

For the provider-created loader, `new_loader` (`store_meth.rs:244`) uses the
same `OwnedCtx::<OsslStoreLoader>::zalloc()` owner (`:244`), publishes with
`loader.into_raw()` (`:258`), and is reclaimed by the same
`OSSL_STORE_LOADER_free` release; only its `prov`/`refcnt` initialisation
differs. No structural item is retained.

### 8.3 Miri

**Miri ran, and the focused owner-transition tests pass under both aliasing
models.** The earlier "rustup: not found" result was a PATH problem, not a
missing toolchain: the court image has Rust at `/usr/local/cargo/bin`, and Miri
is installed in the `nightly-2026-10-01` toolchain under
`/work/.phase25-rustup`. Toolchain: `miri 0.1.0 (21b707e3f9 2026-09-30)`.
The requested `nightly-2026-10-05` is not present in either container; the
pinned available Miri is 2026-10-01, and that is the toolchain recorded here.

Commands (court container, `CARGO_BUILD_JOBS=4`,
`CARGO_TARGET_DIR=/work/target/miri-ob3`, one run at a time):

```
export PATH=/usr/local/cargo/bin:$PATH \
       RUSTUP_HOME=/work/.phase25-rustup CARGO_HOME=/usr/local/cargo
cargo +nightly-2026-10-01 miri test --lib \
  runtime::bio::owned::release_model_tests -- --test-threads=1
```

| run | flags | result |
|---|---|---|
| owner-transition model, Stacked Borrows (default) | none | **14 passed, 0 failed** |
| owner-transition model, Tree Borrows | `MIRIFLAGS=-Zmiri-tree-borrows` | **14 passed, 0 failed** |
| zero-state subset, Stacked Borrows | none, filter `zero_state_sweep_evp_md` | **2 passed, 0 failed** |
| zero-state subset, Tree Borrows | `MIRIFLAGS=-Zmiri-tree-borrows`, same filter | **2 passed, 0 failed** |

`-Zmiri-stacked-borrows` is not an accepted flag in this Miri
(`error: unknown unstable option: miri-stacked-borrows`); Stacked Borrows is
the default and was run without a flag. The tests are the model/correspondence
suite (`runtime::bio::owned::release_model_tests`) and the `EvpMd`/`EvpMdCtx`
zero-state pair. **Scope limitation:** Miri covers these Rust-level owner
transitions and zero-state destructor executions only. It does not cover the C
ABI, the authority binary, `CRYPTO_set_mem_functions` hooks, concurrency, or
every production path; it is not a whole-crate Miri result.

### 8.4 Per-type zero validity

All 130 shared `CtxDestroy` types were inspected field-by-field. **No zero-validity defect.** 36 suspicious fields were `Option<unsafe extern "C" fn(...)>` or `Option<&'static ...>`; all-zero is `None` under the guaranteed null-pointer niche and is a valid value. No bare `Vec`/`Box`/`String`/`NonNull`/`NonZero*`/reference/function-pointer field was found. The executable sweep is necessary but not sufficient; this field inspection is the independent check.

### 8.5 Reconciled CtxDestroy count

A grep of `src/**/*.rs` for `impl ... CtxDestroy for` returns **138**:
**130** production shared-trait impls, **6** module-local impls (`ec/lib.rs` 2,
`ssl/ssl_lib.rs` 4), and **2** test-only `ProbeCtx` impls
(`runtime/bio/owned.rs`, `runtime/bio/owned_ctx_model.rs`). The earlier
`137 = 130+6+1` and `138 = 130+8` statements were both wrong in their
breakdown; the true split is **130+6+2 = 138**. The `130 swept impls plus
these 8` sentence in §2 was corrected accordingly. The 136 rows in
`DESTRUCTOR-CONTRACTS.md` remain 130 shared + 6 module-local (test-only impls
excluded).

