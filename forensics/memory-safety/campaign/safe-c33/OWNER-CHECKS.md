# OWNER-CHECKS — OB-1: `runtime::owned_buf::OwnedBuf` release-state model

**Status: `SAFETY_DISCHARGED`** (adjudicated; see §7). The check package
below is the independent evidence; the per-caller audit is in
`OWNER-CALLERS.md`.

**Summary of the discharge evidence:**

- §7(1): all 11 unsafe constructors and the `Drop`/`into_raw` transitions have
  explicit seam/extent/ownership contracts. The six former F4 gaps now state
  the exact seam, extent and ownership transfer: `ecx_set_params`
  (`CRYPTO_secure_zalloc`/`keylen`/`CRYPTO_secure_clear_free`), `load_err`
  (secure malloc/`prvkey_bytes`/secure clear), `finish_with_error`
  (`CRYPTO_strdup`/`CRYPTO_malloc`/`BUF_MEM`, plain free), `asn1_write_micalg`
  (NUL-terminated plain string + terminator), `SCT_set0_*` (public C entries:
  caller's `CRYPTO_*` block, ownership transfers, `SCT_free` releases), and
  `OSSL_COMP_CERT_new` (`CRYPTO_memdup`/`len`, plain free).
- §7(2): **455/455** production sites ESTABLISHED, **0 UNATTRIBUTED, 0
  DEFECT** (`OWNER-CALLERS.md`).
- §7(3): every adoption site is inside an `unsafe fn`; safe constructors always
  set `num = allocation len`; the five-boundary model plus the
  `TransitionChangedBound` algebraic check covers all `usize`.
- Independent runs: 1,381 library tests / 22 ignored, 22/22 probes, model
  17/17, ASan on the production paths (owned_buf 13/13, ecx 2/2, x509spki 4/4,
  kdf 1/1) with no address errors.

Retained, non-blocking: caller provenance/alignment/exclusivity remains
source-audited (no safe-Rust caller can reach an unsafe constructor); focused
ASan, no Miri; the unrelated 18-byte `ErrState` thread-local leak (by design,
not an `OwnedBuf` release). These are enumerated residuals, not unknowns.

## 1. Scope

The release-mode invariant of the shared `runtime::owned_buf::OwnedBuf`
(`OB-1`): the four private `Release` arms, the safe allocating constructors, the
`unsafe` adoption constructors, `set_clear`, `set_release_line`, `into_raw`, and
`Drop`.

This check does **not** re-audit the callers. The per-caller provenance, extent,
coordinate and exclusivity witnesses are in `OWNER-CALLERS.md`. The model here
mirrors the type's own transition rules and checks the production state/`Drop`
correspondence; it does not prove a caller's `num <= extent`, provenance, or
single-owner obligation.

Out of scope: allocator behaviour, pointer provenance/alignment, object
initialisation, aliasing, concurrency, panic safety, secret-lifetime cleansing,
timing, and release-build optimisation. Miri is unavailable and was not run; one
focused ASan run was made (§8), but no differential court or whole-library model
checking was run.

## 2. Source identity

| item | value |
|---|---|
| branch | `integrate/safe-c33` |
| HEAD | `a98fd53e901404395f8d6118878875f8bbe831ef` |
| working tree | OB-1 batch uncommitted (`kdf.rs`, `ecx_kmgmt.rs`, `owned_buf.rs`, `x509spki.rs`) plus this check's two new test artefacts and the F4 alias/`# Safety` documentation (`evp/pkey_ctx.rs`, `ec/dh/rsa/pmeth.rs`) |
| `src/runtime/owned_buf.rs` | `a9860dccd93a91ca3b2f8ec23a0480636931de4e4d0902ea19ffc311d8298fda` (1040 lines) |
| `src/runtime/owned_buf_model.rs` | `117b6006f87b19d3ab8f38b5b5c7ffb641e5d9075914b6aa8afe68a6abfbed2a` (1296 lines) |
| `src/evp/kdf.rs` | `1e5a3151e0f321f562151a284496009b4a772bd0c1124eea546ad6f0117470c2` |
| `src/provider/ecx_kmgmt.rs` | `3603d6bb6a6c0b96e9aeb81c5a66cfcfd1b20666bf842ba45b52c497514d2f69` |
| `src/x509/x509spki.rs` | `2f38bf1c4eaaf482174ef037b90a353d7d515cdc12e2516a8d12413df6e84e4f` |
| `src/evp/pkey_ctx.rs` | `823044330e3275726d6e3efeedcee0f96f0e821937596d34a9707c717b92c74c` (F4 alias contract) |
| `src/ec/pmeth.rs` | `a58b54779a24b3d0e78c49f33bed8a0b04d44b967098564db97fb5ee85620a47` (F4 `# Safety`) |
| `src/dh/pmeth.rs` | `a51ebf4815e7ca253ebf0188ebd97d5e41885f2db551964c187c583cba3a9be8` (F4 `# Safety`) |
| `src/rsa/pmeth.rs` | `a81d96ae9e0bec395c1a454a1f34acebd8e8e21af1ad6aaa57f08744f5e4a7fe` (F4 `# Safety`) |
| `OWNER-CALLERS.md` | `ce1d8b44c662654000e6fddca4c6743a096a3b1a6c9a8bacb78b6cfb69c8e2a0` |

The hashes identify the working tree, not a commit. Any later edit to these files
invalidates this receipt until re-run.

## 3. What was added

All additions are test-only:

- `src/runtime/owned_buf_model.rs` — an independently written exhaustive
  state-machine model, the five negative-control rule sets, and the production
  correspondence tests. It is compiled only through
  `#[cfg(test)] #[path = "owned_buf_model.rs"] mod release_model_tests;` in
  `owned_buf.rs`.
- `src/runtime/owned_buf.rs` — a `#[cfg(test)] mod drop_probe` thread-local and
  probe writes inside the existing `Drop` arms. The four release calls and their
  order are unchanged; the probes exist only to make the selected arm observable
  to the correspondence tests.
- This document.

No production release path, allocation size, coordinate, `#[repr(C)]` layout,
exported symbol, or unsafe contract was changed by this check.

## 4. Model

State: `(extent, Mode, live, raw_taken, releases, last_release, force_plain)`,
where `Mode` is one of:

```text
Plain          { file, line }
Cleansed       { num, file, line }
Conditional    { num, clear, file, line }
SecureCleansed { num, file, line }
```

Operations: six per live state — `set_clear(false)`, `set_clear(true)`,
`set_release_line(7)`, `set_release_line(9)`, `into_raw`, `drop`. The exploration
is a reachable-state BFS with state deduplication, so it enumerates the whole
finite abstract state graph, not a sampled set of sequences.

The release selected by the model's `drop` is:

| stored arm | release |
|---|---|
| `Plain` | `Plain { file, line }` |
| `Cleansed { num }` | `Cleansed { num, file, line }` |
| `Conditional { num, clear: true }` | `Cleansed { num, file, line }` |
| `Conditional { num, clear: false }` | `Plain { file, line }` |
| `SecureCleansed { num }` | `SecureCleansed { num, file, line }` |

### Bounds (adjudicator gap 1)

| dimension | values |
|---|---|
| allocation extent | `{0, 1, 4, usize::MAX-1, usize::MAX}` = `{0, 1, 4, 18446744073709551614, 18446744073709551615}` |
| file tokens | `{0xA, 0xB}` |
| constructor line | `{7, 8}` |
| `set_release_line` target | `{7, 9}` |
| adoption cleansing length | per extent, the boundary set `{0, 1, extent-1, extent, extent+1}`, with unrepresentable values omitted and duplicates removed |
| admitted adoption pairs | 15 (across the five extents) |
| rejected adoption pairs (`num > extent`) | 4 representative pairs in the Cleansed probe; 80 start-generation attempts across all four adoption kinds, file/line tokens included |
| start states | **360** (safe plain/cleansed/secure and plain/cleansed/conditional/secure adoptions) |
| Real reachable transitions | **2,340** |
| transition cap | 100,000 (not reached) |

For `extent = usize::MAX`, `extent+1` is not representable; the boundary set is
`{0, 1, usize::MAX-1, usize::MAX}`. The excluded state is still exercised at
`extent = 0, 1, 4` and at `extent = usize::MAX-1` (`num = usize::MAX`).

`adopt_state` now returns `Option<State>` and returns `None` when
`num > extent`; `starts` does not enqueue such a case. The test
`adoption_outside_the_caller_contract_is_rejected` asserts every boundary pair
with `num > extent` is rejected and that no reachable Real state carries
`num > extent`.

### Algebraic preservation

Full `usize` enumeration is impossible, so the invariant is checked over the
transition relation instead of sampled: every operation copies `extent` and the
stored cleansing length unchanged (no operation recomputes either), so
`num <= extent` is preserved for **every** `usize`. `step` reports
`TransitionChangedBound` if a transition changes either field, and the bounds
test asserts the Real graph has none. Combined with the constructor rejection,
the only remaining bounded check is the safe-constructor identity
`num = extent`, which is checked at the five boundary extents.

The model is sequential. It does not model allocation success/failure, allocator
hooks, or interleavings.

## 5. Per-invariant results

| # | invariant | model result | production correspondence |
|---|---|---|---|
| (a) | every safe constructor sets `num = allocation length` | 0 violations over the Real state graph | `safe_constructors_store_the_model_mode`, `secure_safe_constructors_store_the_model_mode` |
| (b) | the release function matches the stored mode exactly | 0 violations | `drop_dispatch_matches_the_model_for_every_mode` (all five release selections) |
| (c) | `num` never exceeds the assumed extent, in the stored arm and in the release call | 0 violations | `NumExceedsExtent` + `TransitionChangedBound`; algebraic preservation over the relation, rejection test for `num > extent` |
| (d) | `into_raw` suppresses `Drop` exactly once; `Drop` otherwise releases exactly once | 0 violations | `into_raw_suppresses_the_release_in_production`, `drop_dispatch_matches_the_model_for_every_mode` |
| (e) | `set_clear` cannot change `num` or a non-`Conditional` mode | 0 violations | `set_clear_matches_the_model`, `set_clear_never_changes_a_non_conditional_mode` |
| (f) | `set_release_line` changes only the line | 0 violations | `set_release_line_changes_only_the_line` |

The Real run printed:

```text
OB-1 model (Real): 360 start states, 2340 transitions
OB-1 model bounds: extents=[0, 1, 4, 18446744073709551614, 18446744073709551615], admitted boundary pairs=15, rejected (num > extent)=4, Real starts=360, Real transitions=2340
OB-1 adoption boundary lengths: [[0, 1], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 18446744073709551613, 18446744073709551614, 18446744073709551615], [0, 1, 18446744073709551614, 18446744073709551615]]
```

and asserted `violations.is_empty()` plus the two bound checks above.

## 6. Negative controls (mutants)

Each mutant is selected through the same `Proto` parameter as the Real rules; the
harness, the start generator and the invariant checks are identical. Mutant (iii)
has the two arms the brief names.

| mutant | injected defect | detected by | observed counts |
|---|---|---|---|
| (i) `SafeCtorOvershoot` | a safe constructor stores `num = extent + 1` | (a), (c) | `SafeCtorNumNotExtent: 32`, `NumExceedsExtent: 368`, 2,628 transitions |
| (ii) `NonConditionalDowngrade` | `set_clear` is accepted on a `Cleansed`/`SecureCleansed` arm and `Drop` is forced to `Plain` | (e), (b) | `SetClearChangedNonConditional: 840`, `ReleaseModeMismatch: 180`, 3,600 transitions |
| (iii-a) `DoubleRelease` | `Drop` increments the release count twice | (d) | `DoubleRelease: 390`, `MultipleReleases: 390`, 2,340 transitions |
| (iii-b) `IntoRawLeak` | `into_raw` releases instead of transferring ownership | (d) | `IntoRawReleased: 390`, 2,340 transitions |

Counts are transition-level violation counts, not distinct states. The four
mutant tests fail unless the corresponding violation is observed.

## 7. Production `Drop` and `into_raw`

The production arms (`src/runtime/owned_buf.rs`, current line numbers) are:

```rust
// L703-709
Release::Plain { file, line } => {
    #[cfg(test)]
    drop_probe::LAST.with(|last| last.set(Some(drop_probe::Call::Plain)));
    unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), file.as_ptr(), line) };
}

// L710-719
Release::Cleansed { num, file, line } => {
    #[cfg(test)]
    drop_probe::LAST.with(|last| last.set(Some(drop_probe::Call::Cleansed { num })));
    unsafe { CRYPTO_clear_free(self.ptr.cast::<c_void>(), num, file.as_ptr(), line) };
}

// L720-749
Release::Conditional { num, clear, file, line } => {
    #[cfg(test)]
    conditional_probe::LAST.with(|last| last.set(Some((clear, num))));
    #[cfg(test)]
    drop_probe::LAST.with(|last| {
        last.set(Some(if clear {
            drop_probe::Call::Cleansed { num }
        } else {
            drop_probe::Call::Plain
        }))
    });
    unsafe {
        if clear {
            CRYPTO_clear_free(self.ptr.cast::<c_void>(), num, file.as_ptr(), line);
        } else {
            CRYPTO_free(self.ptr.cast::<c_void>(), file.as_ptr(), line);
        }
    }
}

// L750-763
Release::SecureCleansed { num, file, line } => {
    #[cfg(test)]
    drop_probe::LAST
        .with(|last| last.set(Some(drop_probe::Call::SecureCleansed { num })));
    unsafe {
        CRYPTO_secure_clear_free(self.ptr.cast::<c_void>(), num, file.as_ptr(), line)
    };
}
```

`into_raw` (`L649-654`) moves the pointer out and suppresses `Drop`:

```rust
pub(crate) fn into_raw(self) -> *mut c_uchar {
    let p = self.ptr;
    core::mem::forget(self);
    p
}
```

The matching is exhaustive over the private enum, so the four arms are the whole
release surface. The only `cfg(test)` additions are the probe writes shown above;
the selected allocator calls are exactly the model's table in §4.

## 7a. F4 ABI contract evidence (adjudicator gap 2)

The full site-by-site enumeration, declaration quotes and line references are in
`OWNER-CALLERS.md` F4. Result summary:

- **No safe fn.** Every contract-only adoption named in `OWNER-CALLERS.md` is
  inside an `unsafe fn`. The three `pkey_*_ctrl` functions
  (`ec/pmeth.rs:525`, `dh/pmeth.rs:278`, `rsa/pmeth.rs:902`) are
  `unsafe extern "C"`; the three `params` helpers
  (`params/mod.rs:2964/3011/3107`) are `pub(crate) unsafe fn`, and every call
  expression is inside an `unsafe fn` or `unsafe extern "C"` set-params
  callback.
- **`params` provenance/extent is stated.** `params/mod.rs:2960-2963` and
  `3102-3106` require `*out` to be NULL or a block of `*out_len` bytes from this
  allocator. Proven.
- **Three `pkey_*_ctrl` contracts are now specified.** `PkeyMethCtrlFn`
  (`evp/pkey_ctx.rs:1751-1776`) documents the provenance, extent and transfer
  obligation for the EC/DH UKM and RSA OAEP-label arms, and each callback's
  `# Safety` (`ec/pmeth.rs:519-524`, `dh/pmeth.rs:272-277`,
  `rsa/pmeth.rs:896-901`) states its arm-specific clause. **Closed at the
  contract-text level.**
- **Other P4 adoptions:** `cms_env::adopt_decrypted_key` states the whole block
  and the produced length (proven); `ecx_set_params`, `finish_with_error`,
  `asn1_write_micalg` and `load_err` state liveness/ownership but omit the
  adopted argument's seam and/or extent; `SCT_set0_*` and `OSSL_COMP_CERT_new`
  state ownership but not the seam. **Retained obligations.**

These gaps are contract-text gaps. No safe-Rust caller was found.

## 8. Gate results (court container)

Commands were run via `docker/openssl-rs-court.sh exec` with
`CARGO_BUILD_JOBS=4`; the test run used `--test-threads=4`.

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | clean (0 diffs) |
| `cargo clippy --all-targets -- -D warnings` | clean (0 errors) |
| `cargo test --lib -- --test-threads=4` | **1381 passed, 0 failed, 22 ignored, 0 filtered** |
| `bash scripts/adv-probe.sh` | **22/22 probes passed** |
| focused `release_model_tests` | 17 passed, 0 failed |

The 22 ignored tests and the 22 adversarial probes are unchanged from the
established baseline; no test was removed, newly ignored, or weakened. The new
count includes the 17 model/correspondence tests added by this check (the
boundary/rejection test is the 17th).

### AddressSanitizer (adjudicator gap 4)

ASan **was run** in the dedicated `docker/openssl-rs-asan.sh` venue, not the
court (the court's `RLIMIT_DATA` is incompatible with ASan's shadow). The image
`openssl-rs-asan:1` was built from `docker/openssl-rs-asan.Dockerfile` with the
pinned sanitizer toolchain `nightly-2026-10-05`, then:

```text
TMPDIR=/work/.asan-tmp CARGO_TARGET_DIR=/work/target-asan \
  RUSTFLAGS="-Zsanitizer=address" CARGO_BUILD_JOBS=4 \
  cargo +nightly-2026-10-05 test -Zbuild-std \
  --target x86_64-unknown-linux-gnu --lib release_model_tests -- --test-threads=1
```

Then the production paths (same venue, flags and toolchain):

```text
runtime::owned_buf::tests
  test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 1390 filtered out; finished in 0.00s
provider::ecx_kmgmt::tests::ecx_set_params_releases
  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 1401 filtered out; finished in 0.00s
x509::x509spki::tests
  test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 1399 filtered out; finished in 0.00s
evp::kdf::tests::the_derived_key_failure_release_is_cleansing
  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1402 filtered out; finished in 0.00s
```

Both secure-heap tests ran under ASan and passed:
`secure_cleansed_block_releases_through_the_secure_allocator`,
`ecx_set_params_releases_the_scalar_through_the_secure_heap`, plus the plain
fallback. No test was skipped.

**LeakSanitizer observation (reported, not hidden).** With default ASan options
the `runtime::owned_buf::tests` binary prints the 13-pass line and then exits 1
with `LeakSanitizer: detected memory leaks` — 18 bytes from
`ErrState::set_debug` ← `raise_integer_overflow` ← `OwnedBuf::new_array` in the
intentional `new_array_overflow_is_none` negative test. The thread-local error
state is deliberately a `thread_local!` value with no `Drop`
(`runtime/err.rs:576-577`, `STATE` @635), so this is retained error-queue
storage, not an `OwnedBuf` release leak. Re-running the same filter with
`ASAN_OPTIONS=detect_leaks=0` gives exactly
`test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 1390 filtered out; finished in 0.00s`
and exit 0, with no address errors. The leak is recorded as a residual
observation for the adjudicator; it is not claimed as clean.

Instrumentation was confirmed on the produced test binary: `nm` reports
`__asan_init` and the `__asan_report_*` family. Two earlier attempts failed for
environmental reasons, not code: `/asan` is on a full 26 GiB overlay (`No space
left on device`), and `/tmp` is on the same overlay. Redirecting the target to
`/work/target-asan` and `TMPDIR` to `/work/.asan-tmp` made the run succeed. The
`target-asan` and `.asan-tmp` scratch directories were removed after the run.

Scope: these are focused test binaries under ASan (17 model tests; 20
production-path tests, including the secure-heap and F1/F2/F3 tests). This is
**not** a whole-library sanitizer run, not a differential court, and carries no
ASan negative control; it does not by itself establish a memory-safety result.

## 9. Limits (what this is not)

1. **The model mirrors the rules; it is not derived from them.** A shared
   misreading of `Drop` would appear in both. The correspondence tests reduce that
   risk by inspecting the actual private `Release` value and observing the actual
   selected arm for every mode, but they do not prove the release body.
2. **Caller obligations are not proved.** `adopt_*` provenance, whole-block
   identity, alignment, initialisation, exclusive ownership, exact coordinates,
   and `num <= extent` are source-level audited in `OWNER-CALLERS.md`; this check
   assumes them to build states. It does not prove them.
3. **No aliasing/initialisation/allocator model.** The harness allocates small
   real blocks through the seam for the correspondence tests, but never models
   overflow, partial initialisation, allocator refusal, double-free detection at
   runtime, or pointer provenance. `new_array`'s checked overflow is covered by
   its own library test, not by this model.
4. **Focused ASan runs; no Miri, differential court, or fuzzing.** Miri is
   unavailable on the court toolchain. ASan covered the 17
   `release_model_tests` and 20 production-path tests (see §8); it is not a
   whole-library or aliasing result, and no sanitizer negative control was run.
   LeakSanitizer reported an 18-byte retained thread-local error string in the
   overflow test; that observation is retained, not dismissed.
5. **No concurrency or reentrancy result.** `OwnedBuf` is not established
   `Send`/`Sync` here; allocator hooks are external callbacks and out of scope.
6. **No release-build or constant-time result.** The probes are `cfg(test)` and
   absent from release builds; the model says nothing about optimisation,
   secret-dependent flow, or cleansing effectiveness in memory.
7. **Finite constructor domain; algebraic transition proof.** Five boundary
   extents, two file tokens and two lines bound the exploration, and adoption
   `num` is sampled at `{0, 1, extent-1, extent, extent+1}`. Arbitrary coordinate
   values and arbitrary intermediate `num` values are not enumerated. The
   `num <= extent` preservation is checked over the transition relation for all
   `usize` (both fields are copied), but the safe-constructor identity
   `num = extent` is only checked at the five extents. Rejection of `num >
   extent` is proven for the boundary representatives and follows from the
   `contract_admits` predicate for any `usize`.
8. **No graduation decision.** Passing this harness does not make OB-1 or any
   consumer `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE` under §7. The retained and
   unknown obligations in `OWNER-CALLERS.md` remain open, and the adjudicator
   decides whether this evidence supports `INDEPENDENTLY_CHECKED`.
9. **Source-reading helpers are not individually modelled.** `new_array`,
   `new_memdup`, `new_strdup` and `new_strndup` also produce the `Plain` arm, so
   the model's `Plain` row covers their release shape; their source-readability,
   NUL-termination and checked-product obligations remain caller contracts and
   are not modelled here.
