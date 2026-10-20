# OB-2 checks — `OwnedStr` transition model, contract closure, focused ASan

**Scope.** This receipt covers (A) the three previously `UNATTRIBUTED` OB-2
call sites, now given explicit contracts; (B) a bounded, test-only
`OwnedStr` ownership-transition model with three negative controls and
production-correspondence tests; and (C) focused AddressSanitizer runs over the
production `OwnedStr` paths. It records evidence; the adjudicator's disposition
is recorded below.

**Source identity.** Candidate `integrate/safe-c33` at
`a0c8a01e7e3fa771c65865a0b858b95fa56c0713`, plus the uncommitted worktree
changes below. Authority for every quoted C behaviour:
`forensics/authorities/src/openssl-3.6.5/`.

**Adjudicator verdict.** `SAFETY_DISCHARGED`, scoped to `OwnedStr` only. The
candidate source identity for that verdict is the one immediately above plus
this worktree; the verdict does not extend to consumers, caller families, or
the excluded row/static hazards in §7.

## 1. Changed artefacts and hashes (SHA-256)

| artefact | SHA-256 |
|---|---|
| `src/runtime/err.rs` (contract docs) | `cef2f9d503717ae6b9d072dd5aa4b3bb60bf659541e176f8ccb41e7fd4e6cdd0` |
| `src/x509/v3_lib.rs` (`i2s` type + `X509V3_EXT_add` contract) | `f9a83269452ee21d31781559761c3810df1897e0d1bd4728d427841e4dd5f7d9` |
| `src/x509/v3_prn.rs` (contract comment, SAFETY, focused test) | `cb2e79a36a7a638093c419c426892b664ffe2b84a82eaab337b496bb35166e9e` |
| `src/rand/rand_lib.rs` (`random_set_string` contract) | `e717ab2990c471a3bc1b899bfe7e8b92ddb1cc9480234fa42a8046fc03a9b78d` |
| `src/runtime/owned_str.rs` (test probe + model include) | `c6c154997a4018fb28f34643cb1b8e48a4bd3bbfed367f44371ffd6b82679db2` |
| `src/runtime/owned_str_model.rs` (new, test-only) | `d15c51d11e83cf5ca3aeb96c6cb918ed3a2ad73f40e2fb78009acf6572e9dad4` |
| `OB2-CALLERS.md` | `e558e09b6ef141968680cefcfc770576b59d570a5eb67c8de38fe2a9528148c9` |
| `git diff` of tracked `src/` (excludes the new files) | `bbbad530cfa3012ea65f08a781878c4493f548ba9810daf1d42a3dd10a9d3d18` |

Authority sources quoted at the sites:

| authority file | SHA-256 |
|---|---|
| `crypto/err/err.c` | `93bbd6c00f8d8313d5cc5b2cd20ce7efef04e135757d01d37e720c3712d43d4e` |
| `crypto/err/err_local.h` | `591ec3bec62947239774972d57468f35a850dcd88883e5a147d638b5353b310b` |
| `include/openssl/err.h.in` | `a1af86fbb51488cffe1529bceaa980cf29e242310a70c557512867a8ee479a9c` |
| `crypto/x509/v3_lib.c` | `6f1092daad6075488c3bcfbb9aa40204c761fea03f7e76e3f75c5da7b4f682b0` |
| `crypto/x509/v3_prn.c` | `c3ff2c745575179b00b2f0e5e3930899bcf981f7de8e4db91de2cc692515bca0` |
| `include/openssl/x509v3.h.in` | `b503ca4a0d271274e56bfdd888c929ce2af9ffaddebf2bde4fa7e7f15ebc764e` |
| `doc/man3/s2i_ASN1_IA5STRING.pod` | `b28de2551bd189ec4e4b2b93f378717dae5f2341b441f08132c5a56d36c49b23` |

## 2. Contract closure (Part A)

All three sites are now `ESTABLISHED` in `OB2-CALLERS.md`; the row counts are
131/131 (including the four test-only correspondence-test sites added in this
batch). The text added is a caller contract, not a runtime check.

1. **`ERR_set_error_data` and the `err_data` slot**
   (`src/runtime/err.rs`). The exported `unsafe extern "C"` entry and the
   internal `clear_data`/`set_data` pair now state: with `ERR_TXT_MALLOCED`,
   `data` is a whole `CRYPTO_malloc`/`CRYPTO_strdup` block, NUL-terminated with
   a `strlen+1` C-string extent (exact for the strdup route), exclusively owned
   by the error state, released exactly once by ERR; without the flag it is
   borrowed and must outlive the entry. Authority: the `ERR_TXT_MALLOCED`
   definition (`err.h.in:52`), the two `OPENSSL_free` arms (`err_local.h:25,79`),
   and the ownership comment plus `strlen(data)+1` estimate
   (`err.c:803-807`).
2. **`X509V3ExtI2s` / `X509V3_EXT_add` / `X509V3_EXT_print`**
   (`src/x509/v3_lib.rs`, `src/x509/v3_prn.rs`). An application-supplied `i2s`
   must return the base of one whole `OPENSSL_malloc`/`CRYPTO_strdup` block,
   NUL-terminated within a `strlen+1` C-string extent; ownership transfers to
   the extension machinery and the print path releases it once. Authority:
   `X509V3_EXT_print` assigns the callback result to `char *value` and the
   `err:` label runs `OPENSSL_free(value)` (`v3_prn.c:106,130`); the
   `i2s_ASN1_*` docs say "It is the caller's responsibility to free the returned
   string" (`s2i_ASN1_IA5STRING.pod`); `X509V3_EXT_add` only pushes the caller's
   row (`v3_lib.c:25-37`).
3. **`random_set_string`** (`src/rand/rand_lib.rs`). Its `# Safety` now states
   that `*p` is NULL or an exclusively owned `CRYPTO_strdup` block released
   once, and lists all twelve call sites: four in `RAND_set_DRBG_type`, two in
   `RAND_set_seed_source_type`, six in `random_conf_init`, all addresses of
   `RandGlobal` fields installed by this helper / `set_random_provider_name` or
   zero-initialised, and released by `RandGlobal::destroy_body` or this helper.

In-tree `i2s` implementations were checked: the standard casts in
`v3_int.rs`, `v3_enum.rs`, `v3_skid.rs`, `v3_audit_id.rs`, and the custom
`v3_soa_id.rs`, `v3_ind_iss.rs`, `v3_no_ass.rs`, `v3_no_rev_avail.rs`,
`v3_group_ac.rs`, `ct/ct_x509v3.rs` all return `CRYPTO_strdup`/`CRYPTO_malloc`
blocks. No in-tree caller passes a borrowed `i2s` result.

## 3. Model (Part B) — bounds and results

`src/runtime/owned_str_model.rs` is compiled only under `#[cfg(test)]` through
`owned_str.rs`. States: `Absent` (`adopt(NULL)` → `None`), `Null`
(`adopt_nullable(NULL)`), `Owned`, `Released`, `Transferred`; the block origin
(`Absent`/`Null`/`Block`) distinguishes a real release from `free(NULL)`.

**Bounds.** Four adoption starts × every `{IntoRaw, Drop}` sequence of length
`0..=4` (31 sequences per start) = **124 traces / 392 transitions**. The real
rules produce **0** invariant violations. The model abstracts pointers,
allocator behaviour, provenance, concurrency and memory safety; it is not a
proof and does not run Miri.

| negative control | modelled defect | detector result |
|---|---|---|
| `DoubleRelease` | `Drop` releases the block twice | `MultipleReleases > 0` |
| `IntoRawReleases` | `into_raw` releases instead of transferring | `IntoRawReleased > 0` |
| `NullReleaseCounted` | `free(NULL)` counted as a real release | `NullReleaseCounted > 0` |

The explicit `real_rules_never_release_after_transfer_or_twice` test also
confirms the real rules keep `releases == 0` after `into_raw` and exactly `1`
after a single `Drop`, including a second `Drop` attempt.

**Production correspondence.** The transitions the model mirrors are, in
`src/runtime/owned_str.rs`:

```rust
pub(crate) fn into_raw(self) -> *mut c_char {
    let p = self.ptr;
    core::mem::forget(self);
    p
}

// Drop:
unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file.as_ptr(), self.line) };
```

`into_raw` is the transfer (`mem::forget` suppresses `Drop`); `Drop` is the
single plain `CRYPTO_free`, including for a NULL handle, where the seam treats
it as the authority's no-op `free(NULL)`. `owned_str.rs` also has a test-only
thread-local `drop_probe` set immediately before that call, so the
correspondence tests observe whether `Drop` ran and whether its pointer was
NULL; the production release itself is unchanged. Tests compare the model against
production for: `adopt(NULL)` → `None`; `adopt_nullable(NULL)` → one
`free(NULL)` and zero real releases; non-NULL adoption → exactly one real
release; `into_raw` → no `Drop` and zero releases (the raw pointer is then
freed manually once). Test result: **9 model/correspondence tests pass**.

## 4. Focused ASan (Part C)

**Venue.** `docker/openssl-rs-asan.sh` (cgroup-capped ASan venue, no
`RLIMIT_DATA`, `no-new-privileges`, no system `openssl` CLI). Toolchain:
`rustc 1.101.0-nightly (282215592 2026-10-04)`, `cargo 1.101.0-nightly
(f3865b2a4 2026-09-29)`, Debian clang 14.0.6. Build:

```
RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=1"
cargo +nightly-2026-10-05 test -Zbuild-std --lib --target x86_64-unknown-linux-gnu
CC=/asan/bin/asan-cc AR=ar ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=0
CARGO_TARGET_DIR=/work/target/asan-focus CARGO_BUILD_JOBS=4
-- --test-threads=4 <filter>
```

The container's 26 GiB overlay was full, so the build target was placed on the
host bind mount at `target/asan-focus` (inside the ignored `target/` tree); the
normal court target was not reused.

**Instrumentation evidence.** Test binary
`/work/target/asan-focus/x86_64-unknown-linux-gnu/debug/build/openssl-rs/e5ce922b5aa27603/out/openssl_rs-e5ce922b5aa27603`,
size `123,841,656` bytes, SHA-256
`6d4c960dc2a21e1619a8de359b47d84405d02db03e083fc001e2e9973c882f90`,
`nm` finds **515** `__asan*` symbols. Venue canary
(`forensics/tools/asan_canary.c`, clang `-fsanitize=address`) produced
`heap-use-after-free` at `asan_canary.c:31` with exit 134, so the instrument
fires in this venue.

| focused filter | exercised production path | result |
|---|---|---|
| `runtime::owned_str` | `OwnedStr` adopt/into_raw/Drop + model | **16 passed**, no ASan report |
| `runtime::err` | ERR slot ownership, `err_state` save/clear | **14 passed**, no ASan report |
| `x509::v3_prn` | new focused test drives `X509V3_EXT_print` → SKID `i2s` → `OwnedStr::adopt` → `Drop` | **1 passed**, no ASan report |

The `v3_prn` test is new (that module had no unit tests). It builds a DER
`ASN1_OCTET_STRING`, creates a subject-key-identifier `X509_EXTENSION`, prints
it to a memory BIO, and releases both objects. It exercises `v3_prn.rs:270`
(the `OwnedStr::adopt` of the callback result) on the instrumented build.

## 5. Ordinary gate (court container)

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | pass (`FMT_RC=0`) |
| `cargo clippy --all-targets -- -D warnings` | pass |
| `cargo test --lib -- --test-threads=4` | **1391 passed; 0 failed; 22 ignored** |

No test was newly ignored and none was removed. The historical baseline is
1183 library tests; the count has grown since, and this change adds 9 model/
correspondence tests and 1 focused `v3_prn` test.

## 6. Honest limits

- The `SAFETY_DISCHARGED` verdict above is the adjudicator's scoped decision for
  `OwnedStr`; it is not a proof of the whole crate and does not graduate any
  consumer. The model and ASan evidence below are bounded.
- The model is a finite abstraction (124 traces / 392 transitions). It does not
  model pointers, allocator identity, `CRYPTO_set_mem_functions` hooks,
  concurrency, or compiler optimisations, and it does not run Miri.
- The ASan runs cover only the three focused filters above, not the whole crate
  or the downstream courts. Leak detection was disabled (`detect_leaks=0`);
  `abort_on_error=0` was used for the test runs.
- `ERR_set_error_data` itself has no in-tree caller, so ASan exercised the ERR
  slot release/replace paths through the internal raise/save/clear flows, not a
  hostile C caller passing a non-seam pointer. The new contracts are the only
  thing excluding that caller class; the C ABI cannot enforce them.
- The `v3_prn` focus is one standard SKID extension, not the full extension
  table or a hostile application-supplied `i2s`.
- The ASan binary hash and results above predate the final doc-only
  `random_set_string` extent wording in `rand_lib.rs`; that edit changes no
  generated code. It was not rebuilt, per the instruction to run only
  `fmt --check` for this closure.
- `src/` changes are documentation plus test-only code. No commit was made.

## 7. Adjudicator's non-blocking follow-ups

These are recorded as follow-ups; they do not change the scoped `OwnedStr`
verdict above.

1. **Targeted Miri is unavailable.** Stacked Borrows and Tree Borrows runs are
   not available on the pinned toolchain, so no Miri evidence is claimed for
   `OwnedStr` adoption/transfer/Drop interleavings.
2. **Violating-caller negative controls remain unrun.** For
   `ERR_set_error_data` and a custom `i2s`, a C caller that violates the
   documented contract is outside the OB-2 boundary; any future detector for
   that class would need an isolated child-process allocator hook, because the
   violation is a C caller's, not a safe-Rust caller's.
3. **Row/static hazards are excluded and remain blockers.** The mutable
   `X509_TRUST_get0` / `X509_PURPOSE_get0` row pointers and the
   `DSO_METHOD_openssl` shared static method table are excluded from OB-2; they
   remain blockers for any caller-family or `SAFE_COMPATIBLE` claim.
