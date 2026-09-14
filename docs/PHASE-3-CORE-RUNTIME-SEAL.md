# Phase 3 — Core runtime: seal

Status: **sealed for the surfaces listed below. Not parity, and not closed.**

Authority: `openssl-3.6.4-production`
Platform: Linux x86-64, profile `linux-x86_64-default-shared-legacy-notests`
Courts: `forensics/tools/phase3_courts.py` → `artifacts/phase3/COURTS.json`

## 1. What this phase built

The substrate every later subsystem stands on, in the order
`docs/RELEASE_GATES.md` §1 requires — deliberately **not** AES, SHA, RSA or TLS:

| subsystem | module | symbols |
|---|---|---|
| allocation, sizing, cleansing, installable allocator | `src/runtime/mem.rs` | `CRYPTO_*` memory surface |
| the thread-local error queue | `src/runtime/err.rs` | `ERR_*` |
| metadata stacks | `src/runtime/stack.rs` | `OPENSSL_sk_*` |
| per-object extension data | `src/runtime/ex_data.rs` | `CRYPTO_*_ex_data` |
| the hash table | `src/runtime/lhash.rs` | `OPENSSL_LH_*` |
| secure heap | `src/runtime/secure.rs` | `CRYPTO_secure_*` |
| threads, atomics, TLS keys | `src/runtime/thread.rs` | `CRYPTO_THREAD_*`, `CRYPTO_atomic_*` |
| init, cleanup, runtime identity | `src/runtime/init.rs` | `OPENSSL_init*`, `OpenSSL_version*` |
| the object / NID database | `src/runtime/obj.rs` + `obj_table.rs` | `OBJ_*` |

Census at seal time: **206 libcrypto symbols are IMPLEMENTED** (measured from the
built crate by `forensics/tools/implemented_surface.py`; the number is derived,
never typed). The remaining libcrypto and libssl exports stay `SCAFFOLDED` and
abort with a diagnostic rather than returning a plausible value.

## 2. The evidence

Five differential courts, each a C probe compiled twice — against the authority
and against the candidate — and compared line by line:

```
RT-MEM      82 observations   pass
RT-EXDATA   38 observations   pass
RT-THREAD   36 observations   pass
RT-SECURE   32 observations   pass
RT-LHASH    45 observations   pass
           233 observations   all_pass=True
```

A passing court means the candidate produced the same observable transcript as
the authority for the behaviours that probe exercises. It is a
**differential-compatibility** result. It is **not** cryptographic correctness,
**not** security proof, and says nothing about any behaviour the probes do not
touch (`docs/PARITY_MODEL.md`).

The whole Phase 2 ABI suite still passes with the implementation linked in
(`artifacts/phase2/COURTS.json`), and the crate's own 70 unit tests pass with
`clippy -D warnings` clean.

## 3. What the probes found that memory would have got wrong

This is the return on measuring instead of recalling. Every one of these is a
behaviour a hand-written implementation would plausibly have got backwards, and
several were in fact wrong in the first revision of `src/runtime/`:

- `CRYPTO_malloc(0)` returns **non-NULL**; a zero-length request is still an
  allocation.
- `CRYPTO_realloc(p, 0)` returns NULL **without** releasing `p`, while
  `CRYPTO_clear_realloc(p, old, 0)` releases through `CRYPTO_clear_free`. The
  asymmetry is real, and it is an ownership difference, not a cosmetic one.
- `CRYPTO_clear_realloc` **shrinking** returns the same pointer without moving the
  block, after cleansing the discarded tail.
- `old_num` in `CRYPTO_clear_realloc_array` is an **element count**, not a byte
  count. Getting this wrong does not fail loudly: it makes the authority cleanse
  past the end of the block, which is how the distinction was discovered — by
  observing heap corruption in an earlier revision of the probe.
- The `*_array` overflow paths raise `ERR_LIB_CRYPTO`/`ERR_R_OVERFLOW` (packed
  `0x0780007F`) attributed to the **caller's** file and line, with an empty
  function name, an empty non-NULL data pointer and flags 0.
- `CRYPTO_memcmp` returns **exactly 1** for any difference, not the OR of the byte
  differences.
- `CRYPTO_aligned_alloc` reports the block to release through `*freeptr`, which
  differs from the returned pointer exactly when the base is not aligned.
- `CRYPTO_set_mem_functions` does not latch: a second identical installation
  returns 1.
- The atomics write the **resulting** value through `ret`, not the pre-operation
  value. `fetch_or` alone is the natural Rust spelling and is wrong here.
- `CRYPTO_new_ex_data` performs the constructor callback but does **not** allocate
  the slot stack, and `CRYPTO_dup_ex_data` returns 1 **without invoking any dup
  callback** when the source has no stack. Class validation is skipped entirely on
  that path, so a zeroed structure with an invalid class returns 1.
- `CRYPTO_secure_allocated` is a **range check**, not a liveness check: it reports
  1 for a released block and 1 for an interior pointer, and 0 for a plain
  allocation from `CRYPTO_malloc`.
- `OPENSSL_LH_strhash` reproduced over 18 inputs; the values are asserted in
  `src/runtime/lhash.rs`. It is caller-observable, so an approximation would be a
  compatibility defect.

## 4. Fault boundaries — recorded, not reproduced

Five authority faults were found. Reproducing a crash to obtain parity is
explicitly forbidden, so each is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` §6 and the probe prints a
`NOT_MEASURED_AUTHORITY_FAULTS` marker so the boundary is visible rather than
silently absent: NULL `ret` in the atomics; NULL `CRYPTO_EX_DATA` in
`CRYPTO_get_ex_data`/`CRYPTO_set_ex_data`; `CRYPTO_secure_used` before init or
after `done`; `CRYPTO_secure_actual_size` on a released block; and the `doall`
family on a table without thunks.

For each, the parity claim is **narrowed** rather than the fault copied, and the
narrowing is stated in the module that owns the symbol.

## 5. Deliberate scaffolding, and what it means

- `OPENSSL_LH_stats`, `OPENSSL_LH_node_stats` and their `_bio` relatives take a
  `BIO *`, which is Phase 4. They are **not defined**, so they remain `SCAFFOLDED`
  and abort. They are not faked.
- `ERR_print_errors*` and `ERR_add_error_mem_bio` likewise need BIO and remain
  `SCAFFOLDED`.
- The ERR reason-string tables are not yet generated, so
  `ERR_reason_error_string` and `ERR_lib_error_string` return NULL and
  `ERR_error_string_n` renders the numeric fallback. This is a **known,
  measurable divergence** with the remedy already identified (generate the tables
  from the authority's own `crypto/err/openssl.txt`). It is not worked around in
  the probe: the RT-ERR court does not yet exist, and when it does it will show
  this as a residual until the tables are generated.
- The runtime identity strings are the authority's captured values, and the
  build-metadata string is deliberately **different** (it must describe
  openssl-rs, not OpenSSL) — see `docs/NON_CLAIMS.md` and the module note.

## 6. What is explicitly NOT claimed

- Not that the runtime is complete: `RT-ERR` and `RT-STACK` probes do not exist
  yet, so `ERR_*` and `OPENSSL_sk_*` have **no differential court**. They are
  implemented and unit-tested, but `docs/PARITY_MODEL.md` does not promote a
  dimension without a court, so they remain unproved at `SEMANTIC_PASS`.
- Not that any symbol is `PARITY_VERIFIED`. The ledger's `OVERALL` stays below
  that until every applicable dimension is proved.
- Not that the candidate is a drop-in replacement. 5,993 of 6,499 libcrypto and
  libssl exports are still scaffolds.
- Not FIPS validated, and not FIPS-capable.

## 7. Exit criteria

| criterion | state |
|---|---|
| runtime subsystems implemented | met, with the scaffolding in §5 declared |
| differential courts exist and pass | met for `RT-MEM`, `RT-EXDATA`, `RT-THREAD`, `RT-SECURE`, `RT-LHASH` |
| `RT-ERR`, `RT-STACK` courts | **open** |
| authority faults recorded, not reproduced | met |
| no scaffold claims parity | met (`SHELL_MANIFEST.json` classifies every scaffold) |
| distribution shell still passes with the implementation linked | met |

Phase 3 therefore stays **in-progress** in the derived phase state. The seal
records what is established; it does not close the stratum.
