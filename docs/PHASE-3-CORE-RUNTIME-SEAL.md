# Phase 3 — Core runtime: seal

Status: **complete for the surfaces listed below. Not parity.** Completion here
means every obligation in the stratum's symbol families is either proved by a
differential court or recorded as a hand-off to a later phase; it does not mean
any symbol has reached `PARITY_VERIFIED`.

Authority: `openssl-3.6.4-production`
Platform: Linux x86-64, profile `linux-x86_64-default-shared-legacy-notests`
Courts: `forensics/tools/phase3_courts.py` → `artifacts/phase3/COURTS.json`
Ledger: `forensics/tools/phase3_obligations.py` → `forensics/phase3-obligations.json`

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
| **generated** ERR reason tables | `src/runtime/err_strings.rs` | the authority's `*_str_reasons` arrays |
| **generated** ERR raise coordinates | `src/runtime/err_sites.rs` | the authority's `OPENSSL_FILE`/`LINE`/`FUNC` per site |
| **generated** `ERR_load_*_strings` | `src/runtime/err_loaders.rs` | 31 entry points that load, not no-ops |

Three of those files are generated from the authority's own sources by
`gen_err_strings.py` and `gen_err_raise_sites.py`, both byte-reproducible and both
content-addressed in the headers they emit.

Census at seal time: **209 of the 220 libcrypto exports in the Phase 3 families
are IMPLEMENTED**; the other 11 are recorded hand-offs (§5). Both numbers are
derived by `implemented_surface.py` and `phase3_obligations.py`; neither is
typed.

## 2. The evidence

Seven differential courts, each a C probe compiled twice — against the authority
and against the candidate — and compared line by line:

```
RT-MEM       82 observations   pass
RT-EXDATA    38 observations   pass
RT-ERR     3857 observations   pass
RT-STACK    159 observations   pass
RT-THREAD    36 observations   pass
RT-SECURE    32 observations   pass
RT-LHASH     45 observations   pass
           4249 observations   all_pass=True
```

A passing court means the candidate produced the same observable transcript as
the authority for the behaviours that probe exercises. It is a
**differential-compatibility** result. It is **not** cryptographic correctness,
**not** security proof, and says nothing about any behaviour the probes do not
touch (`docs/PARITY_MODEL.md`).

The whole Phase 2 ABI suite still passes with the implementation linked in
(`artifacts/phase2/COURTS.json`), and the crate's own 80 unit tests pass with
`clippy -D warnings` clean.

## 3. What the probes found that memory would have got wrong

This is the return on measuring instead of recalling. Every one of these is a
behaviour a hand-written implementation would plausibly have got backwards, and
several were in fact wrong in the first revision of `src/runtime/`:

### Memory and initialisation

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

### The error queue

- `ERR_STATE` is a **public, layout-bearing struct** in `err.h` and
  `ERR_get_state` returns a pointer to it, so the ring *is* the representation: a
  private Rust queue with a mirrored view would already fail the RT-ERR probe.
  Sixteen slots hold fifteen usable errors, because `ERR_new` advances `top` and
  then pushes `bottom` if they meet.
- A slot claimed by `ERR_new` but not yet given a library and reason is
  **incomplete**: `err_buffer` is zero and the queue does not report it. That also
  makes `ERR_peek_last_error()` return 0 while a newer, incomplete slot exists.
- `ERR_reason_error_string` tries the library-qualified key and then the bare
  reason. `ERR_PACK` discards the function field in 3.x, so
  `ERR_func_error_string` is a bare `return NULL` — there is nothing to look up.
- **The string registry is loaded, not compiled in.** The authority's
  `int_error_hash` starts empty; it is populated by loaders driven by
  initialisation. `ossl_err_get_state_int` creates a thread's `ERR_STATE` and then
  runs `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS)` — "ignore failures
  from these" — which loads the generic tables plus every library in
  `ossl_err_load_crypto_strings`. Measured: *before any ERR call on a thread*,
  `ERR_reason_error_string` and `ERR_lib_error_string` both return NULL even for a
  library whose table is compiled in, and `ERR_error_string` renders the numeric
  fallback.
- `err_all.c` **deliberately skips** `ossl_err_load_SSL_strings`, so all 357 SSL
  reasons are NULL until `OPENSSL_INIT_LOAD_SSL_STRINGS` is processed. The probe
  measures both sides of that transition.
- Six further reasons (`OSSL_DECODER`, `OSSL_ENCODER`) ship a compiled array that
  no loader in the crypto set loads. They are **always** NULL, and the probe
  asserts exactly that rather than assuming it.
- The **descriptions** come from the checked-in `*_err.c` files, not from
  `openssl.txt`. Measured: `openssl.txt` says
  `BIO_R_LOCAL_ADDR_NOT_AVAILABLE:111:local addr not available` while
  `crypto/bio/bio_err.c` says `"local address not available"`, and callers see the
  compiled text. The **codes** diverge too: `openssl.txt` says
  `BIO_R_PEER_ADDR_NOT_AVAILABLE:114` and `include/openssl/bioerr.h` says `151`,
  and the compiled array uses 151. Both facts are now enforced in the generator.
- `ERR_error_string_n` substitutes a compact `err:%lx:%lx:%lx:%lx` form when the
  pretty form **exactly fills** the buffer. The authority's test is
  `strlen(buf) == len - 1` *after* a bounded write, so a truncated rendering also
  triggers it; testing the untruncated length instead is wrong and was.
- A system error (`ERR_SYSTEM_FLAG` set) is rendered through the platform's
  `strerror_r`, never through the reason table, and `ERR_GET_LIB`/`ERR_GET_REASON`
  are system-aware: `ERR_lib_error_string(0x80000002)` is `"system library"`, not
  library 0. Reproducing the resolution without those two special cases produces
  `lib(0)::reason(2)`.
- `ERR_error_string`'s buffer is a **shared static**, not thread-local. Two calls
  overwrite each other; that is reproduced rather than "fixed".
- After `OPENSSL_cleanup`, `ossl_err_get_state_int`'s
  `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY)` fails, so every `ERR_*` call
  becomes a no-op and **no error is recorded** — including the `ERR_R_INIT_FAIL`
  that a refused `OPENSSL_init_crypto` would otherwise raise.
- The legacy getters are **not uniform in arity**: `_func` takes one output,
  `_line` two, `_line_data` four, `_data` two different ones. Defining them
  through a single five-parameter macro produced exports whose ABI did not match
  the declarations in the installed headers. The RT-ERR probe found this by
  calling them the way the header says to — and it is a class of defect the
  Phase 2 `ABI-SYMBOL` court cannot see, because that court compares names,
  versions, types, binding and visibility, not signatures. Recorded in §6.

### The stack

- `OPENSSL_sk_find` and `OPENSSL_sk_find_ex` return an **index**, not a pointer.
  `sk_TYPE_find` in `safestack.h` is `int`, and a candidate returning a pointer
  links and then misbehaves.
- The comparator receives **pointers to the elements**, not the elements:
  `typedef int (*sk_TYPE_compfunc)(const T *const *a, const T *const *b)`. Calling
  it with the element values is not a style difference; a generated comparator
  dereferences its arguments.
- On an ordered stack lookup is `ossl_bsearch`, which is why `find` and `find_ex`
  **differ on a hit**: `find` walks back to the first equal element, `find_ex`
  answers the probed position. Measured on `{10,10,20,20,30,30,40,50}`:
  `find(10) == 0` and `find_ex(10) == 1`.
- `find_ex` also answers the **nearest** element on a miss
  (`OSSL_BSEARCH_VALUE_ON_NOMATCH`), so `find_ex(99) == 7` on that stack while
  `find(99) == -1`.
- `OPENSSL_sk_find_all`'s `*pnum` is the **number of equal elements**, not an
  index, and the authority returns **without touching `*pnum`** on a NULL or empty
  stack and on a NULL key with a comparator installed.
- `OPENSSL_sk_insert` with a **negative** position appends rather than failing.
- `OPENSSL_sk_zero` does **not** clear the sorted flag; `OPENSSL_sk_sort` without a
  comparator does **not** set it; `OPENSSL_sk_delete` does not clear it either.
- `OPENSSL_sk_dup(NULL)` and `OPENSSL_sk_deep_copy(NULL, …)` return a **fresh empty
  stack**, not NULL.
- `OPENSSL_sk_set` raises on both failure modes, and the out-of-range case attaches
  the index as data (`i=%d`, flags `ERR_TXT_MALLOCED | ERR_TXT_STRING`).
- Generators install a destructor **thunk** through `OPENSSL_sk_set_thunks`, and
  `OPENSSL_sk_pop_free` prefers the thunk over its `func` argument. All 26
  `OPENSSL_sk_*` exports, including `OPENSSL_sk_set_thunks`, are implemented.

### Error records carry authority source coordinates

`ERR_raise` is a macro that records `OPENSSL_FILE`, `OPENSSL_LINE` and
`OPENSSL_FUNC`, and `ERR_get_error_all` hands them to the caller. They are
therefore part of the contract, and they are reproduced **exactly** rather than
normalized away:

```
OPENSSL_sk_set(NULL, …)   ->  ../../src/openssl-3.6.4/crypto/stack/stack.c:482  OPENSSL_sk_set
OPENSSL_sk_set(st, 7, …)  ->  ../../src/openssl-3.6.4/crypto/stack/stack.c:486  OPENSSL_sk_set   (data "i=7")
OPENSSL_sk_reserve(NULL)  ->  ../../src/openssl-3.6.4/crypto/stack/stack.c:251  OPENSSL_sk_reserve
OPENSSL_sk_insert(NULL)   ->  ../../src/openssl-3.6.4/crypto/stack/stack.c:271  OPENSSL_sk_insert
OPENSSL_sk_reserve(st, INT_MAX) -> …/stack.c:186  sk_reserve
OPENSSL_init_crypto after cleanup -> …/init.c:504  OPENSSL_init_crypto
```

`gen_err_raise_sites.py` derives all fourteen sites from the pinned source and the
admitted build record: the line from the call site, the function from the
enclosing definition, and the `__FILE__` prefix from
`relpath(source_tree, build_dir)` — because the authority was built out of tree
and `__FILE__` is the path as spelled on the compiler's command line. The `lib`
and `reason` values are resolved by compiling a one-off C program against the
authority's own headers, so the numbers are the authority's numbers.

Two sites in the same families are **not reachable** and are recorded as such:
`sk_reserve`'s growth-overflow arm (`stack.c:212`) and `OPENSSL_sk_insert`'s
`num == max_nodes` arm (`stack.c:275`) both need on the order of a billion
elements. Their conditions are reproduced faithfully; the probe does not claim
them.

## 4. Fault boundaries — recorded, not reproduced

Eight authority behaviours in this stratum are faults or uninitialised reads
rather than documented failures. Reproducing a crash to obtain parity is
explicitly forbidden, so each is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` §6 and the probe prints a marker so the
boundary is visible rather than silently absent:

| behaviour | authority | candidate |
|---|---|---|
| NULL `ret` in `CRYPTO_atomic_*` | writes to NULL | returns the value, writes nothing |
| NULL `CRYPTO_EX_DATA` in `CRYPTO_get/set_ex_data` | dereferences NULL | returns 0 / NULL |
| `CRYPTO_secure_used` before init / after `done` | reads a NULL arena | reports 0 |
| `CRYPTO_secure_actual_size` on a released block | walks freed metadata | reports the size or 0 |
| `OPENSSL_LH_doall*` on a table with no thunks | calls a NULL thunk | iterates directly |
| `OPENSSL_sk_set_cmp_func(NULL, …)` | dereferences NULL | returns NULL |
| `OPENSSL_sk_pop_free(st, NULL)` with elements and no thunk | calls a NULL function pointer | skips the callback |
| `OPENSSL_sk_deep_copy(st, NULL, f)` with elements | calls a NULL copy function | returns NULL |

One further difference is not a fault but an **uninitialised field**:
`OPENSSL_sk_deep_copy(NULL, …)` sets `num`, `sorted` and `comp` but leaves
`free_thunk` as whatever `OPENSSL_malloc` returned. The candidate stores NULL.
This is a nondeterministic read in the authority, so no probe can compare it, and
the safer value is the only reproducible one.

For each, the parity claim is **narrowed** rather than the fault copied, and the
narrowing is stated in the module that owns the symbol.

## 5. Deliberate scaffolding, and what it means

- Eleven symbols in the Phase 3 families are **deferred to Phase 4** because they
  need a `BIO *` or a `FILE *`: `ERR_print_errors`, `ERR_print_errors_cb`,
  `ERR_print_errors_fp`, `ERR_add_error_mem_bio`, the six
  `OPENSSL_LH_*stats*` entry points, and `OBJ_create_objects`. They are listed,
  with their owning phase and reason, in `forensics/phase3-obligations.json`,
  which `phase_state.py` consumes. They are **not** faked and **not** implemented
  as no-ops: they remain `SCAFFOLDED` and abort.
- `phase3_obligations.py` fails closed. If a later change adds an export to one of
  the Phase 3 families and does not implement it or defer it, the ledger refuses
  to generate and the phase state cannot report `complete`.
- The runtime identity strings are the authority's captured values, and the
  build-metadata string is deliberately **different** (it must describe
  openssl-rs, not OpenSSL) — see `docs/NON_CLAIMS.md` and the module note.
- `CRYPTO_mem_ctrl`, `CRYPTO_set_mem_debug`, `CRYPTO_mem_debug_*` and
  `CRYPTO_mem_leaks*` are not implemented **and not exported**, because the
  admitted profile defines `OPENSSL_NO_CRYPTO_MDEBUG` and the authority does not
  export them either. The ABI symbol court would flag an unexpected export.

## 6. What is explicitly NOT claimed

- Not that the runtime is complete in the sense of covering OpenSSL. The stratum
  is complete; the library is not. 5,685 libcrypto exports and all 603 libssl
  exports are still scaffolds.
- Not that any symbol is `PARITY_VERIFIED`. The ledger's `OVERALL` stays below
  that until every applicable dimension is proved.
- Not that a passing court proves security. `RT-ERR` and `RT-STACK` are
  differential-compatibility courts; they say nothing about
  `docs/SECURITY_DIVERGENCE_POLICY.md`'s constant-time obligations.
- Not that signature/arity compatibility is courted. `ABI-SYMBOL` compares name,
  version, ELF type, binding and visibility; it does **not** compare C prototypes.
  The RT-ERR court found a real arity defect in this very phase, which shows the
  differential probes can catch this class — but a symbol whose declaration is
  wrong and whose behaviour is never exercised by any probe would still pass.
  Closing that gap needs a declaration-vs-definition arity court and is recorded
  as an open obligation for the phase that owns the header generator.
- Not FIPS validated, and not FIPS-capable.
- Not a drop-in replacement. See `docs/NON_CLAIMS.md`.

## 7. Exit criteria

| criterion | state |
|---|---|
| runtime subsystems implemented | met; the generated ERR tables, coordinates and loaders are part of the implementation |
| differential courts exist and pass | met: RT-MEM, RT-EXDATA, RT-ERR, RT-STACK, RT-THREAD, RT-SECURE, RT-LHASH — 4,249 observations, no residual |
| `RT-ERR`, `RT-STACK` courts | met |
| every export in the phase's symbol families accounted for | met, by `forensics/phase3-obligations.json` (220 owned: 209 implemented, 11 deferred to Phase 4 with reasons) |
| authority faults recorded, not reproduced | met |
| no scaffold claims parity | met (`SHELL_MANIFEST.json` classifies every scaffold) |
| distribution shell still passes with the implementation linked | met |
| earlier strata complete | met: phases 0, 1 and 2 are `complete` in the derived state |

`forensics/phase-state.json` therefore derives phase 3 as **complete**, with the
eleven deferrals listed beside it rather than folded into a status word. The seal
records what is established; it does not promote any symbol to parity.

## 8. FRF evidence

Seven FRF courts put the runtime on the claim-bearing side of the house. Each
admitted reference is `openssl-rt-3.6.4-r2`: the *reference program* is the probe
harness, so a change in the harness is a change in the reference and gets a new
reference identity, exactly as FRF insists.

The compiled Phase 3 claim is

```
ffd0d7b3b15bf8fd97f70f023ace973577e4b79b723ce1fe23cfb2ef9a31d87d
```

at `--policy sensitivity-backed`: every claimed axis demonstrated that it can see
its own defect class, on that axis and no other. The whole chain — admit, run,
challenge, dispose the release-banner residual, emit receipts, compile claims — is
one command, `forensics/frf/run_courts.sh`, and it ends with the evidence tree
verifying (`graph_verified: yes`, `object_closure: complete`).

**Two things a reader must not infer.**

1. FRF extracts the `stdout` axis as `stdout-first-line`, so the claim's own
   wording is narrower than what was observed. The harness makes that line a
   digest of the entire transcript, so the claim covers every observation — but
   the mapping is stated in `forensics/frf/README.md` rather than left to be
   assumed.
2. The evidence is bound to the candidate artifact it was taken against. A
   release rebuilds that artifact, and FRF run identities do not vary with
   `execution_context` hashes, so the store is recreated and every court is
   re-observed per release. Nothing is carried forward.

## 9. Gemel

Change `C10`,
trajectory `T10`,
checkpoint `K6` (`checkpoint.8958092650197b473c5b00d9c0de22e075c4765efc2e8a4ab9d452ffae97cf61`).
Projection in `forensics/GEMEL_TRAJECTORY.md`, rendered by
`forensics/tools/render_gemel_trajectory.sh`.

The native store is not Git-tracked (D17). Two things in this boundary are worth
reading in the projection rather than here: a change created by mistake while
probing Gemel's own claim-kind enum carries the Phase 3 working-tree operations
because it was created first, and the correction change that records its durable
identity — because Gemel renumbers derived names, which is how the mistake became
visible at all.
