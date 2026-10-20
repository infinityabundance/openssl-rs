# Opaque-representation decisions — the four P1 objects (subphases 43–44)

Authority: pinned `openssl-3.6.4` under
`forensics/authorities/src/openssl-3.6.4/`, installed headers under
`artifacts/phase2/install/include/openssl/`.
Target: `x86_64-unknown-linux-gnu`, LP64, glibc (Debian 12), C `int` 4 /
pointer 8 / `unsigned long` 8, measured in the court container
(`docker/openssl-rs-court.sh exec …`). All project commands ran in the
container; no host build was used.

This record decides the representation of the four exported opaque objects left
as **P1** by the sweep-30/32 classification:

- `CRYPTO_RWLOCK` (`src/runtime/thread.rs`)
- `OPENSSL_STACK` (`src/runtime/stack.rs`)
- `OPENSSL_LHASH` (`src/runtime/lhash.rs`)
- `BN_RECP_CTX` (`src/bn/recp.rs`)

It records the decisions and the two option-B prototypes (subphases 43 and
44). It promotes **nothing** to `SAFETY_DISCHARGED` and claims **no** consumer
graduation.

## 1. Measurements

The authority sizes were measured by compiling the exact authority field lists
(the `struct` definitions from `threads_pthread.c`, `stack/stack.c`,
`lhash/lhash_local.h` and `bn/bn_local.h`) with `cc -D_GNU_SOURCE` in the court
container. Rust sizes were printed by temporary `cargo test` probes in the same
container, then the probes were removed; for `BN_RECP_CTX` the retained
compile-time `size_of`/`align_of` asserts and the hook-size test pin the value
permanently, and `CRYPTO_RWLOCK` does the same from subphase 44.

| Type | Authority definition (fields) | Authority size / align | Rust representation | Rust size / align | `size_of::<Rust>() <= size_of::<C>()`? |
|---|---|---|---|---:|---:|
| `CRYPTO_RWLOCK` | opaque `typedef void`; on this target `USE_RWLOCK` ⇒ `pthread_rwlock_t` (glibc: readers/writers futex words, `__cur_writer`, `__shared`, pad, `__flags`) | **56 / 8** | `RwlockInner { state: Mutex<LockState>, cond: Condvar }`; `LockState { writer: bool, writer_id: Option<u64>, readers: usize }` — inline in the 56-byte block on this target, `Box` elsewhere | **48 / 8** | **yes** (48 ≤ 56) |
| `OPENSSL_STACK` | `int num; const void **data; int sorted; int num_alloc; OPENSSL_sk_compfunc comp; OPENSSL_sk_freefunc_thunk free_thunk;` | **40 / 8** | `Inner { items: Vec<*const c_void>, num_alloc: c_int, comp: Option<fn>, sorted: bool, free_thunk: Option<fn> }` | **48 / 8** | **no** (48 > 40) |
| `OPENSSL_LHASH` | `OPENSSL_LH_NODE **b; comp; hash; hashw; compw; daw; daaw; unsigned int num_nodes, num_alloc_nodes, p, pmax; unsigned long up_load, down_load, num_items; int error;` | **104 / 8** | `Inner { b: Vec<Vec<Node>>, 8 × usize counters/limits, 6 × Option<fn> }` | **136 / 8** | **no** (136 > 104) |
| `BN_RECP_CTX` | `struct bn_recp_ctx_st { BIGNUM N; BIGNUM Nr; int num_bits; int shift; int flags; }`; `BIGNUM` = `BN_ULONG *d; int top, dmax, neg, flags;` = 24 / 8 | **64 / 8** | `RecpCtx { n: Vec<Limb>, neg: bool, nr: Vec<Limb>, num_bits: c_int, shift: c_int }` | **64 / 8** | **yes** (64 ≤ 64) |

Notes:

- `CRYPTO_RWLOCK`'s authority size is the `USE_RWLOCK` branch
  (`PTHREAD_RWLOCK_INITIALIZER` defined, not riscv). The fallback branch
  allocates `pthread_mutex_t`, measured **40 / 8** on this target. A future
  change that selects the fallback would change the authority size; the values
  above are conditional on the admitted build profile, not on the type name.
- The Rust structs are `repr(Rust)`: the compiler may reorder fields. No offset
  is asserted or read; only total size and alignment are used.
- `Vec`/`Box` storage remains Rust-allocator memory for every type.

## 2. Exported lifecycle and hook visibility

All four lifecycles are exported C symbols; the authority allocates the header
through `OPENSSL_zalloc`/`OPENSSL_malloc`, which expand to `CRYPTO_*` with
`OPENSSL_FILE`/`OPENSSL_LINE`. A caller-installed `CRYPTO_set_mem_functions`
hook therefore observes these allocations on the authority side, including size
and `(file, line)`.

| Type | Exported lifecycle | Authority header allocation | Authority release | Current candidate hook visibility |
|---|---|---|---|---|
| `CRYPTO_RWLOCK` | `CRYPTO_THREAD_lock_new` / `CRYPTO_THREAD_lock_free` | `OPENSSL_zalloc(sizeof(pthread_rwlock_t))` (`threads_pthread.c:910`) | `OPENSSL_free(lock)` (`:1005`) | **visible** on the measured target — one 56-byte block at `crypto/threads_pthread.c:910`, released at `:1005` (option B); `Box` elsewhere |
| `OPENSSL_STACK` | `OPENSSL_sk_new*` / `OPENSSL_sk_free` / `OPENSSL_sk_pop_free` | `OPENSSL_zalloc(sizeof(OPENSSL_STACK))` (`stack.c:230`); `OPENSSL_malloc(sizeof(*ret))` in dup/deep_copy (`:53`,`:91`) | `OPENSSL_free(st->data); OPENSSL_free(st)` (`stack.c:463-464`) | **invisible** — `Box<Inner>` + `Vec` |
| `OPENSSL_LHASH` | `OPENSSL_LH_new` / `OPENSSL_LH_free` | `OPENSSL_zalloc(sizeof(*ret))` (`lhash.c:67`) | `OPENSSL_free(lh->b); OPENSSL_free(lh)` (`lhash.c:92-93`) | **invisible** — `Box<Inner>` + `Vec` |
| `BN_RECP_CTX` | `BN_RECP_CTX_new` / `BN_RECP_CTX_free` | `OPENSSL_zalloc(sizeof(*ret))` (`bn_recp.c:24`) | `BN_free(N); BN_free(Nr); OPENSSL_free(recp)` (`bn_recp.c:37-40`) | **visible for the context block** after subphase 43 (64 bytes, `crypto/bn/bn_recp.c:24/40`); limb `Vec` storage still invisible |

The authority also makes secondary allocations the header model does not
reproduce byte-for-byte: the stack's element array (`OPENSSL_calloc(4, 8)` for
the first reserve / `realloc` growth), the lhash bucket array
(`OPENSSL_calloc(16, 8)`) and the reciprocal's `BIGNUM` limb arrays. Those are
algorithm-level storage, not the opaque header. The P1 residual is about the
header block; this record does not claim total-allocation parity.

## 3. Options considered

### Option A — retain Rust-owned (current state for two types)

- **Safety**: strongest and simplest. `Box`/`Vec` own their storage; one
  destructor; no size/alignment assumption and no raw adoption at the lifecycle
  edge.
- **Compatibility**: the header allocation is invisible to a caller-installed
  hook, so the hook observes neither the authority's byte count nor its
  `(file, line)`. OpenSSL's documented behaviour does not otherwise change.
- **Performance**: one Rust allocator call for the header (plus `Vec` growth);
  no extra indirection.
- **Maintenance**: lowest. The P1 residual stays open and must be reported.
- **Verdict**: valid and preferred where B is impossible or C adds hidden state.

### Option B — authority-sized block with the Rust state inline

Allocate exactly the authority's header size through `CRYPTO_zalloc` and
`ptr::write` the Rust value into it; reverse with `drop_in_place` and
`CRYPTO_free`. Permitted only when:

1. `size_of::<Rust>() <= size_of::<C>()`, and
2. `align_of::<Rust>() <=` the alignment the C allocator contract guarantees
   (at least the authority's own `alignof`), and
3. the block is exclusively owned from allocation to release.

- **Safety**: sound when (1)–(3) hold and the size/align facts are compile-time
  asserts. A growth in the Rust type becomes a build error rather than
  out-of-bounds storage. The block is never aliased before the `write`, and the
  destructor runs exactly once. The C allocator's alignment obligation is the
  same one the authority relies on for `BIGNUM` and `pthread_rwlock_t`; a hook
  that returns under-aligned memory violates the C allocator contract.
- **Compatibility**: the hook observes **exactly** the authority's header size
  and coordinates. The Rust field layout is not the C layout, which is
  permitted because the type is opaque.
- **Performance**: one allocation, same size as the authority, no indirection.
- **Maintenance**: needs a target-gated measured constant. If the authority
  layout is not measured for a target, keep A there; do not guess. If the Rust
  type grows past the constant, the build fails loudly.
- **Limitation**: only the header block gains parity. `Vec`/member storage
  remains Rust-owned and invisible.

### Option C — authority-sized header containing a pointer to Rust state

Allocate the authority-sized header and store a `Box<Inner>` pointer in it.

- **Safety**: sound only with an explicit owning wrapper that reads the pointer,
  drops the state, and releases the header exactly once, plus a construction
  path that cannot leave a half-written pointer. Adds a second allocation,
  indirection and a failure/rollback path.
- **Compatibility**: the header allocation is the authority's size, so the
  header allocation *event* matches. The state allocation does not: if it goes
  through the Rust allocator the hook does not see it (hidden memory); if it
  goes through `CRYPTO_*` the hook sees an extra allocation of a non-authority
  size that the authority never makes. Neither is exact total hook parity.
- **Performance**: two allocations and a pointer chase.
- **Maintenance**: highest; two ownership layers and more partial-construction
  states.
- **Verdict**: not chosen for any of the four types.

### Parity rule

**No option may claim exact hook-size parity unless the allocation passed to the
hook is the authority's size.** Option A has no such allocation. Option B has
one only when `size_of::<Rust>() <= size_of::<C>()` and the value passed to
`CRYPTO_zalloc` is the authority's size constant. Option C can claim parity for
the header event only, never for the additional state allocation. No option
here claims total-memory parity, because every representation keeps some
Rust-owned storage outside the C seam.

## 4. Per-type recommendation

| Type | Recommendation | Rationale |
|---|---|---|
| `CRYPTO_RWLOCK` | **B, implemented in subphase 44** | 48 ≤ 56 and 8 ≤ 8, so B is sound with target-gated compile-time asserts. `Mutex`/`Condvar` sizes are toolchain-dependent, so the assert is load-bearing; targets without a measured authority layout retain A (`Box`). |
| `OPENSSL_STACK` | **Retain A** | B is impossible (48 > 40). C buys only header-event parity while introducing hidden state memory and a second allocation; the stack's `Vec` element storage remains invisible either way. A is the sound, low-risk choice until the `Inner` representation can be made ≤ 40 bytes. |
| `OPENSSL_LHASH` | **Retain A** | B is impossible (136 > 104). The gap (32 bytes) is too large for field packing without changing the representation substantially, and C again buys only header-event parity. A retained. |
| `BN_RECP_CTX` | **B, implemented in subphase 43** | 64 == 64 and 8 == 8. The block is exclusively owned, `RecpCtx` is our own type (no std layout dependency), and one `CRYPTO_zalloc`/`CRYPTO_free` pair reproduces the authority's header event exactly. |

## 5. The option-B prototypes

### 5.1 `BN_RECP_CTX` (subphase 43)

- `AUTHORITY_BN_RECP_CTX_SIZE = 64` and
  `AUTHORITY_BN_RECP_CTX_ALIGN = 8` are target-gated to
  `linux`/`x86_64`/`64-bit` and protected by module-level `const _: () =
  assert!(…)` for both `size_of::<RecpCtx>()` and `align_of::<RecpCtx>()`.
- `BN_RECP_CTX_new` calls
  `CRYPTO_zalloc(64, c"crypto/bn/bn_recp.c", 24)` and writes `RecpCtx` into
  the returned block. `BN_RECP_CTX_free` runs `drop_in_place` and releases the
  same block at `line 40`, via a guard that guarantees the block release even if
  a destructor ever unwinds.
- The exported symbol, signature and opaque handle are unchanged; `RecpCtx`
  remains private-state and is never field-accessed by a caller.
- On any other target the module keeps option A (`Box`); no unmeasured size
  constant is used.
- Deterministic test:
  `bn::recp::tests::hook_observes_authority_size_and_single_release`. Because
  the allocator seam latches after a process's first `CRYPTO_*` allocation, the
  test re-enters the test binary with `--exact … --test-threads=1` in a child
  process, installs a recording allocator first, then asserts: exactly one
  allocation of **64** bytes, file `crypto/bn/bn_recp.c`, allocation line 24,
  exactly one free of the same pointer, file/line 40, and no second allocation.

### 5.2 `CRYPTO_RWLOCK` (subphase 44)

- `AUTHORITY_CRYPTO_RWLOCK_SIZE = 56` and `AUTHORITY_CRYPTO_RWLOCK_ALIGN = 8`
  are target-gated to `linux`/`x86_64`/`64-bit` and protected by module-level
  `const _: () = assert!(…)` for the pointer width, pointer size, C `int` size,
  and `size_of`/`align_of` of `RwlockInner`.
- `CRYPTO_THREAD_lock_new` calls
  `CRYPTO_zalloc(56, c"crypto/threads_pthread.c", 910)` and writes the
  fully-initialised `RwlockInner` into the block. A `CRYPTO_zalloc` refusal
  returns NULL exactly as the authority does (no error is raised).
- `CRYPTO_THREAD_lock_free` runs `drop_in_place` and releases the same block at
  line 1005 through a guard, so the C block is released exactly once even if a
  destructor ever unwinds. NULL remains a no-op.
- No `RwlockInner` field is read from the zeroed block: the zeroing is not relied
  on for validity, and `pthread_rwlock_t` is not used as the representation. The
  lock is `Mutex` + `Condvar`, whose inline `write`/`drop_in_place` the option-B
  contract permits.
- The exported symbol, signature, opaque handle, and allocator/free coordinates
  are unchanged. On any other target the module keeps option A (`Box`).
- Deterministic test:
  `runtime::thread::tests::lock_hook::hook_observes_authority_size_and_single_release`.
  It re-enters the test binary in a child process, installs a recording allocator
  first, and asserts exactly one 56-byte allocation at file
  `crypto/threads_pthread.c` line 910, successful read/write lock and unlock, one
  release of the same pointer at line 1005, and no second allocation.

## 6. Residuals and non-claims

- **P1 status**: `BN_RECP_CTX` and `CRYPTO_RWLOCK` now have authority-size
  parity for their header block on the measured target. `OPENSSL_STACK` and
  `OPENSSL_LHASH` retain option A and the hook-invisibility residual. This is a
  **partial** resolution of P1, not a discharge. `OPENSSL_STACK`/`OPENSSL_LHASH`
  remain option A because B is impossible (`size_of::<Rust>() > size_of::<C>()`).
- `CRYPTO_RWLOCK` has no secondary Rust-owned header state: its `Mutex`/`Condvar`
  live inline in the same block, so the option-B header event covers the whole
  object. The `n`/`nr` limb `Vec` storage of `BN_RECP_CTX` is still Rust-owned and
  invisible to the hook. The stack element array and lhash bucket array remain
  algorithm-level Rust storage. Total allocation parity is not claimed.
- No type is promoted to `SAFETY_DISCHARGED`; the §7 independent-check package
  remains outstanding.
- No change was made to `docker/`, the allocator seam, exported signatures,
  `#[repr(C)]` handles, or the gate configuration.
- If a future target has an authority layout that cannot be measured, option A
  remains the answer; a hardcoded size without a target gate and compile-time
  check is not acceptable.
