# FFI failure atomicity (HAZ-16)

**Status:** measurement and partial repair, not a universal atomicity claim.
**Hazard:** `HAZ-16` — "A panic at the FFI boundary leaves partially mutated
state" (`docs/HAZARD-REGISTER.md`).
**Obligation:** `OBL-PANIC-ATOMICITY` (`docs/REQUIREMENTS-TRACEABILITY.md`).
**Authority rule:** `AGENTS.md` §4.
**Evidence:** `evidence/haz-16/{CLASSIFICATION.json,RECEIPT.md}`, generated from
`evidence/haz-16/{enumerate_ffi_mutation.py,build_classification.py}`.

`guard_ffi` (`src/ffi/mod.rs`) catches a panic and never resumes. That is a
non-unwinding guarantee, not a state guarantee: the closure has already run as
far as the panic point. This document measures which exported FFI entries can
leave a caller-visible object in an inconsistent state when a fallible step or a
defect interrupts them, classifies the covered population, records the three
repairs made in this batch, and states exactly what is not covered.

## 1. What is (and is not) claimed

- The covered population is the **79** `guard_ffi`-wrapped entries in the nine
  library-object owner files listed in §3.
- The crate-wide candidate superset is **823** entries. The difference is
  deliberately not claimed: see §7.
- `FAILURE_ATOMIC` is asserted **for the library object**, not for a
  caller-supplied output buffer. A defect that panics in the middle of a copy
  can leave a partially written caller buffer; the return value remains the
  documented failure signal and no library object is inconsistent. §7 records
  this as a non-claim rather than an atomicity result.
- No timing, Miri or sanitizer conclusion is drawn from the unit tests.

## 2. Enumeration method

The population is produced mechanically so that it can be re-run and checked.

1. `evidence/haz-16/enumerate_ffi_mutation.py` walks every `.rs` file under
   `src/` (**883** files).
2. It locates each `#[no_mangle]` item followed by an `extern "C" fn`
   (optionally `pub`, optionally `unsafe`) and extracts the body by brace
   matching.
3. It marks the entry `guarded` when the body calls `guard_ffi`.
4. It marks a mutation candidate when the body matches at least one of a fixed
   signal set: `(*obj).field =`, output-parameter writes, `ptr::write/copy`,
   `Vec` mutation (`push`/`insert`/`remove`/…), setters and `raise_site`, and
   lifetime operations (`Box::from_raw`, `*_free`, `destroy`, `from_raw`).

Current result:

| measurement | count |
|---|---:|
| scripts scanned | 883 |
| exported functions found | 6511 |
| `guard_ffi`-wrapped | 1485 |
| mutation candidates | 823 |
| **covered population** | **79** |

The covered population is the candidate subset in these owner files:

```
src/runtime/stack.rs        OPENSSL_STACK
src/runtime/lhash.rs        OPENSSL_LHASH
src/runtime/bio/mod.rs      BIO
src/runtime/bio/iolib.rs    BIO
src/bn/bignum.rs            BIGNUM
src/bn/ctx.rs               BN_CTX, BN_GENCB
src/bn/blinding.rs          BN_BLINDING
src/runtime/ex_data.rs      CRYPTO_EX_DATA
src/runtime/obj.rs          ASN1_OBJECT, OBJ_NAME registry
```

`evidence/haz-16/build_classification.py` re-runs the enumerator in-process,
filters to those files, and **fails** if a covered entry has no disposition or
if a disposition names an entry that is no longer covered. The population can
therefore shrink only by an explicit edit, never by omission.

Reproduce:

```
python3 evidence/haz-16/enumerate_ffi_mutation.py
python3 evidence/haz-16/build_classification.py
python3 -m json.tool evidence/haz-16/CLASSIFICATION.json >/dev/null
```

## 3. The four classes

| class | meaning |
|---|---|
| `FAILURE_ATOMIC` | No observable partial object state is possible: every fallible step precedes the first observable change, or the operations after the first change are total. |
| `ROLLBACK` | An explicit compensating action restores a consistent prior state, or a consistent prefix that a retry can finish. |
| `POISONED` | The object refuses further use with a defined outcome. |
| `PARTIAL_EXPOSED` | A caller can observe or use inconsistent state. This is the finding class. |

Result for the covered population (`evidence/haz-16/CLASSIFICATION.json`):

| class | count |
|---|---:|
| `FAILURE_ATOMIC` | 72 |
| `ROLLBACK` | 3 |
| `POISONED` | 1 |
| `PARTIAL_EXPOSED` | 3 |
| **total** | **79** |

## 4. Classification table

| file | entry | class | basis |
|---|---|---|---|
| `src/bn/bignum.rs` | `BN_bin2bn` | `FAILURE_ATOMIC` | the limbs are decoded into a local vector and stored once |
| `src/bn/bignum.rs` | `BN_bn2bin` | `FAILURE_ATOMIC` | the magnitude is copied into the caller's buffer; the `BIGNUM` is read-only and no library field changes (the caller buffer residual is the §4 non-claim) |
| `src/bn/bignum.rs` | `BN_bn2mpi` | `FAILURE_ATOMIC` | the encoding is written into the caller's buffer or a fresh owned buffer; the `BIGNUM` is read-only |
| `src/bn/bignum.rs` | `BN_clear` | `FAILURE_ATOMIC` | an in-place zeroing with no fallible step |
| `src/bn/bignum.rs` | `BN_clear_bit` | `FAILURE_ATOMIC` | a single masked limb write |
| `src/bn/bignum.rs` | `BN_clear_free` | `FAILURE_ATOMIC` | one cleansed release of the limbs and the object |
| `src/bn/bignum.rs` | `BN_consttime_swap` | `FAILURE_ATOMIC` | both operands are reserved before the loop, and every loop step is total; no fallible operation exists inside the swap |
| `src/bn/bignum.rs` | `BN_copy` | `FAILURE_ATOMIC` | `try_assign_limbs` performs the only fallible step before the destination is changed; the sign write follows it |
| `src/bn/bignum.rs` | `BN_free` | `FAILURE_ATOMIC` | one release of the limbs and the object |
| `src/bn/bignum.rs` | `BN_lebin2bn` | `FAILURE_ATOMIC` | as `BN_bin2bn`, with the byte order reversed before the single store |
| `src/bn/bignum.rs` | `BN_mpi2bn` | `FAILURE_ATOMIC` | the decoded limbs are built locally and stored once |
| `src/bn/bignum.rs` | `BN_secure_new` | `FAILURE_ATOMIC` | the value is allocated locally and the secure flag is set before the handle is returned |
| `src/bn/bignum.rs` | `BN_set_bit` | `FAILURE_ATOMIC` | the growth is performed before the bit is set |
| `src/bn/bignum.rs` | `BN_set_flags` | `FAILURE_ATOMIC` | one flag write |
| `src/bn/bignum.rs` | `BN_set_negative` | `FAILURE_ATOMIC` | one scalar write |
| `src/bn/bignum.rs` | `BN_set_word` | `FAILURE_ATOMIC` | the limb vector is built locally and stored once |
| `src/bn/bignum.rs` | `BN_swap` | `FAILURE_ATOMIC` | two `mem::swap` operations on values; total |
| `src/bn/bignum.rs` | `BN_with_flags` | `FAILURE_ATOMIC` | one flag write |
| `src/bn/blinding.rs` | `BN_BLINDING_convert_ex` | `FAILURE_ATOMIC` | the counter advance is a complete state, `r` receives the current inverse, and the `n` multiply is atomic in its callee |
| `src/bn/blinding.rs` | `BN_BLINDING_create_param` | `FAILURE_ATOMIC` | the factor, its inverse and the exponent are computed into temporaries and published only after every fallible step (fixed in this batch) |
| `src/bn/blinding.rs` | `BN_BLINDING_free` | `FAILURE_ATOMIC` | one release of the block and its members |
| `src/bn/blinding.rs` | `BN_BLINDING_invert_ex` | `FAILURE_ATOMIC` | the multiply it delegates to computes into a local magnitude and stores the result only after all fallible work |
| `src/bn/blinding.rs` | `BN_BLINDING_new` | `FAILURE_ATOMIC` | the handle owns the block from the start; every failure arm releases it through `Drop` without publishing it |
| `src/bn/blinding.rs` | `BN_BLINDING_update` | `FAILURE_ATOMIC` | both squares are computed into `TempBn`s and published, with the counter, only after both succeed (fixed in this batch) |
| `src/bn/ctx.rs` | `BN_CTX_free` | `FAILURE_ATOMIC` | one release of the pool and the context |
| `src/bn/ctx.rs` | `BN_CTX_get` | `FAILURE_ATOMIC` | pool growth is fallible and precedes `used += 1`; a fresh value is cleared before it is handed out |
| `src/bn/ctx.rs` | `BN_CTX_start` | `FAILURE_ATOMIC` | one mark pushed onto the context's stack |
| `src/bn/ctx.rs` | `BN_GENCB_free` | `FAILURE_ATOMIC` | one release |
| `src/bn/ctx.rs` | `BN_GENCB_new` | `FAILURE_ATOMIC` | local construction, no publication before success |
| `src/runtime/bio/iolib.rs` | `BIO_callback_ctrl` | `FAILURE_ATOMIC` | the callback is installed by one field write after the NULL and type checks |
| `src/runtime/bio/iolib.rs` | `BIO_ctrl` | `FAILURE_ATOMIC` | the command arguments are read, the callback runs, and the result is written once; application mutation inside a callback is HAZ-06/HAZ-20, not this boundary |
| `src/runtime/bio/iolib.rs` | `BIO_do_connect_retry` | `FAILURE_ATOMIC` | each retry re-reads the socket state and the loop's only carried state is the iteration budget |
| `src/runtime/bio/iolib.rs` | `BIO_get_line` | `FAILURE_ATOMIC` | the loop reads through the same method and returns its own count; no library field is published ahead of the transfer |
| `src/runtime/bio/iolib.rs` | `BIO_gets` | `FAILURE_ATOMIC` | the method fills the caller buffer and the return value reports the count; no library field changes before it |
| `src/runtime/bio/iolib.rs` | `BIO_puts` | `FAILURE_ATOMIC` | the method performs the transfer and `num_write` follows it; a failure return reports the transfer's own outcome |
| `src/runtime/bio/iolib.rs` | `BIO_recvmmsg` | `FAILURE_ATOMIC` | as `BIO_sendmmsg`: the out-count is zeroed first and written once after the method |
| `src/runtime/bio/iolib.rs` | `BIO_sendmmsg` | `FAILURE_ATOMIC` | `*msgs_processed` is zeroed before the method and the method's own result is the only later write |
| `src/runtime/bio/mod.rs` | `BIO_dup_chain` | `ROLLBACK` | a failure frees the unlinked new BIO and the partial head through `BIO_free_all` |
| `src/runtime/bio/mod.rs` | `BIO_find_type` | `FAILURE_ATOMIC` | read-only walk with no mutation |
| `src/runtime/bio/mod.rs` | `BIO_free` | `POISONED` | the reference gate claims the last reference (the destroying sentinel) before any callback; a free-callback veto leaves the object retired, and both reuse and a retry of the release are refused |
| `src/runtime/bio/mod.rs` | `BIO_free_all` | `FAILURE_ATOMIC` | each element is released through the independently guarded `BIO_free`; a veto leaks that element and the walk continues, with no released element reachable from a surviving one |
| `src/runtime/bio/mod.rs` | `BIO_get_retry_BIO` | `FAILURE_ATOMIC` | the walk and the single `reason` write are total after the NULL checks |
| `src/runtime/bio/mod.rs` | `BIO_new_ex` | `FAILURE_ATOMIC` | the block is built locally; an `ex_data` or `create` failure tears the block down before it is published |
| `src/runtime/bio/mod.rs` | `BIO_push` | `FAILURE_ATOMIC` | both chain links are written before the notification; the notification's result is ignored by the authority and the chain graph is complete |
| `src/runtime/bio/mod.rs` | `BIO_up_ref` | `FAILURE_ATOMIC` | one atomic reference increment |
| `src/runtime/bio/mod.rs` | `BIO_vfree` | `FAILURE_ATOMIC` | a forward to `BIO_free`, whose gate is the state transition |
| `src/runtime/ex_data.rs` | `CRYPTO_dup_ex_data` | `PARTIAL_EXPOSED` | the destination is filled slot by slot; a `dup_func` or allocation failure returns 0 with the earlier slots already written |
| `src/runtime/ex_data.rs` | `CRYPTO_free_ex_data` | `PARTIAL_EXPOSED` | free callbacks run before the slot stack is released and the container zeroed; a callback that panics leaves the stack and the zeroing undone |
| `src/runtime/ex_data.rs` | `CRYPTO_get_ex_data` | `FAILURE_ATOMIC` | read-only lookup |
| `src/runtime/ex_data.rs` | `CRYPTO_get_ex_new_index` | `FAILURE_ATOMIC` | a registry slot is appended under the lock; no caller object is touched |
| `src/runtime/ex_data.rs` | `CRYPTO_new_ex_data` | `PARTIAL_EXPOSED` | the container is zeroed and then populated by application `new_func` callbacks; a callback that panics leaves the slots it had already filled |
| `src/runtime/ex_data.rs` | `CRYPTO_set_ex_data` | `FAILURE_ATOMIC` | padding pushes precede the single element write; a failed push leaves only NULL padding |
| `src/runtime/lhash.rs` | `OPENSSL_LH_delete` | `FAILURE_ATOMIC` | the element is removed and the count decremented; the optional contraction cannot fail the operation |
| `src/runtime/lhash.rs` | `OPENSSL_LH_flush` | `FAILURE_ATOMIC` | an in-place clear under the table lock with no fallible step |
| `src/runtime/lhash.rs` | `OPENSSL_LH_free` | `FAILURE_ATOMIC` | one release of the whole table |
| `src/runtime/lhash.rs` | `OPENSSL_LH_insert` | `FAILURE_ATOMIC` | the growth step precedes the bucket push, and `num_items` increments only after that push |
| `src/runtime/obj.rs` | `OBJ_NAME_add` | `FAILURE_ATOMIC` | the entry is published under the lock before the replaced record is retired; a deferred destructor's failure cannot leave the registry inconsistent |
| `src/runtime/obj.rs` | `OBJ_NAME_cleanup` | `FAILURE_ATOMIC` | the registry is cleared under the lock |
| `src/runtime/obj.rs` | `OBJ_NAME_new_index` | `FAILURE_ATOMIC` | a comparator/destructor slot is appended under the lock |
| `src/runtime/obj.rs` | `OBJ_NAME_remove` | `FAILURE_ATOMIC` | the entry is removed under the lock before its deferred release |
| `src/runtime/obj.rs` | `OBJ_add_object` | `FAILURE_ATOMIC` | the record is built locally and inserted under the registry lock |
| `src/runtime/obj.rs` | `OBJ_add_sigid` | `FAILURE_ATOMIC` | a registry append under the lock |
| `src/runtime/obj.rs` | `OBJ_create` | `FAILURE_ATOMIC` | the record is built locally and inserted under the registry lock; a consumed NID is the authority's own observable |
| `src/runtime/obj.rs` | `OBJ_get0_data` | `FAILURE_ATOMIC` | read-only accessor |
| `src/runtime/obj.rs` | `OBJ_length` | `FAILURE_ATOMIC` | read-only accessor |
| `src/runtime/obj.rs` | `OBJ_nid2ln` | `FAILURE_ATOMIC` | read-only lookup |
| `src/runtime/obj.rs` | `OBJ_nid2obj` | `FAILURE_ATOMIC` | read-only lookup of a cached object |
| `src/runtime/obj.rs` | `OBJ_nid2sn` | `FAILURE_ATOMIC` | read-only lookup |
| `src/runtime/obj.rs` | `OBJ_sigid_free` | `FAILURE_ATOMIC` | the registry is cleared under the lock |
| `src/runtime/obj.rs` | `OBJ_txt2nid` | `FAILURE_ATOMIC` | parse and lookup; no caller object is mutated |
| `src/runtime/obj.rs` | `OBJ_txt2obj` | `FAILURE_ATOMIC` | the object is built locally and returned only on success |
| `src/runtime/stack.rs` | `OPENSSL_sk_deep_copy` | `ROLLBACK` | a copy failure frees every element already produced and the unlinked candidate before returning NULL |
| `src/runtime/stack.rs` | `OPENSSL_sk_free` | `FAILURE_ATOMIC` | one `Box::from_raw` release of the whole object; no intermediate publish |
| `src/runtime/stack.rs` | `OPENSSL_sk_insert` | `FAILURE_ATOMIC` | `sk_reserve` precedes the insertion; the length and `sorted` flag change only after the insert succeeds |
| `src/runtime/stack.rs` | `OPENSSL_sk_new_reserve` | `FAILURE_ATOMIC` | the stack is built locally and returned only after `from_boxes` completes; no caller can see a partial object |
| `src/runtime/stack.rs` | `OPENSSL_sk_pop_free` | `ROLLBACK` | each element is removed from the `Vec` before its destructor runs; a panic leaves only the unreleased remainder, and a retry is legal (fixed in this batch) |
| `src/runtime/stack.rs` | `OPENSSL_sk_reserve` | `FAILURE_ATOMIC` | `try_reserve` precedes the `num_alloc` assignment; a refusal leaves the count and the element array unchanged |
| `src/runtime/stack.rs` | `OPENSSL_sk_set` | `FAILURE_ATOMIC` | one element write plus the `sorted` flag; both are total operations after the index check |
| `src/runtime/stack.rs` | `OPENSSL_sk_zero` | `FAILURE_ATOMIC` | one pass setting every slot to NULL, with no fallible step inside it |

## 5. Demonstrated `PARTIAL_EXPOSED` entries

Three entries were `PARTIAL_EXPOSED` before this batch and were demonstrated
with a test-only panic hook. The hook is thread-local, `#[cfg(test)]`-only, and
absent from release behaviour. Each demonstration arms the hook, calls the
entry, lets `guard_ffi` catch the panic, and then uses the object exactly as a
legal caller would.

### 5.1 `BN_BLINDING_update` — the factor and its inverse stop being a pair

The authority (and the pre-fix conversion) squared `Ai` and then `A` in place.
A panic between the two multiplications left `Ai` squared and `A` unsquared.
The object was then **usable**: `BN_BLINDING_update` returned the documented
failure value for the interrupted call, but every later `convert`/`invert`
round trip returned success (1) and a value that does not cancel.

Observed on the pre-fix ordering, with the panic injected between the squares:

```
thread '...a_panic_between_the_blinding_squares...' panicked at src/bn/blinding.rs:
injected defect: panic between the blinding squares
thread '...a_panic_between_the_blinding_squares...' panicked at src/bn/blinding.rs:
assertion failed: unsafe { round_trip_cancels(b, m, d, ctx, keep, expect) }
```

The assertion is the caller-shaped round trip: multiply by the factor,
exponentiate by the private exponent, multiply by the inverse. With the pair
mismatched it does not reproduce `n^d`, while both calls report success.

### 5.2 `BN_BLINDING_create_param` — a fresh factor published before its inverse

With a caller-supplied context, the pre-fix body wrote the fresh random factor
into `b->a` before computing its inverse. A panic after the draw left `b->a`
holding a new random value and `b->ai` holding the inverse of the *previous*
factor. The entry still returned the caller's context (and `guard_ffi`
returned its failure value for the interrupted call), so the caller retained a
context that looked initialised and produced wrong results on every later use.

Observed on the pre-fix ordering:

```
thread '...a_panic_after_the_blinding_draw...' panicked at src/bn/blinding.rs:
injected defect: panic after the blinding draw
thread '...a_panic_after_the_blinding_draw...' panicked at src/bn/blinding.rs:
assertion failed: unsafe { round_trip_cancels(b, m, d, ctx, keep, expect) }
```

### 5.3 `OPENSSL_sk_pop_free` — a released element still reachable

The pre-fix body iterated the element array in place and released the enclosing
stack only after the loop. A panic after the first destructor left the
already-released element in the array. `OPENSSL_sk_value(st, 0)` then handed out
a released pointer, and a retry of `pop_free` invoked the destructor on it a
second time — a double release.

Observed on the pre-fix ordering:

```
thread '...a_panic_during_pop_free...' panicked at src/runtime/stack.rs:
injected defect: panic after an element was released
thread '...a_panic_during_pop_free...' panicked at src/runtime/stack.rs:
assertion `left == right` failed: only the unprocessed element remains
  left: 2
 right: 1
```

### 5.4 Remaining `PARTIAL_EXPOSED` rows

Three `CRYPTO_EX_DATA` entries remain partial: `CRYPTO_new_ex_data`,
`CRYPTO_free_ex_data` and `CRYPTO_dup_ex_data`. They are callback-driven
container state: an application `new_func`/`free_func`/`dup_func` (or an
allocation) that fails part-way leaves the slots it had already visited. They
are recorded rather than fixed because the object is a generic extension-slot
container, not a key/nonce/plaintext/digest/verified-chain context, and the
partial population is produced by the application callback rather than by a
library algorithm. A fix would require a per-class transactional slot protocol
whose compatibility consequences are not measured here.

## 6. Repairs

All three repairs are failure-atomic: every fallible step runs against
temporaries, and the object is changed only after the last one succeeds. No
success-path return value changes.

### 6.1 `BN_BLINDING_update`

- **Before:** `ai = ai²` in place, then `a = a²` in place. A failure or panic
  between them left a non-inverse pair and an advanced counter.
- **After:** both squares are computed into `TempBn` locals (cleansed on every
  exit, including unwind) and published with `BN_swap` (`publish_member`) only
  after both succeed. The counter is committed with the pair and rolled back on
  failure. A failed re-creation is detected through the internal
  `create_param_impl` instead of the exported wrapper's pointer, which answers
  `b` for a non-null `b` even on failure.
- **Observed after:** the interrupted call returns 0; the factor pair is
  unchanged; the caller-shaped round trip still cancels; a retry succeeds.

### 6.2 `BN_BLINDING_create_param`

- **Before:** `b->a` was filled with the fresh draw, `b->e` was replaced, and
  `m_ctx`/`bn_mod_exp` were installed before the inverse, exponentiation and
  Montgomery conversion had succeeded. On failure the caller got `b` itself,
  partly updated.
- **After:** `create_param_impl` computes the factor, its inverse and the new
  exponent into `TempBn` locals, using the effective exponent and Montgomery
  context from the arguments without publishing them. `a`, `ai`, `e`,
  `m_ctx` and `bn_mod_exp` are published together after every fallible step.
  A failure leaves `b` exactly as it was. The return value for a non-null `b`
  is unchanged (`b`); for a null `b` the new context is still freed and NULL is
  returned.
- **Compatibility delta:** on the failure path the authority returns a partly
  initialised `b`; this implementation returns `b` unchanged. That is a
  deliberate safety improvement on an error path, recorded here and in
  `RECEIPT.md`. No success-path value changes.

### 6.3 `OPENSSL_sk_pop_free`

- **Before:** iterate in place; release the stack after the loop.
- **After:** each element is removed from the vector **before** its destructor
  runs. A panic therefore leaves only elements whose destructors have not yet
  run, in their original order, and the enclosing stack alive. A retry is legal
  and releases the remainder exactly once.
- **Compatibility delta:** destruction order is unchanged (front to back). The
  loop is O(n²) in the number of elements because `Vec::remove(0)` shifts; the
  element count is already bounded by the stack's `INT_MAX` ceiling, and the
  alternative — publishing a released element — is the defect. No success-path
  return value changes (the function returns `void`).

### 6.4 Allocation delta

Both blinding repairs allocate temporaries that the in-place authority did not:
two `BIGNUM`s per squaring update and two per `create_param` call (plus one
duplicate when the caller supplies an exponent). They are Rust-allocator
`BIGNUM`s, not `CRYPTO_*`-seam allocations, so a `CRYPTO_set_mem_functions`
hook does not observe them; the values they replace are cleansed. The delta is
recorded because allocation surveys (T21/T29) count Rust allocations as well.

### 6.5 Test hooks

`#[cfg(test)]` hooks inject the panic at the pre-fix mutation point:

- `src/bn/blinding.rs::test_hooks::{arm_between_squares,arm_after_draw}`;
- `src/runtime/stack.rs::test_hooks::arm_mid_pop_free`.

They are thread-local, consumed once, and compiled out of release builds. They
are the only injected panics; no production path gained a panic.

## 7. Tests and revert controls

| entry | failure-path test | success-path test | revert control (observed) |
|---|---|---|---|
| `BN_BLINDING_update` | `bn::blinding::tests::a_panic_between_the_blinding_squares_leaves_the_factor_pair_usable` | `bn::blinding::tests::the_blinding_round_trip_cancels_after_the_private_exponentiation` | publishing `ai` before computing the `a` square → the failure-path test fails on `round_trip_cancels` |
| `BN_BLINDING_create_param` | `bn::blinding::tests::a_panic_after_the_blinding_draw_does_not_publish_the_new_factor` | `bn::blinding::tests::create_param_on_an_existing_context_still_publishes_a_cancelling_pair` | copying the fresh draw into `b->a` before the inverse → the failure-path test fails on `round_trip_cancels` |
| `OPENSSL_sk_pop_free` | `runtime::stack::tests::a_panic_during_pop_free_leaves_only_unreleased_elements_reachable` | `runtime::stack::tests::pop_free_releases_each_element_once_on_the_success_path` | restoring the in-place iteration → the failure-path test fails with `sk_num == 2` |

The revert controls were executed by temporarily restoring the pre-fix
ordering in the working tree, running the named tests, recording the failure
output (quoted in §5), and restoring the fixed files. The committed tests are
the fixed ones; the control is the same test under the reverted ordering.

## 8. Entries deliberately left alone

| class / entry | reason |
|---|---|
| `CRYPTO_new_ex_data`, `CRYPTO_free_ex_data`, `CRYPTO_dup_ex_data` (`PARTIAL_EXPOSED`) | generic extension-slot container; the partial population is application callback state; see §5.4. |
| `BIO_free` (`POISONED`) | the existing reference gate already refuses reuse and retry after a free-callback veto; no change needed. |
| `BIO_push` | the chain links are complete before the notification; the notification result is ignored by the authority, so there is no half-applied link. |
| `BIO_free_all` | a veto leaks the element and the walk continues; no released element is reachable from a surviving one. Leak-only, not partial state. |
| `BN_bn2bin`, `BN_bn2mpi` (and the `BIO` read paths) | the only mutable storage is the caller's output buffer; see the buffer non-claim below. |
| all remaining 744 mutation candidates (823 − 79) | outside the covered object owners. They are `NOT_AUDITED`, not `PASS`. |

## 9. Non-claims

- **Not universal atomicity.** 79 of 823 mutation candidates are classified;
  the rest are `NOT_AUDITED`. No entry is claimed atomic because it passed a
  focused test.
- **Not a `SAFETY_DISCHARGED` claim.** The repairs have unit evidence and revert
  controls, but no independent adjudication, no Miri/sanitizer run and no
  dependency-closure analysis. `OBL-PANIC-ATOMICITY` remains open.
- **Caller output buffers are not covered.** A defect that panics mid-copy can
  leave a partial buffer in `BN_bn2bin`, `BN_bn2mpi`, `BIO_gets` or
  `BIO_get_line`. The failure return is the documented discard signal and no
  library object is inconsistent; claiming those buffers atomic would require a
  temporary copy and is not done here.
- **`evp`, `rsa`, `ec`, `x509` entry points are not in the covered
  population.** They do not call `guard_ffi`: a panic there aborts at Rust's
  `extern "C"` boundary rather than being caught with a partially mutated
  object. That is a different defect class (an abort, not a caught partial
  state) and was not changed here. `HAZ-16`'s residual risk for those families
  is therefore not bounded by this document.
- **Application callbacks are reentrancy edges, not atomicity boundaries.** A
  callback that mutates the object it runs on is `HAZ-06`/`HAZ-20` territory;
  this document classifies only the library's own mutations around a callback.
- **No timing or constant-time claim** is made about the repaired blinding
  paths. The repairs add allocations and a swap on the failure-atomic path; the
  constant-time posture of the arithmetic kernels is unchanged and is measured
  elsewhere (T7/T19).
