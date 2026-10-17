# Runtime / alias adjudication — `SslCtx`, `Ssl`, `X509Store` (subphase 39)

> **Subphase 40 update.** The callback re-entrancy edge recorded below is now
> repaired for all four reference-counted types by a destroying sentinel in the
> existing `AtomicI32` count (`src/runtime/refcount.rs`). Deterministic
> re-entrancy tests pass for `X509Store`, `SslSession`, `SslCtx` and `Ssl`. No row
> is promoted to `SAFETY_DISCHARGED`: the §7 dependency closure and independent
> check package remain outstanding.
>
> **Subphase 41 update.** `Ssl` and `SslCtx` are promoted to `ESTABLISHED`
> after a field-by-field ownership audit against the authority and four concrete
> fixes: the session-cache `owner` back-pointer is cleared on every removal path
> (S1, a use-after-free), the context finishes its structural `ENGINE` reference
> (S2), the connection releases its DANE state (S3), and `SSL_free` performs the
> authority's `ssl_clear_bad_session` before releasing the session (S4). Seven
> deterministic alias/refcount tests were added. `X509Store` stays `CONTRACTED`;
> nothing is `SAFETY_DISCHARGED`.
>
> **Subphase 42 update.** `X509Store` is promoted to `ESTABLISHED` after driving
> the lookup `free` hook independently: `store_free_from_lookup_free_hook_is_defined_noop`
> asserts the hook runs once, observes `REF_DESTROYING`, sees `X509_STORE_up_ref`
> refuse resurrection, and that the re-entrant `X509_STORE_free` leaves the
> sentinel in place. The teardown order is the authority's. The ex-data callback's
> authority-parity partial-release exposure is recorded in §5 as a retained
> obligation; the two D1/D2 `CipherDestroy` rows are re-adjudicated to
> `ESTABLISHED`. Nothing is `SAFETY_DISCHARGED`.

Independent runtime-boundary review of the three `CONTRACTED` `CtxDestroy`
rows. Source witnesses are current-candidate line numbers at the time of this
pass. No row is promoted to `DISCHARGED`; the authority, ABI, allocator
coordinates, free order and `#[repr(C)]` offsets are unchanged except for the
layout-compatible atomic swap recorded in row 3.

## Row verdicts

| row | refcount | callback re-entrancy | alias/lifecycle | status |
|---|---|---|---|---|
| `SslCtx` (`src/ssl/ssl_lib.rs` `SslCtx::destroy_body`) | `AtomicI32`, sentinel gate sound | **repaired**: sentinel no-op, test passes | S1 owner back-pointer fixed; S2 engine finish added | `ESTABLISHED` |
| `Ssl` (`src/ssl/ssl_lib.rs` `Ssl::destroy_body`) | `AtomicI32`, sentinel gate sound | **repaired**: sentinel no-op, test passes | S3 DANE final added; S4 cache teardown added; chains borrowed-by-accessor | `ESTABLISHED` |
| `X509Store` (`src/x509/x509_lu.rs:770-805`) | **fixed**: `AtomicI32`, layout-compatible | **repaired**: sentinel no-op, ex-data and lookup-`free` tests pass | store callbacks gate through the same sentinel | `ESTABLISHED` |

No STOP defect was introduced. S1–S4 were real ownership/lifecycle defects and
are fixed; the callback edge in all three rows is a retained boundary, not a
claim of safety. `ESTABLISHED` is the subphase-38 source-witness status, not
`DISCHARGED`.

## 1. `X509Store` refcount — defect and fix

**Verdict: yes, a real defect for concurrent use.**

Before this pass the store stored `CRYPTO_REF_COUNT references` as a plain
`c_int` and moved it with ordinary read-modify-write:

- `X509_STORE_up_ref` read `(*xs).references`, added one, wrote it back
  (old `:1945-1948`);
- `X509_STORE_free` did the same subtraction, wrote it back, then freed when
  the result was `<= 0` (old `:1883-1888`);
- the constructor wrote `references = 1` (old `:1859`).

That is a data race under the OpenSSL reference-count contract. Two concurrent
`up_ref`s can read the same value and lose one increment; a last `free` racing
an `up_ref` can free the store while the other caller believes it holds a
reference, or can leave a live count on a freed block (use-after-free). The
authority does not behave this way: `include/internal/refcount.h` defines
`CRYPTO_UP_REF` as `ossl_atomic_add_fetch` and `CRYPTO_DOWN_REF` as
`ossl_atomic_sub_fetch` with an acquire fence on zero. The C ABI is explicitly
multi-context: `SSL_CTX_set1_cert_store` (`src/ssl/ssl_lib.rs:7837-7842`)
takes a store reference that may be exercised and released from different
threads, which is why the authority's gate is atomic.

**Fix.** `references` is now `core::sync::atomic::AtomicI32`; the three sites
use the authority's orderings:

- constructor: `store(1, Relaxed)` (`src/x509/x509_lu.rs:1870`);
- `X509_STORE_up_ref`: `fetch_add(1, Relaxed)`.wrapping_add(1)
  (`:1958`), still answering `i > 1`;
- `X509_STORE_free`: `fetch_sub(1, Release)`.wrapping_sub(1), acquiring
  `fence(Acquire)` when the new count is zero, then the existing `i > 0`
  early return (`:1894-1900`).

**Layout audit.** `AtomicI32` has the same size and alignment as `c_int`
(4/4). The compile-time asserts now pin size 160, `references` offset 144,
`lock` offset 152, `X509Store` align 8, and explicitly assert
`size_of::<AtomicI32>() == size_of::<c_int>()` plus the alignment equality
(`:511`, `:535-541`). Every other field, `#[repr(C)]`, exported signature,
allocator size (`CRYPTO_zalloc(size_of::<X509Store>(),
"crypto/x509/x509_lu.c", 184)`), free site (`:253`) and member free order are
unchanged. A C caller reading or writing the member as `int` observes the same
bytes; the crate's own operations are now the authority's atomic operations.

**Test.** `store_refcount_is_atomic_under_concurrent_up_ref`
(`src/x509/x509_lu.rs`, test module after `X509_STORE_up_ref`) starts 8
threads, each performing 2,000 `X509_STORE_up_ref` calls on one store, then
asserts the count is exactly `1 + 8 * 2,000` and releases exactly that many
references. Under the old plain read-modify-write the test is a data race with
lost updates and can fail or trigger a premature final free; under the atomic
field the result is deterministic.

**Compatibility delta.** None observable: the new-count answer of `up_ref`
(`1` unless the count was zero), the release point, the free order and the
block coordinates are identical. The only change is the ordering/atomicity the
authority already specifies. The test adds one library test.

**Retained status (why the row stayed `CONTRACTED` through subphase 41).**
`destroy_body` still runs the `X509_LOOKUP_METHOD.free` hook via
`X509_LOOKUP_free` (`:790-794`) and the store ex-data `free_func` via
`CRYPTO_free_ex_data` (`:797-801`), and either can call `X509_STORE_free(xs)`
again. **Repaired in subphase 40:** the gateway installs `REF_DESTROYING` before
the body runs, so the re-entrant call observes the sentinel and returns without a
second `OwnedCtx`. **Driven independently in subphase 42:** the lookup `free`
hook now has its own deterministic test (§5); the row is promoted to
`ESTABLISHED` and retains only the §7 independent-check package plus the
authority-parity partial-release path recorded there.

## 2. `Ssl` / `SslCtx` callback re-entrancy — repaired in subphase 40

**Verdict: the edge was reachable; the gate now rejects it.** It is not
reachable from wholly safe Rust code (`SSL_free`/`SSL_CTX_free` and callback
registration are FFI surfaces), but it is reachable from a C application
callback, which §21 treats as part of the boundary rather than an
assumed-correct actor. The line numbers in this section are the subphase-39
candidate witnesses; the subphase-40 gate is in `src/runtime/refcount.rs`.

`CRYPTO_free_ex_data` invokes every registered `free_func` with
`obj =` the object pointer and the registry lock already released
(`src/runtime/ex_data.rs:489-501`); the slots are zeroed only after the
callbacks (`:505-516`). Nothing suppresses re-entry.

`Ssl` exact path:

1. `SSL_free(s)` decrements `s->references` to 0 (`src/ssl/ssl_lib.rs:3505`).
2. `OwnedCtx::<Ssl>::from_raw(s)` takes ownership and `Drop` calls
   `Ssl::destroy_body` (`:3512`, `:3523`).
3. `destroy_body` calls `SSL_SESSION_free(s->session)` (`:3542`),
   `BIO_free_all(s->wbio)` / `BIO_free_all(s->rbio)` (`:3546-3547`), then
   `CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data)` (`:3573`).
4. The application `free_func` receives `obj = s` itself. `BIO_free` performs
   its own ex-data callback with the BIO as `obj`
   (`src/runtime/bio/mod.rs:1110-1116`), and a BIO `destroy`/callback can
   recover `s` from `argp` or `BIO_get_data`.
5. Before subphase 40, that callback called `SSL_free(s)` again: the count was
   0, `down_ref` yielded -1, `if i > 0` was false, so a **second**
   `OwnedCtx::<Ssl>` was created and `destroy_body` ran a second time on the
   same block/members. The sentinel now makes that second call a no-op.

Why the old refcount did not prevent it: zero was not a distinguished
"destroying" state. Any `free` that observed `i <= 0` was treated as the last
reference, and any `up_ref` could still add one to a zero count (returning
failure while corrupting the count). `guard_ffi` only prevents an unwind from
crossing the ABI; it does not roll back or poison the half-destroyed object.
The subphase-40 sentinel supplies that ownership state.

`SslCtx` exact path: `SSL_CTX_free(ctx)` decrements to 0 (`:3140`), takes
`OwnedCtx::<SslCtx>` (`:3147`), and `destroy_body` dispatches
`CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, …)` (`:3174`), then
`X509_STORE_free(ctx->cert_store)` (`:3175`) and
`CTLOG_STORE_free(ctx->ctlog_store)` (`:3178`). The context's own
`free_func` receives `obj = ctx`; the store's lookup `free` hook and ex-data
callback, and the CT-log callback, can recover `ctx` through application
state. Before subphase 40 a re-entrant `SSL_CTX_free(ctx)` again saw zero and
tore the context down a second time; the sentinel now rejects it.

Session interaction: `Ssl::destroy_body` releases the session before the SSL
ex-data callback (`:3542`). `SSL_SESSION_free` uses the same `i > 0` gate
(`src/ssl/ssl_sess.rs:541-548`) and invokes its ex-data callback at `:566`,
so `SSL_SESSION_free` had the same self-re-entrancy shape (already
`ESTABLISHED` for its non-callback obligations). The subphase-40 gate now
rejects the re-entry; the deterministic session test passes. A session callback
can reach `SSL_free` only through application state, not through its own `obj`
pointer.

**Why the fix is a state guard, not callback removal.** The edge is identical
in the C authority (`SSL_free`/`SSL_CTX_free` also reach `CRYPTO_free_ex_data`
with a zero count, and `REF_ASSERT_ISNT(i < 0)` is compiled out under
`NDEBUG`), so it is UB in the authority rather than a documented behaviour to
conserve (§17). The callback is also a legitimate extension point, so the
correct unit is a state guard.

**Implemented (subphase 40).** Poison the existing `AtomicI32` instead of adding
a field (layouts are fixed). The shared protocol is `src/runtime/refcount.rs`:

- `*_free` loads the count; zero, a negative value and `REF_DESTROYING`
  (`i32::MIN`) are a defined no-op. A positive `n > 1` is released with
  `compare_exchange(n, n - 1, Release, Acquire)`; `n == 1` is claimed with
  `compare_exchange(1, REF_DESTROYING, AcqRel, Acquire)`, and only the winner
  runs the destructor body. The `AcqRel` success ordering carries the
  authority's release down-ref plus the acquire fence at zero.
- `*_up_ref` CAS-increments only a positive count (`Relaxed`, the authority's
  ordering); zero or `REF_DESTROYING` answers failure (`0`) without changing the
  count, so a dying object cannot be resurrected.
- `SSL_dup`'s quiescent path now returns NULL when that guarded increment fails
  instead of returning a connection whose count could not be raised.

This turns the authority's over-free UB into a defined no-op/failure, a
deliberate §17 safety divergence. All four reference-counted types
(`Ssl`, `SslCtx`, `SslSession`, `X509Store`) use the same gate.

## 3. Subphase 40 — deterministic re-entrancy controls

The gate has one test per reference-counted type, plus four unit tests for the
protocol itself. Each type test registers a real `CRYPTO_EX_free` callback for
that object class, sets the callback slot on one object, frees that object once,
and asserts the callback ran exactly once and that its re-entrant `*_free` was a
no-op:

| type | test | callback re-enters | result |
|---|---|---|---|
| `X509Store` | `x509::x509_lu::tests::store_free_reentrancy_is_defined_noop` | `X509_STORE_free(store)` | pass |
| `SslSession` | `ssl::ssl_sess::refcount_reentrancy_tests::session_free_reentrancy_is_defined_noop` | `SSL_SESSION_free(session)` | pass |
| `SslCtx` | `ssl::ssl_lib::refcount_reentrancy_tests::ctx_free_reentrancy_is_defined_noop` | `SSL_CTX_free(ctx)` | pass |
| `Ssl` | `ssl::ssl_lib::refcount_reentrancy_tests::ssl_free_reentrancy_is_defined_noop` | `SSL_free(ssl)` | pass |

The callbacks are gated on the object address, so the process-global ex-data
index they register is inert for every other object. The tests use no
allocator hook and are ordinary (not `#[ignore]`d) library tests.

`src/runtime/refcount.rs` also carries `down_ref_claims_last_reference_then_retires`,
`up_ref_refuses_zero_and_destroying`, `up_ref_preserves_positive_count_answer` and
`ref_destroying_never_matches_a_live_count`.

## 4. Subphase 41 — `Ssl`/`SslCtx` alias/lifecycle closure

### 4.1 Ownership rules established

The complete field-by-field table is in `DESTRUCTOR-CONTRACTS.md` →
“Subphase 41”. The rules that close the alias obligations are:

- **Two context references, never one shared ref.** `SSL_new` up-refs `ctx`
  (authority `ssl_lib.c:705`) and separately `session_ctx` (`:828`).
  `SSL_set_SSL_CTX` (authority `:5492-5543`) up-refs the new context and
  releases only `ctx`; `session_ctx` keeps the original context alive. The
  destructor releases both once. Test:
  `ssl_set_ssl_ctx_keeps_the_two_context_references_distinct` (counts
  `3/1 -> 2/2 -> 1/1`).
- **The session is a strong reference.** `SSL_set_session` up-refs before the
  assignment and only releases the incoming reference on its failure arm
  (authority `ssl_sess.c:945-970`); lookup returns a ref-owning session; the
  destructor releases exactly one reference. `SSL_get_session` and
  `SSL_get_peer_cert_chain` borrow; `SSL_get1_session` is the explicit new-ref
  accessor. Test: `set_session_and_ssl_free_release_the_session_once`
  (`1 -> 2 -> 1 -> 2 -> 1 -> 0`).
- **The chains are owned by the connection, borrowed by the accessors.**
  `peer_chain` and `verified_chain` are separate stacks of owned `X509`
  references (`verified_chain` comes from `X509_STORE_CTX_get1_chain`), each
  freed once by `OSSL_STACK_OF_X509_free`. `SSL_get_peer_cert_chain` and
  `SSL_get0_verified_chain` return the stored pointer, never an up-ref and
  never a transfer. The reduced path's session-NULL fallback to
  `s->peer_chain` is a documented divergence from the authority's NULL answer.
  Test: `peer_and_verified_chain_accessors_return_borrowed_owners`.
- **`SSL_dup`/`SSL_clear` do not create shared owners.** `SSL_dup` builds a
  fresh `SSL_new` (its own two context refs), duplicates chains/cert material,
  and never shares an owned pointer with the source; the session arm remains a
  recorded reduction (the fresh-connection branch is the reachable one).
  `SSL_clear` remains the recorded reduced body (method check only), so it
  performs no release and creates no alias.
- **`SslSession.owner` is a weak back-pointer.** It is never released by the
  session destructor; every cache removal path must clear it.

### 4.2 Defects found and fixed

| id | defect | fix | source witness |
|---|---|---|---|
| S1 | `SslSession.owner` survived cache removal/flush/context teardown; a caller-held session then pointed into a freed `SSL_CTX` and `SSL_SESSION_set_timeout` read `owner->lock` | clear `owner` in `cache_delete_ptr`, `SSL_CTX_flush_sessions_ex` and `ssl_ctx_session_cache_free` | authority `SSL_SESSION_list_remove`, `ssl_sess.c:1349` |
| S2 | `SSL_CTX_set_client_cert_engine`'s structural `ENGINE_init` reference was never finished | `ENGINE_finish((*ctx).client_cert_engine)` in `SslCtx::destroy_body` | authority `tls_engine_finish`, `ssl_lib.c:4409` |
| S3 | per-connection DANE records/certs/matched cert leaked on `SSL_free` | `dane_final(&mut (*s).dane)` in `Ssl::destroy_body` | authority `ssl_lib.c:1462` |
| S4 | `SSL_free` released `s->session` without first removing it from the cache | `ssl_clear_bad_session(s)` before `SSL_SESSION_free` | authority `ssl_lib.c:1473-1476` |

No `#[repr(C)]` layout, exported signature, allocator coordinate, or member
release order was changed: S2 is inserted at the authority's position, and S3/S4
add the authority's own calls before the existing `cert_free`/`SSL_SESSION_free`.

### 4.3 Tests added

Seven deterministic library tests (not ignored, no allocator hook). The three in
`ssl_sess.rs` assert the `owner` is NULL after removal, after flush, and after
context teardown while the session is still alive; the last also calls
`SSL_SESSION_set_timeout`/`_get_timeout` on the surviving session, which would
have dereferenced the freed context before S1. The four in `ssl_lib.rs` assert
the session reference sequence, the `SSL_new`/`SSL_free` context balance, the
`SSL_set_SSL_CTX` split, and chain accessor identity/borrowed ownership.

### 4.4 Status and retained obligations

`Ssl` and `SslCtx` are `ESTABLISHED`. Retained: the §7 independent-check
package; the currently-unset `Ssl` members (`waitctx`, `bbio`, `scts`,
`shared_sigalgs`, `peer_sigalgs`) have no release path because no writer in this
slice allocates them — a future writer must add one; and `SSL_clear`/`SSL_dup`
session arms remain recorded compatibility reductions. Nothing is
`SAFETY_DISCHARGED`.

## 5. Subphase 42 — `X509Store` callback-family closure and D1/D2 re-adjudication

**Test added.** `x509::x509_lu::tests::store_free_from_lookup_free_hook_is_defined_noop`
builds a minimal `X509_LOOKUP_METHOD` whose only callback is `free`, installs it
with `X509_STORE_add_lookup`, and calls `X509_STORE_free` on the store's sole
reference. The hook:

1. runs exactly once;
2. reads `references == REF_DESTROYING` before re-entry;
3. calls `X509_STORE_up_ref`, which answers `0` and does not change the count;
4. re-enters `X509_STORE_free(store)`; and
5. reads the count after that call and finds `REF_DESTROYING` still in place.

Together with `DownRef::Last` being the only arm that builds
`OwnedCtx::<X509Store>`, this witnesses a single block release: the re-entrant
call cannot reach `Last` or a second `destroy_body`.

**Teardown order.** Candidate (`src/x509/x509_lu.rs:786-806`) and authority
(`crypto/x509/x509_lu.c:240-253`): lookups (`shutdown`, then `free` → method
`free` hook) → lookup stack → object cache → ex-data (`free_func`)
→ verify param → lock → block. All member releases are single and
NULL/zero-tolerant for the all-zero store.

**Callbacks that can observe teardown state.**

- The lookup `free` hook runs before any store member is released, so it sees a
  fully built store whose count is `REF_DESTROYING`; re-entry is defined.
- The ex-data `free_func` runs after `get_cert_methods` and `objs` are released,
  with both struct fields still holding the freed pointers. A callback that calls
  `X509_STORE_free`/`X509_STORE_up_ref` is defined; one that calls a store mutator
  reading `objs`/`get_cert_methods` (for example `X509_STORE_add_lookup`,
  `X509_STORE_add_cert`, `X509_STORE_add_crl`) would dereference freed memory.
  This is the authority's own order (`:246-249`) and is retained as a callback
  contract, not counted as a conversion defect.
- The candidate caches `OPENSSL_sk_num` before the lookup loop; the authority
  re-evaluates it (`:241`). A hook that pushes another lookup during teardown is
  freed by the authority and left on the freed stack here (callback-created leak
  only). Retained divergence.

**D1/D2.** `ProvAesSivCtx` and `ProvAesGcmSivCtx` are `ESTABLISHED`: the body is
the authority's `*_freectx` minus the block, the NULL `hw` guard makes the
all-zero state a no-op, both hardware lookups always return a static table, and
`a_zeroed_siv_context_drops_without_a_hardware_table` exercises the zero state.
The guard is a §17 divergence for the unconstructed state only (the authority
dereferences unconditionally); no sanitizer/model-checker backs the control.
Neither row is `SAFETY_DISCHARGED`.

## Evidence limits (subphase 41)

- The concurrent-increment test exercises lost updates, not every interleaving;
  no loom/Miri/sanitizer run was performed for this pass.
- The re-entrancy controls are deterministic single-threaded runs. They prove
  the sentinel path rejects the in-body re-entry; they are not a model-checked
  proof of every interleaving, and no Miri/sanitizer/loom run was performed.
- The tests cover the ex-data `free_func` and, since subphase 42, the lookup
  `free` hook. The `BIO_free_all` and CT-log callback paths reach the same
  `*_free` gate, so the same protocol applies, but those specific callback
  families were not driven independently.
- The subphase-42 ex-data partial-release path is source-witnessed, not triggered:
  no test calls a store mutator from the callback, because the authority's own
  ordering makes that a caller-contract violation rather than a supported state.
- S1 is proven by the deterministic `owner == NULL` assertions and the
  surviving-session timeout call; the absence of a use-after-free is not backed
  by ASan/Miri in this pass. S2/S3 are source-witnessed authority-parity fixes;
  no allocator hook or leak detector measured the released bytes.
- The unset `Ssl` members (`waitctx`, `bbio`, `scts`, `shared_sigalgs`,
  `peer_sigalgs`) are asserted unset by source inspection, not by a runtime
  invariant.
- No row is `SAFETY_DISCHARGED`; §7's dependency-closure and independent-check
  package remains outstanding.
