# Runtime / alias adjudication — `SslCtx`, `Ssl`, `X509Store` (subphase 39)

> **Subphase 40 update.** The callback re-entrancy edge recorded below is now
> repaired for all four reference-counted types by a destroying sentinel in the
> existing `AtomicI32` count (`src/runtime/refcount.rs`). Deterministic
> re-entrancy tests pass for `X509Store`, `SslSession`, `SslCtx` and `Ssl`. No row
> is promoted to `SAFETY_DISCHARGED`: the §7 dependency closure and independent
> check package remain outstanding.

Independent runtime-boundary review of the three `CONTRACTED` `CtxDestroy`
rows. Source witnesses are current-candidate line numbers at the time of this
pass. No row is promoted to `DISCHARGED`; the authority, ABI, allocator
coordinates, free order and `#[repr(C)]` offsets are unchanged except for the
layout-compatible atomic swap recorded in row 3.

## Row verdicts

| row | refcount | callback re-entrancy | status |
|---|---|---|---|
| `SslCtx` (`src/ssl/ssl_lib.rs:3155-3187`) | `AtomicI32`, last-ref gate sound (`:1302`, `:3134-3148`, `:2902-2909`) | **repaired**: sentinel no-op, test passes | `CONTRACTED` |
| `Ssl` (`src/ssl/ssl_lib.rs:3520-3584`) | `AtomicI32`, last-ref gate sound (`:1637`, `:3499-3514`, `:2902-2909`) | **repaired**: sentinel no-op, test passes | `CONTRACTED` |
| `X509Store` (`src/x509/x509_lu.rs:770-805`) | **fixed**: `AtomicI32`, layout-compatible (`:511`, `:535-541`, `:1870`, `:1894-1900`, `:1958`) | **repaired**: sentinel no-op, test passes | `CONTRACTED` |

No STOP defect was introduced. The `X509Store` refcount defect is a genuine
boundary defect and is fixed; the callback edge in all three rows is a retained
boundary, not a claim of safety.

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

**Retained status (why the row stays `CONTRACTED`).** `destroy_body` still runs
the `X509_LOOKUP_METHOD.free` hook via `X509_LOOKUP_free` (`:790-794`) and the
store ex-data `free_func` via `CRYPTO_free_ex_data` (`:797-801`), and either
can call `X509_STORE_free(xs)` again. **Repaired in subphase 40:** the new gate
installs `REF_DESTROYING` before the body runs, so the re-entrant call observes
the sentinel and returns without a second `OwnedCtx`. The row remains
`CONTRACTED` because the positive control is a deterministic unit test, not the
§7 independent-check package.

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

## Evidence limits (subphase 40)

- The concurrent-increment test exercises lost updates, not every interleaving;
  no loom/Miri/sanitizer run was performed for this pass.
- The re-entrancy controls are deterministic single-threaded runs. They prove
  the sentinel path rejects the in-body re-entry; they are not a model-checked
  proof of every interleaving, and no Miri/sanitizer/loom run was performed.
- The tests cover the ex-data `free_func` edge. The `BIO_free_all`, lookup
  `free` hook and CT-log callback paths reach the same `*_free` gate, so the
  same protocol applies, but those specific callback families were not driven
  independently.
- No row is `SAFETY_DISCHARGED`; §7's dependency-closure and independent-check
  package remains outstanding.
