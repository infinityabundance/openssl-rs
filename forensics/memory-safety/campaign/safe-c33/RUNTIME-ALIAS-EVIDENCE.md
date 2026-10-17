# Runtime / alias adjudication — `SslCtx`, `Ssl`, `X509Store` (subphase 39)

Independent runtime-boundary review of the three `CONTRACTED` `CtxDestroy`
rows. Source witnesses are current-candidate line numbers at the time of this
pass. No row is promoted to `DISCHARGED`; the authority, ABI, allocator
coordinates, free order and `#[repr(C)]` offsets are unchanged except for the
layout-compatible atomic swap recorded in row 3.

## Row verdicts

| row | refcount | callback re-entrancy | status |
|---|---|---|---|
| `SslCtx` (`src/ssl/ssl_lib.rs:3155-3187`) | `AtomicI32`, last-ref gate sound (`:1302`, `:3134-3148`, `:2902-2909`) | **reachable** | `CONTRACTED` |
| `Ssl` (`src/ssl/ssl_lib.rs:3520-3584`) | `AtomicI32`, last-ref gate sound (`:1637`, `:3499-3514`, `:2902-2909`) | **reachable** | `CONTRACTED` |
| `X509Store` (`src/x509/x509_lu.rs:770-805`) | **fixed**: `AtomicI32`, layout-compatible (`:511`, `:535-541`, `:1870`, `:1894-1900`, `:1958`) | **reachable** | `CONTRACTED` |

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

**Retained blocker (why the row stays `CONTRACTED`).** `destroy_body` runs two
application-controlled callback classes after the count has reached zero: the
`X509_LOOKUP_METHOD.free` hook via `X509_LOOKUP_free` (`:790-794`) and the
store ex-data `free_func` via `CRYPTO_free_ex_data` (`:797-801`). Either can
call `X509_STORE_free(xs)` again. The gate is `i > 0`; a second call takes the
count from 0 to -1, gets `i <= 0`, and constructs a second `OwnedCtx`, so the
store is torn down twice. Atomicity does not prevent this; the missing piece
is an explicit "destroying" ownership state.

## 2. `Ssl` / `SslCtx` callback re-entrancy — reachable

**Verdict: reachable; retained boundary.** It is not reachable from wholly
safe Rust code (`SSL_free`/`SSL_CTX_free` and callback registration are FFI
surfaces), but it is reachable from a C application callback, which §21 treats
as part of the boundary rather than an assumed-correct actor.

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
5. That callback calls `SSL_free(s)` again. The count is 0, so
   `down_ref` yields -1; `if i > 0` is false, so a **second**
   `OwnedCtx::<Ssl>` is created and `destroy_body` runs a second time on the
   same block/members.

Why the refcount does not prevent it: zero is not a distinguished
"destroying" state. Any `free` that observes `i <= 0` is treated as the last
reference, and any `up_ref` can still add one to a zero count (returning
failure while corrupting the count). `guard_ffi` only prevents an unwind from
crossing the ABI; it does not roll back or poison the half-destroyed object.

`SslCtx` exact path: `SSL_CTX_free(ctx)` decrements to 0 (`:3140`), takes
`OwnedCtx::<SslCtx>` (`:3147`), and `destroy_body` dispatches
`CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, …)` (`:3174`), then
`X509_STORE_free(ctx->cert_store)` (`:3175`) and
`CTLOG_STORE_free(ctx->ctlog_store)` (`:3178`). The context's own
`free_func` receives `obj = ctx`; the store's lookup `free` hook and ex-data
callback, and the CT-log callback, can recover `ctx` through application
state. A re-entrant `SSL_CTX_free(ctx)` again sees zero and tears the context
down a second time.

Session interaction: `Ssl::destroy_body` releases the session before the SSL
ex-data callback (`:3542`). `SSL_SESSION_free` uses the same `i > 0` gate
(`src/ssl/ssl_sess.rs:541-548`) and invokes its ex-data callback at `:566`,
so `SSL_SESSION_free` has the same self-re-entrancy shape (already
`ESTABLISHED` for its non-callback obligations; this callback edge is not
discharged). A session callback can reach `SSL_free` only through application
state, not through its own `obj` pointer.

**Why this is not being redesigned in this subphase.** The edge is identical
in the C authority (`SSL_free`/`SSL_CTX_free` also reach `CRYPTO_free_ex_data`
with a zero count, and `REF_ASSERT_ISNT(i < 0)` is compiled out under
`NDEBUG`), so it is UB in the authority rather than a documented behaviour to
conserve (§17). The callback is also a legitimate extension point, so the
correct unit is a state guard, not removal of the callback.

**Minimal proposed fix (next subphase).** Poison the existing `AtomicI32`
instead of adding a field (layouts are fixed):

- after the last release in `SSL_free` / `SSL_CTX_free` / `X509_STORE_free`,
  `compare_exchange(0, DESTROYING, AcqRel, Acquire)`, where `DESTROYING` is a
  reserved sentinel (e.g. `i32::MIN`) that can never be a legitimate count;
- `*_free` returns immediately when it observes `DESTROYING` (no second
  `OwnedCtx`);
- `*_up_ref` performs `compare_exchange(n, n + 1, Relaxed, Relaxed)` only for
  `n > 0`, so it fails on zero/sentinel rather than resurrecting a dying
  object.

This turns the authority's over-free UB into a defined no-op/failure, a
deliberate §17 safety divergence. It must be applied to all three rows (and
considered for `SslSession`) in one coherent batch with negative controls for
both the destructor re-entry and the up-ref-after-zero cases.

## Evidence limits

- The concurrent-increment test exercises lost updates, not every interleaving;
  no loom/Miri/sanitizer run was performed for this pass.
- The callback paths are source-witnessed. No callback probe was added because
  the current behaviour is a double teardown (UB); the positive canary belongs
  with the poisoning fix.
- No row is `SAFETY_DISCHARGED`; §7's dependency-closure and independent-check
  package remains outstanding.
