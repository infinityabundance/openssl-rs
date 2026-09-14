# Concurrency Model

Status: **constitution** (Phase 0).

Concurrency is part of the observable contract. Thread-local state, refcounts and
initialisation ordering are all things applications can observe, so they are
courted directly rather than assumed.

## 1. Surfaces

```
documented thread safety        thread-local queues and state
provider / context concurrency  refcount behaviour
initialisation (once) semantics teardown
process / fork interactions (where observable)
locks and atomics (CRYPTO_THREAD_*)
```

## 2. The error queue is the canonical example

OpenSSL's `ERR` queue is **thread-local**. A correct candidate must reproduce:

- per-thread queue identity and isolation;
- ordering within a thread;
- clearing, marks and peek semantics;
- interaction with `errno` and with `SSL_get_error`.

Internally, the queue **must not** be reduced to `Result<T, Error>` if doing so
loses OpenSSL behaviour. Rust ergonomics are subordinate to compatibility at the
C boundary; a convenience wrapper may exist *above* the faithful mechanism, never
*instead of* it.

Multi-threaded courts exist for every failure-oriented API family, capturing:

```
return   errno   ERR_peek*   ERR_get*   queue sequence
library  reason  function/file/line where exposed
additional error data   queue state after reads   queue state after clear
thread isolation
```

## 3. Thread-safety obligations are generated

The authority defines which APIs document thread safety (`THREADS` annotations in
the headers). These are mined into the atlas and become `THREAD-STATE` court
obligations. A claim of thread safety is made only where the authority makes it.

## 4. Model checking

Isolated concurrency machinery (lock-free structures, refcount state machines,
the fetch cache) is additionally exercised with `loom`/model tests where useful.
Model tests supplement the differential courts; they do not replace them.

## 5. Fork and process interaction

Where observable (for example DRBG fork handling), behaviour is courted against
the authority. A difference is a residual with a classification, not a silent
divergence.

## 6. Instrumentation

Concurrency courts use:

- `thread sanitizer` on the candidate where feasible;
- canary/refcount probes in the authority process;
- deterministic scheduling for reproducibility where the mechanism permits it,
  with the schedule recorded as part of the run.
