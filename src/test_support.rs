//! Test-only support for tests that touch the crate's **process-global** state.
//!
//! The crate reconstructs a C library whose state is process-global: init and
//! cleanup, the default `OSSL_LIB_CTX`, the memory functions, the error
//! registry, the object database, the property/method stores, RCU and the
//! thread-event register. Tests that mutate that state cannot run concurrently
//! with one another, **whichever module they live in**, so the exclusion domain
//! is the whole crate: every such test takes [`lock_global_state`].
//!
//! A per-module `Mutex` -- the shape this module replaced -- could not express
//! that. Two tests in different modules, each holding its own lock, were not
//! mutually exclusive even though both touched a global, so "this test is
//! serialised" was weaker than it looked. Under `--test-threads=1` the defect was
//! invisible; under the default parallel harness it was luck.
//!
//! The classification rule, applied at every lock site:
//!
//! * A test that **mutates** process-global state, or reads it under an
//!   assertion, takes the lock and names the global it needs in its comment.
//! * A test that only reads immutable data (a `const` table, a version string)
//!   must **not** take it, so the parallel-safe subset stays parallel.
//! * A test that additionally depends on a `#[cfg(test)]` fault, or on a
//!   sibling test not having run, says so at its lock: that is the explicit
//!   classification a reviewer asked for.
//!
//! One global cannot be classified this way: the **secure heap**, because a
//! large set of tests reaches `CRYPTO_secure_*` indirectly (X25519/ECDH key
//! generation, ML-DSA/ML-KEM, SM2, TLS handshakes) and some of that work happens
//! on worker threads that could not hold a `MutexGuard` at all. Those callers
//! are correct in production; they only make the secure-heap *fixtures* wrong.
//! The lock therefore also claims the heap for the holding thread (see
//! `runtime::secure::test_lease`), so a fixture's arena accounting cannot be
//! disturbed by a concurrent test that never asked for the lock.

use std::sync::{Mutex, MutexGuard};

/// The one lock every test that touches process-global state takes.
///
/// A single `Mutex` for the whole test binary, so a test in one module is
/// mutually exclusive with a test in any other module.
static GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

/// What [`lock_global_state`] hands back.
///
/// The fields are declared lease-first so the secure-heap lease is released
/// *before* the crate-wide lock: the heap returns to other threads only while
/// the caller still owns the lock.
pub(crate) struct GlobalStateGuard {
    _lease: crate::runtime::secure::test_lease::Lease,
    _lock: MutexGuard<'static, ()>,
}

/// Acquire the crate-wide global-state lock, recovering from poisoning.
///
/// A test that panics while holding the lock poisons it, but the process-global
/// state is no more corrupt than it already was and a poisoned run is a failure
/// regardless, so the guard is recovered through `into_inner` rather than
/// cascading panics into every later test. This is the same discipline the
/// per-module locks used.
///
/// The guard also claims the process-global secure heap for this thread: while
/// it is alive, another thread's `CRYPTO_secure_*` allocation takes the
/// allocator's documented plain fallback rather than a chunk in an arena the
/// test may be asserting about. A chunk allocated *before* the claim still
/// releases into the arena, because release routes by arena containment. See
/// `runtime::secure::test_lease` for the defect this closes and why the callers
/// cannot all be given this lock instead.
pub(crate) fn lock_global_state() -> GlobalStateGuard {
    let lock = GLOBAL_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let lease = crate::runtime::secure::test_lease::acquire();
    GlobalStateGuard {
        _lease: lease,
        _lock: lock,
    }
}
