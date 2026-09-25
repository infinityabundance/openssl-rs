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

use std::sync::{Mutex, MutexGuard};

/// The one lock every test that touches process-global state takes.
///
/// A single `Mutex` for the whole test binary, so a test in one module is
/// mutually exclusive with a test in any other module.
static GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the crate-wide global-state lock, recovering from poisoning.
///
/// A test that panics while holding the lock poisons it, but the process-global
/// state is no more corrupt than it already was and a poisoned run is a failure
/// regardless, so the guard is recovered through `into_inner` rather than
/// cascading panics into every later test. This is the same discipline the
/// per-module locks used.
pub(crate) fn lock_global_state() -> MutexGuard<'static, ()> {
    GLOBAL_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
