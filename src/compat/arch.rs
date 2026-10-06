//! Phase 23 — the ENGINE -> Provider -> no-ENGINE architecture model and the init/thread epochs.
//!
//! The second and third halves of Phase 23.7's policy layer
//! (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7). The architecture model is read
//! from the authority's own evidence — the plane census for 0.9.8zh
//! (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 4.7) and the parameterization receipt for
//! 3.6.4 — and the init/thread epochs are modelled rather than stubbed:
//!
//!   * the historical epoch has **explicit** global initialisation and **application-provided
//!     locking callbacks** (`CRYPTO_set_locking_callback`/`CRYPTO_set_id_callback` are real
//!     functions in 0.9.8zh); [`LegacyLocking`] is a working, safe registry of those callbacks;
//!   * the modern epoch initialises **automatically** and tears down with `OPENSSL_cleanup`, and
//!     the app-locking callbacks are macros that do nothing; the shared implementation is
//!     `crate::runtime::init` and `crate::runtime::thread`, which this module describes rather
//!     than duplicates (a per-version fork is exactly what 23.7 forbids).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_ulong};

use super::policy::{
    AlgorithmRegistryModel, AuthoritySpec, EngineModel, InitModel, ProviderModel, ThreadModel,
};

/// The architecture model of an authority: which extension mechanism is primary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArchitectureModel {
    /// The ENGINE model.
    pub engine: EngineModel,
    /// The provider model.
    pub provider: ProviderModel,
    /// The algorithm-registry model.
    pub algorithms: AlgorithmRegistryModel,
}

impl ArchitectureModel {
    /// The model an authority's spec names.
    pub fn of(spec: &AuthoritySpec) -> Self {
        Self {
            engine: spec.engine,
            provider: spec.provider,
            algorithms: spec.algorithms,
        }
    }

    /// Whether the provider store is the primary registry (3.0 and later).
    pub fn provider_is_primary(&self) -> bool {
        matches!(self.provider, ProviderModel::ProviderStore)
            && matches!(self.algorithms, AlgorithmRegistryModel::ProviderFetch)
    }

    /// Whether engines are the extension mechanism (before the provider model).
    pub fn engine_is_primary(&self) -> bool {
        matches!(self.engine, EngineModel::BuiltInEngines)
            && matches!(self.algorithms, AlgorithmRegistryModel::LegacyMethodTables)
    }

    /// The `<engine> -> <provider> -> <registry>` chain this model sits on, as a static string.
    pub fn chain(&self) -> &'static str {
        match (self.engine, self.provider) {
            (EngineModel::NoEngine, ProviderModel::ProviderStore) => {
                "no-engine -> provider -> provider-fetch"
            }
            (_, ProviderModel::ProviderStore) => "deprecated-engine -> provider -> provider-fetch",
            (EngineModel::BuiltInEngines, ProviderModel::NoProviders) => {
                "engine -> no-provider -> legacy-method-tables"
            }
            _ => "engine -> no-provider -> legacy-method-tables",
        }
    }
}

/// The initialisation and threading model of an authority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InitThreadModel {
    /// The initialisation model.
    pub init: InitModel,
    /// The threading model.
    pub thread: ThreadModel,
}

impl InitThreadModel {
    /// The model an authority's spec names.
    pub fn of(spec: &AuthoritySpec) -> Self {
        Self {
            init: spec.init,
            thread: spec.thread,
        }
    }

    /// Whether the distribution initialises itself (and so must also clean up).
    pub fn is_automatic(&self) -> bool {
        matches!(self.init, InitModel::AutomaticInit)
    }

    /// Whether the application must install locking callbacks.
    pub fn requires_application_locking(&self) -> bool {
        matches!(self.thread, ThreadModel::ApplicationLockingCallbacks)
    }

    /// The teardown entry point the epoch names, or `None` when there is none.
    pub fn cleanup_entry_point(&self) -> Option<&'static str> {
        if self.is_automatic() {
            Some("OPENSSL_cleanup")
        } else {
            None
        }
    }
}

/// An application-supplied locking callback: `void (*)(int, int, const char *, int)`.
pub type LockingCallback = fn(c_int, c_int, *const c_char, c_int);

/// An application-supplied thread-id callback: `unsigned long (*)(void)`.
pub type IdCallback = fn() -> c_ulong;

/// A safe model of the pre-1.1.0 application-provided locking contract.
///
/// In 0.9.8zh `CRYPTO_set_locking_callback` and `CRYPTO_set_id_callback` are real functions: the
/// application installs callbacks and the library calls them around the `CRYPTO_num_locks()`
/// locks. This registry is that contract, functional and testable; it is the historical half of
/// the init/thread epoch and is deliberately **not** a stub. It carries no global state — a
/// caller owns one and drives it — so it cannot perturb the crate's own runtime.
#[derive(Default)]
pub struct LegacyLocking {
    locking: Option<LockingCallback>,
    thread_id: Option<IdCallback>,
    locks: usize,
}

impl LegacyLocking {
    /// A registry over `locks` locks (`CRYPTO_num_locks()` in the authority).
    pub fn new(locks: usize) -> Self {
        Self {
            locking: None,
            thread_id: None,
            locks,
        }
    }

    /// `CRYPTO_num_locks()`.
    pub fn num_locks(&self) -> usize {
        self.locks
    }

    /// `CRYPTO_set_locking_callback(func)`.
    pub fn set_locking_callback(&mut self, callback: Option<LockingCallback>) {
        self.locking = callback;
    }

    /// `CRYPTO_set_id_callback(func)`.
    pub fn set_id_callback(&mut self, callback: Option<IdCallback>) {
        self.thread_id = callback;
    }

    /// `CRYPTO_get_locking_callback()`.
    pub fn locking_callback(&self) -> Option<LockingCallback> {
        self.locking
    }

    /// Take the lock `lock` in `mode`, answering whether a callback ran.
    ///
    /// A missing callback is a legal state — the application has not installed one — and is
    /// reported as `false` rather than treated as an error, exactly as the authority's callers
    /// guard on a non-NULL callback.
    pub fn lock(&self, mode: c_int, lock: c_int, file: *const c_char, line: c_int) -> bool {
        match self.locking {
            Some(callback) => {
                callback(mode, lock, file, line);
                true
            }
            None => false,
        }
    }

    /// The current thread's id from the installed callback, or `None`.
    pub fn thread_id(&self) -> Option<c_ulong> {
        self.thread_id.map(|callback| callback())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::policy::{HISTORICAL_0_9_8ZH, PRODUCTION_3_6_4};

    #[test]
    fn the_historical_generation_is_the_engine_generation() {
        let m = ArchitectureModel::of(&HISTORICAL_0_9_8ZH);
        assert!(m.engine_is_primary());
        assert!(!m.provider_is_primary());
        assert_eq!(m.chain(), "engine -> no-provider -> legacy-method-tables");
    }

    #[test]
    fn the_production_generation_is_the_provider_generation() {
        let m = ArchitectureModel::of(&PRODUCTION_3_6_4);
        assert!(m.provider_is_primary());
        assert!(!m.engine_is_primary());
        assert_eq!(m.chain(), "deprecated-engine -> provider -> provider-fetch");
    }

    #[test]
    fn the_historical_epoch_requires_application_locking_and_no_cleanup() {
        let it = InitThreadModel::of(&HISTORICAL_0_9_8ZH);
        assert!(!it.is_automatic());
        assert!(it.requires_application_locking());
        assert_eq!(it.cleanup_entry_point(), None);
    }

    #[test]
    fn the_modern_epoch_is_automatic_and_cleans_up() {
        let it = InitThreadModel::of(&PRODUCTION_3_6_4);
        assert!(it.is_automatic());
        assert!(!it.requires_application_locking());
        assert_eq!(it.cleanup_entry_point(), Some("OPENSSL_cleanup"));
    }

    #[test]
    fn the_legacy_locking_registry_really_runs_the_callbacks() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static LOCKS_TAKEN: AtomicUsize = AtomicUsize::new(0);
        fn locking(_mode: c_int, _lock: c_int, _file: *const c_char, _line: c_int) {
            LOCKS_TAKEN.fetch_add(1, Ordering::SeqCst);
        }
        fn thread_id() -> c_ulong {
            7
        }

        let mut lk = LegacyLocking::new(4);
        assert_eq!(lk.num_locks(), 4);
        // No callback is installed yet: the call is legal and reports that nothing ran.
        assert!(!lk.lock(1, 0, core::ptr::null(), 0));
        assert_eq!(lk.thread_id(), None);

        lk.set_locking_callback(Some(locking));
        lk.set_id_callback(Some(thread_id));
        assert!(lk.lock(1, 2, core::ptr::null(), 0));
        assert!(lk.lock(0, 2, core::ptr::null(), 0));
        assert_eq!(LOCKS_TAKEN.load(Ordering::SeqCst), 2);
        assert_eq!(lk.thread_id(), Some(7));

        lk.set_locking_callback(None);
        assert!(!lk.lock(1, 2, core::ptr::null(), 0));
        assert_eq!(LOCKS_TAKEN.load(Ordering::SeqCst), 2);
    }
}
