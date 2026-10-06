//! Phase 23 — the authority-specific prototype contracts, and their narrow wrappers.
//!
//! A C symbol has **no runtime signature**. The same exported name therefore carries a different
//! *declaration* under different authorities, and the compatibility distribution must export the
//! contract the selected authority's header declares. In 0.9.8zh `HMAC_Init_ex`, `HMAC_Update`
//! and `HMAC_Final` return `void`; from 1.1.0 they return `int`, and `EVP_MD_CTX_init` is a
//! function in 0.9.8zh but a macro over `EVP_MD_CTX_reset` in 3.6.4
//! (`forensics/multitrack/abi-facades.json`, records `P-*`). This module records each era's
//! contract and wraps the shared implementation with the era's result type, so the difference is
//! an adapter rather than a fork (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7).
//!
//! The wrappers are safe: they take the shared implementation as a closure or as a borrow of the
//! historical locking registry, and they never reinterpret a pointer. The `#[cfg(test)]` tests
//! drive each one so a wrapper that stopped calling its shared implementation would fail.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use super::arch::{LegacyLocking, LockingCallback};
use crate::evp::digest::EvpMdCtx;

/// The shape a C contract takes: a callable function, or a macro with no runtime symbol.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContractKind {
    /// A real, callable function.
    Function,
    /// A macro: it has no runtime signature and no exported symbol.
    Macro,
}

/// One era's declaration of a symbol.
#[derive(Clone, Copy, Debug)]
pub struct Declaration {
    /// The era the declaration belongs to (`"0.9.8zh"`, `"3.6.4"`).
    pub era: &'static str,
    /// The declaration, as the authority's header writes it.
    pub declaration: &'static str,
    /// Whether it is a function or a macro in that era.
    pub kind: ContractKind,
    /// The header the declaration is read from.
    pub header: &'static str,
}

/// A symbol whose declaration differs across eras.
#[derive(Clone, Copy, Debug)]
pub struct PrototypeContract {
    /// The exported symbol name.
    pub symbol: &'static str,
    /// The historical (pre-1.1.0) declaration.
    pub historical: Declaration,
    /// The canonical (3.6.4 production) declaration.
    pub canonical: Declaration,
}

/// The contracts this stratum establishes, matching `forensics/multitrack/abi-facades.json`.
pub const CONTRACTS: &[PrototypeContract] = &[
    PrototypeContract {
        symbol: "EVP_MD_CTX_init",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (EVP_MD_CTX *)",
            kind: ContractKind::Function,
            header: "evp.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "EVP_MD_CTX_reset((ctx))",
            kind: ContractKind::Macro,
            header: "evp.h",
        },
    },
    PrototypeContract {
        symbol: "EVP_MD_CTX_create",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "EVP_MD_CTX *(void)",
            kind: ContractKind::Function,
            header: "evp.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "EVP_MD_CTX_new()",
            kind: ContractKind::Macro,
            header: "evp.h",
        },
    },
    PrototypeContract {
        symbol: "EVP_MD_CTX_destroy",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (EVP_MD_CTX *)",
            kind: ContractKind::Function,
            header: "evp.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "EVP_MD_CTX_free((ctx))",
            kind: ContractKind::Macro,
            header: "evp.h",
        },
    },
    PrototypeContract {
        symbol: "HMAC_Init_ex",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "int (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
    },
    PrototypeContract {
        symbol: "HMAC_Update",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (HMAC_CTX *, const unsigned char *, size_t)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "int (HMAC_CTX *, const unsigned char *, size_t)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
    },
    PrototypeContract {
        symbol: "HMAC_Final",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (HMAC_CTX *, unsigned char *, unsigned int *)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "int (HMAC_CTX *, unsigned char *, unsigned int *)",
            kind: ContractKind::Function,
            header: "hmac.h",
        },
    },
    PrototypeContract {
        symbol: "CRYPTO_set_locking_callback",
        historical: Declaration {
            era: "0.9.8zh",
            declaration: "void (void (*)(int, int, const char *, int))",
            kind: ContractKind::Function,
            header: "crypto.h",
        },
        canonical: Declaration {
            era: "3.6.4",
            declaration: "",
            kind: ContractKind::Macro,
            header: "crypto.h",
        },
    },
];

/// The contract for a symbol, or `None` when this stratum does not cover it.
pub fn contract(symbol: &str) -> Option<&'static PrototypeContract> {
    CONTRACTS.iter().find(|c| c.symbol == symbol)
}

/// The 0.9.8zh `EVP_MD_CTX_init` prototype: the era's declaration returns `void`, so the shared
/// implementation's `int` result is discarded — the era cannot observe it.
pub fn evp_md_ctx_init<F: FnOnce() -> c_int>(shared: F) {
    let _ = shared();
}

/// The 0.9.8zh `EVP_MD_CTX_create` prototype: a pointer-returning function that matches the
/// shared `EVP_MD_CTX_new` contract, so the wrapper is the identity on the result.
pub fn evp_md_ctx_create<F: FnOnce() -> *mut EvpMdCtx>(shared: F) -> *mut EvpMdCtx {
    shared()
}

/// The 0.9.8zh `EVP_MD_CTX_destroy` prototype: `void`, matching the shared `EVP_MD_CTX_free`.
pub fn evp_md_ctx_destroy<F: FnOnce()>(shared: F) {
    shared();
}

/// The 0.9.8zh `HMAC_Init_ex` prototype: `void`, discarding the shared `int` result.
pub fn hmac_init_ex<F: FnOnce() -> c_int>(shared: F) {
    let _ = shared();
}

/// The 0.9.8zh `HMAC_Update` prototype: `void`, discarding the shared `int` result.
pub fn hmac_update<F: FnOnce() -> c_int>(shared: F) {
    let _ = shared();
}

/// The 0.9.8zh `HMAC_Final` prototype: `void`, discarding the shared `int` result.
pub fn hmac_final<F: FnOnce() -> c_int>(shared: F) {
    let _ = shared();
}

/// The 0.9.8zh `CRYPTO_set_locking_callback` prototype: a real installer, adapted onto the
/// historical locking registry (`super::arch::LegacyLocking`), where the 3.6.4 macro is a no-op.
pub fn crypto_set_locking_callback(
    registry: &mut LegacyLocking,
    callback: Option<LockingCallback>,
) {
    registry.set_locking_callback(callback);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn every_contract_names_both_eras_and_the_difference_is_real() {
        for c in CONTRACTS {
            assert_eq!(c.historical.era, "0.9.8zh");
            assert_eq!(c.canonical.era, "3.6.4");
            assert!(
                c.historical.declaration != c.canonical.declaration
                    || c.historical.kind != c.canonical.kind,
                "{} records no era difference",
                c.symbol
            );
        }
        assert!(contract("HMAC_Init_ex").is_some());
        assert!(contract("SSL_CTX_new").is_none());
    }

    #[test]
    fn the_void_wrappers_call_the_shared_implementation_and_discard_its_result() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn shared() -> c_int {
            CALLS.fetch_add(1, Ordering::SeqCst);
            42
        }
        evp_md_ctx_init(shared);
        hmac_init_ex(shared);
        hmac_update(shared);
        hmac_final(shared);
        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn the_pointer_wrapper_preserves_the_shared_result() {
        let p = 0x10usize as *mut EvpMdCtx;
        assert!(core::ptr::eq(evp_md_ctx_create(|| p), p));
    }

    #[test]
    fn the_destroy_wrapper_calls_the_shared_implementation() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        evp_md_ctx_destroy(|| {
            CALLS.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_locking_installer_reaches_the_historical_registry() {
        fn locking(_mode: c_int, _lock: c_int, _file: *const core::ffi::c_char, _line: c_int) {}
        let mut registry = LegacyLocking::new(1);
        assert!(registry.locking_callback().is_none());
        crypto_set_locking_callback(&mut registry, Some(locking));
        assert!(registry.locking_callback().is_some());
        crypto_set_locking_callback(&mut registry, None);
        assert!(registry.locking_callback().is_none());
    }
}
