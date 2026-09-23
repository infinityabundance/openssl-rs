//! Phase 8 — the default provider's `OSSL_OP_KEYMGMT` rows, and the key-manager units behind them.
//!
//! The authority publishes forty rows of `providers/defltprov.c`'s `deflt_keymgmt[]`, and this
//! module is where the crate's own `deflt_query(OSSL_OP_KEYMGMT)` answers them. **Why it exists at
//! all** is the measurement D384/D385 recorded: the `OSSL_OP_KEYEXCH`, `OSSL_OP_SIGNATURE`,
//! `OSSL_OP_KEM` and `OSSL_OP_ASYM_CIPHER` rows are all reached through the *key type's* keymgmt
//! row — `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)` fetches `DH` under `OSSL_OP_KEYMGMT` first —
//! so with no keymgmt arm none of those operations is drivable and the exchange units the previous
//! passes withheld could not be courted. This is the gate.
//!
//! ## What is landed here, and what is not
//!
//! Each unit is transcribed **whole** (D327's rule). This module currently carries the
//! `kdf_legacy_kmgmt.c` unit, whose three rows (`TLS1-PRF`, `HKDF`, `SCRYPT`) share the authority's
//! one `ossl_kdf_keymgmt_functions` — a deliberately *empty* key manager: a legacy KDF has no key
//! material, so `kdf_has` answers 1 unconditionally and the only real content is the `KDF_DATA`
//! reference-counted handle `exchange/kdf_exch.c` also uses. It is the smallest of the four
//! reachable keymgmt units and the one the exchange gate needs first.
//!
//! The PQC units (`ml_dsa_kmgmt.c.in`, `ml_kem_kmgmt.c.in`, `mlx_kmgmt.c.in`, `slh_dsa_kmgmt.c.in`)
//! are **not reachable** on this tree: their units are built on `crypto/ml_dsa/`, `crypto/ml_kem/`
//! and `crypto/slh_dsa/`, none of which the crate has. They are recorded rather than stubbed, the
//! the way D382/D384/D385 record their own unreachable units.
//!
//! SPDX-License-Identifier: Apache-2.0

// The three `ossl_kdf_data_*` exports are `pub` and `#[no_mangle]` because the authority's own
// `prov/kdfexchange.h` declares them and `exchange/kdf_exch.c` links to them across translation
// units; here they are reached only from this crate, but the symbol and its width are the ABI's,
// not this module's. `provider` is a `pub(crate)` module, so `pub` on them is `unreachable_pub`; the
// module-level allow is the same one `src/rsa/object.rs` and `src/aria.rs` carry for the same
// reason. `unreachable_pub` is a *warn* in `Cargo.toml` and `-D warnings` promotes it, so without
// this the three symbols would have to be narrowed away from the ABI they transcribe.
#![allow(unreachable_pub)]

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::Ordering;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_NEW};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The generated unit's own `__FILE__`, for `OPENSSL_zalloc`'s allocation attribution.
const FILE_KDF_LEGACY_KMGMT: *const core::ffi::c_char =
    c"providers/implementations/keymgmt/kdf_legacy_kmgmt.c".as_ptr();

/// `struct kdf_data_st` — `providers/implementations/include/prov/kdfexchange.h:14-17`. A legacy KDF
/// key-manager handle is nothing but the library context it was created in and a reference count;
/// the KDF itself lives in the `EVP_KDF_CTX` the *exchange* unit builds.
///
/// `CRYPTO_REF_COUNT` is a bare `int` on this profile (`internal/refcount.h`), so it is an
/// `AtomicI32` with relaxed/release ordering, exactly as `crypto/ec/ecx_key.c`'s object is.
#[repr(C)]
pub(crate) struct KdfData {
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub refcnt: AtomicI32,
}

/// The default provider is always in a happy state on this build, so `ossl_prov_is_running()` — a
/// `FIPS_MODULE` self-test hook — answers 1. Kept as a function rather than an inlined `1` so every
/// authority guard is a guard in the transcription.
#[inline]
fn is_running() -> c_int {
    1
}

/// `KDF_DATA *ossl_kdf_data_new(void *provctx)` — `kdf_legacy_kmgmt.c:29-47`.
///
/// # Safety
/// `provctx` is the provider context the caller was given, or NULL.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_new(provctx: *mut c_void) -> *mut KdfData {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let kdfdata = CRYPTO_zalloc(core::mem::size_of::<KdfData>(), FILE_KDF_LEGACY_KMGMT, 0)
            .cast::<KdfData>();
        if kdfdata.is_null() {
            return ptr::null_mut();
        }

        // `if (!CRYPTO_NEW_REF(&kdfdata->refcnt, 1))` — the header's fallback arm on this profile is
        // `refcnt->val = n; return 1;`, so the failure branch (and its `OPENSSL_free`) is
        // unreachable rather than omitted. `NEW_REF` cannot fail for an inline atomic.
        // SAFETY: `refcnt` is a field of this call's own allocation.
        (*kdfdata).refcnt.store(1, Ordering::Relaxed);
        // SAFETY: as above; `provctx` is the caller's.
        (*kdfdata).libctx = prov_libctx_of(provctx);

        kdfdata
    }
}

/// `void ossl_kdf_data_free(KDF_DATA *kdfdata)` — `kdf_legacy_kmgmt.c:49-62`.
///
/// # Safety
/// `kdfdata` is NULL or a live handle; it must not be used again unless a reference remains.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_free(kdfdata: *mut KdfData) {
    if kdfdata.is_null() {
        return;
    }

    // SAFETY: `kdfdata` is live per the contract. `CRYPTO_DOWN_REF` answers the value *after* the
    // decrement, and the release/acquire fence is the header's.
    let ref_ = unsafe { (*kdfdata).refcnt.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if ref_ == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    if ref_ > 0 {
        return;
    }

    // `CRYPTO_FREE_REF(&kdfdata->refcnt)` is empty on this profile's arm of the header.
    // SAFETY: this is the last reference to the handle.
    unsafe { CRYPTO_free(kdfdata.cast(), FILE_KDF_LEGACY_KMGMT, 61) };
}

/// `int ossl_kdf_data_up_ref(KDF_DATA *kdfdata)` — `kdf_legacy_kmgmt.c:64-80`. The one guard the
/// authority keeps though both current callers already hold it (the comment says so at `:68-74`).
///
/// # Safety
/// `kdfdata` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_up_ref(kdfdata: *mut KdfData) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    // `CRYPTO_UP_REF` is a relaxed fetch-add; the authority ignores its out-parameter here.
    // SAFETY: `kdfdata` is live per the contract.
    unsafe { (*kdfdata).refcnt.fetch_add(1, Ordering::Relaxed) };
    1
}

/// `static void *kdf_newdata(void *provctx)` — `kdf_legacy_kmgmt.c:82-85`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn kdf_newdata(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's.
    unsafe { ossl_kdf_data_new(provctx).cast() }
}

/// `static void kdf_freedata(void *kdfdata)` — `kdf_legacy_kmgmt.c:87-90`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn kdf_freedata(kdfdata: *mut c_void) {
    // SAFETY: the caller hands back what `kdf_newdata` answered.
    unsafe { ossl_kdf_data_free(kdfdata.cast()) };
}

/// `static int kdf_has(const void *keydata, int selection)` — `kdf_legacy_kmgmt.c:92-95`. Nothing is
/// missing, because there is nothing: a legacy KDF has no key material.
///
/// # Safety
/// The keymgmt `has` dispatch contract; neither argument is read.
unsafe extern "C" fn kdf_has(_keydata: *const c_void, _selection: c_int) -> c_int {
    1
}

/// `const OSSL_DISPATCH ossl_kdf_keymgmt_functions[]` — `kdf_legacy_kmgmt.c:97-102`. Three slots,
/// the authority's three, in its order.
pub(crate) static KDF_KEYMGMT_FUNCTIONS: [OsslDispatch; 4] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: kdf_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: kdf_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: kdf_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_keymgmt[]` — `providers/defltprov.c:551-666`, **the rows this
/// module has landed**, in the authority's order.
///
/// The KDF rows share `ossl_kdf_keymgmt_functions` exactly as the authority's three do
/// (`defltprov.c:588-595`) — that many-to-one association is a fact about the authority, and the
/// census's dispatch association is a partition equality (D386) so it is described rather than
/// rejected.
///
/// **The property definition is `"provider=default"` on every row** (`defltprov.c`'s `ALG` macro,
/// D247), and the description is left NULL on every row, which is this crate's convention for the
/// fourth `OSSL_ALGORITHM` field (no landed table sets it, and nothing reads it).
pub(crate) static DEFLT_KEYMGMT: [OsslAlgorithm; 4] = [
    OsslAlgorithm {
        // `PROV_NAMES_TLS1_PRF` — the primary name alone.
        algorithm_names: c"TLS1-PRF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF`.
        algorithm_names: c"HKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SCRYPT` — the OID alias is part of the row.
        algorithm_names: c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
