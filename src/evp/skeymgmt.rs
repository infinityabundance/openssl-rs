//! Phase 7.3f — `EVP_SKEYMGMT`, and the `EVP_SKEY` it manages.
//!
//! `crypto/evp/skeymgmt_meth.c` and `crypto/evp/s_lib.c`, both whole: **24 exports**, eleven of them
//! the method object and thirteen the thing the method produces. They are in one module because the
//! atlas assigns ownership by the header that promises a symbol, both headers are `evp.h`, and the
//! two files are one subject — a symmetric key and the manager that imports, generates and exports
//! it. The authority splits them across two translation units; the split is bookkeeping rather than
//! a boundary, and the second file's first statement is `EVP_SKEY_export` reaching into the first.
//!
//! ## The fourth class, and the first whose object is not a context
//!
//! `EVP_MD`, `EVP_CIPHER`, `EVP_MAC` and `EVP_KDF` are four names for the same shape: a method
//! object that has a *context* object, and the context is where the state is. `EVP_SKEY` breaks that
//! in a way that changes the reference arithmetic:
//!
//! ```text
//! EVP_SKEY_import(libctx, "SKEY-AES", NULL, SELECT_SECRET_KEY, params)
//!   -> EVP_SKEYMGMT_fetch(libctx, "SKEY-AES", NULL)        the method, one reference
//!        -> evp_skey_alloc(skeymgmt)                        takes its own reference
//!             -> EVP_SKEYMGMT_free(skeymgmt)                the fetch's reference, given back
//!   -> skeymgmt->import(provctx, selection, params)         the provider's key data
//! ```
//!
//! So an `EVP_SKEY` **owns a reference to its method**, where an `EVP_MD_CTX` owns a reference to
//! its method only for the life of the context. There is no `EVP_SKEY_CTX` and there is no
//! `EVP_SKEY_new`: the object is *made* by an operation (import or generate), never by a bare
//! constructor, which is why the file has no `new`/`free` pair around a NULL method and why
//! `EVP_SKEY_free` releases the method as part of releasing the key.
//!
//! ## Three things `skeymgmt_from_algorithm` does that no sibling class does
//!
//!   * **the structural check has no counter.** `EVP_MD`'s is five functions or four, `EVP_MAC`'s is
//!     three and two, `EVP_KDF`'s is one and two. This class's is three plain NULL tests on `free`,
//!     `import` and `export` — and they are *not* counted, so a provider that publishes all three
//!     twice is accepted, and one that publishes two of the three is refused. The reason is that the
//!     three are the mandatory set and there is no fold to weigh; `render` (a legacy half), `get_key_id`,
//!     `gen_params` and `imp_params` are all optional and none of them is counted.
//!   * **`EVP_SKEYMGMT_up_ref` answers 1 unconditionally.** It reads the count, ignores the result,
//!     and returns the constant — so it cannot fail, and every `if (!EVP_SKEYMGMT_up_ref(...))` in
//!     this module is a shape the authority keeps for symmetry rather than a path it can take.
//!     `EVP_SKEY_up_ref` is the opposite: it too answers 1-or-0, but it *computes* — and computes
//!     the same thing `EVP_MAC_up_ref` does not, because `CRYPTO_UP_REF` writes the **new** count.
//!   * **a NULL method is guarded everywhere, and `names_do_all` is the one that answers 0.** The
//!     three field accessors and the two parameter accessors answer NULL for a NULL method,
//!     `is_a` answers 0, `free` returns — and `EVP_SKEYMGMT_names_do_all` answers **0** where its
//!     `EVP_MAC` sibling answers 1. A transcription that copied the sibling would be wrong in a way
//!     only this observation catches.
//!
//! ## `EVP_SKEY_to_provider`, and the one place a NULL key is refused
//!
//! The transfer is a round trip through the provider interface: **export** the key's data to
//! parameters and **import** it into the destination's method, because the two providers' key data
//! are different objects and there is no common representation. Two arms of it are worth naming:
//! a destination that *is* the origin short-circuits to an `up_ref` of the same pointer rather than
//! a copy, and a `prov` of NULL means "the default one", resolved by name through the libctx.
//!
//! ## What is not here
//!
//! `EVP_PKEY_derive_SKEY` is `crypto/evp/pkey_derive.c`'s and is **7.4's** with its module named:
//! it takes an `EVP_PKEY_CTX`, and this stratum has no `EVP_PKEY` yet. The four `*_SKEY` entry points
//! that *are* this subphase's — `EVP_MAC_init_SKEY`, `EVP_KDF_CTX_set_SKEY`, `EVP_KDF_derive_SKEY`
//! and `EVP_CipherInit_SKEY` — live in the modules that own their classes and are written there,
//! against this module's types, because a function belongs with the object it is a method of.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{
    evp_generic_do_all, evp_generic_fetch, evp_generic_fetch_from_prov, GenericDoAllFn,
    MethodFromAlgorithmFn,
};
use crate::evp::fetch::{evp_is_a, evp_names_do_all};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::{
    ossl_provider_ctx, ossl_provider_free, ossl_provider_name, ossl_provider_up_ref, OsslProvider,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};
use crate::selftest::OsslCallback;

/// `OSSL_OP_SKEYMGMT` — `include/openssl/core_dispatch.h`. The **last** operation the walk visits,
/// and the reason the walk's range runs to `OSSL_OP__HIGHEST` rather than to the last named id.
pub(crate) const OSSL_OP_SKEYMGMT: c_int = 15;

/// The authority's translation units, so a failing allocation records its coordinates. Two files,
/// two constants, because the two halves of this module are two translation units in the authority.
const FILE_METH: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/skeymgmt_meth.c".as_ptr();
/// `crypto/evp/s_lib.c`, the second half.
const FILE_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/s_lib.c".as_ptr();
/// `skeymgmt_new`'s `OPENSSL_zalloc(sizeof(*skeymgmt))` (line 52).
const LINE_ZALLOC_SKEYMGMT: c_int = 52;
/// `EVP_SKEYMGMT_free`'s `OPENSSL_free(skeymgmt->type_name)` (line 169).
const LINE_FREE_TYPE_NAME: c_int = 169;
/// `EVP_SKEYMGMT_free`'s `OPENSSL_free(skeymgmt)` (line 172).
const LINE_FREE_SKEYMGMT: c_int = 172;
/// `evp_skey_alloc`'s `OPENSSL_zalloc(sizeof(*skey))` (line 39).
const LINE_ZALLOC_SKEY: c_int = 39;
/// `evp_skey_alloc`'s `OPENSSL_free(skey)` (line 60).
const LINE_FREE_SKEY_ON_ALLOC: c_int = 60;
/// `EVP_SKEY_free`'s `OPENSSL_free(skey)` (line 225).
const LINE_FREE_SKEY: c_int = 225;

/// `OSSL_SKEYMGMT_SELECT_PARAMETERS` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_SKEYMGMT_SELECT_PARAMETERS: c_int = 0x01;
/// `OSSL_SKEYMGMT_SELECT_SECRET_KEY` — the bit `EVP_SKEY_import_raw_key` sets.
pub(crate) const OSSL_SKEYMGMT_SELECT_SECRET_KEY: c_int = 0x02;
/// `OSSL_SKEYMGMT_SELECT_ALL` — the bit `EVP_SKEY_to_provider` transfers.
pub(crate) const OSSL_SKEYMGMT_SELECT_ALL: c_int =
    OSSL_SKEYMGMT_SELECT_PARAMETERS | OSSL_SKEYMGMT_SELECT_SECRET_KEY;

/// `OSSL_SKEY_PARAM_RAW_BYTES` — `include/openssl/core_names.h`.
pub(crate) const OSSL_SKEY_PARAM_RAW_BYTES: *const c_char = c"raw-bytes".as_ptr();

/// `OSSL_SKEY_TYPE_GENERIC` — `include/openssl/core_names.h`. The name `evp_skey_alloc_fetch` falls
/// back to when the caller's own key type is unknown, and the reason the fallback is a *second*
/// fetch rather than an error.
const OSSL_SKEY_TYPE_GENERIC: *const c_char = c"GENERIC-SECRET".as_ptr();

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the seven function-pointer types.
//
// `OSSL_FUNC_SKEYMGMT_*` from `include/openssl/core_dispatch.h`, and each type is what
// `OSSL_CORE_MAKE_FUNC` generates for the corresponding entry. The ids are part of the wire format
// a provider is compiled against, so they are copied rather than derived.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_SKEYMGMT_FREE`. Mandatory, and one of the three the structural check tests.
const OSSL_FUNC_SKEYMGMT_FREE: c_int = 1;
/// `OSSL_FUNC_SKEYMGMT_IMPORT`. Mandatory.
const OSSL_FUNC_SKEYMGMT_IMPORT: c_int = 2;
/// `OSSL_FUNC_SKEYMGMT_EXPORT`. Mandatory, and the third of the three.
const OSSL_FUNC_SKEYMGMT_EXPORT: c_int = 3;
/// `OSSL_FUNC_SKEYMGMT_GENERATE`. Optional: `EVP_SKEY_generate` answers the fetch's NULL if absent.
const OSSL_FUNC_SKEYMGMT_GENERATE: c_int = 4;
/// `OSSL_FUNC_SKEYMGMT_GET_KEY_ID`. Optional, and not counted.
const OSSL_FUNC_SKEYMGMT_GET_KEY_ID: c_int = 5;
/// `OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS`. Optional, and not counted.
const OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS: c_int = 6;
/// `OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS`. Optional, and not counted.
const OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS: c_int = 7;

/// `OSSL_FUNC_skeymgmt_free_fn` — `void (*)(void *keydata)`.
///
/// **The key data's destructor, and it is mandatory**, which is why the structural check names it:
/// there is no generic way to release a provider's key, and a method that cannot release one would
/// leak on every import.
pub(crate) type SkeymgmtFreeFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_skeymgmt_import_fn` — `void *(*)(void *provctx, int selection,
/// const OSSL_PARAM params[])`.
pub(crate) type SkeymgmtImportFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const OsslParam) -> *mut c_void;
/// `OSSL_FUNC_skeymgmt_export_fn` — `int (*)(void *keydata, int selection,
/// OSSL_CALLBACK *param_cb, void *cbarg)`.
///
/// The data comes **out** through a callback rather than a return value, and that is the shape the
/// whole class is built around: `EVP_SKEY_get0_raw_key` and `EVP_SKEY_to_provider` are both
/// different readings of the same `export`, and neither could be written if `export` returned a
/// buffer it owned.
pub(crate) type SkeymgmtExportFn =
    unsafe extern "C" fn(*mut c_void, c_int, Option<OsslCallback>, *mut c_void) -> c_int;
/// `OSSL_FUNC_skeymgmt_imp_settable_params_fn` — `const OSSL_PARAM *(*)(void *provctx)`.
pub(crate) type SkeymgmtImpSettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_skeymgmt_gen_settable_params_fn` — the same signature.
pub(crate) type SkeymgmtGenSettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_skeymgmt_generate_fn` — `void *(*)(void *provctx, const OSSL_PARAM params[])`.
pub(crate) type SkeymgmtGenerateFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> *mut c_void;
/// `OSSL_FUNC_skeymgmt_get_key_id_fn` — `const char *(*)(void *keydata)`.
pub(crate) type SkeymgmtGetKeyIdFn = unsafe extern "C" fn(*mut c_void) -> *const c_char;

// ---------------------------------------------------------------------------------------------
// The two objects.
// ---------------------------------------------------------------------------------------------

/// `struct evp_skeymgmt_st` — `EVP_SKEYMGMT`, from `crypto/evp/evp_local.h`.
///
/// Seven callbacks and five bookkeeping fields, in the authority's order. Every callback is an
/// `Option` because the walk fills each field only if it is still NULL and because four of the seven
/// are optional.
///
/// `pub` for the reason every internal type in an exported signature is: twelve exported functions
/// take or return one, Rust requires the type of an exported item's parameter to be at least as
/// visible, and the authority keeps `evp_skeymgmt_st` in `crypto/evp/evp_local.h`, which is not
/// installed. Every field is `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpSkeyMgmt {
    /// `int name_id` — the namemap identity the method was fetched under.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — the provider that published it, holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_skeymgmt_imp_settable_params_fn *imp_params`.
    pub(crate) imp_params: Option<SkeymgmtImpSettableParamsFn>,
    /// `OSSL_FUNC_skeymgmt_import_fn *import`.
    pub(crate) import: Option<SkeymgmtImportFn>,
    /// `OSSL_FUNC_skeymgmt_export_fn *export`.
    pub(crate) export: Option<SkeymgmtExportFn>,
    /// `OSSL_FUNC_skeymgmt_gen_settable_params_fn *gen_params`.
    pub(crate) gen_params: Option<SkeymgmtGenSettableParamsFn>,
    /// `OSSL_FUNC_skeymgmt_generate_fn *generate`.
    pub(crate) generate: Option<SkeymgmtGenerateFn>,
    /// `OSSL_FUNC_skeymgmt_get_key_id_fn *get_key_id`.
    pub(crate) get_key_id: Option<SkeymgmtGetKeyIdFn>,
    /// `OSSL_FUNC_skeymgmt_free_fn *free` — the mandatory key-data destructor.
    pub(crate) free: Option<SkeymgmtFreeFn>,
}

/// `struct evp_skey_st` — `EVP_SKEY`, from `include/crypto/evp.h`.
///
/// **Four fields and two references**, and it is the only object in this stratum that holds a lock
/// of its own. The reference count and the lock are the two halves of the same statement: a key is
/// imported once and used from several threads, so the count and the guard around the provider's key
/// data are both needed, and the authority allocates the lock *at import* rather than lazily.
///
/// `pub` for the same reason `EvpSkeyMgmt` is, and with one more: `EVP_MAC_init_SKEY`,
/// `EVP_KDF_CTX_set_SKEY`, `EVP_KDF_derive_SKEY` and `EVP_CipherInit_SKEY` are written in their own
/// modules against this type.
#[repr(C)]
pub struct EvpSkey {
    /// `CRYPTO_REF_COUNT references`.
    pub(crate) references: AtomicI32,
    /// `CRYPTO_RWLOCK *lock` — allocated by `evp_skey_alloc`, released by `EVP_SKEY_free`.
    pub(crate) lock: *mut CryptoRwlock,
    /// `void *keydata` — the provider's own key, opaque here.
    pub(crate) keydata: *mut c_void,
    /// `EVP_SKEYMGMT *skeymgmt` — the method, and **this object owns a reference to it**.
    pub(crate) skeymgmt: *mut EvpSkeyMgmt,
}

// ---------------------------------------------------------------------------------------------
// The method object
// ---------------------------------------------------------------------------------------------

/// `int (*)(void *keymgmt)` over `EVP_SKEYMGMT_up_ref` — the shape `evp_generic_fetch` wants.
///
/// The authority writes this as a cast of the exported function, `(int (*)(void *))EVP_SKEYMGMT_up_ref`,
/// because C's `int (*)(EVP_SKEYMGMT *)` and `int (*)(void *)` have the same ABI. The crate keeps a
/// named trampoline instead, the shape `src/evp/mac.rs` uses, so the cast does not have to be
/// written at each of the three call sites and so the ABI claim is stated once.
///
/// # Safety
/// `vkeymgmt` must be a live `EvpSkeyMgmt`.
unsafe extern "C" fn evp_skeymgmt_up_ref(vkeymgmt: *mut c_void) -> c_int {
    // SAFETY: `vkeymgmt` is live per the contract.
    unsafe { EVP_SKEYMGMT_up_ref(vkeymgmt.cast::<EvpSkeyMgmt>()) }
}

/// `void (*)(void *)` over `EVP_SKEYMGMT_free` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vkeymgmt` must be NULL or a live `EvpSkeyMgmt`.
unsafe extern "C" fn evp_skeymgmt_free(vkeymgmt: *mut c_void) {
    // SAFETY: `vkeymgmt` is NULL or live per the contract.
    unsafe { EVP_SKEYMGMT_free(vkeymgmt.cast::<EvpSkeyMgmt>()) };
}

/// `static void *skeymgmt_new(void)`.
///
/// A zeroed block and a reference count of 1. Unlike `evp_md_new` there is no `origin` field to set
/// — a method of this class exists only as the answer to a fetch — and unlike `evp_rand_new` there
/// is no dispatch table kept, because nothing in this class is handed to a child.
///
/// # Safety
/// No preconditions: it allocates and writes one field.
unsafe fn skeymgmt_new() -> *mut EvpSkeyMgmt {
    let skeymgmt = CRYPTO_zalloc(
        core::mem::size_of::<EvpSkeyMgmt>(),
        FILE_METH,
        LINE_ZALLOC_SKEYMGMT,
    )
    .cast::<EvpSkeyMgmt>();
    if skeymgmt.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `skeymgmt` is a fresh zeroed block this call owns.
    unsafe { (*skeymgmt).refcnt = AtomicI32::new(1) };
    skeymgmt
}

/// `static void *skeymgmt_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// The class constructor `evp_generic_fetch` is handed. It differs from every sibling in this
/// stratum in one visible way: **there is no counter**. `EVP_MD`'s constructor weighs five
/// functions against four, `EVP_MAC`'s three against two, `EVP_KDF`'s one against two, and this one
/// is three plain NULL tests:
///
/// ```c
/// if (skeymgmt->free == NULL || skeymgmt->import == NULL || skeymgmt->export == NULL) { refuse }
/// ```
///
/// No fold, no optional arm to weigh, and nothing that can be published twice to reach a count — so
/// a provider that lists `import` twice still has one `import`, and one that lists two of the three
/// is refused. `generate`, `get_key_id`, `imp_params` and `gen_params` are all outside the test.
///
/// The two error paths raise **different reasons**, which is the second thing to get right:
/// `EVP_R_INVALID_PROVIDER_FUNCTIONS` for the structural test and `EVP_R_INITIALIZATION_ERROR` for a
/// provider reference that will not move.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live or NULL.
unsafe extern "C" fn skeymgmt_from_algorithm(
    name_id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let skeymgmt = unsafe { skeymgmt_new() };
    if skeymgmt.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `skeymgmt` is live.
    unsafe { (*skeymgmt).name_id = name_id };

    // SAFETY: `algodef` is live per the contract.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `skeymgmt` is this call's own object.
        unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        return ptr::null_mut();
    }
    // SAFETY: `skeymgmt` is live and `type_name` is the string just allocated for it.
    unsafe { (*skeymgmt).type_name = type_name };
    // SAFETY: `algodef` is live and `skeymgmt` is live.
    unsafe { (*skeymgmt).description = (*algodef).algorithm_description };

    // The walk: seven arms, each filling its field only if it is still empty, so the *first* entry
    // for an id wins. There is no counter here, which is exactly the structural difference from
    // every sibling class in this stratum -- so the arms are plain, with no `if` on a running total.
    let mut entry = fns;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator; `skeymgmt` is this call's own live object.
    unsafe {
        while (*entry).function_id != OSSL_DISPATCH_END {
            let id = (*entry).function_id;
            match id {
                OSSL_FUNC_SKEYMGMT_FREE if (*skeymgmt).free.is_none() => {
                    (*skeymgmt).free = entry_function::<SkeymgmtFreeFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_IMPORT if (*skeymgmt).import.is_none() => {
                    (*skeymgmt).import = entry_function::<SkeymgmtImportFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_EXPORT if (*skeymgmt).export.is_none() => {
                    (*skeymgmt).export = entry_function::<SkeymgmtExportFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_GENERATE if (*skeymgmt).generate.is_none() => {
                    (*skeymgmt).generate = entry_function::<SkeymgmtGenerateFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_GET_KEY_ID if (*skeymgmt).get_key_id.is_none() => {
                    (*skeymgmt).get_key_id = entry_function::<SkeymgmtGetKeyIdFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS if (*skeymgmt).imp_params.is_none() => {
                    (*skeymgmt).imp_params = entry_function::<SkeymgmtImpSettableParamsFn>(entry);
                }
                OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS if (*skeymgmt).gen_params.is_none() => {
                    (*skeymgmt).gen_params = entry_function::<SkeymgmtGenSettableParamsFn>(entry);
                }
                _ => {}
            }
            entry = entry.add(1);
        }
    }

    // The structural check, and it is three tests rather than an arithmetic.
    // SAFETY: `skeymgmt` is live.
    let complete = unsafe {
        (*skeymgmt).free.is_some() && (*skeymgmt).import.is_some() && (*skeymgmt).export.is_some()
    };
    if !complete {
        // SAFETY: `skeymgmt` is this call's own object.
        unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SKEYMGMT_METH_116) };
        return ptr::null_mut();
    }

    // SAFETY: `prov` is live or NULL per the contract.
    if !prov.is_null() && (unsafe { ossl_provider_up_ref(prov) }) == 0 {
        // SAFETY: `skeymgmt` is this call's own object.
        unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SKEYMGMT_METH_122) };
        return ptr::null_mut();
    }
    // SAFETY: `skeymgmt` is live.
    unsafe { (*skeymgmt).prov = prov };

    skeymgmt.cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// The exported method object
// ---------------------------------------------------------------------------------------------

/// `EVP_SKEYMGMT *EVP_SKEYMGMT_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpSkeyMgmt {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_SKEYMGMT,
            algorithm,
            properties,
            skeymgmt_from_algorithm as MethodFromAlgorithmFn,
            evp_skeymgmt_up_ref as MethodUpRefFn,
            evp_skeymgmt_free as MethodFreeFn,
        )
    }
    .cast::<EvpSkeyMgmt>()
}

/// `int EVP_SKEYMGMT_up_ref(EVP_SKEYMGMT *keymgmt)`.
///
/// Reads the count, discards the result, and answers **1**. That is not an oversight in the
/// authority: `CRYPTO_UP_REF` returns 1 unconditionally on every platform it is defined for, so
/// there is nothing to report and the sibling classes' `i > 1` arithmetic is not needed here.
///
/// # Safety
/// `keymgmt` must be a live `EvpSkeyMgmt`.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_up_ref(keymgmt: *mut EvpSkeyMgmt) -> c_int {
    // SAFETY: `keymgmt` is live per the contract.
    unsafe { (*keymgmt).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void EVP_SKEYMGMT_free(EVP_SKEYMGMT *keymgmt)`.
///
/// The order is the authority's: the name, the provider reference, the block.
///
/// # Safety
/// `keymgmt` must be NULL or a live `EvpSkeyMgmt`.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_free(keymgmt: *mut EvpSkeyMgmt) {
    if keymgmt.is_null() {
        return;
    }
    // SAFETY: `keymgmt` is live per the contract.
    let last = unsafe { (*keymgmt).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference and the block is this call's.
    unsafe {
        CRYPTO_free(
            (*keymgmt).type_name.cast::<c_void>(),
            FILE_METH,
            LINE_FREE_TYPE_NAME,
        );
        ossl_provider_free((*keymgmt).prov);
        CRYPTO_free(keymgmt.cast::<c_void>(), FILE_METH, LINE_FREE_SKEYMGMT);
    }
}

/// `const OSSL_PROVIDER *EVP_SKEYMGMT_get0_provider(const EVP_SKEYMGMT *keymgmt)`.
///
/// # Safety
/// `keymgmt` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_get0_provider(
    keymgmt: *const EvpSkeyMgmt,
) -> *const OsslProvider {
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live per the contract.
    unsafe { (*keymgmt).prov }
}

/// `const char *EVP_SKEYMGMT_get0_name(const EVP_SKEYMGMT *keymgmt)`.
///
/// # Safety
/// `keymgmt` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_get0_name(keymgmt: *const EvpSkeyMgmt) -> *const c_char {
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live per the contract.
    unsafe { (*keymgmt).type_name }
}

/// `const char *EVP_SKEYMGMT_get0_description(const EVP_SKEYMGMT *keymgmt)`.
///
/// # Safety
/// `keymgmt` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_get0_description(
    keymgmt: *const EvpSkeyMgmt,
) -> *const c_char {
    if keymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `keymgmt` is live per the contract.
    unsafe { (*keymgmt).description }
}

/// `int EVP_SKEYMGMT_is_a(const EVP_SKEYMGMT *keymgmt, const char *name)`.
///
/// # Safety
/// `keymgmt` must be NULL or live; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_is_a(
    keymgmt: *const EvpSkeyMgmt,
    name: *const c_char,
) -> c_int {
    if keymgmt.is_null() {
        return 0;
    }
    // SAFETY: `keymgmt` is live per the contract.
    let (prov, name_id) = unsafe { ((*keymgmt).prov, (*keymgmt).name_id) };
    // SAFETY: `prov` is NULL or live, and the namemap contract is `evp_is_a`'s.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `int EVP_SKEYMGMT_names_do_all(const EVP_SKEYMGMT *keymgmt,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// **A NULL method answers 0**, where `EVP_MAC_names_do_all` answers 1 and `EVP_MD`'s reaches for a
/// NULL provider. It is the one refusal in this class that is observable, and it is why the court
/// calls this accessor on NULL rather than trusting the family's symmetry.
///
/// # Safety
/// `keymgmt` must be NULL or live; `fn_` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_names_do_all(
    keymgmt: *const EvpSkeyMgmt,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    if keymgmt.is_null() {
        return 0;
    }
    // SAFETY: `keymgmt` is live per the contract.
    let (prov, name_id) = unsafe { ((*keymgmt).prov, (*keymgmt).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *EVP_SKEYMGMT_get0_gen_settable_params(const EVP_SKEYMGMT *skeymgmt)`.
///
/// A NULL method and a method with no `gen_params` both answer NULL, and the two are deliberately
/// indistinguishable here — unlike `get_ctx_params` in the KDF class, where a missing callback and
/// a refusing one are different answers.
///
/// # Safety
/// `skeymgmt` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_get0_gen_settable_params(
    skeymgmt: *const EvpSkeyMgmt,
) -> *const OsslParam {
    if skeymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `skeymgmt` is live per the contract.
    let (gen_params, prov) = unsafe { ((*skeymgmt).gen_params, (*skeymgmt).prov) };
    let Some(f) = gen_params else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `const OSSL_PARAM *EVP_SKEYMGMT_get0_imp_settable_params(const EVP_SKEYMGMT *skeymgmt)`.
///
/// The generation half's twin, named for the *import* parameters.
///
/// # Safety
/// `skeymgmt` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_get0_imp_settable_params(
    skeymgmt: *const EvpSkeyMgmt,
) -> *const OsslParam {
    if skeymgmt.is_null() {
        return ptr::null();
    }
    // SAFETY: `skeymgmt` is live per the contract.
    let (imp_params, prov) = unsafe { ((*skeymgmt).imp_params, (*skeymgmt).prov) };
    let Some(f) = imp_params else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `void EVP_SKEYMGMT_do_all_provided(OSSL_LIB_CTX *libctx,
/// void (*fn)(EVP_SKEYMGMT *keymgmt, void *arg), void *arg)`.
///
/// A **NULL visitor is refused** rather than passed to a walk that would call it; the boundary is
/// `EVP_MD_do_all_provided`'s, measured in `docs/SECURITY_DIVERGENCE_POLICY.md`
/// D-MD-DOALL-NULL-1.
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEYMGMT_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpSkeyMgmt, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(visitor) = fn_ else {
        return;
    };
    // SAFETY: `visitor` is a live function pointer and `GenericDoAllFn` is the same ABI with an
    // unnamed pointee — the authority's own cast. Nothing is called through it except by the walk,
    // in this call.
    let trampoline: GenericDoAllFn = unsafe { core::mem::transmute::<_, GenericDoAllFn>(visitor) };
    // SAFETY: `libctx` is NULL or live; the three class callbacks are this module's own.
    unsafe {
        evp_generic_do_all(
            libctx,
            OSSL_OP_SKEYMGMT,
            trampoline,
            arg,
            skeymgmt_from_algorithm as MethodFromAlgorithmFn,
            evp_skeymgmt_up_ref as MethodUpRefFn,
            evp_skeymgmt_free as MethodFreeFn,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The method's own call-throughs.
//
// Four `static`/non-static helpers in `skeymgmt_meth.c` that the rest of the class reaches the
// provider through. Three of the four assert their callback is present rather than testing it,
// because the structural check has already guaranteed it.
// ---------------------------------------------------------------------------------------------

/// `void *evp_skeymgmt_generate(const EVP_SKEYMGMT *skeymgmt, const OSSL_PARAM params[])`.
///
/// Answers NULL for a method with no `generate` — the one optional call-through in the four, and the
/// reason `EVP_SKEY_generate` can fail at the *first* operation rather than at the fetch.
///
/// # Safety
/// `skeymgmt` must be a live `EvpSkeyMgmt`; `params` NULL or a terminated array.
pub(crate) unsafe fn evp_skeymgmt_generate(
    skeymgmt: *const EvpSkeyMgmt,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `skeymgmt` is live per the contract.
    let (generate, prov) = unsafe { ((*skeymgmt).generate, (*skeymgmt).prov) };
    let Some(f) = generate else {
        return ptr::null_mut();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `f` is the provider's own callback, `provctx` is its context and `params` is the
    // caller's array.
    unsafe { f(provctx, params) }
}

/// `void *evp_skeymgmt_import(const EVP_SKEYMGMT *skeymgmt, int selection,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `skeymgmt` must be a live `EvpSkeyMgmt` whose `import` is non-NULL, which the structural check
/// guarantees; `params` NULL or a terminated array.
pub(crate) unsafe fn evp_skeymgmt_import(
    skeymgmt: *const EvpSkeyMgmt,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `skeymgmt` is live and its `import` is non-NULL per the contract.
    let f = unsafe { (*skeymgmt).import };
    let Some(import) = f else {
        return ptr::null_mut();
    };
    // SAFETY: `skeymgmt` is live, so its provider field is readable.
    let prov = unsafe { (*skeymgmt).prov };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `import` is the provider's own callback and the rest are the caller's arguments.
    unsafe { import(provctx, selection, params) }
}

/// `int evp_skeymgmt_export(const EVP_SKEYMGMT *skeymgmt, void *keydata, int selection,
/// OSSL_CALLBACK *param_cb, void *cbarg)`.
///
/// Note the argument order: the **key data** is the second argument and the provider context is not
/// involved at all. `export` is the one callback in the class that is not a function of `provctx`,
/// because the thing being read is the key rather than the provider.
///
/// # Safety
/// `skeymgmt` must be a live `EvpSkeyMgmt` whose `export` is non-NULL; `keydata` the key its own
/// `import`/`generate` produced; `param_cb` NULL or a valid callback.
pub(crate) unsafe fn evp_skeymgmt_export(
    skeymgmt: *const EvpSkeyMgmt,
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `skeymgmt` is live and its `export` is non-NULL per the contract.
    let f = unsafe { (*skeymgmt).export };
    let Some(export) = f else {
        return 0;
    };
    // SAFETY: `export` is the provider's own callback and the rest are the caller's arguments.
    unsafe { export(keydata, selection, param_cb, cbarg) }
}

/// `void evp_skeymgmt_freedata(const EVP_SKEYMGMT *skeymgmt, void *keydata)`.
///
/// # Safety
/// `skeymgmt` must be a live `EvpSkeyMgmt` whose `free` is non-NULL; `keydata` the key it produced
/// and not already released.
pub(crate) unsafe fn evp_skeymgmt_freedata(skeymgmt: *const EvpSkeyMgmt, keydata: *mut c_void) {
    // SAFETY: `skeymgmt` is live and its `free` is non-NULL per the contract.
    let f = unsafe { (*skeymgmt).free };
    if let Some(free) = f {
        // SAFETY: `free` is the provider's own destructor and `keydata` is its key.
        unsafe { free(keydata) };
    }
}

/// `EVP_SKEYMGMT *evp_skeymgmt_fetch_from_prov(OSSL_PROVIDER *prov, const char *name,
/// const char *properties)` — internal, and the only fetch in this module that is not the caller's.
///
/// # Safety
/// `prov` live; `name` and `properties` NULL or NUL-terminated.
pub(crate) unsafe fn evp_skeymgmt_fetch_from_prov(
    prov: *mut OsslProvider,
    name: *const c_char,
    properties: *const c_char,
) -> *mut EvpSkeyMgmt {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_SKEYMGMT,
            name,
            properties,
            skeymgmt_from_algorithm as MethodFromAlgorithmFn,
            evp_skeymgmt_up_ref as MethodUpRefFn,
            evp_skeymgmt_free as MethodFreeFn,
        )
    }
    .cast::<EvpSkeyMgmt>()
}

// ---------------------------------------------------------------------------------------------
// `EVP_SKEY`
// ---------------------------------------------------------------------------------------------

/// `int EVP_SKEY_export(const EVP_SKEY *skey, int selection, OSSL_CALLBACK *export_cb,
/// void *export_cbarg)`.
///
/// # Safety
/// `skey` NULL or live; `export_cb` NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_export(
    skey: *const EvpSkey,
    selection: c_int,
    export_cb: Option<OsslCallback>,
    export_cbarg: *mut c_void,
) -> c_int {
    if skey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::S_LIB_25) };
        return 0;
    }
    // SAFETY: `skey` is live per the contract.
    let (skeymgmt, keydata) = unsafe { ((*skey).skeymgmt, (*skey).keydata) };
    // SAFETY: `skeymgmt` is the method this key holds a reference to, so it is live; `keydata` is
    // its key.
    unsafe { evp_skeymgmt_export(skeymgmt, keydata, selection, export_cb, export_cbarg) }
}

/// `EVP_SKEY *evp_skey_alloc(EVP_SKEYMGMT *skeymgmt)` — internal.
///
/// Three allocations and a reference, and the two that can fail unwind through one label. The
/// authority's `ossl_assert(skeymgmt != NULL)` is non-fatal in this build and its value is the
/// condition of a `!`, so a NULL method is a NULL answer rather than an abort — recorded in
/// `docs/UNSAFE.md` and reproduced, not "improved".
///
/// **`EVP_SKEYMGMT_up_ref` cannot fail**, so the `else goto err` arm the authority writes is
/// unreachable; it is kept as a branch on the return value anyway, because that is the shape a
/// reader of the original expects to find and because a change to the up-ref's contract would
/// otherwise land here silently.
///
/// # Safety
/// `skeymgmt` must be NULL or a live `EvpSkeyMgmt`.
pub(crate) unsafe fn evp_skey_alloc(skeymgmt: *mut EvpSkeyMgmt) -> *mut EvpSkey {
    if skeymgmt.is_null() {
        return ptr::null_mut();
    }

    let skey = CRYPTO_zalloc(core::mem::size_of::<EvpSkey>(), FILE_LIB, LINE_ZALLOC_SKEY)
        .cast::<EvpSkey>();
    if skey.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `skey` is a fresh zeroed block this call owns.
    unsafe { (*skey).references = AtomicI32::new(1) };

    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::S_LIB_47) };
        // SAFETY: `skey` is this call's own block and no lock was taken.
        unsafe { CRYPTO_free(skey.cast::<c_void>(), FILE_LIB, LINE_FREE_SKEY_ON_ALLOC) };
        return ptr::null_mut();
    }
    // SAFETY: `skey` is live and `lock` is the lock just allocated for it.
    unsafe { (*skey).lock = lock };

    // SAFETY: `skeymgmt` is live per the contract.
    if (unsafe { EVP_SKEYMGMT_up_ref(skeymgmt) }) != 0 {
        // SAFETY: `skey` is live and `skeymgmt` is live.
        unsafe { (*skey).skeymgmt = skeymgmt };
        return skey;
    }

    // The `else goto err` arm, which is dead because the up-ref answers the constant 1.
    // SAFETY: `skey` is this call's own block and its lock is this call's own.
    unsafe {
        CRYPTO_THREAD_lock_free((*skey).lock);
        CRYPTO_free(skey.cast::<c_void>(), FILE_LIB, LINE_FREE_SKEY_ON_ALLOC);
    }
    ptr::null_mut()
}

/// `static EVP_SKEY *evp_skey_alloc_fetch(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
/// const char *propquery)`.
///
/// **Two fetches, not one.** A caller who names a key type nobody publishes is not an error: the
/// method is asked for again under `OSSL_SKEY_TYPE_GENERIC` (`"GENERIC-SECRET"`), and only a second
/// failure raises `ERR_R_FETCH_FAILED`. The generic name is what lets a provider hold keys whose
/// type it does not model.
///
/// # Safety
/// `libctx` NULL or live; `skeymgmtname` and `propquery` NULL or NUL-terminated.
unsafe fn evp_skey_alloc_fetch(
    libctx: *mut c_void,
    skeymgmtname: *const c_char,
    propquery: *const c_char,
) -> *mut EvpSkey {
    // SAFETY: the arguments are forwarded under this function's contract.
    let mut skeymgmt = unsafe { EVP_SKEYMGMT_fetch(libctx, skeymgmtname, propquery) };
    if skeymgmt.is_null() {
        // SAFETY: as above.
        skeymgmt = unsafe { EVP_SKEYMGMT_fetch(libctx, OSSL_SKEY_TYPE_GENERIC, propquery) };
        if skeymgmt.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::S_LIB_79) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `skeymgmt` is live.
    let skey = unsafe { evp_skey_alloc(skeymgmt) };
    // The fetch's reference, given back: the key took its own.
    // SAFETY: `skeymgmt` is live and this is the reference `EVP_SKEYMGMT_fetch` returned.
    unsafe { EVP_SKEYMGMT_free(skeymgmt) };

    skey
}

/// `EVP_SKEY *EVP_SKEY_import(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
/// const char *propquery, int selection, const OSSL_PARAM *params)`.
///
/// # Safety
/// `libctx` NULL or live; the two strings NULL or NUL-terminated; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_import(
    libctx: *mut c_void,
    skeymgmtname: *const c_char,
    propquery: *const c_char,
    selection: c_int,
    params: *const OsslParam,
) -> *mut EvpSkey {
    // SAFETY: the arguments are forwarded under this function's contract.
    let skey = unsafe { evp_skey_alloc_fetch(libctx, skeymgmtname, propquery) };
    if skey.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `skey` is live, so its method and key data fields are readable and writable.
    let keydata = unsafe { evp_skeymgmt_import((*skey).skeymgmt, selection, params) };
    if keydata.is_null() {
        // SAFETY: `skey` is this call's own object.
        unsafe { EVP_SKEY_free(skey) };
        return ptr::null_mut();
    }
    // SAFETY: `skey` is live and `keydata` is what its method just produced.
    unsafe { (*skey).keydata = keydata };
    skey
}

/// `EVP_SKEY *EVP_SKEY_import_SKEYMGMT(OSSL_LIB_CTX *libctx, EVP_SKEYMGMT *skeymgmt,
/// int selection, const OSSL_PARAM *params)`.
///
/// The same import with the method **already in hand**, which is the entry point
/// `EVP_SKEY_to_provider` needs: it holds a method fetched for another reason and would otherwise
/// re-resolve it by name. The `libctx` is unused in the authority too — the parameter is there so
/// that the two import entry points have the same first argument, and the method is what actually
/// decides where the key goes.
///
/// # Safety
/// `skeymgmt` NULL or live; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_import_SKEYMGMT(
    _libctx: *mut c_void,
    skeymgmt: *mut EvpSkeyMgmt,
    selection: c_int,
    params: *const OsslParam,
) -> *mut EvpSkey {
    let _ = _libctx;
    // SAFETY: `skeymgmt` is NULL or live per the contract.
    let skey = unsafe { evp_skey_alloc(skeymgmt) };
    if skey.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `skey` is live and now holds a reference to `skeymgmt`.
    let keydata = unsafe { evp_skeymgmt_import((*skey).skeymgmt, selection, params) };
    if keydata.is_null() {
        // SAFETY: `skey` is this call's own object.
        unsafe { EVP_SKEY_free(skey) };
        return ptr::null_mut();
    }
    // SAFETY: `skey` is live and `keydata` is what its method just produced.
    unsafe { (*skey).keydata = keydata };
    skey
}

/// `EVP_SKEY *EVP_SKEY_generate(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
/// const char *propquery, const OSSL_PARAM *params)`.
///
/// # Safety
/// `libctx` NULL or live; the two strings NULL or NUL-terminated; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_generate(
    libctx: *mut c_void,
    skeymgmtname: *const c_char,
    propquery: *const c_char,
    params: *const OsslParam,
) -> *mut EvpSkey {
    // SAFETY: the arguments are forwarded under this function's contract.
    let skey = unsafe { evp_skey_alloc_fetch(libctx, skeymgmtname, propquery) };
    if skey.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `skey` is live, so its method field is readable.
    let keydata = unsafe { evp_skeymgmt_generate((*skey).skeymgmt, params) };
    if keydata.is_null() {
        // SAFETY: `skey` is this call's own object.
        unsafe { EVP_SKEY_free(skey) };
        return ptr::null_mut();
    }
    // SAFETY: `skey` is live and `keydata` is what its method just produced.
    unsafe { (*skey).keydata = keydata };
    skey
}

/// `static int get_secret_key(const OSSL_PARAM params[], void *arg)` — the export callback
/// `EVP_SKEY_get0_raw_key` passes.
///
/// It reads exactly one parameter and **answers 0 when it is absent**, which is what makes
/// `EVP_SKEY_get0_raw_key` fail on a key whose provider does not publish its bytes — the AES key
/// type, whose bytes are not what it exports.
///
/// # Safety
/// `params` must be a terminated array; `arg` must point at a live `RawKeyDetails`.
unsafe extern "C" fn get_secret_key(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let details = arg.cast::<RawKeyDetails>();
    if details.is_null() {
        return 0;
    }
    // SAFETY: `params` is a terminated array per the contract.
    let p = unsafe { crate::params::OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: `details` is live and its two fields are the caller's own storage.
    let (key, len) = unsafe { ((*details).key, (*details).len) };
    // SAFETY: `p` is the located parameter and the two out-pointers are the caller's.
    unsafe { crate::params::OSSL_PARAM_get_octet_string_ptr(p, key, len) }
}

/// `struct raw_key_details_st { const void **key; size_t *len; }` — the callback's argument.
#[repr(C)]
struct RawKeyDetails {
    /// `const void **key` — the caller's out-parameter, written by the callback.
    key: *mut *const c_void,
    /// `size_t *len` — the caller's second out-parameter.
    len: *mut usize,
}

/// `int EVP_SKEY_get0_raw_key(const EVP_SKEY *skey, const unsigned char **key, size_t *len)`.
///
/// Three NULL tests and then an **export**, not a field read: the key's bytes are the provider's and
/// are only ever obtained by asking it to write them into the caller's pointers.
///
/// # Safety
/// `skey` live or NULL; `key` and `len` NULL or live out-parameters.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_get0_raw_key(
    skey: *const EvpSkey,
    key: *mut *const c_uchar,
    len: *mut usize,
) -> c_int {
    if skey.is_null() || key.is_null() || len.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::S_LIB_169) };
        return 0;
    }
    let mut details = RawKeyDetails {
        key: key.cast::<*const c_void>(),
        len,
    };
    // SAFETY: `skey` is live per the contract.
    let (skeymgmt, keydata) = unsafe { ((*skey).skeymgmt, (*skey).keydata) };
    // SAFETY: `skeymgmt` is the method this key holds a reference to; `keydata` is its key; the
    // callback is this frame's own and its argument outlives the call.
    unsafe {
        evp_skeymgmt_export(
            skeymgmt,
            keydata,
            OSSL_SKEYMGMT_SELECT_SECRET_KEY,
            Some(get_secret_key),
            ptr::addr_of_mut!(details).cast::<c_void>(),
        )
    }
}

/// `EVP_SKEY *EVP_SKEY_import_raw_key(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
/// unsigned char *key, size_t keylen, const char *propquery)`.
///
/// The one convenience constructor in the class, and it is built out of the general one: a
/// single-element `params` array naming `OSSL_SKEY_PARAM_RAW_BYTES`, and a selection of
/// `SELECT_SECRET_KEY` alone. Note that the buffer is passed **by reference, not copied** — the
/// provider's `import` decides what to do with it, and this function does not own it.
///
/// # Safety
/// `libctx` NULL or live; `skeymgmtname` and `propquery` NULL or NUL-terminated; `key` NULL or
/// readable for `keylen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_import_raw_key(
    libctx: *mut c_void,
    skeymgmtname: *const c_char,
    key: *mut c_uchar,
    keylen: usize,
    propquery: *const c_char,
) -> *mut EvpSkey {
    let mut params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: the constructor takes no precondition beyond a key string and a buffer, and the rest
    // of the array is already terminated.
    params[0] = unsafe {
        OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, key.cast::<c_void>(), keylen)
    };
    // SAFETY: `params` is this frame's own terminated array and the arguments are forwarded under
    // this function's contract.
    unsafe {
        EVP_SKEY_import(
            libctx,
            skeymgmtname,
            propquery,
            OSSL_SKEYMGMT_SELECT_SECRET_KEY,
            params.as_ptr(),
        )
    }
}

/// `int EVP_SKEY_up_ref(EVP_SKEY *skey)`.
///
/// `CRYPTO_UP_REF` writes the **new** count into its out-parameter and returns 1, so the authority's
/// `<= 0` guard is unreachable and the answer is exactly `new > 1`: a key whose count was 0 is not
/// brought back to life, and a key whose count was 1 or more takes a reference.
///
/// # Safety
/// `skey` must be a live `EvpSkey`.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_up_ref(skey: *mut EvpSkey) -> c_int {
    // SAFETY: `skey` is live per the contract.
    let previous = unsafe { (*skey).references.fetch_add(1, Ordering::AcqRel) };
    if previous + 1 > 1 {
        1
    } else {
        0
    }
}

/// `void EVP_SKEY_free(EVP_SKEY *skey)`.
///
/// The release order is the authority's and it is the whole reason this class holds a method
/// reference: the key data goes back to the provider, **then** the method, then the lock, then the
/// block. A transcription that freed the method first would leave `evp_skeymgmt_freedata` reading a
/// released method.
///
/// # Safety
/// `skey` must be NULL or a live `EvpSkey`.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_free(skey: *mut EvpSkey) {
    if skey.is_null() {
        return;
    }
    // SAFETY: `skey` is live per the contract.
    let new = unsafe { (*skey).references.fetch_sub(1, Ordering::AcqRel) } - 1;
    if new > 0 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference and every field is this call's
    // to release.
    unsafe {
        evp_skeymgmt_freedata((*skey).skeymgmt, (*skey).keydata);
        EVP_SKEYMGMT_free((*skey).skeymgmt);
        CRYPTO_THREAD_lock_free((*skey).lock);
        CRYPTO_free(skey.cast::<c_void>(), FILE_LIB, LINE_FREE_SKEY);
    }
}

/// `const char *EVP_SKEY_get0_key_id(const EVP_SKEY *skey)`.
///
/// NULL for a NULL key, and NULL for a method with no `get_key_id` — the same answer for two
/// different reasons, and both are the authority's.
///
/// # Safety
/// `skey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_get0_key_id(skey: *const EvpSkey) -> *const c_char {
    if skey.is_null() {
        return ptr::null();
    }
    // SAFETY: `skey` is live per the contract.
    let skeymgmt = unsafe { (*skey).skeymgmt };
    // SAFETY: `skeymgmt` is live, being the method this key holds a reference to.
    let f = unsafe { (*skeymgmt).get_key_id };
    let Some(get_key_id) = f else {
        return ptr::null();
    };
    // SAFETY: `skey` is live and `get_key_id` is a callback of its method, taking the key data.
    let keydata = unsafe { (*skey).keydata };
    // SAFETY: `get_key_id` is the provider's own callback and `keydata` is its key.
    unsafe { get_key_id(keydata) }
}

/// `const char *EVP_SKEY_get0_skeymgmt_name(const EVP_SKEY *skey)`.
///
/// # Safety
/// `skey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_get0_skeymgmt_name(skey: *const EvpSkey) -> *const c_char {
    if skey.is_null() {
        return ptr::null();
    }
    // SAFETY: `skey` is live per the contract.
    let skeymgmt = unsafe { (*skey).skeymgmt };
    // SAFETY: `skeymgmt` is live, being the method this key holds a reference to.
    unsafe { (*skeymgmt).type_name }
}

/// `const char *EVP_SKEY_get0_provider_name(const EVP_SKEY *skey)`.
///
/// # Safety
/// `skey` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_get0_provider_name(skey: *const EvpSkey) -> *const c_char {
    if skey.is_null() {
        return ptr::null();
    }
    // SAFETY: `skey` is live per the contract.
    let skeymgmt = unsafe { (*skey).skeymgmt };
    // SAFETY: `skeymgmt` is live, being the method this key holds a reference to.
    let prov = unsafe { (*skeymgmt).prov };
    // SAFETY: `prov` is NULL or live.
    unsafe { ossl_provider_name(prov) }
}

/// `int EVP_SKEY_is_a(const EVP_SKEY *skey, const char *name)`.
///
/// The key's identity **is its method's** identity: there is no separate namemap entry for a key,
/// and this is a straight delegation rather than a lookup.
///
/// # Safety
/// `skey` must be NULL or live; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_is_a(skey: *const EvpSkey, name: *const c_char) -> c_int {
    if skey.is_null() {
        return 0;
    }
    // SAFETY: `skey` is live per the contract.
    let skeymgmt = unsafe { (*skey).skeymgmt };
    // SAFETY: `skeymgmt` is live and `name` is the caller's.
    unsafe { EVP_SKEYMGMT_is_a(skeymgmt, name) }
}

/// `struct transfer_cb_ctx { int selection; EVP_SKEYMGMT *skeymgmt; void *keydata; }`.
#[repr(C)]
struct TransferCbCtx {
    /// `int selection` — the bits the destination is asked for.
    selection: c_int,
    /// `EVP_SKEYMGMT *skeymgmt` — the destination method.
    skeymgmt: *mut EvpSkeyMgmt,
    /// `void *keydata` — the destination's key, written by the callback.
    keydata: *mut c_void,
}

/// `static int transfer_cb(const OSSL_PARAM params[], void *arg)` — the export callback
/// `EVP_SKEY_to_provider` passes.
///
/// **It answers 1 unconditionally**, even when the import it performs returned NULL. The failure is
/// not lost — `EVP_SKEY_to_provider` tests `ctx.keydata` immediately afterwards — but the callback
/// itself does not report it, which is a shape worth reproducing exactly: a transcription that
/// returned the import's success would stop the export at the first parameter and change the
/// observable error.
///
/// # Safety
/// `params` must be a terminated array; `arg` must point at a live `TransferCbCtx`.
unsafe extern "C" fn transfer_cb(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let ctx = arg.cast::<TransferCbCtx>();
    if ctx.is_null() {
        return 1;
    }
    // SAFETY: `ctx` is live per the contract.
    let (skeymgmt, selection) = unsafe { ((*ctx).skeymgmt, (*ctx).selection) };
    // SAFETY: `skeymgmt` is the destination method and `params` is the export's own array.
    let keydata = unsafe { evp_skeymgmt_import(skeymgmt, selection, params) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).keydata = keydata };
    1
}

/// `EVP_SKEY *EVP_SKEY_to_provider(EVP_SKEY *skey, OSSL_LIB_CTX *libctx, OSSL_PROVIDER *prov,
/// const char *propquery)`.
///
/// Four arms, and the order they are tested in is the contract:
///
///   1. **a destination that is the origin** — the same `name_id` *and* the same provider — is not a
///      transfer at all; it is an `up_ref` of the same pointer, so the caller gets back the object
///      it passed. This is the only place in the class where two `EVP_SKEY *` compare equal;
///   2. **a named provider** that is not the origin fetches the method *from that provider*, by
///      `evp_skeymgmt_fetch_from_prov`, so the destination is the provider's own method rather than
///      one the libctx would have resolved;
///   3. **no provider** means the default, resolved by name through the libctx — the same fetch
///      `EVP_SKEY_import` would have made;
///   4. anything else is the round trip: export to parameters, import into the destination, and
///      release the method reference this function took on the way in.
///
/// # Safety
/// `skey` NULL or live; `libctx` NULL or live; `prov` NULL or live; `propquery` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SKEY_to_provider(
    skey: *mut EvpSkey,
    libctx: *mut c_void,
    prov: *mut OsslProvider,
    propquery: *const c_char,
) -> *mut EvpSkey {
    if skey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::S_LIB_285) };
        return ptr::null_mut();
    }

    // SAFETY: `skey` is live per the contract.
    let origin = unsafe { (*skey).skeymgmt };

    // The first arm's fetch, before the short-circuit below can use it.
    let fetched: *mut EvpSkeyMgmt = if !prov.is_null() {
        // SAFETY: `origin` is live, so its provider is readable.
        let origin_prov = unsafe { (*origin).prov };
        if origin_prov == prov {
            // The destination *is* the origin: take the caller's reference on the origin's own
            // method, which the short-circuit below gives back.
            // SAFETY: `origin` is live.
            unsafe { EVP_SKEYMGMT_up_ref(origin) };
            origin
        } else {
            // SAFETY: `origin` is live, so its type name is readable; `prov` and `propquery` are the
            // caller's.
            let type_name = unsafe { (*origin).type_name };
            // SAFETY: `prov` is live and the two strings are NULL or NUL-terminated.
            unsafe { evp_skeymgmt_fetch_from_prov(prov, type_name, propquery) }
        }
    } else {
        // SAFETY: `origin` is live, so its type name is readable; `libctx` and `propquery` are the
        // caller's.
        let type_name = unsafe { (*origin).type_name };
        // SAFETY: `libctx` is NULL or live and the two strings are NULL or NUL-terminated.
        unsafe { EVP_SKEYMGMT_fetch(libctx, type_name, propquery) }
    };

    if fetched.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::S_LIB_305) };
        return ptr::null_mut();
    }

    // The short-circuit: the same name *and* the same provider.
    // SAFETY: `origin` and `fetched` are both live.
    let same =
        unsafe { (*origin).name_id == (*fetched).name_id && (*origin).prov == (*fetched).prov };
    if same {
        // SAFETY: `skey` is live per the contract.
        if (unsafe { EVP_SKEY_up_ref(skey) }) != 0 {
            // SAFETY: `fetched` is live and this is the reference taken above.
            unsafe { EVP_SKEYMGMT_free(fetched) };
            return skey;
        }
        // SAFETY: `fetched` is live and this is the reference taken above.
        unsafe { EVP_SKEYMGMT_free(fetched) };
        return ptr::null_mut();
    }

    let mut ctx = TransferCbCtx {
        selection: OSSL_SKEYMGMT_SELECT_ALL,
        skeymgmt: fetched,
        keydata: ptr::null_mut(),
    };

    // SAFETY: `skey` is live and `ctx` is this frame's own live object whose address outlives the
    // call.
    let exported = unsafe {
        EVP_SKEY_export(
            skey,
            ctx.selection,
            Some(transfer_cb),
            ptr::addr_of_mut!(ctx).cast::<c_void>(),
        )
    };
    if exported == 0 || ctx.keydata.is_null() {
        // SAFETY: `fetched` is live and this is the reference taken above.
        unsafe { EVP_SKEYMGMT_free(fetched) };
        return ptr::null_mut();
    }

    // SAFETY: `fetched` is live.
    let ret = unsafe { evp_skey_alloc(fetched) };
    if ret.is_null() {
        // The destination's key data is the export's, and releasing it is the destination method's
        // job -- `ret` was never given it, so the method is asked to free it here.
        // SAFETY: `fetched` is live and `ctx.keydata` is what its own `import` produced.
        unsafe { evp_skeymgmt_freedata(fetched, ctx.keydata) };
        // SAFETY: `fetched` is live and this is the reference taken above (and the one `evp_skey_alloc`
        // did not take).
        unsafe { EVP_SKEYMGMT_free(fetched) };
        return ptr::null_mut();
    }

    // SAFETY: `ret` is live and `ctx.keydata` is the key data imported into `ret`'s method.
    unsafe { (*ret).keydata = ctx.keydata };

    // The reference `evp_skey_alloc` took is the key's; this one was the fetch's.
    // SAFETY: `fetched` is live and this is the extra reference.
    unsafe { EVP_SKEYMGMT_free(fetched) };

    ret
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// A method built by hand, so the arms of this file that are not about fetching can be read
    /// without a provider.
    fn a_hand_built_skeymgmt() -> EvpSkeyMgmt {
        EvpSkeyMgmt {
            name_id: 41,
            type_name: ptr::null_mut(),
            description: c"a hand-built SKEYMGMT".as_ptr(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            imp_params: None,
            import: None,
            export: None,
            gen_params: None,
            generate: None,
            get_key_id: None,
            free: None,
        }
    }

    /// A key whose method is `mgmt` and whose key data is `keydata`, on the caller's stack.
    fn a_hand_built_skey(mgmt: *mut EvpSkeyMgmt, keydata: *mut c_void) -> EvpSkey {
        EvpSkey {
            references: AtomicI32::new(1),
            lock: ptr::null_mut(),
            keydata,
            skeymgmt: mgmt,
        }
    }

    /// The coordinate of the last error raised, against a recorded site.
    fn assert_coordinate(site: &err_sites::ErrSite) {
        use crate::runtime::err::ERR_peek_last_error_all;

        let mut file: *const c_char = ptr::null();
        let mut line: c_int = 0;
        let mut func: *const c_char = ptr::null();
        let mut data: *const c_char = ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: every output pointer is this frame's own storage.
        let code = unsafe {
            ERR_peek_last_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
        };
        assert_ne!(code, 0, "an error was raised");
        // SAFETY: the call wrote a NUL-terminated string the error state still owns.
        assert_eq!(unsafe { CStr::from_ptr(file) }, site.file, "file");
        assert_eq!(line, site.line, "line");
        // SAFETY: as above.
        assert_eq!(unsafe { CStr::from_ptr(func) }, site.func, "func");
        crate::runtime::err::ERR_clear_error();
    }

    #[test]
    fn the_method_accessors_read_fields_and_guard_null() {
        let mgmt = a_hand_built_skeymgmt();
        let p: *const EvpSkeyMgmt = ptr::addr_of!(mgmt);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            /* The name accessor answers `type_name`, which is NULL on this fixture, and the
             * description accessor answers the description: two different fields, not aliases. */
            assert!(EVP_SKEYMGMT_get0_name(p).is_null());
            assert_eq!(
                CStr::from_ptr(EVP_SKEYMGMT_get0_description(p)),
                c"a hand-built SKEYMGMT"
            );
            assert!(EVP_SKEYMGMT_get0_provider(p).is_null());
            assert!(EVP_SKEYMGMT_get0_name(ptr::null()).is_null());
            assert!(EVP_SKEYMGMT_get0_description(ptr::null()).is_null());
            assert!(EVP_SKEYMGMT_get0_provider(ptr::null()).is_null());
            assert_eq!(EVP_SKEYMGMT_is_a(ptr::null(), c"anything".as_ptr()), 0);
            /* The two parameter accessors answer NULL for a NULL method and for a method with no
             * callback alike -- the same answer for two reasons. */
            assert!(EVP_SKEYMGMT_get0_gen_settable_params(ptr::null()).is_null());
            assert!(EVP_SKEYMGMT_get0_imp_settable_params(ptr::null()).is_null());
            assert!(EVP_SKEYMGMT_get0_gen_settable_params(p).is_null());
            assert!(EVP_SKEYMGMT_get0_imp_settable_params(p).is_null());
        }
    }

    /// `names_do_all` is the one accessor in this class that answers **0** for a NULL method, where
    /// every sibling class answers 1. The boundary is what the court observes and what this pins.
    #[test]
    fn names_do_all_refuses_a_null_method_where_its_siblings_do_not() {
        // SAFETY: NULL is the documented refusal for this accessor, and every other argument is
        // inert.
        let refused = unsafe { EVP_SKEYMGMT_names_do_all(ptr::null(), None, ptr::null_mut()) };
        assert_eq!(refused, 0);
    }

    /// `up_ref` answers the constant 1 and `free` guards NULL: the asymmetry between the two halves
    /// of `EVP_SKEYMGMT`'s reference contract.
    #[test]
    fn up_ref_answers_one_and_free_guards_null() {
        let mut mgmt = a_hand_built_skeymgmt();
        let p: *mut EvpSkeyMgmt = ptr::addr_of_mut!(mgmt);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_SKEYMGMT_up_ref(p), 1);
            assert_eq!(mgmt.refcnt.load(Ordering::Acquire), 2);
            assert_eq!(EVP_SKEYMGMT_up_ref(p), 1);
            assert_eq!(mgmt.refcnt.load(Ordering::Acquire), 3);
            /* One `free` takes one reference and stops, so the stack object is never released. */
            EVP_SKEYMGMT_free(p);
            assert_eq!(mgmt.refcnt.load(Ordering::Acquire), 2);
            EVP_SKEYMGMT_free(ptr::null_mut());
        }
    }

    /// `EVP_SKEY_up_ref` computes where its method's sibling does not: a count of 1 takes a
    /// reference and answers 1, and a count of 0 does not resurrect the object and answers 0.
    #[test]
    fn a_key_reference_is_taken_only_from_a_live_key() {
        let mut mgmt = a_hand_built_skeymgmt();
        let mp: *mut EvpSkeyMgmt = ptr::addr_of_mut!(mgmt);
        let mut skey = a_hand_built_skey(mp, ptr::null_mut());
        let sp: *mut EvpSkey = ptr::addr_of_mut!(skey);
        // SAFETY: `sp` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_SKEY_up_ref(sp), 1);
            assert_eq!(skey.references.load(Ordering::Acquire), 2);
            /* A count of zero is not brought back to life: `CRYPTO_UP_REF` would make it 1 and the
             * authority's answer is `new > 1`. */
            skey.references.store(0, Ordering::Release);
            assert_eq!(EVP_SKEY_up_ref(sp), 0);
            assert_eq!(skey.references.load(Ordering::Acquire), 1);
        }
    }

    /// `EVP_SKEY_export` on a NULL key raises `ERR_R_PASSED_NULL_PARAMETER`, and the key's
    /// accessors answer NULL for a NULL key rather than dereferencing it.
    #[test]
    fn a_null_key_is_refused_by_export_and_answered_by_the_accessors() {
        // SAFETY: NULL is the documented refusal for these entry points.
        unsafe {
            assert_eq!(EVP_SKEY_export(ptr::null(), 0, None, ptr::null_mut()), 0);
            assert_coordinate(&err_sites::S_LIB_25);
            assert!(EVP_SKEY_get0_key_id(ptr::null()).is_null());
            assert!(EVP_SKEY_get0_skeymgmt_name(ptr::null()).is_null());
            assert!(EVP_SKEY_get0_provider_name(ptr::null()).is_null());
            assert_eq!(EVP_SKEY_is_a(ptr::null(), c"x".as_ptr()), 0);
            assert!(EVP_SKEY_to_provider(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null()
            )
            .is_null());
            assert_coordinate(&err_sites::S_LIB_285);
        }
    }

    /// A key's identity accessors are its method's: three delegations and one that is a field read.
    #[test]
    fn the_key_accessors_delegate_to_its_method() {
        static TYPE_NAME: &[u8] = b"SKEY-COURT\0";
        let mut mgmt = a_hand_built_skeymgmt();
        mgmt.type_name = TYPE_NAME.as_ptr().cast::<c_char>().cast_mut();
        let mp: *mut EvpSkeyMgmt = ptr::addr_of_mut!(mgmt);
        let skey = a_hand_built_skey(mp, ptr::null_mut());
        let sp: *const EvpSkey = ptr::addr_of!(skey);
        // SAFETY: `sp` is this frame's own live object and `mp` is its method.
        unsafe {
            assert_eq!(
                CStr::from_ptr(EVP_SKEY_get0_skeymgmt_name(sp)),
                c"SKEY-COURT"
            );
            /* No provider, so `ossl_provider_name` answers NULL rather than dereferencing. */
            assert!(EVP_SKEY_get0_provider_name(sp).is_null());
            /* No `get_key_id` on this method, so the answer is NULL -- the same as for a NULL key. */
            assert!(EVP_SKEY_get0_key_id(sp).is_null());
        }
    }

    /// `EVP_SKEY_get0_raw_key` refuses all three NULLs before reaching the provider, and raises one
    /// coordinate for all three.
    #[test]
    fn get0_raw_key_refuses_every_null_up_front() {
        let mut mgmt = a_hand_built_skeymgmt();
        let mp: *mut EvpSkeyMgmt = ptr::addr_of_mut!(mgmt);
        let skey = a_hand_built_skey(mp, ptr::null_mut());
        let sp: *const EvpSkey = ptr::addr_of!(skey);
        let mut key: *const c_uchar = ptr::null();
        let mut len: usize = 0;
        // SAFETY: `sp` is this frame's own live object and the two out-parameters are this frame's.
        unsafe {
            assert_eq!(EVP_SKEY_get0_raw_key(ptr::null(), &mut key, &mut len), 0);
            assert_coordinate(&err_sites::S_LIB_169);
            assert_eq!(EVP_SKEY_get0_raw_key(sp, ptr::null_mut(), &mut len), 0);
            assert_coordinate(&err_sites::S_LIB_169);
            assert_eq!(EVP_SKEY_get0_raw_key(sp, &mut key, ptr::null_mut()), 0);
            assert_coordinate(&err_sites::S_LIB_169);
        }
    }

    /// The two callbacks this module installs, driven directly: `get_secret_key` answers 0 for an
    /// absent parameter where `transfer_cb` answers 1 for everything — including an import that
    /// failed, which is the shape worth pinning because the caller tests `keydata` afterwards
    /// rather than the callback's answer.
    ///
    /// Each callback is handed **its own** argument structure. They are not interchangeable: a
    /// `TransferCbCtx` written into a `RawKeyDetails`' storage is an out-of-bounds write, and the
    /// first version of this test did exactly that and aborted on a null dereference, which is the
    /// debug-assertion layer earning its keep in a unit test.
    #[test]
    fn the_export_callbacks_answer_what_their_callers_test() {
        let empty = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
        let mut details = RawKeyDetails {
            key: ptr::null_mut(),
            len: ptr::null_mut(),
        };
        // SAFETY: `empty` is a terminated array and `details` is this frame's own live object.
        let absent =
            unsafe { get_secret_key(empty.as_ptr(), ptr::addr_of_mut!(details).cast::<c_void>()) };
        assert_eq!(absent, 0);

        /// An `import` that refuses, so the callback is driven on the path where the provider
        /// answers NULL -- the one arm where `transfer_cb`'s constant 1 is observable.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn refusing_import(
            _provctx: *mut c_void,
            _selection: c_int,
            _params: *const OsslParam,
        ) -> *mut c_void {
            ptr::null_mut()
        }

        let mut mgmt = a_hand_built_skeymgmt();
        mgmt.import = Some(refusing_import);
        let mut ctx = TransferCbCtx {
            selection: OSSL_SKEYMGMT_SELECT_ALL,
            skeymgmt: ptr::addr_of_mut!(mgmt),
            keydata: ptr::null_mut(),
        };
        // SAFETY: `empty` is a terminated array and `ctx` is this frame's own live object whose
        // method is this frame's own live method.
        let always =
            unsafe { transfer_cb(empty.as_ptr(), ptr::addr_of_mut!(ctx).cast::<c_void>()) };
        assert_eq!(
            always, 1,
            "the callback reports success even when the import refused"
        );
        assert!(
            ctx.keydata.is_null(),
            "and the failure is left in the out-parameter"
        );
    }

    /// `evp_skey_alloc` refuses a NULL method where `evp_skeymgmt_import` reaches for one: the
    /// `ossl_assert` at the top of the allocator is the boundary, and it is non-fatal.
    #[test]
    fn the_allocator_refuses_a_null_method() {
        // SAFETY: NULL is the documented refusal.
        assert!(unsafe { evp_skey_alloc(ptr::null_mut()) }.is_null());
    }
}
