//! `crypto/store/store_meth.c` — the `OSSL_STORE_LOADER` method object and its fetch.
//! Phase 10 (10.5).
//!
//! The unit is 511 lines and ten exports: the object's reference-counted constructor and
//! destructor, the `OSSL_OP_STORE` dispatch scan, the fetch over the store-loader method
//! store (slot 15), `do_all_provided`, `names_do_all`, `settable_ctx_params` and the four
//! by-name accessors (`get0_provider`, `get0_properties`, `get0_description`, `is_a`). The
//! internal workers (`new_loader`, the six `ossl_method_construct` callbacks,
//! `loader_from_algorithm`, `inner_loader_fetch`, the two store bridges and
//! `ossl_store_loader_get_number`) land with them.
//!
//! It is the **twin** of `src/decoder_meth.rs` (D363/D366), one function at a time: the
//! same temporary-store/`reserve`/`get`/`put`/`construct`/`destruct` interface, the same
//! cache-first fetch and the same "unsupported vs fetch-failed" error split. It is not a
//! copy: every body was read from `store_meth.c`, and where the two differ the difference
//! is recorded. Three of them matter:
//!
//! * the name the method store is keyed by is the **scheme**, and a loader has exactly one,
//!   so `construct_loader` uses `ossl_namemap_add_name` rather than the decoder's
//!   separator-aware `ossl_namemap_add_names`;
//! * the sanity check is the authority's own four clauses
//!   (`loader_from_algorithm`:4, `(p_open == NULL && p_attach == NULL) || p_load == NULL ||
//!   p_eof == NULL || p_close == NULL`) — `p_set_ctx_params` alone is optional;
//! * the fetch's error text names a `Scheme` rather than a `Name`, and the helpful suffix
//!   ("No store loader found. For standard store loaders you need at least one of the
//!   default or base providers available. Did you forget to load them? Info: ") is part of
//!   the message the unsupported arm emits.
//!
//! # Slot 15
//!
//! `get_loader_store` reads `OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX` (15), which
//! `src/context/mod.rs`'s `context_init` now builds in the authority's own position
//! (`crypto/context.c:139`, after `encoder_store` and before `provider_store`). The two
//! bridges in `src/provider/stores.rs` are real calls as a result.
//!
//! # The local `err_sites` declaration
//!
//! `crypto/store/store_meth.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! six raise coordinates are declared here under the generator's own naming, the way
//! `src/pkcs12/p12_npas.rs` and `src/provider/encode_key2any.rs` declare theirs.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::context::dispatch::OsslDispatch;
use crate::context::namemap::{
    ossl_namemap_add_name, ossl_namemap_doall_names, ossl_namemap_name2num, ossl_namemap_num2name,
    ossl_namemap_stored,
};
use crate::context::{
    lib_ctx_get_data, lib_ctx_get_descriptor, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX,
};
use crate::evp::method_store::{ossl_method_construct, OsslMethodConstructMethod};
use crate::property::store::{
    ossl_method_lock_store, ossl_method_store_add, ossl_method_store_cache_flush_all,
    ossl_method_store_cache_get, ossl_method_store_cache_set, ossl_method_store_do_all,
    ossl_method_store_fetch, ossl_method_store_free, ossl_method_store_new,
    ossl_method_store_remove_all_provided, ossl_method_unlock_store, OsslMethodStore,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{
    ossl_provider_free, ossl_provider_libctx, ossl_provider_up_ref, OsslProvider,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::{
    OsslStoreLoader, StorePAttachFn, StorePCloseFn, StorePDeleteFn, StorePEofFn,
    StorePExportObjectFn, StorePLoadFn, StorePOpenExFn, StorePOpenFn, StorePSetCtxParamsFn,
    StorePSettableCtxParamsFn, OSSL_FUNC_STORE_ATTACH, OSSL_FUNC_STORE_CLOSE,
    OSSL_FUNC_STORE_DELETE, OSSL_FUNC_STORE_EOF, OSSL_FUNC_STORE_EXPORT_OBJECT,
    OSSL_FUNC_STORE_LOAD, OSSL_FUNC_STORE_OPEN, OSSL_FUNC_STORE_OPEN_EX,
    OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, OSSL_FUNC_STORE_SET_CTX_PARAMS,
};

/// `#define OSSL_OP_STORE 22` — `include/openssl/core_dispatch.h:297`.
const OSSL_OP_STORE: c_int = 22;

/// `ERR_LIB_OSSL_STORE` — `include/openssl/err.h:158`.
const ERR_LIB_OSSL_STORE: c_int = 44;
/// `OSSL_STORE_R_LOADER_INCOMPLETE` — `include/openssl/storeerr.h:33`.
const OSSL_STORE_R_LOADER_INCOMPLETE: c_int = 116;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h:362`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h:354`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `ERR_R_UNSUPPORTED` — `err.h:366`, `268 | ERR_RFLAG_COMMON`.
const ERR_R_UNSUPPORTED: c_int = 524556;
/// `ERR_R_FETCH_FAILED` — `err.h:367`, `269 | ERR_RFLAG_COMMON`.
const ERR_R_FETCH_FAILED: c_int = 524557;

/// One `store_meth.c` raise coordinate. `line` and `func` are the authority file's own.
const fn meth_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
    dynamic_reason: bool,
) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/store/store_meth.c",
        line,
        func,
        lib: ERR_LIB_OSSL_STORE,
        reason,
        dynamic_reason,
    }
}

/// `loader_from_algorithm` at `store_meth.c:241`.
const STORE_METH_241: err_sites::ErrSite = meth_site(
    241,
    c"loader_from_algorithm",
    OSSL_STORE_R_LOADER_INCOMPLETE,
    false,
);
/// `inner_loader_fetch` at `store_meth.c:300`.
const STORE_METH_300: err_sites::ErrSite = meth_site(
    300,
    c"inner_loader_fetch",
    ERR_R_PASSED_INVALID_ARGUMENT,
    false,
);
/// `inner_loader_fetch` at `store_meth.c:362` — the computed `ERR_R_UNSUPPORTED` /
/// `ERR_R_FETCH_FAILED` reason, which is why the site is `dynamic_reason`.
const STORE_METH_362: err_sites::ErrSite = meth_site(362, c"inner_loader_fetch", 0, true);
/// `OSSL_STORE_LOADER_get0_provider` at `store_meth.c:413`.
const STORE_METH_413: err_sites::ErrSite = meth_site(
    413,
    c"OSSL_STORE_LOADER_get0_provider",
    ERR_R_PASSED_NULL_PARAMETER,
    false,
);
/// `OSSL_STORE_LOADER_get0_properties` at `store_meth.c:423`.
const STORE_METH_423: err_sites::ErrSite = meth_site(
    423,
    c"OSSL_STORE_LOADER_get0_properties",
    ERR_R_PASSED_NULL_PARAMETER,
    false,
);
/// `ossl_store_loader_get_number` at `store_meth.c:433`.
const STORE_METH_433: err_sites::ErrSite = meth_site(
    433,
    c"ossl_store_loader_get_number",
    ERR_R_PASSED_NULL_PARAMETER,
    false,
);

// ---------------------------------------------------------------------------
// The object — `store_meth.c:19-72`
// ---------------------------------------------------------------------------

/// `int OSSL_STORE_LOADER_up_ref(OSSL_STORE_LOADER *loader)` — `store_meth.c:19-26`.
///
/// Answers **1** unconditionally; the count is raised only when the loader is a provider
/// loader (`loader->prov != NULL`), which is what distinguishes it from the legacy object
/// `store_register.c` builds (whose refcount is unused).
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_up_ref(loader: *mut OsslStoreLoader) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe {
        if !(*loader).prov.is_null() {
            (*loader).refcnt.fetch_add(1, Ordering::AcqRel);
        }
    }
    1
}

/// `void OSSL_STORE_LOADER_free(OSSL_STORE_LOADER *loader)` — `store_meth.c:28-40`.
///
/// For a provider loader the reference is released, and only the last reference releases
/// the provider and the block. For a legacy loader (`prov == NULL`) the count is untouched
/// and the block is freed directly. The **borrowed** `scheme`, `propdef` and `description`
/// are never freed — the authority's own comment at `:42-45` says the scheme is a constant
/// string.
///
/// # Safety
/// `loader` must be NULL or a live loader this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_free(loader: *mut OsslStoreLoader) {
    if loader.is_null() {
        return;
    }
    // SAFETY: `loader` is non-NULL per the guard above.
    unsafe {
        if !(*loader).prov.is_null() {
            let last = (*loader).refcnt.fetch_sub(1, Ordering::AcqRel);
            if last > 1 {
                return;
            }
            ossl_provider_free((*loader).prov);
        }
        CRYPTO_free(loader.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `static OSSL_STORE_LOADER *new_loader(OSSL_PROVIDER *prov)` — `store_meth.c:46-62`.
///
/// A zeroed object with a reference count of 1 and a provider reference. The authority's
/// alternative to `OSSL_STORE_LOADER_new` for the reason its comment gives: the provider
/// loader's scheme is not a constant string.
///
/// # Safety
/// `prov` must be live.
unsafe fn new_loader(prov: *mut OsslProvider) -> *mut OsslStoreLoader {
    // SAFETY: the constructor asks only for a zeroed block of the object's size.
    let loader = CRYPTO_zalloc(core::mem::size_of::<OsslStoreLoader>(), ptr::null(), 0)
        .cast::<OsslStoreLoader>();
    if loader.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `loader` is fresh and uniquely owned; `CRYPTO_NEW_REF` is the count-1 store.
    unsafe { (*loader).refcnt.store(1, Ordering::Release) };
    // SAFETY: `prov` is live per the contract.
    if unsafe { ossl_provider_up_ref(prov) } == 0 {
        // SAFETY: `loader` is this function's own allocation, and the provider reference
        // failed so nothing else holds the block.
        unsafe { CRYPTO_free(loader.cast::<c_void>(), ptr::null(), 0) };
        return ptr::null_mut();
    }
    // SAFETY: `loader` is live.
    unsafe { (*loader).prov = prov };
    loader
}

/// `static int up_ref_loader(void *method)` — `store_meth.c:64-67`.
///
/// # Safety
/// `method` must be a live loader.
unsafe extern "C" fn up_ref_loader(method: *mut c_void) -> c_int {
    // SAFETY: `method` is a live loader per the contract.
    unsafe { OSSL_STORE_LOADER_up_ref(method.cast::<OsslStoreLoader>()) }
}

/// `static void free_loader(void *method)` — `store_meth.c:69-72`.
///
/// # Safety
/// `method` must be a live loader.
unsafe extern "C" fn free_loader(method: *mut c_void) {
    // SAFETY: `method` is a live loader per the contract.
    unsafe { OSSL_STORE_LOADER_free(method.cast::<OsslStoreLoader>()) }
}

// ---------------------------------------------------------------------------
// The dispatch scan — `store_meth.c:178-245`
// ---------------------------------------------------------------------------

/// `static void *loader_from_algorithm(int scheme_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)` — `store_meth.c:178-245`.
///
/// The dispatch scan. The ten `<OSSL_FUNC_STORE_*>` identities are read one per arm; each
/// is stored only if its slot is still empty, so a table that repeats an id keeps the first.
/// The four-clause sanity check refuses a loader without a constructor (`open` or `attach`),
/// a `load`, an `eof` or a `close`.
///
/// # Safety
/// `algodef` must be a live algorithm definition whose `implementation` is a terminated
/// dispatch table; `prov` must be live.
// The arms keep the authority's `case V: if (slot == NULL) slot = ...;` shape: a match arm
// whose body is a single `if`. Folding the `if` into a match guard would read as
// `case V && slot == NULL`, which is the same behaviour but not the same statement, and this
// unit's correctness argument is that the dispatch scan is transcribed arm for arm.
#[allow(clippy::collapsible_match)]
unsafe fn loader_from_algorithm(
    scheme_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut OsslStoreLoader {
    // SAFETY: `prov` is live per the contract.
    let loader = unsafe { new_loader(prov) };
    if loader.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `algodef` is live per the contract, and its `implementation` is the
    // terminated dispatch table `algodef`'s own algorithm definition names.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };
    // SAFETY: `loader` is a fresh, uniquely-owned object.
    unsafe {
        (*loader).scheme_id = scheme_id;
        (*loader).propdef = (*algodef).property_definition;
        (*loader).description = (*algodef).algorithm_description;

        let mut f = fns;
        while !f.is_null() && (*f).function_id != 0 {
            let function = (*f).function;
            if !function.is_null() {
                match (*f).function_id {
                    OSSL_FUNC_STORE_OPEN => {
                        if (*loader).p_open.is_none() {
                            (*loader).p_open =
                                Some(core::mem::transmute::<*mut c_void, StorePOpenFn>(function));
                        }
                    }
                    OSSL_FUNC_STORE_ATTACH => {
                        if (*loader).p_attach.is_none() {
                            (*loader).p_attach = Some(core::mem::transmute::<
                                *mut c_void,
                                StorePAttachFn,
                            >(function));
                        }
                    }
                    OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS => {
                        if (*loader).p_settable_ctx_params.is_none() {
                            (*loader).p_settable_ctx_params = Some(core::mem::transmute::<
                                *mut c_void,
                                StorePSettableCtxParamsFn,
                            >(
                                function
                            ));
                        }
                    }
                    OSSL_FUNC_STORE_SET_CTX_PARAMS => {
                        if (*loader).p_set_ctx_params.is_none() {
                            (*loader).p_set_ctx_params =
                                Some(core::mem::transmute::<*mut c_void, StorePSetCtxParamsFn>(
                                    function,
                                ));
                        }
                    }
                    OSSL_FUNC_STORE_LOAD => {
                        if (*loader).p_load.is_none() {
                            (*loader).p_load =
                                Some(core::mem::transmute::<*mut c_void, StorePLoadFn>(function));
                        }
                    }
                    OSSL_FUNC_STORE_EOF => {
                        if (*loader).p_eof.is_none() {
                            (*loader).p_eof =
                                Some(core::mem::transmute::<*mut c_void, StorePEofFn>(function));
                        }
                    }
                    OSSL_FUNC_STORE_CLOSE => {
                        if (*loader).p_close.is_none() {
                            (*loader).p_close =
                                Some(core::mem::transmute::<*mut c_void, StorePCloseFn>(function));
                        }
                    }
                    OSSL_FUNC_STORE_EXPORT_OBJECT => {
                        if (*loader).p_export_object.is_none() {
                            (*loader).p_export_object =
                                Some(core::mem::transmute::<*mut c_void, StorePExportObjectFn>(
                                    function,
                                ));
                        }
                    }
                    OSSL_FUNC_STORE_DELETE => {
                        if (*loader).p_delete.is_none() {
                            (*loader).p_delete = Some(core::mem::transmute::<
                                *mut c_void,
                                StorePDeleteFn,
                            >(function));
                        }
                    }
                    OSSL_FUNC_STORE_OPEN_EX => {
                        if (*loader).p_open_ex.is_none() {
                            (*loader).p_open_ex = Some(core::mem::transmute::<
                                *mut c_void,
                                StorePOpenExFn,
                            >(function));
                        }
                    }
                    _ => {}
                }
            }
            f = f.add(1);
        }

        // Only `set_ctx_params` is optional.
        if ((*loader).p_open.is_none() && (*loader).p_attach.is_none())
            || (*loader).p_load.is_none()
            || (*loader).p_eof.is_none()
            || (*loader).p_close.is_none()
        {
            OSSL_STORE_LOADER_free(loader);
            raise_site(&STORE_METH_241);
            return ptr::null_mut();
        }
    }
    loader
}

// ---------------------------------------------------------------------------
// Fetch support — `store_meth.c:74-385`
// ---------------------------------------------------------------------------

/// `struct loader_data_st` — `store_meth.c:75-84`.
#[repr(C)]
struct LoaderDataSt {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `int scheme_id` — for `get_loader_from_store`.
    scheme_id: c_int,
    /// `const char *scheme` — for `get_loader_from_store`.
    scheme: *const c_char,
    /// `const char *propquery` — for `get_loader_from_store`.
    propquery: *const c_char,
    /// `OSSL_METHOD_STORE *tmp_store` — for `get_tmp_loader_store`.
    tmp_store: *mut OsslMethodStore,
    /// `unsigned int flag_construct_error_occurred : 1`.
    flag_construct_error_occurred: c_int,
}

/// `static void *get_tmp_loader_store(void *data)` — `store_meth.c:92-99`.
///
/// # Safety
/// `data` must be a live [`LoaderDataSt`].
unsafe extern "C" fn get_tmp_loader_store(data: *mut c_void) -> *mut c_void {
    let methdata = data.cast::<LoaderDataSt>();
    // SAFETY: `methdata` is live per the contract.
    unsafe {
        if (*methdata).tmp_store.is_null() {
            (*methdata).tmp_store = ossl_method_store_new((*methdata).libctx);
        }
        (*methdata).tmp_store.cast::<c_void>()
    }
}

/// `static void dealloc_tmp_loader_store(void *store)` — `store_meth.c:101-105`.
///
/// # Safety
/// `store` must be NULL or a store this file created.
unsafe extern "C" fn dealloc_tmp_loader_store(store: *mut c_void) {
    if !store.is_null() {
        // SAFETY: `store` is a store `get_tmp_loader_store` created and nobody else released.
        unsafe { ossl_method_store_free(store.cast::<OsslMethodStore>()) };
    }
}

/// `static OSSL_METHOD_STORE *get_loader_store(OSSL_LIB_CTX *libctx)` —
/// `store_meth.c:108-111`.
fn get_loader_store(libctx: *mut c_void) -> *mut OsslMethodStore {
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the read is not guarded.
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX).cast::<OsslMethodStore>()
}

/// `static int reserve_loader_store(void *store, void *data)` — `store_meth.c:113-122`.
///
/// # Safety
/// `store` NULL or a live store; `data` a live [`LoaderDataSt`].
unsafe extern "C" fn reserve_loader_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<LoaderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live per the contract.
        store = get_loader_store(unsafe { (*methdata).libctx });
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live here.
    unsafe { ossl_method_lock_store(store) }
}

/// `static int unreserve_loader_store(void *store, void *data)` — `store_meth.c:124-133`.
///
/// # Safety
/// As [`reserve_loader_store`].
unsafe extern "C" fn unreserve_loader_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<LoaderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live per the contract.
        store = get_loader_store(unsafe { (*methdata).libctx });
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live here.
    unsafe { ossl_method_unlock_store(store) }
}

/// `static void *get_loader_from_store(void *store, const OSSL_PROVIDER **prov, void *data)` —
/// `store_meth.c:136-156`.
///
/// # Safety
/// `store` NULL or live; `prov` NULL or writable; `data` a live [`LoaderDataSt`].
unsafe extern "C" fn get_loader_from_store(
    store: *mut c_void,
    prov: *mut *const OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<LoaderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    let mut method: *mut c_void = ptr::null_mut();

    // SAFETY: `methdata` is live per the contract.
    unsafe {
        let mut id = (*methdata).scheme_id;
        if id == 0 && !(*methdata).scheme.is_null() {
            let namemap = ossl_namemap_stored((*methdata).libctx);
            if namemap.is_null() {
                return ptr::null_mut();
            }
            id = ossl_namemap_name2num(namemap, (*methdata).scheme);
        }

        if store.is_null() {
            store = get_loader_store((*methdata).libctx);
            if store.is_null() {
                return ptr::null_mut();
            }
        }

        if ossl_method_store_fetch(store, id, (*methdata).propquery, prov, &mut method) == 0 {
            return ptr::null_mut();
        }
    }
    method
}

/// `static int put_loader_in_store(void *store, void *method, const OSSL_PROVIDER *prov,
/// const char *scheme, const char *propdef, void *data)` — `store_meth.c:158-176`.
///
/// # Safety
/// `store` NULL or live; `method` live; `prov` live; `scheme` and `propdef` NULL or
/// NUL-terminated; `data` a live [`LoaderDataSt`].
unsafe extern "C" fn put_loader_in_store(
    store: *mut c_void,
    method: *mut c_void,
    prov: *const OsslProvider,
    scheme: *const c_char,
    propdef: *const c_char,
    data: *mut c_void,
) -> c_int {
    let methdata = data.cast::<LoaderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();

    // SAFETY: `methdata` is live per the contract.
    unsafe {
        let namemap = ossl_namemap_stored((*methdata).libctx);
        if namemap.is_null() {
            return 0;
        }
        let id = ossl_namemap_name2num(namemap, scheme);
        if id == 0 {
            return 0;
        }

        if store.is_null() {
            store = get_loader_store((*methdata).libctx);
            if store.is_null() {
                return 0;
            }
        }

        ossl_method_store_add(store, prov, id, propdef, method, up_ref_loader, free_loader)
    }
}

/// `static void *construct_loader(const OSSL_ALGORITHM *algodef, OSSL_PROVIDER *prov,
/// void *data)` — `store_meth.c:252-280`.
///
/// # Safety
/// `algodef` and `prov` must be live; `data` a live [`LoaderDataSt`].
unsafe extern "C" fn construct_loader(
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<LoaderDataSt>();
    // SAFETY: `prov` is live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let namemap = ossl_namemap_stored(libctx);
    // SAFETY: `algodef` is live per the contract.
    let scheme = unsafe { (*algodef).algorithm_names };
    // SAFETY: `namemap` is live or NULL, which `ossl_namemap_add_name` refuses.
    let id = unsafe { ossl_namemap_add_name(namemap, 0, scheme) };
    let method = if id != 0 {
        // SAFETY: `algodef` and `prov` are live, and `id` is the number the name map gave.
        unsafe { loader_from_algorithm(id, algodef, prov) }
    } else {
        ptr::null_mut()
    };

    if method.is_null() {
        // SAFETY: `methdata` is live per the contract.
        unsafe { (*methdata).flag_construct_error_occurred = 1 };
    }
    method.cast::<c_void>()
}

/// `static void destruct_loader(void *method, void *data)` — `store_meth.c:283-286`.
///
/// # Safety
/// `method` must be a live loader; `data` is unused.
unsafe extern "C" fn destruct_loader(method: *mut c_void, _data: *mut c_void) {
    // SAFETY: `method` is live per the contract.
    unsafe { OSSL_STORE_LOADER_free(method.cast::<OsslStoreLoader>()) };
}

/// `static OSSL_STORE_LOADER *inner_loader_fetch(struct loader_data_st *methdata,
/// const char *scheme, const char *properties)` — `store_meth.c:289-371`.
///
/// # Safety
/// `methdata` must point at a live, initialised [`LoaderDataSt`]; `scheme` and `properties`
/// NULL or NUL-terminated.
unsafe fn inner_loader_fetch(
    methdata: *mut LoaderDataSt,
    scheme: *const c_char,
    properties: *const c_char,
) -> *mut OsslStoreLoader {
    // SAFETY: `methdata` is live per the contract.
    let libctx = unsafe { (*methdata).libctx };
    let store = get_loader_store(libctx);
    let namemap = ossl_namemap_stored(libctx);
    let propq: *const c_char = if !properties.is_null() {
        properties
    } else {
        c"".as_ptr()
    };
    let mut method: *mut c_void = ptr::null_mut();

    if store.is_null() || namemap.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_METH_300) };
        return ptr::null_mut();
    }

    // SAFETY: `namemap` is live and `scheme` is NULL or NUL-terminated.
    let mut id = if !scheme.is_null() {
        // SAFETY: `namemap` is live and `scheme` is non-NULL and NUL-terminated here.
        unsafe { ossl_namemap_name2num(namemap, scheme) }
    } else {
        0
    };

    let mut unsupported = id == 0;

    // SAFETY: `store` and `namemap` are live; `methdata` is live.
    unsafe {
        if id == 0
            || ossl_method_store_cache_get(store, ptr::null_mut(), id, propq, &mut method) == 0
        {
            let mcm = OsslMethodConstructMethod {
                get_tmp_store: get_tmp_loader_store,
                lock_store: reserve_loader_store,
                unlock_store: unreserve_loader_store,
                get: get_loader_from_store,
                put: put_loader_in_store,
                construct: construct_loader,
                destruct: destruct_loader,
            };
            let mut prov: *mut OsslProvider = ptr::null_mut();

            (*methdata).scheme_id = id;
            (*methdata).scheme = scheme;
            (*methdata).propquery = propq;
            (*methdata).flag_construct_error_occurred = 0;
            method = ossl_method_construct(
                libctx,
                OSSL_OP_STORE,
                &mut prov,
                0, /* !force_cache */
                &mcm,
                methdata.cast::<c_void>(),
            );
            if !method.is_null() {
                if id == 0 {
                    id = ossl_namemap_name2num(namemap, scheme);
                }
                ossl_method_store_cache_set(
                    store,
                    prov,
                    id,
                    propq,
                    method,
                    up_ref_loader,
                    free_loader,
                );
            }

            /* If we never were in the constructor, the algorithm to be fetched is unsupported. */
            unsupported = (*methdata).flag_construct_error_occurred == 0;
        }

        if (id != 0 || !scheme.is_null()) && method.is_null() {
            let code = if unsupported {
                ERR_R_UNSUPPORTED
            } else {
                ERR_R_FETCH_FAILED
            };
            let helpful = if unsupported {
                c"No store loader found. For standard store loaders you need at least one of the \
                  default or base providers available. Did you forget to load them? Info: "
                    .as_ptr()
            } else {
                c"".as_ptr()
            };
            let reported = if scheme.is_null() {
                ossl_namemap_num2name(namemap, id, 0)
            } else {
                scheme
            };
            let mut msg = [0 as c_char; 1024];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s%s, Scheme (%s : %d), Properties (%s)".as_ptr(),
                helpful,
                lib_ctx_get_descriptor((*methdata).libctx),
                if reported.is_null() {
                    c"<null>".as_ptr()
                } else {
                    reported
                },
                id,
                if properties.is_null() {
                    c"<null>".as_ptr()
                } else {
                    properties
                },
            );
            raise_site_dynamic_data(&STORE_METH_362, code, msg.as_ptr());
        }
    }

    method.cast::<OsslStoreLoader>()
}

/// `OSSL_STORE_LOADER *OSSL_STORE_LOADER_fetch(OSSL_LIB_CTX *libctx, const char *scheme,
/// const char *properties)` — `store_meth.c:373-385`.
///
/// # Safety
/// `libctx` NULL or live; `scheme` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_fetch(
    libctx: *mut c_void,
    scheme: *const c_char,
    properties: *const c_char,
) -> *mut OsslStoreLoader {
    let mut methdata = LoaderDataSt {
        libctx,
        scheme_id: 0,
        scheme: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
    };
    // SAFETY: `methdata` is live and initialised per the contract.
    let method = unsafe { inner_loader_fetch(&mut methdata, scheme, properties) };
    // SAFETY: `methdata.tmp_store` is NULL or a store this call created.
    unsafe { dealloc_tmp_loader_store(methdata.tmp_store.cast::<c_void>()) };
    method
}

/// `int ossl_store_loader_store_cache_flush(OSSL_LIB_CTX *libctx)` — `store_meth.c:387-394`.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_store_loader_store_cache_flush(libctx: *mut c_void) -> c_int {
    let store = get_loader_store(libctx);
    if !store.is_null() {
        // SAFETY: `store` is the live slot-15 store.
        return unsafe { ossl_method_store_cache_flush_all(store) };
    }
    1
}

/// `int ossl_store_loader_store_remove_all_provided(const OSSL_PROVIDER *prov)` —
/// `store_meth.c:396-404`.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_store_loader_store_remove_all_provided(
    prov: *const OsslProvider,
) -> c_int {
    // SAFETY: `prov` is live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let store = get_loader_store(libctx);
    if !store.is_null() {
        // SAFETY: the slot-15 store is live and `prov` is live.
        return unsafe { ossl_method_store_remove_all_provided(store, prov) };
    }
    1
}

// ---------------------------------------------------------------------------
// The accessors — `store_meth.c:410-511`
// ---------------------------------------------------------------------------

/// `const OSSL_PROVIDER *OSSL_STORE_LOADER_get0_provider(const OSSL_STORE_LOADER *loader)` —
/// `store_meth.c:410-418`.
///
/// # Safety
/// `loader` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_provider(
    loader: *const OsslStoreLoader,
) -> *const OsslProvider {
    if loader.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_METH_413) };
        return ptr::null();
    }
    // SAFETY: `loader` is live per the guard above.
    unsafe { (*loader).prov }
}

/// `const char *OSSL_STORE_LOADER_get0_properties(const OSSL_STORE_LOADER *loader)` —
/// `store_meth.c:420-428`.
///
/// # Safety
/// `loader` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_properties(
    loader: *const OsslStoreLoader,
) -> *const c_char {
    if loader.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_METH_423) };
        return ptr::null();
    }
    // SAFETY: `loader` is live per the guard above.
    unsafe { (*loader).propdef }
}

/// `int ossl_store_loader_get_number(const OSSL_STORE_LOADER *loader)` —
/// `store_meth.c:430-438`.
///
/// # Safety
/// `loader` must be NULL or live.
#[allow(dead_code)] // read by store_lib.c's `OSSL_STORE_vctrl`, withheld (see the module root)
pub(crate) unsafe fn ossl_store_loader_get_number(loader: *const OsslStoreLoader) -> c_int {
    if loader.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_METH_433) };
        return 0;
    }
    // SAFETY: `loader` is live per the guard above.
    unsafe { (*loader).scheme_id }
}

/// `const char *OSSL_STORE_LOADER_get0_description(const OSSL_STORE_LOADER *loader)` —
/// `store_meth.c:440-443`.
///
/// The authority does **not** check `loader` here, and neither does this transcription: it
/// is called on a fetched loader by construction.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_description(
    loader: *const OsslStoreLoader,
) -> *const c_char {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).description }
}

/// `int OSSL_STORE_LOADER_is_a(const OSSL_STORE_LOADER *loader, const char *name)` —
/// `store_meth.c:445-454`.
///
/// # Safety
/// `loader` must be live; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_is_a(
    loader: *const OsslStoreLoader,
    name: *const c_char,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    let prov = unsafe { (*loader).prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live or NULL and `name` is NUL-terminated; the comparison is
        // against this loader's own scheme id.
        return c_int::from(
            unsafe { ossl_namemap_name2num(namemap, name) } == unsafe { (*loader).scheme_id },
        );
    }
    0
}

/// `struct do_one_data_st` — `store_meth.c:456-459`.
struct DoOneData {
    /// `void (*user_fn)(OSSL_STORE_LOADER *loader, void *arg)`.
    user_fn: unsafe extern "C" fn(*mut OsslStoreLoader, *mut c_void),
    /// `void *user_arg`.
    user_arg: *mut c_void,
}

/// `static void do_one(int id, void *method, void *arg)` — `store_meth.c:461-466`.
///
/// # Safety
/// `method` must be a live loader and `arg` a live [`DoOneData`].
unsafe extern "C" fn do_one(_id: c_int, method: *mut c_void, arg: *mut c_void) {
    // SAFETY: `arg` is a live `DoOneData` per the contract.
    let data = arg.cast::<DoOneData>();
    // SAFETY: `data` is live; `user_fn` is the caller's own callback.
    unsafe { ((*data).user_fn)(method.cast::<OsslStoreLoader>(), (*data).user_arg) };
}

/// `void OSSL_STORE_LOADER_do_all_provided(OSSL_LIB_CTX *libctx,
/// void (*user_fn)(OSSL_STORE_LOADER *loader, void *arg), void *user_arg)` —
/// `store_meth.c:468-486`.
///
/// The **fetch runs first**, filling the temporary store, and only then are both stores
/// walked; the temporary one is released last. Because no `OSSL_OP_STORE` row is published
/// in this pass (`file_store.c` is withheld -- see the module root), the walk finds nothing
/// and the observations `RT-STORE` makes are its refusal arms.
///
/// # Safety
/// `libctx` NULL or live; `user_fn` a valid callback; `user_arg` opaque to this file.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_do_all_provided(
    libctx: *mut c_void,
    user_fn: unsafe extern "C" fn(*mut OsslStoreLoader, *mut c_void),
    user_arg: *mut c_void,
) {
    let mut methdata = LoaderDataSt {
        libctx,
        scheme_id: 0,
        scheme: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
    };
    // SAFETY: `methdata` is live; `inner_loader_fetch`'s contract is met with NULLs.
    unsafe { inner_loader_fetch(&mut methdata, ptr::null(), ptr::null()) };

    let mut data = DoOneData { user_fn, user_arg };
    // SAFETY: each store is NULL or live and `data` is this frame's own.
    unsafe {
        if !methdata.tmp_store.is_null() {
            ossl_method_store_do_all(
                methdata.tmp_store,
                Some(do_one),
                ptr::addr_of_mut!(data).cast::<c_void>(),
            );
        }
        ossl_method_store_do_all(
            get_loader_store(libctx),
            Some(do_one),
            ptr::addr_of_mut!(data).cast::<c_void>(),
        );
    }
    // SAFETY: `methdata.tmp_store` is NULL or a store this call created.
    unsafe { dealloc_tmp_loader_store(methdata.tmp_store.cast::<c_void>()) };
}

/// `int OSSL_STORE_LOADER_names_do_all(const OSSL_STORE_LOADER *loader,
/// void (*fn)(const char *name, void *data), void *data)` — `store_meth.c:488-503`.
///
/// # Safety
/// `loader` must be NULL or live; `fn` NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_names_do_all(
    loader: *const OsslStoreLoader,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    if loader.is_null() {
        return 0;
    }
    // SAFETY: `loader` is live per the guard above.
    let prov = unsafe { (*loader).prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live or NULL; the callback is the caller's.
        return unsafe { ossl_namemap_doall_names(namemap, (*loader).scheme_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *OSSL_STORE_LOADER_settable_ctx_params(const OSSL_STORE_LOADER *loader)`
/// — `store_meth.c:505-511`.
///
/// Passes **NULL** to the provider callback, exactly as the authority does.
///
/// # Safety
/// `loader` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_settable_ctx_params(
    loader: *const OsslStoreLoader,
) -> *const crate::params::OsslParam {
    if !loader.is_null() {
        // SAFETY: `loader` is live per the guard above.
        if let Some(settable) = unsafe { (*loader).p_settable_ctx_params } {
            // SAFETY: `settable` is a live provider callback; the authority passes NULL.
            return unsafe { settable(ptr::null_mut()) };
        }
    }
    ptr::null()
}
