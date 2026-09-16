//! Phase 7.2 — `crypto/evp/evp_fetch.c`'s **default-property** half.
//!
//! `evp_fetch.c` is two stories in one file, and the boundary between them is a lock. The
//! *fetch* story — `inner_evp_generic_fetch` down through `evp_generic_fetch`, with the six
//! `mcm` callbacks that `crypto/core_fetch.c` walks — needs `EVP_MD_fetch`'s and
//! `EVP_CIPHER_fetch`'s method objects, which are 7.3's and 7.4's. The *default properties*
//! story needs none of it: it reads and writes the per-context global-property list 6.7a
//! already holds, parses a query with 6.7b's grammar, and flushes the store's cache — which
//! D142/D143 landed. So this file is the second story, and it is what makes Phase 7 have
//! **exported** symbols at all.
//!
//! ## What a default property is, and why it is stored as text before it is stored as a list
//!
//! `EVP_set_default_properties(libctx, "fips=yes")` is a *context-wide* preference: every fetch
//! against that context merges its own query with this one before matching, so a caller that
//! has not asked for anything in particular still gets FIPS-approved algorithms from a context
//! that was configured for them. Three things follow from that and are easy to get backwards:
//!
//!   * the properties are stored as an `OSSL_PROPERTY_LIST`, but they are **also rendered back
//!     to a string** and handed to every activated provider (`ossl_provider_default_props_update`)
//!     before the list replaces the old one — because a provider may be reached through
//!     `OSSL_PROVIDER_do_all` and asked to rebuild its own tables against the new query, and a
//!     list is not a string;
//!   * the old list is **freed and the new one adopted**, not merged in: merging happens one
//!     level up, in `evp_default_properties_merge`, and only when the context already has
//!     something;
//!   * after the swap the **store's query cache is flushed**, because every cached answer was
//!     computed under the old query and is now not only stale but wrong.
//!
//! ## `mirrored`, and the one-way flag
//!
//! A child context starts with its parent's global properties *mirrored* into it. Setting
//! properties *explicitly* on a context therefore stops mirroring
//! (`ossl_global_properties_stop_mirroring`), and a *mirroring* update — the `mirrored` argument —
//! is refused outright once that has happened. The flag is one-way: there is no call that turns
//! mirroring back on, which is why the refusal is not a bug to be fixed but the whole of the
//! feature.
//!
//! ## The two functions that render the list back
//!
//! `ossl_property_list_to_string` is called **twice** in each of them, and the first call is a
//! size query with a NULL buffer that answers the bytes needed including the terminator. So a
//! first answer of 0 means the list is not renderable rather than that it is empty, and the
//! authority treats it as an internal error — which is why `propstr` is tested for NULL *after*
//! the allocation rather than testing `strsz` first: a zero length leaves `propstr` NULL and
//! takes the same branch.
//!
//! SPDX-License-Identifier: Apache-2.0

// The fetch half of this file has no caller in this crate yet: `evp_generic_fetch` and
// `evp_generic_fetch_from_prov` are the two functions every `EVP_<class>_fetch` is a macro
// around, and the classes are 7.3's and 7.4's. The default-property half above is reached
// through its four exports. One allowance rather than twenty per-item ones whose comments would
// each restate this paragraph, and what retires it is 7.3.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_void};

use crate::context::namemap::{
    ossl_namemap_add_names, ossl_namemap_doall_names, ossl_namemap_name2num,
    ossl_namemap_name2num_n, ossl_namemap_num2name, ossl_namemap_stored,
};
use crate::context::{
    lib_ctx_get_data, lib_ctx_is_global_default, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX,
};
use crate::evp::method_store::{
    ossl_method_construct, McmConstructFn, McmDestructFn, McmGetFn, McmGetTmpStoreFn,
    McmLockStoreFn, McmPutFn, McmUnlockStoreFn, OsslMethodConstructMethod,
};
use crate::property::globals::{
    ossl_ctx_global_properties, ossl_global_properties_no_mirrored,
    ossl_global_properties_stop_mirroring,
};
use crate::property::list::OsslPropertyList;
use crate::property::parse::{
    ossl_parse_query, ossl_property_free, ossl_property_list_to_string, ossl_property_merge,
};
use crate::property::query::ossl_property_is_enabled;
use crate::property::store::{MethodFreeFn, MethodUpRefFn, OsslMethodStore};
use crate::provider::activate::ossl_provider_default_props_update;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::stores::ossl_decoder_cache_flush;
use crate::provider::{ossl_provider_libctx, OsslProvider};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::err::{raise_site_data, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use core::ptr;

/// The authority's translation unit, so a failing allocation records its coordinates.
pub(crate) const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c".as_ptr();

/// `evp_set_parsed_default_properties`'s `OPENSSL_malloc(strsz)` (line 483).
const LINE_MALLOC_PROPSTR: c_int = 483;

/// `ERR_MAX_DATA_SIZE` — `include/openssl/err.h`.
///
/// The size `ERR_vset_error` grows its buffer to before formatting, and therefore the size the
/// formatted message is truncated at. The fetch path's two messages carry a name, a property
/// query and a context descriptor, so they can exceed this and are truncated **exactly here**;
/// the constant is the authority's number rather than a comfortable one for that reason.
const ERR_DATA_BUFFER: usize = 1024;
/// `evp_get_global_properties_str`'s `OPENSSL_strdup("")` (line 592).
///
/// The line is the *call's*, not the macro's, because `OPENSSL_strdup` expands to
/// `CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)` and those two expand at the call site.
const LINE_STRDUP_EMPTY: c_int = 592;

/// `static OSSL_METHOD_STORE *get_evp_method_store(OSSL_LIB_CTX *libctx)`.
///
/// One slot read, and the reason it is a function rather than open-coded at its four call sites
/// is the reason it is one here: the index number appears **once** in this file, so the four
/// store-touching functions cannot disagree about which slot the EVP fetch path uses.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn get_evp_method_store(libctx: *mut c_void) -> *mut OsslMethodStore {
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the slot read needs no
    // block even though this function is `unsafe`.
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX).cast::<OsslMethodStore>()
}

/// `static int evp_set_parsed_default_properties(OSSL_LIB_CTX *libctx,
/// OSSL_PROPERTY_LIST *def_prop, int loadconfig, int mirrored)`.
///
/// Takes **ownership** of `def_prop` on the success path and of it again on the failure path,
/// because its callers free it there (`evp_set_default_properties_int` and
/// `evp_default_properties_merge` both call `ossl_property_free` when this answers 0). What it
/// does *not* own is the old list, which it releases itself.
///
/// # Safety
/// `libctx` NULL or live; `def_prop` NULL or a live list this call may adopt.
unsafe fn evp_set_parsed_default_properties(
    libctx: *mut c_void,
    def_prop: *mut OsslPropertyList,
    loadconfig: c_int,
    mirrored: c_int,
) -> c_int {
    // SAFETY: `libctx` is NULL or live per the contract.
    let store = unsafe { get_evp_method_store(libctx) };
    // SAFETY: as above.
    let plp = unsafe { ossl_ctx_global_properties(libctx, loadconfig) };

    if !plp.is_null() && !store.is_null() {
        // SAFETY: `libctx` is live and `plp` is the slot's own field.
        unsafe {
            if mirrored != 0 {
                // A mirroring update is refused once this context has properties of its own.
                if ossl_global_properties_no_mirrored(libctx) != 0 {
                    return 0;
                }
            } else {
                // An explicit update stops mirroring, permanently.
                ossl_global_properties_stop_mirroring(libctx);
            }

            // The size query, then the render. A zero from the size query leaves `propstr` NULL
            // and takes the allocation's failure branch, which is the authority's own shape.
            let strsz = ossl_property_list_to_string(libctx, def_prop, core::ptr::null_mut(), 0);
            let propstr = if strsz > 0 {
                CRYPTO_malloc(strsz, FILE, LINE_MALLOC_PROPSTR).cast::<c_char>()
            } else {
                core::ptr::null_mut()
            };
            if propstr.is_null() {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::EVP_FETCH_485);
                return 0;
            }
            if ossl_property_list_to_string(libctx, def_prop, propstr, strsz) == 0 {
                CRYPTO_free(propstr.cast::<c_void>(), FILE, LINE_MALLOC_PROPSTR);
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::EVP_FETCH_492);
                return 0;
            }
            // Every activated provider is told, because a provider that rebuilds its own tables
            // needs the query as text.
            ossl_provider_default_props_update(libctx, propstr);
            CRYPTO_free(propstr.cast::<c_void>(), FILE, LINE_MALLOC_PROPSTR);

            // The old list goes, the new one is adopted, and the cache is invalidated.
            ossl_property_free(*plp);
            *plp = def_prop;

            let ret = crate::property::store::ossl_method_store_cache_flush_all(store);
            // The decoder cache is not a method store and its flush is its own stratum's; the
            // absent-slot answer is discarded here exactly as the authority discards it.
            let _ = ossl_decoder_cache_flush(libctx);
            return ret;
        }
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::EVP_FETCH_507) };
    0
}

/// `int evp_set_default_properties_int(OSSL_LIB_CTX *libctx, const char *propq, int loadconfig,
/// int mirrored)`.
///
/// The parse, and the free that only happens on failure: a successful call hands the list to
/// `evp_set_parsed_default_properties`, which adopts it.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
pub(crate) unsafe fn evp_set_default_properties_int(
    libctx: *mut c_void,
    propq: *const c_char,
    loadconfig: c_int,
    mirrored: c_int,
) -> c_int {
    let mut pl: *mut OsslPropertyList = core::ptr::null_mut();
    if !propq.is_null() {
        // SAFETY: `libctx` is NULL or live and `propq` is NUL-terminated per the contract.
        pl = unsafe { ossl_parse_query(libctx, propq, 1) };
        if pl.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_FETCH_517) };
            return 0;
        }
    }
    // SAFETY: `pl` is NULL or this call's own list.
    if unsafe { evp_set_parsed_default_properties(libctx, pl, loadconfig, mirrored) } == 0 {
        // SAFETY: the callee did not adopt it.
        unsafe { ossl_property_free(pl) };
        return 0;
    }
    1
}

/// `int EVP_set_default_properties(OSSL_LIB_CTX *libctx, const char *propq)`.
///
/// `loadconfig = 1`, `mirrored = 0` — the public call may load the configuration file, and it
/// always counts as explicit.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_set_default_properties(
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_set_default_properties_int(libctx, propq, 1, 0) }
}

/// `static int evp_default_properties_merge(OSSL_LIB_CTX *libctx, const char *propq,
/// int loadconfig)`.
///
/// **Merging only happens when the context already has properties.** With none, the query is
/// simply *set* — and note the `loadconfig` handed to that call is **0**, not the caller's: the
/// configuration file has already been loaded by the accessor just above, and loading it twice
/// would be work for nothing.
///
/// The temporary list `pl1` is this function's own: it is parsed and released here, and what
/// survives is the merged list, which `evp_set_parsed_default_properties` adopts.
///
/// # Safety
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
unsafe fn evp_default_properties_merge(
    libctx: *mut c_void,
    propq: *const c_char,
    loadconfig: c_int,
) -> c_int {
    // SAFETY: `libctx` is NULL or live per the contract.
    let plp = unsafe { ossl_ctx_global_properties(libctx, loadconfig) };

    if propq.is_null() {
        return 1;
    }
    // SAFETY: `plp` is NULL or the slot's own field.
    if plp.is_null() || unsafe { *plp }.is_null() {
        // SAFETY: `loadconfig` is 0 for the reason above, and the arguments are otherwise
        // forwarded.
        return unsafe { evp_set_default_properties_int(libctx, propq, 0, 0) };
    }
    // SAFETY: `libctx` is NULL or live and `propq` is NUL-terminated.
    let pl1 = unsafe { ossl_parse_query(libctx, propq, 1) };
    if pl1.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_543) };
        return 0;
    }
    // SAFETY: `pl1` is this call's own list and `*plp` is the context's live one.
    let pl2 = unsafe { ossl_property_merge(pl1, *plp) };
    // SAFETY: `pl1` is this call's own and the merge does not adopt it.
    unsafe { ossl_property_free(pl1) };
    if pl2.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_549) };
        return 0;
    }
    // SAFETY: `pl2` is a live merged list this call owns.
    if unsafe { evp_set_parsed_default_properties(libctx, pl2, 0, 0) } == 0 {
        // SAFETY: the callee did not adopt it.
        unsafe { ossl_property_free(pl2) };
        return 0;
    }
    1
}

/// `static int evp_default_property_is_enabled(OSSL_LIB_CTX *libctx, const char *prop_name)`.
///
/// `loadconfig = 1` here, unlike the merge's inner call: this is a *read* of a property, and a
/// read that has not loaded the configuration file could answer "not enabled" for a property the
/// configuration file itself set.
///
/// # Safety
/// `libctx` NULL or live; `prop_name` NUL-terminated.
unsafe fn evp_default_property_is_enabled(libctx: *mut c_void, prop_name: *const c_char) -> c_int {
    // SAFETY: `libctx` is NULL or live per the contract.
    let plp = unsafe { ossl_ctx_global_properties(libctx, 1) };
    if plp.is_null() {
        return 0;
    }
    // SAFETY: `plp` is the slot's own field, so `*plp` is NULL or the context's live list, and
    // `prop_name` is NUL-terminated.
    unsafe { ossl_property_is_enabled(libctx, prop_name, *plp) }
}

/// `int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx)`.
///
/// # Safety
/// `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_default_properties_is_fips_enabled(libctx: *mut c_void) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_default_property_is_enabled(libctx, c"fips".as_ptr()) }
}

/// `int evp_default_properties_enable_fips_int(OSSL_LIB_CTX *libctx, int enable,
/// int loadconfig)`.
///
/// Two queries and no third: enabling *merges* `fips=yes` into the context's properties, and
/// disabling merges the **negative** form `-fips`, because a property that is simply absent is
/// not the same as one that is forbidden — a provider may declare `fips=yes` and a caller that
/// only omitted the property would still be offered it.
///
/// # Safety
/// `libctx` NULL or live.
pub(crate) unsafe fn evp_default_properties_enable_fips_int(
    libctx: *mut c_void,
    enable: c_int,
    loadconfig: c_int,
) -> c_int {
    let query: *const c_char = if enable != 0 {
        c"fips=yes".as_ptr()
    } else {
        c"-fips".as_ptr()
    };
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_default_properties_merge(libctx, query, loadconfig) }
}

/// `int EVP_default_properties_enable_fips(OSSL_LIB_CTX *libctx, int enable)`.
///
/// # Safety
/// `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_default_properties_enable_fips(
    libctx: *mut c_void,
    enable: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_default_properties_enable_fips_int(libctx, enable, 1) }
}

/// `char *evp_get_global_properties_str(OSSL_LIB_CTX *libctx, int loadconfig)`.
///
/// An **empty string**, not NULL, when the context has no properties slot at all — which is a
/// distinction a caller can see, because it is a valid `char *` to free and to print. A list
/// that cannot be rendered *is* NULL, with an error raised, which is the other end of the same
/// distinction.
///
/// # Safety
/// `libctx` NULL or live.
pub(crate) unsafe fn evp_get_global_properties_str(
    libctx: *mut c_void,
    loadconfig: c_int,
) -> *mut c_char {
    // SAFETY: `libctx` is NULL or live per the contract.
    let plp = unsafe { ossl_ctx_global_properties(libctx, loadconfig) };
    if plp.is_null() {
        // `OPENSSL_strdup` is a macro for `CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)`, so
        // the coordinates are this call site's even though the string is the empty literal.
        // SAFETY: a NUL-terminated literal and a compile-time-constant site.
        return unsafe { CRYPTO_strdup(c"".as_ptr(), FILE, LINE_STRDUP_EMPTY) };
    }

    // SAFETY: `plp` is the slot's own field, so `*plp` is the context's live list.
    let sz = unsafe { ossl_property_list_to_string(libctx, *plp, core::ptr::null_mut(), 0) };
    if sz == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_596) };
        return core::ptr::null_mut();
    }
    // `CRYPTO_malloc` is a SAFE function in this crate (D113), so the allocation needs no block.
    let propstr = CRYPTO_malloc(sz, FILE, LINE_MALLOC_PROPSTR).cast::<c_char>();
    if propstr.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `propstr` is `sz` bytes and the list is live.
    if unsafe { ossl_property_list_to_string(libctx, *plp, propstr, sz) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_604) };
        // SAFETY: `propstr` is this call's own allocation.
        unsafe { CRYPTO_free(propstr.cast::<c_void>(), FILE, LINE_MALLOC_PROPSTR) };
        return core::ptr::null_mut();
    }
    propstr
}

/// `char *EVP_get1_default_properties(OSSL_LIB_CTX *libctx)`.
///
/// The `loadconfig` argument is the interesting part: it is
/// `ossl_lib_ctx_is_global_default(libctx)`, so reading the default properties *of the default
/// context* loads the configuration file first and reading them from any other context does not.
/// A caller who made a context of their own is not asking for the file's properties, and one who
/// asked for the default context's is.
///
/// # Safety
/// `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_get1_default_properties(libctx: *mut c_void) -> *mut c_char {
    // `lib_ctx_is_global_default` is a SAFE function in this crate.
    let loadconfig = lib_ctx_is_global_default(libctx);
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_get_global_properties_str(libctx, loadconfig) }
}

/* ---------------------------------------------------------------------------------------------
 * The fetch itself: `crypto/evp/evp_fetch.c`'s other half.
 * -------------------------------------------------------------------------------------------*/

/// `ERR_RFLAG_COMMON` (`include/openssl/err.h`) — the bit every `ERR_R_*` common reason carries.
///
/// `#define ERR_RFLAG_COMMON (0x2 << ERR_RFLAGS_OFFSET)` with `ERR_RFLAGS_OFFSET` 18.
const ERR_RFLAG_COMMON: c_int = 0x2 << 18;

/// `ERR_R_FETCH_FAILED`, as the reason site `EVP_FETCH_352` records it.
///
/// Taken from the generated site rather than typed: the value is the authority's own, resolved
/// through its headers by `gen_err_raise_sites.py`, and this constant is the second place in the
/// file that needs it.
const ERR_R_FETCH_FAILED: c_int = err_sites::EVP_FETCH_352.reason;

/// `ERR_R_UNSUPPORTED` (`err.h`): `(268 | ERR_RFLAG_COMMON)`.
///
/// The *other* arm of the authority's `int code = unsupported ? ERR_R_UNSUPPORTED :
/// ERR_R_FETCH_FAILED;` at `crypto/evp/evp_fetch.c:372`, whose raise site `EVP_FETCH_376` is
/// recorded with `dynamic_reason` precisely because the generator refuses to guess which arm a
/// site takes. Composed from the header's own flag rather than written as a literal, the same way
/// `src/runtime/init.rs` spells `ERR_R_INIT_FAIL`.
///
/// This constant was **missing** until `RT-FETCH`'s unloaded-provider observation printed the
/// error queue: the first revision used `err_sites::EVP_FETCH_352.reason` for *both* arms, so a
/// fetch that found nothing raised `ERR_R_FETCH_FAILED` where the authority raises
/// `ERR_R_UNSUPPORTED`. Nothing else could have shown it — the two arms build the same message,
/// so the code is the entire difference, and no transcript line contradicted it. The unit test
/// below pins the typed value against the generated site `PARAM_BUILD_265`, which raises this
/// constant literally.
const ERR_R_UNSUPPORTED: c_int = 268 | ERR_RFLAG_COMMON;

/// `#define NAME_SEPARATOR ':'` — `crypto/evp/evp_local.h`.
///
/// The separator an algorithm's alias list uses, and the reason a fetch of `"SHA2-256"` finds a
/// method whose `algorithm_names` is `"SHA256:SHA2-256:sha256"`: the *first* name before the
/// separator is the identity, and the namemap is told about all of them at once.
const NAME_SEPARATOR: c_char = b':' as c_char;

/// `#define METHOD_ID_OPERATION_MASK 0x000000FF`.
const METHOD_ID_OPERATION_MASK: u32 = 0x0000_00FF;
/// `#define METHOD_ID_OPERATION_MAX ((1 << 8) - 1)`.
const METHOD_ID_OPERATION_MAX: u32 = (1 << 8) - 1;
/// `#define METHOD_ID_NAME_MASK 0x7FFFFF00`.
const METHOD_ID_NAME_MASK: u32 = 0x7FFF_FF00;
/// `#define METHOD_ID_NAME_OFFSET 8`.
const METHOD_ID_NAME_OFFSET: u32 = 8;
/// `#define METHOD_ID_NAME_MAX ((1 << 23) - 1)`.
const METHOD_ID_NAME_MAX: u32 = (1 << 23) - 1;

/// `static uint32_t evp_method_id(int name_id, unsigned int operation_id)`.
///
/// The composite identity the whole EVP store is keyed by:
///
/// ```text
/// +---------23 bits--------+-8 bits-+
/// |      name identity     | op id  |
/// +------------------------+--------+
/// ```
///
/// and the width is not decoration. The composite is limited to **31** bits so the top bit of the
/// `u32` is always zero — the authority's own comment says why: the value is passed as an `int` on
/// its way to `ossl_method_store_cache_set` and from there into `filter_on_operation_id`, and a
/// value with bit 31 set would sign-extend when shifted back down, so the operation id a `do_all`
/// filters on would be wrong for exactly the names with the most aliases.
///
/// Both `ossl_assert`s are `(x) != 0` under `NDEBUG`, so an out-of-range id is a **refusal that
/// answers 0** rather than an abort — and 0 is the value the callers test for, which is why
/// "could not build an id" and "id is 0" are the same thing throughout this file.
fn evp_method_id(name_id: c_int, operation_id: u32) -> u32 {
    if name_id <= 0 || name_id as u32 > METHOD_ID_NAME_MAX {
        return 0;
    }
    if operation_id == 0 || operation_id > METHOD_ID_OPERATION_MAX {
        return 0;
    }
    (((name_id as u32) << METHOD_ID_NAME_OFFSET) & METHOD_ID_NAME_MASK)
        | (operation_id & METHOD_ID_OPERATION_MASK)
}

/// `void *(*method_from_algorithm)(int name_id, const OSSL_ALGORITHM *, OSSL_PROVIDER *)`.
pub(crate) type MethodFromAlgorithmFn =
    unsafe extern "C" fn(c_int, *const OsslAlgorithm, *mut OsslProvider) -> *mut c_void;

/// `void (*user_fn)(void *method, void *arg)` — the visitor `evp_generic_do_all` takes.
pub(crate) type GenericDoAllFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

/// `struct evp_method_data_st` — the walk's state, and the only thing this half of the file
/// passes to `ossl_method_construct` as its opaque `mcm_data`.
///
/// Three of its fields are **for one reader each**, which the authority's own comments say and
/// which is why the names are kept: `operation_id`, `name_id` and `names` are read by
/// `get_evp_method_from_store`, and `propquery` by the same function, while `tmp_store` is read
/// and written by `get_tmp_evp_method_store`. The three function pointers are the *class's*
/// constructors, handed in by whoever called `evp_generic_fetch` — which is what makes this file
/// generic over MD, CIPHER, MAC, KDF and the rest without naming one of them.
///
/// `flag_construct_error_occurred` is a one-bit field in the authority, and it is the difference
/// between two error reasons a caller reads back: a name that resolved but whose construction
/// failed answers `ERR_R_FETCH_FAILED`, and a name that resolved to nothing answers
/// `ERR_R_UNSUPPORTED`. It is a `u32` here with only 0 and 1 written, for the same reason
/// `OsslProvider`'s flags are.
#[repr(C)]
pub(crate) struct EvpMethodData {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `int operation_id` — for `get_evp_method_from_store`.
    pub(crate) operation_id: c_int,
    /// `int name_id` — for `get_evp_method_from_store`.
    pub(crate) name_id: c_int,
    /// `const char *names` — for `get_evp_method_from_store`.
    pub(crate) names: *const c_char,
    /// `const char *propquery` — for `get_evp_method_from_store`.
    pub(crate) propquery: *const c_char,
    /// `OSSL_METHOD_STORE *tmp_store` — for `get_tmp_evp_method_store`.
    pub(crate) tmp_store: *mut OsslMethodStore,
    /// `unsigned int flag_construct_error_occurred : 1`.
    pub(crate) flag_construct_error_occurred: u32,
    /// `void *(*method_from_algorithm)(int, const OSSL_ALGORITHM *, OSSL_PROVIDER *)`.
    pub(crate) method_from_algorithm: MethodFromAlgorithmFn,
    /// `int (*refcnt_up_method)(void *)`.
    pub(crate) refcnt_up_method: MethodUpRefFn,
    /// `void (*destruct_method)(void *)`.
    pub(crate) destruct_method: MethodFreeFn,
}

/// `static void *get_tmp_evp_method_store(void *data)`.
///
/// The temporary store, **created once per fetch** and returned again on every later call — which
/// is what `ossl_method_construct`'s `reserve_store` relies on: it calls this once per map, and
/// without the `tmp_store == NULL` test every operation the walk visits would get its own store
/// and the methods constructed for the first would be invisible to the second.
///
/// # Safety
/// `data` must be a live `EvpMethodData`.
unsafe extern "C" fn get_tmp_evp_method_store(data: *mut c_void) -> *mut c_void {
    let methdata = data.cast::<EvpMethodData>();
    // SAFETY: `methdata` is live per the contract.
    unsafe {
        if (*methdata).tmp_store.is_null() {
            (*methdata).tmp_store =
                crate::property::store::ossl_method_store_new((*methdata).libctx);
        }
        (*methdata).tmp_store.cast::<c_void>()
    }
}

/// `static void dealloc_tmp_evp_method_store(void *store)`.
///
/// Both callers run it **after** the walk and after the final lookup, so the temporary store's
/// `mcm->get` has already answered from it. It is also what makes the temporary store's lifetime
/// the caller's rather than the store's: a method that was put there and never taken keeps its
/// reference, and this is where it is dropped.
///
/// A NULL store is a no-op, which is the common case — a fetch that found the method in the
/// global store never makes one.
///
/// # Safety
/// `store` must be NULL or a store this module's `get_tmp_evp_method_store` built.
unsafe fn dealloc_tmp_evp_method_store(store: *mut OsslMethodStore) {
    if !store.is_null() {
        // SAFETY: `store` came from `ossl_method_store_new` and is released once, here.
        unsafe { crate::property::store::ossl_method_store_free(store) };
    }
}

/// `static int reserve_evp_method_store(void *store, void *data)`.
///
/// The `mcm->lock_store`, and the **reservation** lock: `ossl_method_lock_store` is `biglock`,
/// not the store's array lock, because the walk is taking the whole store for the duration of a
/// fetch of a set of algorithms.
///
/// The NULL-store branch is the interface's own spelling of "the global store, please": the store
/// the walk hands in is the *temporary* one, and if there is none this resolves the context's.
///
/// # Safety
/// `data` must be a live `EvpMethodData`; `store` NULL or live.
unsafe extern "C" fn reserve_evp_method_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<EvpMethodData>();
    // SAFETY: `methdata` is live per the contract.
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: as above, and `get_evp_method_store` only reads the slot.
        store = unsafe { get_evp_method_store((*methdata).libctx) };
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live.
    unsafe { crate::property::store::ossl_method_lock_store(store) }
}

/// `static int unreserve_evp_method_store(void *store, void *data)`.
///
/// `ossl_method_unlock_store`, with the same NULL-store resolution — and the same store must come
/// back out, which it does because the walk passes back the value `reserve` left in
/// `ConstructData`.
///
/// # Safety
/// `data` must be a live `EvpMethodData`; `store` NULL or live and, if non-NULL, locked by this
/// thread.
unsafe extern "C" fn unreserve_evp_method_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<EvpMethodData>();
    // SAFETY: `methdata` is live per the contract.
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: as above, and `get_evp_method_store` only reads the slot.
        store = unsafe { get_evp_method_store((*methdata).libctx) };
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live and this thread holds its reservation.
    unsafe { crate::property::store::ossl_method_unlock_store(store) }
}

/// `static void *get_evp_method_from_store(void *store, const OSSL_PROVIDER **prov, void *data)`.
///
/// The lookup, and the three ways it can fail are three different answers to the walk:
///
///   * no name id and no name to look up — NULL, and the walk goes on to construct;
///   * an id that `evp_method_id` refuses — NULL for the same reason;
///   * a store that is not there — NULL, because there is nowhere to look.
///
/// Two details the authority's comments make explicit and that a transcription could lose:
/// **the name is truncated at the first separator before it is looked up**, because a name list
/// is only a *list* for construction — a lookup treats the whole string as one name, which is the
/// corner case `inner_evp_generic_fetch` names when it re-resolves the id after construction; and
/// `prov` is an **out-parameter**, because the method that answers also names which provider it
/// came from.
///
/// # Safety
/// `data` must be a live `EvpMethodData` with `libctx` live; `store` NULL or live; `prov` NULL or
/// writable for a provider pointer.
unsafe extern "C" fn get_evp_method_from_store(
    store: *mut c_void,
    prov: *mut *const OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<EvpMethodData>();
    let mut method: *mut c_void = ptr::null_mut();

    // SAFETY: `methdata` is live per the contract.
    let mut name_id = unsafe { (*methdata).name_id };
    // SAFETY: as above.
    let names = unsafe { (*methdata).names };
    if name_id == 0 && !names.is_null() {
        // SAFETY: as above, so `libctx` is live.
        let namemap = ossl_namemap_stored(unsafe { (*methdata).libctx });
        if namemap.is_null() {
            return ptr::null_mut();
        }
        // The truncation at the first separator.
        // SAFETY: `names` is NUL-terminated per the struct's contract.
        let q = unsafe { c_strchr(names, NAME_SEPARATOR) };
        let l = if q.is_null() {
            // SAFETY: as above.
            unsafe { c_strlen(names) }
        } else {
            (q as usize) - (names as usize)
        };
        // SAFETY: `namemap` is live, `names` is readable for `l` bytes.
        name_id = unsafe { ossl_namemap_name2num_n(namemap, names, l) };
    }

    if name_id == 0 {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let operation_id = unsafe { (*methdata).operation_id };
    let meth_id = evp_method_id(name_id, operation_id as u32);
    if meth_id == 0 {
        return ptr::null_mut();
    }

    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live, so `libctx` is.
        store = unsafe { get_evp_method_store((*methdata).libctx) };
        if store.is_null() {
            return ptr::null_mut();
        }
    }

    // SAFETY: `store` is live; the query is the struct's own borrowed string; `prov` is the
    // caller's out-parameter and `method` is this frame's writable slot.
    let propquery = unsafe { (*methdata).propquery };
    // SAFETY: as above.
    if unsafe {
        crate::property::store::ossl_method_store_fetch(
            store,
            meth_id as c_int,
            propquery,
            prov,
            &mut method,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    method
}

/// `static int put_evp_method_in_store(void *store, void *method, const OSSL_PROVIDER *prov,
/// const char *names, const char *propdef, void *data)`.
///
/// The insert, and the reason it re-derives the name id rather than taking the one
/// `construct_evp_method` already had: **the walk calls this with the names the *provider*
/// published**, and the identity is defined by the namemap, so deriving it here is what makes
/// "the method I constructed" and "the method I can look up" the same entry. The authority's own
/// comment says the names are already in the namemap by this point, so the derivation cannot
/// create a new one.
///
/// A NULL `names` is allowed and truncates to zero, which makes `name2num_n` answer 0 and the
/// whole call a refusal — so an algorithm with no name is not stored rather than stored under an
/// empty one.
///
/// # Safety
/// `data` must be a live `EvpMethodData` with `libctx` live; `store` NULL or live; `prov` live;
/// `names` and `propdef` NULL or NUL-terminated.
unsafe extern "C" fn put_evp_method_in_store(
    store: *mut c_void,
    method: *mut c_void,
    prov: *const OsslProvider,
    names: *const c_char,
    propdef: *const c_char,
    data: *mut c_void,
) -> c_int {
    let methdata = data.cast::<EvpMethodData>();

    let mut l: usize = 0;
    if !names.is_null() {
        // SAFETY: `names` is NUL-terminated per the contract.
        let q = unsafe { c_strchr(names, NAME_SEPARATOR) };
        l = if q.is_null() {
            // SAFETY: as above.
            unsafe { c_strlen(names) }
        } else {
            (q as usize) - (names as usize)
        };
    }

    // SAFETY: `methdata` is live per the contract, so `libctx` is live.
    let namemap = unsafe { ossl_namemap_stored((*methdata).libctx) };
    if namemap.is_null() {
        return 0;
    }
    // SAFETY: `namemap` is live and `names` is readable for `l` bytes.
    let name_id = unsafe { ossl_namemap_name2num_n(namemap, names, l) };
    // SAFETY: `methdata` is live.
    let operation_id = unsafe { (*methdata).operation_id };
    let meth_id = evp_method_id(name_id, operation_id as u32);
    if name_id == 0 || meth_id == 0 {
        return 0;
    }

    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live, so `libctx` is.
        store = unsafe { get_evp_method_store((*methdata).libctx) };
        if store.is_null() {
            return 0;
        }
    }

    // SAFETY: `store` is live, `method` is the object just constructed, `prov` is live, `names`
    // and `propdef` are the provider's own strings, and the two callbacks are the class's own.
    unsafe {
        crate::property::store::ossl_method_store_add(
            store,
            prov,
            meth_id as c_int,
            propdef,
            method,
            (*methdata).refcnt_up_method,
            (*methdata).destruct_method,
        )
    }
}

/// `static void *construct_evp_method(const OSSL_ALGORITHM *algodef, OSSL_PROVIDER *prov,
/// void *data)`.
///
/// The one place a new namemap entry can come from, as the authority's comment says — which is
/// why `add_names` is called with the **whole** alias list and the separator, so `"SHA256:SHA2-256"`
/// becomes one id with two names. If the name is already there, `add_names` answers its existing
/// number, so this is idempotent by construction rather than by a lookup first.
///
/// **`flag_construct_error_occurred` is set here and only here**, and it is the whole of the
/// distinction between the two error reasons a failed fetch reports: a class constructor that
/// refused means "the algorithm is known but could not be built" (`ERR_R_FETCH_FAILED`), and a
/// namemap that could not give an id means "this is not an algorithm I have"
/// (`ERR_R_UNSUPPORTED`). Setting the flag on the *namemap* failure too would make every fetch of
/// an unknown name report a construction error.
///
/// The libctx is the **provider's**, not the caller's: an algorithm belongs to the context its
/// provider was loaded into, and the namemap a name is registered in is that one's.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated; `prov`
/// live; `data` a live `EvpMethodData`.
unsafe extern "C" fn construct_evp_method(
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<EvpMethodData>();
    // SAFETY: `prov` is live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `libctx` is a live context.
    let namemap = ossl_namemap_stored(libctx);
    // SAFETY: `algodef` is live.
    let names = unsafe { (*algodef).algorithm_names };
    // SAFETY: `namemap` is live and `names` is NUL-terminated.
    let name_id = unsafe { ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR) };
    if name_id == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `methdata` is live, so the class's constructor is the caller's own.
    let method = unsafe { ((*methdata).method_from_algorithm)(name_id, algodef, prov) };
    if method.is_null() {
        // SAFETY: `methdata` is live.
        unsafe { (*methdata).flag_construct_error_occurred = 1 };
    }
    method
}

/// `static void destruct_evp_method(void *method, void *data)`.
///
/// The class's destructor, through the pointer the caller supplied. This is the decrement that
/// matches the reference `ossl_method_store_add` took, which is what
/// `ossl_method_construct_this` calls it for.
///
/// # Safety
/// `data` must be a live `EvpMethodData`; `method` live.
unsafe extern "C" fn destruct_evp_method(method: *mut c_void, data: *mut c_void) {
    let methdata = data.cast::<EvpMethodData>();
    // SAFETY: `methdata` is live per the contract.
    unsafe { ((*methdata).destruct_method)(method) };
}

/// `static void *inner_evp_generic_fetch(struct evp_method_data_st *methdata,
/// OSSL_PROVIDER *prov, int operation_id, const char *name, const char *properties,
/// void *(*new_method)(...), int (*up_ref_method)(void *), void (*free_method)(void *))`.
///
/// The generic fetch. Five things about it are worth holding on to:
///
///   * **the cache is tried first, and only then the walk.** `ossl_method_store_cache_get` is a
///     *result* cache keyed by the composite id and the query, so a repeat fetch of the same name
///     under the same query does not construct anything;
///   * **`unsupported` starts as "the name resolved to nothing"** and is *replaced*, not
///     refined, after a walk that completed without any constructor refusing: the flag means "a
///     class constructor refused", and its absence means the algorithm genuinely is not there;
///   * the walk's `provider_rw` is `&prov`, so a walk started with a named provider writes back
///     the provider that answered, and a walk started with NULL accepts any;
///   * **the id is re-resolved after construction**, because a name list may have registered
///     names the initial `name2num` did not know — the authority's own comment calls this a
///     corner case, and it is the case where a fetch of `"sha256:sha2-256"` constructs a method
///     and then fails to cache it because the *combined* string is not a name;
///   * `properties` is used **only in the error message**: the query the store is given is the
///     caller's `properties` or the empty string, and the difference between them is only
///     visible in what `ERR_get_error_all` reports back.
///
/// The error data is the authority's format string verbatim, including the context descriptor,
/// because that text is readable through `ERR_get_error_all` and is therefore contract.
///
/// # Safety
/// `methdata` must be a live `EvpMethodData` whose `libctx` is live and whose three function
/// pointers are valid; `prov` NULL or live; `name` and `properties` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn inner_evp_generic_fetch(
    methdata: *mut EvpMethodData,
    prov: *mut OsslProvider,
    operation_id: c_int,
    name: *const c_char,
    properties: *const c_char,
    new_method: MethodFromAlgorithmFn,
    up_ref_method: MethodUpRefFn,
    free_method: MethodFreeFn,
) -> *mut c_void {
    // SAFETY: `methdata` is live per the contract.
    let libctx = unsafe { (*methdata).libctx };
    // SAFETY: `libctx` is live per the contract and this only reads the slot.
    let store = unsafe { get_evp_method_store(libctx) };
    // SAFETY: `libctx` is live, so this answers the namemap or NULL.
    let namemap = ossl_namemap_stored(libctx);

    if store.is_null() || namemap.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_278) };
        return ptr::null_mut();
    }
    // `ossl_assert(operation_id > 0)`: non-fatal, so an internal programming error is a refusal.
    if operation_id <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_FETCH_287) };
        return ptr::null_mut();
    }

    // The `properties` default is the **empty string**, not NULL: it is the cache's key.
    let propq: *const c_char = if properties.is_null() {
        c"".as_ptr()
    } else {
        properties
    };

    // SAFETY: `namemap` is live and `name` is NULL or NUL-terminated.
    let mut name_id = if name.is_null() {
        0
    } else {
        // SAFETY: `namemap` is live and `name` is NUL-terminated per the contract.
        unsafe { ossl_namemap_name2num(namemap, name) }
    };

    let mut meth_id: u32 = 0;
    if name_id != 0 {
        meth_id = evp_method_id(name_id, operation_id as u32);
        if meth_id == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_FETCH_303) };
            return ptr::null_mut();
        }
    }

    let mut unsupported = name_id == 0;
    let mut method: *mut c_void = ptr::null_mut();
    let mut prov_rw = prov;

    if meth_id == 0 {
        // No id can be built, so there is nothing to look up: fall through to the walk.
    } else {
        // SAFETY: `store` is live, `prov_rw` may be written by the get, and `method` is this
        // frame's own writable slot.
        let hit = unsafe {
            crate::property::store::ossl_method_store_cache_get(
                store,
                prov_rw,
                meth_id as c_int,
                propq,
                &mut method,
            )
        };
        if hit == 0 {
            method = ptr::null_mut();
        }
    }

    if meth_id == 0 || method.is_null() {
        // The six callbacks are this module's own; each documents what it needs. No `unsafe`
        // block is needed to build the interface itself -- only to call it.
        let mcm = OsslMethodConstructMethod {
            get_tmp_store: get_tmp_evp_method_store as McmGetTmpStoreFn,
            lock_store: reserve_evp_method_store as McmLockStoreFn,
            unlock_store: unreserve_evp_method_store as McmUnlockStoreFn,
            get: get_evp_method_from_store as McmGetFn,
            put: put_evp_method_in_store as McmPutFn,
            construct: construct_evp_method as McmConstructFn,
            destruct: destruct_evp_method as McmDestructFn,
        };

        // SAFETY: `methdata` is live; every field written is this file's own.
        unsafe {
            (*methdata).operation_id = operation_id;
            (*methdata).name_id = name_id;
            (*methdata).names = name;
            (*methdata).propquery = propq;
            (*methdata).method_from_algorithm = new_method;
            (*methdata).refcnt_up_method = up_ref_method;
            (*methdata).destruct_method = free_method;
            (*methdata).flag_construct_error_occurred = 0;
        }

        // SAFETY: `libctx` is live, `prov_rw` is this frame's own provider slot and the walk may
        // write it, `mcm` is this frame's own live interface, and `methdata` outlives the walk.
        method = unsafe {
            ossl_method_construct(
                libctx,
                operation_id,
                &mut prov_rw,
                0, /* !force_cache */
                &mcm,
                methdata.cast::<c_void>(),
            )
        };

        if !method.is_null() {
            // The re-resolution, for the name-list corner case the authority names.
            if name_id == 0 {
                // SAFETY: `namemap` is live and `name` is NUL-terminated.
                name_id = unsafe { ossl_namemap_name2num(namemap, name) };
            }
            if name_id == 0 {
                let mut msg = [0 as c_char; ERR_DATA_BUFFER];
                // SAFETY: `msg` is a 1024-byte buffer, the format is the authority's, and `name`
                // is NUL-terminated.
                unsafe {
                    BIO_snprintf(
                        msg.as_mut_ptr(),
                        msg.len(),
                        c"Algorithm %s cannot be found".as_ptr(),
                        name,
                    )
                };
                // SAFETY: a compile-time-constant site; the message is NUL-terminated.
                unsafe { raise_site_data(&err_sites::EVP_FETCH_352, msg.as_ptr()) };
                // SAFETY: the construction left this reference for us and nobody took it.
                unsafe { free_method(method) };
                method = ptr::null_mut();
            } else {
                meth_id = evp_method_id(name_id, operation_id as u32);
                if meth_id != 0 {
                    // SAFETY: `store` is live, `prov_rw` is the provider that answered, and the
                    // method is live with the class's own callbacks.
                    unsafe {
                        crate::property::store::ossl_method_store_cache_set(
                            store,
                            prov_rw,
                            meth_id as c_int,
                            propq,
                            method,
                            up_ref_method,
                            free_method,
                        );
                    }
                }
            }
        }

        // "If we never were in the constructor, the algorithm to be fetched is unsupported."
        // SAFETY: `methdata` is live.
        unsupported = unsafe { (*methdata).flag_construct_error_occurred } == 0;
    }

    if (name_id != 0 || !name.is_null()) && method.is_null() {
        // The two reasons the authority computes between. The site is recorded with
        // `dynamic_reason` because `ERR_raise_data(ERR_LIB_EVP, code, ...)` passes an
        // *identifier*: the generator could not resolve a constant and refused to guess one, so
        // the choice between the two constants is made here, where the authority makes it.
        let code = if unsupported {
            ERR_R_UNSUPPORTED
        } else {
            ERR_R_FETCH_FAILED
        };
        let mut msg = [0 as c_char; ERR_DATA_BUFFER];
        // The name is resolved back to a string for the message when the caller gave an id
        // rather than a name.
        let shown = if name.is_null() {
            // SAFETY: `namemap` is live and the id was derived from it.
            unsafe { ossl_namemap_num2name(namemap, name_id, 0) }
        } else {
            name
        };
        // SAFETY: `msg` is a 1024-byte buffer, the format is the authority's, and every argument
        // is a NUL-terminated string or a plain integer.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s, Algorithm (%s : %d), Properties (%s)".as_ptr(),
                crate::context::lib_ctx_get_descriptor(libctx),
                if shown.is_null() {
                    c"<null>".as_ptr()
                } else {
                    shown
                },
                name_id,
                if properties.is_null() {
                    c"<null>".as_ptr()
                } else {
                    properties
                },
            );
        }
        // SAFETY: a compile-time-constant site with a run-time reason -- which is why this is
        // the dynamic form: the *coordinates* stay this site's, and the reason is the `code`
        // chosen above. The message is NUL-terminated.
        unsafe { raise_site_dynamic_data(&err_sites::EVP_FETCH_376, code, msg.as_ptr()) };
    }

    method
}

/// `void *evp_generic_fetch(OSSL_LIB_CTX *libctx, int operation_id, const char *name,
/// const char *properties, void *(*new_method)(...), int (*up_ref_method)(void),
/// void (*free_method)(void))`.
///
/// The public-ish wrapper every `EVP_<class>_fetch` is a macro around: no provider is named, so
/// any activated provider may answer, and the temporary store is released here — after
/// `inner_evp_generic_fetch` has finished looking in it.
///
/// **`tmp_store` is initialised to NULL and the initialisation is load-bearing.** It is the
/// `get_tmp_evp_method_store` sentinel: a non-NULL value there would make the walk reuse a store
/// this call did not create.
///
/// # Safety
/// `libctx` NULL or live; `name` and `properties` NULL or NUL-terminated; the three callbacks
/// valid for the class being fetched.
pub(crate) unsafe fn evp_generic_fetch(
    libctx: *mut c_void,
    operation_id: c_int,
    name: *const c_char,
    properties: *const c_char,
    new_method: MethodFromAlgorithmFn,
    up_ref_method: MethodUpRefFn,
    free_method: MethodFreeFn,
) -> *mut c_void {
    let mut methdata = EvpMethodData {
        libctx,
        operation_id: 0,
        name_id: 0,
        names: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
        method_from_algorithm: new_method,
        refcnt_up_method: up_ref_method,
        destruct_method: free_method,
    };
    // SAFETY: `methdata` is this frame's own live object and the arguments are this function's.
    let method = unsafe {
        inner_evp_generic_fetch(
            &mut methdata,
            ptr::null_mut(),
            operation_id,
            name,
            properties,
            new_method,
            up_ref_method,
            free_method,
        )
    };
    // SAFETY: the temporary store is NULL or one the walk made, and this call owns it.
    unsafe { dealloc_tmp_evp_method_store(methdata.tmp_store) };
    method
}

/// `void *evp_generic_fetch_from_prov(OSSL_PROVIDER *prov, int operation_id, const char *name,
/// const char *properties, void *(*new_method)(...), int (*up_ref_method)(void),
/// void (*free_method)(void))`.
///
/// **Special, and the authority says so**: it returns methods from the given provider *only*, and
/// it exists for the case where one method has to fetch an associated one — an `EVP_PKEY`
/// operation reaching for the digest its provider registered. The libctx is the **provider's**,
/// so the store searched is the one that provider was loaded into rather than any caller's.
///
/// # Safety
/// `prov` live; `name` and `properties` NULL or NUL-terminated; the three callbacks valid.
pub(crate) unsafe fn evp_generic_fetch_from_prov(
    prov: *mut OsslProvider,
    operation_id: c_int,
    name: *const c_char,
    properties: *const c_char,
    new_method: MethodFromAlgorithmFn,
    up_ref_method: MethodUpRefFn,
    free_method: MethodFreeFn,
) -> *mut c_void {
    // SAFETY: `prov` is live per the contract.
    let mut methdata = EvpMethodData {
        // SAFETY: `prov` is live per the contract, so its context is readable.
        libctx: unsafe { ossl_provider_libctx(prov) },
        operation_id: 0,
        name_id: 0,
        names: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
        method_from_algorithm: new_method,
        refcnt_up_method: up_ref_method,
        destruct_method: free_method,
    };
    // SAFETY: `methdata` is this frame's own live object, and `prov` is the caller's.
    let method = unsafe {
        inner_evp_generic_fetch(
            &mut methdata,
            prov,
            operation_id,
            name,
            properties,
            new_method,
            up_ref_method,
            free_method,
        )
    };
    // SAFETY: as in `evp_generic_fetch`.
    unsafe { dealloc_tmp_evp_method_store(methdata.tmp_store) };
    method
}

/// `struct filter_data_st { int operation_id; void (*user_fn)(void *method, void *arg);
/// void *user_arg; }`.
#[repr(C)]
struct FilterData {
    /// `int operation_id`.
    operation_id: c_int,
    /// `void (*user_fn)(void *, void *)`.
    user_fn: GenericDoAllFn,
    /// `void *user_arg`.
    user_arg: *mut c_void,
}

/// `static void filter_on_operation_id(int id, void *method, void *arg)`.
///
/// The store's `do_all` hands the **composite id**, and this masks the low byte back out — which
/// is the reason `evp_method_id` limits the whole thing to 31 bits: a composite with bit 31 set
/// would sign-extend when narrowed to `int` and the mask would then compare against the wrong
/// operation. That is the one place the id's width is load-bearing rather than tidy.
///
/// # Safety
/// `arg` must be a live `FilterData`; `method` is passed through to the caller's visitor.
unsafe extern "C" fn filter_on_operation_id(id: c_int, method: *mut c_void, arg: *mut c_void) {
    let data = arg.cast::<FilterData>();
    // SAFETY: `data` is live per the contract.
    // SAFETY: `data` is live per the contract, so `operation_id` is readable.
    let wanted = unsafe { (*data).operation_id } as u32;
    if ((id as u32) & METHOD_ID_OPERATION_MASK) == wanted {
        // SAFETY: `data` is live, so the user's visitor is the caller's own.
        unsafe { ((*data).user_fn)(method, (*data).user_arg) };
    }
}

/// `void evp_generic_do_all(OSSL_LIB_CTX *libctx, int operation_id,
/// void (*user_fn)(void *method, void *arg), void *user_arg, void *(*new_method)(...),
/// int (*up_ref_method)(void), void (*free_method)(void))`.
///
/// **A fetch with a NULL name, and then two walks.** `inner_evp_generic_fetch` is called with no
/// name precisely so that *every* algorithm is constructed and put into the store — a `do_all`
/// cannot enumerate what was never fetched — and its answer is discarded. Then the temporary
/// store, if the walk made one, is walked before the context's own.
///
/// That means a `do_all` constructs every method of every activated provider, which is the
/// authority's own economics and has a visible consequence: a provider whose constructor refuses
/// for one algorithm leaves that algorithm out of the enumeration, because nothing was stored for
/// it.
///
/// # Safety
/// `libctx` NULL or live; the three callbacks valid for the class; `user_fn` valid.
pub(crate) unsafe fn evp_generic_do_all(
    libctx: *mut c_void,
    operation_id: c_int,
    user_fn: GenericDoAllFn,
    user_arg: *mut c_void,
    new_method: MethodFromAlgorithmFn,
    up_ref_method: MethodUpRefFn,
    free_method: MethodFreeFn,
) {
    let mut methdata = EvpMethodData {
        libctx,
        operation_id: 0,
        name_id: 0,
        names: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
        method_from_algorithm: new_method,
        refcnt_up_method: up_ref_method,
        destruct_method: free_method,
    };
    // The fetch that is only for its side effect: NULL name, NULL properties, answer discarded.
    // SAFETY: `methdata` is this frame's own live object.
    let _ = unsafe {
        inner_evp_generic_fetch(
            &mut methdata,
            ptr::null_mut(),
            operation_id,
            ptr::null(),
            ptr::null(),
            new_method,
            up_ref_method,
            free_method,
        )
    };

    let mut data = FilterData {
        operation_id,
        user_fn,
        user_arg,
    };
    let dp: *mut c_void = ptr::addr_of_mut!(data).cast::<c_void>();
    // SAFETY: `methdata.tmp_store` is NULL or a live store this call owns; the visitor and its
    // argument outlive both walks.
    unsafe {
        if !methdata.tmp_store.is_null() {
            crate::property::store::ossl_method_store_do_all(
                methdata.tmp_store,
                Some(filter_on_operation_id),
                dp,
            );
        }
        // No block of its own: the enclosing `unsafe` is this statement's.
        let store = get_evp_method_store(libctx);
        crate::property::store::ossl_method_store_do_all(store, Some(filter_on_operation_id), dp);
        dealloc_tmp_evp_method_store(methdata.tmp_store);
    }
}

/// `int evp_is_a(OSSL_PROVIDER *prov, int number, const char *legacy_name, const char *name)`.
///
/// "Is this name the same algorithm as the one I already have a number for?" — and the two paths
/// are not symmetric. With a provider, the number is the caller's and only `name` is resolved;
/// **without** a provider the *legacy* name is resolved instead, because a caller with no
/// provider is asking about a name the legacy table knows and the namemap is where the two are
/// reconciled. The libctx is `ossl_provider_libctx(NULL)` in that case, which is the default
/// context rather than a NULL context.
///
/// # Safety
/// `prov` NULL or live; `legacy_name` and `name` NULL or NUL-terminated.
pub(crate) unsafe fn evp_is_a(
    prov: *mut OsslProvider,
    mut number: c_int,
    legacy_name: *const c_char,
    name: *const c_char,
) -> c_int {
    // SAFETY: `prov` is NULL or live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `libctx` is NULL or live.
    let namemap = ossl_namemap_stored(libctx);
    if prov.is_null() {
        // SAFETY: `namemap` is live and `legacy_name` is NUL-terminated.
        number = unsafe { ossl_namemap_name2num(namemap, legacy_name) };
    }
    // SAFETY: `namemap` is live and `name` is NUL-terminated.
    c_int::from(unsafe { ossl_namemap_name2num(namemap, name) } == number)
}

/// `int evp_names_do_all(OSSL_PROVIDER *prov, int number,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// Every name an id is known by, in the namemap of the context the provider belongs to — which is
/// the call that makes `"SHA2-256"` reachable from a method registered as `"SHA256"`.
///
/// # Safety
/// `prov` NULL or live; `fn` valid.
pub(crate) unsafe fn evp_names_do_all(
    prov: *mut OsslProvider,
    number: c_int,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `prov` is NULL or live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `libctx` is NULL or live.
    let namemap = ossl_namemap_stored(libctx);
    // SAFETY: `namemap` is live and the visitor is the caller's.
    unsafe { ossl_namemap_doall_names(namemap, number, fn_, data) }
}

/// `strchr`, behind a safe-to-call-from-`unsafe` name.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strchr(s: *const c_char, c: c_char) -> *const c_char {
    extern "C" {
        // The signature is the crate's own spelling of this libc function, so the declaration
        // does not clash with `src/dso/dlfcn.rs`'s and `src/runtime/bio/sys.rs`'s.
        fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    }
    // SAFETY: the caller's contract.
    unsafe { strchr(s, c as c_int) }.cast_const()
}

/// `strlen`, behind a safe-to-call-from-`unsafe` name.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    extern "C" {
        fn strlen(s: *const c_char) -> usize;
    }
    // SAFETY: the caller's contract.
    unsafe { strlen(s) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use core::ffi::CStr;
    use core::ptr;

    /// A context of this test's own, so nothing here changes the process-global default
    /// context's properties. That matters more than usual for this surface: the default
    /// properties are *per-context state that changes what every later fetch in that context
    /// resolves to*, so a test that set them on the default would be a test that changed the
    /// behaviour of every other test in the binary.
    struct Ctx(*mut c_void);

    impl Ctx {
        fn new() -> Ctx {
            // `OSSL_LIB_CTX_new` is a SAFE function in this crate: it takes no arguments and
            // answers a context this value releases once.
            let ctx = OSSL_LIB_CTX_new();
            assert!(!ctx.is_null(), "the context was built");
            Ctx(ctx)
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from `OSSL_LIB_CTX_new` and is released once, here.
            unsafe { OSSL_LIB_CTX_free(self.0) };
        }
    }

    /// The string `EVP_get1_default_properties` answers, as bytes, and released.
    ///
    /// Bytes rather than `&str`: the crate's unit tests do not link `alloc`, and the whole point
    /// of this surface is the *exact text* a provider is handed — so a comparison that went
    /// through a UTF-8 validity check would be comparing something weaker than what is claimed.
    fn take_string(p: *mut c_char) -> Vec<u8> {
        assert!(!p.is_null(), "the properties were rendered");
        // SAFETY: `p` is a NUL-terminated string this call owns, per the function's contract.
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
        // SAFETY: `p` is this call's own allocation, from `CRYPTO_strdup` or `CRYPTO_malloc`.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), ptr::null(), 0) };
        bytes
    }

    /// The round trip, and the two ends of it that a plausible implementation gets wrong: the
    /// text that comes back is the query that went in, and a **NULL** query is a *success* that
    /// leaves the context with no properties — not a refusal.
    #[test]
    fn setting_properties_round_trips_the_text_and_null_clears_them() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live and the argument is a literal.
        unsafe {
            assert_eq!(
                EVP_set_default_properties(ctx.0, c"fips=yes".as_ptr()),
                1,
                "a parseable query is accepted"
            );
            // SAFETY: the answered string is this call's own.
            let s = take_string(EVP_get1_default_properties(ctx.0));
            assert_eq!(s, b"fips=yes", "the text is the query's own spelling");

            assert_eq!(
                EVP_set_default_properties(ctx.0, ptr::null()),
                1,
                "a NULL query clears rather than refusing"
            );
            let empty = take_string(EVP_get1_default_properties(ctx.0));
            assert!(empty.is_empty(), "and the text is empty, not NULL");
        }
    }

    /// `EVP_default_properties_enable_fips` **merges**, and the two directions are not symmetric:
    /// enabling adds `fips=yes`, disabling adds the *negative* form `-fips`. A property that is
    /// merely absent is not the same as one that is forbidden, and an implementation that
    /// cleared the list instead would pass a naive test and select the wrong algorithms.
    #[test]
    fn enabling_and_disabling_fips_merge_the_two_opposite_forms() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live and every argument is a literal or a plain integer.
        unsafe {
            assert_eq!(
                EVP_default_properties_is_fips_enabled(ctx.0),
                0,
                "a fresh context is not fips"
            );

            assert_eq!(EVP_default_properties_enable_fips(ctx.0, 1), 1);
            assert_eq!(
                EVP_default_properties_is_fips_enabled(ctx.0),
                1,
                "and now it is"
            );
            let on = take_string(EVP_get1_default_properties(ctx.0));
            assert_eq!(on, b"fips=yes");

            assert_eq!(EVP_default_properties_enable_fips(ctx.0, 0), 1);
            assert_eq!(
                EVP_default_properties_is_fips_enabled(ctx.0),
                0,
                "the negative form turns it back off"
            );
            let off = take_string(EVP_get1_default_properties(ctx.0));
            // **The merge replaces the conflicting property rather than accumulating both.**
            // The first version of this test asserted `fips=yes,-fips` and the run said
            // `-fips`: a merge gives the incoming query precedence over the list it merges
            // into, so a property cannot survive as both itself and its negation. That is the
            // observable, and the assertion is now the measurement rather than the guess --
            // which matters here because a list holding both forms would select nothing and
            // look like a working merge in any test that only checked the return code.
            assert_eq!(off, b"-fips", "the incoming query wins over the stored one");
        }
    }

    /// A query the grammar refuses is a refusal **at the authority's own coordinate**, and the
    /// context's properties are left untouched. The coordinate is the observable here, not the
    /// return code: `EVP_R_DEFAULT_QUERY_PARSE_ERROR` raised from the wrong line is a difference
    /// a caller reading `ERR_get_error_all` would see.
    #[test]
    fn an_unparsable_query_is_refused_and_leaves_the_properties_alone() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live and the argument is a literal.
        unsafe {
            assert_eq!(EVP_set_default_properties(ctx.0, c"fips=yes".as_ptr()), 1);
            assert_eq!(
                EVP_set_default_properties(ctx.0, c"===no".as_ptr()),
                0,
                "the grammar refuses this"
            );
            let mut file: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut func: *const c_char = ptr::null();
            let mut data: *const c_char = ptr::null();
            let mut flags: c_int = 0;
            // SAFETY: every output pointer is this frame's own storage.
            let code = crate::runtime::err::ERR_peek_last_error_all(
                &mut file, &mut line, &mut func, &mut data, &mut flags,
            );
            assert_ne!(code, 0, "an error was raised");
            assert_eq!(
                line,
                err_sites::EVP_FETCH_517.line,
                "at the authority's line"
            );
            // SAFETY: the call above wrote a NUL-terminated string the error state still owns.
            assert_eq!(CStr::from_ptr(func), err_sites::EVP_FETCH_517.func);

            let kept = take_string(EVP_get1_default_properties(ctx.0));
            assert_eq!(kept, b"fips=yes", "the refusal changed nothing");
        }
    }

    /// The slot the whole of this file reaches is the one `context_init` builds, and a context
    /// whose store is missing is refused rather than treated as having none. This asserts the
    /// first half — that the slot is there — because the second half is only reachable by
    /// making a context fail its own initialisation, which is `RT-LIBCTX`'s territory.
    #[test]
    fn the_store_this_surface_flushes_is_the_contexts_own() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live.
        let store = unsafe { get_evp_method_store(ctx.0) };
        assert!(!store.is_null(), "slot 0 is filled for a fresh context");
    }

    /// `ERR_R_UNSUPPORTED` is composed from `err.h`'s flag, so its value is *derived* rather
    /// than transcribed — and this asserts the derivation against a second, independent reading
    /// of the same authority fact: `crypto/param_build.c:265` raises the constant literally, so
    /// the generated site's `reason` is what the authority's own compiler put in the error
    /// queue. If the flag or the number ever drifts, one of the two readers changes and this
    /// fails, which is the whole reason `RT-FETCH`'s unloaded-provider observation is worth
    /// having: the reason code is the only place this defect is visible, and a court can only
    /// see it while a probe calls the path.
    #[test]
    fn the_unsupported_reason_agrees_with_the_generated_site_that_raises_it() {
        assert_eq!(
            ERR_R_UNSUPPORTED,
            err_sites::PARAM_BUILD_265.reason,
            "the composed value and the authority's literal are the same code"
        );
        assert_ne!(
            ERR_R_UNSUPPORTED, ERR_R_FETCH_FAILED,
            "the two arms of the authority's choice are different codes"
        );
    }
}
