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

use core::ffi::{c_char, c_int, c_void};

use crate::context::{
    lib_ctx_get_data, lib_ctx_is_global_default, OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX,
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
use crate::property::store::OsslMethodStore;
use crate::provider::activate::ossl_provider_default_props_update;
use crate::provider::stores::ossl_decoder_cache_flush;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};

/// The authority's translation unit, so a failing allocation records its coordinates.
pub(crate) const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c".as_ptr();

/// `evp_set_parsed_default_properties`'s `OPENSSL_malloc(strsz)` (line 483).
const LINE_MALLOC_PROPSTR: c_int = 483;
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
}
