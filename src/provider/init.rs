//! Phase 6.8c — `provider_init`, and the teardown that closes the loop.
//!
//! A provider becomes "loaded" in two steps: `ossl_provider_new` **constructs** it
//! (6.8a/6.8b), and this function **initialises** it. Between the two the object is only
//! partially loaded, which is the authority's own wording in `ossl_provider_new`'s tail.
//!
//! ## Two paths to an init function, and only one of them touches the filesystem
//!
//! A provider arrives here with `init_function` already set (a builtin registered through
//! `OSSL_PROVIDER_add_builtin`, or one of the three predefined names) or with it NULL, which
//! the authority's comment says indicates a loadable module. The module path resolution is
//! four sources in a fixed order, and the order is the whole of the behaviour:
//!
//! 1. the store's `default_path`, set by `OSSL_PROVIDER_set_default_search_path`;
//! 2. else `OPENSSL_MODULES` from the environment, through `ossl_safe_getenv` — the *secure*
//!    variant, so the variable is ignored for a set-user-ID process;
//! 3. else `ossl_get_modulesdir()`, the compiled-in default;
//! 4. and the *name* is either `prov->path` or, if that is NULL, the name translated by
//!    [`crate::dso::DSO_convert_filename`] with `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY` set —
//!    so `"legacy"` becomes `"legacy.so"` and **not** `"liblegacy.so"`.
//!
//! The two are then joined by `DSO_merge`, which is why NULL has to mean "no directory":
//! an empty string would merge as one and produce a leading `/`.
//!
//! ## `ossl_assert` under NDEBUG is an `if`
//!
//! The first statement is `if (!ossl_assert(!prov->flag_initialized))` — a refusal of double
//! initialisation. `include/internal/common.h` defines `ossl_assert(x)` as
//! `ossl_assert_int(...)` under `!NDEBUG` and as plain `ossl_likely((x) != 0)` under `NDEBUG`,
//! and **this build defines `NDEBUG`** in `configdata.pm`'s `defines`. So the macro is
//! non-fatal and raises nothing of its own; it is written here as the `if` it expands to,
//! which is the same build fact D109 and D113 already depend on. Writing an abort would be a
//! divergence invented for safety rather than read from the build.
//!
//! ## The dispatch-table walk stores pointers; it does not interpret them
//!
//! Nine ids are looked for in the table the provider publishes, and each match stores the
//! entry's function pointer in the corresponding field. Nothing is called, so a provider that
//! publishes a table with a misspelled id is not detected here — it is detected when the
//! missing operation is asked for. That is the authority's behaviour and it is why the fields
//! are nullable and every caller tests them.
//!
//! ## The reason strings are recorded but not renderable, and that is registered
//!
//! A provider may publish `OSSL_FUNC_PROVIDER_GET_REASON_STRINGS`, a table of its own error
//! reasons. The authority copies it — prefixing the provider's error-library number onto each
//! entry, because `ERR_load_strings` patches the array in place — and installs it. This crate's
//! `ERR_load_strings` is a no-op (`src/runtime/err.rs`: the authority's tables are compiled in,
//! so the entry point exists for source compatibility), so the copy is made and handed over
//! and **nothing renders it**. The block is implemented faithfully anyway, because a later
//! change to the ERR subsystem has to be able to find it — and the consequence is registered
//! as a divergence rather than left as a surprise.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::owned_str::OwnedStr;
use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::context::dispatch::OsslDispatch;
use crate::dso::{
    DSO_bind_func, DSO_convert_filename, DSO_ctrl, DSO_free, DSO_load, DSO_merge, DSO_new,
    DSO_CTRL_SET_FLAGS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,
};
use crate::provider::core_dispatch::CORE_DISPATCH;
use crate::provider::{get_provider_store, OsslProvider, ProviderInitFn, FLAG_INITIALIZED};
use crate::runtime::defaults::ossl_get_modulesdir;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data, ERR_load_strings};
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_strdup};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::thread::{CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock};

/// The authority's translation unit, for the allocation-tracking `file` argument.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/provider_core.c".as_ptr();
const FILE_SEAM: SeamFile = SeamFile::new(c"../../src/openssl-3.6.4/crypto/provider_core.c");

// The provider-side dispatch ids `provider_init` looks for, from
// `include/openssl/core_dispatch.h`'s 1024-series. Read from the header rather than derived
// from the order the walk happens to use in: `QUERY_OPERATION` is 1027 and `SELF_TEST` 1031,
// which is *not* the sequence the switch is written in, so a guessed id would silently store
// one operation's function in another's field.
/// `OSSL_FUNC_PROVIDER_TEARDOWN`.
pub(crate) const FUNC_PROVIDER_TEARDOWN: c_int = 1024;
/// `OSSL_FUNC_PROVIDER_GETTABLE_PARAMS`.
pub(crate) const FUNC_PROVIDER_GETTABLE_PARAMS: c_int = 1025;
/// `OSSL_FUNC_PROVIDER_GET_PARAMS`.
pub(crate) const FUNC_PROVIDER_GET_PARAMS: c_int = 1026;
/// `OSSL_FUNC_PROVIDER_QUERY_OPERATION`.
pub(crate) const FUNC_PROVIDER_QUERY_OPERATION: c_int = 1027;
/// `OSSL_FUNC_PROVIDER_UNQUERY_OPERATION`.
pub(crate) const FUNC_PROVIDER_UNQUERY_OPERATION: c_int = 1028;
/// `OSSL_FUNC_PROVIDER_GET_REASON_STRINGS`.
const FUNC_PROVIDER_GET_REASON_STRINGS: c_int = 1029;
/// `OSSL_FUNC_PROVIDER_GET_CAPABILITIES`.
pub(crate) const FUNC_PROVIDER_GET_CAPABILITIES: c_int = 1030;
/// `OSSL_FUNC_PROVIDER_SELF_TEST`.
pub(crate) const FUNC_PROVIDER_SELF_TEST: c_int = 1031;
/// `OSSL_FUNC_PROVIDER_RANDOM_BYTES`.
pub(crate) const FUNC_PROVIDER_RANDOM_BYTES: c_int = 1032;

/// `ERR_LIB_OFFSET` — the shift `ERR_GET_LIB` applies.
const ERR_LIB_OFFSET: c_uint = 23;
/// `ERR_LIB_MASK`.
const ERR_LIB_MASK: c_uint = 0xFF;
/// `ERR_PACK(lib, 0, 0)` — the library-name entry's code.
const fn err_pack_lib(lib: c_int) -> c_ulong {
    ((lib as c_ulong) << ERR_LIB_OFFSET) & ((ERR_LIB_MASK as c_ulong) << ERR_LIB_OFFSET)
}

/// `typedef struct { int id; const char *ptr; } OSSL_ITEM` — `openssl/core.h`.
///
/// The authority's comment says `ERR_STRING_DATA` and `OSSL_ITEM` are "essentially the same
/// type", which is why the copy below can read one as the other. Spelled out because neither
/// is in an installed header.
#[repr(C)]
struct OsslItem {
    /// The reason's id, or 0 for the terminator.
    id: c_int,
    /// The reason's text.
    ptr: *const c_char,
}

/// `typedef struct { unsigned long error; const char *string; } ERR_STRING_DATA`.
#[repr(C)]
struct ErrStringData {
    /// The packed code `ERR_load_strings` patches with the library number.
    error: c_ulong,
    /// The text, borrowed from the provider's own table.
    string: *const c_char,
}

/// `OSSL_FUNC_provider_get_reason_strings_fn` — the ninth id, and the only one whose entry is
/// not stored on the provider object. It is consumed inside `provider_init` and then dropped.
///
/// # Safety
/// The provider must have published a `provider_get_reason_strings` entry.
type GetReasonStringsFn = unsafe extern "C" fn(provctx: *mut c_void) -> *const OsslItem;

/// `static int provider_init(OSSL_PROVIDER *prov)`.
///
/// The two failure points that raise with data carry the provider's name, so
/// [`raise_name_data`] builds the authority's `"name=%s"` shape.
///
/// # Safety
/// `prov` must be live, not-yet-initialised, and not reachable from another thread for the
/// duration: the initialisation flag is tested and set without a lock here, exactly as the
/// authority's is, because its caller initialises a provider before publishing it.
pub(crate) unsafe fn provider_init(prov: *mut OsslProvider) -> c_int {
    // The authority's `ossl_assert(!prov->flag_initialized)`. `NDEBUG` is defined in this
    // build, so the macro is `(x) != 0` and this is the `if` it expands to.
    // SAFETY: `prov` is live.
    if unsafe { (*prov).flags } & FLAG_INITIALIZED != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_CORE_959) };
        return 0;
    }

    // SAFETY: `prov` is live, so `name` is NUL-terminated (or NULL for a provider that has
    // not had one set, which no constructor produces).
    let name = unsafe { (*prov).name };

    // SAFETY: every field read and written below belongs to `prov`, which is live and
    // exclusively owned for the duration of this call.
    if unsafe { (*prov).init_function }.is_none() {
        // A loadable module: resolve the path, load it, and bind the provider's entry point.
        // SAFETY: `prov` is live.
        if unsafe { (*prov).module }.is_null() {
            // SAFETY: `DSO_new` takes no arguments and raises its own errors on failure.
            let dso = unsafe { DSO_new() };
            if dso.is_null() {
                return 0;
            }
            // SAFETY: `prov` is live, so the field write is to owned storage.
            unsafe { (*prov).module = dso };

            // SAFETY: `prov` is live, so `libctx` is the context it was constructed against.
            let libctx = unsafe { (*prov).libctx };
            // SAFETY: `libctx` is NULL or live.
            let store = unsafe { get_provider_store(libctx) };
            if store.is_null() {
                return 0;
            }
            // SAFETY: `store` is live, so `default_path_lock` was created with it; `dup` is this
            // call's fresh exclusive block from the seam.
            let (_allocated_load_dir, mut load_dir) = unsafe {
                if CRYPTO_THREAD_read_lock((*store).default_path_lock) == 0 {
                    return 0;
                }
                if (*store).default_path.is_null() {
                    CRYPTO_THREAD_unlock((*store).default_path_lock);
                    (None, ptr::null())
                } else {
                    // The duplicate is made **before** the unlock so the lock covers the read
                    // of the string, and released by the owner on every path below.
                    let dup = CRYPTO_strdup((*store).default_path, FILE, LINE_LOAD_DIR_DUP);
                    CRYPTO_THREAD_unlock((*store).default_path_lock);
                    if dup.is_null() {
                        return 0;
                    }
                    let owned = OwnedStr::adopt(dup, FILE_SEAM, LINE_LOAD_DIR_FREE);
                    let ptr = owned
                        .as_ref()
                        .map_or(ptr::null(), |s| s.as_ptr() as *const c_char);
                    (owned, ptr)
                }
            };
            if load_dir.is_null() {
                // The *secure* variant: ignored for a set-user-ID process.
                // SAFETY: the literal is NUL-terminated.
                let env = unsafe { ossl_safe_getenv(c"OPENSSL_MODULES".as_ptr()) };
                if !env.is_null() {
                    load_dir = env;
                } else {
                    load_dir = ossl_get_modulesdir();
                }
            }

            // Extension-only translation, so `"legacy"` becomes `"legacy.so"` rather than
            // `"liblegacy.so"` -- a module's name is not a library's name.
            // SAFETY: `dso` is live and the command's `parg` is unused.
            unsafe {
                DSO_ctrl(
                    dso,
                    DSO_CTRL_SET_FLAGS,
                    c_long::from(DSO_FLAG_NAME_TRANSLATION_EXT_ONLY),
                    ptr::null_mut(),
                );
            }

            // SAFETY: `prov` is live.
            let module_path: *const c_char = unsafe { (*prov).path };
            let (_allocated_path, module_path) = if module_path.is_null() {
                // `provider_core.c:1009` passes the provider's **name**, not NULL: the DSO's own
                // `filename` is unset for a provider constructed by name, so a NULL here would
                // raise `DSO_R_NO_FILENAME` and the module could never load.
                // SAFETY: `dso` is live and `name` is the provider's NUL-terminated name; the
                // answer is a fresh allocation, adopted by the handle whose `Drop` is its single
                // release at the authority's own free site.
                let owned = unsafe {
                    let path = DSO_convert_filename(dso, (*prov).name);
                    OwnedStr::adopt(path, FILE_SEAM, LINE_ALLOCATED_PATH_FREE)
                };
                let ptr = owned
                    .as_ref()
                    .map_or(ptr::null(), |s| s.as_ptr() as *const c_char);
                (owned, ptr)
            } else {
                (None, module_path)
            };
            let mut merged_path: Option<OwnedStr> = None;
            if !module_path.is_null() {
                // SAFETY: both specs are NULL or NUL-terminated; the answer is a fresh
                // allocation.
                let merged = unsafe { DSO_merge(dso, module_path, load_dir) };
                // SAFETY: `merged` is this call's fresh exclusive block from the seam; the
                // handle's `Drop` is its single release at the authority's own free site.
                merged_path = unsafe { OwnedStr::adopt(merged, FILE_SEAM, LINE_MERGED_PATH_FREE) };
            }
            let merged_ptr = merged_path
                .as_ref()
                .map_or(ptr::null(), |s| s.as_ptr() as *const c_char);

            // The authority short-circuits on a NULL merge result (`merged_path == NULL ||`)
            // and never calls `DSO_load` in that case. Calling it with a NULL filename would
            // raise `DSO_R_NO_FILENAME` on the error queue, which the authority does not.
            let loaded = if merged_ptr.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `merged_ptr` is NUL-terminated; the load is the DSO layer's.
                unsafe { DSO_load(dso, merged_ptr, ptr::null_mut(), 0) }
            };
            if loaded.is_null() {
                // SAFETY: `dso` is live and holds the only reference to itself.
                unsafe { DSO_free(dso) };
                // SAFETY: `prov` is live.
                unsafe { (*prov).module = ptr::null_mut() };
            }

            // The authority's three `OPENSSL_free` calls are now the owners' `Drop` at the end of
            // this block, in the same order: `merged_path` (1021), `allocated_path` (1022) and
            // `allocated_load_dir` (1023). Rust drops locals in reverse declaration order, so no
            // release moved relative to the authority's.
        }

        // SAFETY: `prov` is live.
        if unsafe { (*prov).module }.is_null() {
            // The DSO layer has already recorded its own errors; this is the authority's
            // tracepoint, which in this build is the only record.
            if !name.is_null() {
                // SAFETY: a compile-time-constant site and a NUL-terminated name.
                unsafe { raise_name_data(&err_sites::PROVIDER_CORE_1026, name) };
            }
            return 0;
        }

        // The provider's entry point, bound by the name the ABI fixes.
        // SAFETY: `prov` is live, so `module` is a live, loaded DSO.
        let sym = unsafe { DSO_bind_func((*prov).module, c"OSSL_provider_init".as_ptr()) };
        match sym {
            // SAFETY: the symbol is the provider's `OSSL_provider_init`, whose signature is
            // `ProviderInitFn`; `DSO_bind_func` answers a `void (*)(void)` because that is the
            // only thing a `dlsym` answer can be, so the reinterpretation is the caller's.
            Some(f) => unsafe {
                (*prov).init_function =
                    Some(core::mem::transmute::<unsafe extern "C" fn(), ProviderInitFn>(f));
            },
            None => {
                // SAFETY: `prov` is live.
                unsafe { (*prov).init_function = None };
            }
        }
    }

    // SAFETY: `prov` is live.
    let init = unsafe { (*prov).init_function };
    let Some(init) = init else {
        if !name.is_null() {
            // SAFETY: a compile-time-constant site and a NUL-terminated name.
            unsafe { raise_name_data(&err_sites::PROVIDER_CORE_1038, name) };
        }
        return 0;
    };

    let mut provider_dispatch: *const OsslDispatch = ptr::null();
    let mut tmp_provctx: *mut c_void = ptr::null_mut();
    // SAFETY: `init` is the provider's own entry point, `prov` cast to `OSSL_CORE_HANDLE *`
    // is the handle the ABI passes, and the table's address outlives the call.
    let ok = unsafe {
        init(
            prov.cast::<c_void>(),
            CORE_DISPATCH.0.as_ptr(),
            ptr::addr_of_mut!(provider_dispatch),
            ptr::addr_of_mut!(tmp_provctx),
        )
    };
    if ok == 0 {
        if !name.is_null() {
            // SAFETY: a compile-time-constant site and a NUL-terminated name.
            unsafe { raise_name_data(&err_sites::PROVIDER_CORE_1054, name) };
        }
        return 0;
    }
    // SAFETY: `prov` is live and the provider returned its own context and table.
    unsafe {
        (*prov).provctx = tmp_provctx;
        (*prov).dispatch = provider_dispatch;
    }

    let mut get_reason_strings: Option<GetReasonStringsFn> = None;
    if !provider_dispatch.is_null() {
        let mut d = provider_dispatch;
        // SAFETY: the walk stops at the `function_id == 0` terminator, which every provider
        // table ends with -- a provider ABI obligation this side cannot verify, exactly as the
        // authority's `for (; provider_dispatch->function_id != 0; ...)` cannot. Each entry read
        // is within the provider's own array. An entry that publishes an id with a NULL
        // `function` is stored as the raw NULL for the eight `void *` fields; the one typed
        // field (reason strings) is skipped, because a NULL Rust `fn` value is not valid.
        unsafe {
            while (*d).function_id != 0 {
                match (*d).function_id {
                    FUNC_PROVIDER_TEARDOWN => (*prov).teardown = (*d).function,
                    FUNC_PROVIDER_GETTABLE_PARAMS => (*prov).gettable_params = (*d).function,
                    FUNC_PROVIDER_GET_PARAMS => (*prov).get_params = (*d).function,
                    FUNC_PROVIDER_SELF_TEST => (*prov).self_test = (*d).function,
                    FUNC_PROVIDER_RANDOM_BYTES => (*prov).random_bytes = (*d).function,
                    FUNC_PROVIDER_GET_CAPABILITIES => (*prov).get_capabilities = (*d).function,
                    FUNC_PROVIDER_QUERY_OPERATION => (*prov).query_operation = (*d).function,
                    FUNC_PROVIDER_UNQUERY_OPERATION => (*prov).unquery_operation = (*d).function,
                    FUNC_PROVIDER_GET_REASON_STRINGS if !(*d).function.is_null() => {
                        // The authority's `OSSL_FUNC_provider_get_reason_strings` macro
                        // answers NULL for an entry whose `function` is NULL, and its caller
                        // then skips the table. Forming a Rust `fn` value from NULL is not a
                        // valid value, so the guard keeps a provider's NULL entry the no-op
                        // it is in C.
                        get_reason_strings = Some(core::mem::transmute::<
                            *mut c_void,
                            GetReasonStringsFn,
                        >((*d).function));
                    }
                    _ => {}
                }
                d = d.add(1);
            }
        }
    }

    if let Some(get_reason_strings) = get_reason_strings {
        // SAFETY: `prov` is live and `provctx` is what the provider just returned.
        let table = unsafe { get_reason_strings((*prov).provctx) };
        // The authority dereferences the answer without a NULL test (`reasonstrings[cnt]`),
        // which is undefined behaviour for a provider that returns NULL. Refusing instead is
        // a deliberate safety improvement over the authority, not a behaviour parity claim:
        // the table is simply not installed.
        if !table.is_null() {
            // Count to the terminator first, refusing an entry that already carries a library
            // number -- the copy below would otherwise double-prefix it.
            let mut cnt = 0usize;
            // SAFETY: the table is terminated by `id == 0`, which is what the walk stops on.
            unsafe {
                while (*table.add(cnt)).id != 0 {
                    if ((*table.add(cnt)).id as c_uint >> ERR_LIB_OFFSET) & ERR_LIB_MASK != 0 {
                        return 0;
                    }
                    cnt += 1;
                }
            }
            cnt += 1; // One for the terminating item.

            // One extra entry for the library name itself.
            let Some(entries) = cnt.checked_add(1) else {
                return 0;
            };
            // SAFETY: a fresh zeroed array of `entries` entries; `CRYPTO_calloc` checks the
            // element-count product and raises the authority's integer-overflow error.
            let strings = CRYPTO_calloc(
                entries,
                core::mem::size_of::<ErrStringData>(),
                FILE,
                LINE_REASON_STRINGS,
            );
            // SAFETY: `strings` is this call's fresh exclusive block from the seam; the handle's
            // `Drop` is its single release at the authority's own free site.
            // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL answers `None`.
            let Some(strings) = (unsafe {
                OwnedBuf::adopt_plain(strings.cast::<c_uchar>(), FILE_SEAM, LINE_REASON_STRINGS)
            }) else {
                return 0;
            };
            let table_out = strings.as_ptr().cast::<ErrStringData>();
            // SAFETY: `table_out` has `entries` writable entries; each `string` borrows from the
            // provider's own table, which outlives the provider because the provider owns it.
            unsafe {
                // SAFETY: `prov` is live.
                let error_lib = (*prov).error_lib;
                (*table_out).error = err_pack_lib(error_lib);
                (*table_out).string = (*prov).name;
                let mut i = 1usize;
                while i <= cnt {
                    (*table_out.add(i)).error = (*table.add(i - 1)).id as c_ulong;
                    (*table_out.add(i)).string = (*table.add(i - 1)).ptr;
                    i += 1;
                }
                // SAFETY: `prov` is live and the array is the one just built; the provider takes
                // ownership of it here, exactly as the authority stores the pointer before
                // `ERR_load_strings`.
                (*prov).error_strings = strings.into_raw().cast::<c_void>();
                ERR_load_strings(error_lib, (*prov).error_strings);
            }
        }
    }

    // With this flag set the provider has become fully loaded.
    // SAFETY: `prov` is live and exclusively owned.
    unsafe { (*prov).flags |= FLAG_INITIALIZED };
    1
}

/// The authority's `ERR_raise_data(ERR_LIB_CRYPTO, reason, "name=%s", prov->name)`.
///
/// The data is built as `"name="` plus the name. The authority formats it with its own
/// printf engine, which would *also* interpret a `%` in the name; a provider name containing
/// one is not something any constructor produces, and reproducing the interpretation would
/// mean re-deriving the format engine here for a case that cannot arise.
///
/// # Safety
/// `site` must be a compile-time-constant site and `name` NUL-terminated.
unsafe fn raise_name_data(site: &err_sites::ErrSite, name: *const c_char) {
    let mut m = b"name=".to_vec();
    // SAFETY: `name` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { crate::dso::c_str_bytes(name) });
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `void ossl_provider_teardown(const OSSL_PROVIDER *prov)`.
///
/// Skipped when the provider is a child, which is why 6.8e has to keep the flag honest: a
/// child provider is torn down by its parent's deactivation rather than by its own free.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_provider_teardown(prov: *const OsslProvider) {
    if prov.is_null() {
        return;
    }
    // SAFETY: `prov` is live; the two fields read are a function pointer and a flag.
    let (teardown, ischild) = unsafe { ((*prov).teardown, (*prov).ischild & 1 != 0) };
    if teardown.is_null() || ischild {
        return;
    }
    // SAFETY: `prov` is live, and the field read is a raw pointer it owns.
    let provctx = unsafe { (*prov).provctx };
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_teardown`, whose
    // signature is `void (void *provctx)`; `provctx` is what the provider returned from init.
    unsafe {
        let f = core::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void)>(teardown);
        f(provctx);
    }
}

// The authority's allocation coordinates, read from `crypto/provider_core.c`.
/// `provider_init`'s `OPENSSL_strdup(store->default_path)`.
const LINE_LOAD_DIR_DUP: c_int = 989;
/// `provider_init`'s `OPENSSL_free(merged_path)`.
const LINE_MERGED_PATH_FREE: c_int = 1021;
/// `provider_init`'s `OPENSSL_free(allocated_path)`.
const LINE_ALLOCATED_PATH_FREE: c_int = 1022;
/// `provider_init`'s `OPENSSL_free(allocated_load_dir)`.
const LINE_LOAD_DIR_FREE: c_int = 1023;
/// `provider_init`'s `OPENSSL_calloc(cnt + 1, sizeof(ERR_STRING_DATA))`.
const LINE_REASON_STRINGS: c_int = 1121;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ossl_provider_free, ossl_provider_new};

    /// A provider table that publishes `get_reason_strings` with a NULL `function`. The
    /// authority's `OSSL_FUNC_provider_get_reason_strings` macro answers NULL for exactly this
    /// entry and `provider_init`'s `if (p_get_reason_strings != NULL)` skips the table, so the
    /// provider still initialises. This is the negative control for the typed-field guard in
    /// the walk: without it the NULL entry became an invalid Rust `fn` value and was called.
    static NULL_REASON_DISPATCH: [OsslDispatch; 2] = [
        OsslDispatch {
            function_id: FUNC_PROVIDER_GET_REASON_STRINGS,
            function: ptr::null_mut(),
        },
        OsslDispatch {
            function_id: 0,
            function: ptr::null_mut(),
        },
    ];

    unsafe extern "C" fn null_reason_init(
        _handle: *const c_void,
        _input: *const OsslDispatch,
        output: *mut *const OsslDispatch,
        provctx: *mut *mut c_void,
    ) -> c_int {
        // SAFETY: both out-parameters are writable per `ProviderInitFn`'s contract.
        unsafe {
            *output = NULL_REASON_DISPATCH.as_ptr();
            *provctx = ptr::null_mut();
        }
        1
    }

    #[test]
    fn a_null_reason_strings_entry_is_ignored_like_the_authority() {
        const NAME: &core::ffi::CStr = c"init-null-reason-strings";
        // SAFETY: a NULL context is the default one and every pointer is a literal or a value
        // this test owns.
        unsafe {
            let prov = ossl_provider_new(
                ptr::null_mut(),
                NAME.as_ptr(),
                Some(null_reason_init),
                ptr::null_mut(),
                0,
            );
            assert!(!prov.is_null(), "the provider must construct");
            assert_eq!(provider_init(prov), 1, "a NULL entry is not a failure");
            assert_ne!((*prov).flags & FLAG_INITIALIZED, 0);
            assert_eq!((*prov).dispatch, NULL_REASON_DISPATCH.as_ptr());
            assert!((*prov).teardown.is_null(), "NULL is stored as absent");
            ossl_provider_free(prov);
        }
    }
}
