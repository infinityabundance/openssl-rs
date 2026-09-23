//! Phase 6.8a — `crypto/provider_core.c` §§1–950: the provider object and its store.
//!
//! A provider is a **named, reference-counted object in a per-context store**, and the
//! store is an `OSSL_LIB_CTX` sub-object: slot 1 of the index table
//! (`OSSL_LIB_CTX_PROVIDER_STORE_INDEX`). Everything later — loading, activation, the
//! dispatch tables, the fetch — is written against what this file creates, which is why it
//! comes first and why it is worth building with nothing yet to load.
//!
//! ## The store is *sorted*, and that is an observable property of it
//!
//! `ossl_provider_store_new` builds its stack with `sk_OSSL_PROVIDER_new(ossl_provider_cmp)`
//! rather than `_new_null`, and `ossl_provider_find` calls `sk_OSSL_PROVIDER_sort`
//! **before** it searches. So the store is ordered by name, lookups are binary searches,
//! and a stack that was pushed into in a different order is silently reordered by the next
//! lookup. `ossl_provider_cmp` is invoked by the stack machinery on **pointers to slots**,
//! not on elements — `crypto/stack/stack.c` sorts the array of element pointers with
//! `qsort` and passes `&data[i]` — so the comparator dereferences twice. That is the single
//! easiest thing to get wrong in this file, and it is invisible until the store holds two
//! providers whose name order differs from their insertion order.
//!
//! ## `provider_new` and `ossl_provider_new` are two different constructors
//!
//! `provider_new` is the low-level one: allocate, create three locks, deep-copy the
//! parameters, dup the name. It does **not** set `libctx`, does not resolve a template, and
//! does not set the module path. `ossl_provider_new` is the one callers use: it resolves
//! `name` against the compiled-in predefined table *and* the store's registered
//! `OSSL_PROVIDER_INFO` list, merges the caller's `params` over the template's, calls
//! `provider_new`, then sets the path, the context and the per-provider error library
//! number. It is 6.8b's, because the predefined table is what makes it non-trivial.
//!
//! ## `ossl_provider_find` takes a reference, and may run the config loader first
//!
//! The answer carries a **new reference** the caller must release, so a failed up-ref is
//! reported as "not found" rather than as a partial object. And unless `noconfig` is set it
//! calls `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG)` on the *default* context before
//! searching — which is how a provider named only in `openssl.cnf` becomes findable
//! without the caller having loaded anything. That is why this is not a pure lookup, and it
//! is reproduced rather than skipped.
//!
//! ## What this subphase deliberately does not write
//!
//! Five things belong to a later part and are named **where they would go** rather than
//! approximated. A fabricated error site or a silently skipped branch would both read as
//! evidence, which is the one thing this project does not allow:
//!
//! * `ossl_provider_free`'s `flag_initialized` arm — `ossl_provider_teardown`, the error
//!   string unload and the `operation_bits` free. **6.8c**, because `provider_init` is what
//!   sets the flag and nothing here can.
//! * `ossl_provider_free`'s `else if (prov->ischild)` arm and `ossl_provider_up_ref`'s
//!   `ischild` arm — **6.8e**, because nothing can set `ischild` until
//!   `ossl_provider_set_child` lands there.
//! * `ossl_provider_add_to_store`'s `create_provider_children`, and `provider_activate`'s
//!   — **landed with 6.8e.** The guard that stood here until then was `prov->store == NULL`
//!   rather than an emptiness test, and it answered 1 rather than failing loudly, so the
//!   "fails loudly" claim in its own documentation was never true. Both call sites now make
//!   the authority's call and `store->child_cbs` is a stack a registered parent can be in.
//! * `provider_deactivate_free`'s `ossl_provider_deactivate(prov, 1)` — **6.8c**, for the
//!   same reason as the first.
//! * `ossl_init_thread_deregister(prov)` in `ossl_provider_free` — **6.6e-ii**. It is the
//!   one line the authority calls *unconditionally*, whether or not init succeeded, and it
//!   is therefore the most important of the five to remember.
//!
//! `DSO_free(prov->module)` **is** written, because `DSO_free` accepts NULL and the field is
//! NULL for every object this subphase can build.
//!
//! ## The `OSSL_PROVIDER_*` exports are not declared here
//!
//! They are 6.8b/6.8c work. The obligation ledger counts a symbol as implemented the moment
//! it is defined, so declaring them before `RT-PROVIDER` exists would move twenty-two rows
//! on evidence that does not exist. Every item below is `pub(crate)`, carries no
//! `#[no_mangle]`, and is a coordinate rather than a claim — the treatment `crypto/context.c`'s
//! internals and `property.c`'s already receive.
//!
//! ## Allocation coordinates
//!
//! `CRYPTO_malloc` and friends take the authority's `file` and `line`, because Phase 3's
//! memory-debug court reads them back out. Every constant below is the authority's own line
//! number in `crypto/provider_core.c`, taken from the file rather than recalled (D33).
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) mod activate;
// 6.8d: `crypto/provider_conf.c`, the `providers` configuration module.
pub(crate) mod cipher;
pub(crate) mod conf;
pub(crate) mod ctx;
// 6.8e: `crypto/provider_child.c`, the child provider and its parent callbacks.
pub(crate) mod child;
pub(crate) mod core_dispatch;
pub(crate) mod digest;
pub(crate) mod dsa_kmgmt;
pub(crate) mod ec_kem;
pub(crate) mod ec_kmgmt;
pub(crate) mod ecdh_exch;
pub(crate) mod ecx_exch;
pub(crate) mod ecx_kem;
pub(crate) mod ecx_kmgmt;
pub(crate) mod exchange;
pub(crate) mod init;
pub(crate) mod kdf;
pub(crate) mod kem;
pub(crate) mod kem_util;
pub(crate) mod keymgmt;
pub(crate) mod mac;
pub(crate) mod mac_legacy_kmgmt;
pub(crate) mod rand;
pub(crate) mod rsa_kmgmt;
pub(crate) mod seed_src;
pub(crate) mod seeding;
pub(crate) mod skeymgmt;
pub(crate) mod stores;
pub(crate) mod util;

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::OsslDispatch;
use crate::context::{lib_ctx_get_data, lib_ctx_is_default_symbol};
use crate::dso::{DSO_free, DSO_get_filename, Dso};
use crate::ffi::guard_ffi;
use crate::params::{
    OsslParam, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, ERR_get_next_error_library};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};
use crate::runtime::mem::{
    CRYPTO_calloc, CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc_array, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_delete, OPENSSL_sk_delete_ptr, OPENSSL_sk_find,
    OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};
use crate::selftest::OsslCallback;

/// `OSSL_LIB_CTX_PROVIDER_STORE_INDEX` — slot 1, from `include/internal/cryptlib.h`.
pub(crate) const PROVIDER_STORE_INDEX: c_int = 1;

/// The authority's translation unit, for the allocation-tracking `file` argument.
pub(crate) const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/provider_core.c".as_ptr();

/// `crypto/provider.c`, for the one allocation that lives there.
///
/// The allocation-tracking `file` is part of what Phase 3's memory-debug court reads back,
/// so `OSSL_PROVIDER_add_builtin`'s dup must name *its* file and not `provider_core.c`'s.
pub(crate) const FILE_PROVIDER: *const c_char =
    c"../../src/openssl-3.6.4/crypto/provider.c".as_ptr();

/// `BUILTINS_BLOCK_SIZE` — the store's provider-info array grows by ten entries.
const BUILTINS_BLOCK_SIZE: usize = 10;

// The authority's allocation coordinates, gathered in one table rather than scattered
// beside their uses, so the whole set can be read at once and compared against
// `crypto/provider_core.c` with one screenful of text.
//
// Every one of them is currently **unread**: the functions that pass them to the allocator
// are unreachable until 6.8c declares the `OSSL_PROVIDER_*` exports, and `rustc` does not
// count a reference from dead code as a use. The allowance below is therefore a single,
// auditable one covering exactly this table. It is removed in the commit that lands 6.8c --
// and if it is still here after that, the coordinates have stopped being used, which is a
// defect rather than a style matter.
mod lines {
    #![allow(dead_code)] // every user is unreachable until 6.8c declares the exports
    use core::ffi::c_int;

    /// `infopair_free`'s `OPENSSL_free(pair->name)`.
    pub(super) const L_PAIR_FREE_NAME: c_int = 252;
    /// `infopair_free`'s `OPENSSL_free(pair->value)`.
    pub(super) const L_PAIR_FREE_VALUE: c_int = 253;
    /// `infopair_free`'s `OPENSSL_free(pair)`.
    pub(super) const L_PAIR_FREE: c_int = 254;
    /// `infopair_copy`'s `OPENSSL_zalloc`.
    pub(super) const L_PAIR_COPY: c_int = 259;
    /// `infopair_copy`'s `OPENSSL_strdup(src->name)`.
    pub(super) const L_PAIR_COPY_NAME: c_int = 264;
    /// `infopair_copy`'s `OPENSSL_strdup(src->value)`.
    pub(super) const L_PAIR_COPY_VALUE: c_int = 269;
    /// `ossl_provider_info_clear`'s two frees.
    pub(super) const L_INFO_CLEAR_NAME: c_int = 282;
    /// `ossl_provider_info_clear`'s `OPENSSL_free(info->path)`.
    pub(super) const L_INFO_CLEAR_PATH: c_int = 283;
    /// `ossl_provider_store_free`'s `OPENSSL_free(store->default_path)`.
    pub(super) const L_STORE_FREE_PATH: c_int = 295;
    /// `ossl_provider_store_free`'s `OPENSSL_free(store->provinfo)`.
    pub(super) const L_STORE_FREE_PROVINFO: c_int = 305;
    /// `ossl_provider_store_free`'s `OPENSSL_free(store)`.
    pub(super) const L_STORE_FREE: c_int = 306;
    /// `ossl_provider_store_new`'s `OPENSSL_zalloc`.
    pub(super) const L_STORE_NEW: c_int = 311;
    /// `ossl_provider_info_add_to_store`'s `OPENSSL_calloc`.
    pub(super) const L_INFO_ADD_CALLOC: c_int = 374;
    /// `ossl_provider_info_add_to_store`'s `OPENSSL_realloc_array`.
    pub(super) const L_INFO_ADD_REALLOC: c_int = 383;
    /// `provider_new`'s `OPENSSL_zalloc`.
    pub(super) const L_PROV_NEW: c_int = 447;
    /// `provider_new`'s `OPENSSL_strdup(name)`.
    pub(super) const L_PROV_NEW_NAME: c_int = 469;
    /// `ossl_provider_free`'s `OPENSSL_free(prov->error_strings)`.
    pub(super) const L_PROV_FREE_ERROR_STRINGS: c_int = 754;
    /// `ossl_provider_free`'s `OPENSSL_free(prov->operation_bits)`.
    pub(super) const L_PROV_FREE_OPERATION_BITS: c_int = 759;
    /// `ossl_provider_free`'s frees, in the authority's order.
    pub(super) const L_PROV_FREE_NAME: c_int = 774;
    /// `ossl_provider_free`'s `OPENSSL_free(prov->path)`.
    pub(super) const L_PROV_FREE_PATH: c_int = 775;
    /// `ossl_provider_free`'s `OPENSSL_free(prov)`.
    pub(super) const L_PROV_FREE: c_int = 781;
    /// `ossl_provider_set_module_path`'s `OPENSSL_free(prov->path)`.
    pub(super) const L_SET_PATH_FREE: c_int = 794;
    /// `ossl_provider_set_module_path`'s `OPENSSL_strdup(module_path)`.
    pub(super) const L_SET_PATH_DUP: c_int = 798;
    /// `infopair_add`'s `OPENSSL_zalloc`.
    pub(super) const L_PAIR_ADD: c_int = 808;
    /// `infopair_add`'s `OPENSSL_strdup(name)`.
    pub(super) const L_PAIR_ADD_NAME: c_int = 809;
    /// `infopair_add`'s `OPENSSL_strdup(value)`.
    pub(super) const L_PAIR_ADD_VALUE: c_int = 810;
    /// `infopair_add`'s error-arm frees.
    pub(super) const L_PAIR_ADD_ERR_NAME: c_int = 824;
    /// `infopair_add`'s `OPENSSL_free(pair->value)`.
    pub(super) const L_PAIR_ADD_ERR_VALUE: c_int = 825;
    /// `infopair_add`'s `OPENSSL_free(pair)`.
    pub(super) const L_PAIR_ADD_ERR: c_int = 826;
    pub(super) const L_ADD_BUILTIN_DUP: c_int = 136;
    /// `ossl_provider_child_cb_free`'s `OPENSSL_free(cb)` — 6.8e's allocation site.
    pub(super) const L_CHILD_CB_FREE: c_int = 246;
    /// `OSSL_PROVIDER_set_default_search_path`'s `OPENSSL_strdup(path)`.
    pub(super) const L_SET_SEARCH_PATH_DUP: c_int = 914;
    /// `OSSL_PROVIDER_set_default_search_path`'s `OPENSSL_free(store->default_path)`.
    pub(super) const L_SET_SEARCH_PATH_FREE: c_int = 920;
    /// `OSSL_PROVIDER_set_default_search_path`'s `OPENSSL_free(p)` on the failure path.
    pub(super) const L_SET_SEARCH_PATH_ERR: c_int = 925;
}

/// The stack comparator's signature, as `OPENSSL_sk_new` takes it.
///
/// `crypto/stack/stack.c` invokes it on **pointers to the slots**, not on the elements, so
/// by the time a caller has an element type the parameters are double pointers. The alias
/// in `crate::runtime::stack` is private, so it is spelled here.
type SkCompFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
/// The element-freeing callback's signature, as `OPENSSL_sk_pop_free` takes it.
type SkFreeFn = unsafe extern "C" fn(*mut c_void);
/// The element-copying callback's signature, as `OPENSSL_sk_deep_copy` takes it.
type SkCopyFn = unsafe extern "C" fn(*const c_void) -> *mut c_void;

/// `typedef int (*OSSL_provider_init_fn)(const OSSL_CORE_HANDLE *handle, const
/// OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)` — `openssl/provider.h`.
// The parameters are deliberately **unnamed**. `ABI-PROTOTYPE` canonicalises a function
// pointer's argument *types*, and a named argument is not a type: `handle: *const c_void`
// is unreadable to it, so a named alias is reported under `type_unmapped` and never counted
// as checked. Every function-pointer alias in this crate is spelled this way for that
// reason, and this one was not until 6.8c put it in an export's signature and the court
// said so.
pub(crate) type ProviderInitFn = unsafe extern "C" fn(
    *const c_void,
    *const OsslDispatch,
    *mut *const OsslDispatch,
    *mut *mut c_void,
) -> c_int;

/// `typedef struct { char *name; char *value; } INFOPAIR` — `crypto/provider_local.h`.
///
/// The layout is internal (`provider_local.h` is not installed), but the field order is the
/// authority's so that the copy and free callbacks read the same way.
#[repr(C)]
pub(crate) struct InfoPair {
    /// A NUL-terminated parameter name, owned.
    pub(crate) name: *mut c_char,
    /// A NUL-terminated parameter value, owned.
    pub(crate) value: *mut c_char,
}

/// `OSSL_PROVIDER_INFO` — `crypto/provider_local.h`.
///
/// Used for two things: the compiled-in predefined table and the store's registered
/// builtins. `is_fallback` is a **one-bit** bitfield in C; it is a `u32` here and only bit 0
/// is ever read or written, because the struct never crosses the ABI and the authority's own
/// initializers set nothing but that bit.
#[repr(C)]
pub(crate) struct OsslProviderInfo {
    /// The provider's name, owned by whoever inserted the entry.
    pub(crate) name: *mut c_char,
    /// The module path, or NULL. Owned the same way.
    pub(crate) path: *mut c_char,
    /// Non-NULL for a builtin, NULL for a module to be loaded by name.
    pub(crate) init: Option<ProviderInitFn>,
    /// The provider's implicit parameters, or NULL.
    pub(crate) parameters: *mut OpenSslStack,
    /// The authority's `is_fallback : 1`.
    pub(crate) is_fallback: c_uint,
}

/// `struct ossl_provider_st` — `OSSL_PROVIDER`, opaque everywhere outside this directory.
///
/// The two one-bit fields at the top of the authority's struct (`flag_initialized` and
/// `flag_activated`) share one storage unit in C, so they are one `u32` here with named
/// masks — see [`FLAG_INITIALIZED`] and [`FLAG_ACTIVATED`]. The object is opaque, so no
/// offset is observable and the compression is not a divergence.
///
/// The authority places `error_lib` and `error_strings` behind `#ifndef FIPS_MODULE`; both
/// are present because this build is not the FIPS module.
#[repr(C)]
pub struct OsslProvider {
    /// The authority's two one-bit flag fields, as named masks.
    pub(crate) flags: c_uint,
    /// Guards `flags`.
    pub(crate) flag_lock: *mut CryptoRwlock,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// Guards `activatecnt`.
    pub(crate) activatecnt_lock: *mut CryptoRwlock,
    /// The activation count, which is **not** the reference count.
    pub(crate) activatecnt: c_int,
    /// The provider's name, owned.
    pub(crate) name: *mut c_char,
    /// The module path from the template, owned.
    pub(crate) path: *mut c_char,
    /// The loaded module, or NULL for a builtin.
    pub(crate) module: *mut Dso,
    /// Non-NULL for a builtin provider.
    pub(crate) init_function: Option<ProviderInitFn>,
    /// The provider's implicit parameters, owned.
    pub(crate) parameters: *mut OpenSslStack,
    /// The context this instance belongs to.
    pub(crate) libctx: *mut c_void,
    /// The store this instance was added to, or NULL until it is.
    pub(crate) store: *mut ProviderStore,
    /// `ERR_get_next_error_library()`'s answer for this provider.
    pub(crate) error_lib: c_int,
    /// The provider's error string table, or NULL. Unloaded in 6.8c.
    pub(crate) error_strings: *mut c_void,
    /// `provider_teardown` — 6.8c.
    pub(crate) teardown: *mut c_void,
    /// `provider_gettable_params` — 6.8b.
    pub(crate) gettable_params: *mut c_void,
    /// `provider_get_params` — 6.8b.
    pub(crate) get_params: *mut c_void,
    /// `provider_get_capabilities` — 6.8b.
    pub(crate) get_capabilities: *mut c_void,
    /// `provider_self_test` — 6.8b.
    pub(crate) self_test: *mut c_void,
    /// `provider_random_bytes` — 6.8c.
    pub(crate) random_bytes: *mut c_void,
    /// `provider_query_operation` — 6.8c.
    pub(crate) query_operation: *mut c_void,
    /// `provider_unquery_operation` — 6.8c.
    pub(crate) unquery_operation: *mut c_void,
    /// The `query_operation` cache, or NULL until 6.8c allocates it.
    pub(crate) operation_bits: *mut u8,
    /// The cache's size in bytes.
    pub(crate) operation_bits_sz: usize,
    /// Guards the two fields above.
    pub(crate) opbits_lock: *mut CryptoRwlock,
    /// The core handle this provider was created from, for a child — 6.8e.
    pub(crate) handle: *const c_void,
    /// The authority's `ischild : 1`.
    pub(crate) ischild: c_uint,
    /// The provider's own context, from `init`.
    pub(crate) provctx: *mut c_void,
    /// The dispatch table the provider published, or NULL until 6.8c.
    pub(crate) dispatch: *const OsslDispatch,
}

/// `flag_initialized` — bit 0 of [`OsslProvider::flags`].
///
/// Unread in this subphase: `provider_init` is what sets it and that is 6.8c's, so the only
/// consumer is the arm of `ossl_provider_free` that 6.8c inserts.
pub(crate) const FLAG_INITIALIZED: c_uint = 0x01;
/// `flag_activated` — bit 1 of [`OsslProvider::flags`].
pub(crate) const FLAG_ACTIVATED: c_uint = 0x02;

/// `struct provider_store_st` — the per-context object in slot 1.
///
/// `child_cbs` is the stack of registered child callbacks, which only 6.8e can push into. It
/// is present so the store's layout matches the authority's and so the teardown frees it
/// exactly once.
#[repr(C)]
pub(crate) struct ProviderStore {
    /// The context this store belongs to.
    pub(crate) libctx: *mut c_void,
    /// The **sorted** stack of providers.
    pub(crate) providers: *mut OpenSslStack,
    /// The stack of `OSSL_PROVIDER_CHILD_CB`, registered by 6.8e.
    pub(crate) child_cbs: *mut OpenSslStack,
    /// Guards `default_path`.
    pub(crate) default_path_lock: *mut CryptoRwlock,
    /// Guards `providers` and `child_cbs`.
    pub(crate) lock: *mut CryptoRwlock,
    /// The default module search path, owned.
    pub(crate) default_path: *mut c_char,
    /// The registered builtin table, owned; `provinfosz` entries are allocated.
    pub(crate) provinfo: *mut OsslProviderInfo,
    /// How many entries are live.
    pub(crate) numprovinfo: usize,
    /// How many are allocated.
    pub(crate) provinfosz: usize,
    /// `use_fallbacks : 1` — cleared by `ossl_provider_disable_fallback_loading` and by a
    /// non-retaining `ossl_provider_add_to_store`.
    pub(crate) use_fallbacks: c_uint,
    /// `freeing : 1` — set while the store is being torn down, and never cleared.
    pub(crate) freeing: c_uint,
}

/// `strcmp` on two NUL-terminated strings.
///
/// # Safety
/// Both must be NUL-terminated.
unsafe fn c_strcmp(a: *const c_char, b: *const c_char) -> c_int {
    let mut i = 0isize;
    loop {
        // SAFETY: both are NUL-terminated, so the walk stops at or before their
        // terminators.
        let ca = unsafe { *a.offset(i) } as u8;
        // SAFETY: as above.
        let cb = unsafe { *b.offset(i) } as u8;
        if ca != cb {
            return c_int::from(ca) - c_int::from(cb);
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
}

/// `static int ossl_provider_cmp(const OSSL_PROVIDER *const *a, const OSSL_PROVIDER *const *b)`
///
/// The parameters are **addresses of stack slots**, so each is dereferenced once to reach
/// the provider and once more to reach its name. The order is `strcmp`, so a store is sorted
/// by byte value and not by length or insertion order.
///
/// # Safety
/// Both parameters must be pointers to slots of a `*mut OsslProvider` stack, and each slot's
/// provider must be live with a NUL-terminated `name`.
unsafe extern "C" fn ossl_provider_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the caller's contract is that these are slot addresses, so each is a slot of
    // a `*mut OsslProvider` stack.
    let pa = unsafe { *(a as *const *mut OsslProvider) };
    // SAFETY: as above.
    let pb = unsafe { *(b as *const *mut OsslProvider) };
    // SAFETY: both providers are live with NUL-terminated names.
    unsafe { c_strcmp((*pa).name, (*pb).name) }
}

/// The comparator's signature, asserted rather than assumed.
///
/// `OPENSSL_sk_new` takes the comparator through `crate::runtime::stack`'s own private
/// alias, so a coercion happens at the call site and nothing would notice if this
/// function's signature drifted. This makes the drift a compile error instead — the same
/// reasoning as `ABI-PROTOTYPE`, applied to the one function-pointer field in this file
/// that is passed as a value rather than cast.
const _: SkCompFn = ossl_provider_cmp;

/// `static void infopair_free(INFOPAIR *pair)`.
///
/// # Safety
/// `p` must be NULL or a live `InfoPair` made by `infopair_copy` or `infopair_add`.
unsafe extern "C" fn infopair_free(p: *mut c_void) {
    let pair = p.cast::<InfoPair>();
    if pair.is_null() {
        return;
    }
    // SAFETY: `pair` is live, so both fields are NULL or owned allocations.
    unsafe {
        if !(*pair).name.is_null() {
            CRYPTO_free((*pair).name.cast::<c_void>(), FILE, lines::L_PAIR_FREE_NAME);
        }
        if !(*pair).value.is_null() {
            CRYPTO_free(
                (*pair).value.cast::<c_void>(),
                FILE,
                lines::L_PAIR_FREE_VALUE,
            );
        }
        CRYPTO_free(pair.cast::<c_void>(), FILE, lines::L_PAIR_FREE);
    }
}

/// `static INFOPAIR *infopair_copy(const INFOPAIR *src)`.
///
/// The authority's `err:` arm frees `dest->name` and `dest` but not `dest->value`, because
/// the only way to arrive there with a value set is a failed `OPENSSL_strdup` for it. The
/// two paths are written as one here: at either arrival `value` is NULL, so [`infopair_free`]
/// performs exactly the same three tests.
///
/// # Safety
/// `p` must be a live `InfoPair`.
unsafe extern "C" fn infopair_copy(p: *const c_void) -> *mut c_void {
    let src = p.cast::<InfoPair>();
    // SAFETY: a fresh zeroed block of exactly this type.
    let dest = CRYPTO_zalloc(core::mem::size_of::<InfoPair>(), FILE, lines::L_PAIR_COPY)
        .cast::<InfoPair>();
    if dest.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dest` is a fresh block and `src` is live per the contract, so both its
    // fields are NULL or NUL-terminated.
    unsafe {
        if !(*src).name.is_null() {
            (*dest).name = CRYPTO_strdup((*src).name, FILE, lines::L_PAIR_COPY_NAME);
            if (*dest).name.is_null() {
                infopair_free(dest.cast::<c_void>());
                return ptr::null_mut();
            }
        }
        if !(*src).value.is_null() {
            (*dest).value = CRYPTO_strdup((*src).value, FILE, lines::L_PAIR_COPY_VALUE);
            if (*dest).value.is_null() {
                infopair_free(dest.cast::<c_void>());
                return ptr::null_mut();
            }
        }
    }
    dest.cast::<c_void>()
}

/// `static int infopair_add(STACK_OF(INFOPAIR) **infopairsk, const char *name,
/// const char *value)`.
///
/// A missing stack is created on the way in, so the caller passes the address of its own
/// field. A failure after the pair is built frees the pair and leaves the stack as it found
/// it — **except** that a stack this call created is kept, which is the authority's
/// behaviour: the creation and the push are separate steps and only the push's failure has
/// an error site.
///
/// # Safety
/// `infopairsk` must be writable; `name` and `value` must be NUL-terminated.
pub(crate) unsafe fn infopair_add(
    infopairsk: *mut *mut OpenSslStack,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: a fresh zeroed block of exactly this type.
    let pair =
        CRYPTO_zalloc(core::mem::size_of::<InfoPair>(), FILE, lines::L_PAIR_ADD).cast::<InfoPair>();
    if pair.is_null() {
        return 0;
    }
    // SAFETY: `pair` is a fresh block; both strings are NUL-terminated per the contract.
    unsafe {
        (*pair).name = CRYPTO_strdup(name, FILE, lines::L_PAIR_ADD_NAME);
        if (*pair).name.is_null() {
            CRYPTO_free(pair.cast::<c_void>(), FILE, lines::L_PAIR_ADD);
            return 0;
        }
        (*pair).value = CRYPTO_strdup(value, FILE, lines::L_PAIR_ADD_VALUE);
        if (*pair).value.is_null() {
            CRYPTO_free(
                (*pair).name.cast::<c_void>(),
                FILE,
                lines::L_PAIR_ADD_ERR_NAME,
            );
            CRYPTO_free(
                (*pair).value.cast::<c_void>(),
                FILE,
                lines::L_PAIR_ADD_ERR_VALUE,
            );
            CRYPTO_free(pair.cast::<c_void>(), FILE, lines::L_PAIR_ADD_ERR);
            return 0;
        }
        if (*infopairsk).is_null() {
            *infopairsk = OPENSSL_sk_new_null();
            if (*infopairsk).is_null() {
                infopair_free(pair.cast::<c_void>());
                return 0;
            }
        }
        if OPENSSL_sk_push(*infopairsk, pair.cast::<c_void>()) <= 0 {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::PROVIDER_CORE_816);
            infopair_free(pair.cast::<c_void>());
            return 0;
        }
    }
    1
}

/// `void ossl_provider_info_clear(OSSL_PROVIDER_INFO *info)`.
///
/// The three fields are cleared as well as released, so a double clear on the same entry is
/// a no-op rather than a double free — which matters because the store's teardown clears
/// every entry it holds and the array is then released whole.
///
/// # Safety
/// `info` must be a live `OsslProviderInfo`.
pub(crate) unsafe fn ossl_provider_info_clear(info: *mut OsslProviderInfo) {
    // SAFETY: `info` is live, so its two strings are NULL or owned and its stack is NULL or
    // one this crate built.
    unsafe {
        if !(*info).name.is_null() {
            CRYPTO_free(
                (*info).name.cast::<c_void>(),
                FILE,
                lines::L_INFO_CLEAR_NAME,
            );
        }
        if !(*info).path.is_null() {
            CRYPTO_free(
                (*info).path.cast::<c_void>(),
                FILE,
                lines::L_INFO_CLEAR_PATH,
            );
        }
        OPENSSL_sk_pop_free((*info).parameters, Some(infopair_free));
        (*info).name = ptr::null_mut();
        (*info).path = ptr::null_mut();
        (*info).parameters = ptr::null_mut();
    }
}

/// `int ossl_provider_info_add_parameter(OSSL_PROVIDER_INFO *provinfo, const char *name,
/// const char *value)`.
///
/// # Safety
/// `provinfo` must be live; both strings NUL-terminated.
pub(crate) unsafe fn ossl_provider_info_add_parameter(
    provinfo: *mut OsslProviderInfo,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: `provinfo` is live, so the address of its `parameters` field is valid for the
    // duration of the call.
    unsafe { infopair_add(ptr::addr_of_mut!((*provinfo).parameters), name, value) }
}

/// `static void ossl_provider_child_cb_free(OSSL_PROVIDER_CHILD_CB *cb)`.
///
/// The struct is 6.8e's; this frees the allocation and nothing inside it, which is what the
/// authority does — the callbacks belong to the registrant, not to the store.
///
/// # Safety
/// `p` must be NULL or an allocation from 6.8e's registration path.
unsafe extern "C" fn child_cb_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: the block came from this crate's allocator in 6.8e.
    unsafe { CRYPTO_free(p, FILE, lines::L_CHILD_CB_FREE) };
}

/// The coordinates `ossl_provider_register_child_cb` allocates and frees at.
mod child_cb_lines {
    /// `child_cb = OPENSSL_malloc(sizeof(*child_cb))`.
    pub(super) const L_CB_ALLOC: core::ffi::c_int = 2138;
    /// `OPENSSL_free(child_cb)` in the lock-failure arm and in the rollback.
    pub(super) const L_CB_FREE: core::ffi::c_int = 2151;
    /// `OPENSSL_free(child_cb)` in the rollback arm.
    pub(super) const L_CB_FREE_ROLLBACK: core::ffi::c_int = 2189;
}

use crate::provider::activate::ProviderChildCb;

/// `static int ossl_provider_register_child_cb(const OSSL_CORE_HANDLE *handle, ...)`.
///
/// The **parent side** of the child mechanism: a third-party provider that wants its own
/// library context to see its providers calls this — through the core dispatch entry
/// `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB`, which is what publishes it — and the core records
/// the three callbacks against the provider the handle names.
///
/// The body is a walk of the store's already-activated providers, calling `create_cb` for
/// each under the **store lock**, with the authority's own justification: *"We hold the store
/// lock while calling the user callback... the user callback must be short and simple."* The
/// `flag_lock` is taken and released per provider so a concurrent deactivation is possible,
/// which the authority accepts because the other thread then calls `remove_cb`.
///
/// One line of the authority's is not written: `propsstr = evp_get_global_properties_str(
/// libctx, 0)` and the `global_props_cb(propsstr, cbdata)` call that follows. That function is
/// `crypto/evp/evp_fetch.c`'s and therefore **Phase 7's**, and it is a recorded deferral in
/// `forensics/prerequisites.json`. The consequence is observable and recorded as
/// `D-CHILD-REGISTER-PROPS-1`: a parent with global properties does not hand them to the
/// child at registration time, so the child's default property query stays unset where the
/// authority would set it. Everything else — the allocation, the identity recorded, the walk,
/// the per-provider `create_cb`, the rollback that calls `remove_cb` for every provider it had
/// already handed over, and the push — is the authority's.
///
/// # Safety
/// `handle` must be the `OSSL_PROVIDER *` of the registering parent; `cbdata` is opaque to
/// this function and is passed back to every callback.
pub(crate) unsafe fn ossl_provider_register_child_cb(
    handle: *const c_void,
    create_cb: Option<crate::provider::child::CreateChildCbFn>,
    remove_cb: Option<crate::provider::child::RemoveChildCbFn>,
    global_props_cb: Option<crate::provider::child::GlobalPropsCbFn>,
    cbdata: *mut c_void,
) -> c_int {
    // The cast the authority's comment justifies: the handle *is* the provider object.
    let thisprov = handle.cast::<OsslProvider>().cast_mut();
    // SAFETY: `thisprov` is live per the caller's contract.
    let libctx = unsafe { (*thisprov).libctx };
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }

    // `OPENSSL_malloc`, which is a macro over `CRYPTO_malloc` that fills in the file and
    // line at the call site — which is why this needs no `unsafe` block.
    let child_cb = CRYPTO_malloc(
        core::mem::size_of::<ProviderChildCb>(),
        FILE,
        child_cb_lines::L_CB_ALLOC,
    )
    .cast::<ProviderChildCb>();
    if child_cb.is_null() {
        return 0;
    }
    // SAFETY: `child_cb` is this call's own fresh block.
    unsafe {
        (*child_cb).prov = thisprov;
        (*child_cb).create_cb = create_cb;
        (*child_cb).remove_cb = remove_cb;
        (*child_cb).global_props_cb = global_props_cb;
        (*child_cb).cbdata = cbdata;
    }

    // SAFETY: `store` is live, so its lock exists.
    if unsafe { CRYPTO_THREAD_write_lock((*store).lock) } == 0 {
        // SAFETY: `child_cb` is this call's own allocation.
        unsafe { CRYPTO_free(child_cb.cast::<c_void>(), FILE, child_cb_lines::L_CB_FREE) };
        return 0;
    }

    // `evp_get_global_properties_str` and its `global_props_cb` call are Phase 7's; see the
    // documentation for the recorded divergence.

    // SAFETY: `store` is live and its lock is held, so the provider list is this thread's to
    // read. `i` is the authority's loop variable and is deliberately visible after the loop,
    // because the rollback below starts from wherever it stopped.
    // SAFETY: `store` is live, so its provider list is a live stack.
    let max = unsafe { OPENSSL_sk_num((*store).providers) };
    // SAFETY: `store` is live and its lock is held by this thread, so the provider list and
    // each provider's flag lock are this thread's to read, and `child_cbs` is this thread's
    // to push onto.
    let (ret, mut i) = unsafe {
        let mut i = 0;
        let mut ret: c_int = 0;
        while i < max {
            let prov = OPENSSL_sk_value((*store).providers, i).cast::<OsslProvider>();
            if CRYPTO_THREAD_read_lock((*prov).flag_lock) == 0 {
                break;
            }
            let activated = (*prov).flags & FLAG_ACTIVATED != 0;
            CRYPTO_THREAD_unlock((*prov).flag_lock);
            let Some(create) = create_cb else { break };
            if activated && create(prov.cast::<c_void>(), cbdata) == 0 {
                break;
            }
            i += 1;
        }
        if i == max {
            // Success: record the registration.
            ret = OPENSSL_sk_push((*store).child_cbs, child_cb.cast::<c_void>());
        }
        (ret, i)
    };

    if i != max || ret <= 0 {
        // The rollback: every provider the loop already handed over is handed back, walking
        // *downwards* from where it stopped, and then the registration block is released.
        // SAFETY: `store` is live and its lock is held.
        unsafe {
            while i >= 0 {
                let prov = OPENSSL_sk_value((*store).providers, i).cast::<OsslProvider>();
                if let Some(remove) = remove_cb {
                    remove(prov.cast::<c_void>(), cbdata);
                }
                i -= 1;
            }
            CRYPTO_free(
                child_cb.cast::<c_void>(),
                FILE,
                child_cb_lines::L_CB_FREE_ROLLBACK,
            );
        }
        // The rollback reports failure whatever `ret` was; the authority assigns 0.
        // SAFETY: `store` is live and its lock is held.
        unsafe { CRYPTO_THREAD_unlock((*store).lock) };
        return 0;
    }

    // SAFETY: `store` is live and its lock is held.
    unsafe { CRYPTO_THREAD_unlock((*store).lock) };
    // The **push's own answer**, which is the new length of `store->child_cbs` and not a
    // boolean: the authority writes `ret = sk_OSSL_PROVIDER_CHILD_CB_push(...)` and returns
    // `ret`. So the first registration answers 1, the second 2, and a caller can tell how many
    // parents are already registered. This returned a literal `1` until `RT-PROVIDER-3P`
    // measured it, because a registration that succeeds and a count that is one look identical
    // when only one parent ever registers -- and the authority's own child, which registers
    // during `ossl_provider_init_as_child`, is exactly the second one.
    ret
}

/// `static void ossl_provider_deregister_child_cb(const OSSL_CORE_HANDLE *handle)`.
///
/// Finds the registration by **provider identity** — the first entry whose `prov` is the
/// handle's own object — deletes it from the stack and releases the block. The three
/// callbacks are not called on the way out: a deregistration is a parent withdrawing its
/// consent, not a teardown of what it was shown.
///
/// # Safety
/// `handle` must be the `OSSL_PROVIDER *` of a parent that registered.
pub(crate) unsafe fn ossl_provider_deregister_child_cb(handle: *const c_void) {
    let thisprov = handle.cast::<OsslProvider>().cast_mut();
    // SAFETY: `thisprov` is live per the caller's contract.
    let libctx = unsafe { (*thisprov).libctx };
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return;
    }
    // SAFETY: `store` is live, so its lock exists.
    if unsafe { CRYPTO_THREAD_write_lock((*store).lock) } == 0 {
        return;
    }

    // SAFETY: `store` is live and its lock is held.
    unsafe {
        let max = OPENSSL_sk_num((*store).child_cbs);
        let mut i = 0;
        while i < max {
            let child_cb = OPENSSL_sk_value((*store).child_cbs, i).cast::<ProviderChildCb>();
            if (*child_cb).prov == thisprov {
                OPENSSL_sk_delete((*store).child_cbs, i);
                CRYPTO_free(child_cb.cast::<c_void>(), FILE, child_cb_lines::L_CB_FREE);
                break;
            }
            i += 1;
        }
        CRYPTO_THREAD_unlock((*store).lock);
    }
}

/// `void *ossl_provider_store_new(OSSL_LIB_CTX *ctx)`.
///
/// The construction order is load-bearing: the providers stack is built **with the
/// comparator**, then the default-path lock, then the child-callback stack, then the store
/// lock. A failure at any step calls [`ossl_provider_store_free`] on the partial object,
/// which is why that function tolerates NULL fields and a NULL store.
///
/// # Safety
/// `ctx` is stored and never dereferenced.
pub(crate) unsafe fn ossl_provider_store_new(ctx: *mut c_void) -> *mut c_void {
    // SAFETY: a fresh zeroed block of exactly this type.
    let store = CRYPTO_zalloc(
        core::mem::size_of::<ProviderStore>(),
        FILE,
        lines::L_STORE_NEW,
    )
    .cast::<ProviderStore>();
    if store.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `store` is a fresh zeroed block this function owns, so every field write below
    // is to uninitialised-owned storage.
    let built = unsafe {
        (*store).providers = OPENSSL_sk_new(Some(ossl_provider_cmp));
        if (*store).providers.is_null() {
            false
        } else {
            (*store).default_path_lock = CRYPTO_THREAD_lock_new();
            if (*store).default_path_lock.is_null() {
                false
            } else {
                (*store).child_cbs = OPENSSL_sk_new_null();
                if (*store).child_cbs.is_null() {
                    false
                } else {
                    (*store).lock = CRYPTO_THREAD_lock_new();
                    !(*store).lock.is_null()
                }
            }
        }
    };
    if !built {
        // SAFETY: `store` is the partially built object above, so the free below sees NULL
        // for the fields that were never reached.
        unsafe { ossl_provider_store_free(store.cast::<c_void>()) };
        return ptr::null_mut();
    }
    // SAFETY: `store` is live and exclusively owned.
    unsafe {
        (*store).libctx = ctx;
        (*store).use_fallbacks = 1;
    }
    store.cast::<c_void>()
}

/// `void ossl_provider_store_free(void *vstore)`.
///
/// `freeing` is set **first**, before anything is released, and is never cleared: 6.8e's
/// child callbacks read it to tell a real removal from part of the teardown.
///
/// Each pointer is cleared as it is released, so a second call over the same object is a
/// no-op rather than a double free — which the partial-construction path relies on.
///
/// # Safety
/// `vstore` must be NULL or a store from [`ossl_provider_store_new`].
pub(crate) unsafe fn ossl_provider_store_free(vstore: *mut c_void) {
    let store = vstore.cast::<ProviderStore>();
    if store.is_null() {
        return;
    }
    // SAFETY: `store` is live, so each field is NULL or owned by it.
    unsafe {
        (*store).freeing = 1;
        if !(*store).default_path.is_null() {
            CRYPTO_free(
                (*store).default_path.cast::<c_void>(),
                FILE,
                lines::L_STORE_FREE_PATH,
            );
        }
        (*store).default_path = ptr::null_mut();
        OPENSSL_sk_pop_free((*store).providers, Some(provider_deactivate_free));
        (*store).providers = ptr::null_mut();
        OPENSSL_sk_pop_free((*store).child_cbs, Some(child_cb_free));
        (*store).child_cbs = ptr::null_mut();
        CRYPTO_THREAD_lock_free((*store).default_path_lock);
        CRYPTO_THREAD_lock_free((*store).lock);
        (*store).default_path_lock = ptr::null_mut();
        (*store).lock = ptr::null_mut();
        let mut i = 0usize;
        while i < (*store).numprovinfo {
            ossl_provider_info_clear((*store).provinfo.add(i));
            i += 1;
        }
        (*store).numprovinfo = 0;
        if !(*store).provinfo.is_null() {
            CRYPTO_free(
                (*store).provinfo.cast::<c_void>(),
                FILE,
                lines::L_STORE_FREE_PROVINFO,
            );
        }
        (*store).provinfo = ptr::null_mut();
        (*store).provinfosz = 0;
        CRYPTO_free(store.cast::<c_void>(), FILE, lines::L_STORE_FREE);
    }
}

/// `static void provider_deactivate_free(OSSL_PROVIDER *prov)`.
///
/// The authority's wrapper calls `ossl_provider_deactivate(prov, 1)` when the provider is
/// activated and then `ossl_provider_free(prov)`. The deactivation is 6.8c's, and it is
/// **named where it would go** rather than skipped silently: `flag_activated` is set only by
/// 6.8c's `provider_activate`, so no object this subphase can build reaches that arm, and
/// 6.8c must add the call here — the store's teardown is this function's only caller.
///
/// # Safety
/// `p` must be NULL or a live provider.
unsafe extern "C" fn provider_deactivate_free(p: *mut c_void) {
    let prov = p.cast::<OsslProvider>();
    if prov.is_null() {
        return;
    }
    // The guard is `flag_activated`, read **without** `flag_lock`: this runs during the store's
    // teardown, when nothing else can be looking at the provider, and the authority reads the
    // bit directly for the same reason.
    // SAFETY: `prov` is live.
    if unsafe { (*prov).flags } & FLAG_ACTIVATED != 0 {
        // SAFETY: `prov` is live. The answer is discarded: this is a teardown path and there
        // is no caller to report to.
        unsafe { crate::provider::activate::ossl_provider_deactivate(prov, 1) };
    }
    // SAFETY: `prov` is live.
    unsafe { ossl_provider_free(prov) };
}

/// The slot-1 cast, spelled once so the pointer conversion is in one place.
///
/// # Safety
/// `libctx` must be NULL or a live context.
unsafe fn provider_store_slot(libctx: *mut c_void) -> *mut ProviderStore {
    lib_ctx_get_data(libctx, PROVIDER_STORE_INDEX).cast::<ProviderStore>()
}

/// `static struct provider_store_st *get_provider_store(OSSL_LIB_CTX *libctx)`.
///
/// Slot 1, or NULL with `ERR_R_INTERNAL_ERROR`. This function cannot distinguish "the
/// context has no store" from "there is no context", because `ossl_lib_ctx_get_data`
/// answers NULL for both, so it reports the internal error the authority reports.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn get_provider_store(libctx: *mut c_void) -> *mut ProviderStore {
    // SAFETY: `libctx` is NULL or live per the contract.
    let store = unsafe { provider_store_slot(libctx) };
    if store.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_CORE_335) };
    }
    store
}

/// `int ossl_provider_disable_fallback_loading(OSSL_LIB_CTX *libctx)`.
///
/// Answers 1 only when the store exists *and* the lock was taken, so a context with no store
/// is an error here rather than a no-op.
///
/// # Safety
/// `libctx` must be NULL or live.
pub(crate) unsafe fn ossl_provider_disable_fallback_loading(libctx: *mut c_void) -> c_int {
    // SAFETY: `libctx` is NULL or live; `get_provider_store` raises in the NULL answer's
    // case.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so `lock` was created by `ossl_provider_store_new`.
    unsafe {
        if CRYPTO_THREAD_write_lock((*store).lock) == 0 {
            return 0;
        }
        (*store).use_fallbacks = 0;
        CRYPTO_THREAD_unlock((*store).lock);
    }
    1
}

/// `int ossl_provider_info_add_to_store(OSSL_LIB_CTX *libctx, OSSL_PROVIDER_INFO *entry)`.
///
/// The entry is **moved**, not copied: `store->provinfo[numprovinfo] = *entry` is a struct
/// assignment, so ownership of `name`, `path` and `parameters` passes to the store. The array
/// starts at `BUILTINS_BLOCK_SIZE` entries and grows by that much, so capacity is never zero
/// once a name has been accepted.
///
/// The two refusals are ordered: a NULL name is `ERR_R_PASSED_NULL_PARAMETER`, a missing
/// store is `ERR_R_INTERNAL_ERROR`, and the name check comes **first**.
///
/// # Safety
/// `libctx` NULL or live; `entry` live and writable.
pub(crate) unsafe fn ossl_provider_info_add_to_store(
    libctx: *mut c_void,
    entry: *mut OsslProviderInfo,
) -> c_int {
    // SAFETY: `entry` is live per the contract.
    if unsafe { (*entry).name }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_CORE_362) };
        return 0;
    }
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_CORE_367) };
        return 0;
    }
    // SAFETY: `store` is live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*store).lock) == 0 {
            return 0;
        }
        if (*store).provinfosz == 0 {
            let p = CRYPTO_calloc(
                BUILTINS_BLOCK_SIZE,
                core::mem::size_of::<OsslProviderInfo>(),
                FILE,
                lines::L_INFO_ADD_CALLOC,
            )
            .cast::<OsslProviderInfo>();
            if p.is_null() {
                CRYPTO_THREAD_unlock((*store).lock);
                return 0;
            }
            (*store).provinfo = p;
            (*store).provinfosz = BUILTINS_BLOCK_SIZE;
        } else if (*store).numprovinfo == (*store).provinfosz {
            let newsz = (*store).provinfosz + BUILTINS_BLOCK_SIZE;
            let tmp = CRYPTO_realloc_array(
                (*store).provinfo.cast::<c_void>(),
                newsz,
                core::mem::size_of::<OsslProviderInfo>(),
                FILE,
                lines::L_INFO_ADD_REALLOC,
            )
            .cast::<OsslProviderInfo>();
            if tmp.is_null() {
                CRYPTO_THREAD_unlock((*store).lock);
                return 0;
            }
            (*store).provinfo = tmp;
            (*store).provinfosz = newsz;
        }
        ptr::copy_nonoverlapping(entry, (*store).provinfo.add((*store).numprovinfo), 1);
        (*store).numprovinfo += 1;
        CRYPTO_THREAD_unlock((*store).lock);
    }
    1
}

/// A zeroed provider template, which is what `ossl_provider_find` searches with and what
/// [`ossl_provider`]-shaped tests start from.
///
/// The authority writes `OSSL_PROVIDER tmpl = { 0, };` and then sets only `name`, so every
/// other field is zero. Spelling that out here is what makes the search key a value rather
/// than a caller-owned object with stray fields.
pub(crate) fn blank_provider() -> OsslProvider {
    OsslProvider {
        flags: 0,
        flag_lock: ptr::null_mut(),
        refcnt: AtomicI32::new(0),
        activatecnt_lock: ptr::null_mut(),
        activatecnt: 0,
        name: ptr::null_mut(),
        path: ptr::null_mut(),
        module: ptr::null_mut(),
        init_function: None,
        parameters: ptr::null_mut(),
        libctx: ptr::null_mut(),
        store: ptr::null_mut(),
        error_lib: 0,
        error_strings: ptr::null_mut(),
        teardown: ptr::null_mut(),
        gettable_params: ptr::null_mut(),
        get_params: ptr::null_mut(),
        get_capabilities: ptr::null_mut(),
        self_test: ptr::null_mut(),
        random_bytes: ptr::null_mut(),
        query_operation: ptr::null_mut(),
        unquery_operation: ptr::null_mut(),
        operation_bits: ptr::null_mut(),
        operation_bits_sz: 0,
        opbits_lock: ptr::null_mut(),
        handle: ptr::null(),
        ischild: 0,
        provctx: ptr::null_mut(),
        dispatch: ptr::null(),
    }
}

/// A zeroed `OSSL_PROVIDER_INFO`, which is what both `ossl_provider_new`'s template and
/// `OSSL_PROVIDER_add_builtin`'s entry start as — the authority writes `memset(&entry, 0,
/// sizeof(entry))` in both places.
pub(crate) fn blank_info() -> OsslProviderInfo {
    OsslProviderInfo {
        name: ptr::null_mut(),
        path: ptr::null_mut(),
        init: None,
        parameters: ptr::null_mut(),
        is_fallback: 0,
    }
}

/// One row of [`PREDEFINED_PROVIDERS`], with the name as a `CStr` so the table carries
/// nothing that needs freeing and a reader can see every row at a glance.
///
/// The authority's row also carries `path` (NULL for all of them) and `parameters` (NULL for
/// all of them), which are absent rather than spelled as NULL fields because the C comment
/// says *"These compile-time templates always have NULL parameters"*.
pub(crate) struct PredefinedProvider {
    /// The provider's name as a literal; the terminator row's is empty.
    pub(crate) name: &'static core::ffi::CStr,
    /// The authority's `is_fallback : 1`.
    pub(crate) is_fallback: c_uint,
    /// The provider's compiled-in entry point, or `None` where it has not landed yet.
    ///
    /// `default` names [`crate::provider::digest::ossl_default_provider_init`], which 8.1b
    /// landed. `base` and `null` name `ossl_base_provider_init` and
    /// `ossl_null_provider_init`, which are other subphases' and are still `None`: a row
    /// whose entry point does not exist cannot publish a table, and naming one here would
    /// make the registry depend on every algorithm in the library.
    pub(crate) init: Option<ProviderInitFn>,
}

/// `const OSSL_PROVIDER_INFO ossl_predefined_providers[]` — `crypto/provider_predefined.c`.
///
/// **This profile's table has three rows, not four**, and that is a build fact rather than
/// a reading of the source's `#ifdef`s: `configdata.pm` records `enable-shared
/// enable-legacy`, so `STATIC_LEGACY` is *not* defined and the `legacy` row is compiled out.
/// Legacy is a module this build loads by name, which is why `DSO` had to land before the
/// registry could drive it.
///
/// `is_fallback` is 1 for `default` and 0 for `base` and `null`. That one bit is what
/// `provider_activate_fallbacks` uses to decide what to load when nothing has been asked for
/// (6.8c), so `default` is what an operation with no explicit `OSSL_PROVIDER_load` gets --
/// and `base`, which declares no algorithms of its own, is not.
///
/// **The `default` row carries its entry point; `base` and `null` are `None`.** The three
/// authority rows name `ossl_default_provider_init`, `ossl_base_provider_init` and
/// `ossl_null_provider_init` in `providers/`. `default`'s digest half landed with 8.1b, so it
/// is named here and the fallback walk activates `default` instead of failing at `DSO_load`;
/// `base` and `null` are still 7/8's and their absence is recorded rather than hidden -- a
/// `provider_new` for either receives `None` and `provider_init` takes the `DSO` branch, which
/// is the remaining part of D117's residual.
///
/// `is_fallback` is 1 for `default` and 0 for `base` and `null`. That one bit is what
/// `provider_activate_fallbacks` uses to decide what to load when nothing has been asked for
/// (6.8c), so `default` is what an operation with no explicit `OSSL_PROVIDER_load` gets --
/// and `base`, which declares no algorithms of its own, is not.
pub(crate) static PREDEFINED_PROVIDERS: [PredefinedProvider; 4] = [
    PredefinedProvider {
        name: c"default",
        is_fallback: 1,
        init: Some(crate::provider::digest::ossl_default_provider_init),
    },
    PredefinedProvider {
        name: c"base",
        is_fallback: 0,
        init: None,
    },
    PredefinedProvider {
        name: c"null",
        is_fallback: 0,
        init: None,
    },
    // The authority's terminator: `{ NULL, NULL, NULL, NULL, 0 }`.
    PredefinedProvider {
        name: c"",
        is_fallback: 0,
        init: None,
    },
];

/// The row whose name matches, or `None` at the terminator.
///
/// A linear scan, as the authority's loop is, stopping at the first match: two rows sharing a
/// name would leave the second unreachable, which is the authority's behaviour as well.
fn predefined_row(name: *const c_char) -> Option<&'static PredefinedProvider> {
    for row in PREDEFINED_PROVIDERS.iter() {
        if row.name.to_bytes().is_empty() {
            return None;
        }
        // SAFETY: `name` is NUL-terminated per every caller's contract, and `row.name` is a
        // literal with a terminator.
        if unsafe { c_strcmp(name, row.name.as_ptr()) } == 0 {
            return Some(row);
        }
    }
    None
}

/// `int OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX *libctx, const char *name,
/// OSSL_provider_init_fn *init_fn)`.
///
/// Two NULL checks, both `ERR_R_PASSED_NULL_PARAMETER` **before** anything is allocated, so a
/// refusal costs nothing. The name is dup'd into the *entry*, and the entry is then moved into
/// the store by [`ossl_provider_info_add_to_store`] — so the failure arm has to clear the
/// entry itself, which is what releases that dup.
///
/// This is the only way a caller registers a provider without a shared object, and it is
/// therefore the surface `RT-PROVIDER` can exercise before any provider module exists on
/// either side: the probe declares its own `init` function, registers it, and the registry
/// mechanics become observable without a single built-in provider.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated; `init_fn` non-NULL.
pub(crate) unsafe fn ossl_provider_add_builtin(
    libctx: *mut c_void,
    name: *const c_char,
    init_fn: Option<ProviderInitFn>,
) -> c_int {
    if name.is_null() || init_fn.is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_132) };
        return 0;
    }
    let mut entry = blank_info();
    // SAFETY: `name` is NUL-terminated per the contract.
    entry.name = unsafe { CRYPTO_strdup(name, FILE_PROVIDER, lines::L_ADD_BUILTIN_DUP) };
    if entry.name.is_null() {
        return 0;
    }
    entry.init = init_fn;
    // SAFETY: `entry` is a live local, so its address is valid for the call; the store takes
    // ownership of its owned fields on success.
    let added = unsafe { ossl_provider_info_add_to_store(libctx, ptr::addr_of_mut!(entry)) };
    if added == 0 {
        // SAFETY: the store did not take the entry, so its name is still ours.
        unsafe { ossl_provider_info_clear(ptr::addr_of_mut!(entry)) };
        return 0;
    }
    1
}

/// `OSSL_PROVIDER *ossl_provider_new(OSSL_LIB_CTX *libctx, const char *name,
/// OSSL_provider_init_fn *init_function, OSSL_PARAM *params, int noconfig)`.
///
/// The constructor callers actually use, and the merge rule is the whole of it. With a NULL
/// `init_function` it resolves `name` twice — once against the compiled-in predefined table
/// and once against the store's registered builtins — and the two resolutions do different
/// things:
///
/// * a **predefined** match supplies the name, path and init, and the store entry may then
///   contribute only *parameters*;
/// * a **store** match contributes all of them.
///
/// The parameter rule inside the store loop is the one that is easy to soften:
///
/// ```c
/// if (params != NULL || p->parameters == NULL) { template.parameters = NULL; break; }
/// ```
///
/// An **empty** parameter set is not the same as no parameter set. A caller passing a
/// non-NULL `params` array suppresses the config-file defaults entirely; a caller passing NULL
/// inherits them, unless the entry has none, in which case the template keeps NULL either way.
/// The `break` is unconditional in each arm, so the loop never looks past the first match.
///
/// `params`, when given, is walked and only `OSSL_PARAM_UTF8_STRING` entries are taken — a
/// parameter of any other type is **skipped rather than refused**, which is why a caller may
/// pass a mixed array. The caller's `data` pointer is copied into an `INFOPAIR` as a string
/// and not aliased.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated; `params` NULL or a terminated `OSSL_PARAM`
/// array.
pub(crate) unsafe fn ossl_provider_new(
    libctx: *mut c_void,
    name: *const c_char,
    init_function: Option<ProviderInitFn>,
    params: *mut OsslParam,
    noconfig: c_int,
) -> *mut OsslProvider {
    // `noconfig` is accepted and unused, exactly as in the authority: the parameter exists for
    // `ossl_provider_find`, which this function does not call.
    let _ = noconfig;
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return ptr::null_mut();
    }

    let mut template = blank_info();
    let mut chosen = false;
    if init_function.is_none() {
        if let Some(row) = predefined_row(name) {
            // SAFETY: the row is a literal with a terminator, so its pointer is valid for the
            // program's life; the template does not own it, and `provider_new` dup's it.
            template.name = row.name.as_ptr().cast_mut();
            template.is_fallback = row.is_fallback;
            template.init = row.init;
            chosen = true;
        }
        // SAFETY: `store` is live.
        unsafe {
            if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
                return ptr::null_mut();
            }
            let mut i = 0usize;
            while i < (*store).numprovinfo {
                let p = (*store).provinfo.add(i);
                // SAFETY: `p` is a live entry and both names are NUL-terminated.
                if c_strcmp((*p).name, name) != 0 {
                    i += 1;
                    continue;
                }
                // A predefined provider takes only its *parameters* from the store entry; a
                // registered one takes the whole entry, whose name and path the store owns.
                if !chosen {
                    template.name = (*p).name;
                    template.path = (*p).path;
                    template.init = (*p).init;
                    template.is_fallback = (*p).is_fallback;
                }
                if !params.is_null() || (*p).parameters.is_null() {
                    break;
                }
                // Always copied, never shared: the entry may be mutated later.
                let copied = OPENSSL_sk_deep_copy(
                    (*p).parameters,
                    Some(infopair_copy as SkCopyFn),
                    Some(infopair_free as SkFreeFn),
                );
                if copied.is_null() {
                    CRYPTO_THREAD_unlock((*store).lock);
                    return ptr::null_mut();
                }
                template.parameters = copied;
                break;
            }
            CRYPTO_THREAD_unlock((*store).lock);
        }
    } else {
        template.init = init_function;
    }

    if !params.is_null() {
        // The caller's array replaces whatever the template had, so the template's list -- if
        // any was copied -- is released first. The authority reaches the same state by
        // assigning NULL over it without freeing, which leaks; that is a defect in the
        // authority and is not reproduced.
        if !template.parameters.is_null() {
            // SAFETY: the list was copied for the template and is owned here.
            unsafe { OPENSSL_sk_pop_free(template.parameters, Some(infopair_free)) };
            template.parameters = ptr::null_mut();
        }
        template.parameters = OPENSSL_sk_new_null();
        if template.parameters.is_null() {
            return ptr::null_mut();
        }
        let mut i = 0isize;
        loop {
            // SAFETY: `params` is a terminated array per the contract and `i` walks it.
            let entry = unsafe { &*params.offset(i) };
            if entry.key.is_null() {
                break;
            }
            // Only UTF8 strings are taken; every other type is skipped, not refused.
            if entry.data_type == OSSL_PARAM_UTF8_STRING {
                // SAFETY: the descriptor declares a NUL-terminated string at `data`.
                let ok = unsafe {
                    ossl_provider_info_add_parameter(
                        ptr::addr_of_mut!(template),
                        entry.key,
                        entry.data.cast::<c_char>(),
                    )
                };
                if ok <= 0 {
                    // SAFETY: the list is the one just built and is ours to release.
                    unsafe { OPENSSL_sk_pop_free(template.parameters, Some(infopair_free)) };
                    return ptr::null_mut();
                }
            }
            i += 1;
        }
    }

    // `provider_new` raises its own errors, so nothing is added on failure.
    // SAFETY: `name` is NUL-terminated and `template.parameters` is NULL or a live stack.
    let prov = unsafe { provider_new(name, template.init, template.parameters) };

    if !template.parameters.is_null() {
        // SAFETY: the parameters were copied for the template, so they are ours to release;
        // `provider_new` deep-copied them again.
        unsafe { OPENSSL_sk_pop_free(template.parameters, Some(infopair_free)) };
    }
    if prov.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `prov` is live and `template.path` is NULL or NUL-terminated.
    if unsafe { ossl_provider_set_module_path(prov, template.path) } == 0 {
        // SAFETY: `prov` is live and holds the only reference to itself.
        unsafe { ossl_provider_free(prov) };
        return ptr::null_mut();
    }

    // SAFETY: `prov` is live and exclusively owned.
    unsafe {
        (*prov).libctx = libctx;
        (*prov).error_lib = ERR_get_next_error_library();
    }
    prov
}

/// `OSSL_PROVIDER *ossl_provider_find(OSSL_LIB_CTX *libctx, const char *name, int noconfig)`.
///
/// The answer carries a **new reference**, so a failed up-ref is reported as "not found"
/// rather than as a partially owned object. The sort happens under the store lock and before
/// the find, so the search is a binary search over a stack that may have been pushed into in
/// any order.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated.
pub(crate) unsafe fn ossl_provider_find(
    libctx: *mut c_void,
    name: *const c_char,
    noconfig: c_int,
) -> *mut OsslProvider {
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return ptr::null_mut();
    }
    if noconfig == 0 {
        // SAFETY: `lib_ctx_is_default_symbol` is a SAFE function in this crate and answers 0
        // for NULL, so there is nothing to guard here.
        let is_default = lib_ctx_is_default_symbol(libctx) != 0;
        if is_default {
            // `OPENSSL_init_crypto` is likewise safe in this crate, and this is the same
            // call `a_strnid` makes for the same reason.
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, ptr::null());
        }
    }
    let mut tmpl = blank_provider();
    tmpl.name = name.cast_mut();
    // SAFETY: `tmpl` outlives the search and is not mutated while the lock is held.
    let key: *const c_void = ptr::addr_of!(tmpl).cast::<c_void>();
    // SAFETY: `store` is live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*store).lock) == 0 {
            return ptr::null_mut();
        }
        OPENSSL_sk_sort((*store).providers);
        let mut prov: *mut OsslProvider = ptr::null_mut();
        let i = OPENSSL_sk_find((*store).providers, key);
        if i != -1 {
            prov = OPENSSL_sk_value((*store).providers, i).cast::<OsslProvider>();
        }
        CRYPTO_THREAD_unlock((*store).lock);
        if !prov.is_null() && ossl_provider_up_ref(prov) == 0 {
            prov = ptr::null_mut();
        }
        prov
    }
}

/// `int ossl_provider_add_to_store(OSSL_PROVIDER *prov, OSSL_PROVIDER **actualprov,
/// int retain_fallbacks)`.
///
/// The losing side of a race is handled rather than reported: two threads may each
/// construct a provider with the same name and race to insert it, and the thread that loses
/// **deactivates and frees its own object** and leaves the winner's in the store. The caller
/// that asked for `actualprov` therefore has to be told which object is now authoritative,
/// and this function hands back a *reference* to it.
///
/// Three details are load-bearing:
///
/// * `*actualprov` is NULLed **first**, before any failure path can return, so a caller
///   cannot be left with an uninitialised output on a refusal.
/// * the insertion and `create_provider_children` are inside the lock and the up-ref of the
///   winner is **outside** it — the up-ref can make an upcall, and no lock may be held across
///   one.
/// * `use_fallbacks` is cleared only on a successful *insertion* and only when
///   `retain_fallbacks` is zero, so a losing thread cannot disable the fallback chain.
///
/// Two tails belong to later work and are named rather than approximated: the losing
/// branch calls `ossl_provider_deactivate(prov, 0)` (**6.8c**), and the winning branch ends
/// with `ossl_decoder_cache_flush(prov->libctx)` (**Phase 7**). `create_provider_children`
/// sits inside the winning branch's lock, where the authority puts it, because the insertion
/// it belongs to is undone if a registered parent refuses.
///
/// # Safety
/// `prov` must be live with a non-NULL `libctx`; `actualprov` NULL or writable.
pub(crate) unsafe fn ossl_provider_add_to_store(
    prov: *mut OsslProvider,
    actualprov: *mut *mut OsslProvider,
    retain_fallbacks: c_int,
) -> c_int {
    if !actualprov.is_null() {
        // SAFETY: `actualprov` is writable per the contract.
        unsafe { *actualprov = ptr::null_mut() };
    }
    // SAFETY: `prov` is live.
    let libctx = unsafe { (*prov).libctx };
    // SAFETY: `prov` is live, so `libctx` is the context it was built against.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live, so its name is NUL-terminated.
    let name = unsafe { (*prov).name };
    let mut tmpl = blank_provider();
    tmpl.name = name;
    // SAFETY: `tmpl` outlives the search and is not mutated while the lock is held.
    let key: *const c_void = ptr::addr_of!(tmpl).cast::<c_void>();

    // SAFETY: `store` is live, so `lock` was created by `ossl_provider_store_new` and
    // `providers` is a live stack; `key` points at `tmpl`, which outlives the search.
    let (idx, actualtmp) = unsafe {
        if CRYPTO_THREAD_write_lock((*store).lock) == 0 {
            return 0;
        }
        let idx = OPENSSL_sk_find((*store).providers, key);
        // The object that will be authoritative: the caller's on a free slot, the store's on
        // an occupied one.
        let actualtmp = if idx == -1 {
            prov
        } else {
            OPENSSL_sk_value((*store).providers, idx).cast::<OsslProvider>()
        };
        if idx == -1 {
            if OPENSSL_sk_push((*store).providers, prov.cast::<c_void>()) == 0 {
                CRYPTO_THREAD_unlock((*store).lock);
                return 0;
            }
            (*prov).store = store;
            // The authority's `create_provider_children`, which is where a parent that has
            // registered child callbacks is told that this provider is now active. It is
            // **inside** the store lock, unlike the `provider_activate` call site, because
            // the insertion it belongs to has to be undone if the parent refuses -- and it
            // could not run at all until 6.8e landed `ossl_provider_register_child_cb`,
            // which is the only thing that can push onto `store->child_cbs`. Leaving the
            // call out is not a no-op: `RT-PROVIDER-3P` observes the parent's callback being
            // called from `main`, after `init` has returned, and only this line calls it.
            if crate::provider::activate::create_provider_children(prov) == 0 {
                OPENSSL_sk_delete_ptr((*store).providers, prov.cast::<c_void>());
                CRYPTO_THREAD_unlock((*store).lock);
                return 0;
            }
            if retain_fallbacks == 0 {
                (*store).use_fallbacks = 0;
            }
        }
        CRYPTO_THREAD_unlock((*store).lock);
        (idx, actualtmp)
    };

    if !actualprov.is_null() {
        // The up-ref is outside the lock: it can make an upcall.
        // SAFETY: `actualtmp` is a live provider, either the caller's or the store's.
        if unsafe { ossl_provider_up_ref(actualtmp) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROVIDER_CORE_694) };
            return 0;
        }
        // SAFETY: `actualprov` is writable per the contract.
        unsafe { *actualprov = actualtmp };
    }

    if idx >= 0 {
        // The losing thread's object is deactivated and then freed, and the comment above
        // says why: it was created by this thread and the store's object is the one that will
        // be used. The deactivation is skipped for a provider that was never activated, which
        // is what `flag_activated` distinguishes.
        // SAFETY: `prov` is live.
        if unsafe { (*prov).flags } & FLAG_ACTIVATED != 0 {
            // SAFETY: `prov` is live. The `removechildren` argument is 0 because this thread
            // did not create children — it lost the race before reaching
            // `create_provider_children`'s call site.
            unsafe { crate::provider::activate::ossl_provider_deactivate(prov, 0) };
        }
        // SAFETY: `prov` is the caller's object, which the store did not take.
        unsafe { ossl_provider_free(prov) };
    } else {
        // Outside the lock, and the authority's own comment says why: other threads tolerate
        // getting the wrong result briefly while creating `OSSL_DECODER_CTX`s.
        // SAFETY: `prov` is live, so `libctx` is the context it was built against.
        unsafe { crate::provider::stores::ossl_decoder_cache_flush((*prov).libctx) };
    }
    1
}

/// `static OSSL_PROVIDER *provider_new(const char *name, OSSL_provider_init_fn *init_function,
/// STACK_OF(INFOPAIR) *parameters)`.
///
/// Three locks in a fixed order — `activatecnt_lock`, then `opbits_lock` and `flag_lock`
/// together with the parameter deep-copy, then the name. The first group has its **own**
/// error arm (`ERR_R_CRYPTO_LIB`) and so does the second; the name's has none, because
/// `OPENSSL_strdup` raises its own.
///
/// # Safety
/// `name` NUL-terminated; `parameters` NULL or a live stack.
pub(crate) unsafe fn provider_new(
    name: *const c_char,
    init_function: Option<ProviderInitFn>,
    parameters: *mut OpenSslStack,
) -> *mut OsslProvider {
    // SAFETY: a fresh zeroed block of exactly this type.
    let prov = CRYPTO_zalloc(
        core::mem::size_of::<OsslProvider>(),
        FILE,
        lines::L_PROV_NEW,
    )
    .cast::<OsslProvider>();
    if prov.is_null() {
        return ptr::null_mut();
    }
    // The authority's `CRYPTO_NEW_REF` cannot fail for an inline atomic, so its failure arm
    // (`OPENSSL_free(prov)` at line 450) is unreachable here.
    // SAFETY: `prov` is a fresh block this function owns.
    unsafe { (*prov).refcnt = AtomicI32::new(1) };
    // SAFETY: `prov` is live and exclusively owned.
    let lock_ok = unsafe {
        (*prov).activatecnt_lock = CRYPTO_THREAD_lock_new();
        !(*prov).activatecnt_lock.is_null()
    };
    if !lock_ok {
        // The authority's ordering here is `ossl_provider_free(prov)` **then** the raise.
        // SAFETY: `prov` is live and partially built; `ossl_provider_free` tolerates NULL
        // fields.
        unsafe {
            ossl_provider_free(prov);
            raise_site(&err_sites::PROVIDER_CORE_455);
        }
        return ptr::null_mut();
    }
    // SAFETY: `prov` is live and exclusively owned; `parameters` is NULL or a live stack
    // per the contract.
    let rest_ok = unsafe {
        (*prov).opbits_lock = CRYPTO_THREAD_lock_new();
        (*prov).flag_lock = CRYPTO_THREAD_lock_new();
        (*prov).parameters = OPENSSL_sk_deep_copy(
            parameters,
            Some(infopair_copy as SkCopyFn),
            Some(infopair_free as SkFreeFn),
        );
        !(*prov).opbits_lock.is_null()
            && !(*prov).flag_lock.is_null()
            && !(*prov).parameters.is_null()
    };
    if !rest_ok {
        // SAFETY: `prov` is live and partially built.
        unsafe {
            ossl_provider_free(prov);
            raise_site(&err_sites::PROVIDER_CORE_466);
        }
        return ptr::null_mut();
    }
    // SAFETY: `prov` is live; `name` is NUL-terminated per the contract.
    unsafe {
        (*prov).name = CRYPTO_strdup(name, FILE, lines::L_PROV_NEW_NAME);
        if (*prov).name.is_null() {
            ossl_provider_free(prov);
            return ptr::null_mut();
        }
        (*prov).init_function = init_function;
    }
    prov
}

/// `int ossl_provider_up_ref(OSSL_PROVIDER *prov)`.
///
/// Answers the count *after* the increment, which callers treat as a boolean. A NULL object
/// is a **refusal** here rather than a no-op, unlike `DSO_up_ref`'s counterpart in some
/// other families: this function does not test for NULL at all and the authority's callers
/// never pass one, so the NULL test below is a safety guard for this crate's callers rather
/// than a reproduction.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_up_ref(prov: *mut OsslProvider) -> c_int {
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live.
    let ref_ = unsafe { (*prov).refcnt.fetch_add(1, Ordering::AcqRel) } + 1;
    if ref_ <= 0 {
        return 0;
    }
    // The child arm, and it is a *rollback*: a child's reference is a reference on its
    // parent, and if the parent refuses the count the reference just taken is given back
    // before the caller is told the call failed. That is why the failure path calls
    // `ossl_provider_free` rather than simply answering 0.
    // SAFETY: `prov` is live.
    if unsafe { (*prov).ischild } != 0 {
        // SAFETY: `prov` is live and this call holds the reference taken above.
        if unsafe { crate::provider::child::ossl_provider_up_ref_parent(prov, 0) } == 0 {
            // SAFETY: `prov` is live; this releases the reference taken above.
            unsafe { ossl_provider_free(prov) };
            return 0;
        }
    }
    ref_
}

/// `void ossl_provider_free(OSSL_PROVIDER *prov)`.
///
/// The teardown is deliberately **late** — when the last *reference* goes, not the last
/// activation — because other structures may still hold the provider after it was
/// deactivated and may still need its services.
///
/// Three of the authority's lines are not written; each is named where it goes and the
/// reason is in the module doc.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_free(prov: *mut OsslProvider) {
    if prov.is_null() {
        return;
    }
    // SAFETY: `prov` is live.
    let ref_ = unsafe { (*prov).refcnt.fetch_sub(1, Ordering::AcqRel) } - 1;
    if ref_ != 0 {
        // The child arm: the release of *this* reference is a release of the parent's,
        // and it is made before the early return so that the parent sees one balance
        // for every one it handed out. `ossl_provider_free_parent` answers 1 for a
        // self-referencing child without calling anything.
        // SAFETY: `prov` is live.
        if unsafe { (*prov).ischild } != 0 {
            // SAFETY: `prov` is live.
            unsafe { crate::provider::child::ossl_provider_free_parent(prov, 0) };
        }
        //
        // The whole teardown is inside the authority's `if (ref == 0)`, which is the
        // point of it: "there may be other structures hanging on to the provider after
        // the last deactivation and may therefore need full access to the provider's
        // services. Therefore, we deinit late." A teardown on *every* release would
        // call the provider's `teardown` while other holders were still using it, so
        // the arm below must not be reached from here.
        return;
    }
    // The authority's `if (prov->flag_initialized)` arm: the teardown is what tells the
    // *provider* to release its own state, and it happens on the last reference, while
    // the provider's context and dispatch table are still readable.
    // SAFETY: `prov` is live and this is its last reference, so nothing else can reach it.
    unsafe {
        if (*prov).flags & FLAG_INITIALIZED != 0 {
            crate::provider::init::ossl_provider_teardown(prov);
            if !(*prov).error_strings.is_null() {
                CRYPTO_free(
                    (*prov).error_strings,
                    FILE,
                    lines::L_PROV_FREE_ERROR_STRINGS,
                );
                (*prov).error_strings = ptr::null_mut();
            }
            if !(*prov).operation_bits.is_null() {
                CRYPTO_free(
                    (*prov).operation_bits.cast::<c_void>(),
                    FILE,
                    lines::L_PROV_FREE_OPERATION_BITS,
                );
                (*prov).operation_bits = ptr::null_mut();
            }
            (*prov).operation_bits_sz = 0;
            (*prov).flags &= !FLAG_INITIALIZED;
        }
    }
    // SAFETY: `prov` is live and this is its last reference, so nothing else can reach it.
    // Every field is NULL or owned by construction.
    unsafe {
        // The authority calls this **unconditionally** and *before* the module is released,
        // whether or not initialisation succeeded, because an init that failed may still have
        // registered a thread handler -- and its own comment says so. A handler left registered
        // would run at thread exit against a provider that no longer exists. 6.6e-ii.
        crate::runtime::thread_events::ossl_init_thread_deregister(prov.cast::<c_void>());
        DSO_free((*prov).module);
        if !(*prov).name.is_null() {
            CRYPTO_free((*prov).name.cast::<c_void>(), FILE, lines::L_PROV_FREE_NAME);
        }
        if !(*prov).path.is_null() {
            CRYPTO_free((*prov).path.cast::<c_void>(), FILE, lines::L_PROV_FREE_PATH);
        }
        OPENSSL_sk_pop_free((*prov).parameters, Some(infopair_free));
        CRYPTO_THREAD_lock_free((*prov).opbits_lock);
        CRYPTO_THREAD_lock_free((*prov).flag_lock);
        CRYPTO_THREAD_lock_free((*prov).activatecnt_lock);
        CRYPTO_free(prov.cast::<c_void>(), FILE, lines::L_PROV_FREE);
    }
}

/// `int ossl_provider_set_module_path(OSSL_PROVIDER *prov, const char *module_path)`.
///
/// The previous path is released **before** the NULL test, so a NULL argument clears it and
/// answers 1. A failed dup leaves `path` NULL and answers 0, which is why the caller treats
/// 0 as fatal rather than as "no path".
///
/// # Safety
/// `prov` must be live; `module_path` NULL or NUL-terminated.
pub(crate) unsafe fn ossl_provider_set_module_path(
    prov: *mut OsslProvider,
    module_path: *const c_char,
) -> c_int {
    // SAFETY: `prov` is live, so `path` is NULL or an owned allocation.
    unsafe {
        if !(*prov).path.is_null() {
            CRYPTO_free((*prov).path.cast::<c_void>(), FILE, lines::L_SET_PATH_FREE);
        }
        (*prov).path = ptr::null_mut();
        if module_path.is_null() {
            return 1;
        }
        (*prov).path = CRYPTO_strdup(module_path, FILE, lines::L_SET_PATH_DUP);
        if (*prov).path.is_null() {
            return 0;
        }
    }
    1
}

/// `const char *ossl_provider_name(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_name(prov: *const OsslProvider) -> *const c_char {
    if prov.is_null() {
        return ptr::null();
    }
    // SAFETY: `prov` is live.
    unsafe { (*prov).name }
}

/// `const DSO *ossl_provider_dso(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
#[allow(dead_code)] // unreachable until Phases 7-10's store methods ask for a provider's DSO
pub(crate) unsafe fn ossl_provider_dso(prov: *const OsslProvider) -> *const Dso {
    if prov.is_null() {
        return ptr::null();
    }
    // SAFETY: `prov` is live.
    unsafe { (*prov).module }
}

/// `const char *ossl_provider_module_name(const OSSL_PROVIDER *prov)`.
///
/// A builtin has no module and `DSO_get_filename(NULL)` raises, so the authority's callers
/// only reach this for a provider that has one. The NULL test below is this crate's guard,
/// not a reproduction.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_provider_module_name(prov: *const OsslProvider) -> *const c_char {
    // SAFETY: `prov` is live.
    let module = unsafe { (*prov).module };
    if module.is_null() {
        return ptr::null();
    }
    // SAFETY: `module` is a live `DSO`.
    unsafe { DSO_get_filename(module) }
}

/// `const char *ossl_provider_module_path(const OSSL_PROVIDER *prov)`.
///
/// The same answer as [`ossl_provider_module_name`]; the authority's `FIXME` about whether it
/// is a full path is reproduced as-is rather than fixed.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_provider_module_path(prov: *const OsslProvider) -> *const c_char {
    // SAFETY: `prov` is live.
    unsafe { ossl_provider_module_name(prov) }
}

/// `const OSSL_DISPATCH *ossl_provider_get0_dispatch(const OSSL_PROVIDER *prov)`.
///
/// NULL-tolerant, unlike the string accessors.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_get0_dispatch(prov: *const OsslProvider) -> *const OsslDispatch {
    if prov.is_null() {
        return ptr::null();
    }
    // SAFETY: `prov` is live.
    unsafe { (*prov).dispatch }
}

/// `OSSL_LIB_CTX *ossl_provider_libctx(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_libctx(prov: *const OsslProvider) -> *mut c_void {
    if prov.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prov` is live.
    unsafe { (*prov).libctx }
}

/// `void *ossl_provider_ctx(const OSSL_PROVIDER *prov)`.
///
/// The answer is the provider's *own* context from its `init` call, which is NULL until
/// 6.8c initialises it.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_ctx(prov: *const OsslProvider) -> *mut c_void {
    if prov.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prov` is live.
    unsafe { (*prov).provctx }
}

/// The body of `OSSL_PROVIDER_set_default_search_path`.
///
/// The duplicate is made **before** the lock, so a context with no store does not have to be
/// distinguished before allocating; the copy is released on every failure path.
///
/// # Safety
/// `libctx` NULL or live; `path` NULL or NUL-terminated.
pub(crate) unsafe fn ossl_provider_set_default_search_path(
    libctx: *mut c_void,
    path: *const c_char,
) -> c_int {
    let mut p: *mut c_char = ptr::null_mut();
    if !path.is_null() {
        // SAFETY: `path` is NUL-terminated per the contract.
        p = unsafe { CRYPTO_strdup(path, FILE, lines::L_SET_SEARCH_PATH_DUP) };
        if p.is_null() {
            return 0;
        }
    }
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if !store.is_null() {
        // SAFETY: `store` is live, so `default_path_lock` was created by the store's
        // constructor.
        let locked = unsafe { CRYPTO_THREAD_write_lock((*store).default_path_lock) != 0 };
        if locked {
            // SAFETY: `store` is live and the lock is held; `default_path` is NULL or owned.
            unsafe {
                if !(*store).default_path.is_null() {
                    CRYPTO_free(
                        (*store).default_path.cast::<c_void>(),
                        FILE,
                        lines::L_SET_SEARCH_PATH_FREE,
                    );
                }
                (*store).default_path = p;
                CRYPTO_THREAD_unlock((*store).default_path_lock);
            }
            return 1;
        }
    }
    if !p.is_null() {
        // SAFETY: `p` came from `CRYPTO_strdup` and was not stored.
        unsafe { CRYPTO_free(p.cast::<c_void>(), FILE, lines::L_SET_SEARCH_PATH_ERR) };
    }
    0
}

/// The body of `OSSL_PROVIDER_get0_default_search_path`.
///
/// Borrowed, not copied: the caller must not free it, and any later
/// `set_default_search_path` releases it.
///
/// # Safety
/// `libctx` NULL or live.
pub(crate) unsafe fn ossl_provider_get0_default_search_path(libctx: *mut c_void) -> *const c_char {
    let mut path: *const c_char = ptr::null();
    // SAFETY: `libctx` is NULL or live.
    let store = unsafe { get_provider_store(libctx) };
    if !store.is_null() {
        // SAFETY: `store` is live, so `default_path_lock` was created.
        let locked = unsafe { CRYPTO_THREAD_read_lock((*store).default_path_lock) != 0 };
        if locked {
            // SAFETY: `store` is live and the lock is held.
            unsafe {
                path = (*store).default_path;
                CRYPTO_THREAD_unlock((*store).default_path_lock);
            }
        }
    }
    path
}

/// The body of `OSSL_PROVIDER_get_conf_parameters`.
///
/// Walks the provider's `INFOPAIR` list and writes only the parameters the caller's array
/// actually has — an unmatched pair is **skipped, not an error**. A missing list answers 1,
/// so a provider with no parameters is indistinguishable from one whose parameters all
/// matched, which is what the authority's `if (prov->parameters == NULL) return 1;` means.
///
/// # Safety
/// `prov` live; `params` NULL or a terminated `OSSL_PARAM` array.
pub(crate) unsafe fn ossl_provider_get_conf_parameters(
    prov: *const OsslProvider,
    params: *mut OsslParam,
) -> c_int {
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live.
    let list = unsafe { (*prov).parameters };
    if list.is_null() {
        return 1;
    }
    // SAFETY: `list` is a live stack of `InfoPair` pointers.
    let n = unsafe { OPENSSL_sk_num(list) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i < n`, so the slot holds a pair this provider owns.
        let pair = unsafe { OPENSSL_sk_value(list, i) }.cast::<InfoPair>();
        // SAFETY: `pair` is live; `params` is a terminated array per the contract.
        unsafe {
            let p = crate::params::OSSL_PARAM_locate(params, (*pair).name);
            if !p.is_null() && crate::params::OSSL_PARAM_set_utf8_ptr(p, (*pair).value) == 0 {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// `strcmp(val, "1")` and then case-insensitive comparisons for the four words — the
/// authority's exact pairing, which is why `"1"` alone is not matched by `"TRUE"`-style
/// case folding.
///
/// # Safety
/// `val` must be NUL-terminated.
unsafe fn conf_bool_true(val: *const c_char) -> bool {
    // SAFETY: both are NUL-terminated.
    unsafe {
        if c_strcmp(val, c"1".as_ptr()) == 0 {
            return true;
        }
        OPENSSL_strcasecmp(val, c"yes".as_ptr()) == 0
            || OPENSSL_strcasecmp(val, c"true".as_ptr()) == 0
            || OPENSSL_strcasecmp(val, c"on".as_ptr()) == 0
    }
}

/// The falsifying half of the same pairing.
///
/// # Safety
/// `val` must be NUL-terminated.
unsafe fn conf_bool_false(val: *const c_char) -> bool {
    // SAFETY: both are NUL-terminated.
    unsafe {
        if c_strcmp(val, c"0".as_ptr()) == 0 {
            return true;
        }
        OPENSSL_strcasecmp(val, c"no".as_ptr()) == 0
            || OPENSSL_strcasecmp(val, c"false".as_ptr()) == 0
            || OPENSSL_strcasecmp(val, c"off".as_ptr()) == 0
    }
}

/// The body of `OSSL_PROVIDER_conf_get_bool`.
///
/// The value arrives as a `UTF8_PTR` parameter, so the caller's variable receives the
/// *provider's* string rather than a copy. Three things decide the answer and all three are
/// required: the walk must succeed, the parameter must have been **modified** (which is how
/// `OSSL_PARAM_set_utf8_ptr` reports that it found and wrote the key), and the pointer must
/// be non-NULL. A value outside the two recognising sets falls through to `defval` rather
/// than to 0, so an unrecognised string is indistinguishable from an absent parameter.
///
/// # Safety
/// `prov` live; `name` NUL-terminated.
pub(crate) unsafe fn ossl_provider_conf_get_bool(
    prov: *const OsslProvider,
    name: *const c_char,
    defval: c_int,
) -> c_int {
    let mut val: *const c_char = ptr::null();
    // The authority's `OSSL_PARAM param[2] = { OSSL_PARAM_END, OSSL_PARAM_END }` — two
    // all-zero descriptors, the second of which terminates the array.
    let mut param = [blank_param(), blank_param()];
    // SAFETY: `param` is a live two-element array and `val` outlives the call.
    unsafe {
        param[0].key = name;
        param[0].data_type = OSSL_PARAM_UTF8_PTR;
        param[0].data = ptr::addr_of_mut!(val).cast::<c_void>();
        param[0].data_size = core::mem::size_of::<*mut c_char>();
        param[0].return_size = OSSL_PARAM_UNMODIFIED;

        // Errors are ignored, returning the default value.
        if ossl_provider_get_conf_parameters(prov, param.as_mut_ptr()) != 0
            && crate::params::OSSL_PARAM_modified(ptr::addr_of!(param[0])) != 0
            && !val.is_null()
        {
            if conf_bool_true(val) {
                return 1;
            }
            if conf_bool_false(val) {
                return 0;
            }
        }
    }
    defval
}

/// `OSSL_PARAM_END` — the all-zero terminating descriptor.
pub(crate) fn blank_param() -> OsslParam {
    OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

// ---------------------------------------------------------------------------
// The twenty-two `OSSL_PROVIDER_*` exports
// ---------------------------------------------------------------------------
//
// `crypto/provider.c`'s wrappers plus the five that live in `provider_core.c`, in the
// authority's own order. Every one is a thin delegation and every one is a **coordinate**:
// the ledger counts a symbol as implemented the moment it is defined, so this section is
// what moves twenty-two rows of `forensics/phase6-obligations.json` and it lands in the same
// commit as `RT-PROVIDER`, the court that observes the behaviour behind them.
//
// Three of them are not thin, and each is the whole reason it is written out:
//
//   * `OSSL_PROVIDER_try_load_ex` is the one place the **construction order** is decided:
//     find, or create storeless, then activate **once** (which is when `provider_init` runs
//     and the only time it can), then add to the store, then activate the store's object if
//     this thread lost the race. Every other entry point funnels through it.
//   * `OSSL_PROVIDER_load_ex` disables fallback loading **before** it tries to load, so a
//     failed `OSSL_PROVIDER_load` has a side effect: the next operation that would have
//     loaded `default` automatically no longer does. That is the authority's design and not
//     an accident of ordering, and the value is inverted -- `load_ex` refuses when
//     `ossl_provider_disable_fallback_loading` **succeeds**.
//   * `OSSL_PROVIDER_unload` deactivates and *then* frees, and reports the deactivation's
//     verdict rather than the free's, which returns nothing.
//
// The prototypes are the authority's (`provider.h` lines 21-88), and `ABI-PROTOTYPE`'s class
// and type planes check every one of them against `functions.json` -- including the four
// `OSSL_ALGORITHM` and `OSSL_DISPATCH` pointee shapes, which is why `OsslAlgorithm` and
// `OsslDispatch` exist as named types rather than as `*const c_void`.

/// `OSSL_PROVIDER *OSSL_PROVIDER_try_load_ex(OSSL_LIB_CTX *libctx, const char *name,
/// OSSL_PARAM *params, int retain_fallbacks)`.
///
/// The one entry point that decides the construction order. `isnew` is what makes the
/// `ossl_provider_add_to_store` call conditional: a provider that was already in the store
/// has already been through it.
///
/// The second activation is the losing thread's remedy. When two threads create objects with
/// the same name, `ossl_provider_add_to_store` hands back the store's, and the caller must take
/// its own reference to that object — which is what the second `ossl_provider_activate`
/// establishes before returning it.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated; `params` NULL or an `OSSL_PARAM` array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_try_load_ex(
    libctx: *mut c_void,
    name: *const c_char,
    params: *mut OsslParam,
    retain_fallbacks: c_int,
) -> *mut OsslProvider {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `libctx` is NULL or live and `name` is NUL-terminated; `noconfig` is 0, as
        // the authority's own call has it, so the config loader may run first.
        let mut prov = unsafe { ossl_provider_find(libctx, name, 0) };
        let mut isnew = 0;
        if prov.is_null() {
            // SAFETY: as above; the initialiser comes from the template, not the caller.
            prov = unsafe { ossl_provider_new(libctx, name, None, params, 0) };
            if prov.is_null() {
                return ptr::null_mut();
            }
            isnew = 1;
        }
        // SAFETY: `prov` is live; `upcalls` is 1 and `aschild` 0, as in the authority.
        if unsafe { crate::provider::activate::ossl_provider_activate(prov, 1, 0) } == 0 {
            // SAFETY: `prov` is live and this function's own reference.
            unsafe { ossl_provider_free(prov) };
            return ptr::null_mut();
        }
        let mut actual = prov;
        if isnew != 0 {
            // SAFETY: `prov` is live and `actual` is a writable slot of the right type.
            let added = unsafe { ossl_provider_add_to_store(prov, &mut actual, retain_fallbacks) };
            if added == 0 {
                // SAFETY: `prov` is live, activated, and not in the store.
                unsafe {
                    crate::provider::activate::ossl_provider_deactivate(prov, 1);
                    ossl_provider_free(prov);
                }
                return ptr::null_mut();
            }
        }
        if actual != prov {
            // SAFETY: `actual` is the store's object, which `ossl_provider_add_to_store`
            // up-ref'd on this function's behalf.
            if unsafe { crate::provider::activate::ossl_provider_activate(actual, 1, 0) } == 0 {
                // SAFETY: `actual` is live and holds the reference taken above.
                unsafe { ossl_provider_free(actual) };
                return ptr::null_mut();
            }
        }
        actual
    })
}

/// `OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *libctx, const char *name,
/// int retain_fallbacks)`.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_try_load(
    libctx: *mut c_void,
    name: *const c_char,
    retain_fallbacks: c_int,
) -> *mut OsslProvider {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: every argument is passed through unchanged; `params` is NULL.
        unsafe { OSSL_PROVIDER_try_load_ex(libctx, name, ptr::null_mut(), retain_fallbacks) }
    })
}

/// `OSSL_PROVIDER *OSSL_PROVIDER_load_ex(OSSL_LIB_CTX *libctx, const char *name,
/// OSSL_PARAM *params)`.
///
/// The refusal is **inverted**, and that is the whole function: *any* attempt to load a
/// provider disables automatic loading of the default one, so a failure here is a promise that
/// the next operation will not silently supply `default` instead. `ossl_provider_disable_fallback_loading`
/// answers 1 on success — `retain_fallbacks` is then **0**, because a load that asked for a
/// named provider did not ask for the fallbacks.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated; `params` NULL or an `OSSL_PARAM` array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_load_ex(
    libctx: *mut c_void,
    name: *const c_char,
    params: *mut OsslParam,
) -> *mut OsslProvider {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `libctx` is NULL or live, which is the contract of the call.
        if unsafe { ossl_provider_disable_fallback_loading(libctx) } != 0 {
            // SAFETY: as above.
            return unsafe { OSSL_PROVIDER_try_load_ex(libctx, name, params, 0) };
        }
        ptr::null_mut()
    })
}

/// `OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *libctx, const char *name)`.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_load(
    libctx: *mut c_void,
    name: *const c_char,
) -> *mut OsslProvider {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: every argument is passed through unchanged; `params` is NULL.
        unsafe { OSSL_PROVIDER_load_ex(libctx, name, ptr::null_mut()) }
    })
}

/// `int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov)`.
///
/// Deactivate, then free: the free is unconditional once the deactivation succeeded, because
/// the caller's reference is what is being released either way. The **answer** is the
/// deactivation's, because `ossl_provider_free` has none to give.
///
/// # Safety
/// `prov` must be NULL or a live provider the caller holds a reference to.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_unload(prov: *mut OsslProvider) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is NULL or live; `removechildren` is 1, as in the authority.
        if unsafe { crate::provider::activate::ossl_provider_deactivate(prov, 1) } == 0 {
            return 0;
        }
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_free(prov) };
        1
    })
}

/// `const OSSL_PARAM *OSSL_PROVIDER_gettable_params(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_gettable_params(
    prov: *const OsslProvider,
) -> *const OsslParam {
    guard_ffi(ptr::null(), || {
        // SAFETY: `prov` is live.
        unsafe { crate::provider::activate::ossl_provider_gettable_params(prov) }
    })
}

/// `int OSSL_PROVIDER_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])`.
///
/// # Safety
/// `prov` must be live; `params` NULL or the provider's array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get_params(
    prov: *const OsslProvider,
    params: *mut OsslParam,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is live.
        unsafe { crate::provider::activate::ossl_provider_get_params(prov, params) }
    })
}

/// `const OSSL_ALGORITHM *OSSL_PROVIDER_query_operation(const OSSL_PROVIDER *prov,
/// int operation_id, int *no_cache)`.
///
/// # Safety
/// `prov` must be live; `no_cache` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_query_operation(
    prov: *const OsslProvider,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const crate::provider::activate::OsslAlgorithm {
    guard_ffi(ptr::null(), || {
        // SAFETY: `prov` is live; `no_cache` is NULL or writable per the contract.
        unsafe {
            crate::provider::activate::ossl_provider_query_operation(prov, operation_id, no_cache)
        }
    })
}

/// `void OSSL_PROVIDER_unquery_operation(const OSSL_PROVIDER *prov, int operation_id,
/// const OSSL_ALGORITHM *algs)`.
///
/// # Safety
/// `prov` must be live; `algs` must be what the matching query answered.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_unquery_operation(
    prov: *const OsslProvider,
    operation_id: c_int,
    algs: *const crate::provider::activate::OsslAlgorithm,
) {
    guard_ffi((), || {
        // SAFETY: `prov` is live; `algs` is the query's answer.
        unsafe {
            crate::provider::activate::ossl_provider_unquery_operation(prov, operation_id, algs)
        }
    })
}

/// `void *OSSL_PROVIDER_get0_provider_ctx(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get0_provider_ctx(prov: *const OsslProvider) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `prov` is NULL or live.
        unsafe { ossl_provider_ctx(prov) }
    })
}

/// `const OSSL_DISPATCH *OSSL_PROVIDER_get0_dispatch(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get0_dispatch(
    prov: *const OsslProvider,
) -> *const OsslDispatch {
    guard_ffi(ptr::null(), || {
        // SAFETY: `prov` is NULL or live.
        unsafe { ossl_provider_get0_dispatch(prov) }
    })
}

/// `int OSSL_PROVIDER_self_test(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_self_test(prov: *const OsslProvider) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is live.
        unsafe { crate::provider::activate::ossl_provider_self_test(prov) }
    })
}

/// `int OSSL_PROVIDER_get_capabilities(const OSSL_PROVIDER *prov, const char *capability,
/// OSSL_CALLBACK *cb, void *arg)`.
///
/// # Safety
/// `prov` must be live; `capability` NULL or NUL-terminated; `cb`/`arg` are the provider's to
/// interpret.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get_capabilities(
    prov: *const OsslProvider,
    capability: *const c_char,
    cb: Option<OsslCallback>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is live.
        unsafe {
            crate::provider::activate::ossl_provider_get_capabilities(prov, capability, cb, arg)
        }
    })
}

/// `int OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX *libctx, const char *name,
/// OSSL_provider_init_fn *init_fn)`.
///
/// The third parameter is `Option<ProviderInitFn>` and **not** `ProviderInitFn`, which is the
/// one place in this file where the distinction between "a function pointer" and "a nullable
/// function pointer" is the difference between a correct answer and a wrong one: the
/// authority refuses a NULL entry point with `ERR_R_PASSED_NULL_PARAMETER` **before** it
/// allocates anything, so a bare parameter would make `Some(NULL)` indistinguishable from a
/// real one and the registration would succeed where the authority's fails. `ABI-PROTOTYPE`
/// canonicalises `Option<F>` and `F` identically -- a nullable function pointer and a bare one
/// are the same type to a caller -- so the nullable spelling costs nothing and is the one the
/// contract needs. `RT-PROVIDER` found this: `add_builtin.null_init` answered 1 where the
/// authority answers 0.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated; `init_fn` NULL or a valid entry point.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_add_builtin(
    libctx: *mut c_void,
    name: *const c_char,
    init_fn: Option<ProviderInitFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the three arguments are the contract's; `ossl_provider_add_builtin` is the
        // one that tests them, and it raises what the authority raises.
        unsafe { ossl_provider_add_builtin(libctx, name, init_fn) }
    })
}

/// `const char *OSSL_PROVIDER_get0_name(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get0_name(prov: *const OsslProvider) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_name(prov) }
    })
}

/// `int OSSL_PROVIDER_do_all(OSSL_LIB_CTX *ctx, int (*cb)(OSSL_PROVIDER *provider,
/// void *cbdata), void *cbdata)`.
///
/// # Safety
/// `ctx` NULL or live; `cb` non-NULL and valid for every provider on the stack.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_do_all(
    ctx: *mut c_void,
    cb: crate::provider::activate::ProviderDoAllFn,
    cbdata: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live.
        unsafe { crate::provider::activate::ossl_provider_doall_activated(ctx, cb, cbdata) }
    })
}

/// `int OSSL_PROVIDER_available(OSSL_LIB_CTX *libctx, const char *name)`.
///
/// # Safety
/// `libctx` NULL or live; `name` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_available(
    libctx: *mut c_void,
    name: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `libctx` is NULL or live; `name` is passed through to `ossl_provider_find`,
        // whose contract is NULL or NUL-terminated.
        unsafe { crate::provider::activate::ossl_provider_available(libctx, name) }
    })
}

/// `int OSSL_PROVIDER_add_conf_parameter(OSSL_PROVIDER *prov, const char *name,
/// const char *value)`.
///
/// The only export in this file whose body is another function **in this file**, because
/// `infopair_add` is `provider_core.c`'s static helper and this is its one external caller.
///
/// # Safety
/// `prov` must be live; `name` and `value` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_add_conf_parameter(
    prov: *mut OsslProvider,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if prov.is_null() {
            return 0;
        }
        // SAFETY: `prov` is live, so the address of its `parameters` field is valid for the
        // duration of the call; both strings are NUL-terminated.
        unsafe { infopair_add(ptr::addr_of_mut!((*prov).parameters), name, value) }
    })
}

/// `int OSSL_PROVIDER_get_conf_parameters(const OSSL_PROVIDER *prov, OSSL_PARAM params[])`.
///
/// # Safety
/// `prov` must be live; `params` NULL or an array of at least one descriptor.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get_conf_parameters(
    prov: *const OsslProvider,
    params: *mut OsslParam,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_get_conf_parameters(prov, params) }
    })
}

/// `int OSSL_PROVIDER_conf_get_bool(const OSSL_PROVIDER *prov, const char *name, int defval)`.
///
/// # Safety
/// `prov` must be live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_conf_get_bool(
    prov: *const OsslProvider,
    name: *const c_char,
    defval: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_conf_get_bool(prov, name, defval) }
    })
}

/// `int OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *libctx, const char *path)`.
///
/// # Safety
/// `libctx` NULL or live; `path` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_set_default_search_path(
    libctx: *mut c_void,
    path: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `libctx` is NULL or live; `path` is NULL or NUL-terminated.
        unsafe { ossl_provider_set_default_search_path(libctx, path) }
    })
}

/// `const char *OSSL_PROVIDER_get0_default_search_path(OSSL_LIB_CTX *libctx)`.
///
/// # Safety
/// `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PROVIDER_get0_default_search_path(
    libctx: *mut c_void,
) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `libctx` is NULL or live.
        unsafe { ossl_provider_get0_default_search_path(libctx) }
    })
}

#[cfg(test)]
mod tests {
    //! The comparator's slot indirection, the store's constructor and teardown, the
    //! parameter list, and the two synchronisation-free accessors.
    //!
    //! Everything here is reachable without a provider module, which is the point of the
    //! subphase: a store that cannot be built cannot be tested, and a store that can be built
    //! can be tested with nothing yet to put in it.
    //!
    //! `alloc` is not linked for unit tests, so no `String` or `Vec` appears below.

    use super::*;
    // `OPENSSL_sk_is_sorted` is asserted only from here, so it is imported only here: the
    // library build never asks whether a stack is known-sorted.
    use crate::runtime::stack::OPENSSL_sk_is_sorted;

    /// A provider standing in for a stack element. The name is borrowed from a `CStr`
    /// literal, so nothing is owned and nothing is freed.
    fn provider_named(name: &'static core::ffi::CStr) -> OsslProvider {
        let mut p = blank_provider();
        p.name = name.as_ptr().cast_mut();
        p.refcnt = AtomicI32::new(1);
        p
    }

    #[test]
    fn the_comparator_is_given_addresses_of_slots_and_orders_by_name() {
        let mut alpha = provider_named(c"alpha");
        let mut beta = provider_named(c"beta");
        let a: *mut OsslProvider = ptr::addr_of_mut!(alpha);
        let b: *mut OsslProvider = ptr::addr_of_mut!(beta);
        // The stack machinery hands the comparator the *addresses of the slots*, so these
        // are the pointers it would receive -- not `a` and `b` themselves. Passing `a` and
        // `b` directly is the mistake this test exists to make impossible.
        // SAFETY: both slots hold live providers with NUL-terminated names.
        let forward =
            unsafe { ossl_provider_cmp(ptr::addr_of!(a).cast(), ptr::addr_of!(b).cast()) };
        // SAFETY: as above, with the slots exchanged.
        let reverse =
            unsafe { ossl_provider_cmp(ptr::addr_of!(b).cast(), ptr::addr_of!(a).cast()) };
        assert!(forward < 0, "alpha sorts before beta, got {forward}");
        assert!(
            reverse > 0,
            "and exchanging them makes it positive, got {reverse}"
        );
        // SAFETY: as above, with the same slot twice.
        let equal = unsafe { ossl_provider_cmp(ptr::addr_of!(a).cast(), ptr::addr_of!(a).cast()) };
        assert_eq!(equal, 0, "a name compares equal to itself");
    }

    #[test]
    fn the_store_is_built_empty_with_fallbacks_on_and_a_sorted_provider_stack() {
        // SAFETY: the constructor takes a context it stores without dereferencing.
        let store = unsafe { ossl_provider_store_new(ptr::null_mut()) }.cast::<ProviderStore>();
        assert!(!store.is_null(), "the store must be constructible");
        // SAFETY: `store` is live.
        unsafe {
            assert!(!(*store).providers.is_null(), "the provider stack is built");
            assert_eq!(OPENSSL_sk_num((*store).providers), 0, "and starts empty");
            assert!(!(*store).child_cbs.is_null(), "the child stack is built");
            assert!(!(*store).lock.is_null(), "the store lock is built");
            assert!(!(*store).default_path_lock.is_null(), "and the path lock");
            assert_eq!((*store).use_fallbacks, 1, "fallbacks start enabled");
            assert_eq!((*store).freeing, 0);
            assert_eq!((*store).numprovinfo, 0);
            assert_eq!((*store).provinfosz, 0, "the info table is unallocated");
            assert!(
                (*store).default_path.is_null(),
                "and there is no search path"
            );
            // A stack built with a comparator is *not* sorted until it is asked to sort,
            // which is what `find` does first.
            assert_eq!(OPENSSL_sk_is_sorted((*store).providers), 0);
        }
        // SAFETY: `store` is live and nothing was added to it.
        unsafe { ossl_provider_store_free(store.cast::<c_void>()) };
    }

    #[test]
    fn an_info_entry_owns_its_parameters_and_clear_releases_and_resets_them() {
        // A fresh zeroed entry, which is how both callers build one. `clear`'s reset is what
        // makes the store's teardown safe to run over an array it then releases whole.
        // `CRYPTO_zalloc` is a *safe* function in this crate, so no block is needed: the
        // convention is that every pointer operation gets its own block with a SAFETY line,
        // not that every call does.
        let entry = CRYPTO_zalloc(
            core::mem::size_of::<OsslProviderInfo>(),
            FILE,
            lines::L_INFO_ADD_CALLOC,
        )
        .cast::<OsslProviderInfo>();
        assert!(!entry.is_null(), "an entry is constructible");
        // SAFETY: `entry` is live and zeroed; both strings are literals.
        unsafe {
            assert!(
                (*entry).parameters.is_null(),
                "a fresh entry has no parameters"
            );
            assert_eq!(
                ossl_provider_info_add_parameter(entry, c"alpha".as_ptr(), c"one".as_ptr()),
                1
            );
            assert_eq!(
                ossl_provider_info_add_parameter(entry, c"beta".as_ptr(), c"two".as_ptr()),
                1
            );
            assert!(!(*entry).parameters.is_null());
            assert_eq!(OPENSSL_sk_num((*entry).parameters), 2);
            // Insertion order: this stack has no comparator, unlike the store's.
            let first = OPENSSL_sk_value((*entry).parameters, 0).cast::<InfoPair>();
            // SAFETY: the slot holds a pair this entry owns.
            assert_eq!(c_strcmp((*first).name, c"alpha".as_ptr()), 0);
            // SAFETY: as above.
            assert_eq!(c_strcmp((*first).value, c"one".as_ptr()), 0);

            ossl_provider_info_clear(entry);
            assert!((*entry).parameters.is_null(), "the list pointer is cleared");
            assert!((*entry).name.is_null());
            assert!((*entry).path.is_null());
            // A second clear over an already-cleared entry must not free anything again.
            ossl_provider_info_clear(entry);
            // SAFETY: `entry` was allocated above and its contents are now all NULL.
            CRYPTO_free(entry.cast::<c_void>(), FILE, lines::L_INFO_ADD_CALLOC);
        }
    }

    #[test]
    fn a_provider_is_created_with_three_locks_a_deep_copied_parameter_list_and_a_name() {
        // The parameter list is built here rather than through a store, so the deep copy is
        // observed directly: the copy must not alias the source.
        // SAFETY: a live stack of `InfoPair`, built the way `infopair_add` builds one.
        let mut src: *mut OpenSslStack = ptr::null_mut();
        // SAFETY: `src` is the address of a local field, `name` and `value` are literals.
        let added = unsafe { infopair_add(ptr::addr_of_mut!(src), c"k".as_ptr(), c"v".as_ptr()) };
        assert_eq!(added, 1, "the source pair is added");
        assert!(!src.is_null());
        // SAFETY: `src` is live and non-NULL.
        let src_pair = unsafe { OPENSSL_sk_value(src, 0) }.cast::<InfoPair>();
        // SAFETY: `src` is live, so the first slot is a pair.
        assert_eq!(unsafe { OPENSSL_sk_num(src) }, 1);

        // SAFETY: `src` is NULL-or-live, the name is a literal.
        let prov = unsafe { provider_new(c"testprov".as_ptr(), None, src) };
        assert!(!prov.is_null(), "the provider must be constructible");
        // SAFETY: `prov` is live.
        unsafe {
            assert_eq!((*prov).refcnt.load(Ordering::Acquire), 1);
            assert!(!(*prov).flag_lock.is_null());
            assert!(!(*prov).activatecnt_lock.is_null());
            assert!(!(*prov).opbits_lock.is_null());
            assert_eq!((*prov).flags, 0, "neither flag is set at construction");
            assert_eq!((*prov).activatecnt, 0);
            assert!(
                !(*prov).parameters.is_null(),
                "the parameter list is copied"
            );
            assert_eq!(OPENSSL_sk_num((*prov).parameters), 1);
            assert!(
                (*prov).parameters != src,
                "and it is a *deep* copy, not the source stack"
            );
            // The copied pair is a different allocation holding equal text.
            let copy = OPENSSL_sk_value((*prov).parameters, 0).cast::<InfoPair>();
            assert!(copy != src_pair, "the pair itself is copied too");
            assert_ne!((*copy).name, (*src_pair).name, "and so is its name");
            // SAFETY: both name fields are NUL-terminated.
            assert_eq!(c_strcmp((*copy).name, (*src_pair).name), 0);
            // SAFETY: as above, for the values.
            assert_eq!(c_strcmp((*copy).value, (*src_pair).value), 0);
            assert!(
                (*prov).module.is_null(),
                "a builtin-in-waiting has no module"
            );
            assert!((*prov).path.is_null(), "and no path until it is set");
        }
        // SAFETY: `prov` is live and holds the only reference to itself.
        unsafe { ossl_provider_free(prov) };
        // SAFETY: `src` is live and was not given away.
        unsafe { OPENSSL_sk_pop_free(src, Some(infopair_free)) };
    }

    #[test]
    fn the_module_path_setter_clears_on_null_and_replaces_on_a_second_call() {
        // SAFETY: a provider with no store, built directly.
        let prov = unsafe { provider_new(c"p".as_ptr(), None, ptr::null_mut()) };
        assert!(!prov.is_null());
        // SAFETY: `prov` is live.
        unsafe {
            assert_eq!(ossl_provider_set_module_path(prov, c"/a/b.so".as_ptr()), 1);
            // SAFETY: `path` is NUL-terminated.
            assert_eq!(c_strcmp((*prov).path, c"/a/b.so".as_ptr()), 0);
            assert_eq!(ossl_provider_set_module_path(prov, c"/c/d.so".as_ptr()), 1);
            // The *content* is what is asserted, and deliberately not the address: the
            // second `OPENSSL_strdup` runs after the first block was freed, so the
            // allocator is free to hand back the same address -- and on this platform it
            // does. An address comparison here would measure the allocator rather than this
            // function, and would pass or fail for reasons that have nothing to do with the
            // contract. It was written that way first, and it failed.
            // SAFETY: `path` is NUL-terminated and holds the second name.
            assert_eq!(c_strcmp((*prov).path, c"/c/d.so".as_ptr()), 0);
            assert_ne!(
                c_strcmp((*prov).path, c"/a/b.so".as_ptr()),
                0,
                "replaced, not kept"
            );
            assert_eq!(ossl_provider_set_module_path(prov, ptr::null()), 1);
            assert!(
                (*prov).path.is_null(),
                "a NULL path clears rather than refuses"
            );
        }
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_free(prov) };
    }

    #[test]
    fn the_accessors_are_null_tolerant_where_the_authority_says_they_are() {
        // SAFETY: every accessor accepts NULL by this function's contract.
        unsafe {
            assert!(ossl_provider_name(ptr::null()).is_null());
            assert!(ossl_provider_dso(ptr::null()).is_null());
            assert!(ossl_provider_get0_dispatch(ptr::null()).is_null());
            assert!(ossl_provider_libctx(ptr::null()).is_null());
            assert!(ossl_provider_ctx(ptr::null()).is_null());
        }
        // SAFETY: a provider with no module and no dispatch table.
        let prov = unsafe { provider_new(c"q".as_ptr(), None, ptr::null_mut()) };
        assert!(!prov.is_null());
        // SAFETY: `prov` is live.
        unsafe {
            // SAFETY: `name` is NUL-terminated.
            assert_eq!(c_strcmp(ossl_provider_name(prov), c"q".as_ptr()), 0);
            assert!(ossl_provider_dso(prov).is_null());
            assert!(ossl_provider_get0_dispatch(prov).is_null());
            assert!(ossl_provider_libctx(prov).is_null());
            assert!(ossl_provider_ctx(prov).is_null(), "not initialised yet");
            // `module_name`/`module_path` would raise on a NULL module, so they are not
            // called here: the authority's callers only reach them for a loaded provider.
        }
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_free(prov) };
    }

    #[test]
    fn the_conf_parameter_walk_skips_keys_the_caller_did_not_ask_for() {
        // SAFETY: a provider with two parameters and nothing else.
        let mut src: *mut OpenSslStack = ptr::null_mut();
        // SAFETY: `src` is a local field and both strings are literals.
        unsafe {
            assert_eq!(
                infopair_add(ptr::addr_of_mut!(src), c"a".as_ptr(), c"1".as_ptr()),
                1
            );
            assert_eq!(
                infopair_add(ptr::addr_of_mut!(src), c"b".as_ptr(), c"yes".as_ptr()),
                1
            );
        }
        // SAFETY: `src` is NULL-or-live.
        let prov = unsafe { provider_new(c"conf".as_ptr(), None, src) };
        assert!(!prov.is_null());
        // SAFETY: `prov` is live.
        unsafe { OPENSSL_sk_pop_free(src, Some(infopair_free)) };

        // A caller asking for `a` only: the walk must write it and skip `b` silently.
        let mut val: *const c_char = ptr::null();
        let mut param = [blank_param(), blank_param()];
        // SAFETY: `param` is a live array and `val` outlives the call; `prov` is live.
        unsafe {
            param[0].key = c"a".as_ptr();
            param[0].data_type = OSSL_PARAM_UTF8_PTR;
            param[0].data = ptr::addr_of_mut!(val).cast::<c_void>();
            param[0].data_size = core::mem::size_of::<*mut c_char>();
            param[0].return_size = OSSL_PARAM_UNMODIFIED;
            assert_eq!(
                ossl_provider_get_conf_parameters(prov, param.as_mut_ptr()),
                1
            );
            assert_ne!(
                param[0].return_size, OSSL_PARAM_UNMODIFIED,
                "`a` was written"
            );
            assert!(!val.is_null());
            // SAFETY: `val` points at the provider's own string, which is NUL-terminated.
            assert_eq!(c_strcmp(val, c"1".as_ptr()), 0);
            assert_eq!(
                param[1].return_size, OSSL_PARAM_UNMODIFIED,
                "the terminator was not written"
            );
        }
        // SAFETY: `prov` is live.
        unsafe { ossl_provider_free(prov) };
    }

    #[test]
    fn the_boolean_reader_recognises_the_authority_six_words_and_falls_through_otherwise() {
        // SAFETY: every pointer below is a NUL-terminated literal.
        unsafe {
            assert!(conf_bool_true(c"1".as_ptr()));
            assert!(conf_bool_true(c"yes".as_ptr()));
            assert!(conf_bool_true(c"YES".as_ptr()));
            assert!(conf_bool_true(c"True".as_ptr()));
            assert!(conf_bool_true(c"ON".as_ptr()));
            assert!(conf_bool_false(c"0".as_ptr()));
            assert!(conf_bool_false(c"no".as_ptr()));
            assert!(conf_bool_false(c"OFF".as_ptr()));
            assert!(conf_bool_false(c"False".as_ptr()));
            // The words are not interchangeable across the two sets.
            assert!(!conf_bool_true(c"no".as_ptr()));
            assert!(!conf_bool_false(c"yes".as_ptr()));
            // And an unrecognised value belongs to neither, which is what makes it fall
            // through to the caller's default rather than to 0.
            assert!(!conf_bool_true(c"maybe".as_ptr()));
            assert!(!conf_bool_false(c"maybe".as_ptr()));
            assert!(!conf_bool_true(c"".as_ptr()));
            assert!(!conf_bool_false(c"".as_ptr()));
            // `"1"` is *not* case-folded to match `"YES"`, and neither is `"0"`.
            assert!(!conf_bool_true(c"YES ".as_ptr()));
        }
    }

    #[test]
    fn the_predefined_table_is_default_base_null_and_default_is_the_fallback() {
        // This profile's table has three rows because `configdata.pm` records
        // `enable-shared enable-legacy`, so `STATIC_LEGACY` is not defined and the `legacy`
        // row is compiled out. Asserting the rows is what keeps a future build change from
        // silently adding one this file would then resolve.
        let rows: &[&core::ffi::CStr] = &[c"default", c"base", c"null"];
        for (i, name) in rows.iter().enumerate() {
            assert_eq!(
                PREDEFINED_PROVIDERS[i].name.to_bytes(),
                name.to_bytes(),
                "row {i} is named as the authority names it"
            );
        }
        // The terminator is the empty name, which is how the scan stops.
        assert!(PREDEFINED_PROVIDERS[3].name.to_bytes().is_empty());
        // `default` is the only fallback: it is what an operation with no explicit load gets,
        // and `base` -- which declares no algorithms of its own -- is not.
        assert_eq!(
            PREDEFINED_PROVIDERS[0].is_fallback, 1,
            "default is a fallback"
        );
        assert_eq!(PREDEFINED_PROVIDERS[1].is_fallback, 0, "base is not");
        assert_eq!(PREDEFINED_PROVIDERS[2].is_fallback, 0, "null is not");
        assert!(predefined_row(c"default".as_ptr()).is_some());
        assert!(predefined_row(c"base".as_ptr()).is_some());
        assert!(predefined_row(c"null".as_ptr()).is_some());
        // `legacy` is a *module* in this profile and must not be found here: it is loaded by
        // name through the DSO layer, which is why 6.9 had to precede this registry.
        assert!(predefined_row(c"legacy".as_ptr()).is_none());
        assert!(predefined_row(c"fips".as_ptr()).is_none());
        assert!(
            predefined_row(c"".as_ptr()).is_none(),
            "the terminator matches nothing"
        );
        assert!(
            predefined_row(c"DEFAULT".as_ptr()).is_none(),
            "the comparison is exact"
        );
    }

    #[test]
    fn a_blank_info_entry_is_all_zero_because_both_constructors_start_that_way() {
        let info = blank_info();
        assert!(info.name.is_null());
        assert!(info.path.is_null());
        assert!(info.init.is_none());
        assert!(info.parameters.is_null());
        assert_eq!(info.is_fallback, 0);
        // Every predefined row's `is_fallback` is one bit, matching the authority's
        // `unsigned int is_fallback : 1`.
        for row in PREDEFINED_PROVIDERS.iter() {
            assert!(row.is_fallback <= 1, "is_fallback is one bit");
        }
    }
}
