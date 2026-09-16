//! Phase 6.8d — `crypto/provider_conf.c`: the `providers` configuration module.
//!
//! This is the half of provider activation that a **configuration file** reaches. A file
//! writes
//!
//! ```text
//! openssl_conf = openssl_init
//! [openssl_init]
//! providers = provider_sect
//! [provider_sect]
//! default = default_sect
//! legacy = legacy_sect
//! [default_sect]
//! activate = 1
//! [legacy_sect]
//! soft_load = yes
//! activate = yes
//! ```
//!
//! and each `[provider_sect]` entry becomes one `provider_conf_load` call. Nothing else in
//! this stratum turns a *file* into a loaded provider, which is why 6.8d is ordered after
//! 6.10: it *is* a `CONF_MODULE`, so it could not exist before the registry did.
//!
//! ## The two entry points a section entry can produce, and they are different objects
//!
//! `provider_conf_load` reads the *command* section first, in a whole pass of its own, and
//! only then decides what to do. The decision is `activate`:
//!
//! * **`activate` true** — `provider_conf_activate` builds a real `OSSL_PROVIDER`, hands it
//!   the parameters, activates it, and records it in this module's own
//!   `activated_providers` list so that a second load of the same name is a no-op.
//! * **`activate` false** — an `OSSL_PROVIDER_INFO` *template* is built instead and added to
//!   the store, which is what makes a provider **findable by name** without being loaded.
//!   `OSSL_PROVIDER_load` then finds the template and loads the module it names.
//!
//! Three commands are **special** and are consumed rather than passed through:
//! `identity` (overrides the name), `soft_load`, `module` (the path) and `activate`. Every
//! other command is a parameter and reaches `OSSL_PROVIDER_add_conf_parameter` or
//! `ossl_provider_info_add_parameter`.
//!
//! ## Recursion is detected by *pointer*, and that is not an accident
//!
//! `provider_conf_params_internal` recurses on a section's entries and refuses a section it
//! has already visited — `CONF_R_RECURSIVE_SECTION_REFERENCE`. The comparison is
//! `sk_OPENSSL_CSTRING_value(visited, i) == value`, i.e. **identity of the string the
//! `CONF` owns**, not `strcmp`. Two different sections with the same *content* are not
//! recursive; the same section reached twice is. A transcription that compared text would
//! refuse a legitimate configuration, and one that did not compare at all would not
//! terminate.
//!
//! ## The buffer is 512 bytes and the refusal is checked *before* the append
//!
//! The accumulated parameter name is `char buffer[512]`, and the test is
//! `buffer_len + strlen(sectconf->name) >= sizeof(buffer)` — so a name that would exactly
//! fill the buffer is refused, not truncated, and the refusal is `-1` (fatal) rather than a
//! non-fatal 0. The prefix is `name` plus a `.`, and at the top level `name` is NULL and the
//! prefix is empty.
//!
//! ## The four ignored `OSSL_TRACE` calls
//!
//! The pinned profile is `no-trace`, so the file's `OSSL_TRACE1`/`OSSL_TRACE2` lines compile
//! to nothing and there is nothing to transcribe. A reader comparing the two files should not
//! look for them.
//!
//! SPDX-License-Identifier: Apache-2.0

// The authority's names are kept verbatim: `ABI-PROTOTYPE` and the export courts resolve
// exports by name, and a `provider_conf_init` renamed would be a different symbol.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::conf::lib::{NCONF_get0_libctx, NCONF_get_section};
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{CONF_imodule_get_value, CONF_module_add, ConfImodule};
use crate::runtime::err::err_sites::{
    PROVIDER_CONF_100, PROVIDER_CONF_211, PROVIDER_CONF_224, PROVIDER_CONF_280, PROVIDER_CONF_302,
    PROVIDER_CONF_328, PROVIDER_CONF_412,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

use super::activate::{ossl_provider_activate, ossl_provider_deactivate};
use super::{
    infopair_add, ossl_provider_add_to_store, ossl_provider_disable_fallback_loading,
    ossl_provider_find, ossl_provider_free, ossl_provider_info_add_parameter,
    ossl_provider_info_add_to_store, ossl_provider_info_clear, ossl_provider_name,
    ossl_provider_new, ossl_provider_set_module_path, OsslProvider, OsslProviderInfo,
};
use crate::context::lib_ctx_get_data;

/// `crypto/provider_conf.c`, for the coordinates of every allocation this module makes.
///
/// `OPENSSL_zalloc` and `OPENSSL_strdup` are macros over the `CRYPTO_*` family that fill in
/// `OPENSSL_FILE`/`OPENSSL_LINE` at the call site.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/provider_conf.c".as_ptr();

/// `PROVIDER_CONF_GLOBAL *pcgbl = OPENSSL_zalloc(sizeof(*pcgbl))` in
/// `ossl_prov_conf_ctx_new`.
const L_PCGBL: c_int = 32;
/// `OPENSSL_free(pcgbl)` in `ossl_prov_conf_ctx_new`'s failure arm.
const L_PCGBL_ERR: c_int = 39;
/// `OPENSSL_free(pcgbl)` in `ossl_prov_conf_ctx_free`.
const L_PCGBL_FREE: c_int = 55;
/// `entry.name = OPENSSL_strdup(name)` in `provider_conf_load`.
const L_ENTRY_NAME: c_int = 369;
/// `entry.path = OPENSSL_strdup(path)`.
const L_ENTRY_PATH: c_int = 374;

/// `OSSL_LIB_CTX_PROVIDER_CONF_INDEX` — `include/internal/cryptlib.h`, and the slot
/// [`ossl_prov_conf_ctx_new`]'s object is stored in.
const OSSL_LIB_CTX_PROVIDER_CONF_INDEX: c_int = 16;

/// The authority's `char buffer[512]` in `provider_conf_params_internal`.
const BUFFER_SIZE: usize = 512;

/// `PROVIDER_CONF_GLOBAL` — the module's per-context state.
///
/// `activated_providers` is **this module's** list, not the provider store's: a provider a
/// configuration activated is recorded here so that a second `providers` section naming it
/// does nothing, and it is the list whose entries the module releases when its context is
/// torn down.
#[repr(C)]
pub(crate) struct ProviderConfGlobal {
    /// `CRYPTO_RWLOCK *lock` — held across `provider_conf_activate`'s whole body, so two
    /// threads cannot activate the same provider twice.
    pub(crate) lock: *mut CryptoRwlock,
    /// `STACK_OF(OSSL_PROVIDER) *activated_providers` — NULL until the first activation.
    pub(crate) activated_providers: *mut OpenSslStack,
}

/// `void *ossl_prov_conf_ctx_new(OSSL_LIB_CTX *libctx)`.
///
/// The context's slot-16 constructor. It takes the context and does not read it — the
/// authority's signature does the same, because the object holds nothing context-specific.
/// Its own lock is created here, and a lock failure releases the object rather than returning
/// a half-built one.
///
/// # Safety
/// `libctx` is accepted and unused; the authority's argument is the context being built, which
/// the caller in `context_init` is holding, so it is live.
pub(crate) unsafe fn ossl_prov_conf_ctx_new(_libctx: *mut c_void) -> *mut ProviderConfGlobal {
    let pcgbl = CRYPTO_zalloc(core::mem::size_of::<ProviderConfGlobal>(), FILE, L_PCGBL)
        .cast::<ProviderConfGlobal>();
    if pcgbl.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pcgbl` is this call's own fresh zeroed object.
    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        // SAFETY: `pcgbl` is this call's own allocation and has not been published.
        unsafe { CRYPTO_free(pcgbl.cast::<c_void>(), FILE, L_PCGBL_ERR) };
        return ptr::null_mut();
    }
    // SAFETY: `pcgbl` is this call's own live object, so writing its field does not alias.
    unsafe { (*pcgbl).lock = lock };

    pcgbl
}

/// `void ossl_prov_conf_ctx_free(void *vpcgbl)` — the slot's releaser.
///
/// `sk_OSSL_PROVIDER_pop_free(activated_providers, ossl_provider_free)` first — so every
/// provider this module activated is released through the provider layer's own teardown,
/// which is what deregisters it from the store — then the lock, then the object. The stack
/// itself is freed by `pop_free`; a NULL stack is accepted.
///
/// It does **not** check `pcgbl` for NULL, and neither does the authority: `context_deinit_objs`
/// is the only caller and it tests the *slot* first.
///
/// # Safety
/// `vpcgbl` must be NULL or the object [`ossl_prov_conf_ctx_new`] returned and this function
/// has not already released.
pub(crate) unsafe fn ossl_prov_conf_ctx_free(vpcgbl: *mut c_void) {
    let pcgbl = vpcgbl.cast::<ProviderConfGlobal>();
    if pcgbl.is_null() {
        return;
    }
    // SAFETY: `pcgbl` is live per the contract, so its two fields are this object's.
    unsafe {
        OPENSSL_sk_pop_free((*pcgbl).activated_providers, Some(provider_free_thunk));
        CRYPTO_THREAD_lock_free((*pcgbl).lock);
        CRYPTO_free(pcgbl.cast::<c_void>(), FILE, L_PCGBL_FREE);
    }
}

/// The `ossl_provider_free` callback in the shape `OPENSSL_sk_pop_free` takes. The authority
/// passes the function pointer directly; the registry's stack here is untyped, so the adapter
/// exists to make the coercion explicit rather than to change it.
unsafe extern "C" fn provider_free_thunk(value: *mut c_void) {
    // SAFETY: the list's entries are `OSSL_PROVIDER *` and it is handing each one over for
    // release.
    unsafe { ossl_provider_free(value.cast::<OsslProvider>()) };
}

/// `static const char *skip_dot(const char *name)`.
///
/// `strchr` and one increment, so **one** leading dot is skipped: `..foo` becomes `.foo`,
/// which is the authority's operation rather than a trim of every dot. A name with no dot is
/// returned unchanged, so this is not a "basename" either — `a.b` becomes `b` and `a.b.c`
/// becomes `b.c`.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn skip_dot(name: *const c_char) -> *const c_char {
    // SAFETY: `name` is NUL-terminated per the contract.
    let p = unsafe { crate::runtime::bio::sys::strchr(name, b'.' as c_int) };
    if p.is_null() {
        name
    } else {
        // SAFETY: `p` points at a byte inside `name`, so the byte after it is inside the same
        // allocation — including the terminator, which is a legitimate answer.
        unsafe { p.add(1) }
    }
}

/// `static int provider_conf_params_internal(OSSL_PROVIDER *prov, OSSL_PROVIDER_INFO *provinfo,
/// const char *name, const char *value, const CONF *cnf, STACK_OF(OPENSSL_CSTRING) *visited)`.
///
/// The recursive half. Returns 1 for success, 0 for a non-fatal failure and **-1** for a
/// fatal one, and the three answers mean different things to the caller — see the module
/// documentation for the recursion test and the buffer bound.
///
/// Two details of the walk are the authority's and each is easy to get wrong:
///
/// * a nested call's **0 is swallowed**: the loop only propagates `rc < 0`, so a section with
///   one bad parameter and one good one returns 1. Only the *fatal* answers escape.
/// * the terminal case adds the parameter through `OSSL_PROVIDER_add_conf_parameter` when
///   there is a provider and through `ossl_provider_info_add_parameter` when there is only a
///   template, so the two entry points of the module really do fill two different objects.
///
/// # Safety
/// `prov` must be NULL or live; `provinfo` must be NULL or live and non-NULL whenever `prov`
/// is NULL; `name` NULL or NUL-terminated; `value` NUL-terminated and owned by `cnf`; `cnf`
/// live; `visited` a live stack of `const char *` this walk owns.
unsafe fn provider_conf_params_internal(
    prov: *mut OsslProvider,
    provinfo: *mut OsslProviderInfo,
    name: *const c_char,
    value: *const c_char,
    cnf: *const Conf,
    visited: *mut OpenSslStack,
) -> c_int {
    let mut ok: c_int = 1;

    // SAFETY: `cnf` is live and `value` is NUL-terminated.
    let sect = unsafe { NCONF_get_section(cnf, value) };
    if !sect.is_null() {
        // SAFETY: `visited` is this walk's own live stack.
        let visited_count = unsafe { OPENSSL_sk_num(visited) };
        let mut i = 0;
        while i < visited_count {
            // SAFETY: `i < visited_count`, so this is one of the stack's own entries; the
            // comparison is of the *pointers* the `CONF` owns, which is the authority's test
            // and not `strcmp`.
            if unsafe { OPENSSL_sk_value(visited, i) }.cast_const() == value.cast_mut().cast() {
                // SAFETY: a compile-time-constant site and this thread's own error queue.
                unsafe { raise_site(&PROVIDER_CONF_100) };
                return -1;
            }
            i += 1;
        }

        // SAFETY: `visited` is live and `value` is kept alive by `cnf`, which outlives the
        // walk.
        if unsafe { OPENSSL_sk_push(visited, value.cast_mut().cast()) } == 0 {
            return -1;
        }

        // The accumulated prefix: `name` plus a dot, or empty at the top level.
        let mut buffer = [0 as c_char; BUFFER_SIZE];
        let mut buffer_len: usize = 0;
        if !name.is_null() {
            // `OPENSSL_strlcpy(buffer, name, sizeof(buffer))` then `OPENSSL_strlcat(buffer,
            // ".", ...)` — the pair truncates rather than overflowing, so the `>=` test inside
            // the loop is what actually refuses a long name.
            // SAFETY: both calls take the buffer's own address and length and a
            // NUL-terminated source.
            unsafe {
                strlcpy(buffer.as_mut_ptr(), name, BUFFER_SIZE);
                strlcat(buffer.as_mut_ptr(), c".".as_ptr(), BUFFER_SIZE);
            }
            // SAFETY: `buffer` is NUL-terminated by the two calls above.
            buffer_len = unsafe { c_strlen(buffer.as_ptr()) };
        }

        // SAFETY: `sect` is the section's own stack, live for the duration of this call.
        let count = unsafe { OPENSSL_sk_num(sect) };
        let mut j = 0;
        while j < count {
            // SAFETY: `j < count`, so this is one of the section's own entries.
            let sectconf = unsafe { OPENSSL_sk_value(sect, j) }.cast::<ConfValue>();
            // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated strings owned by
            // the `CONF`.
            let (entry_name, entry_value) = unsafe { ((*sectconf).name, (*sectconf).value) };
            // SAFETY: `entry_name` is NUL-terminated.
            let entry_len = unsafe { c_strlen(entry_name) };
            if buffer_len + entry_len >= BUFFER_SIZE {
                // SAFETY: `visited` is this walk's own stack and the push above is the
                // matching one.
                unsafe { OPENSSL_sk_pop(visited) };
                return -1;
            }
            // `buffer[buffer_len] = '\0'; OPENSSL_strlcat(buffer, sectconf->name, ...)`.
            buffer[buffer_len] = 0;
            // SAFETY: `buffer` has room for `entry_len` more bytes plus the terminator, per
            // the test above.
            unsafe { strlcat(buffer.as_mut_ptr(), entry_name, BUFFER_SIZE) };

            // SAFETY: all six arguments are the caller's, and the recursion's contract is this
            // function's.
            // SAFETY: all six arguments are the caller's, and the recursion's contract is
            // this function's.
            let rc = unsafe {
                provider_conf_params_internal(
                    prov,
                    provinfo,
                    buffer.as_ptr(),
                    entry_value,
                    cnf,
                    visited,
                )
            };
            if rc < 0 {
                // SAFETY: the matching pop for this call's push.
                unsafe { OPENSSL_sk_pop(visited) };
                return rc;
            }
            j += 1;
        }
        // SAFETY: the matching pop for this call's push.
        unsafe { OPENSSL_sk_pop(visited) };
    } else {
        // The terminal case. `name` is the accumulated parameter name and `value` its value.
        ok = if !prov.is_null() {
            // SAFETY: `prov` is live, so the address of its `parameters` field is valid for
            // the duration of the call, and both strings are NUL-terminated. This is the
            // authority's `OSSL_PROVIDER_add_conf_parameter`, whose body is this one call.
            unsafe { infopair_add(ptr::addr_of_mut!((*prov).parameters), name, value) }
        } else {
            // SAFETY: `provinfo` is live and both strings are NUL-terminated.
            unsafe { ossl_provider_info_add_parameter(provinfo, name, value) }
        };
    }

    ok
}

/// `static int provider_conf_params(OSSL_PROVIDER *prov, OSSL_PROVIDER_INFO *provinfo,
/// const char *name, const char *value, const CONF *cnf)`.
///
/// The `visited` stack's whole lifetime: it is created here, used by the recursion, and freed
/// here. A stack-allocation failure is **-1**, which is fatal, because without it a recursive
/// configuration would not terminate.
///
/// # Safety
/// As [`provider_conf_params_internal`], minus `visited`.
unsafe fn provider_conf_params(
    prov: *mut OsslProvider,
    provinfo: *mut OsslProviderInfo,
    name: *const c_char,
    value: *const c_char,
    cnf: *const Conf,
) -> c_int {
    // SAFETY: a fresh empty list; the entries are borrowed `const char *` from the `CONF`, so
    // the list owns nothing and `OPENSSL_sk_free` is the right release.
    let visited = OPENSSL_sk_new_null();
    if visited.is_null() {
        return -1;
    }

    // SAFETY: all five arguments are the caller's; `visited` is live.
    let rc = unsafe { provider_conf_params_internal(prov, provinfo, name, value, cnf, visited) };

    // SAFETY: `visited` is this function's own handle and its entries are not owned.
    unsafe { OPENSSL_sk_free(visited) };

    rc
}

/// `static int prov_already_activated(const char *name, STACK_OF(OSSL_PROVIDER) *activated)`.
///
/// A linear search of **this module's** list by name, and a NULL list is "nothing activated"
/// rather than an error. The comparison is `strcmp` against `OSSL_PROVIDER_get0_name`, so it
/// is the provider's name and not the section's.
///
/// # Safety
/// `name` must be NUL-terminated; `activated` NULL or a live stack of live providers.
unsafe fn prov_already_activated(name: *const c_char, activated: *mut OpenSslStack) -> c_int {
    if activated.is_null() {
        return 0;
    }
    // SAFETY: `activated` is live, so `OPENSSL_sk_num` is a length and not a dereference of
    // anything questionable.
    let max = unsafe { OPENSSL_sk_num(activated) };
    let mut i = 0;
    while i < max {
        // SAFETY: `i < max`, so this is one of the stack's own entries.
        let tstprov = unsafe { OPENSSL_sk_value(activated, i) }.cast::<OsslProvider>();
        // SAFETY: `tstprov` is a live provider and `name` is NUL-terminated.
        let pname = unsafe { ossl_provider_name(tstprov) };
        // SAFETY: both are NUL-terminated.
        if unsafe { crate::runtime::bio::sys::strcmp(pname, name) } == 0 {
            return 1;
        }
        i += 1;
    }
    0
}

/// `static int provider_conf_activate(OSSL_LIB_CTX *libctx, const char *name, const char
/// *value, const char *path, int soft, const CONF *cnf)`.
///
/// Loads and activates one provider, or finds that it is already activated.
///
/// Four behaviours are contract rather than implementation:
///
/// * **the module's lock is held across the whole body**, including the provider's own
///   construction, so two threads cannot both decide a provider is absent.
/// * **fallback loading is disabled first.** A configuration that names a provider must not
///   quietly fall back to another one, so `ossl_provider_disable_fallback_loading` runs
///   *before* the provider is looked for — and its failure is fatal rather than silent.
/// * **`soft` decides whether a failure is fatal.** A provider that cannot be found or built
///   answers -1 with `soft == 0` and 0 with `soft != 0`, and in the soft case the error queue
///   is **cleared** so the caller does not inherit a reason for a failure it was told to
///   tolerate.
/// * **the `actual` provider, not the one built here, is what gets recorded** when the store
///   already had an entry under that name: the newly built object is discarded and the
///   already-present one is activated and pushed.
///
/// # Safety
/// `libctx` must be NULL or live; `name` NUL-terminated; `value` and `cnf` live as
/// [`provider_conf_params`] requires; `path` NULL or NUL-terminated.
unsafe fn provider_conf_activate(
    libctx: *mut c_void,
    name: *const c_char,
    value: *const c_char,
    path: *const c_char,
    soft: c_int,
    cnf: *const Conf,
) -> c_int {
    // `OSSL_LIB_CTX_get_data` is a safe entry point that validates its own arguments: it
    // answers this context's slot-16 object or NULL, and the NULL case is the very next test.
    let pcgbl =
        lib_ctx_get_data(libctx, OSSL_LIB_CTX_PROVIDER_CONF_INDEX).cast::<ProviderConfGlobal>();
    let mut ok: c_int = 0;

    if pcgbl.is_null() {
        // SAFETY: a compile-time-constant site and this thread's own error queue.
        unsafe { raise_site(&PROVIDER_CONF_211) };
        return -1;
    }
    // SAFETY: `pcgbl` is live, so its lock was created by the slot's constructor.
    if unsafe { CRYPTO_THREAD_write_lock((*pcgbl).lock) } == 0 {
        // SAFETY: as above.
        unsafe { raise_site(&PROVIDER_CONF_211) };
        return -1;
    }

    // SAFETY: `pcgbl` is live and the lock is held.
    if unsafe { prov_already_activated(name, (*pcgbl).activated_providers) } == 0 {
        // SAFETY: the lock is held and `libctx` is NULL or live.
        if unsafe { ossl_provider_disable_fallback_loading(libctx) } == 0 {
            // SAFETY: the lock is held.
            unsafe { CRYPTO_THREAD_unlock((*pcgbl).lock) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&PROVIDER_CONF_224) };
            return -1;
        }

        // SAFETY: `libctx` is NULL or live and `name` is NUL-terminated. `noconfig = 1`
        // because this call *is* the configuration.
        let mut prov = unsafe { ossl_provider_find(libctx, name, 1) };
        if prov.is_null() {
            // SAFETY: as above, with no initialiser and no parameters — the parameters arrive
            // through `provider_conf_params` below.
            prov = unsafe { ossl_provider_new(libctx, name, None, ptr::null_mut(), 1) };
        }
        if prov.is_null() {
            // SAFETY: the lock is held.
            unsafe { CRYPTO_THREAD_unlock((*pcgbl).lock) };
            if soft != 0 {
                // A failure the caller was told to tolerate must not leave a reason behind.
                // `ERR_clear_error` is a safe entry point here, as it is everywhere in this
                // crate: it takes no arguments and touches only this thread's own queue.
                crate::runtime::err::ERR_clear_error();
            }
            return if soft == 0 { -1 } else { 0 };
        }

        if !path.is_null() {
            // SAFETY: `prov` is live and `path` is NUL-terminated.
            unsafe { ossl_provider_set_module_path(prov, path) };
        }

        // SAFETY: `prov` is live and the template is NULL, which is the activated half.
        ok = unsafe { provider_conf_params(prov, ptr::null_mut(), ptr::null(), value, cnf) };

        if ok == 1 {
            // SAFETY: `prov` is live.
            if unsafe { ossl_provider_activate(prov, 1, 0) } == 0 {
                ok = 0;
            } else {
                let mut actual: *mut OsslProvider = ptr::null_mut();
                // SAFETY: `prov` is live and `actual` is writable.
                if unsafe { ossl_provider_add_to_store(prov, &mut actual, 0) } == 0 {
                    // SAFETY: `prov` is live and still up-refd.
                    unsafe { ossl_provider_deactivate(prov, 1) };
                    ok = 0;
                } else if actual != prov
                    // SAFETY: `actual` is the store's winner and is live.
                    && unsafe { ossl_provider_activate(actual, 1, 0) } == 0
                {
                    // SAFETY: `actual` is live and this call holds the reference the store
                    // handed over.
                    unsafe { ossl_provider_free(actual) };
                    ok = 0;
                } else {
                    // SAFETY: `pcgbl` is live and the lock is held, so this list is this
                    // thread's to grow.
                    unsafe {
                        if (*pcgbl).activated_providers.is_null() {
                            (*pcgbl).activated_providers = OPENSSL_sk_new_null();
                        }
                        if (*pcgbl).activated_providers.is_null()
                            || OPENSSL_sk_push((*pcgbl).activated_providers, actual.cast()) == 0
                        {
                            ossl_provider_deactivate(actual, 1);
                            ossl_provider_free(actual);
                            ok = 0;
                        } else {
                            ok = 1;
                        }
                    }
                }
            }
        }

        if ok <= 0 {
            // SAFETY: `prov` is live and this call holds its reference.
            unsafe { ossl_provider_free(prov) };
        }
    }
    // SAFETY: `pcgbl` is live and the lock is held by this thread.
    unsafe { CRYPTO_THREAD_unlock((*pcgbl).lock) };

    ok
}

/// `static int provider_conf_parse_bool_setting(const char *confname, const char *confvalue,
/// int *val)`.
///
/// Seven true spellings and seven false ones, **exactly**: `1`/`yes`/`YES`/`true`/`TRUE`/`on`/
/// `ON` and `0`/`no`/`NO`/`false`/`FALSE`/`off`/`OFF`. A NULL value is refused, and so is
/// anything else — including `Yes`, `On`, `2` and the empty string, all of which raise
/// `CRYPTO_R_PROVIDER_SECTION_ERROR` with the `"directive %s set to unrecognized value"`
/// message.
///
/// # Safety
/// `confname` must be NUL-terminated and is used only in the raised message; `confvalue` NULL
/// or NUL-terminated; `val` writable.
unsafe fn provider_conf_parse_bool_setting(
    confname: *const c_char,
    confvalue: *const c_char,
    val: *mut c_int,
) -> c_int {
    if confvalue.is_null() {
        // SAFETY: this thread's own error queue; the site and the message are the authority's.
        unsafe { raise_site_data(&PROVIDER_CONF_280, directive_message(confname)) };
        return 0;
    }

    // SAFETY: `confvalue` is NUL-terminated.
    if matches_any(confvalue, TRUE_WORDS) != 0 {
        // SAFETY: `val` is writable per the contract.
        unsafe { *val = 1 };
    } else if matches_any(confvalue, FALSE_WORDS) != 0 {
        // SAFETY: as above.
        unsafe { *val = 0 };
    } else {
        // SAFETY: this thread's own error queue; the second site and the same message.
        unsafe { raise_site_data(&PROVIDER_CONF_302, directive_message(confname)) };
        return 0;
    }

    1
}

/// The seven spellings that mean true, in the authority's own order.
const TRUE_WORDS: &[*const c_char] = &[
    c"1".as_ptr(),
    c"yes".as_ptr(),
    c"YES".as_ptr(),
    c"true".as_ptr(),
    c"TRUE".as_ptr(),
    c"on".as_ptr(),
    c"ON".as_ptr(),
];
/// The seven that mean false.
const FALSE_WORDS: &[*const c_char] = &[
    c"0".as_ptr(),
    c"no".as_ptr(),
    c"NO".as_ptr(),
    c"false".as_ptr(),
    c"FALSE".as_ptr(),
    c"off".as_ptr(),
    c"OFF".as_ptr(),
];

/// Whether `s` is `strcmp`-equal to any of `words`.
///
/// A **safe** function, per D113's rule: it dereferences neither argument, so it has no
/// contract of its own to state -- both pointers are handed to `strcmp`, which is where the
/// requirement lives. That is what lets the two call sites below stand in an `if`/`else if`
/// chain without each needing an `unsafe` block of its own.
///
/// # Safety
/// The caller's responsibility, discharged by the call sites: `s` must be NUL-terminated, and
/// every entry of `words` is a static literal.
fn matches_any(s: *const c_char, words: &[*const c_char]) -> c_int {
    for w in words {
        // SAFETY: `s` is NUL-terminated and `w` is a static literal -- the contract this
        // function's caller meets.
        if unsafe { crate::runtime::bio::sys::strcmp(s, *w) } == 0 {
            return 1;
        }
    }
    0
}

/// Whether `a` and `b` are `strcmp`-equal. Safe for the same reason as [`matches_any`].
///
/// # Safety
/// Both must be NUL-terminated.
fn same(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: both are NUL-terminated per the contract.
    unsafe { crate::runtime::bio::sys::strcmp(a, b) == 0 }
}

/// `static int provider_conf_load(OSSL_LIB_CTX *libctx, const char *name, const char *value,
/// const CONF *cnf)`.
///
/// One entry of the `providers` section. The **first pass** reads the command section and
/// picks out the four special commands; the second decides between activation and a template.
///
/// The answer is `ok >= 0`, which collapses activation's tristate: 1 for a successful
/// activation, 1 for a **non-fatal** activation failure, and 0 only for a fatal one. A caller
/// therefore sees only success or a fatal failure, and that is deliberate — a `soft_load`
/// provider that could not be loaded must not fail the configuration.
///
/// `name = skip_dot(name)` happens **before** the section is read and again is not undone, so
/// a section entry written `.default` and one written `default` take the same path.
///
/// # Safety
/// `libctx` must be NULL or live; `name` and `value` NUL-terminated; `cnf` live.
unsafe fn provider_conf_load(
    libctx: *mut c_void,
    name: *const c_char,
    value: *const c_char,
    cnf: *const Conf,
) -> c_int {
    let mut soft: c_int = 0;
    let mut path: *const c_char = ptr::null();
    let mut activate: c_int = 0;
    let mut ok: c_int;
    let mut added: c_int = 0;

    // SAFETY: `name` is NUL-terminated.
    let mut name = unsafe { skip_dot(name) };

    // SAFETY: `cnf` is live and `value` is NUL-terminated.
    let ecmds = unsafe { NCONF_get_section(cnf, value) };
    if ecmds.is_null() {
        // SAFETY: this thread's own error queue, the generated site, and the `section=%s`
        // message the authority formats.
        unsafe { raise_site_data(&PROVIDER_CONF_328, section_not_found_message(value)) };
        return 0;
    }

    // SAFETY: `ecmds` is the section's own stack, live for the duration of this call.
    let count = unsafe { OPENSSL_sk_num(ecmds) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of the section's own entries.
        let ecmd = unsafe { OPENSSL_sk_value(ecmds, i) }.cast::<ConfValue>();
        // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated and owned by `cnf`.
        let (raw_name, confvalue) = unsafe { ((*ecmd).name, (*ecmd).value) };
        // SAFETY: `raw_name` is NUL-terminated.
        let confname = unsafe { skip_dot(raw_name) };

        // The four pseudo-commands. `strcmp` on the *dot-stripped* name, so `.activate` and
        // `activate` are the same command. `same` is safe and its contract is the one line
        // above: `confname` is NUL-terminated and each literal is static -- which is what lets
        // the chain stand without an `unsafe` block per comparison.
        if same(confname, c"identity".as_ptr()) {
            name = confvalue;
        } else if same(confname, c"soft_load".as_ptr()) {
            // SAFETY: all three arguments are this call's.
            if unsafe { provider_conf_parse_bool_setting(confname, confvalue, &mut soft) } == 0 {
                return 0;
            }
        } else if same(confname, c"module".as_ptr()) {
            path = confvalue;
        } else if same(confname, c"activate".as_ptr()) {
            // SAFETY: as above.
            if unsafe { provider_conf_parse_bool_setting(confname, confvalue, &mut activate) } == 0
            {
                return 0;
            }
        }
        i += 1;
    }

    if activate != 0 {
        // SAFETY: all six arguments are this call's.
        ok = unsafe { provider_conf_activate(libctx, name, value, path, soft, cnf) };
    } else {
        // The template path. The authority builds the entry on the **stack** and zeroes it, so
        // every field it does not set is NULL -- including `init`, which is what makes the
        // entry a description rather than a provider.
        // SAFETY: every field of `OsslProviderInfo` is either a pointer, a count or an
        // `Option<fn>` -- all of which have a valid all-zero bit pattern -- so a zeroed value
        // is a valid instance whose strings are NULL and whose list is empty.
        let mut entry: OsslProviderInfo = unsafe { core::mem::zeroed() };
        ok = 1;
        if !name.is_null() {
            // SAFETY: `name` is NUL-terminated.
            entry.name = unsafe { CRYPTO_strdup(name, FILE, L_ENTRY_NAME) };
            if entry.name.is_null() {
                ok = 0;
            }
        }
        if ok != 0 && !path.is_null() {
            // SAFETY: `path` is NUL-terminated.
            entry.path = unsafe { CRYPTO_strdup(path, FILE, L_ENTRY_PATH) };
            if entry.path.is_null() {
                ok = 0;
            }
        }
        if ok != 0 {
            // SAFETY: `prov` is NULL and the template is this call's own stack object, so the
            // parameters land in it.
            ok = unsafe {
                provider_conf_params(ptr::null_mut(), &mut entry, ptr::null(), value, cnf)
            };
        }
        if ok >= 1 && (!entry.path.is_null() || !entry.parameters.is_null()) {
            // SAFETY: `libctx` is NULL or live and `entry` is live.
            ok = unsafe { ossl_provider_info_add_to_store(libctx, &mut entry) };
            added = ok;
        }
        if added == 0 {
            // SAFETY: `entry` is live; the store took a copy or refused it, so its two strings
            // and its parameter list are this call's to release.
            unsafe { ossl_provider_info_clear(&mut entry) };
        }
    }

    // `ok >= 0` — see the documentation for why the tristate collapses here.
    if ok >= 0 {
        1
    } else {
        0
    }
}

/// `static int provider_conf_init(CONF_IMODULE *md, const CONF *cnf)` — the module's reader.
///
/// The module's value names the section whose entries are provider names. Each entry is one
/// [`provider_conf_load`], and the **first** one that answers 0 stops the walk — so a
/// configuration with three providers where the second fails leaves the first activated and
/// the third untouched, and the error queue holds the second one's reason.
///
/// # Safety
/// `md` must be a live initialisation and `cnf` the configuration it was loaded from.
unsafe extern "C" fn provider_conf_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // SAFETY: `md` is live per the callback's contract.
    let value = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `value` is NUL-terminated.
    let elist = unsafe { NCONF_get_section(cnf, value) };
    if elist.is_null() {
        // SAFETY: this thread's own error queue and the generated site, which carries no data.
        unsafe { raise_site(&PROVIDER_CONF_412) };
        return 0;
    }

    // SAFETY: `cnf` is live, so its owning context is this file's to pass on.
    let libctx = unsafe { NCONF_get0_libctx(cnf.cast_mut()) };
    // SAFETY: `elist` is the section's own stack, live for the duration of this call.
    let count = unsafe { OPENSSL_sk_num(elist) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of the section's own entries.
        let cval = unsafe { OPENSSL_sk_value(elist, i) }.cast::<ConfValue>();
        // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated and owned by `cnf`.
        let (name, value) = unsafe { ((*cval).name, (*cval).value) };
        // SAFETY: all four arguments are this call's.
        if unsafe { provider_conf_load(libctx, name, value, cnf) } == 0 {
            return 0;
        }
        i += 1;
    }

    1
}

/// `void ossl_provider_add_conf_module(void)` — the seventh call of
/// `OPENSSL_load_builtin_modules`, and the last one this stratum can make.
///
/// One `CONF_module_add` with a **NULL** finish function, unlike `ssl_conf`'s: this module has
/// nothing to tear down at unload time, because what it built belongs to the provider store
/// and to the context's slot 16, both of which the context releases itself.
pub(crate) fn ossl_provider_add_conf_module() {
    // SAFETY: the name is a static NUL-terminated string, and the initialiser is the
    // registry's declared type.
    unsafe {
        CONF_module_add(
            c"providers".as_ptr(),
            Some(provider_conf_init as crate::runtime::confmod::ConfInitFn),
            None,
        );
    }
}

// ---------------------------------------------------------------------------
// The two helpers the transcription needs and the authority gets from libc
// ---------------------------------------------------------------------------

/// `size_t strlen(const char *)`.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract, so this walk is bounded.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `size_t OPENSSL_strlcpy(char *dst, const char *src, size_t siz)`.
///
/// The authority's version, which is `o_str.c`'s and which the crate already has as an
/// export; this is the internal spelling the module uses.
///
/// # Safety
/// `dst` must be writable for `siz` bytes and `src` NUL-terminated.
unsafe fn strlcpy(dst: *mut c_char, src: *const c_char, siz: usize) -> usize {
    if siz == 0 {
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: `src` is NUL-terminated and `dst` has `siz` writable bytes.
    unsafe {
        while i + 1 < siz {
            let c = *src.add(i);
            if c == 0 {
                break;
            }
            *dst.add(i) = c;
            i += 1;
        }
        *dst.add(i) = 0;
        c_strlen(src)
    }
}

/// `size_t OPENSSL_strlcat(char *dst, const char *src, size_t siz)`.
///
/// # Safety
/// `dst` must be NUL-terminated and writable for `siz` bytes; `src` NUL-terminated.
unsafe fn strlcat(dst: *mut c_char, src: *const c_char, siz: usize) -> usize {
    // SAFETY: `dst` is NUL-terminated per the contract.
    let dst_len = unsafe { c_strlen(dst) };
    if dst_len >= siz {
        // The authority's own answer for a full destination: no write, and the length it
        // *would* have been.
        // SAFETY: `src` is NUL-terminated.
        return siz + unsafe { c_strlen(src) };
    }
    // SAFETY: the copy starts at the destination's terminator and is bounded by `siz`.
    unsafe {
        let copied = strlcpy(dst.add(dst_len), src, siz - dst_len);
        dst_len + copied
    }
}

/// `"directive %s set to unrecognized value"` — the message both bool-setting raises carry.
///
/// A `static` buffer, as `confmod/mod.rs`'s three are, for the reason recorded there: the
/// authority's `ERR_vset_error` allocates, the raise copies the bytes before returning, and no
/// caller holds the pointer afterwards. `BIO_snprintf` is the function `ERR_vset_error` itself
/// formats through.
///
/// # Safety
/// `confname` must be NUL-terminated.
unsafe fn directive_message(confname: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: the buffer is a static of exactly the declared length and the format string is a
    // static NUL-terminated one whose single conversion is `%s`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"directive %s set to unrecognized value".as_ptr(),
            confname,
        )
    };
    // SAFETY: the pointer is to the static written immediately above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `"section=%s not found"` — the message `provider_conf_load` raises.
///
/// # Safety
/// `value` must be NUL-terminated.
unsafe fn section_not_found_message(value: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: as `directive_message`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"section=%s not found".as_ptr(),
            value,
        )
    };
    // SAFETY: as above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `ERR_MAX_DATA_SIZE`, from `crypto/err/err_local.h`. The authority refuses to format a
/// message longer than this, so a longer one is truncated in both implementations.
const ERR_MAX_DATA_SIZE: usize = 1024;
