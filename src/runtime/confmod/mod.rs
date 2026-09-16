//! Phase 6.10b — `crypto/conf/conf_mod.c`: the configuration module registry.
//!
//! `openssl.cnf` does not only hold values; it names *modules* that are handed the
//! configuration and may act on it. `CONF_modules_load` resolves the section the file names,
//! looks each entry up in a registry of modules, and calls the one it finds. This module is
//! that registry, and its fifteen exports are the surface a consumer uses to add a module,
//! drive a load, and read what a module's initialiser recorded.
//!
//! ## Two lists, and the discipline that makes them lock-free to read
//!
//! `supported_modules` holds one entry per *module* — registered statically by
//! `CONF_module_add`, or by loading a DSO. `initialized_modules` holds one entry per
//! *successful initialisation*, and there may be several for one module, because
//! `module_find` deliberately lets one module be named more than once. Both are `STACK_OF`
//! **pointers**, and neither is ever mutated in place. Every change is
//!
//! ```text
//! ossl_rcu_write_lock
//!   old = supported_modules          (the live list)
//!   new = sk_dup(old)                (a *shallow* copy: the array, not the entries)
//!   ... push, or delete-and-collect ...
//!   ossl_rcu_assign_ptr(&supported_modules, &new)
//! ossl_rcu_write_unlock
//! ossl_synchronize_rcu               (wait for readers of `old`)
//! sk_free(old)                       (release the old array)
//! ```
//!
//! The `dup` being shallow is what makes the last line correct rather than a double free: the
//! old handle owns an array of pointers and nothing behind them, and the entries themselves
//! belong to the list that is still live. So a **reader takes no lock at all** — it takes an
//! RCU read hold, dereferences the published pointer, walks, and releases — which is what
//! `CONF_modules_load` needs, because it may run from a module's own initialiser.
//!
//! ## This registry is why RCU exists in this build
//!
//! `ossl_rcu_lock_new(1, NULL)` at `conf_mod.c:102` is the **only** call to the RCU layer in
//! the whole library, and the `1` is raised to two quiescent points by `ossl_rcu_lock_new`
//! itself. That is `D-RCU-4`'s consequence narrowing: the RCU layer's evidence is its
//! transcription and its unit tests today, and this consumer is what makes `RT-CONF-MOD` able
//! to reach it.
//!
//! ## Where the `OSSL_TRACE` calls went
//!
//! `CONF_modules_load` has `OSSL_TRACE1(CONF, ...)` at `:157` and `OSSL_TRACE3(CONF, ...)` at
//! `:177`. The pinned profile is configured `no-trace`, so `OPENSSL_NO_TRACE` is defined and
//! `OSSL_TRACE*` expands to nothing (`src/runtime/trace.rs` records the measurement). There is
//! no trace call to transcribe, and a reader comparing the two files should not look for one.
//!
//! ## Six of the seven initialisers `OPENSSL_load_builtin_modules` calls are other strata's
//!
//! The function's content is seven calls, and the authority's comment — `/* Add builtin
//! modules here */` — is the whole of its design. `ASN1_add_oid_module` is this block's (6.10d)
//! and is called. `ASN1_add_stable_module` (Phase 11, whose handler needs `X509V3_parse_list`),
//! `EVP_add_alg_module` (Phase 7), `ossl_config_add_ssl_module` (libssl, Phase 14),
//! `ossl_provider_add_conf_module` (6.8d), `ossl_random_add_conf_module` (Phase 9) and
//! `ENGINE_add_conf_module` (Phase 13) are not.
//!
//! **Their absence is a divergence, not a stub.** A configuration whose `openssl_conf` names
//! `openssl_init` and whose section asks for one of those modules observes the difference: the
//! authority registers six modules there and this crate registers one. That is the "fan-out is
//! a recorded residual" D121 named, and `RT-CONF-MOD` observes it directly — the registry is
//! append-only here, so a stack's length is the observable.
//!
//! ## The error coordinates are generated
//!
//! Every raise in this file is one of `src/runtime/err_sites.rs`'s `CONF_MOD_<line>` constants,
//! because the generator that writes them reads the authority's own source. `CONF_MOD_331` is
//! the one whose **reason is a variable** — `module_load_dso` raises with `errcode`, set by
//! which of three steps failed — so it goes through `raise_site_dynamic` rather than
//! `raise_site`. Two of the reasons in this file are `ERR_R_CRYPTO_LIB`, which the generator
//! records as the *packed* word `524303` rather than as the reason alone, because
//! `set_error` takes the packed word.
//!
//! Three messages carry arguments, and all three are built with [`BIO_snprintf`] — the
//! authority's own formatter, `crypto/bio/bio_print.c`'s `ossl_do_vsnprintf`, which is the
//! function `ERR_vset_error` itself formats through. That matters for one of them:
//! `"module=%s, value=%s retcode=%-8d"` pads the return code to eight columns *left*
//! justified, and Rust's formatting language has no equivalent, so building it with `format!`
//! would have produced different bytes.
//!
//! ## `ossl_config_modules_free` is called from `OPENSSL_cleanup`, and its order is fixed
//!
//! `CONF_modules_unload(1)` — which itself calls `conf_modules_finish_int` first — then
//! `module_lists_free`, which frees the RCU lock and NULLs both lists.
//! `conf_modules_finish_int` answers **0** when the lock is already NULL, with the authority's
//! own reason: *"If module_list_lock is NULL here it means we were already unloaded."* An
//! unload after the free therefore returns early rather than faulting, and that NULL test is
//! load-bearing rather than defensive.
//!
//! SPDX-License-Identifier: Apache-2.0

// The authority's names are kept verbatim: `ABI-PROTOTYPE` and the export courts resolve
// exports by name, and a `CONF_modules_load` renamed to `conf_modules_load` would be a
// different symbol.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::bio::print::BIO_snprintf;

use crate::dso::{DSO_bind_func, DSO_free, DSO_load, Dso};
use crate::runtime::conf::api::_CONF_get_string;
use crate::runtime::conf::lib::{
    NCONF_free, NCONF_get_number_e, NCONF_get_section, NCONF_get_string, NCONF_load, NCONF_new_ex,
};
use crate::runtime::conf::modparse::CONF_get1_default_config_file;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::err::err_reasons::CONF_R_NO_SUCH_FILE;
use crate::runtime::err::err_sites::{
    CONF_MOD_104, CONF_MOD_163, CONF_MOD_276, CONF_MOD_286, CONF_MOD_331, CONF_MOD_475,
    CONF_MOD_482,
};
use crate::runtime::err::{
    peek_last_reason, raise_site, raise_site_data, raise_site_dynamic, ERR_clear_last_mark,
    ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::rcu::{
    ossl_rcu_assign_uptr, ossl_rcu_lock_free, ossl_rcu_lock_new, ossl_rcu_read_lock,
    ossl_rcu_read_unlock, ossl_rcu_uptr_deref, ossl_rcu_write_lock, ossl_rcu_write_unlock,
    ossl_synchronize_rcu, RcuLockSt,
};
pub mod asn1;

use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::CRYPTO_THREAD_run_once;

use crate::context::{OSSL_LIB_CTX_get_conf_diagnostics, OSSL_LIB_CTX_set_conf_diagnostics};

/// `crypto/conf/conf_mod.c`, for the coordinates of every allocation this module makes.
///
/// The authority's own string, which `OPENSSL_FILE` expands to — including the `../../` prefix,
/// because the object file was compiled from inside the build tree.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c".as_ptr();

// The authority's allocation coordinates, one per call site. `OPENSSL_zalloc`,
// `OPENSSL_malloc` and `OPENSSL_strdup` are macros over `CRYPTO_*` that fill in
// `OPENSSL_FILE`/`OPENSSL_LINE` at the call, so each of these is the line the macro expands on
// rather than the line of any definition.
/// `new = OPENSSL_zalloc(sizeof(*new))` in `module_add`.
const L_MODULE_NEW: c_int = 358;
/// `tmod->name = OPENSSL_strdup(name)` in `module_add`.
const L_MODULE_NAME: c_int = 362;
/// `imod = OPENSSL_malloc(sizeof(*imod))` in `module_init`.
const L_IMODULE_NEW: c_int = 440;
/// `imod->name = OPENSSL_strdup(name)`.
const L_IMODULE_NAME: c_int = 445;
/// `imod->value = OPENSSL_strdup(value)`.
const L_IMODULE_VALUE: c_int = 446;
/// `OPENSSL_free(tmod->name)`/`OPENSSL_free(tmod)` in `module_add`'s error arm.
const L_MODULE_FREE_ERR: c_int = 381;
/// `OPENSSL_free(md->name)`/`OPENSSL_free(md)` in `module_free`.
const L_MODULE_FREE: c_int = 566;
/// `OPENSSL_free(imod->name)`, `OPENSSL_free(imod->value)`, `OPENSSL_free(imod)` in
/// `module_finish` and in `module_init`'s `memerr` arm.
const L_IMODULE_FREE: c_int = 616;

/// `ERR_MAX_DATA_SIZE`, from `crypto/err/err_local.h`.
///
/// The authority's `ERR_vset_error` refuses to format a message longer than this, so one that
/// would exceed it is truncated in both implementations. The three messages in this file are
/// built with [`BIO_snprintf`], so the truncation point is the same one.
const ERR_MAX_DATA_SIZE: usize = 1024;

/// `#define CONF_R_ERROR_LOADING_DSO` — `include/openssl/conferr.h`.
const CONF_R_ERROR_LOADING_DSO: c_int = 110;
/// `#define CONF_R_MISSING_INIT_FUNCTION` — `include/openssl/conferr.h`.
const CONF_R_MISSING_INIT_FUNCTION: c_int = 112;

/// `#define DEFAULT_CONF_MFLAGS` — `include/internal/conf.h`.
///
/// `CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE | CONF_MFLAGS_IGNORE_RETURN_CODES`.
pub const DEFAULT_CONF_MFLAGS: c_ulong =
    CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE | CONF_MFLAGS_IGNORE_RETURN_CODES;

/// `#define CONF_MFLAGS_IGNORE_ERRORS 0x1` — `openssl/conf.h`.
pub const CONF_MFLAGS_IGNORE_ERRORS: c_ulong = 0x1;
/// `#define CONF_MFLAGS_IGNORE_RETURN_CODES 0x2` — `openssl/conf.h`.
pub const CONF_MFLAGS_IGNORE_RETURN_CODES: c_ulong = 0x2;
/// `#define CONF_MFLAGS_SILENT 0x4` — `openssl/conf.h`.
pub const CONF_MFLAGS_SILENT: c_ulong = 0x4;
/// `#define CONF_MFLAGS_NO_DSO 0x8` — `openssl/conf.h`.
pub const CONF_MFLAGS_NO_DSO: c_ulong = 0x8;
/// `#define CONF_MFLAGS_IGNORE_MISSING_FILE 0x10` — `openssl/conf.h`.
pub const CONF_MFLAGS_IGNORE_MISSING_FILE: c_ulong = 0x10;
/// `#define CONF_MFLAGS_DEFAULT_SECTION 0x20` — `openssl/conf.h`.
pub const CONF_MFLAGS_DEFAULT_SECTION: c_ulong = 0x20;

/// `typedef int conf_init_func(CONF_IMODULE *md, const CONF *cnf)` — `openssl/conf.h`.
///
/// Unnamed parameters, for the reason `ProviderInitFn` states: `ABI-PROTOTYPE` reads a function
/// pointer's *types*, and a named argument is not one.
pub type ConfInitFn = unsafe extern "C" fn(*mut ConfImodule, *const Conf) -> c_int;

/// `typedef void conf_finish_func(CONF_IMODULE *md)` — `openssl/conf.h`.
pub type ConfFinishFn = unsafe extern "C" fn(*mut ConfImodule);

/// `struct conf_module_st` — `CONF_MODULE`.
///
/// Opaque to a consumer: it is reached only through `CONF_module_add`'s two accessors and
/// through `CONF_imodule_get_module`.
#[repr(C)]
pub struct ConfModule {
    /// `DSO *dso` — the loaded object, or NULL for a static module. Owned here, released by
    /// [`module_free`].
    pub(crate) dso: *mut Dso,
    /// `char *name` — a copy, owned here.
    pub(crate) name: *mut c_char,
    /// `conf_init_func *init` — the initialiser, or NULL.
    pub(crate) init: Option<ConfInitFn>,
    /// `conf_finish_func *finish` — the teardown, or NULL.
    pub(crate) finish: Option<ConfFinishFn>,
    /// `int links` — how many live initialisations name this module.
    pub(crate) links: c_int,
    /// `void *usr_data` — a value the consumer stores; never touched here.
    pub(crate) usr_data: *mut c_void,
}

/// `struct conf_imodule_st` — `CONF_IMODULE`.
///
/// One *successful initialisation*. `flags` is not set by this module at all: it is a field the
/// module's own initialiser writes through `CONF_imodule_set_flags`, which is why that accessor
/// pair exists.
#[repr(C)]
pub struct ConfImodule {
    /// `CONF_MODULE *pmod` — the registry entry this initialisation is of.
    pub(crate) pmod: *mut ConfModule,
    /// `char *name` — the name the configuration used; a copy owned here.
    pub(crate) name: *mut c_char,
    /// `char *value` — the value the configuration gave; a copy owned here.
    pub(crate) value: *mut c_char,
    /// `unsigned long flags` — written by the initialiser.
    pub(crate) flags: c_ulong,
    /// `void *usr_data` — a value the initialiser stores; never touched here.
    pub(crate) usr_data: *mut c_void,
}

/// `static CRYPTO_ONCE init_module_list_lock` — the run-once that creates the RCU lock.
///
/// An `AtomicI32` rather than a bare `static`, because `pthread_once` writes through the pointer
/// it is given and a bare `static` is in read-only storage — the defect that crashed
/// `OSSL_LIB_CTX_new()` once already (D106).
static INIT_MODULE_LIST_LOCK: AtomicI32 = AtomicI32::new(0);

/// `static CRYPTO_RCU_LOCK *module_list_lock` — the lock protecting both lists, or NULL before
/// the once has run and after [`module_lists_free`].
///
/// An `AtomicPtr` rather than a bare pointer behind an `unsafe impl Sync`, because the ordering
/// that matters is the once's: every read happens after `RUN_ONCE` answered 1, which is a
/// synchronisation point. The `Acquire` load here is belt-and-braces rather than the mechanism,
/// and it costs nothing.
static MODULE_LIST_LOCK: AtomicPtr<RcuLockSt> = AtomicPtr::new(ptr::null_mut());

/// `static STACK_OF(CONF_MODULE) *supported_modules` — the registry. Replaced wholesale.
///
/// Reached through [`ossl_rcu_uptr_deref`]/[`ossl_rcu_assign_uptr`], which are the authority's
/// own `ossl_rcu_deref`/`ossl_rcu_assign_ptr`; the `AtomicPtr` is the storage they operate on.
static SUPPORTED_MODULES: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static STACK_OF(CONF_IMODULE) *initialized_modules` — the live initialisations.
static INITIALIZED_MODULES: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static CRYPTO_ONCE load_builtin_modules` — the once behind
/// `DEFINE_RUN_ONCE_STATIC(do_load_builtin_modules)`.
static LOAD_BUILTIN_MODULES: AtomicI32 = AtomicI32::new(0);

/// `DEFINE_RUN_ONCE_STATIC(do_init_module_list_lock)`.
///
/// A **safe** `extern "C" fn`, because that is the type `CRYPTO_THREAD_run_once` takes: a once
/// body is called by `pthread_once`, and an `unsafe fn` is not coercible to it.
extern "C" fn do_init_module_list_lock() {
    // SAFETY: a NULL context resolves to the default one, and this is the authority's own
    // argument — `ossl_rcu_lock_new(1, NULL)`.
    let lock = unsafe { ossl_rcu_lock_new(1, ptr::null_mut()) };
    if lock.is_null() {
        // SAFETY: the site is a compile-time constant generated from the authority's source.
        unsafe { raise_site(&CONF_MOD_104) };
        return;
    }
    MODULE_LIST_LOCK.store(lock, Ordering::Release);
}

/// `DEFINE_RUN_ONCE_STATIC(do_load_builtin_modules)`.
extern "C" fn do_load_builtin_modules() {
    OPENSSL_load_builtin_modules();
    // `ENGINE_load_builtin_engines()` follows in the authority under `!OPENSSL_NO_ENGINE`, and
    // ENGINE **is** enabled in this profile. Phase 13 owns it; see the module documentation for
    // why its absence is a recorded divergence rather than a stub.
}

/// `RUN_ONCE(&init_module_list_lock, do_init_module_list_lock)` — true when the lock exists.
fn ensure_module_list_lock() -> bool {
    // SAFETY: the once is this module's own static, initially zero, and the body is a safe
    // `extern "C" fn` of no arguments.
    let ran = unsafe {
        CRYPTO_THREAD_run_once(
            INIT_MODULE_LIST_LOCK.as_ptr(),
            Some(do_init_module_list_lock),
        )
    };
    ran != 0
}

/// The live lock, or NULL when the once has not run or [`module_lists_free`] has.
fn module_list_lock() -> *mut RcuLockSt {
    MODULE_LIST_LOCK.load(Ordering::Acquire)
}

/// `ossl_rcu_deref(&supported_modules)` — the `Acquire` load of the published list.
///
/// The authority spells this `ossl_rcu_deref`, which is `ossl_rcu_uptr_deref` with a cast; this
/// calls the second so that the memory order is stated in one place for both.
fn supported_modules() -> *mut OpenSslStack {
    // SAFETY: this is a `*mut *mut c_void` view of a live `AtomicPtr<OpenSslStack>`, which is
    // the contract `ossl_rcu_uptr_deref` states.
    unsafe { ossl_rcu_uptr_deref(SUPPORTED_MODULES.as_ptr().cast::<*mut c_void>()) }
        .cast::<OpenSslStack>()
}

/// `ossl_rcu_deref(&initialized_modules)`.
fn initialized_modules() -> *mut OpenSslStack {
    // SAFETY: as `supported_modules`.
    unsafe { ossl_rcu_uptr_deref(INITIALIZED_MODULES.as_ptr().cast::<*mut c_void>()) }
        .cast::<OpenSslStack>()
}

/// `ossl_rcu_assign_ptr(&supported_modules, &new)` — the `Release` publication.
///
/// # Safety
/// The caller must hold the write lock, and `new` must be a list this thread owns and is
/// transferring to the registry.
unsafe fn publish_supported(new: *mut OpenSslStack) {
    let mut value = new.cast::<c_void>();
    // SAFETY: the caller holds the write lock, so this thread is the only writer, and the double
    // pointer is a `*mut *mut c_void` view of a live `AtomicPtr`.
    unsafe { ossl_rcu_assign_uptr(SUPPORTED_MODULES.as_ptr().cast::<*mut c_void>(), &mut value) };
}

/// `ossl_rcu_assign_ptr(&initialized_modules, &new)` — the `Release` publication.
///
/// # Safety
/// As [`publish_supported`].
unsafe fn publish_initialized(new: *mut OpenSslStack) {
    let mut value = new.cast::<c_void>();
    // SAFETY: as `publish_supported`.
    unsafe {
        ossl_rcu_assign_uptr(
            INITIALIZED_MODULES.as_ptr().cast::<*mut c_void>(),
            &mut value,
        )
    };
}

/// `static void module_free(CONF_MODULE *md)` — releases one registry entry.
///
/// # Safety
/// `md` must be NULL or an entry this module allocated and has already removed from every list,
/// so that nothing can reach it.
unsafe fn module_free(md: *mut ConfModule) {
    if md.is_null() {
        return;
    }
    // SAFETY: per the contract the entry is unreachable, so its fields are this thread's to
    // take. `DSO_free` accepts NULL and both frees do.
    unsafe {
        DSO_free((*md).dso);
        CRYPTO_free((*md).name.cast(), FILE, L_MODULE_FREE);
        CRYPTO_free(md.cast(), FILE, L_MODULE_FREE);
    }
}

/// The `module_free` callback in the shape `OPENSSL_sk_pop_free` takes.
unsafe extern "C" fn module_free_thunk(value: *mut c_void) {
    // SAFETY: the stack's entries are `ConfModule *` and it is handing each one over for
    // release.
    unsafe { module_free(value.cast()) };
}

/// `static void module_finish(CONF_IMODULE *imod)` — finishes one initialisation.
///
/// The module's own `finish` runs **before** its link count drops, which is what lets a finish
/// callback that consults `links` — or that re-registers the module — see the state it was
/// initialised in.
///
/// # Safety
/// `imod` must be NULL or an initialisation this module created and has already unlinked.
unsafe fn module_finish(imod: *mut ConfImodule) {
    if imod.is_null() {
        return;
    }
    // SAFETY: per the contract the initialisation is unreachable, so its fields and its module
    // pointer are this thread's to read and write.
    unsafe {
        let pmod = (*imod).pmod;
        if let Some(finish) = (*pmod).finish {
            finish(imod);
        }
        (*pmod).links -= 1;
        CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
        CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
        CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
    }
}

/// `static void module_lists_free(void)` — the teardown half of `ossl_config_modules_free`.
fn module_lists_free() {
    let lock = module_list_lock();
    MODULE_LIST_LOCK.store(ptr::null_mut(), Ordering::Release);
    // SAFETY: the lock is this registry's own, no reader can still be inside it once every
    // caller has stopped, and `ossl_rcu_lock_free` accepts NULL.
    unsafe { ossl_rcu_lock_free(lock) };

    // Both handles are taken *out* of their published slots before either is released, so a
    // reader that arrived between the two stores cannot see a pointer about to be freed.
    let supported = SUPPORTED_MODULES.swap(ptr::null_mut(), Ordering::AcqRel);
    let initialized = INITIALIZED_MODULES.swap(ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: both are this registry's own handles, and `OPENSSL_sk_free` accepts NULL.
    unsafe {
        OPENSSL_sk_free(supported);
        OPENSSL_sk_free(initialized);
    }
}

/// `static int conf_diagnostics(const CONF *cnf)`.
///
/// Reads `config_diagnostics` from the file and, when the file answers, makes that answer the
/// context's setting; otherwise it answers the context's setting. The mark/pop pair around the
/// lookup is what keeps a missing key from leaving an error on the queue.
///
/// # Safety
/// `cnf` must be a live `CONF`.
unsafe fn conf_diagnostics(cnf: *const Conf) -> c_int {
    let mut result: c_long = 0;
    // SAFETY: `cnf` is live per the contract, and `result` is this frame's own local. The
    // mark/pop pair brackets the lookup exactly as the authority's does.
    let status = unsafe {
        ERR_set_mark();
        let s = NCONF_get_number_e(
            cnf,
            ptr::null(),
            c"config_diagnostics".as_ptr(),
            &mut result,
        );
        ERR_pop_to_mark();
        s
    };
    // SAFETY: `cnf` is live, so its `libctx` is the context the file was created against; both
    // accessors answer for a NULL context too.
    let libctx = unsafe { (*cnf).libctx };
    if status > 0 {
        // SAFETY: as above.
        unsafe { OSSL_LIB_CTX_set_conf_diagnostics(libctx, (result > 0) as c_int) };
        return (result > 0) as c_int;
    }
    // SAFETY: as above.
    unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) }
}

/// `"openssl_conf=%s"` — the message `CONF_modules_load` raises when the named section is
/// missing.
///
/// # Safety
/// `vsection` must be NUL-terminated.
unsafe fn openssl_conf_message(vsection: *const c_char) -> *const c_char {
    // A `static` rather than a thread-local or an allocation. The authority's `ERR_vset_error`
    // allocates; this does not, which is a divergence in *storage* only, because the raise
    // copies the bytes before returning and no caller holds the pointer afterwards. It also
    // makes the function non-reentrant, which is why the buffer is written immediately before
    // the single call that consumes it.
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: the buffer is a static of exactly the declared length, and the format string is a
    // static NUL-terminated one whose single conversion is `%s`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"openssl_conf=%s".as_ptr(),
            vsection,
        )
    };
    // SAFETY: the pointer is to the static written immediately above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `"module=%s"` — the message `module_run` raises for an unknown module.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn module_name_message(name: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: as `openssl_conf_message`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"module=%s".as_ptr(),
            name,
        )
    };
    // SAFETY: as above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `"module=%s, value=%s retcode=%-8d"` — the message `module_run` raises when a module's
/// initialiser fails.
///
/// The `%-8d` is why this one could not be built with Rust's `format!`: there is no
/// left-justified integer in Rust's formatting language, and the authority's output pads the
/// return code to eight columns with *trailing* spaces. `BIO_snprintf` is the function
/// `ERR_vset_error` itself formats through, so the padding matches by construction.
///
/// # Safety
/// `name` and `value` must be NUL-terminated.
unsafe fn module_init_message(
    name: *const c_char,
    value: *const c_char,
    ret: c_int,
) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: the buffer is a static of exactly the declared length, and the format string is a
    // static NUL-terminated one with two `%s` and one `%-8d`, matching the three arguments.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"module=%s, value=%s retcode=%-8d".as_ptr(),
            name,
            value,
            ret,
        )
    };
    // SAFETY: as above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `"module=%s, path=%s"` — the message `module_load_dso` raises.
///
/// # Safety
/// `name` and `path` must be NUL-terminated.
unsafe fn dso_message(name: *const c_char, path: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: as `module_init_message`, with two `%s`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"module=%s, path=%s".as_ptr(),
            name,
            path,
        )
    };
    // SAFETY: as above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `int CONF_modules_load(const CONF *cnf, const char *appname, unsigned long flags)`.
///
/// The main entry point: resolve the section the file names, walk it, and run each entry as a
/// module.
///
/// Three behaviours here are what a court notices rather than the mechanics:
///
/// * a **NULL** `cnf` answers **1** — "nothing to do" is not an error;
/// * an `appname` the file does not define falls through to `openssl_conf` **only** when
///   `CONF_MFLAGS_DEFAULT_SECTION` is set, so that flag decides which section is loaded;
/// * when no section resolves at all the answer is **1** and the queue is popped back to the
///   mark, so a file with no configuration leaves no trace behind. That is the common case:
///   almost every `openssl.cnf` in the wild has no `openssl_conf`.
///
/// # Safety
/// `cnf` must be NULL or live throughout, and `appname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_load(
    cnf: *const Conf,
    appname: *const c_char,
    flags: c_ulong,
) -> c_int {
    guard_ffi(0, || {
        if cnf.is_null() {
            return 1;
        }

        let mut flags = flags;
        // SAFETY: `cnf` is non-NULL, per the test above.
        if unsafe { conf_diagnostics(cnf) } != 0 {
            flags &= !(CONF_MFLAGS_IGNORE_ERRORS
                | CONF_MFLAGS_IGNORE_RETURN_CODES
                | CONF_MFLAGS_SILENT
                | CONF_MFLAGS_IGNORE_MISSING_FILE);
        }

        // SAFETY: `cnf` is live and `appname` is NULL or NUL-terminated.
        let mut vsection: *mut c_char = unsafe {
            ERR_set_mark();
            if appname.is_null() {
                ptr::null_mut()
            } else {
                NCONF_get_string(cnf, ptr::null(), appname)
            }
        };

        if appname.is_null() || (vsection.is_null() && (flags & CONF_MFLAGS_DEFAULT_SECTION) != 0) {
            // SAFETY: `cnf` is live; the name is a static NUL-terminated string.
            vsection = unsafe { NCONF_get_string(cnf, ptr::null(), c"openssl_conf".as_ptr()) };
        }

        if vsection.is_null() {
            // SAFETY: this thread's own error queue.
            ERR_pop_to_mark();
            return 1;
        }

        // SAFETY: `cnf` is live and `vsection` is a name the file itself provided.
        let values = unsafe { NCONF_get_section(cnf, vsection) };
        if values.is_null() {
            if (flags & CONF_MFLAGS_SILENT) == 0 {
                // SAFETY: this thread's own queue, and a compile-time-constant site.
                unsafe {
                    ERR_clear_last_mark();
                    raise_site_data(&CONF_MOD_163, openssl_conf_message(vsection));
                }
            } else {
                // SAFETY: as above.
                ERR_pop_to_mark();
            }
            return 0;
        }
        // SAFETY: this thread's own error queue.
        ERR_pop_to_mark();

        // SAFETY: `values` is the section's own stack, live for the duration of this call.
        let count = unsafe { OPENSSL_sk_num(values) };
        let mut i = 0;
        while i < count {
            // SAFETY: `i < count`, so this is one of the section's own entries.
            let entry = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
            // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated strings owned by
            // the `CONF`, and the authority passes them in this order.
            let (name, value) = unsafe { ((*entry).name, (*entry).value) };
            // SAFETY: this thread's own error queue.
            ERR_set_mark();
            // SAFETY: `cnf` is live and both strings belong to it.
            let ret = unsafe { module_run(cnf, name, value, flags) };
            if ret <= 0 && (flags & CONF_MFLAGS_IGNORE_ERRORS) == 0 {
                // SAFETY: this thread's own error queue.
                ERR_clear_last_mark();
                return ret;
            }
            // SAFETY: as above.
            ERR_pop_to_mark();
            i += 1;
        }

        1
    })
}

/// `static int module_run(const CONF *cnf, const char *name, const char *value, unsigned long flags)`.
///
/// Ensures the built-ins are registered, finds the module — by name, then by loading a DSO
/// unless `CONF_MFLAGS_NO_DSO` says not to — and initialises it.
///
/// The `RUN_ONCE` here is what makes `CONF_modules_load` sufficient on its own: nothing has to
/// have registered the built-ins first.
///
/// # Safety
/// `cnf` must be live and `name`/`value` NUL-terminated.
unsafe fn module_run(
    cnf: *const Conf,
    name: *const c_char,
    value: *const c_char,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the once is this module's own static and the body is a safe `extern "C" fn`.
    let ran = unsafe {
        CRYPTO_THREAD_run_once(LOAD_BUILTIN_MODULES.as_ptr(), Some(do_load_builtin_modules))
    };
    if ran == 0 {
        return -1;
    }

    // SAFETY: `name` is NUL-terminated per the contract.
    let mut md = unsafe { module_find(name) };

    if md.is_null() && (flags & CONF_MFLAGS_NO_DSO) == 0 {
        // SAFETY: `cnf`, `name` and `value` are live per the contract.
        md = unsafe { module_load_dso(cnf, name, value) };
    }

    if md.is_null() {
        if (flags & CONF_MFLAGS_SILENT) == 0 {
            // SAFETY: a compile-time-constant site, this thread's own queue, and the message is
            // formatted with the authority's own formatter.
            unsafe { raise_site_data(&CONF_MOD_276, module_name_message(name)) };
        }
        return -1;
    }

    // SAFETY: `md` is a live registry entry and `cnf` is live.
    let ret = unsafe { module_init(md, name, value, cnf) };

    if ret <= 0 && (flags & CONF_MFLAGS_SILENT) == 0 {
        // SAFETY: a compile-time-constant site, this thread's own queue, and the message is
        // formatted with the authority's own formatter.
        unsafe { raise_site_data(&CONF_MOD_286, module_init_message(name, value, ret)) };
    }

    ret
}

/// `static CONF_MODULE *module_load_dso(const CONF *cnf, const char *name, const char *value)`.
///
/// The DSO path: the *value* names a section, and that section's `path` entry is what is loaded
/// — so a configuration can point at a module by a path that is not its name. When there is no
/// such section, or no `path` in it, the name itself is used.
///
/// Every failure raises `CONF_MOD_331`, whose reason is a **variable**: `errcode` is a local set
/// by which of the three steps failed. That is why this is the one raise in the file that goes
/// through `raise_site_dynamic`.
///
/// # Safety
/// `cnf` must be live and `name`/`value` NUL-terminated.
unsafe fn module_load_dso(
    cnf: *const Conf,
    name: *const c_char,
    value: *const c_char,
) -> *mut ConfModule {
    // SAFETY: `cnf` is live and `value` names a section in it; this is the private lookup
    // precisely because a missing section is not an error here.
    let looked_up = unsafe { _CONF_get_string(cnf, value, c"path".as_ptr()) };
    let path = if looked_up.is_null() { name } else { looked_up };

    // SAFETY: `path` is NUL-terminated, and a NULL context and method ask for the default
    // reader.
    let dso = unsafe { DSO_load(ptr::null_mut(), path, ptr::null_mut(), 0) };
    if dso.is_null() {
        // SAFETY: a compile-time-constant site, the reason is the variable the authority's
        // `errcode` is, and the message is formatted with the authority's own formatter.
        unsafe {
            raise_site_dynamic(&CONF_MOD_331, CONF_R_ERROR_LOADING_DSO);
            raise_site_data(&CONF_MOD_331, dso_message(name, path));
        }
        return ptr::null_mut();
    }

    // SAFETY: `dso` is live; the two names are static NUL-terminated strings.
    let ifunc = unsafe { DSO_bind_func(dso, c"OPENSSL_init".as_ptr()) };
    let Some(ifunc) = ifunc else {
        // SAFETY: `dso` was created here and is reachable from nowhere else.
        unsafe {
            DSO_free(dso);
            raise_site_dynamic(&CONF_MOD_331, CONF_R_MISSING_INIT_FUNCTION);
            raise_site_data(&CONF_MOD_331, dso_message(name, path));
        }
        return ptr::null_mut();
    };

    // SAFETY: as above; the finish function is optional in the authority too.
    let ffunc = unsafe { DSO_bind_func(dso, c"OPENSSL_finish".as_ptr()) };

    // `DSO_bind_func` answers a bare `extern "C" fn()` for *any* symbol, and the registry stores
    // the declared type. The cast is the one the authority performs at
    // `(conf_init_func *)DSO_bind_func(...)`, and it is sound in the same sense: a module whose
    // `OPENSSL_init` is not of that shape is a module that violated its own contract.
    // SAFETY: `ifunc` is a function pointer bound from a loaded object, and the registry's
    // caller will call it with the signature the authority's cast implies.
    let ifunc = Some(unsafe { core::mem::transmute::<unsafe extern "C" fn(), ConfInitFn>(ifunc) });
    // SAFETY: as above, for the optional finish function.
    let ffunc =
        ffunc.map(|f| unsafe { core::mem::transmute::<unsafe extern "C" fn(), ConfFinishFn>(f) });

    // SAFETY: `dso` is live and both callbacks have the declared types.
    let md = unsafe { module_add(dso, name, ifunc, ffunc) };
    if md.is_null() {
        // `module_add` takes the DSO's reference only on success, so the failing path releases
        // the reference `DSO_load` created here.
        // SAFETY: `dso` was created above and is reachable from nowhere else.
        unsafe {
            DSO_free(dso);
            raise_site_dynamic(&CONF_MOD_331, CONF_R_ERROR_LOADING_DSO);
            raise_site_data(&CONF_MOD_331, dso_message(name, path));
        }
        return ptr::null_mut();
    }

    md
}

/// `static CONF_MODULE *module_add(DSO *dso, const char *name, conf_init_func *ifunc, conf_finish_func *ffunc)`.
///
/// The copy-modify-swap, in the shape the module documentation describes. Reading the error
/// path is worth the time: `new_modules` is freed there and `old_modules` is **not**, because
/// `old_modules` is the handle still published in `supported_modules` while `new_modules` is the
/// shallow copy the failure discards.
///
/// # Safety
/// `name` must be NUL-terminated, and `dso` NULL or a live DSO whose reference this function
/// takes on success.
unsafe fn module_add(
    dso: *mut Dso,
    name: *const c_char,
    ifunc: Option<ConfInitFn>,
    ffunc: Option<ConfFinishFn>,
) -> *mut ConfModule {
    if !ensure_module_list_lock() {
        return ptr::null_mut();
    }
    let lock = module_list_lock();
    if lock.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `lock` is the live lock.
    unsafe { ossl_rcu_write_lock(lock) };

    let old_modules = supported_modules();
    // SAFETY: both operations accept a NULL handle and answer NULL, which is what the
    // authority's `old_modules == NULL` test relies on.
    let new_modules = unsafe {
        if old_modules.is_null() {
            OPENSSL_sk_new_null()
        } else {
            OPENSSL_sk_dup(old_modules)
        }
    };
    if new_modules.is_null() {
        // SAFETY: the write lock is held by this thread.
        unsafe { ossl_rcu_write_unlock(lock) };
        return ptr::null_mut();
    }

    let tmod =
        CRYPTO_zalloc(core::mem::size_of::<ConfModule>(), FILE, L_MODULE_NEW).cast::<ConfModule>();
    if tmod.is_null() {
        // SAFETY: the local list is this thread's own and is discarded here; the write lock is
        // held by this thread.
        unsafe {
            ossl_rcu_write_unlock(lock);
            OPENSSL_sk_free(new_modules);
        }
        return ptr::null_mut();
    }

    // SAFETY: `tmod` is a fresh zeroed block, so every write below is unaliased; `name` is
    // NUL-terminated per the contract, and `CRYPTO_strdup` is what the authority's
    // `OPENSSL_strdup` expands to at `:362` — the coordinates are that call's.
    unsafe {
        (*tmod).dso = dso;
        (*tmod).name = CRYPTO_strdup(name, FILE, L_MODULE_NAME);
        (*tmod).init = ifunc;
        (*tmod).finish = ffunc;
    }
    // SAFETY: `tmod` is this function's own fresh allocation.
    if unsafe { (*tmod).name }.is_null() {
        // SAFETY: as above; the entry and the local list are this thread's own.
        unsafe {
            ossl_rcu_write_unlock(lock);
            CRYPTO_free(tmod.cast(), FILE, L_MODULE_FREE_ERR);
            OPENSSL_sk_free(new_modules);
        }
        return ptr::null_mut();
    }

    // SAFETY: `new_modules` is a live list this thread owns.
    if unsafe { OPENSSL_sk_push(new_modules, tmod.cast()) } == 0 {
        // SAFETY: as above; the name was allocated above and is released here.
        unsafe {
            ossl_rcu_write_unlock(lock);
            CRYPTO_free((*tmod).name.cast(), FILE, L_MODULE_FREE_ERR);
            CRYPTO_free(tmod.cast(), FILE, L_MODULE_FREE_ERR);
            OPENSSL_sk_free(new_modules);
        }
        return ptr::null_mut();
    }

    // SAFETY: the write lock is held, so this thread is the only publisher and `new_modules` is
    // being transferred to the registry.
    unsafe {
        publish_supported(new_modules);
        ossl_rcu_write_unlock(lock);
        ossl_synchronize_rcu(lock);
        // The old handle owns an array and nothing behind it, so releasing it is correct once no
        // reader can still be walking it — which the synchronize above established.
        OPENSSL_sk_free(old_modules);
    }
    tmod
}

/// `strncmp(a, b, n)` — the C library's, written out because this crate has no wrapper for it.
///
/// Byte comparison of `unsigned char` values, stopping at the first difference or at `n` bytes.
/// Returns the sign of the difference, which is all `module_find` needs; the authority does not
/// use the magnitude either.
///
/// # Safety
/// `a` and `b` must each be readable for `n` bytes, or NUL-terminated within the first `n`.
unsafe fn strncmp_prefix(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    let mut i = 0;
    while i < n {
        // SAFETY: both pointers are readable for `n` bytes per the contract.
        let ca = unsafe { *a.add(i) } as u8;
        // SAFETY: as above.
        let cb = unsafe { *b.add(i) } as u8;
        if ca != cb {
            return ca as c_int - cb as c_int;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// `static CONF_MODULE *module_find(const char *name)`.
///
/// The name-matching rule is the one the authority's own comment states, and the reason this is
/// not a plain stack lookup: a name of the form `modname.XXXX` matches `modname`, so the same
/// module can be initialised more than once.
///
/// Two consequences are observable and neither is obviously the intent. The comparison is
/// `strncmp(entry->name, name, nchar)` where `nchar` is the length *up to the last dot*, so it
/// is a **prefix** test rather than an equality test: an entry named `abc` matches a lookup for
/// `abc.anything`, and also one for `abcdef`. And a name whose last dot is its **first**
/// character — `.foo` — has `nchar == 0`, so `strncmp(..., 0)` answers 0 and the **first**
/// registered module is returned. Both are reachable from a configuration file; `RT-CONF-MOD`
/// observes the second.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn module_find(name: *const c_char) -> *mut ConfModule {
    // The length of the prefix to compare: everything before the last dot, or the whole name.
    // SAFETY: `name` is NUL-terminated per the contract, so the scan is bounded.
    let nchar = unsafe {
        let mut p = name;
        let mut last_dot: *const c_char = ptr::null();
        while *p != 0 {
            if *p == b'.' as c_char {
                last_dot = p;
            }
            p = p.add(1);
        }
        if last_dot.is_null() {
            p.offset_from(name) as usize
        } else {
            last_dot.offset_from(name) as usize
        }
    };

    if !ensure_module_list_lock() {
        return ptr::null_mut();
    }
    let lock = module_list_lock();
    if lock.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `lock` is the live lock.
    if unsafe { ossl_rcu_read_lock(lock) } == 0 {
        return ptr::null_mut();
    }

    let mods = supported_modules();
    // SAFETY: `mods` is the published list, live until the next synchronize — which cannot run
    // while this thread holds the read lock.
    let count = unsafe { OPENSSL_sk_num(mods) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`.
        let tmod = unsafe { OPENSSL_sk_value(mods, i) }.cast::<ConfModule>();
        // SAFETY: a registry entry's `name` is a live NUL-terminated string and `name` is one
        // too, and the comparison reads at most `nchar` bytes of each — measured from `name`
        // itself, and an entry's own name is at least that long or the comparison stops at a
        // terminator first.
        if unsafe { strncmp_prefix((*tmod).name, name, nchar) } == 0 {
            // SAFETY: `lock` is held for reading by this thread.
            unsafe { ossl_rcu_read_unlock(lock) };
            return tmod;
        }
        i += 1;
    }

    // SAFETY: `lock` is held for reading by this thread.
    unsafe { ossl_rcu_read_unlock(lock) };
    ptr::null_mut()
}

/// `static int module_init(CONF_MODULE *pmod, const char *name, const char *value, const CONF *cnf)`.
///
/// Records one initialisation and calls the module's initialiser, if it has one.
///
/// The failure arm is the part to read closely: it calls `pmod->finish(imod)` **only when the
/// initialiser ran**, because a module that was never entered has nothing to tear down and
/// calling its finish would hand it an object it never saw.
///
/// # Safety
/// `pmod` must be a live registry entry, and `name`/`value`/`cnf` live as in [`module_run`].
unsafe fn module_init(
    pmod: *mut ConfModule,
    name: *const c_char,
    value: *const c_char,
    cnf: *const Conf,
) -> c_int {
    let mut ret: c_int = 1;

    let imod = CRYPTO_malloc(core::mem::size_of::<ConfImodule>(), FILE, L_IMODULE_NEW)
        .cast::<ConfImodule>();
    if imod.is_null() {
        return -1;
    }

    // SAFETY: `imod` is a fresh block, so every write below is unaliased. The two duplicates are
    // the authority's `OPENSSL_strdup` expansions at `:445` and `:446`. `CONF_IMODULE` has no
    // `flags` initialiser in the authority either — the allocation is `OPENSSL_malloc`, so the
    // field starts indeterminate and the module's own initialiser is what sets it.
    unsafe {
        (*imod).pmod = pmod;
        (*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);
        (*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);
        (*imod).flags = 0;
        (*imod).usr_data = ptr::null_mut();
    }

    // SAFETY: `imod` is this function's own fresh allocation.
    if unsafe { (*imod).name }.is_null() || unsafe { (*imod).value }.is_null() {
        // SAFETY: the contract's `memerr` arm: release the record and answer -1. `imod` has not
        // been published anywhere.
        unsafe {
            CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
        }
        return -1;
    }

    // SAFETY: `pmod` is live and `imod`/`cnf` are live. The initialiser's contract is the
    // authority's: it is handed both and may read or store on the `imod`.
    let init_result = unsafe { (*pmod).init.map(|init| init(imod, cnf)) };
    if let Some(r) = init_result {
        ret = r;
        if ret <= 0 {
            // SAFETY: the initialiser ran, so the module's finish is what the authority calls
            // next; then the contract's `memerr` arm releases the record. `pmod` is live.
            unsafe {
                if let Some(finish) = (*pmod).finish {
                    finish(imod);
                }
                CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
                CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
                CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
            }
            return -1;
        }
    }

    let had_init = init_result.is_some();
    if !ensure_module_list_lock() {
        // The contract's `err` arm reached from a run-once failure; `pmod` is live.
        // SAFETY: as the `memerr` arm above, plus the finish call the `err` arm makes when the
        // initialiser had run.
        unsafe {
            if had_init {
                if let Some(finish) = (*pmod).finish {
                    finish(imod);
                }
            }
            CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
        }
        return -1;
    }
    let lock = module_list_lock();
    if lock.is_null() {
        return -1;
    }
    // SAFETY: `lock` is the live lock.
    unsafe { ossl_rcu_write_lock(lock) };

    let old_modules = initialized_modules();
    // SAFETY: both operations accept a NULL handle and answer NULL, as in `module_add`.
    let new_modules = unsafe {
        if old_modules.is_null() {
            OPENSSL_sk_new_null()
        } else {
            OPENSSL_sk_dup(old_modules)
        }
    };
    if new_modules.is_null() {
        // SAFETY: the write lock is held by this thread, `pmod` is live, and the site is a
        // compile-time constant. The authority's `err` arm follows the unlock.
        unsafe {
            ossl_rcu_write_unlock(lock);
            raise_site(&CONF_MOD_475);
            if had_init {
                if let Some(finish) = (*pmod).finish {
                    finish(imod);
                }
            }
            CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
        }
        return -1;
    }

    // SAFETY: `new_modules` is a live list this thread owns.
    if unsafe { OPENSSL_sk_push(new_modules, imod.cast()) } == 0 {
        // SAFETY: as above; the local list is released here and the entry is torn down.
        unsafe {
            ossl_rcu_write_unlock(lock);
            OPENSSL_sk_free(new_modules);
            raise_site(&CONF_MOD_482);
            if had_init {
                if let Some(finish) = (*pmod).finish {
                    finish(imod);
                }
            }
            CRYPTO_free((*imod).name.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free((*imod).value.cast(), FILE, L_IMODULE_FREE);
            CRYPTO_free(imod.cast(), FILE, L_IMODULE_FREE);
        }
        return -1;
    }

    // SAFETY: the write lock is held, so `pmod->links` is this thread's alone and `new_modules`
    // is being transferred to the registry.
    unsafe {
        (*pmod).links += 1;
        publish_initialized(new_modules);
        ossl_rcu_write_unlock(lock);
        ossl_synchronize_rcu(lock);
        OPENSSL_sk_free(old_modules);
    }
    ret
}

/// `static int conf_modules_finish_int(void)` — finishes every live initialisation.
///
/// Answers **0** when the registry's lock has been freed, which is the authority's own test and
/// its own comment: *"If module_list_lock is NULL here it means we were already unloaded."* A
/// second unload therefore returns early instead of walking a list that no longer exists.
fn conf_modules_finish_int() -> bool {
    if !ensure_module_list_lock() {
        return false;
    }
    let lock = module_list_lock();
    if lock.is_null() {
        return false;
    }

    // SAFETY: `lock` is the live lock.
    unsafe { ossl_rcu_write_lock(lock) };
    let old_modules = initialized_modules();
    // SAFETY: the write lock is held, so this thread is the only publisher, and NULL is the
    // empty list.
    unsafe {
        publish_initialized(ptr::null_mut());
        ossl_rcu_write_unlock(lock);
        ossl_synchronize_rcu(lock);
    }

    // The walk pops from the tail, so the *most recently* initialised module is finished first —
    // the reverse of the order they were recorded in.
    loop {
        // SAFETY: `old_modules` is a list this thread owned and removed from the registry, and
        // no reader can still hold it after the synchronize above.
        let imod = unsafe { OPENSSL_sk_pop(old_modules) }.cast::<ConfImodule>();
        if imod.is_null() {
            break;
        }
        // SAFETY: `imod` is one of the entries the popped list owned and is now unreachable.
        unsafe { module_finish(imod) };
    }
    // SAFETY: `old_modules` is this thread's own handle.
    unsafe { OPENSSL_sk_free(old_modules) };
    true
}

/// `void CONF_modules_unload(int all)`.
///
/// Removes every dynamic module with no live initialisations, or every module at all when `all`
/// is set. The walk is **reverse** so that a delete by index is safe, and the removed entries
/// are collected into `to_delete` and released only **after** the synchronize — which is the
/// part that matters: an entry a reader can still reach must not be freed.
#[no_mangle]
pub extern "C" fn CONF_modules_unload(all: c_int) {
    guard_ffi((), || {
        if !conf_modules_finish_int() {
            return;
        }
        let lock = module_list_lock();
        if lock.is_null() {
            return;
        }
        // SAFETY: `lock` is the live lock.
        unsafe { ossl_rcu_write_lock(lock) };

        let old_modules = supported_modules();
        // SAFETY: a NULL handle answers NULL, which the test below turns into an early return; a
        // non-NULL one is the published list.
        let new_modules = unsafe { OPENSSL_sk_dup(old_modules) };
        if new_modules.is_null() {
            // SAFETY: the write lock is held by this thread.
            unsafe { ossl_rcu_write_unlock(lock) };
            return;
        }

        // SAFETY: a fresh empty list; the comparator is NULL because this list is only pushed to
        // and popped from, never searched.
        let to_delete = OPENSSL_sk_new_null();

        // SAFETY: `new_modules` is a live list this thread owns, and working in reverse is what
        // makes a delete-by-index correct — the authority's own comment says so.
        unsafe {
            let mut i = OPENSSL_sk_num(new_modules) - 1;
            while i >= 0 {
                let md = OPENSSL_sk_value(new_modules, i).cast::<ConfModule>();
                // A static module (no DSO) or one still in use survives unless `all` is set.
                if (((*md).links > 0) || (*md).dso.is_null()) && all == 0 {
                    i -= 1;
                    continue;
                }
                OPENSSL_sk_delete(new_modules, i);
                OPENSSL_sk_push(to_delete, md.cast());
                i -= 1;
            }

            // An emptied list is published as NULL rather than as an empty stack. That is the
            // authority's choice, and it is observable through a second unload's early return.
            let mut published = new_modules;
            if OPENSSL_sk_num(new_modules) == 0 {
                OPENSSL_sk_free(new_modules);
                published = ptr::null_mut();
            }
            publish_supported(published);
            ossl_rcu_write_unlock(lock);
            ossl_synchronize_rcu(lock);
            OPENSSL_sk_free(old_modules);
            OPENSSL_sk_pop_free(to_delete, Some(module_free_thunk));
        }
    })
}

/// `void CONF_modules_finish(void)`.
#[no_mangle]
pub extern "C" fn CONF_modules_finish() {
    guard_ffi((), || {
        conf_modules_finish_int();
    })
}

/// `void ossl_config_modules_free(void)` — the `OPENSSL_cleanup` teardown.
///
/// Not an export: it is declared in `crypto/conf/conf_local.h` and called from `crypto/init.c`.
/// `CONF_modules_unload(1)` does the finishing — it calls `conf_modules_finish_int` first — and
/// [`module_lists_free`] then releases the lock and both list handles.
pub(crate) fn ossl_config_modules_free() {
    CONF_modules_unload(1);
    module_lists_free();
}

/// `int CONF_module_add(const char *name, conf_init_func *ifunc, conf_finish_func *ffunc)`.
///
/// Answers 1 on success and 0 on failure — the *inverse* of `module_add`'s pointer, and the
/// conversion is the whole body.
///
/// # Safety
/// `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_module_add(
    name: *const c_char,
    ifunc: Option<ConfInitFn>,
    ffunc: Option<ConfFinishFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `name` is NUL-terminated per the caller's contract, and a NULL DSO is what
        // makes this a static module.
        if unsafe { module_add(ptr::null_mut(), name, ifunc, ffunc) }.is_null() {
            0
        } else {
            1
        }
    })
}

/// `const char *CONF_imodule_get_name(const CONF_IMODULE *md)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_get_name(md: *const ConfImodule) -> *const c_char {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).name }
}

/// `const char *CONF_imodule_get_value(const CONF_IMODULE *md)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_get_value(md: *const ConfImodule) -> *const c_char {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).value }
}

/// `void *CONF_imodule_get_usr_data(const CONF_IMODULE *md)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_get_usr_data(md: *const ConfImodule) -> *mut c_void {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).usr_data }
}

/// `void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_set_usr_data(md: *mut ConfImodule, usr_data: *mut c_void) {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).usr_data = usr_data };
}

/// `CONF_MODULE *CONF_imodule_get_module(const CONF_IMODULE *md)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_get_module(md: *const ConfImodule) -> *mut ConfModule {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).pmod }
}

/// `unsigned long CONF_imodule_get_flags(const CONF_IMODULE *md)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_get_flags(md: *const ConfImodule) -> c_ulong {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).flags }
}

/// `void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags)`.
///
/// # Safety
/// `md` must be a live initialisation.
#[no_mangle]
pub unsafe extern "C" fn CONF_imodule_set_flags(md: *mut ConfImodule, flags: c_ulong) {
    // SAFETY: `md` is live per the caller's contract.
    unsafe { (*md).flags = flags };
}

/// `void *CONF_module_get_usr_data(CONF_MODULE *pmod)`.
///
/// # Safety
/// `pmod` must be a live registry entry.
#[no_mangle]
pub unsafe extern "C" fn CONF_module_get_usr_data(pmod: *mut ConfModule) -> *mut c_void {
    // SAFETY: `pmod` is live per the caller's contract.
    unsafe { (*pmod).usr_data }
}

/// `void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data)`.
///
/// # Safety
/// `pmod` must be a live registry entry.
#[no_mangle]
pub unsafe extern "C" fn CONF_module_set_usr_data(pmod: *mut ConfModule, usr_data: *mut c_void) {
    // SAFETY: `pmod` is live per the caller's contract.
    unsafe { (*pmod).usr_data = usr_data };
}

/// `void OPENSSL_load_builtin_modules(void)`.
///
/// Seven calls in the authority and two that this crate can make today. See the module
/// documentation for which five belong to other strata and for why their absence is a recorded
/// divergence rather than a stub: registering nothing where the authority registers a module is
/// a behaviour a configuration file can observe, so it must be *stated* rather than faked.
///
/// `ASN1_add_oid_module` is 6.10d, `ossl_config_add_ssl_module` is 6.10e and
/// `ossl_provider_add_conf_module` is 6.8d; all three are called. `ENGINE_add_conf_module`
/// (Phase 13), `EVP_add_alg_module` (Phase 7), `ossl_random_add_conf_module` (Phase 9) and
/// `ASN1_add_stable_module` (Phase 11) are not.
#[no_mangle]
pub extern "C" fn OPENSSL_load_builtin_modules() {
    guard_ffi((), || {
        crate::runtime::confmod::asn1::ASN1_add_oid_module();
        crate::runtime::conf::conf_ssl::ossl_config_add_ssl_module();
        crate::provider::conf::ossl_provider_add_conf_module();
    })
}

/// `int CONF_modules_load_file_ex(OSSL_LIB_CTX *libctx, const char *filename, const char *appname, unsigned long flags)`.
///
/// The file-shaped entry point: resolve the filename, build a `CONF` against the context, load
/// it, and hand it to [`CONF_modules_load`].
///
/// Three details are what a consumer sees.
///
/// A NULL `filename` means "the default file", and an **empty** default is not an error: the
/// function answers 1 without trying to open anything, which is what makes an unset
/// `OPENSSL_CONF` harmless. A missing file is an error **unless**
/// `CONF_MFLAGS_IGNORE_MISSING_FILE` is set *and* the queue's last reason is
/// `CONF_R_NO_SUCH_FILE` — both halves, so a permission failure is not swallowed. And
/// `CONF_MFLAGS_IGNORE_RETURN_CODES` forces the answer to 1 **unless** the diagnostics setting
/// is on.
///
/// ## Every failure converges on one tail, and that is not a style choice
///
/// The authority's body is a sequence of `goto err` jumps onto a shared label, and the block
/// after that label runs **once for every path**, successful or not. Two of its statements make
/// the difference observable:
///
/// * `if ((flags & CONF_MFLAGS_IGNORE_RETURN_CODES) != 0 && !diagnostics) ret = 1;` applies to
///   the *failure* paths too, so a caller who set that flag sees 1 even when the file could not
///   be read — unless diagnostics is on;
/// * the `ERR_pop_to_mark`/`ERR_clear_last_mark` pair is chosen by the *final* `ret`, so a
///   failure that a later statement turned into a success pops the mark rather than clearing it.
///
/// A version of this function that returned early from each failure would leave both of those
/// undone, and the compiler says so from the other side: the first read of `diagnostics` is
/// dead when every early return skips its use. The label is reproduced as a labelled block.
///
/// # Safety
/// `libctx` must be NULL or live, and `filename`/`appname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_load_file_ex(
    libctx: *mut c_void,
    filename: *const c_char,
    appname: *const c_char,
    flags: c_ulong,
) -> c_int {
    guard_ffi(0, || {
        let mut ret: c_int = 0;
        // SAFETY: `libctx` is NULL or live per the contract. This first value is read by the
        // shared tail on every failure path that precedes the `CONF_modules_load` call, which is
        // exactly what the authority's `diagnostics` is for.
        let mut diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) };

        // SAFETY: this thread's own error queue.
        ERR_set_mark();

        // The file this call reads, and whether it is this call's to release. `owned` stays
        // visible to the tail, which is where the authority frees it.
        let mut owned: *mut c_char = ptr::null_mut();
        let mut file: *const c_char = filename;
        let mut conf: *mut Conf = ptr::null_mut();

        // The authority's `err:` label. Every `break 'err` below is a `goto err`.
        'err: {
            if filename.is_null() {
                owned = CONF_get1_default_config_file();
                if owned.is_null() {
                    break 'err;
                }
                // SAFETY: `owned` is a NUL-terminated string this call owns.
                if unsafe { *owned } == 0 {
                    // "Do not try to load an empty file name but do not error out."
                    ret = 1;
                    break 'err;
                }
                file = owned;
            }

            // SAFETY: `libctx` is NULL or live, and a NULL method asks for the default reader.
            conf = unsafe { NCONF_new_ex(libctx, ptr::null_mut()) };
            if conf.is_null() {
                break 'err;
            }

            // SAFETY: `conf` is live and `file` is NUL-terminated.
            if unsafe { NCONF_load(conf, file, ptr::null_mut()) } <= 0 {
                if (flags & CONF_MFLAGS_IGNORE_MISSING_FILE) != 0
                    && peek_last_reason() == CONF_R_NO_SUCH_FILE as c_ulong
                {
                    ret = 1;
                }
                break 'err;
            }

            // SAFETY: `conf` is live.
            ret = unsafe { CONF_modules_load(conf, appname, flags) };
            // "CONF_modules_load() might change the diagnostics setting, reread it."
            // SAFETY: `libctx` is NULL or live.
            diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) };
        }

        // The authority frees the filename only when it allocated it.
        if filename.is_null() {
            // SAFETY: `owned` is NULL or this call's own allocation.
            unsafe { CRYPTO_free(owned.cast(), FILE, 0) };
        }
        // SAFETY: `conf` is NULL or this call's own configuration; `NCONF_free` accepts NULL.
        unsafe { NCONF_free(conf) };

        if (flags & CONF_MFLAGS_IGNORE_RETURN_CODES) != 0 && diagnostics == 0 {
            ret = 1;
        }

        // SAFETY: this thread's own error queue.
        if ret > 0 {
            ERR_pop_to_mark();
        } else {
            ERR_clear_last_mark();
        }
        ret
    })
}

/// `int CONF_modules_load_file(const char *filename, const char *appname, unsigned long flags)`.
///
/// # Safety
/// As [`CONF_modules_load_file_ex`], with the default context.
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_load_file(
    filename: *const c_char,
    appname: *const c_char,
    flags: c_ulong,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: a NULL context resolves to the default one, and the two strings are the
        // caller's, passed through unchanged.
        unsafe { CONF_modules_load_file_ex(ptr::null_mut(), filename, appname, flags) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authority defines `DEFAULT_CONF_MFLAGS` **once**, in
    /// `include/internal/conf.h`, and this crate names it in two places for two different
    /// reasons: this module needs the four bits separately, and
    /// `crate::runtime::conf::init_settings` needs the composed word as the value
    /// `OPENSSL_INIT_new` installs. Two spellings of one authority definition is exactly the
    /// drift a test is for, so the two are compared rather than trusted.
    #[test]
    fn the_two_spellings_of_default_conf_mflags_agree() {
        let composed = CONF_MFLAGS_DEFAULT_SECTION
            | CONF_MFLAGS_IGNORE_MISSING_FILE
            | CONF_MFLAGS_IGNORE_RETURN_CODES;
        assert_eq!(composed, DEFAULT_CONF_MFLAGS);
        assert_eq!(
            composed,
            crate::runtime::conf::init_settings::DEFAULT_CONF_MFLAGS
        );
    }

    /// The four ignore bits are the authority's values, and the mask
    /// `CONF_modules_load` clears when a configuration turns diagnostics on is exactly four
    /// of them — `NO_DSO` and `DEFAULT_SECTION` are **not** cleared, which is why a load
    /// under diagnostics still does not attempt a DSO.
    #[test]
    fn the_ignore_bits_and_their_mask_are_the_authority_values() {
        assert_eq!(CONF_MFLAGS_IGNORE_ERRORS, 0x1);
        assert_eq!(CONF_MFLAGS_IGNORE_RETURN_CODES, 0x2);
        assert_eq!(CONF_MFLAGS_SILENT, 0x4);
        assert_eq!(CONF_MFLAGS_NO_DSO, 0x8);
        assert_eq!(CONF_MFLAGS_IGNORE_MISSING_FILE, 0x10);
        assert_eq!(CONF_MFLAGS_DEFAULT_SECTION, 0x20);

        let cleared = CONF_MFLAGS_IGNORE_ERRORS
            | CONF_MFLAGS_IGNORE_RETURN_CODES
            | CONF_MFLAGS_SILENT
            | CONF_MFLAGS_IGNORE_MISSING_FILE;
        assert_eq!(cleared & CONF_MFLAGS_NO_DSO, 0);
        assert_eq!(cleared & CONF_MFLAGS_DEFAULT_SECTION, 0);
        assert_eq!(cleared & 0x20, 0);
    }
}
