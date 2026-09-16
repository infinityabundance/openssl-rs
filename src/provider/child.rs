//! Phase 6.8e — `crypto/provider_child.c`: the child provider, and the callbacks a parent
//! registers.
//!
//! A **child provider** is a provider that lives inside another provider's library context:
//! the parent is a third-party provider, and when it creates a `OSSL_LIB_CTX` for its own
//! use it gets a *child* context whose provider set is the parent's. The child's providers
//! are proxies — their `OSSL_provider_init` is [`ossl_child_provider_init`], which does not
//! implement anything, and asks the parent for the real provider's context and dispatch table
//! through the four upcalls it was handed.
//!
//! ```text
//! parent (third-party provider, libctx P)
//!   │  ossl_provider_init_as_child(child_ctx, handle, dispatch)
//!   │    stores the handle and seven upcalls in child_ctx's slot 18
//!   │    calls the parent's register_child_cb with three callbacks
//!   ▼
//! child_ctx (OSSL_LIB_CTX, ischild = 1)
//!   │  parent decides to expose a provider
//!   │    parent calls provider_create_child_cb(handle, child_ctx)
//!   │      creates an OSSL_PROVIDER whose init is ossl_child_provider_init
//!   ▼
//! a "child provider": activation asks the parent, through the *parent's* dispatch table,
//! for that provider's provider-ctx and dispatch — which is what makes the parent's
//! implementation reachable through the child's name.
//! ```
//!
//! ## What this module owns, and what it only *hands over*
//!
//! The four functions `ossl_provider_init_as_child` and the two parent-ref helpers use
//! (`ossl_provider_up_ref_parent`, `ossl_provider_free_parent`) are this module's. The three
//! **callbacks** it registers are this module's too, but they are *invoked by the parent*, so
//! nothing in this crate calls them today.
//!
//! [`provider_global_props_cb`] is the one exception among them, and the exception is named
//! rather than hidden: its body is `evp_set_default_properties_int(ctx, props, 0, 1)`, which
//! is `crypto/evp/evp_fetch.c`'s and therefore **Phase 7's**. The crate does not have it, so
//! the callback answers 0 — the authority's failure answer — without raising. That is a
//! recorded divergence (`D-CHILD-PROPS-CB-1`) and not a stub: the function is written, it is
//! reachable, and what it cannot do is stated in the divergence policy with the phase that
//! will make it real. It is also unreachable in this crate until a third-party provider can
//! take the parent role, which is 6.12's court — so no court can observe it yet, and the
//! divergence entry says so.
//!
//! ## The validation list omits one pointer, and the omission is load-bearing
//!
//! `ossl_provider_init_as_child` requires **seven** of the eight dispatch entries it stores:
//! `c_get_libctx`, `c_provider_register_child_cb`, `c_prov_name`, `c_prov_get0_provider_ctx`,
//! `c_prov_get0_dispatch`, `c_prov_up_ref` and `c_prov_free`. The eighth,
//! `c_provider_deregister_child_cb`, is **not** in the test — and
//! [`ossl_provider_deinit_child`] calls it unguarded. So a parent that publishes a table
//! without `OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB` initialises successfully and then
//! **jumps through NULL** at teardown.
//!
//! That is a fault, so it is not reproduced: this crate's [`ossl_provider_deinit_child`]
//! checks the pointer and returns when it is absent. The check is the divergence, it is
//! recorded as `D-CHILD-DEREGISTER-NULL-1`, and the *init* half is the authority's exactly —
//! seven pointers, in that order, so a table missing the deregister cb still initialises.
//! Reproducing only the safe half of the pair is the point: the initialisation contract is
//! observable and the fault is not.
//!
//! ## The slot is created eagerly and filled lazily
//!
//! `ossl_child_prov_ctx_new` is `OPENSSL_zalloc` and nothing else — **no lock**. The lock is
//! created by `ossl_provider_init_as_child`, so a slot object that was never initialised has
//! a NULL lock, and `ossl_child_prov_ctx_free` calls `CRYPTO_THREAD_lock_free(NULL)` on it,
//! which is defined. That ordering is why the constructor cannot fail on a lock and why the
//! free needs no NULL test on the field.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::context::lib_ctx_get_data;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

use super::activate::{ossl_provider_activate, ossl_provider_deactivate};
use super::{
    ossl_provider_add_to_store, ossl_provider_find, ossl_provider_free, ossl_provider_libctx,
    ossl_provider_new, OsslProvider, ProviderInitFn,
};
use crate::context::dispatch::OsslDispatch;

/// `crypto/provider_child.c`, for the coordinates of its allocations.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/provider_child.c".as_ptr();

/// `return OPENSSL_zalloc(sizeof(struct child_prov_globals))` in
/// `ossl_child_prov_ctx_new`.
const L_GLOBALS: c_int = 29;
/// `OPENSSL_free(gbl)` in `ossl_child_prov_ctx_free`.
const L_GLOBALS_FREE: c_int = 37;

/// `OSSL_LIB_CTX_CHILD_PROVIDER_INDEX` — `include/internal/cryptlib.h`.
const OSSL_LIB_CTX_CHILD_PROVIDER_INDEX: c_int = 18;

// The dispatch ids, from `include/openssl/core_dispatch.h`. The four the walk reads are the
// core id and the seven 10x-series provider ids.
/// `#define OSSL_FUNC_CORE_GET_LIBCTX 4`.
const OSSL_FUNC_CORE_GET_LIBCTX: c_int = 4;
/// `#define OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB 105`.
const OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB: c_int = 105;
/// `#define OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB 106`.
const OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB: c_int = 106;
/// `#define OSSL_FUNC_PROVIDER_NAME 107`.
const OSSL_FUNC_PROVIDER_NAME: c_int = 107;
/// `#define OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX 108`.
const OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX: c_int = 108;
/// `#define OSSL_FUNC_PROVIDER_GET0_DISPATCH 109`.
const OSSL_FUNC_PROVIDER_GET0_DISPATCH: c_int = 109;
/// `#define OSSL_FUNC_PROVIDER_UP_REF 110`.
const OSSL_FUNC_PROVIDER_UP_REF: c_int = 110;
/// `#define OSSL_FUNC_PROVIDER_FREE 111`.
const OSSL_FUNC_PROVIDER_FREE: c_int = 111;

/// `OSSL_FUNC_core_get_libctx_fn` — `const OSSL_CORE_HANDLE *(*)(const OSSL_CORE_HANDLE *)`.
///
/// The return is the parent's `OPENSSL_CORE_CTX *`, which the authority casts to
/// `OSSL_LIB_CTX *` because the child is a built-in provider and may. The cast is this
/// module's, at the one call site that makes it.
pub(crate) type CoreGetLibCtxFn = unsafe extern "C" fn(*const c_void) -> *mut c_void;

/// `OSSL_FUNC_provider_register_child_cb_fn`.
///
/// The three callbacks a parent is handed are the whole mechanism: `create_cb` when the
/// parent exposes a provider, `remove_cb` when it withdraws one, and `global_props_cb` when
/// its global properties change. All three take the `cbdata` the parent was given, which is
/// the child context itself.
pub(crate) type RegisterChildCbFn = unsafe extern "C" fn(
    *const c_void,
    Option<CreateChildCbFn>,
    Option<RemoveChildCbFn>,
    Option<GlobalPropsCbFn>,
    *mut c_void,
) -> c_int;

/// `OSSL_FUNC_provider_deregister_child_cb_fn` — `void (*)(const OSSL_CORE_HANDLE *)`.
pub(crate) type DeregisterChildCbFn = unsafe extern "C" fn(*const c_void);

/// `int (*)(const OSSL_CORE_HANDLE *provider, void *cbdata)` — the create callback's type.
pub(crate) type CreateChildCbFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
/// As [`CreateChildCbFn`], for the remove callback.
pub(crate) type RemoveChildCbFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
/// `int (*)(const char *props, void *cbdata)` — the global-properties callback's type.
pub(crate) type GlobalPropsCbFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;

/// `OSSL_FUNC_provider_name_fn` — `const char *(*)(const OSSL_CORE_HANDLE *prov)`.
pub(crate) type ChildNameFn = unsafe extern "C" fn(*const c_void) -> *const c_char;
/// `OSSL_FUNC_provider_get0_provider_ctx_fn`.
pub(crate) type ChildGet0ProviderCtxFn = unsafe extern "C" fn(*const c_void) -> *mut c_void;
/// `OSSL_FUNC_provider_get0_dispatch_fn`.
pub(crate) type ChildGet0DispatchFn = unsafe extern "C" fn(*const c_void) -> *const OsslDispatch;
/// `OSSL_FUNC_provider_up_ref_fn` — `int (*)(const OSSL_CORE_HANDLE *prov, int activate)`.
pub(crate) type ChildUpRefFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
/// `OSSL_FUNC_provider_free_fn` — `int (*)(const OSSL_CORE_HANDLE *prov, int deactivate)`.
pub(crate) type ChildFreeFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;

/// `struct child_prov_globals` — the child context's slot-18 object.
///
/// Every field but the lock is written by [`ossl_provider_init_as_child`] and read by the
/// callbacks it registers; `curr_prov` is written by the create callback and read by
/// [`ossl_child_provider_init`], which is why the create callback holds the lock across the
/// store — the authority's own comment says that is what the lock is for.
#[repr(C)]
pub(crate) struct ChildProvGlobals {
    /// `const OSSL_CORE_HANDLE *handle` — the parent's own handle.
    pub(crate) handle: *const c_void,
    /// `const OSSL_CORE_HANDLE *curr_prov` — the provider whose child is being initialised.
    pub(crate) curr_prov: *const c_void,
    /// `CRYPTO_RWLOCK *lock` — NULL until [`ossl_provider_init_as_child`] creates it.
    pub(crate) lock: *mut CryptoRwlock,
    /// `c_get_libctx` — the parent's "which context am I" upcall.
    pub(crate) c_get_libctx: Option<CoreGetLibCtxFn>,
    /// `c_provider_register_child_cb`.
    pub(crate) c_provider_register_child_cb: Option<RegisterChildCbFn>,
    /// `c_provider_deregister_child_cb` — the one pointer the init does not validate.
    pub(crate) c_provider_deregister_child_cb: Option<DeregisterChildCbFn>,
    /// `c_prov_name`.
    pub(crate) c_prov_name: Option<ChildNameFn>,
    /// `c_prov_get0_provider_ctx`.
    pub(crate) c_prov_get0_provider_ctx: Option<ChildGet0ProviderCtxFn>,
    /// `c_prov_get0_dispatch`.
    pub(crate) c_prov_get0_dispatch: Option<ChildGet0DispatchFn>,
    /// `c_prov_up_ref`.
    pub(crate) c_prov_up_ref: Option<ChildUpRefFn>,
    /// `c_prov_free`.
    pub(crate) c_prov_free: Option<ChildFreeFn>,
}

/// `void *ossl_child_prov_ctx_new(OSSL_LIB_CTX *libctx)`.
///
/// `OPENSSL_zalloc` and nothing else: **no lock**. See the module documentation for why that
/// ordering is the authority's and why the free can then be unconditional.
///
/// # Safety
/// `libctx` is accepted and unused; the authority's argument is the context being built.
pub(crate) unsafe fn ossl_child_prov_ctx_new(_libctx: *mut c_void) -> *mut c_void {
    CRYPTO_zalloc(core::mem::size_of::<ChildProvGlobals>(), FILE, L_GLOBALS).cast::<c_void>()
}

/// `void ossl_child_prov_ctx_free(void *vgbl)`.
///
/// The lock first — which is NULL for a slot that was never initialised, and
/// `CRYPTO_THREAD_lock_free` accepts NULL — then the object. The authority's version does not
/// check `gbl` for NULL either; `context_deinit_objs` tests the slot.
///
/// # Safety
/// `vgbl` must be NULL or the object [`ossl_child_prov_ctx_new`] returned and this function
/// has not already released.
pub(crate) unsafe fn ossl_child_prov_ctx_free(vgbl: *mut c_void) {
    let gbl = vgbl.cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return;
    }
    // SAFETY: `gbl` is live per the contract, so both fields are this object's.
    unsafe {
        CRYPTO_THREAD_lock_free((*gbl).lock);
        CRYPTO_free(gbl.cast::<c_void>(), FILE, L_GLOBALS_FREE);
    }
}

/// `static int ossl_child_provider_init(const OSSL_CORE_HANDLE *handle,
/// const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)`.
///
/// **The whole of a child provider's implementation.** It reads one entry out of the dispatch
/// table its *parent* handed it — `OSSL_FUNC_CORE_GET_LIBCTX` — and ignores everything else,
/// then uses it to find the child context's globals and to ask the parent's own upcalls for
/// the real provider's context and dispatch table. So a child provider is a name that answers
/// the parent's implementation, and this function is the indirection.
///
/// The cast `(OSSL_LIB_CTX *)c_get_libctx(handle)` is the authority's and its comment says
/// why it is legal *here* and not for a normal provider: this is a built-in, so the parent's
/// `OPENSSL_CORE_CTX *` really is the child `OSSL_LIB_CTX`.
///
/// # Safety
/// The argument contract is `OSSL_provider_init_fn`'s: `in` must be a terminated dispatch
/// table, and `out`/`provctx` writable.
pub(crate) unsafe extern "C" fn ossl_child_provider_init(
    handle: *const c_void,
    r#in: *const OsslDispatch,
    out: *mut *const OsslDispatch,
    provctx: *mut *mut c_void,
) -> c_int {
    let mut c_get_libctx: Option<CoreGetLibCtxFn> = None;

    // The walk: every entry with the id this function cares about, and the *last* one wins,
    // which is what `break`-less iteration over a duplicated id would do. The authority's
    // `switch` assigns on each match, so a table naming the id twice keeps the second.
    let mut p = r#in;
    // SAFETY: `in` is a terminated dispatch table per the contract.
    unsafe {
        while (*p).function_id != 0 {
            if (*p).function_id == OSSL_FUNC_CORE_GET_LIBCTX {
                // SAFETY: the entry's `function` is the parent's
                // `OSSL_FUNC_core_get_libctx_fn`; the id is what says so.
                c_get_libctx = Some(core::mem::transmute::<*mut c_void, CoreGetLibCtxFn>(
                    (*p).function,
                ));
            }
            p = p.add(1);
        }
    }

    let Some(get_libctx) = c_get_libctx else {
        return 0;
    };

    // SAFETY: `get_libctx` is the parent's upcall, and `handle` is the handle it was given.
    let ctx = unsafe { get_libctx(handle) };
    // The cast the authority's comment justifies. `lib_ctx_get_data` is a safe entry point
    // that validates its own arguments.
    let gbl = lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX).cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: `gbl` is live, so `curr_prov` is the handle the create callback stored and both
    // upcalls are non-NULL — `ossl_provider_init_as_child` refuses a table without them.
    unsafe {
        let Some(get_ctx) = (*gbl).c_prov_get0_provider_ctx else {
            return 0;
        };
        let Some(get_dispatch) = (*gbl).c_prov_get0_dispatch else {
            return 0;
        };
        *provctx = get_ctx((*gbl).curr_prov);
        *out = get_dispatch((*gbl).curr_prov);
    }

    1
}

/// `static int provider_create_child_cb(const OSSL_CORE_HANDLE *prov, void *cbdata)` — the
/// parent telling the child that a provider is now available.
///
/// `cbdata` is the child context. The body is the one place the module's two directions meet:
/// it stores `prov` as `curr_prov` **under the lock**, because
/// [`ossl_child_provider_init`] — called from inside `ossl_provider_activate` below — reads
/// it back.
///
/// Two branches, and the difference between them is the whole reason this function exists:
///
/// * **the name is already in the child's store** — the provider was created before, or it was
///   loaded explicitly. The reference `ossl_provider_find` took is dropped (the store's keeps
///   it alive), and the provider is activated **as a child** (`aschild = 1`). An explicitly
///   loaded provider is therefore *not* adopted: it is activated, which is all the difference
///   between the two cases amounts to.
/// * **the name is new** — a fresh `OSSL_PROVIDER` is built with
///   [`ossl_child_provider_init`] as its initialiser, activated (`aschild = 0`, because the
///   *creation* is what must not recurse), then marked a child with
///   `ossl_provider_set_child` and added to the store with a NULL `actual` — the authority
///   does not care which object won, because it just built one and nothing else can have the
///   name.
///
/// # Safety
/// `prov` must be the parent's handle for the provider; `cbdata` must be the child context,
/// which is what [`ossl_provider_init_as_child`] passed to the parent.
pub(crate) unsafe extern "C" fn provider_create_child_cb(
    prov: *const c_void,
    cbdata: *mut c_void,
) -> c_int {
    let ctx = cbdata;
    let gbl = lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX).cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: `gbl` is live, so its lock was created by `ossl_provider_init_as_child`.
    if unsafe { CRYPTO_THREAD_write_lock((*gbl).lock) } == 0 {
        return 0;
    }

    let ret: c_int;
    // SAFETY: `gbl` is live and its name upcall is non-NULL, per the init's validation.
    unsafe {
        let Some(name_fn) = (*gbl).c_prov_name else {
            CRYPTO_THREAD_unlock((*gbl).lock);
            return 0;
        };
        let provname = name_fn(prov);
        (*gbl).curr_prov = prov;

        let mut cprov = ossl_provider_find(ctx, provname, 1);
        if !cprov.is_null() {
            // The store's reference keeps it; this one is dropped.
            ossl_provider_free(cprov);
            if ossl_provider_activate(cprov, 0, 1) == 0 {
                CRYPTO_THREAD_unlock((*gbl).lock);
                return 0;
            }
        } else {
            cprov = ossl_provider_new(
                ctx,
                provname,
                Some(ossl_child_provider_init as ProviderInitFn),
                ptr::null_mut(),
                1,
            );
            if cprov.is_null() {
                CRYPTO_THREAD_unlock((*gbl).lock);
                return 0;
            }
            if ossl_provider_activate(cprov, 0, 0) == 0 {
                ossl_provider_free(cprov);
                CRYPTO_THREAD_unlock((*gbl).lock);
                return 0;
            }
            if ossl_provider_set_child(cprov, prov) == 0
                || ossl_provider_add_to_store(cprov, ptr::null_mut(), 0) == 0
            {
                ossl_provider_deactivate(cprov, 0);
                ossl_provider_free(cprov);
                CRYPTO_THREAD_unlock((*gbl).lock);
                return 0;
            }
        }
        ret = 1;
        CRYPTO_THREAD_unlock((*gbl).lock);
    }

    ret
}

/// `static int provider_remove_child_cb(const OSSL_CORE_HANDLE *prov, void *cbdata)` — the
/// parent withdrawing a provider.
///
/// The name is looked up and the reference dropped, then **only a child is deactivated**:
/// `ossl_provider_is_child` gates the call, so a provider the application loaded explicitly
/// and the parent then withdrew is left alone. That gate is the whole of the difference
/// between this callback and [`provider_create_child_cb`]'s first branch.
///
/// # Safety
/// As [`provider_create_child_cb`].
pub(crate) unsafe extern "C" fn provider_remove_child_cb(
    prov: *const c_void,
    cbdata: *mut c_void,
) -> c_int {
    let ctx = cbdata;
    let gbl = lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX).cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: `gbl` is live and its name upcall is non-NULL, per the init's validation.
    unsafe {
        let Some(name_fn) = (*gbl).c_prov_name else {
            return 0;
        };
        let provname = name_fn(prov);
        let cprov = ossl_provider_find(ctx, provname, 1);
        if cprov.is_null() {
            return 0;
        }
        // The reference `find` took is dropped; the store's keeps the object alive.
        ossl_provider_free(cprov);
        if ossl_provider_is_child(cprov) != 0 && ossl_provider_deactivate(cprov, 1) == 0 {
            return 0;
        }
    }

    1
}

/// `static int provider_global_props_cb(const char *props, void *cbdata)` — the parent's
/// global properties changed.
///
/// The authority's body is `evp_set_default_properties_int(ctx, props, 0, 1)`, which is
/// `crypto/evp/evp_fetch.c`'s and therefore **Phase 7's**. The crate does not have it, so
/// this answers 0 — the authority's own failure answer — and raises nothing.
///
/// **That is a recorded divergence, not a stub.** `D-CHILD-PROPS-CB-1` in
/// `docs/SECURITY_DIVERGENCE_POLICY.md` states what differs (the callback reports failure
/// where the authority would set the property query and report success) and which phase
/// makes it real. It is also unreachable in this crate today, because nothing can take the
/// parent role until a third-party provider does — which is 6.12's court — and the entry says
/// that too rather than implying a court has seen it.
///
/// # Safety
/// `props` must be NULL or NUL-terminated; `cbdata` must be the child context.
pub(crate) unsafe extern "C" fn provider_global_props_cb(
    _props: *const c_char,
    _cbdata: *mut c_void,
) -> c_int {
    0
}

/// `int ossl_provider_init_as_child(OSSL_LIB_CTX *ctx, const OSSL_CORE_HANDLE *handle,
/// const OSSL_DISPATCH *in)` — the child context's whole initialisation.
///
/// Reads the eight dispatch entries it recognises, **requires seven of them** (see the module
/// documentation for the eighth), creates the lock, and hands the parent its three callbacks.
/// The order matters: a NULL context, a missing slot, a missing pointer and a failed lock all
/// answer 0 *before* the parent is told anything, so a parent that sees its
/// `register_child_cb` called may rely on every upcall it published being stored.
///
/// # Safety
/// `ctx` must be NULL or live; `handle` the parent's handle; `in` a terminated dispatch
/// table.
pub(crate) unsafe fn ossl_provider_init_as_child(
    ctx: *mut c_void,
    handle: *const c_void,
    r#in: *const OsslDispatch,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }

    let gbl = lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX).cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: `gbl` is live, so every write below is to this context's own object.
    unsafe {
        (*gbl).handle = handle;

        let mut p = r#in;
        while (*p).function_id != 0 {
            let f = (*p).function;
            match (*p).function_id {
                // SAFETY: each `function` is a pointer to the function whose id the entry
                // carries; the id is the only thing that says so, which is the dispatch
                // table's contract.
                OSSL_FUNC_CORE_GET_LIBCTX => {
                    (*gbl).c_get_libctx =
                        Some(core::mem::transmute::<*mut c_void, CoreGetLibCtxFn>(f))
                }
                OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB => {
                    (*gbl).c_provider_register_child_cb =
                        Some(core::mem::transmute::<*mut c_void, RegisterChildCbFn>(f))
                }
                OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB => {
                    (*gbl).c_provider_deregister_child_cb =
                        Some(core::mem::transmute::<*mut c_void, DeregisterChildCbFn>(f))
                }
                OSSL_FUNC_PROVIDER_NAME => {
                    (*gbl).c_prov_name = Some(core::mem::transmute::<*mut c_void, ChildNameFn>(f))
                }
                OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX => {
                    (*gbl).c_prov_get0_provider_ctx = Some(core::mem::transmute::<
                        *mut c_void,
                        ChildGet0ProviderCtxFn,
                    >(f))
                }
                OSSL_FUNC_PROVIDER_GET0_DISPATCH => {
                    (*gbl).c_prov_get0_dispatch =
                        Some(core::mem::transmute::<*mut c_void, ChildGet0DispatchFn>(f))
                }
                OSSL_FUNC_PROVIDER_UP_REF => {
                    (*gbl).c_prov_up_ref =
                        Some(core::mem::transmute::<*mut c_void, ChildUpRefFn>(f))
                }
                OSSL_FUNC_PROVIDER_FREE => {
                    (*gbl).c_prov_free = Some(core::mem::transmute::<*mut c_void, ChildFreeFn>(f))
                }
                _ => {}
            }
            p = p.add(1);
        }

        // The seven, in the authority's order. `c_provider_deregister_child_cb` is *not*
        // here -- that omission is the authority's, and reproducing it is what makes the
        // documentation's D-CHILD-DEREGISTER-NULL-1 a statement about the *init*.
        if (*gbl).c_get_libctx.is_none()
            || (*gbl).c_provider_register_child_cb.is_none()
            || (*gbl).c_prov_name.is_none()
            || (*gbl).c_prov_get0_provider_ctx.is_none()
            || (*gbl).c_prov_get0_dispatch.is_none()
            || (*gbl).c_prov_up_ref.is_none()
            || (*gbl).c_prov_free.is_none()
        {
            return 0;
        }

        let lock = CRYPTO_THREAD_lock_new();
        if lock.is_null() {
            return 0;
        }
        (*gbl).lock = lock;

        let register = (*gbl).c_provider_register_child_cb;
        let Some(register) = register else {
            return 0;
        };
        if register(
            (*gbl).handle,
            Some(provider_create_child_cb),
            Some(provider_remove_child_cb),
            Some(provider_global_props_cb),
            ctx,
        ) == 0
        {
            return 0;
        }
    }

    1
}

/// `void ossl_provider_deinit_child(OSSL_LIB_CTX *ctx)`.
///
/// The deregistration. The authority calls `gbl->c_provider_deregister_child_cb(gbl->handle)`
/// **unguarded**, and that pointer is the one `ossl_provider_init_as_child` does not validate
/// — so a parent that published a table without it makes this a jump through NULL. This
/// version checks and returns, and the check is `D-CHILD-DEREGISTER-NULL-1`: the fault is
/// recorded rather than reproduced, and the *unvalidated* init half is kept so that the
/// authority's initialisation contract is what a court compares.
///
/// # Safety
/// `ctx` must be NULL or live.
pub(crate) unsafe fn ossl_provider_deinit_child(ctx: *mut c_void) {
    let gbl = lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX).cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return;
    }

    // SAFETY: `gbl` is live. The pointer may be absent, which is the divergence.
    unsafe {
        if let Some(deregister) = (*gbl).c_provider_deregister_child_cb {
            deregister((*gbl).handle);
        }
    }
}

/// `int ossl_provider_up_ref_parent(OSSL_PROVIDER *prov, int activate)`.
///
/// A child provider whose parent **is the provider it was created in** is
/// self-referencing, and the reference is not taken: the authority's comment says that is what
/// lets the parent's teardown run at the right moment. For any other parent the reference is
/// taken through the parent's own upcall.
///
/// # Safety
/// `prov` must be a live provider.
pub(crate) unsafe fn ossl_provider_up_ref_parent(
    prov: *mut OsslProvider,
    activate: c_int,
) -> c_int {
    // SAFETY: `prov` is live, so its libctx is the one it was built in.
    let gbl = lib_ctx_get_data(
        unsafe { ossl_provider_libctx(prov) },
        OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
    )
    .cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: `gbl` is live and `prov` is live.
    unsafe {
        let parent_handle = ossl_provider_get_parent(prov);
        if parent_handle == (*gbl).handle {
            return 1;
        }
        let Some(up_ref) = (*gbl).c_prov_up_ref else {
            return 0;
        };
        up_ref(parent_handle, activate)
    }
}

/// `int ossl_provider_free_parent(OSSL_PROVIDER *prov, int deactivate)`.
///
/// The mirror of [`ossl_provider_up_ref_parent`], with the same self-referencing case.
///
/// # Safety
/// As [`ossl_provider_up_ref_parent`].
pub(crate) unsafe fn ossl_provider_free_parent(
    prov: *mut OsslProvider,
    deactivate: c_int,
) -> c_int {
    // SAFETY: as above.
    let gbl = lib_ctx_get_data(
        unsafe { ossl_provider_libctx(prov) },
        OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
    )
    .cast::<ChildProvGlobals>();
    if gbl.is_null() {
        return 0;
    }

    // SAFETY: as above.
    unsafe {
        let parent_handle = ossl_provider_get_parent(prov);
        if parent_handle == (*gbl).handle {
            return 1;
        }
        let Some(free_fn) = (*gbl).c_prov_free else {
            return 0;
        };
        let handle = ossl_provider_get_parent(prov);
        free_fn(handle, deactivate)
    }
}

/// The empty-slot case, named once so the three accessors below read the same way.
///
/// `ossl_provider_get_parent`, `_is_child` and `_set_child` are `crypto/provider_core.c`'s and
/// live here because this is the module that can set them; the authority keeps them in
/// `provider_core.c` only because that file is where the object is.
///
/// # Safety
/// `prov` must be NULL or live.
#[inline]
unsafe fn child_fields(prov: *const OsslProvider) -> Option<(*const c_void, c_uint)> {
    if prov.is_null() {
        return None;
    }
    // SAFETY: `prov` is live per the caller's contract.
    unsafe { Some(((*prov).handle, (*prov).ischild)) }
}

/// `const OSSL_CORE_HANDLE *ossl_provider_get_parent(OSSL_PROVIDER *prov)`.
///
/// The stored handle, which is NULL for a provider that is not a child.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_get_parent(prov: *mut OsslProvider) -> *const c_void {
    // SAFETY: `prov` is NULL or live per the caller's contract.
    match unsafe { child_fields(prov) } {
        Some((handle, _)) => handle,
        None => ptr::null(),
    }
}

/// `int ossl_provider_is_child(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_is_child(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is NULL or live per the caller's contract.
    match unsafe { child_fields(prov) } {
        Some((_, ischild)) => ischild as c_int,
        None => 0,
    }
}

/// `int ossl_provider_set_child(OSSL_PROVIDER *prov, const OSSL_CORE_HANDLE *handle)`.
///
/// Stores the handle and sets the flag, and answers **1** unconditionally — including for a
/// NULL `prov`, which the authority would fault on. The flag is what the three arms that were
/// waiting for this function read: `ossl_provider_free`'s `else if (prov->ischild)`,
/// `ossl_provider_up_ref`'s, and `ossl_provider_deactivate`'s remove-children arm.
///
/// # Safety
/// `prov` must be a live provider this call owns a reference to.
pub(crate) unsafe fn ossl_provider_set_child(
    prov: *mut OsslProvider,
    handle: *const c_void,
) -> c_int {
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live per the caller's contract.
    unsafe {
        (*prov).handle = handle;
        (*prov).ischild = 1;
    }
    1
}
