//! Phase 10.9 — `crypto/engine/eng_lib.c`: the `ENGINE` object and the cleanup
//! stack the registry's callbacks are parked on.
//!
//! ## What this subphase is, and what it withholds
//!
//! 10.9 is the digest substrate: the engine table `X509_digest` reaches through
//! `ossl_asn1_item_digest_ex` (`crypto/asn1/a_digest.c:68`, `ENGINE_get_digest_engine`)
//! and the functional-reference release beside it (`:71`, `ENGINE_finish`). The twelve
//! authority units section 6 names are transcribed only as far as the **reachable call
//! graph** needs them; every function whose closure is unlanded is withheld by name in
//! its module rather than answered with a placeholder. This module is the object and
//! registry core: the `ENGINE` structure, its structural reference count, its ex-data
//! block, the engine-wide run-once lock, and the cleanup list `engine_table_register`
//! and `engine_list_add` register callbacks on.
//!
//! **Withheld by name, with its blocker:**
//!
//! * `engine_cleanup_int` — its closure is landed, but the authority reaches it only from
//!   `OPENSSL_cleanup` (`crypto/init.c`, Phase 3), which this crate's landed
//!   `OPENSSL_cleanup` does not yet call; landing it would define a symbol nothing reaches
//!   and letting the crate claim the cleanup ran would be false. It waits for the init
//!   sequence to name it, exactly as the authority's own comment "must be called before
//!   engine_cleanup_int()" (`src/runtime/init.rs:935`) records.
//! * `engine_set_all_null` **is** landed and is now called: Phase 16.2 landed
//!   `crypto/engine/eng_dyn.c:488` (`src/engine/eng_dyn.rs`), its only caller. It is the
//!   compile-time inventory of the structure's fields — the authority's own comment says it
//!   is placed beside `ENGINE_new` so a new field is caught.
//!
//! **Not this module's, and not this stratum's.** The five legacy method slots' accessors
//! (`ENGINE_set_RSA`/`_DSA`/`_DH`/`_EC`/`_RAND` and the getters) are `tb_rsa.c`,
//! `tb_dsa.c`, `tb_dh.c`, `tb_eckey.c` and `tb_rand.c`, and the three key-loader accessors
//! are `eng_pkey.c` — units section 6 does **not** name for 10.9 — so they are out of scope
//! rather than withheld from this module. The fields themselves (`rsa_meth` … `rand_meth`,
//! `load_privkey`, `load_pubkey`, `load_ssl_client_cert`) stay in the layout so its offsets
//! are the authority's.
//!
//! ## The `CRYPTO_REF_COUNT` is the fallback arm, and the layout is measured
//!
//! `struct engine_st` (`crypto/engine/eng_local.h:111-155`) is `#[repr(C)]` here and its
//! offsets are asserted below. The numbers come from `courts/layout/measure-engine.c`,
//! compiled against the pinned authority's own internal header. `CRYPTO_REF_COUNT` is
//! the C11 `_Atomic int` — four bytes — and `CRYPTO_EX_DATA` is the two-pointer block
//! `crypto/ex_data.c` defines, so `struct_ref`/`funct_ref` sit at 156/160 and `ex_data`
//! at 168. `CRYPTO_NEW_REF`/`CRYPTO_FREE_REF` are the `#ifndef CRYPTO_NEW_FREE_DEFINED`
//! fallbacks for that arm (`internal/refcount.h:279-288`): a plain assignment and a
//! no-op, which is what the two helpers below reproduce.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{ENG_LIB_206, ENG_LIB_216, ENG_LIB_33};
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_ENGINE,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_push, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_new, CRYPTO_THREAD_run_once, CryptoOnce, CryptoRwlock,
};

/// The authority's `OPENSSL_FILE` for this unit, so an allocation a caller's
/// `CRYPTO_set_mem_functions` sees carries the authority's coordinate.
const FILE: *const c_char = c"crypto/engine/eng_lib.c".as_ptr();
/// `OPENSSL_LINE` of `ENGINE_new`'s `OPENSSL_zalloc` (`:36`).
const LINE_NEW: c_int = 36;
/// `OPENSSL_LINE` of `ENGINE_new`'s allocation-failure free and `engine_free_util`'s free.
const LINE_FREE: c_int = 39;
/// `OPENSSL_LINE` of `int_cleanup_item`'s `OPENSSL_malloc` (`:132`).
const LINE_ITEM: c_int = 132;

/// `ENGINE_GEN_INT_FUNC_PTR` — `int (*)(ENGINE *)`.
pub type EngineGenIntFuncPtr = unsafe extern "C" fn(*mut Engine) -> c_int;
/// `ENGINE_CTRL_FUNC_PTR` — `int (*)(ENGINE *, int, long, void *, void (*)(void))`.
pub type EngineCtrlFuncPtr = unsafe extern "C" fn(
    *mut Engine,
    c_int,
    c_long,
    *mut c_void,
    Option<unsafe extern "C" fn()>,
) -> c_int;
/// `ENGINE_LOAD_KEY_PTR` — the `EVP_PKEY *(*)(...)` key loader. `EVP_PKEY`, `UI_METHOD`
/// and the callback data are opaque here.
pub type EngineLoadKeyPtr =
    unsafe extern "C" fn(*mut Engine, *const c_char, *mut c_void, *mut c_void) -> *mut c_void;
/// `ENGINE_SSL_CLIENT_CERT_PTR` — the seven-argument SSL client-certificate loader. Every
/// structured parameter is opaque: the digest path never reads one.
pub type EngineSslClientCertPtr = unsafe extern "C" fn(
    *mut Engine,
    *mut c_void,
    *mut c_void,
    *mut *mut c_void,
    *mut *mut c_void,
    *mut *mut c_void,
    *mut c_void,
    *mut c_void,
) -> c_int;
/// `ENGINE_CIPHERS_PTR` — `int (*)(ENGINE *, const EVP_CIPHER **, const int **, int)`.
pub type EngineCiphersPtr =
    unsafe extern "C" fn(*mut Engine, *mut *const c_void, *mut *const c_int, c_int) -> c_int;
/// `ENGINE_DIGESTS_PTR` — `int (*)(ENGINE *, const EVP_MD **, const int **, int)`.
pub type EngineDigestsPtr =
    unsafe extern "C" fn(*mut Engine, *mut *const c_void, *mut *const c_int, c_int) -> c_int;
/// `ENGINE_PKEY_METHS_PTR` — `int (*)(ENGINE *, EVP_PKEY_METHOD **, const int **, int)`.
pub type EnginePkeyMethsPtr =
    unsafe extern "C" fn(*mut Engine, *mut *mut c_void, *mut *const c_int, c_int) -> c_int;
/// `ENGINE_PKEY_ASN1_METHS_PTR` — `int (*)(ENGINE *, EVP_PKEY_ASN1_METHOD **, const int **, int)`.
pub type EnginePkeyAsn1MethsPtr =
    unsafe extern "C" fn(*mut Engine, *mut *mut c_void, *mut *const c_int, c_int) -> c_int;

/// `ENGINE_CMD_DEFN` (`openssl/engine.h:257-262`) — the caller-supplied control-command
/// definition a registered `cmd_defns` list is walked over.
#[repr(C)]
pub struct EngineCmdDefn {
    /// `unsigned int cmd_num` — the command number; zero marks the list's end.
    pub cmd_num: c_uint,
    /// `const char *cmd_name` — NULL marks the list's end.
    pub cmd_name: *const c_char,
    /// `const char *cmd_desc` — optional; `eng_ctrl.c` substitutes `""`.
    pub cmd_desc: *const c_char,
    /// `unsigned int cmd_flags` — one of `ENGINE_CMD_FLAG_*`.
    pub cmd_flags: c_uint,
}

const _: () = {
    assert!(size_of::<EngineCmdDefn>() == 32);
    assert!(core::mem::offset_of!(EngineCmdDefn, cmd_num) == 0);
    assert!(core::mem::offset_of!(EngineCmdDefn, cmd_name) == 8);
    assert!(core::mem::offset_of!(EngineCmdDefn, cmd_desc) == 16);
    assert!(core::mem::offset_of!(EngineCmdDefn, cmd_flags) == 24);
};

/// `struct engine_st` (`crypto/engine/eng_local.h:111-155`) — the `ENGINE` object.
///
/// The five legacy method slots are typed `*const c_void`: their objects are other
/// strata's and this module never dereferences one. The callback slots the registry does
/// call are typed.
#[repr(C)]
pub struct Engine {
    /// `const char *id`
    pub(crate) id: *const c_char,
    /// `const char *name`
    pub(crate) name: *const c_char,
    /// `const RSA_METHOD *rsa_meth`
    pub(crate) rsa_meth: *const c_void,
    /// `const DSA_METHOD *dsa_meth`
    pub(crate) dsa_meth: *const c_void,
    /// `const DH_METHOD *dh_meth`
    pub(crate) dh_meth: *const c_void,
    /// `const EC_KEY_METHOD *ec_meth`
    pub(crate) ec_meth: *const c_void,
    /// `const RAND_METHOD *rand_meth`
    pub(crate) rand_meth: *const c_void,
    /// `ENGINE_CIPHERS_PTR ciphers`
    pub(crate) ciphers: Option<EngineCiphersPtr>,
    /// `ENGINE_DIGESTS_PTR digests`
    pub(crate) digests: Option<EngineDigestsPtr>,
    /// `ENGINE_PKEY_METHS_PTR pkey_meths`
    pub(crate) pkey_meths: Option<EnginePkeyMethsPtr>,
    /// `ENGINE_PKEY_ASN1_METHS_PTR pkey_asn1_meths`
    pub(crate) pkey_asn1_meths: Option<EnginePkeyAsn1MethsPtr>,
    /// `ENGINE_GEN_INT_FUNC_PTR destroy`
    pub(crate) destroy: Option<EngineGenIntFuncPtr>,
    /// `ENGINE_GEN_INT_FUNC_PTR init`
    pub(crate) init: Option<EngineGenIntFuncPtr>,
    /// `ENGINE_GEN_INT_FUNC_PTR finish`
    pub(crate) finish: Option<EngineGenIntFuncPtr>,
    /// `ENGINE_CTRL_FUNC_PTR ctrl`
    pub(crate) ctrl: Option<EngineCtrlFuncPtr>,
    /// `ENGINE_LOAD_KEY_PTR load_privkey`
    pub(crate) load_privkey: Option<EngineLoadKeyPtr>,
    /// `ENGINE_LOAD_KEY_PTR load_pubkey`
    pub(crate) load_pubkey: Option<EngineLoadKeyPtr>,
    /// `ENGINE_SSL_CLIENT_CERT_PTR load_ssl_client_cert`
    pub(crate) load_ssl_client_cert: Option<EngineSslClientCertPtr>,
    /// `const ENGINE_CMD_DEFN *cmd_defns`
    pub(crate) cmd_defns: *const EngineCmdDefn,
    /// `int flags`
    pub(crate) flags: c_int,
    /// `CRYPTO_REF_COUNT struct_ref` — the structural reference count.
    pub(crate) struct_ref: c_int,
    /// `int funct_ref` — the functional reference count; `funct_ref <= struct_ref`.
    pub(crate) funct_ref: c_int,
    /// `CRYPTO_EX_DATA ex_data` — the per-ENGINE data block.
    pub(crate) ex_data: CryptoExData,
    /// `ENGINE *prev` — the list's predecessor; not itself a reference.
    pub(crate) prev: *mut Engine,
    /// `ENGINE *next` — the list's successor; each non-NULL `next` is one reference.
    pub(crate) next: *mut Engine,
    /// `ENGINE *prev_dyn` — the dynamic-engine list's predecessor.
    pub(crate) prev_dyn: *mut Engine,
    /// `ENGINE *next_dyn` — the dynamic-engine list's successor.
    pub(crate) next_dyn: *mut Engine,
    /// `ENGINE_DYNAMIC_ID dynamic_id` — the dynamic engine's unload hook, or NULL.
    pub(crate) dynamic_id: Option<unsafe extern "C" fn()>,
}

const _: () = {
    assert!(size_of::<Engine>() == 224);
    assert!(core::mem::offset_of!(Engine, id) == 0);
    assert!(core::mem::offset_of!(Engine, name) == 8);
    assert!(core::mem::offset_of!(Engine, rsa_meth) == 16);
    assert!(core::mem::offset_of!(Engine, dsa_meth) == 24);
    assert!(core::mem::offset_of!(Engine, dh_meth) == 32);
    assert!(core::mem::offset_of!(Engine, ec_meth) == 40);
    assert!(core::mem::offset_of!(Engine, rand_meth) == 48);
    assert!(core::mem::offset_of!(Engine, ciphers) == 56);
    assert!(core::mem::offset_of!(Engine, digests) == 64);
    assert!(core::mem::offset_of!(Engine, pkey_meths) == 72);
    assert!(core::mem::offset_of!(Engine, pkey_asn1_meths) == 80);
    assert!(core::mem::offset_of!(Engine, destroy) == 88);
    assert!(core::mem::offset_of!(Engine, init) == 96);
    assert!(core::mem::offset_of!(Engine, finish) == 104);
    assert!(core::mem::offset_of!(Engine, ctrl) == 112);
    assert!(core::mem::offset_of!(Engine, load_privkey) == 120);
    assert!(core::mem::offset_of!(Engine, load_pubkey) == 128);
    assert!(core::mem::offset_of!(Engine, load_ssl_client_cert) == 136);
    assert!(core::mem::offset_of!(Engine, cmd_defns) == 144);
    assert!(core::mem::offset_of!(Engine, flags) == 152);
    assert!(core::mem::offset_of!(Engine, struct_ref) == 156);
    assert!(core::mem::offset_of!(Engine, funct_ref) == 160);
    assert!(core::mem::offset_of!(Engine, ex_data) == 168);
    assert!(core::mem::offset_of!(Engine, prev) == 184);
    assert!(core::mem::offset_of!(Engine, next) == 192);
    assert!(core::mem::offset_of!(Engine, prev_dyn) == 200);
    assert!(core::mem::offset_of!(Engine, next_dyn) == 208);
    assert!(core::mem::offset_of!(Engine, dynamic_id) == 216);
};

// ---------------------------------------------------------------------------------------------
// The engine-wide lock — `eng_lib.c:15-25`
// ---------------------------------------------------------------------------------------------

/// `CRYPTO_RWLOCK *global_engine_lock` (`:15`).
static GLOBAL_ENGINE_LOCK: AtomicPtr<CryptoRwlock> = AtomicPtr::new(ptr::null_mut());

/// `CRYPTO_ONCE engine_lock_init = CRYPTO_ONCE_STATIC_INIT` (`:17`).
///
/// An `AtomicI32` rather than a bare `static`, because `pthread_once` writes through the
/// pointer it is given.
static ENGINE_LOCK_INIT: AtomicI32 = AtomicI32::new(0);

/// The engine lock, or NULL before [`run_engine_lock_init`].
///
/// The authority reads `global_engine_lock` directly at every call site; this accessor is
/// the crate's equivalent, and every caller runs the once first.
pub(crate) fn global_engine_lock() -> *mut CryptoRwlock {
    GLOBAL_ENGINE_LOCK.load(Ordering::Acquire)
}

/// `DEFINE_RUN_ONCE(do_engine_lock_init)` body (`:21-25`).
extern "C" fn do_engine_lock_init() {
    let lock = CRYPTO_THREAD_lock_new();
    GLOBAL_ENGINE_LOCK.store(lock, Ordering::Release);
}

/// `RUN_ONCE(&engine_lock_init, do_engine_lock_init)`.
///
/// The authority's `RUN_ONCE` answers the init function's own return value, so a failed
/// `CRYPTO_THREAD_lock_new` is a failed once. The crate's `CRYPTO_THREAD_run_once` is the
/// pthread primitive and answers only whether `pthread_once` succeeded, so the lock's
/// validity is the second half of the test.
///
/// # Safety
/// No argument; safe to call from any thread. Declared `unsafe` to match the call sites
/// the authority writes under `RUN_ONCE`.
pub(crate) unsafe fn run_engine_lock_init() -> bool {
    // SAFETY: `ENGINE_LOCK_INIT` is this module's once storage, initially zero, and
    // `do_engine_lock_init` is a valid `extern "C" fn()` init.
    // SAFETY: the operation's pointers are live per the caller's contract.
    let ran = unsafe {
        CRYPTO_THREAD_run_once(
            ENGINE_LOCK_INIT.as_ptr() as *mut CryptoOnce,
            Some(do_engine_lock_init),
        )
    };
    ran != 0 && !global_engine_lock().is_null()
}

// ---------------------------------------------------------------------------------------------
// The reference count — `internal/refcount.h`, the `#ifndef CRYPTO_NEW_FREE_DEFINED` arm
// ---------------------------------------------------------------------------------------------

/// `CRYPTO_UP_REF(refcnt, &ret)` — relaxed fetch-add, answering the **new** value.
///
/// # Safety
/// `p` must be a live refcount and `ret` a writable slot.
pub(crate) unsafe fn up_ref(p: *mut c_int, ret: *mut c_int) {
    // SAFETY: the caller guarantees both pointers.
    let new = unsafe { (*p).wrapping_add(1) };
    // SAFETY: as above.
    unsafe { *p = new };
    // SAFETY: the caller offers a writable slot.
    unsafe { *ret = new };
}

/// `CRYPTO_DOWN_REF(refcnt, &ret)` — fetch-sub, answering the **new** value.
///
/// The fallback `CRYPTO_NEW_FREE_DEFINED` arm has no fence; the release/acquire fence the
/// atomic arm carries is reproduced anyway, because `engine_free_util` depends on the
/// destructor seeing every earlier mutation.
///
/// # Safety
/// As [`up_ref`].
pub(crate) unsafe fn down_ref(p: *mut c_int, ret: *mut c_int) {
    // SAFETY: the caller guarantees both pointers.
    let new = unsafe { (*p).wrapping_sub(1) };
    // SAFETY: as above.
    unsafe { *p = new };
    core::sync::atomic::fence(Ordering::Release);
    if new == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    // SAFETY: the caller offers a writable slot.
    unsafe { *ret = new };
}

// ---------------------------------------------------------------------------------------------
// The object lifecycle — `eng_lib.c:27-107`
// ---------------------------------------------------------------------------------------------

/// `ENGINE *ENGINE_new(void)` — `crypto/engine/eng_lib.c:27-49`.
#[no_mangle]
pub extern "C" fn ENGINE_new() -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the once storage is this module's and the init is the one above.
        if !unsafe { run_engine_lock_init() } {
            // SAFETY: `ENG_LIB_33` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIB_33) };
            return ptr::null_mut();
        }
        let ret = CRYPTO_zalloc(size_of::<Engine>(), FILE, LINE_NEW) as *mut Engine;
        if ret.is_null() {
            return ptr::null_mut();
        }
        // `CRYPTO_NEW_REF(&ret->struct_ref, 1)` — the fallback arm assigns.
        // SAFETY: `ret` is a fresh zeroed `Engine`.
        unsafe { (*ret).struct_ref = 1 };
        // SAFETY: `ret` is live and its `ex_data` block is in place.
        let ok = unsafe {
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_ENGINE,
                ret.cast::<c_void>(),
                ptr::addr_of_mut!((*ret).ex_data),
            )
        };
        if ok == 0 {
            // SAFETY: `ret` is the allocation above and is not used again.
            unsafe { CRYPTO_free(ret.cast::<c_void>(), FILE, LINE_FREE) };
            return ptr::null_mut();
        }
        ret
    })
}

/// `void engine_set_all_null(ENGINE *e)` — `crypto/engine/eng_lib.c:56-75`.
///
/// Its only authority caller is `crypto/engine/eng_dyn.c:488`, the dynamic-engine
/// roll-back `dynamic_load` performs after the version check and before `bind_engine`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`.
pub(crate) unsafe fn engine_set_all_null(e: *mut Engine) {
    if e.is_null() {
        return;
    }
    // SAFETY: `e` is live per the contract; every store is to a field of an `ENGINE`.
    unsafe {
        (*e).id = ptr::null();
        (*e).name = ptr::null();
        (*e).rsa_meth = ptr::null();
        (*e).dsa_meth = ptr::null();
        (*e).dh_meth = ptr::null();
        (*e).rand_meth = ptr::null();
        (*e).ciphers = None;
        (*e).digests = None;
        (*e).destroy = None;
        (*e).init = None;
        (*e).finish = None;
        (*e).ctrl = None;
        (*e).load_privkey = None;
        (*e).load_pubkey = None;
        (*e).cmd_defns = ptr::null();
        (*e).flags = 0;
        (*e).dynamic_id = None;
    }
}

/// `int engine_free_util(ENGINE *e, int not_locked)` — `crypto/engine/eng_lib.c:77-102`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE` whose caller holds a structural reference.
pub(crate) unsafe fn engine_free_util(e: *mut Engine, not_locked: c_int) -> c_int {
    if e.is_null() {
        return 1;
    }
    let mut i: c_int = 0;
    // SAFETY: `e` is live and `struct_ref` is its refcount; `i` is a local slot.
    unsafe { down_ref(ptr::addr_of_mut!((*e).struct_ref), &mut i) };
    if i > 0 {
        return 1;
    }
    // The dynamically allocated public-key methods, then the destroy hook, then the
    // dynamic-id unlink, the ex-data free and the object itself — the authority's order.
    // SAFETY: `e` is live and this is its last reference.
    unsafe {
        crate::engine::tb_pkmeth::engine_pkey_meths_free(e);
        crate::engine::tb_asnmth::engine_pkey_asn1_meths_free(e);
    }
    // SAFETY: `e` is live; `destroy` is the caller's hook or NULL.
    if let Some(destroy) = unsafe { (*e).destroy } {
        // SAFETY: the hook is the caller's and is called with the ENGINE it was set on.
        unsafe { destroy(e) };
    }
    // SAFETY: `e` is live and this is its last reference.
    unsafe {
        crate::engine::eng_list::engine_remove_dynamic_id(e, not_locked);
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_ENGINE,
            e.cast::<c_void>(),
            ptr::addr_of_mut!((*e).ex_data),
        );
        CRYPTO_free(e.cast::<c_void>(), FILE, LINE_FREE);
    }
    1
}

/// `int ENGINE_free(ENGINE *e)` — `crypto/engine/eng_lib.c:104-107`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_free(e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded; `e` is NULL or live per the caller's contract.
        unsafe { engine_free_util(e, 1) }
    })
}

// ---------------------------------------------------------------------------------------------
// The cleanup stack — `eng_lib.c:109-184`
// ---------------------------------------------------------------------------------------------

/// `void (*)(void)` — `ENGINE_CLEANUP_CB`.
pub type EngineCleanupCb = unsafe extern "C" fn();

/// `struct st_engine_cleanup_item` (`crypto/engine/eng_local.h:45-47`).
#[repr(C)]
pub(crate) struct EngineCleanupItem {
    /// `ENGINE_CLEANUP_CB *cb`
    pub(crate) cb: Option<EngineCleanupCb>,
}

const _: () = {
    assert!(size_of::<EngineCleanupItem>() == 8);
    assert!(core::mem::offset_of!(EngineCleanupItem, cb) == 0);
};

/// `static STACK_OF(ENGINE_CLEANUP_ITEM) *cleanup_stack = NULL` (`:117`).
static CLEANUP_STACK: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static int int_cleanup_check(int create)` — `crypto/engine/eng_lib.c:118-126`.
fn int_cleanup_check(create: bool) -> bool {
    if !CLEANUP_STACK.load(Ordering::Acquire).is_null() {
        return true;
    }
    if !create {
        return false;
    }
    let stack = OPENSSL_sk_new_null();
    CLEANUP_STACK.store(stack, Ordering::Release);
    !stack.is_null()
}

/// `static ENGINE_CLEANUP_ITEM *int_cleanup_item(ENGINE_CLEANUP_CB *cb)` — `:128-136`.
fn int_cleanup_item(cb: Option<EngineCleanupCb>) -> *mut EngineCleanupItem {
    let item =
        CRYPTO_malloc(size_of::<EngineCleanupItem>(), FILE, LINE_ITEM) as *mut EngineCleanupItem;
    if item.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `item` is the fresh allocation above and is writable.
    unsafe { (*item).cb = cb };
    item
}

/// `int engine_cleanup_add_first(ENGINE_CLEANUP_CB *cb)` — `:138-151`.
///
/// # Safety
/// `cb` is a caller callback invoked at cleanup; it must be valid until then.
pub(crate) unsafe fn engine_cleanup_add_first(cb: Option<EngineCleanupCb>) -> c_int {
    if !int_cleanup_check(true) {
        return 0;
    }
    let item = int_cleanup_item(cb);
    if !item.is_null() {
        let stack = CLEANUP_STACK.load(Ordering::Acquire);
        // SAFETY: `stack` is the non-NULL stack `int_cleanup_check` created.
        if unsafe { OPENSSL_sk_insert(stack, item.cast::<c_void>(), 0) } > 0 {
            return 1;
        }
        // SAFETY: `item` was not inserted and is not used again.
        unsafe { CRYPTO_free(item.cast::<c_void>(), FILE, LINE_ITEM) };
    }
    0
}

/// `int engine_cleanup_add_last(ENGINE_CLEANUP_CB *cb)` — `:153-166`.
///
/// # Safety
/// As [`engine_cleanup_add_first`].
pub(crate) unsafe fn engine_cleanup_add_last(cb: Option<EngineCleanupCb>) -> c_int {
    if !int_cleanup_check(true) {
        return 0;
    }
    let item = int_cleanup_item(cb);
    if !item.is_null() {
        let stack = CLEANUP_STACK.load(Ordering::Acquire);
        // SAFETY: `stack` is the non-NULL stack `int_cleanup_check` created.
        if unsafe { OPENSSL_sk_push(stack, item.cast::<c_void>()) } > 0 {
            return 1;
        }
        // SAFETY: `item` was not inserted and is not used again.
        unsafe { CRYPTO_free(item.cast::<c_void>(), FILE, LINE_ITEM) };
    }
    0
}

/// `static void engine_cleanup_cb_free(ENGINE_CLEANUP_ITEM *item)` — `:169-173`.
///
/// The `sk_*_pop_free` callback: run the item's callback, then free the item. It is
/// unreachable until `engine_cleanup_int` is called (see the module header).
///
/// # Safety
/// `item` must be a live `EngineCleanupItem`.
#[allow(dead_code)] // unreachable until `engine_cleanup_int` is named by `OPENSSL_cleanup`
unsafe extern "C" fn engine_cleanup_cb_free(item: *mut c_void) {
    let item = item.cast::<EngineCleanupItem>();
    // SAFETY: the stack's elements are `int_cleanup_item` allocations.
    if let Some(cb) = unsafe { (*item).cb } {
        // SAFETY: the callback was registered by a caller and is live.
        unsafe { cb() };
    }
    // SAFETY: `item` is not used again.
    unsafe { CRYPTO_free(item.cast::<c_void>(), FILE, LINE_ITEM) };
}

// `void engine_cleanup_int(void)` (`crypto/engine/eng_lib.c:175-184`) is withheld. Its closure
// is landed, but the authority calls it only from `OPENSSL_cleanup` (`crypto/init.c`), which
// this crate's landed `OPENSSL_cleanup` does not yet name. Landing it here would define a
// symbol nothing reaches and would let the crate claim the cleanup ran. The blocker is the
// init sequence, not this unit.

// ---------------------------------------------------------------------------------------------
// The ex_data support — `eng_lib.c:186-196`
// ---------------------------------------------------------------------------------------------

/// `int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg)` — `crypto/engine/eng_lib.c:188-191`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_ex_data(e: *mut Engine, idx: c_int, arg: *mut c_void) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            return 0;
        }
        // SAFETY: `e` is live and `ex_data` is its block.
        unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*e).ex_data), idx, arg) }
    })
}

/// `void *ENGINE_get_ex_data(const ENGINE *e, int idx)` — `:193-196`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_ex_data(e: *const Engine, idx: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if e.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `e` is live and `ex_data` is its block.
        unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*e).ex_data), idx) }
    })
}

// ---------------------------------------------------------------------------------------------
// The element accessors — `eng_lib.c:198-297`
// ---------------------------------------------------------------------------------------------

/// `int ENGINE_set_id(ENGINE *e, const char *id)` — `crypto/engine/eng_lib.c:203-211`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_id(e: *mut Engine, id: *const c_char) -> c_int {
    guard_ffi(0, || {
        if id.is_null() {
            // SAFETY: `ENG_LIB_206` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIB_206) };
            return 0;
        }
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).id = id };
        1
    })
}

/// `int ENGINE_set_name(ENGINE *e, const char *name)` — `:213-221`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_name(e: *mut Engine, name: *const c_char) -> c_int {
    guard_ffi(0, || {
        if name.is_null() {
            // SAFETY: `ENG_LIB_216` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIB_216) };
            return 0;
        }
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).name = name };
        1
    })
}

/// `int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f)` — `:223-227`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_destroy_function(
    e: *mut Engine,
    destroy_f: Option<EngineGenIntFuncPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).destroy = destroy_f };
        1
    })
}

/// `int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f)` — `:229-233`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_init_function(
    e: *mut Engine,
    init_f: Option<EngineGenIntFuncPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).init = init_f };
        1
    })
}

/// `int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f)` — `:235-239`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_finish_function(
    e: *mut Engine,
    finish_f: Option<EngineGenIntFuncPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).finish = finish_f };
        1
    })
}

/// `int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f)` — `:241-245`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_ctrl_function(
    e: *mut Engine,
    ctrl_f: Option<EngineCtrlFuncPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).ctrl = ctrl_f };
        1
    })
}

/// `int ENGINE_set_flags(ENGINE *e, int flags)` — `:247-251`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_flags(e: *mut Engine, flags: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).flags = flags };
        1
    })
}

/// `int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns)` — `:253-257`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_cmd_defns(
    e: *mut Engine,
    defns: *const EngineCmdDefn,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).cmd_defns = defns };
        1
    })
}

/// `const char *ENGINE_get_id(const ENGINE *e)` — `:259-262`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_id(e: *const Engine) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).id }
    })
}

/// `const char *ENGINE_get_name(const ENGINE *e)` — `:264-267`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_name(e: *const Engine) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `e` is the caller's live ENGINE.
        unsafe { (*e).name }
    })
}

/// `ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e)` — `:269-272`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_destroy_function(
    e: *const Engine,
) -> Option<EngineGenIntFuncPtr> {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).destroy }
}

/// `ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e)` — `:274-277`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_init_function(e: *const Engine) -> Option<EngineGenIntFuncPtr> {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).init }
}

/// `ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e)` — `:279-282`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_finish_function(
    e: *const Engine,
) -> Option<EngineGenIntFuncPtr> {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).finish }
}

/// `ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e)` — `:284-287`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_ctrl_function(e: *const Engine) -> Option<EngineCtrlFuncPtr> {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).ctrl }
}

/// `int ENGINE_get_flags(const ENGINE *e)` — `:289-292`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_flags(e: *const Engine) -> c_int {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).flags }
}

/// `const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e)` — `:294-297`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_cmd_defns(e: *const Engine) -> *const EngineCmdDefn {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).cmd_defns }
}

/// `void *ENGINE_get_static_state(void)` — `crypto/engine/eng_lib.c:306-309`.
///
/// The address of a module-private `static int`, which is what an application compares
/// across an `ENGINE` to detect a shared static state. It is a fixed address, not a value.
#[no_mangle]
pub extern "C" fn ENGINE_get_static_state() -> *mut c_void {
    static INTERNAL_STATIC_HACK: AtomicI32 = AtomicI32::new(0);
    INTERNAL_STATIC_HACK.as_ptr().cast::<c_void>()
}
