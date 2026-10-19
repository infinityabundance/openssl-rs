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
    /// `CRYPTO_REF_COUNT struct_ref` — the structural reference count. `CRYPTO_REF_COUNT` is
    /// the authority's C11 `_Atomic int`; [`AtomicI32`] is its layout-compatible Rust form.
    pub(crate) struct_ref: AtomicI32,
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
    assert!(size_of::<AtomicI32>() == size_of::<c_int>());
    assert!(core::mem::align_of::<AtomicI32>() == core::mem::align_of::<c_int>());
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
// Ownership of the `ENGINE` object
// ---------------------------------------------------------------------------------------------

/// An owned `ENGINE` block still under construction.
///
/// [`ENGINE_new`] allocates the block and fills its members one at a time; on its `CRYPTO_new_ex_data`
/// refusal the authority's release is the block alone (`crypto/engine/eng_lib.c:46`), so the
/// destructor ([`OwnedEngine`]) over members that may not be set must not run. [`Self::finish`] hands
/// the block to the C ABI on success.
struct RawEngine {
    ptr: ptr::NonNull<Engine>,
}

impl RawEngine {
    /// `CRYPTO_zalloc(sizeof(*ret), FILE, 36)`, or `None` when it answers NULL.
    fn new() -> Option<RawEngine> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<Engine>()` bytes, which is exactly `Engine`'s layout.
        let raw = CRYPTO_zalloc(size_of::<Engine>(), FILE, LINE_NEW).cast::<Engine>();
        ptr::NonNull::new(raw).map(|ptr| RawEngine { ptr })
    }

    /// The writable start of the block.
    fn as_ptr(&self) -> *mut Engine {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the C ABI's answer.
    fn finish(self) -> *mut Engine {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for RawEngine {
    /// The authority's `ENGINE_new` refusal release (`crypto/engine/eng_lib.c:46`): the block alone,
    /// at the authority's own `OPENSSL_free` site.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `new` allocated and has not been handed out; its single
        // release is the authority's own plain `CRYPTO_free`.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), FILE, LINE_FREE) };
    }
}

/// An owned `ENGINE` block at its last structural reference.
///
/// The block keeps the authority's `#[repr(C)]` layout and its exact `CRYPTO_zalloc` size/`file`/`line`,
/// but its *ownership* is this type: [`Self::from_raw`] reclaims the block the refcount reaches zero
/// on and `Drop` runs the authority's own destructor body (`engine_free_util`'s,
/// `crypto/engine/eng_lib.c:77-102`) followed by its single block release. The destructor's
/// `engine_remove_dynamic_id` step takes the caller's `not_locked` flag, so the owner carries it --
/// the generic `CtxDestroy` shape in the adjacent units cannot express that runtime argument.
struct OwnedEngine {
    ptr: ptr::NonNull<Engine>,
    not_locked: c_int,
}

impl OwnedEngine {
    /// Reclaim the `ENGINE` block at its last structural reference, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live `ENGINE` this file allocated whose caller holds its last structural
    /// reference, so no other owner will release it; `Drop` is the block's single release.
    unsafe fn from_raw(ptr: *mut Engine, not_locked: c_int) -> Option<OwnedEngine> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedEngine { ptr, not_locked })
    }
}

impl Drop for OwnedEngine {
    /// `engine_free_util`'s last-reference body (`crypto/engine/eng_lib.c:77-102`): the dynamically
    /// allocated public-key method tables, the destroy hook, the dynamic-id unlink, the ex-data free
    /// and the block release -- the authority's own order.
    fn drop(&mut self) {
        let ptr = self.ptr.as_ptr();
        // SAFETY: `ptr` is the block `from_raw` reclaimed at its last reference; every member is set
        // because only a completed `ENGINE_new` object reaches its last reference, and this is the
        // block's single release.
        unsafe {
            crate::engine::tb_pkmeth::engine_pkey_meths_free(ptr);
            crate::engine::tb_asnmth::engine_pkey_asn1_meths_free(ptr);
            if let Some(destroy) = (*ptr).destroy {
                destroy(ptr);
            }
            crate::engine::eng_list::engine_remove_dynamic_id(ptr, self.not_locked);
            CRYPTO_free_ex_data(
                CRYPTO_EX_INDEX_ENGINE,
                ptr.cast::<c_void>(),
                ptr::addr_of_mut!((*ptr).ex_data),
            );
            CRYPTO_free(ptr.cast::<c_void>(), FILE, LINE_FREE);
        }
    }
}

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
// The reference count — `internal/refcount.h`, shared destroying-sentinel protocol
// ---------------------------------------------------------------------------------------------
//
// `Engine::struct_ref` is the authority's `CRYPTO_REF_COUNT` (a C11 `_Atomic int`). The
// authority moves it with a plain fetch-add/fetch-sub, which cannot distinguish "the count
// reached zero" from "the destructor is running". `Engine_free`'s last-reference body calls
// the `destroy` hook and `CRYPTO_free_ex_data`, so an application callback can re-enter
// `ENGINE_free` while the object is being torn down; a second teardown would be a double free.
// The crate's shared protocol (`runtime::refcount`) reserves `i32::MIN` for that state and
// refuses both a re-entrant release and a resurrection.

/// `CRYPTO_UP_REF` with the shared checked/sentinel protocol.
///
/// Answers 1 when the reference was taken and 0 without changing the count when the count is
/// zero, negative, destroying, or `i32::MAX`.
///
/// # Safety
/// `p` must be a live `AtomicI32` refcount of a live `ENGINE` whose count is published
/// and positive, and the caller must hold the structural reference it acts for (or act
/// for an owner that will not release it during the call), acquiring exactly one new
/// reference.
pub(crate) unsafe fn up_ref(p: *mut AtomicI32) -> c_int {
    // SAFETY: the caller guarantees `p` is a live refcount belonging to a live object and
    // acts for an existing owner; the new reference is owned exactly once by that caller.
    unsafe { crate::runtime::refcount::up_ref(&*p) }
}

/// `CRYPTO_DOWN_REF` with the shared checked/sentinel protocol.
///
/// # Safety
/// As [`up_ref`], plus: the caller owns exactly one reference to the object whose
/// `struct_ref` is `p`, and on [`crate::runtime::refcount::DownRef::Last`] it is the
/// unique destructor runner and must not use the object afterwards.
pub(crate) unsafe fn down_ref(p: *mut AtomicI32) -> crate::runtime::refcount::DownRef {
    // SAFETY: the caller guarantees `p` is a live refcount of a live object and owns the
    // reference this call releases; on `Last` it alone runs the destructor body.
    unsafe { crate::runtime::refcount::down_ref(&*p) }
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
        let Some(raw) = RawEngine::new() else {
            return ptr::null_mut();
        };
        let ret = raw.as_ptr();
        // `CRYPTO_NEW_REF(&ret->struct_ref, 1)` — the fallback arm assigns.
        // SAFETY: `ret` is a fresh zeroed `Engine` and its `ex_data` block is in place.
        let ok = unsafe {
            (*ret).struct_ref.store(1, Ordering::Relaxed);
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_ENGINE,
                ret.cast::<c_void>(),
                ptr::addr_of_mut!((*ret).ex_data),
            )
        };
        if ok == 0 {
            // `raw`'s `Drop` releases the block alone, exactly the authority's refusal path.
            return ptr::null_mut();
        }
        raw.finish()
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
    // SAFETY: `e` is live, `struct_ref` is its refcount, and this frame owns the structural
    // reference it releases; on `Last` it is the unique destructor runner.
    match unsafe { down_ref(ptr::addr_of_mut!((*e).struct_ref)) } {
        crate::runtime::refcount::DownRef::Last => {}
        // A zero/negative/destroying count is a defined no-op. The destroying arm is the
        // re-entrant `ENGINE_free` issued by an ex-data or `destroy` callback, which must not
        // run the destructor body a second time.
        crate::runtime::refcount::DownRef::Remaining
        | crate::runtime::refcount::DownRef::Retired => return 1,
    }
    // SAFETY: `e` is live and this is its last structural reference, so no other owner will release
    // it; `Drop` runs the authority's own destructor body and this is the block's single release.
    drop(unsafe { OwnedEngine::from_raw(e, not_locked) });
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

/// An owned `struct st_engine_cleanup_item`.
///
/// The item is a plain `CRYPTO_malloc` block the cleanup stack adopts and releases at one site
/// (`crypto/engine/eng_lib.c`); its `Drop` is that single release.
struct OwnedItem {
    ptr: ptr::NonNull<EngineCleanupItem>,
}

impl OwnedItem {
    /// `CRYPTO_malloc(sizeof(*item), FILE, 132)`, or `None` when it answers NULL; the item's `cb` is
    /// set before it is handed out.
    fn new(cb: Option<EngineCleanupCb>) -> Option<OwnedItem> {
        let raw = CRYPTO_malloc(size_of::<EngineCleanupItem>(), FILE, LINE_ITEM)
            .cast::<EngineCleanupItem>();
        let ptr = ptr::NonNull::new(raw)?;
        // SAFETY: `ptr` is a fresh, writable `EngineCleanupItem` of this call's own allocation.
        unsafe { (*ptr.as_ptr()).cb = cb };
        Some(OwnedItem { ptr })
    }

    /// The item's address, for the stack that takes it over.
    fn as_ptr(&self) -> *mut EngineCleanupItem {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the item to the cleanup stack that takes it over.
    fn into_raw(self) -> *mut EngineCleanupItem {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim an element the cleanup stack hands to its `sk_*_pop_free` callback, for release by
    /// `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live item this file allocated that no other owner will release.
    unsafe fn from_raw(ptr: *mut EngineCleanupItem) -> Option<OwnedItem> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedItem { ptr })
    }
}

impl Drop for OwnedItem {
    /// The item's single release, through the same seam and the authority's own site.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a block this handle owns and has not released; the authority's own
        // `CRYPTO_free` accepts NULL.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), FILE, LINE_ITEM) };
    }
}

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
fn int_cleanup_item(cb: Option<EngineCleanupCb>) -> Option<OwnedItem> {
    OwnedItem::new(cb)
}

/// `int engine_cleanup_add_first(ENGINE_CLEANUP_CB *cb)` — `:138-151`.
///
/// # Safety
/// `cb` is a caller callback invoked at cleanup; it must be valid until then.
pub(crate) unsafe fn engine_cleanup_add_first(cb: Option<EngineCleanupCb>) -> c_int {
    if !int_cleanup_check(true) {
        return 0;
    }
    let Some(item) = int_cleanup_item(cb) else {
        return 0;
    };
    let stack = CLEANUP_STACK.load(Ordering::Acquire);
    // SAFETY: `stack` is the non-NULL stack `int_cleanup_check` created.
    if unsafe { OPENSSL_sk_insert(stack, item.as_ptr().cast::<c_void>(), 0) } > 0 {
        // The stack now owns the item; `into_raw` gives up this handle's ownership.
        item.into_raw();
        return 1;
    }
    // `item` was not inserted; its `Drop` releases it at the authority's own site.
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
    let Some(item) = int_cleanup_item(cb) else {
        return 0;
    };
    let stack = CLEANUP_STACK.load(Ordering::Acquire);
    // SAFETY: `stack` is the non-NULL stack `int_cleanup_check` created.
    if unsafe { OPENSSL_sk_push(stack, item.as_ptr().cast::<c_void>()) } > 0 {
        // The stack now owns the item; `into_raw` gives up this handle's ownership.
        item.into_raw();
        return 1;
    }
    // `item` was not inserted; its `Drop` releases it at the authority's own site.
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
    // SAFETY: `item` is a live `EngineCleanupItem` this callback takes ownership of per the
    // `sk_*_pop_free` contract; `Drop` is its single release.
    drop(unsafe { OwnedItem::from_raw(item) });
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
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
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_ctrl_function(e: *const Engine) -> Option<EngineCtrlFuncPtr> {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).ctrl }
}

/// `int ENGINE_get_flags(const ENGINE *e)` — `:289-292`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_flags(e: *const Engine) -> c_int {
    // SAFETY: `e` is the caller's live ENGINE.
    unsafe { (*e).flags }
}

/// `const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e)` — `:294-297`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
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

#[cfg(test)]
mod refcount_tests {
    use super::*;
    use crate::engine::eng_list::ENGINE_up_ref;
    use crate::runtime::ex_data::CRYPTO_get_ex_new_index;
    use crate::runtime::refcount::REF_DESTROYING;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Barrier;
    use std::thread;

    static DESTROY_CALLS_MT: AtomicUsize = AtomicUsize::new(0);
    static DESTROY_CALLS_RE: AtomicUsize = AtomicUsize::new(0);
    static REENTER_TARGET: AtomicUsize = AtomicUsize::new(0);
    static REENTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SAW_SENTINEL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn counting_destroy_mt(_e: *mut Engine) -> c_int {
        DESTROY_CALLS_MT.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn counting_destroy_re(_e: *mut Engine) -> c_int {
        DESTROY_CALLS_RE.fetch_add(1, Ordering::SeqCst);
        1
    }

    /// The ex-data free hook runs inside `ENGINE_free`'s last-reference body, before the block
    /// release. Re-entering `ENGINE_free` from it must observe the destroying sentinel.
    unsafe extern "C" fn reenter_free(
        parent: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        _idx: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) {
        let e = REENTER_TARGET.load(Ordering::SeqCst) as *mut Engine;
        if e.is_null() || parent.cast::<Engine>() != e {
            return;
        }
        REENTER_CALLS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: `parent` is the still-allocated ENGINE whose ex-data is being torn down.
        let count = unsafe { (*e).struct_ref.load(Ordering::Acquire) };
        if count == REF_DESTROYING {
            SAW_SENTINEL.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: the target is the ENGINE whose ex-data is being torn down; the block is
        // still allocated at this point.
        unsafe { ENGINE_free(e) };
    }

    #[test]
    fn up_ref_refuses_overflow_without_changing_the_count() {
        let e = ENGINE_new();
        assert!(!e.is_null());
        // SAFETY: `e` is live and this call owns its only structural reference.
        unsafe {
            (*e).struct_ref.store(i32::MAX, Ordering::Relaxed);
            assert_eq!(ENGINE_up_ref(e), 0);
            assert_eq!((*e).struct_ref.load(Ordering::Relaxed), i32::MAX);
            (*e).struct_ref.store(1, Ordering::Relaxed);
            assert_eq!(ENGINE_free(e), 1);
        }
    }

    #[test]
    fn eight_threads_share_the_count_and_run_one_destructor() {
        DESTROY_CALLS_MT.store(0, Ordering::SeqCst);
        let e = ENGINE_new();
        assert!(!e.is_null());
        // SAFETY: `e` is live and this call owns its initial structural reference.
        unsafe { ENGINE_set_destroy_function(e, Some(counting_destroy_mt)) };

        const THREADS: usize = 8;
        let addr = e as usize;
        let barrier = Barrier::new(THREADS);
        thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    let e = addr as *mut Engine;
                    barrier.wait();
                    // SAFETY: the object carries a live reference throughout the race.
                    unsafe {
                        assert_eq!(ENGINE_up_ref(e), 1);
                        assert_eq!(ENGINE_free(e), 1);
                    }
                });
            }
        });

        // SAFETY: `e` is live; every worker returned its reference.
        unsafe {
            assert_eq!((*e).struct_ref.load(Ordering::Acquire), 1);
            assert_eq!(DESTROY_CALLS_MT.load(Ordering::SeqCst), 0);
            // The final release is the unique last reference, so it alone tears down.
            assert_eq!(ENGINE_free(e), 1);
        }
        assert_eq!(DESTROY_CALLS_MT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reentrant_free_from_an_ex_data_callback_is_a_defined_noop() {
        REENTER_CALLS.store(0, Ordering::SeqCst);
        SAW_SENTINEL.store(0, Ordering::SeqCst);
        DESTROY_CALLS_RE.store(0, Ordering::SeqCst);
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_ENGINE,
            0,
            ptr::null_mut(),
            None,
            None,
            Some(reenter_free),
        );
        assert!(idx >= 1, "an engine ex-data index must be available");

        let e = ENGINE_new();
        assert!(!e.is_null());
        // SAFETY: `e` is live and this call owns its only structural reference.
        unsafe {
            ENGINE_set_destroy_function(e, Some(counting_destroy_re));
            assert_eq!(ENGINE_set_ex_data(e, idx, ptr::dangling_mut::<c_void>()), 1);
            REENTER_TARGET.store(e as usize, Ordering::SeqCst);

            assert_eq!(ENGINE_free(e), 1);
        }
        REENTER_TARGET.store(0, Ordering::SeqCst);
        assert_eq!(REENTER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            SAW_SENTINEL.load(Ordering::SeqCst),
            1,
            "the re-entrant callback observes the destroying sentinel"
        );
        assert_eq!(DESTROY_CALLS_RE.load(Ordering::SeqCst), 1);
    }
}
