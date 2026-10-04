//! Phase 10.9 / 13.1 — `crypto/engine/eng_list.c`: the linked list of registered engines.
//!
//! This is the registry's **fetch** surface: the list a caller walks with
//! `ENGINE_get_first`/`ENGINE_get_next`, the publish/retract pair `ENGINE_add`/
//! `ENGINE_remove`, and the by-id lookup `ENGINE_by_id`. 10.9 landed the list core and the
//! dynamic-id list `engine_free_util` unlinks from, and withheld `ENGINE_by_id` by name;
//! 13.1 lands it and the helpers its `ENGINE_FLAGS_BY_ID_COPY` arm reaches.
//!
//! ## `ENGINE_by_id` and the dynamic fallback
//!
//! `ENGINE_by_id` (`:408-473`) loads the built-ins, walks the list for the id, and — on a
//! miss that is not the id `"dynamic"` itself — recurses into `ENGINE_by_id("dynamic")` and
//! drives the dynamic engine with `ENGINE_ctrl_cmd_string` to load a shared object from
//! `OPENSSL_ENGINES` (or the compiled-in engines directory). Phase 16.2 landed
//! `crypto/engine/eng_dyn.c` (`src/engine/eng_dyn.rs`), so the dynamic engine is registered
//! when a caller sets `OPENSSL_INIT_ENGINE_DYNAMIC`: the recursion now finds it and the miss
//! path drives the loader rather than taking `goto notfound` immediately. When the loader's
//! `LOAD` itself refuses (no shared object) the fallback still ends at the authority's own
//! `notfound` arm. The `<id>`-in-list half is transcribed whole, so a caller that registered
//! an engine with `ENGINE_add` finds it exactly as the authority would; the fallback's
//! failure coordinate (`ENGINE_R_NO_SUCH_ENGINE`, `id=%s`) is the authority's too.
//!
//! ## The list owns one structural reference per member
//!
//! `engine_list_head` and every non-NULL `next` each account for exactly one structural
//! reference on the member they point at, and the `prev`/`tail` pointers are pure
//! optimisation — they add a reference for `head` only, not for `tail` or `prev`
//! (`eng_list.c:16-26`). `ENGINE_get_next` therefore takes a reference on what it returns
//! and releases the one it was given, which is why the iteration idiom is
//! `for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::engine::eng_lib::{
    engine_cleanup_add_last, engine_free_util, global_engine_lock, run_engine_lock_init, up_ref,
    Engine,
};
use crate::ffi::guard_ffi;
use crate::runtime::defaults::ossl_get_enginesdir;
use crate::runtime::err::err_sites::{
    ENG_LIST_106, ENG_LIST_124, ENG_LIST_132, ENG_LIST_235, ENG_LIST_262, ENG_LIST_288,
    ENG_LIST_315, ENG_LIST_343, ENG_LIST_347, ENG_LIST_353, ENG_LIST_365, ENG_LIST_371,
    ENG_LIST_413, ENG_LIST_420, ENG_LIST_470, ENG_LIST_479, ENG_LIST_64, ENG_LIST_73, ENG_LIST_89,
    ENG_LIST_97,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

extern "C" {
    /// `int strcmp(const char *s1, const char *s2)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// `static ENGINE *engine_list_head = NULL` (`:27`).
static ENGINE_LIST_HEAD: AtomicPtr<Engine> = AtomicPtr::new(ptr::null_mut());
/// `static ENGINE *engine_list_tail = NULL` (`:28`).
static ENGINE_LIST_TAIL: AtomicPtr<Engine> = AtomicPtr::new(ptr::null_mut());
/// `static ENGINE *engine_dyn_list_head = NULL` (`:33`).
static ENGINE_DYN_LIST_HEAD: AtomicPtr<Engine> = AtomicPtr::new(ptr::null_mut());
/// `static ENGINE *engine_dyn_list_tail = NULL` (`:34`).
static ENGINE_DYN_LIST_TAIL: AtomicPtr<Engine> = AtomicPtr::new(ptr::null_mut());

/// `ENGINE_FLAGS_BY_ID_COPY` — `include/openssl/engine.h:88`, `(int)0x0004`.
///
/// Set on an `ENGINE` whose `ENGINE_by_id` answer must be a *copy* rather than the registered
/// object itself; the `ENGINE_FLAGS_BY_ID_COPY` arm of [`ENGINE_by_id`] reaches [`engine_cpy`].
const ENGINE_FLAGS_BY_ID_COPY: c_int = 0x0004;

/// A write-lock acquisition that reports success, used at the authority's call sites.
fn lock() -> bool {
    // SAFETY: the caller runs `run_engine_lock_init` first; the lock is the engine lock.
    unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) != 0 }
}

/// The unlock half.
fn unlock() {
    // SAFETY: the caller holds the engine lock.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
}

/// `static void engine_list_cleanup(void)` — `crypto/engine/eng_list.c:42-51`.
///
/// Registered on the cleanup stack the first time the list becomes non-empty. It is
/// unreachable until `engine_cleanup_int` is named by `OPENSSL_cleanup` (see `eng_lib.rs`).
unsafe extern "C" fn engine_list_cleanup() {
    loop {
        let head = ENGINE_LIST_HEAD.load(Ordering::Acquire);
        if head.is_null() {
            return;
        }
        // `ENGINE_remove(iterator)` — the same call the authority makes, and the loop's
        // exit condition is the list emptying.
        // SAFETY: `head` is the list's first member.
        let removed = unsafe { ENGINE_remove(head) };
        if removed == 0 {
            return;
        }
    }
}

/// `static int engine_list_add(ENGINE *e)` — `:57-117`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`; the engine lock must be held.
unsafe fn engine_list_add(e: *mut Engine) -> c_int {
    if e.is_null() {
        // SAFETY: `ENG_LIST_64` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_LIST_64) };
        return 0;
    }
    let mut conflict = false;
    let mut iterator = ENGINE_LIST_HEAD.load(Ordering::Acquire);
    while !iterator.is_null() && !conflict {
        // SAFETY: `iterator` is a live list member; `e` is the caller's live ENGINE.
        conflict = unsafe { strcmp((*iterator).id, (*e).id) == 0 };
        // SAFETY: `iterator` is live.
        iterator = unsafe { (*iterator).next };
    }
    if conflict {
        // SAFETY: `ENG_LIST_73` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_LIST_73) };
        return 0;
    }

    // Having the engine in the list assumes a structural reference.
    let mut r: c_int = 0;
    // SAFETY: `e` is live and `struct_ref` is its refcount.
    unsafe { up_ref(ptr::addr_of_mut!((*e).struct_ref), &mut r) };
    let head = ENGINE_LIST_HEAD.load(Ordering::Acquire);
    if head.is_null() {
        // Adding to an empty list.
        let tail = ENGINE_LIST_TAIL.load(Ordering::Acquire);
        if !tail.is_null() {
            // SAFETY: `e` is live; its structural reference is dropped back.
            unsafe { crate::engine::eng_lib::down_ref(ptr::addr_of_mut!((*e).struct_ref), &mut r) };
            // SAFETY: `ENG_LIST_89` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_89) };
            return 0;
        }
        // The first time the list allocates, register the cleanup.
        // SAFETY: `engine_list_cleanup` is a valid `extern "C" fn()` callback.
        if unsafe { engine_cleanup_add_last(Some(engine_list_cleanup)) } == 0 {
            // SAFETY: `e` is live; its structural reference is dropped back.
            unsafe { crate::engine::eng_lib::down_ref(ptr::addr_of_mut!((*e).struct_ref), &mut r) };
            // SAFETY: `ENG_LIST_97` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_97) };
            return 0;
        }
        ENGINE_LIST_HEAD.store(e, Ordering::Release);
        // SAFETY: `e` is live.
        unsafe { (*e).prev = ptr::null_mut() };
    } else {
        // Adding to the tail of an existing list.
        let tail = ENGINE_LIST_TAIL.load(Ordering::Acquire);
        let bad = tail.is_null() || {
            // SAFETY: `tail` is a live list member.
            unsafe { !(*tail).next.is_null() }
        };
        if bad {
            // SAFETY: `e` is live; its structural reference is dropped back.
            unsafe { crate::engine::eng_lib::down_ref(ptr::addr_of_mut!((*e).struct_ref), &mut r) };
            // SAFETY: `ENG_LIST_106` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_106) };
            return 0;
        }
        // SAFETY: `tail` is live and `e` is live.
        unsafe {
            (*tail).next = e;
            (*e).prev = tail;
        }
    }
    // However it came to be, `e` is the last item in the list.
    ENGINE_LIST_TAIL.store(e, Ordering::Release);
    // SAFETY: `e` is live.
    unsafe { (*e).next = ptr::null_mut() };
    1
}

/// `static int engine_list_remove(ENGINE *e)` — `:119-147`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`; the engine lock must be held.
unsafe fn engine_list_remove(e: *mut Engine) -> c_int {
    if e.is_null() {
        // SAFETY: `ENG_LIST_124` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_LIST_124) };
        return 0;
    }
    // Check that `e` is in the list.
    let mut iterator = ENGINE_LIST_HEAD.load(Ordering::Acquire);
    while !iterator.is_null() && iterator != e {
        // SAFETY: `iterator` is a live list member.
        iterator = unsafe { (*iterator).next };
    }
    if iterator.is_null() {
        // SAFETY: `ENG_LIST_132` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_LIST_132) };
        return 0;
    }
    // SAFETY: `e` is a live list member.
    unsafe {
        if !(*e).next.is_null() {
            (*(*e).next).prev = (*e).prev;
        }
        if !(*e).prev.is_null() {
            (*(*e).prev).next = (*e).next;
        }
        if ENGINE_LIST_HEAD.load(Ordering::Acquire) == e {
            ENGINE_LIST_HEAD.store((*e).next, Ordering::Release);
        }
        if ENGINE_LIST_TAIL.load(Ordering::Acquire) == e {
            ENGINE_LIST_TAIL.store((*e).prev, Ordering::Release);
        }
    }
    // SAFETY: `e` is live and this releases the list's own structural reference.
    unsafe { engine_free_util(e, 0) };
    1
}

/// `int engine_add_dynamic_id(ENGINE *e, ENGINE_DYNAMIC_ID dynamic_id, int not_locked)` —
/// `:150-200`.
///
/// Reached through [`engine_cpy`], which the `ENGINE_FLAGS_BY_ID_COPY` arm of [`ENGINE_by_id`]
/// calls. The dynamic-id *unlink* half, [`engine_remove_dynamic_id`], is live
/// (`engine_free_util` calls it).
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`. When `not_locked` is zero the caller holds the
/// engine lock; when non-zero this function takes and releases it.
#[allow(unpredictable_function_pointer_comparisons)] // the authority compares the ids it was given
pub(crate) unsafe fn engine_add_dynamic_id(
    e: *mut Engine,
    dynamic_id: Option<unsafe extern "C" fn()>,
    not_locked: c_int,
) -> c_int {
    if e.is_null() {
        return 0;
    }
    // SAFETY: `e` is live.
    let already = unsafe { (*e).dynamic_id };
    if already.is_none() && dynamic_id.is_none() {
        return 0;
    }
    if not_locked != 0 && !lock() {
        return 0;
    }
    if dynamic_id.is_some() {
        let mut iterator = ENGINE_DYN_LIST_HEAD.load(Ordering::Acquire);
        while !iterator.is_null() {
            // SAFETY: `iterator` is a live list member.
            if unsafe { (*iterator).dynamic_id } == dynamic_id {
                return dyn_err(not_locked);
            }
            // SAFETY: `iterator` is live.
            iterator = unsafe { (*iterator).next };
        }
        // SAFETY: `e` is live.
        if unsafe { (*e).dynamic_id }.is_some() {
            return dyn_err(not_locked);
        }
        // SAFETY: `e` is live.
        unsafe { (*e).dynamic_id = dynamic_id };
    }
    let head = ENGINE_DYN_LIST_HEAD.load(Ordering::Acquire);
    if head.is_null() {
        if !ENGINE_DYN_LIST_TAIL.load(Ordering::Acquire).is_null() {
            return dyn_err(not_locked);
        }
        ENGINE_DYN_LIST_HEAD.store(e, Ordering::Release);
        // SAFETY: `e` is live.
        unsafe { (*e).prev_dyn = ptr::null_mut() };
    } else {
        let tail = ENGINE_DYN_LIST_TAIL.load(Ordering::Acquire);
        let bad = tail.is_null() || {
            // SAFETY: `tail` is a live list member.
            unsafe { !(*tail).next_dyn.is_null() }
        };
        if bad {
            return dyn_err(not_locked);
        }
        // SAFETY: `tail` is live and `e` is live.
        unsafe {
            (*tail).next_dyn = e;
            (*e).prev_dyn = tail;
        }
    }
    ENGINE_DYN_LIST_TAIL.store(e, Ordering::Release);
    // SAFETY: `e` is live.
    unsafe { (*e).next_dyn = ptr::null_mut() };
    if not_locked != 0 {
        unlock();
    }
    1
}

/// The shared `err:` tail of [`engine_add_dynamic_id`], which returns without a value.
fn dyn_err(not_locked: c_int) -> c_int {
    if not_locked != 0 {
        unlock();
    }
    0
}

/// `void engine_remove_dynamic_id(ENGINE *e, int not_locked)` — `:203-226`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`. When `not_locked` is zero the caller holds the
/// engine lock; when non-zero this function takes and releases it.
pub(crate) unsafe fn engine_remove_dynamic_id(e: *mut Engine, not_locked: c_int) {
    if e.is_null() {
        return;
    }
    // SAFETY: `e` is live.
    if unsafe { (*e).dynamic_id }.is_none() {
        return;
    }
    if not_locked != 0 && !lock() {
        return;
    }
    // SAFETY: `e` is a live list member.
    unsafe {
        (*e).dynamic_id = None;
        if !(*e).next_dyn.is_null() {
            (*(*e).next_dyn).prev_dyn = (*e).prev_dyn;
        }
        if !(*e).prev_dyn.is_null() {
            (*(*e).prev_dyn).next_dyn = (*e).next_dyn;
        }
        if ENGINE_DYN_LIST_HEAD.load(Ordering::Acquire) == e {
            ENGINE_DYN_LIST_HEAD.store((*e).next_dyn, Ordering::Release);
        }
        if ENGINE_DYN_LIST_TAIL.load(Ordering::Acquire) == e {
            ENGINE_DYN_LIST_TAIL.store((*e).prev_dyn, Ordering::Release);
        }
    }
    if not_locked != 0 {
        unlock();
    }
}

/// `ENGINE *ENGINE_get_first(void)` — `crypto/engine/eng_list.c:229-254`.
#[no_mangle]
pub extern "C" fn ENGINE_get_first() -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        if !unsafe { run_engine_lock_init() } {
            // SAFETY: `ENG_LIST_235` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_235) };
            return ptr::null_mut();
        }
        if !lock() {
            return ptr::null_mut();
        }
        let ret = ENGINE_LIST_HEAD.load(Ordering::Acquire);
        if !ret.is_null() {
            let mut r: c_int = 0;
            // SAFETY: `ret` is a live list member and `struct_ref` its refcount.
            unsafe { up_ref(ptr::addr_of_mut!((*ret).struct_ref), &mut r) };
        }
        unlock();
        ret
    })
}

/// `ENGINE *ENGINE_get_last(void)` — `:256-281`.
#[no_mangle]
pub extern "C" fn ENGINE_get_last() -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        if !unsafe { run_engine_lock_init() } {
            // SAFETY: `ENG_LIST_262` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_262) };
            return ptr::null_mut();
        }
        if !lock() {
            return ptr::null_mut();
        }
        let ret = ENGINE_LIST_TAIL.load(Ordering::Acquire);
        if !ret.is_null() {
            let mut r: c_int = 0;
            // SAFETY: `ret` is a live list member and `struct_ref` its refcount.
            unsafe { up_ref(ptr::addr_of_mut!((*ret).struct_ref), &mut r) };
        }
        unlock();
        ret
    })
}

/// `ENGINE *ENGINE_get_next(ENGINE *e)` — `:284-309`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_next(e: *mut Engine) -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        if e.is_null() {
            // SAFETY: `ENG_LIST_288` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_288) };
            return ptr::null_mut();
        }
        if !lock() {
            return ptr::null_mut();
        }
        // SAFETY: `e` is a live list member.
        let ret = unsafe { (*e).next };
        if !ret.is_null() {
            let mut r: c_int = 0;
            // SAFETY: `ret` is a live list member and `struct_ref` its refcount.
            unsafe { up_ref(ptr::addr_of_mut!((*ret).struct_ref), &mut r) };
        }
        unlock();
        // Release the structural reference to the previous ENGINE.
        // SAFETY: `ENGINE_free` accepts a live ENGINE.
        unsafe { crate::engine::eng_lib::ENGINE_free(e) };
        ret
    })
}

/// `ENGINE *ENGINE_get_prev(ENGINE *e)` — `:311-336`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_prev(e: *mut Engine) -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        if e.is_null() {
            // SAFETY: `ENG_LIST_315` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_315) };
            return ptr::null_mut();
        }
        if !lock() {
            return ptr::null_mut();
        }
        // SAFETY: `e` is a live list member.
        let ret = unsafe { (*e).prev };
        if !ret.is_null() {
            let mut r: c_int = 0;
            // SAFETY: `ret` is a live list member and `struct_ref` its refcount.
            unsafe { up_ref(ptr::addr_of_mut!((*ret).struct_ref), &mut r) };
        }
        unlock();
        // SAFETY: `ENGINE_free` accepts a live ENGINE.
        unsafe { crate::engine::eng_lib::ENGINE_free(e) };
        ret
    })
}

/// `int ENGINE_add(ENGINE *e)` — `:339-358`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_add(e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            // SAFETY: `ENG_LIST_343` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_343) };
            return 0;
        }
        // SAFETY: `e` is live.
        let (id, name) = unsafe { ((*e).id, (*e).name) };
        if id.is_null() || name.is_null() {
            // SAFETY: `ENG_LIST_347` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_347) };
            return 0;
        }
        if !lock() {
            return 0;
        }
        let mut to_return = 1;
        // SAFETY: the lock is held and `e` is live.
        if unsafe { engine_list_add(e) } == 0 {
            // SAFETY: `ENG_LIST_353` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_353) };
            to_return = 0;
        }
        unlock();
        to_return
    })
}

/// `int ENGINE_remove(ENGINE *e)` — `:361-376`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_remove(e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            // SAFETY: `ENG_LIST_365` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_365) };
            return 0;
        }
        if !lock() {
            return 0;
        }
        let mut to_return = 1;
        // SAFETY: the lock is held and `e` is live.
        if unsafe { engine_list_remove(e) } == 0 {
            // SAFETY: `ENG_LIST_371` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_371) };
            to_return = 0;
        }
        unlock();
        to_return
    })
}

/// `static void engine_cpy(ENGINE *dest, const ENGINE *src)` — `:378-406`.
///
/// Called only from the `ENGINE_FLAGS_BY_ID_COPY` arm of [`ENGINE_by_id`].
///
/// # Safety
/// Both pointers must be live `ENGINE`s.
unsafe fn engine_cpy(dest: *mut Engine, src: *const Engine) {
    // SAFETY: both are live per the caller's contract.
    unsafe {
        (*dest).id = (*src).id;
        (*dest).name = (*src).name;
        (*dest).rsa_meth = (*src).rsa_meth;
        (*dest).dsa_meth = (*src).dsa_meth;
        (*dest).dh_meth = (*src).dh_meth;
        (*dest).ec_meth = (*src).ec_meth;
        (*dest).rand_meth = (*src).rand_meth;
        (*dest).ciphers = (*src).ciphers;
        (*dest).digests = (*src).digests;
        (*dest).pkey_meths = (*src).pkey_meths;
        (*dest).destroy = (*src).destroy;
        (*dest).init = (*src).init;
        (*dest).finish = (*src).finish;
        (*dest).ctrl = (*src).ctrl;
        (*dest).load_privkey = (*src).load_privkey;
        (*dest).load_pubkey = (*src).load_pubkey;
        (*dest).cmd_defns = (*src).cmd_defns;
        (*dest).flags = (*src).flags;
        (*dest).dynamic_id = (*src).dynamic_id;
    }
    // SAFETY: `dest` is live; the dynamic-id list is the engine lock's.
    unsafe { engine_add_dynamic_id(dest, None, 0) };
}

/// `int ENGINE_up_ref(ENGINE *e)` — `crypto/engine/eng_list.c:475-484`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_up_ref(e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            // SAFETY: `ENG_LIST_479` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_479) };
            return 0;
        }
        let mut i: c_int = 0;
        // SAFETY: `e` is live and `struct_ref` is its refcount.
        unsafe { up_ref(ptr::addr_of_mut!((*e).struct_ref), &mut i) };
        1
    })
}

/// `ENGINE *ENGINE_by_id(const char *id)` — `crypto/engine/eng_list.c:408-473`.
///
/// Loads the built-ins, then walks the registry for `id`. A hit returns a structural
/// reference — a fresh copy through [`engine_cpy`] when the engine carries
/// [`ENGINE_FLAGS_BY_ID_COPY`], otherwise an increment of the registered object. A miss that
/// is not `"dynamic"` recurses into the dynamic engine; with no dynamic engine registered
/// that recursion answers NULL and this takes the authority's own `goto notfound`
/// (`ENGINE_R_NO_SUCH_ENGINE`, `id=%s`). See the module header for why the fallback cannot
/// load a shared object in this crate.
///
/// # Safety
/// `id` must be NULL or NUL-terminated.
#[no_mangle]
#[allow(unpredictable_function_pointer_comparisons)] // the recursion compares the ids it is given
pub unsafe extern "C" fn ENGINE_by_id(id: *const c_char) -> *mut Engine {
    guard_ffi(ptr::null_mut(), || {
        if id.is_null() {
            // SAFETY: `ENG_LIST_413` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_413) };
            return ptr::null_mut();
        }
        // The authority's first act, on every call: load the built-in engines.
        // SAFETY: the loader's contract is the caller's.
        unsafe { crate::engine::eng_all::ENGINE_load_builtin_engines() };

        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        if !unsafe { run_engine_lock_init() } {
            // SAFETY: `ENG_LIST_420` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_LIST_420) };
            return ptr::null_mut();
        }
        if !lock() {
            return ptr::null_mut();
        }
        let mut iterator = ENGINE_LIST_HEAD.load(Ordering::Acquire);
        // SAFETY: `id` is NUL-terminated per the contract and `iterator` is a live list member.
        while !iterator.is_null() && unsafe { strcmp(id, (*iterator).id) != 0 } {
            // SAFETY: `iterator` is a live list member.
            iterator = unsafe { (*iterator).next };
        }
        if !iterator.is_null() {
            // A structural reference is what must be returned. An `ENGINE` that returns copies
            // gets a duplicate; every other one has its refcount incremented.
            // SAFETY: `iterator` is a live list member.
            if unsafe { (*iterator).flags } & ENGINE_FLAGS_BY_ID_COPY != 0 {
                let cp = crate::engine::eng_lib::ENGINE_new();
                if cp.is_null() {
                    iterator = ptr::null_mut();
                } else {
                    // SAFETY: `cp` is the fresh ENGINE and `iterator` a live registered one.
                    unsafe { engine_cpy(cp, iterator) };
                    iterator = cp;
                }
            } else {
                let mut r: c_int = 0;
                // SAFETY: `iterator` is a live list member and `struct_ref` its refcount.
                unsafe { up_ref(ptr::addr_of_mut!((*iterator).struct_ref), &mut r) };
            }
        }
        unlock();
        if !iterator.is_null() {
            return iterator;
        }
        // Prevent infinite recursion if the id being looked up *is* the dynamic engine.
        // SAFETY: the literal is NUL-terminated and `id` is NUL-terminated per the contract.
        if unsafe { strcmp(id, c"dynamic".as_ptr()) } != 0 {
            // SAFETY: the literal is NUL-terminated.
            let mut load_dir: *const c_char =
                unsafe { ossl_safe_getenv(c"OPENSSL_ENGINES".as_ptr()) };
            if load_dir.is_null() {
                load_dir = ossl_get_enginesdir();
            }
            // SAFETY: the literal is NUL-terminated.
            let dyn_engine = unsafe { ENGINE_by_id(c"dynamic".as_ptr()) };
            let mut loaded = !dyn_engine.is_null();
            if loaded {
                // SAFETY: `dyn_engine` is live; the command names are static literals and the
                // argument strings are NUL-terminated (or NULL for `LOAD`, the authority's
                // `NO_INPUT` convention).
                unsafe {
                    loaded = crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string(
                        dyn_engine,
                        c"ID".as_ptr(),
                        id,
                        0,
                    ) != 0
                        && crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string(
                            dyn_engine,
                            c"DIR_LOAD".as_ptr(),
                            c"2".as_ptr(),
                            0,
                        ) != 0
                        && crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string(
                            dyn_engine,
                            c"DIR_ADD".as_ptr(),
                            load_dir,
                            0,
                        ) != 0
                        && crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string(
                            dyn_engine,
                            c"LIST_ADD".as_ptr(),
                            c"1".as_ptr(),
                            0,
                        ) != 0
                        && crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string(
                            dyn_engine,
                            c"LOAD".as_ptr(),
                            ptr::null::<c_char>(),
                            0,
                        ) != 0;
                }
            }
            if loaded {
                return dyn_engine;
            }
            // notfound: release the dynamic engine (NULL safe) and raise the id.
            // SAFETY: `dyn_engine` is NULL or a live structural reference this call owns.
            unsafe { crate::engine::eng_lib::ENGINE_free(dyn_engine) };
            let mut msg: Vec<u8> = b"id=".to_vec();
            // SAFETY: `id` is non-NULL and NUL-terminated per the contract.
            msg.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(id) }.to_bytes());
            msg.push(0);
            // SAFETY: `ENG_LIST_470` is a generated constant whose strings are static, and
            // `msg` is NUL-terminated.
            unsafe { raise_site_data(&ENG_LIST_470, msg.as_ptr().cast::<c_char>()) };
            return ptr::null_mut();
        }
        // notfound from the non-`dynamic` arm's own recursion (`iterator` is NULL here).
        // SAFETY: `ENGINE_free` accepts NULL.
        unsafe { crate::engine::eng_lib::ENGINE_free(iterator) };
        let mut msg: Vec<u8> = b"id=".to_vec();
        // SAFETY: `id` is non-NULL and NUL-terminated per the contract.
        msg.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(id) }.to_bytes());
        msg.push(0);
        // SAFETY: `ENG_LIST_470` is a generated constant whose strings are static, and `msg`
        // is NUL-terminated.
        unsafe { raise_site_data(&ENG_LIST_470, msg.as_ptr().cast::<c_char>()) };
        ptr::null_mut()
    })
}
