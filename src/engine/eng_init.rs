//! Phase 10.9 — `crypto/engine/eng_init.c`: the functional reference pair.
//!
//! This is the module `X509_digest` reaches through `ossl_asn1_item_digest_ex`
//! (`crypto/asn1/a_digest.c:71`): the engine table hands back a functional reference, and
//! `ENGINE_finish` is how it is released. Every function here lands; nothing is withheld.
//!
//! ## What a functional reference is
//!
//! An `ENGINE` carries two counts. `struct_ref` keeps the structure itself alive, and
//! `funct_ref` counts *usable* references. Taking a functional reference up's the
//! structural count (so the object cannot be freed underneath a user) and calls the
//! caller's `init` hook the first time only; releasing it calls the `finish` hook when the
//! functional count reaches zero and then drops the structural reference, which is what
//! makes `ENGINE_finish` also a `ENGINE_free`.
//!
//! ## The two arms a plausible reading gets wrong
//!
//! * `engine_unlocked_finish` **decrements `funct_ref` before** calling the destructor, so
//!   `finish` observes a zero count. A version that decremented afterwards could let two
//!   threads together take 2 to 0 without either calling `finish`, which the authority's
//!   own comment (`:56-63`) names.
//! * When it calls the handler it **releases the engine lock first** and re-acquires it
//!   after (`:67-72`), so a `finish` hook may take the lock itself. A `not_locked` caller
//!   (`engine_table_register`'s `engine_unlocked_finish(pile->funct, 0)`) skips both.
//!
//! ## `ENGINE_REF_PRINT` is empty on this build
//!
//! The authority's `ENGINE_REF_PRINT` is `OSSL_TRACE6(ENGINE_REF_COUNT, ...)`, and the
//! admitted build configures `no-trace`, so `OSSL_TRACE*` expands to a statement that does
//! nothing (`crypto/trace.h` under `OPENSSL_NO_TRACE`). The calls below are therefore
//! omitted rather than stubbed, and the count bookkeeping they would have printed is the
//! real content.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::engine::eng_lib::{
    engine_free_util, global_engine_lock, run_engine_lock_init, up_ref, Engine,
};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{ENG_INIT_117, ENG_INIT_79, ENG_INIT_90, ENG_INIT_95};
use crate::runtime::err::raise_site;
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// `int engine_unlocked_init(ENGINE *e)` — `crypto/engine/eng_init.c:20-46`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`; the engine lock must be held by the caller.
pub(crate) unsafe fn engine_unlocked_init(e: *mut Engine) -> c_int {
    let mut to_return: c_int = 1;
    // SAFETY: `e` is live per the contract.
    if unsafe { (*e).funct_ref } == 0 {
        // SAFETY: the pointer is live per the caller's contract.
        if let Some(init) = unsafe { (*e).init } {
            // SAFETY: the hook is the caller's and is called with its own ENGINE.
            to_return = unsafe { init(e) };
        }
    }
    if to_return != 0 {
        let mut r: c_int = 0;
        // SAFETY: `e` is live and `struct_ref` is its refcount.
        unsafe { up_ref(ptr::addr_of_mut!((*e).struct_ref), &mut r) };
        // `CRYPTO_UP_REF` cannot fail on the fallback arm, but the authority still guards
        // the count's increment on the hook having succeeded, so this mirrors the shape.
        // SAFETY: `e` is live.
        unsafe { (*e).funct_ref += 1 };
    }
    to_return
}

/// `int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers)` — `:52-83`.
///
/// # Safety
/// `e` must be a live `ENGINE`; the engine lock must be held when `unlock_for_handlers` is
/// zero, and is released and re-acquired when it is non-zero.
pub(crate) unsafe fn engine_unlocked_finish(e: *mut Engine, unlock_for_handlers: c_int) -> c_int {
    let mut to_return: c_int = 1;
    // Reduce the functional count here, before the handler, so a terminating call can
    // release the lock without a race — the authority's own ordering.
    // SAFETY: `e` is live.
    unsafe { (*e).funct_ref -= 1 };
    // SAFETY: `e` is live.
    if unsafe { (*e).funct_ref } == 0 {
        // SAFETY: the pointer is live per the caller's contract.
        if let Some(finish) = unsafe { (*e).finish } {
            if unlock_for_handlers != 0 {
                // SAFETY: the caller holds the lock; it must be the engine lock.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            }
            // SAFETY: the hook is the caller's and is called with its own ENGINE.
            to_return = unsafe { finish(e) };
            if unlock_for_handlers != 0 {
                // SAFETY: re-acquiring the same lock the authority dropped.
                if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
                    return 0;
                }
            }
            if to_return == 0 {
                return 0;
            }
        }
    }
    // Release the structural reference too. `not_locked = 0`: the lock is held.
    // SAFETY: `e` is live and this is a functional release, so the caller holds a reference.
    if unsafe { engine_free_util(e, 0) } == 0 {
        // SAFETY: `ENG_INIT_79` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_INIT_79) };
        return 0;
    }
    to_return
}

/// `int ENGINE_init(ENGINE *e)` — `crypto/engine/eng_init.c:86-103`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_init(e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            // SAFETY: `ENG_INIT_90` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_INIT_90) };
            return 0;
        }
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        if !unsafe { run_engine_lock_init() } {
            // SAFETY: `ENG_INIT_95` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_INIT_95) };
            return 0;
        }
        // SAFETY: the lock exists after the once.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return 0;
        }
        // SAFETY: the lock is held and `e` is live.
        let ret = unsafe { engine_unlocked_init(e) };
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        ret
    })
}

/// `int ENGINE_finish(ENGINE *e)` — `crypto/engine/eng_init.c:106-121`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_finish(e: *mut Engine) -> c_int {
    guard_ffi(1, || {
        if e.is_null() {
            return 1;
        }
        // SAFETY: the lock is the engine lock; it exists whenever an engine does, because
        // every constructor runs the once first.
        // SAFETY: the lock is the engine lock, created by the run-once.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return 0;
        }
        // SAFETY: the lock is held and `e` is live.
        let to_return = unsafe { engine_unlocked_finish(e, 1) };
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        if to_return == 0 {
            // SAFETY: `ENG_INIT_117` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_INIT_117) };
            return 0;
        }
        to_return
    })
}
