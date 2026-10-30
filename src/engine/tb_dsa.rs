//! Phase 13.2 — `crypto/engine/tb_dsa.c`: the `DSA_METHOD` implementation table.
//!
//! The DSA sibling of `tb_rsa.c`, identical in shape: a single synthetic NID (`static const
//! int dummy_nid = 1`, `:16`), the engine's `dsa_meth` registered under it, and
//! `ENGINE_get_default_DSA` selecting that one key. Every function lands; nothing is
//! withheld.
//!
//! ## The method object is another stratum's
//!
//! `DSA_METHOD` is Phase 8's type and this table never dereferences one: the field is an
//! opaque `*const c_void` in `eng_lib.rs`'s layout. The court's observable is the pointer
//! the engine carries, not any behaviour of the method.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::engine::eng_lib::Engine;
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_register, engine_table_unregister, ossl_engine_table_select,
    EngineTableSlot,
};
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_dsa.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:61`).
const LINE_SELECT: c_int = 61;

/// `static ENGINE_TABLE *dsa_table = NULL` (`:15`).
static DSA_TABLE: EngineTableSlot = EngineTableSlot::new();

/// `static const int dummy_nid = 1` (`:16`).
static DUMMY_NID: c_int = 1;

/// The typed `ENGINE_TABLE *` slot the table helpers take.
pub(crate) fn dsa_table_slot() -> &'static EngineTableSlot {
    &DSA_TABLE
}

/// `void ENGINE_unregister_DSA(ENGINE *e)` — `crypto/engine/tb_dsa.c:18-21`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_DSA(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(dsa_table_slot(), e) };
}

/// `static void engine_unregister_all_DSA(void)` — `:23-26`.
///
/// # Safety
/// Invoked as a cleanup-stack callback after an engine was registered through the public
/// engine API. That path (`ENGINE_new` / `ENGINE_by_id` / `ENGINE_get_first`) has already
/// initialised the engine lock, and the lock is not held when the callback runs;
/// [`engine_table_cleanup`] takes it. If the lock were uninitialised, the cleanup would
/// return before releasing the table (a documented no-op/leak, not UB).
unsafe extern "C" fn engine_unregister_all_dsa() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(dsa_table_slot()) };
}

/// `int ENGINE_register_DSA(ENGINE *e)` — `:28-35`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_DSA(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).dsa_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            dsa_table_slot(),
            Some(engine_unregister_all_dsa),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            0,
        )
    }
}

/// `void ENGINE_register_all_DSA(void)` — `:37-43`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_DSA() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_DSA(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_DSA(ENGINE *e)` — `:45-52`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_DSA(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).dsa_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            dsa_table_slot(),
            Some(engine_unregister_all_dsa),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            1,
        )
    }
}

/// `ENGINE *ENGINE_get_default_DSA(void)` — `:59-63`.
#[no_mangle]
pub extern "C" fn ENGINE_get_default_DSA() -> *mut Engine {
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is the one key.
    unsafe { ossl_engine_table_select(dsa_table_slot(), DUMMY_NID, FILE, LINE_SELECT) }
}

/// `const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e)` — `:66-69`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_DSA(e: *const Engine) -> *const c_void {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).dsa_meth }
}

/// `int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth)` — `:72-76`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_DSA(e: *mut Engine, dsa_meth: *const c_void) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).dsa_meth = dsa_meth };
    1
}
