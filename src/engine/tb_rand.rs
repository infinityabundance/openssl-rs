//! Phase 13.2 — `crypto/engine/tb_rand.c`: the `RAND_METHOD` implementation table.
//!
//! The RAND table keys on a single synthetic NID. The authority declares `static const int
//! dummy_nid = 1` (`:16`) and registers the engine's `rand_meth` under it whether or not
//! the engine's id would otherwise be addressable; `ENGINE_get_default_RAND` selects that
//! one NID. Every function of this unit lands; nothing is withheld.
//!
//! ## The table cannot raise
//!
//! `ENGINE_get_RAND` is a bare field read and the register/unregister arms return `1`
//! whether or not the engine carries a method, so there is no `ERR_raise` coordinate in
//! this unit — which is why `gen_err_raise_sites.py` does not list it.
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
const FILE: *const c_char = c"crypto/engine/tb_rand.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:61`).
const LINE_SELECT: c_int = 61;

/// `static ENGINE_TABLE *rand_table = NULL` (`:15`).
static RAND_TABLE: EngineTableSlot = EngineTableSlot::new();

/// `static const int dummy_nid = 1` (`:16`).
static DUMMY_NID: c_int = 1;

/// The typed `ENGINE_TABLE *` slot the table helpers take.
pub(crate) fn rand_table_slot() -> &'static EngineTableSlot {
    &RAND_TABLE
}

/// `void ENGINE_unregister_RAND(ENGINE *e)` — `crypto/engine/tb_rand.c:18-21`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_RAND(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(rand_table_slot(), e) };
}

/// `static void engine_unregister_all_RAND(void)` — `:23-26`.
///
/// # Safety
/// Invoked as a cleanup-stack callback after an engine was registered through the public
/// engine API. That path (`ENGINE_new` / `ENGINE_by_id` / `ENGINE_get_first`) has already
/// initialised the engine lock, and the lock is not held when the callback runs;
/// [`engine_table_cleanup`] takes it. If the lock were uninitialised, the cleanup would
/// return before releasing the table (a documented no-op/leak, not UB).
unsafe extern "C" fn engine_unregister_all_rand() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(rand_table_slot()) };
}

/// `int ENGINE_register_RAND(ENGINE *e)` — `:28-35`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_RAND(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).rand_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            rand_table_slot(),
            Some(engine_unregister_all_rand),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            0,
        )
    }
}

/// `void ENGINE_register_all_RAND(void)` — `:37-43`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_RAND() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_RAND(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_RAND(ENGINE *e)` — `:45-52`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_RAND(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).rand_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            rand_table_slot(),
            Some(engine_unregister_all_rand),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            1,
        )
    }
}

/// `ENGINE *ENGINE_get_default_RAND(void)` — `:59-63`.
#[no_mangle]
pub extern "C" fn ENGINE_get_default_RAND() -> *mut Engine {
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is the one key.
    unsafe { ossl_engine_table_select(rand_table_slot(), DUMMY_NID, FILE, LINE_SELECT) }
}

/// `const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e)` — `:66-69`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_RAND(e: *const Engine) -> *const c_void {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).rand_meth }
}

/// `int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth)` — `:72-76`.
///
/// # Safety
/// `e` must be a non-NULL pointer to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_RAND(e: *mut Engine, rand_meth: *const c_void) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).rand_meth = rand_meth };
    1
}
