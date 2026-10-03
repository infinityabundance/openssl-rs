//! Phase 13.2 — `crypto/engine/tb_dh.c`: the `DH_METHOD` implementation table.
//!
//! The DH sibling of `tb_rsa.c`, identical in shape: a single synthetic NID (`static const
//! int dummy_nid = 1`, `:16`), the engine's `dh_meth` registered under it, and
//! `ENGINE_get_default_DH` selecting that one key. Every function lands; nothing is
//! withheld.
//!
//! ## The method object is another stratum's
//!
//! `DH_METHOD` is Phase 8's type and this table never dereferences one: the field is an
//! opaque `*const c_void` in `eng_lib.rs`'s layout. The court's observable is the pointer
//! the engine carries, not any behaviour of the method.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::engine::eng_lib::Engine;
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_register, engine_table_unregister, ossl_engine_table_select,
};
use crate::runtime::lhash::OpenSslLhash;

/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_dh.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:61`).
const LINE_SELECT: c_int = 61;

/// `static ENGINE_TABLE *dh_table = NULL` (`:15`).
static DH_TABLE: AtomicPtr<OpenSslLhash> = AtomicPtr::new(ptr::null_mut());

/// `static const int dummy_nid = 1` (`:16`).
static DUMMY_NID: c_int = 1;

/// The `ENGINE_TABLE **` the table helpers take.
fn dh_table_slot() -> *mut *mut OpenSslLhash {
    core::ptr::addr_of!(DH_TABLE) as *mut *mut OpenSslLhash
}

/// `void ENGINE_unregister_DH(ENGINE *e)` — `crypto/engine/tb_dh.c:18-21`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_DH(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(dh_table_slot(), e) };
}

/// `static void engine_unregister_all_DH(void)` — `:23-26`.
unsafe extern "C" fn engine_unregister_all_dh() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(dh_table_slot()) };
}

/// `int ENGINE_register_DH(ENGINE *e)` — `:28-35`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_DH(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).dh_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            dh_table_slot(),
            Some(engine_unregister_all_dh),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            0,
        )
    }
}

/// `void ENGINE_register_all_DH(void)` — `:37-43`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_DH() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_DH(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_DH(ENGINE *e)` — `:45-52`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_DH(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).dh_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            dh_table_slot(),
            Some(engine_unregister_all_dh),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            1,
        )
    }
}

/// `ENGINE *ENGINE_get_default_DH(void)` — `:59-63`.
#[no_mangle]
pub extern "C" fn ENGINE_get_default_DH() -> *mut Engine {
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is the one key.
    unsafe { ossl_engine_table_select(dh_table_slot(), DUMMY_NID, FILE, LINE_SELECT) }
}

/// `const DH_METHOD *ENGINE_get_DH(const ENGINE *e)` — `:66-69`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_DH(e: *const Engine) -> *const c_void {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).dh_meth }
}

/// `int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth)` — `:72-76`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_DH(e: *mut Engine, dh_meth: *const c_void) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).dh_meth = dh_meth };
    1
}
