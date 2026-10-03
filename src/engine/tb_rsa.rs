//! Phase 13.2 — `crypto/engine/tb_rsa.c`: the `RSA_METHOD` implementation table.
//!
//! One of the four legacy method tables whose shape is identical: a single synthetic NID
//! (`static const int dummy_nid = 1`, `:16`), the engine's `rsa_meth` registered under it,
//! and `ENGINE_get_default_RSA` selecting that one key. Every function lands; nothing is
//! withheld.
//!
//! ## The method object is another stratum's
//!
//! `RSA_METHOD` is Phase 8's type and this table never dereferences one: the field is an
//! opaque `*const c_void` in `eng_lib.rs`'s layout, and `ENGINE_get_RSA`/`ENGINE_set_RSA`
//! are a field read and a field write. The court's observable is therefore the pointer the
//! engine carries, not any behaviour of the method.
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
const FILE: *const c_char = c"crypto/engine/tb_rsa.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:61`).
const LINE_SELECT: c_int = 61;

/// `static ENGINE_TABLE *rsa_table = NULL` (`:15`).
static RSA_TABLE: AtomicPtr<OpenSslLhash> = AtomicPtr::new(ptr::null_mut());

/// `static const int dummy_nid = 1` (`:16`).
static DUMMY_NID: c_int = 1;

/// The `ENGINE_TABLE **` the table helpers take.
fn rsa_table_slot() -> *mut *mut OpenSslLhash {
    core::ptr::addr_of!(RSA_TABLE) as *mut *mut OpenSslLhash
}

/// `void ENGINE_unregister_RSA(ENGINE *e)` — `crypto/engine/tb_rsa.c:18-21`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_RSA(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(rsa_table_slot(), e) };
}

/// `static void engine_unregister_all_RSA(void)` — `:23-26`.
unsafe extern "C" fn engine_unregister_all_rsa() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(rsa_table_slot()) };
}

/// `int ENGINE_register_RSA(ENGINE *e)` — `:28-35`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_RSA(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).rsa_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            rsa_table_slot(),
            Some(engine_unregister_all_rsa),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            0,
        )
    }
}

/// `void ENGINE_register_all_RSA(void)` — `:37-43`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_RSA() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_RSA(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_RSA(ENGINE *e)` — `:45-52`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_RSA(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).rsa_meth }.is_null() {
        return 1;
    }
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is one int.
    unsafe {
        engine_table_register(
            rsa_table_slot(),
            Some(engine_unregister_all_rsa),
            e,
            ptr::addr_of!(DUMMY_NID),
            1,
            1,
        )
    }
}

/// `ENGINE *ENGINE_get_default_RSA(void)` — `:59-63`.
#[no_mangle]
pub extern "C" fn ENGINE_get_default_RSA() -> *mut Engine {
    // SAFETY: the table slot is this module's static; `DUMMY_NID` is the one key.
    unsafe { ossl_engine_table_select(rsa_table_slot(), DUMMY_NID, FILE, LINE_SELECT) }
}

/// `const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e)` — `:66-69`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_RSA(e: *const Engine) -> *const c_void {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).rsa_meth }
}

/// `int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth)` — `:72-76`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_RSA(e: *mut Engine, rsa_meth: *const c_void) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).rsa_meth = rsa_meth };
    1
}
