//! Phase 13.2 — `crypto/engine/tb_cipher.c`: the cipher implementation table.
//!
//! The sibling of `tb_digest.rs`, transcribed whole. The table is the one
//! `ENGINE_get_cipher_engine` selects a functional reference from, once
//! `ENGINE_register_ciphers`/`ENGINE_set_default_ciphers` have populated it from an
//! engine's `ciphers` callback. Every function of this unit lands; nothing is withheld.
//!
//! ## The callback is the observable, not the table
//!
//! Unlike the digest table, nothing on this stratum's call graph selects a cipher through
//! this table (the legacy `EVP_CIPHER` statics are 13.6's), so `ENGINE_get_cipher` and
//! `ENGINE_get_cipher_engine` land because their closure is complete — an opaque
//! `EVP_CIPHER *` and the table helpers — rather than because a caller reaches them. The
//! court drives them over a fixed in-process callback, which is what makes a
//! transcription that returns a method the authority also returns at least observable.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::engine::eng_lib::{Engine, EngineCiphersPtr};
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_register, engine_table_unregister, ossl_engine_table_select,
};
use crate::runtime::err::err_sites::TB_CIPHER_78;
use crate::runtime::err::raise_site;
use crate::runtime::lhash::OpenSslLhash;

/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_cipher.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:68`).
const LINE_SELECT: c_int = 68;

/// `static ENGINE_TABLE *cipher_table = NULL` (`:15`).
static CIPHER_TABLE: AtomicPtr<OpenSslLhash> = AtomicPtr::new(ptr::null_mut());

/// The `ENGINE_TABLE **` the table helpers take.
fn cipher_table_slot() -> *mut *mut OpenSslLhash {
    core::ptr::addr_of!(CIPHER_TABLE) as *mut *mut OpenSslLhash
}

/// `void ENGINE_unregister_ciphers(ENGINE *e)` — `crypto/engine/tb_cipher.c:17-20`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_ciphers(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(cipher_table_slot(), e) };
}

/// `static void engine_unregister_all_ciphers(void)` — `:22-25`.
unsafe extern "C" fn engine_unregister_all_ciphers() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(cipher_table_slot()) };
}

/// `int ENGINE_register_ciphers(ENGINE *e)` — `:27-38`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_ciphers(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).ciphers }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `ciphers` callback is the caller's.
        let num_nids = unsafe {
            match (*e).ciphers {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    cipher_table_slot(),
                    Some(engine_unregister_all_ciphers),
                    e,
                    nids,
                    num_nids,
                    0,
                )
            };
        }
    }
    1
}

/// `void ENGINE_register_all_ciphers(void)` — `:40-46`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_ciphers() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_ciphers(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_ciphers(ENGINE *e)` — `:48-59`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_ciphers(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).ciphers }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `ciphers` callback is the caller's.
        let num_nids = unsafe {
            match (*e).ciphers {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    cipher_table_slot(),
                    Some(engine_unregister_all_ciphers),
                    e,
                    nids,
                    num_nids,
                    1,
                )
            };
        }
    }
    1
}

/// `ENGINE *ENGINE_get_cipher_engine(int nid)` — `:66-70`.
#[no_mangle]
pub extern "C" fn ENGINE_get_cipher_engine(nid: c_int) -> *mut Engine {
    // SAFETY: the table slot is this module's static; `FILE`/`LINE_SELECT` are the
    // authority's coordinate (used only by the empty trace calls).
    unsafe { ossl_engine_table_select(cipher_table_slot(), nid, FILE, LINE_SELECT) }
}

/// `const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid)` — `:73-82`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_cipher(e: *mut Engine, nid: c_int) -> *const c_void {
    let mut ret: *const c_void = ptr::null();
    // SAFETY: `e` is the caller's engine.
    let f = unsafe { ENGINE_get_ciphers(e) };
    let ok = match f {
        // SAFETY: `f` is the caller's callback; `ret` is a writable slot.
        Some(f) => unsafe { f(e, ptr::addr_of_mut!(ret), ptr::null_mut(), nid) },
        None => 0,
    };
    if ok == 0 {
        // SAFETY: `TB_CIPHER_78` is a generated constant whose strings are static.
        unsafe { raise_site(&TB_CIPHER_78) };
        return ptr::null();
    }
    ret
}

/// `ENGINE_CIPHERS_PTR ENGINE_get_ciphers(const ENGINE *e)` — `:85-88`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_ciphers(e: *const Engine) -> Option<EngineCiphersPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).ciphers }
}

/// `int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f)` — `:91-95`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_ciphers(e: *mut Engine, f: Option<EngineCiphersPtr>) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).ciphers = f };
    1
}
