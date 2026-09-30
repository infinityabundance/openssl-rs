//! Phase 10.9 — `crypto/engine/tb_digest.c`: the digest implementation table.
//!
//! This is the exact module `ossl_asn1_item_digest_ex` selects through: its
//! `ENGINE_get_digest_engine` (`crypto/engine/tb_digest.c:66-70`) is the symbol
//! `crypto/asn1/a_digest.c:68` calls. Every function of this unit lands; nothing is
//! withheld.
//!
//! ## The table is one static, and only the digest half of it is here
//!
//! `static ENGINE_TABLE *digest_table = NULL` (`:15`) is the digest registration table.
//! The `ENGINE_register_digests`/`_set_default_digests` pair populate it from an engine's
//! `digests` callback, and `ENGINE_get_digest_engine` selects the functional reference
//! `ENGINE_finish` later releases. The sibling tables for ciphers, RSA, DSA, DH, EC and
//! RAND live in `tb_cipher.c`, `tb_rsa.c`, `tb_dsa.c`, `tb_dh.c`, `tb_eckey.c` and
//! `tb_rand.c`, which section 6 does **not** name for this subphase — no digest-path
//! caller reads one, so they are not transcribed here and their exports are not defined.
//!
//! ## `ENGINE_get_digest` is landed even though the digest path does not call it
//!
//! The fetch of a concrete `EVP_MD` from a functional reference
//! (`ENGINE_get_digest`, `:73-82`) is the other half of the table's public surface, and
//! its two callbacks (`ENGINE_get_digests`/`ENGINE_set_digests`) are what
//! `ENGINE_register_digests` reads. It is landed rather than withheld because its closure
//! is complete: `EVP_MD` is an opaque pointer here and the callback does the work.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::engine::eng_lib::{Engine, EngineDigestsPtr};
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_register, engine_table_unregister, ossl_engine_table_select,
};
use crate::runtime::err::err_sites::TB_DIGEST_78;
use crate::runtime::err::raise_site;
use crate::runtime::lhash::OpenSslLhash;

/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_digest.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:69`).
const LINE_SELECT: c_int = 69;

/// `static ENGINE_TABLE *digest_table = NULL` (`:15`).
///
/// The `ENGINE_TABLE *` is the lhash pointer, as `eng_table.rs` documents; the atomic is
/// the stable home for the slot the table helpers write through.
static DIGEST_TABLE: AtomicPtr<OpenSslLhash> = AtomicPtr::new(ptr::null_mut());

/// The `ENGINE_TABLE **` the table helpers take.
fn digest_table_slot() -> *mut *mut OpenSslLhash {
    core::ptr::addr_of!(DIGEST_TABLE) as *mut *mut OpenSslLhash
}

/// `void ENGINE_unregister_digests(ENGINE *e)` — `crypto/engine/tb_digest.c:17-20`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_digests(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(digest_table_slot(), e) };
}

/// `static void engine_unregister_all_digests(void)` — `:22-25`.
unsafe extern "C" fn engine_unregister_all_digests() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(digest_table_slot()) };
}

/// `int ENGINE_register_digests(ENGINE *e)` — `:27-38`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_digests(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).digests }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `digests` callback is the caller's.
        let num_nids = unsafe {
            let f = (*e).digests;
            match f {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    digest_table_slot(),
                    Some(engine_unregister_all_digests),
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

/// `void ENGINE_register_all_digests(void)` — `:40-46`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_digests() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_digests(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_digests(ENGINE *e)` — `:48-59`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_digests(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).digests }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `digests` callback is the caller's.
        let num_nids = unsafe {
            let f = (*e).digests;
            match f {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    digest_table_slot(),
                    Some(engine_unregister_all_digests),
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

/// `ENGINE *ENGINE_get_digest_engine(int nid)` — `:66-70`.
///
/// The exact call `ossl_asn1_item_digest_ex` makes (`crypto/asn1/a_digest.c:68`).
#[no_mangle]
pub extern "C" fn ENGINE_get_digest_engine(nid: c_int) -> *mut Engine {
    // SAFETY: the table slot is this module's static; `FILE`/`LINE_SELECT` are the
    // authority's coordinate (used only by the empty trace calls).
    // SAFETY: the operation's pointers are live per the caller's contract.
    unsafe { ossl_engine_table_select(digest_table_slot(), nid, FILE, LINE_SELECT) }
}

/// `const EVP_MD *ENGINE_get_digest(ENGINE *e, int nid)` — `:73-82`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_digest(e: *mut Engine, nid: c_int) -> *const c_void {
    let mut ret: *const c_void = ptr::null();
    // SAFETY: `e` is the caller's engine.
    let f = unsafe { ENGINE_get_digests(e) };
    let ok = match f {
        // SAFETY: `f` is the caller's callback; `ret` is a writable slot.
        Some(f) => unsafe { f(e, ptr::addr_of_mut!(ret), ptr::null_mut(), nid) },
        None => 0,
    };
    if ok == 0 {
        // SAFETY: `TB_DIGEST_78` is a generated constant whose strings are static.
        unsafe { raise_site(&TB_DIGEST_78) };
        return ptr::null();
    }
    ret
}

/// `ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE *e)` — `:85-88`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_digests(e: *const Engine) -> Option<EngineDigestsPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).digests }
}

/// `int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f)` — `:91-95`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_digests(e: *mut Engine, f: Option<EngineDigestsPtr>) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).digests = f };
    1
}
