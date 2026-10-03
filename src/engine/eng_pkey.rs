//! Phase 13.2 — `crypto/engine/eng_pkey.c`: the key-loader binding surface.
//!
//! Three setter/getter pairs bind an engine's private-key, public-key and SSL
//! client-certificate loader onto its structure, and three exported entry points drive them:
//! `ENGINE_load_private_key` (`:56-83`), `ENGINE_load_public_key` (`:85-112`) and
//! `ENGINE_load_ssl_client_cert` (`:114-138`). Every function of this unit lands; nothing is
//! withheld.
//!
//! ## The two refusal coordinates are the observable
//!
//! Each entry point checks `e == NULL` (`ENGINE_R`/`ERR_R_PASSED_NULL_PARAMETER`), then
//! `e->funct_ref == 0` (`ENGINE_R_NOT_INITIALISED`, under the engine lock), then the
//! presence of the loader (`ENGINE_R_NO_LOAD_FUNCTION`), in that order; the private- and
//! public-key arms add a fourth, `ENGINE_R_FAILED_LOADING_PRIVATE_KEY`/
//! `_PUBLIC_KEY`, when the loader returns NULL. The court drives the NULL, uninitialised
//! and no-loader arms and compares only the returned value — the error queue is never read —
//! because those three are exactly the arms whose *order* a plausible transcription gets
//! wrong (`funct_ref` must be tested before the loader, or an uninitialised engine with a
//! loader would be attempted).
//!
//! ## The path succeeds by calling the caller's loader
//!
//! The loader's `EVP_PKEY *` is opaque here: `ENGINE_LOAD_KEY_PTR` is
//! `eng_lib.rs`'s four-argument function type, and this module forwards the caller's
//! `key_id`/`ui_method`/`callback_data` unchanged. The SSL client-certificate loader is the
//! seven-argument `ENGINE_SSL_CLIENT_CERT_PTR`, whose structured parameters are equally
//! opaque; the entry point returns its value verbatim, with no NULL test of its own, which
//! is the authority's own shape.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::engine::eng_lib::{
    global_engine_lock, Engine, EngineLoadKeyPtr, EngineSslClientCertPtr,
};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    ENG_PKEY_103, ENG_PKEY_108, ENG_PKEY_121, ENG_PKEY_128, ENG_PKEY_133, ENG_PKEY_62, ENG_PKEY_69,
    ENG_PKEY_74, ENG_PKEY_79, ENG_PKEY_91, ENG_PKEY_98,
};
use crate::runtime::err::raise_site;
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// `int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f)` —
/// `crypto/engine/eng_pkey.c:17-22`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_load_privkey_function(
    e: *mut Engine,
    loadpriv_f: Option<EngineLoadKeyPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's engine.
        unsafe { (*e).load_privkey = loadpriv_f };
        1
    })
}

/// `int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f)` —
/// `:24-28`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_load_pubkey_function(
    e: *mut Engine,
    loadpub_f: Option<EngineLoadKeyPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's engine.
        unsafe { (*e).load_pubkey = loadpub_f };
        1
    })
}

/// `int ENGINE_set_load_ssl_client_cert_function(ENGINE *e,
///     ENGINE_SSL_CLIENT_CERT_PTR loadssl_f)` — `:30-36`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_load_ssl_client_cert_function(
    e: *mut Engine,
    loadssl_f: Option<EngineSslClientCertPtr>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is the caller's engine.
        unsafe { (*e).load_ssl_client_cert = loadssl_f };
        1
    })
}

/// `ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e)` — `:38-41`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_load_privkey_function(
    e: *const Engine,
) -> Option<EngineLoadKeyPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).load_privkey }
}

/// `ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e)` — `:43-46`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_load_pubkey_function(
    e: *const Engine,
) -> Option<EngineLoadKeyPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).load_pubkey }
}

/// `ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function(const ENGINE *e)` —
/// `:48-52`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_ssl_client_cert_function(
    e: *const Engine,
) -> Option<EngineSslClientCertPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).load_ssl_client_cert }
}

/// `EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method,
///     void *callback_data)` — `:56-83`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]; `key_id` and the two callback pointers
/// must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_load_private_key(
    e: *mut Engine,
    key_id: *const c_char,
    ui_method: *mut c_void,
    callback_data: *mut c_void,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if e.is_null() {
            // SAFETY: `ENG_PKEY_62` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_62) };
            return ptr::null_mut();
        }
        // SAFETY: the lock is the engine lock; a NULL lock returns 0, mirroring the
        // authority's `if (!CRYPTO_THREAD_write_lock(...))`.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the lock is held and `e` is live.
        if unsafe { (*e).funct_ref } == 0 {
            // SAFETY: the lock is held.
            unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            // SAFETY: `ENG_PKEY_69` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_69) };
            return ptr::null_mut();
        }
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        // SAFETY: `e` is live.
        let loader = unsafe { (*e).load_privkey };
        let Some(loader) = loader else {
            // SAFETY: `ENG_PKEY_74` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_74) };
            return ptr::null_mut();
        };
        // SAFETY: `loader` is the caller's callback, called with its own engine and the
        // caller's arguments.
        let pkey = unsafe { loader(e, key_id, ui_method, callback_data) };
        if pkey.is_null() {
            // SAFETY: `ENG_PKEY_79` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_79) };
            return ptr::null_mut();
        }
        pkey
    })
}

/// `EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method,
///     void *callback_data)` — `:85-112`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]; `key_id` and the two callback pointers
/// must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_load_public_key(
    e: *mut Engine,
    key_id: *const c_char,
    ui_method: *mut c_void,
    callback_data: *mut c_void,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if e.is_null() {
            // SAFETY: `ENG_PKEY_91` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_91) };
            return ptr::null_mut();
        }
        // SAFETY: the lock is the engine lock; a NULL lock returns 0.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the lock is held and `e` is live.
        if unsafe { (*e).funct_ref } == 0 {
            // SAFETY: the lock is held.
            unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            // SAFETY: `ENG_PKEY_98` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_98) };
            return ptr::null_mut();
        }
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        // SAFETY: `e` is live.
        let loader = unsafe { (*e).load_pubkey };
        let Some(loader) = loader else {
            // SAFETY: `ENG_PKEY_103` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_103) };
            return ptr::null_mut();
        };
        // SAFETY: `loader` is the caller's callback, called with its own engine and the
        // caller's arguments.
        let pkey = unsafe { loader(e, key_id, ui_method, callback_data) };
        if pkey.is_null() {
            // SAFETY: `ENG_PKEY_108` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_108) };
            return ptr::null_mut();
        }
        pkey
    })
}

/// `int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn,
///     X509 **pcert, EVP_PKEY **ppkey, STACK_OF(X509) **pother, UI_METHOD *ui_method,
///     void *callback_data)` — `:114-138`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]; every other pointer must be valid per the
/// authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_load_ssl_client_cert(
    e: *mut Engine,
    s: *mut c_void,
    ca_dn: *mut c_void,
    pcert: *mut *mut c_void,
    ppkey: *mut *mut c_void,
    pother: *mut *mut c_void,
    ui_method: *mut c_void,
    callback_data: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        if e.is_null() {
            // SAFETY: `ENG_PKEY_121` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_121) };
            return 0;
        }
        // SAFETY: the lock is the engine lock; a NULL lock returns 0.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return 0;
        }
        // SAFETY: the lock is held and `e` is live.
        if unsafe { (*e).funct_ref } == 0 {
            // SAFETY: the lock is held.
            unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            // SAFETY: `ENG_PKEY_128` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_128) };
            return 0;
        }
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        // SAFETY: `e` is live.
        let loader = unsafe { (*e).load_ssl_client_cert };
        let Some(loader) = loader else {
            // SAFETY: `ENG_PKEY_133` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_PKEY_133) };
            return 0;
        };
        // SAFETY: `loader` is the caller's callback, called with its own engine and the
        // caller's arguments.
        unsafe { loader(e, s, ca_dn, pcert, ppkey, pother, ui_method, callback_data) }
    })
}
