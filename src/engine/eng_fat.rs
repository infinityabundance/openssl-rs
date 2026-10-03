//! Phase 13.3 — `crypto/engine/eng_fat.c`: the control fat helpers.
//!
//! Four exports, and they are the whole of subphase 13.3's open rows. `ENGINE_set_default`
//! and `ENGINE_set_default_string` are the bulk setters over the per-algorithm tables 13.2
//! landed; `ENGINE_register_complete` and `ENGINE_register_all_complete` are the bulk
//! registrars over the same tables. `eng_ctrl.c` (0 open) is the command dispatcher beside
//! them and is transcribed whole in `eng_ctrl.rs`; this unit is the fat layer over it.
//!
//! ## The `ENGINE_METHOD_*` masks are the dispatch
//!
//! `ENGINE_set_default` is a sequence of `flags & ENGINE_METHOD_*` tests, each forwarding to
//! the matching `tb_*` `ENGINE_set_default_*`. `ENGINE_METHOD_*` are `engine.h` macros
//! (`:45-57`), and the crate had no constant for them before this unit, so they are defined
//! here with the authority's own values rather than inferred. `ENGINE_METHOD_ALL` is
//! `0xFFFF`; `int_def_cb` sets it for the string `"ALL"`.
//!
//! ## The string spelling is a table of prefix comparisons
//!
//! `ENGINE_set_default_string` hands `def_list` to `CONF_parse_list`, whose callback
//! `int_def_cb` turns each element into one or more method bits. Every arm is a
//! `strncmp(alg, WORD, len) == 0` — a comparison over the element's whole length, so an
//! element matches only when it *is* the word — and the order matters: `PKEY` is tested
//! before `PKEY_CRYPTO`/`PKEY_ASN1`, and because each match consumes the entire element the
//! later two are reached only for their own exact spellings. An unknown element returns `0`,
//! which stops `CONF_parse_list`; the caller then raises `ENGINE_R_INVALID_STRING` with the
//! authority's `"str=%s"` operand.
//!
//! ## The one call that used to be a forward declaration
//!
//! `src/engine/eng_cnf.rs` (Phase 13.1) transcribed `int_engine_configure`'s
//! `default_algorithms` arm before this unit existed, and declared `ENGINE_set_default_string`
//! as an `extern "C"` scaffold for it. That declaration is dropped with this landing: the
//! call is now resolved by this module's definition, and `eng_cnf.rs` imports it.
//!
//! ## No later-stratum dependency, and one divergence that is not ours
//!
//! The closure is complete: every callee is a 13.2 table, the registry walk 10.9/13.1 landed,
//! `CONF_parse_list` and the `ERR` queue. The `#ifndef OPENSSL_NO_DSA`/`NO_DH`/`NO_EC` guards
//! the authority wraps three arms in are all *enabled* in the admitted build, so the crate's
//! unconditional calls are the admitted configuration rather than a divergence. The one arm
//! this unit cannot reproduce is `ENGINE_register_all_complete`'s walk over the *built-in*
//! registry: the authority registers `rdrand` and `dynamic` and this crate registers nothing
//! (`src/engine/eng_all.rs`), so the walk sees only engines a caller registered. The court
//! drives it over a synthetic engine for that reason.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};

use crate::engine::eng_lib::Engine;
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::tb_asnmth::{
    ENGINE_register_pkey_asn1_meths, ENGINE_set_default_pkey_asn1_meths,
};
use crate::engine::tb_cipher::{ENGINE_register_ciphers, ENGINE_set_default_ciphers};
use crate::engine::tb_dh::{ENGINE_register_DH, ENGINE_set_default_DH};
use crate::engine::tb_digest::{ENGINE_register_digests, ENGINE_set_default_digests};
use crate::engine::tb_dsa::{ENGINE_register_DSA, ENGINE_set_default_DSA};
use crate::engine::tb_eckey::{ENGINE_register_EC, ENGINE_set_default_EC};
use crate::engine::tb_pkmeth::{ENGINE_register_pkey_meths, ENGINE_set_default_pkey_meths};
use crate::engine::tb_rand::{ENGINE_register_RAND, ENGINE_set_default_RAND};
use crate::engine::tb_rsa::{ENGINE_register_RSA, ENGINE_set_default_RSA};
use crate::runtime::bio::sys::strncmp;
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::err::err_sites::ENG_FAT_86;
use crate::runtime::err::raise_site_data;

/// `ENGINE_METHOD_RSA` (`openssl/engine.h:45`) — `(unsigned int)0x0001`.
const ENGINE_METHOD_RSA: c_uint = 0x0001;
/// `ENGINE_METHOD_DSA` (`:46`) — `(unsigned int)0x0002`.
const ENGINE_METHOD_DSA: c_uint = 0x0002;
/// `ENGINE_METHOD_DH` (`:47`) — `(unsigned int)0x0004`.
const ENGINE_METHOD_DH: c_uint = 0x0004;
/// `ENGINE_METHOD_RAND` (`:48`) — `(unsigned int)0x0008`.
const ENGINE_METHOD_RAND: c_uint = 0x0008;
/// `ENGINE_METHOD_CIPHERS` (`:49`) — `(unsigned int)0x0040`.
const ENGINE_METHOD_CIPHERS: c_uint = 0x0040;
/// `ENGINE_METHOD_DIGESTS` (`:50`) — `(unsigned int)0x0080`.
const ENGINE_METHOD_DIGESTS: c_uint = 0x0080;
/// `ENGINE_METHOD_PKEY_METHS` (`:51`) — `(unsigned int)0x0200`.
const ENGINE_METHOD_PKEY_METHS: c_uint = 0x0200;
/// `ENGINE_METHOD_PKEY_ASN1_METHS` (`:52`) — `(unsigned int)0x0400`.
const ENGINE_METHOD_PKEY_ASN1_METHS: c_uint = 0x0400;
/// `ENGINE_METHOD_EC` (`:53`) — `(unsigned int)0x0800`.
const ENGINE_METHOD_EC: c_uint = 0x0800;
/// `ENGINE_METHOD_ALL` (`:55`) — `(unsigned int)0xFFFF`.
const ENGINE_METHOD_ALL: c_uint = 0xFFFF;
/// `ENGINE_FLAGS_NO_REGISTER_ALL` (`:96`) — `(int)0x0008`.
const ENGINE_FLAGS_NO_REGISTER_ALL: c_int = 0x0008;

/// `int ENGINE_set_default(ENGINE *e, unsigned int flags)` — `crypto/engine/eng_fat.c:17-46`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]; the authority's arm bodies dereference it.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default(e: *mut Engine, flags: c_uint) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_CIPHERS != 0 && unsafe { ENGINE_set_default_ciphers(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_DIGESTS != 0 && unsafe { ENGINE_set_default_digests(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_RSA != 0 && unsafe { ENGINE_set_default_RSA(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_DSA != 0 && unsafe { ENGINE_set_default_DSA(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_DH != 0 && unsafe { ENGINE_set_default_DH(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_EC != 0 && unsafe { ENGINE_set_default_EC(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_RAND != 0 && unsafe { ENGINE_set_default_RAND(e) } == 0 {
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    if flags & ENGINE_METHOD_PKEY_METHS != 0 && unsafe { ENGINE_set_default_pkey_meths(e) } == 0 {
        return 0;
    }
    if flags & ENGINE_METHOD_PKEY_ASN1_METHS != 0
        // SAFETY: `e` is the caller's engine.
        && unsafe { ENGINE_set_default_pkey_asn1_meths(e) } == 0
    {
        return 0;
    }
    1
}

/// `static int int_def_cb(const char *alg, int len, void *arg)` — `:50-80`.
///
/// The `CONF_parse_list` callback. `arg` is the `unsigned int *pflags` accumulator; `alg` is
/// the element (not NUL-terminated, which is why `len` is passed) and is NULL for an empty
/// element, which the authority refuses.
///
/// # Safety
/// `alg` must be NULL or readable for `len` bytes; `arg` must be a writable `*mut c_uint`.
unsafe extern "C" fn int_def_cb(alg: *const c_char, len: c_int, arg: *mut c_void) -> c_int {
    if alg.is_null() {
        return 0;
    }
    let pflags = arg.cast::<c_uint>();
    let n = len as usize;
    // Every arm below is `strncmp(alg, WORD, len) == 0`, the authority's own test. `strncmp`
    // is the authority's, so a comparison over the element's whole length is reproduced
    // exactly rather than replaced by a Rust prefix test.
    // SAFETY: `alg` is readable for `len` bytes and each literal is a static NUL-terminated
    // `&str`; `n` is the authority's own `size_t` conversion of `len`.
    let word = |w: &[u8]| unsafe { strncmp(alg, w.as_ptr().cast::<c_char>(), n) == 0 };
    let bit = if word(b"ALL\0") {
        ENGINE_METHOD_ALL
    } else if word(b"RSA\0") {
        ENGINE_METHOD_RSA
    } else if word(b"DSA\0") {
        ENGINE_METHOD_DSA
    } else if word(b"DH\0") {
        ENGINE_METHOD_DH
    } else if word(b"EC\0") {
        ENGINE_METHOD_EC
    } else if word(b"RAND\0") {
        ENGINE_METHOD_RAND
    } else if word(b"CIPHERS\0") {
        ENGINE_METHOD_CIPHERS
    } else if word(b"DIGESTS\0") {
        ENGINE_METHOD_DIGESTS
    } else if word(b"PKEY\0") {
        ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS
    } else if word(b"PKEY_CRYPTO\0") {
        ENGINE_METHOD_PKEY_METHS
    } else if word(b"PKEY_ASN1\0") {
        ENGINE_METHOD_PKEY_ASN1_METHS
    } else {
        return 0;
    };
    // SAFETY: `arg` is a writable `unsigned int` accumulator per the callback contract.
    unsafe { *pflags |= bit };
    1
}

/// Format `"str=%s"` the way `crypto/err/err.c`'s `_dopr` does, with a NULL pointer rendered
/// as `<NULL>`.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes());
    }
}

/// `int ENGINE_set_default_string(ENGINE *e, const char *def_list)` — `:82-91`.
///
/// The `default_algorithms` control's body: parse `def_list` into an `ENGINE_METHOD_*` mask,
/// then hand it to `ENGINE_set_default`. A refused element raises `ENGINE_R_INVALID_STRING`
/// with the authority's `"str=%s"` operand and answers 0 rather than setting anything.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]; `def_list` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_string(
    e: *mut Engine,
    def_list: *const c_char,
) -> c_int {
    let mut flags: c_uint = 0;
    // SAFETY: `def_list` is NULL or NUL-terminated; `int_def_cb` is the callback and
    // `flags` is the writable accumulator it ORs into.
    if unsafe {
        CONF_parse_list(
            def_list,
            c_int::from(b','),
            1,
            Some(int_def_cb),
            core::ptr::addr_of_mut!(flags).cast::<c_void>(),
        )
    } == 0
    {
        let mut msg: Vec<u8> = b"str=".to_vec();
        // SAFETY: `def_list` is NULL or NUL-terminated.
        unsafe { push_cstr_or_null(&mut msg, def_list) };
        msg.push(0);
        // SAFETY: `ENG_FAT_86` is a generated constant whose strings are static, and `msg`
        // is NUL-terminated.
        unsafe { raise_site_data(&ENG_FAT_86, msg.as_ptr().cast::<c_char>()) };
        return 0;
    }
    // SAFETY: `e` is the caller's engine.
    unsafe { ENGINE_set_default(e, flags) }
}

/// `int ENGINE_register_complete(ENGINE *e)` — `:93-111`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_complete(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine; each register arm is the matching 13.2 table.
    unsafe {
        ENGINE_register_ciphers(e);
        ENGINE_register_digests(e);
        ENGINE_register_RSA(e);
        ENGINE_register_DSA(e);
        ENGINE_register_DH(e);
        ENGINE_register_EC(e);
        ENGINE_register_RAND(e);
        ENGINE_register_pkey_meths(e);
        ENGINE_register_pkey_asn1_meths(e);
    }
    1
}

/// `int ENGINE_register_all_complete(void)` — `:113-121`.
///
/// Walks the registry and registers every engine that does not carry
/// `ENGINE_FLAGS_NO_REGISTER_ALL`. The authority's built-in `rdrand`/`dynamic` engines are
/// not registered in this crate (see `src/engine/eng_all.rs`), so the walk sees only what a
/// caller published.
///
/// # Safety
/// The registry must be in the state `ENGINE_get_first`/`ENGINE_get_next`'s contract requires;
/// the walk hands each member to `ENGINE_register_complete`.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_all_complete() -> c_int {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        if unsafe { (*e).flags } & ENGINE_FLAGS_NO_REGISTER_ALL == 0 {
            // SAFETY: `e` is live.
            unsafe { ENGINE_register_complete(e) };
        }
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
    1
}
