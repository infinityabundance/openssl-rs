//! `crypto/x509/x509_d2.c` — the `X509_STORE_load_*`/`X509_STORE_set_default_paths` surface.
//! **This slice lands the unit whole**: all nine open exports.
//!
//! `crypto/x509/x509_d2.c` is 117 lines. Every function here is a thin driver over
//! [`X509_STORE_add_lookup`](crate::x509::x509_lu::X509_STORE_add_lookup) and one
//! `X509_LOOKUP_ctrl(_ex)` macro (`X509_LOOKUP_load_file(_ex)`, `X509_LOOKUP_add_dir`,
//! `X509_LOOKUP_add_store_ex`), so what decides landability is the single method constructor each
//! arm names.
//!
//! ## Landed
//!
//! The three method constructors this unit reaches are all landed, so nothing waits:
//!
//! * `X509_STORE_set_default_paths_ex` (`:15-44`) and `X509_STORE_set_default_paths` (`:45-48`) —
//!   installs the file, hashed-directory and store-URI lookups and loads each one's default. Its
//!   constructors are [`X509_LOOKUP_file`](crate::x509::by_file::X509_LOOKUP_file) (11.6, whose
//!   default-file blocker `x509_def.rs` discharged),
//!   [`X509_LOOKUP_hash_dir`](crate::x509::by_dir::X509_LOOKUP_hash_dir) (11.7, whose `lstat`/`stat`
//!   probe is now served by `src/runtime/dir_posix.c`) and
//!   [`X509_LOOKUP_store`](crate::x509::by_store::X509_LOOKUP_store) (11.1b).
//! * `X509_STORE_load_file_ex` (`:50-63`) and `X509_STORE_load_file` (`:65-68`) — the file arm,
//!   over `X509_LOOKUP_file`.
//! * `X509_STORE_load_path` (`:70-80`) — the directory arm, over `X509_LOOKUP_hash_dir`.
//! * `X509_STORE_load_store_ex` (`:82-93`) and `X509_STORE_load_store` (`:95-98`) — the URI arm,
//!   over `X509_LOOKUP_store`.
//! * `X509_STORE_load_locations_ex` (`:100-111`) and `X509_STORE_load_locations` (`:113-117`) — the
//!   combined arm, over `X509_STORE_load_file_ex` and `X509_STORE_load_path`.
//!
//! `court/unit_ready.py` measured this unit's blocker set as exactly the three constructors
//! (`X509_LOOKUP_file <- by_file.c`, `X509_LOOKUP_hash_dir <- by_dir.c`, `X509_LOOKUP_store <-
//! by_store.c`); all three are landed, so every row here lands.
//!
//! `crypto/x509/x509_d2.c` raises nothing — its only error-queue call is the trailing
//! `ERR_clear_error()` in `X509_STORE_set_default_paths_ex` (`:41`) — so it is deliberately **not**
//! listed in `gen_err_raise_sites.py`'s covered set and declares no raise coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::runtime::err::ERR_clear_error;
use crate::x509::by_dir::X509_LOOKUP_hash_dir;
use crate::x509::by_file::X509_LOOKUP_file;
use crate::x509::by_store::X509_LOOKUP_store;
use crate::x509::x509_lu::{
    X509Lookup, X509Store, X509_LOOKUP_ctrl, X509_LOOKUP_ctrl_ex, X509_STORE_add_lookup,
};

/// `X509_L_FILE_LOAD` — `include/openssl/x509_vfy.h:283`, the command behind
/// `X509_LOOKUP_load_file(_ex)`.
const X509_L_FILE_LOAD: c_int = 1;
/// `X509_L_ADD_DIR` — `include/openssl/x509_vfy.h:284`, the command behind `X509_LOOKUP_add_dir`.
const X509_L_ADD_DIR: c_int = 2;
/// `X509_L_ADD_STORE` — `include/openssl/x509_vfy.h:285`, the command behind
/// `X509_LOOKUP_add_store_ex`.
const X509_L_ADD_STORE: c_int = 3;
/// `X509_FILETYPE_PEM` — `include/openssl/x509.h.in:70`.
const X509_FILETYPE_PEM: c_int = 1;
/// `X509_FILETYPE_DEFAULT` — `include/openssl/x509.h:170`.
const X509_FILETYPE_DEFAULT: c_int = 3;

/// `int X509_STORE_set_default_paths_ex(X509_STORE *ctx, OSSL_LIB_CTX *libctx, const char *propq)`
/// — `crypto/x509/x509_d2.c:15-44`.
///
/// Installs the file, hashed-directory and store-URI lookups on `ctx` and loads each one's default
/// — the compiled-in bundle and directory, and the store URI defaults (presently none). A failed
/// lookup answers 0; the default loads' own answers are ignored, and any errors they raise are
/// cleared before the 1 answer.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_default_paths_ex(
    ctx: *mut X509Store,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `X509_LOOKUP_file` is a static table's address and `ctx` is live per the contract.
    let lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_file()) };
    if lookup.is_null() {
        return 0;
    }
    // The `X509_LOOKUP_load_file_ex(lookup, NULL, X509_FILETYPE_DEFAULT, libctx, propq)` macro.
    // SAFETY: `lookup` is live; the arguments are the caller's; a NULL name is what the macro
    // passes.
    unsafe {
        X509_LOOKUP_ctrl_ex(
            lookup,
            X509_L_FILE_LOAD,
            ptr::null(),
            c_long::from(X509_FILETYPE_DEFAULT),
            ptr::null_mut(),
            libctx,
            propq,
        );
    }

    // SAFETY: `X509_LOOKUP_hash_dir` is a static table's address and `ctx` is live.
    let lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir()) };
    if lookup.is_null() {
        return 0;
    }
    // The `X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT)` macro.
    // SAFETY: `lookup` is live; a NULL name is what the macro passes.
    unsafe {
        X509_LOOKUP_ctrl(
            lookup,
            X509_L_ADD_DIR,
            ptr::null(),
            c_long::from(X509_FILETYPE_DEFAULT),
            ptr::null_mut(),
        );
    }

    // SAFETY: `X509_LOOKUP_store` is a static table's address and `ctx` is live.
    let lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_store()) };
    if lookup.is_null() {
        return 0;
    }
    // The `X509_LOOKUP_add_store_ex(lookup, NULL, libctx, propq)` macro.
    // SAFETY: `lookup` is live; the arguments are the caller's; a NULL name is what the macro
    // passes.
    unsafe {
        X509_LOOKUP_ctrl_ex(
            lookup,
            X509_L_ADD_STORE,
            ptr::null(),
            0,
            ptr::null_mut(),
            libctx,
            propq,
        );
    }

    // Clear any errors.
    ERR_clear_error();
    1
}

/// `int X509_STORE_set_default_paths(X509_STORE *ctx)` — `crypto/x509/x509_d2.c:45-48`.
///
/// [`X509_STORE_set_default_paths_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_default_paths(ctx: *mut X509Store) -> c_int {
    // SAFETY: the contract is `X509_STORE_set_default_paths_ex`'s with NULL libctx/propq.
    unsafe { X509_STORE_set_default_paths_ex(ctx, ptr::null_mut(), ptr::null()) }
}

/// `int X509_STORE_load_file_ex(X509_STORE *ctx, const char *file, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/x509/x509_d2.c:50-63`.
///
/// Adds the file lookup to `ctx` and loads `file` as PEM. A NULL `file`, a failed lookup, or a
/// rejected load answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`; `file` NULL or NUL-terminated; `libctx` NULL or live; `propq`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_file_ex(
    ctx: *mut X509Store,
    file: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if file.is_null() {
        return 0;
    }
    // SAFETY: `X509_LOOKUP_file` is a static table's address and `ctx` is live per the contract.
    let lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_file()) };
    if lookup.is_null() {
        return 0;
    }
    // The `X509_LOOKUP_load_file_ex(lookup, file, X509_FILETYPE_PEM, libctx, propq)` macro.
    // SAFETY: `lookup` is live; `file` is NUL-terminated per the contract; `libctx`/`propq` are
    // the caller's.
    if unsafe {
        X509_LOOKUP_ctrl_ex(
            lookup,
            X509_L_FILE_LOAD,
            file,
            c_long::from(X509_FILETYPE_PEM),
            ptr::null_mut(),
            libctx,
            propq,
        )
    } <= 0
    {
        return 0;
    }
    1
}

/// `int X509_STORE_load_file(X509_STORE *ctx, const char *file)` —
/// `crypto/x509/x509_d2.c:65-68`.
///
/// [`X509_STORE_load_file_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_STORE_load_file_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_file(ctx: *mut X509Store, file: *const c_char) -> c_int {
    // SAFETY: the contract is `X509_STORE_load_file_ex`'s with NULL libctx/propq.
    unsafe { X509_STORE_load_file_ex(ctx, file, ptr::null_mut(), ptr::null()) }
}

/// `int X509_STORE_load_path(X509_STORE *ctx, const char *path)` —
/// `crypto/x509/x509_d2.c:70-80`.
///
/// Adds the hashed-directory lookup to `ctx` and loads the directory `path` as PEM. A NULL `path`,
/// a failed lookup, or a rejected add answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`; `path` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_path(ctx: *mut X509Store, path: *const c_char) -> c_int {
    if path.is_null() {
        return 0;
    }
    // SAFETY: `X509_LOOKUP_hash_dir` is a static table's address and `ctx` is live per the
    // contract.
    let lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir()) };
    if lookup.is_null() {
        return 0;
    }
    // The `X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)` macro.
    // SAFETY: `lookup` is live; `path` is NUL-terminated per the contract.
    if unsafe {
        X509_LOOKUP_ctrl(
            lookup,
            X509_L_ADD_DIR,
            path,
            c_long::from(X509_FILETYPE_PEM),
            ptr::null_mut(),
        )
    } <= 0
    {
        return 0;
    }
    1
}

/// `int X509_STORE_load_store_ex(X509_STORE *ctx, const char *uri, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/x509/x509_d2.c:82-93`.
///
/// Adds the store-URI lookup to `ctx` (or finds the one already there) and records `uri` on it. A
/// NULL `uri`, a failed lookup, or a rejected `X509_L_ADD_STORE` command answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`; `uri` NULL or NUL-terminated; `libctx` NULL or live; `propq`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_store_ex(
    ctx: *mut X509Store,
    uri: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if uri.is_null() {
        return 0;
    }
    // SAFETY: `X509_LOOKUP_store` is a static table's address and `ctx` is live per the contract.
    let lookup: *mut X509Lookup = unsafe { X509_STORE_add_lookup(ctx, X509_LOOKUP_store()) };
    if lookup.is_null() {
        return 0;
    }
    // SAFETY: `lookup` is live; `uri`/`libctx`/`propq` are the caller's. This is the
    // `X509_LOOKUP_add_store_ex` macro's own `X509_LOOKUP_ctrl_ex` call.
    if unsafe {
        X509_LOOKUP_ctrl_ex(
            lookup,
            X509_L_ADD_STORE,
            uri,
            0,
            ptr::null_mut(),
            libctx,
            propq,
        )
    } == 0
    {
        return 0;
    }
    1
}

/// `int X509_STORE_load_store(X509_STORE *ctx, const char *uri)` —
/// `crypto/x509/x509_d2.c:95-98`.
///
/// [`X509_STORE_load_store_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_STORE_load_store_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_store(ctx: *mut X509Store, uri: *const c_char) -> c_int {
    // SAFETY: the contract is `X509_STORE_load_store_ex`'s with NULL libctx/propq.
    unsafe { X509_STORE_load_store_ex(ctx, uri, ptr::null_mut(), ptr::null()) }
}

/// `int X509_STORE_load_locations_ex(X509_STORE *ctx, const char *file, const char *path,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x509_d2.c:100-111`.
///
/// Loads `file` (when non-NULL) and `path` (when non-NULL) into `ctx`. Both NULL, or either load
/// failing, answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE`; `file`/`path` NULL or NUL-terminated; `libctx` NULL or live;
/// `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_locations_ex(
    ctx: *mut X509Store,
    file: *const c_char,
    path: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if file.is_null() && path.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`file`/`libctx`/`propq` are the caller's; `file` is non-NULL here.
    if !file.is_null() && unsafe { X509_STORE_load_file_ex(ctx, file, libctx, propq) } == 0 {
        return 0;
    }
    // SAFETY: `ctx`/`path` are the caller's; `path` is non-NULL here.
    if !path.is_null() && unsafe { X509_STORE_load_path(ctx, path) } == 0 {
        return 0;
    }
    1
}

/// `int X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *path)` —
/// `crypto/x509/x509_d2.c:113-117`.
///
/// [`X509_STORE_load_locations_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_STORE_load_locations_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_locations(
    ctx: *mut X509Store,
    file: *const c_char,
    path: *const c_char,
) -> c_int {
    // SAFETY: the contract is `X509_STORE_load_locations_ex`'s with NULL libctx/propq.
    unsafe { X509_STORE_load_locations_ex(ctx, file, path, ptr::null_mut(), ptr::null()) }
}
