//! `crypto/x509/x509_d2.c` — the `X509_STORE_load_*`/`X509_STORE_set_default_paths` surface. **This
//! slice lands two of its nine open exports** — [`X509_STORE_load_store_ex`] and
//! [`X509_STORE_load_store`] — and withholds the other seven by name, each with the one unlanded
//! lookup constructor it reaches.
//!
//! `crypto/x509/x509_d2.c` is 117 lines. Every function here is a thin driver over
//! [`X509_STORE_add_lookup`](crate::x509::x509_lu::X509_STORE_add_lookup) and one
//! `X509_LOOKUP_ctrl(_ex)` macro (`X509_LOOKUP_load_file(_ex)`, `X509_LOOKUP_add_dir`,
//! `X509_LOOKUP_add_store_ex`), so what decides landability is the single method constructor each
//! arm names.
//!
//! ## Landed
//!
//! * `X509_STORE_load_store_ex` (`:82-93`) and `X509_STORE_load_store` (`:95-98`) — the URI arm.
//!   Its one constructor is [`X509_LOOKUP_store`](crate::x509::by_store::X509_LOOKUP_store), which
//!   11.1b lands, and `X509_LOOKUP_add_store_ex` expands to the landed
//!   [`X509_LOOKUP_ctrl_ex`](crate::x509::x509_lu::X509_LOOKUP_ctrl_ex). Nothing waits.
//!
//! ## Withheld by name, with each name's blocker
//!
//! Seven of the nine open exports, in one of two shapes:
//!
//! * `X509_STORE_set_default_paths_ex` (`:15-44`) and `X509_STORE_set_default_paths` (`:45-48`) —
//!   install all three lookup methods and then load the default file, directory and store URI.
//!   Blocked by [`X509_LOOKUP_file`](crate::x509::by_file) *and*
//!   [`X509_LOOKUP_hash_dir`](crate::x509::by_dir): both are withheld, each for the reason its own
//!   module doc records (11.6's unlanded PEM readers, and 11.7's default-path names).
//! * `X509_STORE_load_file_ex` (`:50-63`) and `X509_STORE_load_file` (`:65-68`) — the file arm.
//!   Blocked by `X509_LOOKUP_file`, for the same reason.
//! * `X509_STORE_load_path` (`:70-80`) — the directory arm. Blocked by `X509_LOOKUP_hash_dir`, for
//!   the same reason.
//! * `X509_STORE_load_locations_ex` (`:100-111`) and `X509_STORE_load_locations` (`:113-117`) — the
//!   combined arm. It calls only `X509_STORE_load_file_ex` and `X509_STORE_load_path`, both
//!   withheld above, so it is blocked by them rather than by a constructor directly.
//!
//! `court/unit_ready.py` measures this unit's blocker set as exactly the three constructors
//! (`X509_LOOKUP_file <- by_file.c`, `X509_LOOKUP_hash_dir <- by_dir.c`, `X509_LOOKUP_store <-
//! by_store.c`); the third is landed here, so two of the three are discharged and the seven are
//! the rows that wait.
//!
//! `crypto/x509/x509_d2.c` raises nothing — its only error-queue call is the trailing
//! `ERR_clear_error()` in `X509_STORE_set_default_paths_ex` (`:41`) — so it is deliberately **not**
//! listed in `gen_err_raise_sites.py`'s covered set and declares no raise coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::x509::by_store::X509_LOOKUP_store;
use crate::x509::x509_lu::{X509Lookup, X509Store, X509_LOOKUP_ctrl_ex, X509_STORE_add_lookup};

/// `X509_L_ADD_STORE` — `include/openssl/x509_vfy.h:285`, the command behind
/// `X509_LOOKUP_add_store_ex`.
const X509_L_ADD_STORE: c_int = 3;

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
