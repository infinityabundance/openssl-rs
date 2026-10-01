//! `crypto/x509/by_file.c` — the `X509_LOOKUP_file` method and its two file loaders. **This slice
//! lands the five loaders** — `X509_load_cert_file_ex`/`_file`, `X509_load_crl_file` and
//! `X509_load_cert_crl_file_ex`/`_file` — and withholds the method constructor
//! `X509_LOOKUP_file` (`:41-44`), its row `x509_file_lookup` (`:26-39`) and the two control doors
//! `by_file_ctrl_ex` (`:46-82`)/`by_file_ctrl` (`:84-88`), for the one unmet dependency recorded
//! below.
//!
//! `crypto/x509/by_file.c` is 284 lines. Its two loaders read a certificate bundle through the
//! `pem.h` X.509 readers — `PEM_read_bio_X509_AUX` (`crypto/pem/pem_xaux.c`, 11.6),
//! `PEM_read_bio_X509_CRL` (`crypto/pem/pem_all.c`, 11.6) and `PEM_X509_INFO_read_bio_ex`
//! (`crypto/pem/pem_info.c`, 11.6) into the `X509_INFO` item `crypto/asn1/x_info.c` (11.7) — and
//! through the landed `d2i_X509_bio`/`d2i_X509_CRL_bio` (`x_all.rs`) and the landed
//! `X509_STORE_add_cert`/`X509_STORE_add_crl` (`x509_lu.rs`). Those readers were the loaders'
//! only blockers, and 11.6/11.7 have discharged them, so **the five loaders are transcribed
//! here** and the module is no longer a doc and six withholds.
//!
//! ## Withheld by name, with the one unmet blocker
//!
//! * `X509_LOOKUP_file` (`:41-44`) and its table `x509_file_lookup` (`:26-39`) — the method
//!   constructor. The table's `ctrl`/`ctrl_ex` slots are `by_file_ctrl` (`:84-88`) and
//!   `by_file_ctrl_ex` (`:46-82`), and all three are withheld **together**, because
//!   `by_file_ctrl_ex`'s `X509_FILETYPE_DEFAULT` arm calls `X509_get_default_cert_file`
//!   (`crypto/x509/x509_def.c:98-106`). That name is withheld in its own unit as a D451-class
//!   divergence: its answer is a compile-time path built from the admitted build's forensic
//!   `OPENSSLDIR`, while the candidate distribution reports `OPENSSLDIR: N/A`
//!   (`src/runtime/init.rs:1133`) and the directory plane is Phase 16's (`ossl_get_openssldir`,
//!   `src/runtime/defaults.rs`). The candidate's symbol of that name is a **scaffolded abort**
//!   (`artifacts/phase2/shell/libcrypto.shell.rs:5772`), so a transcription that called it would
//!   abort on every `X509_FILETYPE_DEFAULT` load rather than load the default bundle — the reason
//!   the name is left withheld rather than stubbed. Every other callee of `by_file_ctrl_ex` is
//!   landed — `ossl_safe_getenv` (`runtime/getenv.rs`), `X509_get_default_cert_file_env`
//!   (`x509_def.rs`) and this module's own two loaders — so exactly one default-path call waits on
//!   11.7/16.
//!
//! The three callers of the constructor — `X509_LOOKUP_file`, `X509_STORE_load_file(_ex)` and
//! `X509_STORE_set_default_paths(_ex)` in [`crate::x509::x509_d2`] — wait with it.
//!
//! ## The landed five
//!
//! * `X509_load_cert_file_ex` (`:90-165`) and its wrapper `X509_load_cert_file` (`:167-170`) —
//!   the certificate-file loader. Its `X509_FILETYPE_PEM` arm loops over `PEM_read_bio_X509_AUX`
//!   until the reader reports `PEM_R_NO_START_LINE`, adding each certificate to the lookup's
//!   store; its `X509_FILETYPE_ASN1` arm is one `d2i_X509_bio`. `BIO_read_filename` is the macro
//!   `BIO_ctrl(b, BIO_C_SET_FILENAME, BIO_CLOSE | BIO_FP_READ, name)`, transcribed as that
//!   expansion.
//! * `X509_load_crl_file` (`:172-230`) — the CRL-file loader. Its PEM arm loops over
//!   `PEM_read_bio_X509_CRL`; its ASN.1 arm is one `d2i_X509_CRL_bio`.
//! * `X509_load_cert_crl_file_ex` (`:232-279`) and its wrapper `X509_load_cert_crl_file`
//!   (`:281-284`) — the mixed loader. A non-PEM `type` is handed to `X509_load_cert_file_ex`;
//!   otherwise `PEM_X509_INFO_read_bio_ex` reads the bundle into a `STACK_OF(X509_INFO)` and each
//!   record's certificate and CRL are added to the lookup's store.
//!
//! ## The raise sites
//!
//! `crypto/x509/by_file.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the
//! seventeen coordinates the landed loaders reach are **declared locally** in the
//! `err_sites::ErrSite` shape (as `v3_addr.rs` does). Their reason values are read from
//! `include/openssl/err.h.in` (the `ERR_R_*` commons) and the generated `x509err.h`/`pemerr.h`
//! (the `X509_R_*`/`PEM_R_*` rows cited on each constant): `ERR_R_PASSED_NULL_PARAMETER` is
//! `258 | ERR_R_FATAL` = 786690, `ERR_R_BIO_LIB` is `ERR_LIB_BIO (2) | ERR_RFLAG_COMMON`, and
//! both `ERR_R_ASN1_LIB` (`ERR_LIB_ASN1 (13)`) and `ERR_R_PEM_LIB` (`ERR_LIB_PEM (9)`) are the
//! same `| ERR_RFLAG_COMMON`. The `by_file_ctrl_ex` raise at `:68` is reachable only from a
//! withheld name, so no coordinate is declared for it.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::ptr;

use crate::asn1::x_info::{X509Info, X509_INFO_free};
use crate::pem::pem_all::PEM_read_bio_X509_CRL;
use crate::pem::pem_info::PEM_X509_INFO_read_bio_ex;
use crate::pem::pem_xaux::PEM_read_bio_X509_AUX;
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_s_file};
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_CLOSE, BIO_C_SET_FILENAME, BIO_FP_READ};
use crate::runtime::err::err_reasons::{
    PEM_R_NO_START_LINE, X509_R_BAD_X509_FILETYPE, X509_R_NO_CERTIFICATE_FOUND,
    X509_R_NO_CERTIFICATE_OR_CRL_FOUND, X509_R_NO_CRL_FOUND,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{
    peek_last_reason, raise_site, ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark,
    ERR_set_mark,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::x509_lu::{X509Lookup, X509_STORE_add_cert, X509_STORE_add_crl};
use crate::x509::x_all::{d2i_X509_CRL_bio, d2i_X509_bio};
use crate::x509::x_crl::{X509Crl, X509_CRL_free};
use crate::x509::x_x509::{X509_free, X509_new_ex, X509};

/// `X509_FILETYPE_PEM` — `include/openssl/x509.h.in:70`.
const X509_FILETYPE_PEM: c_int = 1;
/// `X509_FILETYPE_ASN1` — `include/openssl/x509.h.in:71`.
const X509_FILETYPE_ASN1: c_int = 2;

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BIO_LIB` — `include/openssl/err.h.in:326`, `ERR_LIB_BIO (2) | ERR_RFLAG_COMMON`.
const ERR_R_BIO_LIB: c_int = 524290;
/// `ERR_R_PEM_LIB` — `include/openssl/err.h.in:325`, `ERR_LIB_PEM (9) | ERR_RFLAG_COMMON`.
const ERR_R_PEM_LIB: c_int = 524297;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in:328`, `ERR_LIB_ASN1 (13) | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// One `by_file.c` raise coordinate, declared locally (see the module doc).
const fn by_file_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/by_file.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_load_cert_file_ex`'s NULL `file` at `by_file.c:98` (`ERR_R_PASSED_NULL_PARAMETER`).
const BY_FILE_98: ErrSite =
    by_file_site(98, c"X509_load_cert_file_ex", ERR_R_PASSED_NULL_PARAMETER);
/// The same function's failed BIO/`BIO_read_filename` at `by_file.c:105` (`ERR_R_BIO_LIB`).
const BY_FILE_105: ErrSite = by_file_site(105, c"X509_load_cert_file_ex", ERR_R_BIO_LIB);
/// The same function's failed `X509_new_ex` at `by_file.c:111` (`ERR_R_ASN1_LIB`).
const BY_FILE_111: ErrSite = by_file_site(111, c"X509_load_cert_file_ex", ERR_R_ASN1_LIB);
/// The same function's empty PEM bundle at `by_file.c:125` (`X509_R_NO_CERTIFICATE_FOUND`,
/// `x509err.h:49`).
const BY_FILE_125: ErrSite =
    by_file_site(125, c"X509_load_cert_file_ex", X509_R_NO_CERTIFICATE_FOUND);
/// The same function's PEM failure after a certificate at `by_file.c:127` (`ERR_R_PEM_LIB`).
const BY_FILE_127: ErrSite = by_file_site(127, c"X509_load_cert_file_ex", ERR_R_PEM_LIB);
/// The same function's failed loop-`X509_new_ex` at `by_file.c:145` (`ERR_R_ASN1_LIB`).
const BY_FILE_145: ErrSite = by_file_site(145, c"X509_load_cert_file_ex", ERR_R_ASN1_LIB);
/// The same function's failed ASN.1 decode at `by_file.c:153` (`X509_R_NO_CERTIFICATE_FOUND`).
const BY_FILE_153: ErrSite =
    by_file_site(153, c"X509_load_cert_file_ex", X509_R_NO_CERTIFICATE_FOUND);
/// The same function's unknown `type` at `by_file.c:158` (`X509_R_BAD_X509_FILETYPE`,
/// `x509err.h:24`).
const BY_FILE_158: ErrSite = by_file_site(158, c"X509_load_cert_file_ex", X509_R_BAD_X509_FILETYPE);
/// `X509_load_crl_file`'s NULL `file` at `by_file.c:179` (`ERR_R_PASSED_NULL_PARAMETER`).
const BY_FILE_179: ErrSite = by_file_site(179, c"X509_load_crl_file", ERR_R_PASSED_NULL_PARAMETER);
/// The same function's failed BIO/`BIO_read_filename` at `by_file.c:185` (`ERR_R_BIO_LIB`).
const BY_FILE_185: ErrSite = by_file_site(185, c"X509_load_crl_file", ERR_R_BIO_LIB);
/// The same function's empty PEM bundle at `by_file.c:199` (`X509_R_NO_CRL_FOUND`,
/// `x509err.h:52`).
const BY_FILE_199: ErrSite = by_file_site(199, c"X509_load_crl_file", X509_R_NO_CRL_FOUND);
/// The same function's PEM failure after a CRL at `by_file.c:201` (`ERR_R_PEM_LIB`).
const BY_FILE_201: ErrSite = by_file_site(201, c"X509_load_crl_file", ERR_R_PEM_LIB);
/// The same function's failed ASN.1 decode at `by_file.c:218` (`X509_R_NO_CRL_FOUND`).
const BY_FILE_218: ErrSite = by_file_site(218, c"X509_load_crl_file", X509_R_NO_CRL_FOUND);
/// The same function's unknown `type` at `by_file.c:223` (`X509_R_BAD_X509_FILETYPE`).
const BY_FILE_223: ErrSite = by_file_site(223, c"X509_load_crl_file", X509_R_BAD_X509_FILETYPE);
/// `X509_load_cert_crl_file_ex`'s failed `BIO_new_file` at `by_file.c:248` (`ERR_R_BIO_LIB`).
const BY_FILE_248: ErrSite = by_file_site(248, c"X509_load_cert_crl_file_ex", ERR_R_BIO_LIB);
/// The same function's failed `PEM_X509_INFO_read_bio_ex` at `by_file.c:254` (`ERR_R_PEM_LIB`).
const BY_FILE_254: ErrSite = by_file_site(254, c"X509_load_cert_crl_file_ex", ERR_R_PEM_LIB);
/// The same function's empty bundle at `by_file.c:275` (`X509_R_NO_CERTIFICATE_OR_CRL_FOUND`,
/// `x509err.h:50`).
const BY_FILE_275: ErrSite = by_file_site(
    275,
    c"X509_load_cert_crl_file_ex",
    X509_R_NO_CERTIFICATE_OR_CRL_FOUND,
);

/// The `X509_INFO` destructor [`X509_load_cert_crl_file_ex`] passes to `OPENSSL_sk_pop_free`.
///
/// # Safety
///
/// `elem` must be NULL or a record the PEM bundle reader allocated.
unsafe extern "C" fn x509_info_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a record per the contract; `X509_INFO_free` accepts NULL.
    unsafe { X509_INFO_free(elem.cast::<X509Info>()) };
}

/// `int X509_load_cert_file_ex(X509_LOOKUP *ctx, const char *file, int type, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/x509/by_file.c:90-165`.
///
/// Reads one certificate file into `ctx`'s store and answers how many certificates were added (a
/// failure answers 0). A PEM file is read block by block through `PEM_read_bio_X509_AUX` until the
/// reader reports `PEM_R_NO_START_LINE` after at least one certificate; an ASN.1 file is one
/// `d2i_X509_bio`. Because `X509_STORE_add_cert` takes a reference rather than a copy, each PEM
/// iteration allocates a fresh `X509` for the reader.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP` whose store is live; `file` must be NULL or NUL-terminated;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_load_cert_file_ex(
    ctx: *mut X509Lookup,
    file: *const c_char,
    type_: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut in_: *mut Bio = ptr::null_mut();
    let mut count: c_int = 0;
    let mut x: *mut X509 = ptr::null_mut();

    // `err:` in the authority; every `goto err` leaves the block with `count` set as the
    // authority leaves it, and the shared epilogue below runs exactly once.
    'err: {
        if file.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_98) };
            break 'err;
        }

        // SAFETY: `BIO_s_file` answers a static method table.
        in_ = unsafe { BIO_new(BIO_s_file()) };

        // `BIO_read_filename(in, file)` is the macro `BIO_ctrl(in, BIO_C_SET_FILENAME,
        // BIO_CLOSE | BIO_FP_READ, (char *)file)`.
        if in_.is_null()
            // SAFETY: the left arm short-circuits on NULL, so `in_` is a fresh file BIO here, and
            // `file` is NUL-terminated per the contract.
            || unsafe {
                BIO_ctrl(
                    in_,
                    BIO_C_SET_FILENAME,
                    c_long::from(BIO_CLOSE | BIO_FP_READ),
                    file.cast_mut().cast::<c_void>(),
                )
            } <= 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_105) };
            break 'err;
        }

        // SAFETY: `libctx`/`propq` are forwarded under the caller's contract.
        x = unsafe { X509_new_ex(libctx, propq) };
        if x.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_111) };
            break 'err;
        }

        if type_ == X509_FILETYPE_PEM {
            loop {
                ERR_set_mark();
                // SAFETY: `in_` is live; the reader takes a slot the frame owns.
                if unsafe {
                    PEM_read_bio_X509_AUX(
                        in_,
                        &raw mut x,
                        None,
                        c"".as_ptr().cast_mut().cast::<c_void>(),
                    )
                }
                .is_null()
                {
                    if peek_last_reason() as c_long == PEM_R_NO_START_LINE as c_long && count > 0 {
                        ERR_pop_to_mark();
                        break;
                    } else {
                        ERR_clear_last_mark();
                        if count == 0 {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&BY_FILE_125) };
                        } else {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&BY_FILE_127) };
                            count = 0;
                        }
                        break 'err;
                    }
                }
                ERR_clear_last_mark();

                // SAFETY: `ctx` is live with a live store per the contract; `x` is a live
                // certificate.
                if unsafe { X509_STORE_add_cert((*ctx).store_ctx, x) } == 0 {
                    count = 0;
                    break 'err;
                }
                // `X509_STORE_add_cert` added a reference rather than a copy, so the reader
                // needs a fresh `X509` for its next block.
                // SAFETY: `x` was this call's own certificate until the add up-ref'd it.
                unsafe { X509_free(x) };
                // SAFETY: `libctx`/`propq` are forwarded under the caller's contract.
                x = unsafe { X509_new_ex(libctx, propq) };
                if x.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&BY_FILE_145) };
                    count = 0;
                    break 'err;
                }
                count += 1;
            }
        } else if type_ == X509_FILETYPE_ASN1 {
            // SAFETY: `in_` is a live file BIO and `x` is a slot this frame owns.
            if unsafe { d2i_X509_bio(in_, &raw mut x) }.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BY_FILE_153) };
                break 'err;
            }
            // SAFETY: `ctx` is live with a live store; `x` is the decoded certificate.
            count = unsafe { X509_STORE_add_cert((*ctx).store_ctx, x) };
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_158) };
            break 'err;
        }
    }

    // SAFETY: `x` is NULL or this call's own certificate; `in_` is NULL or this call's own BIO.
    unsafe {
        X509_free(x);
        BIO_free(in_);
    }
    count
}

/// `int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type)` —
/// `crypto/x509/by_file.c:167-170`.
///
/// [`X509_load_cert_file_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_load_cert_file_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_load_cert_file(
    ctx: *mut X509Lookup,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    // SAFETY: the contract is `X509_load_cert_file_ex`'s with NULL libctx/propq.
    unsafe { X509_load_cert_file_ex(ctx, file, type_, ptr::null_mut(), ptr::null()) }
}

/// `int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)` —
/// `crypto/x509/by_file.c:172-230`.
///
/// Reads one CRL file into `ctx`'s store and answers how many CRLs were added (a failure answers
/// 0). A PEM file is read CRL by CRL through `PEM_read_bio_X509_CRL` until the reader reports
/// `PEM_R_NO_START_LINE` after at least one CRL; an ASN.1 file is one `d2i_X509_CRL_bio`. Unlike
/// the certificate loader, each PEM CRL is decoded into a fresh object, so it is released at the
/// end of every iteration.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP` whose store is live; `file` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_load_crl_file(
    ctx: *mut X509Lookup,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    let mut in_: *mut Bio = ptr::null_mut();
    let mut count: c_int = 0;
    let mut x: *mut X509Crl = ptr::null_mut();

    // `err:` in the authority; see [`X509_load_cert_file_ex`] for the shape.
    'err: {
        if file.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_179) };
            break 'err;
        }

        // SAFETY: `BIO_s_file` answers a static method table.
        in_ = unsafe { BIO_new(BIO_s_file()) };

        // SAFETY: `in_` is NULL or a fresh file BIO; `file` is NUL-terminated per the contract.
        if in_.is_null()
            // SAFETY: the left arm short-circuits on NULL, so `in_` is a fresh file BIO here, and
            // `file` is NUL-terminated per the contract.
            || unsafe {
                BIO_ctrl(
                    in_,
                    BIO_C_SET_FILENAME,
                    c_long::from(BIO_CLOSE | BIO_FP_READ),
                    file.cast_mut().cast::<c_void>(),
                )
            } <= 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_185) };
            break 'err;
        }

        if type_ == X509_FILETYPE_PEM {
            loop {
                // SAFETY: `in_` is a live file BIO; the reader allocates a fresh CRL.
                x = unsafe {
                    PEM_read_bio_X509_CRL(
                        in_,
                        ptr::null_mut(),
                        None,
                        c"".as_ptr().cast_mut().cast::<c_void>(),
                    )
                };
                if x.is_null() {
                    if peek_last_reason() as c_long == PEM_R_NO_START_LINE as c_long && count > 0 {
                        ERR_clear_error();
                        break;
                    } else {
                        if count == 0 {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&BY_FILE_199) };
                        } else {
                            // SAFETY: a compile-time-constant site.
                            unsafe { raise_site(&BY_FILE_201) };
                            count = 0;
                        }
                        break 'err;
                    }
                }
                // SAFETY: `ctx` is live with a live store per the contract; `x` is a live CRL.
                if unsafe { X509_STORE_add_crl((*ctx).store_ctx, x) } == 0 {
                    count = 0;
                    break 'err;
                }
                count += 1;
                // SAFETY: `x` was this call's own CRL until the add up-ref'd it. The reader
                // allocates a fresh CRL each pass, so `x` is reassigned before it is read again;
                // on the terminating NULL read it is already NULL for the epilogue.
                unsafe { X509_CRL_free(x) };
            }
        } else if type_ == X509_FILETYPE_ASN1 {
            // SAFETY: `in_` is a live file BIO.
            x = unsafe { d2i_X509_CRL_bio(in_, ptr::null_mut()) };
            if x.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BY_FILE_218) };
                break 'err;
            }
            // SAFETY: `ctx` is live with a live store; `x` is the decoded CRL.
            count = unsafe { X509_STORE_add_crl((*ctx).store_ctx, x) };
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_223) };
            break 'err;
        }
    }

    // SAFETY: `x` is NULL or this call's own CRL; `in_` is NULL or this call's own BIO.
    unsafe {
        X509_CRL_free(x);
        BIO_free(in_);
    }
    count
}

/// `int X509_load_cert_crl_file_ex(X509_LOOKUP *ctx, const char *file, int type, OSSL_LIB_CTX
/// *libctx, const char *propq)` — `crypto/x509/by_file.c:232-279`.
///
/// Reads a PEM bundle of certificates and CRLs into `ctx`'s store and answers how many objects
/// were added (a failure answers 0). A non-PEM `type` is handed to
/// [`X509_load_cert_file_ex`], per the authority. Otherwise `PEM_X509_INFO_read_bio_ex` reads the
/// whole file into a `STACK_OF(X509_INFO)`, whose records' certificate and CRL slots (in that
/// order) are each added. An empty bundle raises `X509_R_NO_CERTIFICATE_OR_CRL_FOUND`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP` whose store is live; `file` must be NULL or NUL-terminated;
/// `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_load_cert_crl_file_ex(
    ctx: *mut X509Lookup,
    file: *const c_char,
    type_: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if type_ != X509_FILETYPE_PEM {
        // SAFETY: the contract is `X509_load_cert_file_ex`'s.
        return unsafe { X509_load_cert_file_ex(ctx, file, type_, libctx, propq) };
    }

    let mut count: c_int = 0;

    // The authority's non-Windows arm is `BIO_new_file(file, "r")`.
    // SAFETY: `file` is NULL or NUL-terminated per the contract.
    let in_ = unsafe { BIO_new_file(file, c"r".as_ptr()) };
    if in_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BY_FILE_248) };
        return 0;
    }

    // SAFETY: `in_` is this call's own live BIO; `libctx`/`propq` are the caller's.
    let inf = unsafe {
        PEM_X509_INFO_read_bio_ex(
            in_,
            ptr::null_mut(),
            None,
            c"".as_ptr().cast_mut().cast::<c_void>(),
            libctx,
            propq,
        )
    };
    // SAFETY: `in_` is this call's own BIO and the reader no longer borrows it.
    unsafe { BIO_free(in_) };
    if inf.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BY_FILE_254) };
        return 0;
    }

    'err: {
        // SAFETY: `inf` is a live stack of `X509_INFO` records this call owns.
        for i in 0..unsafe { OPENSSL_sk_num(inf) } {
            // SAFETY: `inf` is live and `i` is in range.
            let itmp = unsafe { OPENSSL_sk_value(inf, i) }.cast::<X509Info>();
            // SAFETY: `itmp` is a live record on the stack.
            if !unsafe { (*itmp).x509 }.is_null() {
                // SAFETY: `ctx` is live with a live store; the record's certificate is live.
                if unsafe { X509_STORE_add_cert((*ctx).store_ctx, (*itmp).x509) } == 0 {
                    count = 0;
                    break 'err;
                }
                count += 1;
            }
            // SAFETY: `itmp` is a live record on the stack.
            if !unsafe { (*itmp).crl }.is_null() {
                // SAFETY: `ctx` is live with a live store; the record's CRL is live.
                if unsafe { X509_STORE_add_crl((*ctx).store_ctx, (*itmp).crl) } == 0 {
                    count = 0;
                    break 'err;
                }
                count += 1;
            }
        }
        if count == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_FILE_275) };
        }
    }

    // SAFETY: `inf` is this call's own stack and every record on it; the thunk handles NULL.
    unsafe { OPENSSL_sk_pop_free(inf, Some(x509_info_free_thunk)) };
    count
}

/// `int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type)` —
/// `crypto/x509/by_file.c:281-284`.
///
/// [`X509_load_cert_crl_file_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_load_cert_crl_file_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_load_cert_crl_file(
    ctx: *mut X509Lookup,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    // SAFETY: the contract is `X509_load_cert_crl_file_ex`'s with NULL libctx/propq.
    unsafe { X509_load_cert_crl_file_ex(ctx, file, type_, ptr::null_mut(), ptr::null()) }
}
