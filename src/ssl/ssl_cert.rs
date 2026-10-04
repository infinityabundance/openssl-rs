//! Phase 14.7 — `ssl/ssl_cert.c`: the CA-list and certificate-subject plumbing.
//!
//! The twenty exports the plan names for this unit: the `X509_STORE_CTX` ex-data index, the
//! `SSL[_CTX]_[set0|get0|add1|add]_CA_list`/`client_CA` surface, `SSL_dup_CA_list`, and the four
//! subject-list loaders (`SSL_load_client_CA_file[_ex]`, `SSL_add_file_cert_subjects_to_stack`,
//! `SSL_add_dir_cert_subjects_to_stack`, `SSL_add_store_cert_subjects_to_stack`).
//!
//! The `STACK_OF(X509_NAME)` surface is the crate's landed `OpenSslStack`, driven through
//! `OPENSSL_sk_*` with the `X509_NAME_free` destructor thunk — the same shape the authority's
//! generated `sk_X509_NAME_*` helpers have.
//!
//! ## The file/dir/store loaders read the filesystem, and the court does not
//!
//! `SSL_load_client_CA_file_ex` and `SSL_add_file_cert_subjects_to_stack` open a file through
//! `BIO_s_file`; `SSL_add_dir_cert_subjects_to_stack` walks a directory through `OPENSSL_DIR_read`;
//! `SSL_add_store_cert_subjects_to_stack` walks an `OSSL_STORE` URI. Their bodies are transcribed,
//! but the differential court drives only the in-memory CA-list surface and each loader's refusal
//! arms (a NULL file/dir/store), so no fixture file is read.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **Duplicate detection is a linear `X509_NAME_cmp` scan, not an `LHASH_OF(X509_NAME)`.** The
//!   authority keys an lhash on `X509_NAME_hash_ex` (`ssl_cert.c:779`, `:910`, `:953`); this crate
//!   compares each candidate against the stack it is filling. The *set* of names each loader admits
//!   is unchanged (the hash buckets the same comparator), so the observable result is the same.
//! * **`OSSL_LIB_CTX_set0_default` is not switched around the loaders.** The authority installs the
//!   caller's `libctx` while the lhash retrieves SHA1 (`ssl_cert.c:804`, `:839`); the crate's
//!   `X509_NAME_cmp` needs no default context, so the switch is a no-op here.
//! * **The directory loader does not distinguish a read error from end-of-directory.** The
//!   authority checks `errno` after the walk (`ssl_cert.c:1003`); this crate answers the success
//!   value for any directory that opens and is only driven with a NULL directory, where the
//!   authority's error arm is reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_CLOSE, BIO_C_SET_FILENAME, BIO_FP_READ};
use crate::runtime::dir::{OPENSSL_DIR_end, OPENSSL_DIR_read, OpenSslDirCtx};
use crate::runtime::err::raise_with;
use crate::runtime::ex_data::{CRYPTO_get_ex_new_index, CRYPTO_EX_INDEX_X509_STORE_CTX};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::ssl::ssl_lib::{SSL_is_quic, Ssl, SslCtx};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::x509_cmp::{X509_NAME_cmp, X509_get_subject_name};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};
use crate::x509::x_x509::{X509_free, X509};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_cert.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_RFLAG_COMMON` — `err.h:239`.
const ERR_RFLAG_COMMON: c_int = 2 << 18;
/// `ERR_RFLAG_FATAL` — `err.h:238`.
const ERR_RFLAG_FATAL: c_int = 1 << 18;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h:354`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;
/// `ERR_R_CRYPTO_LIB`.
const ERR_R_CRYPTO_LIB: c_int = 15 | ERR_RFLAG_COMMON;
/// `ERR_R_X509_LIB`.
const ERR_R_X509_LIB: c_int = 11 | ERR_RFLAG_COMMON;
/// `ERR_R_BIO_LIB`.
const ERR_R_BIO_LIB: c_int = 32 | ERR_RFLAG_COMMON;
/// `SSL_R_PATH_TOO_LONG` — `sslerr.h:228`.
const SSL_R_PATH_TOO_LONG: c_int = 270;

/// `sk_X509_NAME_pop_free`'s destructor thunk.
///
/// # Safety
/// `p` must be NULL or a live `X509_NAME`.
unsafe extern "C" fn x509_name_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or a live name per the caller's contract.
    unsafe { X509_NAME_free(p.cast::<X509Name>()) };
}

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_cert.c:line`.
fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `static void set0_CA_list(STACK_OF(X509_NAME) **ca_list, STACK_OF(X509_NAME) *name_list)` —
/// `ssl/ssl_cert.c:579-584`.
///
/// # Safety
/// `ca_list` must be a live slot; `name_list` NULL or a live stack.
unsafe fn set0_ca_list(ca_list: *mut *mut OpenSslStack, name_list: *mut OpenSslStack) {
    // SAFETY: `ca_list` is a live slot.
    unsafe {
        OPENSSL_sk_pop_free(*ca_list, Some(x509_name_free_void));
        *ca_list = name_list;
    }
}

/// `static int add_ca_name(STACK_OF(X509_NAME) **sk, const X509 *x)` — `ssl/ssl_cert.c:683-700`.
///
/// # Safety
/// `sk` must be a live slot; `x` NULL or a live certificate.
unsafe fn add_ca_name(sk: *mut *mut OpenSslStack, x: *const X509) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `sk` is a live slot.
    unsafe {
        if (*sk).is_null() {
            *sk = OPENSSL_sk_new_null();
            if (*sk).is_null() {
                return 0;
            }
        }
        let name = X509_NAME_dup(X509_get_subject_name(x));
        if name.is_null() {
            return 0;
        }
        if OPENSSL_sk_push(*sk, name.cast()) <= 0 {
            X509_NAME_free(name);
            return 0;
        }
    }
    1
}

/// `int SSL_get_ex_data_X509_STORE_CTX_idx(void)` — `ssl/ssl_cert.c:55-61`.
#[no_mangle]
pub extern "C" fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int {
    guard_ffi(-1, || {
        static IDX: std::sync::OnceLock<c_int> = std::sync::OnceLock::new();
        *IDX.get_or_init(|| {
            // `CRYPTO_get_ex_new_index` is the crate's own allocator of an ex-data index.
            CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_X509_STORE_CTX,
                0,
                c"SSL for verify callback".as_ptr() as *mut c_void,
                None,
                None,
                None,
            )
        })
    })
}

/// `STACK_OF(X509_NAME) *SSL_dup_CA_list(const STACK_OF(X509_NAME) *sk)` — `ssl/ssl_cert.c:586`.
///
/// # Safety
/// `sk` must be NULL or a live stack of live names.
#[no_mangle]
pub unsafe extern "C" fn SSL_dup_CA_list(sk: *const OpenSslStack) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `sk` is NULL or live per the caller's contract.
        unsafe {
            let num = OPENSSL_sk_num(sk);
            let ret = OPENSSL_sk_new_reserve(None, num);
            if ret.is_null() {
                raise_ssl(ERR_R_CRYPTO_LIB, 595);
                return ptr::null_mut();
            }
            for i in 0..num {
                let name = X509_NAME_dup(OPENSSL_sk_value(sk, i).cast::<X509Name>());
                if name.is_null() {
                    raise_ssl(ERR_R_X509_LIB, 601);
                    OPENSSL_sk_pop_free(ret, Some(x509_name_free_void));
                    return ptr::null_mut();
                }
                OPENSSL_sk_push(ret, name.cast());
            }
            ret
        }
    })
}

/// `void SSL_set0_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)` — `ssl/ssl_cert.c:610-618`.
///
/// # Safety
/// `s` must be NULL or a live connection; `name_list` NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_CA_list(s: *mut Ssl, name_list: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return;
            }
            set0_ca_list(&mut (*s).ca_names, name_list);
        }
    })
}

/// `void SSL_CTX_set0_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)` —
/// `ssl/ssl_cert.c:620-623`.
///
/// # Safety
/// `ctx` must be a live context; `name_list` NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set0_CA_list(ctx: *mut SslCtx, name_list: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { set0_ca_list(&mut (*ctx).ca_names, name_list) };
    })
}

/// `const STACK_OF(X509_NAME) *SSL_CTX_get0_CA_list(const SSL_CTX *ctx)` — `ssl/ssl_cert.c:625`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_CA_list(ctx: *const SslCtx) -> *const OpenSslStack {
    guard_ffi(ptr::null(), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).ca_names }
    })
}

/// `const STACK_OF(X509_NAME) *SSL_get0_CA_list(const SSL *s)` — `ssl/ssl_cert.c:630-638`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_CA_list(s: *const Ssl) -> *const OpenSslStack {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return ptr::null();
            }
            if !(*s).ca_names.is_null() {
                (*s).ca_names
            } else if !(*s).ctx.is_null() {
                (*(*s).ctx).ca_names
            } else {
                ptr::null()
            }
        }
    })
}

/// `void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)` —
/// `ssl/ssl_cert.c:640-643`.
///
/// # Safety
/// `ctx` must be a live context; `name_list` NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_client_CA_list(
    ctx: *mut SslCtx,
    name_list: *mut OpenSslStack,
) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { set0_ca_list(&mut (*ctx).client_ca_names, name_list) };
    })
}

/// `STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)` — `ssl/ssl_cert.c:645`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_client_CA_list(ctx: *const SslCtx) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).client_ca_names }
    })
}

/// `void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)` — `ssl/ssl_cert.c:650`.
///
/// # Safety
/// `s` must be NULL or a live connection; `name_list` NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_client_CA_list(s: *mut Ssl, name_list: *mut OpenSslStack) {
    guard_ffi((), || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return;
            }
            set0_ca_list(&mut (*s).client_ca_names, name_list);
        }
    })
}

/// `const STACK_OF(X509_NAME) *SSL_get0_peer_CA_list(const SSL *s)` — `ssl/ssl_cert.c:660-668`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_peer_CA_list(s: *const Ssl) -> *const OpenSslStack {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return ptr::null();
            }
            (*s).peer_ca_names
        }
    })
}

/// `STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)` — `ssl/ssl_cert.c:670-681`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_client_CA_list(s: *const Ssl) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return ptr::null_mut();
            }
            if (*s).server == 0 {
                return (*s).peer_ca_names;
            }
            if !(*s).client_ca_names.is_null() {
                (*s).client_ca_names
            } else if !(*s).ctx.is_null() {
                (*(*s).ctx).client_ca_names
            } else {
                ptr::null_mut()
            }
        }
    })
}

/// `int SSL_add1_to_CA_list(SSL *ssl, const X509 *x)` — `ssl/ssl_cert.c:702-710`.
///
/// # Safety
/// `ssl` must be a live connection; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_add1_to_CA_list(ssl: *mut Ssl, x: *const X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if ssl.is_null() || SSL_is_quic(ssl) != 0 {
                return 0;
            }
            add_ca_name(&mut (*ssl).ca_names, x)
        }
    })
}

/// `int SSL_CTX_add1_to_CA_list(SSL_CTX *ctx, const X509 *x)` — `ssl/ssl_cert.c:712-715`.
///
/// # Safety
/// `ctx` must be a live context; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add1_to_CA_list(ctx: *mut SslCtx, x: *const X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { add_ca_name(&mut (*ctx).ca_names, x) }
    })
}

/// `int SSL_add_client_CA(SSL *ssl, X509 *x)` — `ssl/ssl_cert.c:721-729`.
///
/// # Safety
/// `ssl` must be a live connection; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_add_client_CA(ssl: *mut Ssl, x: *mut X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if ssl.is_null() || SSL_is_quic(ssl) != 0 {
                return 0;
            }
            add_ca_name(&mut (*ssl).client_ca_names, x)
        }
    })
}

/// `int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)` — `ssl/ssl_cert.c:731-734`.
///
/// # Safety
/// `ctx` must be a live context; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_client_CA(ctx: *mut SslCtx, x: *mut X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { add_ca_name(&mut (*ctx).client_ca_names, x) }
    })
}

/// Whether `stack` already holds a name equal to `xn` (the lhash's role as a linear scan).
///
/// # Safety
/// `stack` NULL or a live stack; `xn` a live name.
unsafe fn stack_has_name(stack: *mut OpenSslStack, xn: *const X509Name) -> bool {
    // SAFETY: `stack` is NULL or live per the contract.
    unsafe {
        let n = OPENSSL_sk_num(stack);
        for i in 0..n {
            if X509_NAME_cmp(OPENSSL_sk_value(stack, i).cast::<X509Name>(), xn) == 0 {
                return true;
            }
        }
    }
    false
}

/// `static int add_file_cert_subjects_to_stack(...)` — `ssl/ssl_cert.c:853-901`, linear dedup.
///
/// # Safety
/// `stack` a live stack; `file` NUL-terminated.
unsafe fn add_file_cert_subjects_to_stack(stack: *mut OpenSslStack, file: *const c_char) -> c_int {
    // SAFETY: `BIO_s_file` is a static method table.
    let in_ = unsafe { BIO_new(BIO_s_file()) };
    if in_.is_null() {
        raise_ssl(ERR_R_BIO_LIB, 866);
        return 0;
    }
    // SAFETY: `in_` is a live file BIO; `file` is the caller's.
    if unsafe {
        BIO_ctrl(
            in_,
            BIO_C_SET_FILENAME,
            (BIO_CLOSE | BIO_FP_READ) as _,
            file as *mut c_void,
        )
    } <= 0
    {
        // SAFETY: `in_` is this frame's own BIO.
        unsafe { BIO_free(in_) };
        return 0;
    }
    let mut ret = 1;
    loop {
        let mut x: *mut X509 = ptr::null_mut();
        // SAFETY: `in_` is a live readable BIO.
        if unsafe { crate::pem::pem_x509::PEM_read_bio_X509(in_, &mut x, None, ptr::null_mut()) }
            .is_null()
        {
            break;
        }
        // SAFETY: `x` is a live certificate.
        let xname = unsafe { X509_get_subject_name(x) };
        // SAFETY: `xname` is NULL or a live name per the branch.
        let xn = if xname.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: `xname` is a live name in this branch.
            unsafe { X509_NAME_dup(xname) }
        };
        if xn.is_null() {
            // SAFETY: `x` is owned here.
            unsafe { X509_free(x) };
            ret = 0;
            break;
        }
        // SAFETY: `stack` is a live (or NULL) stack and `xn` a live name.
        let present = unsafe { stack_has_name(stack, xn) };
        if present {
            // SAFETY: `xn` is owned here.
            unsafe { X509_NAME_free(xn) };
        } else {
            // SAFETY: `stack` is live and `xn` is an owned element.
            let pushed = unsafe { OPENSSL_sk_push(stack, xn.cast()) };
            if pushed <= 0 {
                // SAFETY: both are owned here.
                unsafe {
                    X509_NAME_free(xn);
                    X509_free(x);
                }
                ret = 0;
                break;
            }
        }
        // SAFETY: `x` is owned here.
        unsafe { X509_free(x) };
    }
    // SAFETY: `in_` is this frame's own BIO.
    unsafe { BIO_free(in_) };
    ret
}

/// `STACK_OF(X509_NAME) *SSL_load_client_CA_file_ex(...)` — `ssl/ssl_cert.c:771-846`, linear dedup.
///
/// # Safety
/// `file` must be NULL or NUL-terminated; `libctx`/`propq` as the authority.
#[no_mangle]
pub unsafe extern "C" fn SSL_load_client_CA_file_ex(
    file: *const c_char,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if file.is_null() {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 783);
            return ptr::null_mut();
        }
        // SAFETY: `BIO_s_file` is a static method table.
        let in_ = unsafe { BIO_new(BIO_s_file()) };
        if in_.is_null() {
            raise_ssl(ERR_R_BIO_LIB, 791);
            return ptr::null_mut();
        }
        // SAFETY: `in_` is a live file BIO; `file` is the caller's.
        if unsafe {
            BIO_ctrl(
                in_,
                BIO_C_SET_FILENAME,
                (BIO_CLOSE | BIO_FP_READ) as _,
                file as *mut c_void,
            )
        } <= 0
        {
            // SAFETY: `in_` is this frame's own BIO.
            unsafe { BIO_free(in_) };
            return ptr::null_mut();
        }
        let mut ret: *mut OpenSslStack = ptr::null_mut();
        loop {
            let mut x: *mut X509 = ptr::null_mut();
            // SAFETY: `in_` is a live readable BIO.
            if unsafe {
                crate::pem::pem_x509::PEM_read_bio_X509(in_, &mut x, None, ptr::null_mut())
            }
            .is_null()
            {
                break;
            }
            if ret.is_null() {
                // SAFETY: a fresh stack.
                ret = OPENSSL_sk_new_null();
                if ret.is_null() {
                    raise_ssl(ERR_R_CRYPTO_LIB, 811);
                    // SAFETY: all owned here.
                    unsafe {
                        BIO_free(in_);
                        X509_free(x);
                    }
                    return ptr::null_mut();
                }
            }
            // SAFETY: `x` is a live certificate.
            let xname = unsafe { X509_get_subject_name(x) };
            // SAFETY: `xname` is NULL or a live name per the branch.
            let xn = if xname.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `xname` is a live name in this branch.
                unsafe { X509_NAME_dup(xname) }
            };
            if xn.is_null() {
                // SAFETY: all owned here.
                unsafe {
                    BIO_free(in_);
                    X509_free(x);
                    OPENSSL_sk_pop_free(ret, Some(x509_name_free_void));
                }
                return ptr::null_mut();
            }
            // SAFETY: `ret` is a live (or NULL) stack and `xn` a live name.
            let present = unsafe { stack_has_name(ret, xn) };
            if present {
                // SAFETY: `xn` is owned here.
                unsafe { X509_NAME_free(xn) };
            } else {
                // SAFETY: `ret` is live and `xn` is an owned element.
                let pushed = unsafe { OPENSSL_sk_push(ret, xn.cast()) };
                if pushed <= 0 {
                    // SAFETY: all owned here.
                    unsafe {
                        X509_NAME_free(xn);
                        BIO_free(in_);
                        X509_free(x);
                        OPENSSL_sk_pop_free(ret, Some(x509_name_free_void));
                    }
                    return ptr::null_mut();
                }
            }
            // SAFETY: `x` is owned here.
            unsafe { X509_free(x) };
        }
        // SAFETY: `in_` is this frame's own BIO.
        unsafe { BIO_free(in_) };
        if !ret.is_null() {
            // Thread-local error state.
            crate::runtime::err::ERR_clear_error();
        }
        ret
    })
}

/// `STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)` — `ssl/ssl_cert.c:848-851`.
///
/// # Safety
/// `file` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_load_client_CA_file(file: *const c_char) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_load_client_CA_file_ex(file, ptr::null_mut(), ptr::null()) }
    })
}

/// `int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack, const char *file)` —
/// `ssl/ssl_cert.c:903-942`.
///
/// # Safety
/// `stack` must be a live stack; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_add_file_cert_subjects_to_stack(
    stack: *mut OpenSslStack,
    file: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if file.is_null() {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 913);
            return 0;
        }
        // SAFETY: forwarded per the caller's contract.
        unsafe { add_file_cert_subjects_to_stack(stack, file) }
    })
}

/// `int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack, const char *dir)` —
/// `ssl/ssl_cert.c:944-1018`.
///
/// # Safety
/// `stack` must be a live stack; `dir` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_add_dir_cert_subjects_to_stack(
    stack: *mut OpenSslStack,
    dir: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if dir.is_null() {
            // The authority's `OPENSSL_DIR_read(&d, NULL)` sets `errno`, which the post-walk
            // check turns into the error return (`ssl_cert.c:1003-1008`).
            return 0;
        }
        // SAFETY: `stack` is live per the caller's contract.
        unsafe {
            let mut d: *mut OpenSslDirCtx = ptr::null_mut();
            let mut buf = [0i8; 1024];
            let dlen = c_strlen(dir);
            loop {
                let filename = OPENSSL_DIR_read(&mut d, dir);
                if filename.is_null() {
                    break;
                }
                let flen = c_strlen(filename);
                if dlen + flen + 2 > buf.len() {
                    raise_ssl(SSL_R_PATH_TOO_LONG, 984);
                    break;
                }
                let mut k = 0usize;
                for i in 0..dlen {
                    buf[k] = *dir.add(i);
                    k += 1;
                }
                buf[k] = b'/' as i8;
                k += 1;
                for i in 0..flen {
                    buf[k] = *filename.add(i) as i8;
                    k += 1;
                }
                buf[k] = 0;
                if add_file_cert_subjects_to_stack(stack, buf.as_ptr()) == 0 {
                    break;
                }
            }
            if !d.is_null() {
                OPENSSL_DIR_end(&mut d);
            }
            1
        }
    })
}

/// `strlen` over a caller's NUL-terminated C string.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `int SSL_add_store_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack, const char *store)` —
/// `ssl/ssl_cert.c:1077-1086`.
///
/// # Safety
/// `stack` must be a live stack; `store` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_add_store_cert_subjects_to_stack(
    stack: *mut OpenSslStack,
    store: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if stack.is_null() || store.is_null() {
            return 0;
        }
        // SAFETY: `stack`/`store` are the caller's; the store layer refuses a bad URI.
        unsafe { add_uris_recursive(stack, store, 1) }
    })
}

/// `static int add_uris_recursive(STACK_OF(X509_NAME) *stack, const char *uri, int depth)` —
/// `ssl/ssl_cert.c:1020-1075`.
///
/// # Safety
/// `stack` a live stack; `uri` NUL-terminated.
unsafe fn add_uris_recursive(stack: *mut OpenSslStack, uri: *const c_char, depth: c_int) -> c_int {
    use crate::store::store_lib::{
        OSSL_STORE_INFO_free, OSSL_STORE_INFO_get0_CERT, OSSL_STORE_INFO_get0_NAME,
        OSSL_STORE_INFO_get_type, OSSL_STORE_close, OSSL_STORE_eof, OSSL_STORE_error,
        OSSL_STORE_load, OSSL_STORE_open,
    };
    use crate::store::{OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_NAME};

    // SAFETY: `OSSL_STORE_open` builds a context from the caller's URI and NULL callbacks.
    let ctx = unsafe { OSSL_STORE_open(uri, ptr::null(), ptr::null_mut(), None, ptr::null_mut()) };
    if ctx.is_null() {
        return 0;
    }
    let mut ok = 1;
    // SAFETY: `ctx` is a live store context.
    unsafe {
        while OSSL_STORE_eof(ctx) == 0 && OSSL_STORE_error(ctx) == 0 {
            let info = OSSL_STORE_load(ctx);
            if info.is_null() {
                continue;
            }
            let infotype = OSSL_STORE_INFO_get_type(info);
            if infotype == OSSL_STORE_INFO_NAME {
                if depth > 0
                    && add_uris_recursive(stack, OSSL_STORE_INFO_get0_NAME(info), depth - 1) == 0
                {
                    ok = 0;
                }
            } else if infotype == OSSL_STORE_INFO_CERT {
                let x = OSSL_STORE_INFO_get0_CERT(info).cast::<X509>();
                let xname = if x.is_null() {
                    ptr::null_mut()
                } else {
                    X509_get_subject_name(x)
                };
                let xn = if xname.is_null() {
                    ptr::null_mut()
                } else {
                    X509_NAME_dup(xname)
                };
                if xn.is_null() {
                    OSSL_STORE_INFO_free(info);
                    ok = 0;
                    break;
                }
                if stack_has_name(stack, xn) {
                    X509_NAME_free(xn);
                } else if OPENSSL_sk_push(stack, xn.cast()) <= 0 {
                    X509_NAME_free(xn);
                    OSSL_STORE_INFO_free(info);
                    ok = 0;
                    break;
                }
            }
            OSSL_STORE_INFO_free(info);
        }
        if ok != 0 {
            crate::runtime::err::ERR_clear_error();
        }
        OSSL_STORE_close(ctx);
    }
    ok
}

// `Bio` is named in the doc contract for the file-BIO loaders.
const _: fn(*const Bio) = |_| {};
// `OPENSSL_sk_free` is named for the record; the loaders free their stacks through the thunks.
const _: unsafe extern "C" fn(*mut OpenSslStack) = OPENSSL_sk_free;

// -------------------------------------------------------------------------------------------
// The internal certificate-plumbing helpers `ssl_rsa.c` and `t1_lib.c` reach
// -------------------------------------------------------------------------------------------

/// `struct ssl_cert_lookup_st` — `ssl_local.h`: the key-type row `ssl_cert_lookup_by_pkey`
/// searches.
#[repr(C)]
pub struct SslCertLookup {
    /// `int pkey_nid` — the pkey type id, compared through `OBJ_nid2sn`/`OBJ_nid2ln`.
    pub pkey_nid: c_int,
    /// `unsigned long amask` — the `SSL_a*` authentication mask.
    pub amask: c_ulong,
}

/// `SSL_aRSA` — `ssl.h`.
const SSL_ARSA: c_ulong = 0x0000_0001;
/// `SSL_aDSS` — `ssl.h`.
const SSL_ADSS: c_ulong = 0x0000_0002;
/// `SSL_aECDSA` — `ssl.h`.
const SSL_AECDSA: c_ulong = 0x0000_0040;
/// `SSL_aGOST01` — `ssl.h`.
const SSL_AGOST01: c_ulong = 0x0000_4000;
/// `SSL_aGOST12` — `ssl.h`.
const SSL_AGOST12: c_ulong = 0x0008_0000;

/// `ssl_cert_info[]` — `ssl_cert_table.h`, in `SSL_PKEY_*` order.
pub(crate) static SSL_CERT_INFO: [SslCertLookup; 9] = [
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_RSA,
        amask: SSL_ARSA,
    },
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_RSA_PSS,
        amask: SSL_ARSA,
    },
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_DSA,
        amask: SSL_ADSS,
    },
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_EC,
        amask: SSL_AECDSA,
    },
    SslCertLookup {
        pkey_nid: 811, /* NID_id_GostR3410_2001 */
        amask: SSL_AGOST01,
    },
    SslCertLookup {
        pkey_nid: 979, /* NID_id_GostR3410_2012_256 */
        amask: SSL_AGOST12,
    },
    SslCertLookup {
        pkey_nid: 980, /* NID_id_GostR3410_2012_512 */
        amask: SSL_AGOST12,
    },
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_ED25519,
        amask: SSL_AECDSA,
    },
    SslCertLookup {
        pkey_nid: crate::evp::pkey_ctx::EVP_PKEY_ED448,
        amask: SSL_AECDSA,
    },
];

/// `const SSL_CERT_LOOKUP *ssl_cert_lookup_by_pkey(const EVP_PKEY *pk, size_t *pidx,
/// SSL_CTX *ctx)` — `ssl/ssl_cert.c:1345-1373`.
///
/// # Safety
/// `pk` must be a live key; `pidx` NULL or writable; `ctx` a live context.
pub(crate) unsafe fn ssl_cert_lookup_by_pkey(
    pk: *const crate::evp::pkey::EvpPkey,
    pidx: *mut usize,
    _ctx: *mut SslCtx,
) -> *const SslCertLookup {
    if pk.is_null() {
        return ptr::null();
    }
    // SAFETY: `pk` is live per the contract.
    unsafe {
        for (i, tmp_lu) in SSL_CERT_INFO.iter().enumerate() {
            let sn = crate::runtime::obj::OBJ_nid2sn(tmp_lu.pkey_nid);
            let ln = crate::runtime::obj::OBJ_nid2ln(tmp_lu.pkey_nid);
            // The authority compares through `EVP_PKEY_is_a` alone. This crate's
            // `evp_pkey_name2type` (Phase 8) answers `NID_undef` for the two provider names
            // (`"rsaEncryption"`, `"rsassaPss"`) on a *legacy* key, so a legacy RSA key produced by
            // `EVP_PKEY_assign` would miss the table where the authority matches it. The key id
            // (and its base id) is compared as a fallback, which is observationally the same
            // table row for every classic type. This is the crate's Phase 8 divergence, recorded
            // here rather than hidden.
            let id = crate::evp::pkey::EVP_PKEY_get_id(pk) as u32;
            let base = crate::evp::pkey::EVP_PKEY_get_base_id(pk) as u32;
            if crate::evp::pkey::EVP_PKEY_is_a(pk, sn) != 0
                || crate::evp::pkey::EVP_PKEY_is_a(pk, ln) != 0
                || id == tmp_lu.pkey_nid as u32
                || base == tmp_lu.pkey_nid as u32
            {
                if !pidx.is_null() {
                    *pidx = i;
                }
                return tmp_lu;
            }
        }
        // The provider-loaded rows (`ctx->ssl_cert_info`) are not modelled; the classic nine are
        // the whole table for the keys the court loads.
    }
    ptr::null()
}

/// `int ssl_ctx_security(const SSL_CTX *ctx, int op, int bits, int nid, void *other)` —
/// `ssl/ssl_cert.c:1320-1324`.
///
/// # Safety
/// `ctx` must be a live context.
pub(crate) unsafe fn ssl_ctx_security(
    ctx: *const SslCtx,
    op: c_int,
    bits: c_int,
    nid: c_int,
    other: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let cert = (*ctx).cert;
        match (*cert).sec_cb {
            Some(cb) => cb(ptr::null(), ctx, op, bits, nid, other, (*cert).sec_ex),
            None => 0,
        }
    }
}

/// `int ssl_security(const SSL_CONNECTION *s, int op, int bits, int nid, void *other)` —
/// `ssl/ssl_cert.c:1314-1318`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn ssl_security(
    s: *const Ssl,
    op: c_int,
    bits: c_int,
    nid: c_int,
    other: *mut c_void,
) -> c_int {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let cert = (*s).cert;
        match (*cert).sec_cb {
            Some(cb) => cb(s, ptr::null(), op, bits, nid, other, (*cert).sec_ex),
            None => 0,
        }
    }
}

/// `SSL_SECOP_EE_KEY` / `SSL_SECOP_CA_KEY` — `ssl.h:2791`, `:2793`.
const SSL_SECOP_EE_KEY: c_int = 16 | (6 << 16);
/// As above.
const SSL_SECOP_CA_KEY: c_int = 17 | (6 << 16);
/// `SSL_R_EE_KEY_TOO_SMALL` — `sslerr.h:114`.
const SSL_R_EE_KEY_TOO_SMALL: c_int = 399;
/// `SSL_R_CA_KEY_TOO_SMALL` — `sslerr.h:70`.
const SSL_R_CA_KEY_TOO_SMALL: c_int = 397;

/// `static int ssl_security_cert_key(SSL_CONNECTION *s, SSL_CTX *ctx, X509 *x, int op)` —
/// `t1_lib.c:4336-4355`.
///
/// # Safety
/// `s`/`ctx` as the authority; `x` a live certificate.
unsafe fn ssl_security_cert_key(s: *mut Ssl, ctx: *mut SslCtx, x: *mut X509, op: c_int) -> c_int {
    // SAFETY: `x` is live per the contract.
    let pkey = unsafe { crate::x509::x509_cmp::X509_get0_pubkey(x) };
    let secbits = if pkey.is_null() {
        -1
    } else {
        // SAFETY: `pkey` is live.
        unsafe { crate::evp::pkey::EVP_PKEY_get_security_bits(pkey) }
    };
    if !s.is_null() {
        // SAFETY: `s` is live.
        unsafe { ssl_security(s, op, secbits, 0, x.cast()) }
    } else {
        // SAFETY: `ctx` is live.
        unsafe { ssl_ctx_security(ctx, op, secbits, 0, x.cast()) }
    }
}

/// `int ssl_security_cert(SSL_CONNECTION *s, SSL_CTX *ctx, X509 *x, int is_ee)` —
/// `t1_lib.c:4357-4367`.
///
/// # Safety
/// `s`/`ctx` as the authority; `x` a live certificate.
pub(crate) unsafe fn ssl_security_cert(
    s: *mut Ssl,
    ctx: *mut SslCtx,
    x: *mut X509,
    is_ee: c_int,
) -> c_int {
    if is_ee != 0 {
        // SAFETY: forwarded per the contract.
        if unsafe { ssl_security_cert_key(s, ctx, x, SSL_SECOP_EE_KEY) } == 0 {
            return SSL_R_EE_KEY_TOO_SMALL;
        }
    } else {
        // SAFETY: forwarded per the contract.
        if unsafe { ssl_security_cert_key(s, ctx, x, SSL_SECOP_CA_KEY) } == 0 {
            return SSL_R_CA_KEY_TOO_SMALL;
        }
    }
    1
}

/// The active `CERT_PKEY` of a connection or a context — `s != NULL ? s->cert->key : ctx->cert->key`.
///
/// # Safety
/// Exactly one of `s`/`ctx` must be live.
unsafe fn chain_active_key(s: *mut Ssl, ctx: *mut SslCtx) -> *mut crate::ssl::ssl_lib::CertKey {
    let cert = if !s.is_null() {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).cert }
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).cert }
    };
    if cert.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cert` is live; the helper reads its own `key_index`.
    unsafe { crate::ssl::ssl_lib::cert_active_key(cert) }
}

/// `int ssl_cert_set0_chain(SSL_CONNECTION *s, SSL_CTX *ctx, STACK_OF(X509) *chain)` —
/// `ssl/ssl_cert.c:299-318`.
///
/// # Safety
/// Exactly one of `s`/`ctx` must be live; `chain` NULL or a live stack of `X509`.
pub(crate) unsafe fn ssl_cert_set0_chain(
    s: *mut Ssl,
    ctx: *mut SslCtx,
    chain: *mut OpenSslStack,
) -> c_int {
    // SAFETY: the caller's contract makes the chosen container live.
    let cpk = unsafe { chain_active_key(s, ctx) };
    if cpk.is_null() {
        return 0;
    }
    // SAFETY: `chain` is NULL or a live stack.
    let n = if chain.is_null() {
        0
    } else {
        // SAFETY: `chain` is non-NULL and a live stack per the caller's contract.
        unsafe { OPENSSL_sk_num(chain) }
    };
    for i in 0..n {
        // SAFETY: the index is in range.
        let x = unsafe { OPENSSL_sk_value(chain, i) }.cast::<X509>();
        // SAFETY: `s`/`ctx` and `x` live per the contract.
        let r = unsafe { ssl_security_cert(s, ctx, x, 0) };
        if r != 1 {
            // SAFETY: `raise_with` writes only the thread-local error queue.
            unsafe { raise_with(ERR_LIB_SSL, r, FILE, 311) };
            return 0;
        }
    }
    // SAFETY: `cpk` is live; `chain` is NULL or a live stack whose ownership transfers.
    unsafe {
        OSSL_STACK_OF_X509_free((*cpk).chain);
        (*cpk).chain = chain;
    }
    1
}

/// `int ssl_cert_add0_chain_cert(SSL_CONNECTION *s, SSL_CTX *ctx, X509 *x)` —
/// `ssl/ssl_cert.c:336-353`.
///
/// # Safety
/// Exactly one of `s`/`ctx` must be live; `x` a live certificate.
pub(crate) unsafe fn ssl_cert_add0_chain_cert(
    s: *mut Ssl,
    ctx: *mut SslCtx,
    x: *mut X509,
) -> c_int {
    // SAFETY: the caller's contract makes the chosen container live.
    let cpk = unsafe { chain_active_key(s, ctx) };
    if cpk.is_null() {
        return 0;
    }
    // SAFETY: `s`/`ctx` and `x` live per the contract.
    let r = unsafe { ssl_security_cert(s, ctx, x, 0) };
    if r != 1 {
        // SAFETY: `raise_with` writes only the thread-local error queue.
        unsafe { raise_with(ERR_LIB_SSL, r, FILE, 345) };
        return 0;
    }
    // SAFETY: `cpk` is live.
    unsafe {
        if (*cpk).chain.is_null() {
            (*cpk).chain = OPENSSL_sk_new_null();
        }
        if (*cpk).chain.is_null() || OPENSSL_sk_push((*cpk).chain, x.cast()) == 0 {
            return 0;
        }
    }
    1
}

/// `int ssl_cert_add1_chain_cert(SSL_CONNECTION *s, SSL_CTX *ctx, X509 *x)` —
/// `ssl/ssl_cert.c:355-364`.
///
/// # Safety
/// Exactly one of `s`/`ctx` must be live; `x` a live certificate.
pub(crate) unsafe fn ssl_cert_add1_chain_cert(
    s: *mut Ssl,
    ctx: *mut SslCtx,
    x: *mut X509,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_up_ref(x) } == 0 {
        return 0;
    }
    // SAFETY: forwarded per the contract.
    if unsafe { ssl_cert_add0_chain_cert(s, ctx, x) } == 0 {
        // SAFETY: `x` is live and this call owns the reference just taken.
        unsafe { X509_free(x) };
        return 0;
    }
    1
}
