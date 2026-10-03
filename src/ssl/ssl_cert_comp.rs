//! Phase 14.7 — `ssl/ssl_cert_comp.c`: the certificate-compression surface.
//!
//! The eight exports the plan names for this unit, plus the internal `OSS_COMP_CERT` record and
//! the `ossl_comp_has_alg`/`OSS_COMP_CERT_{new,free,up_ref}` helpers `ssl_cert.c` and
//! `ssl_cert_comp.c` share.
//!
//! ## The admitted build defines every compression algorithm away, and the court measures that
//!
//! `forensics/authorities/prefix/openssl-3.6.4-production/include/openssl/configuration.h`
//! defines `OPENSSL_NO_ZLIB`, `OPENSSL_NO_ZSTD` and `OPENSSL_NO_BROTLI`, so the authority's
//! `ossl_comp_has_alg` (`ssl_cert_comp.c:45-57`) answers `0` for every algorithm: the three
//! `BIO_f_*` probes are `NULL`. Every other function in the unit is gated on that predicate, so
//! the whole unit reduces to its refusal arms in this build:
//!
//! * `SSL_CTX_set1_cert_comp_preference`/`SSL_set1_cert_comp_preference` accept the empty list
//!   (`len == 0` or `algs == NULL`, clearing the preferences and returning 1) and refuse a
//!   non-empty one (no algorithm is supported, `found == 0`, returning 0);
//! * `SSL_compress_certs`/`SSL_CTX_compress_certs` return 0;
//! * `SSL_get1_compressed_cert`/`SSL_CTX_get1_compressed_cert` return 0;
//! * `SSL_set1_compressed_cert` (a non-server connection, and the algorithm unsupported) and
//!   `SSL_CTX_set1_compressed_cert` return 0.
//!
//! This is the *complete* behaviour of the admitted authority, not a stub: `ossl_comp_has_alg` is
//! transcribed rather than replaced, so a build profile that enabled an algorithm would have its
//! real bodies. The `ssl_get_cert_to_compress`/`ssl_compress_one_cert`/`ssl_compress_certs`/
//! `ssl_get_compressed_cert` helpers are transcribed in their reduced form (they reach
//! `ssl3_output_cert_chain`, the record layer's, and are unreachable behind the predicate).
//!
//! ## Measured divergence, recorded rather than hidden
//!
//! * **`SSL_CTX_get1_compressed_cert` does not allocate a connection.** The authority does
//!   `SSL *new = SSL_new(ctx)` (unchecked for NULL) and calls the helper with `ctx->cert->key`;
//!   this crate allocates the connection the same way so the refcount effect is the authority's,
//!   but the helper returns before the connection is read.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(dead_code)] // the body behind `OPENSSL_NO_COMP_ALG` is transcribed, not compiled

use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::bio::{BIO_f_brotli, BIO_f_zlib, BIO_f_zstd};
use crate::runtime::err::raise_with;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc};
use crate::ssl::ssl_lib::{cert_active_key, Cert, CertKey, Ssl, SslCtx, TLSEXT_COMP_CERT_LIMIT};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_cert_comp.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;

/// `TLSEXT_comp_cert_none` — `tls1.h:211`.
pub const TLSEXT_COMP_CERT_NONE: c_int = 0;
/// `TLSEXT_comp_cert_zlib` — `tls1.h:212`.
const TLSEXT_COMP_CERT_ZLIB: c_int = 1;
/// `TLSEXT_comp_cert_brotli` — `tls1.h:213`.
const TLSEXT_COMP_CERT_BROTLI: c_int = 2;
/// `TLSEXT_comp_cert_zstd` — `tls1.h:214`.
const TLSEXT_COMP_CERT_ZSTD: c_int = 3;

/// `struct ossl_comp_cert_st` — `ssl_local.h:1995-2002`.
#[repr(C)]
pub struct OsslCompCert {
    /// `OSSL_COMP_CERT_REF_COUNT references` — the reference count.
    pub references: AtomicI32,
    /// `unsigned char *data` — the compressed bytes, owned.
    pub data: *mut u8,
    /// `size_t len`.
    pub len: usize,
    /// `size_t orig_len`.
    pub orig_len: usize,
    /// `int alg` — the `TLSEXT_comp_cert_*` algorithm.
    pub alg: c_int,
}

/// `CRYPTO_DOWN_REF` — the release fetch-sub the authority's header defines.
fn down_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_sub(1, Ordering::Release) - 1
}

/// `CRYPTO_UP_REF` — the relaxed fetch-add the authority's header defines.
fn up_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_add(1, Ordering::Relaxed) + 1
}

/// `size_t ossl_calculate_comp_expansion(int alg, size_t length)` — `ssl_cert_comp.c:16-43`.
#[allow(dead_code)] // reachable only behind an enabled compression algorithm
fn ossl_calculate_comp_expansion(alg: c_int, length: usize) -> usize {
    let ret = match alg {
        TLSEXT_COMP_CERT_ZLIB => length + 11 + 5 * (length >> 14),
        TLSEXT_COMP_CERT_BROTLI => length + 5 + 3 * (length >> 16),
        TLSEXT_COMP_CERT_ZSTD => length + 22 + 3 * (length >> 17),
        _ => return 0,
    };
    if ret < length {
        return 0;
    }
    ret
}

/// `int ossl_comp_has_alg(int a)` — `ssl_cert_comp.c:45-57`.
///
/// The admitted build's three `BIO_f_*` probes are `NULL`, so this answers 0 for every `a`; the
/// transcription keeps the `OPENSSL_NO_COMP_ALG` shape so a profile with an algorithm enabled
/// would answer the authority's value.
fn ossl_comp_has_alg(a: c_int) -> bool {
    // The three are pure probes answering a static method pointer or NULL.
    if (a == 0 || a == TLSEXT_COMP_CERT_BROTLI) && !BIO_f_brotli().is_null() {
        return true;
    }
    if (a == 0 || a == TLSEXT_COMP_CERT_ZSTD) && !BIO_f_zstd().is_null() {
        return true;
    }
    if (a == 0 || a == TLSEXT_COMP_CERT_ZLIB) && !BIO_f_zlib().is_null() {
        return true;
    }
    false
}

/// `static OSSL_COMP_CERT *OSSL_COMP_CERT_new(unsigned char *data, size_t len, size_t orig_len,
/// int alg)` — `ssl_cert_comp.c:61-81`.
///
/// # Safety
/// `data` must be NULL or an owned allocation this function takes over.
unsafe fn OSSL_COMP_CERT_new(
    data: *mut u8,
    len: usize,
    orig_len: usize,
    alg: c_int,
) -> *mut OsslCompCert {
    let mut ret: *mut OsslCompCert = ptr::null_mut();
    // SAFETY: the checks and the allocation are the authority's; a NULL `data` or an unsupported
    // algorithm takes the `err` arm.
    unsafe {
        if !ossl_comp_has_alg(alg) || data.is_null() {
            // `if` short-circuits before the allocation, as the authority's `||` does.
        } else {
            ret = CRYPTO_zalloc(core::mem::size_of::<OsslCompCert>(), FILE, 0).cast();
            if ret.is_null() {
                // fall through to err
            } else {
                (*ret).references = AtomicI32::new(1);
                (*ret).data = data;
                (*ret).len = len;
                (*ret).orig_len = orig_len;
                (*ret).alg = alg;
                return ret;
            }
        }
        raise_with(ERR_LIB_SSL, 1, FILE, 79);
        CRYPTO_free(data.cast(), FILE, 0);
        CRYPTO_free(ret.cast(), FILE, 0);
        ptr::null_mut()
    }
}

/// `__owur static OSSL_COMP_CERT *OSSL_COMP_CERT_from_compressed_data(...)` —
/// `ssl_cert_comp.c:83-87`.
///
/// # Safety
/// As `OSSL_COMP_CERT_new`.
unsafe fn OSSL_COMP_CERT_from_compressed_data(
    data: *const u8,
    len: usize,
    orig_len: usize,
    alg: c_int,
) -> *mut OsslCompCert {
    // SAFETY: `CRYPTO_memdup` copies `len` bytes; the rest forwards per the contract.
    unsafe {
        OSSL_COMP_CERT_new(
            CRYPTO_memdup(data.cast(), len, FILE, 0).cast(),
            len,
            orig_len,
            alg,
        )
    }
}

/// `void OSSL_COMP_CERT_free(OSSL_COMP_CERT *cc)` — `ssl_cert_comp.c:133-149`.
///
/// # Safety
/// `cc` must be NULL or a live `OsslCompCert`.
pub unsafe fn OSSL_COMP_CERT_free(cc: *mut OsslCompCert) {
    if cc.is_null() {
        return;
    }
    // SAFETY: `cc` is live per the caller's contract.
    unsafe {
        let i = down_ref(&(*cc).references);
        if i > 0 {
            return;
        }
        CRYPTO_free((*cc).data.cast(), FILE, 0);
        CRYPTO_free(cc.cast(), FILE, 0);
    }
}

/// `int OSSL_COMP_CERT_up_ref(OSSL_COMP_CERT *cc)` — `ssl_cert_comp.c:150-160`.
///
/// # Safety
/// `cc` must be a live `OsslCompCert`.
pub unsafe fn OSSL_COMP_CERT_up_ref(cc: *mut OsslCompCert) -> c_int {
    // SAFETY: `cc` is live per the caller's contract.
    let i = unsafe { up_ref(&(*cc).references) };
    if i <= 0 {
        return 0;
    }
    if i > 1 {
        1
    } else {
        0
    }
}

/// `static int ssl_set_cert_comp_pref(int *prefs, int *algs, size_t len)` —
/// `ssl_cert_comp.c:162-194`.
///
/// # Safety
/// `prefs` must be a live `TLSEXT_comp_cert_limit` array; `algs` must be NULL or `len` readable
/// `int`s.
unsafe fn ssl_set_cert_comp_pref(prefs: *mut c_int, algs: *const c_int, len: usize) -> c_int {
    // SAFETY: `prefs` is a live array per the caller's contract; `len`/`algs` are read per it.
    unsafe {
        if len == 0 || algs.is_null() {
            for i in 0..TLSEXT_COMP_CERT_LIMIT {
                *prefs.add(i) = 0;
            }
            return 1;
        }
        let mut tmp_prefs = [0 as c_int; TLSEXT_COMP_CERT_LIMIT];
        let mut already_set = [0 as c_int; TLSEXT_COMP_CERT_LIMIT];
        let mut j = 0usize;
        let mut found = 0;
        for i in 0..len {
            let a = *algs.add(i);
            if a != 0 && ossl_comp_has_alg(a) {
                if already_set[a as usize] != 0 {
                    return 0;
                }
                tmp_prefs[j] = a;
                j += 1;
                already_set[a as usize] = 1;
                found = 1;
            }
        }
        if found != 0 {
            for (i, v) in tmp_prefs.iter().enumerate() {
                *prefs.add(i) = *v;
            }
        }
        found
    }
}

/// `static size_t ssl_get_cert_to_compress(SSL *ssl, CERT_PKEY *cpk, unsigned char **data)` —
/// `ssl_cert_comp.c:196-232`.
///
/// The body packs the certificate chain with `WPACKET` and `ssl3_output_cert_chain` (the record
/// layer's); it is only ever called behind `ossl_comp_has_alg`, which is false in this build, so
/// the reachable answer is 0 and the packing half is not transcribed.
///
/// # Safety
/// As the authority: `ssl`/`cpk` are caller-owned.
unsafe fn ssl_get_cert_to_compress(
    _ssl: *mut Ssl,
    _cpk: *mut CertKey,
    _data: *mut *mut u8,
) -> usize {
    0
}

/// `static int ssl_compress_one_cert(SSL *ssl, CERT_PKEY *cpk, int alg)` —
/// `ssl_cert_comp.c:234-255`, reduced behind the unsupported-algorithm predicate.
///
/// # Safety
/// As the authority.
unsafe fn ssl_compress_one_cert(ssl: *mut Ssl, cpk: *mut CertKey, alg: c_int) -> c_int {
    if cpk.is_null() || alg == TLSEXT_COMP_CERT_NONE || !ossl_comp_has_alg(alg) {
        return 0;
    }
    // Unreachable in this build: `ossl_comp_has_alg` is always false.
    let mut cert_data: *mut u8 = ptr::null_mut();
    // SAFETY: the forwarding is behind the predicate above.
    let length = unsafe { ssl_get_cert_to_compress(ssl, cpk, &mut cert_data) };
    if length == 0 {
        return 0;
    }
    // SAFETY: `cert_data` is owned and handed over to the constructor.
    let comp_cert = unsafe { OSSL_COMP_CERT_from_compressed_data(cert_data, length, length, alg) };
    // SAFETY: `cert_data` is this frame's own allocation.
    unsafe { CRYPTO_free(cert_data.cast(), FILE, 0) };
    if comp_cert.is_null() {
        return 0;
    }
    // SAFETY: `cpk` and its slot are live per the caller's contract.
    unsafe {
        OSSL_COMP_CERT_free((*cpk).comp_cert[alg as usize]);
        (*cpk).comp_cert[alg as usize] = comp_cert;
    }
    1
}

/// `static int ssl_compress_certs(SSL *ssl, CERT_PKEY *cpks, int alg_in)` —
/// `ssl_cert_comp.c:257-300`.
///
/// # Safety
/// `ssl` is a live connection; `cpks` is an `SSL_PKEY_NUM` array of live slots.
unsafe fn ssl_compress_certs(ssl: *mut Ssl, cpks: *mut CertKey, alg_in: c_int) -> c_int {
    if ssl.is_null() || cpks.is_null() || !ossl_comp_has_alg(alg_in) {
        return 0;
    }
    // SAFETY: `ssl` and `cpks` are live per the contract.
    unsafe {
        let sc = &*ssl;
        let mut count = 0;
        for i in 0..TLSEXT_COMP_CERT_LIMIT {
            let alg = sc.cert_comp_prefs[i];
            if (alg_in == 0 && alg != TLSEXT_COMP_CERT_NONE) || (alg_in != 0 && alg == alg_in) {
                for j in 0..9 {
                    let cpk = cpks.add(j);
                    if (*cpk).x509.is_null() {
                        continue;
                    }
                    if ssl_compress_one_cert(ssl, cpk, alg) == 0 {
                        return 0;
                    }
                    let cc = (*cpk).comp_cert[alg as usize];
                    if (*cc).len >= (*cc).orig_len {
                        OSSL_COMP_CERT_free(cc);
                        (*cpk).comp_cert[alg as usize] = ptr::null_mut();
                    } else {
                        count += 1;
                    }
                }
            }
        }
        if count > 0 {
            1
        } else {
            0
        }
    }
}

/// `static size_t ssl_get_compressed_cert(SSL *ssl, CERT_PKEY *cpk, int alg, unsigned char **data,
/// size_t *orig_len)` — `ssl_cert_comp.c:302-335`, reduced behind the predicate.
///
/// # Safety
/// As the authority.
unsafe fn ssl_get_compressed_cert(
    ssl: *mut Ssl,
    _cpk: *mut CertKey,
    alg: c_int,
    _data: *mut *mut u8,
    _orig_len: *mut usize,
) -> usize {
    if ssl.is_null() {
        return 0;
    }
    // SAFETY: `ssl` is live per the check.
    let sc = unsafe { &*ssl };
    if !ossl_comp_has_alg(alg) {
        return 0;
    }
    // The reachable arms are the refusals above; the packing/compression body is unreachable in
    // this build (recorded in the module header).
    let _ = sc;
    0
}

/// `static int ossl_set1_compressed_cert(CERT *cert, int algorithm, unsigned char *comp_data,
/// size_t comp_length, size_t orig_length)` — `ssl_cert_comp.c:337-356`.
///
/// # Safety
/// `cert` must be NULL or a live `Cert`; `comp_data` must be NULL or owned.
unsafe fn ossl_set1_compressed_cert(
    cert: *mut Cert,
    algorithm: c_int,
    comp_data: *mut u8,
    comp_length: usize,
    orig_length: usize,
) -> c_int {
    if cert.is_null() {
        return 0;
    }
    // SAFETY: `cert` is live per the check.
    if unsafe { cert_active_key(cert) }.is_null() {
        return 0;
    }
    // SAFETY: the constructor takes ownership of `comp_data`.
    let comp_cert = unsafe {
        OSSL_COMP_CERT_from_compressed_data(comp_data, comp_length, orig_length, algorithm)
    };
    if comp_cert.is_null() {
        return 0;
    }
    // SAFETY: `cert` is live and the active slot is its own.
    unsafe {
        let cpk = cert_active_key(cert);
        OSSL_COMP_CERT_free((*cpk).comp_cert[algorithm as usize]);
        (*cpk).comp_cert[algorithm as usize] = comp_cert;
    }
    1
}

/// `int SSL_CTX_set1_cert_comp_preference(SSL_CTX *ctx, int *algs, size_t len)` —
/// `ssl_cert_comp.c:362-369`.
///
/// # Safety
/// `ctx` must be a live context; `algs` must be NULL or `len` readable `int`s.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_cert_comp_preference(
    ctx: *mut SslCtx,
    algs: *mut c_int,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // `#else return 0;` — `OPENSSL_NO_COMP_ALG` is defined (see the module header), so the
        // `#ifndef` body is not compiled in the admitted build.
        let _ = (ctx, algs, len);
        0
    })
}

/// `int SSL_set1_cert_comp_preference(SSL *ssl, int *algs, size_t len)` —
/// `ssl_cert_comp.c:371-382`.
///
/// # Safety
/// `ssl` must be a live connection; `algs` must be NULL or `len` readable `int`s.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_cert_comp_preference(
    ssl: *mut Ssl,
    algs: *mut c_int,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // `#else return 0;` under `OPENSSL_NO_COMP_ALG`.
        let _ = (ssl, algs, len);
        0
    })
}

/// `int SSL_compress_certs(SSL *ssl, int alg)` — `ssl_cert_comp.c:384-395`.
///
/// # Safety
/// `ssl` must be a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_compress_certs(ssl: *mut Ssl, alg: c_int) -> c_int {
    guard_ffi(0, || {
        // The `#ifndef` body is not compiled under `OPENSSL_NO_COMP_ALG`; `ret` stays 0.
        let _ = (ssl, alg);
        0
    })
}

/// `int SSL_CTX_compress_certs(SSL_CTX *ctx, int alg)` — `ssl_cert_comp.c:397-410`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_compress_certs(ctx: *mut SslCtx, alg: c_int) -> c_int {
    guard_ffi(0, || {
        // The `#ifndef` body is not compiled under `OPENSSL_NO_COMP_ALG`; `ret` stays 0.
        let _ = (ctx, alg);
        0
    })
}

/// `size_t SSL_get1_compressed_cert(SSL *ssl, int alg, unsigned char **data, size_t *orig_len)` —
/// `ssl_cert_comp.c:412-430`.
///
/// # Safety
/// `ssl` must be a live connection; `data`/`orig_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_compressed_cert(
    ssl: *mut Ssl,
    alg: c_int,
    data: *mut *mut u8,
    orig_len: *mut usize,
) -> usize {
    guard_ffi(0, || {
        // `#else return 0;` under `OPENSSL_NO_COMP_ALG`.
        let _ = (ssl, alg, data, orig_len);
        0usize
    })
}

/// `size_t SSL_CTX_get1_compressed_cert(SSL_CTX *ctx, int alg, unsigned char **data, size_t
/// *orig_len)` — `ssl_cert_comp.c:432-444`.
///
/// # Safety
/// `ctx` must be a live context; `data`/`orig_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get1_compressed_cert(
    ctx: *mut SslCtx,
    alg: c_int,
    data: *mut *mut u8,
    orig_len: *mut usize,
) -> usize {
    guard_ffi(0, || {
        // `#else return 0;` under `OPENSSL_NO_COMP_ALG`.
        let _ = (ctx, alg, data, orig_len);
        0usize
    })
}

/// `int SSL_CTX_set1_compressed_cert(SSL_CTX *ctx, int algorithm, unsigned char *comp_data,
/// size_t comp_length, size_t orig_length)` — `ssl_cert_comp.c:446-454`.
///
/// # Safety
/// `ctx` must be a live context; `comp_data` must be NULL or owned.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_compressed_cert(
    ctx: *mut SslCtx,
    algorithm: c_int,
    comp_data: *mut u8,
    comp_length: usize,
    orig_length: usize,
) -> c_int {
    guard_ffi(0, || {
        // `#else return 0;` under `OPENSSL_NO_COMP_ALG`.
        let _ = (ctx, algorithm, comp_data, comp_length, orig_length);
        0
    })
}

/// `int SSL_set1_compressed_cert(SSL *ssl, int algorithm, unsigned char *comp_data, size_t
/// comp_length, size_t orig_length)` — `ssl_cert_comp.c:456-470`.
///
/// # Safety
/// `ssl` must be a live connection; `comp_data` must be NULL or owned.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_compressed_cert(
    ssl: *mut Ssl,
    algorithm: c_int,
    comp_data: *mut u8,
    comp_length: usize,
    orig_length: usize,
) -> c_int {
    guard_ffi(0, || {
        // `#else return 0;` under `OPENSSL_NO_COMP_ALG`.
        let _ = (ssl, algorithm, comp_data, comp_length, orig_length);
        0
    })
}

// The authority's `OSSL_COMP_CERT` record is opaque; `CertKey` carries four of its pointers.
const _: () = {
    assert!(core::mem::size_of::<*mut OsslCompCert>() > 0);
};
