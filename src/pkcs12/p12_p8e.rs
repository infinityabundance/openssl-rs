//! `crypto/pkcs12/p12_p8e.c` — the `PKCS8_encrypt` pair and the `PKCS8_set0_pbe` pair.
//! Phase 10 (10.4).
//!
//! **Two of the four land here, and the other two are held open on a measured Phase 11 blocker.**
//!
//! * `PKCS8_set0_pbe`/`PKCS8_set0_pbe_ex` take an already-built `X509_ALGOR` and a
//!   `PKCS8_PRIV_KEY_INFO`, encrypt the key with `PKCS12_item_i2d_encrypt_ex` (landed, D368) and
//!   answer a fresh `X509_SIG`. Their closure is landed, so they land.
//! * `PKCS8_encrypt`/`PKCS8_encrypt_ex` **build** the `X509_ALGOR` and call
//!   `PKCS5_pbe2_set_iv_ex` (`crypto/asn1/p5_pbev2.c`) or `PKCS5_pbe_set_ex`
//!   (`crypto/asn1/p5_pbe.c`). Both are `x509.h` exports with `owner_phase: 11` in
//!   `forensics/atlas/symbol-ownership.json`, and neither is landed. There is no stub here: the
//!   pair stays `open` in `forensics/phase10-obligations.json` with that blocker, and the
//!   `PKCS8_encrypt_ex`-dependent rows elsewhere (10.2's `create_pkcs8_encrypt*`, 10.1's
//!   `encode_key2any.c`, and 10.6's two `i2d_PKCS8PrivateKey_nid_*` writers) stay blocked with it.
//!
//! ## `PKCS8_set0_pbe_ex` and ownership
//!
//! The authority writes the algorithm pointer straight into the fresh `X509_SIG` without
//! duplicating it, so the caller's `X509_ALGOR` is **adopted** — the same adoption
//! `PKCS12_SAFEBAG_create0_*` performs. The encrypted octets are a fresh `ASN1_OCTET_STRING` from
//! `PKCS12_item_i2d_encrypt_ex`, whose `zbuf` is `1`: the plaintext `PrivateKeyInfo` encoding is
//! cleansed before release. That is why this unit's only raise is the encrypt failure at `:79`
//! (the two allocation failures belong to the held-open pair).
//!
//! ## The court
//!
//! The unit raises, so `crypto/pkcs12/p12_p8e.c` is an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES` under the `PKCS12_P8E` stem. `RT-PKCS12` drives `PKCS8_set0_pbe` by building a
//! fixed `X509_ALGOR` through the PBE table and comparing the `X509_SIG`'s DER.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::p8_pkey::{PKCS8_PRIV_KEY_INFO_it, Pkcs8PrivKeyInfo};
use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::x_algor::X509Algor;
use crate::asn1::x_sig::X509Sig;
use crate::pkcs12::p12_decr::PKCS12_item_i2d_encrypt_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_zalloc;

/// `crypto/pkcs12/p12_p8e.c` — the authority's `__FILE__` string, for the allocator's bookkeeping.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_p8e.c";

/// `X509_SIG *PKCS8_set0_pbe_ex(const char *pass, int passlen, PKCS8_PRIV_KEY_INFO *p8inf,
/// X509_ALGOR *pbe, OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/pkcs12/p12_p8e.c:69-93`.
///
/// The answer is a fresh `X509_SIG` that **adopts** `pbe`; the caller must not free it separately.
///
/// # Safety
/// `pass` is NULL or a string of `passlen` bytes (or NUL-terminated when `passlen == -1`);
/// `p8inf` is a live `PKCS8_PRIV_KEY_INFO`; `pbe` is a live `X509_ALGOR` whose ownership transfers
/// to the answer; `ctx`/`propq` are the PBE lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_set0_pbe_ex(
    pass: *const c_char,
    passlen: c_int,
    p8inf: *mut Pkcs8PrivKeyInfo,
    pbe: *mut X509Algor,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509Sig {
    // SAFETY: `pbe` is live and `p8inf` is a live value of the item; `zbuf` is 1, so the plaintext
    // encoding is cleansed before release.
    let enckey = unsafe {
        PKCS12_item_i2d_encrypt_ex(
            pbe,
            PKCS8_PRIV_KEY_INFO_it(),
            pass,
            passlen,
            p8inf.cast::<c_void>(),
            1,
            ctx,
            propq,
        )
    };
    if enckey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_P8E_79) };
        return ptr::null_mut();
    }

    // SAFETY: a non-zero byte count; a failed allocation answers NULL.
    let p8 = CRYPTO_zalloc(core::mem::size_of::<X509Sig>(), FILE.as_ptr(), 83).cast::<X509Sig>();

    if p8.is_null() {
        // SAFETY: `enckey` is this call's own octet string.
        unsafe { ASN1_OCTET_STRING_free(enckey) };
        return ptr::null_mut();
    }
    // SAFETY: `p8` is a fresh zeroed `X509_SIG`, so both slots are writable; `pbe` is adopted.
    unsafe {
        (*p8).algor = pbe;
        (*p8).digest = enckey;
    }

    p8
}

/// `X509_SIG *PKCS8_set0_pbe(const char *pass, int passlen, PKCS8_PRIV_KEY_INFO *p8inf,
/// X509_ALGOR *pbe)` — `crypto/pkcs12/p12_p8e.c:95-99`.
///
/// # Safety
/// As [`PKCS8_set0_pbe_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_set0_pbe(
    pass: *const c_char,
    passlen: c_int,
    p8inf: *mut Pkcs8PrivKeyInfo,
    pbe: *mut X509Algor,
) -> *mut X509Sig {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS8_set0_pbe_ex(pass, passlen, p8inf, pbe, ptr::null_mut(), ptr::null()) }
}
