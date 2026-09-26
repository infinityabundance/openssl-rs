//! `crypto/pkcs12/p12_mutl.c` — the `MacData` accessors and the MAC setup. Phase 10 (10.3,
//! re-opened by the `PKCS7` subset).
//!
//! The unit is 552 lines and fifteen exports, of which this slice lands three:
//! [`PKCS12_mac_present`] and [`PKCS12_get0_mac`] (the two accessors over a `PKCS12`'s `mac`
//! column) and [`PKCS12_setup_mac`] (which builds the `PKCS12_MAC_DATA` a later `gen_mac` fills).
//! `PKCS12_gen_mac`/`PKCS12_verify_mac`/`PKCS12_set_mac`/`PKCS12_set_pbmac1_pbkdf2` stay `open` on
//! 10.4's `PKCS12_key_gen_utf8_ex` — the PKCS#12 KDF — and are not touched here.
//!
//! `setup_mac`'s closure was measured rather than assumed: it reaches `PKCS12_MAC_DATA_free`/
//! `_new` (this crate's `p12_asn.rs`), `ASN1_INTEGER_new`/`ASN1_INTEGER_set`, `RAND_bytes_ex`
//! (Phase 9, landed), `X509_SIG_getm`, `X509_ALGOR_set0` and `OBJ_nid2obj` — no `PKCS7` container
//! operation at all. What it needed from the pulled-forward subset is only that `PKCS12_new` can
//! build the object at all, which the `authsafes` column's `PKCS7` had blocked.
//!
//! `setup_mac`'s `salt == NULL` arm draws through `p12->authsafes->ctx.libctx`, so the `PKCS7`
//! context is read here even though no `PKCS7` item operation runs; the drawn salt is observable
//! only as "not the caller's" and the court drives the caller-supplied arm so the bytes stay
//! fixed. The file is covered by `gen_err_raise_sites.py` for its `ERR_R_ASN1_LIB` sites.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::layout::{Asn1String, V_ASN1_NULL};
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_INTEGER_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_set0};
use crate::asn1::x_sig::{X509_SIG_get0, X509_SIG_getm};
use crate::pkcs12::p12_asn::{PKCS12_MAC_DATA_free, PKCS12_MAC_DATA_new, Pkcs12};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::OBJ_nid2obj;

/// The authority translation unit for this module.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_mutl.c";

/// `PKCS12_SALT_LEN` — `include/openssl/pkcs12.h.in:56`.
const PKCS12_SALT_LEN: c_int = 16;

/// `PKCS12_ERROR` — `pkcs12.h.in:82`. `setup_mac` answers it when the `MacData` cannot be built.
const PKCS12_ERROR: c_int = 0;

/// `int PKCS12_mac_present(const PKCS12 *p12)` — `crypto/pkcs12/p12_mutl.c:31-34`.
///
/// # Safety
/// `p12` is a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_mac_present(p12: *const Pkcs12) -> c_int {
    // SAFETY: `p12` is live per the caller's contract.
    if unsafe { (*p12).mac }.is_null() {
        0
    } else {
        1
    }
}

/// `void PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac, const X509_ALGOR **pmacalg,
/// const ASN1_OCTET_STRING **psalt, const ASN1_INTEGER **piter, const PKCS12 *p12)` —
/// `crypto/pkcs12/p12_mutl.c:36-58`.
///
/// Each out-parameter is independently optional. With a `MacData` present the digest and its
/// algorithm come from the `X509_SIG` and the salt/iterations are borrowed straight off the
/// object; without one every requested slot is cleared to null.
///
/// # Safety
/// `p12` is a live `PKCS12`; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_get0_mac(
    pmac: *mut *const Asn1String,
    pmacalg: *mut *const X509Algor,
    psalt: *mut *const Asn1String,
    piter: *mut *const Asn1String,
    p12: *const Pkcs12,
) {
    // SAFETY: `p12` is live per the caller's contract; each out-pointer is checked before use.
    unsafe {
        let mac = (*p12).mac;
        if !mac.is_null() {
            X509_SIG_get0((*mac).dinfo, pmacalg, pmac);
            if !psalt.is_null() {
                *psalt = (*mac).salt;
            }
            if !piter.is_null() {
                *piter = (*mac).iter;
            }
        } else {
            if !pmac.is_null() {
                *pmac = ptr::null();
            }
            if !pmacalg.is_null() {
                *pmacalg = ptr::null();
            }
            if !psalt.is_null() {
                *psalt = ptr::null();
            }
            if !piter.is_null() {
                *piter = ptr::null();
            }
        }
    }
}

/// `static int pkcs12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen, int nid)`
/// — `crypto/pkcs12/p12_mutl.c:403-445`.
///
/// Builds a fresh `PKCS12_MAC_DATA` over the already-selected digest `nid`, optionally sets the
/// iteration count, and fills the salt: from the caller when one is supplied, otherwise drawn.
/// A `saltlen` of 0 means `PKCS12_SALT_LEN`; a negative one is refused without raising, while the
/// three allocation/set failures raise `ERR_R_ASN1_LIB` — the same arms the authority has.
///
/// # Safety
/// `p12` is a live `PKCS12`; `salt` is NULL or `saltlen` readable bytes.
unsafe fn pkcs12_setup_mac(
    p12: *mut Pkcs12,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    nid: c_int,
) -> c_int {
    // SAFETY: `p12` is live per the caller's contract.
    unsafe {
        PKCS12_MAC_DATA_free((*p12).mac);
        (*p12).mac = ptr::null_mut();

        let mac = PKCS12_MAC_DATA_new();
        if mac.is_null() {
            return PKCS12_ERROR;
        }
        (*p12).mac = mac;

        if iter > 1 {
            let it = ASN1_INTEGER_new();
            if it.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_415);
                return 0;
            }
            (*mac).iter = it;
            if ASN1_INTEGER_set((*mac).iter, c_long::from(iter)) == 0 {
                raise_site(&err_sites::PKCS12_MUTL_419);
                return 0;
            }
        }

        let saltlen = if saltlen == 0 {
            PKCS12_SALT_LEN
        } else if saltlen < 0 {
            return 0;
        } else {
            saltlen
        };

        let data = CRYPTO_malloc(saltlen as usize, FILE.as_ptr(), 427).cast::<c_uchar>();
        if data.is_null() {
            return 0;
        }
        (*(*mac).salt).data = data;
        (*(*mac).salt).length = saltlen;

        if salt.is_null() {
            let libctx = (*(*p12).authsafes).ctx.libctx;
            if RAND_bytes_ex(libctx, (*(*mac).salt).data, saltlen as usize, 0) <= 0 {
                return 0;
            }
        } else {
            ptr::copy_nonoverlapping(salt, (*(*mac).salt).data, saltlen as usize);
        }

        let mut macalg: *mut X509Algor = ptr::null_mut();
        X509_SIG_getm((*mac).dinfo, &mut macalg, ptr::null_mut());
        if X509_ALGOR_set0(macalg, OBJ_nid2obj(nid), V_ASN1_NULL, ptr::null_mut()) == 0 {
            raise_site(&err_sites::PKCS12_MUTL_440);
            return 0;
        }
    }
    1
}

/// `int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen,
/// const EVP_MD *md_type)` — `crypto/pkcs12/p12_mutl.c:448-452`.
///
/// # Safety
/// `p12` is a live `PKCS12`; `salt` is NULL or `saltlen` readable bytes; `md_type` is a live
/// digest method.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_setup_mac(
    p12: *mut Pkcs12,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    md_type: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: `md_type` is live per the caller's contract; the rest is forwarded.
    let nid = unsafe { crate::evp::digest::EVP_MD_get_type(md_type) };
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { pkcs12_setup_mac(p12, iter, salt, saltlen, nid) }
}
