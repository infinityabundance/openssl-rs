//! `crypto/x509/x509_r2x.c` -- `X509_REQ_to_X509`, the request-to-certificate construction.
//! Phase 11.4.
//!
//! The unit is 66 lines and defines **one export and no internals**: [`X509_REQ_to_X509`]
//! (`:20-66`). It lands here -- every callee (`X509_new`, `ASN1_INTEGER_new`/`_set`,
//! `X509_REQ_get_subject_name`, `X509_set_subject_name`/`_issuer_name`/`_pubkey`,
//! `X509_gmtime_adj`, `X509_REQ_get0_pubkey`, `X509_sign`, `EVP_md5`, `X509_free`) is already the
//! crate's, so nothing is withheld.
//!
//! The construction duplicates the request's subject into both the certificate's subject and its
//! issuer, sets `notBefore` to now and `notAfter` `60*60*24*days` seconds ahead, copies the
//! request's public key, and signs with `pkey` and MD5. The version is left at the v1 default
//! **unless** the request carries attributes, in which case it is forced to `2` (v3). Note the
//! authority's deliberate non-reuse: the request's attribute stack is *not* copied into the
//! certificate's extensions (the commented-out `xi->extensions = ri->attributes`), so an
//! attribute-bearing request produces a v3 certificate with no extensions.
//!
//! ## The raise
//!
//! One: `X509_new` failing at `:28` raises `ERR_LIB_X509`/`ERR_R_ASN1_LIB` and answers NULL. The
//! unit is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the coordinate
//! (`X509_REQ_TO_X509_28`) is declared here in the crate's `ErrSite` idiom. Every other failure
//! arm is the `err:` label (`:63-65`), which frees the half-built certificate and answers NULL
//! without raising.
//!
//! ## The court
//!
//! `RT-X509-REQ` (`courts/phase11/rt_x509_req_probe.c`) drives the construction over the fixed
//! request DER and a fixed RSA private key, observing the time-independent structure -- the
//! version, the subject/issuer names against the request's, the copied public key and the
//! signature algorithm -- never the `now`-based validity or the signature bytes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_INTEGER_new;
use crate::evp::legacy_md5::EVP_md5;
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::OPENSSL_sk_num;
use crate::x509::x509_req::{X509Req, X509_REQ_get0_pubkey, X509_REQ_get_subject_name};
use crate::x509::x509_set::{X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name};
use crate::x509::x509_vfy::X509_gmtime_adj;
use crate::x509::x_all::X509_sign;
use crate::x509::x_x509::{X509_free, X509_new, X509};

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_ASN1_LIB` -- `include/openssl/err.h.in:328`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// `X509_REQ_to_X509`'s `X509_new`-failure raise at `crypto/x509/x509_r2x.c:28`,
/// `ERR_R_ASN1_LIB`.
const X509_REQ_TO_X509_28: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/x509_r2x.c",
    line: 28,
    func: c"X509_REQ_to_X509",
    lib: ERR_LIB_X509,
    reason: ERR_R_ASN1_LIB,
    dynamic_reason: false,
};

/// `X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey)` --
/// `crypto/x509/x509_r2x.c:20-66`.
///
/// Builds a certificate from a request: subject and issuer from the request's subject, validity
/// from now to `60*60*24*days` seconds ahead, the request's public key, and a v3 version only when
/// the request carries attributes. Signs with `pkey` under MD5. A NULL `X509_new` raises
/// `ERR_R_ASN1_LIB` at `:28`; every other failure frees the partial certificate and answers NULL
/// without raising.
///
/// # Safety
///
/// `r` is a live `X509_REQ`; `pkey` is a live private key able to sign with MD5.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_to_X509(
    r: *mut X509Req,
    days: c_int,
    pkey: *mut EvpPkey,
) -> *mut X509 {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let ret = X509_new();
        if ret.is_null() {
            raise_site(&X509_REQ_TO_X509_28);
            return core::ptr::null_mut();
        }

        // duplicate the request
        let xi = &raw mut (*ret).cert_info;

        if OPENSSL_sk_num((*r).req_info.attributes) != 0 {
            (*xi).version = ASN1_INTEGER_new();
            if (*xi).version.is_null() {
                X509_free(ret);
                return core::ptr::null_mut();
            }
            if ASN1_INTEGER_set((*xi).version, 2) == 0 {
                X509_free(ret);
                return core::ptr::null_mut();
            }
            // The authority's commented-out `xi->extensions = ri->attributes` is NOT done: the
            // request's attributes never become the certificate's extensions.
        }

        let xn = X509_REQ_get_subject_name(r);
        if X509_set_subject_name(ret, xn) == 0 {
            X509_free(ret);
            return core::ptr::null_mut();
        }
        if X509_set_issuer_name(ret, xn) == 0 {
            X509_free(ret);
            return core::ptr::null_mut();
        }

        if X509_gmtime_adj((*xi).validity.notBefore, 0).is_null() {
            X509_free(ret);
            return core::ptr::null_mut();
        }
        let after = c_long::from(60 * 60 * 24) * c_long::from(days);
        if X509_gmtime_adj((*xi).validity.notAfter, after).is_null() {
            X509_free(ret);
            return core::ptr::null_mut();
        }

        let pubkey = X509_REQ_get0_pubkey(r);
        if pubkey.is_null() || X509_set_pubkey(ret, pubkey) == 0 {
            X509_free(ret);
            return core::ptr::null_mut();
        }

        if X509_sign(ret, pkey, EVP_md5()) == 0 {
            X509_free(ret);
            return core::ptr::null_mut();
        }
        ret
    }
}
