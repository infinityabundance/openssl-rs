//! `crypto/pkcs12/p12_init.c` — `PKCS12_init(_ex)`, the container builder's seed. Phase 10 (10.3,
//! re-opened by the `PKCS7` subset).
//!
//! The unit is 64 lines and three names. [`PKCS12_init_ex`] builds a `PKCS12` item, sets its
//! version to 3 and points its `authsafes` column at a `NID_pkcs7_<mode>` contentInfo, carrying
//! the caller's library context and property query into that object; [`PKCS12_init`] is its
//! no-context wrapper. [`ossl_pkcs12_get0_pkcs7ctx`] is the internal borrow the `d2i_PKCS12_bio`/
//! `_fp` readers use to find the context of a value they are asked to decode into.
//!
//! It was one of the eighteen rows D440 left open with `PKCS7_it` as their measured blocker, and
//! landing the pulled-forward `PKCS7` subset ([`crate::pkcs7`]) is what unblocks it: the only
//! non-`PKCS7` calls are `ASN1_INTEGER_set`, `OBJ_nid2obj` and `ASN1_OCTET_STRING_new`, all
//! landed. Its four raise sites are covered by `gen_err_raise_sites.py` rather than
//! reconstructed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::pkcs12::p12_asn::{PKCS12_free, PKCS12_new, Pkcs12};
use crate::pkcs7::{ossl_pkcs7_set0_libctx, ossl_pkcs7_set1_propq, Pkcs7Ctx};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{NID_pkcs7_data, OBJ_nid2obj};

/// `PKCS12 *PKCS12_init_ex(int mode, OSSL_LIB_CTX *ctx, const char *propq)` —
/// `crypto/pkcs12/p12_init.c:18-52`.
///
/// The allocation failure raises `ERR_R_ASN1_LIB`; the failed property-query copy raises
/// `ERR_R_PKCS7_LIB`; and a `mode` other than `NID_pkcs7_data` reaches the `default:` arm and
/// raises `PKCS12_R_UNSUPPORTED_PKCS12_MODE`. Every failure after the object exists releases it.
///
/// # Safety
/// `ctx` is null or a live library context; `propq` is null or a NUL-terminated string. The
/// answer is owned by the caller.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spelling
#[no_mangle]
pub unsafe extern "C" fn PKCS12_init_ex(
    mode: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs12 {
    // SAFETY: no preconditions.
    let pkcs12 = PKCS12_new();
    if pkcs12.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_INIT_23) };
        return core::ptr::null_mut();
    }
    // SAFETY: `pkcs12` is live and every column this touches was built by the item layer.
    unsafe {
        if ASN1_INTEGER_set((*pkcs12).version, 3) == 0 {
            PKCS12_free(pkcs12);
            return core::ptr::null_mut();
        }
        (*(*pkcs12).authsafes).type_ = OBJ_nid2obj(mode);

        ossl_pkcs7_set0_libctx((*pkcs12).authsafes, ctx);
        if ossl_pkcs7_set1_propq((*pkcs12).authsafes, propq) == 0 {
            raise_site(&err_sites::PKCS12_INIT_32);
            PKCS12_free(pkcs12);
            return core::ptr::null_mut();
        }

        match mode {
            NID_pkcs7_data => {
                (*(*pkcs12).authsafes).d.data = ASN1_OCTET_STRING_new();
                if (*(*pkcs12).authsafes).d.data.is_null() {
                    raise_site(&err_sites::PKCS12_INIT_39);
                    PKCS12_free(pkcs12);
                    return core::ptr::null_mut();
                }
            }
            _ => {
                raise_site(&err_sites::PKCS12_INIT_44);
                PKCS12_free(pkcs12);
                return core::ptr::null_mut();
            }
        }
    }
    pkcs12
}

/// `PKCS12 *PKCS12_init(int mode)` — `crypto/pkcs12/p12_init.c:54-57`.
///
/// # Safety
/// No preconditions. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_init(mode: c_int) -> *mut Pkcs12 {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS12_init_ex(mode, core::ptr::null_mut(), core::ptr::null()) }
}

/// `const PKCS7_CTX *ossl_pkcs12_get0_pkcs7ctx(const PKCS12 *p12)` —
/// `crypto/pkcs12/p12_init.c:59-64`.
///
/// The `authsafes` object's context, or null when there is no container or no `authsafes` column.
/// `d2i_PKCS12_bio`/`_fp` call this to find the context of the value they are decoding into.
///
/// # Safety
/// `p12` is null or a live `PKCS12`; a non-null answer borrows its `authsafes` object's context.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs12_get0_pkcs7ctx(p12: *const Pkcs12) -> *const Pkcs7Ctx {
    if p12.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `p12` is live per the caller's contract.
    unsafe {
        if (*p12).authsafes.is_null() {
            return core::ptr::null();
        }
        core::ptr::addr_of!((*(*p12).authsafes).ctx)
    }
}
