//! `crypto/pkcs7/pk7_attr.c` — the S/MIME capability and signed-attribute builders.
//! Phase 12.2.
//!
//! `PKCS7_add_attrib_smimecap` encodes an `X509_ALGORS` stack into the
//! `SMIMECapabilities` signed attribute; `PKCS7_get_smimecap` decodes it back;
//! `PKCS7_simple_smimecap` appends one algorithm; `PKCS7_add_attrib_content_type` and
//! `PKCS7_add0_attrib_signing_time` add the two optional attributes; and
//! `PKCS7_add1_attrib_digest` sets the message digest.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{
    Asn1String, V_ASN1_INTEGER, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_UTCTIME,
};
use crate::asn1::prim::{ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new,
    ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set, ASN1_TIME_free,
};
use crate::asn1::x_algor::{X509_ALGORS_it, X509_ALGOR_free, X509_ALGOR_new};
use crate::pkcs7::pk7_asn1::Pkcs7SignerInfo;
use crate::pkcs7::pk7_doit::{PKCS7_add_signed_attribute, PKCS7_get_signed_attribute};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{
    Asn1Object, NID_SMIMECapabilities, NID_pkcs7_data, NID_pkcs9_contentType,
    NID_pkcs9_messageDigest, NID_pkcs9_signingTime, OBJ_nid2obj,
};
use crate::runtime::stack::{OPENSSL_sk_push, OpenSslStack};
use crate::x509::x509_vfy::X509_gmtime_adj;

/// `int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si, STACK_OF(X509_ALGOR) *cap)` —
/// `pk7_attr.c:20-41`.
///
/// # Safety
/// `si` is live; `cap` is a live stack that is serialised.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_attrib_smimecap(
    si: *mut Pkcs7SignerInfo,
    cap: *mut OpenSslStack,
) -> c_int {
    // SAFETY: no preconditions.
    let seq = ASN1_STRING_new();
    if seq.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_ATTR_26) };
        return 0;
    }
    // SAFETY: `seq` is live; `cap` is the caller's.
    let len =
        unsafe { ASN1_item_i2d(cap.cast(), ptr::addr_of_mut!((*seq).data), X509_ALGORS_it()) };
    // SAFETY: `seq` is live.
    unsafe { (*seq).length = len };
    // SAFETY: `seq` is live and its `data` field is readable.
    if len <= 0 || unsafe { (*seq).data }.is_null() {
        // SAFETY: `seq` is live and owned here.
        unsafe { ASN1_STRING_free(seq) };
        return 1;
    }
    // SAFETY: `si` is live; `seq` is the attribute value.
    if unsafe { PKCS7_add_signed_attribute(si, NID_SMIMECapabilities, V_ASN1_SEQUENCE, seq.cast()) }
        == 0
    {
        // SAFETY: `seq` is live and owned here.
        unsafe { ASN1_STRING_free(seq) };
        return 0;
    }
    1
}

/// `STACK_OF(X509_ALGOR) *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si)` — `pk7_attr.c:43-55`.
///
/// # Safety
/// `si` is live; a non-null answer is a fresh stack the caller owns.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_smimecap(si: *mut Pkcs7SignerInfo) -> *mut OpenSslStack {
    // SAFETY: `si` is live.
    let cap = unsafe { PKCS7_get_signed_attribute(si, NID_SMIMECapabilities) };
    if cap.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cap` is live.
    if unsafe { (*cap).type_ } != V_ASN1_SEQUENCE {
        return ptr::null_mut();
    }
    // SAFETY: the union's sequence member is the encoded capabilities.
    let seq = unsafe { (*cap).value.ptr.cast::<Asn1String>() };
    // SAFETY: `seq` is live.
    let mut p: *const c_uchar = unsafe { (*seq).data };
    // SAFETY: `p` describes `seq`'s content; the out-cursor is writable.
    unsafe {
        ASN1_item_d2i(
            ptr::null_mut(),
            &mut p,
            (*seq).length as core::ffi::c_long,
            X509_ALGORS_it(),
        )
    }
    .cast::<OpenSslStack>()
}

/// `int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)` —
/// `pk7_attr.c:58-95`.
///
/// # Safety
/// `sk` is a live stack; `arg` is the optional parameter value.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_simple_smimecap(
    sk: *mut OpenSslStack,
    nid: c_int,
    arg: c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let alg = X509_ALGOR_new();
    if alg.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_ATTR_64) };
        return 0;
    }
    // SAFETY: `alg` is live.
    unsafe {
        ASN1_OBJECT_free((*alg).algorithm);
        (*alg).algorithm = OBJ_nid2obj(nid);
    }
    let mut nbit: *mut Asn1String = ptr::null_mut();
    if arg > 0 {
        // SAFETY: `alg` is live.
        unsafe {
            (*alg).parameter = crate::asn1::a_type::ASN1_TYPE_new();
            if (*alg).parameter.is_null() {
                raise_site(&err_sites::PKCS7_ATTR_71);
                X509_ALGOR_free(alg);
                return 0;
            }
            nbit = ASN1_INTEGER_new();
            if nbit.is_null() {
                raise_site(&err_sites::PKCS7_ATTR_75);
                X509_ALGOR_free(alg);
                return 0;
            }
            if ASN1_INTEGER_set(nbit, arg as core::ffi::c_long) == 0 {
                raise_site(&err_sites::PKCS7_ATTR_79);
                ASN1_INTEGER_free(nbit);
                X509_ALGOR_free(alg);
                return 0;
            }
            (*((*alg).parameter)).value.ptr = nbit.cast();
            (*((*alg).parameter)).type_ = V_ASN1_INTEGER;
            nbit = ptr::null_mut();
        }
    }
    // SAFETY: `sk` is a live stack; `alg` is fresh.
    if unsafe { OPENSSL_sk_push(sk, alg.cast()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe {
            raise_site(&err_sites::PKCS7_ATTR_87);
            ASN1_INTEGER_free(nbit);
            X509_ALGOR_free(alg);
        }
        return 0;
    }
    1
}

/// `int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid)` —
/// `pk7_attr.c:97-105`.
///
/// # Safety
/// `si` is live; `coid` is null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_attrib_content_type(
    si: *mut Pkcs7SignerInfo,
    coid: *mut Asn1Object,
) -> c_int {
    // SAFETY: `si` is live.
    if !unsafe { PKCS7_get_signed_attribute(si, NID_pkcs9_contentType) }.is_null() {
        return 0;
    }
    let coid = if coid.is_null() {
        OBJ_nid2obj(NID_pkcs7_data)
    } else {
        coid
    };
    // SAFETY: `si` is live.
    unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, coid.cast()) }
}

/// `int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t)` —
/// `pk7_attr.c:107-121`.
///
/// # Safety
/// `si` is live; `t` is null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add0_attrib_signing_time(
    si: *mut Pkcs7SignerInfo,
    t: *mut Asn1String,
) -> c_int {
    let mut tmp: *mut Asn1String = ptr::null_mut();
    let t = if t.is_null() {
        // SAFETY: no preconditions.
        let fresh = unsafe { X509_gmtime_adj(ptr::null_mut(), 0) };
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_ATTR_112) };
            return 0;
        }
        tmp = fresh;
        fresh
    } else {
        t
    };
    // SAFETY: `si` is live.
    if unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, t.cast()) }
        == 0
    {
        // SAFETY: `tmp` is null or owned here.
        unsafe { ASN1_TIME_free(tmp) };
        return 0;
    }
    1
}

/// `int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si, const unsigned char *md, int mdlen)` —
/// `pk7_attr.c:123-137`.
///
/// # Safety
/// `si` is live; `md` is `mdlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add1_attrib_digest(
    si: *mut Pkcs7SignerInfo,
    md: *const c_uchar,
    mdlen: c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let os = ASN1_OCTET_STRING_new();
    if os.is_null() {
        return 0;
    }
    // SAFETY: `os` is live; `md`/`mdlen` describe the digest.
    if unsafe { ASN1_STRING_set(os, md.cast(), mdlen) } == 0
        // SAFETY: `si` is live.
        || unsafe {
            PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, os.cast())
        } == 0
    {
        // SAFETY: `os` is live and owned here.
        unsafe { ASN1_OCTET_STRING_free(os) };
        return 0;
    }
    1
}
