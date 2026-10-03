//! `crypto/cmp/cmp_hdr.c` — the CMP `PKIHeader` accessors. Phase 12.4 (the three `OSSL_CMP_HDR_*`
//! getters; the header builders are reached by the message engine and land with it).
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_free;
use crate::asn1::layout::{Asn1String, Asn1Type};
use crate::asn1::prim::{ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::ASN1_GENERALIZEDTIME_new;
use crate::asn1::time::ASN1_GENERALIZEDTIME_set;
use crate::asn1::typ::ASN1_NULL_new;
use crate::cmp::cmp_asn::{
    CmpItav, CmpPkiHeader, OSSL_CMP_ITAV_create, OSSL_CMP_ITAV_dup, OSSL_CMP_ITAV_free,
    OSSL_CMP_ITAV_push0_stack_item,
};
use crate::cmp::cmp_ctx::{OSSL_CMP_CTX_set1_senderNonce, OsslCmpCtx};
use crate::cmp::cmp_util::{
    ossl_cmp_asn1_octet_string_set1, ossl_cmp_asn1_octet_string_set1_bytes, ossl_cmp_log_str,
    ossl_cmp_sk_ASN1_UTF8STRING_push_str, OSSL_CMP_LOG_DEBUG,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::sys::time;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_id_it_implicitConfirm, NID_undef, OBJ_nid2obj, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_genn::{GENERAL_NAME_set1_X509_NAME, GeneralName, GEN_DIRNAME};
use crate::x509::v3_skid::i2s_ASN1_OCTET_STRING;
use crate::x509::x509_cmp::{X509_get_issuer_name, X509_get_subject_name};
use crate::x509::x509_req::{X509Req, X509_REQ_get_subject_name};
use crate::x509::x509name::X509_NAME_entry_count;
use crate::x509::x_name::X509Name;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_hdr.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;

const fn cmp_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: FILE,
        line,
        func,
        lib: ERR_LIB_CMP,
        reason,
        dynamic_reason: false,
    }
}

/// `ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:43-50`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_transactionID(
    hdr: *const CmpPkiHeader,
) -> *mut Asn1String {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(46, c"OSSL_CMP_HDR_get0_transactionID", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).transaction_id }
}

/// `ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:59-66`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_recipNonce(hdr: *const CmpPkiHeader) -> *mut Asn1String {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(62, c"OSSL_CMP_HDR_get0_recipNonce", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).recip_nonce }
}

/// `STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_HDR_get0_geninfo_ITAVs(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:68-76`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_geninfo_ITAVs(
    hdr: *const CmpPkiHeader,
) -> *mut OpenSslStack {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(72, c"OSSL_CMP_HDR_get0_geninfo_ITAVs", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).general_info }
}

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&cmp_site(line, func, reason));
    }
}

/// `int ossl_cmp_hdr_set_pvno(OSSL_CMP_PKIHEADER *hdr, int pvno)` — `cmp_hdr.c:17-22`. Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`.
#[allow(non_snake_case)]
pub(crate) unsafe fn ossl_cmp_hdr_set_pvno(hdr: *mut CmpPkiHeader, pvno: c_int) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live.
    unsafe { ASN1_INTEGER_set((*hdr).pvno, pvno as c_long) }
}

/// `int ossl_cmp_hdr_get_pvno(const OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:24-33`. Internal.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_get_pvno(hdr: *const CmpPkiHeader) -> c_int {
    if hdr.is_null() {
        return -1;
    }
    let mut pvno: i64 = 0;
    // SAFETY: `hdr` is live.
    if unsafe { ASN1_INTEGER_get_int64(&mut pvno, (*hdr).pvno) } == 0
        || pvno < 0
        || pvno > c_int::MAX as i64
    {
        return -1;
    }
    pvno as c_int
}

/// `int ossl_cmp_hdr_get_protection_nid(const OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:35-41`.
/// Internal.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_get_protection_nid(hdr: *const CmpPkiHeader) -> c_int {
    if hdr.is_null() {
        return NID_undef;
    }
    // SAFETY: `hdr` is live.
    let alg = unsafe { (*hdr).protection_alg };
    if alg.is_null() {
        return NID_undef;
    }
    // SAFETY: `alg` is live.
    unsafe { OBJ_obj2nid((*alg).algorithm) }
}

/// `ASN1_OCTET_STRING *ossl_cmp_hdr_get0_senderNonce(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:52-57`. Internal.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_get0_senderNonce(hdr: *const CmpPkiHeader) -> *mut Asn1String {
    if hdr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).sender_nonce }
}

/// `int ossl_cmp_general_name_is_NULL_DN(GENERAL_NAME *name)` — `cmp_hdr.c:78-83`. Internal.
///
/// # Safety
/// `name` is NULL or a live `GENERAL_NAME`.
pub(crate) unsafe fn ossl_cmp_general_name_is_NULL_DN(name: *mut GeneralName) -> c_int {
    if name.is_null() {
        return 1;
    }
    // SAFETY: `name` is live; the `directoryName` arm is read only under `GEN_DIRNAME`.
    unsafe {
        c_int::from(
            (*name).type_ == GEN_DIRNAME && X509_NAME_entry_count((*name).d.directoryName) == 0,
        )
    }
}

/// `int ossl_cmp_hdr_set1_sender(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)` —
/// `cmp_hdr.c:90-95`. Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`; `nm` is NULL or live.
pub(crate) unsafe fn ossl_cmp_hdr_set1_sender(
    hdr: *mut CmpPkiHeader,
    nm: *const X509Name,
) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live and the field is a general-name slot.
    unsafe { GENERAL_NAME_set1_X509_NAME(ptr::addr_of_mut!((*hdr).sender).cast(), nm) }
}

/// `int ossl_cmp_hdr_set1_recipient(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)` —
/// `cmp_hdr.c:97-102`. Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`; `nm` is NULL or live.
pub(crate) unsafe fn ossl_cmp_hdr_set1_recipient(
    hdr: *mut CmpPkiHeader,
    nm: *const X509Name,
) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live and the field is a general-name slot.
    unsafe { GENERAL_NAME_set1_X509_NAME(ptr::addr_of_mut!((*hdr).recipient).cast(), nm) }
}

/// `int ossl_cmp_hdr_update_messageTime(OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:104-112`.
/// Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_update_messageTime(hdr: *mut CmpPkiHeader) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live.
    unsafe {
        if (*hdr).message_time.is_null() {
            (*hdr).message_time = ASN1_GENERALIZEDTIME_new();
            if (*hdr).message_time.is_null() {
                return 0;
            }
        }
        c_int::from(!ASN1_GENERALIZEDTIME_set((*hdr).message_time, time(ptr::null_mut())).is_null())
    }
}

/// `static int set_random(ASN1_OCTET_STRING **tgt, OSSL_CMP_CTX *ctx, int len)` —
/// `cmp_hdr.c:115-126`.
///
/// # Safety
/// `tgt` is a writable slot; `ctx` is a live `OSSL_CMP_CTX`.
unsafe fn set_random(tgt: *mut *mut Asn1String, ctx: *mut OsslCmpCtx, len: c_int) -> c_int {
    // SAFETY: `CRYPTO_malloc` returns `len` writable bytes or NULL.
    let bytes = CRYPTO_malloc(len as usize, FILE.as_ptr(), 117).cast::<u8>();
    let mut res = 0;
    // SAFETY: `bytes` is NULL or writable for `len` bytes; `ctx` is live.
    if bytes.is_null() || unsafe { RAND_bytes_ex((*ctx).libctx, bytes, len as usize, 0) } <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(121, c"set_random", 110) };
    } else {
        // SAFETY: `tgt` is a writable slot; `bytes` is readable for `len` bytes.
        res = unsafe { ossl_cmp_asn1_octet_string_set1_bytes(tgt, bytes, len) };
    }
    // SAFETY: `bytes` is NULL or was allocated here.
    unsafe { CRYPTO_free(bytes.cast(), FILE.as_ptr(), 124) };
    res
}

/// `int ossl_cmp_hdr_set1_senderKID(OSSL_CMP_PKIHEADER *hdr,
/// const ASN1_OCTET_STRING *senderKID)` — `cmp_hdr.c:128-134`. Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`; `sender_kid` is NULL or live.
pub(crate) unsafe fn ossl_cmp_hdr_set1_senderKID(
    hdr: *mut CmpPkiHeader,
    sender_kid: *const Asn1String,
) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live and the field is a live slot.
    unsafe { ossl_cmp_asn1_octet_string_set1(ptr::addr_of_mut!((*hdr).sender_kid), sender_kid) }
}

/// `int ossl_cmp_hdr_push0_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)` —
/// `cmp_hdr.c:137-147`. Internal.
///
/// # Safety
/// `hdr`/`text` are live; ownership of `text` transfers to the header.
pub(crate) unsafe fn ossl_cmp_hdr_push0_freeText(
    hdr: *mut CmpPkiHeader,
    text: *mut Asn1String,
) -> c_int {
    if hdr.is_null() || text.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live.
    unsafe {
        if (*hdr).free_text.is_null() {
            (*hdr).free_text = OPENSSL_sk_new_null();
            if (*hdr).free_text.is_null() {
                return 0;
            }
        }
        OPENSSL_sk_push((*hdr).free_text, text.cast())
    }
}

/// `int ossl_cmp_hdr_push1_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)` —
/// `cmp_hdr.c:149-160`. Internal.
///
/// # Safety
/// `hdr`/`text` are live.
pub(crate) unsafe fn ossl_cmp_hdr_push1_freeText(
    hdr: *mut CmpPkiHeader,
    text: *mut Asn1String,
) -> c_int {
    if hdr.is_null() || text.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live.
    unsafe {
        if (*hdr).free_text.is_null() {
            (*hdr).free_text = OPENSSL_sk_new_null();
            if (*hdr).free_text.is_null() {
                return 0;
            }
        }
        ossl_cmp_sk_ASN1_UTF8STRING_push_str(
            (*hdr).free_text,
            (*text).data.cast::<c_char>(),
            (*text).length,
        )
    }
}

/// `int ossl_cmp_hdr_generalInfo_push0_item(OSSL_CMP_PKIHEADER *hdr, OSSL_CMP_ITAV *itav)` —
/// `cmp_hdr.c:162-168`. Internal.
///
/// # Safety
/// `hdr`/`itav` are live; ownership of `itav` transfers to the header.
pub(crate) unsafe fn ossl_cmp_hdr_generalInfo_push0_item(
    hdr: *mut CmpPkiHeader,
    itav: *mut CmpItav,
) -> c_int {
    if hdr.is_null() || itav.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live and the field is a live slot.
    unsafe { OSSL_CMP_ITAV_push0_stack_item(ptr::addr_of_mut!((*hdr).general_info), itav) }
}

/// `int ossl_cmp_hdr_generalInfo_push1_items(OSSL_CMP_PKIHEADER *hdr,
/// const STACK_OF(OSSL_CMP_ITAV) *itavs)` — `cmp_hdr.c:170-190`. Internal.
///
/// # Safety
/// `hdr` is live; `itavs` is NULL or a live stack.
pub(crate) unsafe fn ossl_cmp_hdr_generalInfo_push1_items(
    hdr: *mut CmpPkiHeader,
    itavs: *const OpenSslStack,
) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `itavs` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(itavs as *mut OpenSslStack) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let src = unsafe { OPENSSL_sk_value(itavs as *mut OpenSslStack, i) }.cast::<CmpItav>();
        // SAFETY: `src` is a live element.
        let itav = unsafe { OSSL_CMP_ITAV_dup(src) };
        if itav.is_null() {
            return 0;
        }
        // SAFETY: `hdr` and `itav` are live.
        if unsafe { ossl_cmp_hdr_generalInfo_push0_item(hdr, itav) } == 0 {
            // SAFETY: `itav` is live.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return 0;
        }
        i += 1;
    }
    1
}

/// `int ossl_cmp_hdr_set_implicitConfirm(OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:192-214`.
/// Internal.
///
/// # Safety
/// `hdr` is a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_set_implicitConfirm(hdr: *mut CmpPkiHeader) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `ASN1_NULL_new` answers the sentinel.
    let asn1null = ASN1_NULL_new().cast::<Asn1Type>();
    if asn1null.is_null() {
        return 0;
    }
    // SAFETY: `OBJ_nid2obj` answers a static object.
    let itav = unsafe { OSSL_CMP_ITAV_create(OBJ_nid2obj(NID_id_it_implicitConfirm), asn1null) };
    if itav.is_null() {
        // SAFETY: `asn1null` is the sentinel.
        unsafe { ASN1_TYPE_free(asn1null) };
        return 0;
    }
    // SAFETY: `hdr` and `itav` are live.
    if unsafe { ossl_cmp_hdr_generalInfo_push0_item(hdr, itav) } == 0 {
        // SAFETY: the failure path owns both.
        unsafe {
            ASN1_TYPE_free(asn1null);
            OSSL_CMP_ITAV_free(itav);
        }
        return 0;
    }
    1
}

/// `int ossl_cmp_hdr_has_implicitConfirm(const OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:216-235`.
/// Internal.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
pub(crate) unsafe fn ossl_cmp_hdr_has_implicitConfirm(hdr: *const CmpPkiHeader) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: `hdr` is live.
    let general_info = unsafe { (*hdr).general_info };
    // SAFETY: `general_info` is NULL or a live stack.
    let itav_count = unsafe { OPENSSL_sk_num(general_info) };
    let mut i = 0;
    while i < itav_count {
        // SAFETY: `i` is in range.
        let itav = unsafe { OPENSSL_sk_value(general_info, i) }.cast::<CmpItav>();
        if !itav.is_null() {
            // SAFETY: `itav` is live.
            let nid = unsafe { OBJ_obj2nid((*itav).info_type) };
            if nid == NID_id_it_implicitConfirm {
                return 1;
            }
        }
        i += 1;
    }
    0
}

/// `int ossl_cmp_hdr_set_transactionID(OSSL_CMP_CTX *ctx, OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:246-263`. Internal.
///
/// # Safety
/// `ctx`/`hdr` are live.
pub(crate) unsafe fn ossl_cmp_hdr_set_transactionID(
    ctx: *mut OsslCmpCtx,
    hdr: *mut CmpPkiHeader,
) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).transaction_id }.is_null() {
        // SAFETY: `ctx` is live; the field is a writable slot.
        if unsafe { set_random(ptr::addr_of_mut!((*ctx).transaction_id), ctx, 16) } == 0 {
            return 0;
        }
        // SAFETY: `ctx` is live; the transaction is now set.
        let tid = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), (*ctx).transaction_id) };
        if !tid.is_null() {
            // SAFETY: `tid` is NUL-terminated; `ctx` is live.
            unsafe {
                ossl_cmp_log_str(
                    OSSL_CMP_LOG_DEBUG,
                    ctx,
                    c"ossl_cmp_hdr_set_transactionID",
                    FILE,
                    257,
                    format_args!("Starting new transaction with ID={}", cstr_to_str(tid)),
                )
            };
        }
        // SAFETY: `tid` is NULL or allocated by `i2s_ASN1_OCTET_STRING`.
        unsafe { CRYPTO_free(tid.cast(), FILE.as_ptr(), 258) };
    }
    // SAFETY: `ctx`/`hdr` are live.
    unsafe {
        ossl_cmp_asn1_octet_string_set1(
            ptr::addr_of_mut!((*hdr).transaction_id),
            (*ctx).transaction_id,
        )
    }
}

/// `const char *` to `&str`, lossily, for log formatting only.
///
/// # Safety
/// `s` is NULL or NUL-terminated.
unsafe fn cstr_to_str<'a>(s: *const c_char) -> std::borrow::Cow<'a, str> {
    if s.is_null() {
        return std::borrow::Cow::Borrowed("");
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { std::ffi::CStr::from_ptr(s).to_string_lossy() }
}

/// `int ossl_cmp_hdr_init(OSSL_CMP_CTX *ctx, OSSL_CMP_PKIHEADER *hdr)` — `cmp_hdr.c:266-343`.
/// Internal.
///
/// # Safety
/// `ctx`/`hdr` are live.
pub(crate) unsafe fn ossl_cmp_hdr_init(ctx: *mut OsslCmpCtx, hdr: *mut CmpPkiHeader) -> c_int {
    if ctx.is_null() || hdr.is_null() {
        return 0;
    }

    /* set the CMP version */
    // SAFETY: `hdr` is live.
    if unsafe { ossl_cmp_hdr_set_pvno(hdr, 2) } == 0 {
        return 0;
    }

    // SAFETY: every pointer read here is from the live `ctx`.
    let sender = unsafe {
        if !(*ctx).cert.is_null() {
            X509_get_subject_name((*ctx).cert)
        } else if !(*ctx).old_cert.is_null() {
            X509_get_subject_name((*ctx).old_cert)
        } else if !(*ctx).p10_csr.is_null() {
            X509_REQ_get_subject_name((*ctx).p10_csr.cast::<X509Req>())
        } else {
            (*ctx).subject_name
        }
    };
    // SAFETY: `hdr` is live; `sender` is NULL or live.
    if unsafe { ossl_cmp_hdr_set1_sender(hdr, sender) } == 0 {
        return 0;
    }

    // SAFETY: every pointer read here is from the live `ctx`.
    let rcp = unsafe {
        if !(*ctx).recipient.is_null() {
            (*ctx).recipient
        } else if !(*ctx).srv_cert.is_null() {
            X509_get_subject_name((*ctx).srv_cert)
        } else if !(*ctx).issuer.is_null() {
            (*ctx).issuer
        } else if !(*ctx).old_cert.is_null() {
            X509_get_issuer_name((*ctx).old_cert)
        } else if !(*ctx).cert.is_null() {
            X509_get_issuer_name((*ctx).cert)
        } else {
            ptr::null_mut()
        }
    };
    // SAFETY: `hdr` is live; `rcp` is NULL or live.
    if unsafe { ossl_cmp_hdr_set1_recipient(hdr, rcp) } == 0 {
        return 0;
    }

    /* set current time as message time */
    // SAFETY: `hdr` is live.
    if unsafe { ossl_cmp_hdr_update_messageTime(hdr) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live; the field is NULL or live.
    if !unsafe { (*ctx).recip_nonce }.is_null()
        // SAFETY: `hdr` is live and its field is a writable slot; `ctx`'s nonce is live.
        && unsafe {
            ossl_cmp_asn1_octet_string_set1(
                ptr::addr_of_mut!((*hdr).recip_nonce),
                (*ctx).recip_nonce,
            )
        } == 0
    {
        return 0;
    }

    // SAFETY: `ctx`/`hdr` are live.
    if unsafe { ossl_cmp_hdr_set_transactionID(ctx, hdr) } == 0 {
        return 0;
    }

    /* set random senderNonce */
    // SAFETY: `hdr` is live and the field is a writable slot.
    if unsafe { set_random(ptr::addr_of_mut!((*hdr).sender_nonce), ctx, 16) } == 0 {
        return 0;
    }

    /* store senderNonce - for cmp with recipNonce in next outgoing msg */
    // SAFETY: `ctx` is live; `hdr`'s nonce is live.
    if unsafe { OSSL_CMP_CTX_set1_senderNonce(ctx, (*hdr).sender_nonce) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live; the field is NULL or live.
    if !unsafe { (*ctx).free_text }.is_null()
        // SAFETY: `hdr` is live; the free-text value is live.
        && unsafe { ossl_cmp_hdr_push1_freeText(hdr, (*ctx).free_text) } == 0
    {
        return 0;
    }

    1
}
