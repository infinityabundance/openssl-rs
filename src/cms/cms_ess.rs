//! `crypto/cms/cms_ess.c` — the `CMS_ReceiptRequest` surface and the signing-certificate
//! envelope checks. Phase 12.3c.
//!
//! The `IMPLEMENT_ASN1_FUNCTIONS(CMS_ReceiptRequest)` block (the `_new`/`_free`/`d2i`/`i2d`
//! names) and the eight hand-written exports land here, together with the internals `cms_smime.c`
//! reaches (`ossl_cms_signerinfo_get_signing_cert(_v2)`, `ossl_cms_check_signing_certs`,
//! `cms_msgSigDigest`, `ossl_cms_msgSigDigest_add1`, `ossl_cms_Receipt_verify` and
//! `ossl_cms_encode_Receipt`).
//!
//! The signing-certificate checks reach `crypto/ess/`'s item groups and
//! `OSSL_ESS_check_signing_certs`, which are Phase 12.7's and are shell-scaffolded here; the
//! `CMS_CADES` arm of `CMS_verify` is the only caller, so the delegation is the authority's own
//! prototype and the hand-off stays open rather than stubbed.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_digest::ossl_asn1_item_digest_ex;
use crate::asn1::asn_pack::{ASN1_item_pack, ASN1_item_unpack};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{
    Asn1Item, Asn1String, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
};
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{ASN1_STRING_cmp, ASN1_STRING_set, ASN1_STRING_set0};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::obj::{
    Asn1Object, NID_id_smime_aa_msgSigDigest, NID_id_smime_aa_receiptRequest,
    NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_id_smime_ct_receipt, NID_pkcs9_contentType, OBJ_cmp, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_genn::GENERAL_NAMES_free;

use super::cms_asn1::*;
use super::cms_att::{CMS_signed_add1_attr_by_NID, CMS_signed_get0_data_by_OBJ};
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, raise_cms, ERR_R_ASN1_LIB, ERR_R_CMS_LIB,
};

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:43`.
const EVP_MAX_MD_SIZE: usize = 64;

// The ESS surface `ossl_cms_check_signing_certs` reaches. It is Phase 12.7's (`crypto/ess/`); the
// shell scaffolds the exports, so this unit declares them as the authority's prototypes spell them
// and the `CMS_CADES` arm is the only caller.
extern "C" {
    fn ESS_SIGNING_CERT_free(sc: *mut c_void);
    fn ESS_SIGNING_CERT_V2_free(sc: *mut c_void);
    fn ESS_SIGNING_CERT_it() -> *const Asn1Item;
    fn ESS_SIGNING_CERT_V2_it() -> *const Asn1Item;
    fn OSSL_ESS_check_signing_certs(
        ss: *const c_void,
        ssv2: *const c_void,
        chain: *const OpenSslStack,
        check_embedded: c_int,
    ) -> c_int;
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for [`GENERAL_NAMES_free`].
///
/// # Safety
/// `p` is a `GENERAL_NAMES` per the stack's element type.
unsafe extern "C" fn general_names_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { GENERAL_NAMES_free(p.cast()) };
}

/// `CMS_ReceiptRequest *CMS_ReceiptRequest_new(void)` — `IMPLEMENT_ASN1_FUNCTIONS(CMS_ReceiptRequest)`,
/// `cms_ess.c:22`.
///
/// # Safety
/// The returned pointer must be released with [`CMS_ReceiptRequest_free`].
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ReceiptRequest_new() -> *mut CmsReceiptRequest {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(CMS_ReceiptRequest_it()) }.cast()
}

/// `void CMS_ReceiptRequest_free(CMS_ReceiptRequest *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ReceiptRequest_free(a: *mut CmsReceiptRequest) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), CMS_ReceiptRequest_it()) };
}

/// `CMS_ReceiptRequest *d2i_CMS_ReceiptRequest(CMS_ReceiptRequest **a,`
/// `const unsigned char **in, long len)`.
///
/// # Safety
/// The `ASN1_item_d2i` contract.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_CMS_ReceiptRequest(
    a: *mut *mut CmsReceiptRequest,
    in_: *mut *const c_uchar,
    len: core::ffi::c_long,
) -> *mut CmsReceiptRequest {
    // SAFETY: the caller's contract; the item is static.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, CMS_ReceiptRequest_it()) }.cast()
}

/// `int i2d_CMS_ReceiptRequest(const CMS_ReceiptRequest *a, unsigned char **out)`.
///
/// # Safety
/// The `ASN1_item_i2d` contract.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_CMS_ReceiptRequest(
    a: *const CmsReceiptRequest,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract; the item is static.
    unsafe { ASN1_item_i2d(a.cast(), out, CMS_ReceiptRequest_it()) }
}

/// `int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr)` — `cms_ess.c:26-46`.
///
/// # Safety
/// `si` is live; `prr` is NULL or writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get1_ReceiptRequest(
    si: *mut CmsSignerInfo,
    prr: *mut *mut CmsReceiptRequest,
) -> c_int {
    let obj = OBJ_nid2obj(NID_id_smime_aa_receiptRequest);

    if !prr.is_null() {
        // SAFETY: `prr` is writable.
        unsafe { *prr = ptr::null_mut() };
    }
    // SAFETY: `si`/`obj` are live.
    let str_ =
        unsafe { CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE) }.cast::<Asn1String>();
    if str_.is_null() {
        return 0;
    }

    // SAFETY: `str_` is live; the item is static.
    let rr = unsafe { ASN1_item_unpack(str_, CMS_ReceiptRequest_it()) }.cast::<CmsReceiptRequest>();
    if rr.is_null() {
        return -1;
    }
    if !prr.is_null() {
        // SAFETY: `prr` is writable.
        unsafe { *prr = rr };
    } else {
        // SAFETY: `rr` is owned here.
        unsafe { CMS_ReceiptRequest_free(rr) };
    }
    1
}

/// `static int ossl_cms_signerinfo_get_signing_cert(const CMS_SignerInfo *si,`
/// `ESS_SIGNING_CERT **psc)` — `cms_ess.c:52-73`.
///
/// # Safety
/// `si` is live; `psc` is NULL or writable.
unsafe fn ossl_cms_signerinfo_get_signing_cert(
    si: *const CmsSignerInfo,
    psc: *mut *mut c_void,
) -> c_int {
    let obj = OBJ_nid2obj(NID_id_smime_aa_signingCertificate);

    if !psc.is_null() {
        // SAFETY: `psc` is writable.
        unsafe { *psc = ptr::null_mut() };
    }
    // SAFETY: `si`/`obj` are live.
    let str_ =
        unsafe { CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE) }.cast::<Asn1String>();
    if str_.is_null() {
        return 0;
    }

    // SAFETY: `str_` is live; the item is the ESS item (Phase 12.7).
    let sc = unsafe { ASN1_item_unpack(str_, ESS_SIGNING_CERT_it()) };
    if sc.is_null() {
        return -1;
    }
    if !psc.is_null() {
        // SAFETY: `psc` is writable.
        unsafe { *psc = sc };
    } else {
        // SAFETY: `sc` is owned here.
        unsafe { ESS_SIGNING_CERT_free(sc) };
    }
    1
}

/// `static int ossl_cms_signerinfo_get_signing_cert_v2(const CMS_SignerInfo *si,`
/// `ESS_SIGNING_CERT_V2 **psc)` — `cms_ess.c:79-100`.
///
/// # Safety
/// `si` is live; `psc` is NULL or writable.
unsafe fn ossl_cms_signerinfo_get_signing_cert_v2(
    si: *const CmsSignerInfo,
    psc: *mut *mut c_void,
) -> c_int {
    let obj = OBJ_nid2obj(NID_id_smime_aa_signingCertificateV2);

    if !psc.is_null() {
        // SAFETY: `psc` is writable.
        unsafe { *psc = ptr::null_mut() };
    }
    // SAFETY: `si`/`obj` are live.
    let str_ =
        unsafe { CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE) }.cast::<Asn1String>();
    if str_.is_null() {
        return 0;
    }

    // SAFETY: `str_` is live; the item is the ESS item (Phase 12.7).
    let sc = unsafe { ASN1_item_unpack(str_, ESS_SIGNING_CERT_V2_it()) };
    if sc.is_null() {
        return -1;
    }
    if !psc.is_null() {
        // SAFETY: `psc` is writable.
        unsafe { *psc = sc };
    } else {
        // SAFETY: `sc` is owned here.
        unsafe { ESS_SIGNING_CERT_V2_free(sc) };
    }
    1
}

/// `int ossl_cms_check_signing_certs(const CMS_SignerInfo *si, const STACK_OF(X509) *chain)` —
/// `cms_ess.c:102-114`.
///
/// # Safety
/// `si` is live; `chain` is NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_check_signing_certs(
    si: *const CmsSignerInfo,
    chain: *const OpenSslStack,
) -> c_int {
    let mut ss: *mut c_void = ptr::null_mut();
    let mut ssv2: *mut c_void = ptr::null_mut();
    // SAFETY: `si` is live; the slots are this frame's.
    let ret = unsafe { ossl_cms_signerinfo_get_signing_cert(si, &mut ss) } >= 0
        // SAFETY: `si` is live.
        && unsafe { ossl_cms_signerinfo_get_signing_cert_v2(si, &mut ssv2) } >= 0
        // SAFETY: the ESS checker is Phase 12.7's export; the pointers are NULL or live.
        && unsafe { OSSL_ESS_check_signing_certs(ss, ssv2, chain, 1) } > 0;

    // SAFETY: each is NULL or owned.
    unsafe {
        ESS_SIGNING_CERT_free(ss);
        ESS_SIGNING_CERT_V2_free(ssv2);
    }
    c_int::from(ret)
}

/// `CMS_ReceiptRequest *CMS_ReceiptRequest_create0_ex(unsigned char *id, int idlen,`
/// `int allorfirst, STACK_OF(GENERAL_NAMES) *receiptList,`
/// `STACK_OF(GENERAL_NAMES) *receiptsTo, OSSL_LIB_CTX *libctx)` — `cms_ess.c:116-157`.
///
/// # Safety
/// `id` is NULL or readable for `idlen`; the stacks are NULL or live and ownership passes to the
/// result.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ReceiptRequest_create0_ex(
    id: *mut c_uchar,
    idlen: c_int,
    allorfirst: c_int,
    receipt_list: *mut OpenSslStack,
    receipts_to: *mut OpenSslStack,
    libctx: *mut c_void,
) -> *mut CmsReceiptRequest {
    // SAFETY: the item answers a fresh receipt request.
    let rr = unsafe { CMS_ReceiptRequest_new() };
    if rr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(125, c"CMS_ReceiptRequest_create0_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `rr` is live.
    if !id.is_null() {
        // SAFETY: `rr` is live; `id` ownership transfers.
        unsafe { ASN1_STRING_set0((*rr).signed_content_identifier, id.cast(), idlen) };
    } else {
        // SAFETY: `rr` is live; the string answers a 32-byte block.
        if unsafe { ASN1_STRING_set((*rr).signed_content_identifier, ptr::null(), 32) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(132, c"CMS_ReceiptRequest_create0_ex", ERR_R_ASN1_LIB) };
            // SAFETY: `rr` is owned here.
            unsafe { CMS_ReceiptRequest_free(rr) };
            return ptr::null_mut();
        }
        // SAFETY: `rr` is live.
        let data = unsafe { (*(*rr).signed_content_identifier).data };
        // SAFETY: `libctx` is NULL or live; `data` is 32 bytes.
        if unsafe { RAND_bytes_ex(libctx, data, 32, 0) } <= 0 {
            // SAFETY: `rr` is owned here.
            unsafe { CMS_ReceiptRequest_free(rr) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `rr` is live; the old stack is owned by the caller's value.
    unsafe { OPENSSL_sk_pop_free((*rr).receipts_to, Some(general_names_free_void)) };
    // SAFETY: `rr` is live.
    unsafe { (*rr).receipts_to = receipts_to };

    // SAFETY: `rr` is live.
    let rf = unsafe { (*rr).receipts_from };
    if !receipt_list.is_null() {
        // SAFETY: `rf` is live.
        unsafe {
            (*rf).type_ = 1;
            (*rf).d = receipt_list.cast();
        }
    } else {
        // SAFETY: `rf` is live; the union's `allOrFirstTier` member is an int in the pointer slot.
        unsafe {
            (*rf).type_ = 0;
            ptr::write(ptr::addr_of_mut!((*rf).d).cast::<c_int>(), allorfirst);
        }
    }

    rr
}

/// `CMS_ReceiptRequest *CMS_ReceiptRequest_create0(unsigned char *id, int idlen,`
/// `int allorfirst, STACK_OF(GENERAL_NAMES) *receiptList,`
/// `STACK_OF(GENERAL_NAMES) *receiptsTo)` — `cms_ess.c:159-165`.
///
/// # Safety
/// As [`CMS_ReceiptRequest_create0_ex`] with a NULL `libctx`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ReceiptRequest_create0(
    id: *mut c_uchar,
    idlen: c_int,
    allorfirst: c_int,
    receipt_list: *mut OpenSslStack,
    receipts_to: *mut OpenSslStack,
) -> *mut CmsReceiptRequest {
    // SAFETY: the arguments are the caller's.
    unsafe {
        CMS_ReceiptRequest_create0_ex(
            id,
            idlen,
            allorfirst,
            receipt_list,
            receipts_to,
            ptr::null_mut(),
        )
    }
}

/// `int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr)` —
/// `cms_ess.c:167-190`.
///
/// # Safety
/// `si`/`rr` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_ReceiptRequest(
    si: *mut CmsSignerInfo,
    rr: *mut CmsReceiptRequest,
) -> c_int {
    let mut rrder: *mut c_uchar = ptr::null_mut();

    // SAFETY: `rr` is live; `rrder` is this frame's slot.
    let rrderlen = unsafe { i2d_CMS_ReceiptRequest(rr, &mut rrder) };
    if rrderlen < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(174, c"CMS_add1_ReceiptRequest", ERR_R_CMS_LIB) };
        // SAFETY: `rrder` is NULL or owned here.
        unsafe { crate::runtime::mem::CRYPTO_free(rrder.cast(), c"cms_ess.c".as_ptr(), 187) };
        return 0;
    }

    // SAFETY: `si`/`rrder` are live.
    if unsafe {
        CMS_signed_add1_attr_by_NID(
            si,
            NID_id_smime_aa_receiptRequest,
            V_ASN1_SEQUENCE,
            rrder.cast(),
            rrderlen,
        )
    } == 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(180, c"CMS_add1_ReceiptRequest", ERR_R_CMS_LIB) };
        // SAFETY: `rrder` is owned here.
        unsafe { crate::runtime::mem::CRYPTO_free(rrder.cast(), c"cms_ess.c".as_ptr(), 187) };
        return 0;
    }

    // SAFETY: `rrder` is owned here.
    unsafe { crate::runtime::mem::CRYPTO_free(rrder.cast(), c"cms_ess.c".as_ptr(), 187) };
    1
}

/// `void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr, ASN1_STRING **pcid,`
/// `int *pallorfirst, STACK_OF(GENERAL_NAMES) **plist,`
/// `STACK_OF(GENERAL_NAMES) **prto)` — `cms_ess.c:192-213`.
///
/// # Safety
/// `rr` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_ReceiptRequest_get0_values(
    rr: *mut CmsReceiptRequest,
    pcid: *mut *mut Asn1String,
    pallorfirst: *mut c_int,
    plist: *mut *mut OpenSslStack,
    prto: *mut *mut OpenSslStack,
) {
    if !pcid.is_null() {
        // SAFETY: `pcid` is writable; `rr` is live.
        unsafe { *pcid = (*rr).signed_content_identifier };
    }
    // SAFETY: `rr` is live.
    let rf = unsafe { (*rr).receipts_from };
    // SAFETY: `rf` is live.
    if unsafe { (*rf).type_ } == 0 {
        if !pallorfirst.is_null() {
            // SAFETY: `rf` is live; the union's `allOrFirstTier` member is an int.
            unsafe {
                *pallorfirst = ptr::read(ptr::addr_of!((*rf).d).cast::<c_int>());
            }
        }
        if !plist.is_null() {
            // SAFETY: `plist` is writable.
            unsafe { *plist = ptr::null_mut() };
        }
    } else {
        if !pallorfirst.is_null() {
            // SAFETY: `pallorfirst` is writable.
            unsafe { *pallorfirst = -1 };
        }
        if !plist.is_null() {
            // SAFETY: `plist` is writable; `rf` is live.
            unsafe { *plist = (*rf).d.cast() };
        }
    }
    if !prto.is_null() {
        // SAFETY: `prto` is writable; `rr` is live.
        unsafe { *prto = (*rr).receipts_to };
    }
}

/// `static int cms_msgSigDigest(CMS_SignerInfo *si, unsigned char *dig,` `unsigned int *diglen)` —
/// `cms_ess.c:217-230`.
///
/// # Safety
/// `si` is live; `dig` is writable for `EVP_MAX_MD_SIZE`; `diglen` is writable.
unsafe fn cms_msgSigDigest(
    si: *mut CmsSignerInfo,
    dig: *mut c_uchar,
    diglen: *mut c_uint,
) -> c_int {
    // SAFETY: `si` is live.
    let aoid = unsafe { (*(*si).digest_algorithm).algorithm };
    // SAFETY: the lookup is the `EVP_get_digestbyobj` macro expansion.
    let md = unsafe { EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(aoid))) };
    if md.is_null() {
        return 0;
    }
    // SAFETY: `si` is live; the item is static; `dig`/`diglen` are the caller's.
    if unsafe {
        ossl_asn1_item_digest_ex(
            cms_attributes_verify_it(),
            md,
            (*si).signed_attrs.cast(),
            dig,
            diglen,
            ossl_cms_ctx_get0_libctx((*si).cms_ctx),
            ossl_cms_ctx_get0_propq((*si).cms_ctx),
        )
    } == 0
    {
        return 0;
    }
    1
}

/// `int ossl_cms_msgSigDigest_add1(CMS_SignerInfo *dest, CMS_SignerInfo *src)` —
/// `cms_ess.c:234-249`.
///
/// # Safety
/// `dest`/`src` are live.
pub(crate) unsafe extern "C" fn ossl_cms_msgSigDigest_add1(
    dest: *mut CmsSignerInfo,
    src: *mut CmsSignerInfo,
) -> c_int {
    let mut dig = [0u8; EVP_MAX_MD_SIZE];
    let mut diglen: c_uint = 0;

    // SAFETY: `src` is live; `dig`/`diglen` are this frame's.
    if unsafe { cms_msgSigDigest(src, dig.as_mut_ptr(), &mut diglen) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                240,
                c"ossl_cms_msgSigDigest_add1",
                crate::runtime::err::err_reasons::CMS_R_MSGSIGDIGEST_ERROR,
            )
        };
        return 0;
    }
    // SAFETY: `dest` is live; `dig` is readable for `diglen`.
    if unsafe {
        CMS_signed_add1_attr_by_NID(
            dest,
            NID_id_smime_aa_msgSigDigest,
            V_ASN1_OCTET_STRING,
            dig.as_ptr().cast(),
            diglen as c_int,
        )
    } == 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(245, c"ossl_cms_msgSigDigest_add1", ERR_R_CMS_LIB) };
        return 0;
    }
    1
}

/// `int ossl_cms_Receipt_verify(CMS_ContentInfo *cms, CMS_ContentInfo *req_cms)` —
/// `cms_ess.c:253-373`.
///
/// # Safety
/// `cms`/`req_cms` are live.
pub(crate) unsafe extern "C" fn ossl_cms_Receipt_verify(
    cms: *mut CmsContentInfo,
    req_cms: *mut CmsContentInfo,
) -> c_int {
    let mut r = 0;
    let mut rr: *mut CmsReceiptRequest = ptr::null_mut();
    let mut rct: *mut CmsReceipt = ptr::null_mut();
    let mut osi: *mut CmsSignerInfo = ptr::null_mut();
    let mut dig = [0u8; EVP_MAX_MD_SIZE];
    let mut diglen: c_uint = 0;
    let mut i;

    // Get SignerInfos, also checks SignedData content type.
    // SAFETY: `req_cms`/`cms` are live.
    let osis = unsafe { super::cms_sd::CMS_get0_SignerInfos(req_cms) };
    // SAFETY: `cms` is live.
    let sis = unsafe { super::cms_sd::CMS_get0_SignerInfos(cms) };
    if osis.is_null() || sis.is_null() {
        return r;
    }

    // SAFETY: `sis` is live.
    if unsafe { OPENSSL_sk_num(sis) } != 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                272,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NEED_ONE_SIGNER,
            )
        };
        return r;
    }

    // Check receipt content type.
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid(super::cms_lib::CMS_get0_eContentType(cms)) } != NID_id_smime_ct_receipt
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                278,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NOT_A_SIGNED_RECEIPT,
            )
        };
        return r;
    }

    // Extract and decode receipt content.
    // SAFETY: `cms` is live.
    let pcont = unsafe { super::cms_lib::CMS_get0_content(cms) };
    let pcont_empty = pcont.is_null() || {
        // SAFETY: `pcont` is a live slot (non-null per the short circuit).
        unsafe { *pcont }.is_null()
    };
    if pcont_empty {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                285,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_CONTENT,
            )
        };
        return r;
    }

    // SAFETY: `*pcont` is live; the item is static.
    rct = unsafe { ASN1_item_unpack(*pcont, cms_receipt_it()) }.cast::<CmsReceipt>();
    if rct.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                292,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_RECEIPT_DECODE_ERROR,
            )
        };
        return r;
    }

    // Locate original request.
    // SAFETY: `osis` is live.
    let osis_num = unsafe { OPENSSL_sk_num(osis) };
    i = 0;
    while i < osis_num {
        // SAFETY: `i` is in range.
        osi = unsafe { OPENSSL_sk_value(osis, i) }.cast::<CmsSignerInfo>();
        // SAFETY: `osi`/`rct` are live.
        if unsafe { ASN1_STRING_cmp((*osi).signature, (*rct).originator_signature_value) } == 0 {
            break;
        }
        i += 1;
    }

    if i == osis_num {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                305,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_SIGNATURE,
            )
        };
        return r;
    }

    // SAFETY: `sis` is live.
    let si = unsafe { OPENSSL_sk_value(sis, 0) }.cast::<CmsSignerInfo>();

    // Get msgSigDigest value and compare.
    let oid = OBJ_nid2obj(NID_id_smime_aa_msgSigDigest);
    // SAFETY: `si`/`oid` are live.
    let msig = unsafe { CMS_signed_get0_data_by_OBJ(si, oid, -3, V_ASN1_OCTET_STRING) }
        .cast::<Asn1String>();

    if msig.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                318,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_MSGSIGDIGEST,
            )
        };
        return r;
    }

    // SAFETY: `osi` is live; `dig`/`diglen` are this frame's.
    if unsafe { cms_msgSigDigest(osi, dig.as_mut_ptr(), &mut diglen) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                323,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_MSGSIGDIGEST_ERROR,
            )
        };
        return r;
    }

    // SAFETY: `msig` is live.
    if diglen != unsafe { (*msig).length } as c_uint {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                328,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_MSGSIGDIGEST_WRONG_LENGTH,
            )
        };
        return r;
    }

    // SAFETY: `msig` is live; `dig` is readable for `diglen`, as is `msig->data`.
    if unsafe {
        core::slice::from_raw_parts(dig.as_ptr(), diglen as usize)
            != core::slice::from_raw_parts((*msig).data, diglen as usize)
    } {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                333,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE,
            )
        };
        return r;
    }

    // Compare content types.
    let ctype_oid = OBJ_nid2obj(NID_pkcs9_contentType);
    // SAFETY: `osi`/`ctype_oid` are live.
    let octype = unsafe { CMS_signed_get0_data_by_OBJ(osi, ctype_oid, -3, V_ASN1_OBJECT) }
        .cast::<Asn1Object>();
    if octype.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                343,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_CONTENT_TYPE,
            )
        };
        return r;
    }

    // Compare details in receipt request.
    // SAFETY: `octype`/`rct` are live.
    if unsafe { OBJ_cmp(octype, (*rct).content_type) } != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                350,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_TYPE_MISMATCH,
            )
        };
        return r;
    }

    // Get original receipt request details.
    // SAFETY: `osi` is live; `rr` is this frame's slot.
    if unsafe { CMS_get1_ReceiptRequest(osi, &mut rr) } <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                357,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_RECEIPT_REQUEST,
            )
        };
        return r;
    }

    // SAFETY: `rr`/`rct` are live.
    if unsafe {
        ASN1_STRING_cmp(
            (*rr).signed_content_identifier,
            (*rct).signed_content_identifier,
        )
    } != 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                363,
                c"ossl_cms_Receipt_verify",
                crate::runtime::err::err_reasons::CMS_R_CONTENTIDENTIFIER_MISMATCH,
            )
        };
        return r;
    }

    r = 1;

    // SAFETY: each is NULL or owned.
    unsafe {
        CMS_ReceiptRequest_free(rr);
        m_asn1_free(rct.cast(), cms_receipt_it());
    }
    r
}

/// `ASN1_OCTET_STRING *ossl_cms_encode_Receipt(CMS_SignerInfo *si)` — `cms_ess.c:380-416`.
///
/// # Safety
/// `si` is live.
pub(crate) unsafe extern "C" fn ossl_cms_encode_Receipt(si: *mut CmsSignerInfo) -> *mut Asn1String {
    let mut rr: *mut CmsReceiptRequest = ptr::null_mut();

    // Get original receipt request details.
    // SAFETY: `si` is live; `rr` is this frame's slot.
    if unsafe { CMS_get1_ReceiptRequest(si, &mut rr) } <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                392,
                c"ossl_cms_encode_Receipt",
                crate::runtime::err::err_reasons::CMS_R_NO_RECEIPT_REQUEST,
            )
        };
        return ptr::null_mut();
    }

    // Get original content type.
    let ctype_oid = OBJ_nid2obj(NID_pkcs9_contentType);
    // SAFETY: `si`/`ctype_oid` are live.
    let ctype = unsafe { CMS_signed_get0_data_by_OBJ(si, ctype_oid, -3, V_ASN1_OBJECT) }
        .cast::<Asn1Object>();
    if ctype.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                402,
                c"ossl_cms_encode_Receipt",
                crate::runtime::err::err_reasons::CMS_R_NO_CONTENT_TYPE,
            )
        };
        // SAFETY: `rr` is owned here.
        unsafe { CMS_ReceiptRequest_free(rr) };
        return ptr::null_mut();
    }

    // SAFETY: `si`/`rr` are live.
    let mut rct = CmsReceipt {
        version: 1,
        content_type: ctype,
        // SAFETY: `rr` is live.
        signed_content_identifier: unsafe { (*rr).signed_content_identifier },
        // SAFETY: `si` is live.
        originator_signature_value: unsafe { (*si).signature },
    };

    // SAFETY: `rct` is live; the item is static; a NULL oct is the macro's own fresh-string arm.
    let os = unsafe {
        ASN1_item_pack(
            (&mut rct as *mut CmsReceipt).cast(),
            cms_receipt_it(),
            ptr::null_mut(),
        )
    };

    // SAFETY: `rr` is NULL or owned.
    unsafe { CMS_ReceiptRequest_free(rr) };
    os
}
