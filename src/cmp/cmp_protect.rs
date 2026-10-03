//! `crypto/cmp/cmp_protect.c` — the CMP message protection engine. Phase 12.4b.
//!
//! This unit transcribes the three free functions of `cmp_protect.c`: the protection calculator
//! `ossl_cmp_calc_protection`, the own-chain builder `ossl_cmp_set_own_chain`, the extra-cert
//! adder `ossl_cmp_msg_add_extraCerts` and the message protector `ossl_cmp_msg_protect`, together
//! with the static `pbmac_algor` and `set_senderKID` helpers. It was the last non-`cmp/`
//! prerequisite 12.4 named: the PasswordBasedMAC arm reaches `OSSL_CRMF_pbm_new`, which 12.7
//! landed.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::a_sign::ASN1_item_sign_ex;
use crate::asn1::bitstr::ASN1_BIT_STRING_set;
use crate::asn1::layout::{Asn1String, V_ASN1_SEQUENCE};
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_BIT_STRING_new, ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set,
};
use crate::asn1::x_algor::{
    ossl_X509_ALGOR_from_nid, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_new,
};
use crate::cmp::cmp_asn::{
    cmp_protectedpart_it, i2d_OSSL_CMP_PROTECTEDPART, CmpMsg, CmpProtectedPart,
};
use crate::cmp::cmp_ctx::{OSSL_CMP_CTX_print_errors, OsslCmpCtx};
use crate::cmp::cmp_hdr::{ossl_cmp_general_name_is_NULL_DN, ossl_cmp_hdr_set1_senderKID};
use crate::cms::cms_asn1::ossl_asn1_string_set_bits_left;
use crate::crmf::crmf_asn::{
    d2i_OSSL_CRMF_PBMPARAMETER, i2d_OSSL_CRMF_PBMPARAMETER, OSSL_CRMF_PBMPARAMETER_free,
};
use crate::crmf::crmf_pbm::{OSSL_CRMF_pbm_new, OSSL_CRMF_pbmp_new};
use crate::evp::digest::EVP_MD_get_type;
use crate::evp::pkey::EVP_PKEY_get_default_digest_name;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{NID_id_PasswordBasedMAC, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_num};
use crate::x509::v3_genn::GeneralName;
use crate::x509::v3_purp::X509_get0_subject_key_id;
use crate::x509::x509_cmp::{
    ossl_x509_add_cert_new, ossl_x509_add_certs_new, X509_check_private_key,
};
use crate::x509::x509_vfy::X509_build_chain;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_protect.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h.in:801`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_PREPEND` — `include/openssl/x509.h.in:802`.
const X509_ADD_FLAG_PREPEND: c_int = 0x2;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h.in:803`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;
/// `X509_ADD_FLAG_NO_SS` — `include/openssl/x509.h.in:804`.
const X509_ADD_FLAG_NO_SS: c_int = 0x8;

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CMP,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `ASN1_BIT_STRING *ossl_cmp_calc_protection(const OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)`
/// — `cmp_protect.c:26-124`. Internal.
///
/// # Safety
/// `ctx` a live `OSSL_CMP_CTX`; `msg` a live `OSSL_CMP_MSG` with a live header and body.
pub(crate) unsafe fn ossl_cmp_calc_protection(
    ctx: *const OsslCmpCtx,
    msg: *const CmpMsg,
) -> *mut Asn1String {
    if ctx.is_null() || msg.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `msg` is live; the two slots belong to the protected part.
    let prot_part = CmpProtectedPart {
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        header: unsafe { (*msg).header },
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        body: unsafe { (*msg).body },
    };

    // SAFETY: `msg` is live.
    let protection_alg = unsafe { (*(*msg).header).protection_alg };
    if protection_alg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(43, c"ossl_cmp_calc_protection", 134) };
        return ptr::null_mut();
    }
    let mut algor_oid: *const Asn1Object = ptr::null();
    let mut pptype: c_int = 0;
    let mut ppval: *const c_void = ptr::null();
    // SAFETY: `protection_alg` is live and the three slots are writable.
    unsafe { X509_ALGOR_get0(&mut algor_oid, &mut pptype, &mut ppval, protection_alg) };

    // SAFETY: `algor_oid` is the algorithm the accessor just read.
    if unsafe { OBJ_obj2nid(algor_oid) } == NID_id_PasswordBasedMAC {
        let mut prot_part_der: *mut u8 = ptr::null_mut();
        let mut sig_len: usize = 0;
        let mut protection: *mut u8 = ptr::null_mut();
        let mut pbm: *mut crate::crmf::crmf_asn::CrmfPbmParameter = ptr::null_mut();
        let mut prot: *mut Asn1String;

        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).secret_value }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(59, c"ossl_cmp_calc_protection", 166) };
            return ptr::null_mut();
        }
        if pptype != V_ASN1_SEQUENCE || ppval.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(63, c"ossl_cmp_calc_protection", 115) };
            return ptr::null_mut();
        }

        // SAFETY: `prot_part` is a live local; the slot is writable.
        let len: c_int =
            unsafe { i2d_OSSL_CMP_PROTECTEDPART(ptr::addr_of!(prot_part), &mut prot_part_der) };
        if len < 0 || prot_part_der.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(69, c"ossl_cmp_calc_protection", 115) };
            // SAFETY: both are NULL or allocated here.
            unsafe {
                CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
                CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
            }
            return ptr::null_mut();
        }

        // SAFETY: `ppval` is the ASN1_STRING carrying the PBMPARAMETER per the type check.
        let pbm_str = ppval as *const Asn1String;
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        let pbm_str_len = unsafe { (*pbm_str).length };
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        let mut pbm_str_uc: *const u8 = unsafe { (*pbm_str).data };
        // SAFETY: the cursor and length describe the string's content.
        pbm = unsafe { d2i_OSSL_CRMF_PBMPARAMETER(&mut pbm, &mut pbm_str_uc, pbm_str_len as i64) };
        if pbm.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(78, c"ossl_cmp_calc_protection", 138) };
            // SAFETY: both are NULL or allocated here.
            unsafe {
                CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
                CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
            }
            return ptr::null_mut();
        }

        // SAFETY: `ctx` is live; `pbm` and the buffers are the caller's.
        let secret = unsafe { (*ctx).secret_value };
        // SAFETY: `secret` is live per the check above.
        let (secret_data, secret_len) = unsafe { ((*secret).data, (*secret).length) };
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        let ok = unsafe {
            OSSL_CRMF_pbm_new(
                (*ctx).libctx,
                (*ctx).propq,
                pbm,
                prot_part_der,
                len as usize,
                secret_data,
                secret_len as usize,
                &mut protection,
                &mut sig_len,
            )
        };
        if ok == 0 {
            // SAFETY: the failure path owns the four allocations.
            unsafe {
                OSSL_CRMF_PBMPARAMETER_free(pbm);
                CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
                CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
            }
            return ptr::null_mut();
        }

        if sig_len > c_int::MAX as usize {
            // SAFETY: the failure path owns the four allocations.
            unsafe {
                OSSL_CRMF_PBMPARAMETER_free(pbm);
                CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
                CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ASN1_BIT_STRING_new` returns a fresh string or NULL.
        prot = ASN1_BIT_STRING_new();
        if prot.is_null() {
            // SAFETY: the failure path owns the four allocations.
            unsafe {
                OSSL_CRMF_PBMPARAMETER_free(pbm);
                CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
                CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
            }
            return ptr::null_mut();
        }
        // SAFETY: `prot` is live.
        unsafe { ossl_asn1_string_set_bits_left(prot, 0) };
        // SAFETY: `prot` is live and the buffer readable for `sig_len`.
        if unsafe { ASN1_BIT_STRING_set(prot, protection, sig_len as c_int) } == 0 {
            // SAFETY: `prot` is this call's own object.
            unsafe { ASN1_BIT_STRING_free(prot) };
            prot = ptr::null_mut();
        }
        // SAFETY: the four allocations are NULL or this call's own.
        unsafe {
            OSSL_CRMF_PBMPARAMETER_free(pbm);
            CRYPTO_free(protection.cast(), FILE.as_ptr(), 98);
            CRYPTO_free(prot_part_der.cast(), FILE.as_ptr(), 99);
        }
        prot
    } else {
        // SAFETY: `ctx` is live.
        let mut md = unsafe { (*ctx).digest };
        let mut name = [0 as c_char; 80];
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).pkey }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(107, c"ossl_cmp_calc_protection", 130) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx`'s key is live; `name` is a writable 80-byte buffer.
        if unsafe { EVP_PKEY_get_default_digest_name((*ctx).pkey, name.as_mut_ptr(), name.len()) }
            > 0
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            && unsafe { crate::runtime::bio::sys::strcmp(name.as_ptr(), c"UNDEF".as_ptr()) } == 0
        {
            md = ptr::null_mut();
        }

        // SAFETY: `ASN1_BIT_STRING_new` returns a fresh string or NULL.
        let prot = ASN1_BIT_STRING_new();
        if prot.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx`/`msg` are live; `prot_part` is a live local; `prot` is writable.
        if unsafe {
            ASN1_item_sign_ex(
                cmp_protectedpart_it(),
                protection_alg,
                ptr::null_mut(),
                prot,
                ptr::addr_of!(prot_part).cast(),
                ptr::null(),
                (*ctx).pkey,
                md,
                (*ctx).libctx,
                (*ctx).propq,
            )
        } != 0
        {
            return prot;
        }
        // SAFETY: `prot` is this call's own object.
        unsafe { ASN1_BIT_STRING_free(prot) };
        ptr::null_mut()
    }
}

/// `void ossl_cmp_set_own_chain(OSSL_CMP_CTX *ctx)` — `cmp_protect.c:126-143`. Internal.
///
/// # Safety
/// `ctx` a live `OSSL_CMP_CTX`.
pub(crate) unsafe fn ossl_cmp_set_own_chain(ctx: *mut OsslCmpCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).chain }.is_null() {
        // SAFETY: `ctx` is live.
        let chain = unsafe {
            X509_build_chain(
                (*ctx).cert,
                (*ctx).untrusted,
                ptr::null_mut(),
                0,
                (*ctx).libctx,
                (*ctx).propq,
            )
        };
        // SAFETY: `ctx` is live and the field is a writable slot.
        unsafe { (*ctx).chain = chain };
        if !chain.is_null() {
            // SAFETY: `ctx` is live.
            unsafe {
                crate::cmp::cmp_util::ossl_cmp_log0(
                    crate::cmp::cmp_util::OSSL_CMP_LOG_DEBUG,
                    ctx,
                    c"ossl_cmp_set_own_chain",
                    136,
                    c"success building chain for own CMP signer cert",
                )
            };
        } else {
            /* dump errors to avoid confusion when printing further ones */
            // SAFETY: `ctx` is live.
            unsafe {
                OSSL_CMP_CTX_print_errors(ctx);
                crate::cmp::cmp_util::ossl_cmp_log0(
                    crate::cmp::cmp_util::OSSL_CMP_LOG_WARNING,
                    ctx,
                    c"ossl_cmp_set_own_chain",
                    140,
                    c"could not build chain for own CMP signer cert",
                );
            }
        }
    }
}

/// `int ossl_cmp_msg_add_extraCerts(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)` — `cmp_protect.c:146-180`.
/// Internal.
///
/// # Safety
/// `ctx`/`msg` are live.
pub(crate) unsafe fn ossl_cmp_msg_add_extraCerts(ctx: *mut OsslCmpCtx, msg: *mut CmpMsg) -> c_int {
    if ctx.is_null() || msg.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).unprotected_send != 0 }
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { (*ctx).secret_value }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && !unsafe { (*ctx).cert }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && !unsafe { (*ctx).pkey }.is_null()
    {
        let prepend = X509_ADD_FLAG_UP_REF
            | X509_ADD_FLAG_NO_DUP
            | X509_ADD_FLAG_PREPEND
            | X509_ADD_FLAG_NO_SS;

        // SAFETY: `ctx` is live.
        unsafe { ossl_cmp_set_own_chain(ctx) };
        // SAFETY: `ctx` is live.
        let chain = unsafe { (*ctx).chain };
        if !chain.is_null() {
            // SAFETY: `msg` is live and its field is a writable slot; `chain` is live.
            if unsafe {
                ossl_x509_add_certs_new(ptr::addr_of_mut!((*msg).extra_certs), chain, prepend)
            } == 0
            {
                return 0;
            }
        } else {
            /* make sure that at least our own signer cert is included first */
            // SAFETY: `msg` is live and the field is a writable slot; `ctx`'s cert is live.
            if unsafe {
                ossl_x509_add_cert_new(ptr::addr_of_mut!((*msg).extra_certs), (*ctx).cert, prepend)
            } == 0
            {
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe {
                crate::cmp::cmp_util::ossl_cmp_log0(
                    crate::cmp::cmp_util::OSSL_CMP_LOG_DEBUG,
                    ctx,
                    c"ossl_cmp_msg_add_extraCerts",
                    165,
                    c"fallback: adding just own CMP signer cert",
                )
            };
        }
    }

    /* add any additional certificates from ctx->extraCertsOut */
    // SAFETY: `msg` is live and the field is a writable slot; `ctx`'s stack is live.
    if unsafe {
        ossl_x509_add_certs_new(
            ptr::addr_of_mut!((*msg).extra_certs),
            (*ctx).extra_certs_out,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
        )
    } == 0
    {
        return 0;
    }

    /* in case extraCerts are empty list avoid empty ASN.1 sequence */
    // SAFETY: `msg` is live.
    if unsafe { OPENSSL_sk_num((*msg).extra_certs) } == 0 {
        // SAFETY: `msg`'s field is a live stack or NULL.
        unsafe {
            OPENSSL_sk_free((*msg).extra_certs);
            (*msg).extra_certs = ptr::null_mut();
        }
    }
    1
}

/// `static X509_ALGOR *pbmac_algor(const OSSL_CMP_CTX *ctx)` — `cmp_protect.c:186-215`.
///
/// # Safety
/// `ctx` a live `OSSL_CMP_CTX`.
unsafe fn pbmac_algor(ctx: *const OsslCmpCtx) -> *mut crate::asn1::x_algor::X509Algor {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let mut pbm_der: *mut u8 = ptr::null_mut();

    // SAFETY: `ctx` is live.
    let pbm = unsafe {
        OSSL_CRMF_pbmp_new(
            (*ctx).libctx,
            (*ctx).pbm_slen,
            EVP_MD_get_type((*ctx).pbm_owf),
            (*ctx).pbm_itercnt as usize,
            (*ctx).pbm_mac,
        )
    };
    // SAFETY: `ASN1_STRING_new` returns a fresh string or NULL.
    let pbm_str = ASN1_STRING_new();
    if pbm.is_null() || pbm_str.is_null() {
        // SAFETY: `pbm_str` is NULL or this call's own; `pbm_der`/`pbm` likewise.
        unsafe {
            ASN1_STRING_free(pbm_str);
            CRYPTO_free(pbm_der.cast(), FILE.as_ptr(), 212);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        }
        return ptr::null_mut();
    }
    // SAFETY: `pbm` is live; the slot is writable.
    let pbm_der_len = unsafe { i2d_OSSL_CRMF_PBMPARAMETER(pbm, &mut pbm_der) };
    if pbm_der_len < 0 {
        // SAFETY: `pbm_str` is this call's own.
        unsafe {
            ASN1_STRING_free(pbm_str);
            CRYPTO_free(pbm_der.cast(), FILE.as_ptr(), 212);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        }
        return ptr::null_mut();
    }
    // SAFETY: `pbm_str` is live; `pbm_der` readable for `pbm_der_len`.
    if unsafe { ASN1_STRING_set(pbm_str, pbm_der.cast(), pbm_der_len) } == 0 {
        // SAFETY: `pbm_str` is this call's own.
        unsafe {
            ASN1_STRING_free(pbm_str);
            CRYPTO_free(pbm_der.cast(), FILE.as_ptr(), 212);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        }
        return ptr::null_mut();
    }
    // SAFETY: `pbm_der`/`pbm` are this call's own.
    unsafe {
        let alg =
            ossl_X509_ALGOR_from_nid(NID_id_PasswordBasedMAC, V_ASN1_SEQUENCE, pbm_str.cast());
        if alg.is_null() {
            ASN1_STRING_free(pbm_str);
        }
        CRYPTO_free(pbm_der.cast(), FILE.as_ptr(), 212);
        OSSL_CRMF_PBMPARAMETER_free(pbm);
        alg
    }
}

/// `static int set_senderKID(const OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg, const ASN1_OCTET_STRING`
/// `*id)` — `cmp_protect.c:217-223`.
///
/// # Safety
/// `ctx`/`msg` are live; `id` is NULL or live.
unsafe fn set_senderKID(ctx: *const OsslCmpCtx, msg: *mut CmpMsg, id: *const Asn1String) -> c_int {
    let id = if id.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).reference_value }
    } else {
        id.cast_mut()
    };
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    c_int::from(id.is_null() || unsafe { ossl_cmp_hdr_set1_senderKID((*msg).header, id) } != 0)
}

/// `int ossl_cmp_msg_protect(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)` — `cmp_protect.c:226-306`.
/// Internal.
///
/// # Safety
/// `ctx`/`msg` are live.
pub(crate) unsafe fn ossl_cmp_msg_protect(ctx: *mut OsslCmpCtx, msg: *mut CmpMsg) -> c_int {
    if ctx.is_null() || msg.is_null() {
        return 0;
    }

    /*
     * For the case of re-protection remove pre-existing protection.
     * Does not remove any pre-existing extraCerts.
     */
    // SAFETY: `msg` is live.
    unsafe {
        X509_ALGOR_free((*(*msg).header).protection_alg);
        (*(*msg).header).protection_alg = ptr::null_mut();
        ASN1_BIT_STRING_free((*msg).protection);
        (*msg).protection = ptr::null_mut();
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).unprotected_send } != 0 {
        // SAFETY: `ctx`/`msg` are live.
        if unsafe { set_senderKID(ctx, msg, ptr::null()) } == 0 {
            /* goto err */
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    } else if !unsafe { (*ctx).secret_value }.is_null() {
        /* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
        // SAFETY: `ctx` is live.
        let alg = unsafe { pbmac_algor(ctx) };
        // SAFETY: `msg` is live.
        unsafe { (*(*msg).header).protection_alg = alg };
        if alg.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
        // SAFETY: `ctx`/`msg` are live.
        if unsafe { set_senderKID(ctx, msg, ptr::null()) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    } else if !unsafe { (*ctx).cert }.is_null() && !unsafe { (*ctx).pkey }.is_null() {
        /* use MSG_SIG_ALG according to 5.1.3.3 if client cert and key given */

        /* make sure that key and certificate match */
        // SAFETY: `ctx`'s cert and key are live.
        if unsafe { X509_check_private_key((*ctx).cert, (*ctx).pkey) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(260, c"ossl_cmp_msg_protect", 114) };
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }

        // SAFETY: `X509_ALGOR_new` returns a fresh algorithm or NULL.
        let alg = X509_ALGOR_new();
        // SAFETY: `msg` is live.
        unsafe { (*(*msg).header).protection_alg = alg };
        if alg.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
        /* set senderKID to keyIdentifier of the cert according to 5.1.1 */
        // SAFETY: `ctx`'s cert is live.
        if unsafe { set_senderKID(ctx, msg, X509_get0_subject_key_id((*ctx).cert)) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(276, c"ossl_cmp_msg_protect", 130) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
        return 0;
    }
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { (*ctx).unprotected_send } == 0 {
        // SAFETY: `ctx`/`msg` are live.
        let protection = unsafe { ossl_cmp_calc_protection(ctx, msg) };
        // SAFETY: `msg` is live.
        unsafe { (*msg).protection = protection };
        if protection.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
            return 0;
        }
    }

    /*
     * For signature-based protection add ctx->cert followed by its chain.
     * Finally add any additional certificates from ctx->extraCertsOut.
     */
    // SAFETY: `ctx`/`msg` are live.
    if unsafe { ossl_cmp_msg_add_extraCerts(ctx, msg) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
        return 0;
    }

    /*
     * As required by RFC 9810 section 5.1.1, if the sender name is not known to the client it is
     * set to NULL-DN. In this case for identification at least the senderKID must be set, where we
     * took the referenceValue as fallback.
     */
    // SAFETY: `msg` is live.
    if !(unsafe { ossl_cmp_general_name_is_NULL_DN((*(*msg).header).sender.cast::<GeneralName>()) }
        != 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { (*(*msg).header).sender_kid }.is_null())
    {
        return 1;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(301, c"ossl_cmp_msg_protect", 111) };
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(304, c"ossl_cmp_msg_protect", 127) };
    0
}
