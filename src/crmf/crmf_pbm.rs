//! `crypto/crmf/crmf_pbm.c` — the PasswordBasedMac parameter builder and MAC. Phase 12.7.
//!
//! The two exports `crmf_pbm.c` publishes: `OSSL_CRMF_pbmp_new`, which fills an
//! `OSSL_CRMF_PBMPARAMETER` with a fresh salt, a one-way function, an iteration count and a MAC
//! algorithm, and `OSSL_CRMF_pbm_new`, which derives the base key by iterating the OWF over
//! (secret ‖ salt) and MACs the message with it. Both are reached from the CMP protection engine's
//! PasswordBasedMAC arm, which is why 12.4 left the CMP entries that need them open until 12.7.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::V_ASN1_UNDEF;
use crate::asn1::prim::{ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::ASN1_OCTET_STRING_set;
use crate::asn1::x_algor::X509_ALGOR_set0;
use crate::crmf::crmf_asn::{
    CrmfPbmParameter, OSSL_CRMF_PBMPARAMETER_free, OSSL_CRMF_PBMPARAMETER_new,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free,
};
use crate::evp::evp_pbe::{EVP_PBE_find, EVP_PBE_TYPE_PRF};
use crate::evp::mac::EVP_Q_mac;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::err::err_reasons::*;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};
use crate::runtime::obj::{Asn1Object, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/crmf/crmf_pbm.c";

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `OSSL_CRMF_PBM_MAX_ITERATION_COUNT` — `crmf_local.h:226`.
const OSSL_CRMF_PBM_MAX_ITERATION_COUNT: i64 = 100000;
/// `ERR_LIB_CRMF` — `include/openssl/err.h.in:121`.
const ERR_LIB_CRMF: c_int = 56;
/// `V_ASN1_UNDEF` in `X509_ALGOR_set0`'s terms.
const UNDEF: c_int = V_ASN1_UNDEF;

// `ERR_add_error_data(num, ...)` — `crypto/err/err.c`, declared for the failure tail's one string.
extern "C" {
    fn ERR_add_error_data(num: c_int, ...);
}

/// `ERR_raise(ERR_LIB_CRMF, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_crmf(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CRMF,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(OSSL_LIB_CTX *libctx, size_t slen, int owfnid,`
/// `size_t itercnt, int macnid)` — `crmf_pbm.c:27-101`.
///
/// # Safety
/// `libctx` is NULL or a live context; the returned parameter is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_pbmp_new(
    libctx: *mut c_void,
    slen: usize,
    owfnid: c_int,
    itercnt: usize,
    macnid: c_int,
) -> *mut CrmfPbmParameter {
    // SAFETY: the accessor answers a fresh item value.
    let pbm = OSSL_CRMF_PBMPARAMETER_new();
    if pbm.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `slen` is the caller's requested salt length.
    let salt = CRYPTO_malloc(slen, FILE.as_ptr(), 42).cast::<u8>();
    if salt.is_null() {
        // SAFETY: `pbm` is live; the free accepts NULL salt.
        unsafe { OSSL_CRMF_PBMPARAMETER_free(pbm) };
        return ptr::null_mut();
    }
    // SAFETY: `libctx` is the caller's; `salt` is writable for `slen` bytes.
    if unsafe { RAND_bytes_ex(libctx, salt, slen, 0) } <= 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(45, c"OSSL_CRMF_pbmp_new", CRMF_R_FAILURE_OBTAINING_RANDOM);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        };
        return ptr::null_mut();
    }
    // SAFETY: `pbm` is live and its `salt` is a fresh octet string.
    unsafe {
        if ASN1_OCTET_STRING_set((*pbm).salt, salt, slen as c_int) == 0 {
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
            return ptr::null_mut();
        }
        if X509_ALGOR_set0((*pbm).owf, OBJ_nid2obj(owfnid), UNDEF, ptr::null_mut()) == 0 {
            raise_crmf(57, c"OSSL_CRMF_pbmp_new", CRMF_R_SETTING_OWF_ALGOR_FAILURE);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
            return ptr::null_mut();
        }
    }
    if itercnt < 100 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(72, c"OSSL_CRMF_pbmp_new", CRMF_R_ITERATIONCOUNT_BELOW_100);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        };
        return ptr::null_mut();
    }
    if itercnt as i64 > OSSL_CRMF_PBM_MAX_ITERATION_COUNT {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(76, c"OSSL_CRMF_pbmp_new", CRMF_R_BAD_PBM_ITERATIONCOUNT);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
        };
        return ptr::null_mut();
    }
    // SAFETY: `pbm` is live and its `iteration_count` is a fresh integer.
    unsafe {
        if ASN1_INTEGER_set((*pbm).iteration_count, itercnt as c_long) == 0 {
            raise_crmf(81, c"OSSL_CRMF_pbmp_new", CRMF_R_CRMFERROR);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
            return ptr::null_mut();
        }
        if X509_ALGOR_set0((*pbm).mac, OBJ_nid2obj(macnid), UNDEF, ptr::null_mut()) == 0 {
            raise_crmf(91, c"OSSL_CRMF_pbmp_new", CRMF_R_SETTING_MAC_ALGOR_FAILURE);
            CRYPTO_free(salt.cast(), FILE.as_ptr(), 98);
            OSSL_CRMF_PBMPARAMETER_free(pbm);
            return ptr::null_mut();
        }
    }
    // SAFETY: `salt` is a heap buffer this function owns.
    unsafe { CRYPTO_free(salt.cast(), FILE.as_ptr(), 95) };
    pbm
}

/// `int OSSL_CRMF_pbm_new(OSSL_LIB_CTX *libctx, const char *propq, const OSSL_CRMF_PBMPARAMETER`
/// `*pbmp, const unsigned char *msg, size_t msglen, const unsigned char *sec, size_t seclen,`
/// `unsigned char **out, size_t *outlen)` — `crmf_pbm.c:115-223`.
///
/// # Safety
/// `pbmp`/`msg`/`sec` are NULL or live buffers of their stated lengths; `out`/`outlen` are NULL or
/// writable; on success `*out` owns a fresh buffer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_pbm_new(
    libctx: *mut c_void,
    propq: *const c_char,
    pbmp: *const CrmfPbmParameter,
    msg: *const c_uchar,
    msglen: usize,
    sec: *const c_uchar,
    seclen: usize,
    out: *mut *mut c_uchar,
    outlen: *mut usize,
) -> c_int {
    let mut hmac_md_nid: c_int = crate::runtime::obj::NID_undef;
    let mut mdname = [0i8; OSSL_MAX_NAME_SIZE];
    let mut hmac_mdname = [0i8; OSSL_MAX_NAME_SIZE];
    let mut basekey = [0u8; EVP_MAX_MD_SIZE];
    let mut bklen: c_uint = EVP_MAX_MD_SIZE as c_uint;
    let mut ok = 0;

    if out.is_null()
        || pbmp.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || unsafe { (*pbmp).mac }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || unsafe { (*(*pbmp).mac).algorithm }.is_null()
        || msg.is_null()
        || sec.is_null()
    {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(134, c"OSSL_CRMF_pbm_new", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `EVP_MAX_MD_SIZE` is the authority's upper bound.
    let mac_res = CRYPTO_malloc(EVP_MAX_MD_SIZE, FILE.as_ptr(), 137).cast::<u8>();
    if mac_res.is_null() {
        return 0;
    }
    // SAFETY: `pbmp` is live per the check above; `mdname` is writable.
    unsafe {
        OBJ_obj2txt(
            mdname.as_mut_ptr(),
            mdname.len() as c_int,
            (*(*pbmp).owf).algorithm,
            0,
        )
    };
    // SAFETY: `mdname` is NUL-terminated; `libctx`/`propq` are the caller's.
    let owf = unsafe { EVP_MD_fetch(libctx, mdname.as_ptr(), propq) };
    if owf.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(147, c"OSSL_CRMF_pbm_new", CRMF_R_UNSUPPORTED_ALGORITHM);
            CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214);
        };
        return 0;
    }
    // SAFETY: no preconditions.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            EVP_MD_free(owf);
            CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214);
        };
        return 0;
    }
    // SAFETY: `ctx`/`owf` are live; the code drains the secret then the salt.
    let mut iterations: i64 = 0;
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    unsafe {
        if EVP_DigestInit_ex(ctx, owf, ptr::null_mut()) == 0
            || EVP_DigestUpdate(ctx, sec.cast(), seclen) == 0
            || EVP_DigestUpdate(
                ctx,
                (*(*pbmp).salt).data.cast(),
                (*(*pbmp).salt).length as usize,
            ) == 0
            || EVP_DigestFinal_ex(ctx, basekey.as_mut_ptr(), &mut bklen) == 0
            || ASN1_INTEGER_get_int64(&mut iterations, (*pbmp).iteration_count) == 0
            || !(100..=OSSL_CRMF_PBM_MAX_ITERATION_COUNT).contains(&iterations)
        {
            raise_crmf(168, c"OSSL_CRMF_pbm_new", CRMF_R_BAD_PBM_ITERATIONCOUNT);
            OPENSSL_cleanse(basekey.as_mut_ptr().cast(), bklen as usize);
            EVP_MD_free(owf);
            EVP_MD_CTX_free(ctx);
            CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214);
            return 0;
        }
        while {
            iterations -= 1;
            iterations > 0
        } {
            if EVP_DigestInit_ex(ctx, owf, ptr::null_mut()) == 0
                || EVP_DigestUpdate(ctx, basekey.as_ptr().cast(), bklen as usize) == 0
                || EVP_DigestFinal_ex(ctx, basekey.as_mut_ptr(), &mut bklen) == 0
            {
                OPENSSL_cleanse(basekey.as_mut_ptr().cast(), bklen as usize);
                EVP_MD_free(owf);
                EVP_MD_CTX_free(ctx);
                CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214);
                return 0;
            }
        }
        let mac_nid = OBJ_obj2nid((*(*pbmp).mac).algorithm);
        let mut pcnid: c_int = 0;
        if EVP_PBE_find(
            EVP_PBE_TYPE_PRF,
            mac_nid,
            &mut pcnid,
            &mut hmac_md_nid,
            ptr::null_mut(),
        ) == 0
            || OBJ_obj2txt(
                hmac_mdname.as_mut_ptr(),
                hmac_mdname.len() as c_int,
                OBJ_nid2obj(hmac_md_nid),
                0,
            ) <= 0
        {
            raise_crmf(193, c"OSSL_CRMF_pbm_new", CRMF_R_UNSUPPORTED_ALGORITHM);
            OPENSSL_cleanse(basekey.as_mut_ptr().cast(), bklen as usize);
            EVP_MD_free(owf);
            EVP_MD_CTX_free(ctx);
            CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214);
            return 0;
        }
        if EVP_Q_mac(
            libctx,
            c"HMAC".as_ptr(),
            propq,
            hmac_mdname.as_ptr(),
            ptr::null(),
            basekey.as_ptr().cast(),
            bklen as usize,
            msg,
            msglen,
            mac_res,
            EVP_MAX_MD_SIZE,
            outlen,
        )
        .is_null()
        {
            // fall through to the shared failure tail
        } else {
            ok = 1;
        }
        OPENSSL_cleanse(basekey.as_mut_ptr().cast(), bklen as usize);
        EVP_MD_free(owf);
        EVP_MD_CTX_free(ctx);
    }

    if ok == 1 {
        // SAFETY: `out` is writable per the check above.
        unsafe { *out = mac_res };
        return 1;
    }
    // SAFETY: `mac_res` is a heap buffer this function owns.
    unsafe { CRYPTO_free(mac_res.cast(), FILE.as_ptr(), 214) };
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    if !pbmp.is_null() && !unsafe { (*pbmp).mac }.is_null() {
        let mut buf = [0i8; 128];
        // SAFETY: `buf` is writable; the algorithm is live.
        if unsafe {
            OBJ_obj2txt(
                buf.as_mut_ptr(),
                buf.len() as c_int,
                (*(*pbmp).mac).algorithm,
                0,
            )
        } != 0
        {
            // SAFETY: the one-argument variadic `ERR_add_error_data`; `buf` is NUL-terminated.
            unsafe { ERR_add_error_data(1, buf.as_ptr()) };
        }
    }
    0
}

/// Keep the unused `Asn1Object` import meaningful for the OID type documentation.
const _: fn(*mut Asn1Object) = |_| {};
