//! `crypto/pkcs7/pk7_smime.c` — the simple PKCS#7 sign/verify/encrypt/decrypt functions.
//! Phase 12.2.
//!
//! The signer engine (`PKCS7_sign(_ex)`, `PKCS7_final`, `PKCS7_sign_add_signer`), the verifier
//! (`PKCS7_verify`, `PKCS7_get0_signers`) and the enveloped engine (`PKCS7_encrypt(_ex)`,
//! `PKCS7_decrypt`).
//!
//! ## The one delegate that is 12.9's
//!
//! `PKCS7_verify` and `PKCS7_decrypt` call `SMIME_text` under `PKCS7_TEXT`
//! (`pk7_smime.c:331,517`), and `PKCS7_text`'s owning unit is `crypto/asn1/asn_mime.c`, one of
//! the Phase-5 hand-offs 12.9 lands. The declaration below is the authority's own `asn1.h`
//! prototype, so when 12.9 lands the unit the arm binds to it. The court never reaches it:
//! without a key and a certificate there is no signer for the verifier to walk.
//!
//! `ERR_raise_data`'s formatted data is also unusual here: the crate's error API exposes
//! [`crate::runtime::err::raise_site`] (reason and coordinate, no data) and
//! `raise_site_data` (a fixed string). The certificate-verify arm at `pk7_smime.c:298` raises
//! its `PKCS7_R_CERTIFICATE_VERIFY_ERROR` through `raise_site`, so the reason and the coordinate
//! are exact and the `"Verify error: %s"` textual suffix is not reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::asn_mime::SMIME_crlf_copy;
use crate::asn1::x_algor::X509_ALGOR_free;
use crate::evp::cipher::EvpCipher;
use crate::evp::digest::EvpMd;
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::evp::pkey::EvpPkey;
use crate::pkcs7::pk7_asn1::{Pkcs7, Pkcs7SignerInfo};
use crate::pkcs7::pk7_attr::{
    PKCS7_add1_attrib_digest, PKCS7_add_attrib_content_type, PKCS7_add_attrib_smimecap,
    PKCS7_simple_smimecap,
};
use crate::pkcs7::pk7_doit::{
    bio_get_cipher_status, bio_set_mem_eof_return, PKCS7_SIGNER_INFO_sign, PKCS7_dataDecode,
    PKCS7_dataFinal, PKCS7_dataInit, PKCS7_digest_from_attributes, PKCS7_signatureVerify,
};
use crate::pkcs7::pk7_lib::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_get0_ctx,
    pkcs7_get0_certificates, pkcs7_type_is_enveloped, pkcs7_type_is_signed,
    pkcs7_type_is_signed_and_enveloped, PKCS7_add_certificate, PKCS7_add_recipient,
    PKCS7_add_signature, PKCS7_content_new, PKCS7_ctrl, PKCS7_get_signer_info, PKCS7_set_cipher,
    PKCS7_set_type,
};
use crate::runtime::bio::bf_buff::BIO_f_buffer;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_push, BIO_read,
    BIO_write, Bio, BIO_CTRL_FLUSH, BIO_TYPE_CIPHER,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    NID_aes_128_cbc, NID_aes_192_cbc, NID_aes_256_cbc, NID_des_cbc, NID_des_ede3_cbc,
    NID_id_Gost28147_89, NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512, NID_id_GostR3411_94,
    NID_pkcs7_data, NID_pkcs7_enveloped, NID_pkcs7_signed, NID_rc2_cbc, OBJ_cmp, OBJ_nid2sn,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_cmp::{
    ossl_x509_add_certs_new, X509_check_private_key, X509_find_by_issuer_and_serial,
};
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_txt::X509_verify_cert_error_string;
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set0_crls, X509_STORE_CTX_set_default, X509_verify_cert,
};
use crate::x509::x_x509::X509;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_smime.c";

/// `BUFFERSIZE` — `pk7_smime.c:19`.
const BUFFERSIZE: c_int = 4096;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h:997`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;

/// `PKCS7_TEXT` — `pkcs7.h.in:206`.
const PKCS7_TEXT: c_int = 0x1;
/// `PKCS7_NOCERTS` — `pkcs7.h.in:207`.
const PKCS7_NOCERTS: c_int = 0x2;
/// `PKCS7_NOSIGS` — `pkcs7.h.in:208`.
const PKCS7_NOSIGS: c_int = 0x4;
/// `PKCS7_NOCHAIN` — `pkcs7.h.in:209`.
const PKCS7_NOCHAIN: c_int = 0x8;
/// `PKCS7_NOINTERN` — `pkcs7.h.in:210`.
const PKCS7_NOINTERN: c_int = 0x10;
/// `PKCS7_NOVERIFY` — `pkcs7.h.in:211`.
const PKCS7_NOVERIFY: c_int = 0x20;
/// `PKCS7_DETACHED` — `pkcs7.h.in:212`.
const PKCS7_DETACHED: c_int = 0x40;
/// `PKCS7_NOATTR` — `pkcs7.h.in:214`.
const PKCS7_NOATTR: c_int = 0x100;
/// `PKCS7_NOSMIMECAP` — `pkcs7.h.in:215`.
const PKCS7_NOSMIMECAP: c_int = 0x200;
/// `PKCS7_STREAM` — `pkcs7.h.in:218`.
const PKCS7_STREAM: c_int = 0x1000;
/// `PKCS7_NOCRL` — `pkcs7.h.in:219`.
const PKCS7_NOCRL: c_int = 0x2000;
/// `PKCS7_PARTIAL` — `pkcs7.h.in:220`.
const PKCS7_PARTIAL: c_int = 0x4000;
/// `PKCS7_REUSE_DIGEST` — `pkcs7.h.in:221`.
const PKCS7_REUSE_DIGEST: c_int = 0x8000;
/// `PKCS7_NO_DUAL_CONTENT` — `pkcs7.h.in:222`.
const PKCS7_NO_DUAL_CONTENT: c_int = 0x10000;
/// `PKCS7_OP_SET_DETACHED_SIGNATURE` — `pkcs7.h.in:183`.
const PKCS7_OP_SET_DETACHED_SIGNATURE: c_int = 1;
/// `PKCS7_OP_GET_DETACHED_SIGNATURE` — `pkcs7.h.in:184`.
const PKCS7_OP_GET_DETACHED_SIGNATURE: c_int = 2;

extern "C" {
    /// `int SMIME_text(BIO *in, BIO *out)` — `crypto/asn1/asn_mime.c`, 12.9's.
    fn SMIME_text(in_: *mut Bio, out: *mut Bio) -> c_int;
}

/// The `X509_ALGOR_free` destructor shape `OPENSSL_sk_pop_free` takes.
///
/// # Safety
/// `p` is null or an `X509_ALGOR` this item layer owns.
unsafe extern "C" fn x509_algor_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_ALGOR_free(p.cast()) };
}

/// `BIO_flush(BIO *)` — `BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL)`.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn bio_flush(b: *mut Bio) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut()) as c_int }
}

/// `PKCS7_set_detached(p, v)` — `pkcs7.h.in:197`.
///
/// # Safety
/// `p7` is live.
unsafe fn pkcs7_set_detached(p7: *mut Pkcs7, v: c_long) -> c_long {
    // SAFETY: `p7` is live.
    unsafe { PKCS7_ctrl(p7, PKCS7_OP_SET_DETACHED_SIGNATURE, v, ptr::null_mut()) }
}

/// `PKCS7_get_detached(p)` — `pkcs7.h.in:199`.
///
/// # Safety
/// `p7` is live.
unsafe fn pkcs7_get_detached(p7: *mut Pkcs7) -> c_long {
    // SAFETY: `p7` is live.
    unsafe { PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, ptr::null_mut()) }
}

/// `PKCS7 *PKCS7_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data,
/// int flags, OSSL_LIB_CTX *libctx, const char *propq)` — `pk7_smime.c:23-65`.
///
/// # Safety
/// The two keys/certs and the BIO are live; `libctx`/`propq` are null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_sign_ex(
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    certs: *mut OpenSslStack,
    data: *mut Bio,
    flags: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs7 {
    // SAFETY: `libctx`/`propq` are the caller's.
    let p7 = unsafe { crate::pkcs7::pk7_asn1::PKCS7_new_ex(libctx, propq) };
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_31) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    if unsafe { PKCS7_set_type(p7, NID_pkcs7_signed) } == 0 {
        // SAFETY: `p7` is live and owned here.
        unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    if unsafe { PKCS7_content_new(p7, NID_pkcs7_data) } == 0 {
        // SAFETY: `p7` is live and owned here.
        unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
        return ptr::null_mut();
    }
    if !pkey.is_null() {
        // SAFETY: all four are live per the caller's contract.
        if unsafe { PKCS7_sign_add_signer(p7, signcert, pkey, ptr::null(), flags) }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_SMIME_42) };
            // SAFETY: `p7` is live and owned here.
            unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
            return ptr::null_mut();
        }
    }
    if (flags & PKCS7_NOCERTS) == 0 {
        // SAFETY: `certs` is null or a live stack.
        let n = unsafe { OPENSSL_sk_num(certs) };
        let mut i = 0;
        while i < n {
            // SAFETY: `certs` is a live stack and `i` is in range.
            let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
            // SAFETY: `p7`/`x` are live.
            if unsafe { PKCS7_add_certificate(p7, x) } == 0 {
                // SAFETY: `p7` is live and owned here.
                unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
                return ptr::null_mut();
            }
            i += 1;
        }
    }
    if (flags & PKCS7_DETACHED) != 0 {
        // SAFETY: `p7` is live.
        unsafe { pkcs7_set_detached(p7, 1) };
    }
    if (flags & (PKCS7_STREAM | PKCS7_PARTIAL)) != 0 {
        return p7;
    }
    // SAFETY: `p7` is live; `data` is null or live.
    if unsafe { PKCS7_final(p7, data, flags) } != 0 {
        return p7;
    }
    // SAFETY: `p7` is live and owned here.
    unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
    ptr::null_mut()
}

/// `PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data,
/// int flags)` — `pk7_smime.c:67-71`.
///
/// # Safety
/// As [`PKCS7_sign_ex`], with no context.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_sign(
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    certs: *mut OpenSslStack,
    data: *mut Bio,
    flags: c_int,
) -> *mut Pkcs7 {
    // SAFETY: the caller's contract.
    unsafe {
        PKCS7_sign_ex(
            signcert,
            pkey,
            certs,
            data,
            flags,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int PKCS7_final(PKCS7 *p7, BIO *data, int flags)` — `pk7_smime.c:73-97`.
///
/// # Safety
/// `p7` and `data` are live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_final(p7: *mut Pkcs7, data: *mut Bio, flags: c_int) -> c_int {
    // SAFETY: `p7` is live.
    let p7bio = unsafe { PKCS7_dataInit(p7, ptr::null_mut()) };
    if p7bio.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_79) };
        return 0;
    }
    // SAFETY: `data`/`p7bio` are live.
    if unsafe { SMIME_crlf_copy(data, p7bio, flags) } == 0 {
        // SAFETY: `p7bio` is live and owned here.
        unsafe { BIO_free_all(p7bio) };
        return 0;
    }
    // SAFETY: `p7bio` is live.
    unsafe { bio_flush(p7bio) };
    // SAFETY: `p7`/`p7bio` are live.
    if unsafe { PKCS7_dataFinal(p7, p7bio) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_89) };
        // SAFETY: `p7bio` is live and owned here.
        unsafe { BIO_free_all(p7bio) };
        return 0;
    }
    // SAFETY: `p7bio` is live and owned here.
    unsafe { BIO_free_all(p7bio) };
    1
}

/// `add_cipher_smcap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)` — `pk7_smime.c:101-106`.
///
/// # Safety
/// `sk` is a live stack.
unsafe fn add_cipher_smcap(sk: *mut OpenSslStack, nid: c_int, arg: c_int) -> c_int {
    // SAFETY: `nid` names the cipher; the macro is `EVP_get_cipherbynid`.
    let c = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(nid)) };
    if !c.is_null() {
        // SAFETY: `sk` is live.
        return unsafe { PKCS7_simple_smimecap(sk, nid, arg) };
    }
    1
}

/// `add_digest_smcap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)` — `pk7_smime.c:108-113`.
///
/// # Safety
/// `sk` is a live stack.
unsafe fn add_digest_smcap(sk: *mut OpenSslStack, nid: c_int, arg: c_int) -> c_int {
    // SAFETY: `nid` names the digest; the macro is `EVP_get_digestbynid`.
    let d = unsafe { EVP_get_digestbyname(OBJ_nid2sn(nid)) };
    if !d.is_null() {
        // SAFETY: `sk` is live.
        return unsafe { PKCS7_simple_smimecap(sk, nid, arg) };
    }
    1
}

/// `PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7, X509 *signcert, EVP_PKEY *pkey,
/// const EVP_MD *md, int flags)` — `pk7_smime.c:115-177`.
///
/// # Safety
/// `p7`/`signcert`/`pkey` are live; `md` is null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_sign_add_signer(
    p7: *mut Pkcs7,
    signcert: *mut X509,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
    flags: c_int,
) -> *mut Pkcs7SignerInfo {
    // SAFETY: `signcert`/`pkey` are live.
    if unsafe { X509_check_private_key(signcert, pkey) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_123) };
        return ptr::null_mut();
    }
    // SAFETY: `p7`/`signcert`/`pkey` are live; `md` is the caller's.
    let si = unsafe { PKCS7_add_signature(p7, signcert, pkey, md) };
    if si.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_129) };
        return ptr::null_mut();
    }
    // SAFETY: `si`/`p7` are live.
    unsafe { (*si).ctx = ossl_pkcs7_get0_ctx(p7) };
    if (flags & PKCS7_NOCERTS) == 0 {
        // SAFETY: `p7`/`signcert` are live.
        if unsafe { PKCS7_add_certificate(p7, signcert) } == 0 {
            return ptr::null_mut();
        }
    }
    let smcap: *mut OpenSslStack;
    if (flags & PKCS7_NOATTR) == 0 {
        // SAFETY: `si` is live.
        if unsafe { PKCS7_add_attrib_content_type(si, ptr::null_mut()) } == 0 {
            return ptr::null_mut();
        }
        if (flags & PKCS7_NOSMIMECAP) == 0 {
            smcap = OPENSSL_sk_new_null();
            if smcap.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS7_SMIME_145) };
                return ptr::null_mut();
            }
            // SAFETY: `smcap` is live; each name is the authority's own chain.
            let ok = unsafe {
                add_cipher_smcap(smcap, NID_aes_256_cbc, -1) != 0
                    && add_digest_smcap(smcap, NID_id_GostR3411_2012_256, -1) != 0
                    && add_digest_smcap(smcap, NID_id_GostR3411_2012_512, -1) != 0
                    && add_digest_smcap(smcap, NID_id_GostR3411_94, -1) != 0
                    && add_cipher_smcap(smcap, NID_id_Gost28147_89, -1) != 0
                    && add_cipher_smcap(smcap, NID_aes_192_cbc, -1) != 0
                    && add_cipher_smcap(smcap, NID_aes_128_cbc, -1) != 0
                    && add_cipher_smcap(smcap, NID_des_ede3_cbc, -1) != 0
                    && add_cipher_smcap(smcap, NID_rc2_cbc, 128) != 0
                    && add_cipher_smcap(smcap, NID_rc2_cbc, 64) != 0
                    && add_cipher_smcap(smcap, NID_des_cbc, -1) != 0
                    && add_cipher_smcap(smcap, NID_rc2_cbc, 40) != 0
                    && PKCS7_add_attrib_smimecap(si, smcap) != 0
            };
            if !ok {
                // SAFETY: `smcap` is live and owned here.
                unsafe { OPENSSL_sk_pop_free(smcap, Some(x509_algor_free_void)) };
                return ptr::null_mut();
            }
            // SAFETY: `smcap` is live and owned here.
            unsafe { OPENSSL_sk_pop_free(smcap, Some(x509_algor_free_void)) };
        }
        if (flags & PKCS7_REUSE_DIGEST) != 0 {
            // SAFETY: `p7`/`si` are live.
            if unsafe { pkcs7_copy_existing_digest(p7, si) } == 0 {
                return ptr::null_mut();
            }
            if (flags & PKCS7_PARTIAL) == 0
                // SAFETY: `si` is live.
                && unsafe { PKCS7_SIGNER_INFO_sign(si) } == 0
            {
                return ptr::null_mut();
            }
        }
    }
    si
}

/// `pkcs7_copy_existing_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si)` — `pk7_smime.c:184-208`.
///
/// # Safety
/// `p7`/`si` are live.
unsafe fn pkcs7_copy_existing_digest(p7: *mut Pkcs7, si: *mut Pkcs7SignerInfo) -> c_int {
    // SAFETY: `p7` is live.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: `sinfos` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    let mut i = 0;
    while i < n {
        // SAFETY: `sinfos` is a live stack and `i` is in range.
        let sitmp = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<Pkcs7SignerInfo>();
        if si == sitmp {
            break;
        }
        // SAFETY: `sitmp`/`si` are live.
        let (a, b) = unsafe { ((*sitmp).auth_attr, (*si).digest_alg) };
        // SAFETY: `a` is null or a live stack.
        if unsafe { OPENSSL_sk_num(a) } <= 0 {
            i += 1;
            continue;
        }
        // SAFETY: `b`/`sitmp` are live.
        let same = unsafe { OBJ_cmp((*b).algorithm, (*(*sitmp).digest_alg).algorithm) == 0 };
        if same {
            // SAFETY: `a` is a live stack.
            let osdig = unsafe { PKCS7_digest_from_attributes(a) };
            if !osdig.is_null() {
                // SAFETY: `si`/`osdig` are live.
                return unsafe { PKCS7_add1_attrib_digest(si, (*osdig).data, (*osdig).length) };
            }
            break;
        }
        i += 1;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PKCS7_SMIME_206) };
    0
}

/// `int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store, BIO *indata, BIO *out,
/// int flags)` — `pk7_smime.c:211-364`.
///
/// # Safety
/// `p7` is live; `certs`/`store`/`indata`/`out` are null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_verify(
    p7: *mut Pkcs7,
    certs: *mut OpenSslStack,
    store: *mut X509Store,
    indata: *mut Bio,
    out: *mut Bio,
    flags: c_int,
) -> c_int {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_229) };
        return 0;
    }
    if !pkcs7_type_is_signed(p7) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_234) };
        return 0;
    }
    // SAFETY: `p7` is live.
    if unsafe { pkcs7_get_detached(p7) } != 0 && indata.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_240) };
        return 0;
    }
    if (flags & PKCS7_NO_DUAL_CONTENT) != 0
        // SAFETY: `p7` is live.
        && unsafe { pkcs7_get_detached(p7) } == 0
        && !indata.is_null()
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_253) };
        return 0;
    }

    // SAFETY: `p7` is live.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: `sinfos` is null or a live stack.
    if sinfos.is_null() || unsafe { OPENSSL_sk_num(sinfos) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_261) };
        return 0;
    }

    // SAFETY: `p7` is live; `certs` is the caller's.
    let signers = unsafe { PKCS7_get0_signers(p7, certs, flags) };
    if signers.is_null() {
        return 0;
    }

    // SAFETY: `p7` is live.
    let p7_ctx = unsafe { ossl_pkcs7_get0_ctx(p7) };
    // SAFETY: the context is the object's.
    let cert_ctx = unsafe {
        X509_STORE_CTX_new_ex(
            ossl_pkcs7_ctx_get0_libctx(p7_ctx),
            ossl_pkcs7_ctx_get0_propq(p7_ctx),
        )
    };
    if cert_ctx.is_null() {
        // SAFETY: `signers` is live and owned here.
        unsafe { OPENSSL_sk_free(signers) };
        return 0;
    }
    let mut untrusted: *mut OpenSslStack = ptr::null_mut();
    if (flags & PKCS7_NOVERIFY) == 0 {
        // SAFETY: `certs` is null or live.
        if unsafe { ossl_x509_add_certs_new(&mut untrusted, certs, X509_ADD_FLAG_NO_DUP) } == 0 {
            // SAFETY: owned here.
            unsafe {
                X509_STORE_CTX_free(cert_ctx);
                OPENSSL_sk_free(signers);
            }
            return 0;
        }
        // SAFETY: `p7` is live.
        let included_certs = unsafe { pkcs7_get0_certificates(p7) };
        if (flags & PKCS7_NOCHAIN) == 0
            // SAFETY: `included_certs` is null or live.
            && unsafe { ossl_x509_add_certs_new(&mut untrusted, included_certs, X509_ADD_FLAG_NO_DUP) }
                == 0
        {
            // SAFETY: owned here.
            unsafe {
                X509_STORE_CTX_free(cert_ctx);
                OPENSSL_sk_free(untrusted);
                OPENSSL_sk_free(signers);
            }
            return 0;
        }
        // SAFETY: `signers` is a live stack.
        let n = unsafe { OPENSSL_sk_num(signers) };
        let mut k = 0;
        while k < n {
            // SAFETY: `signers` is a live stack and `k` is in range.
            let signer = unsafe { OPENSSL_sk_value(signers, k) }.cast::<X509>();
            // SAFETY: the context, store, signer and chain are live.
            if unsafe { X509_STORE_CTX_init(cert_ctx, store, signer, untrusted) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_site(&err_sites::PKCS7_SMIME_287);
                    X509_STORE_CTX_free(cert_ctx);
                    OPENSSL_sk_free(untrusted);
                    OPENSSL_sk_free(signers);
                }
                return 0;
            }
            if (flags & PKCS7_NOCHAIN) == 0
                // SAFETY: `cert_ctx` is live.
                && unsafe { X509_STORE_CTX_set_default(cert_ctx, c"smime_sign".as_ptr()) } == 0
            {
                // SAFETY: owned here.
                unsafe {
                    X509_STORE_CTX_free(cert_ctx);
                    OPENSSL_sk_free(untrusted);
                    OPENSSL_sk_free(signers);
                }
                return 0;
            }
            if (flags & PKCS7_NOCRL) == 0 {
                // SAFETY: `p7` is live.
                let crl = unsafe { (*(*p7).d.sign).crl };
                // SAFETY: `cert_ctx` is live.
                unsafe { X509_STORE_CTX_set0_crls(cert_ctx, crl) };
            }
            // SAFETY: `cert_ctx` is live.
            let i = unsafe { X509_verify_cert(cert_ctx) };
            if i <= 0 {
                // SAFETY: `cert_ctx` is live.
                let j = unsafe { X509_STORE_CTX_get_error(cert_ctx) };
                let _ = j;
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_site(&err_sites::PKCS7_SMIME_298);
                    X509_STORE_CTX_free(cert_ctx);
                    OPENSSL_sk_free(untrusted);
                    OPENSSL_sk_free(signers);
                }
                let _ = X509_verify_cert_error_string(j as c_long);
                return 0;
            }
            k += 1;
        }
    }

    // SAFETY: `p7` is live; `indata` is null or live.
    let mut p7bio = unsafe { PKCS7_dataInit(p7, indata) };
    if p7bio.is_null() {
        // SAFETY: owned here.
        unsafe {
            X509_STORE_CTX_free(cert_ctx);
            OPENSSL_sk_free(untrusted);
            OPENSSL_sk_free(signers);
        }
        return 0;
    }

    let mut tmpout: *mut Bio = out;
    let text = (flags & PKCS7_TEXT) != 0;
    if text {
        // SAFETY: no preconditions.
        tmpout = unsafe { BIO_new(BIO_s_mem()) };
        if tmpout.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_312);
                BIO_free_all(p7bio);
                X509_STORE_CTX_free(cert_ctx);
                OPENSSL_sk_free(untrusted);
                OPENSSL_sk_free(signers);
            }
            return 0;
        }
        // SAFETY: `tmpout` is live.
        unsafe { bio_set_mem_eof_return(tmpout, 0) };
    }

    // SAFETY: no preconditions.
    let buf = CRYPTO_malloc(BUFFERSIZE as usize, FILE.as_ptr(), 320).cast::<c_char>();
    if buf.is_null() {
        // SAFETY: owned here.
        unsafe {
            if text {
                BIO_free(tmpout);
            }
            BIO_free_all(p7bio);
            X509_STORE_CTX_free(cert_ctx);
            OPENSSL_sk_free(untrusted);
            OPENSSL_sk_free(signers);
        }
        return 0;
    }
    loop {
        // SAFETY: `p7bio`/`buf` are live.
        let i = unsafe { BIO_read(p7bio, buf.cast(), BUFFERSIZE) };
        if i <= 0 {
            break;
        }
        if !tmpout.is_null() {
            // SAFETY: `tmpout`/`buf` are live.
            unsafe { BIO_write(tmpout, buf.cast(), i) };
        }
    }

    if text {
        // SAFETY: `tmpout`/`out` are live.
        if unsafe { SMIME_text(tmpout, out) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_332);
                BIO_free(tmpout);
                CRYPTO_free(buf.cast(), FILE.as_ptr(), 355);
                BIO_free_all(p7bio);
                X509_STORE_CTX_free(cert_ctx);
                OPENSSL_sk_free(untrusted);
                OPENSSL_sk_free(signers);
            }
            return 0;
        }
    }

    if (flags & PKCS7_NOSIGS) == 0 {
        // SAFETY: `sinfos` is a live stack.
        let n = unsafe { OPENSSL_sk_num(sinfos) };
        let mut i = 0;
        while i < n {
            // SAFETY: `sinfos`/`signers` are live stacks and `i` is in range.
            let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<Pkcs7SignerInfo>();
            // SAFETY: as above.
            let signer = unsafe { OPENSSL_sk_value(signers, i) }.cast::<X509>();
            // SAFETY: `p7bio`/`p7`/`si`/`signer` are live.
            let j = unsafe { PKCS7_signatureVerify(p7bio, p7, si, signer) };
            if j <= 0 {
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_site(&err_sites::PKCS7_SMIME_344);
                    if text {
                        BIO_free(tmpout);
                    }
                    CRYPTO_free(buf.cast(), FILE.as_ptr(), 355);
                    BIO_free_all(p7bio);
                    X509_STORE_CTX_free(cert_ctx);
                    OPENSSL_sk_free(untrusted);
                    OPENSSL_sk_free(signers);
                }
                return 0;
            }
            i += 1;
        }
    }
    let ret = 1;

    // SAFETY: owned here.
    unsafe {
        if text {
            BIO_free(tmpout);
        }
        CRYPTO_free(buf.cast(), FILE.as_ptr(), 355);
        X509_STORE_CTX_free(cert_ctx);
    }
    // SAFETY: unwind the BIO chain back to the caller's `indata`.
    while !p7bio.is_null() && p7bio != indata {
        // SAFETY: `p7bio` is a live chain.
        let next = unsafe { BIO_pop(p7bio) };
        // SAFETY: `p7bio` is live and owned here.
        unsafe { BIO_free(p7bio) };
        p7bio = next;
    }
    // SAFETY: both are live stacks owned here.
    unsafe {
        OPENSSL_sk_free(signers);
        OPENSSL_sk_free(untrusted);
    }
    ret
}

/// `STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs, int flags)` —
/// `pk7_smime.c:366-423`.
///
/// # Safety
/// `p7` is live; `certs` is null or live. A non-null answer is a fresh stack the caller owns.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get0_signers(
    p7: *mut Pkcs7,
    certs: *mut OpenSslStack,
    flags: c_int,
) -> *mut OpenSslStack {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_377) };
        return ptr::null_mut();
    }
    if !pkcs7_type_is_signed(p7) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_382) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    let included_certs = unsafe { pkcs7_get0_certificates(p7) };
    // SAFETY: `p7` is live.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: `sinfos` is null or a live stack.
    if unsafe { OPENSSL_sk_num(sinfos) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_392) };
        return ptr::null_mut();
    }
    let signers = OPENSSL_sk_new_null();
    if signers.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_397) };
        return ptr::null_mut();
    }
    // SAFETY: `sinfos` is a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    let mut i = 0;
    while i < n {
        // SAFETY: `sinfos` is a live stack and `i` is in range.
        let si = unsafe { OPENSSL_sk_value(sinfos, i) }.cast::<Pkcs7SignerInfo>();
        // SAFETY: `si` is live.
        let ias = unsafe { (*si).issuer_and_serial };
        // SAFETY: `certs`/`ias` are live.
        let mut signer =
            unsafe { X509_find_by_issuer_and_serial(certs, (*ias).issuer, (*ias).serial) };
        if signer.is_null() && (flags & PKCS7_NOINTERN) == 0 {
            // SAFETY: `included_certs`/`ias` are live.
            signer = unsafe {
                X509_find_by_issuer_and_serial(included_certs, (*ias).issuer, (*ias).serial)
            };
        }
        if signer.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_412);
                OPENSSL_sk_free(signers);
            }
            return ptr::null_mut();
        }
        // SAFETY: `signers` is a live stack; `signer` is live.
        if unsafe { OPENSSL_sk_push(signers, signer.cast()) } == 0 {
            // SAFETY: `signers` is live and owned here.
            unsafe { OPENSSL_sk_free(signers) };
            return ptr::null_mut();
        }
        i += 1;
    }
    signers
}

/// `PKCS7 *PKCS7_encrypt_ex(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher, int flags,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `pk7_smime.c:427-467`.
///
/// # Safety
/// `certs` is null or live; `in` is live; `libctx`/`propq` are null or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_encrypt_ex(
    certs: *mut OpenSslStack,
    in_: *mut Bio,
    cipher: *const EvpCipher,
    flags: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs7 {
    // SAFETY: `libctx`/`propq` are the caller's.
    let p7 = unsafe { crate::pkcs7::pk7_asn1::PKCS7_new_ex(libctx, propq) };
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_437) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live.
    if unsafe { PKCS7_set_type(p7, NID_pkcs7_enveloped) } == 0 {
        // SAFETY: `p7` is live and owned here.
        unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
        return ptr::null_mut();
    }
    // SAFETY: `p7`/`cipher` are live.
    if unsafe { PKCS7_set_cipher(p7, cipher) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe {
            raise_site(&err_sites::PKCS7_SMIME_444);
            crate::pkcs7::pk7_asn1::PKCS7_free(p7);
        }
        return ptr::null_mut();
    }
    // SAFETY: `certs` is null or a live stack.
    let n = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < n {
        // SAFETY: `certs` is a live stack and `i` is in range.
        let x509 = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `p7`/`x509` are live.
        if unsafe { PKCS7_add_recipient(p7, x509) }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_451);
                crate::pkcs7::pk7_asn1::PKCS7_free(p7);
            }
            return ptr::null_mut();
        }
        i += 1;
    }
    if (flags & PKCS7_STREAM) != 0 {
        return p7;
    }
    // SAFETY: `p7` is live; `in_` is live.
    if unsafe { PKCS7_final(p7, in_, flags) } != 0 {
        return p7;
    }
    // SAFETY: `p7` is live and owned here.
    unsafe { crate::pkcs7::pk7_asn1::PKCS7_free(p7) };
    ptr::null_mut()
}

/// `PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher, int flags)` —
/// `pk7_smime.c:469-473`.
///
/// # Safety
/// As [`PKCS7_encrypt_ex`], with no context.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_encrypt(
    certs: *mut OpenSslStack,
    in_: *mut Bio,
    cipher: *const EvpCipher,
    flags: c_int,
) -> *mut Pkcs7 {
    // SAFETY: the caller's contract.
    unsafe { PKCS7_encrypt_ex(certs, in_, cipher, flags, ptr::null_mut(), ptr::null()) }
}

/// `int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags)` —
/// `pk7_smime.c:475-546`.
///
/// # Safety
/// `p7`/`pkey`/`cert` are live; `data` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_decrypt(
    p7: *mut Pkcs7,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    data: *mut Bio,
    flags: c_int,
) -> c_int {
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_482) };
        return 0;
    }
    if !pkcs7_type_is_enveloped(p7) && !pkcs7_type_is_signed_and_enveloped(p7) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_488) };
        return 0;
    }
    if !cert.is_null() {
        // SAFETY: `cert`/`pkey` are live.
        if unsafe { X509_check_private_key(cert, pkey) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_SMIME_493) };
            return 0;
        }
    }
    // SAFETY: `p7`/`pkey`/`cert` are live.
    let tmpmem = unsafe { PKCS7_dataDecode(p7, pkey, ptr::null_mut(), cert) };
    if tmpmem.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS7_SMIME_499) };
        return 0;
    }
    if (flags & PKCS7_TEXT) != 0 {
        // SAFETY: no preconditions.
        let tmpbuf = unsafe { BIO_new(BIO_f_buffer()) };
        if tmpbuf.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_507);
                BIO_free_all(tmpmem);
            }
            return 0;
        }
        // SAFETY: `tmpbuf`/`tmpmem` are live.
        let bread = unsafe { BIO_push(tmpbuf, tmpmem) };
        if bread.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_site(&err_sites::PKCS7_SMIME_512);
                BIO_free_all(tmpbuf);
                BIO_free_all(tmpmem);
            }
            return 0;
        }
        // SAFETY: `bread`/`data` are live.
        let mut ret = unsafe { SMIME_text(bread, data) };
        // SAFETY: `tmpmem` is live.
        if ret > 0 && unsafe { BIO_method_type(tmpmem) } == BIO_TYPE_CIPHER {
            // SAFETY: `tmpmem` is a live cipher BIO.
            if unsafe { bio_get_cipher_status(tmpmem) } <= 0 {
                ret = 0;
            }
        }
        // SAFETY: `bread` is live and owns the chain.
        unsafe { BIO_free_all(bread) };
        return ret;
    }
    // SAFETY: no preconditions.
    let buf = CRYPTO_malloc(BUFFERSIZE as usize, FILE.as_ptr(), 525).cast::<c_char>();
    if buf.is_null() {
        // SAFETY: `tmpmem` is live and owned here.
        unsafe { BIO_free_all(tmpmem) };
        return 0;
    }
    let mut ret = 0;
    loop {
        // SAFETY: `tmpmem`/`buf` are live.
        let i = unsafe { BIO_read(tmpmem, buf.cast(), BUFFERSIZE) };
        if i <= 0 {
            ret = 1;
            // SAFETY: `tmpmem` is live.
            if unsafe { BIO_method_type(tmpmem) } == BIO_TYPE_CIPHER {
                // SAFETY: `tmpmem` is a live cipher BIO.
                if unsafe { bio_get_cipher_status(tmpmem) } <= 0 {
                    ret = 0;
                }
            }
            break;
        }
        // SAFETY: `data`/`buf` are live.
        if unsafe { BIO_write(data, buf.cast(), i) } != i {
            break;
        }
    }
    // SAFETY: `buf`/`tmpmem` are owned here.
    unsafe {
        CRYPTO_free(buf.cast(), FILE.as_ptr(), 543);
        BIO_free_all(tmpmem);
    }
    ret
}
