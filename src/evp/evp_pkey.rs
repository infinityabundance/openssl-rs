//! `crypto/evp/evp_pkey.c`'s `evp_pkcs82pkey_legacy` — the legacy `PKCS8_PRIV_KEY_INFO`
//! to `EVP_PKEY` step. D368.
//!
//! One internal of a large unit, landed because it is the second leg of
//! `pem_read_bio_key_legacy`'s PKCS#8 path (`crypto/pem/pem_pkey.c:142`, `:170`) and the
//! fallback `ossl_d2i_PrivateKey_legacy` reaches for a `PrivateKeyInfo` that the type-specific
//! decoder refused. Its siblings in the unit — `EVP_PKCS82PKEY_ex`, `EVP_PKCS82PKEY`,
//! `EVP_PKEY2PKCS8`, `EVP_PKEY_get0_asn1` and the encoder half — are Phase 10's exports and are
//! **not** landed here; this module is a partial transcription of `crypto/evp/evp_pkey.c` and
//! names what it withholds rather than implying the unit is whole.
//!
//! ## The method is reached through the decoded algorithm, not the caller
//!
//! The function decodes the `PrivateKeyInfo`'s algorithm OID with `PKCS8_pkey_get0`, resolves it
//! to a NID, and lets `EVP_PKEY_set_type` answer the `EVP_PKEY_ASN1_METHOD` — which is why this
//! could not land before 8.8 published `standard_methods[]` (D341's cycle). The decode then runs
//! `priv_decode_ex` when the method has one and `priv_decode` otherwise, with different failure
//! diagnostics for each.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::p8_pkey::{
    d2i_PKCS8_PRIV_KEY_INFO, i2d_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free,
    PKCS8_PRIV_KEY_INFO_new, PKCS8_pkey_get0, Pkcs8PrivKeyInfo,
};
use crate::asn1::text::i2t_ASN1_OBJECT;
use crate::decoder_lib::{OSSL_DECODER_CTX_get_num_decoders, OSSL_DECODER_from_data};
use crate::decoder_meth::OSSL_DECODER_CTX_free;
use crate::decoder_pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::encoder_lib::OSSL_ENCODER_to_data;
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{
    evp_pkey_is_provided, EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_type, EvpPkey,
    OSSL_KEYMGMT_SELECT_ALL,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid, OBJ_obj2txt};

/// `EVP_PKEY_KEY_PARAMETERS`/`_PUBLIC_KEY`/`_KEYPAIR` — `include/openssl/evp.h:106-113`, spelled
/// from the `OSSL_KEYMGMT_SELECT_*` bits as the header composes them. `src/evp/pkey.rs` keeps its
/// copies module-private, so the trio is spelled here for the two PKCS#8 helpers.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
const EVP_PKEY_KEY_PARAMETERS: c_int = 0x04 | 0x80;
const EVP_PKEY_PUBLIC_KEY: c_int = EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const EVP_PKEY_KEYPAIR: c_int = EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

/// `EVP_PKEY *evp_pkcs82pkey_legacy(const PKCS8_PRIV_KEY_INFO *p8, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/evp/evp_pkey.c:30-70`.
///
/// The answer is a fresh `EVP_PKEY` the caller owns, or NULL; every failure releases it.
///
/// # Safety
/// `p8` must be a live `PKCS8_PRIV_KEY_INFO`; `libctx`/`propq` are the method's decode context.
#[no_mangle]
pub unsafe extern "C" fn evp_pkcs82pkey_legacy(
    p8: *const Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut algoid: *const Asn1Object = ptr::null();
    // SAFETY: `p8` is live and the three NULL out-slots are skipped by the reader.
    if unsafe {
        PKCS8_pkey_get0(
            &raw mut algoid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            p8,
        )
    } == 0
    {
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_PKEY_41) };
        return ptr::null_mut();
    }

    // SAFETY: `algoid` is live and `pkey` is live.
    if unsafe { EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid)) } == 0 {
        let mut obj_tmp = [0 as c_char; 80];
        // SAFETY: `obj_tmp` is an 80-byte buffer and `algoid` is live.
        unsafe { i2t_ASN1_OBJECT(obj_tmp.as_mut_ptr(), 80, algoid) };
        let mut msg = [0 as c_char; 96];
        // SAFETY: `msg` is a 96-byte buffer and the format is the authority's.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"TYPE=%s".as_ptr(),
                obj_tmp.as_ptr(),
            )
        };
        // SAFETY: a compile-time-constant site; the message is NUL-terminated.
        unsafe { raise_site_data(&err_sites::EVP_PKEY_47, msg.as_ptr()) };
        // SAFETY: `pkey` is live and this call owns it.
        unsafe { EVP_PKEY_free(pkey) };
        return ptr::null_mut();
    }

    // SAFETY: `pkey` is live and `EVP_PKEY_set_type` above succeeded, so its `ameth` is set.
    let ameth = unsafe { (*pkey).ameth };
    // SAFETY: `ameth` is the key's own method table.
    let (priv_decode_ex, priv_decode) = unsafe { ((*ameth).priv_decode_ex, (*ameth).priv_decode) };
    let ok = if let Some(dec) = priv_decode_ex {
        // SAFETY: the callback was read from the live key and `p8` is live.
        (unsafe { dec(pkey, p8, libctx, propq) }) != 0
    } else if let Some(dec) = priv_decode {
        // SAFETY: the callback was read from the live key and `p8` is live.
        if unsafe { dec(pkey, p8) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_PKEY_57) };
            false
        } else {
            true
        }
    } else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_PKEY_61) };
        false
    };

    if !ok {
        // SAFETY: `pkey` is live and this call owns it.
        unsafe { EVP_PKEY_free(pkey) };
        return ptr::null_mut();
    }
    pkey
}

/// `PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(const EVP_PKEY *pkey)` — `crypto/evp/evp_pkey.c:129-185`.
///
/// **Internal, not the export.** `EVP_PKEY2PKCS8` is declared in `x509.h` and owned by Phase 11
/// (`forensics/atlas/symbol-ownership.json`), so this module does not define its symbol. It is
/// transcribed because `crypto/asn1/i2d_evp.c`'s `i2d_PrivateKey_impl` (`:118`, `:122`) and
/// `crypto/pem/pem_pk8.c`'s `do_pk8pkey` (`:131`, `:157`) both call it, and the legacy
/// `priv_encode` half is the only one this stratum's fixed keys reach.
///
/// The provided-key arm encodes to PKCS#8 DER through the encoder framework and re-parses it back
/// with `d2i_PKCS8_PRIV_KEY_INFO`; the legacy arm builds the `PKCS8_PRIV_KEY_INFO` and lets the
/// method's `priv_encode` fill it.
///
/// # Safety
/// `pkey` must be a live `EVP_PKEY`.
pub(crate) unsafe fn ossl_evp_pkey2pkcs8(pkey: *const EvpPkey) -> *mut Pkcs8PrivKeyInfo {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    let p8: *mut Pkcs8PrivKeyInfo;
    let mut ctx: *mut crate::encoder_meth::OsslEncoderCtx = ptr::null_mut();

    // SAFETY: `pkey` is live per the contract.
    if unsafe { evp_pkey_is_provided(pkey) } != 0 {
        let selection = OSSL_KEYMGMT_SELECT_ALL;
        let mut der: *mut c_uchar = ptr::null_mut();
        let mut derlen: usize = 0;

        // SAFETY: `pkey` is live; the three strings are literals.
        ctx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey,
                selection,
                c"DER".as_ptr(),
                c"PrivateKeyInfo".as_ptr(),
                ptr::null(),
            )
        };
        if ctx.is_null()
            // SAFETY: `ctx` is live and `der`/`derlen` are this frame's out-parameters.
            || unsafe { OSSL_ENCODER_to_data(ctx, &mut der, &mut derlen) } == 0
        {
            // SAFETY: `ctx` is NULL or the context the framework made.
            unsafe { OSSL_ENCODER_CTX_free(ctx) };
            return ptr::null_mut();
        }
        let pp: *const c_uchar = der;
        let mut pp_mut = pp;
        // SAFETY: `pp_mut` is a readable cursor and `derlen` describes it.
        p8 = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut pp_mut, derlen as c_long) };
        // SAFETY: `der` is the buffer the encoder allocated.
        unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
        if p8.is_null() {
            // SAFETY: `ctx` is live.
            unsafe { OSSL_ENCODER_CTX_free(ctx) };
            return ptr::null_mut();
        }
    } else {
        // SAFETY: no preconditions.
        p8 = PKCS8_PRIV_KEY_INFO_new();
        if p8.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_PKEY_160) };
            return ptr::null_mut();
        }
        // SAFETY: `pkey` is live.
        let ameth = unsafe { (*pkey).ameth };
        if !ameth.is_null() {
            // SAFETY: `ameth` is the key's own method table.
            let priv_encode = unsafe { (*ameth).priv_encode };
            match priv_encode {
                // SAFETY: the callback was read from the live key and `p8` is this frame's.
                Some(enc) => {
                    // SAFETY: the callback was read from the live key and `p8`/`pkey` are live.
                    if unsafe { enc(p8, pkey) } == 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::EVP_PKEY_167) };
                        // SAFETY: `p8` is this frame's.
                        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
                        return ptr::null_mut();
                    }
                }
                None => {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::EVP_PKEY_171) };
                    // SAFETY: `p8` is this frame's.
                    unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
                    return ptr::null_mut();
                }
            }
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_PKEY_175) };
            // SAFETY: `p8` is this frame's.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            return ptr::null_mut();
        }
    }
    // The authority frees the encoder context at its `end:` label whether it was built or not.
    // SAFETY: `ctx` is NULL or the context the framework made.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    p8
}

/// `EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/evp/evp_pkey.c:73-124`.
///
/// **Internal, not the export**: `EVP_PKCS82PKEY_ex` is `x509.h`'s and Phase 11's. It is
/// transcribed because `crypto/pem/pem_pk8.c`'s `d2i_PKCS8PrivateKey_bio` (`:194`) calls it; the
/// decoder-first arm is the one a fixed key reaches (`decode_der2key.c` publishes the DER
/// `PrivateKeyInfo` rows), with the legacy `evp_pkcs82pkey_legacy` fallback behind it.
///
/// # Safety
/// `p8` must be a live `PKCS8_PRIV_KEY_INFO`; `libctx`/`propq` are the decode context.
pub(crate) unsafe fn ossl_evp_pkcs82pkey_ex(
    p8: *const Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    const OSSL_MAX_NAME_SIZE: usize = 50;
    let mut algoid: *const Asn1Object = ptr::null();
    let mut keytype = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut pkey: *mut EvpPkey = ptr::null_mut();
    let mut encoded_data: *mut c_uchar = ptr::null_mut();

    if p8.is_null()
        // SAFETY: `p8` is live and `algoid` is this frame's out-parameter.
        || unsafe {
            PKCS8_pkey_get0(
                &raw mut algoid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                p8,
            )
        } == 0
        // SAFETY: `algoid` is live and `keytype` is a live buffer of the size passed.
        || unsafe {
            OBJ_obj2txt(
                keytype.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                algoid,
                0,
            )
        } == 0
    {
        return ptr::null_mut();
    }

    // SAFETY: `p8` is live and `encoded_data` is this frame's out-parameter.
    let encoded_len = unsafe { i2d_PKCS8_PRIV_KEY_INFO(p8, &mut encoded_data) };
    if encoded_len <= 0 || encoded_data.is_null() {
        return ptr::null_mut();
    }

    let mut p8_data: *const c_uchar = encoded_data;
    let mut len: usize = encoded_len as usize;
    let selection = EVP_PKEY_KEYPAIR | EVP_PKEY_KEY_PARAMETERS;
    // SAFETY: `pkey` is this frame's slot; the two strings are live and NUL-terminated.
    let mut dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &mut pkey,
            c"DER".as_ptr(),
            c"PrivateKeyInfo".as_ptr(),
            keytype.as_ptr(),
            selection,
            libctx,
            propq,
        )
    };

    if !dctx.is_null()
        // SAFETY: `dctx` is live.
        && unsafe { OSSL_DECODER_CTX_get_num_decoders(dctx) } == 0
    {
        // SAFETY: `dctx` is this frame's.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        // SAFETY: `pkey` is this frame's slot; the keytype is deliberately NULL.
        dctx = unsafe {
            OSSL_DECODER_CTX_new_for_pkey(
                &mut pkey,
                c"DER".as_ptr(),
                c"PrivateKeyInfo".as_ptr(),
                ptr::null(),
                selection,
                libctx,
                propq,
            )
        };
    }

    if dctx.is_null()
        // SAFETY: `dctx` is live; `p8_data`/`len` are this frame's.
        || unsafe { OSSL_DECODER_from_data(dctx, &raw mut p8_data, &raw mut len) } == 0
    {
        // SAFETY: `p8` is live and the context arguments are the caller's; this is the authority's
        // legacy fallback.
        pkey = unsafe { evp_pkcs82pkey_legacy(p8, libctx, propq) };
    }

    // SAFETY: `encoded_data` is the buffer `i2d_PKCS8_PRIV_KEY_INFO` allocated.
    unsafe {
        CRYPTO_clear_free(
            encoded_data.cast::<c_void>(),
            encoded_len as usize,
            ptr::null(),
            0,
        )
    };
    // SAFETY: `dctx` is NULL or live.
    unsafe { OSSL_DECODER_CTX_free(dctx) };
    pkey
}
