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

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::asn1::p8_pkey::{PKCS8_pkey_get0, Pkcs8PrivKeyInfo};
use crate::asn1::text::i2t_ASN1_OBJECT;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_type, EvpPkey};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};

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
