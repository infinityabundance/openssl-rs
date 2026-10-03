//! `crypto/cms/cms_ec.c` — the ECDH key-agreement envelope arm. Phase 12.3b.
//!
//! Defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_env.c`'s `ossl_cms_env_asn1_ctrl` reaches it and it is cms-local. Landed whole in 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_get, ASN1_TYPE_new};
use crate::asn1::layout::{Asn1String, V_ASN1_NULL, V_ASN1_SEQUENCE, V_ASN1_UNDEF};
use crate::asn1::string::{
    ASN1_STRING_free, ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::asn1::x_algor::{
    d2i_X509_ALGOR, i2d_X509_ALGOR, X509Algor, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_new,
    X509_ALGOR_set0,
};
use crate::decoder_lib::OSSL_DECODER_from_data;
use crate::decoder_meth::{OSSL_DECODER_CTX_free, OsslDecoderCtx};
use crate::decoder_pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::ec::ctrl::{
    EVP_PKEY_CTX_get_ecdh_cofactor_mode, EVP_PKEY_CTX_get_ecdh_kdf_md,
    EVP_PKEY_CTX_get_ecdh_kdf_type, EVP_PKEY_CTX_set0_ecdh_kdf_ukm,
    EVP_PKEY_CTX_set_ecdh_cofactor_mode, EVP_PKEY_CTX_set_ecdh_kdf_md,
    EVP_PKEY_CTX_set_ecdh_kdf_outlen, EVP_PKEY_CTX_set_ecdh_kdf_type,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_asn1_to_param,
    EVP_CIPHER_param_to_asn1, EVP_EncryptInit_ex,
};
use crate::evp::digest::{EVP_MD_get_type, EvpMd};
use crate::evp::exchange::EVP_PKEY_derive_set_peer;
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key, EVP_PKEY_new,
    EVP_PKEY_set1_encoded_public_key, EvpPkey,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get0_libctx, EVP_PKEY_CTX_get0_peerkey, EVP_PKEY_CTX_get0_pkey,
    EVP_PKEY_CTX_get0_propq, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_set_group_name, EvpPkeyCtx,
    EVP_PKEY_ECDH_KDF_NONE, EVP_PKEY_ECDH_KDF_X9_63,
};
use crate::evp::pmeth_gn::{EVP_PKEY_paramgen, EVP_PKEY_paramgen_init};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{
    NID_X9_62_id_ecPublicKey, NID_dh_cofactor_kdf, NID_dh_std_kdf, NID_undef, OBJ_find_sigid_algs,
    OBJ_find_sigid_by_algs, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt,
};

use super::cms_asn1::{ossl_asn1_string_set_bits_left, CMS_SharedInfo_encode, CmsRecipientInfo};

/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:529`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `crypto/store/store_result.c`'s
/// `OSSL_KEYMGMT_SELECT_ALL | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int = 0x04 | 0x80;
/// `INT_MAX` — `limits.h`.
const INT_MAX: c_long = c_int::MAX as c_long;

/// `EVP_PKEY *pkey_type2param(int ptype, const void *pval, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_ec.c:20-71`.
///
/// # Safety
/// `pval` matches `ptype`; the decoder and paramgen calls are the authority's own.
unsafe fn pkey_type2param(
    ptype: c_int,
    pval: *const c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut pkey: *mut EvpPkey = ptr::null_mut();
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut ctx: *mut OsslDecoderCtx = ptr::null_mut();

    if ptype == crate::asn1::layout::V_ASN1_SEQUENCE {
        // SAFETY: `pval` is an `ASN1_STRING` in this arm.
        let pstr = pval.cast::<Asn1String>();
        // SAFETY: `pstr` is live.
        let mut pm = unsafe { (*pstr).data } as *const u8;
        // SAFETY: `pstr` is live.
        let mut pmlen = unsafe { (*pstr).length } as usize;
        let selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;

        // SAFETY: the decoder answers a fresh context; `pkey` is this frame's slot.
        ctx = unsafe {
            OSSL_DECODER_CTX_new_for_pkey(
                &mut pkey,
                c"DER".as_ptr(),
                ptr::null(),
                c"EC".as_ptr(),
                selection,
                libctx,
                propq,
            )
        };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live; `pm` is readable for `pmlen`.
        if unsafe { OSSL_DECODER_from_data(ctx, &mut pm, &mut pmlen) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    39,
                    c"pkey_type2param",
                    crate::runtime::err::err_reasons::CMS_R_DECODE_ERROR,
                )
            };
            // SAFETY: `pkey`/`ctx` are owned here.
            unsafe {
                EVP_PKEY_free(pkey);
                OSSL_DECODER_CTX_free(ctx);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is owned here.
        unsafe { OSSL_DECODER_CTX_free(ctx) };
        return pkey;
    } else if ptype == crate::asn1::layout::V_ASN1_OBJECT {
        // SAFETY: `pval` is an `ASN1_OBJECT` in this arm.
        let poid = pval.cast::<Asn1Object>();
        let mut groupname = [0 as c_char; OSSL_MAX_NAME_SIZE];

        // SAFETY: the context constructor answers a fresh context.
        pctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"EC".as_ptr(), propq) };
        // SAFETY: `pctx` is live.
        if pctx.is_null() || unsafe { EVP_PKEY_paramgen_init(pctx) } <= 0 {
            return ptr::null_mut();
        }
        // SAFETY: `groupname` is writable; `poid` is live.
        if unsafe {
            OBJ_obj2txt(
                groupname.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                poid,
                0,
            )
        } <= 0
            // SAFETY: `pctx` is live; `groupname` is a C string.
            || unsafe { EVP_PKEY_CTX_set_group_name(pctx, groupname.as_ptr()) } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    54,
                    c"pkey_type2param",
                    crate::runtime::err::err_reasons::CMS_R_DECODE_ERROR,
                )
            };
            // SAFETY: `pkey`/`pctx` are owned here.
            unsafe {
                EVP_PKEY_free(pkey);
                crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pctx);
            }
            return ptr::null_mut();
        }
        // SAFETY: `pctx` is live; `pkey` is this frame's slot.
        if unsafe { EVP_PKEY_paramgen(pctx, &mut pkey) } <= 0 {
            // SAFETY: `pkey`/`pctx` are owned here.
            unsafe {
                EVP_PKEY_free(pkey);
                crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pctx);
            }
            return ptr::null_mut();
        }
        // SAFETY: `pctx` is owned here.
        unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pctx) };
        return pkey;
    }

    // SAFETY: the site is a compile-time constant.
    unsafe {
        super::cms_lib::raise_cms(
            63,
            c"pkey_type2param",
            crate::runtime::err::err_reasons::CMS_R_DECODE_ERROR,
        )
    };
    ptr::null_mut()
}

/// `int ecdh_cms_set_peerkey(EVP_PKEY_CTX *pctx, X509_ALGOR *alg, ASN1_BIT_STRING *pubkey)` —
/// `cms_ec.c:73-122`.
///
/// # Safety
/// `pctx`/`alg`/`pubkey` are live.
unsafe fn ecdh_cms_set_peerkey(
    pctx: *mut EvpPkeyCtx,
    alg: *mut X509Algor,
    pubkey: *mut Asn1String,
) -> c_int {
    let mut aoid: *const Asn1Object = ptr::null();
    let mut atype = 0;
    let mut aval: *const c_void = ptr::null();
    let mut rv = 0;
    let mut pkpeer: *mut EvpPkey = ptr::null_mut();

    // SAFETY: `alg` is live; the slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut atype, &mut aval, alg) };
    // SAFETY: `aoid` is live.
    if unsafe { OBJ_obj2nid(aoid) } != NID_X9_62_id_ecPublicKey {
        return rv;
    }

    // If absent parameters get group from main key.
    if atype == V_ASN1_UNDEF || atype == V_ASN1_NULL {
        // SAFETY: `pctx` is live.
        let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
        if pk.is_null() {
            return rv;
        }
        // SAFETY: the allocator answers a fresh key.
        pkpeer = unsafe { EVP_PKEY_new() };
        if pkpeer.is_null() {
            return rv;
        }
        // SAFETY: `pkpeer`/`pk` are live.
        if unsafe { EVP_PKEY_copy_parameters(pkpeer, pk) } == 0 {
            // SAFETY: `pkpeer` is owned here.
            unsafe { EVP_PKEY_free(pkpeer) };
            return rv;
        }
    } else {
        // SAFETY: `atype`/`aval` describe the parameter; the contexts are live.
        pkpeer = unsafe {
            pkey_type2param(
                atype,
                aval,
                EVP_PKEY_CTX_get0_libctx(pctx),
                EVP_PKEY_CTX_get0_propq(pctx),
            )
        };
        if pkpeer.is_null() {
            return rv;
        }
    }
    // We have parameters now; set public key.
    // SAFETY: `pubkey` is live.
    let plen = unsafe { ASN1_STRING_length(pubkey) };
    // SAFETY: `pubkey` is live.
    let p = unsafe { ASN1_STRING_get0_data(pubkey) };
    if p.is_null() || plen == 0 {
        // SAFETY: `pkpeer` is owned here.
        unsafe { EVP_PKEY_free(pkpeer) };
        return rv;
    }

    // SAFETY: `pkpeer` is live; `p` is readable for `plen`.
    if unsafe { EVP_PKEY_set1_encoded_public_key(pkpeer, p, plen as usize) } <= 0 {
        // SAFETY: `pkpeer` is owned here.
        unsafe { EVP_PKEY_free(pkpeer) };
        return rv;
    }

    // SAFETY: `pctx`/`pkpeer` are live.
    if unsafe { EVP_PKEY_derive_set_peer(pctx, pkpeer) } > 0 {
        rv = 1;
    }
    // SAFETY: `pkpeer` is owned here.
    unsafe { EVP_PKEY_free(pkpeer) };
    rv
}

/// `int ecdh_cms_set_kdf_param(EVP_PKEY_CTX *pctx, int eckdf_nid)` — `cms_ec.c:125-157`.
///
/// # Safety
/// `pctx` is live.
unsafe fn ecdh_cms_set_kdf_param(pctx: *mut EvpPkeyCtx, eckdf_nid: c_int) -> c_int {
    if eckdf_nid == NID_undef {
        return 0;
    }

    let mut kdfmd_nid = 0;
    let mut kdf_nid = 0;
    // SAFETY: `kdfmd_nid`/`kdf_nid` are this frame's slots.
    if unsafe { OBJ_find_sigid_algs(eckdf_nid, &mut kdfmd_nid, &mut kdf_nid) } == 0 {
        return 0;
    }

    let cofactor = if kdf_nid == NID_dh_std_kdf {
        0
    } else if kdf_nid == NID_dh_cofactor_kdf {
        1
    } else {
        return 0;
    };

    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_CTX_set_ecdh_cofactor_mode(pctx, cofactor) } <= 0 {
        return 0;
    }

    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_X9_63) } <= 0 {
        return 0;
    }

    // SAFETY: `OBJ_nid2sn` answers a static string or NULL; the lookup is the macro expansion.
    let kdf_md = unsafe { EVP_get_digestbyname(OBJ_nid2sn(kdfmd_nid)) };
    if kdf_md.is_null() {
        return 0;
    }

    // SAFETY: `pctx`/`kdf_md` are live.
    if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) } <= 0 {
        return 0;
    }
    1
}

/// `int ecdh_cms_set_shared_info(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)` — `cms_ec.c:159-224`.
///
/// # Safety
/// `pctx`/`ri` are live.
unsafe fn ecdh_cms_set_shared_info(pctx: *mut EvpPkeyCtx, ri: *mut CmsRecipientInfo) -> c_int {
    let mut rv = 0;
    let mut alg: *mut X509Algor = ptr::null_mut();
    let mut kekalg: *mut X509Algor = ptr::null_mut();
    let mut ukm: *mut Asn1String = ptr::null_mut();
    let mut der: *mut c_uchar = ptr::null_mut();
    let mut plen;
    let mut keylen = 0;
    let mut kekcipher: *mut crate::evp::cipher::EvpCipher = ptr::null_mut();
    let mut aoid: *const Asn1Object = ptr::null();
    let mut ptype = 0;
    let mut parameter: *const c_void = ptr::null();
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: `ri` is live.
    if unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_alg(ri, &mut alg, &mut ukm) } == 0 {
        return rv;
    }

    // SAFETY: `alg` is live; the slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut ptype, &mut parameter, alg) };

    // SAFETY: `aoid` is live.
    if unsafe { ecdh_cms_set_kdf_param(pctx, OBJ_obj2nid(aoid)) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                181,
                c"ecdh_cms_set_shared_info",
                crate::runtime::err::err_reasons::CMS_R_KDF_PARAMETER_ERROR,
            )
        };
        return rv;
    }

    if ptype != V_ASN1_SEQUENCE {
        return rv;
    }

    // SAFETY: `parameter` is a live string.
    let p = unsafe { ASN1_STRING_get0_data(parameter.cast::<Asn1String>()) };
    // SAFETY: same.
    plen = unsafe { ASN1_STRING_length(parameter.cast::<Asn1String>()) };
    // SAFETY: `p` is readable for `plen`; the item answers a fresh identifier.
    let mut pp = p;
    // SAFETY: the pointer is live per the checks above.
    kekalg = unsafe { d2i_X509_ALGOR(ptr::null_mut(), &mut pp, plen as c_long) };
    if kekalg.is_null() {
        return rv;
    }
    // SAFETY: `ri` is live.
    let kekctx = unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_ctx(ri) };
    if kekctx.is_null() {
        // SAFETY: `kekalg` is owned here.
        unsafe { X509_ALGOR_free(kekalg) };
        return rv;
    }
    // SAFETY: `name` is writable; `kekalg` is live.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*kekalg).algorithm,
            0,
        )
    };
    // SAFETY: `pctx` is live; `name` is a C string.
    kekcipher = unsafe {
        EVP_CIPHER_fetch(
            EVP_PKEY_CTX_get0_libctx(pctx),
            name.as_ptr(),
            EVP_PKEY_CTX_get0_propq(pctx),
        )
    };
    if kekcipher.is_null()
        // SAFETY: `kekcipher` is live.
        || unsafe { EVP_CIPHER_get_mode(kekcipher) } != EVP_CIPH_WRAP_MODE
    {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
        }
        return rv;
    }
    // SAFETY: `kekctx`/`kekcipher` are live.
    if unsafe { EVP_EncryptInit_ex(kekctx, kekcipher, ptr::null_mut(), ptr::null(), ptr::null()) }
        == 0
    {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
        }
        return rv;
    }
    // SAFETY: `kekctx`/`kekalg` are live.
    if unsafe { EVP_CIPHER_asn1_to_param(kekctx, (*kekalg).parameter) } <= 0 {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
        }
        return rv;
    }

    // SAFETY: `kekctx` is live.
    keylen = unsafe { EVP_CIPHER_CTX_get_key_length(kekctx) };
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) } <= 0 {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
        }
        return rv;
    }

    // SAFETY: `der` is this frame's slot; `kekalg`/`ukm` are live.
    plen = unsafe { CMS_SharedInfo_encode(&mut der, kekalg, ukm, keylen) };

    if plen <= 0 {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
            CRYPTO_free(der.cast(), c"cms_ec.c".as_ptr(), 222);
        }
        return rv;
    }

    // SAFETY: `pctx` is live; `der` ownership transfers.
    if unsafe { EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, der, plen) } <= 0 {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(kekcipher);
            X509_ALGOR_free(kekalg);
        }
        return rv;
    }
    der = ptr::null_mut();

    rv = 1;
    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_free(kekcipher);
        X509_ALGOR_free(kekalg);
        CRYPTO_free(der.cast(), c"cms_ec.c".as_ptr(), 222);
    }
    rv
}

/// `int ecdh_cms_decrypt(CMS_RecipientInfo *ri)` — `cms_ec.c:226-254`.
///
/// # Safety
/// `ri` is live.
unsafe fn ecdh_cms_decrypt(ri: *mut CmsRecipientInfo) -> c_int {
    // SAFETY: `ri` is live.
    let pctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    if pctx.is_null() {
        return 0;
    }
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_CTX_get0_peerkey(pctx) }.is_null() {
        let mut alg: *mut X509Algor = ptr::null_mut();
        let mut pubkey: *mut Asn1String = ptr::null_mut();

        // SAFETY: `ri` is live.
        if unsafe {
            super::cms_kari::CMS_RecipientInfo_kari_get0_orig_id(
                ri,
                &mut alg,
                &mut pubkey,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            return 0;
        }
        if alg.is_null() || pubkey.is_null() {
            return 0;
        }
        // SAFETY: `pctx`/`alg`/`pubkey` are live.
        if unsafe { ecdh_cms_set_peerkey(pctx, alg, pubkey) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    244,
                    c"ecdh_cms_decrypt",
                    crate::runtime::err::err_reasons::CMS_R_PEER_KEY_ERROR,
                )
            };
            return 0;
        }
    }
    // SAFETY: `pctx`/`ri` are live.
    if unsafe { ecdh_cms_set_shared_info(pctx, ri) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                249,
                c"ecdh_cms_decrypt",
                crate::runtime::err::err_reasons::CMS_R_SHARED_INFO_ERROR,
            )
        };
        return 0;
    }
    1
}

/// `int ecdh_cms_encrypt(CMS_RecipientInfo *ri)` — `cms_ec.c:256-386`.
///
/// # Safety
/// `ri` is live.
unsafe fn ecdh_cms_encrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut ctx: *mut crate::evp::cipher_ctx::EvpCipherCtx = ptr::null_mut();
    let keylen;
    let mut talg: *mut X509Algor = ptr::null_mut();
    let mut wrap_alg: *mut X509Algor = ptr::null_mut();
    let mut aoid: *const Asn1Object = ptr::null();
    let mut pubkey: *mut Asn1String = ptr::null_mut();
    let mut wrap_str: *mut Asn1String = ptr::null_mut();
    let mut ukm: *mut Asn1String = ptr::null_mut();
    let mut penc: *mut c_uchar = ptr::null_mut();
    let mut penclen;
    let mut rv = 0;
    let mut ecdh_nid;
    let mut kdf_type;
    let mut kdf_nid = 0;
    let wrap_nid;
    let mut kdf_md: *const EvpMd = ptr::null();

    // SAFETY: `ri` is live.
    let pctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    if pctx.is_null() {
        return 0;
    }
    // SAFETY: `pctx` is live.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `ri` is live.
    if unsafe {
        super::cms_kari::CMS_RecipientInfo_kari_get0_orig_id(
            ri,
            &mut talg,
            &mut pubkey,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return rv;
    }
    // SAFETY: `talg` is live; the slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut aoid, ptr::null_mut(), ptr::null_mut(), talg) };

    'body: {
        // Is everything uninitialised?
        // SAFETY: `aoid` is live.
        if aoid == { OBJ_nid2obj(NID_undef) } {
            // Set the key.
            let mut penc2: *mut c_uchar = ptr::null_mut();
            // SAFETY: `pkey` is live; `penc2` is this frame's slot.
            let enckeylen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey, &mut penc2) };
            if enckeylen as c_long > INT_MAX || enckeylen == 0 {
                // SAFETY: `penc2` is owned here.
                unsafe { CRYPTO_free(penc2.cast(), c"cms_ec.c".as_ptr(), 289) };
                break 'body;
            }
            // SAFETY: `pubkey`/`penc2` are live; ownership transfers.
            unsafe { ASN1_STRING_set0(pubkey, penc2.cast(), enckeylen as c_int) };
            // SAFETY: `pubkey` is live.
            unsafe { ossl_asn1_string_set_bits_left(pubkey, 0) };

            // SAFETY: `talg` is live.
            unsafe {
                X509_ALGOR_set0(
                    talg,
                    OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
                    V_ASN1_UNDEF,
                    ptr::null_mut(),
                )
            };
        }

        // See if custom parameters set.
        // SAFETY: `pctx` is live.
        kdf_type = unsafe { EVP_PKEY_CTX_get_ecdh_kdf_type(pctx) };
        if kdf_type <= 0 {
            break 'body;
        }
        // SAFETY: `pctx` is live; `kdf_md` is this frame's slot.
        if unsafe { EVP_PKEY_CTX_get_ecdh_kdf_md(pctx, &mut kdf_md) } <= 0 {
            break 'body;
        }
        // SAFETY: `pctx` is live.
        ecdh_nid = unsafe { EVP_PKEY_CTX_get_ecdh_cofactor_mode(pctx) };
        if ecdh_nid < 0 {
            break 'body;
        } else if ecdh_nid == 0 {
            ecdh_nid = NID_dh_std_kdf;
        } else if ecdh_nid == 1 {
            ecdh_nid = NID_dh_cofactor_kdf;
        }

        if kdf_type == EVP_PKEY_ECDH_KDF_NONE {
            kdf_type = EVP_PKEY_ECDH_KDF_X9_63;
            // SAFETY: `pctx` is live.
            if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, kdf_type) } <= 0 {
                break 'body;
            }
        } else {
            // Unknown KDF.
            break 'body;
        }
        if kdf_md.is_null() {
            // Fixme later for better MD.
            // SAFETY: the context and key are live.
            kdf_md = EVP_sha1();
            // SAFETY: `pctx`/`kdf_md` are live.
            if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) } <= 0 {
                break 'body;
            }
        }

        // SAFETY: `ri` is live.
        if unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_alg(ri, &mut talg, &mut ukm) } == 0
        {
            break 'body;
        }

        // Lookup NID for KDF+cofactor+digest.
        // SAFETY: `kdf_nid` is this frame's slot.
        if unsafe { OBJ_find_sigid_by_algs(&mut kdf_nid, EVP_MD_get_type(kdf_md), ecdh_nid) } == 0 {
            break 'body;
        }
        // Get wrap NID.
        // SAFETY: `ri` is live.
        ctx = unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_ctx(ri) };
        // SAFETY: `ctx` is live.
        wrap_nid =
            unsafe { crate::evp::cipher::EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(ctx)) };
        // SAFETY: `ctx` is live.
        keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };

        // Package wrap algorithm in an AlgorithmIdentifier.
        // SAFETY: the allocator answers a fresh identifier.
        wrap_alg = X509_ALGOR_new();
        if wrap_alg.is_null() {
            break 'body;
        }
        // SAFETY: `wrap_alg` is live.
        unsafe { (*wrap_alg).algorithm = OBJ_nid2obj(wrap_nid) };
        // SAFETY: the allocator answers a fresh type.
        unsafe { (*wrap_alg).parameter = ASN1_TYPE_new() };
        // SAFETY: `wrap_alg` is live.
        if unsafe { (*wrap_alg).parameter }.is_null() {
            break 'body;
        }
        // SAFETY: `ctx`/`wrap_alg` are live.
        if unsafe { EVP_CIPHER_param_to_asn1(ctx, (*wrap_alg).parameter) } <= 0 {
            break 'body;
        }
        // SAFETY: `wrap_alg` is live.
        if unsafe { ASN1_TYPE_get((*wrap_alg).parameter) } == NID_undef {
            // SAFETY: the parameter is owned here.
            unsafe { ASN1_TYPE_free((*wrap_alg).parameter) };
            // SAFETY: `wrap_alg` is live.
            unsafe { (*wrap_alg).parameter = ptr::null_mut() };
        }

        // SAFETY: `pctx` is live.
        if unsafe { EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) } <= 0 {
            break 'body;
        }

        // SAFETY: `penc` is this frame's slot; `wrap_alg`/`ukm` are live.
        penclen = unsafe { CMS_SharedInfo_encode(&mut penc, wrap_alg, ukm, keylen) };

        if penclen <= 0 {
            break 'body;
        }

        // SAFETY: `pctx` is live; `penc` ownership transfers.
        if unsafe { EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, penc, penclen) } <= 0 {
            break 'body;
        }
        penc = ptr::null_mut();

        // Wrap encoding of wrap AlgorithmIdentifier into parameter of another AlgorithmIdentifier.
        // SAFETY: `wrap_alg` is live; `penc` is this frame's slot.
        penclen = unsafe { i2d_X509_ALGOR(wrap_alg, &mut penc) };
        if penclen <= 0 {
            break 'body;
        }
        // SAFETY: the allocator answers a fresh string.
        wrap_str = ASN1_STRING_new();
        if wrap_str.is_null() {
            break 'body;
        }
        // SAFETY: `wrap_str`/`penc` are live; ownership transfers.
        unsafe { ASN1_STRING_set0(wrap_str, penc.cast(), penclen) };
        penc = ptr::null_mut();
        // SAFETY: `talg`/`wrap_str` are live.
        rv = unsafe {
            X509_ALGOR_set0(talg, OBJ_nid2obj(kdf_nid), V_ASN1_SEQUENCE, wrap_str.cast())
        };
        if rv == 0 {
            // SAFETY: `wrap_str` is owned here.
            unsafe { ASN1_STRING_free(wrap_str) };
        }
    }
    // SAFETY: each is NULL or owned.
    unsafe {
        CRYPTO_free(penc.cast(), c"cms_ec.c".as_ptr(), 383);
        X509_ALGOR_free(wrap_alg);
    }
    rv
}

/// `int ossl_cms_ecdh_envelope(CMS_RecipientInfo *ri, int decrypt)` — `cms_ec.c:388-400`.
///
/// # Safety
/// `ri` is live.
pub(crate) unsafe extern "C" fn ossl_cms_ecdh_envelope(
    ri: *mut CmsRecipientInfo,
    decrypt: c_int,
) -> c_int {
    if decrypt == 1 {
        // SAFETY: `ri` is live.
        return unsafe { ecdh_cms_decrypt(ri) };
    }
    if decrypt == 0 {
        // SAFETY: `ri` is live.
        return unsafe { ecdh_cms_encrypt(ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        super::cms_lib::raise_cms(
            398,
            c"ossl_cms_ecdh_envelope",
            crate::runtime::err::err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
        )
    };
    0
}
