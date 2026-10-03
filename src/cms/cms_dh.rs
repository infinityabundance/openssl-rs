//! `crypto/cms/cms_dh.c` — the DH/DHX key-agreement envelope arm. Phase 12.3b.
//!
//! Defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_env.c`'s `ossl_cms_env_asn1_ctrl` reaches it and it is cms-local. Landed whole in 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::{Asn1String, V_ASN1_NULL, V_ASN1_SEQUENCE};
use crate::asn1::prim::{ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::asn1::string::{
    ASN1_STRING_free, ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::asn1::x_algor::{
    d2i_X509_ALGOR, i2d_X509_ALGOR, X509Algor, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_new,
    X509_ALGOR_set0,
};
use crate::bn::bignum::{BN_bn2binpad, BN_free, BigNum};
use crate::dh::ctrl::{
    EVP_PKEY_CTX_get_dh_kdf_md, EVP_PKEY_CTX_get_dh_kdf_type, EVP_PKEY_CTX_set0_dh_kdf_oid,
    EVP_PKEY_CTX_set0_dh_kdf_ukm, EVP_PKEY_CTX_set_dh_kdf_md, EVP_PKEY_CTX_set_dh_kdf_outlen,
    EVP_PKEY_CTX_set_dh_kdf_type,
};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode, EVP_CIPHER_get_type,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_asn1_to_param,
    EVP_EncryptInit_ex,
};
use crate::evp::digest::EvpMd;
use crate::evp::exchange::EVP_PKEY_derive_set_peer;
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_get_bn_param, EVP_PKEY_get_size,
    EVP_PKEY_is_a, EVP_PKEY_new, EVP_PKEY_set1_encoded_public_key, EvpPkey,
    OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get0_libctx, EVP_PKEY_CTX_get0_peerkey, EVP_PKEY_CTX_get0_pkey,
    EVP_PKEY_CTX_get0_propq, EvpPkeyCtx, EVP_PKEY_DH_KDF_X9_42,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup};
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{
    NID_dhpublicnumber, NID_id_smime_alg_ESDH, NID_undef, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt,
};

use super::cms_asn1::{ossl_asn1_string_set_bits_left, CmsRecipientInfo};

/// `CIPHER_CTX` wrapping mode `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:529`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `int dh_cms_set_peerkey(EVP_PKEY_CTX *pctx, X509_ALGOR *alg, ASN1_BIT_STRING *pubkey)` —
/// `cms_dh.c:20-79`.
///
/// # Safety
/// `pctx`/`alg`/`pubkey` are live.
unsafe fn dh_cms_set_peerkey(
    pctx: *mut EvpPkeyCtx,
    alg: *mut X509Algor,
    pubkey: *mut Asn1String,
) -> c_int {
    let mut aoid: *const Asn1Object = ptr::null();
    let mut atype = 0;
    let mut aval: *const c_void = ptr::null();
    let mut public_key: *mut Asn1String = ptr::null_mut();
    let mut rv = 0;
    let mut pkpeer: *mut EvpPkey = ptr::null_mut();
    let mut bnpub: *mut BigNum = ptr::null_mut();
    let mut buf: *mut c_uchar = ptr::null_mut();
    let mut plen;

    // SAFETY: `alg` is live; the three slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut atype, &mut aval, alg) };
    // SAFETY: `aoid` is live.
    if unsafe { OBJ_obj2nid(aoid) } != NID_dhpublicnumber {
        return rv;
    }
    // Only absent parameters allowed in RFC XXXX.
    if atype != crate::asn1::layout::V_ASN1_UNDEF && atype != V_ASN1_NULL {
        return rv;
    }

    // SAFETY: `pctx` is live.
    let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pk` is live.
    if pk.is_null() || unsafe { EVP_PKEY_is_a(pk, c"DHX".as_ptr()) } == 0 {
        return rv;
    }

    // Get public key.
    // SAFETY: `pubkey` is live.
    plen = unsafe { ASN1_STRING_length(pubkey) };
    // SAFETY: `pubkey` is live.
    let p = unsafe { ASN1_STRING_get0_data(pubkey) };
    if p.is_null() || plen == 0 {
        return rv;
    }

    // SAFETY: `p` is readable for `plen`; the item answers a fresh integer.
    let mut pp = p;
    // SAFETY: the arguments meet the callee's contract.
    public_key = unsafe {
        ASN1_item_d2i(ptr::null_mut(), &mut pp, plen as c_long, ASN1_INTEGER_it())
            .cast::<Asn1String>()
    };
    if public_key.is_null() {
        return rv;
    }

    // Pad to full p parameter size as EVP_PKEY_set1_encoded_public_key() checks it.
    // SAFETY: `pk` is live.
    plen = unsafe { EVP_PKEY_get_size(pk) };
    // SAFETY: `public_key` is live.
    bnpub = unsafe { ASN1_INTEGER_to_BN(public_key, ptr::null_mut()) };
    if bnpub.is_null() {
        // SAFETY: the arguments meet the callee's contract.
        unsafe { ASN1_STRING_free(public_key) };
        return rv;
    }
    // SAFETY: `plen >= 0` per the key size.
    buf = CRYPTO_malloc(plen as usize, c"cms_dh.c".as_ptr(), 60).cast::<c_uchar>();
    if buf.is_null() {
        // SAFETY: the arguments are live scalars.
        unsafe {
            ASN1_STRING_free(public_key);
            BN_free(bnpub);
        }
        return rv;
    }
    // SAFETY: `bnpub` is live; `buf` is `plen` bytes.
    if unsafe { BN_bn2binpad(bnpub, buf, plen) } < 0 {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            ASN1_STRING_free(public_key);
            BN_free(bnpub);
            CRYPTO_free(buf.cast(), c"cms_dh.c".as_ptr(), 61);
        }
        return rv;
    }

    // SAFETY: the allocator answers a fresh key.
    pkpeer = unsafe { EVP_PKEY_new() };
    let ok = !pkpeer.is_null()
        // SAFETY: `pkpeer`/`pk` are live.
        && unsafe { EVP_PKEY_copy_parameters(pkpeer, pk) } != 0
        // SAFETY: `pkpeer` is live; `buf` is `plen` bytes.
        && unsafe { EVP_PKEY_set1_encoded_public_key(pkpeer, buf, plen as usize) } > 0;
    if ok {
        // SAFETY: `pctx`/`pkpeer` are live.
        if unsafe { EVP_PKEY_derive_set_peer(pctx, pkpeer) } > 0 {
            rv = 1;
        }
    }
    // SAFETY: each is NULL or owned.
    unsafe {
        ASN1_STRING_free(public_key);
        BN_free(bnpub);
        CRYPTO_free(buf.cast(), c"cms_dh.c".as_ptr(), 76);
        EVP_PKEY_free(pkpeer);
    }
    rv
}

/// `int dh_cms_set_shared_info(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)` — `cms_dh.c:81-165`.
///
/// # Safety
/// `pctx`/`ri` are live.
unsafe fn dh_cms_set_shared_info(pctx: *mut EvpPkeyCtx, ri: *mut CmsRecipientInfo) -> c_int {
    let mut rv = 0;
    let mut alg: *mut X509Algor = ptr::null_mut();
    let mut kekalg: *mut X509Algor = ptr::null_mut();
    let mut ukm: *mut Asn1String = ptr::null_mut();
    let mut dukm: *mut c_uchar = ptr::null_mut();
    let mut dukmlen = 0;
    let keylen;
    let mut plen = 0;
    let mut kekcipher: *mut crate::evp::cipher::EvpCipher = ptr::null_mut();
    let mut aoid: *const Asn1Object = ptr::null();
    let mut parameter: *const c_void = ptr::null();
    let mut ptype = 0;
    let mut name = [0 as core::ffi::c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: `ri` is live.
    if unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_alg(ri, &mut alg, &mut ukm) } == 0 {
        return rv;
    }

    // SAFETY: `alg` is live; the three slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut aoid, &mut ptype, &mut parameter, alg) };

    // For DH we only have one OID permissible.
    // SAFETY: `aoid` is live.
    if unsafe { OBJ_obj2nid(aoid) } != NID_id_smime_alg_ESDH {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                107,
                c"dh_cms_set_shared_info",
                crate::runtime::err::err_reasons::CMS_R_KDF_PARAMETER_ERROR,
            )
        };
        return rv;
    }

    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_X9_42) } <= 0
        // SAFETY: `pctx`/`sha1` are live.
        || unsafe { EVP_PKEY_CTX_set_dh_kdf_md(pctx, EVP_sha1()) } <= 0
    {
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
    if unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*kekalg).algorithm,
            0,
        )
    } <= 0
    {
        // SAFETY: `kekalg` is owned here.
        unsafe { X509_ALGOR_free(kekalg) };
        return rv;
    }

    // SAFETY: `pctx` is live; `name` is a C string.
    kekcipher = unsafe {
        EVP_CIPHER_fetch(
            EVP_PKEY_CTX_get0_libctx(pctx),
            name.as_ptr(),
            EVP_PKEY_CTX_get0_propq(pctx),
        )
    };
    let kekok = !kekcipher.is_null()
        // SAFETY: `kekcipher` is live.
        && unsafe { EVP_CIPHER_get_mode(kekcipher) } == EVP_CIPH_WRAP_MODE;
    if kekok {
        // SAFETY: `kekctx`/`kekcipher` are live.
        if unsafe {
            EVP_EncryptInit_ex(kekctx, kekcipher, ptr::null_mut(), ptr::null(), ptr::null())
        } != 0
        {
            // SAFETY: `kekctx`/`kekalg` are live.
            if unsafe { EVP_CIPHER_asn1_to_param(kekctx, (*kekalg).parameter) } > 0 {
                // SAFETY: `kekctx` is live.
                keylen = unsafe { EVP_CIPHER_CTX_get_key_length(kekctx) };
                // SAFETY: `pctx` is live.
                if unsafe { EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) } > 0 {
                    // SAFETY: `kekcipher` is live.
                    let knid = unsafe { EVP_CIPHER_get_type(kekcipher) };
                    // SAFETY: `pctx` is live.
                    if unsafe { EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, OBJ_nid2obj(knid)) } > 0 {
                        let mut dukm_ok = true;
                        if !ukm.is_null() {
                            // SAFETY: `ukm` is live.
                            dukmlen = unsafe { ASN1_STRING_length(ukm) };
                            // SAFETY: `ukm` is live.
                            dukm = unsafe {
                                CRYPTO_memdup(
                                    ASN1_STRING_get0_data(ukm).cast(),
                                    dukmlen as usize,
                                    c"cms_dh.c".as_ptr(),
                                    150,
                                )
                                .cast::<c_uchar>()
                            };
                            dukm_ok = !dukm.is_null();
                        }
                        if dukm_ok {
                            // SAFETY: `pctx` is live.
                            if unsafe { EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) } > 0 {
                                dukm = ptr::null_mut();
                                rv = 1;
                            }
                        }
                    }
                }
            }
        }
    }
    // SAFETY: each is NULL or owned.
    unsafe {
        X509_ALGOR_free(kekalg);
        EVP_CIPHER_free(kekcipher);
        CRYPTO_free(dukm.cast(), c"cms_dh.c".as_ptr(), 163);
    }
    rv
}

/// `int dh_cms_decrypt(CMS_RecipientInfo *ri)` — `cms_dh.c:167-194`.
///
/// # Safety
/// `ri` is live.
unsafe fn dh_cms_decrypt(ri: *mut CmsRecipientInfo) -> c_int {
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
        if unsafe { dh_cms_set_peerkey(pctx, alg, pubkey) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    184,
                    c"dh_cms_decrypt",
                    crate::runtime::err::err_reasons::CMS_R_PEER_KEY_ERROR,
                )
            };
            return 0;
        }
    }
    // SAFETY: `pctx`/`ri` are live.
    if unsafe { dh_cms_set_shared_info(pctx, ri) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                189,
                c"dh_cms_decrypt",
                crate::runtime::err::err_reasons::CMS_R_SHARED_INFO_ERROR,
            )
        };
        return 0;
    }
    1
}

/// `int dh_cms_encrypt(CMS_RecipientInfo *ri)` — `cms_dh.c:196-334`.
///
/// # Safety
/// `ri` is live.
unsafe fn dh_cms_encrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut ctx: *mut crate::evp::cipher_ctx::EvpCipherCtx = ptr::null_mut();
    let keylen;
    let mut talg: *mut X509Algor = ptr::null_mut();
    let mut wrap_alg: *mut X509Algor = ptr::null_mut();
    let mut aoid: *const Asn1Object = ptr::null();
    let mut pubkey: *mut Asn1String = ptr::null_mut();
    let mut wrap_str: *mut Asn1String = ptr::null_mut();
    let mut ukm: *mut Asn1String = ptr::null_mut();
    let mut penc: *mut c_uchar = ptr::null_mut();
    let mut dukm: *mut c_uchar = ptr::null_mut();
    let mut penclen;
    let mut dukmlen = 0;
    let mut rv = 0;
    let mut kdf_type;
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

    'body: {
        // SAFETY: `talg` is live; the three slots are this frame's.
        unsafe { X509_ALGOR_get0(&mut aoid, ptr::null_mut(), ptr::null_mut(), talg) };
        // Is everything uninitialised?
        // SAFETY: `aoid` is live.
        if aoid == { OBJ_nid2obj(NID_undef) } {
            let mut bn_pub_key: *mut BigNum = ptr::null_mut();

            // SAFETY: `pkey` is live; `bn_pub_key` is this frame's slot.
            if unsafe { EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &mut bn_pub_key) } == 0
            {
                break 'body;
            }

            // SAFETY: `bn_pub_key` is live.
            let pubk = unsafe { BN_to_ASN1_INTEGER(bn_pub_key, ptr::null_mut()) };
            // SAFETY: `bn_pub_key` is owned here.
            unsafe { BN_free(bn_pub_key) };
            if pubk.is_null() {
                break 'body;
            }

            // Set the key.
            // SAFETY: `pubk` is live; `penc` is this frame's slot.
            penclen = unsafe { ASN1_item_i2d(pubk.cast(), &mut penc, ASN1_INTEGER_it()) };
            // SAFETY: `pubk` is owned here.
            unsafe { ASN1_STRING_free(pubk) };
            if penclen <= 0 {
                break 'body;
            }
            // SAFETY: `pubkey`/`penc` are live; ownership transfers.
            unsafe { ASN1_STRING_set0(pubkey, penc.cast(), penclen) };
            // SAFETY: `pubkey` is live.
            unsafe { ossl_asn1_string_set_bits_left(pubkey, 0) };

            penc = ptr::null_mut();
            // SAFETY: `talg` is live.
            unsafe {
                X509_ALGOR_set0(
                    talg,
                    OBJ_nid2obj(NID_dhpublicnumber),
                    crate::asn1::layout::V_ASN1_UNDEF,
                    ptr::null_mut(),
                )
            };
        }

        // See if custom parameters set.
        // SAFETY: `pctx` is live.
        kdf_type = unsafe { EVP_PKEY_CTX_get_dh_kdf_type(pctx) };
        // SAFETY: `pctx` is live; `kdf_md` is this frame's slot.
        if kdf_type <= 0 || unsafe { EVP_PKEY_CTX_get_dh_kdf_md(pctx, &mut kdf_md) } <= 0 {
            break 'body;
        }

        if kdf_type == crate::evp::pkey_ctx::EVP_PKEY_DH_KDF_NONE {
            kdf_type = EVP_PKEY_DH_KDF_X9_42;
            // SAFETY: `pctx` is live.
            if unsafe { EVP_PKEY_CTX_set_dh_kdf_type(pctx, kdf_type) } <= 0 {
                break 'body;
            }
        } else if kdf_type != EVP_PKEY_DH_KDF_X9_42 {
            // Unknown KDF.
            break 'body;
        }
        if kdf_md.is_null() {
            // Only SHA1 supported.
            // SAFETY: the context and key are live.
            kdf_md = EVP_sha1();
            // SAFETY: `pctx`/`kdf_md` are live.
            if unsafe { EVP_PKEY_CTX_set_dh_kdf_md(pctx, kdf_md) } <= 0 {
                break 'body;
            }
        // SAFETY: the arguments meet the callee's contract.
        } else if unsafe { crate::evp::digest::EVP_MD_get_type(kdf_md) }
            != crate::runtime::obj::NID_sha1
        {
            // Unsupported digest.
            break 'body;
        }

        // SAFETY: `ri` is live.
        if unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_alg(ri, &mut talg, &mut ukm) } == 0
        {
            break 'body;
        }

        // Get wrap NID.
        // SAFETY: `ri` is live.
        ctx = unsafe { super::cms_kari::CMS_RecipientInfo_kari_get0_ctx(ri) };
        // SAFETY: `ctx` is live.
        wrap_nid = unsafe { EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(ctx)) };
        // SAFETY: `pctx` is live.
        if unsafe { EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, OBJ_nid2obj(wrap_nid)) } <= 0 {
            break 'body;
        }
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
        unsafe { (*wrap_alg).parameter = crate::asn1::a_type::ASN1_TYPE_new() };
        // SAFETY: `wrap_alg` is live.
        if unsafe { (*wrap_alg).parameter }.is_null() {
            break 'body;
        }
        // SAFETY: `ctx`/`wrap_alg` are live.
        if unsafe { crate::evp::cipher_ctx::EVP_CIPHER_param_to_asn1(ctx, (*wrap_alg).parameter) }
            <= 0
        {
            break 'body;
        }
        // SAFETY: `wrap_alg` is live.
        if unsafe { crate::asn1::a_type::ASN1_TYPE_get((*wrap_alg).parameter) } == NID_undef {
            // SAFETY: the parameter is owned here.
            unsafe { crate::asn1::a_type::ASN1_TYPE_free((*wrap_alg).parameter) };
            // SAFETY: `wrap_alg` is live.
            unsafe { (*wrap_alg).parameter = ptr::null_mut() };
        }

        // SAFETY: `pctx` is live.
        if unsafe { EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) } <= 0 {
            break 'body;
        }

        if !ukm.is_null() {
            // SAFETY: `ukm` is live.
            dukmlen = unsafe { ASN1_STRING_length(ukm) };
            // SAFETY: `ukm` is live.
            dukm = unsafe {
                CRYPTO_memdup(
                    ASN1_STRING_get0_data(ukm).cast(),
                    dukmlen as usize,
                    c"cms_dh.c".as_ptr(),
                    302,
                )
                .cast::<c_uchar>()
            };
            if dukm.is_null() {
                break 'body;
            }
        }

        // SAFETY: `pctx` is live.
        if unsafe { EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) } <= 0 {
            break 'body;
        }
        dukm = ptr::null_mut();

        // Wrap encoding of wrap AlgorithmIdentifier into parameter of another AlgorithmIdentifier.
        penc = ptr::null_mut();
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
            X509_ALGOR_set0(
                talg,
                OBJ_nid2obj(NID_id_smime_alg_ESDH),
                V_ASN1_SEQUENCE,
                wrap_str.cast(),
            )
        };
        if rv == 0 {
            // SAFETY: `wrap_str` is owned here.
            unsafe { ASN1_STRING_free(wrap_str) };
        }
    }
    // SAFETY: each is NULL or owned.
    unsafe {
        CRYPTO_free(penc.cast(), c"cms_dh.c".as_ptr(), 330);
        X509_ALGOR_free(wrap_alg);
        CRYPTO_free(dukm.cast(), c"cms_dh.c".as_ptr(), 332);
    }
    rv
}

/// `int ossl_cms_dh_envelope(CMS_RecipientInfo *ri, int decrypt)` — `cms_dh.c:336-348`.
///
/// # Safety
/// `ri` is live.
pub(crate) unsafe extern "C" fn ossl_cms_dh_envelope(
    ri: *mut CmsRecipientInfo,
    decrypt: c_int,
) -> c_int {
    if decrypt == 1 {
        // SAFETY: `ri` is live.
        return unsafe { dh_cms_decrypt(ri) };
    }
    if decrypt == 0 {
        // SAFETY: `ri` is live.
        return unsafe { dh_cms_encrypt(ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        super::cms_lib::raise_cms(
            346,
            c"ossl_cms_dh_envelope",
            crate::runtime::err::err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
        )
    };
    0
}
