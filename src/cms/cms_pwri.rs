//! `crypto/cms/cms_pwri.c` — the password recipient engine and the RFC 3211 KEK wrap/unwrap.
//! Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_new;
use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::layout::{Asn1String, V_ASN1_SEQUENCE};
use crate::asn1::p5_pbev2::PKCS5_pbkdf2_set_ex;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_flags, EVP_CIPHER_get_type,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding,
    EVP_CIPHER_asn1_to_param, EVP_CIPHER_param_to_asn1, EVP_CipherInit_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
};
use crate::evp::evp_pbe::EVP_PBE_CipherInit_ex;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{NID_id_alg_PWRI_KEK, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::OPENSSL_sk_push;

use super::cms_asn1::*;
use super::cms_lib::{ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq};

/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:531`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x20_0000;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri, unsigned char *pass,`
/// `ossl_ssize_t passlen)` — `cms_pwri.c:22-37`.
///
/// # Safety
/// `ri` is live; `pass` is NULL or readable for `passlen` when `passlen >= 0`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_set0_password(
    ri: *mut CmsRecipientInfo,
    pass: *mut c_uchar,
    mut passlen: isize,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_PASS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                27,
                c"CMS_RecipientInfo_set0_password",
                crate::runtime::err::err_reasons::CMS_R_NOT_PWRI,
            )
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let pwri = unsafe { (*ri).d.cast::<CmsPasswordRecipientInfo>() };
    // SAFETY: `pwri` is live.
    unsafe { (*pwri).pass = pass };
    if !pass.is_null() && passlen < 0 {
        // SAFETY: `pass` is a NUL-terminated string in this arm.
        passlen = unsafe { c_strlen(pass) } as isize;
    }
    // SAFETY: `pwri` is live.
    unsafe { (*pwri).passlen = passlen as usize };
    1
}

/// `strlen(3)`'s observable contract for the C string `s`.
///
/// # Safety
/// `s` is a NUL-terminated C string.
unsafe fn c_strlen(s: *const c_uchar) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms, int iter,`
/// `int wrap_nid, int pbe_nid, unsigned char *pass, ossl_ssize_t passlen,`
/// `const EVP_CIPHER *kekciph)` — `cms_pwri.c:39-193`.
///
/// # Safety
/// `cms` is live; `pass` is NULL or readable for `passlen` when `passlen >= 0`; `kekciph` is
/// NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_recipient_password(
    cms: *mut CmsContentInfo,
    iter: c_int,
    mut wrap_nid: c_int,
    pbe_nid: c_int,
    pass: *mut c_uchar,
    passlen: isize,
    mut kekciph: *const c_void,
) -> *mut CmsRecipientInfo {
    let _ = pbe_nid;
    let mut ri: *mut CmsRecipientInfo = ptr::null_mut();
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut encalg: *mut X509Algor = ptr::null_mut();
    let mut iv = [0u8; EVP_MAX_IV_LENGTH];
    let ivlen;
    // SAFETY: `cms` is live.
    let cms_ctx = unsafe { super::cms_lib::ossl_cms_get0_cmsctx(cms) };

    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    if ec.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    let ris = unsafe { super::cms_env::CMS_get0_RecipientInfos(cms) };
    if ris.is_null() {
        return ptr::null_mut();
    }

    if wrap_nid <= 0 {
        wrap_nid = NID_id_alg_PWRI_KEK;
    }

    // Get from enveloped data.
    // SAFETY: `ec` is live.
    if kekciph.is_null() {
        // SAFETY: the pointer is live per the checks above.
        kekciph = unsafe { (*ec).cipher };
    }

    if kekciph.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                71,
                c"CMS_add0_recipient_password",
                crate::runtime::err::err_reasons::CMS_R_NO_CIPHER,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `kekciph` is live.
    if unsafe { EVP_CIPHER_get_flags(kekciph.cast()) } & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                75,
                c"CMS_add0_recipient_password",
                crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_KEK_ALGORITHM,
            )
        };
        return ptr::null_mut();
    }
    if wrap_nid != NID_id_alg_PWRI_KEK {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                79,
                c"CMS_add0_recipient_password",
                crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM,
            )
        };
        return ptr::null_mut();
    }

    'body: {
        // Setup algorithm identifier for cipher.
        // SAFETY: the allocator answers a fresh identifier.
        encalg = X509_ALGOR_new();
        if encalg.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    86,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }
        // SAFETY: the allocator answers a fresh context.
        ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    91,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_EVP_LIB,
                )
            };
            break 'body;
        }

        // SAFETY: `ctx`/`kekciph` are live.
        if unsafe {
            EVP_EncryptInit_ex(
                ctx,
                kekciph.cast(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    96,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_EVP_LIB,
                )
            };
            break 'body;
        }

        // SAFETY: `ctx` is live.
        ivlen = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if ivlen < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    102,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_EVP_LIB,
                )
            };
            break 'body;
        }

        if ivlen > 0 {
            // SAFETY: `iv` is writable; `cms_ctx` is live.
            if unsafe {
                RAND_bytes_ex(
                    ossl_cms_ctx_get0_libctx(cms_ctx),
                    iv.as_mut_ptr(),
                    ivlen as usize,
                    0,
                )
            } <= 0
            {
                break 'body;
            }
            // SAFETY: `ctx` is live; `iv` is readable.
            if unsafe {
                EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), iv.as_ptr())
            } <= 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    super::cms_lib::raise_cms(
                        110,
                        c"CMS_add0_recipient_password",
                        super::cms_lib::ERR_R_EVP_LIB,
                    )
                };
                break 'body;
            }
            // SAFETY: the allocator answers a fresh type.
            unsafe { (*encalg).parameter = ASN1_TYPE_new() };
            // SAFETY: `encalg` is live.
            if unsafe { (*encalg).parameter }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    super::cms_lib::raise_cms(
                        115,
                        c"CMS_add0_recipient_password",
                        super::cms_lib::ERR_R_ASN1_LIB,
                    )
                };
                break 'body;
            }
            // SAFETY: `ctx`/`encalg` are live.
            if unsafe { EVP_CIPHER_param_to_asn1(ctx, (*encalg).parameter) } <= 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    super::cms_lib::raise_cms(
                        119,
                        c"CMS_add0_recipient_password",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                    )
                };
                break 'body;
            }
        }

        // SAFETY: `ctx` is live.
        let et = unsafe { EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(ctx)) };
        // SAFETY: `encalg` is live.
        unsafe { (*encalg).algorithm = OBJ_nid2obj(et) };

        // SAFETY: `ctx` is owned here.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        ctx = ptr::null_mut();

        // Initialize recipient info.
        // SAFETY: the item answers a fresh recipient.
        ri = unsafe { m_asn1_new(cms_recipientinfo_it()) }.cast::<CmsRecipientInfo>();
        if ri.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    131,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }

        // SAFETY: the item answers a fresh password recipient.
        let pwri = unsafe { m_asn1_new(cms_passwordrecipientinfo_it()) }
            .cast::<CmsPasswordRecipientInfo>();
        // SAFETY: `ri` is live.
        unsafe { (*ri).d = pwri.cast() };
        if pwri.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    137,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }
        // SAFETY: `ri` is live.
        unsafe {
            (*ri).encoded_type = CMS_RECIPINFO_PASS;
            (*ri).type_ = CMS_RECIPINFO_PASS;
        }

        // SAFETY: `pwri` is live.
        unsafe { (*pwri).cms_ctx = cms_ctx };
        // Since this is overwritten, free up the empty structure already there.
        // SAFETY: `pwri` is live.
        unsafe { X509_ALGOR_free((*pwri).key_encryption_algorithm) };
        // SAFETY: the allocator answers a fresh identifier.
        unsafe { (*pwri).key_encryption_algorithm = X509_ALGOR_new() };
        // SAFETY: `pwri` is live.
        if unsafe { (*pwri).key_encryption_algorithm }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    148,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }
        // SAFETY: `pwri` is live.
        unsafe {
            (*(*pwri).key_encryption_algorithm).algorithm = OBJ_nid2obj(wrap_nid);
            (*(*pwri).key_encryption_algorithm).parameter = ASN1_TYPE_new();
        }
        // SAFETY: `pwri` is live.
        if unsafe { (*(*pwri).key_encryption_algorithm).parameter }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    154,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }

        // SAFETY: `pwri` is live.
        let param = unsafe { (*(*pwri).key_encryption_algorithm).parameter };
        // SAFETY: `param` is live; the slot is its sequence member.
        let seq_slot = unsafe { ptr::addr_of_mut!((*param).value.ptr) as *mut *mut Asn1String };
        // SAFETY: `encalg` is live; the item is static.
        if unsafe { ASN1_item_pack(encalg.cast(), X509_ALGOR_it(), seq_slot) }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    159,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_ASN1_LIB,
                )
            };
            break 'body;
        }
        // SAFETY: `param` is live.
        unsafe { (*param).type_ = V_ASN1_SEQUENCE };

        // SAFETY: `encalg` is owned here.
        unsafe { X509_ALGOR_free(encalg) };
        encalg = ptr::null_mut();

        // Setup PBE algorithm.
        // SAFETY: `cms_ctx` is live.
        unsafe {
            (*pwri).key_derivation_algorithm = PKCS5_pbkdf2_set_ex(
                iter,
                ptr::null_mut(),
                0,
                -1,
                -1,
                ossl_cms_ctx_get0_libctx(cms_ctx),
            )
        };

        // SAFETY: `pwri` is live.
        if unsafe { (*pwri).key_derivation_algorithm }.is_null() {
            break 'body;
        }

        // SAFETY: `ri` is live.
        unsafe { CMS_RecipientInfo_set0_password(ri, pass, passlen) };
        // SAFETY: `pwri` is live.
        unsafe { (*pwri).version = 0 };

        // SAFETY: `ris`/`ri` are live.
        if unsafe { OPENSSL_sk_push(ris, ri.cast()) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    181,
                    c"CMS_add0_recipient_password",
                    super::cms_lib::ERR_R_CRYPTO_LIB,
                )
            };
            break 'body;
        }

        return ri;
    }

    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_CTX_free(ctx);
        if !ri.is_null() {
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
        }
        X509_ALGOR_free(encalg);
    }
    ptr::null_mut()
}

/// `int kek_unwrap_key(unsigned char *out, size_t *outlen, const unsigned char *in,`
/// `size_t inlen, EVP_CIPHER_CTX *ctx)` — `cms_pwri.c:200-254`.
///
/// # Safety
/// `out` is writable for `*outlen`; `in` is readable for `inlen`; `ctx` is live.
unsafe fn kek_unwrap_key(
    out: *mut c_uchar,
    outlen: *mut usize,
    input: *const c_uchar,
    inlen: usize,
    ctx: *mut EvpCipherCtx,
) -> c_int {
    // SAFETY: `ctx` is live.
    let blocklen = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
    let mut rv = 0;
    let mut tmp: *mut c_uchar = ptr::null_mut();
    let mut outl: c_int = 0;

    if blocklen < 4 {
        return 0;
    }

    if inlen < 2 * (blocklen as usize) {
        return 0;
    }
    if inlen > c_int::MAX as usize || !inlen.is_multiple_of(blocklen as usize) {
        return 0;
    }
    // SAFETY: `inlen > 0`.
    tmp = CRYPTO_malloc(inlen, c"cms_pwri.c".as_ptr(), 219).cast::<c_uchar>();
    if tmp.is_null() {
        return 0;
    }
    // Setup IV by decrypting last two blocks.
    // SAFETY: `ctx` is live; the buffers are sized.
    let ok = unsafe {
        EVP_DecryptUpdate(
            ctx,
            tmp.add(inlen - 2 * blocklen as usize),
            &mut outl,
            input.add(inlen - 2 * blocklen as usize),
            blocklen * 2,
        )
    } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_DecryptUpdate(
                ctx,
                tmp,
                &mut outl,
                tmp.add(inlen - blocklen as usize),
                blocklen,
            )
        } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_DecryptUpdate(
                ctx,
                tmp,
                &mut outl,
                input,
                (inlen - blocklen as usize) as c_int,
            )
        } != 0
        // Reset IV to original value.
        // SAFETY: `ctx` is live.
        && unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null()) }
            != 0
        // Decrypt again.
        // SAFETY: `ctx` is live; `tmp` is the buffer.
        && unsafe { EVP_DecryptUpdate(ctx, tmp, &mut outl, tmp, inlen as c_int) } != 0;
    if !ok {
        // SAFETY: `tmp` is owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(tmp, inlen) };
        return 0;
    }
    // Check check bytes.
    // SAFETY: `tmp` is readable for `inlen >= 2*blocklen >= 8`.
    if (unsafe { *tmp.add(1) ^ *tmp.add(4) }
        // SAFETY: the arguments meet the callee's contract.
        & unsafe { *tmp.add(2) ^ *tmp.add(5) }
        // SAFETY: the arguments meet the callee's contract.
        & unsafe { *tmp.add(3) ^ *tmp.add(6) })
        != 0xff
    {
        // SAFETY: each pointer is NULL or owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(tmp, inlen) };
        return 0;
    }
    // SAFETY: `tmp` is readable.
    if inlen < 4 + unsafe { *tmp } as usize {
        // SAFETY: each pointer is NULL or owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(tmp, inlen) };
        return 0;
    }
    // SAFETY: `outlen` is writable; `tmp` is readable.
    let n = unsafe { *tmp } as usize;
    // SAFETY: the arguments meet the callee's contract.
    unsafe { *outlen = n };
    // SAFETY: `out` is writable for `n`; `tmp + 4` is readable for `n`.
    unsafe { ptr::copy_nonoverlapping(tmp.add(4), out, n) };
    rv = 1;
    // SAFETY: `tmp` is owned here.
    unsafe { super::cms_asn1::OPENSSL_clear_free(tmp, inlen) };
    rv
}

/// `int kek_wrap_key(unsigned char *out, size_t *outlen, const unsigned char *in,`
/// `size_t inlen, EVP_CIPHER_CTX *ctx, const CMS_CTX *cms_ctx)` — `cms_pwri.c:256-303`.
///
/// # Safety
/// `out` is NULL or writable for the round-up; `in` is readable for `inlen`; `ctx`/`cms_ctx`
/// are live.
unsafe fn kek_wrap_key(
    out: *mut c_uchar,
    outlen: *mut usize,
    input: *const c_uchar,
    inlen: usize,
    ctx: *mut EvpCipherCtx,
    cms_ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: `ctx` is live.
    let blocklen = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
    let mut olen;
    let mut dummy: c_int = 0;

    if blocklen == 0 {
        return 0;
    }

    // First decide length of output buffer: header and round up to a multiple of block length.
    olen = (inlen + 4).div_ceil(blocklen);
    olen *= blocklen;
    if olen < 2 * blocklen {
        return 0;
    }
    if inlen > 0xFF {
        return 0;
    }
    if !out.is_null() {
        // Set header.
        // SAFETY: `out`/`input` are writable/readable; `inlen >= 3` follows from `olen`.
        unsafe {
            *out = inlen as c_uchar;
            *out.add(1) = *input ^ 0xFF;
            *out.add(2) = *input.add(1) ^ 0xFF;
            *out.add(3) = *input.add(2) ^ 0xFF;
            ptr::copy_nonoverlapping(input, out.add(4), inlen);
        }
        // Add random padding to end.
        if olen > inlen + 4
            // SAFETY: `cms_ctx` is live; the buffer is writable.
            && unsafe {
                RAND_bytes_ex(
                    ossl_cms_ctx_get0_libctx(cms_ctx),
                    out.add(4 + inlen),
                    olen - 4 - inlen,
                    0,
                )
            } <= 0
        {
            return 0;
        }
        // Encrypt twice.
        // SAFETY: `ctx` is live; `out` is the buffer.
        if unsafe { EVP_EncryptUpdate(ctx, out, &mut dummy, out, olen as c_int) } == 0
            // SAFETY: as above.
            || unsafe { EVP_EncryptUpdate(ctx, out, &mut dummy, out, olen as c_int) } == 0
        {
            return 0;
        }
    }

    // SAFETY: `outlen` is writable.
    unsafe { *outlen = olen };

    1
}

/// `int ossl_cms_RecipientInfo_pwri_crypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri, int en_de)` — `cms_pwri.c:307-430`.
///
/// # Safety
/// `cms`/`ri` are live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_pwri_crypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
    en_de: c_int,
) -> c_int {
    let mut r = 0;
    let mut algtmp: *mut X509Algor = ptr::null_mut();
    let mut kekalg: *mut X509Algor = ptr::null_mut();
    let mut kekctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut kekcipher: *mut crate::evp::cipher::EvpCipher = ptr::null_mut();
    let mut key: *mut c_uchar = ptr::null_mut();
    let mut keylen = 0usize;
    let mut key_alloc_len = 0usize;
    // SAFETY: `cms` is live.
    let cms_ctx = unsafe { super::cms_lib::ossl_cms_get0_cmsctx(cms) };

    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };

    // SAFETY: `ri` is live.
    let pwri = unsafe { (*ri).d.cast::<CmsPasswordRecipientInfo>() };

    // SAFETY: `pwri` is live.
    if unsafe { (*pwri).pass }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                327,
                c"ossl_cms_RecipientInfo_pwri_crypt",
                crate::runtime::err::err_reasons::CMS_R_NO_PASSWORD,
            )
        };
        return 0;
    }
    // SAFETY: `pwri` is live.
    algtmp = unsafe { (*pwri).key_encryption_algorithm };

    // SAFETY: `algtmp` is live.
    if algtmp.is_null()
        // SAFETY: `algtmp` is live.
        || unsafe { OBJ_obj2nid((*algtmp).algorithm) } != NID_id_alg_PWRI_KEK
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                333,
                c"ossl_cms_RecipientInfo_pwri_crypt",
                crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM,
            )
        };
        return 0;
    }

    // SAFETY: `algtmp` is live; the item is static.
    kekalg = unsafe {
        crate::asn1::a_type::ASN1_TYPE_unpack_sequence(X509_ALGOR_it(), (*algtmp).parameter)
            .cast::<X509Algor>()
    };

    if kekalg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                341,
                c"ossl_cms_RecipientInfo_pwri_crypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER,
            )
        };
        return 0;
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
    // SAFETY: `cms_ctx` is live; `name` is a C string.
    kekcipher = unsafe {
        EVP_CIPHER_fetch(
            ossl_cms_ctx_get0_libctx(cms_ctx),
            name.as_ptr(),
            ossl_cms_ctx_get0_propq(cms_ctx),
        )
    };

    if kekcipher.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                350,
                c"ossl_cms_RecipientInfo_pwri_crypt",
                crate::runtime::err::err_reasons::CMS_R_UNKNOWN_CIPHER,
            )
        };
        // SAFETY: the arguments meet the callee's contract.
        unsafe { X509_ALGOR_free(kekalg) };
        return r;
    }

    'body: {
        // SAFETY: the allocator answers a fresh context.
        kekctx = EVP_CIPHER_CTX_new();
        if kekctx.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    357,
                    c"ossl_cms_RecipientInfo_pwri_crypt",
                    super::cms_lib::ERR_R_EVP_LIB,
                )
            };
            break 'body;
        }
        // Fixup cipher based on AlgorithmIdentifier to set IV etc.
        // SAFETY: `kekctx`/`kekcipher` are live.
        if unsafe {
            EVP_CipherInit_ex(
                kekctx,
                kekcipher,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                en_de,
            )
        } == 0
        {
            break 'body;
        }
        // SAFETY: `kekctx` is live.
        unsafe { EVP_CIPHER_CTX_set_padding(kekctx, 0) };
        // SAFETY: `kekctx`/`kekalg` are live.
        if unsafe { EVP_CIPHER_asn1_to_param(kekctx, (*kekalg).parameter) } <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    365,
                    c"ossl_cms_RecipientInfo_pwri_crypt",
                    crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                )
            };
            break 'body;
        }

        // SAFETY: `pwri` is live.
        algtmp = unsafe { (*pwri).key_derivation_algorithm };

        // Finish password based key derivation to setup key in "ctx".
        if algtmp.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    374,
                    c"ossl_cms_RecipientInfo_pwri_crypt",
                    crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER,
                )
            };
            break 'body;
        }
        // SAFETY: `algtmp`/`pwri`/`kekctx` are live; `cms_ctx` supplies the libctx and propq.
        if unsafe {
            EVP_PBE_CipherInit_ex(
                (*algtmp).algorithm,
                (*pwri).pass.cast::<c_char>(),
                (*pwri).passlen as c_int,
                (*algtmp).parameter,
                kekctx,
                en_de,
                ossl_cms_ctx_get0_libctx(cms_ctx),
                ossl_cms_ctx_get0_propq(cms_ctx),
            )
        } == 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                super::cms_lib::raise_cms(
                    381,
                    c"ossl_cms_RecipientInfo_pwri_crypt",
                    super::cms_lib::ERR_R_EVP_LIB,
                )
            };
            break 'body;
        }

        // Finally wrap/unwrap the key.
        if en_de != 0 {
            // SAFETY: `ec` is live; `keylen` is this frame's slot.
            if unsafe {
                kek_wrap_key(
                    ptr::null_mut(),
                    &mut keylen,
                    (*ec).key,
                    (*ec).keylen,
                    kekctx,
                    cms_ctx,
                )
            } == 0
            {
                break 'body;
            }

            // SAFETY: `keylen > 0`.
            key = CRYPTO_malloc(keylen, c"cms_pwri.c".as_ptr(), 392).cast::<c_uchar>();

            if key.is_null() {
                break 'body;
            }
            key_alloc_len = keylen;

            // SAFETY: `ec` is live; `key` is writable.
            if unsafe { kek_wrap_key(key, &mut keylen, (*ec).key, (*ec).keylen, kekctx, cms_ctx) }
                == 0
            {
                break 'body;
            }
            // SAFETY: `pwri` is live.
            unsafe {
                (*(*pwri).encrypted_key).data = key;
                (*(*pwri).encrypted_key).length = keylen as c_int;
            }
            key = ptr::null_mut();
        } else {
            // SAFETY: `pwri` is live.
            let elen = unsafe { (*(*pwri).encrypted_key).length };
            // SAFETY: `elen >= 0`.
            key = CRYPTO_malloc(elen as usize, c"cms_pwri.c".as_ptr(), 403).cast::<c_uchar>();
            if key.is_null() {
                break 'body;
            }
            key_alloc_len = elen as usize;
            // SAFETY: `pwri` is live; `key` is writable.
            if unsafe {
                kek_unwrap_key(
                    key,
                    &mut keylen,
                    (*(*pwri).encrypted_key).data,
                    elen as usize,
                    kekctx,
                )
            } == 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    super::cms_lib::raise_cms(
                        410,
                        c"ossl_cms_RecipientInfo_pwri_crypt",
                        crate::runtime::err::err_reasons::CMS_R_UNWRAP_FAILURE,
                    )
                };
                break 'body;
            }

            // SAFETY: `ec` is live.
            unsafe { super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen) };
            // SAFETY: `ec` is live.
            unsafe {
                (*ec).key = key;
                (*ec).keylen = keylen;
            }
            key = ptr::null_mut();
        }

        r = 1;
    }

    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_free(kekcipher);
        EVP_CIPHER_CTX_free(kekctx);

        if r == 0 {
            super::cms_asn1::OPENSSL_clear_free(key, key_alloc_len);
        }
        X509_ALGOR_free(kekalg);
    }

    r
}
