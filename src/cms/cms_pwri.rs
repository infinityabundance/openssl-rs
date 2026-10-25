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

use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{NID_id_alg_PWRI_KEK, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::OPENSSL_sk_push;

use super::cms_asn1::*;
use super::cms_lib::{ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq};
use crate::runtime::mem_coords::SeamFile;

/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:531`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x20_0000;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`, `262 | ERR_RFLAG_COMMON`
/// (`ERR_RFLAG_COMMON` is `0x2 << ERR_RFLAGS_OFFSET`, and `ERR_RFLAGS_OFFSET` is 18).
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// The refusal this conversion adds to `CMS_add0_recipient_password` when the selected cipher
/// reports an IV length that does not fit the authority's fixed stack buffer.
///
/// The authority has no such site. `cms_pwri.c:52` declares
/// `unsigned char iv[EVP_MAX_IV_LENGTH]`, and `:107` hands the length returned by
/// `EVP_CIPHER_CTX_get_iv_length()` to `RAND_bytes_ex`, which writes exactly that many bytes. The
/// line names the authority operation this conversion declines: `RAND_bytes_ex` is where an
/// oversized length would have been written past the buffer.
const CMS_PWRI_IV_REFUSED: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/cms/cms_pwri.c",
    line: 107,
    func: c"CMS_add0_recipient_password",
    lib: super::cms_lib::ERR_LIB_CMS,
    reason: ERR_R_PASSED_INVALID_ARGUMENT,
    dynamic_reason: false,
};

/// Test-only observation for the two S28 input-boundary obligations. Thread-local, so concurrent
/// tests cannot see each other's records, and compiled out of every non-test build.
#[cfg(test)]
mod test_hooks {
    use core::cell::Cell;

    thread_local! {
        static PRE_FIX_IV_OVERFLOW: Cell<bool> = const { Cell::new(false) };
        static PRE_FIX_SHORT_WRAP: Cell<bool> = const { Cell::new(false) };
    }

    /// Record that the refusal was reached with an IV longer than the fixed stack buffer. The
    /// authority's `RAND_bytes_ex` would have written past it.
    pub(super) fn note_pre_fix_iv_overflow() {
        PRE_FIX_IV_OVERFLOW.with(|c| c.set(true));
    }

    pub(super) fn pre_fix_iv_overflow_fired() -> bool {
        PRE_FIX_IV_OVERFLOW.with(Cell::get)
    }

    /// Record that the refusal was reached with fewer than the three bytes the header reads.
    /// The authority's header writes would have read `in[0..3]` regardless.
    pub(super) fn note_pre_fix_short_wrap() {
        PRE_FIX_SHORT_WRAP.with(|c| c.set(true));
    }

    pub(super) fn pre_fix_short_wrap_fired() -> bool {
        PRE_FIX_SHORT_WRAP.with(Cell::get)
    }

    pub(super) fn reset() {
        PRE_FIX_IV_OVERFLOW.with(|c| c.set(false));
        PRE_FIX_SHORT_WRAP.with(|c| c.set(false));
    }
}

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

        // `iv` above is the authority's fixed `[u8; EVP_MAX_IV_LENGTH]`, but the length comes from
        // the cipher: `EVP_CIPHER_meth_set_iv_length` accepts any `int`, and a provider's `ivlen`
        // is an unbounded `size_t` cached into an `int`. `RAND_bytes_ex` and the subsequent
        // `EVP_EncryptInit_ex` write exactly the reported length, so a length that does not fit is
        // refused structurally against the buffer instead of assumed to fit.
        if ivlen as usize > EVP_MAX_IV_LENGTH {
            #[cfg(test)]
            test_hooks::note_pre_fix_iv_overflow();
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&CMS_PWRI_IV_REFUSED) };
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
    // The decrypted scratch is this frame's block, allocated through the crate's allocator seam;
    // its release is the authority's cleansing `OPENSSL_clear_free`, run by `Drop`.
    // SAFETY: `inlen > 0`.
    let Some(tmp) = OwnedBuf::new_cleansed_released(
        inlen,
        SeamFile::new(c"cms_pwri.c"),
        219,
        SeamFile::NULL,
        0,
    ) else {
        return 0;
    };
    // Setup IV by decrypting last two blocks.
    // SAFETY: `ctx` is live; the buffers are sized.
    let ok = unsafe {
        EVP_DecryptUpdate(
            ctx,
            tmp.as_ptr().add(inlen - 2 * blocklen as usize),
            &mut outl,
            input.add(inlen - 2 * blocklen as usize),
            blocklen * 2,
        )
    } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_DecryptUpdate(
                ctx,
                tmp.as_ptr(),
                &mut outl,
                tmp.as_ptr().add(inlen - blocklen as usize),
                blocklen,
            )
        } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_DecryptUpdate(
                ctx,
                tmp.as_ptr(),
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
        && unsafe { EVP_DecryptUpdate(ctx, tmp.as_ptr(), &mut outl, tmp.as_ptr(), inlen as c_int) }
            != 0;
    if !ok {
        return 0;
    }
    // SAFETY: `tmp` is readable for `inlen >= 2*blocklen >= 8`.
    let raw = tmp.as_ptr();
    // Check check bytes.
    // SAFETY: `raw` is readable for `inlen >= 2*blocklen >= 8`.
    if (unsafe { *raw.add(1) ^ *raw.add(4) }
        // SAFETY: the arguments meet the callee's contract.
        & unsafe { *raw.add(2) ^ *raw.add(5) }
        // SAFETY: the arguments meet the callee's contract.
        & unsafe { *raw.add(3) ^ *raw.add(6) })
        != 0xff
    {
        return 0;
    }
    // SAFETY: `raw` is readable.
    if inlen < 4 + unsafe { *raw } as usize {
        return 0;
    }
    // SAFETY: `outlen` is writable; `raw` is readable.
    let n = unsafe { *raw } as usize;
    // SAFETY: the arguments meet the callee's contract.
    unsafe { *outlen = n };
    // SAFETY: `out` is writable for `n`; `raw + 4` is readable for `n`.
    unsafe { ptr::copy_nonoverlapping(raw.add(4), out, n) };
    rv = 1;
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
    let blocklen = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
    let mut dummy: c_int = 0;

    // A negative block size is not usable and, cast to `usize`, would make the round-up below
    // meaningless. The authority assigns it to `size_t` and then returns 0 through the same
    // `olen < 2 * blocklen` check; refuse it directly instead.
    if blocklen <= 0 {
        return 0;
    }
    let blocklen = blocklen as usize;

    // The header below reads `in[0]`, `in[1]` and `in[2]` unconditionally, so a three-byte input
    // is a precondition of the authority's own body. The round-up does not imply it: with a
    // four-byte block, `inlen == 2` yields `olen == 8 == 2 * blocklen` and reaches the header.
    if inlen < 3 {
        #[cfg(test)]
        test_hooks::note_pre_fix_short_wrap();
        return 0;
    }

    // First decide length of output buffer: header and round up to a multiple of block length.
    // `inlen` is caller-supplied (the C ABI's `ec->keylen` is a `size_t`), so the sum and the
    // scale use checked arithmetic and overflow is the authority's failure (return 0), not a
    // panic boundary.
    let Some(rounded) = inlen
        .checked_add(4)
        .and_then(|n| n.checked_add(blocklen - 1))
    else {
        return 0;
    };
    let Some(olen) = (rounded / blocklen).checked_mul(blocklen) else {
        return 0;
    };
    if olen < 2 * blocklen {
        return 0;
    }
    if inlen > 0xFF {
        return 0;
    }
    if !out.is_null() {
        // Set header.
        // SAFETY: `out`/`input` are writable/readable; `inlen >= 3` was checked above, so the
        // three header reads are in bounds.
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
    let mut key: Option<OwnedBuf> = None;
    let mut keylen = 0usize;
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

            // The wrapped key is this frame's block, allocated through the crate's allocator
            // seam; its release is the authority's cleansing `OPENSSL_clear_free`, run by `Drop`.
            // SAFETY: `keylen > 0`.
            let Some(key_buf) = OwnedBuf::new_cleansed_released(
                keylen,
                SeamFile::new(c"cms_pwri.c"),
                392,
                SeamFile::NULL,
                0,
            ) else {
                break 'body;
            };

            // SAFETY: `ec` is live; `key_buf` is writable.
            if unsafe {
                kek_wrap_key(
                    key_buf.as_ptr(),
                    &mut keylen,
                    (*ec).key,
                    (*ec).keylen,
                    kekctx,
                    cms_ctx,
                )
            } == 0
            {
                // Keep the block for the tail's release at the authority's own site.
                key = Some(key_buf);
                break 'body;
            }
            // SAFETY: `pwri` is live; ownership of the block transfers to the `ASN1_STRING`.
            unsafe {
                (*(*pwri).encrypted_key).data = key_buf.into_raw();
                (*(*pwri).encrypted_key).length = keylen as c_int;
            }
        } else {
            // SAFETY: `pwri` is live.
            let elen = unsafe { (*(*pwri).encrypted_key).length };
            // The unwrapped key is this frame's block, allocated through the crate's allocator
            // seam; its release is the authority's cleansing `OPENSSL_clear_free`, run by `Drop`.
            // SAFETY: `elen >= 0`.
            let Some(key_buf) = OwnedBuf::new_cleansed_released(
                elen as usize,
                SeamFile::new(c"cms_pwri.c"),
                403,
                SeamFile::NULL,
                0,
            ) else {
                break 'body;
            };
            // SAFETY: `pwri` is live; `key_buf` is writable.
            if unsafe {
                kek_unwrap_key(
                    key_buf.as_ptr(),
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
                // Keep the block for the tail's release at the authority's own site.
                key = Some(key_buf);
                break 'body;
            }

            // SAFETY: `ec` is live; ownership of the block transfers to `ec.key`.
            unsafe {
                super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
                (*ec).key = key_buf.into_raw();
                (*ec).keylen = keylen;
            }
        }

        r = 1;
    }

    // SAFETY: `kekcipher`/`kekctx` are NULL or owned.
    unsafe {
        EVP_CIPHER_free(kekcipher);
        EVP_CIPHER_CTX_free(kekctx);
    }
    // `key` still holds the block only when the wrap/unwrap above failed; its release is the
    // authority's cleansing `OPENSSL_clear_free`, run by `Drop` (a no-op once ownership moved on).
    drop(key);
    // SAFETY: `kekalg` is NULL or owned.
    unsafe { X509_ALGOR_free(kekalg) };

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::cipher::{
        EVP_CIPHER_meth_free, EVP_CIPHER_meth_new, EVP_CIPHER_meth_set_iv_length, EvpCipher,
    };
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error};
    use crate::runtime::obj::NID_aes_128_cbc;

    /// A `METH` cipher with the given type, block size, key length and IV length.
    ///
    /// `EVP_CIPHER_meth_new` is the public path by which both lengths reach the authority
    /// unchecked: the initialiser stores whatever `iv_len`/`key_len` the caller passes, and the
    /// legacy init path uses the method in place of a provider cipher.
    ///
    /// # Safety
    /// The answer is a fresh method this caller owns and must release with
    /// `EVP_CIPHER_meth_free`.
    unsafe fn meth_cipher(
        nid: c_int,
        block_size: c_int,
        key_len: c_int,
        iv_len: c_int,
    ) -> *mut EvpCipher {
        // SAFETY: no preconditions; the constructor allocates and writes its fields.
        let cipher = unsafe { EVP_CIPHER_meth_new(nid, block_size, key_len) };
        assert!(!cipher.is_null(), "the method allocation succeeds");
        if iv_len != 0 {
            assert_eq!(
                // SAFETY: `cipher` is this caller's live method.
                unsafe { EVP_CIPHER_meth_set_iv_length(cipher, iv_len) },
                1,
                "a fresh method has no IV length yet"
            );
        }
        cipher
    }

    /// Obligation 1: `CMS_add0_recipient_password` holds the authority's fixed
    /// `[u8; EVP_MAX_IV_LENGTH]`, while the IV length comes from the selected cipher. A longer IV
    /// is refused before `RAND_bytes_ex` can write past the buffer, with an error raised.
    #[test]
    fn cms_pwri_oversized_iv_is_refused() {
        let _g = crate::test_support::lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        let oversized = (EVP_MAX_IV_LENGTH + 16) as c_int;
        // SAFETY: every object is this test's own and each call's preconditions hold by
        // construction; the method outlives the CMS structure, which does not own it.
        unsafe {
            let kekciph = meth_cipher(NID_aes_128_cbc, 16, 16, oversized);
            let cms =
                crate::cms::cms_env::CMS_EnvelopedData_create(crate::evp::e_aes::EVP_aes_128_cbc());
            assert!(!cms.is_null(), "the EnvelopedData allocation succeeds");
            let mut pass = *b"password";

            let ri = CMS_add0_recipient_password(
                cms,
                1,
                0,
                0,
                pass.as_mut_ptr(),
                pass.len() as isize,
                kekciph.cast(),
            );
            assert!(
                ri.is_null(),
                "an IV of {oversized} bytes must not be written into {} bytes",
                EVP_MAX_IV_LENGTH
            );
            assert_ne!(ERR_peek_error(), 0, "the refusal raises an error");
            assert_eq!(
                ERR_peek_error() & 0x7f_ffff,
                (ERR_R_PASSED_INVALID_ARGUMENT as c_ulong) & 0x7f_ffff,
                "the refusal raises ERR_R_PASSED_INVALID_ARGUMENT"
            );
            assert!(
                test_hooks::pre_fix_iv_overflow_fired(),
                "the canary records the pre-fix out-of-bounds write condition"
            );

            crate::cms::cms_lib::CMS_ContentInfo_free(cms);
            EVP_CIPHER_meth_free(kekciph);
        }
        ERR_clear_error();
    }

    /// Obligation 2: `kek_wrap_key` reads `in[0]`, `in[1]` and `in[2]` as the RFC 3211 header.
    /// The round-up does not imply three readable bytes: with a four-byte block and `inlen == 2`,
    /// `olen == 8 == 2 * blocklen`, so the pre-fix body reaches the header. The refusal must come
    /// before any read -- the `NULL` input below would fault on the first `*input`.
    #[test]
    fn cms_pwri_short_wrap_input_is_refused_before_any_read() {
        let _g = crate::test_support::lock_global_state();
        test_hooks::reset();

        // SAFETY: the method and context are this test's own; `cms_ctx` is never touched because
        // the refusal precedes every use, and `input` is deliberately NULL to detect a read.
        unsafe {
            let cipher = meth_cipher(NID_aes_128_cbc, 4, 16, 0);
            let ctx = EVP_CIPHER_CTX_new();
            assert!(!ctx.is_null(), "the context allocation succeeds");
            assert!(
                EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null()) > 0,
                "the legacy method initialises"
            );

            let mut out = [0xA5u8; 8];
            let mut outlen = 0usize;
            let rc = kek_wrap_key(
                out.as_mut_ptr(),
                &mut outlen,
                ptr::null(),
                2,
                ctx,
                ptr::null(),
            );
            assert_eq!(rc, 0, "a two-byte input is refused");
            assert_eq!(out, [0xA5u8; 8], "the refusal writes nothing to `out`");
            assert_eq!(outlen, 0, "the refusal reports no length");
            assert!(
                test_hooks::pre_fix_short_wrap_fired(),
                "the canary records the pre-fix header-read condition"
            );

            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_meth_free(cipher);
        }
    }

    /// Obligation 2, negative control (§16): the canary fires on the pre-fix condition -- a
    /// two-byte input with a four-byte block reaches the authority's header -- and stays quiet
    /// when the input is long enough for the guard.
    #[test]
    fn cms_pwri_pre_fix_short_wrap_negative_control() {
        let _g = crate::test_support::lock_global_state();
        test_hooks::reset();

        println!(
            "cms_pwri canary: pre-fix kek_wrap_key would read in[0..3] for inlen = 2 with a 4-byte block (olen = 8 >= 2 * blocklen)"
        );

        // SAFETY: each method/context pair is this test's own and released before the next is
        // made. `cms_ctx` is NULL only where the path under test cannot reach it.
        unsafe {
            let cipher = meth_cipher(NID_aes_128_cbc, 4, 16, 0);
            let ctx = EVP_CIPHER_CTX_new();
            assert!(!ctx.is_null());
            assert!(EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null()) > 0);
            let mut out = [0u8; 8];
            let mut outlen = 0usize;
            assert_eq!(
                kek_wrap_key(
                    out.as_mut_ptr(),
                    &mut outlen,
                    ptr::null(),
                    2,
                    ctx,
                    ptr::null()
                ),
                0
            );
            assert!(
                test_hooks::pre_fix_short_wrap_fired(),
                "the canary fires on the pre-fix condition"
            );
            println!("cms_pwri canary: fired = true (short-input refusal reached)");
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_meth_free(cipher);

            // Selectivity: four bytes is enough for the header, so the guard must not fire.
            test_hooks::reset();
            let cipher = meth_cipher(NID_aes_128_cbc, 4, 16, 0);
            let ctx = EVP_CIPHER_CTX_new();
            assert!(!ctx.is_null());
            assert!(EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null()) > 0);
            let input = [0x11u8, 0x22, 0x33, 0x44];
            let mut out = [0u8; 8];
            let mut outlen = 0usize;
            let _ = kek_wrap_key(
                out.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
                ctx,
                ptr::null(),
            );
            assert!(
                !test_hooks::pre_fix_short_wrap_fired(),
                "an input of three or more bytes must not trip the canary"
            );
            println!("cms_pwri canary: fired = false for a four-byte input");
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_meth_free(cipher);
        }
    }
}
