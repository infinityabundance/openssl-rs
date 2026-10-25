//! `crypto/cms/cms_enc.c` — the `CMS EncryptedData` content and its session-key setup.
//! Phase 12.3b.
//!
//! [`CMS_EncryptedData_set1_key`], [`ossl_cms_EncryptedContent_init`] and the BIO arm
//! [`ossl_cms_EncryptedContent_init_bio`] land here; the last is what `cms_env.rs` and
//! `cms_lib.rs`'s `CMS_dataInit` reach for the content cipher.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::layout::V_ASN1_UNDEF;
use crate::evp::bio_enc::BIO_f_cipher;
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_flags,
    EVP_CIPHER_get_type, EvpCipher,
};
use crate::evp::cipher_ctx::{
    evp_cipher_asn1_to_param_ex, evp_cipher_param_to_asn1_ex, EVP_CIPHER_CTX_ctrl,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_tag_length, EVP_CIPHER_CTX_rand_key, EVP_CIPHER_CTX_set_key_length,
    EVP_CipherInit_ex, EvpCipherAeadAsn1Params, EvpCipherCtx,
};
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_GET_CIPHER_CTX};
use crate::runtime::err::{ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};

use crate::runtime::obj::{
    NID_pkcs7_data, NID_pkcs7_encrypted, NID_undef, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::owned_buf::OwnedBuf;

use super::cms_asn1::*;
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, ossl_cms_get0_cmsctx, raise_cms,
    ERR_R_ASN1_LIB, ERR_R_EVP_LIB,
};
use crate::runtime::mem_coords::SeamFile;

/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:531`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x20_0000;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `EVP_CTRL_AEAD_SET_TAG` — `include/openssl/evp.h`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `ERR_R_BIO_LIB` — `include/openssl/err.h`.
const ERR_R_BIO_LIB: c_int = 524290;

/// The smallest tag length the decode side accepts: the authority's `ec->taglen < 4`
/// (`cms_enc.c:113`).
const MIN_AEAD_TAG_LEN: usize = 4;

/// Whether `ivlen` fits the authority's `iv[EVP_MAX_IV_LENGTH]`: the stack buffer
/// `ossl_cms_EncryptedContent_init_bio` fills with `RAND_bytes_ex` and copies from.
#[inline]
fn iv_length_fits_authority_buffer(ivlen: c_int) -> bool {
    (0..=EVP_MAX_IV_LENGTH as c_int).contains(&ivlen)
}

/// Why [`AeadParams`] could not establish a valid parameter set.
#[derive(Debug, PartialEq, Eq)]
enum AeadRefusal {
    /// The IV length is negative or does not fit the authority's fixed
    /// `EVP_MAX_IV_LENGTH` buffer.
    IvLength,
    /// The random IV the encode direction needs could not be generated.
    Random,
    /// The tag length is not one the AEAD path may consume.
    TagLength,
}

/// The validated AEAD parameters of one `ossl_cms_EncryptedContent_init_bio` call.
///
/// The authority keeps the IV array, the IV length and the tag length as three loosely
/// coupled locals (`iv`/`aparams.iv`, `ivlen`/`iv_len`, `tag_len`), and the checks that keep
/// them inside the authority's fixed buffer are spread over both directions. This type is the
/// one place they meet, and construction is the only way to obtain one:
///
/// * [`AeadParams::new_for_encryption`] establishes the IV bound **before** `RAND_bytes_ex`
///   writes a byte;
/// * [`AeadParams::decode`] establishes the parsed IV extent, the provider-advertised IV
///   extent and the tag extent **before** either is copied or handed to a provider;
/// * [`AeadParams::set_tag_len`] establishes the encode-side tag bound **before** the ASN.1
///   encoder reads it.
///
/// The fields are private, so the only exits are [`AeadParams::piv`] (after the IV bound) and
/// [`AeadParams::bridge`] (after both bounds). A provider that advertises a negative UTF-8
/// tag length is refused here; the authority casts it to `unsigned int` and encodes it.
struct AeadParams {
    /// The initialisation vector, at most [`EVP_MAX_IV_LENGTH`] bytes.
    iv: [c_uchar; EVP_MAX_IV_LENGTH],
    /// `0..=EVP_MAX_IV_LENGTH`; the bytes of `iv` that are initialised and that a provider
    /// will be told about.
    iv_len: c_int,
    /// The tag length, validated for the direction that set it.
    tag_len: c_int,
}

impl AeadParams {
    /// Encode direction: establish `iv_len` first, then fill exactly that many bytes.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    unsafe fn new_for_encryption(libctx: *mut c_void, iv_len: c_int) -> Result<Self, AeadRefusal> {
        if !iv_length_fits_authority_buffer(iv_len) {
            return Err(AeadRefusal::IvLength);
        }
        let mut iv = [0u8; EVP_MAX_IV_LENGTH];
        if iv_len > 0 {
            // SAFETY: `iv` has `iv_len` writable bytes and `iv_len` is bounded by the guard
            // above.
            if unsafe { RAND_bytes_ex(libctx, iv.as_mut_ptr(), iv_len as usize, 0) } <= 0 {
                return Err(AeadRefusal::Random);
            }
        }
        Ok(Self {
            iv,
            iv_len,
            tag_len: 0,
        })
    }

    /// Decode direction: establish every extent before the value is used.
    fn decode(
        raw: &EvpCipherAeadAsn1Params,
        cipher_iv_len: c_int,
        tag_len: usize,
    ) -> Result<Self, AeadRefusal> {
        // The parsed length is checked against the destination first, then the length the
        // provider will read, then the tag -- the authority's own order.
        if raw.iv_len as usize > raw.iv.len()
            || !iv_length_fits_authority_buffer(raw.iv_len as c_int)
        {
            return Err(AeadRefusal::IvLength);
        }
        if !iv_length_fits_authority_buffer(cipher_iv_len) {
            return Err(AeadRefusal::IvLength);
        }
        if !(MIN_AEAD_TAG_LEN..=EVP_MAX_IV_LENGTH).contains(&tag_len) {
            return Err(AeadRefusal::TagLength);
        }
        Ok(Self {
            iv: raw.iv,
            iv_len: raw.iv_len as c_int,
            tag_len: tag_len as c_int,
        })
    }

    /// Record the tag length the provider reports for encoding.
    fn set_tag_len(&mut self, tag_len: c_int) -> Result<(), AeadRefusal> {
        if tag_len <= 0 {
            return Err(AeadRefusal::TagLength);
        }
        self.tag_len = tag_len;
        Ok(())
    }

    /// The IV pointer handed to `EVP_CipherInit_ex`: NULL when there is no IV, exactly as the
    /// authority leaves `piv`.
    fn piv(&mut self) -> *mut c_uchar {
        if self.iv_len > 0 {
            self.iv.as_mut_ptr()
        } else {
            ptr::null_mut()
        }
    }

    /// The validated tag length.
    fn tag_len(&self) -> c_int {
        self.tag_len
    }

    /// The bridge struct the ASN.1 encoder reads. Reachable only after a constructor (or
    /// [`AeadParams::set_tag_len`]) validated both lengths.
    fn bridge(&self) -> EvpCipherAeadAsn1Params {
        EvpCipherAeadAsn1Params {
            tag_len: self.tag_len as c_uint,
            iv: self.iv,
            iv_len: self.iv_len as c_uint,
        }
    }
}

/// The cipher this call fetched, released exactly once when the call leaves on every path --
/// the authority's single `EVP_CIPHER_free(fetched_ciph)` at `cms_enc.c:199`.
struct FetchedCipher(*mut EvpCipher);

impl FetchedCipher {
    /// No cipher fetched yet.
    const NONE: Self = Self(ptr::null_mut());

    fn set(&mut self, cipher: *mut EvpCipher) {
        self.0 = cipher;
    }
}

impl Drop for FetchedCipher {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        #[cfg(test)]
        test_hooks::note_cipher_release(self.0 as usize);
        // SAFETY: the field is the cipher this call fetched and has not released.
        unsafe { EVP_CIPHER_free(self.0) };
    }
}

/// The cipher BIO this call created, released exactly once unless ownership moves to the
/// caller -- the authority's `BIO_free(b)` at `cms_enc.c:207`.
struct CipherBio(*mut Bio);

impl CipherBio {
    fn new(bio: *mut Bio) -> Self {
        Self(bio)
    }

    fn as_ptr(&self) -> *mut Bio {
        self.0
    }

    /// Transfer the BIO to the caller; `Drop` no longer releases it.
    fn into_raw(self) -> *mut Bio {
        let bio = self.0;
        core::mem::forget(self);
        bio
    }
}

impl Drop for CipherBio {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        #[cfg(test)]
        test_hooks::note_bio_release(self.0 as usize);
        // SAFETY: the field is the BIO this call created and has neither transferred nor
        // released.
        unsafe { BIO_free(self.0) };
    }
}

/// Test-only witnesses for the ownership and boundary claims (AGENTS.md §16).
#[cfg(test)]
mod test_hooks {
    use core::cell::{Cell, RefCell};

    thread_local! {
        static BIO_ALLOC: Cell<usize> = const { Cell::new(0) };
        static BIO_RELEASES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static CIPHER_RELEASES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static PRE_FIX_IV_OVERFLOW: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn note_bio_alloc(addr: usize) {
        BIO_ALLOC.with(|c| c.set(addr));
    }

    pub(super) fn bio_alloc() -> usize {
        BIO_ALLOC.with(Cell::get)
    }

    pub(super) fn note_bio_release(addr: usize) {
        BIO_RELEASES.with(|c| c.borrow_mut().push(addr));
    }

    pub(super) fn bio_releases() -> Vec<usize> {
        BIO_RELEASES.with(|c| c.borrow().clone())
    }

    pub(super) fn note_cipher_release(addr: usize) {
        CIPHER_RELEASES.with(|c| c.borrow_mut().push(addr));
    }

    pub(super) fn cipher_releases() -> Vec<usize> {
        CIPHER_RELEASES.with(|c| c.borrow().clone())
    }

    /// Record that the refusal was reached with an IV length that the authority would have
    /// written or read past its sixteen-byte buffer.
    pub(super) fn note_pre_fix_iv_overflow() {
        PRE_FIX_IV_OVERFLOW.with(|c| c.set(true));
    }

    pub(super) fn pre_fix_iv_overflow_fired() -> bool {
        PRE_FIX_IV_OVERFLOW.with(Cell::get)
    }

    pub(super) fn reset() {
        BIO_ALLOC.with(|c| c.set(0));
        BIO_RELEASES.with(|c| c.borrow_mut().clear());
        CIPHER_RELEASES.with(|c| c.borrow_mut().clear());
        PRE_FIX_IV_OVERFLOW.with(|c| c.set(false));
    }
}

/// `BIO_get_cipher_ctx(BIO *, EVP_CIPHER_CTX **)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx)`.
///
/// # Safety
/// `b` is a live cipher BIO; `pctx` is writable.
unsafe fn bio_get_cipher_ctx(b: *mut Bio, pctx: *mut *mut EvpCipherCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx.cast()) as c_int }
}

/// `BIO *ossl_cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec,`
/// `const CMS_CTX *cms_ctx, int auth)` — `cms_enc.c:25-209`.
///
/// # Safety
/// `ec` is live; `cms_ctx` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EncryptedContent_init_bio(
    ec: *mut CmsEncryptedContentInfo,
    cms_ctx: *const CmsCtx,
    auth: c_int,
) -> *mut Bio {
    let mut fetched = FetchedCipher::NONE;
    let mut cipher: *const EvpCipher = ptr::null();
    let mut aead: Option<AeadParams> = None;
    let mut piv: *mut c_uchar = ptr::null_mut();
    let mut tkey: Option<OwnedBuf> = None;
    let mut len = 0;
    let mut tkeylen = 0usize;
    let mut ok = 0;
    let mut keep_key = 0;

    // SAFETY: `ec` is live.
    let calg = unsafe { (*ec).content_encryption_algorithm };
    // SAFETY: `cms_ctx` is live.
    let libctx = unsafe { ossl_cms_ctx_get0_libctx(cms_ctx) };
    // SAFETY: `cms_ctx` is live.
    let propq = unsafe { ossl_cms_ctx_get0_propq(cms_ctx) };

    // SAFETY: `ec` is live.
    let enc = c_int::from(!unsafe { (*ec).cipher }.is_null());

    // SAFETY: the allocator answers a fresh cipher BIO.
    let b = CipherBio::new(unsafe { BIO_new(BIO_f_cipher()) });
    #[cfg(test)]
    test_hooks::note_bio_alloc(b.as_ptr() as usize);
    if b.as_ptr().is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(48, c"ossl_cms_EncryptedContent_init_bio", ERR_R_BIO_LIB) };
        return ptr::null_mut();
    }

    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    // SAFETY: `b` is live; `ctx` is this frame's slot.
    unsafe { bio_get_cipher_ctx(b.as_ptr(), &mut ctx) };

    // SAFETY: the site is a compile-time constant.
    ERR_set_mark();
    if enc != 0 {
        // SAFETY: `ec` is live.
        cipher = unsafe { (*ec).cipher.cast() };
        // If not keeping key set cipher to NULL so subsequent calls decrypt.
        // SAFETY: `ec` is live.
        if !unsafe { (*ec).key }.is_null() {
            // SAFETY: `ec` is live.
            unsafe { (*ec).cipher = ptr::null() };
        }
    } else {
        // SAFETY: `calg` is live.
        let aoid = unsafe { (*calg).algorithm };
        // SAFETY: `aoid` is live; the lookup is the macro expansion.
        cipher = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(aoid))) };
    }
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        let fetched_ciph = unsafe { EVP_CIPHER_fetch(libctx, EVP_CIPHER_get0_name(cipher), propq) };
        if !fetched_ciph.is_null() {
            fetched.set(fetched_ciph);
            cipher = fetched_ciph;
        }
    }
    if cipher.is_null() {
        // SAFETY: as above.
        ERR_clear_last_mark();
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                73,
                c"ossl_cms_EncryptedContent_init_bio",
                crate::runtime::err::err_reasons::CMS_R_UNKNOWN_CIPHER,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the queue was marked above.
    ERR_pop_to_mark();

    // SAFETY: `ctx`/`cipher` are live.
    if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), enc) }
        <= 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                79,
                c"ossl_cms_EncryptedContent_init_bio",
                crate::runtime::err::err_reasons::CMS_R_CIPHER_INITIALISATION_ERROR,
            )
        };
        return ptr::null_mut();
    }

    if enc != 0 {
        // SAFETY: `ctx` is live.
        let et = unsafe { EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(ctx)) };
        // SAFETY: `calg` is live.
        unsafe { (*calg).algorithm = OBJ_nid2obj(et) };
        // SAFETY: `calg` is live.
        if unsafe { (*calg).algorithm }.is_null()
            // SAFETY: `calg` is live.
            || unsafe { (*(*calg).algorithm).nid } == NID_undef
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    86,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                )
            };
            return ptr::null_mut();
        }
        // Generate a random IV if we need one. `new_for_encryption` establishes the IV bound
        // before `RAND_bytes_ex` writes, so a provider that advertises more than
        // `EVP_MAX_IV_LENGTH` cannot overrun the type's fixed buffer.
        // SAFETY: `ctx` is live.
        let ivlen = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if ivlen < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(92, c"ossl_cms_EncryptedContent_init_bio", ERR_R_EVP_LIB) };
            return ptr::null_mut();
        }
        // SAFETY: `libctx` is NULL or live per this function's contract, and the constructor
        // establishes the IV bound before writing.
        let params = match unsafe { AeadParams::new_for_encryption(libctx, ivlen) } {
            Ok(params) => params,
            Err(AeadRefusal::Random) => return ptr::null_mut(),
            Err(_) => {
                // The authority fills `unsigned char iv[EVP_MAX_IV_LENGTH]` with `ivlen`
                // bytes (`cms_enc.c:96-98`) and later `memcpy`s `ivlen` bytes into
                // `aparams.iv` (`:179`). A provider may advertise an `ivlen` larger than
                // `EVP_MAX_IV_LENGTH`; the authority then overruns its stack buffer, which
                // §17 forbids reproducing. Refuse at the authority's own IV-length refusal
                // coordinate and reason.
                #[cfg(test)]
                test_hooks::note_pre_fix_iv_overflow();
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(92, c"ossl_cms_EncryptedContent_init_bio", ERR_R_EVP_LIB) };
                return ptr::null_mut();
            }
        };
        aead = Some(params);
        // SAFETY: `aead` holds the IV for the rest of the call and is not moved again.
        piv = aead.as_mut().map_or(ptr::null_mut(), AeadParams::piv);
    } else {
        // The parser writes the decoded IV into this bounded staging area; both extents are
        // validated into an `AeadParams` below before anything is copied or handed on.
        let mut raw = EvpCipherAeadAsn1Params {
            tag_len: 0,
            iv: [0u8; EVP_MAX_IV_LENGTH],
            iv_len: 0,
        };
        // SAFETY: `ctx`/`calg` are live; `raw` is this frame's staging area.
        if unsafe { evp_cipher_asn1_to_param_ex(ctx, (*calg).parameter, &mut raw) } <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    103,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                )
            };
            return ptr::null_mut();
        }
        // SAFETY: `cipher` is live.
        if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
            if auth == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        108,
                        c"ossl_cms_EncryptedContent_init_bio",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_IN_ENVELOPED_DATA,
                    )
                };
                return ptr::null_mut();
            }

            // The IV the parameter set carried was parsed into the staging buffer, and that
            // buffer is what `EVP_CipherInit_ex` below hands to the provider. `decode` bounds
            // both the parsed length and the cipher's advertised IV length by the fixed
            // destination, and the tag by what the AEAD control may consume, before either is
            // read. This is CVE-2025-15467's mechanism made inexpressible at the boundary
            // rather than trusted from the parser (§17).
            // SAFETY: `ctx`/`ec` are live.
            let (cipher_ivlen, requested_tag_len) =
                unsafe { (EVP_CIPHER_CTX_get_iv_length(ctx), (*ec).taglen) };
            let params = match AeadParams::decode(&raw, cipher_ivlen, requested_tag_len) {
                Ok(params) => params,
                Err(AeadRefusal::TagLength) => {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            115,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_SET_TAG_ERROR,
                        )
                    };
                    return ptr::null_mut();
                }
                Err(_) => {
                    #[cfg(test)]
                    test_hooks::note_pre_fix_iv_overflow();
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            103,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                        )
                    };
                    return ptr::null_mut();
                }
            };
            // SAFETY: `ctx` is live; `ec->tag` is readable for the validated tag length.
            if unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx,
                    EVP_CTRL_AEAD_SET_TAG,
                    params.tag_len(),
                    (*ec).tag.cast(),
                )
            } <= 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        115,
                        c"ossl_cms_EncryptedContent_init_bio",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_SET_TAG_ERROR,
                    )
                };
                return ptr::null_mut();
            }
            aead = Some(params);
            // SAFETY: `aead` holds the IV for the rest of the call and is not moved again.
            piv = aead.as_mut().map_or(ptr::null_mut(), AeadParams::piv);
        } else if auth != 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    119,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                )
            };
            return ptr::null_mut();
        }
    }
    // SAFETY: `ctx` is live.
    len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if len <= 0 {
        return ptr::null_mut();
    }
    tkeylen = len as usize;

    'body: {
        // Generate random session key.
        // SAFETY: `ec` is live.
        if enc == 0 || unsafe { (*ec).key }.is_null() {
            // The session key is this frame's scratch, allocated through the crate's allocator seam
            // at the authority's own size/`file`/`line`; its release is the authority's cleansing
            // `OPENSSL_clear_free`, run by `Drop` unless ownership moves into `ec->key`.
            // SAFETY: `tkeylen > 0`.
            let Some(key) = OwnedBuf::new_cleansed_released(
                tkeylen,
                SeamFile::new(c"cms_enc.c"),
                130,
                SeamFile::NULL,
                0,
            ) else {
                break 'body;
            };
            // SAFETY: `ctx` is live; `key` is `tkeylen` writable bytes.
            let rand_ok = unsafe { EVP_CIPHER_CTX_rand_key(ctx, key.as_ptr()) };
            tkey = Some(key);
            if rand_ok <= 0 {
                break 'body;
            }
        }

        // SAFETY: `ec` is live.
        if unsafe { (*ec).key }.is_null() {
            // SAFETY: `ec` is live; ownership of the block moves into `ec->key`.
            unsafe {
                (*ec).key = tkey.take().map_or(ptr::null_mut(), OwnedBuf::into_raw);
                (*ec).keylen = tkeylen;
            }
            if enc != 0 {
                keep_key = 1;
            } else {
                // SAFETY: the queue is this thread's.
                ERR_clear_error();
            }
        }

        // SAFETY: `ec` is live.
        if unsafe { (*ec).keylen } != tkeylen {
            // If necessary set key length.
            // SAFETY: `ctx` is live.
            let klen = unsafe { (*ec).keylen };
            // SAFETY: the context and cipher are live.
            if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, klen as c_int) } <= 0 {
                // SAFETY: `ec` is live.
                if enc != 0 || unsafe { (*ec).debug } != 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            155,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
                        )
                    };
                    break 'body;
                } else {
                    // Use random key.
                    // SAFETY: `ec` is live; the old key is `ec`'s own and the block moves into
                    // `ec->key`.
                    unsafe {
                        super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
                        (*ec).key = tkey.take().map_or(ptr::null_mut(), OwnedBuf::into_raw);
                        (*ec).keylen = tkeylen;
                    }
                    // SAFETY: the queue is this thread's.
                    ERR_clear_error();
                }
            }
        }

        // SAFETY: `ctx` is live; `piv` is NULL or readable.
        if unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), (*ec).key, piv, enc) } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    169,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_CIPHER_INITIALISATION_ERROR,
                )
            };
            break 'body;
        }
        if enc != 0 {
            // SAFETY: `calg` is live.
            unsafe { (*calg).parameter = ASN1_TYPE_new() };
            // SAFETY: `calg` is live.
            if unsafe { (*calg).parameter }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(175, c"ossl_cms_EncryptedContent_init_bio", ERR_R_ASN1_LIB) };
                break 'body;
            }
            // SAFETY: `cipher` is live.
            if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
                // SAFETY: `ctx` is live.
                let tag_len = unsafe { EVP_CIPHER_CTX_get_tag_length(ctx) };
                let Some(params) = aead.as_mut() else {
                    break 'body;
                };
                // The encode direction only has a positive tag to record; `set_tag_len`
                // refuses zero (the authority's `aparams.tag_len <= 0`) before the encoder
                // reads it.
                if params.set_tag_len(tag_len).is_err() {
                    break 'body;
                }
                // SAFETY: `ctx`/`calg` are live; `params` holds the validated lengths and the
                // IV generated for this call.
                if unsafe {
                    evp_cipher_param_to_asn1_ex(ctx, (*calg).parameter, &mut params.bridge())
                } <= 0
                {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            187,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                        )
                    };
                    break 'body;
                }
            } else {
                // The non-AEAD arm reads nothing from the bridge struct; the authority still
                // passes its (uninitialised) `aparams` here. A zeroed struct is the equivalent
                // value.
                let mut unused = EvpCipherAeadAsn1Params {
                    tag_len: 0,
                    iv: [0u8; EVP_MAX_IV_LENGTH],
                    iv_len: 0,
                };
                // SAFETY: `ctx`/`calg` are live.
                if unsafe { evp_cipher_param_to_asn1_ex(ctx, (*calg).parameter, &mut unused) } <= 0
                {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            187,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                        )
                    };
                    break 'body;
                }
            }
            // If parameter type not set omit parameter.
            // SAFETY: `calg` is live.
            if unsafe { (*(*calg).parameter).type_ } == V_ASN1_UNDEF {
                // SAFETY: the parameter is owned here.
                unsafe { ASN1_TYPE_free((*calg).parameter) };
                // SAFETY: `calg` is live.
                unsafe { (*calg).parameter = ptr::null_mut() };
            }
        }
        ok = 1;
    }

    if keep_key == 0 || ok == 0 {
        // SAFETY: `ec` is live; the key is `ec`'s own and may be NULL.
        unsafe {
            super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
            (*ec).key = ptr::null_mut();
        }
    }
    if ok != 0 {
        return b.into_raw();
    }
    // `fetched`, `b` and `tkey` release themselves on the way out.
    ptr::null_mut()
}

/// `int ossl_cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec, const EVP_CIPHER *cipher,`
/// `const unsigned char *key, size_t keylen, const CMS_CTX *cms_ctx)` — `cms_enc.c:211-226`.
///
/// # Safety
/// `ec` is live; `cipher` NULL or live; `key` NULL or readable for `keylen`.
pub(crate) unsafe fn ossl_cms_EncryptedContent_init(
    ec: *mut CmsEncryptedContentInfo,
    cipher: *const EvpCipher,
    key: *const u8,
    keylen: usize,
    _cms_ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).cipher = cipher.cast();
    }
    if !key.is_null() {
        // The session key is this frame's scratch, allocated through the crate's allocator seam at
        // the authority's own size/`file`/`line`; ownership of the block moves into `ec->key`.
        // SAFETY: `key` is non-NULL and readable for `keylen`.
        let Some(owned) = OwnedBuf::new(keylen, SeamFile::new(c"cms_enc.c"), 218) else {
            return 0;
        };
        // SAFETY: `key` is readable for `keylen`; `owned` is `keylen` writable bytes.
        unsafe { ptr::copy_nonoverlapping(key, owned.as_ptr(), keylen) };
        // SAFETY: `ec` is live; ownership of the block moves into `ec->key`.
        unsafe { (*ec).key = owned.into_raw() };
    }
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).keylen = keylen;
        if !cipher.is_null() {
            (*ec).content_type = OBJ_nid2obj(NID_pkcs7_data);
        }
    }
    1
}

/// `int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,`
/// `const unsigned char *key, size_t keylen)` — `cms_enc.c:228-260`.
///
/// # Safety
/// `cms` is live; `ciph` NULL or live; `key` readable for `keylen`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EncryptedData_set1_key(
    cms: *mut CmsContentInfo,
    ciph: *const EvpCipher,
    key: *const u8,
    keylen: usize,
) -> c_int {
    if key.is_null() || keylen == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                234,
                c"CMS_EncryptedData_set1_key",
                crate::runtime::err::err_reasons::CMS_R_NO_KEY,
            )
        };
        return 0;
    }
    // SAFETY: `cms` is live; `ciph` is NULL or live.
    unsafe {
        if !ciph.is_null() {
            if EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
                raise_cms(
                    239,
                    c"CMS_EncryptedData_set1_key",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                );
                return 0;
            }
            let ed = (*cms).d.cast::<CmsEncryptedData>();
            if !ed.is_null() {
                m_asn1_free(ed.cast(), cms_encrypteddata_it());
                (*cms).d = ptr::null_mut();
            }
            let ed = m_asn1_new(cms_encrypteddata_it()).cast::<CmsEncryptedData>();
            if ed.is_null() {
                raise_cms(248, c"CMS_EncryptedData_set1_key", ERR_R_ASN1_LIB);
                return 0;
            }
            (*cms).d = ed.cast();
            (*cms).content_type = OBJ_nid2obj(NID_pkcs7_encrypted);
            (*ed).version = 0;
        } else if OBJ_obj2nid((*cms).content_type) != NID_pkcs7_encrypted {
            raise_cms(
                254,
                c"CMS_EncryptedData_set1_key",
                crate::runtime::err::err_reasons::CMS_R_NOT_ENCRYPTED_DATA,
            );
            return 0;
        }
        let ed = (*cms).d.cast::<CmsEncryptedData>();
        let ec = (*ed).encrypted_content_info;
        ossl_cms_EncryptedContent_init(ec, ciph, key, keylen, ossl_cms_get0_cmsctx(cms))
    }
}

/// `BIO *ossl_cms_EncryptedData_init_bio(const CMS_ContentInfo *cms)` — `cms_enc.c:262-269`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EncryptedData_init_bio(
    cms: *const CmsContentInfo,
) -> *mut Bio {
    // SAFETY: `cms` is live.
    let enc = unsafe { (*cms).d.cast::<CmsEncryptedData>() };
    // SAFETY: `enc` is live.
    if !unsafe { (*(*enc).encrypted_content_info).cipher }.is_null()
        // SAFETY: `enc` is live.
        && !unsafe { (*enc).unprotected_attrs }.is_null()
    {
        // SAFETY: `enc` is live.
        unsafe { (*enc).version = 2 };
    }
    // SAFETY: `cms` is live.
    unsafe {
        ossl_cms_EncryptedContent_init_bio(
            (*enc).encrypted_content_info,
            ossl_cms_get0_cmsctx(cms),
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::a_type::ASN1_TYPE_new;
    use crate::asn1::evp_asn1::{ossl_asn1_type_set_octetstring_int, ASN1_TYPE_get_octetstring};
    use crate::cms::cms_asn1::{cms_encryptedcontentinfo_it, m_asn1_free, m_asn1_new};
    use crate::evp::cipher::{
        EVP_CIPHER_meth_free, EVP_CIPHER_meth_new, EVP_CIPHER_meth_set_ctrl,
        EVP_CIPHER_meth_set_flags, EVP_CIPHER_meth_set_init, EVP_CIPHER_meth_set_iv_length,
        EvpCipher, OBJ_NAME_TYPE_CIPHER_METH,
    };
    use crate::evp::legacy_evp::EVP_add_cipher;
    use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_size_t, OsslParam};
    use crate::provider::OsslProvider;
    use crate::runtime::err::{ERR_clear_error, ERR_peek_last_error};
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::runtime::obj::{
        NID_aes_128_cbc, NID_sha256, OBJ_NAME_remove, OBJ_nid2ln, OBJ_nid2sn,
    };
    use crate::test_support::lock_global_state;
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar, c_ulong, c_void};

    /// `EVP_CIPH_CUSTOM_IV` — `include/openssl/evp.h`.
    const CUSTOM_IV: c_ulong = 0x10;
    /// `EVP_CIPH_GCM_MODE` — `include/openssl/evp.h`.
    const GCM_MODE: c_ulong = 0x6;

    thread_local! {
        static REPORTED_TAG_LEN: Cell<c_int> = const { Cell::new(0) };
        static TAG_LEN_REPORTS: Cell<u32> = const { Cell::new(0) };
    }

    /// `init` callback for the hand-built methods below: the key is accepted, nothing is
    /// decrypted or encrypted by these tests.
    ///
    /// # Safety
    /// None on the arguments: the callback ignores `ctx`, `key` and `iv` without dereferencing
    /// or retaining them, so the dispatch may pass any values. It is installed only through
    /// [`EVP_CIPHER_meth_set_init`], whose parameter type fixes this ABI signature.
    unsafe extern "C" fn noop_init(
        _ctx: *mut c_void,
        _key: *const c_uchar,
        _iv: *const c_uchar,
        _enc: c_int,
    ) -> c_int {
        1
    }

    /// `ctrl` callback for the hand-built methods below: accepts every command.
    ///
    /// # Safety
    /// None on the arguments: the callback ignores `ctx`, `type`, `arg` and `ptr` without
    /// dereferencing or retaining them, so the dispatch may pass any values. It is installed
    /// only through [`EVP_CIPHER_meth_set_ctrl`], whose parameter type fixes this ABI signature.
    unsafe extern "C" fn noop_ctrl(
        _ctx: *mut c_void,
        _type: c_int,
        _arg: c_int,
        _ptr: *mut c_void,
    ) -> c_int {
        1
    }

    /// A provider-style `get_ctx_params` that reports [`REPORTED_TAG_LEN`] for `taglen` and
    /// leaves every other parameter unmodified.
    ///
    /// # Safety
    /// `params` must be NULL or a `key`-terminated array of live [`OsslParam`], as the provider
    /// dispatch (`evp_do_ciph_ctx_getparams`) establishes, and any located entry must be
    /// writable per [`OSSL_PARAM_set_size_t`]. `algctx` is ignored and never dereferenced.
    unsafe extern "C" fn report_tag_len(_algctx: *mut c_void, params: *mut OsslParam) -> c_int {
        // SAFETY: the dispatch contract gives a key-terminated parameter array.
        unsafe {
            let p = OSSL_PARAM_locate(params, c"taglen".as_ptr());
            if p.is_null() {
                return 1;
            }
            let tag_len = REPORTED_TAG_LEN.with(Cell::get);
            TAG_LEN_REPORTS.with(|c| c.set(c.get() + 1));
            if OSSL_PARAM_set_size_t(p, tag_len as usize) == 0 {
                return 0;
            }
        }
        1
    }

    /// A live `CMS_EncryptedContentInfo` this test owns, with its item-allocated `X509_ALGOR`.
    ///
    /// # Safety
    /// The answer is this test's own; release it with [`free_ec`].
    unsafe fn new_ec() -> *mut CmsEncryptedContentInfo {
        // SAFETY: the item answers a fresh object whose members its own free routine releases.
        let ec =
            unsafe { m_asn1_new(cms_encryptedcontentinfo_it()) }.cast::<CmsEncryptedContentInfo>();
        assert!(!ec.is_null(), "the content-info allocation succeeds");
        // SAFETY: `ec` is non-null and points at the freshly constructed item above; its
        // algorithm member is initialised by that constructor.
        let algorithm = unsafe { (*ec).content_encryption_algorithm };
        assert!(
            !algorithm.is_null(),
            "the item allocation includes the algorithm member"
        );
        ec
    }

    /// Release a value from [`new_ec`].
    ///
    /// # Safety
    /// `ec` came from [`new_ec`] and has not been released.
    unsafe fn free_ec(ec: *mut CmsEncryptedContentInfo) {
        // SAFETY: per this helper's contract.
        unsafe { m_asn1_free(ec.cast(), cms_encryptedcontentinfo_it()) };
    }

    /// A hand-built legacy method with the given flags and reported IV length.
    ///
    /// The NID is `NID_sha256`, whose short name no provider publishes **as a cipher**, so the
    /// function's internal `EVP_CIPHER_fetch` answers NULL and the method this test built is the
    /// one the call uses. For the decode path the caller registers it with [`EVP_add_cipher`].
    ///
    /// # Safety
    /// The answer is this test's own; release it with `EVP_CIPHER_meth_free`.
    unsafe fn custom_cipher(flags: c_ulong, iv_len: c_int) -> *mut EvpCipher {
        // SAFETY: no preconditions; the constructor allocates a fresh method.
        let cipher = unsafe { EVP_CIPHER_meth_new(NID_sha256, 16, 16) };
        assert!(!cipher.is_null(), "the method allocation succeeds");
        // SAFETY: `cipher` is this test's live method.
        unsafe {
            assert_eq!(EVP_CIPHER_meth_set_flags(cipher, flags), 1);
            if iv_len != 0 {
                assert_eq!(EVP_CIPHER_meth_set_iv_length(cipher, iv_len), 1);
            }
            assert_eq!(EVP_CIPHER_meth_set_init(cipher, Some(noop_init)), 1);
            assert_eq!(EVP_CIPHER_meth_set_ctrl(cipher, Some(noop_ctrl)), 1);
        }
        cipher
    }

    /// Remove a method from the legacy name table before it is released.
    ///
    /// # Safety
    /// `cipher` is a live method this test registered with [`EVP_add_cipher`].
    unsafe fn unregister(cipher: *mut EvpCipher) {
        // SAFETY: `cipher` is live; the two names are statics the object table owns.
        unsafe {
            let nid = (*cipher).nid;
            OBJ_NAME_remove(OBJ_nid2sn(nid), OBJ_NAME_TYPE_CIPHER_METH);
            OBJ_NAME_remove(OBJ_nid2ln(nid), OBJ_NAME_TYPE_CIPHER_METH);
        }
    }

    /// Obligation 1: a provider that advertises an IV longer than the authority's fixed
    /// `iv[EVP_MAX_IV_LENGTH]` is refused before `RAND_bytes_ex` can write past it.
    #[test]
    fn cms_enc_oversized_iv_is_refused_before_any_write() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        let oversized = (EVP_MAX_IV_LENGTH + 4) as c_int;
        // SAFETY: every object is this test's own and each call's preconditions hold by
        // construction.
        unsafe {
            let cipher = custom_cipher(0, oversized);
            let ec = new_ec();
            (*ec).cipher = cipher.cast();

            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
            assert!(
                b.is_null(),
                "an IV of {oversized} bytes must not be written into {EVP_MAX_IV_LENGTH}"
            );
            assert_ne!(ERR_peek_last_error(), 0, "the refusal raises an error");
            assert_eq!(
                ERR_peek_last_error() & 0x7f_ffff,
                (ERR_R_EVP_LIB as c_ulong) & 0x7f_ffff,
                "the refusal keeps the authority's ERR_R_EVP_LIB coordinate"
            );
            assert!(
                test_hooks::pre_fix_iv_overflow_fired(),
                "the canary records the pre-fix out-of-bounds write condition"
            );
            assert_eq!(
                test_hooks::bio_releases(),
                vec![test_hooks::bio_alloc()],
                "the temporary BIO is released exactly once"
            );

            free_ec(ec);
            EVP_CIPHER_meth_free(cipher);
        }
        ERR_clear_error();
    }

    /// Obligation 1 (§16 negative control): the canary fires on the pre-fix condition and stays
    /// quiet for an IV inside the buffer.
    #[test]
    fn cms_enc_pre_fix_iv_boundary_negative_control() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        let oversized = (EVP_MAX_IV_LENGTH + 4) as c_int;
        println!(
            "cms_enc canary: pre-fix would write {oversized} IV bytes into {} ",
            EVP_MAX_IV_LENGTH
        );

        // SAFETY: every object is this test's own and released before the next is made.
        unsafe {
            let cipher = custom_cipher(0, oversized);
            let ec = new_ec();
            (*ec).cipher = cipher.cast();
            assert!(ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1).is_null());
            assert!(
                test_hooks::pre_fix_iv_overflow_fired(),
                "the canary fires on the pre-fix condition"
            );
            println!("cms_enc canary: fired = true (oversized-IV refusal reached)");
            free_ec(ec);
            EVP_CIPHER_meth_free(cipher);

            // Selectivity: 13 bytes is inside the sixteen-byte buffer.
            test_hooks::reset();
            let cipher = custom_cipher(0, 13);
            let ec = new_ec();
            (*ec).cipher = cipher.cast();
            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
            assert!(!b.is_null(), "a thirteen-byte IV is accepted");
            assert!(
                !test_hooks::pre_fix_iv_overflow_fired(),
                "an IV inside the buffer must not trip the canary"
            );
            BIO_free(b);
            free_ec(ec);
            EVP_CIPHER_meth_free(cipher);
        }
        ERR_clear_error();
    }

    /// Obligation 1: a custom cipher advertising an unusual, in-bounds IV length works end to
    /// end, and the length that reaches the encoded parameter is the one it advertised.
    #[test]
    fn cms_enc_custom_cipher_with_unusual_iv_length_round_trips() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        // SAFETY: every object is this test's own.
        unsafe {
            let cipher = custom_cipher(0, 13);
            let ec = new_ec();
            (*ec).cipher = cipher.cast();

            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
            assert!(!b.is_null(), "a thirteen-byte IV fits the buffer");
            assert_eq!(
                b as usize,
                test_hooks::bio_alloc(),
                "the returned BIO is the one the call allocated"
            );
            assert!(
                test_hooks::bio_releases().is_empty(),
                "success transfers the BIO, so its owner must not release it"
            );
            assert!(
                test_hooks::cipher_releases().is_empty(),
                "no provider cipher was fetched, so none is released"
            );

            let calg = (*ec).content_encryption_algorithm;
            let mut out = [0u8; EVP_MAX_IV_LENGTH];
            // SAFETY: `calg` is live; `out` holds sixteen bytes.
            let n = ASN1_TYPE_get_octetstring(
                (*calg).parameter,
                out.as_mut_ptr(),
                EVP_MAX_IV_LENGTH as c_int,
            );
            assert_eq!(n, 13, "the advertised IV length is the encoded length");

            BIO_free(b);
            free_ec(ec);
            EVP_CIPHER_meth_free(cipher);
        }
        ERR_clear_error();
    }

    /// Obligation 1: malformed tag lengths are refused at the authority's
    /// `CMS_R_CIPHER_AEAD_SET_TAG_ERROR` coordinate, in the authority's order (IV first).
    #[test]
    fn cms_enc_malformed_tag_lengths_are_refused() {
        let _g = lock_global_state();
        ERR_clear_error();

        for taglen in [3usize, 17] {
            test_hooks::reset();
            // SAFETY: every object is this test's own and released before the next iteration.
            unsafe {
                let cipher = custom_cipher(CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER | GCM_MODE, 13);
                assert_eq!(
                    EVP_add_cipher(cipher),
                    1,
                    "the decode path resolves by name"
                );

                let ec = new_ec();
                (*ec).cipher = ptr::null();
                let calg = (*ec).content_encryption_algorithm;
                (*calg).algorithm = OBJ_nid2obj(NID_sha256);
                let mut iv = [0x5Au8; 13];
                (*calg).parameter = ASN1_TYPE_new();
                // A GCM parameter is `SEQUENCE { nonce OCTET STRING, icvLen INTEGER }`.
                assert_eq!(
                    ossl_asn1_type_set_octetstring_int(
                        (*calg).parameter,
                        12,
                        iv.as_mut_ptr(),
                        iv.len() as c_int,
                    ),
                    1,
                    "the parameter set carries the IV"
                );

                let mut tag = [0u8; EVP_MAX_IV_LENGTH];
                (*ec).tag = tag.as_mut_ptr();
                (*ec).taglen = taglen;

                let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
                assert!(b.is_null(), "a tag length of {taglen} is refused");
                assert_eq!(
                    ERR_peek_last_error() & 0x7f_ffff,
                    (crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_SET_TAG_ERROR as c_ulong)
                        & 0x7f_ffff,
                    "the refusal keeps the authority's set-tag reason"
                );
                assert_eq!(
                    test_hooks::bio_releases(),
                    vec![test_hooks::bio_alloc()],
                    "the temporary BIO is released exactly once"
                );

                free_ec(ec);
                unregister(cipher);
                EVP_CIPHER_meth_free(cipher);
            }
            ERR_clear_error();
        }
    }

    /// Obligation 1: a custom provider dispatch may advertise an unusual tag length on the
    /// encode side; the validated type carries it to the encoder instead of guessing 16.
    #[test]
    fn cms_enc_custom_provider_unusual_tag_length_round_trips() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();
        REPORTED_TAG_LEN.with(|c| c.set(32));
        TAG_LEN_REPORTS.with(|c| c.set(0));

        // SAFETY: every object is this test's own; the provider marker is cleared before the
        // method is released, so no provider pointer is ever dereferenced or freed.
        unsafe {
            let cipher = custom_cipher(CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER | GCM_MODE, 12);
            (*cipher).prov = core::ptr::NonNull::<OsslProvider>::dangling().as_ptr();
            (*cipher).get_ctx_params = Some(report_tag_len);

            let ec = new_ec();
            (*ec).cipher = cipher.cast();
            // The authority clears `ec->key` at the end; it must be an allocator block, not a
            // stack buffer, so a caller-supplied key goes through the crate's seam.
            // SAFETY: the allocator answers sixteen writable bytes.
            let key = CRYPTO_malloc(16, c"cms_enc.rs".as_ptr(), 0).cast::<c_uchar>();
            assert!(!key.is_null(), "the key allocation succeeds");
            ptr::write_bytes(key, 0x11, 16);
            (*ec).key = key;
            (*ec).keylen = 16;

            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
            assert!(
                !b.is_null(),
                "a provider-reported tag length of 32 is encoded, not refused"
            );
            assert_eq!(
                TAG_LEN_REPORTS.with(Cell::get),
                1,
                "the encode side asked the provider for its tag length"
            );

            BIO_free(b);
            free_ec(ec);
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);
        }
        ERR_clear_error();
    }

    /// Obligation 2: a successful call transfers the BIO to the caller and releases the fetched
    /// cipher exactly once; neither is released twice.
    #[test]
    fn cms_enc_success_releases_each_owner_once() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        // SAFETY: `ec` is this test's own; `EVP_aes_128_cbc` answers a static method.
        unsafe {
            let ec = new_ec();
            (*ec).cipher = crate::evp::e_aes::EVP_aes_128_cbc().cast();

            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 1);
            assert!(!b.is_null(), "AES-128-CBC initialisation succeeds");
            assert_eq!(
                b as usize,
                test_hooks::bio_alloc(),
                "the returned BIO is the allocated one"
            );
            assert!(
                test_hooks::bio_releases().is_empty(),
                "success transfers the BIO; its owner must not release it"
            );
            let cipher_releases = test_hooks::cipher_releases();
            assert_eq!(
                cipher_releases.len(),
                1,
                "the fetched cipher is released exactly once"
            );
            assert_ne!(
                cipher_releases[0],
                crate::evp::e_aes::EVP_aes_128_cbc() as usize,
                "the released object is the fetched cipher, not the static method"
            );

            BIO_free(b);
            free_ec(ec);
        }
        ERR_clear_error();
    }

    /// Obligation 2: a failed call releases the BIO and the fetched cipher exactly once, at the
    /// same addresses that were allocated/fetched.
    #[test]
    fn cms_enc_failure_releases_each_owner_once() {
        let _g = lock_global_state();
        ERR_clear_error();
        test_hooks::reset();

        // SAFETY: `ec` is this test's own and its members are released by its item free.
        unsafe {
            let ec = new_ec();
            (*ec).cipher = ptr::null();
            let calg = (*ec).content_encryption_algorithm;
            (*calg).algorithm = OBJ_nid2obj(NID_aes_128_cbc);
            // An empty `ASN1_TYPE` is not an octet string, so the IV decoder refuses *after* the
            // provider cipher was fetched and the BIO allocated.
            (*calg).parameter = ASN1_TYPE_new();
            assert!(!(*calg).parameter.is_null());

            let b = ossl_cms_EncryptedContent_init_bio(ec, ptr::null(), 0);
            assert!(b.is_null(), "a parameter set with no IV is refused");
            assert_eq!(
                test_hooks::bio_releases(),
                vec![test_hooks::bio_alloc()],
                "the BIO is released exactly once"
            );
            assert_eq!(
                test_hooks::cipher_releases().len(),
                1,
                "the fetched cipher is released exactly once"
            );

            free_ec(ec);
        }
        ERR_clear_error();
    }
}
