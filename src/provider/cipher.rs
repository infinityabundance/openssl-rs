//! Phase 8.2 — the cipher half of the default provider.
//!
//! `EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL)` resolves through the default library context,
//! the default provider's `OSSL_OP_CIPHER` query, and `evp_cipher_from_algorithm`'s dispatch
//! walk, and the object it returns drives `EVP_EncryptInit_ex`/`_Update`/`_Final_ex` through
//! `src/evp/cipher_ctx.rs`. This module is the `OSSL_OP_CIPHER` half of `providers/defltprov.c`.
//!
//! ## What this lands, and what it deliberately does not
//!
//! This is the **cipher half** of `providers/defltprov.c` for the families this crate has a
//! construction for:
//!
//! * `providers/implementations/ciphers/ciphercommon.c.in`'s generic block/stream engine
//!   (`ossl_cipher_generic_*`), `ciphercommon_block.c`'s block buffering and PKCS#7 padding, and
//!   `ciphercommon_hw.c`'s generic mode functions;
//! * the `IMPLEMENT_generic_cipher`/`IMPLEMENT_tdes_cipher` dispatch shape, one table per row,
//!   with the per-algorithm `*_initkey` (`cipher_aes_hw.c`, `cipher_camellia_hw.c`,
//!   `cipher_tdes_hw.c`, `cipher_tdes_default_hw.c`) and `cipher_null.c` whole;
//! * `deflt_ciphers[]`'s rows for AES, Camellia, 3DES and the `NULL` cipher, with each row's
//!   alias string taken verbatim from `providers/implementations/include/prov/names.h` and each
//!   row's provider checked against `providers/defltprov.c` (**not** `legacyprov.c`): AES,
//!   Camellia and 3DES are the default provider's (`defltprov.c:163-186`, `:275-300`,
//!   `:301-313`), while **single** DES, RC2, RC4, Blowfish, CAST5, IDEA and SEED are the legacy
//!   provider's (`legacyprov.c:108-159`) and get no row here. That per-row check is the defect
//!   D206 found for MD4 and D213 for RC4, restated for ciphers.
//! * the `OSSL_OP_CIPHER` arm of `deflt_query`.
//!
//! What is **absent by design**: `deflt_get_params`/`deflt_gettable_params`/
//! `ossl_prov_get_capabilities`/`provctx` and the `base`/`null` *providers*; the AEAD modes
//! (GCM/CCM/XTS/OCB/SIV/wrap), the CTS rows, ARIA/SM4 (whose constructions do not exist here;
//! D209 §2), ChaCha20, and the asm-selected `cipher_aes_cbc_hmac_*` TLS ciphers. `deflt_ciphers[]`
//! in the authority carries those rows too; this half carries the subset the crate can back.
//!
//! Two arms the authority has are not transcribed because they are unreachable for these rows
//! without a caller setting the corresponding context parameter, and each is named rather than
//! silently dropped: the TLS-record arm of `ossl_cipher_generic_block_update`/`_final`
//! (`ctx->tlsversion > 0`, `ciphercommon.c.in:297-370`), and the `randkey` arm of
//! `des_get_ctx_params`/`ossl_tdes_get_ctx_params`, whose body is `RAND_priv_bytes_ex` —
//! `rand.h` is Phase 9's.
//!
//! ## The generic engine is a macro here for the same reason the digest half's is
//!
//! `IMPLEMENT_generic_cipher` is itself a macro: one body, many instantiations differing only in
//! the row's parameters and its `ossl_prov_cipher_hw_*` selector. A Rust macro is that macro's
//! transcription, and its output is ordinary `pub(crate)` function items and `'static` dispatch
//! tables — **no exported symbol**, so the project's ban on `macro_rules!`-generated exports is
//! not engaged.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::aes::{
    AES_cbc_encrypt, AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AesKey,
};
use crate::camellia::{CamelliaKey, Camellia_set_key};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::des::{
    DES_ecb3_encrypt, DES_ede3_cbc_encrypt, DES_ede3_cfb64_encrypt, DES_ede3_cfb_encrypt,
    DES_ede3_ofb64_encrypt, DES_set_key_unchecked, DesKeySchedule,
};
use crate::evp::cipher::{
    OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,
    OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT, OSSL_FUNC_CIPHER_FINAL,
    OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE,
};
use crate::modes::wrap::{
    CRYPTO_128_unwrap, CRYPTO_128_unwrap_pad, CRYPTO_128_wrap, CRYPTO_128_wrap_pad,
};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt,
    CRYPTO_cfb128_8_encrypt, CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt, CRYPTO_ofb128_encrypt,
    Cbc128F,
};
use crate::params::{
    OsslParam, END, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::activate::OsslAlgorithm;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc,
};

/// The authority translation unit the generic engine is `ciphercommon.c.in`'s, for the
/// allocation-tracking `file` argument.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/ciphercommon.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `OSSL_OP_CIPHER` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_CIPHER: c_int = 2;

/// `ecb128_f` — `include/openssl/modes.h:32-34`.
type Ecb128F = unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, c_int);

// ---------------------------------------------------------------------------------------------
// Flags and parameter names
// ---------------------------------------------------------------------------------------------

/// `PROV_CIPHER_FLAG_CUSTOM_IV`.
const PROV_CIPHER_FLAG_CUSTOM_IV: u64 = 0x0002;
/// `PROV_CIPHER_FLAG_CTS`.
const PROV_CIPHER_FLAG_CTS: u64 = 0x0004;
/// `PROV_CIPHER_FLAG_TLS1_MULTIBLOCK`.
const PROV_CIPHER_FLAG_TLS1_MULTIBLOCK: u64 = 0x0008;
/// `PROV_CIPHER_FLAG_RAND_KEY`.
const PROV_CIPHER_FLAG_RAND_KEY: u64 = 0x0010;
/// `PROV_CIPHER_FLAG_VARIABLE_LENGTH`.
const PROV_CIPHER_FLAG_VARIABLE_LENGTH: u64 = 0x0100;
/// `PROV_CIPHER_FLAG_INVERSE_CIPHER`.
const PROV_CIPHER_FLAG_INVERSE_CIPHER: u64 = 0x0200;
/// `PROV_CIPHER_FLAG_AEAD`.
const PROV_CIPHER_FLAG_AEAD: u64 = 0x0001;
/// `EVP_CIPH_FLAG_ENC_THEN_MAC` — `include/openssl/evp.h:368`.
const EVP_CIPH_FLAG_ENC_THEN_MAC: u64 = 0x10000000;
/// `DES_FLAGS`/`TDES_FLAGS` — `cipher_des.c:23`, `cipher_tdes.h:20`.
const TDES_FLAGS: u64 = PROV_CIPHER_FLAG_RAND_KEY;

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_uint = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_uint = 0x2;
/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:319`.
const EVP_CIPH_WRAP_MODE: c_uint = 0x10002;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_uint = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_uint = 0x4;
/// `EVP_CIPH_CTR_MODE` — `include/openssl/evp.h:315`.
const EVP_CIPH_CTR_MODE: c_uint = 0x5;

/// `GENERIC_BLOCK_SIZE` — `prov/ciphercommon.h:24`.
const GENERIC_BLOCK_SIZE: usize = 16;
/// `MAXCHUNK` — `prov/ciphercommon.h:21`.
const MAXCHUNK: usize = 1 << 30;
/// `MAXBITCHUNK` — `prov/ciphercommon.h:22`.
const MAXBITCHUNK: usize = 1usize << (usize::BITS as usize - 4);

/// `OSSL_CIPHER_PARAM_MODE` — `include/openssl/core_names.h:201`.
const OSSL_CIPHER_PARAM_MODE: *const c_char = c"mode".as_ptr();
/// `OSSL_CIPHER_PARAM_KEYLEN` — `core_names.h:200`.
const OSSL_CIPHER_PARAM_KEYLEN: *const c_char = c"keylen".as_ptr();
/// `OSSL_CIPHER_PARAM_IVLEN` — `core_names.h:199`.
const OSSL_CIPHER_PARAM_IVLEN: *const c_char = c"ivlen".as_ptr();
/// `OSSL_CIPHER_PARAM_BLOCK_SIZE` — `core_names.h:189`.
const OSSL_CIPHER_PARAM_BLOCK_SIZE: *const c_char = c"blocksize".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD` — `core_names.h:175`.
const OSSL_CIPHER_PARAM_AEAD: *const c_char = c"aead".as_ptr();
/// `OSSL_CIPHER_PARAM_CUSTOM_IV` — `core_names.h:192`.
const OSSL_CIPHER_PARAM_CUSTOM_IV: *const c_char = c"custom-iv".as_ptr();
/// `OSSL_CIPHER_PARAM_CTS` — `core_names.h:190`.
const OSSL_CIPHER_PARAM_CTS: *const c_char = c"cts".as_ptr();
/// `OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK` — `core_names.h:209`.
const OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK: *const c_char = c"tls-multi".as_ptr();
/// `OSSL_CIPHER_PARAM_HAS_RAND_KEY` — `core_names.h:197`.
const OSSL_CIPHER_PARAM_HAS_RAND_KEY: *const c_char = c"has-randkey".as_ptr();
/// `OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC` — `core_names.h:194`.
const OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC: *const c_char = c"encrypt-then-mac".as_ptr();
/// `OSSL_CIPHER_PARAM_PADDING` — `core_names.h:203`.
const OSSL_CIPHER_PARAM_PADDING: *const c_char = c"padding".as_ptr();
/// `OSSL_CIPHER_PARAM_NUM` — `core_names.h:202`.
const OSSL_CIPHER_PARAM_NUM: *const c_char = c"num".as_ptr();
/// `OSSL_CIPHER_PARAM_IV` — `core_names.h:198`.
const OSSL_CIPHER_PARAM_IV: *const c_char = c"iv".as_ptr();
/// `OSSL_CIPHER_PARAM_UPDATED_IV` — `core_names.h:221`.
const OSSL_CIPHER_PARAM_UPDATED_IV: *const c_char = c"updated-iv".as_ptr();
/// `OSSL_CIPHER_PARAM_TLS_MAC` — `core_names.h:218`.
const OSSL_CIPHER_PARAM_TLS_MAC: *const c_char = c"tls-mac".as_ptr();
/// `OSSL_CIPHER_PARAM_USE_BITS` — `core_names.h:222`.
const OSSL_CIPHER_PARAM_USE_BITS: *const c_char = c"use-bits".as_ptr();
/// `OSSL_CIPHER_PARAM_TLS_VERSION` — `core_names.h:220`.
const OSSL_CIPHER_PARAM_TLS_VERSION: *const c_char = c"tls-version".as_ptr();
/// `OSSL_CIPHER_PARAM_TLS_MAC_SIZE` — `core_names.h:219`.
const OSSL_CIPHER_PARAM_TLS_MAC_SIZE: *const c_char = c"tls-mac-size".as_ptr();
/// `OSSL_CIPHER_PARAM_RANDOM_KEY` — `core_names.h:205`.
const OSSL_CIPHER_PARAM_RANDOM_KEY: *const c_char = c"randkey".as_ptr();
/// `OSSL_CIPHER_PARAM_DECRYPT_ONLY` — `core_names.h:193`.
const OSSL_CIPHER_PARAM_DECRYPT_ONLY: *const c_char = c"decrypt-only".as_ptr();

// The `PROV_CIPHER_CTX` bitfield order, `prov/ciphercommon.h:69-76`.
const CTX_PAD: c_uint = 1 << 0;
const CTX_ENC: c_uint = 1 << 1;
const CTX_IV_SET: c_uint = 1 << 2;
const CTX_KEY_SET: c_uint = 1 << 3;
const CTX_UPDATED: c_uint = 1 << 4;
const CTX_VARIABLE_KEYLENGTH: c_uint = 1 << 5;
const CTX_INVERSE_CIPHER: c_uint = 1 << 6;
const CTX_USE_BITS: c_uint = 1 << 7;

// ---------------------------------------------------------------------------------------------
// `prov/ciphercommon.h`'s structures
// ---------------------------------------------------------------------------------------------

/// `struct prov_cipher_ctx_st` — `prov/ciphercommon.h:48-100`. The C bitfields are one
/// `unsigned int` here, addressed by the `CTX_*` masks.
#[repr(C)]
pub(crate) struct ProvCipherCtx {
    /// `unsigned char oiv[GENERIC_BLOCK_SIZE]`.
    pub oiv: [c_uchar; GENERIC_BLOCK_SIZE],
    /// `unsigned char buf[GENERIC_BLOCK_SIZE]`.
    pub buf: [c_uchar; GENERIC_BLOCK_SIZE],
    /// `unsigned char iv[GENERIC_BLOCK_SIZE]`.
    pub iv: [c_uchar; GENERIC_BLOCK_SIZE],
    /// `block128_f block`.
    pub block: Option<Block128F>,
    /// `union { cbc128_f cbc; ctr128_f ctr; ecb128_f ecb; } stream`. Three fields, because only
    /// the mode's own hw function reads its member, which is what the union's aliasing gives the
    /// authority.
    pub cbc_fn: Option<Cbc128F>,
    /// `stream.ctr`.
    pub ctr: Option<crate::modes::Ctr128F>,
    /// `stream.ecb`.
    pub ecb: Option<Ecb128F>,
    /// `unsigned int mode`.
    pub mode: c_uint,
    /// `size_t keylen`.
    pub keylen: usize,
    /// `size_t ivlen`.
    pub ivlen: usize,
    /// `size_t blocksize`.
    pub blocksize: usize,
    /// `size_t bufsz`.
    pub bufsz: usize,
    /// `unsigned int cts_mode`.
    pub cts_mode: c_uint,
    /// The `pad`/`enc`/`iv_set`/… bitfields.
    pub bits: c_uint,
    /// `unsigned int tlsversion`.
    pub tlsversion: c_uint,
    /// `unsigned char *tlsmac`.
    pub tlsmac: *mut c_uchar,
    /// `int alloced`.
    pub alloced: c_int,
    /// `size_t tlsmacsize`.
    pub tlsmacsize: usize,
    /// `int removetlspad`.
    pub removetlspad: c_int,
    /// `size_t removetlsfixed`.
    pub removetlsfixed: usize,
    /// `unsigned int num`.
    pub num: c_uint,
    /// `const PROV_CIPHER_HW *hw`.
    pub hw: *const ProvCipherHw,
    /// `const void *ks`.
    pub ks: *const c_void,
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
}

/// `struct prov_cipher_hw_st` — `prov/ciphercommon.h:102-106`.
#[repr(C)]
pub(crate) struct ProvCipherHw {
    /// `int (*init)(PROV_CIPHER_CTX *, const uint8_t *, size_t)`.
    pub init: unsafe extern "C" fn(*mut ProvCipherCtx, *const c_uchar, usize) -> c_int,
    /// `PROV_CIPHER_HW_FN *cipher`.
    pub cipher:
        unsafe extern "C" fn(*mut ProvCipherCtx, *mut c_uchar, *const c_uchar, usize) -> c_int,
    /// `void (*copyctx)(PROV_CIPHER_CTX *, const PROV_CIPHER_CTX *)`.
    pub copyctx: unsafe extern "C" fn(*mut ProvCipherCtx, *const ProvCipherCtx),
}

/// `struct prov_skey_st` — `include/internal/skey.h:17-30`, for the two `*_skey_*` arms.
#[repr(C)]
struct ProvSkey {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `int type`.
    type_: c_int,
    /// `unsigned char *data`.
    data: *mut c_uchar,
    /// `size_t length`.
    length: usize,
}

#[inline]
fn bits(ctx: *const ProvCipherCtx) -> c_uint {
    // SAFETY: the caller holds a live context.
    unsafe { (*ctx).bits }
}

#[inline]
fn bits_set(ctx: *mut ProvCipherCtx, mask: c_uint, on: bool) {
    // SAFETY: the caller holds a live context.
    unsafe {
        if on {
            (*ctx).bits |= mask;
        } else {
            (*ctx).bits &= !mask;
        }
    }
}

impl ProvCipherCtx {
    /// The `enc` bit as the low-level functions' `int`.
    #[inline]
    fn enc_int(&self) -> c_int {
        if self.bits & CTX_ENC != 0 {
            1
        } else {
            0
        }
    }
}

/// `ossl_prov_is_running` — `providers/prov_running.c`. The default provider is always in a
/// happy state on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// Every failure arm. The authority raises an error whose string belongs to a half this module
/// does not carry; the refusal is what the caller observes.
#[inline]
fn fail() -> c_int {
    0
}

/// The block function an `initkey` stored, or a refusal if it stored none — the authority would
/// call through a NULL pointer, which no correct transcription reaches.
#[inline]
unsafe fn block_fn(ctx: *mut ProvCipherCtx) -> Option<Block128F> {
    // SAFETY: the caller holds a live context.
    unsafe { (*ctx).block }
}

// ---------------------------------------------------------------------------------------------
// `ciphercommon_block.c`
// ---------------------------------------------------------------------------------------------

/// `ossl_cipher_fillblock` — `ciphercommon_block.c:39-57`.
///
/// # Safety
/// `buf`/`buflen`/`in`/`inlen` are live per the caller's contract.
unsafe fn ossl_cipher_fillblock(
    buf: *mut c_uchar,
    buflen: *mut usize,
    blocksize: usize,
    in_: *mut *const c_uchar,
    inlen: *mut usize,
) -> usize {
    // SAFETY: the caller's contract; every pointer is dereferenced within the block.
    unsafe {
        let blockmask = !(blocksize - 1);
        let mut bufremain = blocksize - *buflen;
        if *inlen < bufremain {
            bufremain = *inlen;
        }
        ptr::copy_nonoverlapping(*in_, buf.add(*buflen), bufremain);
        *in_ = (*in_).add(bufremain);
        *inlen -= bufremain;
        *buflen += bufremain;
        *inlen & blockmask
    }
}

/// `ossl_cipher_trailingdata` — `ciphercommon_block.c:63-79`.
///
/// # Safety
/// As [`ossl_cipher_fillblock`].
unsafe fn ossl_cipher_trailingdata(
    buf: *mut c_uchar,
    buflen: *mut usize,
    blocksize: usize,
    in_: *mut *const c_uchar,
    inlen: *mut usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if *inlen == 0 {
            return 1;
        }
        if *buflen + *inlen > blocksize {
            return fail();
        }
        ptr::copy_nonoverlapping(*in_, buf.add(*buflen), *inlen);
        *buflen += *inlen;
        *inlen = 0;
        1
    }
}

/// `ossl_cipher_padblock` — `ciphercommon_block.c:82-89`.
///
/// # Safety
/// `buf` is `blocksize` bytes and `*buflen <= blocksize`.
unsafe fn ossl_cipher_padblock(buf: *mut c_uchar, buflen: *mut usize, blocksize: usize) {
    // SAFETY: the caller's contract.
    unsafe {
        let pad = (blocksize - *buflen) as c_uchar;
        let mut i = *buflen;
        while i < blocksize {
            *buf.add(i) = pad;
            i += 1;
        }
    }
}

/// `ossl_cipher_unpadblock` — `ciphercommon_block.c:91-118`.
///
/// # Safety
/// `buf` is `blocksize` bytes and `buflen` holds the block length.
unsafe fn ossl_cipher_unpadblock(buf: *mut c_uchar, buflen: *mut usize, blocksize: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut len = *buflen;
        if len != blocksize {
            return fail();
        }
        let pad = *buf.add(blocksize - 1) as usize;
        if pad == 0 || pad > blocksize {
            return fail();
        }
        let mut i = 0usize;
        while i < pad {
            len -= 1;
            if *buf.add(len) as usize != pad {
                return fail();
            }
            i += 1;
        }
        *buflen = len;
        1
    }
}

/// `ossl_cipher_generic_reset_ctx` — `ciphercommon.c.in:193-200`.
///
/// # Safety
/// `ctx` is live.
unsafe fn ossl_cipher_generic_reset_ctx(ctx: *mut ProvCipherCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() && (*ctx).alloced != 0 {
            CRYPTO_clear_free((*ctx).tlsmac.cast(), (*ctx).tlsmacsize, FILE, LINE);
            (*ctx).alloced = 0;
            (*ctx).tlsmac = ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `ciphercommon.c.in` — the generic engine
// ---------------------------------------------------------------------------------------------

/// `cipher_generic_init_internal` — `ciphercommon.c.in:202-240`.
///
/// # Safety
/// `ctx` is live; `key`/`iv` are readable for their lengths when non-NULL; `params` is NULL or a
/// key-terminated array.
unsafe fn cipher_generic_init_internal(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
    enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).num = 0;
        (*ctx).bufsz = 0;
        bits_set(ctx, CTX_UPDATED, false);
        bits_set(ctx, CTX_ENC, enc != 0);

        if is_running() == 0 {
            return fail();
        }
        if !iv.is_null()
            && (*ctx).mode != EVP_CIPH_ECB_MODE
            && ossl_cipher_generic_initiv(ctx, iv, ivlen) == 0
        {
            return fail();
        }
        if iv.is_null()
            && bits(ctx) & CTX_IV_SET != 0
            && ((*ctx).mode == EVP_CIPH_CBC_MODE
                || (*ctx).mode == EVP_CIPH_CFB_MODE
                || (*ctx).mode == EVP_CIPH_OFB_MODE)
        {
            ptr::copy_nonoverlapping((*ctx).oiv.as_ptr(), (*ctx).iv.as_mut_ptr(), (*ctx).ivlen);
        }
        if !key.is_null() {
            if bits(ctx) & CTX_VARIABLE_KEYLENGTH == 0 {
                if keylen != (*ctx).keylen {
                    return fail();
                }
            } else {
                (*ctx).keylen = keylen;
            }
            let hw = (*ctx).hw;
            if ((*hw).init)(ctx, key, (*ctx).keylen) == 0 {
                return fail();
            }
            bits_set(ctx, CTX_KEY_SET, true);
        }
        ossl_cipher_generic_set_ctx_params(ctx.cast(), params)
    }
}

/// `ossl_cipher_generic_einit` — `ciphercommon.c.in:242-248`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { cipher_generic_init_internal(vctx.cast(), key, keylen, iv, ivlen, params, 1) }
}

/// `ossl_cipher_generic_dinit` — `ciphercommon.c.in:250-256`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { cipher_generic_init_internal(vctx.cast(), key, keylen, iv, ivlen, params, 0) }
}

/// `ossl_cipher_generic_skey_einit` — `ciphercommon.c.in:258-267`.
///
/// # Safety
/// The dispatch contract; `skeydata` is a `PROV_SKEY *`.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_skey_einit(
    vctx: *mut c_void,
    skeydata: *mut c_void,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller passes a live `PROV_SKEY`.
    let key = unsafe { &*(skeydata.cast::<ProvSkey>()) };
    // SAFETY: the caller's contract.
    unsafe { cipher_generic_init_internal(vctx.cast(), key.data, key.length, iv, ivlen, params, 1) }
}

/// `ossl_cipher_generic_skey_dinit` — `ciphercommon.c.in:269-278`.
///
/// # Safety
/// As [`ossl_cipher_generic_skey_einit`].
pub(crate) unsafe extern "C" fn ossl_cipher_generic_skey_dinit(
    vctx: *mut c_void,
    skeydata: *mut c_void,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller passes a live `PROV_SKEY`.
    let key = unsafe { &*(skeydata.cast::<ProvSkey>()) };
    // SAFETY: the caller's contract.
    unsafe { cipher_generic_init_internal(vctx.cast(), key.data, key.length, iv, ivlen, params, 0) }
}

/// `ossl_cipher_generic_block_update` — `ciphercommon.c.in:283-426`.
///
/// The TLS-record arm (`ctx->tlsversion > 0`) is not transcribed; see the module doc.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_block_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let mut out = out;
        let mut in_ = in_;
        let mut inl = inl;
        let mut outlint = 0usize;
        let blksz = (*ctx).blocksize;

        if bits(ctx) & CTX_KEY_SET == 0 {
            return fail();
        }
        if (*ctx).tlsversion > 0 {
            return fail();
        }

        let mut nextblocks;
        if (*ctx).bufsz != 0 {
            nextblocks = ossl_cipher_fillblock(
                (*ctx).buf.as_mut_ptr(),
                ptr::addr_of_mut!((*ctx).bufsz),
                blksz,
                ptr::addr_of_mut!(in_),
                ptr::addr_of_mut!(inl),
            );
        } else {
            nextblocks = inl & !(blksz - 1);
        }

        if (*ctx).bufsz == blksz
            && (bits(ctx) & CTX_ENC != 0 || inl > 0 || bits(ctx) & CTX_PAD == 0)
        {
            if outsize < blksz {
                return fail();
            }
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, (*ctx).buf.as_ptr(), blksz) == 0 {
                return fail();
            }
            (*ctx).bufsz = 0;
            outlint = blksz;
            out = out.add(blksz);
        }
        if nextblocks > 0 {
            if bits(ctx) & CTX_ENC == 0 && bits(ctx) & CTX_PAD != 0 && nextblocks == inl {
                if inl < blksz {
                    return fail();
                }
                nextblocks -= blksz;
            }
            outlint += nextblocks;
            if outsize < outlint {
                return fail();
            }
        }
        if nextblocks > 0 {
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, in_, nextblocks) == 0 {
                return fail();
            }
            in_ = in_.add(nextblocks);
            inl -= nextblocks;
        }
        if inl != 0
            && ossl_cipher_trailingdata(
                (*ctx).buf.as_mut_ptr(),
                ptr::addr_of_mut!((*ctx).bufsz),
                blksz,
                ptr::addr_of_mut!(in_),
                ptr::addr_of_mut!(inl),
            ) == 0
        {
            return fail();
        }
        *outl = outlint;
        if inl == 0 {
            1
        } else {
            0
        }
    }
}

/// `ossl_cipher_generic_block_final` — `ciphercommon.c.in:428-500`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_block_final(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let blksz = (*ctx).blocksize;

        if is_running() == 0 {
            return fail();
        }
        if bits(ctx) & CTX_KEY_SET == 0 {
            return fail();
        }
        if (*ctx).tlsversion > 0 {
            return fail();
        }
        if bits(ctx) & CTX_ENC != 0 {
            if bits(ctx) & CTX_PAD != 0 {
                ossl_cipher_padblock(
                    (*ctx).buf.as_mut_ptr(),
                    ptr::addr_of_mut!((*ctx).bufsz),
                    blksz,
                );
            } else if (*ctx).bufsz == 0 {
                *outl = 0;
                return 1;
            } else if (*ctx).bufsz != blksz {
                return fail();
            }
            if outsize < blksz {
                return fail();
            }
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, (*ctx).buf.as_ptr(), blksz) == 0 {
                return fail();
            }
            (*ctx).bufsz = 0;
            *outl = blksz;
            return 1;
        }
        if (*ctx).bufsz != blksz {
            if (*ctx).bufsz == 0 && bits(ctx) & CTX_PAD == 0 {
                *outl = 0;
                return 1;
            }
            return fail();
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, (*ctx).buf.as_mut_ptr(), (*ctx).buf.as_ptr(), blksz) == 0 {
            return fail();
        }
        if bits(ctx) & CTX_PAD != 0
            && ossl_cipher_unpadblock(
                (*ctx).buf.as_mut_ptr(),
                ptr::addr_of_mut!((*ctx).bufsz),
                blksz,
            ) == 0
        {
            return fail();
        }
        if outsize < (*ctx).bufsz {
            return fail();
        }
        ptr::copy_nonoverlapping((*ctx).buf.as_ptr(), out, (*ctx).bufsz);
        *outl = (*ctx).bufsz;
        (*ctx).bufsz = 0;
        1
    }
}

/// `ossl_cipher_generic_stream_update` — `ciphercommon.c.in:502-563`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_stream_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if bits(ctx) & CTX_KEY_SET == 0 {
            return fail();
        }
        if inl == 0 {
            *outl = 0;
            return 1;
        }
        if outsize < inl {
            return fail();
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, out, in_, inl) == 0 {
            return fail();
        }
        *outl = inl;
        1
    }
}

/// `ossl_cipher_generic_stream_final` — `ciphercommon.c.in:564-579`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_stream_final(
    vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if is_running() == 0 {
            return fail();
        }
        if bits(ctx) & CTX_KEY_SET == 0 {
            return fail();
        }
        *outl = 0;
        1
    }
}

/// `ossl_cipher_generic_cipher` — `ciphercommon.c.in:581-607`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if is_running() == 0 {
            return fail();
        }
        if bits(ctx) & CTX_KEY_SET == 0 {
            return fail();
        }
        if outsize < inl {
            return fail();
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, out, in_, inl) == 0 {
            return fail();
        }
        *outl = inl;
        1
    }
}

/// `ossl_cipher_common_get_ctx_params` — `ciphercommon.c.in:609-649`.
///
/// # Safety
/// `ctx` is live; `params` is NULL or a key-terminated array whose entries are writable.
unsafe fn ossl_cipher_common_get_ctx_params(
    ctx: *mut ProvCipherCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract; `OSSL_PARAM_locate` walks a key-terminated array.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).ivlen) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_uint(p, c_uint::from(bits(ctx) & CTX_PAD != 0)) == 0
        {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).oiv.as_ptr().cast(),
                (*ctx).ivlen,
            ) == 0
        {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).iv.as_ptr().cast(),
                (*ctx).ivlen,
            ) == 0
        {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
        if !p.is_null() && crate::params::OSSL_PARAM_set_uint(p, (*ctx).num) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).keylen) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_ptr(p, (*ctx).tlsmac.cast(), (*ctx).tlsmacsize)
                == 0
        {
            return fail();
        }
        1
    }
}

/// `ossl_cipher_generic_get_ctx_params` — `ciphercommon.c.in:651-659`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_get_ctx_params(
    vctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return fail();
        }
        ossl_cipher_common_get_ctx_params(vctx.cast(), params)
    }
}

/// `ossl_cipher_common_set_ctx_params` — `ciphercommon.c.in:661-711`.
///
/// # Safety
/// `ctx` is live; `params` is NULL or a key-terminated array.
unsafe fn ossl_cipher_common_set_ctx_params(
    ctx: *mut ProvCipherCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract; `OSSL_PARAM_locate_const` walks a key-terminated array.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
        if !p.is_null() {
            let mut pad: c_uint = 0;
            if crate::params::OSSL_PARAM_get_uint(p, &mut pad) == 0 {
                return fail();
            }
            bits_set(ctx, CTX_PAD, pad != 0);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
        if !p.is_null() {
            let mut b: c_uint = 0;
            if crate::params::OSSL_PARAM_get_uint(p, &mut b) == 0 {
                return fail();
            }
            bits_set(ctx, CTX_USE_BITS, b != 0);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
        if !p.is_null() && crate::params::OSSL_PARAM_get_uint(p, &mut (*ctx).tlsversion) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_get_size_t(p, &mut (*ctx).tlsmacsize) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
        if !p.is_null() {
            let mut num: c_uint = 0;
            if crate::params::OSSL_PARAM_get_uint(p, &mut num) == 0 {
                return fail();
            }
            if (*ctx).blocksize > 0 && num >= (*ctx).blocksize as c_uint {
                return fail();
            }
            (*ctx).num = num;
        }
        1
    }
}

/// `ossl_cipher_generic_set_ctx_params` — `ciphercommon.c.in:713-724`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ossl_param_is_empty(params) {
            return 1;
        }
        if vctx.is_null() {
            return fail();
        }
        ossl_cipher_common_set_ctx_params(vctx.cast(), params)
    }
}

/// `ossl_param_is_empty` — `include/internal/common.h`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ossl_param_is_empty(params: *const OsslParam) -> bool {
    if params.is_null() {
        return true;
    }
    // SAFETY: the first entry of a key-terminated array is readable.
    unsafe { (*params).key.is_null() }
}

/// `ossl_cipher_generic_initiv` — `ciphercommon.c.in:726-738`.
///
/// # Safety
/// `ctx` is live; `iv` is `ivlen` bytes.
unsafe fn ossl_cipher_generic_initiv(
    ctx: *mut ProvCipherCtx,
    iv: *const c_uchar,
    ivlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ivlen != (*ctx).ivlen || ivlen > GENERIC_BLOCK_SIZE {
            return fail();
        }
        bits_set(ctx, CTX_IV_SET, true);
        ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), ivlen);
        ptr::copy_nonoverlapping(iv, (*ctx).oiv.as_mut_ptr(), ivlen);
        1
    }
}

/// `ossl_cipher_generic_initkey` — `ciphercommon.c.in:740-760`.
///
/// # Safety
/// `vctx` is live and zero-initialised.
#[allow(clippy::too_many_arguments)]
unsafe fn ossl_cipher_generic_initkey(
    vctx: *mut c_void,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
    mode: c_uint,
    flags: u64,
    hw: *const ProvCipherHw,
    _provctx: *mut c_void,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if flags & PROV_CIPHER_FLAG_INVERSE_CIPHER != 0 {
            bits_set(ctx, CTX_INVERSE_CIPHER, true);
        }
        if flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH != 0 {
            bits_set(ctx, CTX_VARIABLE_KEYLENGTH, true);
        }
        bits_set(ctx, CTX_PAD, true);
        (*ctx).keylen = kbits / 8;
        (*ctx).ivlen = ivbits / 8;
        (*ctx).hw = hw;
        (*ctx).mode = mode;
        (*ctx).blocksize = blkbits / 8;
    }
}

/// A read-only descriptor for a gettable/settable param list.
const fn param(key: *const c_char, data_type: c_uint) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `ossl_cipher_generic_gettable_params` — `ciphercommon.c.in:48-51`, the ten keys
/// `produce_param_decoder` locates.
static CIPHER_GETTABLE_PARAMS: [OsslParam; 11] = [
    param(OSSL_CIPHER_PARAM_MODE, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_AEAD, OSSL_PARAM_INTEGER),
    param(OSSL_CIPHER_PARAM_CUSTOM_IV, OSSL_PARAM_INTEGER),
    param(OSSL_CIPHER_PARAM_CTS, OSSL_PARAM_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, OSSL_PARAM_INTEGER),
    param(OSSL_CIPHER_PARAM_HAS_RAND_KEY, OSSL_PARAM_INTEGER),
    param(OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC, OSSL_PARAM_INTEGER),
    END,
];

/// `ossl_cipher_generic_gettable_params` — `ciphercommon.c.in:48-51`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_gettable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    CIPHER_GETTABLE_PARAMS.as_ptr()
}

/// `cipher_generic_get_ctx_params_list` — `ciphercommon.c.in:114-122`.
static CIPHER_GETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR),
    END,
];

/// `ossl_cipher_generic_gettable_ctx_params` — `ciphercommon.c.in:125-128`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CIPHER_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `cipher_generic_set_ctx_params_list` — `ciphercommon.c.in:133-139`.
static CIPHER_SETTABLE_CTX_PARAMS: [OsslParam; 6] = [
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_USE_BITS, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_VERSION, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    END,
];

/// `ossl_cipher_generic_settable_ctx_params` — `ciphercommon.c.in:142-145`.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CIPHER_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `int ossl_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md, uint64_t flags,
/// size_t kbits, size_t blkbits, size_t ivbits)` — `ciphercommon.c.in:53-109`.
///
/// # Safety
/// `params` is NULL or a key-terminated array whose entries are writable.
pub(crate) unsafe extern "C" fn ossl_cipher_generic_get_params(
    params: *mut OsslParam,
    md: c_uint,
    flags: u64,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !set_uint_flag(params, OSSL_CIPHER_PARAM_MODE, md) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_AEAD,
            flags & PROV_CIPHER_FLAG_AEAD != 0,
        ) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_CUSTOM_IV,
            flags & PROV_CIPHER_FLAG_CUSTOM_IV != 0,
        ) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_CTS,
            flags & PROV_CIPHER_FLAG_CTS != 0,
        ) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
            flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK != 0,
        ) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_HAS_RAND_KEY,
            flags & PROV_CIPHER_FLAG_RAND_KEY != 0,
        ) {
            return fail();
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC,
            flags & EVP_CIPH_FLAG_ENC_THEN_MAC != 0,
        ) {
            return fail();
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_KEYLEN, kbits / 8) {
            return fail();
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_BLOCK_SIZE, blkbits / 8) {
            return fail();
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_IVLEN, ivbits / 8) {
            return fail();
        }
        1
    }
}

/// A `set_uint` on a located param; false when the write failed. An absent param is success.
///
/// # Safety
/// `params` is NULL or a key-terminated array whose entries are writable.
unsafe fn set_uint_flag(params: *mut OsslParam, key: *const c_char, value: c_uint) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate(params, key);
        if p.is_null() {
            return true;
        }
        crate::params::OSSL_PARAM_set_uint(p, value) != 0
    }
}

/// A `set_int` on a located param; false when the write failed. An absent param is success.
///
/// # Safety
/// As [`set_uint_flag`].
unsafe fn set_int_flag(params: *mut OsslParam, key: *const c_char, value: bool) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate(params, key);
        if p.is_null() {
            return true;
        }
        crate::params::OSSL_PARAM_set_int(p, c_int::from(value)) != 0
    }
}

/// A `set_size_t` on a located param; false when the write failed.
///
/// # Safety
/// As [`set_uint_flag`].
unsafe fn set_size_param(params: *mut OsslParam, key: *const c_char, value: usize) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate(params, key);
        if p.is_null() {
            return true;
        }
        crate::params::OSSL_PARAM_set_size_t(p, value) != 0
    }
}

// ---------------------------------------------------------------------------------------------
// `ciphercommon_hw.c` — the generic mode functions
// ---------------------------------------------------------------------------------------------

/// The `stream.cbc`/`stream.ecb` members are options; a missing one is a refusal.
macro_rules! ctx_block {
    ($dat:expr) => {
        match block_fn($dat) {
            Some(b) => b,
            None => return fail(),
        }
    };
}

/// `ossl_cipher_hw_generic_cbc` — `ciphercommon_hw.c:16-27`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_cbc(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if let Some(cbc_fn) = (*dat).cbc_fn {
            cbc_fn(
                in_,
                out,
                len,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                (*dat).enc_int(),
            );
        } else if bits(dat) & CTX_ENC != 0 {
            CRYPTO_cbc128_encrypt(
                in_,
                out,
                len,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                ctx_block!(dat),
            );
        } else {
            CRYPTO_cbc128_decrypt(
                in_,
                out,
                len,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                ctx_block!(dat),
            );
        }
        1
    }
}

/// `ossl_cipher_hw_generic_ecb` — `ciphercommon_hw.c:29-45`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_ecb(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let bl = (*dat).blocksize;
        if len < bl {
            return 1;
        }
        if let Some(ecb) = (*dat).ecb {
            ecb(in_, out, len, (*dat).ks, (*dat).enc_int());
        } else {
            let block = ctx_block!(dat);
            let mut i = 0usize;
            let end = len - bl;
            while i <= end {
                block(in_.add(i), out.add(i), (*dat).ks);
                i += bl;
            }
        }
        1
    }
}

/// `ossl_cipher_hw_generic_ofb128` — `ciphercommon_hw.c:47-56`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_ofb128(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut num = (*dat).num as c_int;
        let block = ctx_block!(dat);
        CRYPTO_ofb128_encrypt(
            in_,
            out,
            len,
            (*dat).ks,
            (*dat).iv.as_mut_ptr(),
            &mut num,
            block,
        );
        (*dat).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_generic_cfb128` — `ciphercommon_hw.c:58-68`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_cfb128(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut num = (*dat).num as c_int;
        let block = ctx_block!(dat);
        CRYPTO_cfb128_encrypt(
            in_,
            out,
            len,
            (*dat).ks,
            (*dat).iv.as_mut_ptr(),
            &mut num,
            (*dat).enc_int(),
            block,
        );
        (*dat).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_generic_cfb8` — `ciphercommon_hw.c:70-80`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_cfb8(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut num = (*dat).num as c_int;
        let block = ctx_block!(dat);
        CRYPTO_cfb128_8_encrypt(
            in_,
            out,
            len,
            (*dat).ks,
            (*dat).iv.as_mut_ptr(),
            &mut num,
            (*dat).enc_int(),
            block,
        );
        (*dat).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_generic_cfb1` — `ciphercommon_hw.c:82-108`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_cfb1(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut num = (*dat).num as c_int;
        let block = ctx_block!(dat);
        if bits(dat) & CTX_USE_BITS != 0 {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                len,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                &mut num,
                (*dat).enc_int(),
                block,
            );
            (*dat).num = num as c_uint;
            return 1;
        }
        let mut len = len;
        let mut out = out;
        let mut in_ = in_;
        while len >= MAXBITCHUNK {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                MAXBITCHUNK * 8,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                &mut num,
                (*dat).enc_int(),
                block,
            );
            len -= MAXBITCHUNK;
            out = out.add(MAXBITCHUNK);
            in_ = in_.add(MAXBITCHUNK);
        }
        if len != 0 {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                len * 8,
                (*dat).ks,
                (*dat).iv.as_mut_ptr(),
                &mut num,
                (*dat).enc_int(),
                block,
            );
        }
        (*dat).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_generic_ctr` — `ciphercommon_hw.c:110-124`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
pub(crate) unsafe extern "C" fn ossl_cipher_hw_generic_ctr(
    dat: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut num = (*dat).num;
        let block = ctx_block!(dat);
        CRYPTO_ctr128_encrypt(
            in_,
            out,
            len,
            (*dat).ks,
            (*dat).iv.as_mut_ptr(),
            (*dat).buf.as_mut_ptr(),
            &mut num,
            block,
        );
        (*dat).num = num;
        1
    }
}
// ---------------------------------------------------------------------------------------------
// The per-algorithm hardware
// ---------------------------------------------------------------------------------------------

/// `PROV_AES_CTX` — `cipher_aes.h:?`: `PROV_CIPHER_CTX base` then the `AES_KEY` union.
#[repr(C)]
pub(crate) struct ProvAesCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks`.
    pub ks: AesKey,
}

/// `PROV_CAMELLIA_CTX` — `cipher_camellia.h`'s shape.
#[repr(C)]
pub(crate) struct ProvCamelliaCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; CAMELLIA_KEY ks; } ks`.
    pub ks: CamelliaKey,
}

/// `PROV_TDES_CTX` — `cipher_tdes.h:22-38`.
#[repr(C)]
pub(crate) struct ProvTdesCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; DES_key_schedule ks[3]; } tks`.
    pub tks: [DesKeySchedule; 3],
}

/// `AES_encrypt` as the generic engine's `block128_f`.
///
/// # Safety
/// As `AES_encrypt`; `key` is an `AES_KEY *`.
unsafe extern "C" fn aes_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { AES_encrypt(in_, out, key.cast()) }
}

/// `AES_decrypt` as the generic engine's `block128_f`.
///
/// # Safety
/// As `AES_decrypt`; `key` is an `AES_KEY *`.
unsafe extern "C" fn aes_block_decrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { AES_decrypt(in_, out, key.cast()) }
}

/// `AES_cbc_encrypt` as the generic engine's `cbc128_f`.
///
/// # Safety
/// As `AES_cbc_encrypt`; `key` is an `AES_KEY *`.
unsafe extern "C" fn aes_cbc_run(
    in_: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe { AES_cbc_encrypt(in_, out, len, key.cast(), ivec, enc) }
}

/// `Camellia_encrypt` as the generic engine's `block128_f`.
///
/// # Safety
/// As `Camellia_encrypt`; `key` is a `CAMELLIA_KEY *`.
unsafe extern "C" fn camellia_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::camellia::Camellia_encrypt(in_, out, key.cast()) }
}

/// `Camellia_decrypt` as the generic engine's `block128_f`.
///
/// # Safety
/// As `Camellia_decrypt`; `key` is a `CAMELLIA_KEY *`.
unsafe extern "C" fn camellia_block_decrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::camellia::Camellia_decrypt(in_, out, key.cast()) }
}

/// `Camellia_cbc_encrypt` as the generic engine's `cbc128_f`.
///
/// # Safety
/// As `Camellia_cbc_encrypt`; `key` is a `CAMELLIA_KEY *`.
unsafe extern "C" fn camellia_cbc_run(
    in_: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe { crate::camellia::Camellia_cbc_encrypt(in_, out, len, key.cast(), ivec, enc) }
}

/// `cipher_hw_aes_initkey` — `cipher_aes_hw.c:19-126`, portable arm.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract.
unsafe extern "C" fn cipher_hw_aes_initkey(
    dat: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `dat` is a `PROV_AES_CTX`.
    unsafe {
        let adat = dat.cast::<ProvAesCtx>();
        let ks = ptr::addr_of_mut!((*adat).ks);
        (*dat).ks = ks.cast();
        let ret = if ((*dat).mode == EVP_CIPH_ECB_MODE || (*dat).mode == EVP_CIPH_CBC_MODE)
            && bits(dat) & CTX_ENC == 0
        {
            (*dat).block = Some(aes_block_decrypt);
            AES_set_decrypt_key(key, (keylen * 8) as c_int, ks)
        } else {
            (*dat).block = Some(aes_block_encrypt);
            AES_set_encrypt_key(key, (keylen * 8) as c_int, ks)
        };
        (*dat).cbc_fn = if (*dat).mode == EVP_CIPH_CBC_MODE {
            Some(aes_cbc_run)
        } else {
            None
        };
        if ret < 0 {
            return fail();
        }
        1
    }
}

/// `IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_aes_copyctx, PROV_AES_CTX)`.
///
/// # Safety
/// The `PROV_CIPHER_HW::copyctx` contract.
unsafe extern "C" fn cipher_hw_aes_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract; both are `PROV_AES_CTX`.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<ProvAesCtx>(), dst.cast::<ProvAesCtx>(), 1);
        (*dst.cast::<ProvAesCtx>()).base.ks = ptr::addr_of!((*dst.cast::<ProvAesCtx>()).ks).cast();
    }
}

/// `cipher_hw_camellia_initkey` — `cipher_camellia_hw.c:20-41`.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract.
unsafe extern "C" fn cipher_hw_camellia_initkey(
    dat: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `dat` is a `PROV_CAMELLIA_CTX`.
    unsafe {
        let adat = dat.cast::<ProvCamelliaCtx>();
        let ks = ptr::addr_of_mut!((*adat).ks);
        (*dat).ks = ks.cast();
        if Camellia_set_key(key, (keylen * 8) as c_int, ks) < 0 {
            return fail();
        }
        let mode = (*dat).mode;
        if bits(dat) & CTX_ENC != 0 || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE) {
            (*dat).block = Some(camellia_block_encrypt);
        } else {
            (*dat).block = Some(camellia_block_decrypt);
        }
        (*dat).cbc_fn = if mode == EVP_CIPH_CBC_MODE {
            Some(camellia_cbc_run)
        } else {
            None
        };
        1
    }
}

/// `IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_camellia_copyctx, PROV_CAMELLIA_CTX)`.
///
/// # Safety
/// The `PROV_CIPHER_HW::copyctx` contract.
unsafe extern "C" fn cipher_hw_camellia_copyctx(
    dst: *mut ProvCipherCtx,
    src: *const ProvCipherCtx,
) {
    // SAFETY: the caller's contract; both are `PROV_CAMELLIA_CTX`.
    unsafe {
        ptr::copy_nonoverlapping(
            src.cast::<ProvCamelliaCtx>(),
            dst.cast::<ProvCamelliaCtx>(),
            1,
        );
        (*dst.cast::<ProvCamelliaCtx>()).base.ks =
            ptr::addr_of!((*dst.cast::<ProvCamelliaCtx>()).ks).cast();
    }
}

/// `ossl_cipher_hw_tdes_ede3_initkey` — `cipher_tdes_hw.c:23-45`.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract; an EDE3 row's key is twenty-four bytes.
unsafe extern "C" fn cipher_hw_tdes_ede3_initkey(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    _keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is a `PROV_TDES_CTX`.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        (*ctx).ks = ks.cast();
        DES_set_key_unchecked(key as *mut [u8; 8], ks);
        DES_set_key_unchecked(key.add(8) as *mut [u8; 8], ks.add(1));
        DES_set_key_unchecked(key.add(16) as *mut [u8; 8], ks.add(2));
        1
    }
}

/// `ossl_cipher_hw_tdes_ede2_initkey` — `cipher_tdes_default_hw.c:22-45`.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract; `key` is sixteen bytes.
unsafe extern "C" fn cipher_hw_tdes_ede2_initkey(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    _keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is a `PROV_TDES_CTX`.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        (*ctx).ks = ks.cast();
        DES_set_key_unchecked(key as *mut [u8; 8], ks);
        DES_set_key_unchecked(key.add(8) as *mut [u8; 8], ks.add(1));
        ptr::copy_nonoverlapping(ks, ks.add(2), 1);
        1
    }
}

/// `ossl_cipher_hw_tdes_copyctx` — `cipher_tdes_hw.c:47-55`.
///
/// # Safety
/// The `PROV_CIPHER_HW::copyctx` contract.
unsafe extern "C" fn cipher_hw_tdes_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract; both are `PROV_TDES_CTX`.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<ProvTdesCtx>(), dst.cast::<ProvTdesCtx>(), 1);
        (*dst.cast::<ProvTdesCtx>()).base.ks =
            ptr::addr_of!((*dst.cast::<ProvTdesCtx>()).tks).cast();
    }
}

/// `ossl_cipher_hw_tdes_ecb` — `cipher_tdes_hw.c:80-94`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_ecb(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if len < 8 {
            return 1;
        }
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let mut i = 0usize;
        let end = len - 8;
        while i <= end {
            DES_ecb3_encrypt(
                in_.add(i) as *mut [u8; 8],
                out.add(i) as *mut [u8; 8],
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).enc_int(),
            );
            i += 8;
        }
        1
    }
}

/// `ossl_cipher_hw_tdes_cbc` — `cipher_tdes_hw.c:57-78`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_cbc(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            DES_ede3_cbc_encrypt(
                in_,
                out,
                MAXCHUNK as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                (*ctx).enc_int(),
            );
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            DES_ede3_cbc_encrypt(
                in_,
                out,
                inl as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                (*ctx).enc_int(),
            );
        }
        1
    }
}

/// `ossl_cipher_hw_tdes_ofb` — `cipher_tdes_default_hw.c:47-66`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_ofb(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let mut num = (*ctx).num as c_int;
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            DES_ede3_ofb64_encrypt(
                in_,
                out,
                MAXCHUNK as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                &mut num,
            );
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            DES_ede3_ofb64_encrypt(
                in_,
                out,
                inl as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                &mut num,
            );
        }
        (*ctx).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_tdes_cfb` — `cipher_tdes_default_hw.c:68-90`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_cfb(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let mut num = (*ctx).num as c_int;
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            DES_ede3_cfb64_encrypt(
                in_,
                out,
                MAXCHUNK as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                &mut num,
                (*ctx).enc_int(),
            );
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            DES_ede3_cfb64_encrypt(
                in_,
                out,
                inl as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                &mut num,
                (*ctx).enc_int(),
            );
        }
        (*ctx).num = num as c_uint;
        1
    }
}

/// `ossl_cipher_hw_tdes_cfb8` — `cipher_tdes_default_hw.c:118-136`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_cfb8(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            DES_ede3_cfb_encrypt(
                in_,
                out,
                8,
                MAXCHUNK as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                (*ctx).enc_int(),
            );
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            DES_ede3_cfb_encrypt(
                in_,
                out,
                8,
                inl as c_long,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                (*ctx).enc_int(),
            );
        }
        1
    }
}

/// `ossl_cipher_hw_tdes_cfb1` — `cipher_tdes_default_hw.c:96-116`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_tdes_cfb1(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let tctx = ctx.cast::<ProvTdesCtx>();
        let ks = ptr::addr_of_mut!((*tctx).tks).cast::<DesKeySchedule>();
        let inl = if bits(ctx) & CTX_USE_BITS == 0 {
            inl * 8
        } else {
            inl
        };
        let mut c = [0u8; 1];
        let mut d = [0u8; 1];
        let mut n = 0usize;
        while n < inl {
            c[0] = if *in_.add(n / 8) & (1u8 << (7 - n % 8)) != 0 {
                0x80
            } else {
                0
            };
            DES_ede3_cfb_encrypt(
                c.as_ptr(),
                d.as_mut_ptr(),
                1,
                1,
                ks,
                ks.add(1),
                ks.add(2),
                (*ctx).iv.as_mut_ptr().cast(),
                (*ctx).enc_int(),
            );
            *out.add(n / 8) = (*out.add(n / 8) & !(0x80u8 >> (n % 8))) | ((d[0] & 0x80) >> (n % 8));
            n += 1;
        }
        1
    }
}

// ---------------------------------------------------------------------------------------------
// The contexts' free/dup, one pair per algorithm
// ---------------------------------------------------------------------------------------------

/// `aes_freectx` — `cipher_aes.c:25-31`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesCtx>(), FILE, LINE);
    }
}

/// `aes_dupctx` — `cipher_aes.c:33-47`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_dupctx(ctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvAesCtx>(), FILE, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let src = ctx.cast::<ProvAesCtx>();
        let hw = (*src).base.hw;
        ((*hw).copyctx)(ret.cast(), ctx.cast());
        ret
    }
}

/// `camellia_freectx` — `cipher_camellia.c:25-31`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn camellia_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvCamelliaCtx>(), FILE, LINE);
    }
}

/// `camellia_dupctx` — `cipher_camellia.c:33-47`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn camellia_dupctx(ctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvCamelliaCtx>(), FILE, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let src = ctx.cast::<ProvCamelliaCtx>();
        let hw = (*src).base.hw;
        ((*hw).copyctx)(ret.cast(), ctx.cast());
        ret
    }
}

/// `ossl_tdes_freectx` — `cipher_tdes_common.c:57-63`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvTdesCtx>(), FILE, LINE);
    }
}

/// `ossl_tdes_dupctx` — `cipher_tdes_common.c:40-55`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_dupctx(ctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvTdesCtx>(), FILE, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let src = ctx.cast::<ProvTdesCtx>();
        let hw = (*src).base.hw;
        ((*hw).copyctx)(ret.cast(), ctx.cast());
        ret
    }
}

// ---------------------------------------------------------------------------------------------
// `cipher_tdes_common.c`'s params
// ---------------------------------------------------------------------------------------------

/// `ossl_tdes_get_params` — `cipher_tdes_common.c:183-201`.
///
/// # Safety
/// As [`ossl_cipher_generic_get_params`].
unsafe extern "C" fn ossl_tdes_get_params(
    params: *mut OsslParam,
    md: c_uint,
    flags: u64,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        // `decrypt_only` is 0 outside `FIPS_MODULE`, and this build is not the FIPS module.
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_DECRYPT_ONLY);
        if !p.is_null() && crate::params::OSSL_PARAM_set_int(p, 0) == 0 {
            return fail();
        }
        ossl_cipher_generic_get_params(params, md, flags, kbits, blkbits, ivbits)
    }
}

/// `ossl_tdes_gettable_ctx_params` — `CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_*` with the
/// `RANDOM_KEY` row, `cipher_tdes_common.c:131-134`.
static TDES_GETTABLE_CTX_PARAMS: [OsslParam; 9] = [
    param(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_RANDOM_KEY, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR),
    END,
];

/// `ossl_tdes_gettable_ctx_params` — `cipher_tdes_common.c:131-134`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_tdes_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    TDES_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_*` for 3DES, `cipher_tdes_common.c:170-172`.
static TDES_SETTABLE_CTX_PARAMS: [OsslParam; 6] = [
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_USE_BITS, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_VERSION, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    END,
];

/// `ossl_tdes_settable_ctx_params`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_tdes_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    TDES_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `ossl_tdes_get_ctx_params` — `cipher_tdes_common.c:152-168`, without the `randkey` arm
/// (its body is `RAND_priv_bytes_ex`; see the module doc).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_tdes_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ossl_cipher_generic_get_ctx_params(vctx, params) }
}

/// `ossl_tdes_set_ctx_params` — `cipher_tdes_common.c:174-181`, without the FIPS indicator.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_tdes_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ossl_cipher_generic_set_ctx_params(vctx, params) }
}

// ---------------------------------------------------------------------------------------------
// The dispatch rows
// ---------------------------------------------------------------------------------------------

/// The dispatch-table shape `IMPLEMENT_generic_cipher`/`IMPLEMENT_tdes_cipher` publish: an
/// init, a body, a `get_params`, and the table. `$newctx`/`$getparams`/`$table` name the three
/// items this emits; `$update`/`$final` are `block` or `stream`; `$getctx`/`$setctx` and the two
/// gettable/settable selectors are the algorithm's.
macro_rules! cipher_row {
    ($newctx:ident, $getparams:ident, $table:ident, $ctx:ty, $hw:path, $kbits:expr,
     $blkbits:expr, $ivbits:expr, $mode:expr, $flags:expr, $freectx:path, $dupctx:path,
     $update:path, $final:path, $getparam_fn:path, $getctx:path, $setctx:path,
     $gettable:path, $settable:path) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            if is_running() == 0 {
                return ptr::null_mut();
            }
            let ctx = CRYPTO_zalloc(core::mem::size_of::<$ctx>(), FILE, LINE);
            if !ctx.is_null() {
                // SAFETY: `ctx` is a fresh zeroed context of this row's type.
                unsafe {
                    ossl_cipher_generic_initkey(
                        ctx,
                        $kbits,
                        $blkbits,
                        $ivbits,
                        $mode,
                        $flags,
                        ptr::addr_of!($hw),
                        provctx,
                    );
                }
            }
            ctx
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe { $getparam_fn(params, $mode, $flags, $kbits, $blkbits, $ivbits) }
        }

        pub(crate) static $table: [OsslDispatch; 17] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FREECTX,
                function: $freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
                function: $dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: ossl_cipher_generic_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: ossl_cipher_generic_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: $update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: $final as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
                function: ossl_cipher_generic_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: $getctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: $setctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: $gettable as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: $settable as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT,
                function: ossl_cipher_generic_skey_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,
                function: ossl_cipher_generic_skey_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

/// A row's `PROV_CIPHER_HW` static, `PROV_CIPHER_HW_<alg>_mode`.
macro_rules! hw_static {
    ($name:ident, $init:path, $cipher:path, $copy:path) => {
        static $name: ProvCipherHw = ProvCipherHw {
            init: $init,
            cipher: $cipher,
            copyctx: $copy,
        };
    };
}

hw_static!(
    AES_ECB_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_ecb,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_CBC_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_cbc,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_OFB_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_ofb128,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_CFB_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_cfb128,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_CFB1_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_cfb1,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_CFB8_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_cfb8,
    cipher_hw_aes_copyctx
);
hw_static!(
    AES_CTR_HW,
    cipher_hw_aes_initkey,
    ossl_cipher_hw_generic_ctr,
    cipher_hw_aes_copyctx
);

hw_static!(
    CAMELLIA_ECB_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_ecb,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_CBC_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_cbc,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_OFB_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_ofb128,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_CFB_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_cfb128,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_CFB1_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_cfb1,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_CFB8_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_cfb8,
    cipher_hw_camellia_copyctx
);
hw_static!(
    CAMELLIA_CTR_HW,
    cipher_hw_camellia_initkey,
    ossl_cipher_hw_generic_ctr,
    cipher_hw_camellia_copyctx
);

hw_static!(
    TDES_EDE3_ECB_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_ecb,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE3_CBC_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_cbc,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE3_OFB_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_ofb,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE3_CFB_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_cfb,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE3_CFB1_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_cfb1,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE3_CFB8_HW,
    cipher_hw_tdes_ede3_initkey,
    ossl_cipher_hw_tdes_cfb8,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE2_ECB_HW,
    cipher_hw_tdes_ede2_initkey,
    ossl_cipher_hw_tdes_ecb,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE2_CBC_HW,
    cipher_hw_tdes_ede2_initkey,
    ossl_cipher_hw_tdes_cbc,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE2_OFB_HW,
    cipher_hw_tdes_ede2_initkey,
    ossl_cipher_hw_tdes_ofb,
    cipher_hw_tdes_copyctx
);
hw_static!(
    TDES_EDE2_CFB_HW,
    cipher_hw_tdes_ede2_initkey,
    ossl_cipher_hw_tdes_cfb,
    cipher_hw_tdes_copyctx
);

// ---------------------------------------------------------------------------------------------
// `cipher_aes_wrp.c` — the RFC 3394 (WRAP) and RFC 5649 (WRAP-PAD) provider rows
// ---------------------------------------------------------------------------------------------
//
// The wrap rows are their own engine rather than instantiations of the generic one: a wrapped
// message is not a stream of block-mode operations, so `IMPLEMENT_cipher` here supplies its own
// `init`/`update`/`final`. The four `CRYPTO_128_*` entry points this module drives are the ones
// 8.2's `AES_wrap_key`/`AES_unwrap_key` already delegate to (D224), so there is still exactly one
// RFC 3394 implementation in the crate.

/// `AES_WRAP_PAD_IVLEN` — `cipher_aes_wrp.c:22`.
const AES_WRAP_PAD_IVLEN: usize = 4;
/// `AES_WRAP_NOPAD_IVLEN` — `cipher_aes_wrp.c:23`.
const AES_WRAP_NOPAD_IVLEN: usize = 8;
/// `WRAP_FLAGS` — `cipher_aes_wrp.c:25`.
const WRAP_FLAGS: u64 = PROV_CIPHER_FLAG_CUSTOM_IV;
/// `WRAP_FLAGS_INV` — `cipher_aes_wrp.c:26`.
const WRAP_FLAGS_INV: u64 = WRAP_FLAGS | PROV_CIPHER_FLAG_INVERSE_CIPHER;

/// `aeswrap_fn` — `cipher_aes_wrp.c:28-30`.
type AesWrapFn = unsafe extern "C" fn(
    key: *mut c_void,
    iv: *const c_uchar,
    out: *mut c_uchar,
    input: *const c_uchar,
    inlen: usize,
    block: Block128F,
) -> usize;

/// `PROV_AES_WRAP_CTX` — `cipher_aes_wrp.c:39-47`. The anonymous union is flattened to the
/// `AES_KEY`, which is the only member this row reads.
#[repr(C)]
pub(crate) struct ProvAesWrapCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks`.
    pub ks: AesKey,
    /// `aeswrap_fn wrapfn`.
    pub wrapfn: Option<AesWrapFn>,
}

/// `aes_wrap_newctx` — `cipher_aes_wrp.c:49-66`.
///
/// # Safety
/// The returned context is owned by the caller and released by [`aes_wrap_freectx`].
unsafe fn aes_wrap_newctx(
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
    mode: c_uint,
    flags: u64,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let wctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesWrapCtx>(), FILE, LINE);
        if !wctx.is_null() {
            ossl_cipher_generic_initkey(
                wctx,
                kbits,
                blkbits,
                ivbits,
                mode,
                flags,
                ptr::null(),
                ptr::null_mut(),
            );
            // `ctx->pad = (ctx->ivlen == AES_WRAP_PAD_IVLEN)` — the generic `initkey` had set
            // padding on unconditionally.
            let ctx = wctx.cast::<ProvCipherCtx>();
            bits_set(ctx, CTX_PAD, (*ctx).ivlen == AES_WRAP_PAD_IVLEN);
        }
        wctx
    }
}

/// `aes_wrap_dupctx` — `cipher_aes_wrp.c:68-89`.
///
/// # Safety
/// `wctx` is NULL or a live wrap context.
unsafe extern "C" fn aes_wrap_dupctx(wctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || wctx.is_null() {
            return ptr::null_mut();
        }
        let dctx = CRYPTO_memdup(wctx, core::mem::size_of::<ProvAesWrapCtx>(), FILE, LINE);
        if !dctx.is_null() {
            let d = dctx.cast::<ProvAesWrapCtx>();
            if !(*d).base.tlsmac.is_null() && (*d).base.alloced != 0 {
                let tm = CRYPTO_memdup((*d).base.tlsmac.cast(), (*d).base.tlsmacsize, FILE, LINE);
                if tm.is_null() {
                    CRYPTO_free(dctx, FILE, LINE);
                    return ptr::null_mut();
                }
                (*d).base.tlsmac = tm.cast();
            }
        }
        dctx
    }
}

/// `aes_wrap_freectx` — `cipher_aes_wrp.c:91-97`.
///
/// # Safety
/// `vctx` is a context from [`aes_wrap_newctx`] or NULL.
unsafe extern "C" fn aes_wrap_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesWrapCtx>(), FILE, LINE);
    }
}

/// `aes_wrap_init` — `cipher_aes_wrp.c:99-148`.
///
/// # Safety
/// `vctx` is live; `key`/`iv` are the caller's buffers of the stated lengths.
unsafe fn aes_wrap_init(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
    enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let wctx = vctx.cast::<ProvAesWrapCtx>();

        if is_running() == 0 {
            return 0;
        }

        bits_set(ctx, CTX_ENC, enc != 0);
        (*wctx).wrapfn = Some(if bits(ctx) & CTX_PAD != 0 {
            if enc != 0 {
                CRYPTO_128_wrap_pad
            } else {
                CRYPTO_128_unwrap_pad
            }
        } else if enc != 0 {
            CRYPTO_128_wrap
        } else {
            CRYPTO_128_unwrap
        });

        if !iv.is_null() && ossl_cipher_generic_initiv(ctx, iv, ivlen) == 0 {
            return 0;
        }
        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail();
            }
            // SP800-38F §5.1: an inverse-cipher row's forward transform is the *decryption*
            // function, so the wrap direction swaps which AES key schedule is built.
            let use_forward = if bits(ctx) & CTX_INVERSE_CIPHER == 0 {
                enc != 0
            } else {
                enc == 0
            };
            let ks = ptr::addr_of_mut!((*wctx).ks);
            if use_forward {
                AES_set_encrypt_key(key, (keylen * 8) as c_int, ks);
                (*ctx).block = Some(aes_block_encrypt);
            } else {
                AES_set_decrypt_key(key, (keylen * 8) as c_int, ks);
                (*ctx).block = Some(aes_block_decrypt);
            }
        }
        aes_wrap_set_ctx_params(vctx, params)
    }
}

/// `aes_wrap_einit` — `cipher_aes_wrp.c:150-155`.
///
/// # Safety
/// As [`aes_wrap_init`].
unsafe extern "C" fn aes_wrap_einit(
    ctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 1) }
}

/// `aes_wrap_dinit` — `cipher_aes_wrp.c:157-162`.
///
/// # Safety
/// As [`aes_wrap_init`].
unsafe extern "C" fn aes_wrap_dinit(
    ctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 0) }
}

/// `aes_wrap_cipher_internal` — `cipher_aes_wrp.c:164-222`.
///
/// # Safety
/// `vctx` is live; `out`/`input` as the caller's contract.
unsafe fn aes_wrap_cipher_internal(
    vctx: *mut c_void,
    out: *mut c_uchar,
    input: *const c_uchar,
    inlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let wctx = vctx.cast::<ProvAesWrapCtx>();

        /* No final operation so always return zero length */
        if input.is_null() {
            return 0;
        }
        if inlen == 0 || inlen > c_int::MAX as usize {
            return -1;
        }
        if bits(ctx) & CTX_ENC == 0 && (inlen < 16 || inlen & 0x7 != 0) {
            return -1;
        }
        if bits(ctx) & CTX_PAD == 0 && inlen & 0x7 != 0 {
            return -1;
        }
        if out.is_null() {
            if bits(ctx) & CTX_ENC != 0 {
                let n = if bits(ctx) & CTX_PAD != 0 {
                    inlen.div_ceil(8) * 8
                } else {
                    inlen
                };
                return (n + 8) as c_int;
            }
            return (inlen - 8) as c_int;
        }
        let Some(block) = (*ctx).block else {
            // The authority calls the wrap function with a NULL `block128_f` and faults; a
            // probe cannot compare a crash, so the crate refuses where the authority would
            // call through the null. Recorded in docs/DECISIONS.md D230.
            return -1;
        };
        let Some(wrapfn) = (*wctx).wrapfn else {
            return -1;
        };
        let iv = if bits(ctx) & CTX_IV_SET != 0 {
            (*ctx).iv.as_ptr()
        } else {
            ptr::null()
        };
        let rv = wrapfn(
            ptr::addr_of_mut!((*wctx).ks).cast(),
            iv,
            out,
            input,
            inlen,
            block,
        );
        if rv == 0 || rv > c_int::MAX as usize {
            return -1;
        }
        rv as c_int
    }
}

/// `aes_wrap_final` — `cipher_aes_wrp.c:224-232`.
///
/// # Safety
/// `outl` is the caller's slot per the dispatch contract.
unsafe extern "C" fn aes_wrap_final(
    _vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    // SAFETY: `outl` is the caller's slot.
    unsafe { *outl = 0 };
    1
}

/// `aes_wrap_cipher` — `cipher_aes_wrp.c:234-260`.
///
/// # Safety
/// As the dispatch's `update`: `out` is writable for `outsize` bytes and `input` readable for
/// `inl`.
unsafe extern "C" fn aes_wrap_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    input: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        if inl == 0 {
            *outl = 0;
            return 1;
        }
        if outsize < inl {
            return 0;
        }
        let len = aes_wrap_cipher_internal(vctx, out, input, inl);
        if len <= 0 {
            return 0;
        }
        *outl = len as usize;
        1
    }
}

/// `aes_wrap_set_ctx_params` — `cipher_aes_wrp.c:262-283`.
///
/// # Safety
/// `vctx` is live; `params` is NULL or a key-terminated array.
unsafe extern "C" fn aes_wrap_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if ossl_param_is_empty(params) {
            return 1;
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() {
            let mut keylen = 0usize;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut keylen) == 0 {
                return 0;
            }
            if (*ctx).keylen != keylen {
                return 0;
            }
        }
        1
    }
}

/// `IMPLEMENT_cipher` — `cipher_aes_wrp.c:285-320`, one row's dispatch table.
///
/// A Rust macro here for the same reason `cipher_row!` is one: the authority's `IMPLEMENT_cipher`
/// is itself a macro, and the twelve rows differ only in their parameters. The output is
/// `pub(crate)`/private items and a `'static` table — **no exported symbol** — so the project's
/// ban on `macro_rules!`-generated exports is not engaged.
macro_rules! wrap_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr, $ivbits:expr, $flags:expr) => {
        unsafe extern "C" fn $newctx(_provctx: *mut c_void) -> *mut c_void {
            // SAFETY: this row's own parameters; the context is returned to the dispatch.
            unsafe { aes_wrap_newctx($kbits, 64, $ivbits, EVP_CIPH_WRAP_MODE, $flags) }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_WRAP_MODE,
                    $flags,
                    $kbits,
                    64,
                    $ivbits,
                )
            }
        }

        static $table: [OsslDispatch; 14] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: aes_wrap_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: aes_wrap_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: aes_wrap_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: aes_wrap_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FREECTX,
                function: aes_wrap_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
                function: aes_wrap_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: ossl_cipher_generic_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: aes_wrap_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: ossl_cipher_generic_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: ossl_cipher_generic_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

wrap_row!(
    aes256wrap_newctx,
    aes256wrap_get_params,
    AES256WRAP_FUNCTIONS,
    256,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes192wrap_newctx,
    aes192wrap_get_params,
    AES192WRAP_FUNCTIONS,
    192,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes128wrap_newctx,
    aes128wrap_get_params,
    AES128WRAP_FUNCTIONS,
    128,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes256wrappad_newctx,
    aes256wrappad_get_params,
    AES256WRAPPAD_FUNCTIONS,
    256,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes192wrappad_newctx,
    aes192wrappad_get_params,
    AES192WRAPPAD_FUNCTIONS,
    192,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes128wrappad_newctx,
    aes128wrappad_get_params,
    AES128WRAPPAD_FUNCTIONS,
    128,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS
);
wrap_row!(
    aes256wrapinv_newctx,
    aes256wrapinv_get_params,
    AES256WRAPINV_FUNCTIONS,
    256,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS_INV
);
wrap_row!(
    aes192wrapinv_newctx,
    aes192wrapinv_get_params,
    AES192WRAPINV_FUNCTIONS,
    192,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS_INV
);
wrap_row!(
    aes128wrapinv_newctx,
    aes128wrapinv_get_params,
    AES128WRAPINV_FUNCTIONS,
    128,
    AES_WRAP_NOPAD_IVLEN * 8,
    WRAP_FLAGS_INV
);
wrap_row!(
    aes256wrappadinv_newctx,
    aes256wrappadinv_get_params,
    AES256WRAPPADINV_FUNCTIONS,
    256,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS_INV
);
wrap_row!(
    aes192wrappadinv_newctx,
    aes192wrappadinv_get_params,
    AES192WRAPPADINV_FUNCTIONS,
    192,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS_INV
);
wrap_row!(
    aes128wrappadinv_newctx,
    aes128wrappadinv_get_params,
    AES128WRAPPADINV_FUNCTIONS,
    128,
    AES_WRAP_PAD_IVLEN * 8,
    WRAP_FLAGS_INV
);

// ---------------------------------------------------------------------------------------------
// `cipher_cts.c` — the CBC ciphertext-stealing rows (AES and Camellia)
// ---------------------------------------------------------------------------------------------
//
// `cipher_cts.c` is not a mode of its own: its rows reuse the generic engine's CBC hardware
// (`ossl_cipher_hw_generic_cbc`) and replace only the **update** and **final**, because ciphertext
// stealing is not a stream of block-mode calls — the last two blocks are processed together, so
// the whole message is one call. What makes the EVP layer hand this engine the whole call rather
// than its own partial-block buffer is `cts = 1` from `ossl_cipher_generic_get_params`, which
// `evp_cipher_cache_constants` (`crypto/evp/evp_lib.c:355`) turns into `EVP_CIPH_FLAG_CTS`.

/// `CTS_BLOCK_SIZE` — `cipher_cts.c:59`.
const CTS_BLOCK_SIZE: usize = 16;
/// `CTS_CS1` — `cipher_cts.c:55`. The value assigned to 0 is the default.
const CTS_CS1: c_uint = 0;
/// `CTS_CS2` — `cipher_cts.c:56`.
const CTS_CS2: c_uint = 1;
/// `CTS_CS3` — `cipher_cts.c:57`.
const CTS_CS3: c_uint = 2;
/// `OSSL_CIPHER_PARAM_CTS_MODE` — `include/openssl/core_names.h:191`.
const OSSL_CIPHER_PARAM_CTS_MODE: *const c_char = c"cts_mode".as_ptr();
/// `OSSL_CIPHER_CTS_MODE_CS1`/`_CS2`/`_CS3` — `include/openssl/core_names.h:25-27`, in `cts_modes`'
/// order (`cipher_cts.c:71-75`).
const CTS_MODE_NAMES: [*const c_char; 3] = [c"CS1".as_ptr(), c"CS2".as_ptr(), c"CS3".as_ptr()];

/// `ossl_cipher_cbc_cts_mode_id2name` — `cipher_cts.c:77-86`.
fn cts_mode_id2name(id: c_uint) -> *const c_char {
    let mut i = 0usize;
    while i < CTS_MODE_NAMES.len() {
        if id == i as c_uint {
            return CTS_MODE_NAMES[i];
        }
        i += 1;
    }
    ptr::null()
}

/// `ossl_cipher_cbc_cts_mode_name2id` — `cipher_cts.c:88-97`.
///
/// # Safety
/// `name` is NUL-terminated.
unsafe fn cts_mode_name2id(name: *const c_char) -> c_int {
    // SAFETY: the caller's contract; `OPENSSL_strcasecmp` reads both strings to their NUL.
    unsafe {
        let mut i = 0usize;
        while i < CTS_MODE_NAMES.len() {
            if crate::runtime::str::OPENSSL_strcasecmp(name, CTS_MODE_NAMES[i]) == 0 {
                return i as c_int;
            }
            i += 1;
        }
        -1
    }
}

/// `ctx->hw->cipher(ctx, out, in, len)` — the one call every CTS arm makes.
///
/// # Safety
/// `ctx` is live and the buffers hold `len` bytes.
#[inline]
unsafe fn cts_hw_cipher(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        let hw = (*ctx).hw;
        ((*hw).cipher)(ctx, out, in_, len) != 0
    }
}

/// `do_xor` — `cipher_cts.c:124-131`.
///
/// # Safety
/// The three buffers hold `len` bytes.
unsafe fn cts_do_xor(in1: *const c_uchar, in2: *const c_uchar, len: usize, out: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut i = 0usize;
        while i < len {
            *out.add(i) = *in1.add(i) ^ *in2.add(i);
            i += 1;
        }
    }
}

/// `cts128_cs1_encrypt` — `cipher_cts.c:99-122`.
///
/// # Safety
/// The buffers hold `len` bytes and `ctx` is live.
unsafe fn cts128_cs1_encrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let mut tmp_in = [0u8; CTS_BLOCK_SIZE];
        let residue = len % CTS_BLOCK_SIZE;
        let aligned = len - residue;
        if !cts_hw_cipher(ctx, out, in_, aligned) {
            return 0;
        }
        if residue == 0 {
            return aligned;
        }
        let in_ = in_.add(aligned);
        let out = out.add(aligned);
        ptr::copy_nonoverlapping(in_, tmp_in.as_mut_ptr(), residue);
        if !cts_hw_cipher(
            ctx,
            out.sub(CTS_BLOCK_SIZE).add(residue),
            tmp_in.as_ptr(),
            CTS_BLOCK_SIZE,
        ) {
            return 0;
        }
        aligned + residue
    }
}

/// `cts128_cs1_decrypt` — `cipher_cts.c:133-193`.
///
/// # Safety
/// The buffers hold `len` bytes and `ctx` is live.
unsafe fn cts128_cs1_decrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let mut mid_iv = [0u8; CTS_BLOCK_SIZE];
        let mut ct_mid = [0u8; CTS_BLOCK_SIZE];
        let mut cn = [0u8; CTS_BLOCK_SIZE];
        let mut pt_last = [0u8; CTS_BLOCK_SIZE];
        let residue = len % CTS_BLOCK_SIZE;
        if residue == 0 {
            // If there are no partial blocks then it is the same as CBC mode.
            return if cts_hw_cipher(ctx, out, in_, len) {
                len
            } else {
                0
            };
        }
        // Process blocks at the start - but leave the last 2 blocks.
        let head = len - CTS_BLOCK_SIZE - residue;
        let (in_, out) = if head > 0 {
            if !cts_hw_cipher(ctx, out, in_, head) {
                return 0;
            }
            (in_.add(head), out.add(head))
        } else {
            (in_, out)
        };
        // Save the iv that will be used by the second last block, and the C(n) block.
        ptr::copy_nonoverlapping((*ctx).iv.as_ptr(), mid_iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        ptr::copy_nonoverlapping(in_.add(residue), cn.as_mut_ptr(), CTS_BLOCK_SIZE);
        // Decrypt the last block first using an iv of zero.
        (*ctx).iv = [0u8; CTS_BLOCK_SIZE];
        if !cts_hw_cipher(ctx, pt_last.as_mut_ptr(), in_.add(residue), CTS_BLOCK_SIZE) {
            return 0;
        }
        // Rebuild the ciphertext of the second last block from the decrypted last block plus the
        // ciphertext bytes of the partial second last block.
        ptr::copy_nonoverlapping(in_, ct_mid.as_mut_ptr(), residue);
        ptr::copy_nonoverlapping(
            pt_last.as_ptr().add(residue),
            ct_mid.as_mut_ptr().add(residue),
            CTS_BLOCK_SIZE - residue,
        );
        cts_do_xor(
            ct_mid.as_ptr(),
            pt_last.as_ptr(),
            residue,
            out.add(CTS_BLOCK_SIZE),
        );
        // Restore the iv needed by the second last block and decrypt it.
        ptr::copy_nonoverlapping(mid_iv.as_ptr(), (*ctx).iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        if !cts_hw_cipher(ctx, out, ct_mid.as_ptr(), CTS_BLOCK_SIZE) {
            return 0;
        }
        // The returned iv is the C(n) block.
        ptr::copy_nonoverlapping(cn.as_ptr(), (*ctx).iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        head + CTS_BLOCK_SIZE + residue
    }
}

/// `cts128_cs3_encrypt` — `cipher_cts.c:195-225`.
///
/// # Safety
/// The buffers hold `len` bytes and `ctx` is live.
unsafe fn cts128_cs3_encrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len < CTS_BLOCK_SIZE {
            // CS3 requires at least one block.
            return 0;
        }
        if len == CTS_BLOCK_SIZE {
            return if cts_hw_cipher(ctx, out, in_, len) {
                len
            } else {
                0
            };
        }
        let residue = if len.is_multiple_of(CTS_BLOCK_SIZE) {
            CTS_BLOCK_SIZE
        } else {
            len % CTS_BLOCK_SIZE
        };
        let aligned = len - residue;
        if !cts_hw_cipher(ctx, out, in_, aligned) {
            return 0;
        }
        let in_ = in_.add(aligned);
        let out = out.add(aligned);
        let mut tmp_in = [0u8; CTS_BLOCK_SIZE];
        ptr::copy_nonoverlapping(in_, tmp_in.as_mut_ptr(), residue);
        ptr::copy_nonoverlapping(out.sub(CTS_BLOCK_SIZE), out, residue);
        if !cts_hw_cipher(
            ctx,
            out.sub(CTS_BLOCK_SIZE),
            tmp_in.as_ptr(),
            CTS_BLOCK_SIZE,
        ) {
            return 0;
        }
        aligned + residue
    }
}

/// `cts128_cs3_decrypt` — `cipher_cts.c:235-299`.
///
/// # Safety
/// The buffers hold `len` bytes and `ctx` is live.
unsafe fn cts128_cs3_decrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let mut mid_iv = [0u8; CTS_BLOCK_SIZE];
        let mut ct_mid = [0u8; CTS_BLOCK_SIZE];
        let mut cn = [0u8; CTS_BLOCK_SIZE];
        let mut pt_last = [0u8; CTS_BLOCK_SIZE];
        if len < CTS_BLOCK_SIZE {
            // CS3 requires at least one block.
            return 0;
        }
        if len == CTS_BLOCK_SIZE {
            return if cts_hw_cipher(ctx, out, in_, len) {
                len
            } else {
                0
            };
        }
        let residue = if len.is_multiple_of(CTS_BLOCK_SIZE) {
            CTS_BLOCK_SIZE
        } else {
            len % CTS_BLOCK_SIZE
        };
        // Process blocks at the start - but leave the last 2 blocks.
        let head = len - CTS_BLOCK_SIZE - residue;
        let (in_, out) = if head > 0 {
            if !cts_hw_cipher(ctx, out, in_, head) {
                return 0;
            }
            (in_.add(head), out.add(head))
        } else {
            (in_, out)
        };
        // Save the iv for the second last block and the C(n) block. For CS3 the input is
        // C(1)||...||C(n-2)||C(n)||C(n-1)*, so C(n) is at `in`.
        ptr::copy_nonoverlapping((*ctx).iv.as_ptr(), mid_iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        ptr::copy_nonoverlapping(in_, cn.as_mut_ptr(), CTS_BLOCK_SIZE);
        // Decrypt the C(n) block first using an iv of zero.
        (*ctx).iv = [0u8; CTS_BLOCK_SIZE];
        if !cts_hw_cipher(ctx, pt_last.as_mut_ptr(), in_, CTS_BLOCK_SIZE) {
            return 0;
        }
        // Rebuild the ciphertext of C(n-1) from the decrypted C(n) plus the partial last block.
        ptr::copy_nonoverlapping(in_.add(CTS_BLOCK_SIZE), ct_mid.as_mut_ptr(), residue);
        if residue != CTS_BLOCK_SIZE {
            ptr::copy_nonoverlapping(
                pt_last.as_ptr().add(residue),
                ct_mid.as_mut_ptr().add(residue),
                CTS_BLOCK_SIZE - residue,
            );
        }
        cts_do_xor(
            ct_mid.as_ptr(),
            pt_last.as_ptr(),
            residue,
            out.add(CTS_BLOCK_SIZE),
        );
        // Restore the iv for the second last block and decrypt it.
        ptr::copy_nonoverlapping(mid_iv.as_ptr(), (*ctx).iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        if !cts_hw_cipher(ctx, out, ct_mid.as_ptr(), CTS_BLOCK_SIZE) {
            return 0;
        }
        // The returned iv is the C(n) block.
        ptr::copy_nonoverlapping(cn.as_ptr(), (*ctx).iv.as_mut_ptr(), CTS_BLOCK_SIZE);
        head + CTS_BLOCK_SIZE + residue
    }
}

/// `cts128_cs2_encrypt` — `cipher_cts.c:301-312`. For partial blocks CS2 is CS3.
///
/// # Safety
/// As [`cts128_cs3_encrypt`].
unsafe fn cts128_cs2_encrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len.is_multiple_of(CTS_BLOCK_SIZE) {
            return if cts_hw_cipher(ctx, out, in_, len) {
                len
            } else {
                0
            };
        }
        cts128_cs3_encrypt(ctx, in_, out, len)
    }
}

/// `cts128_cs2_decrypt` — `cipher_cts.c:314-325`.
///
/// # Safety
/// As [`cts128_cs3_decrypt`].
unsafe fn cts128_cs2_decrypt(
    ctx: *mut ProvCipherCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len.is_multiple_of(CTS_BLOCK_SIZE) {
            return if cts_hw_cipher(ctx, out, in_, len) {
                len
            } else {
                0
            };
        }
        cts128_cs3_decrypt(ctx, in_, out, len)
    }
}

/// `ossl_cipher_cbc_cts_block_update` — `cipher_cts.c:327-370`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_cipher_cbc_cts_block_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        if inl < CTS_BLOCK_SIZE {
            // There must be at least one block for CTS mode.
            return fail();
        }
        if outsize < inl {
            return fail();
        }
        if out.is_null() {
            *outl = inl;
            return 1;
        }
        // Only one shot is supported.
        if bits(ctx) & CTX_UPDATED != 0 {
            return fail();
        }
        let sz = if bits(ctx) & CTX_ENC != 0 {
            match (*ctx).cts_mode {
                CTS_CS1 => cts128_cs1_encrypt(ctx, in_, out, inl),
                CTS_CS2 => cts128_cs2_encrypt(ctx, in_, out, inl),
                CTS_CS3 => cts128_cs3_encrypt(ctx, in_, out, inl),
                _ => 0,
            }
        } else {
            match (*ctx).cts_mode {
                CTS_CS1 => cts128_cs1_decrypt(ctx, in_, out, inl),
                CTS_CS2 => cts128_cs2_decrypt(ctx, in_, out, inl),
                CTS_CS3 => cts128_cs3_decrypt(ctx, in_, out, inl),
                _ => 0,
            }
        };
        if sz == 0 {
            return fail();
        }
        bits_set(ctx, CTX_UPDATED, true);
        *outl = sz;
        1
    }
}

/// `ossl_cipher_cbc_cts_block_final` — `cipher_cts.c:372-377`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_cipher_cbc_cts_block_final(
    _vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { *outl = 0 };
    1
}

/// `aes_cbc_cts_einit` / `camellia_cbc_cts_einit` — `cipher_aes_cts.inc:28-35` and
/// `cipher_camellia_cts.inc:28-35`, whose bodies are identical: the generic init with no params,
/// then the row's `set_ctx_params` so a `cts_mode` passed to the init call is applied.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract; the generic init reads `params` only if non-NULL.
    unsafe {
        if ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, ptr::null()) == 0 {
            return fail();
        }
        cts_set_ctx_params(vctx, params)
    }
}

/// `aes_cbc_cts_dinit` / `camellia_cbc_cts_dinit` — the pair's decrypt arm.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, ptr::null()) == 0 {
            return fail();
        }
        cts_set_ctx_params(vctx, params)
    }
}

/// `aes_cbc_cts_get_ctx_params` / `camellia_cbc_cts_get_ctx_params` — `cipher_aes_cts.inc:46-61`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if !p.is_null() {
            let name = cts_mode_id2name((*ctx).cts_mode);
            if name.is_null() || crate::params::OSSL_PARAM_set_utf8_string(p, name) == 0 {
                return fail();
            }
        }
        ossl_cipher_generic_get_ctx_params(vctx, params)
    }
}

/// `aes_cbc_cts_set_ctx_params` / `camellia_cbc_cts_set_ctx_params` — `cipher_aes_cts.inc:67-87`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                return fail();
            }
            let id = cts_mode_name2id((*p).data.cast());
            if id < 0 {
                return fail();
            }
            (*ctx).cts_mode = id as c_uint;
        }
        ossl_cipher_generic_set_ctx_params(vctx, params)
    }
}

/// `CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_*` with the `cts_mode` row — `cipher_aes_cts.inc:24-26`.
static CTS_GETTABLE_CTX_PARAMS: [OsslParam; 9] = [
    param(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING),
    param(OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR),
    param(OSSL_CIPHER_PARAM_CTS_MODE, OSSL_PARAM_UTF8_STRING),
    END,
];

/// `aes_cbc_cts_gettable_ctx_params` / `camellia_cbc_cts_gettable_ctx_params`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CTS_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_*` with the `cts_mode` row — `cipher_aes_cts.inc:63-65`.
static CTS_SETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_USE_BITS, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_VERSION, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_CTS_MODE, OSSL_PARAM_UTF8_STRING),
    END,
];

/// `aes_cbc_cts_settable_ctx_params` / `camellia_cbc_cts_settable_ctx_params`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cts_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CTS_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `IMPLEMENT_cts_cipher` — `cipher_cts.h:13-46`. The table has fourteen entries and, unlike
/// `IMPLEMENT_generic_cipher`'s, publishes **no** `skey` init pair; it does publish the one-shot
/// `CIPHER`, which is what makes the EVP layer's provider arm hand this engine the whole call.
///
/// The output is `pub(crate)` items and a `'static` table — **no exported symbol** — so the ban
/// on `macro_rules!`-generated exports is not engaged (the note above `cipher_row!` has the
/// reasoning). One direct invocation per row, so `prototype_court.py`'s macro plane can read
/// every `fn $newctx(`.
macro_rules! cts_row {
    ($newctx:ident, $getparams:ident, $table:ident, $ctx:ty, $hw:path, $kbits:expr,
     $freectx:path, $dupctx:path) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            if is_running() == 0 {
                return ptr::null_mut();
            }
            let ctx = CRYPTO_zalloc(core::mem::size_of::<$ctx>(), FILE, LINE);
            if !ctx.is_null() {
                // SAFETY: `ctx` is a fresh zeroed context of this row's type.
                unsafe {
                    ossl_cipher_generic_initkey(
                        ctx,
                        $kbits,
                        128,
                        128,
                        EVP_CIPH_CBC_MODE,
                        PROV_CIPHER_FLAG_CTS,
                        ptr::addr_of!($hw),
                        provctx,
                    );
                }
            }
            ctx
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_CBC_MODE,
                    PROV_CIPHER_FLAG_CTS,
                    $kbits,
                    128,
                    128,
                )
            }
        }

        pub(crate) static $table: [OsslDispatch; 15] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FREECTX,
                function: $freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
                function: $dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: cts_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: cts_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: ossl_cipher_cbc_cts_block_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: ossl_cipher_cbc_cts_block_final as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
                function: ossl_cipher_generic_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: cts_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: cts_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: cts_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: cts_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

cts_row!(
    aes128cbc_cts_newctx,
    aes128cbc_cts_get_params,
    AES128CBCCTS_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    128,
    aes_freectx,
    aes_dupctx
);
cts_row!(
    aes192cbc_cts_newctx,
    aes192cbc_cts_get_params,
    AES192CBCCTS_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    192,
    aes_freectx,
    aes_dupctx
);
cts_row!(
    aes256cbc_cts_newctx,
    aes256cbc_cts_get_params,
    AES256CBCCTS_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    256,
    aes_freectx,
    aes_dupctx
);
cts_row!(
    camellia128cbc_cts_newctx,
    camellia128cbc_cts_get_params,
    CAMELLIA128CBCCTS_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    128,
    camellia_freectx,
    camellia_dupctx
);
cts_row!(
    camellia192cbc_cts_newctx,
    camellia192cbc_cts_get_params,
    CAMELLIA192CBCCTS_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    192,
    camellia_freectx,
    camellia_dupctx
);
cts_row!(
    camellia256cbc_cts_newctx,
    camellia256cbc_cts_get_params,
    CAMELLIA256CBCCTS_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    256,
    camellia_freectx,
    camellia_dupctx
);

// One direct `cipher_row!` per row: no wrapper macro, so `prototype_court.py`'s macro plane
// can read every `fn $newctx(` and substitute the identifier this invocation supplies.
cipher_row!(
    aes256ecb_newctx,
    aes256ecb_get_params,
    AES256ECB_FUNCTIONS,
    ProvAesCtx,
    AES_ECB_HW,
    256,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192ecb_newctx,
    aes192ecb_get_params,
    AES192ECB_FUNCTIONS,
    ProvAesCtx,
    AES_ECB_HW,
    192,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128ecb_newctx,
    aes128ecb_get_params,
    AES128ECB_FUNCTIONS,
    ProvAesCtx,
    AES_ECB_HW,
    128,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256cbc_newctx,
    aes256cbc_get_params,
    AES256CBC_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    256,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192cbc_newctx,
    aes192cbc_get_params,
    AES192CBC_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    192,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128cbc_newctx,
    aes128cbc_get_params,
    AES128CBC_FUNCTIONS,
    ProvAesCtx,
    AES_CBC_HW,
    128,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256ofb_newctx,
    aes256ofb_get_params,
    AES256OFB_FUNCTIONS,
    ProvAesCtx,
    AES_OFB_HW,
    256,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192ofb_newctx,
    aes192ofb_get_params,
    AES192OFB_FUNCTIONS,
    ProvAesCtx,
    AES_OFB_HW,
    192,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128ofb_newctx,
    aes128ofb_get_params,
    AES128OFB_FUNCTIONS,
    ProvAesCtx,
    AES_OFB_HW,
    128,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256cfb_newctx,
    aes256cfb_get_params,
    AES256CFB_FUNCTIONS,
    ProvAesCtx,
    AES_CFB_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192cfb_newctx,
    aes192cfb_get_params,
    AES192CFB_FUNCTIONS,
    ProvAesCtx,
    AES_CFB_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128cfb_newctx,
    aes128cfb_get_params,
    AES128CFB_FUNCTIONS,
    ProvAesCtx,
    AES_CFB_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256cfb1_newctx,
    aes256cfb1_get_params,
    AES256CFB1_FUNCTIONS,
    ProvAesCtx,
    AES_CFB1_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192cfb1_newctx,
    aes192cfb1_get_params,
    AES192CFB1_FUNCTIONS,
    ProvAesCtx,
    AES_CFB1_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128cfb1_newctx,
    aes128cfb1_get_params,
    AES128CFB1_FUNCTIONS,
    ProvAesCtx,
    AES_CFB1_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256cfb8_newctx,
    aes256cfb8_get_params,
    AES256CFB8_FUNCTIONS,
    ProvAesCtx,
    AES_CFB8_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192cfb8_newctx,
    aes192cfb8_get_params,
    AES192CFB8_FUNCTIONS,
    ProvAesCtx,
    AES_CFB8_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128cfb8_newctx,
    aes128cfb8_get_params,
    AES128CFB8_FUNCTIONS,
    ProvAesCtx,
    AES_CFB8_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes256ctr_newctx,
    aes256ctr_get_params,
    AES256CTR_FUNCTIONS,
    ProvAesCtx,
    AES_CTR_HW,
    256,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes192ctr_newctx,
    aes192ctr_get_params,
    AES192CTR_FUNCTIONS,
    ProvAesCtx,
    AES_CTR_HW,
    192,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    aes128ctr_newctx,
    aes128ctr_get_params,
    AES128CTR_FUNCTIONS,
    ProvAesCtx,
    AES_CTR_HW,
    128,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aes_freectx,
    aes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256ecb_newctx,
    camellia256ecb_get_params,
    CAMELLIA256ECB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_ECB_HW,
    256,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192ecb_newctx,
    camellia192ecb_get_params,
    CAMELLIA192ECB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_ECB_HW,
    192,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128ecb_newctx,
    camellia128ecb_get_params,
    CAMELLIA128ECB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_ECB_HW,
    128,
    128,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256cbc_newctx,
    camellia256cbc_get_params,
    CAMELLIA256CBC_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    256,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192cbc_newctx,
    camellia192cbc_get_params,
    CAMELLIA192CBC_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    192,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128cbc_newctx,
    camellia128cbc_get_params,
    CAMELLIA128CBC_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CBC_HW,
    128,
    128,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256ofb_newctx,
    camellia256ofb_get_params,
    CAMELLIA256OFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_OFB_HW,
    256,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192ofb_newctx,
    camellia192ofb_get_params,
    CAMELLIA192OFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_OFB_HW,
    192,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128ofb_newctx,
    camellia128ofb_get_params,
    CAMELLIA128OFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_OFB_HW,
    128,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256cfb_newctx,
    camellia256cfb_get_params,
    CAMELLIA256CFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192cfb_newctx,
    camellia192cfb_get_params,
    CAMELLIA192CFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128cfb_newctx,
    camellia128cfb_get_params,
    CAMELLIA128CFB_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256cfb1_newctx,
    camellia256cfb1_get_params,
    CAMELLIA256CFB1_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB1_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192cfb1_newctx,
    camellia192cfb1_get_params,
    CAMELLIA192CFB1_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB1_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128cfb1_newctx,
    camellia128cfb1_get_params,
    CAMELLIA128CFB1_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB1_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256cfb8_newctx,
    camellia256cfb8_get_params,
    CAMELLIA256CFB8_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB8_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192cfb8_newctx,
    camellia192cfb8_get_params,
    CAMELLIA192CFB8_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB8_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128cfb8_newctx,
    camellia128cfb8_get_params,
    CAMELLIA128CFB8_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CFB8_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia256ctr_newctx,
    camellia256ctr_get_params,
    CAMELLIA256CTR_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CTR_HW,
    256,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia192ctr_newctx,
    camellia192ctr_get_params,
    CAMELLIA192CTR_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CTR_HW,
    192,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    camellia128ctr_newctx,
    camellia128ctr_get_params,
    CAMELLIA128CTR_FUNCTIONS,
    ProvCamelliaCtx,
    CAMELLIA_CTR_HW,
    128,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    camellia_freectx,
    camellia_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

cipher_row!(
    tdes_ede3_ecb_newctx,
    tdes_ede3_ecb_get_params,
    TDES_EDE3_ECB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_ECB_HW,
    192,
    64,
    0,
    EVP_CIPH_ECB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede3_cbc_newctx,
    tdes_ede3_cbc_get_params,
    TDES_EDE3_CBC_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_CBC_HW,
    192,
    64,
    64,
    EVP_CIPH_CBC_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede3_ofb_newctx,
    tdes_ede3_ofb_get_params,
    TDES_EDE3_OFB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_OFB_HW,
    192,
    8,
    64,
    EVP_CIPH_OFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede3_cfb_newctx,
    tdes_ede3_cfb_get_params,
    TDES_EDE3_CFB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_CFB_HW,
    192,
    8,
    64,
    EVP_CIPH_CFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede3_cfb1_newctx,
    tdes_ede3_cfb1_get_params,
    TDES_EDE3_CFB1_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_CFB1_HW,
    192,
    8,
    64,
    EVP_CIPH_CFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede3_cfb8_newctx,
    tdes_ede3_cfb8_get_params,
    TDES_EDE3_CFB8_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE3_CFB8_HW,
    192,
    8,
    64,
    EVP_CIPH_CFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede2_ecb_newctx,
    tdes_ede2_ecb_get_params,
    TDES_EDE2_ECB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE2_ECB_HW,
    128,
    64,
    0,
    EVP_CIPH_ECB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede2_cbc_newctx,
    tdes_ede2_cbc_get_params,
    TDES_EDE2_CBC_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE2_CBC_HW,
    128,
    64,
    64,
    EVP_CIPH_CBC_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede2_ofb_newctx,
    tdes_ede2_ofb_get_params,
    TDES_EDE2_OFB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE2_OFB_HW,
    128,
    8,
    64,
    EVP_CIPH_OFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

cipher_row!(
    tdes_ede2_cfb_newctx,
    tdes_ede2_cfb_get_params,
    TDES_EDE2_CFB_FUNCTIONS,
    ProvTdesCtx,
    TDES_EDE2_CFB_HW,
    128,
    8,
    64,
    EVP_CIPH_CFB_MODE,
    TDES_FLAGS,
    tdes_freectx,
    tdes_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_tdes_get_params,
    ossl_tdes_get_ctx_params,
    ossl_tdes_set_ctx_params,
    ossl_tdes_gettable_ctx_params,
    ossl_tdes_settable_ctx_params
);

// ---------------------------------------------------------------------------------------------
// `cipher_null.c`
// ---------------------------------------------------------------------------------------------

/// `PROV_CIPHER_NULL_CTX` — `cipher_null.c:18-22`.
#[repr(C)]
struct ProvNullCtx {
    /// `int enc`.
    enc: c_int,
    /// `size_t tlsmacsize`.
    tlsmacsize: usize,
    /// `const unsigned char *tlsmac`.
    tlsmac: *const c_uchar,
}

/// `null_newctx` — `cipher_null.c:24-31`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_newctx(_provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    CRYPTO_zalloc(core::mem::size_of::<ProvNullCtx>(), FILE, LINE)
}

/// `null_freectx` — `cipher_null.c:33-37`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `null_newctx` allocated.
    unsafe { CRYPTO_clear_free(vctx, core::mem::size_of::<ProvNullCtx>(), FILE, LINE) };
}

/// `null_einit` — `cipher_null.c:39-51`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_einit(
    vctx: *mut c_void,
    _key: *const c_uchar,
    _keylen: usize,
    _iv: *const c_uchar,
    _ivlen: usize,
    _params: *const OsslParam,
) -> c_int {
    if is_running() == 0 {
        return fail();
    }
    // SAFETY: the caller's contract.
    unsafe {
        (*vctx.cast::<ProvNullCtx>()).enc = 1;
    }
    1
}

/// `null_dinit` — `cipher_null.c:53-62`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_dinit(
    _vctx: *mut c_void,
    _key: *const c_uchar,
    _keylen: usize,
    _iv: *const c_uchar,
    _ivlen: usize,
    _params: *const OsslParam,
) -> c_int {
    if is_running() == 0 {
        return fail();
    }
    1
}

/// `null_cipher` — `cipher_null.c:64-89`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return fail();
        }
        let ctx = vctx.cast::<ProvNullCtx>();
        let mut inl = inl;
        if (*ctx).enc == 0 && (*ctx).tlsmacsize > 0 {
            if inl < (*ctx).tlsmacsize {
                return fail();
            }
            (*ctx).tlsmac = in_.add(inl - (*ctx).tlsmacsize);
            inl -= (*ctx).tlsmacsize;
        }
        if outsize < inl {
            return fail();
        }
        if !out.is_null() && in_ != out {
            ptr::copy_nonoverlapping(in_, out, inl);
        }
        *outl = inl;
        1
    }
}

/// `null_final` — `cipher_null.c:91-100`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_final(
    _vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    if is_running() == 0 {
        return fail();
    }
    // SAFETY: the out-parameter is the caller's.
    unsafe {
        *outl = 0;
    }
    1
}

/// `null_get_params` — `cipher_null.c:102-106`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_get_params(params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ossl_cipher_generic_get_params(params, 0, 0, 0, 8, 0) }
}

/// `null_known_gettable_ctx_params` — `cipher_null.c:108-113`.
static NULL_GETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    param(OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR),
    END,
];

/// `null_gettable_ctx_params` — `cipher_null.c:115-120`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    NULL_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `null_get_ctx_params` — `cipher_null.c:122-145`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvNullCtx>();
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, 0) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, 0) == 0 {
            return fail();
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_ptr(p, (*ctx).tlsmac.cast(), (*ctx).tlsmacsize)
                == 0
        {
            return fail();
        }
        1
    }
}

/// `null_known_settable_ctx_params` — `cipher_null.c:147-150`.
static NULL_SETTABLE_CTX_PARAMS: [OsslParam; 2] = [
    param(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    END,
];

/// `null_settable_ctx_params` — `cipher_null.c:152-157`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    NULL_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `null_set_ctx_params` — `cipher_null.c:159-174`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn null_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvNullCtx>();
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_get_size_t(p, &mut (*ctx).tlsmacsize) == 0 {
            return fail();
        }
        1
    }
}

/// `ossl_null_functions` — `cipher_null.c:176-196`.
pub(crate) static NULL_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_NEWCTX,
        function: null_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FREECTX,
        function: null_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
        function: null_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
        function: null_einit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
        function: null_dinit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_UPDATE,
        function: null_cipher as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FINAL,
        function: null_final as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
        function: null_cipher as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
        function: null_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        function: ossl_cipher_generic_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        function: null_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        function: null_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        function: null_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        function: null_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// ---------------------------------------------------------------------------------------------
// `deflt_ciphers[]` — the rows, in `defltprov.c`'s order
// ---------------------------------------------------------------------------------------------

/// A row's alias string, verbatim from `providers/implementations/include/prov/names.h`.
macro_rules! alias {
    ($name:ident, $value:literal) => {
        const $name: *const c_char = concat!($value, "\0").as_ptr().cast();
    };
}
alias!(N_NULL, "NULL");
alias!(N_AES_256_ECB, "AES-256-ECB:2.16.840.1.101.3.4.1.41");
alias!(N_AES_192_ECB, "AES-192-ECB:2.16.840.1.101.3.4.1.21");
alias!(N_AES_128_ECB, "AES-128-ECB:2.16.840.1.101.3.4.1.1");
alias!(N_AES_256_CBC, "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42");
alias!(N_AES_192_CBC, "AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22");
alias!(N_AES_128_CBC, "AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2");
alias!(N_AES_128_CBC_CTS, "AES-128-CBC-CTS");
alias!(N_AES_192_CBC_CTS, "AES-192-CBC-CTS");
alias!(N_AES_256_CBC_CTS, "AES-256-CBC-CTS");
alias!(N_AES_256_OFB, "AES-256-OFB:2.16.840.1.101.3.4.1.43");
alias!(N_AES_192_OFB, "AES-192-OFB:2.16.840.1.101.3.4.1.23");
alias!(N_AES_128_OFB, "AES-128-OFB:2.16.840.1.101.3.4.1.3");
alias!(N_AES_256_CFB, "AES-256-CFB:2.16.840.1.101.3.4.1.44");
alias!(N_AES_192_CFB, "AES-192-CFB:2.16.840.1.101.3.4.1.24");
alias!(N_AES_128_CFB, "AES-128-CFB:2.16.840.1.101.3.4.1.4");
alias!(N_AES_256_CFB1, "AES-256-CFB1");
alias!(N_AES_192_CFB1, "AES-192-CFB1");
alias!(N_AES_128_CFB1, "AES-128-CFB1");
alias!(N_AES_256_CFB8, "AES-256-CFB8");
alias!(N_AES_192_CFB8, "AES-192-CFB8");
alias!(N_AES_128_CFB8, "AES-128-CFB8");
alias!(N_AES_256_CTR, "AES-256-CTR");
alias!(N_AES_192_CTR, "AES-192-CTR");
alias!(N_AES_128_CTR, "AES-128-CTR");
alias!(N_CAMELLIA_256_ECB, "CAMELLIA-256-ECB:0.3.4401.5.3.1.9.41");
alias!(N_CAMELLIA_192_ECB, "CAMELLIA-192-ECB:0.3.4401.5.3.1.9.21");
alias!(N_CAMELLIA_128_ECB, "CAMELLIA-128-ECB:0.3.4401.5.3.1.9.1");
alias!(
    N_CAMELLIA_256_CBC,
    "CAMELLIA-256-CBC:CAMELLIA256:1.2.392.200011.61.1.1.1.4"
);
alias!(
    N_CAMELLIA_192_CBC,
    "CAMELLIA-192-CBC:CAMELLIA192:1.2.392.200011.61.1.1.1.3"
);
alias!(
    N_CAMELLIA_128_CBC,
    "CAMELLIA-128-CBC:CAMELLIA128:1.2.392.200011.61.1.1.1.2"
);
alias!(N_CAMELLIA_128_CBC_CTS, "CAMELLIA-128-CBC-CTS");
alias!(N_CAMELLIA_192_CBC_CTS, "CAMELLIA-192-CBC-CTS");
alias!(N_CAMELLIA_256_CBC_CTS, "CAMELLIA-256-CBC-CTS");
alias!(N_CAMELLIA_256_OFB, "CAMELLIA-256-OFB:0.3.4401.5.3.1.9.43");
alias!(N_CAMELLIA_192_OFB, "CAMELLIA-192-OFB:0.3.4401.5.3.1.9.23");
alias!(N_CAMELLIA_128_OFB, "CAMELLIA-128-OFB:0.3.4401.5.3.1.9.3");
alias!(N_CAMELLIA_256_CFB, "CAMELLIA-256-CFB:0.3.4401.5.3.1.9.44");
alias!(N_CAMELLIA_192_CFB, "CAMELLIA-192-CFB:0.3.4401.5.3.1.9.24");
alias!(N_CAMELLIA_128_CFB, "CAMELLIA-128-CFB:0.3.4401.5.3.1.9.4");
alias!(N_CAMELLIA_256_CFB1, "CAMELLIA-256-CFB1");
alias!(N_CAMELLIA_192_CFB1, "CAMELLIA-192-CFB1");
alias!(N_CAMELLIA_128_CFB1, "CAMELLIA-128-CFB1");
alias!(N_CAMELLIA_256_CFB8, "CAMELLIA-256-CFB8");
alias!(N_CAMELLIA_192_CFB8, "CAMELLIA-192-CFB8");
alias!(N_CAMELLIA_128_CFB8, "CAMELLIA-128-CFB8");
alias!(N_CAMELLIA_256_CTR, "CAMELLIA-256-CTR:0.3.4401.5.3.1.9.49");
alias!(N_CAMELLIA_192_CTR, "CAMELLIA-192-CTR:0.3.4401.5.3.1.9.29");
alias!(N_CAMELLIA_128_CTR, "CAMELLIA-128-CTR:0.3.4401.5.3.1.9.9");
alias!(N_DES_EDE3_ECB, "DES-EDE3-ECB:DES-EDE3");
alias!(N_DES_EDE3_CBC, "DES-EDE3-CBC:DES3:1.2.840.113549.3.7");
alias!(N_DES_EDE3_OFB, "DES-EDE3-OFB");
alias!(N_DES_EDE3_CFB, "DES-EDE3-CFB");
alias!(N_DES_EDE3_CFB8, "DES-EDE3-CFB8");
alias!(N_DES_EDE3_CFB1, "DES-EDE3-CFB1");
alias!(N_DES_EDE_ECB, "DES-EDE-ECB:DES-EDE:1.3.14.3.2.17");
alias!(N_DES_EDE_CBC, "DES-EDE-CBC");
alias!(N_DES_EDE_OFB, "DES-EDE-OFB");
alias!(N_DES_EDE_CFB, "DES-EDE-CFB");
alias!(
    N_AES_256_WRAP,
    "AES-256-WRAP:id-aes256-wrap:AES256-WRAP:2.16.840.1.101.3.4.1.45"
);
alias!(
    N_AES_192_WRAP,
    "AES-192-WRAP:id-aes192-wrap:AES192-WRAP:2.16.840.1.101.3.4.1.25"
);
alias!(
    N_AES_128_WRAP,
    "AES-128-WRAP:id-aes128-wrap:AES128-WRAP:2.16.840.1.101.3.4.1.5"
);
alias!(
    N_AES_256_WRAP_PAD,
    "AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD:2.16.840.1.101.3.4.1.48"
);
alias!(
    N_AES_192_WRAP_PAD,
    "AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD:2.16.840.1.101.3.4.1.28"
);
alias!(
    N_AES_128_WRAP_PAD,
    "AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD:2.16.840.1.101.3.4.1.8"
);
alias!(N_AES_256_WRAP_INV, "AES-256-WRAP-INV:AES256-WRAP-INV");
alias!(N_AES_192_WRAP_INV, "AES-192-WRAP-INV:AES192-WRAP-INV");
alias!(N_AES_128_WRAP_INV, "AES-128-WRAP-INV:AES128-WRAP-INV");
alias!(
    N_AES_256_WRAP_PAD_INV,
    "AES-256-WRAP-PAD-INV:AES256-WRAP-PAD-INV"
);
alias!(
    N_AES_192_WRAP_PAD_INV,
    "AES-192-WRAP-PAD-INV:AES192-WRAP-PAD-INV"
);
alias!(
    N_AES_128_WRAP_PAD_INV,
    "AES-128-WRAP-PAD-INV:AES128-WRAP-PAD-INV"
);

/// A `deflt_ciphers[]` row.
const fn row(names: *const c_char, implementation: *const c_void) -> OsslAlgorithm {
    OsslAlgorithm {
        algorithm_names: names,
        property_definition: ptr::null(),
        implementation,
        algorithm_description: ptr::null(),
    }
}

/// `static const OSSL_ALGORITHM_CAPABLE deflt_ciphers[]` — `providers/defltprov.c:161-330`,
/// restricted to the rows this half implements, in the authority's order.
pub(crate) static DEFLT_CIPHERS: [OsslAlgorithm; 72] = [
    row(N_NULL, NULL_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_ECB, AES256ECB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_ECB, AES192ECB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_ECB, AES128ECB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CBC, AES256CBC_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CBC, AES192CBC_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CBC, AES128CBC_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CBC_CTS, AES128CBCCTS_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CBC_CTS, AES192CBCCTS_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CBC_CTS, AES256CBCCTS_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_OFB, AES256OFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_OFB, AES192OFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_OFB, AES128OFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CFB, AES256CFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CFB, AES192CFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CFB, AES128CFB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CFB1, AES256CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CFB1, AES192CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CFB1, AES128CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CFB8, AES256CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CFB8, AES192CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CFB8, AES128CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CTR, AES256CTR_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CTR, AES192CTR_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CTR, AES128CTR_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_WRAP, AES256WRAP_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_WRAP, AES192WRAP_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_WRAP, AES128WRAP_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_WRAP_PAD, AES256WRAPPAD_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_WRAP_PAD, AES192WRAPPAD_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_WRAP_PAD, AES128WRAPPAD_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_WRAP_INV, AES256WRAPINV_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_WRAP_INV, AES192WRAPINV_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_WRAP_INV, AES128WRAPINV_FUNCTIONS.as_ptr().cast()),
    row(
        N_AES_256_WRAP_PAD_INV,
        AES256WRAPPADINV_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_AES_192_WRAP_PAD_INV,
        AES192WRAPPADINV_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_AES_128_WRAP_PAD_INV,
        AES128WRAPPADINV_FUNCTIONS.as_ptr().cast(),
    ),
    row(N_CAMELLIA_256_ECB, CAMELLIA256ECB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_192_ECB, CAMELLIA192ECB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_128_ECB, CAMELLIA128ECB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_256_CBC, CAMELLIA256CBC_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_192_CBC, CAMELLIA192CBC_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_128_CBC, CAMELLIA128CBC_FUNCTIONS.as_ptr().cast()),
    row(
        N_CAMELLIA_128_CBC_CTS,
        CAMELLIA128CBCCTS_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_192_CBC_CTS,
        CAMELLIA192CBCCTS_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_256_CBC_CTS,
        CAMELLIA256CBCCTS_FUNCTIONS.as_ptr().cast(),
    ),
    row(N_CAMELLIA_256_OFB, CAMELLIA256OFB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_192_OFB, CAMELLIA192OFB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_128_OFB, CAMELLIA128OFB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_256_CFB, CAMELLIA256CFB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_192_CFB, CAMELLIA192CFB_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_128_CFB, CAMELLIA128CFB_FUNCTIONS.as_ptr().cast()),
    row(
        N_CAMELLIA_256_CFB1,
        CAMELLIA256CFB1_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_192_CFB1,
        CAMELLIA192CFB1_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_128_CFB1,
        CAMELLIA128CFB1_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_256_CFB8,
        CAMELLIA256CFB8_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_192_CFB8,
        CAMELLIA192CFB8_FUNCTIONS.as_ptr().cast(),
    ),
    row(
        N_CAMELLIA_128_CFB8,
        CAMELLIA128CFB8_FUNCTIONS.as_ptr().cast(),
    ),
    row(N_CAMELLIA_256_CTR, CAMELLIA256CTR_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_192_CTR, CAMELLIA192CTR_FUNCTIONS.as_ptr().cast()),
    row(N_CAMELLIA_128_CTR, CAMELLIA128CTR_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_ECB, TDES_EDE3_ECB_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_CBC, TDES_EDE3_CBC_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_OFB, TDES_EDE3_OFB_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_CFB, TDES_EDE3_CFB_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_CFB8, TDES_EDE3_CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE3_CFB1, TDES_EDE3_CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE_ECB, TDES_EDE2_ECB_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE_CBC, TDES_EDE2_CBC_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE_OFB, TDES_EDE2_OFB_FUNCTIONS.as_ptr().cast()),
    row(N_DES_EDE_CFB, TDES_EDE2_CFB_FUNCTIONS.as_ptr().cast()),
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::AES_MAXNR;

    #[test]
    fn the_cipher_table_terminates_and_names_the_rows() {
        assert_eq!(DEFLT_CIPHERS.len(), 72);
        // SAFETY: every entry up to the terminator is initialised.
        let last = DEFLT_CIPHERS[71].algorithm_names;
        assert!(last.is_null(), "the table is NULL-name terminated");
        // SAFETY: the first row's name is a `'static` C string.
        let first = unsafe { core::ffi::CStr::from_ptr(DEFLT_CIPHERS[0].algorithm_names) };
        assert_eq!(first.to_bytes(), b"NULL");
    }

    #[test]
    fn the_generic_engine_pads_an_ecb_block() {
        let mut ctx = ProvAesCtx {
            base: ProvCipherCtx {
                oiv: [0; 16],
                buf: [0; 16],
                iv: [0; 16],
                block: None,
                cbc_fn: None,
                ctr: None,
                ecb: None,
                mode: EVP_CIPH_ECB_MODE,
                keylen: 16,
                ivlen: 0,
                blocksize: 16,
                bufsz: 0,
                cts_mode: 0,
                bits: 0,
                tlsversion: 0,
                tlsmac: ptr::null_mut(),
                alloced: 0,
                tlsmacsize: 0,
                removetlspad: 0,
                removetlsfixed: 0,
                num: 0,
                hw: ptr::addr_of!(AES_ECB_HW),
                ks: ptr::null(),
                libctx: ptr::null_mut(),
            },
            ks: AesKey {
                rd_key: [0; 4 * (AES_MAXNR + 1)],
                rounds: 0,
            },
        };
        // SAFETY: the context is this frame's and `get_params` writes the caller's descs.
        unsafe {
            ossl_cipher_generic_initkey(
                ptr::addr_of_mut!(ctx).cast(),
                128,
                128,
                0,
                EVP_CIPH_ECB_MODE,
                0,
                ptr::addr_of!(AES_ECB_HW),
                ptr::null_mut(),
            );
        }
        assert_eq!(ctx.base.keylen, 16);
        assert_eq!(ctx.base.blocksize, 16);
        assert_eq!(ctx.base.bits & CTX_PAD, CTX_PAD, "padding defaults on");
    }
}
