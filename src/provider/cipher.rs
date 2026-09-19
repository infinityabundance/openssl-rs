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
//! * `deflt_ciphers[]`'s rows for AES (including the CTS, XTS, OCB, CCM and key-wrap spellings),
//!   Camellia, 3DES and the `NULL` cipher, with each row's alias string taken verbatim from
//!   `providers/implementations/include/prov/names.h` and each row's provider checked against
//!   `providers/defltprov.c` (**not** `legacyprov.c`): AES, Camellia and 3DES are the default
//!   provider's (`defltprov.c:163-186`, `:275-300`, `:301-313`), while **single** DES, RC2, RC4,
//!   Blowfish, CAST5, IDEA and SEED are the legacy provider's (`legacyprov.c:108-159`) and get no
//!   row here. That per-row check is the defect D206 found for MD4 and D213 for RC4, restated for
//!   ciphers.
//! * the AEAD engines the rows select: `cipher_aes_xts.c`, `cipher_aes_ocb.c`,
//!   `cipher_aes_ccm.c` + `ciphercommon_ccm.c`, `cipher_aes_wrp.c` and `cipher_cts.c`;
//! * the `OSSL_OP_CIPHER` arm of `deflt_query`.
//!
//! What is **absent by design**: `deflt_get_params`/`deflt_gettable_params`/
//! `ossl_prov_get_capabilities`/`provctx` and the `base`/`null` *providers*; the `AES-*-GCM` rows
//! (`defltprov.c:202-204`, deferred to Phase 9 on `RAND_bytes_ex` -- D234); the
//! `AES-*-SIV`/`AES-*-GCM-SIV` rows (`defltprov.c:194-201`, whose construction is
//! `crypto/modes/siv128.c`); the thirteen capability-gated `ALGC(...)` `AES-*-CBC-HMAC` rows
//! (`defltprov.c:220-...`), which cannot land before D237's filtering is built; ARIA and SM4
//! (whose low-level constructions do not exist in this profile; D209 §2); ChaCha20
//! (`cipher_chacha20.c`'s units publish no `libcrypto` symbol); and the asm-selected
//! `cipher_aes_cbc_hmac_*` TLS dispatch. `deflt_ciphers[]` in the authority carries those rows
//! too; this half carries the subset the crate can back, and `forensics/atlas/provider-algorithms.json`
//! (D237) is the census that says so row by row.
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
    AES_BLOCK_SIZE,
};
use crate::camellia::{CamelliaKey, Camellia_set_key};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::des::{
    DES_ecb3_encrypt, DES_ede3_cbc_encrypt, DES_ede3_cfb64_encrypt, DES_ede3_cfb_encrypt,
    DES_ede3_ofb64_encrypt, DES_set_key_unchecked, DesKeySchedule,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_up_ref, EvpCipher};
use crate::evp::cipher::{
    OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,
    OSSL_FUNC_CIPHER_DUPCTX, OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT,
    OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE,
};
use crate::modes::ccm::{
    CRYPTO_ccm128_aad, CRYPTO_ccm128_decrypt, CRYPTO_ccm128_encrypt, CRYPTO_ccm128_init,
    CRYPTO_ccm128_setiv, CRYPTO_ccm128_tag, CcmCtx,
};
use crate::modes::ocb::{
    CRYPTO_ocb128_aad, CRYPTO_ocb128_cleanup, CRYPTO_ocb128_copy_ctx, CRYPTO_ocb128_decrypt,
    CRYPTO_ocb128_encrypt, CRYPTO_ocb128_finish, CRYPTO_ocb128_init, CRYPTO_ocb128_setiv,
    CRYPTO_ocb128_tag, OcbCtx,
};
use crate::modes::siv128::{
    ossl_siv128_aad, ossl_siv128_cleanup, ossl_siv128_copy_ctx, ossl_siv128_decrypt,
    ossl_siv128_encrypt, ossl_siv128_finish, ossl_siv128_init, ossl_siv128_set_tag,
    ossl_siv128_speed, Siv128Context, SIV_LEN,
};
use crate::modes::wrap::{
    CRYPTO_128_unwrap, CRYPTO_128_unwrap_pad, CRYPTO_128_wrap, CRYPTO_128_wrap_pad,
};
use crate::modes::xts::{CRYPTO_xts128_encrypt, XtsCtx};
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
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, CRYPTO_memdup, CRYPTO_zalloc,
    OPENSSL_cleanse,
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

/// `union { cbc128_f cbc; ctr128_f ctr; ecb128_f ecb; } stream` — `prov/ciphercommon.h:75-79`.
///
/// A union rather than three fields because **its width is contract**: see `ProvCipherCtx::stream`.
/// Each member is an `Option` because the authority's pointers can be NULL and every reader tests
/// for it; reading a member is `unsafe` and writing one is not, exactly as `union` requires.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union ProvCipherStream {
    /// `cbc128_f cbc`.
    pub cbc: Option<Cbc128F>,
    /// `ctr128_f ctr`.
    pub ctr: Option<crate::modes::Ctr128F>,
    /// `ecb128_f ecb`.
    pub ecb: Option<Ecb128F>,
}

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
    /// `union { cbc128_f cbc; ctr128_f ctr; ecb128_f ecb; } stream` — a **union**, because its
    /// width is observable.
    ///
    /// Three separate fields would be behaviourally identical and sixteen bytes larger, and the
    /// difference reaches an application: the provider allocates `sizeof(*ctx)` for the row's own
    /// context and `CRYPTO_set_mem_functions` hands that `num` to a caller's allocator. It was
    /// modelled as three fields until the `ChaCha20` row's size assertion measured
    /// `sizeof(PROV_CIPHER_CTX)` at 192 against this struct's 208 (D262). Only the mode's own hw
    /// function ever reads its member, which is the aliasing the authority relies on.
    pub stream: ProvCipherStream,
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
    ///
    /// **`Option`, because the authority's field really can be NULL.** `cipher_chacha20_hw.c`'s
    /// `chacha20_hw` initialises only `{ { chacha20_initkey, chacha20_cipher }, chacha20_initiv }`,
    /// so its `base.copyctx` is a null pointer, and `cipher_chacha20.c`'s `chacha20_dupctx` does not
    /// consult it (it is `OPENSSL_memdup` of the whole context). A non-nullable field would have made
    /// that row's hw unrepresentable and forced a fabricated pointer into a transcription, which is
    /// the kind of convenience this crate records instead of taking.
    pub copyctx: Option<unsafe extern "C" fn(*mut ProvCipherCtx, *const ProvCipherCtx)>,
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

/// Every failure arm whose authority counterpart returns `0` **without** raising: the
/// propagation arms (an inner function already queued the error), the `ossl_prov_is_running`
/// refusals, and the arms the authority reaches only through a `NULL` function pointer, which
/// no correct transcription arrives at.
#[inline]
fn fail() -> c_int {
    0
}

/// `ERR_raise(lib, reason)` at a recorded authority site, for a refusal whose value is not `0`.
///
/// The coordinate is generated (`forensics/tools/gen_err_raise_sites.py`) from the pinned
/// source, so the file, line and function a caller reads back through `ERR_get_error_all` are
/// the authority's rather than a plausible spelling.
#[inline]
fn raise_prov(site: &err_sites::ErrSite) {
    // SAFETY: `site` is a generated compile-time constant whose three string pointers are
    // `'static`; no caller state is touched.
    unsafe { raise_site(site) };
}

/// The authority's `ERR_raise(...); return 0;` pair: the refusal *and* the queued error.
///
/// A path where the authority raises and this crate does not is an `ERROR_PASS` failure
/// (`docs/PARITY_MODEL.md` §3.5), not a harmless omission -- which is exactly why `RT-CIPHER`
/// now drains and compares the queue.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    raise_prov(site);
    0
}

/// `produce_param_decoder`'s repeated-key refusal, in one place.
///
/// The authority's generated decoders walk the caller's array and raise
/// `PROV_R_REPEATED_PARAMETER` at the **second** occurrence of any key they know, before a
/// value is read or written. This crate hand-writes the locate-each-key form instead, which
/// is identical for every array without duplicates and silently different for one with them,
/// so the scan is kept here and reports the *decoder's own* recorded coordinate rather than
/// the get/set body's.
///
/// `pub(crate)` because the provider MAC rows (`src/provider/mac.rs`) run the same scan against
/// their own generated decoders, and the subtlety here — the raise site belongs to the *decoder*
/// rather than to the calling body — must not be spelled twice.
///
/// # Safety
/// `params` is NULL or a key-terminated array; the keys in `keys` are `'static` C strings.
pub(crate) unsafe fn repeated_param_site(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a key-terminated array; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if !name.is_null() && core::ffi::CStr::from_ptr(*name).to_bytes() == k {
                    if seen & (1u32 << i) != 0 {
                        return Some(site);
                    }
                    seen |= 1u32 << i;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
}

/// The ten keys `ossl_cipher_generic_get_params_decoder` locates, each with the site of its own
/// repeated-parameter raise (`ciphercommon.c:80-184`).
const GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 10] = [
    (&err_sites::PROV_CIPHERCOMMON_80, OSSL_CIPHER_PARAM_AEAD),
    (
        &err_sites::PROV_CIPHERCOMMON_91,
        OSSL_CIPHER_PARAM_BLOCK_SIZE,
    ),
    (&err_sites::PROV_CIPHERCOMMON_106, OSSL_CIPHER_PARAM_CTS),
    (
        &err_sites::PROV_CIPHERCOMMON_117,
        OSSL_CIPHER_PARAM_CUSTOM_IV,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_129,
        OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_140,
        OSSL_CIPHER_PARAM_HAS_RAND_KEY,
    ),
    (&err_sites::PROV_CIPHERCOMMON_151, OSSL_CIPHER_PARAM_IVLEN),
    (&err_sites::PROV_CIPHERCOMMON_162, OSSL_CIPHER_PARAM_KEYLEN),
    (&err_sites::PROV_CIPHERCOMMON_173, OSSL_CIPHER_PARAM_MODE),
    (
        &err_sites::PROV_CIPHERCOMMON_184,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
    ),
];

/// The seven keys `cipher_generic_get_ctx_params_decoder` locates, each with its raise site
/// (`ciphercommon.c:313-378`).
const GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_CIPHERCOMMON_313, OSSL_CIPHER_PARAM_IVLEN),
    (&err_sites::PROV_CIPHERCOMMON_322, OSSL_CIPHER_PARAM_IV),
    (&err_sites::PROV_CIPHERCOMMON_334, OSSL_CIPHER_PARAM_KEYLEN),
    (&err_sites::PROV_CIPHERCOMMON_345, OSSL_CIPHER_PARAM_NUM),
    (&err_sites::PROV_CIPHERCOMMON_356, OSSL_CIPHER_PARAM_PADDING),
    (&err_sites::PROV_CIPHERCOMMON_367, OSSL_CIPHER_PARAM_TLS_MAC),
    (
        &err_sites::PROV_CIPHERCOMMON_378,
        OSSL_CIPHER_PARAM_UPDATED_IV,
    ),
];

/// The five keys `cipher_generic_set_ctx_params_decoder` locates, each with its raise site
/// (`ciphercommon.c:437-501`).
const SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&err_sites::PROV_CIPHERCOMMON_437, OSSL_CIPHER_PARAM_NUM),
    (&err_sites::PROV_CIPHERCOMMON_448, OSSL_CIPHER_PARAM_PADDING),
    (
        &err_sites::PROV_CIPHERCOMMON_475,
        OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_486,
        OSSL_CIPHER_PARAM_TLS_VERSION,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_501,
        OSSL_CIPHER_PARAM_USE_BITS,
    ),
];

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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_BLOCK_70);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_BLOCK_97);
        }
        let pad = *buf.add(blocksize - 1) as usize;
        if pad == 0 || pad > blocksize {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_BLOCK_107);
        }
        let mut i = 0usize;
        while i < pad {
            len -= 1;
            if *buf.add(len) as usize != pad {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_BLOCK_112);
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
                    return fail_at(&err_sites::PROV_CIPHERCOMMON_719);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_783);
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
                return fail_at(&err_sites::PROV_CIPHERCOMMON_875);
            }
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, (*ctx).buf.as_ptr(), blksz) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_879);
            }
            (*ctx).bufsz = 0;
            outlint = blksz;
            out = out.add(blksz);
        }
        if nextblocks > 0 {
            if bits(ctx) & CTX_ENC == 0 && bits(ctx) & CTX_PAD != 0 && nextblocks == inl {
                if inl < blksz {
                    return fail_at(&err_sites::PROV_CIPHERCOMMON_889);
                }
                nextblocks -= blksz;
            }
            outlint += nextblocks;
            if outsize < outlint {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_896);
            }
        }
        if nextblocks > 0 {
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, in_, nextblocks) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_902);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_928);
        }
        if (*ctx).tlsversion > 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_934);
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
                return fail_at(&err_sites::PROV_CIPHERCOMMON_945);
            }
            if outsize < blksz {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_950);
            }
            let hw = (*ctx).hw;
            if ((*hw).cipher)(ctx, out, (*ctx).buf.as_ptr(), blksz) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_954);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_968);
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, (*ctx).buf.as_mut_ptr(), (*ctx).buf.as_ptr(), blksz) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_973);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_983);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_999);
        }
        if inl == 0 {
            *outl = 0;
            return 1;
        }
        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1009);
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, out, in_, inl) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1014);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1063);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1081);
        }
        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1086);
        }
        let hw = (*ctx).hw;
        if ((*hw).cipher)(ctx, out, in_, inl) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1091);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1102);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_uint(p, c_uint::from(bits(ctx) & CTX_PAD != 0)) == 0
        {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1107);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).oiv.as_ptr().cast(),
                (*ctx).ivlen,
            ) == 0
        {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1113);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).iv.as_ptr().cast(),
                (*ctx).ivlen,
            ) == 0
        {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1119);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
        if !p.is_null() && crate::params::OSSL_PARAM_set_uint(p, (*ctx).num) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1124);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).keylen) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1129);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_ptr(p, (*ctx).tlsmac.cast(), (*ctx).tlsmacsize)
                == 0
        {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1135);
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
        // `ossl_cipher_generic_get_ctx_params` runs the generated decoder before the body: a
        // key the decoder knows, seen twice, is a refusal at the decoder's own coordinate.
        if let Some(site) = repeated_param_site(params, &GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
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
                return fail_at(&err_sites::PROV_CIPHERCOMMON_1157);
            }
            bits_set(ctx, CTX_PAD, pad != 0);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
        if !p.is_null() {
            let mut b: c_uint = 0;
            if crate::params::OSSL_PARAM_get_uint(p, &mut b) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_1167);
            }
            bits_set(ctx, CTX_USE_BITS, b != 0);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
        if !p.is_null() && crate::params::OSSL_PARAM_get_uint(p, &mut (*ctx).tlsversion) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1175);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
        if !p.is_null() && crate::params::OSSL_PARAM_get_size_t(p, &mut (*ctx).tlsmacsize) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1182);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
        if !p.is_null() {
            let mut num: c_uint = 0;
            if crate::params::OSSL_PARAM_get_uint(p, &mut num) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_1191);
            }
            if (*ctx).blocksize > 0 && num >= (*ctx).blocksize as c_uint {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_1195);
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
        // `ossl_cipher_generic_set_ctx_params` runs the generated decoder before the body.
        if let Some(site) = repeated_param_site(params, &SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
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
            return fail_at(&err_sites::PROV_CIPHERCOMMON_1221);
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
///
/// **The `provctx` argument is why `ctx->libctx` exists.** `ciphercommon.c.in:758-759` ends this
/// function with
///
/// ```c
/// if (provctx != NULL)
///     ctx->libctx = PROV_LIBCTX_OF(provctx); /* used for rand */
/// ```
///
/// so a provider cipher context carries the library context of the provider that created it, and
/// the GCM no-IV arm and `cipher_tdes_wrap.c`'s IV generation pass it to `RAND_bytes_ex`. D240
/// recorded that as a measured obligation — the crate published a NULL `provctx`, so the field
/// could never be set — and `src/provider/ctx.rs`'s module doc is its discharge. The field's
/// other readers are the provider rows that sub-fetch (`cmac_prov.c`'s `ossl_prov_cipher_load`,
/// `cipher_aes_siv_hw.c`'s two fetches) through their own `PROV_LIBCTX_OF`.
#[allow(clippy::too_many_arguments)]
unsafe fn ossl_cipher_generic_initkey(
    vctx: *mut c_void,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
    mode: c_uint,
    flags: u64,
    hw: *const ProvCipherHw,
    provctx: *mut c_void,
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
        if !provctx.is_null() {
            (*ctx).libctx = crate::provider::ctx::prov_libctx_of(provctx);
        }
    }
}

/// `OSSL_PARAM_size_t(key, addr)` — `include/openssl/params.h:51-52`: `UNSIGNED_INTEGER` and
/// `sizeof(size_t)`.
///
/// # Why one constructor per authority macro rather than one `(key, data_type)` helper
/// A provider's published lists are **observable**: `EVP_CIPHER_gettable_params`,
/// `EVP_CIPHER_CTX_gettable_params`, `EVP_CIPHER_CTX_settable_params` and the MAC equivalents hand a
/// caller the descriptor array, and a caller reads `data_size`. The authority's generated lists set
/// it from the constructor macro, so the only spelling of a list this crate can check against the
/// authority is the one that carries the macro. The first version of this module took
/// `(key, data_type)` and defaulted the size to zero, which was wrong for every `uint`, `size_t` and
/// `int` entry of every list -- thirty extra or missing entries and one hundred and thirty wrong
/// sizes, none of which any keys-only comparison could see (D253).
pub(crate) const fn param_size_t(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: core::mem::size_of::<usize>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_uint(key, addr)` — `include/openssl/params.h:33-35`: `UNSIGNED_INTEGER` and
/// `sizeof(unsigned int)`.
///
/// # Why the size is here and not derived from the type
/// `OSSL_PARAM_uint` and `OSSL_PARAM_size_t` produce the **same** `data_type` and different
/// `data_size` (4 and 8), so a table that carried only the type could not be checked against the
/// authority by reading the type. Both are covered by two constructors here for exactly that
/// reason, and the provider court prints the size of every published entry.
pub(crate) const fn param_uint(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: core::mem::size_of::<c_uint>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_int(key, addr)` — `params.h:31-32`: `INTEGER` and `sizeof(int)`.
pub(crate) const fn param_int(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: core::mem::size_of::<c_int>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_utf8_string(key, addr, 0)` — `params.h:60-61`: the generated lists pass a zero
/// length, so the descriptor's `data_size` is 0.
pub(crate) const fn param_utf8_string(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_utf8_string(key, b, s)` — `params.h:60-61` with its **data** supplied.
///
/// The zero-length sibling above is what the generated lists use; this three-argument form is what
/// a row that hands a caller a fixed string uses, and `kmac_prov.c`'s `kmac128_new`/`kmac256_new` are
/// the first such place in the crate: they build a one-entry list naming the digest the row is defined
/// over, with `data_size` = `sizeof` of the literal (the NUL included) rather than a `strlen`.
///
pub(crate) const fn param_utf8_string_with(
    key: *const c_char,
    data: *mut c_void,
    data_size: usize,
) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_UTF8_STRING,
        data,
        data_size,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_octet_string(key, addr, 0)` — `params.h:62-63`.
pub(crate) const fn param_octet_string(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_OCTET_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_octet_string(key, b, s)` — `params.h:62-63` with its **data** supplied.
///
/// The zero-length sibling above is the generated lists' form. This one exists for the same reason
/// `param_utf8_string_with` does, and for one more that is easy to miss: `kmac_init` sets the
/// default customisation string with `OSSL_PARAM_octet_string(key, "", 0)`, whose `data` is a
/// **non-NULL** pointer to a zero-length string. `encode_string` branches on `in == NULL`, so a
/// transcription that passed NULL here would leave `custom_len` at 0 where the authority's is 2
/// (`[0x01, 0x00]`), and the two produce different tags for the same key and message.
pub(crate) const fn param_octet_string_with(
    key: *const c_char,
    data: *mut c_void,
    data_size: usize,
) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_OCTET_STRING,
        data,
        data_size,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_octet_ptr(key, addr, 0)` — `params.h:67-68`. The one list that uses it is the NULL
/// cipher's `tls-mac`.
pub(crate) const fn param_octet_ptr(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_OCTET_PTR,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `ossl_cipher_generic_gettable_params` — `ciphercommon.c.in:48-51`, the ten keys
/// `produce_param_decoder` locates.
static CIPHER_GETTABLE_PARAMS: [OsslParam; 11] = [
    param_uint(OSSL_CIPHER_PARAM_MODE),
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE),
    param_int(OSSL_CIPHER_PARAM_AEAD),
    param_int(OSSL_CIPHER_PARAM_CUSTOM_IV),
    param_int(OSSL_CIPHER_PARAM_CTS),
    param_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK),
    param_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY),
    param_int(OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC),
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
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_octet_string(OSSL_CIPHER_PARAM_TLS_MAC),
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
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
    param_uint(OSSL_CIPHER_PARAM_USE_BITS),
    param_uint(OSSL_CIPHER_PARAM_TLS_VERSION),
    param_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE),
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
        // `ossl_cipher_generic_get_params` calls its generated decoder first; a key the decoder
        // knows, seen twice, is a refusal there rather than here.
        if let Some(site) = repeated_param_site(params, &GET_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        if !set_uint_flag(params, OSSL_CIPHER_PARAM_MODE, md) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_212);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_AEAD,
            flags & PROV_CIPHER_FLAG_AEAD != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_217);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_CUSTOM_IV,
            flags & PROV_CIPHER_FLAG_CUSTOM_IV != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_222);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_CTS,
            flags & PROV_CIPHER_FLAG_CTS != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_227);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
            flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_232);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_HAS_RAND_KEY,
            flags & PROV_CIPHER_FLAG_RAND_KEY != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_237);
        }
        if !set_int_flag(
            params,
            OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC,
            flags & EVP_CIPH_FLAG_ENC_THEN_MAC != 0,
        ) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_242);
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_KEYLEN, kbits / 8) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_246);
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_BLOCK_SIZE, blkbits / 8) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_250);
        }
        if !set_size_param(params, OSSL_CIPHER_PARAM_IVLEN, ivbits / 8) {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_254);
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
        if let Some(cbc_fn) = (*dat).stream.cbc {
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
        if let Some(ecb) = (*dat).stream.ecb {
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

//
// `ciphercommon_hw.c:126-193` — the chunked wrappers. `ciphercommon.h:237-243` declares four of them
// and `#define`s three more onto the generic functions, because those modes have no per-chunk work:
//
//     #define ossl_cipher_hw_chunked_ecb  ossl_cipher_hw_generic_ecb
//     #define ossl_cipher_hw_chunked_ctr  ossl_cipher_hw_generic_ctr
//     #define ossl_cipher_hw_chunked_cfb1 ossl_cipher_hw_generic_cfb1
//
// so the ARIA ECB, CTR and CFB1 rows install the generic functions themselves and there is no
// `chunked_*` item for those three here.
//
// **`cfb8` and `cfb128` pass `inl`, not `chunk`, to the generic function**, which is worth stating
// because it reads like a transcription slip and is not one. `ciphercommon_hw.c:153` and `:171`
// both forward `inl`; for an input shorter than `MAXCHUNK` the two are equal, and for a longer one
// the first call covers the whole buffer while the loop's later iterations rewrite a suffix of what
// it already wrote. Transcribing `chunk` there would be a difference from the authority on any
// single update of a gibibyte or more — and would be the *safer* code — so what is transcribed is
// what the authority does.
//

/// `ossl_cipher_hw_chunked_cbc` — `ciphercommon_hw.c:131-143`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_chunked_cbc(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            ossl_cipher_hw_generic_cbc(ctx, out, in_, MAXCHUNK);
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            ossl_cipher_hw_generic_cbc(ctx, out, in_, inl);
        }
        1
    }
}

/// `ossl_cipher_hw_chunked_cfb8` — `ciphercommon_hw.c:145-161`. See the block comment above for why
/// the generic call is handed `inl` rather than `chunk`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_chunked_cfb8(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        let mut chunk = MAXCHUNK;
        if inl < chunk {
            chunk = inl;
        }
        while inl > 0 && inl >= chunk {
            ossl_cipher_hw_generic_cfb8(ctx, out, in_, inl);
            inl -= chunk;
            in_ = in_.add(chunk);
            out = out.add(chunk);
            if inl < chunk {
                chunk = inl;
            }
        }
        1
    }
}

/// `ossl_cipher_hw_chunked_cfb128` — `ciphercommon_hw.c:163-179`. As [`ossl_cipher_hw_chunked_cfb8`].
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_chunked_cfb128(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        let mut chunk = MAXCHUNK;
        if inl < chunk {
            chunk = inl;
        }
        while inl > 0 && inl >= chunk {
            ossl_cipher_hw_generic_cfb128(ctx, out, in_, inl);
            inl -= chunk;
            in_ = in_.add(chunk);
            out = out.add(chunk);
            if inl < chunk {
                chunk = inl;
            }
        }
        1
    }
}

/// `ossl_cipher_hw_chunked_ofb128` — `ciphercommon_hw.c:181-193`.
///
/// # Safety
/// The `PROV_CIPHER_HW_FN` contract.
unsafe extern "C" fn ossl_cipher_hw_chunked_ofb128(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut inl = inl;
        let mut in_ = in_;
        let mut out = out;
        while inl >= MAXCHUNK {
            ossl_cipher_hw_generic_ofb128(ctx, out, in_, MAXCHUNK);
            inl -= MAXCHUNK;
            in_ = in_.add(MAXCHUNK);
            out = out.add(MAXCHUNK);
        }
        if inl > 0 {
            ossl_cipher_hw_generic_ofb128(ctx, out, in_, inl);
        }
        1
    }
}
// ---------------------------------------------------------------------------------------------
// The per-algorithm hardware
// ---------------------------------------------------------------------------------------------

/// The authority's `union { OSSL_UNION_ALIGN; AES_KEY ks; }`, which every AES-family provider context
/// embeds as a member.
///
/// **The union is the contract, not the `AES_KEY`.** `OSSL_UNION_ALIGN` is
/// `double align; ossl_uintmax_t align_int; void *align_ptr` (`internal/common.h:75-78`), so the
/// union is **eight**-aligned, and a 244-byte `AES_KEY` therefore occupies **248** bytes of the
/// enclosing object. The four trailing bytes are part of the allocation request, which is exactly
/// what a `CRYPTO_set_mem_functions` application's allocator receives, so flattening the union to
/// `AES_KEY` under-allocates every AES, XTS, OCB, CCM and wrap context (D269).
///
/// `ks` is at offset zero, so this is transparent to the `*mut AES_KEY` a hw function is handed
/// and to every `addr_of_mut!` taken on a context's `ks` member.
#[repr(C, align(8))]
pub(crate) struct AesKeyUnion {
    /// `AES_KEY ks`.
    pub ks: AesKey,
}

/// `PROV_AES_CTX` — `cipher_aes.h:16-39`: `PROV_CIPHER_CTX base`, the `AES_KEY` union, and the
/// platform union that is a bare `int` in this profile.
#[repr(C)]
pub(crate) struct ProvAesCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks`.
    pub ks: AesKeyUnion,
    /// `union { int dummy; /* the s390x arm is not compiled here */ } plat`. Read by nothing in
    /// this profile; it is present because it is four bytes of the allocation request.
    #[allow(dead_code)]
    // size-only member: `sizeof(PROV_AES_CTX)` is 448 and this is its last four bytes
    pub plat: c_int,
}

/// `PROV_CAMELLIA_CTX` — `cipher_camellia.h`'s shape.
///
/// `CAMELLIA_KEY` is itself eight-aligned and 280 bytes (`src/camellia.rs`), so the union adds no
/// tail padding here and the flattened field is the union's layout exactly.
#[repr(C)]
pub(crate) struct ProvCamelliaCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; CAMELLIA_KEY ks; } ks`.
    pub ks: CamelliaKey,
}

/// `union { void (*cbc)(const void *, void *, size_t, const DES_key_schedule *, unsigned char *); }
/// tstream` — `cipher_tdes.h:26-29`. The assembly path's CBC entry point.
pub(crate) type TdesStreamFn =
    unsafe extern "C" fn(*const c_void, *mut c_void, usize, *const DesKeySchedule, *mut c_uchar);

/// `PROV_TDES_CTX` — `cipher_tdes.h:22-38`. `OSSL_FIPS_IND_DECLARE` is empty in this profile (it is
/// `OSSL_FIPS_IND indicator` only under `FIPS_MODULE`), so the struct is the base, `tks` and
/// `tstream`.
///
/// `tstream` holds the single `void (*cbc)(...)` the assembly path installs. The crate reaches the
/// same behaviour through `cipher_tdes_hw.c`'s own `cbc` function, so nothing writes this member —
/// but it is eight bytes of a 584-byte allocation request, and `cipher_hw_tdes_copyctx` copies it.
#[repr(C)]
pub(crate) struct ProvTdesCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; DES_key_schedule ks[3]; } tks`.
    pub tks: [DesKeySchedule; 3],
    /// `union { void (*cbc)(const void *, void *, size_t, const DES_key_schedule *,
    /// unsigned char *); } tstream`. Left NULL, as the C body leaves it.
    #[allow(dead_code)] // size-only member: see the struct's doc comment
    pub tstream: Option<TdesStreamFn>,
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
        let ks = ptr::addr_of_mut!((*adat).ks.ks);
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
        (*dat).stream.cbc = if (*dat).mode == EVP_CIPH_CBC_MODE {
            Some(aes_cbc_run)
        } else {
            None
        };
        if ret < 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_HW_121);
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
        (*dst.cast::<ProvAesCtx>()).base.ks =
            ptr::addr_of!((*dst.cast::<ProvAesCtx>()).ks.ks).cast();
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
            return fail_at(&err_sites::PROV_CIPHER_CAMELLIA_HW_30);
        }
        let mode = (*dat).mode;
        if bits(dat) & CTX_ENC != 0 || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE) {
            (*dat).block = Some(camellia_block_encrypt);
        } else {
            (*dat).block = Some(camellia_block_decrypt);
        }
        (*dat).stream.cbc = if mode == EVP_CIPH_CBC_MODE {
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
        // `copyctx` is `Option` because `chacha20_hw` leaves it NULL; the three rows that reach
        // here (`cipher_aes.c`, `cipher_camellia.c`, `cipher_tdes_common.c`) all install a
        // non-NULL one through `ossl_cipher_generic_initkey`, and `ctx->hw` is written only by
        // that function or by a row's own init -- so the guard is unreachable through the public
        // surface, and it is a guard rather than a `transmute` because fabricating a pointer is
        // not a transcription.
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), ctx.cast());
        }
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
        // `copyctx` is `Option` because `chacha20_hw` leaves it NULL; the three rows that reach
        // here (`cipher_aes.c`, `cipher_camellia.c`, `cipher_tdes_common.c`) all install a
        // non-NULL one through `ossl_cipher_generic_initkey`, and `ctx->hw` is written only by
        // that function or by a row's own init -- so the guard is unreachable through the public
        // surface, and it is a guard rather than a `transmute` because fabricating a pointer is
        // not a transcription.
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), ctx.cast());
        }
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
        // `copyctx` is `Option` because `chacha20_hw` leaves it NULL; the three rows that reach
        // here (`cipher_aes.c`, `cipher_camellia.c`, `cipher_tdes_common.c`) all install a
        // non-NULL one through `ossl_cipher_generic_initkey`, and `ctx->hw` is written only by
        // that function or by a row's own init -- so the guard is unreachable through the public
        // surface, and it is a guard rather than a `transmute` because fabricating a pointer is
        // not a transcription.
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), ctx.cast());
        }
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
            return fail_at(&err_sites::PROV_CIPHER_TDES_COMMON_195);
        }
        ossl_cipher_generic_get_params(params, md, flags, kbits, blkbits, ivbits)
    }
}

/// `ossl_tdes_gettable_ctx_params` — `CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_*` with the
/// `RANDOM_KEY` row, `cipher_tdes_common.c:131-134`.
static TDES_GETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY),
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
static TDES_SETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
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
            copyctx: Some($copy),
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
    pub ks: AesKeyUnion,
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
                return fail_at(&err_sites::PROV_CIPHER_AES_WRP_123);
            }
            // SP800-38F §5.1: an inverse-cipher row's forward transform is the *decryption*
            // function, so the wrap direction swaps which AES key schedule is built.
            let use_forward = if bits(ctx) & CTX_INVERSE_CIPHER == 0 {
                enc != 0
            } else {
                enc == 0
            };
            let ks = ptr::addr_of_mut!((*wctx).ks.ks);
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
            raise_prov(&err_sites::PROV_CIPHER_AES_WRP_178);
            return -1;
        }
        if bits(ctx) & CTX_ENC == 0 && (inlen < 16 || inlen & 0x7 != 0) {
            raise_prov(&err_sites::PROV_CIPHER_AES_WRP_184);
            return -1;
        }
        if bits(ctx) & CTX_PAD == 0 && inlen & 0x7 != 0 {
            raise_prov(&err_sites::PROV_CIPHER_AES_WRP_190);
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
        if rv == 0 {
            raise_prov(&err_sites::PROV_CIPHER_AES_WRP_214);
            return -1;
        }
        if rv > c_int::MAX as usize {
            raise_prov(&err_sites::PROV_CIPHER_AES_WRP_218);
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
            return fail_at(&err_sites::PROV_CIPHER_AES_WRP_250);
        }
        // `size_t len` in the authority, assigned from an `int`-returning callee: a refusal
        // that returns `-1` becomes `SIZE_MAX`, `len <= 0` is then false, and the row answers
        // **success** with `*outl = SIZE_MAX` while the error sits in the queue. It is not a
        // transcription slip to reproduce -- a divergence here is observable through
        // `EVP_CipherUpdate`, which turns the oversized `*outl` into `EVP_R_UPDATE_ERROR`. The
        // only zero `aes_wrap_cipher_internal` can still produce is its `in == NULL` arm.
        let len = aes_wrap_cipher_internal(vctx, out, input, inl) as usize;
        if len == 0 {
            return 0;
        }
        *outl = len;
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
                return fail_at(&err_sites::PROV_CIPHER_AES_WRP_274);
            }
            if (*ctx).keylen != keylen {
                return fail_at(&err_sites::PROV_CIPHER_AES_WRP_278);
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
static CTS_GETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE),
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
static CTS_SETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_uint(OSSL_CIPHER_PARAM_PADDING),
    param_uint(OSSL_CIPHER_PARAM_NUM),
    param_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE),
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

// ---------------------------------------------------------------------------------------------
// `cipher_aes_xts.c` — the IEEE 1619 AES-XTS rows
// ---------------------------------------------------------------------------------------------
//
// XTS is defined over a **data unit**, not over a block stream, so the row declares a stream
// block size of one byte (`AES_XTS_BLOCK_BITS`) and drives `CRYPTO_xts128_encrypt` directly from
// its own `cipher`. The data cipher's direction is chosen at key time: `block1` is the encrypt
// function for encryption and the **decrypt** function for decryption, while `block2` (the tweak
// cipher) is always the encrypt function (D227).

/// `AES_XTS_FLAGS` — `cipher_aes_xts.c:23`.
const AES_XTS_FLAGS: u64 = PROV_CIPHER_FLAG_CUSTOM_IV;
/// `AES_XTS_IV_BITS` — `cipher_aes_xts.c:24`.
const AES_XTS_IV_BITS: usize = 128;
/// `AES_XTS_BLOCK_BITS` — `cipher_aes_xts.c:25`.
const AES_XTS_BLOCK_BITS: usize = 8;
/// `XTS_MAX_BLOCKS_PER_DATA_UNIT` — `cipher_aes_xts.c:201` (one million blocks).
const XTS_MAX_BLOCKS_PER_DATA_UNIT: usize = 1 << 20;
/// `EVP_CIPH_XTS_MODE` — `include/openssl/evp.h:318`.
const EVP_CIPH_XTS_MODE: c_uint = 0x10001;
/// `ossl_aes_xts_allow_insecure_decrypt` — `cipher_fips.c:?` is **0** outside the FIPS module, so
/// the duplicated-key check is applied to encryption **and** decryption.
const AES_XTS_ALLOW_INSECURE_DECRYPT: c_int = 0;

/// `OSSL_xts_stream_fn` — `cipher_aes_xts.h:20-23`, through `PROV_CIPHER_FUNC`'s
/// `typedef type(*OSSL_##name##_fn) args`.
pub(crate) type OsslXtsStreamFn = unsafe extern "C" fn(
    *const c_uchar,
    *mut c_uchar,
    usize,
    *const AesKey,
    *const AesKey,
    *const c_uchar,
);

/// `PROV_AES_XTS_CTX` — `cipher_aes_xts.h:33-58`, without the s390x members of the platform union
/// (that arm is not compiled in this profile).
///
/// `stream` is the assembly data-unit entry point the hw selects when the CPU reports AES-NI. The
/// crate declines that path for the reason D209 records for AES generally — the assembly is a
/// different code path to the same bytes — so `cipher_hw_aes_xts_generic_initkey` leaves it NULL
/// and `aes_xts_cipher` takes the `CRYPTO_xts128_encrypt` branch the authority takes on a machine
/// without the extension. The member is still transcribed: it is eight bytes of a 736-byte
/// allocation request, and `cipher_hw_aes_xts_copyctx` copies it.
#[repr(C)]
pub(crate) struct ProvAesXtsCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks1` — the data-unit schedule.
    pub ks1: AesKeyUnion,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ks2` — the tweak schedule.
    pub ks2: AesKeyUnion,
    /// `XTS128_CONTEXT xts` — the caller-populated four-field context.
    pub xts: XtsCtx,
    /// `OSSL_xts_stream_fn stream` — NULL here; see the struct's doc comment.
    #[allow(dead_code)] // size-only member: see the struct's doc comment
    pub stream: Option<OsslXtsStreamFn>,
    /// `union { int dummy; /* the s390x arm is not compiled here */ } plat`.
    #[allow(dead_code)] // size-only member, as in `ProvAesCtx`
    pub plat: c_int,
}

/// `aes_xts_check_keys_differ` — `cipher_aes_xts.c:54-63`.
///
/// # Safety
/// `key` is readable for `2 * bytes`.
unsafe fn aes_xts_check_keys_differ(key: *const c_uchar, bytes: usize, enc: c_int) -> c_int {
    // SAFETY: the caller's contract; `CRYPTO_memcmp` reads both halves.
    unsafe {
        if (AES_XTS_ALLOW_INSECURE_DECRYPT == 0 || enc != 0)
            && CRYPTO_memcmp(key.cast(), key.add(bytes).cast(), bytes) == 0
        {
            return fail_at(&err_sites::PROV_CIPHER_AES_XTS_59);
        }
        1
    }
}

/// `cipher_hw_aes_xts_generic_initkey` — `cipher_aes_xts_hw.c:39-88`, the portable arm. The
/// authority's `XTS_SET_KEY_FN` ignores the schedule setters' return values, and so does this.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract; `ctx` is a `PROV_AES_XTS_CTX`.
unsafe extern "C" fn cipher_hw_aes_xts_generic_initkey(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is a `PROV_AES_XTS_CTX`.
    unsafe {
        let xctx = ctx.cast::<ProvAesXtsCtx>();
        let bytes = keylen / 2;
        let bits = (bytes * 8) as c_int;
        let ks1 = ptr::addr_of_mut!((*xctx).ks1.ks);
        let ks2 = ptr::addr_of_mut!((*xctx).ks2.ks);

        if (*ctx).enc_int() != 0 {
            AES_set_encrypt_key(key, bits, ks1);
            (*xctx).xts.block1 = Some(aes_block_encrypt);
        } else {
            AES_set_decrypt_key(key, bits, ks1);
            (*xctx).xts.block1 = Some(aes_block_decrypt);
        }
        AES_set_encrypt_key(key.add(bytes), bits, ks2);
        (*xctx).xts.block2 = Some(aes_block_encrypt);
        (*xctx).xts.key1 = ks1.cast();
        (*xctx).xts.key2 = ks2.cast();
        1
    }
}

/// `cipher_hw_aes_xts_copyctx` — `cipher_aes_xts_hw.c:90-99`.
///
/// # Safety
/// The `PROV_CIPHER_HW::copyctx` contract; both are `PROV_AES_XTS_CTX`.
unsafe extern "C" fn cipher_hw_aes_xts_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract; both are `PROV_AES_XTS_CTX`.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<ProvAesXtsCtx>(), dst.cast::<ProvAesXtsCtx>(), 1);
        let d = dst.cast::<ProvAesXtsCtx>();
        (*d).xts.key1 = ptr::addr_of_mut!((*d).ks1.ks).cast();
        (*d).xts.key2 = ptr::addr_of_mut!((*d).ks2.ks).cast();
    }
}

/// `PROV_CIPHER_HW::cipher` is `NULL` for the XTS rows (`cipher_aes_xts_hw.c:322-326`): the row's
/// own `aes_xts_cipher` drives `CRYPTO_xts128_encrypt`. The crate's `ProvCipherHw::cipher` is a
/// plain function pointer rather than an `Option`, so a never-called stub stands in for the
/// authority's `NULL`.
///
/// # Safety
/// Never called.
unsafe extern "C" fn cipher_hw_aes_xts_cipher_unused(
    _ctx: *mut ProvCipherCtx,
    _out: *mut c_uchar,
    _in_: *const c_uchar,
    _len: usize,
) -> c_int {
    fail()
}

static AES_XTS_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aes_xts_generic_initkey,
    cipher: cipher_hw_aes_xts_cipher_unused,
    copyctx: Some(cipher_hw_aes_xts_copyctx),
};

/// `AES-*-XTS`'s one settable parameter — `cipher_aes_xts.c:244-247`.
static AES_XTS_SETTABLE_CTX_PARAMS: [OsslParam; 2] = [param_size_t(OSSL_CIPHER_PARAM_KEYLEN), END];

/// `aes_xts_settable_ctx_params` — `cipher_aes_xts.c:249-253`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    AES_XTS_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `aes_xts_set_ctx_params` — `cipher_aes_xts.c:255-277`. The key length is a check, not a knob.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ossl_param_is_empty(params) {
            return 1;
        }
        let ctx = vctx.cast::<ProvCipherCtx>();
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() {
            let mut keylen = 0usize;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut keylen) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_XTS_268);
            }
            if keylen != (*ctx).keylen {
                return fail();
            }
        }
        1
    }
}

/// `aes_xts_newctx` — `cipher_aes_xts.c:123-138`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_xts_newctx(
    provctx: *mut c_void,
    mode: c_uint,
    flags: u64,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesXtsCtx>(), FILE, LINE);
        if !ctx.is_null() {
            ossl_cipher_generic_initkey(
                ctx,
                kbits,
                blkbits,
                ivbits,
                mode,
                flags,
                ptr::addr_of!(AES_XTS_HW),
                ptr::null_mut(),
            );
        }
        let _ = provctx;
        ctx
    }
}

/// `aes_xts_freectx` — `cipher_aes_xts.c:140-146`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesXtsCtx>(), FILE, LINE);
    }
}

/// `aes_xts_dupctx` — `cipher_aes_xts.c:148-174`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let in_ = vctx.cast::<ProvAesXtsCtx>();
        let ks1 = ptr::addr_of!((*in_).ks1).cast_mut().cast::<c_void>();
        let ks2 = ptr::addr_of!((*in_).ks2).cast_mut().cast::<c_void>();
        if !(*in_).xts.key1.is_null() && (*in_).xts.key1 != ks1 {
            return ptr::null_mut();
        }
        if !(*in_).xts.key2.is_null() && (*in_).xts.key2 != ks2 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvAesXtsCtx>(), FILE, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let hw = (*in_).base.hw;
        // The same `Option` guard the three `*_dupctx` rows carry, and unreachable for the same
        // reason: `aes_xts` installs a non-NULL `copyctx` through `ossl_cipher_generic_initkey`.
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), vctx.cast());
        }
        ret
    }
}

/// `aes_xts_init` — `cipher_aes_xts.c:72-99`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_xts_init(
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
        if is_running() == 0 {
            return fail();
        }
        bits_set(ctx, CTX_ENC, enc != 0);
        if !iv.is_null() && ossl_cipher_generic_initiv(ctx, iv, ivlen) == 0 {
            return fail();
        }
        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail_at(&err_sites::PROV_CIPHER_AES_XTS_90);
            }
            if aes_xts_check_keys_differ(key, keylen / 2, enc) == 0 {
                return fail();
            }
            let hw = (*ctx).hw;
            if ((*hw).init)(ctx, key, keylen) == 0 {
                return fail();
            }
        }
        aes_xts_set_ctx_params(vctx, params)
    }
}

/// `aes_xts_einit` — `cipher_aes_xts.c:101-110`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_xts_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `aes_xts_dinit` — `cipher_aes_xts.c:112-121`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_xts_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `aes_xts_cipher` — `cipher_aes_xts.c:176-214`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let xctx = vctx.cast::<ProvAesXtsCtx>();
        let ctx = vctx.cast::<ProvCipherCtx>();
        if is_running() == 0
            || (*xctx).xts.key1.is_null()
            || (*xctx).xts.key2.is_null()
            || bits(ctx) & CTX_IV_SET == 0
            || out.is_null()
            || in_.is_null()
            || inl < GENERIC_BLOCK_SIZE
        {
            return fail();
        }
        // IEEE Std 1619-2018's data-unit limit, which SP 800-38E also mandates.
        if inl > XTS_MAX_BLOCKS_PER_DATA_UNIT * GENERIC_BLOCK_SIZE {
            return fail_at(&err_sites::PROV_CIPHER_AES_XTS_202);
        }
        if CRYPTO_xts128_encrypt(
            ptr::addr_of!((*xctx).xts),
            (*ctx).iv.as_ptr(),
            in_,
            out,
            inl,
            (*ctx).enc_int(),
        ) != 0
        {
            return fail();
        }
        *outl = inl;
        1
    }
}

/// `aes_xts_stream_update` — `cipher_aes_xts.c:216-233`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_stream_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHER_AES_XTS_223);
        }
        if aes_xts_cipher(vctx, out, outl, outsize, in_, inl) == 0 {
            // `aes_xts_cipher` itself raises only for the data-unit limit; every other refusal
            // there is a bare `return 0`, and this wrapper is what turns it into an observable
            // error. A short input takes exactly this path: the inner guard returns 0 with no
            // raise and the caller sees `PROV_R_CIPHER_OPERATION_FAILED` at `:228`.
            return fail_at(&err_sites::PROV_CIPHER_AES_XTS_228);
        }
        1
    }
}

/// `aes_xts_stream_final` — `cipher_aes_xts.c:235-242`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_xts_stream_final(
    _vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return fail();
        }
        *outl = 0;
        1
    }
}

/// `IMPLEMENT_cipher` — `cipher_aes_xts.c:279-315` and `cipher_sm4_xts.c:243-279`. The table has
/// fourteen entries in both, in the same order; the one-shot `CIPHER` is the row's own, and the
/// block size is one byte, so the EVP layer treats it as a stream.
///
/// **Every row-specific item is a parameter**, because the two families share the macro and almost
/// nothing inside it: their `einit`/`dinit`, their update, final and cipher, their `get_ctx_params`
/// pair and their settable list are all their own, and only the mode, the entry order and the
/// `get_params` shape are common to both. That is what `IMPLEMENT_cipher` is in the authority too.
macro_rules! xts_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr, $flags:expr, $blkbits:expr,
     $ivbits:expr, $newctx_impl:path, $einit:path, $dinit:path, $update:path, $final:path,
     $cipher:path, $freectx:path, $dupctx:path, $setctx:path, $settable:path) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the dispatch contract.
            unsafe {
                $newctx_impl(
                    provctx,
                    EVP_CIPH_XTS_MODE,
                    $flags,
                    2 * $kbits,
                    $blkbits,
                    $ivbits,
                )
            }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_XTS_MODE,
                    $flags,
                    2 * $kbits,
                    $blkbits,
                    $ivbits,
                )
            }
        }

        pub(crate) static $table: [OsslDispatch; 15] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: $einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: $dinit as *mut c_void,
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
                function: $cipher as *mut c_void,
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
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: ossl_cipher_generic_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: $setctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: $settable as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

xts_row!(
    aes256xts_newctx,
    aes256xts_get_params,
    AES256XTS_FUNCTIONS,
    256,
    AES_XTS_FLAGS,
    AES_XTS_BLOCK_BITS,
    AES_XTS_IV_BITS,
    aes_xts_newctx,
    aes_xts_einit,
    aes_xts_dinit,
    aes_xts_stream_update,
    aes_xts_stream_final,
    aes_xts_cipher,
    aes_xts_freectx,
    aes_xts_dupctx,
    aes_xts_set_ctx_params,
    aes_xts_settable_ctx_params
);
xts_row!(
    aes128xts_newctx,
    aes128xts_get_params,
    AES128XTS_FUNCTIONS,
    128,
    AES_XTS_FLAGS,
    AES_XTS_BLOCK_BITS,
    AES_XTS_IV_BITS,
    aes_xts_newctx,
    aes_xts_einit,
    aes_xts_dinit,
    aes_xts_stream_update,
    aes_xts_stream_final,
    aes_xts_cipher,
    aes_xts_freectx,
    aes_xts_dupctx,
    aes_xts_set_ctx_params,
    aes_xts_settable_ctx_params
);

// ---------------------------------------------------------------------------------------------
// `cipher_sm4_xts.c` / `cipher_sm4_xts_hw.c` — the `SM4-XTS` row
// ---------------------------------------------------------------------------------------------
//
// The AES-XTS shape with two differences that are the whole of the row.
//
// **`SM4-XTS` has two XTS standards and defaults to the GB one.** `cipher_sm4_xts.h:36`'s
// `int xts_standard` is 0 for `GB/T 17964-2021` and 1 for `IEEE Std 1619-2007`, the context is
// `zalloc`'d, and `sm4_xts_cipher` branches on it: 0 calls `ossl_crypto_xts128gb_encrypt`, 1 calls
// `CRYPTO_xts128_encrypt`. So **the default is the GB variant**, which is not the function AES-XTS
// uses at all, and the two doublings are not interchangeable -- `src/modes/xts.rs` records the
// arithmetic difference (GB shifts the big-endian reading right and reduces with `0xe1` at byte 15;
// IEEE shifts the little-endian reading left and reduces with `0x87` at byte 0). The standard is
// selected with `xts_standard`, an `OSSL_PARAM_utf8_string` taking `"GB"` or `"IEEE"`
// case-insensitively.
//
// **The row has its own update, final, cipher, `get_ctx_params` pair and settable list**, so nothing
// here is the generic engine's except `ossl_cipher_generic_get_params` and the two `initiv`-based
// helpers. `sm4_xts_stream_update` is where two of the row's provider reasons live
// (`PROV_R_OUTPUT_BUFFER_TOO_SMALL` before the cipher, `PROV_R_CIPHER_OPERATION_FAILED` after it),
// and `sm4_xts_cipher` is where the other two are (`PROV_R_INVALID_KEY_LENGTH` is in `sm4_xts_init`,
// and `PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE` guards the 2^20-block limit).
//
// Two smaller facts that are easy to lose. `sm4_xts_newctx` passes **NULL** as
// `ossl_cipher_generic_initkey`'s `provctx`, so this row's `ctx->libctx` is NULL and every
// sub-fetch it makes would resolve in the default library context -- which is why D240's
// `provider_context` block classifies it beside the GCM rows rather than with the rows that carry
// their creator's context. And `sm4_xts_dupctx` **refuses** rather than copying when either
// `xts.key1`/`xts.key2` is non-NULL and not the context's own `ks1`/`ks2`, which is an assertion
// about the caller rather than a repair.

/// `SM4_XTS_FLAGS` — `cipher_sm4_xts.c:18`, which is `PROV_CIPHER_FLAG_CUSTOM_IV` and **not** the
/// AEAD pair: XTS is a mode, not an AEAD.
const SM4_XTS_FLAGS: u64 = PROV_CIPHER_FLAG_CUSTOM_IV;
/// `SM4_XTS_IV_BITS` — `cipher_sm4_xts.c:19`.
const SM4_XTS_IV_BITS: usize = 128;
/// `SM4_XTS_BLOCK_BITS` — `cipher_sm4_xts.c:20`. One byte, so the EVP layer treats the row as a
/// stream and `EVP_CipherUpdate` reaches `sm4_xts_cipher` with any length above a block.
const SM4_XTS_BLOCK_BITS: usize = 8;

/// `OSSL_CIPHER_PARAM_XTS_STANDARD` — `util/perl/OpenSSL/paramnames.pm:153` (`"xts_standard"`).
const OSSL_CIPHER_PARAM_XTS_STANDARD: *const c_char = c"xts_standard".as_ptr();

/// The allocation-tracking `file` argument for this row's allocations. `cipher_sm4_xts.c` is a
/// source-tree file, so its `__FILE__` carries the `../../src/openssl-3.6.4/` prefix.
const FILE_SM4_XTS: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c".as_ptr();

/// `OSSL_xts_stream_fn` as `cipher_sm4_xts.h:14-17` generates it, through `PROV_CIPHER_FUNC`'s
/// `typedef type(*OSSL_##name##_fn) args`.
///
/// **This is a different type from the AES row's, under the same name.** `cipher_aes_xts.h:20-23`
/// generates `OSSL_xts_stream_fn` with two `const AES_KEY *` parameters and a five-argument tail;
/// `cipher_sm4_xts.h` generates it with two `const SM4_KEY *` and a trailing `const int enc`. The
/// two headers cannot be included in one translation unit, which is why
/// `courts/layout/measure-sm4-xts-ctx.c` is a separate program from `measure-provider-ctxs.c`.
/// Both spellings are NULL in this profile -- the assembly that would install them is declined --
/// and they exist here for the same reason the AES one does: they are eight bytes of the
/// allocation each (D269, D271).
pub(crate) type OsslSm4XtsStreamFn = unsafe extern "C" fn(
    *const c_uchar,
    *mut c_uchar,
    usize,
    *const crate::sm4::Sm4Key,
    *const crate::sm4::Sm4Key,
    *const c_uchar,
    c_int,
);

/// `PROV_SM4_XTS_CTX` — `cipher_sm4_xts.h:19-44`.
///
/// Measured: 192 + 128 + 128 + 4 + 32 + 8 + 8 = **504**, with `ks1` at 192, `ks2` at 320,
/// `xts_standard` at 448, `xts` at 456, `stream_gb` at 488 and `stream` at 496. `SM4_KEY` is 128
/// bytes and already a multiple of eight, so the two `ks` unions need no tail padding and `XTS128_CONTEXT`
/// is eight-aligned after the `int`, which is why `xts` sits at 456 rather than 452 (D269's rule).
#[repr(C)]
pub(crate) struct ProvSm4XtsCtx {
    /// `PROV_CIPHER_CTX base; /* Must be first */`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; SM4_KEY ks; } ks1` — the data-unit schedule.
    pub ks1: crate::sm4::Sm4Key,
    /// `union { OSSL_UNION_ALIGN; SM4_KEY ks; } ks2` — the tweak schedule.
    pub ks2: crate::sm4::Sm4Key,
    /// `int xts_standard` — 0 for GB/T 17964-2021, 1 for IEEE Std 1619-2007, and **0 is the default**.
    pub xts_standard: c_int,
    /// `XTS128_CONTEXT xts` — the caller-populated four-field context.
    pub xts: XtsCtx,
    /// `OSSL_xts_stream_fn stream_gb` — the GB variant's assembly entry point; NULL here.
    #[allow(dead_code)] // size-only member: see the struct's doc comment
    pub stream_gb: Option<OsslSm4XtsStreamFn>,
    /// `OSSL_xts_stream_fn stream` — the IEEE variant's; NULL here. Nothing writes either, and the
    /// authority's own `XTS_SET_KEY_FN` assigns them from locals that are NULL on every arm this
    /// profile compiles.
    #[allow(dead_code)] // size-only member, as above
    pub stream: Option<OsslSm4XtsStreamFn>,
}

/// `cipher_hw_sm4_xts_generic_initkey` — `cipher_sm4_xts_hw.c:33-73`'s portable arm, which is the
/// `XTS_SET_KEY_FN(ossl_sm4_set_key, ossl_sm4_set_key, ossl_sm4_encrypt, ossl_sm4_decrypt, NULL,
/// NULL)` expansion.
///
/// **`ossl_sm4_set_key` is both setters.** SM4 has one key schedule function: the decryption
/// direction is a property of the block function (`ossl_sm4_decrypt` walks the same schedule
/// backwards), so the decrypt arm rebuilds `ks1` with the *same* setter and only swaps `block1`.
/// `xts.key1`/`xts.key2` are pointed at the **unions** here rather than at the schedules, which is
/// what `sm4_xts_dupctx`'s own-key guard compares against.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract; `ctx` is a live `ProvSm4XtsCtx` and `key` is readable for
/// `keylen` bytes.
unsafe extern "C" fn cipher_hw_sm4_xts_generic_initkey(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is a `PROV_SM4_XTS_CTX`.
    unsafe {
        let xctx = ctx.cast::<ProvSm4XtsCtx>();
        let bytes = keylen / 2;
        let ks1: *mut crate::sm4::Sm4Key = ptr::addr_of_mut!((*xctx).ks1);
        let ks2: *mut crate::sm4::Sm4Key = ptr::addr_of_mut!((*xctx).ks2);

        if (*ctx).enc_int() != 0 {
            crate::sm4::ossl_sm4_set_key(key, ks1);
            (*xctx).xts.block1 = Some(sm4_block_encrypt);
        } else {
            crate::sm4::ossl_sm4_set_key(key, ks1);
            (*xctx).xts.block1 = Some(sm4_block_decrypt);
        }
        crate::sm4::ossl_sm4_set_key(key.add(bytes), ks2);
        (*xctx).xts.block2 = Some(sm4_block_encrypt);
        (*xctx).xts.key1 = ks1.cast();
        (*xctx).xts.key2 = ks2.cast();
        (*xctx).stream_gb = None;
        (*xctx).stream = None;
        1
    }
}

/// `cipher_hw_sm4_xts_copyctx` — `cipher_sm4_xts_hw.c:75-84`. `*dctx = *sctx` then the two key
/// pointers are re-pointed at the destination's own schedules.
///
/// # Safety
/// The `PROV_CIPHER_HW::copyctx` contract; both are `ProvSm4XtsCtx`.
unsafe extern "C" fn cipher_hw_sm4_xts_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract; both are `PROV_SM4_XTS_CTX`.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<ProvSm4XtsCtx>(), dst.cast::<ProvSm4XtsCtx>(), 1);
        let d = dst.cast::<ProvSm4XtsCtx>();
        (*d).xts.key1 = ptr::addr_of_mut!((*d).ks1).cast();
        (*d).xts.key2 = ptr::addr_of_mut!((*d).ks2).cast();
    }
}

/// `static const PROV_CIPHER_HW sm4_generic_xts` — `cipher_sm4_xts_hw.c:86-90`. `cipher` is NULL,
/// as the AES-XTS table's is, so
/// [`cipher_hw_aes_xts_cipher_unused`] stands in for it and its doc comment names both rows.
static SM4_XTS_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_xts_generic_initkey,
    cipher: cipher_hw_aes_xts_cipher_unused,
    copyctx: Some(cipher_hw_sm4_xts_copyctx),
};

/// `const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_xts(size_t keybits)` —
/// `cipher_sm4_xts_hw_x86_64.inc:28-34`. The C table is the answer on both sides of the extension
/// test this profile declines (D266's reason for SM4 generally).
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_cipher_hw_sm4_xts(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_XTS_HW)
}

/// `sm4_xts_init` — `cipher_sm4_xts.c:36-61`.
///
/// The order is the authority's: `enc` first, then the IV, then the key, then the params. The key
/// length is checked against `ctx->keylen` — which `ossl_cipher_generic_initkey` set to
/// `2 * kbits` — and the refusal is this row's `PROV_R_INVALID_KEY_LENGTH` rather than the generic
/// engine's.
///
/// # Safety
/// The dispatch contract.
unsafe fn sm4_xts_init(
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
        let xctx = vctx.cast::<ProvSm4XtsCtx>();
        let ctx = ptr::addr_of_mut!((*xctx).base);
        if is_running() == 0 {
            return fail();
        }
        bits_set(ctx, CTX_ENC, enc != 0);
        if !iv.is_null() && ossl_cipher_generic_initiv(ctx, iv, ivlen) == 0 {
            return fail();
        }
        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_54);
            }
            let hw = (*ctx).hw;
            if ((*hw).init)(ctx, key, keylen) == 0 {
                return fail();
            }
        }
        sm4_xts_set_ctx_params(vctx, params)
    }
}

/// `sm4_xts_einit` — `cipher_sm4_xts.c:63-68`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { sm4_xts_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `sm4_xts_dinit` — `cipher_sm4_xts.c:70-75`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { sm4_xts_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `sm4_xts_newctx` — `cipher_sm4_xts.c:77-88`.
///
/// **`NULL` is passed as the generic init's `provctx`**, which is the authority's own text and not
/// a transcription slip: `ossl_cipher_generic_initkey(..., ossl_prov_cipher_hw_sm4_xts(kbits), NULL)`.
/// `ossl_cipher_generic_initkey` stores `PROV_LIBCTX_OF(provctx)` on `ctx->libctx` only when that
/// argument is non-NULL, so this row's `libctx` is NULL (D240/D241 classify it accordingly).
///
/// # Safety
/// The dispatch contract.
unsafe fn sm4_xts_newctx(
    _provctx: *mut c_void,
    mode: c_uint,
    flags: u64,
    kbits: usize,
    blkbits: usize,
    ivbits: usize,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvSm4XtsCtx>(), FILE_SM4_XTS, LINE);
        if !ctx.is_null() {
            ossl_cipher_generic_initkey(
                ctx.cast(),
                kbits,
                blkbits,
                ivbits,
                mode,
                flags,
                ossl_prov_cipher_hw_sm4_xts(kbits),
                ptr::null_mut(),
            );
        }
        ctx
    }
}

/// `sm4_xts_freectx` — `cipher_sm4_xts.c:90-96`. Reset then cleared, as every row with a schedule
/// does.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast::<ProvCipherCtx>());
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvSm4XtsCtx>(),
            FILE_SM4_XTS,
            LINE,
        );
    }
}

/// `sm4_xts_dupctx` — `cipher_sm4_xts.c:98-119`.
///
/// **The two guards are assertions, not repairs.** A non-NULL `xts.key1` that is not this context's
/// own `ks1` means the context has been pointed somewhere the row does not own, and the authority
/// answers NULL rather than copying the stale pointer. The `hw->copyctx` call is the `Option`
/// guard D265 introduced.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let in_ = vctx.cast::<ProvSm4XtsCtx>();
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ks1: *const crate::sm4::Sm4Key = ptr::addr_of!((*in_).ks1);
        let ks2: *const crate::sm4::Sm4Key = ptr::addr_of!((*in_).ks2);
        if !(*in_).xts.key1.is_null() && (*in_).xts.key1.cast_const() != ks1.cast() {
            return ptr::null_mut();
        }
        if !(*in_).xts.key2.is_null() && (*in_).xts.key2.cast_const() != ks2.cast() {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvSm4XtsCtx>(), FILE_SM4_XTS, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let hw = (*in_).base.hw;
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), vctx.cast());
        }
        ret
    }
}

/// `sm4_xts_cipher` — `cipher_sm4_xts.c:121-162`.
///
/// **The default standard is GB.** `xts_standard` is 0 in a fresh context, so the `else` arm -- the
/// GB/T 17964-2021 variant -- is what a caller who never sets the parameter gets, and the IEEE arm
/// is the opt-in. Both arms prefer a non-NULL `stream`/`stream_gb` and fall back to the C
/// construction function; on this profile the pointers are NULL and the fallback is what runs.
///
/// # Safety
/// The dispatch contract; `in`/`out` are readable/writable for `inl` bytes.
unsafe extern "C" fn sm4_xts_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let xctx = vctx.cast::<ProvSm4XtsCtx>();
        let base = ptr::addr_of_mut!((*xctx).base);

        if is_running() == 0
            || (*xctx).xts.key1.is_null()
            || (*xctx).xts.key2.is_null()
            || bits(base) & CTX_IV_SET == 0
            || out.is_null()
            || in_.is_null()
            || inl < crate::sm4::SM4_BLOCK_SIZE
        {
            return 0;
        }
        // IEEE Std 1619-2018's limit, which NIST SP 800-38E mandates and the row enforces.
        if inl > XTS_MAX_BLOCKS_PER_DATA_UNIT * crate::sm4::SM4_BLOCK_SIZE {
            return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_142);
        }
        if (*xctx).xts_standard != 0 {
            if let Some(stream) = (*xctx).stream {
                stream(
                    in_,
                    out,
                    inl,
                    (*xctx).xts.key1.cast_const().cast(),
                    (*xctx).xts.key2.cast_const().cast(),
                    (*base).iv.as_ptr(),
                    (*base).enc_int(),
                );
            } else if (crate::modes::xts::CRYPTO_xts128_encrypt)(
                ptr::addr_of!((*xctx).xts),
                (*base).iv.as_ptr(),
                in_,
                out,
                inl,
                (*base).enc_int(),
            ) != 0
            {
                return 0;
            }
        } else {
            if let Some(stream_gb) = (*xctx).stream_gb {
                stream_gb(
                    in_,
                    out,
                    inl,
                    (*xctx).xts.key1.cast_const().cast(),
                    (*xctx).xts.key2.cast_const().cast(),
                    (*base).iv.as_ptr(),
                    (*base).enc_int(),
                );
            } else if (crate::modes::xts::ossl_crypto_xts128gb_encrypt)(
                ptr::addr_of!((*xctx).xts),
                (*base).iv.as_ptr(),
                in_,
                out,
                inl,
                (*base).enc_int(),
            ) != 0
            {
                return 0;
            }
        }
        *outl = inl;
        1
    }
}

/// `sm4_xts_stream_update` — `cipher_sm4_xts.c:164-181`. The output-size check is the row's own
/// and sits *before* the cipher, so a too-small buffer is `PROV_R_OUTPUT_BUFFER_TOO_SMALL` rather
/// than the generic engine's refusal; a failing cipher is
/// `PROV_R_CIPHER_OPERATION_FAILED`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_stream_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_171);
        }
        if sm4_xts_cipher(vctx, out, outl, outsize, in_, inl) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_176);
        }
        1
    }
}

/// `sm4_xts_stream_final` — `cipher_sm4_xts.c:183-190`. No tail, because XTS's data unit is the
/// whole message and the row's `cipher` has already emitted every byte.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_stream_final(
    _vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return 0;
        }
        *outl = 0;
        1
    }
}

/// `sm4_xts_known_settable_ctx_params` — `cipher_sm4_xts.c:192-195`, one utf8 string.
static SM4_XTS_SETTABLE_CTX_PARAMS: [OsslParam; 2] = [
    OsslParam {
        key: OSSL_CIPHER_PARAM_XTS_STANDARD,
        data_type: crate::params::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
    OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
];

/// `sm4_xts_settable_ctx_params` — `cipher_sm4_xts.c:197-201`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SM4_XTS_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `sm4_xts_set_ctx_params` — `cipher_sm4_xts.c:203-241`.
///
/// `xts_standard` is a utf8 string compared case-insensitively against `"GB"` and `"IEEE"`; any
/// other spelling raises `PROV_R_FAILED_TO_SET_PARAMETER`, and a non-utf8 parameter type is refused
/// **without** a raise (the `data_type` test returns 0 directly, where the three others raise).
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_xts_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let xctx = vctx.cast::<ProvSm4XtsCtx>();
        if params.is_null() || (*params).key.is_null() {
            return 1;
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_XTS_STANDARD);
        if !p.is_null() {
            if (*p).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            let mut standard: *const c_char = ptr::null();
            if crate::params::OSSL_PARAM_get_utf8_string_ptr(p, &mut standard) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_227);
            }
            if crate::runtime::str::OPENSSL_strcasecmp(standard, c"GB".as_ptr()) == 0 {
                (*xctx).xts_standard = 0;
            } else if crate::runtime::str::OPENSSL_strcasecmp(standard, c"IEEE".as_ptr()) == 0 {
                (*xctx).xts_standard = 1;
            } else {
                return fail_at(&err_sites::PROV_CIPHER_SM4_XTS_235);
            }
        }
        1
    }
}

// `IMPLEMENT_cipher(xts, XTS, 128, SM4_XTS_FLAGS)` — `cipher_sm4_xts.c:280-281`, one invocation
// whose `kbits` is doubled by the macro into a 256-bit key.
xts_row!(
    sm4128xts_newctx,
    sm4128xts_get_params,
    SM4128XTS_FUNCTIONS,
    128,
    SM4_XTS_FLAGS,
    SM4_XTS_BLOCK_BITS,
    SM4_XTS_IV_BITS,
    sm4_xts_newctx,
    sm4_xts_einit,
    sm4_xts_dinit,
    sm4_xts_stream_update,
    sm4_xts_stream_final,
    sm4_xts_cipher,
    sm4_xts_freectx,
    sm4_xts_dupctx,
    sm4_xts_set_ctx_params,
    sm4_xts_settable_ctx_params
);

// ---------------------------------------------------------------------------------------------
// `cipher_aes_ocb.c` / `cipher_aes_ocb_hw.c` — the three AES-OCB rows
// ---------------------------------------------------------------------------------------------

// OCB is a self-contained engine over the landed `crypto/modes/ocb128.c` (D229): it buffers both
// the data and the AAD one block at a time, sets the IV lazily on the first data or AAD call, and
// ends by emitting or verifying the tag. The row publishes a one-shot `CIPHER` (`aes_ocb_cipher`),
// so `EVP_CipherUpdate` with a NULL input reaches the same `final`; and because the AAD arm is
// selected by `out == NULL`, the provider's update function is where both are observable.

/// `AES_OCB_FLAGS` — `cipher_aes_ocb.c:23`, which is `AEAD_FLAGS` (`ciphercommon_aead.h:17`).
const AES_OCB_FLAGS: u64 = PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV;
/// `OCB_DEFAULT_TAG_LEN` — `cipher_aes_ocb.c:25`.
const OCB_DEFAULT_TAG_LEN: usize = 16;
/// `OCB_DEFAULT_IV_LEN` — `cipher_aes_ocb.c:26`.
const OCB_DEFAULT_IV_LEN: usize = 12;
/// `OCB_MIN_IV_LEN` — `cipher_aes_ocb.c:27`.
const OCB_MIN_IV_LEN: usize = 1;
/// `OCB_MAX_IV_LEN` — `cipher_aes_ocb.c:28`.
const OCB_MAX_IV_LEN: usize = 15;
/// `OCB_MAX_TAG_LEN` — `cipher_aes_ocb.h:14`.
const OCB_MAX_TAG_LEN: usize = 16;
/// `OCB_MAX_DATA_LEN` — `cipher_aes_ocb.h:15`.
const OCB_MAX_DATA_LEN: usize = 16;
/// `OCB_MAX_AAD_LEN` — `cipher_aes_ocb.h:16`.
const OCB_MAX_AAD_LEN: usize = 16;
/// `EVP_CIPH_OCB_MODE` — `include/openssl/evp.h:320`.
const EVP_CIPH_OCB_MODE: c_uint = 0x10003;
/// The OCB rows' `blkbits` — `cipher_aes_ocb.c:579-581`, the third `IMPLEMENT_cipher` argument.
const AES_OCB_BLOCK_BITS: usize = 128;

/// `IV_STATE_UNINITIALISED` — `prov/ciphercommon.h:25`.
const IV_STATE_UNINITIALISED: c_uint = 0;
/// `IV_STATE_BUFFERED` — `prov/ciphercommon.h:26`.
const IV_STATE_BUFFERED: c_uint = 1;
/// `IV_STATE_COPIED` — `prov/ciphercommon.h:27`.
const IV_STATE_COPIED: c_uint = 2;
/// `IV_STATE_FINISHED` — `prov/ciphercommon.h:28`.
const IV_STATE_FINISHED: c_uint = 3;

/// `OSSL_CIPHER_PARAM_AEAD_TAG` — `core_names.h:179` (`"tag"`).
const OSSL_CIPHER_PARAM_AEAD_TAG: *const c_char = c"tag".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TAGLEN` — `core_names.h:180` (`"taglen"`).
const OSSL_CIPHER_PARAM_AEAD_TAGLEN: *const c_char = c"taglen".as_ptr();

/// `PROV_AES_OCB_CTX` — `cipher_aes_ocb.h:18-37`, without the s390x members of the platform union
/// (that arm is not compiled in this profile). `key_set` is the `unsigned int : 1` bitfield, which
/// occupies a whole `unsigned int` allocation unit after the named `iv_state`.
#[repr(C)]
pub(crate) struct ProvAesOcbCtx {
    /// `PROV_CIPHER_CTX base`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ksenc` — the encryption/AAD schedule.
    pub ksenc: AesKeyUnion,
    /// `union { OSSL_UNION_ALIGN; AES_KEY ks; } ksdec` — the decryption schedule.
    pub ksdec: AesKeyUnion,
    /// `OCB128_CONTEXT ocb`.
    pub ocb: OcbCtx,
    /// `unsigned int iv_state` — one of `IV_STATE_*`.
    pub iv_state: c_uint,
    /// `unsigned int key_set : 1`.
    pub key_set: c_uint,
    /// `size_t taglen`.
    pub taglen: usize,
    /// `size_t data_buf_len`.
    pub data_buf_len: usize,
    /// `size_t aad_buf_len`.
    pub aad_buf_len: usize,
    /// `unsigned char tag[OCB_MAX_TAG_LEN]`.
    pub tag: [c_uchar; OCB_MAX_TAG_LEN],
    /// `unsigned char data_buf[OCB_MAX_DATA_LEN]`.
    pub data_buf: [c_uchar; OCB_MAX_DATA_LEN],
    /// `unsigned char aad_buf[OCB_MAX_AAD_LEN]`.
    pub aad_buf: [c_uchar; OCB_MAX_AAD_LEN],
}

/// `OSSL_ocb_cipher_fn` — `cipher_aes_ocb.c:30`'s `PROV_CIPHER_FUNC(int, ocb_cipher, ...)`.
type OcbCipherFn = unsafe fn(*mut ProvAesOcbCtx, *const c_uchar, *mut c_uchar, usize) -> c_int;

/// `aes_generic_ocb_setiv` — `cipher_aes_ocb.c:48-53`.
///
/// # Safety
/// The `PROV_AES_OCB_CTX` contract; `iv` is readable for `ivlen` bytes.
unsafe fn aes_generic_ocb_setiv(
    ctx: *mut ProvAesOcbCtx,
    iv: *const c_uchar,
    ivlen: usize,
    taglen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        c_int::from(CRYPTO_ocb128_setiv(ptr::addr_of_mut!((*ctx).ocb), iv, ivlen, taglen) == 1)
    }
}

/// `aes_generic_ocb_setaad` — `cipher_aes_ocb.c:55-60`.
///
/// # Safety
/// `aad` is readable for `alen` bytes.
unsafe fn aes_generic_ocb_setaad(
    ctx: *mut ProvAesOcbCtx,
    aad: *const c_uchar,
    alen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { c_int::from(CRYPTO_ocb128_aad(ptr::addr_of_mut!((*ctx).ocb), aad, alen) == 1) }
}

/// `aes_generic_ocb_gettag` — `cipher_aes_ocb.c:62-66`.
///
/// # Safety
/// `tag` is writable for `tlen` bytes.
unsafe fn aes_generic_ocb_gettag(ctx: *mut ProvAesOcbCtx, tag: *mut c_uchar, tlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { c_int::from(CRYPTO_ocb128_tag(ptr::addr_of_mut!((*ctx).ocb), tag, tlen) > 0) }
}

/// `aes_generic_ocb_final` — `cipher_aes_ocb.c:68-71`. The answer is the *negation* of
/// `CRYPTO_ocb128_finish`'s: the provider wants true when the tag verifies.
///
/// # Safety
/// The `PROV_AES_OCB_CTX` contract.
unsafe fn aes_generic_ocb_final(ctx: *mut ProvAesOcbCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        c_int::from(
            CRYPTO_ocb128_finish(
                ptr::addr_of_mut!((*ctx).ocb),
                ptr::addr_of!((*ctx).tag).cast(),
                (*ctx).taglen,
            ) == 0,
        )
    }
}

/// `aes_generic_ocb_cipher` — `cipher_aes_ocb.c:78-90`.
///
/// # Safety
/// `in_` readable and `out` writable for `len` bytes.
unsafe fn aes_generic_ocb_cipher(
    ctx: *mut ProvAesOcbCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).base.enc_int() != 0 {
            if CRYPTO_ocb128_encrypt(ptr::addr_of_mut!((*ctx).ocb), in_, out, len) == 0 {
                return 0;
            }
        } else if CRYPTO_ocb128_decrypt(ptr::addr_of_mut!((*ctx).ocb), in_, out, len) == 0 {
            return 0;
        }
        1
    }
}

/// `aes_generic_ocb_copy_ctx` — `cipher_aes_ocb.c:92-97`.
///
/// # Safety
/// `dst`/`src` are live `PROV_AES_OCB_CTX`es; the copy points `dst`'s OCB context at `dst`'s own
/// schedules.
unsafe fn aes_generic_ocb_copy_ctx(dst: *mut ProvAesOcbCtx, src: *mut ProvAesOcbCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ocb128_copy_ctx(
            ptr::addr_of_mut!((*dst).ocb),
            ptr::addr_of_mut!((*src).ocb),
            ptr::addr_of_mut!((*dst).ksenc).cast(),
            ptr::addr_of_mut!((*dst).ksdec).cast(),
        )
    }
}

/// `cipher_hw_aes_ocb_generic_initkey` — `cipher_aes_ocb_hw.c:30-58`, the portable arm. The
/// authority's `OCB_SET_KEY_FN` macro cleans up the OCB context first, sets **both** schedules
/// (decryption needs both, because AAD uses encryption), and leaves `key_set` set.
///
/// # Safety
/// The `PROV_CIPHER_HW::init` contract; `ctx` is a `PROV_AES_OCB_CTX` and `key` is readable for
/// `keylen` bytes.
unsafe extern "C" fn cipher_hw_aes_ocb_generic_initkey(
    vctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `vctx` is a `PROV_AES_OCB_CTX`.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();
        let bits = (keylen * 8) as c_int;
        let ksenc = ptr::addr_of_mut!((*ctx).ksenc.ks);
        let ksdec = ptr::addr_of_mut!((*ctx).ksdec.ks);

        CRYPTO_ocb128_cleanup(ptr::addr_of_mut!((*ctx).ocb));
        AES_set_encrypt_key(key, bits, ksenc);
        AES_set_decrypt_key(key, bits, ksdec);
        if CRYPTO_ocb128_init(
            ptr::addr_of_mut!((*ctx).ocb),
            ksenc.cast(),
            ksdec.cast(),
            aes_block_encrypt,
            aes_block_decrypt,
            None,
        ) == 0
        {
            return 0;
        }
        (*ctx).key_set = 1;
        1
    }
}

/// `PROV_CIPHER_HW::cipher` is `NULL` for the OCB rows (`cipher_aes_ocb_hw.c:196-199`), because
/// the row's own `aes_generic_ocb_cipher` drives the mode. The crate's `ProvCipherHw::cipher` is
/// a plain function pointer rather than an `Option`, so a never-called stub stands in for the
/// authority's `NULL`.
///
/// # Safety
/// Never called.
unsafe extern "C" fn cipher_hw_aes_ocb_cipher_unused(
    _ctx: *mut ProvCipherCtx,
    _out: *mut c_uchar,
    _in_: *const c_uchar,
    _len: usize,
) -> c_int {
    fail()
}

static AES_OCB_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aes_ocb_generic_initkey,
    cipher: cipher_hw_aes_ocb_cipher_unused,
    copyctx: Some(cipher_hw_aes_ocb_copyctx_unused),
};

/// `aes_ocb_dupctx` does the copy itself, through `aes_generic_ocb_copy_ctx`
/// (`cipher_aes_ocb.c:332-349`), so the hw table has no `copyctx` to offer. The never-called stub
/// stands in for the authority's `NULL` field.
///
/// # Safety
/// Never called.
unsafe extern "C" fn cipher_hw_aes_ocb_copyctx_unused(
    _dst: *mut ProvCipherCtx,
    _src: *const ProvCipherCtx,
) {
}

/// `aes_ocb_init` — `cipher_aes_ocb.c:102-137`.
///
/// # Safety
/// The dispatch contract; `vctx` is a `PROV_AES_OCB_CTX`.
unsafe fn aes_ocb_init(
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
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        if is_running() == 0 {
            return fail();
        }

        (*ctx).aad_buf_len = 0;
        (*ctx).data_buf_len = 0;
        bits_set(ptr::addr_of_mut!((*ctx).base), CTX_ENC, enc != 0);

        if !iv.is_null() {
            if ivlen != (*ctx).base.ivlen {
                /* IV len must be 1 to 15 */
                if !(OCB_MIN_IV_LEN..=OCB_MAX_IV_LEN).contains(&ivlen) {
                    return fail_at(&err_sites::PROV_CIPHER_AES_OCB_119);
                }
                (*ctx).base.ivlen = ivlen;
            }
            if ossl_cipher_generic_initiv(ptr::addr_of_mut!((*ctx).base), iv, ivlen) == 0 {
                return fail();
            }
            (*ctx).iv_state = IV_STATE_BUFFERED;
        }
        if !key.is_null() {
            if keylen != (*ctx).base.keylen {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_130);
            }
            let hw = (*ctx).base.hw;
            if ((*hw).init)(ptr::addr_of_mut!((*ctx).base), key, keylen) == 0 {
                return fail();
            }
        }
        aes_ocb_set_ctx_params(vctx, params)
    }
}

/// `aes_ocb_einit` — `cipher_aes_ocb.c:139-144`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_ocb_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `aes_ocb_dinit` — `cipher_aes_ocb.c:146-151`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_ocb_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `aes_ocb_block_update_internal` — `cipher_aes_ocb.c:157-206`. Because of the way OCB works,
/// the AAD and the data are buffered identically; only the last block can be partial.
///
/// # Safety
/// Every pointer follows the caller's contract; `ciph` is one of the two local wrappers.
#[allow(clippy::too_many_arguments)]
unsafe fn aes_ocb_block_update_internal(
    ctx: *mut ProvAesOcbCtx,
    buf: *mut c_uchar,
    bufsz: *mut usize,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
    ciph: OcbCipherFn,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut outlint = 0usize;
        let mut out = out;
        let mut in_ = in_;
        let mut inl = inl;

        let nextblocks = if *bufsz != 0 {
            ossl_cipher_fillblock(buf, bufsz, AES_BLOCK_SIZE, &mut in_, &mut inl)
        } else {
            inl & !(AES_BLOCK_SIZE - 1)
        };

        if *bufsz == AES_BLOCK_SIZE {
            if outsize < AES_BLOCK_SIZE {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_173);
            }
            if ciph(ctx, buf, out, AES_BLOCK_SIZE) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_177);
            }
            *bufsz = 0;
            outlint = AES_BLOCK_SIZE;
            if !out.is_null() {
                out = out.add(AES_BLOCK_SIZE);
            }
        }
        if nextblocks > 0 {
            outlint += nextblocks;
            if outsize < outlint {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_188);
            }
            if ciph(ctx, in_, out, nextblocks) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_192);
            }
            in_ = in_.add(nextblocks);
            inl -= nextblocks;
        }
        if inl != 0 && ossl_cipher_trailingdata(buf, bufsz, AES_BLOCK_SIZE, &mut in_, &mut inl) == 0
        {
            /* PROVerr already called */
            return fail();
        }

        *outl = outlint;
        c_int::from(inl == 0)
    }
}

/// `cipher_updateaad` — `cipher_aes_ocb.c:209-213`, a wrapper with the same signature as `cipher`.
///
/// # Safety
/// `in_` is readable for `len` bytes; `out` is ignored.
unsafe fn cipher_updateaad(
    ctx: *mut ProvAesOcbCtx,
    in_: *const c_uchar,
    _out: *mut c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { aes_generic_ocb_setaad(ctx, in_, len) }
}

/// `update_iv` — `cipher_aes_ocb.c:215-227`. The buffered IV is pushed into the OCB context once,
/// on the first data or AAD call, and a used or never-armed IV is a refusal.
///
/// # Safety
/// The `PROV_AES_OCB_CTX` contract.
unsafe fn update_iv(ctx: *mut ProvAesOcbCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if (*ctx).iv_state == IV_STATE_FINISHED || (*ctx).iv_state == IV_STATE_UNINITIALISED {
            return 0;
        }
        if (*ctx).iv_state == IV_STATE_BUFFERED {
            if aes_generic_ocb_setiv(
                ctx,
                (*ctx).base.iv.as_ptr(),
                (*ctx).base.ivlen,
                (*ctx).taglen,
            ) == 0
            {
                return 0;
            }
            (*ctx).iv_state = IV_STATE_COPIED;
        }
        1
    }
}

/// `aes_ocb_block_update` — `cipher_aes_ocb.c:229-258`.
///
/// # Safety
/// The dispatch contract; a NULL `out` selects the AAD arm.
unsafe extern "C" fn aes_ocb_block_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        if (*ctx).key_set == 0 || update_iv(ctx) == 0 {
            return fail();
        }

        if inl == 0 {
            *outl = 0;
            return 1;
        }

        /* Are we dealing with AAD or normal data here? */
        let (buf, buflen, fn_) = if out.is_null() {
            (
                ptr::addr_of_mut!((*ctx).aad_buf).cast::<c_uchar>(),
                ptr::addr_of_mut!((*ctx).aad_buf_len),
                cipher_updateaad as OcbCipherFn,
            )
        } else {
            (
                ptr::addr_of_mut!((*ctx).data_buf).cast::<c_uchar>(),
                ptr::addr_of_mut!((*ctx).data_buf_len),
                aes_generic_ocb_cipher as OcbCipherFn,
            )
        };
        aes_ocb_block_update_internal(ctx, buf, buflen, out, outl, outsize, in_, inl, fn_)
    }
}

/// `aes_ocb_block_final` — `cipher_aes_ocb.c:260-302`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_block_final(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        if is_running() == 0 {
            return fail();
        }

        /* If no block_update has run then the iv still needs to be set */
        if (*ctx).key_set == 0 || update_iv(ctx) == 0 {
            return fail();
        }

        *outl = 0;
        if (*ctx).data_buf_len > 0 {
            if aes_generic_ocb_cipher(ctx, (*ctx).data_buf.as_ptr(), out, (*ctx).data_buf_len) == 0
            {
                return fail();
            }
            *outl = (*ctx).data_buf_len;
            (*ctx).data_buf_len = 0;
        }
        if (*ctx).aad_buf_len > 0 {
            if aes_generic_ocb_setaad(ctx, (*ctx).aad_buf.as_ptr(), (*ctx).aad_buf_len) == 0 {
                return fail();
            }
            (*ctx).aad_buf_len = 0;
        }
        if (*ctx).base.enc_int() != 0 {
            /* If encrypting then just get the tag */
            if aes_generic_ocb_gettag(ctx, (*ctx).tag.as_mut_ptr(), (*ctx).taglen) == 0 {
                return fail();
            }
        } else {
            /* If decrypting then verify */
            if (*ctx).taglen == 0 {
                return fail();
            }
            if aes_generic_ocb_final(ctx) == 0 {
                return fail();
            }
        }
        /* Don't reuse the IV */
        (*ctx).iv_state = IV_STATE_FINISHED;
        1
    }
}

/// `aes_ocb_newctx` — `cipher_aes_ocb.c:304-319`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_ocb_newctx(
    provctx: *mut c_void,
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

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesOcbCtx>(), FILE, LINE);
        if !ctx.is_null() {
            ossl_cipher_generic_initkey(
                ctx,
                kbits,
                blkbits,
                ivbits,
                mode,
                flags,
                ptr::addr_of!(AES_OCB_HW),
                ptr::null_mut(),
            );
            (*ctx.cast::<ProvAesOcbCtx>()).taglen = OCB_DEFAULT_TAG_LEN;
        }
        let _ = provctx;
        ctx
    }
}

/// `aes_ocb_freectx` — `cipher_aes_ocb.c:321-330`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !vctx.is_null() {
            let ctx = vctx.cast::<ProvAesOcbCtx>();
            CRYPTO_ocb128_cleanup(ptr::addr_of_mut!((*ctx).ocb));
            ossl_cipher_generic_reset_ctx(vctx.cast());
            CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesOcbCtx>(), FILE, LINE);
        }
    }
}

/// `aes_ocb_dupctx` — `cipher_aes_ocb.c:332-349`. The shallow copy is repaired by
/// `aes_generic_ocb_copy_ctx`, which re-points the copy's OCB context at the copy's own
/// schedules and duplicates the L-table.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let in_ = vctx.cast::<ProvAesOcbCtx>();
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvAesOcbCtx>(), FILE, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(in_, ret.cast::<ProvAesOcbCtx>(), 1);
        if aes_generic_ocb_copy_ctx(ret.cast::<ProvAesOcbCtx>(), in_) == 0 {
            CRYPTO_free(ret, FILE, LINE);
            return ptr::null_mut();
        }
        ret
    }
}

/// `aes_ocb_set_ctx_params` — `cipher_aes_ocb.c:351-413`. The tag, the IV length and the key
/// length are the three keys; the IV-length arm resets `iv_state` when the length moves, so the
/// next update refuses until a new IV is supplied.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        if ossl_param_is_empty(params) {
            return 1;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_363);
            }
            if (*p).data.is_null() {
                /* Tag len must be 0 to 16 */
                if (*p).data_size > OCB_MAX_TAG_LEN {
                    return fail_at(&err_sites::PROV_CIPHER_AES_OCB_369);
                }
                (*ctx).taglen = (*p).data_size;
            } else {
                if (*ctx).base.enc_int() != 0 {
                    return fail_at(&err_sites::PROV_CIPHER_AES_OCB_375);
                }
                if (*p).data_size != (*ctx).taglen {
                    return fail_at(&err_sites::PROV_CIPHER_AES_OCB_379);
                }
                ptr::copy_nonoverlapping(
                    (*p).data.cast::<c_uchar>(),
                    (*ctx).tag.as_mut_ptr(),
                    (*p).data_size,
                );
            }
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() {
            let mut sz = 0usize;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut sz) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_388);
            }
            /* IV len must be 1 to 15 */
            if !(OCB_MIN_IV_LEN..=OCB_MAX_IV_LEN).contains(&sz) {
                return fail();
            }
            if (*ctx).base.ivlen != sz {
                (*ctx).base.ivlen = sz;
                (*ctx).iv_state = IV_STATE_UNINITIALISED;
            }
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() {
            let mut keylen = 0usize;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut keylen) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_404);
            }
            if (*ctx).base.keylen != keylen {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_408);
            }
        }
        1
    }
}

/// `aes_ocb_get_ctx_params` — `cipher_aes_ocb.c:415-473`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).base.ivlen) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_422);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).base.keylen) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_427);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).taglen) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_433);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if !p.is_null() {
            if (*ctx).base.ivlen > (*p).data_size {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_441);
            }
            if crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).base.oiv.as_ptr().cast(),
                (*ctx).base.ivlen,
            ) == 0
            {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_445);
            }
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null() {
            if (*ctx).base.ivlen > (*p).data_size {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_452);
            }
            if crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).base.iv.as_ptr().cast(),
                (*ctx).base.ivlen,
            ) == 0
            {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_456);
            }
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_463);
            }
            if (*ctx).base.enc_int() == 0 || (*p).data_size != (*ctx).taglen {
                return fail_at(&err_sites::PROV_CIPHER_AES_OCB_467);
            }
            ptr::copy_nonoverlapping(
                (*ctx).tag.as_ptr(),
                (*p).data.cast::<c_uchar>(),
                (*ctx).taglen,
            );
        }
        1
    }
}

/// `cipher_ocb_known_gettable_ctx_params` — `cipher_aes_ocb.c:475-483`.
static OCB_GETTABLE_CTX_PARAMS: [OsslParam; 7] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    END,
];

/// `cipher_ocb_gettable_ctx_params` — `cipher_aes_ocb.c:484-488`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cipher_ocb_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    OCB_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `cipher_ocb_known_settable_ctx_params` — `cipher_aes_ocb.c:490-495`.
static OCB_SETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    END,
];

/// `cipher_ocb_settable_ctx_params` — `cipher_aes_ocb.c:496-500`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn cipher_ocb_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    OCB_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `aes_ocb_cipher` — `cipher_aes_ocb.c:502-539`. A NULL input is `Final`, which generates or
/// checks the tag; otherwise the key and IV are checked before the mode runs.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ocb_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesOcbCtx>();

        if is_running() == 0 {
            return fail();
        }

        /* NULL input indicates Final, which must generate or check the tag. */
        if in_.is_null() {
            return aes_ocb_block_final(vctx, out, outl, outsize);
        }

        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_515);
        }

        if (*ctx).key_set == 0 || update_iv(ctx) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_528);
        }

        if aes_generic_ocb_cipher(ctx, in_, out, inl) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_OCB_533);
        }

        *outl = inl;
        1
    }
}

/// `IMPLEMENT_cipher` — `cipher_aes_ocb.c:541-578`, the three rows' dispatch tables. Each has
/// fourteen entries; the one-shot `CIPHER` is this row's own `aes_ocb_cipher`.
macro_rules! ocb_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the dispatch contract.
            unsafe {
                aes_ocb_newctx(
                    provctx,
                    $kbits,
                    AES_OCB_BLOCK_BITS,
                    OCB_DEFAULT_IV_LEN * 8,
                    EVP_CIPH_OCB_MODE,
                    AES_OCB_FLAGS,
                )
            }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_OCB_MODE,
                    AES_OCB_FLAGS,
                    $kbits,
                    AES_OCB_BLOCK_BITS,
                    OCB_DEFAULT_IV_LEN * 8,
                )
            }
        }

        pub(crate) static $table: [OsslDispatch; 15] = [
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: aes_ocb_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: aes_ocb_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: aes_ocb_block_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: aes_ocb_block_final as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
                function: aes_ocb_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FREECTX,
                function: aes_ocb_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
                function: aes_ocb_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: aes_ocb_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: aes_ocb_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: cipher_ocb_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: cipher_ocb_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

ocb_row!(
    aes256ocb_newctx,
    aes256ocb_get_params,
    AES256OCB_FUNCTIONS,
    256
);
ocb_row!(
    aes192ocb_newctx,
    aes192ocb_get_params,
    AES192OCB_FUNCTIONS,
    192
);
ocb_row!(
    aes128ocb_newctx,
    aes128ocb_get_params,
    AES128OCB_FUNCTIONS,
    128
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
// `ciphercommon_ccm.c` / `cipher_aes_ccm.c` / `cipher_aes_ccm_hw.c` — the three AES-CCM rows
// ---------------------------------------------------------------------------------------------

// CCM is a self-contained engine over the landed `crypto/modes/ccm128.c` (`src/modes/ccm.rs`):
// the row owns the AEAD length bookkeeping that CCM's construction requires -- the message length
// is fixed *before* the AAD, so `L` and `M` and `len` are context state rather than call
// arguments -- the TLS-record arm, and the tag emit/verify. `ciphercommon_ccm.c` is one of the
// build-generated `.c.in` templates (`produce_param_decoder` expands its two decoders into ~130
// lines), so the hand-written locate-each-key form stands in for them exactly as it does for
// `ciphercommon.c`'s and `cipher_aes_ocb.c`'s.
//
// **The AESNI hardware arm is declined, not compared.** `ossl_prov_aes_hw_ccm`
// (`cipher_aes_ccm_hw.c:70-73`) answers `AESNI_CAPABLE ? &aesni_ccm : &aes_ccm`, and
// `AESNI_CAPABLE` is `OPENSSL_ia32cap_P[1] & (1 << 25)` (`include/crypto/aes_platform.h:185`) --
// a property of the host CPU, which is D213's class exactly. The two arms differ in one place:
// `AES_HW_CCM_SET_KEY_FN` stores `ctx->str`, and the AESNI arm stores
// `aesni_ccm64_encrypt_blocks`/`_decrypt_blocks` there while the portable arm stores the `NULL`
// it is handed. `str` selects `CRYPTO_ccm128_encrypt_ccm64` over `CRYPTO_ccm128_encrypt` in
// `ossl_ccm_generic_auth_encrypt`/`_decrypt`; those two functions differ only in *how* the counter
// advances (`n` calls to `ctr64_inc` versus one `ctr64_add(..., n)`) and in nothing else -- the
// CMAC, the keystream, the `blocks` accounting, the tag and every refusal are identical, so the
// selection is not observable through any surface. This transcription is the portable arm;
// `RT-CIPHER` compares the provider's ciphertext and tag against the authority running the AESNI
// arm, which is what proves the choice unobservable rather than assuming it.

/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: usize = 13;
/// `EVP_CCM_TLS_FIXED_IV_LEN` — `include/openssl/evp.h:480`.
const EVP_CCM_TLS_FIXED_IV_LEN: usize = 4;
/// `EVP_CCM_TLS_EXPLICIT_IV_LEN` — `include/openssl/evp.h:482`.
const EVP_CCM_TLS_EXPLICIT_IV_LEN: usize = 8;
/// `AEAD_FLAGS` — `prov/ciphercommon_aead.h:16`, the flag pair every `IMPLEMENT_aead_cipher` row
/// passes: `PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV`.
///
/// **Shared, not AES's.** The AES, ARIA and SM4 CCM rows and the AES-SIV rows all pass it, so it is
/// named for the macro rather than for its first user (D271).
const AEAD_FLAGS: u64 = PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV;
/// `EVP_CIPH_CCM_MODE` — `include/openssl/evp.h:317`.
const EVP_CIPH_CCM_MODE: c_uint = 0x7;
/// The CCM rows' `blkbits` — every `IMPLEMENT_aead_cipher(..., ccm, CCM, ...)` invocation's sixth
/// argument, in `cipher_aes_ccm.c`, `cipher_aria_ccm.c` and `cipher_sm4_ccm.c` alike.
const CCM_BLOCK_BITS: usize = 8;
/// The CCM rows' `ivbits` — the same invocations' seventh argument.
const CCM_IV_BITS: usize = 96;
/// `UNINITIALISED_SIZET` — `prov/ciphercommon_aead.h:14`.
const UNINITIALISED_SIZET: usize = usize::MAX;
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD` — `core_names.h:181` (`"tlsaad"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_AAD: *const c_char = c"tlsaad".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD` — `core_names.h:182` (`"tlsaadpad"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD: *const c_char = c"tlsaadpad".as_ptr();
/// `OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED` — `core_names.h:184` (`"tlsivfixed"`).
const OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED: *const c_char = c"tlsivfixed".as_ptr();

/// The authority's run of five `unsigned int : 1` fields at the head of `PROV_CCM_CTX`
/// (`prov/ciphercommon_ccm.h:35-40`).
///
/// **The ABI packs them.** Consecutive bitfields of one type share an allocation unit on the x86-64
/// System V ABI, so the five bits occupy **four** bytes, not twenty. That is not a tidiness point:
/// the whole context is `OPENSSL_zalloc`'d, so its size is the allocation request an application's
/// `CRYPTO_set_mem_functions` receives, and modelling the five as five `unsigned int`s made every
/// CCM context eight bytes too large (D269). The bits are named after the authority's fields; the
/// positions are this crate's own, because the authority never exposes them.
#[repr(C)]
pub(crate) struct CcmFlags {
    /// The packed flag bits.
    pub bits: c_uint,
}

impl CcmFlags {
    /// `enc == 1`.
    const ENC: c_uint = 1 << 0;
    /// `key_set == 1`.
    const KEY_SET: c_uint = 1 << 1;
    /// `iv_set == 1`.
    const IV_SET: c_uint = 1 << 2;
    /// `tag_set == 1`.
    const TAG_SET: c_uint = 1 << 3;
    /// `len_set == 1`.
    const LEN_SET: c_uint = 1 << 4;

    /// `ctx->enc` as a `c_uint`, so the authority's `== 0`/`!= 0` tests read unchanged.
    fn enc(&self) -> c_uint {
        c_uint::from(self.bits & Self::ENC != 0)
    }
    /// `ctx->enc = ...`.
    fn set_enc(&mut self, value: c_int) {
        self.bits = set_bit(self.bits, Self::ENC, value != 0);
    }
    /// `ctx->key_set` as a `c_uint`.
    fn key_set(&self) -> c_uint {
        c_uint::from(self.bits & Self::KEY_SET != 0)
    }
    /// `ctx->key_set = ...`.
    fn set_key_set(&mut self, value: bool) {
        self.bits = set_bit(self.bits, Self::KEY_SET, value);
    }
    /// `ctx->iv_set` as a `c_uint`.
    fn iv_set(&self) -> c_uint {
        c_uint::from(self.bits & Self::IV_SET != 0)
    }
    /// `ctx->iv_set = ...`.
    fn set_iv_set(&mut self, value: bool) {
        self.bits = set_bit(self.bits, Self::IV_SET, value);
    }
    /// `ctx->tag_set` as a `c_uint`.
    fn tag_set(&self) -> c_uint {
        c_uint::from(self.bits & Self::TAG_SET != 0)
    }
    /// `ctx->tag_set = ...`.
    fn set_tag_set(&mut self, value: bool) {
        self.bits = set_bit(self.bits, Self::TAG_SET, value);
    }
    /// `ctx->len_set` as a `c_uint`.
    fn len_set(&self) -> c_uint {
        c_uint::from(self.bits & Self::LEN_SET != 0)
    }
    /// `ctx->len_set = ...`.
    fn set_len_set(&mut self, value: bool) {
        self.bits = set_bit(self.bits, Self::LEN_SET, value);
    }
}

/// The clear-or-set one bitfield assignment needs.
fn set_bit(bits: c_uint, mask: c_uint, value: bool) -> c_uint {
    if value {
        bits | mask
    } else {
        bits & !mask
    }
}

/// `ccm128_f` — `include/openssl/modes.h:40-44`, the block-stream entry point the `CCM64` assembly
/// path installs. Both arms this profile can select leave `PROV_CCM_CTX::str` NULL.
pub(crate) type Ccm128Fn = unsafe extern "C" fn(
    *const c_uchar,
    *mut c_uchar,
    usize,
    *const c_void,
    *const c_uchar,
    *mut c_uchar,
);

/// `PROV_CCM_CTX` — `prov/ciphercommon_ccm.h:34-55`, the base shared by the AES and ARIA CCM rows.
///
/// Both `flags` and `str` are load-bearing for the **size**: `str` is the `ccm128_f` the `CCM64`
/// assembly path would install, and although the crate reaches CCM through `crypto/modes/ccm128.c`'s
/// scalar path and leaves it NULL, it is eight bytes of a 416-byte allocation request.
#[repr(C)]
pub(crate) struct ProvCcmCtx {
    /// The five `unsigned int : 1` fields, packed.
    pub flags: CcmFlags,
    /// `size_t l` — the RFC 3610 `L` parameter.
    pub l: usize,
    /// `size_t m` — the RFC 3610 `M` parameter, the tag length.
    pub m: usize,
    /// `size_t keylen`.
    pub keylen: usize,
    /// `size_t tls_aad_len` — `UNINITIALISED_SIZET` until a TLS AAD arrives.
    pub tls_aad_len: usize,
    /// `size_t tls_aad_pad_sz`.
    pub tls_aad_pad_sz: usize,
    /// `unsigned char iv[GENERIC_BLOCK_SIZE]`.
    pub iv: [c_uchar; GENERIC_BLOCK_SIZE],
    /// `unsigned char buf[GENERIC_BLOCK_SIZE]` — the tag buffer, and the saved TLS AAD.
    pub buf: [c_uchar; GENERIC_BLOCK_SIZE],
    /// `CCM128_CONTEXT ccm_ctx` — the landed `crypto/modes/ccm128.c` context.
    pub ccm_ctx: CcmCtx,
    /// `ccm128_f str` — NULL here; see the struct's doc comment.
    #[allow(dead_code)] // size-only member: see the struct's doc comment
    pub str: Option<Ccm128Fn>,
    /// `const PROV_CCM_HW *hw`.
    pub hw: *const ProvCcmHw,
}

/// The authority's `union { OSSL_UNION_ALIGN; struct { unsigned char pad[16]; AES_KEY ks; } ks; }`
/// from `cipher_aes_ccm.h:17-38`.
///
/// Two things make this one larger than the plain `AES_KEY` union. The `pad[16]` exists so that the
/// s390x arm's `kmac.k` and `fc` overlap `ks.ks` and `ks.ks.rounds` -- the header says so -- and
/// although neither that arm nor its union member is compiled here, the sixteen bytes are still the
/// first member of the compiled union and still part of the object. Then `OSSL_UNION_ALIGN` adds the
/// usual eight-alignment, so the union is 260 rounded up to **264**, and the whole context is
/// `sizeof(PROV_CCM_CTX)` + 264 = 416 (D269).
#[repr(C, align(8))]
pub(crate) struct AesCcmKeyUnion {
    /// `unsigned char pad[16]`.
    #[allow(dead_code)] // size-only member: see the struct's doc comment
    pub pad: [c_uchar; 16],
    /// `AES_KEY ks` — at offset sixteen, as in the authority.
    pub ks: AesKey,
}

/// `PROV_AES_CCM_CTX` — `cipher_aes_ccm.h:15-46`.
#[repr(C)]
pub(crate) struct ProvAesCcmCtx {
    /// `PROV_CCM_CTX base` — must be first.
    pub base: ProvCcmCtx,
    /// `union { OSSL_UNION_ALIGN; struct { unsigned char pad[16]; AES_KEY ks; } ks; } ccm`.
    pub ks: AesCcmKeyUnion,
}

/// `PROV_CIPHER_FUNC(int, CCM_setkey, ...)` — `prov/ciphercommon_ccm.h:59`.
type CcmSetkeyFn = unsafe fn(*mut ProvCcmCtx, *const c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, CCM_setiv, ...)` — `prov/ciphercommon_ccm.h:61`.
type CcmSetivFn = unsafe fn(*mut ProvCcmCtx, *const c_uchar, usize, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, CCM_setaad, ...)` — `prov/ciphercommon_ccm.h:62`.
type CcmSetaadFn = unsafe fn(*mut ProvCcmCtx, *const c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, CCM_auth_encrypt, ...)` / `..._auth_decrypt` — the two share a shape.
type CcmAuthFn =
    unsafe fn(*mut ProvCcmCtx, *const c_uchar, *mut c_uchar, usize, *mut c_uchar, usize) -> c_int;
/// `PROV_CIPHER_FUNC(int, CCM_gettag, ...)` — `prov/ciphercommon_ccm.h:66`.
type CcmGettagFn = unsafe fn(*mut ProvCcmCtx, *mut c_uchar, usize) -> c_int;

/// `struct prov_ccm_hw_st` — `prov/ciphercommon_ccm.h:69-76`, the per-algorithm method table.
///
/// The authority also carries a `ccm128_f str` field on the *context* rather than here; it is
/// absent because both arms this profile can select leave it `NULL` (see the section note above).
pub(crate) struct ProvCcmHw {
    /// `OSSL_CCM_setkey_fn setkey`.
    pub setkey: CcmSetkeyFn,
    /// `OSSL_CCM_setiv_fn setiv`.
    pub setiv: CcmSetivFn,
    /// `OSSL_CCM_setaad_fn setaad`.
    pub setaad: CcmSetaadFn,
    /// `OSSL_CCM_auth_encrypt_fn auth_encrypt`.
    pub auth_encrypt: CcmAuthFn,
    /// `OSSL_CCM_auth_decrypt_fn auth_decrypt`.
    pub auth_decrypt: CcmAuthFn,
    /// `OSSL_CCM_gettag_fn gettag`.
    pub gettag: CcmGettagFn,
}

// ---------------------------------------------------------------------------------------------
// `ciphercommon_ccm.c` — the shared engine
// ---------------------------------------------------------------------------------------------

/// `ccm_get_ivlen` — `ciphercommon_ccm.c:68-71`: the nonce length `15 - L`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn ccm_get_ivlen(ctx: *const ProvCcmCtx) -> usize {
    // SAFETY: the caller's contract.
    // `l` is only ever written inside `ossl_ccm_set_ctx_params`'s validated `[2, 8]` window and
    // by `ossl_ccm_initctx`, so this cannot wrap; `wrapping_sub` states the authority's `size_t`
    // semantics rather than relying on that invariant, and `overflow-checks` is on in this
    // profile so a plain `-` would be a panic rather than a wrong number if it ever changed.
    unsafe { 15usize.wrapping_sub((*ctx).l) }
}

/// `ccm_tls_init` — `ciphercommon_ccm.c:26-55`.
///
/// # Safety
/// `ctx` is live; `aad` is readable for `alen` bytes.
unsafe fn ccm_tls_init(ctx: *mut ProvCcmCtx, aad: *const c_uchar, alen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 || alen != EVP_AEAD_TLS1_AAD_LEN {
            return 0;
        }

        /* Save the aad for later use. */
        ptr::copy_nonoverlapping(aad, (*ctx).buf.as_mut_ptr(), alen);
        (*ctx).tls_aad_len = alen;

        let mut len = ((*ctx).buf[alen - 2] as usize) << 8 | (*ctx).buf[alen - 1] as usize;
        if len < EVP_CCM_TLS_EXPLICIT_IV_LEN {
            return 0;
        }

        /* Correct length for explicit iv. */
        len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

        if (*ctx).flags.enc() == 0 {
            if len < (*ctx).m {
                return 0;
            }
            /* Correct length for tag. */
            len -= (*ctx).m;
        }
        (*ctx).buf[alen - 2] = (len >> 8) as c_uchar;
        (*ctx).buf[alen - 1] = (len & 0xff) as c_uchar;

        /* Extra padding: tag appended to record. */
        (*ctx).m as c_int
    }
}

/// `ccm_tls_iv_set_fixed` — `ciphercommon_ccm.c:57-66`.
///
/// # Safety
/// `ctx` is live; `fixed` is readable for `flen` bytes.
unsafe fn ccm_tls_iv_set_fixed(ctx: *mut ProvCcmCtx, fixed: *const c_uchar, flen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if flen != EVP_CCM_TLS_FIXED_IV_LEN {
            return 0;
        }

        /* Copy to first part of the iv. */
        ptr::copy_nonoverlapping(fixed, (*ctx).iv.as_mut_ptr(), flen);
        1
    }
}

/// The four keys `ossl_cipher_ccm_set_ctx_params_decoder` locates, each with the site of its own
/// repeated-parameter raise (`ciphercommon_ccm.c:108-153`). The first row's key is
/// `OSSL_CIPHER_PARAM_AEAD_IVLEN`, which `core_names.h:176` aliases to
/// `OSSL_CIPHER_PARAM_IVLEN` (`"ivlen"`) -- it is that alias rather than a second spelling, so
/// that is the constant used here.
const CCM_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 4] = [
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_108,
        OSSL_CIPHER_PARAM_IVLEN,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_123,
        OSSL_CIPHER_PARAM_AEAD_TAG,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_142,
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_153,
        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
    ),
];

/// The seven keys `ossl_cipher_ccm_get_ctx_params_decoder` locates, each with its raise site
/// (`ciphercommon_ccm.c:298-375`).
const CCM_GET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_298,
        OSSL_CIPHER_PARAM_IVLEN,
    ),
    (&err_sites::PROV_CIPHERCOMMON_CCM_307, OSSL_CIPHER_PARAM_IV),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_319,
        OSSL_CIPHER_PARAM_KEYLEN,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_342,
        OSSL_CIPHER_PARAM_AEAD_TAGLEN,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_351,
        OSSL_CIPHER_PARAM_AEAD_TAG,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_363,
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
    ),
    (
        &err_sites::PROV_CIPHERCOMMON_CCM_375,
        OSSL_CIPHER_PARAM_UPDATED_IV,
    ),
];

/// `ossl_ccm_settable_ctx_params` — `ciphercommon_ccm.c:169-173`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CCM_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `ossl_ccm_set_ctx_params` — `ciphercommon_ccm.c:175-247`.
///
/// The tag arm is where CCM's ordering shows: on the encryption side a *tag value* is refused
/// (`PROV_R_TAG_NOT_NEEDED`) because the tag is an output, while a *tag length* with a `NULL`
/// data pointer is how the caller sets `M`. The IV-length arm is the L window: the parameter
/// carries the nonce length and the context keeps `L = 15 - sz`, refused outside `L in [2, 8]`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &CCM_SET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<ProvCcmCtx>();

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_186);
            }
            if (*p).data_size & 1 != 0 || (*p).data_size < 4 || (*p).data_size > 16 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_190);
            }

            if !(*p).data.is_null() {
                if (*ctx).flags.enc() != 0 {
                    return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_196);
                }
                ptr::copy_nonoverlapping(
                    (*p).data.cast::<c_uchar>(),
                    (*ctx).buf.as_mut_ptr(),
                    (*p).data_size,
                );
                (*ctx).flags.set_tag_set(true);
            }
            (*ctx).m = (*p).data_size;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() {
            let mut sz = 0usize;
            if crate::params::OSSL_PARAM_get_size_t(p, &mut sz) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_207);
            }
            let ivlen = 15usize.wrapping_sub(sz);
            if !(2..=8).contains(&ivlen) {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_212);
            }
            if (*ctx).l != ivlen {
                (*ctx).l = ivlen;
                (*ctx).flags.set_iv_set(false);
            }
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_223);
            }
            let sz = ccm_tls_init(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size);
            if sz == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_228);
            }
            (*ctx).tls_aad_pad_sz = sz as usize;
        }

        let p =
            crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_236);
            }
            if ccm_tls_iv_set_fixed(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_240);
            }
        }
        1
    }
}

/// `ossl_ccm_gettable_ctx_params` — `ciphercommon_ccm.c:388-392`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CCM_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `ossl_ccm_get_ctx_params` — `ciphercommon_ccm.c:394-461`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if vctx.is_null() {
            return 0;
        }
        if let Some(site) = repeated_param_site(params, &CCM_GET_CTX_PARAMS_DECODER_KEYS) {
            return fail_at(site);
        }
        let ctx = vctx.cast::<ProvCcmCtx>();

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, ccm_get_ivlen(ctx)) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_403);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).m) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_408);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if !p.is_null() {
            if ccm_get_ivlen(ctx) > (*p).data_size {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_414);
            }
            if crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).iv.as_ptr().cast(),
                (*p).data_size,
            ) == 0
            {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_418);
            }
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null() {
            if ccm_get_ivlen(ctx) > (*p).data_size {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_425);
            }
            if crate::params::OSSL_PARAM_set_octet_string_or_ptr(
                p,
                (*ctx).iv.as_ptr().cast(),
                (*p).data_size,
            ) == 0
            {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_429);
            }
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).keylen) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_435);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).tls_aad_pad_sz) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_440);
        }

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            if (*ctx).flags.enc() == 0 || (*ctx).flags.tag_set() == 0 {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_446);
            }
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_450);
            }
            let hw = (*ctx).hw;
            if ((*hw).gettag)(ctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0 {
                return fail();
            }
            (*ctx).flags.set_tag_set(false);
            (*ctx).flags.set_iv_set(false);
            (*ctx).flags.set_len_set(false);
        }

        1
    }
}

/// `ccm_init` — `ciphercommon_ccm.c:463-491`.
///
/// # Safety
/// The dispatch contract.
unsafe fn ccm_init(
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
        let ctx = vctx.cast::<ProvCcmCtx>();

        if is_running() == 0 {
            return 0;
        }

        (*ctx).flags.set_enc(enc);

        if !iv.is_null() {
            if ivlen != ccm_get_ivlen(ctx) {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_476);
            }
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), ivlen);
            (*ctx).flags.set_iv_set(true);
        }
        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_484);
            }
            let hw = (*ctx).hw;
            if ((*hw).setkey)(ctx, key, keylen) == 0 {
                return 0;
            }
        }
        ossl_ccm_set_ctx_params(ctx.cast(), params)
    }
}

/// `ossl_ccm_einit` — `ciphercommon_ccm.c:493-498`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ccm_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `ossl_ccm_dinit` — `ciphercommon_ccm.c:500-505`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ccm_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `ossl_ccm_stream_update` — `ciphercommon_ccm.c:507-523`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_stream_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_514);
        }

        if ccm_cipher_internal(vctx.cast(), out, outl, in_, inl) == 0 {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_519);
        }
        1
    }
}

/// `ossl_ccm_stream_final` — `ciphercommon_ccm.c:525-546`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_stream_final(
    vctx: *mut c_void,
    _out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCcmCtx>();
        let dummy_in: c_uchar = 0;
        let mut dummy_out: c_uchar = 0;

        if is_running() == 0 {
            return 0;
        }

        /*
         * Encryption sets tag_set after processing the payload, while successful
         * decryption clears iv_set. Use those transitions to avoid processing an
         * operation twice.
         */
        if (*ctx).flags.key_set() == 0
            || ((*ctx).flags.iv_set() != 0
                && ((*ctx).flags.enc() == 0 || (*ctx).flags.tag_set() == 0)
                && ccm_cipher_internal(
                    ctx,
                    ptr::addr_of_mut!(dummy_out),
                    outl,
                    ptr::addr_of!(dummy_in),
                    0,
                ) <= 0)
        {
            return 0;
        }

        *outl = 0;
        1
    }
}

/// `ossl_ccm_cipher` — `ciphercommon_ccm.c:548-570`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn ossl_ccm_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCcmCtx>();

        if is_running() == 0 {
            return 0;
        }

        if in_.is_null() {
            return ossl_ccm_stream_final(vctx, out, outl, outsize);
        }

        if outsize < inl {
            return fail_at(&err_sites::PROV_CIPHERCOMMON_CCM_560);
        }

        if ccm_cipher_internal(ctx, out, outl, in_, inl) <= 0 {
            return 0;
        }

        *outl = inl;
        1
    }
}

/// `ccm_set_iv` — `ciphercommon_ccm.c:572-580`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn ccm_set_iv(ctx: *mut ProvCcmCtx, mlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let hw = (*ctx).hw;

        if ((*hw).setiv)(ctx, (*ctx).iv.as_ptr(), ccm_get_ivlen(ctx), mlen) == 0 {
            return 0;
        }
        (*ctx).flags.set_len_set(true);
        1
    }
}

/// `ccm_tls_cipher` — `ciphercommon_ccm.c:582-626`.
///
/// # Safety
/// `ctx` is live; `in`/`out` follow the dispatch contract.
unsafe fn ccm_tls_cipher(
    ctx: *mut ProvCcmCtx,
    out: *mut c_uchar,
    padlen: *mut usize,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rv = 0;
        let mut olen = 0usize;
        let mut in_ = in_;
        let mut out = out;

        'arm: {
            if is_running() == 0 {
                break 'arm;
            }

            /* Encrypt/decrypt must be performed in place */
            if in_.is_null()
                || out != in_.cast_mut()
                || len < EVP_CCM_TLS_EXPLICIT_IV_LEN + (*ctx).m
            {
                break 'arm;
            }

            /* If encrypting set explicit IV from sequence number (start of AAD) */
            if (*ctx).flags.enc() != 0 {
                ptr::copy_nonoverlapping((*ctx).buf.as_ptr(), out, EVP_CCM_TLS_EXPLICIT_IV_LEN);
            }
            /* Get rest of IV from explicit IV */
            ptr::copy_nonoverlapping(
                in_,
                (*ctx).iv.as_mut_ptr().add(EVP_CCM_TLS_FIXED_IV_LEN),
                EVP_CCM_TLS_EXPLICIT_IV_LEN,
            );
            /* Correct length value */
            let len = len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + (*ctx).m);
            if ccm_set_iv(ctx, len) == 0 {
                break 'arm;
            }

            /* Use saved AAD */
            let hw = (*ctx).hw;
            if ((*hw).setaad)(ctx, (*ctx).buf.as_ptr(), (*ctx).tls_aad_len) == 0 {
                break 'arm;
            }

            /* Fix buffer to point to payload */
            in_ = in_.add(EVP_CCM_TLS_EXPLICIT_IV_LEN);
            out = out.add(EVP_CCM_TLS_EXPLICIT_IV_LEN);
            if (*ctx).flags.enc() != 0 {
                if ((*hw).auth_encrypt)(ctx, in_, out, len, out.add(len), (*ctx).m) == 0 {
                    break 'arm;
                }
                olen = len + EVP_CCM_TLS_EXPLICIT_IV_LEN + (*ctx).m;
            } else {
                if ((*hw).auth_decrypt)(ctx, in_, out, len, in_.add(len).cast_mut(), (*ctx).m) == 0
                {
                    break 'arm;
                }
                olen = len;
            }
            rv = 1;
            break 'arm;
        }

        *padlen = olen;
        rv
    }
}

/// `ccm_cipher_internal` — `ciphercommon_ccm.c:629-...`.
///
/// # Safety
/// `ctx` is live; `out`/`in_` follow the dispatch contract.
unsafe fn ccm_cipher_internal(
    ctx: *mut ProvCcmCtx,
    out: *mut c_uchar,
    padlen: *mut usize,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rv = 0;
        let mut olen = 0usize;
        let hw = (*ctx).hw;

        /* If no key set, return error */
        if (*ctx).flags.key_set() == 0 {
            return 0;
        }

        if (*ctx).tls_aad_len != UNINITIALISED_SIZET {
            return ccm_tls_cipher(ctx, out, padlen, in_, len);
        }

        'arm: {
            /* EVP_*Final() doesn't return any data */
            if in_.is_null() && !out.is_null() {
                break 'arm;
            }

            if (*ctx).flags.iv_set() == 0 {
                break 'arm;
            }

            if out.is_null() {
                if in_.is_null() {
                    if ccm_set_iv(ctx, len) == 0 {
                        break 'arm;
                    }
                } else {
                    /* If we have AAD, we need a message length */
                    if (*ctx).flags.len_set() == 0 && len != 0 {
                        break 'arm;
                    }
                    if ((*hw).setaad)(ctx, in_, len) == 0 {
                        break 'arm;
                    }
                }
            } else {
                /* If not set length yet do it */
                if (*ctx).flags.len_set() == 0 && ccm_set_iv(ctx, len) == 0 {
                    break 'arm;
                }

                if (*ctx).flags.enc() != 0 {
                    if ((*hw).auth_encrypt)(ctx, in_, out, len, ptr::null_mut(), 0) == 0 {
                        break 'arm;
                    }
                    (*ctx).flags.set_tag_set(true);
                } else {
                    /* The tag must be set before actually decrypting data */
                    if (*ctx).flags.tag_set() == 0 {
                        break 'arm;
                    }

                    if ((*hw).auth_decrypt)(ctx, in_, out, len, (*ctx).buf.as_mut_ptr(), (*ctx).m)
                        == 0
                    {
                        break 'arm;
                    }
                    /* Finished - reset flags so calling this method again will fail */
                    (*ctx).flags.set_iv_set(false);
                    (*ctx).flags.set_tag_set(false);
                    (*ctx).flags.set_len_set(false);
                }
            }
            olen = len;
            rv = 1;
            break 'arm;
        }

        *padlen = olen;
        rv
    }
}

/// `ossl_ccm_initctx` — `ciphercommon_ccm.c:476-487`.
///
/// # Safety
/// `ctx` is a live, zeroed context.
unsafe fn ossl_ccm_initctx(ctx: *mut ProvCcmCtx, keybits: usize, hw: *const ProvCcmHw) {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).keylen = keybits / 8;
        (*ctx).flags.set_key_set(false);
        (*ctx).flags.set_iv_set(false);
        (*ctx).flags.set_tag_set(false);
        (*ctx).flags.set_len_set(false);
        (*ctx).l = 8;
        (*ctx).m = 12;
        (*ctx).tls_aad_len = UNINITIALISED_SIZET;
        (*ctx).hw = hw;
    }
}

/// `cipher_ccm_known_settable_ctx_params` — `ciphercommon_ccm.c:74-79`.
static CCM_SETTABLE_CTX_PARAMS: [OsslParam; 5] = [
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED),
    END,
];

/// `cipher_ccm_known_gettable_ctx_params` — `ciphercommon_ccm.c:250-258`.
static CCM_GETTABLE_CTX_PARAMS: [OsslParam; 8] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN),
    param_octet_string(OSSL_CIPHER_PARAM_IV),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD),
    END,
];

// ---------------------------------------------------------------------------------------------
// `cipher_aes_ccm.c` / `cipher_aes_ccm_hw.c` — the AES-specific arm
// ---------------------------------------------------------------------------------------------

/// `ccm_generic_aes_initkey` — `cipher_aes_ccm_hw.c:28-48`'s portable arm, which is the
/// `AES_HW_CCM_SET_KEY_FN(AES_set_encrypt_key, AES_encrypt, NULL, NULL)` expansion: set the
/// encryption schedule, initialise the CCM context over it, store `ctx->str = enc ? NULL : NULL`
/// (see the section note on the declined AESNI arm), and mark the key set.
///
/// # Safety
/// `ctx` is a `PROV_AES_CCM_CTX`; `key` is readable for `keylen` bytes.
unsafe fn ccm_generic_aes_initkey(
    ctx: *mut ProvCcmCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvAesCcmCtx>();
        let ks = ptr::addr_of_mut!((*actx).ks.ks);

        AES_set_encrypt_key(key, (keylen * 8) as c_int, ks);
        CRYPTO_ccm128_init(
            ptr::addr_of_mut!((*ctx).ccm_ctx),
            (*ctx).m as c_uint,
            (*ctx).l as c_uint,
            ks.cast(),
            aes_block_encrypt,
        );
        (*ctx).flags.set_key_set(true);
        1
    }
}

/// `int ossl_ccm_generic_setiv(PROV_CCM_CTX *, const unsigned char *, size_t, size_t)` —
/// `ciphercommon_ccm_hw.c:13-17`.
///
/// # Safety
/// The `PROV_CCM_HW::setiv` contract.
unsafe fn ossl_ccm_generic_setiv(
    ctx: *mut ProvCcmCtx,
    nonce: *const c_uchar,
    nlen: usize,
    mlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        c_int::from(CRYPTO_ccm128_setiv(ptr::addr_of_mut!((*ctx).ccm_ctx), nonce, nlen, mlen) == 0)
    }
}

/// `int ossl_ccm_generic_setaad(PROV_CCM_CTX *, const unsigned char *, size_t)` —
/// `ciphercommon_ccm_hw.c:19-24`. `CRYPTO_ccm128_aad` returns nothing, so this always answers 1.
///
/// # Safety
/// The `PROV_CCM_HW::setaad` contract.
unsafe fn ossl_ccm_generic_setaad(ctx: *mut ProvCcmCtx, aad: *const c_uchar, alen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ccm128_aad(ptr::addr_of_mut!((*ctx).ccm_ctx), aad, alen);
        1
    }
}

/// `int ossl_ccm_generic_gettag(PROV_CCM_CTX *, unsigned char *, size_t)` —
/// `ciphercommon_ccm_hw.c:26-29`.
///
/// # Safety
/// The `PROV_CCM_HW::gettag` contract.
unsafe fn ossl_ccm_generic_gettag(ctx: *mut ProvCcmCtx, tag: *mut c_uchar, tlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { c_int::from(CRYPTO_ccm128_tag(ptr::addr_of_mut!((*ctx).ccm_ctx), tag, tlen) > 0) }
}

/// `int ossl_ccm_generic_auth_encrypt(...)` — `ciphercommon_ccm_hw.c:31-47`. The `ctx->str != NULL`
/// arm is the declined AESNI one, so the `CRYPTO_ccm128_encrypt` arm is the whole function here.
///
/// # Safety
/// The `PROV_CCM_HW::auth_encrypt` contract.
unsafe fn ossl_ccm_generic_auth_encrypt(
    ctx: *mut ProvCcmCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    tag: *mut c_uchar,
    taglen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut rv = c_int::from(
            CRYPTO_ccm128_encrypt(ptr::addr_of_mut!((*ctx).ccm_ctx), in_, out, len) == 0,
        );

        if rv == 1 && !tag.is_null() {
            rv = c_int::from(CRYPTO_ccm128_tag(ptr::addr_of_mut!((*ctx).ccm_ctx), tag, taglen) > 0);
        }
        rv
    }
}

/// `int ossl_ccm_generic_auth_decrypt(...)` — `ciphercommon_ccm_hw.c:49-71`. A tag mismatch
/// **cleanses the output** before answering 0, which is an observable side effect the court sees.
///
/// # Safety
/// The `PROV_CCM_HW::auth_decrypt` contract.
unsafe fn ossl_ccm_generic_auth_decrypt(
    ctx: *mut ProvCcmCtx,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    expected_tag: *mut c_uchar,
    taglen: usize,
) -> c_int {
    // SAFETY: the caller's contract, plus the local tag buffer below.
    unsafe {
        let mut rv = c_int::from(
            CRYPTO_ccm128_decrypt(ptr::addr_of_mut!((*ctx).ccm_ctx), in_, out, len) == 0,
        );

        if rv != 0 {
            let mut tag = [0u8; 16];

            if CRYPTO_ccm128_tag(ptr::addr_of_mut!((*ctx).ccm_ctx), tag.as_mut_ptr(), taglen) == 0
                || CRYPTO_memcmp(tag.as_ptr().cast(), expected_tag.cast(), taglen) != 0
            {
                rv = 0;
            }
        }
        if rv == 0 {
            OPENSSL_cleanse(out.cast(), len);
        }
        rv
    }
}

/// `static const PROV_CCM_HW aes_ccm` — `cipher_aes_ccm_hw.c:50-57`.
static AES_CCM_HW: ProvCcmHw = ProvCcmHw {
    setkey: ccm_generic_aes_initkey,
    setiv: ossl_ccm_generic_setiv,
    setaad: ossl_ccm_generic_setaad,
    auth_encrypt: ossl_ccm_generic_auth_encrypt,
    auth_decrypt: ossl_ccm_generic_auth_decrypt,
    gettag: ossl_ccm_generic_gettag,
};

/// `const PROV_CCM_HW *ossl_prov_aes_hw_ccm(size_t keybits)` — `cipher_aes_ccm_hw.c:70-73`, the
/// portable arm. The AESNI arm's selection is declined (see the section note); its
/// `ossl_ccm_generic_*` methods are the same five, so only `setkey` differs.
///
/// # Safety
/// Always safe; the parameter is unused on this arm.
unsafe fn ossl_prov_aes_hw_ccm(_keybits: usize) -> *const ProvCcmHw {
    ptr::addr_of!(AES_CCM_HW)
}

/// `aes_ccm_newctx` — `cipher_aes_ccm.c:23-34`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_ccm_newctx(_provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_ccm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesCcmCtx>(), FILE_CCM, LINE);
        if !ctx.is_null() {
            ossl_ccm_initctx(ctx.cast(), keybits, ossl_prov_aes_hw_ccm(keybits));
        }
        ctx
    }
}

/// `aes_ccm_dupctx` — `cipher_aes_ccm.c:36-57`. The shallow copy's `ccm_ctx.key` still points at
/// the *original* schedule, so it is re-pointed at the copy's own.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ccm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = provctx.cast::<ProvAesCcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvAesCcmCtx>(),
            FILE_CCM,
            LINE,
        );
        if dupctx.is_null() {
            return ptr::null_mut();
        }
        let dup = dupctx.cast::<ProvAesCcmCtx>();
        (*dup)
            .base
            .ccm_ctx
            .repoint_key(ptr::addr_of_mut!((*dup).ks).cast());

        dupctx
    }
}

/// `aes_ccm_freectx` — `cipher_aes_ccm.c:59-65`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_ccm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `aes_ccm_newctx` allocated.
    unsafe { CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesCcmCtx>(), FILE_CCM, LINE) };
}

/// The allocation-tracking `file` argument for this section's allocations: `cipher_aes_ccm.c`.
const FILE_CCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ccm.c".as_ptr();

/// `IMPLEMENT_aead_cipher` — `prov/ciphercommon_aead.h:18-67`, the CCM rows' dispatch tables. Each
/// has fourteen entries; `CIPHER` is the shared `ossl_ccm_cipher`, `UPDATE` and `FINAL` the shared
/// stream pair, and `GET_PARAMS` is the row's own `blkbits`/`ivbits` triple.
///
/// **The three per-family items are parameters, not fixed**, because the AES, ARIA and SM4 CCM rows
/// differ in exactly those three: the `newctx`/`dupctx`/`freectx` trio each `cipher_<alg>_ccm.c`
/// declares and the context type behind them. Everything else — including `blkbits` and `ivbits`,
/// which all three families pass as `8` and `96` — is shared, which is what makes one macro the
/// honest expansion of one authority macro rather than three transcriptions of it.
///
/// The expansion writes only `pub(crate)` function items and a `'static` table — no exported
/// symbol — so the project's ban on `macro_rules!`-generated exports is not engaged.
macro_rules! ccm_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr, $newctx_impl:path,
     $freectx:path, $dupctx:path) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the dispatch contract.
            unsafe { $newctx_impl(provctx, $kbits) }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_CCM_MODE,
                    AEAD_FLAGS,
                    $kbits,
                    CCM_BLOCK_BITS,
                    CCM_IV_BITS,
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
                function: ossl_ccm_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: ossl_ccm_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: ossl_ccm_stream_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: ossl_ccm_stream_final as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
                function: ossl_ccm_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
                function: $getparams as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                function: ossl_ccm_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: ossl_ccm_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                function: ossl_cipher_generic_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: ossl_ccm_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: ossl_ccm_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

ccm_row!(
    aes128ccm_newctx,
    aes128ccm_get_params,
    AES128CCM_FUNCTIONS,
    128,
    aes_ccm_newctx,
    aes_ccm_freectx,
    aes_ccm_dupctx
);
ccm_row!(
    aes192ccm_newctx,
    aes192ccm_get_params,
    AES192CCM_FUNCTIONS,
    192,
    aes_ccm_newctx,
    aes_ccm_freectx,
    aes_ccm_dupctx
);
ccm_row!(
    aes256ccm_newctx,
    aes256ccm_get_params,
    AES256CCM_FUNCTIONS,
    256,
    aes_ccm_newctx,
    aes_ccm_freectx,
    aes_ccm_dupctx
);

// ---------------------------------------------------------------------------------------------
// `cipher_aria_ccm*.c` and `cipher_sm4_ccm*.c` — the ARIA and SM4 CCM rows
// ---------------------------------------------------------------------------------------------
//
// Both families are the AES-CCM shape one algorithm over: the same `ciphercommon_ccm.c` engine, the
// same six `ossl_ccm_generic_*` methods, and a `ccm_row!` invocation whose only differences are the
// three per-family items the macro takes as parameters.
//
// Three things are worth stating where they can be seen.
//
// **`str` is written, not merely absent.** `ccm_aria_initkey` sets `ctx->str = NULL`
// (`cipher_aria_ccm_hw.c:25`) and the SM4 macro sets `ctx->str = ctx->enc ? fn_ccm_enc : fn_ccm_dec`
// with both call sites passing `NULL` (`cipher_sm4_ccm_hw.c:22`) -- so the value the authority
// produces is NULL on every path, which is what the context's `zalloc` already leaves. The crate
// assigns it anyway, because `PROV_CCM_CTX::str` is a field the authority writes and a transcription
// that relied on the allocator would be right by accident rather than by construction.
//
// **Neither hw table has an assembly arm in this profile.** `cipher_sm4_ccm_hw.c:63-72` selects
// `cipher_sm4_ccm_hw_x86_64.inc`'s `hw_x86_64_sm4_ccm` when `HWSM4_CAPABLE_X86_64` reports the
// extension, and the `.inc`'s `initkey` is the same `SM4_HW_CCM_SET_KEY_FN` expansion with
// `hw_x86_64_sm4_set_key`/`hw_x86_64_sm4_encrypt` in place of the C pair. The assembly is declined
// for the reason D266 records for SM4 generally, so `ossl_prov_sm4_hw_ccm` answers the C table and
// the capability test is not transcribed: a function that always returns the same pointer would be
// a branch the crate cannot take either way.
//
// **`cipher_aria_ccm.c` and `cipher_sm4_ccm.c` are source-tree files**, so their `__FILE__` carries
// the `../../src/openssl-3.6.4/` prefix, as every other provider cipher row's here does.

/// The allocation-tracking `file` argument for the ARIA CCM rows' allocations.
const FILE_ARIA_CCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aria_ccm.c".as_ptr();
/// The allocation-tracking `file` argument for the SM4 CCM row's allocation.
const FILE_SM4_CCM: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_ccm.c".as_ptr();

/// `PROV_ARIA_CCM_CTX` — `cipher_aria_ccm.h:14-20`. Unlike the AES-CCM union this one has no
/// leading `unsigned char pad[16]`, so `ARIA_KEY`'s 276 bytes are the whole union's content and the
/// eight-alignment rounds them to 280: 152 + 280 = **432**, which the unit test binds (D269).
#[repr(C)]
pub(crate) struct ProvAriaCcmCtx {
    /// `PROV_CCM_CTX base; /* Must be first */`.
    pub base: ProvCcmCtx,
    /// `union { OSSL_UNION_ALIGN; ARIA_KEY ks; } ks`.
    pub ks: crate::aria::AriaKey,
}

/// `PROV_SM4_CCM_CTX` — `cipher_sm4_ccm.h:15-22`. `SM4_KEY` is 128 bytes and already a multiple of
/// eight, so the union adds no padding and this is 152 + 128 = **280**.
#[repr(C)]
pub(crate) struct ProvSm4CcmCtx {
    /// `PROV_CCM_CTX base; /* Must be first */`.
    pub base: ProvCcmCtx,
    /// `union { OSSL_UNION_ALIGN; SM4_KEY ks; } ks`.
    pub ks: crate::sm4::Sm4Key,
}

/// `ccm_aria_initkey` — `cipher_aria_ccm_hw.c:16-28`.
///
/// **The schedule setter's return value is ignored.** `cipher_aria_ccm_hw.c` does not test
/// `ossl_aria_set_encrypt_key`'s answer and answers 1 unconditionally, which is why the ARIA CCM
/// rows add no raise site even though the same setter has one in `cipher_aria_hw.c` (D270).
///
/// # Safety
/// `ctx` is a `PROV_ARIA_CCM_CTX`; `key` is readable for `keylen` bytes.
unsafe fn ccm_aria_initkey(ctx: *mut ProvCcmCtx, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvAriaCcmCtx>();
        let ks: *mut crate::aria::AriaKey = ptr::addr_of_mut!((*actx).ks);

        crate::aria::ossl_aria_set_encrypt_key(key, (keylen * 8) as c_int, ks);
        CRYPTO_ccm128_init(
            ptr::addr_of_mut!((*ctx).ccm_ctx),
            (*ctx).m as c_uint,
            (*ctx).l as c_uint,
            ks.cast(),
            aria_block_encrypt,
        );
        (*ctx).str = None;
        (*ctx).flags.set_key_set(true);
        1
    }
}

/// `ccm_sm4_initkey` — `cipher_sm4_ccm_hw.c:25-52`'s portable arm, which is the
/// `SM4_HW_CCM_SET_KEY_FN(ossl_sm4_set_key, ossl_sm4_encrypt, NULL, NULL)` expansion.
///
/// **`ossl_sm4_set_key` takes no bit count**, unlike every other schedule setter on this surface:
/// SM4 has one key size and the function's own signature says so.
///
/// # Safety
/// `ctx` is a `PROV_SM4_CCM_CTX`; `key` is readable for sixteen bytes.
unsafe fn ccm_sm4_initkey(ctx: *mut ProvCcmCtx, key: *const c_uchar, _keylen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let actx = ctx.cast::<ProvSm4CcmCtx>();
        let ks: *mut crate::sm4::Sm4Key = ptr::addr_of_mut!((*actx).ks);

        crate::sm4::ossl_sm4_set_key(key, ks);
        CRYPTO_ccm128_init(
            ptr::addr_of_mut!((*ctx).ccm_ctx),
            (*ctx).m as c_uint,
            (*ctx).l as c_uint,
            ks.cast(),
            sm4_block_encrypt,
        );
        // `ctx->enc ? NULL : NULL` -- both arms of the authority's ternary are NULL here.
        (*ctx).str = None;
        (*ctx).flags.set_key_set(true);
        1
    }
}

/// `static const PROV_CCM_HW ccm_aria` — `cipher_aria_ccm_hw.c:30-37`.
static ARIA_CCM_HW: ProvCcmHw = ProvCcmHw {
    setkey: ccm_aria_initkey,
    setiv: ossl_ccm_generic_setiv,
    setaad: ossl_ccm_generic_setaad,
    auth_encrypt: ossl_ccm_generic_auth_encrypt,
    auth_decrypt: ossl_ccm_generic_auth_decrypt,
    gettag: ossl_ccm_generic_gettag,
};

/// `static const PROV_CCM_HW ccm_sm4` — `cipher_sm4_ccm_hw.c:54-61`.
static SM4_CCM_HW: ProvCcmHw = ProvCcmHw {
    setkey: ccm_sm4_initkey,
    setiv: ossl_ccm_generic_setiv,
    setaad: ossl_ccm_generic_setaad,
    auth_encrypt: ossl_ccm_generic_auth_encrypt,
    auth_decrypt: ossl_ccm_generic_auth_decrypt,
    gettag: ossl_ccm_generic_gettag,
};

/// `const PROV_CCM_HW *ossl_prov_aria_hw_ccm(size_t keybits)` — `cipher_aria_ccm_hw.c:38-41`.
/// ARIA has one CCM table and ignores `keybits`.
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_aria_hw_ccm(_keybits: usize) -> *const ProvCcmHw {
    ptr::addr_of!(ARIA_CCM_HW)
}

/// `const PROV_CCM_HW *ossl_prov_sm4_hw_ccm(size_t keybits)` — `cipher_sm4_ccm_hw_x86_64.inc:28-34`.
/// The C table is the answer on both sides of the extension test this profile declines.
///
/// # Safety
/// Always safe; a uniform signature the hw contract requires.
unsafe fn ossl_prov_sm4_hw_ccm(_keybits: usize) -> *const ProvCcmHw {
    ptr::addr_of!(SM4_CCM_HW)
}

/// `aria_ccm_newctx` — `cipher_aria_ccm.c:18-29`.
///
/// # Safety
/// The dispatch contract.
unsafe fn aria_ccm_newctx(_provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_ccm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAriaCcmCtx>(), FILE_ARIA_CCM, LINE);
        if !ctx.is_null() {
            ossl_ccm_initctx(ctx.cast(), keybits, ossl_prov_aria_hw_ccm(keybits));
        }
        ctx
    }
}

/// `aria_ccm_dupctx` — `cipher_aria_ccm.c:31-44`. The shallow copy's `ccm_ctx.key` still points at
/// the *original* schedule, so it is re-pointed at the copy's own.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_ccm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = provctx.cast::<ProvAriaCcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvAriaCcmCtx>(),
            FILE_ARIA_CCM,
            LINE,
        );
        if dupctx.is_null() {
            return ptr::null_mut();
        }
        let dup = dupctx.cast::<ProvAriaCcmCtx>();
        (*dup)
            .base
            .ccm_ctx
            .repoint_key(ptr::addr_of_mut!((*dup).ks).cast());

        dupctx
    }
}

/// `aria_ccm_freectx` — `cipher_aria_ccm.c:46-51`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_ccm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `aria_ccm_newctx` allocated.
    unsafe {
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvAriaCcmCtx>(),
            FILE_ARIA_CCM,
            LINE,
        )
    };
}

/// `sm4_ccm_newctx` — `cipher_sm4_ccm.c:18-29`.
///
/// # Safety
/// The dispatch contract.
unsafe fn sm4_ccm_newctx(_provctx: *mut c_void, keybits: usize) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_ccm_initctx` writes only within the allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvSm4CcmCtx>(), FILE_SM4_CCM, LINE);
        if !ctx.is_null() {
            ossl_ccm_initctx(ctx.cast(), keybits, ossl_prov_sm4_hw_ccm(keybits));
        }
        ctx
    }
}

/// `sm4_ccm_dupctx` — `cipher_sm4_ccm.c:31-44`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_ccm_dupctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = provctx.cast::<ProvSm4CcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            provctx,
            core::mem::size_of::<ProvSm4CcmCtx>(),
            FILE_SM4_CCM,
            LINE,
        );
        if dupctx.is_null() {
            return ptr::null_mut();
        }
        let dup = dupctx.cast::<ProvSm4CcmCtx>();
        (*dup)
            .base
            .ccm_ctx
            .repoint_key(ptr::addr_of_mut!((*dup).ks).cast());

        dupctx
    }
}

/// `sm4_ccm_freectx` — `cipher_sm4_ccm.c:46-51`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_ccm_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `sm4_ccm_newctx` allocated.
    unsafe {
        CRYPTO_clear_free(
            vctx,
            core::mem::size_of::<ProvSm4CcmCtx>(),
            FILE_SM4_CCM,
            LINE,
        )
    };
}

// `IMPLEMENT_aead_cipher(aria, ccm, CCM, AEAD_FLAGS, <kbits>, 8, 96)` — `cipher_aria_ccm.c:53-58`,
// and `IMPLEMENT_aead_cipher(sm4, ccm, CCM, AEAD_FLAGS, 128, 8, 96)` — `cipher_sm4_ccm.c:53`.
ccm_row!(
    aria128ccm_newctx,
    aria128ccm_get_params,
    ARIA128CCM_FUNCTIONS,
    128,
    aria_ccm_newctx,
    aria_ccm_freectx,
    aria_ccm_dupctx
);
ccm_row!(
    aria192ccm_newctx,
    aria192ccm_get_params,
    ARIA192CCM_FUNCTIONS,
    192,
    aria_ccm_newctx,
    aria_ccm_freectx,
    aria_ccm_dupctx
);
ccm_row!(
    aria256ccm_newctx,
    aria256ccm_get_params,
    ARIA256CCM_FUNCTIONS,
    256,
    aria_ccm_newctx,
    aria_ccm_freectx,
    aria_ccm_dupctx
);
ccm_row!(
    sm4128ccm_newctx,
    sm4128ccm_get_params,
    SM4128CCM_FUNCTIONS,
    128,
    sm4_ccm_newctx,
    sm4_ccm_freectx,
    sm4_ccm_dupctx
);

// ---------------------------------------------------------------------------------------------
// `cipher_aes_siv.c` / `cipher_aes_siv_hw.c` — the three AES-SIV rows
// ---------------------------------------------------------------------------------------------

// SIV is not a mode over the generic engine: the row is a thin shell over the landed
// `crypto/modes/siv128.c` transcription (`src/modes/siv128.rs`), which itself drives the crate's
// own CMAC and AES-CTR through EVP. What the shell owns is the **key split** (a 2n-octet key is n
// octets of CMAC key and n octets of CTR key), the two fetches that split implies, the tag
// get/set pair, and the `speed` parameter that lifts S2V's one-operation limit.
//
// Two things are worth reading twice. `siv_init` **ignores `iv` and `ivlen` entirely** — SIV's
// synthetic IV is the tag, so there is nothing for a caller's IV to do, and the row's `ivbits`
// is 0 — and the `UPDATE` and `CIPHER` dispatch entries are the *same function* (the authority's
// `#define siv_stream_update siv_cipher`), because the AAD arm is selected by `out == NULL`
// rather than by a separate call.

/// `SIV_FLAGS` — `cipher_aes_siv.c:32`, which is `AEAD_FLAGS` (`prov/ciphercommon_aead.h:16`).
const AES_SIV_FLAGS: u64 = PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV;
/// `EVP_CIPH_SIV_MODE` — `include/openssl/evp.h:321`.
const EVP_CIPH_SIV_MODE: c_uint = 0x10004;
/// The SIV rows' `blkbits` — `cipher_aes_siv.c:258-260`'s sixth argument.
const AES_SIV_BLOCK_BITS: usize = 8;
/// The SIV rows' `ivbits` — `cipher_aes_siv.c:258-260`'s seventh argument, and 0 is the point.
const AES_SIV_IV_BITS: usize = 0;
/// `OSSL_CIPHER_PARAM_SPEED` — `core_names.h:208` (`"speed"`).
const OSSL_CIPHER_PARAM_SPEED: *const c_char = c"speed".as_ptr();

/// `PROV_AES_SIV_CTX` — `cipher_aes_siv.h:26-37`, with `enc` as the `unsigned int : 1` run's own
/// allocation unit (as in `ProvAesOcbCtx`).
#[repr(C)]
pub(crate) struct ProvAesSivCtx {
    /// `unsigned int mode`.
    pub mode: c_uint,
    /// `unsigned int enc : 1`.
    pub enc: c_uint,
    /// `size_t keylen` — the input key length, **twice** the underlying cipher's.
    pub keylen: usize,
    /// `size_t taglen` — `SIV_LEN`, and not settable.
    pub taglen: usize,
    /// `SIV128_CONTEXT siv` — the embedded `src/modes/siv128.rs` context.
    pub siv: Siv128Context,
    /// `EVP_CIPHER *ctr` — fetched, so it must be freed.
    pub ctr: *mut EvpCipher,
    /// `EVP_CIPHER *cbc` — fetched, so it must be freed.
    pub cbc: *mut EvpCipher,
    /// `const PROV_CIPHER_HW_AES_SIV *hw`.
    pub hw: *const ProvSivHw,
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
}

/// `PROV_CIPHER_HW_AES_SIV` — `cipher_aes_siv.h:16-23`.
pub(crate) struct ProvSivHw {
    /// `int (*initkey)(void *ctx, const uint8_t *key, size_t keylen)`.
    pub initkey: unsafe fn(*mut c_void, *const c_uchar, usize) -> c_int,
    /// `int (*cipher)(void *ctx, unsigned char *out, const unsigned char *in, size_t len)`.
    pub cipher: unsafe fn(*mut c_void, *mut c_uchar, *const c_uchar, usize) -> c_int,
    /// `void (*setspeed)(void *ctx, int speed)`.
    pub setspeed: unsafe fn(*mut c_void, c_int),
    /// `int (*settag)(void *ctx, const unsigned char *tag, size_t tagl)`.
    pub settag: unsafe fn(*mut c_void, *const c_uchar, usize) -> c_int,
    /// `void (*cleanup)(void *ctx)`.
    pub cleanup: unsafe fn(*mut c_void),
    /// `int (*dupctx)(void *src, void *dst)`.
    pub dupctx: unsafe fn(*mut c_void, *mut c_void) -> c_int,
}

/// The allocation-tracking `file` argument for this section's allocations: `cipher_aes_siv.c`.
const FILE_SIV: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c".as_ptr();

/// `aes_siv_newctx` — `cipher_aes_siv.c:37-54`.
///
/// `keybits` is already the **doubled** value: `IMPLEMENT_cipher`'s `newctx` wrapper passes
/// `2 * kbits`, so `AES-128-SIV` arrives as 256 and `ctx->keylen` is 32.
///
/// **SIV sets `ctx->libctx` at `newctx`, not at `initkey`, and that is why this assignment is
/// load-bearing.** `aes_siv_initkey` is the row's own (`cipher_aes_siv_hw.c`), so it never reaches
/// `ossl_cipher_generic_initkey`'s `if (provctx != NULL) ctx->libctx = PROV_LIBCTX_OF(provctx)`:
/// nothing else in this row would set the field. It is read by `aes_siv_initkey`'s two
/// `EVP_CIPHER_fetch(ctx->libctx, …)` calls and by the `EVP_MAC_fetch(libctx, "CMAC", NULL)` inside
/// `ossl_siv128_init`, so a NULL here does not fail the operation — it silently redirects both
/// sub-fetches into the **global** `OSSL_LIB_CTX`, and the row's ciphertext is unchanged. That is
/// the divergence `RT-CIPHER`'s `defltsiv.libctx.*` arm makes observable, and the default
/// provider now publishes a real `PROV_CTX` (D241), so the macro's argument is no longer NULL.
///
/// # Safety
/// The dispatch contract.
unsafe fn aes_siv_newctx(
    provctx: *mut c_void,
    keybits: usize,
    mode: c_uint,
    _flags: u64,
) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_siv128_init` is only reached through `siv_init`.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvAesSivCtx>(), FILE_SIV, LINE);
        if !ctx.is_null() {
            let ctx = ctx.cast::<ProvAesSivCtx>();
            (*ctx).taglen = SIV_LEN;
            (*ctx).mode = mode;
            (*ctx).keylen = keybits / 8;
            (*ctx).hw = ossl_prov_cipher_hw_aes_siv();
            /* Unconditional, as the authority's line is: `PROV_LIBCTX_OF` is itself NULL-safe. */
            (*ctx).libctx = crate::provider::ctx::prov_libctx_of(provctx);
        }
        ctx
    }
}

/// `aes_siv_freectx` — `cipher_aes_siv.c:56-63`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_siv_freectx(vctx: *mut c_void) {
    // SAFETY: the context is the one `aes_siv_newctx` allocated.
    unsafe {
        if !vctx.is_null() {
            let ctx = vctx.cast::<ProvAesSivCtx>();
            ((*(*ctx).hw).cleanup)(vctx);
            CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAesSivCtx>(), FILE_SIV, LINE);
        }
    }
}

/// `siv_dupctx` — `cipher_aes_siv.c:65-82`. The copy is made by the hw's `dupctx`, which
/// up-refs the two ciphers and repairs the embedded context's pointers.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siv_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let in_ = vctx.cast::<ProvAesSivCtx>();
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvAesSivCtx>(), FILE_SIV, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        if ((*(*in_).hw).dupctx)(vctx, ret) == 0 {
            CRYPTO_free(ret, FILE_SIV, LINE);
            return ptr::null_mut();
        }
        ret
    }
}

/// `siv_init` — `cipher_aes_siv.c:84-103`. `iv`/`ivlen` are accepted and ignored; the key
/// length must be the row's own, and `keylen` handed to the hw is `ctx->keylen` (the whole
/// doubled key) rather than the caller's argument, which is the same value by then.
///
/// # Safety
/// The dispatch contract.
unsafe fn siv_init(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    _iv: *const c_uchar,
    _ivlen: usize,
    params: *const OsslParam,
    enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();

        if is_running() == 0 {
            return 0;
        }

        (*ctx).enc = c_uint::from(enc != 0);

        if !key.is_null() {
            if keylen != (*ctx).keylen {
                return fail_at(&err_sites::PROV_CIPHER_AES_SIV_90);
            }
            if ((*(*ctx).hw).initkey)(vctx, key, (*ctx).keylen) == 0 {
                return 0;
            }
        }
        aes_siv_set_ctx_params(vctx, params)
    }
}

/// `siv_einit` — `cipher_aes_siv.c:105-111`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siv_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { siv_init(vctx, key, keylen, iv, ivlen, params, 1) }
}

/// `siv_dinit` — `cipher_aes_siv.c:113-119`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siv_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { siv_init(vctx, key, keylen, iv, ivlen, params, 0) }
}

/// `siv_cipher` — `cipher_aes_siv.c:121-140`, and the `UPDATE` entry as well.
///
/// The `out != NULL` guard on the size check matters: the AAD call passes `out == NULL` and the
/// final call passes `in == NULL`, and neither is a buffered write to be sized.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siv_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();

        if is_running() == 0 {
            return 0;
        }

        if !out.is_null() && outsize < inl {
            return fail_at(&err_sites::PROV_CIPHER_AES_SIV_122);
        }

        if ((*(*ctx).hw).cipher)(vctx, out, in_, inl) <= 0 {
            return 0;
        }

        if !outl.is_null() {
            *outl = inl;
        }
        1
    }
}

/// `siv_stream_final` — `cipher_aes_siv.c:142-155`. The final call is the hw's `cipher` with a
/// NULL input, which is `ossl_siv128_finish` — the tag computed by the encryption, or the
/// verdict on the tag the decryption verified.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn siv_stream_final(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    _outsize: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();

        if is_running() == 0 {
            return 0;
        }

        if ((*(*ctx).hw).cipher)(vctx, out, ptr::null(), 0) == 0 {
            return 0;
        }

        if !outl.is_null() {
            *outl = 0;
        }
        1
    }
}

/// `aes_siv_get_ctx_params` — `cipher_aes_siv.c:157-183`.
///
/// The tag arm refuses three different things with one reason: a decryption context has no tag
/// to hand back, a size that is not `taglen` is wrong, and a `set_octet_string` failure is the
/// caller's buffer.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_siv_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() && (*p).data_type == OSSL_PARAM_OCTET_STRING {
            let refuse = (*ctx).enc == 0
                || (*p).data_size != (*ctx).taglen
                || crate::params::OSSL_PARAM_set_octet_string(
                    p,
                    ptr::addr_of!((*ctx).siv.tag).cast::<c_void>(),
                    (*ctx).taglen,
                ) == 0;
            if refuse {
                return fail_at(&err_sites::PROV_CIPHER_AES_SIV_161);
            }
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).taglen) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_SIV_167);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, (*ctx).keylen) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_AES_SIV_172);
        }
        1
    }
}

/// `cipher_siv_known_gettable_ctx_params` — `cipher_aes_siv.c:185-190`.
static SIV_GETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    END,
];

/// `aes_siv_gettable_ctx_params` — `cipher_aes_siv.c:191-196`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_siv_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SIV_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `aes_siv_set_ctx_params` — `cipher_aes_siv.c:198-233`.
///
/// Three asymmetries are contract rather than accident: a tag on an **encryption** context is
/// ignored with success (`return 1`, not a refusal); a `keylen` that differs from the row's is a
/// bare `return 0` with **no raise**; and the function always ends by resetting
/// `sctx->final_ret` to `-1`, which is what makes a re-init of a used context behave like a new
/// one.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_siv_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        let mut speed: c_uint = 0;

        if ossl_param_is_empty(params) {
            return 1;
        }

        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if !p.is_null() {
            if (*ctx).enc != 0 {
                return 1;
            }
            if (*p).data_type != OSSL_PARAM_OCTET_STRING
                || ((*(*ctx).hw).settag)(vctx, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0
            {
                return fail_at(&err_sites::PROV_CIPHER_AES_SIV_206);
            }
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
        if !p.is_null() {
            if crate::params::OSSL_PARAM_get_uint(p, &mut speed) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_SIV_213);
            }
            ((*(*ctx).hw).setspeed)(vctx, speed as c_int);
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() {
            let mut keylen = 0usize;

            if crate::params::OSSL_PARAM_get_size_t(p, &mut keylen) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_AES_SIV_223);
            }
            /* The key length can not be modified */
            if keylen != (*ctx).keylen {
                return 0;
            }
        }
        (*ctx).siv.final_ret = -1;

        1
    }
}

/// `cipher_siv_known_settable_ctx_params` — `cipher_aes_siv.c:235-241`.
static SIV_SETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_uint(OSSL_CIPHER_PARAM_SPEED),
    param_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG),
    END,
];

/// `aes_siv_settable_ctx_params` — `cipher_aes_siv.c:242-247`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_siv_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SIV_SETTABLE_CTX_PARAMS.as_ptr()
}

// ---------------------------------------------------------------------------------------------
// `cipher_aes_siv_hw.c` — the portable arm
// ---------------------------------------------------------------------------------------------

/// `aes_siv_initkey` — `cipher_aes_siv_hw.c:18-58`: free any previous ciphers, fetch the
/// CBC/CTR pair for **half** the key, and hand the whole key to `ossl_siv128_init` with the half
/// length.
///
/// The `default: break` arm leaves both fetches NULL, which the following test turns into a 0.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::initkey` contract; `ctx` is a `PROV_AES_SIV_CTX` and `key` is
/// readable for `keylen` bytes.
unsafe fn aes_siv_initkey(vctx: *mut c_void, key: *const c_uchar, keylen: usize) -> c_int {
    // SAFETY: the caller's contract; `vctx` is a `PROV_AES_SIV_CTX`.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        let klen = keylen / 2;
        let libctx = (*ctx).libctx;
        let propq: *const c_char = ptr::null();

        EVP_CIPHER_free((*ctx).cbc);
        EVP_CIPHER_free((*ctx).ctr);
        (*ctx).cbc = ptr::null_mut();
        (*ctx).ctr = ptr::null_mut();

        match klen {
            16 => {
                (*ctx).cbc = EVP_CIPHER_fetch(libctx, c"AES-128-CBC".as_ptr(), propq);
                (*ctx).ctr = EVP_CIPHER_fetch(libctx, c"AES-128-CTR".as_ptr(), propq);
            }
            24 => {
                (*ctx).cbc = EVP_CIPHER_fetch(libctx, c"AES-192-CBC".as_ptr(), propq);
                (*ctx).ctr = EVP_CIPHER_fetch(libctx, c"AES-192-CTR".as_ptr(), propq);
            }
            32 => {
                (*ctx).cbc = EVP_CIPHER_fetch(libctx, c"AES-256-CBC".as_ptr(), propq);
                (*ctx).ctr = EVP_CIPHER_fetch(libctx, c"AES-256-CTR".as_ptr(), propq);
            }
            _ => {}
        }
        if (*ctx).cbc.is_null() || (*ctx).ctr.is_null() {
            return 0;
        }
        /*
         * klen is the length of the underlying cipher, not the input key,
         * which should be twice as long
         */
        ossl_siv128_init(
            ptr::addr_of_mut!((*ctx).siv),
            key,
            klen as c_int,
            (*ctx).cbc,
            (*ctx).ctr,
            libctx,
            propq,
        )
    }
}

/// `aes_siv_dupctx` — `cipher_aes_siv_hw.c:61-79`. The ciphers are up-ref'd *before* the struct
/// copy, so the copy owns them too; the embedded context's three pointers are then cleared and
/// rebuilt by `ossl_siv128_copy_ctx`, which is the whole reason they are cleared.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::dupctx` contract; `in_vctx` and `out_vctx` are live
/// `PROV_AES_SIV_CTX`es.
unsafe fn aes_siv_dupctx(in_vctx: *mut c_void, out_vctx: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let in_ = in_vctx.cast::<ProvAesSivCtx>();
        let out = out_vctx.cast::<ProvAesSivCtx>();

        if !(*in_).cbc.is_null() && EVP_CIPHER_up_ref((*in_).cbc) == 0 {
            return 0;
        }
        if !(*in_).ctr.is_null() && EVP_CIPHER_up_ref((*in_).ctr) == 0 {
            EVP_CIPHER_free((*in_).cbc);
            return 0;
        }

        // SAFETY: the bitwise copy C's `*out = *in` performs; both are live `PROV_AES_SIV_CTX`es.
        ptr::copy_nonoverlapping(in_, out, 1);
        (*out).siv.cipher_ctx = ptr::null_mut();
        (*out).siv.mac_ctx_init = ptr::null_mut();
        (*out).siv.mac = ptr::null_mut();
        if ossl_siv128_copy_ctx(ptr::addr_of_mut!((*out).siv), ptr::addr_of_mut!((*in_).siv)) == 0 {
            return 0;
        }

        1
    }
}

/// `aes_siv_settag` — `cipher_aes_siv_hw.c:81-87`.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::settag` contract.
unsafe fn aes_siv_settag(vctx: *mut c_void, tag: *const c_uchar, tagl: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        ossl_siv128_set_tag(ptr::addr_of_mut!((*ctx).siv), tag, tagl)
    }
}

/// `aes_siv_setspeed` — `cipher_aes_siv_hw.c:89-95`.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::setspeed` contract.
unsafe fn aes_siv_setspeed(vctx: *mut c_void, speed: c_int) {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        ossl_siv128_speed(ptr::addr_of_mut!((*ctx).siv), speed);
    }
}

/// `aes_siv_cleanup` — `cipher_aes_siv_hw.c:97-105`.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::cleanup` contract.
unsafe fn aes_siv_cleanup(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        ossl_siv128_cleanup(ptr::addr_of_mut!((*ctx).siv));
        EVP_CIPHER_free((*ctx).cbc);
        EVP_CIPHER_free((*ctx).ctr);
    }
}

/// `aes_siv_cipher` — `cipher_aes_siv_hw.c:107-125`. The three arms are the whole SIV protocol:
/// a NULL input is the finish, a NULL output is AAD, and anything else is the payload — through
/// `ossl_siv128_encrypt` or `ossl_siv128_decrypt` depending on the direction. Note that the
/// underlying answers are `-1`-or-`0` (`final_ret`) and `0`-or-`1`, so the comparisons are `== 0`
/// and `> 0` respectively rather than a uniform truth test.
///
/// # Safety
/// The `PROV_CIPHER_HW_AES_SIV::cipher` contract.
unsafe fn aes_siv_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvAesSivCtx>();
        let sctx = ptr::addr_of_mut!((*ctx).siv);

        /* EncryptFinal or DecryptFinal */
        if in_.is_null() {
            return c_int::from(ossl_siv128_finish(sctx) == 0);
        }

        /* Deal with associated data */
        if out.is_null() {
            return c_int::from(ossl_siv128_aad(sctx, in_, len) == 1);
        }

        if (*ctx).enc != 0 {
            return c_int::from(ossl_siv128_encrypt(sctx, in_, out, len) > 0);
        }

        c_int::from(ossl_siv128_decrypt(sctx, in_, out, len) > 0)
    }
}

/// `static const PROV_CIPHER_HW_AES_SIV aes_siv_hw` — `cipher_aes_siv_hw.c:127-134`.
static AES_SIV_HW: ProvSivHw = ProvSivHw {
    initkey: aes_siv_initkey,
    cipher: aes_siv_cipher,
    setspeed: aes_siv_setspeed,
    settag: aes_siv_settag,
    cleanup: aes_siv_cleanup,
    dupctx: aes_siv_dupctx,
};

/// `const PROV_CIPHER_HW_AES_SIV *ossl_prov_cipher_hw_aes_siv(size_t keybits)` —
/// `cipher_aes_siv_hw.c:136-139`. The authority has one arm for all key lengths; the AES-NI
/// machinery is inside the fetched AES method, not here.
fn ossl_prov_cipher_hw_aes_siv() -> *const ProvSivHw {
    ptr::addr_of!(AES_SIV_HW)
}

/// `IMPLEMENT_cipher` — `cipher_aes_siv.c:249-306`, the three AES-SIV rows' dispatch tables.
///
/// Each has fourteen entries, and `UPDATE` and `CIPHER` are the *same* function pointer because
/// the authority's `#define siv_stream_update siv_cipher` makes them one. As with `ccm_row!`,
/// the expansion writes only `pub(crate)` items and a `'static` table.
macro_rules! siv_row {
    ($newctx:ident, $getparams:ident, $table:ident, $kbits:expr) => {
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the dispatch contract.
            unsafe { aes_siv_newctx(provctx, 2 * $kbits, EVP_CIPH_SIV_MODE, AES_SIV_FLAGS) }
        }

        unsafe extern "C" fn $getparams(params: *mut OsslParam) -> c_int {
            // SAFETY: the dispatch contract.
            unsafe {
                ossl_cipher_generic_get_params(
                    params,
                    EVP_CIPH_SIV_MODE,
                    AES_SIV_FLAGS,
                    2 * $kbits,
                    AES_SIV_BLOCK_BITS,
                    AES_SIV_IV_BITS,
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
                function: aes_siv_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_DUPCTX,
                function: siv_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                function: siv_einit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
                function: siv_dinit as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_UPDATE,
                function: siv_cipher as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_FINAL,
                function: siv_stream_final as *mut c_void,
            },
            OsslDispatch {
                function_id: crate::evp::cipher::OSSL_FUNC_CIPHER_CIPHER,
                function: siv_cipher as *mut c_void,
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
                function: aes_siv_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                function: aes_siv_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                function: aes_siv_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                function: aes_siv_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

siv_row!(
    aes128siv_newctx,
    aes128siv_get_params,
    AES128SIV_FUNCTIONS,
    128
);
siv_row!(
    aes192siv_newctx,
    aes192siv_get_params,
    AES192SIV_FUNCTIONS,
    192
);
siv_row!(
    aes256siv_newctx,
    aes256siv_get_params,
    AES256SIV_FUNCTIONS,
    256
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
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC),
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
            return fail_at(&err_sites::PROV_CIPHER_NULL_130);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, 0) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_NULL_135);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if !p.is_null()
            && crate::params::OSSL_PARAM_set_octet_ptr(p, (*ctx).tlsmac.cast(), (*ctx).tlsmacsize)
                == 0
        {
            return fail_at(&err_sites::PROV_CIPHER_NULL_141);
        }
        1
    }
}

/// `null_known_settable_ctx_params` — `cipher_null.c:147-150`.
static NULL_SETTABLE_CTX_PARAMS: [OsslParam; 2] =
    [param_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE), END];

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
            return fail_at(&err_sites::PROV_CIPHER_NULL_168);
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
alias!(N_CHACHA20, "ChaCha20");
// The **whole** alias sequence, OIDs included -- `prov/names.h:168-172`. The first version of this
// block used the primary names alone, which is the short-alias defect D244 exists for.
alias!(N_SM4_ECB, "SM4-ECB:1.2.156.10197.1.104.1");
alias!(N_SM4_CBC, "SM4-CBC:SM4:1.2.156.10197.1.104.2");
alias!(N_SM4_CTR, "SM4-CTR:1.2.156.10197.1.104.7");
alias!(N_SM4_OFB, "SM4-OFB:SM4-OFB128:1.2.156.10197.1.104.3");
alias!(N_SM4_CFB, "SM4-CFB:SM4-CFB128:1.2.156.10197.1.104.4");
// The **whole** alias sequence, OIDs included -- `prov/names.h:114-134`. ARIA's mode names carry
// their own OIDs under `1.2.410.200046.1.1.*`, and only the CBC rows carry a short alias
// (`ARIA128`/`ARIA192`/`ARIA256`), exactly as SM4's CBC carries `SM4`.
alias!(N_ARIA_256_ECB, "ARIA-256-ECB:1.2.410.200046.1.1.11");
alias!(N_ARIA_192_ECB, "ARIA-192-ECB:1.2.410.200046.1.1.6");
alias!(N_ARIA_128_ECB, "ARIA-128-ECB:1.2.410.200046.1.1.1");
alias!(N_ARIA_256_CBC, "ARIA-256-CBC:ARIA256:1.2.410.200046.1.1.12");
alias!(N_ARIA_192_CBC, "ARIA-192-CBC:ARIA192:1.2.410.200046.1.1.7");
alias!(N_ARIA_128_CBC, "ARIA-128-CBC:ARIA128:1.2.410.200046.1.1.2");
alias!(N_ARIA_256_OFB, "ARIA-256-OFB:1.2.410.200046.1.1.14");
alias!(N_ARIA_192_OFB, "ARIA-192-OFB:1.2.410.200046.1.1.9");
alias!(N_ARIA_128_OFB, "ARIA-128-OFB:1.2.410.200046.1.1.4");
alias!(N_ARIA_256_CFB, "ARIA-256-CFB:1.2.410.200046.1.1.13");
alias!(N_ARIA_192_CFB, "ARIA-192-CFB:1.2.410.200046.1.1.8");
alias!(N_ARIA_128_CFB, "ARIA-128-CFB:1.2.410.200046.1.1.3");
alias!(N_ARIA_256_CFB1, "ARIA-256-CFB1");
alias!(N_ARIA_192_CFB1, "ARIA-192-CFB1");
alias!(N_ARIA_128_CFB1, "ARIA-128-CFB1");
alias!(N_ARIA_256_CFB8, "ARIA-256-CFB8");
alias!(N_ARIA_192_CFB8, "ARIA-192-CFB8");
alias!(N_ARIA_128_CFB8, "ARIA-128-CFB8");
alias!(N_ARIA_256_CTR, "ARIA-256-CTR:1.2.410.200046.1.1.15");
alias!(N_ARIA_192_CTR, "ARIA-192-CTR:1.2.410.200046.1.1.10");
alias!(N_ARIA_128_CTR, "ARIA-128-CTR:1.2.410.200046.1.1.5");
// The ARIA and SM4 CCM rows' sequences -- `prov/names.h:111-113` and `:174`. Neither carries a
// short alias, unlike their CBC rows.
alias!(N_ARIA_256_CCM, "ARIA-256-CCM:1.2.410.200046.1.1.39");
alias!(N_ARIA_192_CCM, "ARIA-192-CCM:1.2.410.200046.1.1.38");
alias!(N_ARIA_128_CCM, "ARIA-128-CCM:1.2.410.200046.1.1.37");
alias!(N_SM4_CCM, "SM4-CCM:1.2.156.10197.1.104.9");
alias!(N_SM4_XTS, "SM4-XTS:1.2.156.10197.1.104.10");
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
alias!(N_AES_256_XTS, "AES-256-XTS:1.3.111.2.1619.0.1.2");
alias!(N_AES_128_XTS, "AES-128-XTS:1.3.111.2.1619.0.1.1");
alias!(N_AES_256_OCB, "AES-256-OCB");
alias!(N_AES_192_OCB, "AES-192-OCB");
alias!(N_AES_128_OCB, "AES-128-OCB");
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
alias!(N_AES_128_SIV, "AES-128-SIV");
alias!(N_AES_192_SIV, "AES-192-SIV");
alias!(N_AES_256_SIV, "AES-256-SIV");
alias!(
    N_AES_256_CCM,
    "AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47"
);
alias!(
    N_AES_192_CCM,
    "AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27"
);
alias!(
    N_AES_128_CCM,
    "AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7"
);
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
/// `ALG(NAMES, FUNC)` over `ALGC(NAMES, FUNC, NULL)` — `providers/defltprov.c:34-35`.
///
/// **The property definition is `"provider=default"`, not NULL, and that is observable.** The
/// authority's two macros are
///
/// ```c
/// #define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
/// #define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)
/// ```
///
/// so every `deflt_ciphers[]` row carries the default provider's own property, and a fetch whose
/// property query is `provider=default` resolves through it. A NULL here is not the same thing:
/// measured, `EVP_CIPHER_fetch(NULL, "AES-128-CBC", "provider=default")` answers 1 on the authority
/// and answered **0** with NULL, and `"provider!=default"` answered **1** where the authority
/// answers 0 -- the predicate inverted rather than merely absent. The digest and MAC tables already
/// carried it (`DEFLT_DIGESTS` uses `DEFAULT_PROPERTIES`), which is what made this one row
/// constructor the whole of the divergence (D247).
const fn row(names: *const c_char, implementation: *const c_void) -> OsslAlgorithm {
    OsslAlgorithm {
        algorithm_names: names,
        property_definition: c"provider=default".as_ptr(),
        implementation,
        algorithm_description: ptr::null(),
    }
}

/// `static const OSSL_ALGORITHM_CAPABLE deflt_ciphers[]` — `providers/defltprov.c:161-330`,
/// restricted to the rows this half implements, in the authority's order.
pub(crate) static DEFLT_CIPHERS: [OsslAlgorithm; 115] = [
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
    row(N_AES_256_XTS, AES256XTS_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_XTS, AES128XTS_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_OCB, AES256OCB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_OCB, AES192OCB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_OCB, AES128OCB_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_SIV, AES128SIV_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_SIV, AES192SIV_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_SIV, AES256SIV_FUNCTIONS.as_ptr().cast()),
    row(N_AES_256_CCM, AES256CCM_FUNCTIONS.as_ptr().cast()),
    row(N_AES_192_CCM, AES192CCM_FUNCTIONS.as_ptr().cast()),
    row(N_AES_128_CCM, AES128CCM_FUNCTIONS.as_ptr().cast()),
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
    // The `ARIA` family, `defltprov.c:246-274`, between the AES-CBC-HMAC `ALGC` rows (not landed)
    // and `CAMELLIA`. The six GCM and CCM rows precede these in the authority; the GCM three are
    // Phase 9's on `RAND_bytes_ex` and the CCM three are landed below, ahead of the mode rows
    // because that is where the authority puts them.
    row(N_ARIA_256_CCM, ARIA256CCM_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CCM, ARIA192CCM_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CCM, ARIA128CCM_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_ECB, ARIA256ECB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_ECB, ARIA192ECB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_ECB, ARIA128ECB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_CBC, ARIA256CBC_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CBC, ARIA192CBC_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CBC, ARIA128CBC_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_OFB, ARIA256OFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_OFB, ARIA192OFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_OFB, ARIA128OFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_CFB, ARIA256CFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CFB, ARIA192CFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CFB, ARIA128CFB_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_CFB1, ARIA256CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CFB1, ARIA192CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CFB1, ARIA128CFB1_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_CFB8, ARIA256CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CFB8, ARIA192CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CFB8, ARIA128CFB8_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_256_CTR, ARIA256CTR_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_192_CTR, ARIA192CTR_FUNCTIONS.as_ptr().cast()),
    row(N_ARIA_128_CTR, ARIA128CTR_FUNCTIONS.as_ptr().cast()),
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
    row(N_SM4_CCM, SM4128CCM_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_ECB, SM4128ECB_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_CBC, SM4128CBC_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_CTR, SM4128CTR_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_OFB, SM4128OFB128_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_CFB, SM4128CFB128_FUNCTIONS.as_ptr().cast()),
    row(N_SM4_XTS, SM4128XTS_FUNCTIONS.as_ptr().cast()),
    row(N_CHACHA20, CHACHA20_FUNCTIONS.as_ptr().cast()),
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

// ---------------------------------------------------------------------------------------------
// `cipher_chacha20.c` and `cipher_chacha20_hw.c` — the `ChaCha20` stream cipher row
// ---------------------------------------------------------------------------------------------
//
// The one row in this half whose **primitive is not a `ciphercommon` mode**. ChaCha20 is a stream
// cipher with a *counter block* rather than an IV, so the row declares a **one-byte block size**
// (`CHACHA20_BLKLEN`), takes a sixteen-byte counter block as its IV, and owns the whole of its own
// `cipher` — the generic CBC/CTR/ECB/CFB/OFB paths never see it. That is what `PROV_CIPHER_FLAG_CUSTOM_IV`
// is for, and it is also why the row publishes a `get_ctx_params`/`settable_ctx_params` pair of its
// own: the generic list has nothing useful to say about a counter block.
//
// Four things about it are unlike the rows already transcribed.
//
// **The primitive is perlasm-only in this profile, and `crypto/chacha/chacha_enc.c` is not compiled
// at all.** See `src/chacha.rs` for the full record; the consequence here is that `ChaCha20_ctr32`
// is called as `include/crypto/chacha.h` declares it, with the key and counter as **collected
// thirty-two-bit words in host order** rather than as byte vectors. `chacha20_initkey` and
// `chacha20_initiv` are the two places those words are collected, and `CHACHA_U8TOU32`'s shifts are
// little-endian in the header's own text.
//
// **The hw struct is extended, and its `base.copyctx` is NULL.** `PROV_CIPHER_HW_CHACHA20` is
// `PROV_CIPHER_HW base` plus `int (*initiv)(PROV_CIPHER_CTX *)`, and `chacha20_hw` initialises only
// `{ { chacha20_initkey, chacha20_cipher }, chacha20_initiv }` — so `copyctx` is a null pointer.
// `chacha20_dupctx` does not consult it (it is `OPENSSL_memdup` of the whole context), which is why
// this is the row that discovered `ProvCipherHw::copyctx` had to be `Option`.
//
// **`initiv` is called by the row's own `einit`/`dinit`, not by `ossl_cipher_generic_initkey`.** The
// generic init stores the IV in `oiv` and marks `iv_set`; the counter block is then collected
// **only when an IV was actually supplied**, which is what makes a second init without an IV resume
// the counter rather than reset it. That conditional is the row's most easily-lost behaviour.
//
// **`chacha20_cipher` carries the counter itself.** `ChaCha20_ctr32` advances only the first counter
// word and its own comment says a wider counter is the caller's job, so the hw limits each call to
// the exact 32-bit overflow point, carries into `counter[1]`, and keeps the partial block in
// `ctx->buf` with `partial_len` for the next call. A transcription that fed a whole buffer in one
// call would produce the right bytes for every input shorter than 256 GiB and the wrong ones after.

/// `CHACHA20_KEYLEN` — `cipher_chacha20.c:20` (`CHACHA_KEY_SIZE`).
const CHACHA20_KEYLEN: usize = crate::chacha::CHACHA_KEY_SIZE;
/// `CHACHA20_BLKLEN` — `cipher_chacha20.c:21`. **One byte**: the row is a stream cipher and every
/// `ciphercommon` path that reasons about block alignment must see a unit of one.
const CHACHA20_BLKLEN: usize = 1;
/// `CHACHA20_IVLEN` — `cipher_chacha20.c:22` (`CHACHA_CTR_SIZE`).
const CHACHA20_IVLEN: usize = crate::chacha::CHACHA_CTR_SIZE;
/// `CHACHA20_FLAGS` — `cipher_chacha20.c:23`.
const CHACHA20_FLAGS: u64 = PROV_CIPHER_FLAG_CUSTOM_IV;

/// The allocation-tracking `file` argument for this row's allocations. `cipher_chacha20.c` is a
/// **source-tree** file rather than a `.c.in` template, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the opposite of every generated provider unit, and the same
/// distinction `ciphercommon_block.c` records.
const FILE_CHACHA20: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c".as_ptr();

/// `struct prov_chacha20_ctx_st` — `cipher_chacha20.h:17-25`.
///
/// `base` must be first: `chacha20_cipher` and `chacha20_initiv` cast the `PROV_CIPHER_CTX *` they
/// are handed back to this type, and `ossl_cipher_generic_initkey` writes only the base's fields.
///
/// The authority's `key` is a union with `OSSL_UNION_ALIGN` whose live member is `unsigned int d[8]`;
/// the union's alignment is that of the widest scalar, and the unit test below binds the resulting
/// size rather than assuming it.
#[repr(C)]
pub(crate) struct ProvChacha20Ctx {
    /// `PROV_CIPHER_CTX base; /* must be first */`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; unsigned int d[CHACHA_KEY_SIZE / 4]; } key`.
    pub key: [c_uint; CHACHA20_KEYLEN / 4],
    /// `unsigned int counter[CHACHA_CTR_SIZE / 4]`.
    pub counter: [c_uint; CHACHA20_IVLEN / 4],
    /// `unsigned char buf[CHACHA_BLK_SIZE]` — the partial block held between updates.
    pub buf: [c_uchar; crate::chacha::CHACHA_BLK_SIZE],
    /// `unsigned int partial_len` — how much of `buf` has been consumed.
    pub partial_len: c_uint,
}

/// `PROV_CIPHER_HW_CHACHA20` — `cipher_chacha20.h:27-31`: the generic three fields plus `initiv`.
#[repr(C)]
struct ProvCipherHwChacha20 {
    /// `PROV_CIPHER_HW base; /* must be first */`.
    base: ProvCipherHw,
    /// `int (*initiv)(PROV_CIPHER_CTX *ctx)`.
    initiv: unsafe extern "C" fn(*mut ProvCipherCtx) -> c_int,
}

/// `static int chacha20_initkey(PROV_CIPHER_CTX *bctx, const uint8_t *key, size_t keylen)` —
/// `cipher_chacha20_hw.c:19-33`.
///
/// **A NULL key is accepted and only resets `partial_len`.** The condition is `key != NULL`, not a
/// failure, which is what lets a second init without a key resume the stream — the same shape as
/// `chacha20_initiv`'s `iv_set` test.
///
/// # Safety
/// The hw contract; `bctx` is a live `ProvChacha20Ctx`; `key` is NULL or readable for thirty-two
/// bytes.
unsafe extern "C" fn chacha20_initkey(
    bctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    _keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = bctx.cast::<ProvChacha20Ctx>();
        if !key.is_null() {
            let mut i = 0;
            while i < CHACHA20_KEYLEN {
                (*ctx).key[i / 4] =
                    crate::chacha::u8tou32(core::slice::from_raw_parts(key.add(i), 4));
                i += 4;
            }
        }
        (*ctx).partial_len = 0;
        1
    }
}

/// `static int chacha20_initiv(PROV_CIPHER_CTX *bctx)` — `cipher_chacha20_hw.c:35-48`.
///
/// **The counter block is collected only when the base has an IV set.** `bctx->iv_set` is the
/// generic init's record that an IV was supplied on *this* or an earlier init, so the row's
/// `einit`/`dinit` can call this unconditionally and a stream that was never re-IV'd keeps counting
/// where it left off. The `partial_len = 0` is outside the conditional, so an init always discards a
/// partial block.
///
/// # Safety
/// The hw contract; `bctx` is a live `ProvChacha20Ctx`.
unsafe extern "C" fn chacha20_initiv(bctx: *mut ProvCipherCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = bctx.cast::<ProvChacha20Ctx>();
        if bits(bctx) & CTX_IV_SET != 0 {
            let mut i = 0;
            while i < CHACHA20_IVLEN {
                (*ctx).counter[i / 4] = crate::chacha::u8tou32(core::slice::from_raw_parts(
                    (*bctx).oiv.as_ptr().add(i),
                    4,
                ));
                i += 4;
            }
        }
        (*ctx).partial_len = 0;
        1
    }
}

/// `static int chacha20_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out,
/// const unsigned char *in, size_t inl)` — `cipher_chacha20_hw.c:50-113`.
///
/// Three phases, and each exists for a reason that a single `ChaCha20_ctr32` call cannot supply.
///
///   * **The held partial block is finished first**, byte at a time out of `ctx->buf`. If the caller
///     supplies fewer bytes than remain, `partial_len` is left advanced and the call returns 1 with
///     nothing else done — a successful short update.
///   * **Whole blocks go in one call each, but only up to the 32-bit counter's overflow point.**
///     `ChaCha20_ctr32` advances `counter[0]` and nothing else, so this function adds the block count
///     to `counter[0]` *first* and, when that wraps, trims `blocks` back to the exact distance to the
///     wrap before calling. The `1 << 28` clamp above it is the authority's own belt-and-braces: it
///     is "practically never met" and is kept because `blocks` is a `size_t` and the cast to
///     `unsigned int` would otherwise be the only bound.
///   * **The trailing partial block is generated into `ctx->buf` and XORed from there**, so the next
///     call can finish it. The zero fill before the keystream call is what makes `ChaCha20_ctr32`'s
///     output *be* the keystream rather than keystream XOR garbage — the trick is that `inp == out`
///     and the buffer is zeroed first.
///
/// # Safety
/// The hw contract; `out` is writable for `inl` bytes; `in` is readable for `inl` bytes.
unsafe extern "C" fn chacha20_cipher(
    bctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = bctx.cast::<ProvChacha20Ctx>();
        let mut inl = inl;
        let mut out = out;
        let mut in_ = in_;
        let mut n = (*ctx).partial_len;

        if n > 0 {
            while inl > 0 && n < crate::chacha::CHACHA_BLK_SIZE as c_uint {
                *out = *in_ ^ (*ctx).buf[n as usize];
                out = out.add(1);
                in_ = in_.add(1);
                n += 1;
                inl -= 1;
            }
            (*ctx).partial_len = n;

            if inl == 0 {
                return 1;
            }
            if n == crate::chacha::CHACHA_BLK_SIZE as c_uint {
                (*ctx).partial_len = 0;
            }
        }

        let rem = (inl % crate::chacha::CHACHA_BLK_SIZE) as c_uint;
        inl -= rem as usize;
        let mut ctr32 = (*ctx).counter[0];
        while inl >= crate::chacha::CHACHA_BLK_SIZE {
            let mut blocks: usize = inl / crate::chacha::CHACHA_BLK_SIZE;

            /*
             * 1<<28 is just a not-so-small yet not-so-large number...
             * Below condition is practically never met, but it has to
             * be checked for code correctness.
             */
            if core::mem::size_of::<usize>() > core::mem::size_of::<c_uint>()
                && blocks > (1usize << 28)
            {
                blocks = 1usize << 28;
            }

            /*
             * As ChaCha20_ctr32 operates on 32-bit counter, caller
             * has to handle overflow. 'if' below detects the
             * overflow, which is then handled by limiting the
             * amount of blocks to the exact overflow point...
             */
            ctr32 = ctr32.wrapping_add(blocks as c_uint);
            if (ctr32 as usize) < blocks {
                blocks -= ctr32 as usize;
                ctr32 = 0;
            }
            blocks *= crate::chacha::CHACHA_BLK_SIZE;
            crate::chacha::ChaCha20_ctr32(
                out,
                in_,
                blocks,
                (*ctx).key.as_ptr(),
                (*ctx).counter.as_ptr(),
            );
            inl -= blocks;
            in_ = in_.add(blocks);
            out = out.add(blocks);

            (*ctx).counter[0] = ctr32;
            if ctr32 == 0 {
                (*ctx).counter[1] = (*ctx).counter[1].wrapping_add(1);
            }
        }

        if rem > 0 {
            (*ctx).buf = [0; crate::chacha::CHACHA_BLK_SIZE];
            crate::chacha::ChaCha20_ctr32(
                (*ctx).buf.as_mut_ptr(),
                (*ctx).buf.as_ptr(),
                crate::chacha::CHACHA_BLK_SIZE,
                (*ctx).key.as_ptr(),
                (*ctx).counter.as_ptr(),
            );

            /* propagate counter overflow */
            (*ctx).counter[0] = (*ctx).counter[0].wrapping_add(1);
            if (*ctx).counter[0] == 0 {
                (*ctx).counter[1] = (*ctx).counter[1].wrapping_add(1);
            }

            for i in 0..rem as usize {
                out.add(i).write(*in_.add(i) ^ (*ctx).buf[i]);
            }
            (*ctx).partial_len = rem;
        }

        1
    }
}

/// `static const PROV_CIPHER_HW_CHACHA20 chacha20_hw` — `cipher_chacha20_hw.c:115-118`.
///
/// **`base.copyctx` is left out of the initialiser and is therefore NULL**, which is why
/// `ProvCipherHw::copyctx` is an `Option`. Nothing calls it for this row: `chacha20_dupctx` is a
/// `memdup`.
static CHACHA20_HW: ProvCipherHwChacha20 = ProvCipherHwChacha20 {
    base: ProvCipherHw {
        init: chacha20_initkey,
        cipher: chacha20_cipher,
        copyctx: None,
    },
    initiv: chacha20_initiv,
};

/// `const PROV_CIPHER_HW *ossl_prov_cipher_hw_chacha20(size_t keybits)` —
/// `cipher_chacha20_hw.c:120-123`. `keybits` is ignored: there is one ChaCha20 and its key is
/// thirty-two bytes.
fn ossl_prov_cipher_hw_chacha20(_keybits: usize) -> *const ProvCipherHw {
    // `ProvCipherHwChacha20` is `#[repr(C)]` with `base` first, so the two pointers are the same
    // address and the cast is the one the authority's typedef performs. No `unsafe` is needed: the
    // cast and `addr_of!` are both safe, which is itself the statement that this is a layout
    // equivalence rather than a dereference.
    core::ptr::addr_of!(CHACHA20_HW).cast::<ProvCipherHw>()
}

/// `void ossl_chacha20_initctx(PROV_CHACHA20_CTX *ctx)` — `cipher_chacha20.c:44-51`.
///
/// The `0` mode is the authority's: ChaCha20 is not one of `evp.h`'s cipher modes.
///
/// # Safety
/// `ctx` is a live, writable `ProvChacha20Ctx`.
unsafe fn ossl_chacha20_initctx(ctx: *mut ProvChacha20Ctx) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_initkey(
            ctx.cast(),
            CHACHA20_KEYLEN * 8,
            CHACHA20_BLKLEN * 8,
            CHACHA20_IVLEN * 8,
            0,
            CHACHA20_FLAGS,
            ossl_prov_cipher_hw_chacha20(CHACHA20_KEYLEN * 8),
            ptr::null_mut(),
        );
    }
}

/// `static void *chacha20_newctx(void *provctx)` — `cipher_chacha20.c:53-64`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvChacha20Ctx>(), FILE_CHACHA20, LINE)
            .cast::<ProvChacha20Ctx>();
        if !ctx.is_null() {
            ossl_chacha20_initctx(ctx);
        }
        let _ = provctx;
        ctx.cast()
    }
}

/// `static void chacha20_freectx(void *vctx)` — `cipher_chacha20.c:66-74`. The whole context is
/// cleared before release, not merely freed, because it holds key material.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !vctx.is_null() {
            ossl_cipher_generic_reset_ctx(vctx.cast::<ProvCipherCtx>());
            CRYPTO_clear_free(
                vctx,
                core::mem::size_of::<ProvChacha20Ctx>(),
                FILE_CHACHA20,
                LINE,
            );
        }
    }
}

/// `static void *chacha20_dupctx(void *vctx)` — `cipher_chacha20.c:76-95`.
///
/// **The whole context is copied, `hw` included, and the TLS MAC is the one field that needs its own
/// allocation.** Because the copy carries `hw`, the duplicate's `einit` calls the same
/// `chacha20_initiv` the original's does — which is what makes a duplicated context resumable
/// mid-partial-block. The `alloced` guard is what says the MAC buffer belongs to this context rather
/// than to a caller's, so only then is it reallocated; if that allocation fails the whole duplicate
/// is released and NULL returned.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvChacha20Ctx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let dupctx = CRYPTO_memdup(
            ctx.cast(),
            core::mem::size_of::<ProvChacha20Ctx>(),
            FILE_CHACHA20,
            LINE,
        )
        .cast::<ProvChacha20Ctx>();
        if !dupctx.is_null() && !(*dupctx).base.tlsmac.is_null() && (*dupctx).base.alloced != 0 {
            (*dupctx).base.tlsmac = CRYPTO_memdup(
                (*dupctx).base.tlsmac.cast(),
                (*dupctx).base.tlsmacsize,
                FILE_CHACHA20,
                LINE,
            )
            .cast::<c_uchar>();
            if (*dupctx).base.tlsmac.is_null() {
                CRYPTO_free(dupctx.cast(), FILE_CHACHA20, LINE);
                return ptr::null_mut();
            }
        }
        dupctx.cast()
    }
}

/// `static int chacha20_get_params(OSSL_PARAM params[])` — `cipher_chacha20.c:97-103`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_get_params(params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_get_params(
            params,
            0,
            CHACHA20_FLAGS,
            CHACHA20_KEYLEN * 8,
            CHACHA20_BLKLEN * 8,
            CHACHA20_IVLEN * 8,
        )
    }
}

/// `static int chacha20_get_ctx_params(void *vctx, OSSL_PARAM params[])` —
/// `cipher_chacha20.c:105-132`.
///
/// **`updated-iv` is the row's own key and it is generated, not stored.** The counter block is four
/// little-endian words, so it is written out with `CHACHA_U32TOU8` — the same little-endian
/// spelling `CHACHA_U8TOU32` reads back, and the pair is what makes a caller able to save and
/// restore a stream position. `keylen` and `ivlen` are the two constants rather than the context's
/// fields, so a row whose lengths could not be set still reports them.
///
/// Each of the three arms raises `PROV_R_FAILED_TO_SET_PARAMETER` on a failed write, which is a
/// *provider* error and not the params layer's.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvChacha20Ctx>();

        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, CHACHA20_IVLEN) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_CHACHA20_111);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() && crate::params::OSSL_PARAM_set_size_t(p, CHACHA20_KEYLEN) == 0 {
            return fail_at(&err_sites::PROV_CIPHER_CHACHA20_116);
        }
        let p = crate::params::OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if !p.is_null() {
            let mut ivbuf = [0 as c_uchar; CHACHA20_IVLEN];
            for i in 0..4 {
                ivbuf[4 * i..4 * i + 4].copy_from_slice(&(*ctx).counter[i].to_le_bytes());
            }
            if crate::params::OSSL_PARAM_set_octet_string(p, ivbuf.as_ptr().cast(), CHACHA20_IVLEN)
                == 0
            {
                return fail_at(&err_sites::PROV_CIPHER_CHACHA20_126);
            }
        }
        1
    }
}

/// `chacha20_known_gettable_ctx_params` — `cipher_chacha20.c:134-139`. Three keys, and `updated-iv`
/// is `octet_string` rather than the `size_t` the other two are.
static CHACHA20_GETTABLE_CTX_PARAMS: [OsslParam; 4] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    param_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV),
    END,
];

/// `const OSSL_PARAM *chacha20_gettable_ctx_params(void *cctx, void *provctx)` —
/// `cipher_chacha20.c:140-144`. Hand-written rather than the generic list, which is the row's shape.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_gettable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CHACHA20_GETTABLE_CTX_PARAMS.as_ptr()
}

/// `static int chacha20_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `cipher_chacha20.c:146-176`.
///
/// **Both keys are length *checks*, not settings.** `keylen` and `ivlen` are fixed by the row, so a
/// descriptor naming a different value is refused with `PROV_R_INVALID_KEY_LENGTH` or
/// `PROV_R_INVALID_IV_LENGTH` and a descriptor of the wrong *type* is refused by the params layer
/// with `PROV_R_FAILED_TO_GET_PARAMETER`. That is why this row's `settable_ctx_params` publishes two
/// keys that cannot change anything: they exist to be *rejected*, which a caller that hands a generic
/// parameter block through `EVP_EncryptInit_ex` depends on.
///
/// `ossl_param_is_empty` short-circuits both arms, so a NULL or immediately-terminated array answers
/// 1 without locating anything.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let _ = vctx.cast::<ProvChacha20Ctx>();
        if ossl_param_is_empty(params) {
            return 1;
        }

        let mut len: usize = 0;
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if !p.is_null() {
            if crate::params::OSSL_PARAM_get_size_t(p, &mut len) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_CHACHA20_156);
            }
            if len != CHACHA20_KEYLEN {
                return fail_at(&err_sites::PROV_CIPHER_CHACHA20_160);
            }
        }
        let p = crate::params::OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
        if !p.is_null() {
            if crate::params::OSSL_PARAM_get_size_t(p, &mut len) == 0 {
                return fail_at(&err_sites::PROV_CIPHER_CHACHA20_167);
            }
            if len != CHACHA20_IVLEN {
                return fail_at(&err_sites::PROV_CIPHER_CHACHA20_171);
            }
        }
        1
    }
}

/// `chacha20_known_settable_ctx_params` — `cipher_chacha20.c:178-182`.
static CHACHA20_SETTABLE_CTX_PARAMS: [OsslParam; 3] = [
    param_size_t(OSSL_CIPHER_PARAM_KEYLEN),
    param_size_t(OSSL_CIPHER_PARAM_IVLEN),
    END,
];

/// `const OSSL_PARAM *chacha20_settable_ctx_params(void *cctx, void *provctx)` —
/// `cipher_chacha20.c:183-187`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn chacha20_settable_ctx_params(
    _cctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CHACHA20_SETTABLE_CTX_PARAMS.as_ptr()
}

/// `int ossl_chacha20_einit(void *vctx, const unsigned char *key, size_t keylen,
/// const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])` —
/// `cipher_chacha20.c:189-204`.
///
/// **Three steps, and the middle one is the row's whole reason for existing.** The generic init runs
/// with a NULL params array, then — **only if an IV was supplied** — `hw->initiv` collects the
/// counter block, then the row's own `set_ctx_params` runs. The authority's comment on the first line
/// is the contract for the running check: "The generic function checks for `ossl_prov_is_running()`",
/// so this wrapper does not.
///
/// `hw` is read out of the context rather than named, so the extended struct's `initiv` is reached
/// through the same pointer the base was installed with.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_chacha20_einit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret = ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, ptr::null());
        if ret != 0 && !iv.is_null() {
            let ctx = vctx.cast::<ProvCipherCtx>();
            let hw = (*ctx).hw.cast::<ProvCipherHwChacha20>();
            ((*hw).initiv)(ctx);
        }
        if ret != 0 && chacha20_set_ctx_params(vctx, params) == 0 {
            ret = 0;
        }
        ret
    }
}

/// `int ossl_chacha20_dinit(void *vctx, const unsigned char *key, size_t keylen,
/// const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])` —
/// `cipher_chacha20.c:206-221`. The decrypt twin, identical but for the generic call it makes.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn ossl_chacha20_dinit(
    vctx: *mut c_void,
    key: *const c_uchar,
    keylen: usize,
    iv: *const c_uchar,
    ivlen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret = ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, ptr::null());
        if ret != 0 && !iv.is_null() {
            let ctx = vctx.cast::<ProvCipherCtx>();
            let hw = (*ctx).hw.cast::<ProvCipherHwChacha20>();
            ((*hw).initiv)(ctx);
        }
        if ret != 0 && chacha20_set_ctx_params(vctx, params) == 0 {
            ret = 0;
        }
        ret
    }
}

/// `const OSSL_DISPATCH ossl_chacha20_functions[]` — `cipher_chacha20.c:223-245`: fourteen entries
/// and the terminator.
///
/// The row's own `ENCRYPT_INIT`/`DECRYPT_INIT` and its own ctx-params quartet; the update, final and
/// one-shot `cipher` are the **stream** generic ones, because the block size is one byte and there is
/// no padding to add or strip.
pub(crate) static CHACHA20_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_NEWCTX,
        function: chacha20_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FREECTX,
        function: chacha20_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_DUPCTX,
        function: chacha20_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
        function: ossl_chacha20_einit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
        function: ossl_chacha20_dinit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_UPDATE,
        function: ossl_cipher_generic_stream_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FINAL,
        function: ossl_cipher_generic_stream_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_CIPHER,
        function: ossl_cipher_generic_cipher as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
        function: chacha20_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        function: ossl_cipher_generic_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        function: chacha20_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        function: chacha20_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        function: chacha20_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        function: chacha20_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// ---------------------------------------------------------------------------------------------
// `cipher_sm4.c` and `cipher_sm4_hw.c` — the `SM4-*` rows
// ---------------------------------------------------------------------------------------------
//
// **SM4 has no low-level public API in this authority.** `nm -D libcrypto.so.3` lists no `SM4_*`
// symbol, `include/crypto/sm4.h` is internal, and its three names — `ossl_sm4_set_key`,
// `ossl_sm4_encrypt`, `ossl_sm4_decrypt` — are internal functions. So unlike AES and Camellia there
// is no `EVP_sm4 *`-style surface to keep and this unit exists entirely for the default provider's
// eight rows; the primitive is `src/sm4.rs`'s (D266).
//
// **The C path is what is transcribed and the x86-64 hardware path is declined.** `sm4.c` *is*
// compiled in this profile (`libcrypto-lib-sm4.o` exists beside `libcrypto-lib-sm4-x86_64.o`), and
// `cipher_sm4_hw.c`'s `HWSM4_CAPABLE` plus `cipher_sm4_hw_x86_64.inc`'s `HWSM4_CAPABLE_X86_64`
// choose between the two **at runtime**, with the x86-64 table installed when the CPU reports the
// extension. SM4 is a pure function of key and block, so the bytes are identical either way — the
// same decline D209 records for AES and D222 for Camellia's key table.
//
// **The consequence is that each row installs the C `PROV_CIPHER_HW` directly, and the five
// `ossl_prov_cipher_hw_sm4_*` selectors have no caller here.** The authority's
// `IMPLEMENT_generic_cipher` reaches its hw through `ossl_prov_cipher_hw_<alg>_<mode>(kbits)`, and on
// the x86-64 path that function returns `hw_x86_64_sm4_<mode>` — a table whose only difference is
// which pointer `initkey` stores in `ctx->block`. Since the assembly is declined, the C table *is*
// this transcription's answer, so the selectors are transcribed for their own sake and marked as
// uncalled rather than left out: a reader of `cipher_sm4.h` should find every name it declares.
//
// One thing about the row's *behaviour* is worth stating where it can be seen. `IMPLEMENT_generic_cipher`
// passes `blkbits` independently of `kbits`, and `cipher_sm4.c` gives SM4-CTR/OFB/CFB a **block size
// of one byte** (`128, 8, 128`) while ECB and CBC keep 128. That is what tells every
// alignment-reasoning caller that the three stream modes are streams, and it is the `blkbits`
// argument below.

/// `SM4_BLOCK_SIZE * 8` — the two block modes' `blkbits`, expressed through the primitive's own
/// constant rather than as the literal `128` the authority's macro invocation writes. The five
/// stream modes pass `8` instead, which is `cipher_sm4.c:48-52`'s one-byte block size.
const SM4_BLK_BITS: usize = crate::sm4::SM4_BLOCK_SIZE * 8;

/// The allocation-tracking `file` argument for this row's allocations. `cipher_sm4.c` is a
/// source-tree file rather than a `.c.in` template, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix.
const FILE_SM4: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4.c".as_ptr();

/// `ossl_sm4_encrypt` as the generic engine's `block128_f` — `cipher_sm4_hw.c:116`'s cast.
///
/// The cast is a transcription, not a convenience: the authority stores
/// `(block128_f)ossl_sm4_encrypt`, and `block128_f` takes the schedule as a `const void *` while the
/// function itself takes `const SM4_KEY *`. Same address, different type, so the trampoline is what
/// the cast is in C.
///
/// # Safety
/// As [`crate::sm4::ossl_sm4_encrypt`]; `key` is a `SM4_KEY *`.
unsafe extern "C" fn sm4_block_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::sm4::ossl_sm4_encrypt(in_, out, key.cast()) }
}

/// `ossl_sm4_decrypt` as the generic engine's `block128_f`. See [`sm4_block_encrypt`].
///
/// # Safety
/// As [`crate::sm4::ossl_sm4_decrypt`]; `key` is a `SM4_KEY *`.
unsafe extern "C" fn sm4_block_decrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::sm4::ossl_sm4_decrypt(in_, out, key.cast()) }
}

/// `struct prov_sm4_ctx_st` — `cipher_sm4.h:17-24`. The authority's `ks` is a union whose live
/// member is `SM4_KEY`; there is no other member, so it is a plain field whose alignment is the
/// union's, and the unit test binds the resulting size.
#[repr(C)]
pub(crate) struct ProvSm4Ctx {
    /// `PROV_CIPHER_CTX base; /* Must be first */`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; SM4_KEY ks; } ks`.
    pub ks: crate::sm4::Sm4Key,
}

/// `static int cipher_hw_sm4_initkey(PROV_CIPHER_CTX *ctx, const unsigned char *key,
/// size_t keylen)` — `cipher_sm4_hw.c:13-121`, the `#else`-side C body.
///
/// **The encrypt schedule serves both directions, and which block function is stored depends on the
/// mode as well as the direction.** The condition is
/// `ctx->enc || (ctx->mode != ECB && ctx->mode != CBC)`: an *encrypting* context always gets
/// `ossl_sm4_encrypt`, and a **decrypting** one gets `ossl_sm4_decrypt` only for ECB and CBC —
/// because those are the two modes that call the block function directly on the way in. A
/// decrypting CTR/OFB/CFB context gets the *encrypt* function, because those modes only ever encrypt
/// the counter or the feedback register.
///
/// `ctx->ks` is set to point into the context's own `ks` field, which is what the generic modes pass
/// as the `key` argument to the block function.
///
/// `ctx->stream` is left **untouched** — the authority's C branch writes neither `stream.cbc` nor
/// `stream.ecb` nor `stream.ctr`, and the x86-64 branch writes `stream.cbc = NULL`. Both leave it
/// NULL, because `ossl_cipher_generic_initkey` does not write it and the context is `zalloc`'d, so
/// the generic CBC/ECB paths fall through to `block`. Setting it explicitly here would be a
/// difference from the C body that happens to agree with the assembly.
///
/// # Safety
/// The hw contract; `ctx` is live; `key` is readable for sixteen bytes.
unsafe extern "C" fn cipher_hw_sm4_initkey(
    ctx: *mut ProvCipherCtx,
    key: *const c_uchar,
    _keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let sctx = ctx.cast::<ProvSm4Ctx>();
        let ks: *mut crate::sm4::Sm4Key = ptr::addr_of_mut!((*sctx).ks);
        (*ctx).ks = ks.cast();

        if (*ctx).enc_int() != 0
            || ((*ctx).mode != EVP_CIPH_ECB_MODE && (*ctx).mode != EVP_CIPH_CBC_MODE)
        {
            crate::sm4::ossl_sm4_set_key(key, ks);
            (*ctx).block = Some(sm4_block_encrypt);
        } else {
            crate::sm4::ossl_sm4_set_key(key, ks);
            (*ctx).block = Some(sm4_block_decrypt);
        }
        1
    }
}

/// `IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_sm4_copyctx, PROV_SM4_CTX)` — `cipher_sm4_hw.c:124`.
///
/// The macro copies the whole row-specific struct onto the destination's base. Unlike ChaCha20's hw
/// this one **is** installed, because `sm4_dupctx` calls it.
///
/// # Safety
/// The hw contract; both contexts are live and `dst`'s row fields are uninitialised.
unsafe extern "C" fn cipher_hw_sm4_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src.cast::<ProvSm4Ctx>(), dst.cast::<ProvSm4Ctx>(), 1);
    }
}

/// `static void sm4_freectx(void *vctx)` — `cipher_sm4.c:20-25`. Cleared before release, because the
/// context holds a key schedule.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast::<ProvCipherCtx>());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvSm4Ctx>(), FILE_SM4, LINE);
    }
}

/// `static void *sm4_dupctx(void *ctx)` — `cipher_sm4.c:27-41`.
///
/// Note what it does **not** do: it does not check `vctx` for NULL, and it copies only the base plus
/// whatever `copyctx` writes — so the `ks` field arrives through the hw, not through the allocation.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn sm4_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let in_ = vctx.cast::<ProvSm4Ctx>();
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvSm4Ctx>(), FILE_SM4, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let hw = (*in_).base.hw;
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), vctx.cast());
        }
        ret
    }
}

/// `PROV_CIPHER_HW_sm4_mode(mode)` — `cipher_sm4_hw.c:127-137`, the five tables. The `select`
/// variant's `#define`s are empty in the generic case and are transcribed separately below.
static SM4_ECB_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_initkey,
    cipher: ossl_cipher_hw_generic_ecb,
    copyctx: Some(cipher_hw_sm4_copyctx),
};
static SM4_CBC_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_initkey,
    cipher: ossl_cipher_hw_generic_cbc,
    copyctx: Some(cipher_hw_sm4_copyctx),
};
static SM4_OFB128_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_initkey,
    cipher: ossl_cipher_hw_generic_ofb128,
    copyctx: Some(cipher_hw_sm4_copyctx),
};
static SM4_CFB128_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_initkey,
    cipher: ossl_cipher_hw_generic_cfb128,
    copyctx: Some(cipher_hw_sm4_copyctx),
};
static SM4_CTR_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_sm4_initkey,
    cipher: ossl_cipher_hw_generic_ctr,
    copyctx: Some(cipher_hw_sm4_copyctx),
};

/// `const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_ecb(size_t keybits)` —
/// `cipher_sm4_hw.c:139-146`, and the four siblings.
///
/// **Transcribed and uncalled.** The authority's `IMPLEMENT_generic_cipher` reaches its hw through
/// these, and on the x86-64 path they answer `hw_x86_64_sm4_<mode>` when the CPU reports the SM4
/// extension. Since that assembly is declined, the C table is this transcription's answer and each
/// row installs it directly — so these five have no caller in the crate, and they exist because
/// `cipher_sm4.h` declares them and a reader should find every declared name.
///
/// `keybits` is ignored by all five: SM4's key is sixteen bytes and there is one of them.
#[allow(dead_code)] // no caller by construction: the rows install the C tables directly (D266)
fn ossl_prov_cipher_hw_sm4_ecb(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_ECB_HW)
}
/// See [`ossl_prov_cipher_hw_sm4_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_sm4_cbc(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_CBC_HW)
}
/// See [`ossl_prov_cipher_hw_sm4_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_sm4_ofb128(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_OFB128_HW)
}
/// See [`ossl_prov_cipher_hw_sm4_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_sm4_cfb128(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_CFB128_HW)
}
/// See [`ossl_prov_cipher_hw_sm4_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_sm4_ctr(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(SM4_CTR_HW)
}

// `IMPLEMENT_generic_cipher(sm4, SM4, <mode>, <MODE>, 0, 128, <blkbits>, <ivbits>, <typ>)` —
// `cipher_sm4.c:44-52`'s five invocations. The `0` is the mode-flags argument, which is
// `EVP_CIPH_FLAG_DEFAULT_ASN1`-zero here: SM4 has no `CUSTOM_IV` and no `AEAD` flag.
cipher_row!(
    sm4128ecb_newctx,
    sm4128ecb_get_params,
    SM4128ECB_FUNCTIONS,
    ProvSm4Ctx,
    SM4_ECB_HW,
    128,
    SM4_BLK_BITS,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    sm4_freectx,
    sm4_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    sm4128cbc_newctx,
    sm4128cbc_get_params,
    SM4128CBC_FUNCTIONS,
    ProvSm4Ctx,
    SM4_CBC_HW,
    128,
    SM4_BLK_BITS,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    sm4_freectx,
    sm4_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    sm4128ctr_newctx,
    sm4128ctr_get_params,
    SM4128CTR_FUNCTIONS,
    ProvSm4Ctx,
    SM4_CTR_HW,
    128,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    sm4_freectx,
    sm4_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    sm4128ofb128_newctx,
    sm4128ofb128_get_params,
    SM4128OFB128_FUNCTIONS,
    ProvSm4Ctx,
    SM4_OFB128_HW,
    128,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    sm4_freectx,
    sm4_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    sm4128cfb128_newctx,
    sm4128cfb128_get_params,
    SM4128CFB128_FUNCTIONS,
    ProvSm4Ctx,
    SM4_CFB128_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    sm4_freectx,
    sm4_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

// ---------------------------------------------------------------------------------------------
// `cipher_aria.c` and `cipher_aria_hw.c` — the twenty-one `ARIA-*` mode rows
// ---------------------------------------------------------------------------------------------
//
// The ARIA rows are `cipher_sm4.c`'s shape with three differences that all matter.
//
// **The hw uses the `chunked` wrappers, not the plain generic ones.** `cipher_aria_hw.c:35-44`'s
// `PROV_CIPHER_HW_aria_mode` macro spells `ossl_cipher_hw_chunked_##mode`, and `ciphercommon.h:241-243`
// `#define`s three of those onto the generic functions, so ECB, CTR and CFB1 install the generic
// function itself while CBC, OFB, CFB and CFB8 take a chunking wrapper. `cipher_sm4_hw.c` uses the
// generic functions directly, which is why SM4's rows did not need `ciphercommon_hw.c:126-193` to be
// transcribed and ARIA's do.
//
// **There is one schedule function, not two.** `cipher_hw_aria_initkey` stores
// `(block128_f)ossl_aria_encrypt` **unconditionally**, where `cipher_hw_sm4_initkey` selects between
// an encrypt and a decrypt function. That is not a simplification: `src/aria.rs` records that this
// authority has no `ossl_aria_decrypt` at all, and `ossl_aria_set_decrypt_key` builds a schedule
// that the forward function decrypts with. So the branch here chooses which *schedule* to build and
// nothing else.
//
// **The branch has an error arm, and it is this stratum's first ARIA raise.** `ret < 0` raises
// `PROV_R_KEY_SETUP_FAILED` at `cipher_aria_hw.c:25` and answers 0. Both schedule functions answer
// 0, not negative, on success, and `-1` when the key pointer is NULL or `bits` is not 128, 192 or
// 256 -- so the arm is negative-return-driven exactly as `cipher_aria_hw.c` writes it.
//
// The six `ARIA-*-GCM` and `ARIA-*-CCM` rows precede these twenty-one in `deflt_ciphers[]` and are
// their own unit: they come from `cipher_aria_gcm.c` and `cipher_aria_ccm.c`, whose hw is the
// shared GCM and CCM machinery rather than `cipher_aria_hw.c`.

/// `ARIA_BLOCK_SIZE * 8` — the two block modes' `blkbits`. The five stream modes pass `8`, which is
/// `cipher_aria.c`'s one-byte block size for OFB, CFB, CFB1, CFB8 and CTR.
const ARIA_BLK_BITS: usize = crate::aria::ARIA_BLOCK_SIZE * 8;

/// The allocation-tracking `file` argument for this row's allocations. `cipher_aria.c` is a
/// **source-tree** file rather than a `.c.in` template, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix, as `cipher_sm4.c`'s and `cipher_chacha20.c`'s do.
const FILE_ARIA: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aria.c".as_ptr();

/// `ossl_aria_encrypt` as the generic engine's `block128_f` — `cipher_aria_hw.c:29`'s cast, which is
/// unconditional and therefore serves both directions.
///
/// # Safety
/// As [`crate::aria::ossl_aria_encrypt`]; `key` is an `ARIA_KEY *`.
unsafe extern "C" fn aria_block_encrypt(
    in_: *const c_uchar,
    out: *mut c_uchar,
    key: *const c_void,
) {
    // SAFETY: the caller's contract.
    unsafe { crate::aria::ossl_aria_encrypt(in_, out, key.cast()) }
}

/// `struct prov_aria_ctx_st` — `cipher_aria.h:13-19`.
///
/// The authority's `ks` is a union with `OSSL_UNION_ALIGN` whose live member is `ARIA_KEY`, which is
/// 276 bytes and four-aligned, so the union is 280. `ARIA_KEY` is the **last** member of the
/// context, so the union's four trailing bytes and the struct's own four trailing bytes of padding
/// coincide: `size_of` is 192 + 280 = 472 with either model, and the unit test binds that number
/// rather than the reasoning (D269).
#[repr(C)]
pub(crate) struct ProvAriaCtx {
    /// `PROV_CIPHER_CTX base; /* Must be first */`.
    pub base: ProvCipherCtx,
    /// `union { OSSL_UNION_ALIGN; ARIA_KEY ks; } ks`.
    pub ks: crate::aria::AriaKey,
}

/// `static int cipher_hw_aria_initkey(PROV_CIPHER_CTX *dat, const unsigned char *key,
/// size_t keylen)` — `cipher_aria_hw.c:13-31`.
///
/// **The condition chooses the schedule; the block function is the same either way.** An
/// encrypting context always builds the encrypt schedule, and a decrypting one builds the decrypt
/// schedule for ECB and CBC and the encrypt schedule for the five stream modes -- because those
/// modes only ever run the block function forwards over a counter or a feedback register.
///
/// # Safety
/// The hw contract; `dat` is a live `ProvAriaCtx`; `key` is readable for `keylen` bytes.
unsafe extern "C" fn cipher_hw_aria_initkey(
    dat: *mut ProvCipherCtx,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: the caller's contract; `dat` is a `PROV_ARIA_CTX`.
    unsafe {
        let adat = dat.cast::<ProvAriaCtx>();
        let ks: *mut crate::aria::AriaKey = ptr::addr_of_mut!((*adat).ks);
        let mode = (*dat).mode;
        let ret =
            if (*dat).enc_int() != 0 || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE) {
                crate::aria::ossl_aria_set_encrypt_key(key, (keylen * 8) as c_int, ks)
            } else {
                crate::aria::ossl_aria_set_decrypt_key(key, (keylen * 8) as c_int, ks)
            };
        if ret < 0 {
            return fail_at(&err_sites::PROV_CIPHER_ARIA_HW_25);
        }
        (*dat).ks = ks.cast();
        (*dat).block = Some(aria_block_encrypt);
        1
    }
}

/// `IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_aria_copyctx, PROV_ARIA_CTX)` — `cipher_aria_hw.c:33`.
///
/// # Safety
/// The hw contract; both contexts are live and `dst`'s row fields are uninitialised.
unsafe extern "C" fn cipher_hw_aria_copyctx(dst: *mut ProvCipherCtx, src: *const ProvCipherCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<ProvAriaCtx>(), dst.cast::<ProvAriaCtx>(), 1);
    }
}

/// `static void aria_freectx(void *vctx)` — `cipher_aria.c:20-25`. Cleared before release, as
/// `sm4_freectx` is, because the context holds a key schedule.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_freectx(vctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        ossl_cipher_generic_reset_ctx(vctx.cast::<ProvCipherCtx>());
        CRYPTO_clear_free(vctx, core::mem::size_of::<ProvAriaCtx>(), FILE_ARIA, LINE);
    }
}

/// `static void *aria_dupctx(void *ctx)` — `cipher_aria.c:27-41`. No NULL check on `vctx`, and the
/// row fields arrive through `hw->copyctx` rather than through the allocation.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aria_dupctx(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let in_ = vctx.cast::<ProvAriaCtx>();
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let ret = CRYPTO_malloc(core::mem::size_of::<ProvAriaCtx>(), FILE_ARIA, LINE);
        if ret.is_null() {
            return ptr::null_mut();
        }
        let hw = (*in_).base.hw;
        if let Some(copyctx) = (*hw).copyctx {
            copyctx(ret.cast(), vctx.cast());
        }
        ret
    }
}

/// `PROV_CIPHER_HW_aria_mode(mode)` — `cipher_aria_hw.c:46-52`, the seven tables. **The three modes
/// whose `chunked` spelling is a `#define` onto the generic function install that function here**,
/// which is what `ciphercommon.h:241-243` says and what the authority's preprocessed text contains.
static ARIA_ECB_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_generic_ecb,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_CBC_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_chunked_cbc,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_OFB128_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_chunked_ofb128,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_CFB128_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_chunked_cfb128,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_CFB1_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_generic_cfb1,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_CFB8_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_chunked_cfb8,
    copyctx: Some(cipher_hw_aria_copyctx),
};
static ARIA_CTR_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_aria_initkey,
    cipher: ossl_cipher_hw_generic_ctr,
    copyctx: Some(cipher_hw_aria_copyctx),
};

/// `const PROV_CIPHER_HW *ossl_prov_cipher_hw_aria_<mode>(size_t keybits)` —
/// `cipher_aria_hw.c:41-52`, and the six siblings. `cipher_aria.h:21-22` also `#define`s
/// `ossl_prov_cipher_hw_aria_ofb` onto `_ofb128` and `_cfb` onto `_cfb128`.
///
/// **Transcribed and uncalled**, for `ossl_prov_cipher_hw_sm4_*`'s reason: the authority's
/// `IMPLEMENT_generic_cipher` reaches its hw through these, and each row installs the C table
/// directly here, so a reader of `cipher_aria.h` still finds every name it declares.
#[allow(dead_code)] // no caller by construction: the rows install the C tables directly
fn ossl_prov_cipher_hw_aria_ecb(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_ECB_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_cbc(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_CBC_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_ofb128(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_OFB128_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_cfb128(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_CFB128_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_cfb1(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_CFB1_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_cfb8(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_CFB8_HW)
}
/// See [`ossl_prov_cipher_hw_aria_ecb`].
#[allow(dead_code)] // as above
fn ossl_prov_cipher_hw_aria_ctr(_keybits: usize) -> *const ProvCipherHw {
    ptr::addr_of!(ARIA_CTR_HW)
}

// `IMPLEMENT_generic_cipher(aria, ARIA, <mode>, <MODE>, 0, <kbits>, <blkbits>, <ivbits>, <typ>)` —
// `cipher_aria.c:37-73`'s twenty-one invocations. The `0` is the mode-flags argument: ARIA has
// neither `CUSTOM_IV` nor an AEAD flag. ECB's `ivbits` is `0` and CBC's is `128`; every stream mode
// is `8`/`128`, the one-byte block size that tells an alignment-reasoning caller it is a stream.
cipher_row!(
    aria256ecb_newctx,
    aria256ecb_get_params,
    ARIA256ECB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_ECB_HW,
    256,
    ARIA_BLK_BITS,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192ecb_newctx,
    aria192ecb_get_params,
    ARIA192ECB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_ECB_HW,
    192,
    ARIA_BLK_BITS,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128ecb_newctx,
    aria128ecb_get_params,
    ARIA128ECB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_ECB_HW,
    128,
    ARIA_BLK_BITS,
    0,
    EVP_CIPH_ECB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256cbc_newctx,
    aria256cbc_get_params,
    ARIA256CBC_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CBC_HW,
    256,
    ARIA_BLK_BITS,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192cbc_newctx,
    aria192cbc_get_params,
    ARIA192CBC_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CBC_HW,
    192,
    ARIA_BLK_BITS,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128cbc_newctx,
    aria128cbc_get_params,
    ARIA128CBC_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CBC_HW,
    128,
    ARIA_BLK_BITS,
    128,
    EVP_CIPH_CBC_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_block_update,
    ossl_cipher_generic_block_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256ofb128_newctx,
    aria256ofb128_get_params,
    ARIA256OFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_OFB128_HW,
    256,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192ofb128_newctx,
    aria192ofb128_get_params,
    ARIA192OFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_OFB128_HW,
    192,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128ofb128_newctx,
    aria128ofb128_get_params,
    ARIA128OFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_OFB128_HW,
    128,
    8,
    128,
    EVP_CIPH_OFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256cfb128_newctx,
    aria256cfb128_get_params,
    ARIA256CFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB128_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192cfb128_newctx,
    aria192cfb128_get_params,
    ARIA192CFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB128_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128cfb128_newctx,
    aria128cfb128_get_params,
    ARIA128CFB_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB128_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256cfb1_newctx,
    aria256cfb1_get_params,
    ARIA256CFB1_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB1_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192cfb1_newctx,
    aria192cfb1_get_params,
    ARIA192CFB1_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB1_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128cfb1_newctx,
    aria128cfb1_get_params,
    ARIA128CFB1_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB1_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256cfb8_newctx,
    aria256cfb8_get_params,
    ARIA256CFB8_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB8_HW,
    256,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192cfb8_newctx,
    aria192cfb8_get_params,
    ARIA192CFB8_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB8_HW,
    192,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128cfb8_newctx,
    aria128cfb8_get_params,
    ARIA128CFB8_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CFB8_HW,
    128,
    8,
    128,
    EVP_CIPH_CFB_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria256ctr_newctx,
    aria256ctr_get_params,
    ARIA256CTR_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CTR_HW,
    256,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria192ctr_newctx,
    aria192ctr_get_params,
    ARIA192CTR_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CTR_HW,
    192,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);
cipher_row!(
    aria128ctr_newctx,
    aria128ctr_get_params,
    ARIA128CTR_FUNCTIONS,
    ProvAriaCtx,
    ARIA_CTR_HW,
    128,
    8,
    128,
    EVP_CIPH_CTR_MODE,
    0,
    aria_freectx,
    aria_dupctx,
    ossl_cipher_generic_stream_update,
    ossl_cipher_generic_stream_final,
    ossl_cipher_generic_get_params,
    ossl_cipher_generic_get_ctx_params,
    ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_gettable_ctx_params,
    ossl_cipher_generic_settable_ctx_params
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::AES_MAXNR;

    #[test]
    fn the_cipher_table_terminates_and_names_the_rows() {
        assert_eq!(DEFLT_CIPHERS.len(), 115);
        // SAFETY: every entry up to the terminator is initialised.
        let last = DEFLT_CIPHERS[114].algorithm_names;
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
                stream: ProvCipherStream { cbc: None },
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
            ks: AesKeyUnion {
                ks: AesKey {
                    rd_key: [0; 4 * (AES_MAXNR + 1)],
                    rounds: 0,
                },
            },
            plat: 0,
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

    /// **The `ChaCha20` row's context, field for field.** The numbers are the authority's own,
    /// measured by `courts/layout/measure-chacha-ctx.c` compiled against the pinned build's internal
    /// headers: `sizeof(PROV_CIPHER_CTX)` is 192 and `sizeof(PROV_CHACHA20_CTX)` is 312, with `key`
    /// at 192, `counter` at 224, `buf` at 240 and `partial_len` at 304. The allocation request is
    /// what a `CRYPTO_set_mem_functions` application's allocator receives, so the size is contract.
    ///
    /// The three offsets matter as much as the size: `chacha20_initkey` and `chacha20_initiv` cast
    /// the base pointer onto this struct, and `chacha20_cipher` reads `counter` and `partial_len`
    /// through it, so a field in the wrong place is a silent wrong keystream rather than a crash.
    #[test]
    fn the_chacha20_context_is_the_authoritys_size() {
        assert_eq!(core::mem::size_of::<ProvCipherCtx>(), 192);
        assert_eq!(core::mem::size_of::<ProvChacha20Ctx>(), 312);
        assert_eq!(core::mem::align_of::<ProvChacha20Ctx>(), 8);
        assert_eq!(core::mem::offset_of!(ProvChacha20Ctx, key), 192);
        assert_eq!(core::mem::offset_of!(ProvChacha20Ctx, counter), 224);
        assert_eq!(core::mem::offset_of!(ProvChacha20Ctx, buf), 240);
        assert_eq!(core::mem::offset_of!(ProvChacha20Ctx, partial_len), 304);
        // `PROV_CIPHER_HW_CHACHA20` is the generic three pointers plus `initiv`.
        assert_eq!(core::mem::size_of::<ProvCipherHwChacha20>(), 32);
        assert_eq!(CHACHA20_KEYLEN, 32);
        assert_eq!(CHACHA20_BLKLEN, 1);
        assert_eq!(CHACHA20_IVLEN, 16);
    }

    /// **Every landed provider cipher context, measured against the authority's own compiler.**
    /// The allocation request is what a `CRYPTO_set_mem_functions` application's allocator receives,
    /// so each size is contract, and so is each `ks` offset. The numbers are from
    /// `courts/layout/measure-provider-ctxs.c`, compiled against the pinned build's internal headers.
    #[test]
    fn the_provider_contexts_are_the_authoritys_sizes() {
        assert_eq!(core::mem::size_of::<ProvCipherCtx>(), 192);
        assert_eq!(core::mem::size_of::<ProvAesCtx>(), 448);
        assert_eq!(core::mem::offset_of!(ProvAesCtx, ks), 192);
        assert_eq!(core::mem::size_of::<ProvCamelliaCtx>(), 472);
        assert_eq!(core::mem::offset_of!(ProvCamelliaCtx, ks), 192);
        assert_eq!(core::mem::size_of::<ProvTdesCtx>(), 584);
        assert_eq!(core::mem::offset_of!(ProvTdesCtx, tks), 192);
        assert_eq!(core::mem::size_of::<ProvAesXtsCtx>(), 736);
        assert_eq!(core::mem::offset_of!(ProvAesXtsCtx, ks1), 192);
        assert_eq!(core::mem::offset_of!(ProvAesXtsCtx, ks2), 440);
        assert_eq!(core::mem::offset_of!(ProvAesXtsCtx, xts), 688);
        assert_eq!(core::mem::size_of::<ProvAesOcbCtx>(), 944);
        assert_eq!(core::mem::offset_of!(ProvAesOcbCtx, ksenc), 192);
        assert_eq!(core::mem::offset_of!(ProvAesOcbCtx, ksdec), 440);
        assert_eq!(core::mem::offset_of!(ProvAesOcbCtx, ocb), 688);
        assert_eq!(core::mem::offset_of!(ProvAesOcbCtx, iv_state), 864);
        assert_eq!(core::mem::offset_of!(ProvAesOcbCtx, taglen), 872);
        assert_eq!(core::mem::size_of::<ProvAesCcmCtx>(), 416);
        assert_eq!(core::mem::offset_of!(ProvAesCcmCtx, ks), 152);
        assert_eq!(core::mem::size_of::<ProvAesSivCtx>(), 120);
        assert_eq!(core::mem::size_of::<ProvAesWrapCtx>(), 448);
        assert_eq!(core::mem::size_of::<ProvChacha20Ctx>(), 312);
        assert_eq!(core::mem::size_of::<ProvSm4Ctx>(), 320);
        assert_eq!(core::mem::size_of::<ProvAriaCtx>(), 472);
        assert_eq!(core::mem::offset_of!(ProvAriaCtx, ks), 192);
        assert_eq!(core::mem::size_of::<ProvAriaCcmCtx>(), 432);
        assert_eq!(core::mem::offset_of!(ProvAriaCcmCtx, ks), 152);
        assert_eq!(core::mem::size_of::<ProvSm4CcmCtx>(), 280);
        assert_eq!(core::mem::offset_of!(ProvSm4CcmCtx, ks), 152);
        assert_eq!(core::mem::size_of::<ProvSm4XtsCtx>(), 504);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, ks1), 192);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, ks2), 320);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, xts_standard), 448);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, xts), 456);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, stream_gb), 488);
        assert_eq!(core::mem::offset_of!(ProvSm4XtsCtx, stream), 496);
    }

    /// **The row's two parameter lists are its own, not the generic ones.** `ChaCha20` publishes a
    /// *three*-key getter whose third key is `octet_string` -- the counter block as it would be read
    /// back -- and a two-key setter whose entries exist to be *rejected* rather than applied. A
    /// transcription that had reused `CIPHER_GETTABLE_CTX_PARAMS` would pass every encrypt/decrypt
    /// observation and answer both of these wrongly.
    #[test]
    fn the_chacha20_param_lists_are_the_rows_own() {
        // SAFETY: every key is a `'static` C string literal, and the terminator's is NULL.
        unsafe {
            assert_eq!(CHACHA20_GETTABLE_CTX_PARAMS.len(), 4);
            for (i, want) in [b"keylen".as_slice(), b"ivlen", b"updated-iv"]
                .into_iter()
                .enumerate()
            {
                let k = core::ffi::CStr::from_ptr(CHACHA20_GETTABLE_CTX_PARAMS[i].key.cast());
                assert_eq!(k.to_bytes(), want);
            }
            // `updated-iv` is the odd one: `OCTET_STRING`, not the `size_t` of the two above it.
            assert_eq!(CHACHA20_GETTABLE_CTX_PARAMS[2].data_type, 5);
            assert_eq!(CHACHA20_GETTABLE_CTX_PARAMS[2].data_size, 0);
            assert!(CHACHA20_GETTABLE_CTX_PARAMS[3].key.is_null());

            assert_eq!(CHACHA20_SETTABLE_CTX_PARAMS.len(), 3);
            for (i, want) in [b"keylen".as_slice(), b"ivlen"].into_iter().enumerate() {
                let k = core::ffi::CStr::from_ptr(CHACHA20_SETTABLE_CTX_PARAMS[i].key.cast());
                assert_eq!(k.to_bytes(), want);
                assert_eq!(CHACHA20_SETTABLE_CTX_PARAMS[i].data_size, 8);
            }
            assert!(CHACHA20_SETTABLE_CTX_PARAMS[2].key.is_null());
        }

        // Fourteen entries and the terminator, and the four the row overrides are the two inits and
        // the two ctx-params accessors.
        assert_eq!(CHACHA20_FUNCTIONS.len(), 15);
        assert_eq!(
            CHACHA20_FUNCTIONS[3].function_id,
            OSSL_FUNC_CIPHER_ENCRYPT_INIT
        );
        assert_eq!(
            CHACHA20_FUNCTIONS[3].function as usize,
            ossl_chacha20_einit as *const c_void as usize
        );
        assert_eq!(
            CHACHA20_FUNCTIONS[4].function as usize,
            ossl_chacha20_dinit as *const c_void as usize
        );
        assert_eq!(CHACHA20_FUNCTIONS[14].function_id, OSSL_DISPATCH_END);
        assert!(CHACHA20_FUNCTIONS[14].function.is_null());
    }

    /// **`chacha20_hw`'s `copyctx` is NULL, and `initiv` is not.** This is the row that made
    /// `ProvCipherHw::copyctx` an `Option`: the authority's initialiser names only `initkey`,
    /// `cipher` and `initiv`, so a non-nullable field could not have held the truth. `copyctx` is
    /// never called for this row -- `chacha20_dupctx` is a `memdup`.
    #[test]
    fn the_chacha20_hw_leaves_copyctx_null() {
        assert!(CHACHA20_HW.base.copyctx.is_none());
        assert_eq!(
            CHACHA20_HW.base.init as usize,
            chacha20_initkey as *const c_void as usize
        );
        assert_eq!(
            CHACHA20_HW.base.cipher as usize,
            chacha20_cipher as *const c_void as usize
        );
        assert_eq!(
            CHACHA20_HW.initiv as usize,
            chacha20_initiv as *const c_void as usize
        );
        // `ossl_prov_cipher_hw_chacha20` ignores its argument and answers the same pointer.
        assert_eq!(
            ossl_prov_cipher_hw_chacha20(256) as usize,
            core::ptr::addr_of!(CHACHA20_HW) as usize
        );
        // The `#[repr(C)]` cast the initctx makes is an address identity, not a copy.
        assert_eq!(
            ossl_prov_cipher_hw_chacha20(256) as usize,
            core::ptr::addr_of!(CHACHA20_HW.base) as usize
        );
    }

    /// `chacha20_initkey` collects the key as **eight little-endian words**, and a NULL key only
    /// resets `partial_len`. The second half is what makes a re-init without a key resume the
    /// stream, and the word order is what makes the keystream the standard's rather than its
    /// byte-reverse.
    #[test]
    fn chacha20_initkey_collects_little_endian_words_and_tolerates_null() {
        let mut ctx = ProvChacha20Ctx {
            base: zeroed_ctx(),
            key: [0; 8],
            counter: [0; 4],
            buf: [0; 64],
            partial_len: 0,
        };
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }

        // SAFETY: `ctx` is this frame's and `key` is a live local of thirty-two bytes.
        unsafe {
            assert_eq!(
                chacha20_initkey(core::ptr::addr_of_mut!(ctx).cast(), key.as_ptr(), key.len()),
                1
            );
        }
        assert_eq!(ctx.key[0], 0x0302_0100);
        assert_eq!(ctx.key[1], 0x0706_0504);
        assert_eq!(ctx.key[7], 0x1f1e_1d1c);

        // A held partial block is discarded on every init, with or without a key.
        ctx.partial_len = 17;
        // SAFETY: a NULL key takes the early arm and writes only `partial_len`.
        unsafe {
            assert_eq!(
                chacha20_initkey(core::ptr::addr_of_mut!(ctx).cast(), core::ptr::null(), 0),
                1
            );
        }
        assert_eq!(ctx.partial_len, 0);
        // The key survived the keyless init, which is the whole point of the `key != NULL` test.
        assert_eq!(ctx.key[0], 0x0302_0100);
    }

    /// **`chacha20_initiv` collects the counter block only when the base has an IV set.** That
    /// conditional is the row's most easily-lost behaviour: without it, an init that supplies no IV
    /// would silently reset the counter to zero and a resumed stream would restart.
    #[test]
    fn chacha20_initiv_needs_the_base_to_have_an_iv() {
        let mut ctx = ProvChacha20Ctx {
            base: zeroed_ctx(),
            key: [0; 8],
            counter: [0xdead_beef; 4],
            buf: [0; 64],
            partial_len: 9,
        };
        for (i, b) in ctx.base.oiv.iter_mut().enumerate() {
            *b = i as u8;
        }

        // No IV bit: the counter is left exactly as it was, and only `partial_len` resets.
        // SAFETY: `ctx` is this frame's.
        unsafe {
            assert_eq!(chacha20_initiv(core::ptr::addr_of_mut!(ctx).cast()), 1);
        }
        assert_eq!(ctx.counter, [0xdead_beef; 4]);
        assert_eq!(ctx.partial_len, 0);

        // With the bit: the counter block is collected little-endian from `oiv`.
        ctx.base.bits |= CTX_IV_SET;
        // SAFETY: as above.
        unsafe {
            assert_eq!(chacha20_initiv(core::ptr::addr_of_mut!(ctx).cast()), 1);
        }
        assert_eq!(ctx.counter[0], 0x0302_0100);
        assert_eq!(ctx.counter[3], 0x0f0e_0d0c);
    }

    /// The `ChaCha20` row is present in `DEFLT_CIPHERS`, carries the authority's own spelling of the
    /// name, and is the row that sits after the DES EDE family. `PROV_NAMES_ChaCha20` is spelled in
    /// **mixed case** (`prov/names.h:176`), unlike every other name constant in that header, so the
    /// alias sequence is asserted rather than assumed.
    #[test]
    fn the_deflt_ciphers_table_carries_the_chacha20_row() {
        // The terminator's name is NULL, so the scan skips it rather than dereferencing it, and the
        // "not found" answer is a sentinel rather than an `Option` -- an `expect` here would be a
        // `clippy::expect_used` failure under the CI's `-D warnings`.
        let mut found = usize::MAX;
        for (i, row) in DEFLT_CIPHERS.iter().enumerate() {
            if row.algorithm_names.is_null() {
                continue;
            }
            // SAFETY: each landed row's name is a `'static` C string literal, checked non-NULL.
            let name = unsafe { core::ffi::CStr::from_ptr(row.algorithm_names) };
            if name.to_bytes() == b"ChaCha20" {
                found = i;
            }
        }
        assert_ne!(found, usize::MAX, "the ChaCha20 row is published");
        // SAFETY: the row's property is the default provider's own `'static` literal.
        unsafe {
            let props = core::ffi::CStr::from_ptr(DEFLT_CIPHERS[found].property_definition);
            assert_eq!(props.to_bytes(), b"provider=default");
            assert_eq!(
                DEFLT_CIPHERS[found].implementation as usize,
                CHACHA20_FUNCTIONS.as_ptr() as usize
            );
        }
    }

    /// A `PROV_CIPHER_CTX` with every field zero, for the two hw tests above. Written out rather
    /// than `zeroed()` because `ProvCipherCtx` holds raw pointers and a hand-built zero keeps the
    /// tests free of the type's `Default`.
    fn zeroed_ctx() -> ProvCipherCtx {
        ProvCipherCtx {
            oiv: [0; GENERIC_BLOCK_SIZE],
            buf: [0; GENERIC_BLOCK_SIZE],
            iv: [0; GENERIC_BLOCK_SIZE],
            block: None,
            stream: ProvCipherStream { cbc: None },
            mode: 0,
            keylen: 0,
            ivlen: 0,
            blocksize: 0,
            bufsz: 0,
            cts_mode: 0,
            bits: 0,
            tlsversion: 0,
            tlsmac: core::ptr::null_mut(),
            alloced: 0,
            tlsmacsize: 0,
            removetlspad: 0,
            removetlsfixed: 0,
            num: 0,
            hw: core::ptr::null(),
            ks: core::ptr::null(),
            libctx: core::ptr::null_mut(),
        }
    }
}
