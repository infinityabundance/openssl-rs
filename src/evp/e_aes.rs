//! Phase 13.6a — `crypto/evp/e_aes.c`: the deprecated `EVP_CIPHER` statics the AES modes return.
//!
//! `EVP_aes_128_cbc()` and its thirty-seven siblings are one line each —
//! `return &aes_128_cbc;` (`e_aes.c:2381-2383`) — over a `static const EVP_CIPHER` whose legacy
//! half is the `aes_*_init_key`/`aes_*_cipher`/`aes_*_cleanup`/`aes_*_ctrl` callbacks. This module
//! transcribes those objects field for field and the callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs:1864-1887`) opens with the test the digest
//! half states in D290: a method whose `prov` is NULL is **fetched by short name** and `type` is
//! rebound to the provider method. `EVP_aes_128_cbc()`'s object has no provider, so a caller that
//! hands it to `EVP_EncryptInit_ex` runs the Phase-8 provider AES-CBC, not these callbacks. The
//! callbacks are transcribed for faithfulness — an engine is the only reachable caller — exactly
//! as `src/evp/legacy_sha.rs` transcribes the digest ones.
//!
//! ## The portable arm, and the arch arms that are not modelled
//!
//! The authority's build selects a perlasm arm: the `AESNI_CAPABLE`/`HWAES_CAPABLE`/`BSAES_CAPABLE`/
//! `VPAES_CAPABLE`/`AES_GCM_ASM` branches each install a hardware block function. This crate's
//! primitive arm is portable (`src/aes.rs`, D197), so the *portable* `aes_*` callbacks are
//! transcribed and the arch branches are the ones the crate declines: every one of them computes
//! the same function over a different block callback, and the crate calls `AES_encrypt`/
//! `AES_decrypt` through the generic modes. The `AESNI_CAPABLE ? &aesni_… : &aes_…` choice in the
//! generic accessor is settled the same way: this module returns the portable object, whose fields
//! are identical to the AES-NI object's — same `nid`, sizes, `flags` and `ctx_size`, only the
//! callback pointers differ — so the observable surface is the authority's.
//!
//! ## What this module does not define
//!
//! `EVP_aes_*_siv()`, `EVP_aes_*_gcm_siv()` and the `ossl_*` internals are other units. Only the
//! thirty-eight accessors `forensics/atlas/export-defining-units.json` assigns to `e_aes.c` are
//! exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::aes::{
    AES_cbc_encrypt, AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AesKey,
};
use crate::evp::cipher::{
    CipherLegacyCleanupFn, CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn,
    EVP_CIPHER_get_mode, EvpCipher,
};
use crate::evp::cipher_ctx::{
    ossl_is_partially_overlapping, EVP_CIPHER_CTX_buf_noconst, EVP_CIPHER_CTX_ctrl,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_iv_length,
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_CTX_set_num, EVP_CIPHER_CTX_test_flags, EvpCipherCtx,
};
use crate::modes::ccm::{
    CRYPTO_ccm128_aad, CRYPTO_ccm128_decrypt, CRYPTO_ccm128_encrypt, CRYPTO_ccm128_init,
    CRYPTO_ccm128_setiv, CRYPTO_ccm128_tag, CcmCtx,
};
use crate::modes::gcm::{
    CRYPTO_gcm128_aad, CRYPTO_gcm128_decrypt, CRYPTO_gcm128_encrypt, CRYPTO_gcm128_finish,
    CRYPTO_gcm128_init, CRYPTO_gcm128_setiv, CRYPTO_gcm128_tag, GcmCtx,
};
use crate::modes::ocb::{
    CRYPTO_ocb128_aad, CRYPTO_ocb128_cleanup, CRYPTO_ocb128_copy_ctx, CRYPTO_ocb128_decrypt,
    CRYPTO_ocb128_encrypt, CRYPTO_ocb128_finish, CRYPTO_ocb128_init, CRYPTO_ocb128_setiv,
    CRYPTO_ocb128_tag, OcbCtx,
};
use crate::modes::wrap::{
    CRYPTO_128_unwrap, CRYPTO_128_unwrap_pad, CRYPTO_128_wrap, CRYPTO_128_wrap_pad,
};
use crate::modes::xts::{CRYPTO_xts128_encrypt, XtsCtx};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt,
    CRYPTO_cfb128_8_encrypt, CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt,
    CRYPTO_ctr128_encrypt_ctr32, CRYPTO_ofb128_encrypt, Cbc128F, Ccm128F, Ctr128F,
};
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, OPENSSL_cleanse};
use crate::runtime::obj::{
    NID_aes_128_cbc, NID_aes_128_ccm, NID_aes_128_cfb1, NID_aes_128_cfb128, NID_aes_128_cfb8,
    NID_aes_128_ctr, NID_aes_128_ecb, NID_aes_128_gcm, NID_aes_128_ocb, NID_aes_128_ofb128,
    NID_aes_128_xts, NID_aes_192_cbc, NID_aes_192_ccm, NID_aes_192_cfb1, NID_aes_192_cfb128,
    NID_aes_192_cfb8, NID_aes_192_ctr, NID_aes_192_ecb, NID_aes_192_gcm, NID_aes_192_ocb,
    NID_aes_192_ofb128, NID_aes_256_cbc, NID_aes_256_ccm, NID_aes_256_cfb1, NID_aes_256_cfb128,
    NID_aes_256_cfb8, NID_aes_256_ctr, NID_aes_256_ecb, NID_aes_256_gcm, NID_aes_256_ocb,
    NID_aes_256_ofb128, NID_aes_256_xts, NID_id_aes128_wrap, NID_id_aes128_wrap_pad,
    NID_id_aes192_wrap, NID_id_aes192_wrap_pad, NID_id_aes256_wrap, NID_id_aes256_wrap_pad,
};

/// The translation-unit coordinates, as the allocator reports them.
const FILE: &core::ffi::CStr = c"crypto/evp/e_aes.c";
const LINE: c_int = 0;

// ---------------------------------------------------------------------------------------------
// `EVP_CIPH_*` — `include/openssl/evp.h`
// ---------------------------------------------------------------------------------------------

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_int = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_int = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`. The bit-width variants all carry it.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_CTR_MODE` — `include/openssl/evp.h:315`.
const EVP_CIPH_CTR_MODE: c_ulong = 0x5;
/// `EVP_CIPH_GCM_MODE` — `include/openssl/evp.h:316`.
const EVP_CIPH_GCM_MODE: c_ulong = 0x6;
/// `EVP_CIPH_CCM_MODE` — `include/openssl/evp.h:317`.
const EVP_CIPH_CCM_MODE: c_ulong = 0x7;
/// `EVP_CIPH_XTS_MODE` — `include/openssl/evp.h:318`.
const EVP_CIPH_XTS_MODE: c_ulong = 0x10001;
/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:319`.
const EVP_CIPH_WRAP_MODE: c_ulong = 0x10002;
/// `EVP_CIPH_OCB_MODE` — `include/openssl/evp.h:320`.
const EVP_CIPH_OCB_MODE: c_ulong = 0x10003;
/// `EVP_CIPH_CUSTOM_IV` — `include/openssl/evp.h:327`.
const EVP_CIPH_CUSTOM_IV: c_ulong = 0x10;
/// `EVP_CIPH_ALWAYS_CALL_INIT` — `include/openssl/evp.h:329`.
const EVP_CIPH_ALWAYS_CALL_INIT: c_ulong = 0x20;
/// `EVP_CIPH_CTRL_INIT` — `include/openssl/evp.h:331`.
const EVP_CIPH_CTRL_INIT: c_ulong = 0x40;
/// `EVP_CIPH_CUSTOM_COPY` — `include/openssl/evp.h:339`.
const EVP_CIPH_CUSTOM_COPY: c_ulong = 0x400;
/// `EVP_CIPH_CUSTOM_IV_LENGTH` — `include/openssl/evp.h:341`.
const EVP_CIPH_CUSTOM_IV_LENGTH: c_ulong = 0x800;
/// `EVP_CIPH_FLAG_LENGTH_BITS` — `include/openssl/evp.h:346`.
const EVP_CIPH_FLAG_LENGTH_BITS: c_int = 0x2000;
/// `EVP_CIPH_FLAG_CUSTOM_CIPHER` — `include/openssl/evp.h:356`.
const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_ulong = 0x100000;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:357`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x200000;

/// `EVP_CTRL_AEAD_SET_IVLEN` — `include/openssl/evp.h:388`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CTRL_AEAD_GET_TAG` — `include/openssl/evp.h:389`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `EVP_CTRL_AEAD_SET_TAG` — `include/openssl/evp.h:390`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `EVP_CTRL_GCM_IV_GEN` — `include/openssl/evp.h:396`.
const EVP_CTRL_GCM_IV_GEN: c_int = 0x13;
/// `EVP_CTRL_CCM_SET_L` — `include/openssl/evp.h:401`.
const EVP_CTRL_CCM_SET_L: c_int = 0x14;
/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:408`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_GCM_SET_IV_INV` — `include/openssl/evp.h:412`.
const EVP_CTRL_GCM_SET_IV_INV: c_int = 0x18;

/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;
/// `EVP_GCM_TLS_EXPLICIT_IV_LEN` — `include/openssl/evp.h:474`.
const EVP_GCM_TLS_EXPLICIT_IV_LEN: usize = 8;
/// `EVP_GCM_TLS_TAG_LEN` — `include/openssl/evp.h:476`.
const EVP_GCM_TLS_TAG_LEN: usize = 16;
/// `EVP_CCM_TLS_FIXED_IV_LEN` — `include/openssl/evp.h:480`.
const EVP_CCM_TLS_FIXED_IV_LEN: usize = 4;
/// `EVP_CCM_TLS_EXPLICIT_IV_LEN` — `include/openssl/evp.h:482`.
const EVP_CCM_TLS_EXPLICIT_IV_LEN: usize = 8;

/// `XTS_MAX_BLOCKS_PER_DATA_UNIT` — `include/crypto/modes.h:146`.
const XTS_MAX_BLOCKS_PER_DATA_UNIT: usize = 1 << 20;

/// `MAXBITCHUNK` — `e_aes.c:119`.
const MAXBITCHUNK: usize = 1usize << 60;

/// `allow_insecure_decrypt` — `e_aes.c:77`, the non-FIPS value.
const ALLOW_INSECURE_DECRYPT: c_int = 1;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(TYPE, ctx)` — `e_aes.c:65`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn cipher_data(ctx: *const EvpCipherCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }
}

/// `block128_f` view of [`AES_encrypt`].
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn aes_encrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is an `AES_KEY`.
    unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
}

/// `block128_f` view of [`AES_decrypt`].
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn aes_decrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is an `AES_KEY`.
    unsafe { AES_decrypt(input, out, key.cast::<AesKey>()) }
}

/// `cbc128_f` view of [`AES_cbc_encrypt`].
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn aes_cbc_stream(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract; `key` is an `AES_KEY`.
    unsafe { AES_cbc_encrypt(input, out, len, key.cast::<AesKey>(), ivec, enc) }
}

/// `static void ctr64_inc(unsigned char *counter)` — `e_aes.c:122-136`.
///
/// The caller passes `gctx->iv + gctx->ivlen - 8`, so the eight bytes walked are the pointer's own.
///
/// # Safety
/// `counter` points at an eight-byte buffer.
unsafe fn ctr64_inc(counter: *mut u8) {
    // SAFETY: the caller's contract; every index is within the eight bytes.
    unsafe {
        let mut n: usize = 8;
        loop {
            n -= 1;
            let c = counter.add(n).read().wrapping_add(1);
            counter.add(n).write(c);
            if c != 0 {
                return;
            }
            if n == 0 {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The contexts — `e_aes.c:32-117`
// ---------------------------------------------------------------------------------------------

/// `EVP_AES_KEY` — `e_aes.c:32-42`. The `stream` union is split into its two arms, because this
/// crate's portable callbacks fill only one at a time.
pub struct EvpAesKey {
    ks: AesKey,
    block: Block128F,
    stream_cbc: Option<Cbc128F>,
    stream_ctr: Option<Ctr128F>,
}

/// `EVP_AES_GCM_CTX` — `e_aes.c:44-60`.
pub struct EvpAesGcmCtx {
    ks: AesKey,
    key_set: c_int,
    iv_set: c_int,
    gcm: GcmCtx,
    iv: *mut c_uchar,
    ivlen: c_int,
    taglen: c_int,
    iv_gen: c_int,
    /// `int iv_gen_rand` — written only by the `FIPS_MODULE` arm of `aes_gcm_cipher`, which this
    /// profile does not compile, so the field is inert here and marked as such rather than dropped.
    #[allow(dead_code)]
    iv_gen_rand: c_int,
    tls_aad_len: c_int,
    tls_enc_records: u64,
    ctr: Option<Ctr128F>,
}

/// `void (*stream)(...)` — `e_aes.c:68-71`. The AES-XTS perlasm entry, which this profile has no
/// arm for, so the field is always NULL here.
type XtsStreamF =
    unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, *const c_void, *const u8);

/// `EVP_AES_XTS_CTX` — `e_aes.c:62-72`.
pub struct EvpAesXtsCtx {
    ks1: AesKey,
    ks2: AesKey,
    xts: XtsCtx,
    stream: Option<XtsStreamF>,
}

/// `EVP_AES_CCM_CTX` — `e_aes.c:80-93`.
pub struct EvpAesCcmCtx {
    ks: AesKey,
    key_set: c_int,
    iv_set: c_int,
    tag_set: c_int,
    len_set: c_int,
    l: c_int,
    m: c_int,
    tls_aad_len: c_int,
    ccm: CcmCtx,
    str_: Option<Ccm128F>,
}

/// `EVP_AES_OCB_CTX` — `e_aes.c:96-116`.
pub struct EvpAesOcbCtx {
    ksenc: AesKey,
    ksdec: AesKey,
    key_set: c_int,
    iv_set: c_int,
    ocb: OcbCtx,
    iv: *mut c_uchar,
    tag: [c_uchar; 16],
    data_buf: [c_uchar; 16],
    aad_buf: [c_uchar; 16],
    data_buf_len: c_int,
    aad_buf_len: c_int,
    ivlen: c_int,
    taglen: c_int,
}

/// `EVP_AES_WRAP_CTX` — `e_aes.c:3662-3669`.
pub struct EvpAesWrapCtx {
    ks: AesKey,
    iv: *mut c_uchar,
}

// ---------------------------------------------------------------------------------------------
// `BLOCK_CIPHER_generic_pack`'s callbacks — `e_aes.c:2415-2641`
// ---------------------------------------------------------------------------------------------

/// `aes_init_key` — `e_aes.c:2415-2509`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is the live context per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `ctx` is live.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
    if keylen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_AES_2423) };
        return 0;
    }
    // SAFETY: `ctx` is live and `cipher` is the method it borrowed.
    let mode = unsafe { EVP_CIPHER_get_mode((*ctx).cipher) };
    let ret;
    if (mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && enc == 0 {
        // SAFETY: `key` is readable and `ks` writable per the contract.
        ret = unsafe { AES_set_decrypt_key(key, keylen, ptr::addr_of_mut!((*dat).ks)) };
        // SAFETY: `dat` is the context's own block.
        unsafe {
            (*dat).block = aes_decrypt_block;
            (*dat).stream_cbc = if mode == EVP_CIPH_CBC_MODE {
                Some(aes_cbc_stream)
            } else {
                None
            };
        }
    } else {
        // SAFETY: `key` is readable and `ks` writable per the contract.
        ret = unsafe { AES_set_encrypt_key(key, keylen, ptr::addr_of_mut!((*dat).ks)) };
        // SAFETY: `dat` is the context's own block.
        unsafe {
            (*dat).block = aes_encrypt_block;
            (*dat).stream_cbc = if mode == EVP_CIPH_CBC_MODE {
                Some(aes_cbc_stream)
            } else {
                None
            };
        }
    }
    // SAFETY: `dat` is the context's own block; the portable arm installs no `ctr128_f`.
    unsafe { (*dat).stream_ctr = None };
    if ret < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_AES_2504) };
        return 0;
    }
    1
}

/// `aes_cbc_cipher` — `e_aes.c:2511-2527`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_cbc_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `dat` and `ctx` are live; the mode writes exactly the regions named.
    unsafe {
        if let Some(f) = (*dat).stream_cbc {
            f(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                (*ctx).encrypt,
            );
        } else if (*ctx).encrypt != 0 {
            CRYPTO_cbc128_encrypt(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                (*dat).block,
            );
        } else {
            CRYPTO_cbc128_decrypt(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                (*dat).block,
            );
        }
    }
    1
}

/// `aes_ecb_cipher` — `e_aes.c:2529-2543`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ecb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
    // SAFETY: `ctx` is live.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    if len < bl {
        return 1;
    }
    let mut i = 0usize;
    let last = len - bl;
    while i <= last {
        // SAFETY: `dat` is live and the loop stays within `len` bytes of both buffers.
        unsafe { ((*dat).block)(in_.add(i), out.add(i), ptr::addr_of!((*dat).ks).cast()) };
        i += bl;
    }
    1
}

/// `aes_ofb_cipher` — `e_aes.c:2545-2555`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ofb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
    unsafe {
        CRYPTO_ofb128_encrypt(
            in_,
            out,
            len,
            ptr::addr_of!((*dat).ks).cast(),
            (*ctx).iv.as_mut_ptr(),
            &mut num,
            (*dat).block,
        );
        EVP_CIPHER_CTX_set_num(ctx, num);
    }
    1
}

/// `aes_cfb_cipher` — `e_aes.c:2557-2568`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_cfb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
    unsafe {
        CRYPTO_cfb128_encrypt(
            in_,
            out,
            len,
            ptr::addr_of!((*dat).ks).cast(),
            (*ctx).iv.as_mut_ptr(),
            &mut num,
            (*ctx).encrypt,
            (*dat).block,
        );
        EVP_CIPHER_CTX_set_num(ctx, num);
    }
    1
}

/// `aes_cfb8_cipher` — `e_aes.c:2570-2581`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_cfb8_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
    unsafe {
        CRYPTO_cfb128_8_encrypt(
            in_,
            out,
            len,
            ptr::addr_of!((*dat).ks).cast(),
            (*ctx).iv.as_mut_ptr(),
            &mut num,
            (*ctx).encrypt,
            (*dat).block,
        );
        EVP_CIPHER_CTX_set_num(ctx, num);
    }
    1
}

/// `aes_cfb1_cipher` — `e_aes.c:2583-2616`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_cfb1_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) } != 0 {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat` and `ctx` are live; `len` is a bit count here per the contract.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                (*dat).block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
        return 1;
    }
    let mut len = len;
    let mut out = out;
    let mut in_ = in_;
    while len >= MAXBITCHUNK {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` live; a whole chunk of bytes is converted to bits.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                MAXBITCHUNK * 8,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                (*dat).block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
        len -= MAXBITCHUNK;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            out = out.add(MAXBITCHUNK);
            in_ = in_.add(MAXBITCHUNK);
        }
    }
    if len != 0 {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` live.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                len * 8,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                (*dat).block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `aes_ctr_cipher` — `e_aes.c:2618-2641`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ctr_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let n = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    if n < 0 {
        return 0;
    }
    let mut num = n as c_uint;
    // SAFETY: `ctx` is live.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAesKey>();
    // SAFETY: `dat` and `ctx` are live; the `ecount_buf` is the context's own `buf`.
    unsafe {
        if let Some(f) = (*dat).stream_ctr {
            CRYPTO_ctr128_encrypt_ctr32(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_buf_noconst(ctx),
                &mut num,
                f,
            );
        } else {
            CRYPTO_ctr128_encrypt(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_buf_noconst(ctx),
                &mut num,
                (*dat).block,
            );
        }
        EVP_CIPHER_CTX_set_num(ctx, num as c_int);
    }
    1
}

// `BLOCK_CIPHER_generic_pack` for the three key lengths — `e_aes.c:2643-2645`.
// The static objects and accessors are written out below, after the custom modes.

// ---------------------------------------------------------------------------------------------
// GCM — `e_aes.c:2647-3194`
// ---------------------------------------------------------------------------------------------

/// `aes_gcm_cleanup` — `e_aes.c:2647-2656`.
///
/// # Safety
/// The `EVP_CIPHER::cleanup` contract.
unsafe extern "C" fn aes_gcm_cleanup(c: *mut c_void) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let gctx = unsafe { cipher_data(c) }.cast::<EvpAesGcmCtx>();
    if gctx.is_null() {
        return 0;
    }
    // SAFETY: `gctx` is the context's own block.
    unsafe {
        OPENSSL_cleanse(
            ptr::addr_of_mut!((*gctx).gcm).cast(),
            core::mem::size_of::<GcmCtx>(),
        );
        if (*gctx).iv != (*c).iv.as_mut_ptr() {
            CRYPTO_free((*gctx).iv.cast(), FILE.as_ptr(), LINE);
        }
    }
    1
}

/// `aes_gcm_ctrl` — `e_aes.c:2658-2792`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aes_gcm_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let gctx = unsafe { cipher_data(c) }.cast::<EvpAesGcmCtx>();
    match type_ {
        0 => {
            // EVP_CTRL_INIT — `include/openssl/evp.h:379`.
            // SAFETY: `gctx` and `c` are live.
            unsafe {
                (*gctx).key_set = 0;
                (*gctx).iv_set = 0;
                (*gctx).ivlen = crate::evp::cipher::EVP_CIPHER_get_iv_length((*c).cipher);
                (*gctx).iv = (*c).iv.as_mut_ptr();
                (*gctx).taglen = -1;
                (*gctx).iv_gen = 0;
                (*gctx).tls_aad_len = -1;
            }
            1
        }
        0x25 => {
            // EVP_CTRL_GET_IVLEN — `include/openssl/evp.h:442`.
            // SAFETY: `ptr_` is the caller's `int *` per the command's contract.
            unsafe { *ptr_.cast::<c_int>() = (*gctx).ivlen };
            1
        }
        EVP_CTRL_AEAD_SET_IVLEN => {
            if arg <= 0 {
                return 0;
            }
            // SAFETY: `gctx` and `c` are live.
            unsafe {
                if arg > 16 && arg > (*gctx).ivlen {
                    if (*gctx).iv != (*c).iv.as_mut_ptr() {
                        CRYPTO_free((*gctx).iv.cast(), FILE.as_ptr(), LINE);
                    }
                    let fresh = CRYPTO_malloc(arg as usize, FILE.as_ptr(), LINE).cast::<c_uchar>();
                    if fresh.is_null() {
                        return 0;
                    }
                    (*gctx).iv = fresh;
                }
                (*gctx).ivlen = arg;
            }
            1
        }
        EVP_CTRL_AEAD_SET_TAG => {
            // SAFETY: `c` and `gctx` are live; `ptr_` is readable for `arg` bytes.
            unsafe {
                if arg <= 0 || arg > 16 || (*c).encrypt != 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*c).buf.as_mut_ptr(), arg as usize);
                (*gctx).taglen = arg;
            }
            1
        }
        EVP_CTRL_AEAD_GET_TAG => {
            // SAFETY: `c` and `gctx` are live; `ptr_` is writable for `arg` bytes.
            unsafe {
                if arg <= 0 || arg > 16 || (*c).encrypt == 0 || (*gctx).taglen < 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping((*c).buf.as_ptr(), ptr_.cast::<u8>(), arg as usize);
            }
            1
        }
        0x12 => {
            // EVP_CTRL_GCM_SET_IV_FIXED — `include/openssl/evp.h:395`.
            // SAFETY: `gctx`/`c` are live and `ptr_` is readable for the bytes copied.
            unsafe {
                if arg == -1 {
                    ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*gctx).iv, (*gctx).ivlen as usize);
                    (*gctx).iv_gen = 1;
                    return 1;
                }
                if arg < 4 || ((*gctx).ivlen - arg) < 8 {
                    return 0;
                }
                if arg != 0 {
                    ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*gctx).iv, arg as usize);
                }
                if (*c).encrypt != 0
                    && RAND_bytes((*gctx).iv.add(arg as usize), (*gctx).ivlen - arg) <= 0
                {
                    return 0;
                }
                (*gctx).iv_gen = 1;
            }
            1
        }
        EVP_CTRL_GCM_IV_GEN => {
            // SAFETY: `gctx` is live.
            unsafe {
                if (*gctx).iv_gen == 0 || (*gctx).key_set == 0 {
                    return 0;
                }
                CRYPTO_gcm128_setiv(
                    ptr::addr_of_mut!((*gctx).gcm),
                    (*gctx).iv,
                    (*gctx).ivlen as usize,
                );
                let arg = if arg <= 0 || arg > (*gctx).ivlen {
                    (*gctx).ivlen
                } else {
                    arg
                };
                ptr::copy_nonoverlapping(
                    (*gctx).iv.add(((*gctx).ivlen - arg) as usize),
                    ptr_.cast::<u8>(),
                    arg as usize,
                );
                ctr64_inc((*gctx).iv.add(((*gctx).ivlen - 8) as usize));
                (*gctx).iv_set = 1;
            }
            1
        }
        EVP_CTRL_GCM_SET_IV_INV => {
            // SAFETY: `gctx`/`c` are live.
            unsafe {
                if (*gctx).iv_gen == 0 || (*gctx).key_set == 0 || (*c).encrypt != 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping(
                    ptr_.cast::<u8>(),
                    (*gctx).iv.add(((*gctx).ivlen - arg) as usize),
                    arg as usize,
                );
                CRYPTO_gcm128_setiv(
                    ptr::addr_of_mut!((*gctx).gcm),
                    (*gctx).iv,
                    (*gctx).ivlen as usize,
                );
                (*gctx).iv_set = 1;
            }
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            // SAFETY: `c`/`gctx` are live and `ptr_` is readable for `arg` bytes.
            unsafe {
                if arg != EVP_AEAD_TLS1_AAD_LEN {
                    return 0;
                }
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*c).buf.as_mut_ptr(), arg as usize);
                (*gctx).tls_aad_len = arg;
                (*gctx).tls_enc_records = 0;
                let a = arg as usize;
                let mut len = ((*c).buf[a - 2] as c_uint) << 8 | (*c).buf[a - 1] as c_uint;
                if (len as usize) < EVP_GCM_TLS_EXPLICIT_IV_LEN {
                    return 0;
                }
                len -= EVP_GCM_TLS_EXPLICIT_IV_LEN as c_uint;
                if (*c).encrypt == 0 {
                    if (len as usize) < EVP_GCM_TLS_TAG_LEN {
                        return 0;
                    }
                    len -= EVP_GCM_TLS_TAG_LEN as c_uint;
                }
                (*c).buf[a - 2] = (len >> 8) as c_uchar;
                (*c).buf[a - 1] = len as c_uchar;
            }
            EVP_GCM_TLS_TAG_LEN as c_int
        }
        0x8 => {
            // EVP_CTRL_COPY — `include/openssl/evp.h:387`.
            let out = ptr_.cast::<EvpCipherCtx>();
            // SAFETY: `out` is the copy the caller is fixing up.
            let gctx_out = unsafe { cipher_data(out) }.cast::<EvpAesGcmCtx>();
            // SAFETY: `gctx`, `gctx_out`, `out` and `c` are live.
            unsafe {
                if !(*gctx).gcm.key().is_null() {
                    if (*gctx).gcm.key() != ptr::addr_of_mut!((*gctx).ks).cast() {
                        return 0;
                    }
                    (*gctx_out)
                        .gcm
                        .repoint_key(ptr::addr_of_mut!((*gctx_out).ks).cast());
                }
                if (*gctx).iv == (*c).iv.as_mut_ptr() {
                    (*gctx_out).iv = (*out).iv.as_mut_ptr();
                } else {
                    let fresh = CRYPTO_malloc((*gctx).ivlen as usize, FILE.as_ptr(), LINE)
                        .cast::<c_uchar>();
                    if fresh.is_null() {
                        return 0;
                    }
                    (*gctx_out).iv = fresh;
                    ptr::copy_nonoverlapping((*gctx).iv, fresh, (*gctx).ivlen as usize);
                }
            }
            1
        }
        _ => -1,
    }
}

/// `aes_gcm_init_key` — `e_aes.c:2794-2873`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_gcm_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAesGcmCtx>();
    let mut iv = iv;
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        if keylen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_2806) };
            return 0;
        }
        // SAFETY: `key` is readable, `ks` writable, and `gcm` the context's own block.
        unsafe {
            AES_set_encrypt_key(key, keylen, ptr::addr_of_mut!((*gctx).ks));
            CRYPTO_gcm128_init(
                ptr::addr_of_mut!((*gctx).gcm),
                ptr::addr_of_mut!((*gctx).ks).cast(),
                aes_encrypt_block,
            );
            (*gctx).ctr = None;
            if iv.is_null() && (*gctx).iv_set != 0 {
                iv = (*gctx).iv;
            }
            if !iv.is_null() {
                CRYPTO_gcm128_setiv(ptr::addr_of_mut!((*gctx).gcm), iv, (*gctx).ivlen as usize);
                (*gctx).iv_set = 1;
            }
            (*gctx).key_set = 1;
        }
    } else {
        // SAFETY: `gctx` is live.
        unsafe {
            if (*gctx).key_set != 0 {
                CRYPTO_gcm128_setiv(ptr::addr_of_mut!((*gctx).gcm), iv, (*gctx).ivlen as usize);
            } else {
                ptr::copy_nonoverlapping(iv, (*gctx).iv, (*gctx).ivlen as usize);
            }
            (*gctx).iv_set = 1;
            (*gctx).iv_gen = 0;
        }
    }
    1
}

/// `aes_gcm_tls_cipher` — `e_aes.c:2882-3014`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_gcm_tls_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAesGcmCtx>();
    let mut rv: c_int = -1;
    if out != in_.cast_mut() || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) {
        return -1;
    }
    // SAFETY: `ctx` and `gctx` are live.
    unsafe {
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            (*gctx).tls_enc_records = (*gctx).tls_enc_records.wrapping_add(1);
            if (*gctx).tls_enc_records == 0 {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::E_AES_2899);
                (*gctx).iv_set = 0;
                (*gctx).tls_aad_len = -1;
                return rv;
            }
        }
        let ctrl = if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            EVP_CTRL_GCM_IV_GEN
        } else {
            EVP_CTRL_GCM_SET_IV_INV
        };
        if EVP_CIPHER_CTX_ctrl(ctx, ctrl, EVP_GCM_TLS_EXPLICIT_IV_LEN as c_int, out.cast()) <= 0 {
            (*gctx).iv_set = 0;
            (*gctx).tls_aad_len = -1;
            return rv;
        }
        if CRYPTO_gcm128_aad(
            ptr::addr_of_mut!((*gctx).gcm),
            EVP_CIPHER_CTX_buf_noconst(ctx),
            (*gctx).tls_aad_len as usize,
        ) != 0
        {
            (*gctx).iv_set = 0;
            (*gctx).tls_aad_len = -1;
            return rv;
        }
        let in_ = in_.add(EVP_GCM_TLS_EXPLICIT_IV_LEN);
        let out = out.add(EVP_GCM_TLS_EXPLICIT_IV_LEN);
        let len = len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            if CRYPTO_gcm128_encrypt(ptr::addr_of_mut!((*gctx).gcm), in_, out, len) != 0 {
                (*gctx).iv_set = 0;
                (*gctx).tls_aad_len = -1;
                return rv;
            }
            let out = out.add(len);
            CRYPTO_gcm128_tag(ptr::addr_of_mut!((*gctx).gcm), out, EVP_GCM_TLS_TAG_LEN);
            rv = (len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) as c_int;
        } else {
            if CRYPTO_gcm128_decrypt(ptr::addr_of_mut!((*gctx).gcm), in_, out, len) != 0 {
                (*gctx).iv_set = 0;
                (*gctx).tls_aad_len = -1;
                return rv;
            }
            CRYPTO_gcm128_tag(
                ptr::addr_of_mut!((*gctx).gcm),
                EVP_CIPHER_CTX_buf_noconst(ctx),
                EVP_GCM_TLS_TAG_LEN,
            );
            if CRYPTO_memcmp(
                EVP_CIPHER_CTX_buf_noconst(ctx).cast(),
                in_.add(len).cast(),
                EVP_GCM_TLS_TAG_LEN,
            ) != 0
            {
                OPENSSL_cleanse(out.cast(), len);
                (*gctx).iv_set = 0;
                (*gctx).tls_aad_len = -1;
                return rv;
            }
            rv = len as c_int;
        }
        (*gctx).iv_set = 0;
        (*gctx).tls_aad_len = -1;
    }
    rv
}

/// `aes_gcm_cipher` — `e_aes.c:3040-3183`, the non-FIPS portable arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_gcm_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAesGcmCtx>();
    // SAFETY: `gctx` is live.
    unsafe {
        if (*gctx).key_set == 0 {
            return -1;
        }
        if (*gctx).tls_aad_len >= 0 {
            return aes_gcm_tls_cipher(ctx.cast(), out, in_, len);
        }
        if (*gctx).iv_set == 0 {
            return -1;
        }
        if !in_.is_null() {
            if out.is_null() {
                if CRYPTO_gcm128_aad(ptr::addr_of_mut!((*gctx).gcm), in_, len) != 0 {
                    return -1;
                }
            } else if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                if CRYPTO_gcm128_encrypt(ptr::addr_of_mut!((*gctx).gcm), in_, out, len) != 0 {
                    return -1;
                }
            } else if CRYPTO_gcm128_decrypt(ptr::addr_of_mut!((*gctx).gcm), in_, out, len) != 0 {
                return -1;
            }
            return len as c_int;
        }
        if EVP_CIPHER_CTX_is_encrypting(ctx) == 0 {
            if (*gctx).taglen < 0 {
                return -1;
            }
            if CRYPTO_gcm128_finish(
                ptr::addr_of_mut!((*gctx).gcm),
                EVP_CIPHER_CTX_buf_noconst(ctx),
                (*gctx).taglen as usize,
            ) != 0
            {
                return -1;
            }
            (*gctx).iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(
            ptr::addr_of_mut!((*gctx).gcm),
            EVP_CIPHER_CTX_buf_noconst(ctx),
            16,
        );
        (*gctx).taglen = 16;
        (*gctx).iv_set = 0;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// XTS — `e_aes.c:3197-3381`
// ---------------------------------------------------------------------------------------------

/// `aes_xts_ctrl` — `e_aes.c:3197-3222`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aes_xts_ctrl(
    c: *mut c_void,
    type_: c_int,
    _arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let xctx = unsafe { cipher_data(c) }.cast::<EvpAesXtsCtx>();
    if type_ == 0x8 {
        // EVP_CTRL_COPY.
        let out = ptr_.cast::<EvpCipherCtx>();
        // SAFETY: `out` is the copy the caller is fixing up.
        let xctx_out = unsafe { cipher_data(out) }.cast::<EvpAesXtsCtx>();
        // SAFETY: both contexts are live.
        unsafe {
            if !(*xctx).xts.key1.is_null() {
                if (*xctx).xts.key1 != ptr::addr_of_mut!((*xctx).ks1).cast() {
                    return 0;
                }
                (*xctx_out).xts.key1 = ptr::addr_of_mut!((*xctx_out).ks1).cast();
            }
            if !(*xctx).xts.key2.is_null() {
                if (*xctx).xts.key2 != ptr::addr_of_mut!((*xctx).ks2).cast() {
                    return 0;
                }
                (*xctx_out).xts.key2 = ptr::addr_of_mut!((*xctx_out).ks2).cast();
            }
        }
        return 1;
    } else if type_ != 0 {
        return -1;
    }
    // SAFETY: `xctx` is live.
    unsafe {
        (*xctx).xts.key1 = ptr::null_mut();
        (*xctx).xts.key2 = ptr::null_mut();
    }
    1
}

/// `aes_xts_init_key` — `e_aes.c:3224-3339`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_xts_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let xctx = unsafe { cipher_data(ctx) }.cast::<EvpAesXtsCtx>();
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
        let bytes = keylen / 2;
        let bits = bytes * 8;
        if keylen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_3240) };
            return 0;
        }
        // SAFETY: `key` is readable for `2 * bytes` bytes per the contract.
        let duplicate =
            unsafe { CRYPTO_memcmp(key.cast(), key.add(bytes as usize).cast(), bytes as usize) }
                == 0;
        if (ALLOW_INSECURE_DECRYPT == 0 || enc != 0) && duplicate {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_3261) };
            return 0;
        }
        // SAFETY: `xctx` is the context's own block and `key`/`key + bytes` are readable.
        unsafe {
            (*xctx).stream = None;
            if enc != 0 {
                AES_set_encrypt_key(key, bits, ptr::addr_of_mut!((*xctx).ks1));
                (*xctx).xts.block1 = Some(aes_encrypt_block);
            } else {
                AES_set_decrypt_key(key, bits, ptr::addr_of_mut!((*xctx).ks1));
                (*xctx).xts.block1 = Some(aes_decrypt_block);
            }
            AES_set_encrypt_key(
                key.add(bytes as usize),
                bits,
                ptr::addr_of_mut!((*xctx).ks2),
            );
            (*xctx).xts.block2 = Some(aes_encrypt_block);
            (*xctx).xts.key1 = ptr::addr_of_mut!((*xctx).ks1).cast();
        }
    }
    if !iv.is_null() {
        // SAFETY: `xctx`/`ctx` are live; `iv` is readable for sixteen bytes.
        unsafe {
            (*xctx).xts.key2 = ptr::addr_of_mut!((*xctx).ks2).cast();
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), 16);
        }
    }
    1
}

/// `aes_xts_cipher` — `e_aes.c:3341-3372`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_xts_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let xctx = unsafe { cipher_data(ctx) }.cast::<EvpAesXtsCtx>();
    // SAFETY: `xctx` and `ctx` are live.
    unsafe {
        if (*xctx).xts.key1.is_null()
            || (*xctx).xts.key2.is_null()
            || out.is_null()
            || in_.is_null()
            || len < 16
        {
            return 0;
        }
        if len > XTS_MAX_BLOCKS_PER_DATA_UNIT * 16 {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::E_AES_3360);
            return 0;
        }
        if let Some(f) = (*xctx).stream {
            f(
                in_,
                out,
                len,
                (*xctx).xts.key1,
                (*xctx).xts.key2,
                (*ctx).iv.as_ptr(),
            );
        } else if CRYPTO_xts128_encrypt(
            ptr::addr_of!((*xctx).xts),
            (*ctx).iv.as_ptr(),
            in_,
            out,
            len,
            EVP_CIPHER_CTX_is_encrypting(ctx),
        ) != 0
        {
            return 0;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// CCM — `e_aes.c:3383-3660`
// ---------------------------------------------------------------------------------------------

/// `aes_ccm_ctrl` — `e_aes.c:3383-3479`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aes_ccm_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let cctx = unsafe { cipher_data(c) }.cast::<EvpAesCcmCtx>();
    match type_ {
        0 => {
            // EVP_CTRL_INIT.
            // SAFETY: `cctx` is live.
            unsafe {
                (*cctx).key_set = 0;
                (*cctx).iv_set = 0;
                (*cctx).l = 8;
                (*cctx).m = 12;
                (*cctx).tag_set = 0;
                (*cctx).len_set = 0;
                (*cctx).tls_aad_len = -1;
            }
            1
        }
        0x25 => {
            // EVP_CTRL_GET_IVLEN.
            // SAFETY: `ptr_` is the caller's `int *`.
            unsafe { *ptr_.cast::<c_int>() = 15 - (*cctx).l };
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            // SAFETY: `c`/`cctx` live and `ptr_` readable for `arg` bytes.
            unsafe {
                if arg != EVP_AEAD_TLS1_AAD_LEN {
                    return 0;
                }
                ptr::copy_nonoverlapping(
                    ptr_.cast::<u8>(),
                    EVP_CIPHER_CTX_buf_noconst(c),
                    arg as usize,
                );
                (*cctx).tls_aad_len = arg;
                let a = arg as usize;
                let buf = EVP_CIPHER_CTX_buf_noconst(c);
                let mut len = (*buf.add(a - 2) as c_uint) << 8 | *buf.add(a - 1) as c_uint;
                if (len as usize) < EVP_CCM_TLS_EXPLICIT_IV_LEN {
                    return 0;
                }
                len -= EVP_CCM_TLS_EXPLICIT_IV_LEN as c_uint;
                if EVP_CIPHER_CTX_is_encrypting(c) == 0 {
                    if len < (*cctx).m as c_uint {
                        return 0;
                    }
                    len -= (*cctx).m as c_uint;
                }
                *buf.add(a - 2) = (len >> 8) as c_uchar;
                *buf.add(a - 1) = len as c_uchar;
            }
            // SAFETY: `cctx` is the context's own block, read to answer the command.
            unsafe { (*cctx).m }
        }
        0x12 => {
            // EVP_CTRL_CCM_SET_IV_FIXED — `include/openssl/evp.h:400`.
            // SAFETY: `c` is live and `ptr_` readable for four bytes.
            unsafe {
                if arg != EVP_CCM_TLS_FIXED_IV_LEN as c_int {
                    return 0;
                }
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*c).iv.as_mut_ptr(), arg as usize);
            }
            1
        }
        EVP_CTRL_AEAD_SET_IVLEN => {
            let arg = 15 - arg;
            // fall through to the L setter below
            // SAFETY: `cctx` is live.
            unsafe {
                if !(2..=8).contains(&arg) {
                    return 0;
                }
                (*cctx).l = arg;
            }
            1
        }
        EVP_CTRL_CCM_SET_L => {
            // SAFETY: `cctx` is live.
            unsafe {
                if !(2..=8).contains(&arg) {
                    return 0;
                }
                (*cctx).l = arg;
            }
            1
        }
        EVP_CTRL_AEAD_SET_TAG => {
            // SAFETY: `c`/`cctx` live.
            unsafe {
                if (arg & 1) != 0 || !(4..=16).contains(&arg) {
                    return 0;
                }
                if EVP_CIPHER_CTX_is_encrypting(c) != 0 && !ptr_.is_null() {
                    return 0;
                }
                if !ptr_.is_null() {
                    (*cctx).tag_set = 1;
                    ptr::copy_nonoverlapping(
                        ptr_.cast::<u8>(),
                        EVP_CIPHER_CTX_buf_noconst(c),
                        arg as usize,
                    );
                }
                (*cctx).m = arg;
            }
            1
        }
        EVP_CTRL_AEAD_GET_TAG => {
            // SAFETY: `c`/`cctx` live.
            unsafe {
                if EVP_CIPHER_CTX_is_encrypting(c) == 0 || (*cctx).tag_set == 0 {
                    return 0;
                }
                if CRYPTO_ccm128_tag(
                    ptr::addr_of_mut!((*cctx).ccm),
                    ptr_.cast::<u8>(),
                    arg as usize,
                ) == 0
                {
                    return 0;
                }
                (*cctx).tag_set = 0;
                (*cctx).iv_set = 0;
                (*cctx).len_set = 0;
            }
            1
        }
        0x8 => {
            // EVP_CTRL_COPY.
            let out = ptr_.cast::<EvpCipherCtx>();
            // SAFETY: `out` is the copy the caller is fixing up.
            let cctx_out = unsafe { cipher_data(out) }.cast::<EvpAesCcmCtx>();
            // SAFETY: both contexts are live.
            unsafe {
                if !(*cctx).ccm.key().is_null() {
                    if (*cctx).ccm.key() != ptr::addr_of_mut!((*cctx).ks).cast() {
                        return 0;
                    }
                    (*cctx_out)
                        .ccm
                        .repoint_key(ptr::addr_of_mut!((*cctx_out).ks).cast());
                }
            }
            1
        }
        _ => -1,
    }
}

/// `aes_ccm_init_key` — `e_aes.c:3481-3530`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_ccm_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAesCcmCtx>();
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        if keylen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_3493) };
            return 0;
        }
        // SAFETY: `key` readable, `ks` writable, `ccm` the context's own block.
        unsafe {
            AES_set_encrypt_key(key, keylen, ptr::addr_of_mut!((*cctx).ks));
            CRYPTO_ccm128_init(
                ptr::addr_of_mut!((*cctx).ccm),
                (*cctx).m as c_uint,
                (*cctx).l as c_uint,
                ptr::addr_of_mut!((*cctx).ks).cast(),
                aes_encrypt_block,
            );
            (*cctx).str_ = None;
            (*cctx).key_set = 1;
        }
    }
    if !iv.is_null() {
        // SAFETY: `cctx`/`ctx` live; `iv` readable for `15 - L` bytes.
        unsafe {
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), (15 - (*cctx).l) as usize);
            (*cctx).iv_set = 1;
        }
    }
    1
}

/// `aes_ccm_tls_cipher` — `e_aes.c:3532-3579`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ccm_tls_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAesCcmCtx>();
    // SAFETY: `cctx`/`ctx` are live.
    unsafe {
        if out != in_.cast_mut() || len < (EVP_CCM_TLS_EXPLICIT_IV_LEN + (*cctx).m as usize) {
            return -1;
        }
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            ptr::copy_nonoverlapping(
                EVP_CIPHER_CTX_buf_noconst(ctx),
                out,
                EVP_CCM_TLS_EXPLICIT_IV_LEN,
            );
        }
        ptr::copy_nonoverlapping(
            in_,
            (*ctx).iv.as_mut_ptr().add(EVP_CCM_TLS_FIXED_IV_LEN),
            EVP_CCM_TLS_EXPLICIT_IV_LEN,
        );
        let len = len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + (*cctx).m as usize);
        if CRYPTO_ccm128_setiv(
            ptr::addr_of_mut!((*cctx).ccm),
            (*ctx).iv.as_ptr(),
            (15 - (*cctx).l) as usize,
            len,
        ) != 0
        {
            return -1;
        }
        CRYPTO_ccm128_aad(
            ptr::addr_of_mut!((*cctx).ccm),
            EVP_CIPHER_CTX_buf_noconst(ctx),
            (*cctx).tls_aad_len as usize,
        );
        let in_ = in_.add(EVP_CCM_TLS_EXPLICIT_IV_LEN);
        let out = out.add(EVP_CCM_TLS_EXPLICIT_IV_LEN);
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            if CRYPTO_ccm128_encrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) != 0 {
                return -1;
            }
            if CRYPTO_ccm128_tag(
                ptr::addr_of_mut!((*cctx).ccm),
                out.add(len),
                (*cctx).m as usize,
            ) == 0
            {
                return -1;
            }
            return (len + EVP_CCM_TLS_EXPLICIT_IV_LEN + (*cctx).m as usize) as c_int;
        }
        if CRYPTO_ccm128_decrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) == 0 {
            let mut tag = [0u8; 16];
            if CRYPTO_ccm128_tag(
                ptr::addr_of_mut!((*cctx).ccm),
                tag.as_mut_ptr(),
                (*cctx).m as usize,
            ) != 0
                && CRYPTO_memcmp(tag.as_ptr().cast(), in_.add(len).cast(), (*cctx).m as usize) == 0
            {
                return len as c_int;
            }
        }
        OPENSSL_cleanse(out.cast(), len);
        -1
    }
}

/// `aes_ccm_cipher` — `e_aes.c:3581-3651`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ccm_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAesCcmCtx>();
    // SAFETY: `cctx`/`ctx` are live.
    unsafe {
        if (*cctx).key_set == 0 {
            return -1;
        }
        if (*cctx).tls_aad_len >= 0 {
            return aes_ccm_tls_cipher(ctx.cast(), out, in_, len);
        }
        if in_.is_null() && !out.is_null() {
            return 0;
        }
        if (*cctx).iv_set == 0 {
            return -1;
        }
        if out.is_null() {
            if in_.is_null() {
                if CRYPTO_ccm128_setiv(
                    ptr::addr_of_mut!((*cctx).ccm),
                    (*ctx).iv.as_ptr(),
                    (15 - (*cctx).l) as usize,
                    len,
                ) != 0
                {
                    return -1;
                }
                (*cctx).len_set = 1;
                return len as c_int;
            }
            if (*cctx).len_set == 0 && len != 0 {
                return -1;
            }
            CRYPTO_ccm128_aad(ptr::addr_of_mut!((*cctx).ccm), in_, len);
            return len as c_int;
        }
        if EVP_CIPHER_CTX_is_encrypting(ctx) == 0 && (*cctx).tag_set == 0 {
            return -1;
        }
        if (*cctx).len_set == 0 {
            if CRYPTO_ccm128_setiv(
                ptr::addr_of_mut!((*cctx).ccm),
                (*ctx).iv.as_ptr(),
                (15 - (*cctx).l) as usize,
                len,
            ) != 0
            {
                return -1;
            }
            (*cctx).len_set = 1;
        }
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            if CRYPTO_ccm128_encrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) != 0 {
                return -1;
            }
            (*cctx).tag_set = 1;
            return len as c_int;
        }
        let mut rv: c_int = -1;
        if CRYPTO_ccm128_decrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) == 0 {
            let mut tag = [0u8; 16];
            if CRYPTO_ccm128_tag(
                ptr::addr_of_mut!((*cctx).ccm),
                tag.as_mut_ptr(),
                (*cctx).m as usize,
            ) != 0
                && CRYPTO_memcmp(
                    tag.as_ptr().cast(),
                    EVP_CIPHER_CTX_buf_noconst(ctx).cast(),
                    (*cctx).m as usize,
                ) == 0
            {
                rv = len as c_int;
            }
        }
        if rv == -1 {
            OPENSSL_cleanse(out.cast(), len);
        }
        (*cctx).iv_set = 0;
        (*cctx).tag_set = 0;
        (*cctx).len_set = 0;
        rv
    }
}

// ---------------------------------------------------------------------------------------------
// WRAP — `e_aes.c:3662-3847`
// ---------------------------------------------------------------------------------------------

/// `aes_wrap_init_key` — `e_aes.c:3671-3700`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_wrap_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let wctx = unsafe { cipher_data(ctx) }.cast::<EvpAesWrapCtx>();
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        if keylen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_3683) };
            return 0;
        }
        // SAFETY: `ctx`/`wctx` are live and `key` is readable.
        unsafe {
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                AES_set_encrypt_key(key, keylen, ptr::addr_of_mut!((*wctx).ks));
            } else {
                AES_set_decrypt_key(key, keylen, ptr::addr_of_mut!((*wctx).ks));
            }
            if iv.is_null() {
                (*wctx).iv = ptr::null_mut();
            }
        }
    }
    if !iv.is_null() {
        // SAFETY: `ctx` is live.
        let len = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if len < 0 {
            return 0;
        }
        // SAFETY: `iv` readable and `ctx->iv` writable for `len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(iv, (*ctx).iv.as_mut_ptr(), len as usize);
            (*wctx).iv = (*ctx).iv.as_mut_ptr();
        }
    }
    1
}

/// `aes_wrap_cipher` — `e_aes.c:3702-3759`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_wrap_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let wctx = unsafe { cipher_data(ctx) }.cast::<EvpAesWrapCtx>();
    // SAFETY: `ctx` is live.
    let pad = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) } == 4;
    if in_.is_null() {
        return 0;
    }
    if inlen == 0 {
        return -1;
    }
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } == 0 && (inlen < 16 || (inlen & 0x7) != 0) {
        return -1;
    }
    if !pad && (inlen & 0x7) != 0 {
        return -1;
    }
    // SAFETY: `out`/`in_` are the caller's buffers.
    if unsafe { ossl_is_partially_overlapping(out.cast(), in_.cast(), inlen as c_int) } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_AES_3722) };
        return 0;
    }
    if out.is_null() {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
            let inlen = if pad { inlen.div_ceil(8) * 8 } else { inlen };
            return (inlen + 8) as c_int;
        }
        return inlen.wrapping_sub(8) as c_int;
    }
    // SAFETY: `wctx`/`ctx` are live; the buffers hold `inlen` bytes.
    let rv = unsafe {
        if pad {
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                CRYPTO_128_wrap_pad(
                    ptr::addr_of_mut!((*wctx).ks).cast(),
                    (*wctx).iv,
                    out,
                    in_,
                    inlen,
                    aes_encrypt_block,
                )
            } else {
                CRYPTO_128_unwrap_pad(
                    ptr::addr_of_mut!((*wctx).ks).cast(),
                    (*wctx).iv,
                    out,
                    in_,
                    inlen,
                    aes_decrypt_block,
                )
            }
        } else if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            CRYPTO_128_wrap(
                ptr::addr_of_mut!((*wctx).ks).cast(),
                (*wctx).iv,
                out,
                in_,
                inlen,
                aes_encrypt_block,
            )
        } else {
            CRYPTO_128_unwrap(
                ptr::addr_of_mut!((*wctx).ks).cast(),
                (*wctx).iv,
                out,
                in_,
                inlen,
                aes_decrypt_block,
            )
        }
    };
    if rv != 0 {
        rv as c_int
    } else {
        -1
    }
}

// ---------------------------------------------------------------------------------------------
// OCB — `e_aes.c:3849-4153`
// ---------------------------------------------------------------------------------------------

/// `aes_ocb_ctrl` — `e_aes.c:3850-3910`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aes_ocb_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let octx = unsafe { cipher_data(c) }.cast::<EvpAesOcbCtx>();
    match type_ {
        0 => {
            // EVP_CTRL_INIT.
            // SAFETY: `octx`/`c` are live.
            unsafe {
                (*octx).key_set = 0;
                (*octx).iv_set = 0;
                (*octx).ivlen = crate::evp::cipher::EVP_CIPHER_get_iv_length((*c).cipher);
                (*octx).iv = (*c).iv.as_mut_ptr();
                (*octx).taglen = 16;
                (*octx).data_buf_len = 0;
                (*octx).aad_buf_len = 0;
            }
            1
        }
        0x25 => {
            // EVP_CTRL_GET_IVLEN.
            // SAFETY: `ptr_` is the caller's `int *`.
            unsafe { *ptr_.cast::<c_int>() = (*octx).ivlen };
            1
        }
        EVP_CTRL_AEAD_SET_IVLEN => {
            // SAFETY: `octx` is live.
            unsafe {
                if arg <= 0 || arg > 15 {
                    return 0;
                }
                (*octx).ivlen = arg;
            }
            1
        }
        EVP_CTRL_AEAD_SET_TAG => {
            // SAFETY: `octx`/`c` live.
            unsafe {
                if ptr_.is_null() {
                    if !(0..=16).contains(&arg) {
                        return 0;
                    }
                    (*octx).taglen = arg;
                    return 1;
                }
                if arg != (*octx).taglen || EVP_CIPHER_CTX_is_encrypting(c) != 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), (*octx).tag.as_mut_ptr(), arg as usize);
            }
            1
        }
        EVP_CTRL_AEAD_GET_TAG => {
            // SAFETY: `octx`/`c` live.
            unsafe {
                if arg != (*octx).taglen || EVP_CIPHER_CTX_is_encrypting(c) == 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping((*octx).tag.as_ptr(), ptr_.cast::<u8>(), arg as usize);
            }
            1
        }
        0x8 => {
            // EVP_CTRL_COPY.
            let newc = ptr_.cast::<EvpCipherCtx>();
            // SAFETY: `newc` is the copy the caller is fixing up.
            let new_octx = unsafe { cipher_data(newc) }.cast::<EvpAesOcbCtx>();
            // SAFETY: both contexts are live and their key schedules are their own.
            unsafe {
                CRYPTO_ocb128_copy_ctx(
                    ptr::addr_of_mut!((*new_octx).ocb),
                    ptr::addr_of_mut!((*octx).ocb),
                    ptr::addr_of_mut!((*new_octx).ksenc).cast(),
                    ptr::addr_of_mut!((*new_octx).ksdec).cast(),
                )
            }
        }
        _ => -1,
    }
}

/// `aes_ocb_init_key` — `e_aes.c:3912-3991`, the portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aes_ocb_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let octx = unsafe { cipher_data(ctx) }.cast::<EvpAesOcbCtx>();
    let mut iv = iv;
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        if keylen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_AES_3924) };
            return 0;
        }
        // SAFETY: `key` readable, the schedules writable, `ocb` the context's own block.
        unsafe {
            AES_set_encrypt_key(key, keylen, ptr::addr_of_mut!((*octx).ksenc));
            AES_set_decrypt_key(key, keylen, ptr::addr_of_mut!((*octx).ksdec));
            if CRYPTO_ocb128_init(
                ptr::addr_of_mut!((*octx).ocb),
                ptr::addr_of_mut!((*octx).ksenc).cast(),
                ptr::addr_of_mut!((*octx).ksdec).cast(),
                aes_encrypt_block,
                aes_decrypt_block,
                None,
            ) == 0
            {
                return 0;
            }
            if iv.is_null() && (*octx).iv_set != 0 {
                iv = (*octx).iv;
            }
            if !iv.is_null() {
                if CRYPTO_ocb128_setiv(
                    ptr::addr_of_mut!((*octx).ocb),
                    iv,
                    (*octx).ivlen as usize,
                    (*octx).taglen as usize,
                ) != 1
                {
                    return 0;
                }
                (*octx).iv_set = 1;
            }
            (*octx).key_set = 1;
        }
    } else {
        // SAFETY: `octx` is live.
        unsafe {
            if (*octx).key_set != 0 {
                CRYPTO_ocb128_setiv(
                    ptr::addr_of_mut!((*octx).ocb),
                    iv,
                    (*octx).ivlen as usize,
                    (*octx).taglen as usize,
                );
            } else {
                ptr::copy_nonoverlapping(iv, (*octx).iv, (*octx).ivlen as usize);
            }
            (*octx).iv_set = 1;
        }
    }
    1
}

/// `aes_ocb_cipher` — `e_aes.c:3993-4138`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aes_ocb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let octx = unsafe { cipher_data(ctx) }.cast::<EvpAesOcbCtx>();
    // SAFETY: `octx` is live.
    unsafe {
        if (*octx).iv_set == 0 || (*octx).key_set == 0 {
            return -1;
        }
        if !in_.is_null() {
            let buf: *mut c_uchar;
            let buf_len: *mut c_int;
            if out.is_null() {
                buf = (*octx).aad_buf.as_mut_ptr();
                buf_len = ptr::addr_of_mut!((*octx).aad_buf_len);
            } else {
                buf = (*octx).data_buf.as_mut_ptr();
                buf_len = ptr::addr_of_mut!((*octx).data_buf_len);
                if ossl_is_partially_overlapping(
                    out.add(*buf_len as usize).cast(),
                    in_.cast(),
                    len as c_int,
                ) != 0
                {
                    // SAFETY: a compile-time-constant site.
                    raise_site(&err_sites::E_AES_4026);
                    return 0;
                }
            }
            let mut written_len: c_int = 0;
            let mut len = len;
            let mut in_ = in_;
            let mut out = out;
            if *buf_len > 0 {
                let remaining = 16usize - (*buf_len) as usize;
                if remaining > len {
                    ptr::copy_nonoverlapping(in_, buf.add(*buf_len as usize), len);
                    *buf_len += len as c_int;
                    return 0;
                }
                ptr::copy_nonoverlapping(in_, buf.add(*buf_len as usize), remaining);
                len -= remaining;
                in_ = in_.add(remaining);
                if out.is_null() {
                    if CRYPTO_ocb128_aad(ptr::addr_of_mut!((*octx).ocb), buf, 16) == 0 {
                        return -1;
                    }
                } else if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                    if CRYPTO_ocb128_encrypt(ptr::addr_of_mut!((*octx).ocb), buf, out, 16) == 0 {
                        return -1;
                    }
                } else if CRYPTO_ocb128_decrypt(ptr::addr_of_mut!((*octx).ocb), buf, out, 16) == 0 {
                    return -1;
                }
                written_len = 16;
                *buf_len = 0;
                if !out.is_null() {
                    out = out.add(16);
                }
            }
            let trailing_len = len % 16;
            if len != trailing_len {
                if out.is_null() {
                    if CRYPTO_ocb128_aad(ptr::addr_of_mut!((*octx).ocb), in_, len - trailing_len)
                        == 0
                    {
                        return -1;
                    }
                } else if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                    if CRYPTO_ocb128_encrypt(
                        ptr::addr_of_mut!((*octx).ocb),
                        in_,
                        out,
                        len - trailing_len,
                    ) == 0
                    {
                        return -1;
                    }
                } else if CRYPTO_ocb128_decrypt(
                    ptr::addr_of_mut!((*octx).ocb),
                    in_,
                    out,
                    len - trailing_len,
                ) == 0
                {
                    return -1;
                }
                written_len += (len - trailing_len) as c_int;
                in_ = in_.add(len - trailing_len);
            }
            if trailing_len > 0 {
                ptr::copy_nonoverlapping(in_, buf, trailing_len);
                *buf_len = trailing_len as c_int;
            }
            return written_len;
        }
        let mut written_len: c_int = 0;
        if (*octx).data_buf_len > 0 {
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                if CRYPTO_ocb128_encrypt(
                    ptr::addr_of_mut!((*octx).ocb),
                    (*octx).data_buf.as_ptr(),
                    out,
                    (*octx).data_buf_len as usize,
                ) == 0
                {
                    return -1;
                }
            } else if CRYPTO_ocb128_decrypt(
                ptr::addr_of_mut!((*octx).ocb),
                (*octx).data_buf.as_ptr(),
                out,
                (*octx).data_buf_len as usize,
            ) == 0
            {
                return -1;
            }
            written_len = (*octx).data_buf_len;
            (*octx).data_buf_len = 0;
        }
        if (*octx).aad_buf_len > 0 {
            if CRYPTO_ocb128_aad(
                ptr::addr_of_mut!((*octx).ocb),
                (*octx).aad_buf.as_ptr(),
                (*octx).aad_buf_len as usize,
            ) == 0
            {
                return -1;
            }
            (*octx).aad_buf_len = 0;
        }
        if EVP_CIPHER_CTX_is_encrypting(ctx) == 0 {
            if (*octx).taglen < 0 {
                return -1;
            }
            if CRYPTO_ocb128_finish(
                ptr::addr_of_mut!((*octx).ocb),
                (*octx).tag.as_ptr(),
                (*octx).taglen as usize,
            ) != 0
            {
                return -1;
            }
            (*octx).iv_set = 0;
            return written_len;
        }
        if CRYPTO_ocb128_tag(ptr::addr_of_mut!((*octx).ocb), (*octx).tag.as_mut_ptr(), 16) != 1 {
            return -1;
        }
        (*octx).iv_set = 0;
        written_len
    }
}

/// `aes_ocb_cleanup` — `e_aes.c:4140-4145`.
///
/// # Safety
/// The `EVP_CIPHER::cleanup` contract.
unsafe extern "C" fn aes_ocb_cleanup(c: *mut c_void) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let octx = unsafe { cipher_data(c) }.cast::<EvpAesOcbCtx>();
    // SAFETY: `octx` is the context's own block.
    unsafe { CRYPTO_ocb128_cleanup(ptr::addr_of_mut!((*octx).ocb)) };
    1
}

// ---------------------------------------------------------------------------------------------
// The static objects
// ---------------------------------------------------------------------------------------------

/// A `static` `EVP_CIPHER`. The wrapper exists for the reason `src/evp/cipher.rs`'s own
/// `StaticCipher` does: the inner value is a compile-time constant that nothing writes.
struct StaticCipher(EvpCipher);

// SAFETY: the inner value is fully initialised at compile time and never written; every mutating
// arm of `EVP_CIPHER_up_ref`/`EVP_CIPHER_free` is guarded by `origin`, and `EVP_ORIG_GLOBAL` is
// not `EVP_ORIG_DYNAMIC`.
unsafe impl Sync for StaticCipher {}

/// The common shape of `BLOCK_CIPHER_generic`/`BLOCK_CIPHER_custom`'s initialiser, as a `const fn`.
///
/// The authority's macros set `set_asn1_parameters`/`get_asn1_parameters` to `NULL, NULL` (this
/// module's objects all carry `EVP_CIPH_FLAG_DEFAULT_ASN1`, whose value in 3.6.4 is **zero**, but
/// the macros write the two fields explicitly), and everything in the provider half is zero.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    key_len: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    cleanup: Option<CipherLegacyCleanupFn>,
    ctx_size: c_int,
    ctrl: Option<CipherLegacyCtrlFn>,
) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size,
        key_len,
        iv_len,
        flags,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup,
        ctx_size,
        set_asn1_parameters: None,
        get_asn1_parameters: None,
        ctrl,
        app_data: ptr::null_mut(),
        name_id: 0,
        type_name: ptr::null_mut(),
        description: ptr::null(),
        prov: ptr::null_mut(),
        refcnt: AtomicI32::new(0),
        newctx: None,
        einit: None,
        dinit: None,
        cupdate: None,
        cfinal: None,
        ccipher: None,
        p_einit: None,
        p_dinit: None,
        p_cupdate: None,
        p_cfinal: None,
        freectx: None,
        dupctx: None,
        get_params: None,
        get_ctx_params: None,
        set_ctx_params: None,
        gettable_params: None,
        gettable_ctx_params: None,
        settable_ctx_params: None,
        einit_skey: None,
        dinit_skey: None,
    })
}

/// `EVP_CIPH_FLAG_DEFAULT_ASN1` is **0** in 3.6.4 — `include/openssl/evp.h:343` — so the generic
/// pack's `flags | EVP_CIPH_FLAG_DEFAULT_ASN1` is its mode flag alone.
const CUSTOM_FLAGS: c_ulong = EVP_CIPH_CUSTOM_IV
    | EVP_CIPH_FLAG_CUSTOM_CIPHER
    | EVP_CIPH_ALWAYS_CALL_INIT
    | EVP_CIPH_CTRL_INIT
    | EVP_CIPH_CUSTOM_COPY
    | EVP_CIPH_CUSTOM_IV_LENGTH;

/// `XTS_FLAGS` — `e_aes.c:3376-3378`.
const XTS_FLAGS: c_ulong =
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY;

/// `WRAP_FLAGS` — `e_aes.c:3761-3763`.
const WRAP_FLAGS: c_ulong = EVP_CIPH_WRAP_MODE
    | EVP_CIPH_CUSTOM_IV
    | EVP_CIPH_FLAG_CUSTOM_CIPHER
    | EVP_CIPH_ALWAYS_CALL_INIT;

// The generic pack — `BLOCK_CIPHER_generic_pack(NID_aes, keylen, 0)`, `e_aes.c:2643-2645`.

static AES_128_CBC: StaticCipher = legacy_cipher(
    NID_aes_128_cbc,
    16,
    16,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_cbc_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_ECB: StaticCipher = legacy_cipher(
    NID_aes_128_ecb,
    16,
    16,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_ecb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_OFB: StaticCipher = legacy_cipher(
    NID_aes_128_ofb128,
    1,
    16,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aes_init_key),
    Some(aes_ofb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_CFB128: StaticCipher = legacy_cipher(
    NID_aes_128_cfb128,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_CFB1: StaticCipher = legacy_cipher(
    NID_aes_128_cfb1,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_CFB8: StaticCipher = legacy_cipher(
    NID_aes_128_cfb8,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_128_CTR: StaticCipher = legacy_cipher(
    NID_aes_128_ctr,
    1,
    16,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aes_init_key),
    Some(aes_ctr_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_CBC: StaticCipher = legacy_cipher(
    NID_aes_192_cbc,
    16,
    24,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_cbc_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_ECB: StaticCipher = legacy_cipher(
    NID_aes_192_ecb,
    16,
    24,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_ecb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_OFB: StaticCipher = legacy_cipher(
    NID_aes_192_ofb128,
    1,
    24,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aes_init_key),
    Some(aes_ofb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_CFB128: StaticCipher = legacy_cipher(
    NID_aes_192_cfb128,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_CFB1: StaticCipher = legacy_cipher(
    NID_aes_192_cfb1,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_CFB8: StaticCipher = legacy_cipher(
    NID_aes_192_cfb8,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_192_CTR: StaticCipher = legacy_cipher(
    NID_aes_192_ctr,
    1,
    24,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aes_init_key),
    Some(aes_ctr_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_CBC: StaticCipher = legacy_cipher(
    NID_aes_256_cbc,
    16,
    32,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_cbc_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_ECB: StaticCipher = legacy_cipher(
    NID_aes_256_ecb,
    16,
    32,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aes_init_key),
    Some(aes_ecb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_OFB: StaticCipher = legacy_cipher(
    NID_aes_256_ofb128,
    1,
    32,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aes_init_key),
    Some(aes_ofb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_CFB128: StaticCipher = legacy_cipher(
    NID_aes_256_cfb128,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_CFB1: StaticCipher = legacy_cipher(
    NID_aes_256_cfb1,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_CFB8: StaticCipher = legacy_cipher(
    NID_aes_256_cfb8,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aes_init_key),
    Some(aes_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);
static AES_256_CTR: StaticCipher = legacy_cipher(
    NID_aes_256_ctr,
    1,
    32,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aes_init_key),
    Some(aes_ctr_cipher),
    None,
    core::mem::size_of::<EvpAesKey>() as c_int,
    None,
);

// GCM — `BLOCK_CIPHER_custom(NID_aes, keylen, 1, 12, gcm, GCM, …)`, `e_aes.c:3190-3195`.

static AES_128_GCM: StaticCipher = legacy_cipher(
    NID_aes_128_gcm,
    1,
    16,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_GCM_MODE,
    Some(aes_gcm_init_key),
    Some(aes_gcm_cipher),
    Some(aes_gcm_cleanup),
    core::mem::size_of::<EvpAesGcmCtx>() as c_int,
    Some(aes_gcm_ctrl),
);
static AES_192_GCM: StaticCipher = legacy_cipher(
    NID_aes_192_gcm,
    1,
    24,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_GCM_MODE,
    Some(aes_gcm_init_key),
    Some(aes_gcm_cipher),
    Some(aes_gcm_cleanup),
    core::mem::size_of::<EvpAesGcmCtx>() as c_int,
    Some(aes_gcm_ctrl),
);
static AES_256_GCM: StaticCipher = legacy_cipher(
    NID_aes_256_gcm,
    1,
    32,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_GCM_MODE,
    Some(aes_gcm_init_key),
    Some(aes_gcm_cipher),
    Some(aes_gcm_cleanup),
    core::mem::size_of::<EvpAesGcmCtx>() as c_int,
    Some(aes_gcm_ctrl),
);

// XTS — `BLOCK_CIPHER_custom(NID_aes, keylen, 1, 16, xts, XTS, XTS_FLAGS)`, `e_aes.c:3380-3381`.

static AES_128_XTS: StaticCipher = legacy_cipher(
    NID_aes_128_xts,
    1,
    32,
    16,
    XTS_FLAGS | EVP_CIPH_XTS_MODE,
    Some(aes_xts_init_key),
    Some(aes_xts_cipher),
    None,
    core::mem::size_of::<EvpAesXtsCtx>() as c_int,
    Some(aes_xts_ctrl),
);
static AES_256_XTS: StaticCipher = legacy_cipher(
    NID_aes_256_xts,
    1,
    64,
    16,
    XTS_FLAGS | EVP_CIPH_XTS_MODE,
    Some(aes_xts_init_key),
    Some(aes_xts_cipher),
    None,
    core::mem::size_of::<EvpAesXtsCtx>() as c_int,
    Some(aes_xts_ctrl),
);

// CCM — `BLOCK_CIPHER_custom(NID_aes, keylen, 1, 12, ccm, CCM, …)`, `e_aes.c:3655-3660`.

static AES_128_CCM: StaticCipher = legacy_cipher(
    NID_aes_128_ccm,
    1,
    16,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CCM_MODE,
    Some(aes_ccm_init_key),
    Some(aes_ccm_cipher),
    None,
    core::mem::size_of::<EvpAesCcmCtx>() as c_int,
    Some(aes_ccm_ctrl),
);
static AES_192_CCM: StaticCipher = legacy_cipher(
    NID_aes_192_ccm,
    1,
    24,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CCM_MODE,
    Some(aes_ccm_init_key),
    Some(aes_ccm_cipher),
    None,
    core::mem::size_of::<EvpAesCcmCtx>() as c_int,
    Some(aes_ccm_ctrl),
);
static AES_256_CCM: StaticCipher = legacy_cipher(
    NID_aes_256_ccm,
    1,
    32,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CCM_MODE,
    Some(aes_ccm_init_key),
    Some(aes_ccm_cipher),
    None,
    core::mem::size_of::<EvpAesCcmCtx>() as c_int,
    Some(aes_ccm_ctrl),
);

// WRAP — `e_aes.c:3765-3847`.

static AES_128_WRAP: StaticCipher = legacy_cipher(
    NID_id_aes128_wrap,
    8,
    16,
    8,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);
static AES_192_WRAP: StaticCipher = legacy_cipher(
    NID_id_aes192_wrap,
    8,
    24,
    8,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);
static AES_256_WRAP: StaticCipher = legacy_cipher(
    NID_id_aes256_wrap,
    8,
    32,
    8,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);
static AES_128_WRAP_PAD: StaticCipher = legacy_cipher(
    NID_id_aes128_wrap_pad,
    8,
    16,
    4,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);
static AES_192_WRAP_PAD: StaticCipher = legacy_cipher(
    NID_id_aes192_wrap_pad,
    8,
    24,
    4,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);
static AES_256_WRAP_PAD: StaticCipher = legacy_cipher(
    NID_id_aes256_wrap_pad,
    8,
    32,
    4,
    WRAP_FLAGS,
    Some(aes_wrap_init_key),
    Some(aes_wrap_cipher),
    None,
    core::mem::size_of::<EvpAesWrapCtx>() as c_int,
    None,
);

// OCB — `BLOCK_CIPHER_custom(NID_aes, keylen, 16, 12, ocb, OCB, …)`, `e_aes.c:4147-4152`.

static AES_128_OCB: StaticCipher = legacy_cipher(
    NID_aes_128_ocb,
    16,
    16,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_OCB_MODE,
    Some(aes_ocb_init_key),
    Some(aes_ocb_cipher),
    Some(aes_ocb_cleanup),
    core::mem::size_of::<EvpAesOcbCtx>() as c_int,
    Some(aes_ocb_ctrl),
);
static AES_192_OCB: StaticCipher = legacy_cipher(
    NID_aes_192_ocb,
    16,
    24,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_OCB_MODE,
    Some(aes_ocb_init_key),
    Some(aes_ocb_cipher),
    Some(aes_ocb_cleanup),
    core::mem::size_of::<EvpAesOcbCtx>() as c_int,
    Some(aes_ocb_ctrl),
);
static AES_256_OCB: StaticCipher = legacy_cipher(
    NID_aes_256_ocb,
    16,
    32,
    12,
    CUSTOM_FLAGS | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_OCB_MODE,
    Some(aes_ocb_init_key),
    Some(aes_ocb_cipher),
    Some(aes_ocb_cleanup),
    core::mem::size_of::<EvpAesOcbCtx>() as c_int,
    Some(aes_ocb_ctrl),
);

// ---------------------------------------------------------------------------------------------
// The thirty-eight accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_aes_128_cbc(void)` — `e_aes.c`'s `BLOCK_CIPHER_generic_pack`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cbc() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CBC.0)
}
/// `const EVP_CIPHER *EVP_aes_128_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_ecb() -> *const EvpCipher {
    ptr::addr_of!(AES_128_ECB.0)
}
/// `const EVP_CIPHER *EVP_aes_128_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_ofb() -> *const EvpCipher {
    ptr::addr_of!(AES_128_OFB.0)
}
/// `const EVP_CIPHER *EVP_aes_128_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cfb128() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aes_128_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cfb1() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aes_128_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cfb8() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aes_128_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_ctr() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CTR.0)
}
/// `const EVP_CIPHER *EVP_aes_192_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_cbc() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CBC.0)
}
/// `const EVP_CIPHER *EVP_aes_192_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_ecb() -> *const EvpCipher {
    ptr::addr_of!(AES_192_ECB.0)
}
/// `const EVP_CIPHER *EVP_aes_192_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_ofb() -> *const EvpCipher {
    ptr::addr_of!(AES_192_OFB.0)
}
/// `const EVP_CIPHER *EVP_aes_192_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_cfb128() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aes_192_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_cfb1() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aes_192_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_cfb8() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aes_192_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_ctr() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CTR.0)
}
/// `const EVP_CIPHER *EVP_aes_256_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cbc() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CBC.0)
}
/// `const EVP_CIPHER *EVP_aes_256_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_ecb() -> *const EvpCipher {
    ptr::addr_of!(AES_256_ECB.0)
}
/// `const EVP_CIPHER *EVP_aes_256_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_ofb() -> *const EvpCipher {
    ptr::addr_of!(AES_256_OFB.0)
}
/// `const EVP_CIPHER *EVP_aes_256_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cfb128() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aes_256_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cfb1() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aes_256_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cfb8() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aes_256_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_ctr() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CTR.0)
}
/// `const EVP_CIPHER *EVP_aes_128_gcm(void)` — `e_aes.c:3190`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_gcm() -> *const EvpCipher {
    ptr::addr_of!(AES_128_GCM.0)
}
/// `const EVP_CIPHER *EVP_aes_192_gcm(void)` — `e_aes.c:3192`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_gcm() -> *const EvpCipher {
    ptr::addr_of!(AES_192_GCM.0)
}
/// `const EVP_CIPHER *EVP_aes_256_gcm(void)` — `e_aes.c:3194`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_gcm() -> *const EvpCipher {
    ptr::addr_of!(AES_256_GCM.0)
}
/// `const EVP_CIPHER *EVP_aes_128_xts(void)` — `e_aes.c:3380`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_xts() -> *const EvpCipher {
    ptr::addr_of!(AES_128_XTS.0)
}
/// `const EVP_CIPHER *EVP_aes_256_xts(void)` — `e_aes.c:3381`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_xts() -> *const EvpCipher {
    ptr::addr_of!(AES_256_XTS.0)
}
/// `const EVP_CIPHER *EVP_aes_128_ccm(void)` — `e_aes.c:3655`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_ccm() -> *const EvpCipher {
    ptr::addr_of!(AES_128_CCM.0)
}
/// `const EVP_CIPHER *EVP_aes_192_ccm(void)` — `e_aes.c:3657`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_ccm() -> *const EvpCipher {
    ptr::addr_of!(AES_192_CCM.0)
}
/// `const EVP_CIPHER *EVP_aes_256_ccm(void)` — `e_aes.c:3659`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_ccm() -> *const EvpCipher {
    ptr::addr_of!(AES_256_CCM.0)
}
/// `const EVP_CIPHER *EVP_aes_128_wrap(void)` — `e_aes.c:3774`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_wrap() -> *const EvpCipher {
    ptr::addr_of!(AES_128_WRAP.0)
}
/// `const EVP_CIPHER *EVP_aes_192_wrap(void)` — `e_aes.c:3788`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_wrap() -> *const EvpCipher {
    ptr::addr_of!(AES_192_WRAP.0)
}
/// `const EVP_CIPHER *EVP_aes_256_wrap(void)` — `e_aes.c:3802`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_wrap() -> *const EvpCipher {
    ptr::addr_of!(AES_256_WRAP.0)
}
/// `const EVP_CIPHER *EVP_aes_128_wrap_pad(void)` — `e_aes.c:3816`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_wrap_pad() -> *const EvpCipher {
    ptr::addr_of!(AES_128_WRAP_PAD.0)
}
/// `const EVP_CIPHER *EVP_aes_192_wrap_pad(void)` — `e_aes.c:3830`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_wrap_pad() -> *const EvpCipher {
    ptr::addr_of!(AES_192_WRAP_PAD.0)
}
/// `const EVP_CIPHER *EVP_aes_256_wrap_pad(void)` — `e_aes.c:3844`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_wrap_pad() -> *const EvpCipher {
    ptr::addr_of!(AES_256_WRAP_PAD.0)
}
/// `const EVP_CIPHER *EVP_aes_128_ocb(void)` — `e_aes.c:4147`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_ocb() -> *const EvpCipher {
    ptr::addr_of!(AES_128_OCB.0)
}
/// `const EVP_CIPHER *EVP_aes_192_ocb(void)` — `e_aes.c:4149`.
#[no_mangle]
pub extern "C" fn EVP_aes_192_ocb() -> *const EvpCipher {
    ptr::addr_of!(AES_192_OCB.0)
}
/// `const EVP_CIPHER *EVP_aes_256_ocb(void)` — `e_aes.c:4151`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_ocb() -> *const EvpCipher {
    ptr::addr_of!(AES_256_OCB.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each accessor answers the same address on every call — a `const` item would be inlined at
    /// each use and answer a different one — and the object carries the authority's `nid`,
    /// `block_size`, `key_len`, `iv_len` and `EVP_ORIG_GLOBAL`.
    #[test]
    fn the_accessors_are_stable_globals_with_the_authority_sizes() {
        let a = EVP_aes_128_cbc();
        let b = EVP_aes_128_cbc();
        assert_eq!(a, b);
        // SAFETY: `a` is this module's own static.
        unsafe {
            assert_eq!((*a).nid, NID_aes_128_cbc);
            assert_eq!((*a).block_size, 16);
            assert_eq!((*a).key_len, 16);
            assert_eq!((*a).iv_len, 16);
            assert_eq!((*a).origin, EVP_ORIG_GLOBAL);
            assert!((*a).init.is_some());
        }
        let x = EVP_aes_256_xts();
        // SAFETY: `x` is this module's own static.
        unsafe {
            assert_eq!((*x).key_len, 64);
            assert_eq!((*x).flags & EVP_CIPH_XTS_MODE, EVP_CIPH_XTS_MODE);
        }
    }
}
