//! Phase 13.6b — `crypto/evp/e_aria.c`: the deprecated `EVP_CIPHER` statics the ARIA modes return.
//!
//! `EVP_aria_128_cbc()` and its twenty-six siblings are one line each —
//! `return &aria_128_cbc;` (`e_aria.c:173-176`, via `BLOCK_CIPHER_generic`/`BLOCK_CIPHER_aead`) —
//! over a `static const EVP_CIPHER` whose legacy half is the
//! `aria_init_key`/`aria_*_cipher`/`aria_*_cleanup`/`aria_*_ctrl` callbacks. This module transcribes
//! those objects field for field and the callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_aria_128_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` runs the Phase-8 provider ARIA-CBC, not these callbacks. The callbacks are
//! transcribed for faithfulness — an engine is the only reachable caller — exactly as
//! `src/evp/e_aes.rs` transcribes the AES ones.
//!
//! ## The generic macro, and the arch arms that are not modelled
//!
//! The authority's `IMPLEMENT_BLOCK_CIPHER`/`BLOCK_CIPHER_generic`/`BLOCK_CIPHER_aead` macros expand
//! to the ten mode objects per key length, and to the accessors above them. ARIA has no assembly
//! arm in this crate's scope, so the portable callbacks are transcribed whole and every mode reaches
//! `ossl_aria_encrypt` through the generic modes machinery. The `set_asn1_parameters` pair the
//! generic pack installs (`EVP_CIPHER_set_asn1_iv`/`EVP_CIPHER_get_asn1_iv`, `e_aria.c:137-151`) is
//! transcribed; the AEAD, CTR and the two bit-width CFB objects carry `NULL, NULL` there, as the
//! authority's own macros do.
//!
//! ## What this module does not define
//!
//! The `ossl_*` internals and the provider arms are other units. Only the twenty-seven accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_aria.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::aria::{
    ossl_aria_encrypt, ossl_aria_set_decrypt_key, ossl_aria_set_encrypt_key, AriaKey,
};
use crate::asn1::layout::Asn1Type;
use crate::evp::cipher::{
    CipherLegacyAsn1Fn, CipherLegacyCleanupFn, CipherLegacyCtrlFn, CipherLegacyDoFn,
    CipherLegacyInitFn, EVP_CIPHER_get_iv_length, EVP_CIPHER_get_mode, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_buf_noconst, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_num,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num, EVP_CIPHER_CTX_test_flags,
    EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::modes::ccm::{
    CRYPTO_ccm128_aad, CRYPTO_ccm128_decrypt, CRYPTO_ccm128_decrypt_ccm64, CRYPTO_ccm128_encrypt,
    CRYPTO_ccm128_encrypt_ccm64, CRYPTO_ccm128_init, CRYPTO_ccm128_setiv, CRYPTO_ccm128_tag,
    CcmCtx,
};
use crate::modes::gcm::{
    CRYPTO_gcm128_aad, CRYPTO_gcm128_decrypt, CRYPTO_gcm128_encrypt, CRYPTO_gcm128_finish,
    CRYPTO_gcm128_init, CRYPTO_gcm128_setiv, CRYPTO_gcm128_tag, GcmCtx,
};
use crate::modes::{
    CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt, CRYPTO_cfb128_8_encrypt,
    CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt, CRYPTO_ofb128_encrypt, Ccm128F,
};
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, OPENSSL_cleanse};
use crate::runtime::obj::{
    NID_aria_128_cbc, NID_aria_128_ccm, NID_aria_128_cfb1, NID_aria_128_cfb128, NID_aria_128_cfb8,
    NID_aria_128_ctr, NID_aria_128_ecb, NID_aria_128_gcm, NID_aria_128_ofb128, NID_aria_192_cbc,
    NID_aria_192_ccm, NID_aria_192_cfb1, NID_aria_192_cfb128, NID_aria_192_cfb8, NID_aria_192_ctr,
    NID_aria_192_ecb, NID_aria_192_gcm, NID_aria_192_ofb128, NID_aria_256_cbc, NID_aria_256_ccm,
    NID_aria_256_cfb1, NID_aria_256_cfb128, NID_aria_256_cfb8, NID_aria_256_ctr, NID_aria_256_ecb,
    NID_aria_256_gcm, NID_aria_256_ofb128,
};

/// The translation-unit coordinates, as the allocator reports them.
const FILE: &core::ffi::CStr = c"crypto/evp/e_aria.c";
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
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: c_int = 16;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`. The generic block-cipher wrappers' chunk bound.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(TYPE, ctx)` — `e_aria.c:367-368`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn cipher_data(ctx: *const EvpCipherCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }
}

/// `block128_f` view of [`ossl_aria_encrypt`] — the `aria_*` helpers' cast at
/// `e_aria.c:89/101/109/131`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn aria_encrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is an `ARIA_KEY`.
    unsafe { ossl_aria_encrypt(input, out, key.cast::<AriaKey>()) }
}

/// `static void ctr64_inc(unsigned char *counter)` — `e_aria.c:203-216`.
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
// The contexts — `e_aria.c:23-58`
// ---------------------------------------------------------------------------------------------

/// `EVP_ARIA_KEY` — `e_aria.c:24-26`. The schedule, and nothing else.
pub struct EvpAriaKey {
    ks: AriaKey,
}

/// `EVP_ARIA_GCM_CTX` — `e_aria.c:29-42`.
pub struct EvpAriaGcmCtx {
    ks: AriaKey,
    key_set: c_int,
    iv_set: c_int,
    gcm: GcmCtx,
    iv: *mut c_uchar,
    ivlen: c_int,
    taglen: c_int,
    iv_gen: c_int,
    tls_aad_len: c_int,
}

/// `EVP_ARIA_CCM_CTX` — `e_aria.c:45-58`.
pub struct EvpAriaCcmCtx {
    ks: AriaKey,
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

// ---------------------------------------------------------------------------------------------
// `BLOCK_CIPHER_generic`'s callbacks — `e_aria.c:61-198`
// ---------------------------------------------------------------------------------------------

/// `aria_init_key` — `e_aria.c:61-80`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aria_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is the live context per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    // SAFETY: `ctx` is live and `cipher` is the method it borrowed.
    let mode = unsafe { EVP_CIPHER_get_mode((*ctx).cipher) };
    // SAFETY: `ctx` is live.
    let bits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
    let ret = if enc != 0 || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE) {
        // SAFETY: `key` is readable and `ks` writable per the contract.
        unsafe { ossl_aria_set_encrypt_key(key, bits, ptr::addr_of_mut!((*dat).ks)) }
    } else {
        // SAFETY: `key` is readable and `ks` writable per the contract.
        unsafe { ossl_aria_set_decrypt_key(key, bits, ptr::addr_of_mut!((*dat).ks)) }
    };
    if ret < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_ARIA_76) };
        return 0;
    }
    1
}

/// `aria_cbc_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_cbc` (`include/crypto/evp.h:407-419`).
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_cbc_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let mut in_ = in_;
    let mut out = out;
    let mut inl = len;
    // SAFETY: `dat` and `ctx` are live; each chunk stays within the caller's buffers.
    unsafe {
        while inl >= EVP_MAXCHUNK {
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                CRYPTO_cbc128_encrypt(
                    in_,
                    out,
                    EVP_MAXCHUNK,
                    ptr::addr_of_mut!((*dat).ks).cast(),
                    (*ctx).iv.as_mut_ptr(),
                    aria_encrypt_block,
                );
            } else {
                CRYPTO_cbc128_decrypt(
                    in_,
                    out,
                    EVP_MAXCHUNK,
                    ptr::addr_of_mut!((*dat).ks).cast(),
                    (*ctx).iv.as_mut_ptr(),
                    aria_encrypt_block,
                );
            }
            inl -= EVP_MAXCHUNK;
            in_ = in_.add(EVP_MAXCHUNK);
            out = out.add(EVP_MAXCHUNK);
        }
        if inl != 0 {
            if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                CRYPTO_cbc128_encrypt(
                    in_,
                    out,
                    inl,
                    ptr::addr_of_mut!((*dat).ks).cast(),
                    (*ctx).iv.as_mut_ptr(),
                    aria_encrypt_block,
                );
            } else {
                CRYPTO_cbc128_decrypt(
                    in_,
                    out,
                    inl,
                    ptr::addr_of_mut!((*dat).ks).cast(),
                    (*ctx).iv.as_mut_ptr(),
                    aria_encrypt_block,
                );
            }
        }
    }
    1
}

/// `aria_cfb128_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_cfb` with `cbits == 128`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_cfb128_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let mut in_ = in_;
    let mut out = out;
    let mut inl = len;
    let mut chunk = EVP_MAXCHUNK;
    if inl < chunk {
        chunk = inl;
    }
    // SAFETY: `dat`/`ctx` live; the chunk loop stays within `len` bytes of both buffers.
    unsafe {
        while inl != 0 && inl >= chunk {
            let mut num = EVP_CIPHER_CTX_get_num(ctx);
            CRYPTO_cfb128_encrypt(
                in_,
                out,
                chunk,
                ptr::addr_of_mut!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                aria_encrypt_block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
            inl -= chunk;
            in_ = in_.add(chunk);
            out = out.add(chunk);
            if inl < chunk {
                chunk = inl;
            }
        }
    }
    1
}

/// `aria_cfb1_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_cfb` with `cbits == 1`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_cfb1_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let mut in_ = in_;
    let mut out = out;
    let mut inl = len;
    let mut chunk = EVP_MAXCHUNK >> 3;
    if inl < chunk {
        chunk = inl;
    }
    // SAFETY: `dat`/`ctx` live; the bit count is `chunk * 8` unless the caller is counting bits.
    unsafe {
        while inl != 0 && inl >= chunk {
            let mut num = EVP_CIPHER_CTX_get_num(ctx);
            let bits = if EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) == 0 {
                chunk * 8
            } else {
                chunk
            };
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                bits,
                ptr::addr_of_mut!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                aria_encrypt_block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
            inl -= chunk;
            in_ = in_.add(chunk);
            out = out.add(chunk);
            if inl < chunk {
                chunk = inl;
            }
        }
    }
    1
}

/// `aria_cfb8_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_cfb` with `cbits == 8`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_cfb8_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let mut in_ = in_;
    let mut out = out;
    let mut inl = len;
    let mut chunk = EVP_MAXCHUNK;
    if inl < chunk {
        chunk = inl;
    }
    // SAFETY: `dat`/`ctx` live; the chunk loop stays within `len` bytes of both buffers.
    unsafe {
        while inl != 0 && inl >= chunk {
            let mut num = EVP_CIPHER_CTX_get_num(ctx);
            CRYPTO_cfb128_8_encrypt(
                in_,
                out,
                chunk,
                ptr::addr_of_mut!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                (*ctx).encrypt,
                aria_encrypt_block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
            inl -= chunk;
            in_ = in_.add(chunk);
            out = out.add(chunk);
            if inl < chunk {
                chunk = inl;
            }
        }
    }
    1
}

/// `aria_ecb_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_ecb` (`include/crypto/evp.h:378-384`).
///
/// `aria_ecb_encrypt` ignores its `enc` argument (`e_aria.c:120-124`), so every block is an
/// encryption call.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_ecb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
    if len < bl {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let last = len - bl;
    let mut i = 0usize;
    while i <= last {
        // SAFETY: `dat` is live and the loop stays within `len` bytes of both buffers.
        unsafe { ossl_aria_encrypt(in_.add(i), out.add(i), ptr::addr_of!((*dat).ks)) };
        i += bl;
    }
    1
}

/// `aria_ofb_cipher` — `e_aria.c`'s `BLOCK_CIPHER_func_ofb` (`include/crypto/evp.h:388-405`).
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_ofb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    let mut in_ = in_;
    let mut out = out;
    let mut inl = len;
    // SAFETY: `dat`/`ctx` live; each chunk stays within the caller's buffers.
    unsafe {
        while inl >= EVP_MAXCHUNK {
            let mut num = EVP_CIPHER_CTX_get_num(ctx);
            CRYPTO_ofb128_encrypt(
                in_,
                out,
                EVP_MAXCHUNK,
                ptr::addr_of_mut!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                aria_encrypt_block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
            inl -= EVP_MAXCHUNK;
            in_ = in_.add(EVP_MAXCHUNK);
            out = out.add(EVP_MAXCHUNK);
        }
        if inl != 0 {
            let mut num = EVP_CIPHER_CTX_get_num(ctx);
            CRYPTO_ofb128_encrypt(
                in_,
                out,
                inl,
                ptr::addr_of_mut!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                aria_encrypt_block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `aria_ctr_cipher` — `e_aria.c:178-194`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_ctr_cipher(
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
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpAriaKey>();
    // SAFETY: `dat`/`ctx` live; `ecount_buf` is the context's own `buf`.
    unsafe {
        CRYPTO_ctr128_encrypt(
            in_,
            out,
            len,
            ptr::addr_of_mut!((*dat).ks).cast(),
            (*ctx).iv.as_mut_ptr(),
            EVP_CIPHER_CTX_buf_noconst(ctx),
            &mut num,
            aria_encrypt_block,
        );
        EVP_CIPHER_CTX_set_num(ctx, num as c_int);
    }
    1
}

// ---------------------------------------------------------------------------------------------
// GCM — `e_aria.c:218-507`
// ---------------------------------------------------------------------------------------------

/// `aria_gcm_init_key` — `e_aria.c:218-257`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aria_gcm_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaGcmCtx>();
    let mut iv = iv;
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let bits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        // SAFETY: `key` is readable, `ks` writable, and `gcm` the context's own block.
        unsafe {
            let ret = ossl_aria_set_encrypt_key(key, bits, ptr::addr_of_mut!((*gctx).ks));
            CRYPTO_gcm128_init(
                ptr::addr_of_mut!((*gctx).gcm),
                ptr::addr_of_mut!((*gctx).ks).cast(),
                aria_encrypt_block,
            );
            if ret < 0 {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::E_ARIA_233);
                return 0;
            }
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

/// `aria_gcm_ctrl` — `e_aria.c:259-396`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aria_gcm_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let gctx = unsafe { cipher_data(c) }.cast::<EvpAriaGcmCtx>();
    match type_ {
        0 => {
            // EVP_CTRL_INIT — `include/openssl/evp.h:379`.
            // SAFETY: `gctx` and `c` are live.
            unsafe {
                (*gctx).key_set = 0;
                (*gctx).iv_set = 0;
                (*gctx).ivlen = EVP_CIPHER_get_iv_length((*c).cipher);
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
                if arg > EVP_MAX_IV_LENGTH && arg > (*gctx).ivlen {
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
                if arg <= 0 || arg > 16 || EVP_CIPHER_CTX_is_encrypting(c) != 0 {
                    return 0;
                }
                ptr::copy_nonoverlapping(
                    ptr_.cast::<u8>(),
                    EVP_CIPHER_CTX_buf_noconst(c),
                    arg as usize,
                );
                (*gctx).taglen = arg;
            }
            1
        }
        EVP_CTRL_AEAD_GET_TAG => {
            // SAFETY: `c` and `gctx` are live; `ptr_` is writable for `arg` bytes.
            unsafe {
                if arg <= 0
                    || arg > 16
                    || EVP_CIPHER_CTX_is_encrypting(c) == 0
                    || (*gctx).taglen < 0
                {
                    return 0;
                }
                ptr::copy_nonoverlapping(
                    EVP_CIPHER_CTX_buf_noconst(c),
                    ptr_.cast::<u8>(),
                    arg as usize,
                );
            }
            1
        }
        0x12 => {
            // EVP_CTRL_GCM_SET_IV_FIXED — `include/openssl/evp.h:395`.
            // SAFETY: `gctx`/`c` live and `ptr_` readable for the bytes copied.
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
                if EVP_CIPHER_CTX_is_encrypting(c) != 0
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
                if (*gctx).iv_gen == 0
                    || (*gctx).key_set == 0
                    || EVP_CIPHER_CTX_is_encrypting(c) != 0
                {
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
                let buf = EVP_CIPHER_CTX_buf_noconst(c);
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), buf, arg as usize);
                (*gctx).tls_aad_len = arg;
                let a = arg as usize;
                let mut len = (*buf.add(a - 2) as c_uint) << 8 | *buf.add(a - 1) as c_uint;
                if (len as usize) < EVP_GCM_TLS_EXPLICIT_IV_LEN {
                    return 0;
                }
                len -= EVP_GCM_TLS_EXPLICIT_IV_LEN as c_uint;
                if EVP_CIPHER_CTX_is_encrypting(c) == 0 {
                    if (len as usize) < EVP_GCM_TLS_TAG_LEN {
                        return 0;
                    }
                    len -= EVP_GCM_TLS_TAG_LEN as c_uint;
                }
                *buf.add(a - 2) = (len >> 8) as c_uchar;
                *buf.add(a - 1) = len as c_uchar;
            }
            EVP_GCM_TLS_TAG_LEN as c_int
        }
        0x8 => {
            // EVP_CTRL_COPY — `include/openssl/evp.h:387`.
            let out = ptr_.cast::<EvpCipherCtx>();
            // SAFETY: `out` is the copy the caller is fixing up.
            let gctx_out = unsafe { cipher_data(out) }.cast::<EvpAriaGcmCtx>();
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

/// `aria_gcm_cleanup` — `e_aria.c:499-507`.
///
/// # Safety
/// The `EVP_CIPHER::cleanup` contract.
unsafe extern "C" fn aria_gcm_cleanup(c: *mut c_void) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let gctx = unsafe { cipher_data(c) }.cast::<EvpAriaGcmCtx>();
    if gctx.is_null() {
        return 0;
    }
    // SAFETY: `gctx` is the context's own block.
    unsafe {
        if (*gctx).iv != (*c).iv.as_mut_ptr() {
            CRYPTO_free((*gctx).iv.cast(), FILE.as_ptr(), LINE);
        }
    }
    1
}

/// `aria_gcm_tls_cipher` — `e_aria.c:398-452`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_gcm_tls_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaGcmCtx>();
    let mut rv: c_int = -1;
    if out != in_.cast_mut() || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) {
        return -1;
    }
    // SAFETY: `ctx` and `gctx` are live.
    unsafe {
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

/// `aria_gcm_cipher` — `e_aria.c:454-497`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_gcm_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let gctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaGcmCtx>();
    // SAFETY: `gctx` is live.
    unsafe {
        if (*gctx).key_set == 0 {
            return -1;
        }
        if (*gctx).tls_aad_len >= 0 {
            return aria_gcm_tls_cipher(ctx.cast(), out, in_, len);
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
// CCM — `e_aria.c:509-756`
// ---------------------------------------------------------------------------------------------

/// `aria_ccm_init_key` — `e_aria.c:509-536`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn aria_ccm_init_key(
    ctx: *mut c_void,
    key: *const u8,
    iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaCcmCtx>();
    if iv.is_null() && key.is_null() {
        return 1;
    }
    if !key.is_null() {
        // SAFETY: `ctx` is live.
        let bits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
        // SAFETY: `key` readable, `ks` writable, `ccm` the context's own block.
        unsafe {
            let ret = ossl_aria_set_encrypt_key(key, bits, ptr::addr_of_mut!((*cctx).ks));
            CRYPTO_ccm128_init(
                ptr::addr_of_mut!((*cctx).ccm),
                (*cctx).m as c_uint,
                (*cctx).l as c_uint,
                ptr::addr_of_mut!((*cctx).ks).cast(),
                aria_encrypt_block,
            );
            if ret < 0 {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::E_ARIA_525);
                return 0;
            }
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

/// `aria_ccm_ctrl` — `e_aria.c:538-634`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn aria_ccm_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    // SAFETY: `c` is live per the contract.
    let cctx = unsafe { cipher_data(c) }.cast::<EvpAriaCcmCtx>();
    match type_ {
        0 => {
            // EVP_CTRL_INIT — `include/openssl/evp.h:379`.
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
            // EVP_CTRL_GET_IVLEN — `include/openssl/evp.h:442`.
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
                let buf = EVP_CIPHER_CTX_buf_noconst(c);
                ptr::copy_nonoverlapping(ptr_.cast::<u8>(), buf, arg as usize);
                (*cctx).tls_aad_len = arg;
                let a = arg as usize;
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
                (*cctx).m
            }
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
            // EVP_CTRL_COPY — `include/openssl/evp.h:387`.
            let out = ptr_.cast::<EvpCipherCtx>();
            // SAFETY: `out` is the copy the caller is fixing up.
            let cctx_out = unsafe { cipher_data(out) }.cast::<EvpAriaCcmCtx>();
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

/// `aria_ccm_tls_cipher` — `e_aria.c:636-682`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_ccm_tls_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaCcmCtx>();
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
            let r = match (*cctx).str_ {
                Some(f) => {
                    CRYPTO_ccm128_encrypt_ccm64(ptr::addr_of_mut!((*cctx).ccm), in_, out, len, f)
                }
                None => CRYPTO_ccm128_encrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len),
            };
            if r != 0 {
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
        let ok = match (*cctx).str_ {
            Some(f) => {
                CRYPTO_ccm128_decrypt_ccm64(ptr::addr_of_mut!((*cctx).ccm), in_, out, len, f) == 0
            }
            None => CRYPTO_ccm128_decrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) == 0,
        };
        if ok {
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

/// `aria_ccm_cipher` — `e_aria.c:684-753`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn aria_ccm_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let cctx = unsafe { cipher_data(ctx) }.cast::<EvpAriaCcmCtx>();
    // SAFETY: `cctx`/`ctx` are live.
    unsafe {
        if (*cctx).key_set == 0 {
            return -1;
        }
        if (*cctx).tls_aad_len >= 0 {
            return aria_ccm_tls_cipher(ctx.cast(), out, in_, len);
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
            let r = match (*cctx).str_ {
                Some(f) => {
                    CRYPTO_ccm128_encrypt_ccm64(ptr::addr_of_mut!((*cctx).ccm), in_, out, len, f)
                }
                None => CRYPTO_ccm128_encrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len),
            };
            if r != 0 {
                return -1;
            }
            (*cctx).tag_set = 1;
            return len as c_int;
        }
        let mut rv: c_int = -1;
        let ok = match (*cctx).str_ {
            Some(f) => {
                CRYPTO_ccm128_decrypt_ccm64(ptr::addr_of_mut!((*cctx).ccm), in_, out, len, f) == 0
            }
            None => CRYPTO_ccm128_decrypt(ptr::addr_of_mut!((*cctx).ccm), in_, out, len) == 0,
        };
        if ok {
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
// The static objects
// ---------------------------------------------------------------------------------------------

/// A `static` `EVP_CIPHER`. The wrapper exists for the reason `src/evp/e_aes.rs`'s own
/// `StaticCipher` does: the inner value is a compile-time constant that nothing writes.
struct StaticCipher(EvpCipher);

// SAFETY: the inner value is fully initialised at compile time and never written; every mutating
// arm of `EVP_CIPHER_up_ref`/`EVP_CIPHER_free` is guarded by `origin`, and `EVP_ORIG_GLOBAL` is
// not `EVP_ORIG_DYNAMIC`.
unsafe impl Sync for StaticCipher {}

/// The common shape of the ARIA macros' initialiser, as a `const fn`.
///
/// The generic pack (`e_aria.c:134-151`) writes `EVP_CIPHER_set_asn1_iv`/`EVP_CIPHER_get_asn1_iv`
/// into the ASN.1 pair, while `BLOCK_CIPHER_generic`'s CTR arm (`e_aria.c:162-176`) and
/// `BLOCK_CIPHER_aead` (`e_aria.c:763-778`) write `NULL, NULL`; `flags` and `ctrl` differ the same
/// way. Everything in the provider half is zero.
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
    set_asn1: Option<CipherLegacyAsn1Fn>,
    get_asn1: Option<CipherLegacyAsn1Fn>,
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
        set_asn1_parameters: set_asn1,
        get_asn1_parameters: get_asn1,
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

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_set_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn aria_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn aria_get_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `ARIA_AUTH_FLAGS` — `e_aria.c:757-761`. `EVP_CIPH_FLAG_DEFAULT_ASN1` is **0** in 3.6.4
/// (`include/openssl/evp.h:343`), so its OR is a no-op.
const ARIA_AUTH_FLAGS: c_ulong = EVP_CIPH_CUSTOM_IV
    | EVP_CIPH_FLAG_CUSTOM_CIPHER
    | EVP_CIPH_ALWAYS_CALL_INIT
    | EVP_CIPH_CTRL_INIT
    | EVP_CIPH_CUSTOM_COPY
    | EVP_CIPH_FLAG_AEAD_CIPHER
    | EVP_CIPH_CUSTOM_IV_LENGTH;

// The generic block-cipher pack, in `EVP_ARIA_KEY` order — `e_aria.c:134-151` and `:153-160`.

static ARIA_128_CBC: StaticCipher = legacy_cipher(
    NID_aria_128_cbc,
    16,
    16,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_cbc_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_128_ECB: StaticCipher = legacy_cipher(
    NID_aria_128_ecb,
    16,
    16,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_ecb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_128_OFB: StaticCipher = legacy_cipher(
    NID_aria_128_ofb128,
    1,
    16,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aria_init_key),
    Some(aria_ofb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_128_CFB128: StaticCipher = legacy_cipher(
    NID_aria_128_cfb128,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb128_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_128_CFB1: StaticCipher = legacy_cipher(
    NID_aria_128_cfb1,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_128_CFB8: StaticCipher = legacy_cipher(
    NID_aria_128_cfb8,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_128_CTR: StaticCipher = legacy_cipher(
    NID_aria_128_ctr,
    1,
    16,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aria_init_key),
    Some(aria_ctr_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_192_CBC: StaticCipher = legacy_cipher(
    NID_aria_192_cbc,
    16,
    24,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_cbc_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_192_ECB: StaticCipher = legacy_cipher(
    NID_aria_192_ecb,
    16,
    24,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_ecb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_192_OFB: StaticCipher = legacy_cipher(
    NID_aria_192_ofb128,
    1,
    24,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aria_init_key),
    Some(aria_ofb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_192_CFB128: StaticCipher = legacy_cipher(
    NID_aria_192_cfb128,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb128_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_192_CFB1: StaticCipher = legacy_cipher(
    NID_aria_192_cfb1,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_192_CFB8: StaticCipher = legacy_cipher(
    NID_aria_192_cfb8,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_192_CTR: StaticCipher = legacy_cipher(
    NID_aria_192_ctr,
    1,
    24,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aria_init_key),
    Some(aria_ctr_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_256_CBC: StaticCipher = legacy_cipher(
    NID_aria_256_cbc,
    16,
    32,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_cbc_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_256_ECB: StaticCipher = legacy_cipher(
    NID_aria_256_ecb,
    16,
    32,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(aria_init_key),
    Some(aria_ecb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_256_OFB: StaticCipher = legacy_cipher(
    NID_aria_256_ofb128,
    1,
    32,
    16,
    EVP_CIPH_OFB_MODE,
    Some(aria_init_key),
    Some(aria_ofb_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_256_CFB128: StaticCipher = legacy_cipher(
    NID_aria_256_cfb128,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb128_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    Some(aria_set_asn1_iv),
    Some(aria_get_asn1_iv),
    None,
);
static ARIA_256_CFB1: StaticCipher = legacy_cipher(
    NID_aria_256_cfb1,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb1_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_256_CFB8: StaticCipher = legacy_cipher(
    NID_aria_256_cfb8,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(aria_init_key),
    Some(aria_cfb8_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);
static ARIA_256_CTR: StaticCipher = legacy_cipher(
    NID_aria_256_ctr,
    1,
    32,
    16,
    EVP_CIPH_CTR_MODE,
    Some(aria_init_key),
    Some(aria_ctr_cipher),
    None,
    core::mem::size_of::<EvpAriaKey>() as c_int,
    None,
    None,
    None,
);

// `BLOCK_CIPHER_aead(keylen, mode, MODE)` — `e_aria.c:763-786`.

static ARIA_128_GCM: StaticCipher = legacy_cipher(
    NID_aria_128_gcm,
    1,
    16,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_GCM_MODE,
    Some(aria_gcm_init_key),
    Some(aria_gcm_cipher),
    Some(aria_gcm_cleanup),
    core::mem::size_of::<EvpAriaGcmCtx>() as c_int,
    None,
    None,
    Some(aria_gcm_ctrl),
);
static ARIA_192_GCM: StaticCipher = legacy_cipher(
    NID_aria_192_gcm,
    1,
    24,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_GCM_MODE,
    Some(aria_gcm_init_key),
    Some(aria_gcm_cipher),
    Some(aria_gcm_cleanup),
    core::mem::size_of::<EvpAriaGcmCtx>() as c_int,
    None,
    None,
    Some(aria_gcm_ctrl),
);
static ARIA_256_GCM: StaticCipher = legacy_cipher(
    NID_aria_256_gcm,
    1,
    32,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_GCM_MODE,
    Some(aria_gcm_init_key),
    Some(aria_gcm_cipher),
    Some(aria_gcm_cleanup),
    core::mem::size_of::<EvpAriaGcmCtx>() as c_int,
    None,
    None,
    Some(aria_gcm_ctrl),
);
static ARIA_128_CCM: StaticCipher = legacy_cipher(
    NID_aria_128_ccm,
    1,
    16,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_CCM_MODE,
    Some(aria_ccm_init_key),
    Some(aria_ccm_cipher),
    None,
    core::mem::size_of::<EvpAriaCcmCtx>() as c_int,
    None,
    None,
    Some(aria_ccm_ctrl),
);
static ARIA_192_CCM: StaticCipher = legacy_cipher(
    NID_aria_192_ccm,
    1,
    24,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_CCM_MODE,
    Some(aria_ccm_init_key),
    Some(aria_ccm_cipher),
    None,
    core::mem::size_of::<EvpAriaCcmCtx>() as c_int,
    None,
    None,
    Some(aria_ccm_ctrl),
);
static ARIA_256_CCM: StaticCipher = legacy_cipher(
    NID_aria_256_ccm,
    1,
    32,
    12,
    ARIA_AUTH_FLAGS | EVP_CIPH_CCM_MODE,
    Some(aria_ccm_init_key),
    Some(aria_ccm_cipher),
    None,
    core::mem::size_of::<EvpAriaCcmCtx>() as c_int,
    None,
    None,
    Some(aria_ccm_ctrl),
);

// ---------------------------------------------------------------------------------------------
// The twenty-seven accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_aria_128_cbc(void)` — `e_aria.c:134`'s `IMPLEMENT_BLOCK_CIPHER`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_cbc() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CBC.0)
}
/// `const EVP_CIPHER *EVP_aria_128_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_ecb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_ECB.0)
}
/// `const EVP_CIPHER *EVP_aria_128_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_ofb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_OFB.0)
}
/// `const EVP_CIPHER *EVP_aria_128_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_cfb128() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aria_128_cfb1(void)` — `e_aria.c:155`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_cfb1() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aria_128_cfb8(void)` — `e_aria.c:158`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_cfb8() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aria_128_ctr(void)` — `e_aria.c:196`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_ctr() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CTR.0)
}
/// `const EVP_CIPHER *EVP_aria_128_gcm(void)` — `e_aria.c:780`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_gcm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_GCM.0)
}
/// `const EVP_CIPHER *EVP_aria_128_ccm(void)` — `e_aria.c:784`.
#[no_mangle]
pub extern "C" fn EVP_aria_128_ccm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_128_CCM.0)
}
/// `const EVP_CIPHER *EVP_aria_192_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_cbc() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CBC.0)
}
/// `const EVP_CIPHER *EVP_aria_192_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_ecb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_ECB.0)
}
/// `const EVP_CIPHER *EVP_aria_192_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_ofb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_OFB.0)
}
/// `const EVP_CIPHER *EVP_aria_192_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_cfb128() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aria_192_cfb1(void)` — `e_aria.c:156`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_cfb1() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aria_192_cfb8(void)` — `e_aria.c:159`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_cfb8() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aria_192_ctr(void)` — `e_aria.c:197`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_ctr() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CTR.0)
}
/// `const EVP_CIPHER *EVP_aria_192_gcm(void)` — `e_aria.c:781`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_gcm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_GCM.0)
}
/// `const EVP_CIPHER *EVP_aria_192_ccm(void)` — `e_aria.c:785`.
#[no_mangle]
pub extern "C" fn EVP_aria_192_ccm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_192_CCM.0)
}
/// `const EVP_CIPHER *EVP_aria_256_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_cbc() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CBC.0)
}
/// `const EVP_CIPHER *EVP_aria_256_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_ecb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_ECB.0)
}
/// `const EVP_CIPHER *EVP_aria_256_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_ofb() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_OFB.0)
}
/// `const EVP_CIPHER *EVP_aria_256_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_cfb128() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CFB128.0)
}
/// `const EVP_CIPHER *EVP_aria_256_cfb1(void)` — `e_aria.c:157`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_cfb1() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CFB1.0)
}
/// `const EVP_CIPHER *EVP_aria_256_cfb8(void)` — `e_aria.c:160`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_cfb8() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CFB8.0)
}
/// `const EVP_CIPHER *EVP_aria_256_ctr(void)` — `e_aria.c:198`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_ctr() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CTR.0)
}
/// `const EVP_CIPHER *EVP_aria_256_gcm(void)` — `e_aria.c:782`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_gcm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_GCM.0)
}
/// `const EVP_CIPHER *EVP_aria_256_ccm(void)` — `e_aria.c:786`.
#[no_mangle]
pub extern "C" fn EVP_aria_256_ccm() -> *const EvpCipher {
    ptr::addr_of!(ARIA_256_CCM.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accessors answer distinct read-only globals with the authority's sizes.
    #[test]
    fn the_accessors_are_stable_globals_with_the_authority_sizes() {
        fn fields(c: *const EvpCipher) -> (c_int, c_int, c_int, c_int, c_int) {
            // SAFETY: every accessor answers a live static, and the fields are read-only.
            unsafe {
                (
                    (*c).nid,
                    (*c).block_size,
                    (*c).key_len,
                    (*c).iv_len,
                    (*c).origin,
                )
            }
        }
        assert_eq!(
            fields(EVP_aria_128_cbc()),
            (NID_aria_128_cbc, 16, 16, 16, 1)
        );
        assert_eq!(fields(EVP_aria_128_ecb()), (NID_aria_128_ecb, 16, 16, 0, 1));
        assert_eq!(
            fields(EVP_aria_128_ofb()),
            (NID_aria_128_ofb128, 1, 16, 16, 1)
        );
        assert_eq!(
            fields(EVP_aria_128_cfb1()),
            (NID_aria_128_cfb1, 1, 16, 16, 1)
        );
        assert_eq!(fields(EVP_aria_128_ctr()), (NID_aria_128_ctr, 1, 16, 16, 1));
        assert_eq!(fields(EVP_aria_128_gcm()), (NID_aria_128_gcm, 1, 16, 12, 1));
        assert_eq!(fields(EVP_aria_128_ccm()), (NID_aria_128_ccm, 1, 16, 12, 1));
        assert_eq!(
            fields(EVP_aria_192_cbc()),
            (NID_aria_192_cbc, 16, 24, 16, 1)
        );
        assert_eq!(
            fields(EVP_aria_256_cbc()),
            (NID_aria_256_cbc, 16, 32, 16, 1)
        );
        assert_eq!(fields(EVP_aria_256_gcm()), (NID_aria_256_gcm, 1, 32, 12, 1));
        assert_eq!(fields(EVP_aria_256_ccm()), (NID_aria_256_ccm, 1, 32, 12, 1));
        assert_ne!(EVP_aria_128_cbc(), EVP_aria_192_cbc());
        assert_ne!(EVP_aria_128_cbc(), EVP_aria_128_ecb());
    }
}
