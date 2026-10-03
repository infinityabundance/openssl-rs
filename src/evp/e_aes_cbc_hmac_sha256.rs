//! Phase 13.6a — `crypto/evp/e_aes_cbc_hmac_sha256.c`: the two deprecated
//! `EVP_aes_*_cbc_hmac_sha256` statics.
//!
//! The sibling of `src/evp/e_aes_cbc_hmac_sha1.rs`, and the same shape: the accessors answer the
//! AES-NI stitched construction only when `OPENSSL_ia32cap_P[1] & AESNI_CAPABLE` is set, and NULL
//! otherwise (`e_aes_cbc_hmac_sha256.c:912-927`). The construction itself is the provider's
//! (`src/provider/cipher.rs`), reused rather than transcribed twice; the callbacks are carriers
//! for the engine path, exactly as `src/evp/e_aes.rs`'s are.
//!
//! **The one difference from the SHA-1 unit is a raise that is not there.** The authority's
//! `aesni_cbc_hmac_sha256_init_key` and `_cipher` do not call `ERR_raise` at all
//! (`grep ERR_raise e_aes_cbc_hmac_sha256.c` is empty), so the two failure arms this unit shares
//! with its sibling answer 0 without touching the error queue.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::digest::sha2::SHA256_Update;
use crate::evp::cipher::EvpCipher;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::provider::cipher::{
    aesni_cbc_hmac_sha256_cipher, aesni_cbc_hmac_sha256_init_key,
    aesni_cbc_hmac_sha256_set_mac_key, aesni_cbc_hmac_sha256_tls1_multiblock_aad,
    aesni_cbc_hmac_sha256_tls1_multiblock_encrypt, ia32cap_aesni, EvpCtrlTls11MultiblockParam,
    ProvAesHmacSha256Ctx, CTX_ENC,
};
use crate::runtime::obj::{NID_aes_128_cbc_hmac_sha256, NID_aes_256_cbc_hmac_sha256};

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`.
const EVP_ORIG_GLOBAL: c_int = 1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:357`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x200000;
/// `EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK` — `include/openssl/evp.h:358`.
const EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK: c_ulong = 0x400000;

/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:408`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_AEAD_SET_MAC_KEY` — `include/openssl/evp.h:410`.
const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE` — `include/openssl/evp.h:417`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE: c_int = 0x1c;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_AAD` — `include/openssl/evp.h:414`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_AAD: c_int = 0x19;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT` — `include/openssl/evp.h:415`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT: c_int = 0x1a;

/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;
/// `TLS1_1_VERSION`.
const TLS1_1_VERSION: c_uint = 0x0302;
/// `SHA256_DIGEST_LENGTH`.
const SHA256_DIGEST_LENGTH: usize = 32;
/// `AES_BLOCK_SIZE`.
const AES_BLOCK_SIZE: usize = 16;

/// The provider context this unit's callbacks use as `cipher_data`.
type LegacyCtx = ProvAesHmacSha256Ctx;

/// `EVP_AES_HMAC_SHA256`'s `cipher_data`, as the provider context.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated the block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut LegacyCtx {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<LegacyCtx>()
}

/// Copy the EVP context's direction and IV into the provider context the callbacks use.
///
/// # Safety
/// `ctx` and `key` are live and agree on the layout.
unsafe fn sync_in(ctx: *mut EvpCipherCtx, key: *mut LegacyCtx) {
    // SAFETY: both are live per the caller's contract.
    unsafe {
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            (*key).base_ctx.base.bits |= CTX_ENC;
        } else {
            (*key).base_ctx.base.bits &= !CTX_ENC;
        }
        ptr::copy_nonoverlapping((*ctx).iv.as_ptr(), (*key).base_ctx.base.iv.as_mut_ptr(), 16);
    }
}

/// `aesni_cbc_hmac_sha256_init_key` — `e_aes_cbc_hmac_sha256.c:63-86`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn cbc_hmac_sha256_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let data = unsafe { data(ctx) };
    // SAFETY: `ctx` is live.
    let keybits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
    if keybits <= 0 {
        return 0;
    }
    // SAFETY: `ctx`/`data` are live and agree on the layout.
    unsafe {
        sync_in(ctx, data);
        aesni_cbc_hmac_sha256_init_key(
            ptr::addr_of_mut!((*data).base_ctx.base),
            key,
            (keybits / 8) as usize,
        )
    }
}

/// `aesni_cbc_hmac_sha256_cipher` — `e_aes_cbc_hmac_sha256.c:419-737`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cbc_hmac_sha256_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let data = unsafe { data(ctx) };
    // SAFETY: `ctx`/`data` are live and agree on the layout.
    let ret = unsafe {
        sync_in(ctx, data);
        aesni_cbc_hmac_sha256_cipher(ptr::addr_of_mut!((*data).base_ctx.base), out, in_, len)
    };
    // SAFETY: the CBC IV may have advanced; it lives in the EVP context.
    unsafe {
        ptr::copy_nonoverlapping(
            (*data).base_ctx.base.iv.as_ptr(),
            (*ctx).iv.as_mut_ptr(),
            16,
        );
    }
    ret
}

/// `aesni_cbc_hmac_sha256_ctrl` — `e_aes_cbc_hmac_sha256.c:738-865`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn cbc_hmac_sha256_ctrl(
    ctx: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let data = unsafe { data(ctx) };
    // SAFETY: `ctx`/`data` are live and agree on the layout.
    unsafe { sync_in(ctx, data) };
    match type_ {
        EVP_CTRL_AEAD_SET_MAC_KEY => {
            // SAFETY: `ptr_` is readable for `arg` bytes per the command's contract.
            unsafe {
                aesni_cbc_hmac_sha256_set_mac_key(
                    data.cast(),
                    ptr_.cast::<c_uchar>(),
                    arg as usize,
                );
            }
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            let p = ptr_.cast::<c_uchar>();
            if arg != EVP_AEAD_TLS1_AAD_LEN {
                return -1;
            }
            let a = arg as usize;
            // SAFETY: `p` is readable for `arg` bytes and `data` is the context's own block.
            unsafe {
                let mut len = ((*p.add(a - 2)) as c_uint) << 8 | (*p.add(a - 1)) as c_uint;
                if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
                    (*data).base_ctx.payload_length = len as usize;
                    let ver = ((*p.add(a - 4)) as c_uint) << 8 | (*p.add(a - 3)) as c_uint;
                    ptr::copy_nonoverlapping(
                        ver.to_ne_bytes().as_ptr(),
                        (*data).base_ctx.aux.as_mut_ptr(),
                        4,
                    );
                    if ver >= TLS1_1_VERSION {
                        if (len as usize) < AES_BLOCK_SIZE {
                            return 0;
                        }
                        len -= AES_BLOCK_SIZE as c_uint;
                        *p.add(a - 2) = (len >> 8) as c_uchar;
                        *p.add(a - 1) = len as c_uchar;
                    }
                    ptr::copy_nonoverlapping(
                        ptr::addr_of!((*data).head),
                        ptr::addr_of_mut!((*data).md),
                        1,
                    );
                    let md = ptr::addr_of_mut!((*data).md);
                    SHA256_Update(md, p.cast(), a);
                    (((len as usize + SHA256_DIGEST_LENGTH + AES_BLOCK_SIZE)
                        & !(AES_BLOCK_SIZE - 1))
                        - len as usize) as c_int
                } else {
                    ptr::copy_nonoverlapping(p, (*data).base_ctx.aux.as_mut_ptr(), a);
                    (*data).base_ctx.payload_length = a;
                    SHA256_DIGEST_LENGTH as c_int
                }
            }
        }
        EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE => 5 + 16 + ((arg + 20 + 16) & !15),
        EVP_CTRL_TLS1_1_MULTIBLOCK_AAD => {
            if arg < core::mem::size_of::<EvpCtrlTls11MultiblockParam>() as c_int {
                return -1;
            }
            // SAFETY: `ptr_` is a live parameter block per the command's contract.
            let param = ptr_.cast::<EvpCtrlTls11MultiblockParam>();
            // SAFETY: `data` and `param` are live.
            let ret =
                unsafe { aesni_cbc_hmac_sha256_tls1_multiblock_aad(data.cast::<c_void>(), param) };
            if ret == 1 {
                // SAFETY: the provider callback set the packed length on success.
                unsafe { (*data).base_ctx.multiblock_aad_packlen as c_int }
            } else {
                ret
            }
        }
        EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT => {
            // SAFETY: `ptr_` is a live parameter block per the command's contract.
            unsafe {
                aesni_cbc_hmac_sha256_tls1_multiblock_encrypt(
                    data.cast::<c_void>(),
                    ptr_.cast::<EvpCtrlTls11MultiblockParam>(),
                )
            }
        }
        _ => -1,
    }
}

/// `EVP_CIPHER_set_asn1_iv`'s `CipherLegacyAsn1Fn` view.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn cbc_hmac_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `EVP_CIPHER_get_asn1_iv`'s `CipherLegacyAsn1Fn` view.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn cbc_hmac_get_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// A `static` `EVP_CIPHER`; the wrapper is `src/evp/e_aes.rs`'s.
struct StaticCipher(EvpCipher);

// SAFETY: the inner value is fully initialised at compile time and never written.
unsafe impl Sync for StaticCipher {}

/// `BLOCK_CIPHER_custom`'s shape for this unit — `e_aes_cbc_hmac_sha256.c:875-909`.
const fn legacy_cipher(nid: c_int, key_len: c_int) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size: AES_BLOCK_SIZE as c_int,
        key_len,
        iv_len: AES_BLOCK_SIZE as c_int,
        flags: EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK,
        origin: EVP_ORIG_GLOBAL,
        init: Some(cbc_hmac_sha256_init_key),
        do_cipher: Some(cbc_hmac_sha256_cipher),
        cleanup: None,
        ctx_size: core::mem::size_of::<LegacyCtx>() as c_int,
        set_asn1_parameters: Some(cbc_hmac_set_asn1_iv),
        get_asn1_parameters: Some(cbc_hmac_get_asn1_iv),
        ctrl: Some(cbc_hmac_sha256_ctrl),
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

/// `aesni_128_cbc_hmac_sha256_cipher` — `e_aes_cbc_hmac_sha256.c:875-891`.
static AES_128_CBC_HMAC_SHA256: StaticCipher = legacy_cipher(NID_aes_128_cbc_hmac_sha256, 16);
/// `aesni_256_cbc_hmac_sha256_cipher` — `e_aes_cbc_hmac_sha256.c:893-909`.
static AES_256_CBC_HMAC_SHA256: StaticCipher = legacy_cipher(NID_aes_256_cbc_hmac_sha256, 32);

/// `const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void)` — `e_aes_cbc_hmac_sha256.c:912-915`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cbc_hmac_sha256() -> *const EvpCipher {
    if ia32cap_aesni() {
        ptr::addr_of!(AES_128_CBC_HMAC_SHA256.0)
    } else {
        ptr::null()
    }
}

/// `const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void)` — `e_aes_cbc_hmac_sha256.c:917-920`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cbc_hmac_sha256() -> *const EvpCipher {
    if ia32cap_aesni() {
        ptr::addr_of!(AES_256_CBC_HMAC_SHA256.0)
    } else {
        ptr::null()
    }
}
