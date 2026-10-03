//! Phase 13.6a — `crypto/evp/e_aes_cbc_hmac_sha1.c`: the two deprecated `EVP_aes_*_cbc_hmac_sha1`
//! statics.
//!
//! `EVP_aes_128_cbc_hmac_sha1()` returns the AES-NI stitched construction when the AES-NI feature
//! bit is set and **NULL otherwise** — `e_aes_cbc_hmac_sha1.c:936-944`, whose `#else` arm at
//! `:946-954` answers NULL. The predicate is `OPENSSL_ia32cap_P[1] & AESNI_CAPABLE`, the same
//! runtime bit `src/provider/cipher.rs` reads (`ia32cap_aesni`), so this module answers the same
//! thing the authority does on the same host.
//!
//! ## The construction is the provider's, and that is the crate's own precedent
//!
//! D274/D276 established that this unit has **no portable arm**: the `#else` arm calls
//! `aesni_cbc_sha1_enc` and `sha1_block_data_order`, both perlasm, and the crate supplies the
//! construction itself in `src/provider/cipher.rs` (the thirteen `AES-*-CBC-HMAC-*` rows). The
//! legacy callbacks below are that same construction over the legacy context, so they build a
//! provider context from it and call the provider's already-court-verified functions rather than
//! keep a second transcription of one algorithm in two places. The provider context's layout is
//! **not** the authority's `EVP_AES_HMAC_SHA1`, but nothing reads it through the public surface:
//! it is `cipher_data`, obtained only through `EVP_CIPHER_CTX_get_cipher_data`, and `ctx_size` is
//! not an exported accessor.
//!
//! ## The callbacks are carriers
//!
//! As with `src/evp/e_aes.rs`, a caller who hands one of these statics to `EVP_EncryptInit_ex`
//! runs the provider row, not these callbacks; the callbacks exist for the engine path, exactly as
//! `src/evp/legacy_sha.rs` transcribes the digest ones.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::digest::sha1::SHA1_Update;
use crate::evp::cipher::EvpCipher;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::provider::cipher::{
    aesni_cbc_hmac_sha1_cipher, aesni_cbc_hmac_sha1_init_key, aesni_cbc_hmac_sha1_set_mac_key,
    aesni_cbc_hmac_sha1_tls1_multiblock_aad, aesni_cbc_hmac_sha1_tls1_multiblock_encrypt,
    ia32cap_aesni, EvpCtrlTls11MultiblockParam, ProvAesHmacSha1Ctx, CTX_ENC,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{NID_aes_128_cbc_hmac_sha1, NID_aes_256_cbc_hmac_sha1};

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:357`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x200000;
/// `EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK` — `include/openssl/evp.h:358`.
const EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK: c_ulong = 0x400000;

/// `EVP_CTRL_AEAD_SET_MAC_KEY` — `include/openssl/evp.h:410`.
const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;
/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:408`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE` — `include/openssl/evp.h:417`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE: c_int = 0x1c;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_AAD` — `include/openssl/evp.h:414`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_AAD: c_int = 0x19;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT` — `include/openssl/evp.h:415`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT: c_int = 0x1a;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT` — `include/openssl/evp.h:416`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT: c_int = 0x1b;

/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;
/// `TLS1_1_VERSION` — `include/openssl/tls1.h`.
const TLS1_1_VERSION: c_uint = 0x0302;
/// `SHA_DIGEST_LENGTH`.
const SHA_DIGEST_LENGTH: usize = 20;
/// `AES_BLOCK_SIZE`.
const AES_BLOCK_SIZE: usize = 16;

/// The provider context this unit's callbacks use as `cipher_data`.
type LegacyCtx = ProvAesHmacSha1Ctx;

/// `EVP_AES_HMAC_SHA1`'s `cipher_data`, as the provider context.
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

/// `aesni_cbc_hmac_sha1_init_key` — `e_aes_cbc_hmac_sha1.c:67-91`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn cbc_hmac_sha1_init_key(
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
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_AES_CBC_HMAC_SHA1_76) };
        return 0;
    }
    // SAFETY: `ctx`/`data` are live and agree on the layout.
    unsafe {
        sync_in(ctx, data);
        aesni_cbc_hmac_sha1_init_key(
            ptr::addr_of_mut!((*data).base_ctx.base),
            key,
            (keybits / 8) as usize,
        )
    }
}

/// `aesni_cbc_hmac_sha1_cipher` — `e_aes_cbc_hmac_sha1.c:406-767`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cbc_hmac_sha1_cipher(
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
        aesni_cbc_hmac_sha1_cipher(ptr::addr_of_mut!((*data).base_ctx.base), out, in_, len)
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

/// `aesni_cbc_hmac_sha1_ctrl` — `e_aes_cbc_hmac_sha1.c:769-896`.
///
/// The `SET_MAC_KEY`, `MULTIBLOCK_AAD` and `MULTIBLOCK_ENCRYPT` arms delegate to the provider's
/// already-transcribed construction; `TLS1_AAD` is inlined because its **return value is the pad
/// length**, which the provider's parameter dispatch computes elsewhere.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn cbc_hmac_sha1_ctrl(
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
                aesni_cbc_hmac_sha1_set_mac_key(data.cast(), ptr_.cast::<c_uchar>(), arg as usize);
            }
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            // EVP_CTRL_AEAD_TLS1_AAD.
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
                    SHA1_Update(md, p.cast(), a);
                    (((len as usize + SHA_DIGEST_LENGTH + AES_BLOCK_SIZE) & !(AES_BLOCK_SIZE - 1))
                        - len as usize) as c_int
                } else {
                    ptr::copy_nonoverlapping(p, (*data).base_ctx.aux.as_mut_ptr(), a);
                    (*data).base_ctx.payload_length = a;
                    SHA_DIGEST_LENGTH as c_int
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
                unsafe { aesni_cbc_hmac_sha1_tls1_multiblock_aad(data.cast::<c_void>(), param) };
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
                aesni_cbc_hmac_sha1_tls1_multiblock_encrypt(
                    data.cast::<c_void>(),
                    ptr_.cast::<EvpCtrlTls11MultiblockParam>(),
                )
            }
        }
        EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT => -1,
        _ => -1,
    }
}

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_set_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn cbc_hmac_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
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

/// `BLOCK_CIPHER_custom`'s shape for this unit — `e_aes_cbc_hmac_sha1.c:898-934`.
const fn legacy_cipher(nid: c_int, key_len: c_int) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size: AES_BLOCK_SIZE as c_int,
        key_len,
        iv_len: AES_BLOCK_SIZE as c_int,
        flags: EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK,
        origin: EVP_ORIG_GLOBAL,
        init: Some(cbc_hmac_sha1_init_key),
        do_cipher: Some(cbc_hmac_sha1_cipher),
        cleanup: None,
        ctx_size: core::mem::size_of::<LegacyCtx>() as c_int,
        set_asn1_parameters: Some(cbc_hmac_set_asn1_iv),
        get_asn1_parameters: Some(cbc_hmac_get_asn1_iv),
        ctrl: Some(cbc_hmac_sha1_ctrl),
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

/// `aesni_128_cbc_hmac_sha1_cipher` — `e_aes_cbc_hmac_sha1.c:898-915`.
static AES_128_CBC_HMAC_SHA1: StaticCipher = legacy_cipher(NID_aes_128_cbc_hmac_sha1, 16);
/// `aesni_256_cbc_hmac_sha1_cipher` — `e_aes_cbc_hmac_sha1.c:917-934`.
static AES_256_CBC_HMAC_SHA1: StaticCipher = legacy_cipher(NID_aes_256_cbc_hmac_sha1, 32);

/// `const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void)` — `e_aes_cbc_hmac_sha1.c:936-939`.
///
/// The AES-NI feature test is the authority's own: **NULL when the bit is clear**, which is the
/// `#else` arm at `:946-949`.
#[no_mangle]
pub extern "C" fn EVP_aes_128_cbc_hmac_sha1() -> *const EvpCipher {
    if ia32cap_aesni() {
        ptr::addr_of!(AES_128_CBC_HMAC_SHA1.0)
    } else {
        ptr::null()
    }
}

/// `const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void)` — `e_aes_cbc_hmac_sha1.c:941-944`.
#[no_mangle]
pub extern "C" fn EVP_aes_256_cbc_hmac_sha1() -> *const EvpCipher {
    if ia32cap_aesni() {
        ptr::addr_of!(AES_256_CBC_HMAC_SHA1.0)
    } else {
        ptr::null()
    }
}
