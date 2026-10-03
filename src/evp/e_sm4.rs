//! Phase 13.6c — `crypto/evp/e_sm4.c`: the deprecated `EVP_CIPHER` statics the SM4 modes return.
//!
//! `EVP_sm4_cbc()` and its four siblings are one line each — `return &sm4_cbc;`
//! (`e_sm4.c:47-50`, via `DEFINE_BLOCK_CIPHERS`) — over a `static const EVP_CIPHER` whose legacy
//! half is the `sm4_init_key`/`sm4_*_cipher` callbacks. This module transcribes those objects field
//! for field and the five mode callbacks with them.
//!
//! ## The `HWSM4`/`VPSM4` arms are not modelled
//!
//! The authority's `sm4_init_key` selects a hardware block function and fills the `stream` union
//! only when `HWSM4_CAPABLE`/`VPSM4_CAPABLE` (`e_sm4.c:68-138`). This crate's arm is the portable
//! one — the SM4 extension and the vector-permute variants are declines recorded with `src/sm4.rs`
//! — so the branch taken is the inner `{ dat->block = ossl_sm4_*; ossl_sm4_set_key(...); }`, and
//! every member of `stream` stays NULL. The callbacks themselves read `stream.*` first and fall to
//! the generic modes when they are NULL, so the observable is the portable modes run.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_sm4_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` runs the default provider's SM4-CBC row (`defltprov.c:314-323`), not these
//! callbacks. The callbacks are transcribed for faithfulness — an engine is the only reachable
//! caller.
//!
//! ## What this module does not define
//!
//! The `ossl_sm4_*` primitives are Phase 8's (`src/sm4.rs`). Only the five accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_sm4.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::evp::cipher::{CipherLegacyDoFn, CipherLegacyInitFn, EVP_CIPHER_get_mode, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_buf_noconst, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data,
    EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num, EvpCipherCtx,
};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_encrypt,
    CRYPTO_ctr128_encrypt, CRYPTO_ctr128_encrypt_ctr32, CRYPTO_ofb128_encrypt, Ctr128F,
};
use crate::runtime::obj::{NID_sm4_cbc, NID_sm4_cfb128, NID_sm4_ctr, NID_sm4_ecb, NID_sm4_ofb128};
use crate::sm4::{ossl_sm4_decrypt, ossl_sm4_encrypt, ossl_sm4_set_key, Sm4Key};

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_int = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_int = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_CTR_MODE` — `include/openssl/evp.h:315`.
const EVP_CIPH_CTR_MODE: c_ulong = 0x5;
/// `EVP_CIPH_FLAG_DEFAULT_ASN1` — `include/openssl/evp.h:343`. **Zero** in 3.6.4.
const EVP_CIPH_FLAG_DEFAULT_ASN1: c_ulong = 0;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `ecb128_f` — `include/openssl/modes.h:32-34`. Not in `crate::modes` because SM4 is its only
/// legacy user here; the portable init never sets it, so the field is always `None`.
type Ecb128F = unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, c_int);

/// `EVP_C_DATA(EVP_SM4_KEY, ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpSm4Key {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpSm4Key>()
}

/// `block128_f` view of [`ossl_sm4_encrypt`] — `e_sm4.c:136`'s `(block128_f)ossl_sm4_encrypt`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn sm4_encrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is an `SM4_KEY`.
    unsafe { ossl_sm4_encrypt(input, out, key.cast::<Sm4Key>()) }
}

/// `block128_f` view of [`ossl_sm4_decrypt`] — `e_sm4.c:95`'s `(block128_f)ossl_sm4_decrypt`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn sm4_decrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is an `SM4_KEY`.
    unsafe { ossl_sm4_decrypt(input, out, key.cast::<Sm4Key>()) }
}

// ---------------------------------------------------------------------------------------------
// The context — `e_sm4.c:23-34`
// ---------------------------------------------------------------------------------------------

/// `EVP_SM4_KEY` — `e_sm4.c:23-34`. The `stream` union is split into its three arms, because this
/// crate's portable `sm4_init_key` fills none of them.
pub(crate) struct EvpSm4Key {
    /// `SM4_KEY ks`.
    pub(crate) ks: Sm4Key,
    /// `block128_f block`.
    pub(crate) block: Block128F,
    /// `ecb128_f stream.ecb`.
    pub(crate) stream_ecb: Option<Ecb128F>,
    /// `cbc128_f stream.cbc`.
    pub(crate) stream_cbc: Option<crate::modes::Cbc128F>,
    /// `ctr128_f stream.ctr`.
    pub(crate) stream_ctr: Option<Ctr128F>,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_sm4.c:59-227`
// ---------------------------------------------------------------------------------------------

/// `sm4_init_key` — `e_sm4.c:59-140`, portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn sm4_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let mode = unsafe { EVP_CIPHER_get_mode((*ctx).cipher) };
    // SAFETY: `ctx` is live.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block.
    unsafe {
        (*dat).stream_ecb = None;
        (*dat).stream_cbc = None;
        (*dat).stream_ctr = None;
    }
    if (mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && enc == 0 {
        // SAFETY: `dat` is live and `key` is readable for sixteen bytes.
        unsafe {
            (*dat).block = sm4_decrypt_block;
            ossl_sm4_set_key(key, ptr::addr_of_mut!((*dat).ks));
        }
    } else {
        // SAFETY: `dat` is live and `key` is readable for sixteen bytes.
        unsafe {
            (*dat).block = sm4_encrypt_block;
            ossl_sm4_set_key(key, ptr::addr_of_mut!((*dat).ks));
        }
    }
    1
}

/// `sm4_cbc_cipher` — `e_sm4.c:142-157`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn sm4_cbc_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat`/`ctx` are live; the mode writes exactly the regions named.
    unsafe {
        if let Some(f) = (*dat).stream_cbc {
            f(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            );
        } else if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
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

/// `sm4_cfb_cipher` — `e_sm4.c:159-170`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn sm4_cfb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat`/`ctx` are live; `num` is a local.
    unsafe {
        CRYPTO_cfb128_encrypt(
            in_,
            out,
            len,
            ptr::addr_of!((*dat).ks).cast(),
            (*ctx).iv.as_mut_ptr(),
            &mut num,
            EVP_CIPHER_CTX_is_encrypting(ctx),
            (*dat).block,
        );
        EVP_CIPHER_CTX_set_num(ctx, num);
    }
    1
}

/// `sm4_ecb_cipher` — `e_sm4.c:172-190`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn sm4_ecb_cipher(
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
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is live.
    if let Some(f) = unsafe { (*dat).stream_ecb } {
        // SAFETY: `dat`/`ctx` are live and the loop stays within `len` bytes of both buffers.
        unsafe {
            f(
                in_,
                out,
                len,
                ptr::addr_of!((*dat).ks).cast(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    } else {
        let mut i = 0usize;
        let last = len - bl;
        while i <= last {
            // SAFETY: `dat` is live and the loop stays within `len` bytes of both buffers.
            unsafe { ((*dat).block)(in_.add(i), out.add(i), ptr::addr_of!((*dat).ks).cast()) };
            i += bl;
        }
    }
    1
}

/// `sm4_ofb_cipher` — `e_sm4.c:192-202`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn sm4_ofb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat`/`ctx` are live; `num` is a local.
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

/// `sm4_ctr_cipher` — `e_sm4.c:204-227`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn sm4_ctr_cipher(
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
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat`/`ctx` are live; `ecount_buf` is the context's own `buf`.
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

/// The common shape of `BLOCK_CIPHER_generic`'s initialiser — `e_sm4.c:36-50` — as a `const fn`.
/// The ASN.1 pair and `ctrl` are `NULL`, and `cleanup` is `NULL`.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    ctx_size: c_int,
) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size,
        key_len: 128 / 8,
        iv_len,
        flags,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup: None,
        ctx_size,
        set_asn1_parameters: None,
        get_asn1_parameters: None,
        ctrl: None,
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

// `DEFINE_BLOCK_CIPHERS(NID_sm4, 0)` — `e_sm4.c:52-57`, `:229`.

static SM4_CBC: StaticCipher = legacy_cipher(
    NID_sm4_cbc,
    16,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE as c_ulong,
    Some(sm4_init_key),
    Some(sm4_cbc_cipher),
    core::mem::size_of::<EvpSm4Key>() as c_int,
);
static SM4_ECB: StaticCipher = legacy_cipher(
    NID_sm4_ecb,
    16,
    0,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_ECB_MODE as c_ulong,
    Some(sm4_init_key),
    Some(sm4_ecb_cipher),
    core::mem::size_of::<EvpSm4Key>() as c_int,
);
static SM4_OFB: StaticCipher = legacy_cipher(
    NID_sm4_ofb128,
    1,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_OFB_MODE,
    Some(sm4_init_key),
    Some(sm4_ofb_cipher),
    core::mem::size_of::<EvpSm4Key>() as c_int,
);
static SM4_CFB128: StaticCipher = legacy_cipher(
    NID_sm4_cfb128,
    1,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CFB_MODE,
    Some(sm4_init_key),
    Some(sm4_cfb_cipher),
    core::mem::size_of::<EvpSm4Key>() as c_int,
);
static SM4_CTR: StaticCipher = legacy_cipher(
    NID_sm4_ctr,
    1,
    16,
    EVP_CIPH_CTR_MODE,
    Some(sm4_init_key),
    Some(sm4_ctr_cipher),
    core::mem::size_of::<EvpSm4Key>() as c_int,
);

// ---------------------------------------------------------------------------------------------
// The five accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_sm4_cbc(void)` — `e_sm4.c:53`/`:229`'s `DEFINE_BLOCK_CIPHERS`.
#[no_mangle]
pub extern "C" fn EVP_sm4_cbc() -> *const EvpCipher {
    ptr::addr_of!(SM4_CBC.0)
}
/// `const EVP_CIPHER *EVP_sm4_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_sm4_ecb() -> *const EvpCipher {
    ptr::addr_of!(SM4_ECB.0)
}
/// `const EVP_CIPHER *EVP_sm4_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_sm4_ofb() -> *const EvpCipher {
    ptr::addr_of!(SM4_OFB.0)
}
/// `const EVP_CIPHER *EVP_sm4_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_sm4_cfb128() -> *const EvpCipher {
    ptr::addr_of!(SM4_CFB128.0)
}
/// `const EVP_CIPHER *EVP_sm4_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_sm4_ctr() -> *const EvpCipher {
    ptr::addr_of!(SM4_CTR.0)
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
        assert_eq!(fields(EVP_sm4_cbc()), (NID_sm4_cbc, 16, 16, 16, 1));
        assert_eq!(fields(EVP_sm4_ecb()), (NID_sm4_ecb, 16, 16, 0, 1));
        assert_eq!(fields(EVP_sm4_ofb()), (NID_sm4_ofb128, 1, 16, 16, 1));
        assert_eq!(fields(EVP_sm4_cfb128()), (NID_sm4_cfb128, 1, 16, 16, 1));
        assert_eq!(fields(EVP_sm4_ctr()), (NID_sm4_ctr, 1, 16, 16, 1));
        assert_ne!(EVP_sm4_cbc(), EVP_sm4_ecb());
    }
}
