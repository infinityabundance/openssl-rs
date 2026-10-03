//! Phase 13.6c — `crypto/evp/e_cast.c`: the deprecated `EVP_CIPHER` statics the CAST5 modes
//! return.
//!
//! `EVP_cast5_cbc()` and its three siblings are one line each — `return &cast5_cbc;`
//! (`e_cast.c:35`'s `IMPLEMENT_BLOCK_CIPHER`) — over a `static const EVP_CIPHER` whose legacy half
//! is the `cast_init_key`/`cast5_*_cipher` callbacks. This module transcribes those objects field
//! for field and the four mode callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_cast5_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `CAST5-CBC`. Single CAST5 is the **legacy**
//! provider's row (`legacyprov.c`), and only the default provider is activated by default, so the
//! fetch answers NULL and the call refuses — on the authority and in this crate alike. The
//! callbacks are transcribed for faithfulness — an engine is the only reachable caller — exactly as
//! `src/evp/e_aes.rs` transcribes the AES ones.
//!
//! ## What this module does not define
//!
//! The `CAST_*` primitives are Phase 8's (`src/cast.rs`). Only the four accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_cast.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::cast::{
    CAST_cbc_encrypt, CAST_cfb64_encrypt, CAST_ecb_encrypt, CAST_ofb64_encrypt, CAST_set_key,
    CastKey,
};
use crate::evp::cipher::{CipherLegacyAsn1Fn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num,
    EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::runtime::obj::{NID_cast5_cbc, NID_cast5_cfb64, NID_cast5_ecb, NID_cast5_ofb64};

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_ulong = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_VARIABLE_LENGTH` — `include/openssl/evp.h:325`.
const EVP_CIPH_VARIABLE_LENGTH: c_ulong = 0x8;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `CAST_KEY_LENGTH` — `include/openssl/cast.h`.
const CAST_KEY_LENGTH: c_int = 16;

/// `EVP_C_DATA(EVP_CAST_KEY, ctx)` — `e_cast.c:33`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpCastKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpCastKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_cast.c:29-31`
// ---------------------------------------------------------------------------------------------

/// `EVP_CAST_KEY` — `e_cast.c:29-31`. One field: the schedule.
pub struct EvpCastKey {
    /// `CAST_KEY ks`.
    pub ks: CastKey,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_cast.c:35-49`
// ---------------------------------------------------------------------------------------------

/// `cast_init_key` — `e_cast.c:40-49`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn cast_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if keylen <= 0 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block and `key` is readable for `keylen` bytes.
    unsafe { CAST_set_key(ptr::addr_of_mut!((*dat).ks), keylen, key) };
    1
}

/// `cast5_ecb_cipher` — `e_cast.c:35`'s `BLOCK_CIPHER_func_ecb`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cast5_ecb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
    if inl < bl {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let dat = unsafe { data(ctx) };
    let last = inl - bl;
    let mut i = 0usize;
    while i <= last {
        // SAFETY: `dat` is live and the loop stays within `inl` bytes of both buffers.
        unsafe {
            CAST_ecb_encrypt(
                in_.add(i),
                out.add(i),
                ptr::addr_of!((*dat).ks),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        i += bl;
    }
    1
}

/// `cast5_cbc_cipher` — `e_cast.c:35`'s `BLOCK_CIPHER_func_cbc`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cast5_cbc_cipher(
    ctx: *mut c_void,
    mut out: *mut u8,
    mut in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    while inl >= EVP_MAXCHUNK {
        // SAFETY: `dat`/`ctx` are live; the chunk is within the caller's buffers.
        unsafe {
            CAST_cbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        inl -= EVP_MAXCHUNK;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            in_ = in_.add(EVP_MAXCHUNK);
            out = out.add(EVP_MAXCHUNK);
        }
    }
    if inl != 0 {
        // SAFETY: `dat`/`ctx` are live; the remaining bytes are within the caller's buffers.
        unsafe {
            CAST_cbc_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `cast5_cfb64_cipher` — `e_cast.c:35`'s `BLOCK_CIPHER_func_cfb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cast5_cfb64_cipher(
    ctx: *mut c_void,
    mut out: *mut u8,
    mut in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    let mut chunk = EVP_MAXCHUNK;
    if inl < chunk {
        chunk = inl;
    }
    while inl != 0 && inl >= chunk {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` are live; the chunk is within the caller's buffers.
        unsafe {
            CAST_cfb64_encrypt(
                in_,
                out,
                chunk as c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
        inl -= chunk;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            in_ = in_.add(chunk);
            out = out.add(chunk);
        }
        if inl < chunk {
            chunk = inl;
        }
    }
    1
}

/// `cast5_ofb64_cipher` — `e_cast.c:35`'s `BLOCK_CIPHER_func_ofb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn cast5_ofb64_cipher(
    ctx: *mut c_void,
    mut out: *mut u8,
    mut in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    while inl >= EVP_MAXCHUNK {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` are live; the chunk is within the caller's buffers.
        unsafe {
            CAST_ofb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
        inl -= EVP_MAXCHUNK;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            in_ = in_.add(EVP_MAXCHUNK);
            out = out.add(EVP_MAXCHUNK);
        }
    }
    if inl != 0 {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` are live; the remaining bytes are within the caller's buffers.
        unsafe {
            CAST_ofb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
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

/// The common shape of `BLOCK_CIPHER_defs`' initialiser — `e_cast.c:35-38` — as a `const fn`.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    key_len: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    ctx_size: c_int,
    set_asn1: Option<CipherLegacyAsn1Fn>,
    get_asn1: Option<CipherLegacyAsn1Fn>,
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
        cleanup: None,
        ctx_size,
        set_asn1_parameters: set_asn1,
        get_asn1_parameters: get_asn1,
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

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_set_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn cast_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn cast_get_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

// `IMPLEMENT_BLOCK_CIPHER(cast5, ks, CAST, EVP_CAST_KEY, NID_cast5, 8, CAST_KEY_LENGTH, 8, 64,
//     EVP_CIPH_VARIABLE_LENGTH, cast_init_key, NULL, EVP_CIPHER_set_asn1_iv,
//     EVP_CIPHER_get_asn1_iv, NULL)` — `e_cast.c:35-38`.

static CAST5_CBC: StaticCipher = legacy_cipher(
    NID_cast5_cbc,
    8,
    CAST_KEY_LENGTH,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CBC_MODE,
    Some(cast_init_key),
    Some(cast5_cbc_cipher),
    core::mem::size_of::<EvpCastKey>() as c_int,
    Some(cast_set_asn1_iv),
    Some(cast_get_asn1_iv),
);
static CAST5_CFB64: StaticCipher = legacy_cipher(
    NID_cast5_cfb64,
    1,
    CAST_KEY_LENGTH,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CFB_MODE,
    Some(cast_init_key),
    Some(cast5_cfb64_cipher),
    core::mem::size_of::<EvpCastKey>() as c_int,
    Some(cast_set_asn1_iv),
    Some(cast_get_asn1_iv),
);
static CAST5_OFB: StaticCipher = legacy_cipher(
    NID_cast5_ofb64,
    1,
    CAST_KEY_LENGTH,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_OFB_MODE,
    Some(cast_init_key),
    Some(cast5_ofb64_cipher),
    core::mem::size_of::<EvpCastKey>() as c_int,
    Some(cast_set_asn1_iv),
    Some(cast_get_asn1_iv),
);
static CAST5_ECB: StaticCipher = legacy_cipher(
    NID_cast5_ecb,
    8,
    CAST_KEY_LENGTH,
    0,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_ECB_MODE,
    Some(cast_init_key),
    Some(cast5_ecb_cipher),
    core::mem::size_of::<EvpCastKey>() as c_int,
    Some(cast_set_asn1_iv),
    Some(cast_get_asn1_iv),
);

// ---------------------------------------------------------------------------------------------
// The four accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_cast5_cbc(void)` — `e_cast.c:35`'s `IMPLEMENT_BLOCK_CIPHER`.
#[no_mangle]
pub extern "C" fn EVP_cast5_cbc() -> *const EvpCipher {
    ptr::addr_of!(CAST5_CBC.0)
}
/// `const EVP_CIPHER *EVP_cast5_cfb64(void)`.
#[no_mangle]
pub extern "C" fn EVP_cast5_cfb64() -> *const EvpCipher {
    ptr::addr_of!(CAST5_CFB64.0)
}
/// `const EVP_CIPHER *EVP_cast5_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_cast5_ofb() -> *const EvpCipher {
    ptr::addr_of!(CAST5_OFB.0)
}
/// `const EVP_CIPHER *EVP_cast5_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_cast5_ecb() -> *const EvpCipher {
    ptr::addr_of!(CAST5_ECB.0)
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
        assert_eq!(fields(EVP_cast5_cbc()), (NID_cast5_cbc, 8, 16, 8, 1));
        assert_eq!(fields(EVP_cast5_cfb64()), (NID_cast5_cfb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_cast5_ofb()), (NID_cast5_ofb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_cast5_ecb()), (NID_cast5_ecb, 8, 16, 0, 1));
        assert_ne!(EVP_cast5_cbc(), EVP_cast5_ecb());
    }
}
