//! Phase 13.6c — `crypto/evp/e_bf.c`: the deprecated `EVP_CIPHER` statics the Blowfish modes
//! return.
//!
//! `EVP_bf_cbc()` and its three siblings are one line each — `return &bf_cbc;`
//! (`e_bf.c:34`'s `IMPLEMENT_BLOCK_CIPHER`) — over a `static const EVP_CIPHER` whose legacy half is
//! the `bf_init_key`/`bf_*_cipher` callbacks. This module transcribes those objects field for
//! field and the four mode callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_bf_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `BF-CBC`. Single Blowfish is the **legacy**
//! provider's row (`legacyprov.c`), and only the default provider is activated by default, so the
//! fetch answers NULL and the call refuses — on the authority and in this crate alike. The
//! callbacks are transcribed for faithfulness — an engine is the only reachable caller — exactly as
//! `src/evp/e_aes.rs` transcribes the AES ones.
//!
//! ## What this module does not define
//!
//! The `BF_*` primitives are Phase 8's (`src/blowfish.rs`). Only the four accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_bf.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::blowfish::{
    BF_cbc_encrypt, BF_cfb64_encrypt, BF_ecb_encrypt, BF_ofb64_encrypt, BF_set_key, BfKey,
};
use crate::evp::cipher::{CipherLegacyAsn1Fn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num,
    EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::runtime::obj::{NID_bf_cbc, NID_bf_cfb64, NID_bf_ecb, NID_bf_ofb64};

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

/// `EVP_C_DATA(EVP_BF_KEY, ctx)` — `e_bf.c:32`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpBfKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpBfKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_bf.c:28-30`
// ---------------------------------------------------------------------------------------------

/// `EVP_BF_KEY` — `e_bf.c:28-30`. One field: the schedule.
pub struct EvpBfKey {
    /// `BF_KEY ks`.
    pub ks: BfKey,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_bf.c:34-47`
// ---------------------------------------------------------------------------------------------

/// `bf_init_key` — `e_bf.c:38-47`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn bf_init_key(
    ctx: *mut core::ffi::c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if len < 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and `key` is readable for `len` bytes per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block and `key` is readable for `len` bytes.
    unsafe { BF_set_key(ptr::addr_of_mut!((*dat).ks), len, key) };
    1
}

/// `bf_ecb_cipher` — `e_bf.c:34`'s `BLOCK_CIPHER_func_ecb`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn bf_ecb_cipher(
    ctx: *mut core::ffi::c_void,
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
            BF_ecb_encrypt(
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

/// `bf_cbc_cipher` — `e_bf.c:34`'s `BLOCK_CIPHER_func_cbc`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn bf_cbc_cipher(
    ctx: *mut core::ffi::c_void,
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
            BF_cbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as core::ffi::c_long,
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
            BF_cbc_encrypt(
                in_,
                out,
                inl as core::ffi::c_long,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `bf_cfb64_cipher` — `e_bf.c:34`'s `BLOCK_CIPHER_func_cfb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn bf_cfb64_cipher(
    ctx: *mut core::ffi::c_void,
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
            BF_cfb64_encrypt(
                in_,
                out,
                chunk as core::ffi::c_long,
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

/// `bf_ofb_cipher` — `e_bf.c:34`'s `BLOCK_CIPHER_func_ofb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn bf_ofb_cipher(
    ctx: *mut core::ffi::c_void,
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
            BF_ofb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as core::ffi::c_long,
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
            BF_ofb64_encrypt(
                in_,
                out,
                inl as core::ffi::c_long,
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

/// The common shape of `BLOCK_CIPHER_defs`' initialiser — `e_bf.c:34-36` — as a `const fn`.
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
unsafe extern "C" fn bf_set_asn1_iv(
    ctx: *mut core::ffi::c_void,
    type_: *mut core::ffi::c_void,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn bf_get_asn1_iv(
    ctx: *mut core::ffi::c_void,
    type_: *mut core::ffi::c_void,
) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

// `IMPLEMENT_BLOCK_CIPHER(bf, ks, BF, EVP_BF_KEY, NID_bf, 8, 16, 8, 64,
//     EVP_CIPH_VARIABLE_LENGTH, bf_init_key, NULL, EVP_CIPHER_set_asn1_iv,
//     EVP_CIPHER_get_asn1_iv, NULL)` — `e_bf.c:34-36`.

static BF_CBC: StaticCipher = legacy_cipher(
    NID_bf_cbc,
    8,
    16,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CBC_MODE,
    Some(bf_init_key),
    Some(bf_cbc_cipher),
    core::mem::size_of::<EvpBfKey>() as c_int,
    Some(bf_set_asn1_iv),
    Some(bf_get_asn1_iv),
);
static BF_CFB64: StaticCipher = legacy_cipher(
    NID_bf_cfb64,
    1,
    16,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CFB_MODE,
    Some(bf_init_key),
    Some(bf_cfb64_cipher),
    core::mem::size_of::<EvpBfKey>() as c_int,
    Some(bf_set_asn1_iv),
    Some(bf_get_asn1_iv),
);
static BF_OFB: StaticCipher = legacy_cipher(
    NID_bf_ofb64,
    1,
    16,
    8,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_OFB_MODE,
    Some(bf_init_key),
    Some(bf_ofb_cipher),
    core::mem::size_of::<EvpBfKey>() as c_int,
    Some(bf_set_asn1_iv),
    Some(bf_get_asn1_iv),
);
static BF_ECB: StaticCipher = legacy_cipher(
    NID_bf_ecb,
    8,
    16,
    0,
    EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_ECB_MODE,
    Some(bf_init_key),
    Some(bf_ecb_cipher),
    core::mem::size_of::<EvpBfKey>() as c_int,
    Some(bf_set_asn1_iv),
    Some(bf_get_asn1_iv),
);

// ---------------------------------------------------------------------------------------------
// The four accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_bf_cbc(void)` — `e_bf.c:34`'s `IMPLEMENT_BLOCK_CIPHER`.
#[no_mangle]
pub extern "C" fn EVP_bf_cbc() -> *const EvpCipher {
    ptr::addr_of!(BF_CBC.0)
}
/// `const EVP_CIPHER *EVP_bf_cfb64(void)`.
#[no_mangle]
pub extern "C" fn EVP_bf_cfb64() -> *const EvpCipher {
    ptr::addr_of!(BF_CFB64.0)
}
/// `const EVP_CIPHER *EVP_bf_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_bf_ofb() -> *const EvpCipher {
    ptr::addr_of!(BF_OFB.0)
}
/// `const EVP_CIPHER *EVP_bf_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_bf_ecb() -> *const EvpCipher {
    ptr::addr_of!(BF_ECB.0)
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
        assert_eq!(fields(EVP_bf_cbc()), (NID_bf_cbc, 8, 16, 8, 1));
        assert_eq!(fields(EVP_bf_cfb64()), (NID_bf_cfb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_bf_ofb()), (NID_bf_ofb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_bf_ecb()), (NID_bf_ecb, 8, 16, 0, 1));
        assert_ne!(EVP_bf_cbc(), EVP_bf_ecb());
    }
}
