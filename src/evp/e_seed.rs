//! Phase 13.6c — `crypto/evp/e_seed.c`: the deprecated `EVP_CIPHER` statics the SEED modes return.
//!
//! `EVP_seed_cbc()` and its three siblings are one line each — `return &seed_cbc;`
//! (`e_seed.c:32`'s `IMPLEMENT_BLOCK_CIPHER`) — over a `static const EVP_CIPHER` whose legacy half
//! is the `seed_init_key`/`seed_*_cipher` callbacks. This module transcribes those objects field
//! for field and the four mode callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_seed_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `SEED-CBC`. SEED is the **legacy** provider's
//! row (`legacyprov.c`), and only the default provider is activated by default, so the fetch
//! answers NULL and the call refuses — on the authority and in this crate alike. The callbacks are
//! transcribed for faithfulness — an engine is the only reachable caller — exactly as
//! `src/evp/e_aes.rs` transcribes the AES ones.
//!
//! ## `EVP_CIPH_FLAG_DEFAULT_ASN1` is zero, and the ASN.1 pair is NULL
//!
//! `IMPLEMENT_BLOCK_CIPHER`'s last four arguments here are four zeros (`e_seed.c:34`), so the
//! object carries `NULL` for `set_asn1_parameters`, `get_asn1_parameters` and `ctrl`. The
//! `EVP_CIPH_FLAG_DEFAULT_ASN1` OR is a no-op in 3.6.4 (`include/openssl/evp.h:343`).
//!
//! ## What this module does not define
//!
//! The `SEED_*` primitives are Phase 8's (`src/seed.rs`). Only the four accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_seed.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::evp::cipher::{CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_num,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num, EvpCipherCtx,
};
use crate::runtime::obj::{NID_seed_cbc, NID_seed_cfb128, NID_seed_ecb, NID_seed_ofb128};
use crate::seed::{
    SEED_cbc_encrypt, SEED_cfb128_encrypt, SEED_ecb_encrypt, SEED_ofb128_encrypt, SEED_set_key,
    SeedKeySchedule,
};

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_ulong = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_FLAG_DEFAULT_ASN1` — `include/openssl/evp.h:343`. **Zero** in 3.6.4.
const EVP_CIPH_FLAG_DEFAULT_ASN1: c_ulong = 0;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(EVP_SEED_KEY, ctx)` — `e_seed.c:39`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpSeedKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpSeedKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_seed.c:28-30`
// ---------------------------------------------------------------------------------------------

/// `EVP_SEED_KEY` — `e_seed.c:28-30`. One field: the schedule.
pub struct EvpSeedKey {
    /// `SEED_KEY_SCHEDULE ks`.
    pub ks: SeedKeySchedule,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_seed.c:32-41`
// ---------------------------------------------------------------------------------------------

/// `seed_init_key` — `e_seed.c:36-41`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn seed_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block and `key` is readable for sixteen bytes.
    unsafe { SEED_set_key(key, ptr::addr_of_mut!((*dat).ks)) };
    1
}

/// `seed_ecb_cipher` — `e_seed.c:32`'s `BLOCK_CIPHER_func_ecb`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn seed_ecb_cipher(
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
            SEED_ecb_encrypt(
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

/// `seed_cbc_cipher` — `e_seed.c:32`'s `BLOCK_CIPHER_func_cbc`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn seed_cbc_cipher(
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
            SEED_cbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK,
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
            SEED_cbc_encrypt(
                in_,
                out,
                inl,
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `seed_cfb128_cipher` — `e_seed.c:32`'s `BLOCK_CIPHER_func_cfb` with `cbits == 128`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn seed_cfb128_cipher(
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
            SEED_cfb128_encrypt(
                in_,
                out,
                chunk,
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

/// `seed_ofb128_cipher` — `e_seed.c:32`'s `BLOCK_CIPHER_func_ofb` with `cbits == 128`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn seed_ofb128_cipher(
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
            SEED_ofb128_encrypt(
                in_,
                out,
                EVP_MAXCHUNK,
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
            SEED_ofb128_encrypt(
                in_,
                out,
                inl,
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

/// The common shape of `BLOCK_CIPHER_defs`' initialiser — `e_seed.c:32-34` — as a `const fn`.
/// The ASN.1 pair and `ctrl` are `NULL`, and `cleanup` is `NULL`, per the authority's call.
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
        key_len: 16,
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

// `IMPLEMENT_BLOCK_CIPHER(seed, ks, SEED, EVP_SEED_KEY, NID_seed, 16, 16, 16, 128,
//     EVP_CIPH_FLAG_DEFAULT_ASN1, seed_init_key, 0, 0, 0, 0)` — `e_seed.c:32-34`.

static SEED_CBC: StaticCipher = legacy_cipher(
    NID_seed_cbc,
    16,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE,
    Some(seed_init_key),
    Some(seed_cbc_cipher),
    core::mem::size_of::<EvpSeedKey>() as c_int,
);
static SEED_CFB128: StaticCipher = legacy_cipher(
    NID_seed_cfb128,
    1,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CFB_MODE,
    Some(seed_init_key),
    Some(seed_cfb128_cipher),
    core::mem::size_of::<EvpSeedKey>() as c_int,
);
static SEED_OFB: StaticCipher = legacy_cipher(
    NID_seed_ofb128,
    1,
    16,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_OFB_MODE,
    Some(seed_init_key),
    Some(seed_ofb128_cipher),
    core::mem::size_of::<EvpSeedKey>() as c_int,
);
static SEED_ECB: StaticCipher = legacy_cipher(
    NID_seed_ecb,
    16,
    0,
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_ECB_MODE,
    Some(seed_init_key),
    Some(seed_ecb_cipher),
    core::mem::size_of::<EvpSeedKey>() as c_int,
);

// ---------------------------------------------------------------------------------------------
// The four accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_seed_cbc(void)` — `e_seed.c:32`'s `IMPLEMENT_BLOCK_CIPHER`.
#[no_mangle]
pub extern "C" fn EVP_seed_cbc() -> *const EvpCipher {
    ptr::addr_of!(SEED_CBC.0)
}
/// `const EVP_CIPHER *EVP_seed_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_seed_cfb128() -> *const EvpCipher {
    ptr::addr_of!(SEED_CFB128.0)
}
/// `const EVP_CIPHER *EVP_seed_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_seed_ofb() -> *const EvpCipher {
    ptr::addr_of!(SEED_OFB.0)
}
/// `const EVP_CIPHER *EVP_seed_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_seed_ecb() -> *const EvpCipher {
    ptr::addr_of!(SEED_ECB.0)
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
        assert_eq!(fields(EVP_seed_cbc()), (NID_seed_cbc, 16, 16, 16, 1));
        assert_eq!(fields(EVP_seed_cfb128()), (NID_seed_cfb128, 1, 16, 16, 1));
        assert_eq!(fields(EVP_seed_ofb()), (NID_seed_ofb128, 1, 16, 16, 1));
        assert_eq!(fields(EVP_seed_ecb()), (NID_seed_ecb, 16, 16, 0, 1));
        assert_ne!(EVP_seed_cbc(), EVP_seed_ecb());
    }
}
