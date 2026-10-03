//! Phase 13.6c — `crypto/evp/e_xcbc_d.c`: the deprecated `EVP_desx_cbc` static.
//!
//! `EVP_desx_cbc()` is one line — `return &d_xcbc_cipher;` (`e_xcbc_d.c:55-58`) — over a
//! `static const EVP_CIPHER` whose legacy half is the `desx_cbc_init_key`/`desx_cbc_cipher`
//! callbacks. This module transcribes that object field for field and the two callbacks with it.
//!
//! ## The key is a schedule and two whitening blocks
//!
//! `DESX_CBC_KEY` is a `DES_key_schedule` followed by the two eight-byte whitening values
//! (`e_xcbc_d.c:32-36`). `desx_cbc_init_key` expands the first eight bytes of the caller's key into
//! the schedule with `DES_set_key_unchecked` and copies bytes 8..16 / 16..24 into `inw`/`outw`; the
//! 24-byte `key_len` is what makes the caller hand it that much.
//!
//! ## This object is a carrier, and the library replaces it before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_desx_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `DESX-CBC`. DESX is the **legacy** provider's
//! row (`legacyprov.c`), and only the default provider is activated by default, so the fetch
//! answers NULL and the call refuses — on the authority and in this crate alike. The callbacks are
//! transcribed for faithfulness — an engine is the only reachable caller.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::des::{DES_set_key_unchecked, DES_xcbc_encrypt, DesKeySchedule};
use crate::evp::cipher::{CipherLegacyAsn1Fn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_get_asn1_iv,
    EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::runtime::obj::NID_desx_cbc;

/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(DESX_CBC_KEY, ctx)` — `e_xcbc_d.c:38`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut DesxCbcKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<DesxCbcKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_xcbc_d.c:32-36`
// ---------------------------------------------------------------------------------------------

/// `DESX_CBC_KEY` — `e_xcbc_d.c:32-36`. The schedule and the two whitening blocks.
pub struct DesxCbcKey {
    /// `DES_key_schedule ks`.
    pub ks: DesKeySchedule,
    /// `DES_cblock inw`.
    pub inw: [u8; 8],
    /// `DES_cblock outw`.
    pub outw: [u8; 8],
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_xcbc_d.c:60-90`
// ---------------------------------------------------------------------------------------------

/// `desx_cbc_init_key` — `e_xcbc_d.c:60-70`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract; `key` is readable for twenty-four bytes.
unsafe extern "C" fn desx_cbc_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `key` is readable for eight bytes and `ks` is writable.
    unsafe {
        DES_set_key_unchecked(
            key.cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks),
        )
    };
    // SAFETY: `key` is readable for twenty-four bytes and the two blocks are writable.
    unsafe {
        ptr::copy_nonoverlapping(key.add(8), (*dat).inw.as_mut_ptr(), 8);
        ptr::copy_nonoverlapping(key.add(16), (*dat).outw.as_mut_ptr(), 8);
    }
    1
}

/// `desx_cbc_cipher` — `e_xcbc_d.c:72-90`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn desx_cbc_cipher(
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
            DES_xcbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                ptr::addr_of_mut!((*dat).inw),
                ptr::addr_of_mut!((*dat).outw),
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
            DES_xcbc_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                ptr::addr_of_mut!((*dat).inw),
                ptr::addr_of_mut!((*dat).outw),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The static object
// ---------------------------------------------------------------------------------------------

/// A `static` `EVP_CIPHER`. The wrapper exists for the reason `src/evp/e_aes.rs`'s own
/// `StaticCipher` does: the inner value is a compile-time constant that nothing writes.
struct StaticCipher(EvpCipher);

// SAFETY: the inner value is fully initialised at compile time and never written; every mutating
// arm of `EVP_CIPHER_up_ref`/`EVP_CIPHER_free` is guarded by `origin`, and `EVP_ORIG_GLOBAL` is
// not `EVP_ORIG_DYNAMIC`.
unsafe impl Sync for StaticCipher {}

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_set_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn desx_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn desx_get_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `d_xcbc_cipher` — `e_xcbc_d.c:40-53`.
///
/// # Safety
/// The fields are the authority's own constants.
static D_XCBC_CIPHER: StaticCipher = {
    let init: Option<CipherLegacyInitFn> = Some(desx_cbc_init_key);
    let do_cipher: Option<CipherLegacyDoFn> = Some(desx_cbc_cipher);
    let set_asn1: Option<CipherLegacyAsn1Fn> = Some(desx_set_asn1_iv);
    let get_asn1: Option<CipherLegacyAsn1Fn> = Some(desx_get_asn1_iv);
    StaticCipher(EvpCipher {
        nid: NID_desx_cbc,
        block_size: 8,
        key_len: 24,
        iv_len: 8,
        flags: EVP_CIPH_CBC_MODE,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup: None,
        ctx_size: core::mem::size_of::<DesxCbcKey>() as c_int,
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
};

// ---------------------------------------------------------------------------------------------
// The one accessor.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_desx_cbc(void)` — `e_xcbc_d.c:55-58`.
#[no_mangle]
pub extern "C" fn EVP_desx_cbc() -> *const EvpCipher {
    ptr::addr_of!(D_XCBC_CIPHER.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accessor answers a read-only global with the authority's sizes.
    #[test]
    fn the_accessor_is_a_stable_global_with_the_authority_sizes() {
        let c = EVP_desx_cbc();
        // SAFETY: the accessor answers a live static, and the fields are read-only.
        unsafe {
            assert_eq!((*c).nid, NID_desx_cbc);
            assert_eq!((*c).block_size, 8);
            assert_eq!((*c).key_len, 24);
            assert_eq!((*c).iv_len, 8);
            assert_eq!((*c).origin, 1);
        }
    }
}
