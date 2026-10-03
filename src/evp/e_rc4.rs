//! Phase 13.6c — `crypto/evp/e_rc4.c`: the deprecated `EVP_CIPHER` statics the RC4 stream returns.
//!
//! `EVP_rc4()` and `EVP_rc4_40()` are one line each — `return &r4_cipher;` (`e_rc4.c:67-75`) —
//! over a `static const EVP_CIPHER` whose legacy half is the `rc4_init_key`/`rc4_cipher` callbacks.
//! This module transcribes those two objects field for field and the two callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_rc4()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `RC4`. RC4 is the **legacy** provider's row
//! (`legacyprov.c`), and only the default provider is activated by default, so the fetch answers
//! NULL and the call refuses — on the authority and in this crate alike. The callbacks are
//! transcribed for faithfulness — an engine is the only reachable caller.
//!
//! ## What this module does not define
//!
//! The `RC4_*` primitives are Phase 8's (`src/rc4.rs`). Only the two accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_rc4.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::evp::cipher::{CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length, EvpCipherCtx,
};
use crate::rc4::{RC4_set_key, Rc4Key, RC4};
use crate::runtime::obj::{NID_rc4, NID_rc4_40};

/// `EVP_CIPH_VARIABLE_LENGTH` — `include/openssl/evp.h:325`.
const EVP_CIPH_VARIABLE_LENGTH: c_ulong = 0x8;

/// `EVP_RC4_KEY_SIZE` — `include/openssl/rc4.h`.
const EVP_RC4_KEY_SIZE: c_int = 16;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(EVP_RC4_KEY, ctx)` — `e_rc4.c:31`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpRc4Key {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpRc4Key>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_rc4.c:27-29`
// ---------------------------------------------------------------------------------------------

/// `EVP_RC4_KEY` — `e_rc4.c:27-29`. One field: the working key.
pub struct EvpRc4Key {
    /// `RC4_KEY ks`.
    pub ks: Rc4Key,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_rc4.c:77-93`
// ---------------------------------------------------------------------------------------------

/// `rc4_init_key` — `e_rc4.c:77-86`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn rc4_init_key(
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
    unsafe { RC4_set_key(ptr::addr_of_mut!((*dat).ks), keylen, key) };
    1
}

/// `rc4_cipher` — `e_rc4.c:88-93`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc4_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is live; the RC4 call reads and writes exactly `inl` bytes.
    unsafe { RC4(ptr::addr_of_mut!((*dat).ks), inl, in_, out) };
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

/// The common shape of the two hand-written initialisers — `e_rc4.c:37-65` — as a `const fn`.
const fn legacy_cipher(
    nid: c_int,
    key_len: c_int,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    ctx_size: c_int,
) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size: 1,
        key_len,
        iv_len: 0,
        flags: EVP_CIPH_VARIABLE_LENGTH,
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

/// `r4_cipher` — `e_rc4.c:37-50`.
static R4_CIPHER: StaticCipher = legacy_cipher(
    NID_rc4,
    EVP_RC4_KEY_SIZE,
    Some(rc4_init_key),
    Some(rc4_cipher),
    core::mem::size_of::<EvpRc4Key>() as c_int,
);
/// `r4_40_cipher` — `e_rc4.c:52-65`.
static R4_40_CIPHER: StaticCipher = legacy_cipher(
    NID_rc4_40,
    5,
    Some(rc4_init_key),
    Some(rc4_cipher),
    core::mem::size_of::<EvpRc4Key>() as c_int,
);

// ---------------------------------------------------------------------------------------------
// The two accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_rc4(void)` — `e_rc4.c:67-70`.
#[no_mangle]
pub extern "C" fn EVP_rc4() -> *const EvpCipher {
    ptr::addr_of!(R4_CIPHER.0)
}
/// `const EVP_CIPHER *EVP_rc4_40(void)` — `e_rc4.c:72-75`.
#[no_mangle]
pub extern "C" fn EVP_rc4_40() -> *const EvpCipher {
    ptr::addr_of!(R4_40_CIPHER.0)
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
        assert_eq!(fields(EVP_rc4()), (NID_rc4, 1, 16, 0, 1));
        assert_eq!(fields(EVP_rc4_40()), (NID_rc4_40, 1, 5, 0, 1));
        assert_ne!(EVP_rc4(), EVP_rc4_40());
    }
}
