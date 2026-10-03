//! Phase 13.6c — `crypto/evp/e_rc4_hmac_md5.c`: the deprecated `EVP_rc4_hmac_md5` static.
//!
//! `EVP_rc4_hmac_md5()` is one line — `return &r4_hmac_md5_cipher;` (`e_rc4_hmac_md5.c:262-265`) —
//! over a `static EVP_CIPHER` whose legacy half is the `rc4_hmac_md5_init_key`/`_cipher` callbacks
//! and the `rc4_hmac_md5_ctrl` AEAD control. This module transcribes that object field for field
//! and the callbacks with it.
//!
//! ## The `STITCHED_CALL` arm is not modelled
//!
//! The authority compiles the interleaved RC4+MD5 arm only under
//! `RC4_ASM && MD5_ASM && x86_64` (`e_rc4_hmac_md5.c:65-67`), which calls `rc4_md5_enc`, a perlasm
//! helper this crate does not carry. The `#else` arm sets `rc4_off = md5_off = 0` (`:69-72`), and
//! that is the portable transcription here: the primitive calls are the same, only the interleaving
//! differs, so the bytes are identical.
//!
//! ## This object is a carrier, and the library replaces it before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_rc4_hmac_md5()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `RC4-HMAC-MD5`. RC4-HMAC-MD5 is the
//! **legacy** provider's row (`legacyprov.c`), and only the default provider is activated by
//! default, so the fetch answers NULL and the call refuses — on the authority and in this crate
//! alike. The callbacks are transcribed for faithfulness — an engine is the only reachable caller.
//!
//! ## What this module does not define
//!
//! The `RC4` and `MD5_*` primitives are Phase 8's (`src/rc4.rs`, `src/digest/md5.rs`). Only the one
//! accessor `forensics/atlas/export-defining-units.json` assigns to `e_rc4_hmac_md5.c` is exported
//! here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::digest::md5::{MD5_Final, MD5_Init, MD5_Update, Md5Ctx};
use crate::evp::cipher::{CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_is_encrypting,
    EvpCipherCtx,
};
use crate::rc4::{RC4_set_key, Rc4Key, RC4};
use crate::runtime::mem::{CRYPTO_memcmp, OPENSSL_cleanse};
use crate::runtime::obj::NID_rc4_hmac_md5;

/// `EVP_CIPH_STREAM_CIPHER` — `include/openssl/evp.h:310`.
const EVP_CIPH_STREAM_CIPHER: c_ulong = 0x0;
/// `EVP_CIPH_VARIABLE_LENGTH` — `include/openssl/evp.h:325`.
const EVP_CIPH_VARIABLE_LENGTH: c_ulong = 0x8;
/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:357`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x200000;

/// `EVP_CTRL_AEAD_SET_MAC_KEY` — `include/openssl/evp.h:410`.
const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;
/// `EVP_CTRL_AEAD_TLS1_AAD` — `include/openssl/evp.h:408`.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_AEAD_TLS1_AAD_LEN` — `include/openssl/evp.h:461`.
const EVP_AEAD_TLS1_AAD_LEN: c_int = 13;

/// `EVP_RC4_KEY_SIZE` — `include/openssl/rc4.h`.
const EVP_RC4_KEY_SIZE: c_int = 16;
/// `MD5_DIGEST_LENGTH` — `include/openssl/md5.h`.
const MD5_DIGEST_LENGTH: usize = 16;

/// `NO_PAYLOAD_LENGTH` — `e_rc4_hmac_md5.c:37`: `(size_t)-1`.
const NO_PAYLOAD_LENGTH: usize = usize::MAX;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `data(ctx)` — `e_rc4_hmac_md5.c:42`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpRc4HmacMd5 {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpRc4HmacMd5>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_rc4_hmac_md5.c:31-35`
// ---------------------------------------------------------------------------------------------

/// `EVP_RC4_HMAC_MD5` — `e_rc4_hmac_md5.c:31-35`.
pub struct EvpRc4HmacMd5 {
    /// `RC4_KEY ks`.
    pub ks: Rc4Key,
    /// `MD5_CTX head`.
    pub head: Md5Ctx,
    /// `MD5_CTX tail`.
    pub tail: Md5Ctx,
    /// `MD5_CTX md`.
    pub md: Md5Ctx,
    /// `size_t payload_length`.
    pub payload_length: usize,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_rc4_hmac_md5.c:44-241`
// ---------------------------------------------------------------------------------------------

/// `rc4_hmac_md5_init_key` — `e_rc4_hmac_md5.c:44-63`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn rc4_hmac_md5_init_key(
    ctx: *mut c_void,
    inkey: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { data(ctx) };
    // SAFETY: `ctx` is live.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if keylen <= 0 {
        return 0;
    }
    // SAFETY: `key` is the context's own block and `inkey` is readable for `keylen` bytes.
    unsafe {
        RC4_set_key(ptr::addr_of_mut!((*key).ks), keylen, inkey);
        MD5_Init(ptr::addr_of_mut!((*key).head));
        ptr::copy_nonoverlapping(
            ptr::addr_of!((*key).head),
            ptr::addr_of_mut!((*key).tail),
            1,
        );
        ptr::copy_nonoverlapping(ptr::addr_of!((*key).head), ptr::addr_of_mut!((*key).md), 1);
        (*key).payload_length = NO_PAYLOAD_LENGTH;
    }
    1
}

/// `rc4_hmac_md5_cipher` — `e_rc4_hmac_md5.c:74-180`, portable arm.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc4_hmac_md5_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { data(ctx) };
    // SAFETY: `key` is the context's own block.
    let mut plen = unsafe { (*key).payload_length };
    if plen != NO_PAYLOAD_LENGTH && len != plen + MD5_DIGEST_LENGTH {
        return 0;
    }
    // SAFETY: `key`/`ctx` are live; the calls read and write the regions named.
    unsafe {
        if EVP_CIPHER_CTX_is_encrypting(ctx) != 0 {
            if plen == NO_PAYLOAD_LENGTH {
                plen = len;
            }
            MD5_Update(ptr::addr_of_mut!((*key).md), in_.cast(), plen);
            if plen != len {
                // "TLS" mode of operation.
                if in_ != out {
                    ptr::copy_nonoverlapping(in_, out, plen);
                }
                MD5_Final(out.add(plen), ptr::addr_of_mut!((*key).md));
                ptr::copy_nonoverlapping(
                    ptr::addr_of!((*key).tail),
                    ptr::addr_of_mut!((*key).md),
                    1,
                );
                MD5_Update(
                    ptr::addr_of_mut!((*key).md),
                    out.add(plen).cast(),
                    MD5_DIGEST_LENGTH,
                );
                MD5_Final(out.add(plen), ptr::addr_of_mut!((*key).md));
                RC4(ptr::addr_of_mut!((*key).ks), len, out, out);
            } else {
                RC4(ptr::addr_of_mut!((*key).ks), len, in_, out);
            }
        } else {
            let mut mac = [0u8; MD5_DIGEST_LENGTH];
            RC4(ptr::addr_of_mut!((*key).ks), len, in_, out);
            if plen != NO_PAYLOAD_LENGTH {
                // "TLS" mode of operation.
                MD5_Update(ptr::addr_of_mut!((*key).md), out.cast(), plen);
                MD5_Final(mac.as_mut_ptr(), ptr::addr_of_mut!((*key).md));
                ptr::copy_nonoverlapping(
                    ptr::addr_of!((*key).tail),
                    ptr::addr_of_mut!((*key).md),
                    1,
                );
                MD5_Update(
                    ptr::addr_of_mut!((*key).md),
                    mac.as_ptr().cast(),
                    MD5_DIGEST_LENGTH,
                );
                MD5_Final(mac.as_mut_ptr(), ptr::addr_of_mut!((*key).md));
                if CRYPTO_memcmp(out.add(plen).cast(), mac.as_ptr().cast(), MD5_DIGEST_LENGTH) != 0
                {
                    return 0;
                }
            } else {
                MD5_Update(ptr::addr_of_mut!((*key).md), out.cast(), len);
            }
        }
        (*key).payload_length = NO_PAYLOAD_LENGTH;
    }
    1
}

/// `rc4_hmac_md5_ctrl` — `e_rc4_hmac_md5.c:182-241`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn rc4_hmac_md5_ctrl(
    ctx: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { data(ctx) };
    match type_ {
        EVP_CTRL_AEAD_SET_MAC_KEY => {
            let mut hmac_key = [0u8; 64];
            // SAFETY: `key` is live and `ptr_` is readable for `arg` bytes per the contract.
            unsafe {
                if arg > hmac_key.len() as c_int {
                    MD5_Init(ptr::addr_of_mut!((*key).head));
                    MD5_Update(ptr::addr_of_mut!((*key).head), ptr_, arg as usize);
                    MD5_Final(hmac_key.as_mut_ptr(), ptr::addr_of_mut!((*key).head));
                } else {
                    ptr::copy_nonoverlapping(
                        ptr_.cast::<u8>(),
                        hmac_key.as_mut_ptr(),
                        arg as usize,
                    );
                }
                for b in hmac_key.iter_mut() {
                    *b ^= 0x36;
                }
                MD5_Init(ptr::addr_of_mut!((*key).head));
                MD5_Update(
                    ptr::addr_of_mut!((*key).head),
                    hmac_key.as_ptr().cast(),
                    hmac_key.len(),
                );
                for b in hmac_key.iter_mut() {
                    *b ^= 0x36 ^ 0x5c;
                }
                MD5_Init(ptr::addr_of_mut!((*key).tail));
                MD5_Update(
                    ptr::addr_of_mut!((*key).tail),
                    hmac_key.as_ptr().cast(),
                    hmac_key.len(),
                );
                OPENSSL_cleanse(hmac_key.as_mut_ptr().cast(), hmac_key.len());
            }
            1
        }
        EVP_CTRL_AEAD_TLS1_AAD => {
            let p = ptr_.cast::<c_uchar>();
            if arg != EVP_AEAD_TLS1_AAD_LEN {
                return -1;
            }
            // SAFETY: `p` is readable for `arg` bytes per the command's contract.
            let mut len = unsafe {
                ((*p.add(arg as usize - 2)) as u32) << 8 | (*p.add(arg as usize - 1)) as u32
            };
            // SAFETY: `ctx` is live.
            if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } == 0 {
                if len < MD5_DIGEST_LENGTH as u32 {
                    return -1;
                }
                len -= MD5_DIGEST_LENGTH as u32;
                // SAFETY: `p` is writable for the last two bytes per the command's contract.
                unsafe {
                    *p.add(arg as usize - 2) = (len >> 8) as c_uchar;
                    *p.add(arg as usize - 1) = len as c_uchar;
                }
            }
            // SAFETY: `key` is live.
            unsafe {
                (*key).payload_length = len as usize;
                ptr::copy_nonoverlapping(
                    ptr::addr_of!((*key).head),
                    ptr::addr_of_mut!((*key).md),
                    1,
                );
                MD5_Update(ptr::addr_of_mut!((*key).md), p.cast(), arg as usize);
            }
            MD5_DIGEST_LENGTH as c_int
        }
        _ => -1,
    }
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

/// `r4_hmac_md5_cipher` — `e_rc4_hmac_md5.c:243-260`.
static R4_HMAC_MD5_CIPHER: StaticCipher = {
    let init: Option<CipherLegacyInitFn> = Some(rc4_hmac_md5_init_key);
    let do_cipher: Option<CipherLegacyDoFn> = Some(rc4_hmac_md5_cipher);
    let ctrl: Option<CipherLegacyCtrlFn> = Some(rc4_hmac_md5_ctrl);
    StaticCipher(EvpCipher {
        // `#ifdef NID_rc4_hmac_md5 NID_rc4_hmac_md5 #else NID_undef` — the NID is defined.
        nid: NID_rc4_hmac_md5,
        block_size: 1,
        key_len: EVP_RC4_KEY_SIZE,
        iv_len: 0,
        flags: EVP_CIPH_STREAM_CIPHER | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_FLAG_AEAD_CIPHER,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup: None,
        ctx_size: core::mem::size_of::<EvpRc4HmacMd5>() as c_int,
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
};

// ---------------------------------------------------------------------------------------------
// The one accessor.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_rc4_hmac_md5(void)` — `e_rc4_hmac_md5.c:262-265`.
#[no_mangle]
pub extern "C" fn EVP_rc4_hmac_md5() -> *const EvpCipher {
    ptr::addr_of!(R4_HMAC_MD5_CIPHER.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accessor answers a read-only global with the authority's sizes.
    #[test]
    fn the_accessor_is_a_stable_global_with_the_authority_sizes() {
        let c = EVP_rc4_hmac_md5();
        // SAFETY: the accessor answers a live static, and the fields are read-only.
        unsafe {
            assert_eq!((*c).nid, NID_rc4_hmac_md5);
            assert_eq!((*c).block_size, 1);
            assert_eq!((*c).key_len, 16);
            assert_eq!((*c).iv_len, 0);
            assert_eq!((*c).origin, 1);
        }
    }
}
