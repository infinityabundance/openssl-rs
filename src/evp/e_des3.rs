//! Phase 13.6c — `crypto/evp/e_des3.c`: the deprecated `EVP_CIPHER` statics the two-key and
//! three-key Triple-DES modes return, plus the CMS 3DES key-wrap.
//!
//! `EVP_des_ede3_cbc()` and its twelve siblings are one line each — `return &des_ede3_cbc;`
//! (`e_des3.c:206-223`'s `BLOCK_CIPHER_defs`/`BLOCK_CIPHER_def_cfb`) — over a `static const
//! EVP_CIPHER` whose legacy half is the `des_ede_init_key`/`des_ede3_init_key` key callbacks, the
//! shared `des_ede_*_cipher` mode callbacks and the `des3_ctrl` random-key arm. This module
//! transcribes those objects field for field and the callbacks with them, and adds
//! `EVP_des_ede3_wrap` and the `des3_wrap` object with `des_ede3_wrap`/`des_ede3_unwrap`.
//!
//! ## The two-key schedule repeats the first key, and the callback is the three-key one
//!
//! `des_ede_init_key` (`e_des3.c:225-249`) expands `deskey[0]` and `deskey[1]` and then copies
//! the first schedule into `ks3`; the mode callbacks are shared (`e_des3.c:209-212`'s `#define`s),
//! so a two-key context runs the same `DES_ede3_*` primitives as a three-key one. Only the key
//! expansion differs.
//!
//! ## The SPARC `des_t4` arm is not modelled
//!
//! The authority selects `des_t4_ede3_cbc_encrypt`/`_decrypt` through `dat->stream.cbc` only when
//! `SPARC_DES_CAPABLE` (`e_des3.c:232-244`). This crate's arm is portable, so `stream.cbc` stays
//! NULL and `des_ede_cbc_cipher` runs the `DES_ede3_cbc_encrypt` loop. The bytes are the same.
//!
//! ## The wrap object's `RAND_bytes`/`ossl_sha1` calls are the authority's own
//!
//! `des_ede3_wrap` draws the key-wrap IV with `RAND_bytes` (`e_des3.c:375`) and the integrity
//! check value with `ossl_sha1` (`:370`). Those two callbacks are reachable only through an engine,
//! so the wrap object is a carrier exactly as the mode statics are; this module transcribes them
//! faithfully and does not drive them from the court.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_des_ede3_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` runs the default provider's `DES-EDE3-CBC` row (`defltprov.c:301-313`), not
//! these callbacks. The callbacks are transcribed for faithfulness — an engine is the only
//! reachable caller.
//!
//! ## What this module does not define
//!
//! The `DES_*` primitives are Phase 8's (`src/des/`). Only the thirteen accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_des3.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::des::{
    DES_ecb3_encrypt, DES_ede3_cbc_encrypt, DES_ede3_cfb64_encrypt, DES_ede3_cfb_encrypt,
    DES_ede3_ofb64_encrypt, DES_set_key_unchecked, DES_set_odd_parity, DesKeySchedule,
};
use crate::digest::sha1::ossl_sha1;
use crate::evp::cipher::{CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher};
use crate::evp::cipher_ctx::{
    ossl_is_partially_overlapping, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data,
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_CTX_set_num, EVP_CIPHER_CTX_test_flags, EvpCipherCtx,
};
use crate::rand::rand_lib::{RAND_bytes, RAND_priv_bytes};
use crate::runtime::buffer::BUF_reverse;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_memcmp, OPENSSL_cleanse};
use crate::runtime::obj::{
    NID_des_ede3_cbc, NID_des_ede3_cfb1, NID_des_ede3_cfb64, NID_des_ede3_cfb8, NID_des_ede3_ecb,
    NID_des_ede3_ofb64, NID_des_ede_cbc, NID_des_ede_cfb64, NID_des_ede_ecb, NID_des_ede_ofb64,
    NID_id_smime_alg_CMS3DESwrap,
};

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_ulong = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:319`.
const EVP_CIPH_WRAP_MODE: c_ulong = 0x10002;
/// `EVP_CIPH_CUSTOM_IV` — `include/openssl/evp.h:327`.
const EVP_CIPH_CUSTOM_IV: c_ulong = 0x10;
/// `EVP_CIPH_RAND_KEY` — `include/openssl/evp.h:337`.
const EVP_CIPH_RAND_KEY: c_ulong = 0x200;
/// `EVP_CIPH_FLAG_LENGTH_BITS` — `include/openssl/evp.h:346`.
const EVP_CIPH_FLAG_LENGTH_BITS: c_int = 0x2000;
/// `EVP_CIPH_FLAG_CUSTOM_CIPHER` — `include/openssl/evp.h:356`.
const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_ulong = 0x100000;
/// `EVP_CIPH_FLAG_DEFAULT_ASN1` — `include/openssl/evp.h:343`. **Zero** in 3.6.4.
const EVP_CIPH_FLAG_DEFAULT_ASN1: c_ulong = 0;

/// `EVP_CTRL_RAND_KEY` — `include/openssl/evp.h:385`.
const EVP_CTRL_RAND_KEY: c_int = 0x6;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h:28`.
const SHA_DIGEST_LENGTH: usize = 20;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `static const unsigned char wrap_iv[8]` — `e_des3.c:312-314`.
static WRAP_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// The `stream.cbc` function type — `e_des3.c:31-34`. The SPARC arm's pointer; never set here.
type DesEdeCbcF =
    unsafe extern "C" fn(*const c_void, *mut c_void, usize, *const DesKeySchedule, *mut u8);

/// `EVP_C_DATA(DES_EDE_KEY, ctx)` — `e_des3.c:62`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut DesEdeKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<DesEdeKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_des3.c:26-38`
// ---------------------------------------------------------------------------------------------

/// `DES_EDE_KEY` — `e_des3.c:26-35`. Three schedules and the SPARC CBC pointer.
pub struct DesEdeKey {
    /// `DES_key_schedule ks[3]`.
    pub ks: [DesKeySchedule; 3],
    /// `void (*stream.cbc)(...)`.
    pub stream_cbc: Option<DesEdeCbcF>,
}

// ---------------------------------------------------------------------------------------------
// The mode callbacks — `e_des3.c:69-204`
// ---------------------------------------------------------------------------------------------

/// `des_ede_ecb_cipher` — `e_des3.c:69-78`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede_ecb_cipher(
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
            DES_ecb3_encrypt(
                in_.add(i).cast_mut().cast::<[u8; 8]>(),
                out.add(i).cast::<[u8; 8]>(),
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        i += bl;
    }
    1
}

/// `des_ede_ofb_cipher` — `e_des3.c:80-105`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede_ofb_cipher(
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
            DES_ede3_ofb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
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
            DES_ede3_ofb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                &mut num,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `des_ede_cbc_cipher` — `e_des3.c:107-133`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede_cbc_cipher(
    ctx: *mut c_void,
    mut out: *mut u8,
    mut in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block.
    if let Some(f) = unsafe { (*dat).stream_cbc } {
        // SAFETY: `f` is the SPARC accelerator and `dat`/`ctx` are live.
        unsafe {
            f(
                in_.cast(),
                out.cast(),
                inl,
                ptr::addr_of!((*dat).ks[0]),
                (*ctx).iv.as_mut_ptr(),
            )
        };
        return 1;
    }
    while inl >= EVP_MAXCHUNK {
        // SAFETY: `dat`/`ctx` are live; the chunk is within the caller's buffers.
        unsafe {
            DES_ede3_cbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
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
            DES_ede3_cbc_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `des_ede_cfb64_cipher` — `e_des3.c:135-158`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede_cfb64_cipher(
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
            DES_ede3_cfb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
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
            DES_ede3_cfb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `des_ede3_cfb1_cipher` — `e_des3.c:164-184`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `inl` is a byte count unless `LENGTH_BITS` is set.
unsafe extern "C" fn des_ede3_cfb1_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    let mut c = [0u8; 1];
    let mut d = [0u8; 1];
    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) } == 0 {
        inl *= 8;
    }
    // SAFETY: `ctx` is live.
    let dat = unsafe { data(ctx) };
    let mut n = 0usize;
    while n < inl {
        // SAFETY: the loop index stays within the caller's `inl` bits.
        c[0] = if unsafe { *in_.add(n / 8) } & (1u8 << (7 - n % 8)) != 0 {
            0x80
        } else {
            0
        };
        // SAFETY: `dat`/`ctx` are live; `c`/`d` are one byte each.
        unsafe {
            DES_ede3_cfb_encrypt(
                c.as_ptr(),
                d.as_mut_ptr(),
                1,
                1,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        // SAFETY: `out.add(n / 8)` is within the caller's `inl` bits.
        unsafe {
            let o = out.add(n / 8);
            *o = (*o & !(0x80u8 >> (n % 8))) | ((d[0] & 0x80) >> (n % 8));
        }
        n += 1;
    }
    1
}

/// `des_ede3_cfb8_cipher` — `e_des3.c:186-204`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede3_cfb8_cipher(
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
            DES_ede3_cfb_encrypt(
                in_,
                out,
                8,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
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
            DES_ede3_cfb_encrypt(
                in_,
                out,
                8,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks[0]),
                ptr::addr_of_mut!((*dat).ks[1]),
                ptr::addr_of_mut!((*dat).ks[2]),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The key and control callbacks — `e_des3.c:225-298`
// ---------------------------------------------------------------------------------------------

/// `des_ede_init_key` — `e_des3.c:225-249`, portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract; `key` readable for sixteen bytes.
unsafe extern "C" fn des_ede_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block.
    unsafe { (*dat).stream_cbc = None };
    // SAFETY: `key` is readable for sixteen bytes; the two schedules are writable.
    unsafe {
        DES_set_key_unchecked(
            key.cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks[0]),
        );
        DES_set_key_unchecked(
            key.add(8).cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks[1]),
        );
        ptr::copy_nonoverlapping(
            ptr::addr_of!((*dat).ks[0]),
            ptr::addr_of_mut!((*dat).ks[2]),
            1,
        );
    }
    1
}

/// `des_ede3_init_key` — `e_des3.c:251-275`, portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract; `key` readable for twenty-four bytes.
unsafe extern "C" fn des_ede3_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `dat` is the context's own block.
    unsafe { (*dat).stream_cbc = None };
    // SAFETY: `key` is readable for twenty-four bytes; the three schedules are writable.
    unsafe {
        DES_set_key_unchecked(
            key.cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks[0]),
        );
        DES_set_key_unchecked(
            key.add(8).cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks[1]),
        );
        DES_set_key_unchecked(
            key.add(16).cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks[2]),
        );
    }
    1
}

/// `des3_ctrl` — `e_des3.c:277-298`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn des3_ctrl(
    ctx: *mut c_void,
    type_: c_int,
    _arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    match type_ {
        EVP_CTRL_RAND_KEY => {
            // SAFETY: `ctx` is live per the contract.
            let kl = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
            // SAFETY: `ptr_` is writable for `kl` bytes per the command's contract.
            if kl < 0 || unsafe { RAND_priv_bytes(ptr_.cast::<u8>(), kl) } <= 0 {
                return 0;
            }
            // SAFETY: `ptr_` is a `DES_cblock` array of at least `kl` bytes.
            unsafe {
                let deskey = ptr_.cast::<[u8; 8]>();
                DES_set_odd_parity(deskey);
                if kl >= 16 {
                    DES_set_odd_parity(deskey.add(1));
                }
                if kl >= 24 {
                    DES_set_odd_parity(deskey.add(2));
                }
            }
            1
        }
        _ => -1,
    }
}

// ---------------------------------------------------------------------------------------------
// The CMS 3DES key-wrap — `e_des3.c:312-423`
// ---------------------------------------------------------------------------------------------

/// `des_ede3_unwrap` — `e_des3.c:316-359`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `out` writable for `inl - 16` bytes.
unsafe fn des_ede3_unwrap(
    ctx: *mut EvpCipherCtx,
    out: *mut u8,
    in_: *const u8,
    inl: usize,
) -> c_int {
    let mut icv = [0u8; 8];
    let mut iv = [0u8; 8];
    let mut sha1tmp = [0u8; SHA_DIGEST_LENGTH];
    let mut rv: c_int = -1;
    if inl < 24 {
        return -1;
    }
    if out.is_null() {
        return (inl - 16) as c_int;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        ptr::copy_nonoverlapping(WRAP_IV.as_ptr(), (*ctx).iv.as_mut_ptr(), 8);
        // Decrypt the first block, which will end up as the ICV.
        des_ede_cbc_cipher(ctx.cast(), icv.as_mut_ptr(), in_, 8);
        let mut in_ = in_;
        // If decrypting in place, move the whole output along a block so the next call is in place.
        if ptr::eq(out.cast_const(), in_) {
            ptr::copy(out.add(8), out, inl - 8);
            in_ = in_.sub(8);
        }
        des_ede_cbc_cipher(ctx.cast(), out, in_.add(8), inl - 16);
        des_ede_cbc_cipher(ctx.cast(), iv.as_mut_ptr(), in_.add(inl - 8), 8);
        BUF_reverse(icv.as_mut_ptr(), ptr::null(), 8);
        BUF_reverse(out, ptr::null(), inl - 16);
        BUF_reverse((*ctx).iv.as_mut_ptr(), iv.as_ptr(), 8);
        des_ede_cbc_cipher(ctx.cast(), out, out, inl - 16);
        des_ede_cbc_cipher(ctx.cast(), icv.as_mut_ptr(), icv.as_ptr(), 8);
        if !ossl_sha1(out, inl - 16, sha1tmp.as_mut_ptr()).is_null()
            && CRYPTO_memcmp(sha1tmp.as_ptr().cast(), icv.as_ptr().cast(), 8) == 0
        {
            rv = (inl - 16) as c_int;
        }
        OPENSSL_cleanse(icv.as_mut_ptr().cast::<c_void>(), 8);
        OPENSSL_cleanse(sha1tmp.as_mut_ptr().cast::<c_void>(), SHA_DIGEST_LENGTH);
        OPENSSL_cleanse(iv.as_mut_ptr().cast::<c_void>(), 8);
        OPENSSL_cleanse((*ctx).iv.as_mut_ptr().cast::<c_void>(), 8);
        if rv == -1 {
            OPENSSL_cleanse(out.cast::<c_void>(), inl - 16);
        }
    }
    rv
}

/// `des_ede3_wrap` — `e_des3.c:361-384`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `out` writable for `inl + 16` bytes.
unsafe fn des_ede3_wrap(ctx: *mut EvpCipherCtx, out: *mut u8, in_: *const u8, inl: usize) -> c_int {
    let mut sha1tmp = [0u8; SHA_DIGEST_LENGTH];
    if out.is_null() {
        return (inl + 16) as c_int;
    }
    // SAFETY: `out` is writable for `inl + 16`; `in_` is readable for `inl`.
    unsafe {
        ptr::copy(in_, out.add(8), inl);
        if ossl_sha1(in_, inl, sha1tmp.as_mut_ptr()).is_null() {
            return -1;
        }
        ptr::copy_nonoverlapping(sha1tmp.as_ptr(), out.add(inl + 8), 8);
        OPENSSL_cleanse(sha1tmp.as_mut_ptr().cast::<c_void>(), SHA_DIGEST_LENGTH);
        if RAND_bytes((*ctx).iv.as_mut_ptr(), 8) <= 0 {
            return -1;
        }
        ptr::copy_nonoverlapping((*ctx).iv.as_ptr(), out, 8);
        des_ede_cbc_cipher(ctx.cast(), out.add(8), out.add(8), inl + 8);
        BUF_reverse(out, ptr::null(), inl + 16);
        ptr::copy_nonoverlapping(WRAP_IV.as_ptr(), (*ctx).iv.as_mut_ptr(), 8);
        des_ede_cbc_cipher(ctx.cast(), out, out, inl + 16);
    }
    (inl + 16) as c_int
}

/// `des_ede3_wrap_cipher` — `e_des3.c:386-406`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ede3_wrap_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    if inl >= EVP_MAXCHUNK || !inl.is_multiple_of(8) {
        return -1;
    }
    // SAFETY: `out`/`in_` are the caller's buffers and `inl` is their extent.
    if unsafe { ossl_is_partially_overlapping(out.cast(), in_.cast(), inl as c_int) } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_DES3_398) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
        // SAFETY: the caller's contract; `ctx` is a live context.
        unsafe { des_ede3_wrap(ctx, out, in_, inl) }
    } else {
        // SAFETY: the caller's contract; `ctx` is a live context.
        unsafe { des_ede3_unwrap(ctx, out, in_, inl) }
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

/// The common shape of `BLOCK_CIPHER_def1`'s initialiser — `include/crypto/evp.h:450-465` — as a
/// `const fn`. The two `des_ede*` groups carry `NULL` for the ASN.1 pair and `des3_ctrl` for
/// `ctrl` (`e_des3.c:206-223`).
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
        set_asn1_parameters: None,
        get_asn1_parameters: None,
        ctrl: Some(des3_ctrl),
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

/// The shared flag word of the two `des_ede*` groups: `RAND_KEY | DEFAULT_ASN1`.
const EDE_BASE_FLAGS: c_ulong = EVP_CIPH_RAND_KEY | EVP_CIPH_FLAG_DEFAULT_ASN1;

// `BLOCK_CIPHER_defs(des_ede, DES_EDE_KEY, NID_des_ede, 8, 16, 8, 64,
//     EVP_CIPH_RAND_KEY | EVP_CIPH_FLAG_DEFAULT_ASN1, des_ede_init_key, NULL, NULL, NULL,
//     des3_ctrl)` — `e_des3.c:206-208`.

static DES_EDE_CBC: StaticCipher = legacy_cipher(
    NID_des_ede_cbc,
    8,
    16,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(des_ede_init_key),
    Some(des_ede_cbc_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE_CFB64: StaticCipher = legacy_cipher(
    NID_des_ede_cfb64,
    1,
    16,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_ede_init_key),
    Some(des_ede_cfb64_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE_OFB: StaticCipher = legacy_cipher(
    NID_des_ede_ofb64,
    1,
    16,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_OFB_MODE,
    Some(des_ede_init_key),
    Some(des_ede_ofb_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE_ECB: StaticCipher = legacy_cipher(
    NID_des_ede_ecb,
    8,
    16,
    0,
    EDE_BASE_FLAGS | EVP_CIPH_ECB_MODE,
    Some(des_ede_init_key),
    Some(des_ede_ecb_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);

// `BLOCK_CIPHER_defs(des_ede3, ...)` — `e_des3.c:213-215`.

static DES_EDE3_CBC: StaticCipher = legacy_cipher(
    NID_des_ede3_cbc,
    8,
    24,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(des_ede3_init_key),
    Some(des_ede_cbc_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE3_CFB64: StaticCipher = legacy_cipher(
    NID_des_ede3_cfb64,
    1,
    24,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_ede3_init_key),
    Some(des_ede_cfb64_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE3_OFB: StaticCipher = legacy_cipher(
    NID_des_ede3_ofb64,
    1,
    24,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_OFB_MODE,
    Some(des_ede3_init_key),
    Some(des_ede_ofb_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
static DES_EDE3_ECB: StaticCipher = legacy_cipher(
    NID_des_ede3_ecb,
    8,
    24,
    0,
    EDE_BASE_FLAGS | EVP_CIPH_ECB_MODE,
    Some(des_ede3_init_key),
    Some(des_ede_ecb_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);

// `BLOCK_CIPHER_def_cfb(des_ede3, DES_EDE_KEY, NID_des_ede3, 24, 8, 1, ...)` — `e_des3.c:217-219`.
static DES_EDE3_CFB1: StaticCipher = legacy_cipher(
    NID_des_ede3_cfb1,
    1,
    24,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_ede3_init_key),
    Some(des_ede3_cfb1_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);
// `BLOCK_CIPHER_def_cfb(des_ede3, DES_EDE_KEY, NID_des_ede3, 24, 8, 8, ...)` — `e_des3.c:221-223`.
static DES_EDE3_CFB8: StaticCipher = legacy_cipher(
    NID_des_ede3_cfb8,
    1,
    24,
    8,
    EDE_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_ede3_init_key),
    Some(des_ede3_cfb8_cipher),
    core::mem::size_of::<DesEdeKey>() as c_int,
);

/// `des3_wrap` — `e_des3.c:408-418`. Its `key_len` is 24, its `iv_len` 0, and its `flags` are
/// `WRAP_MODE | CUSTOM_IV | FLAG_CUSTOM_CIPHER | DEFAULT_ASN1`.
static DES3_WRAP: StaticCipher = {
    let set_asn1: Option<crate::evp::cipher::CipherLegacyAsn1Fn> = None;
    let get_asn1: Option<crate::evp::cipher::CipherLegacyAsn1Fn> = None;
    StaticCipher(EvpCipher {
        nid: NID_id_smime_alg_CMS3DESwrap,
        block_size: 8,
        key_len: 24,
        iv_len: 0,
        flags: EVP_CIPH_WRAP_MODE
            | EVP_CIPH_CUSTOM_IV
            | EVP_CIPH_FLAG_CUSTOM_CIPHER
            | EVP_CIPH_FLAG_DEFAULT_ASN1,
        origin: EVP_ORIG_GLOBAL,
        init: Some(des_ede3_init_key),
        do_cipher: Some(des_ede3_wrap_cipher),
        cleanup: None,
        ctx_size: core::mem::size_of::<DesEdeKey>() as c_int,
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
// The thirteen accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_des_ede(void)` — `e_des3.c:300-303`.
#[no_mangle]
pub extern "C" fn EVP_des_ede() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE_ECB.0)
}
/// `const EVP_CIPHER *EVP_des_ede3(void)` — `e_des3.c:305-308`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_ECB.0)
}
/// `const EVP_CIPHER *EVP_des_ede_cbc(void)` — `e_des3.c:206`.
#[no_mangle]
pub extern "C" fn EVP_des_ede_cbc() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE_CBC.0)
}
/// `const EVP_CIPHER *EVP_des_ede_cfb64(void)` — `e_des3.c:206`.
#[no_mangle]
pub extern "C" fn EVP_des_ede_cfb64() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE_CFB64.0)
}
/// `const EVP_CIPHER *EVP_des_ede_ecb(void)` — `e_des3.c:206`.
#[no_mangle]
pub extern "C" fn EVP_des_ede_ecb() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE_ECB.0)
}
/// `const EVP_CIPHER *EVP_des_ede_ofb(void)` — `e_des3.c:206`.
#[no_mangle]
pub extern "C" fn EVP_des_ede_ofb() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE_OFB.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_cbc(void)` — `e_des3.c:213`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_cbc() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_CBC.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_cfb1(void)` — `e_des3.c:217`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_cfb1() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_CFB1.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_cfb64(void)` — `e_des3.c:213`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_cfb64() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_CFB64.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_cfb8(void)` — `e_des3.c:221`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_cfb8() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_CFB8.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_ecb(void)` — `e_des3.c:213`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_ecb() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_ECB.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_ofb(void)` — `e_des3.c:213`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_ofb() -> *const EvpCipher {
    ptr::addr_of!(DES_EDE3_OFB.0)
}
/// `const EVP_CIPHER *EVP_des_ede3_wrap(void)` — `e_des3.c:420-423`.
#[no_mangle]
pub extern "C" fn EVP_des_ede3_wrap() -> *const EvpCipher {
    ptr::addr_of!(DES3_WRAP.0)
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
        assert_eq!(fields(EVP_des_ede_cbc()), (NID_des_ede_cbc, 8, 16, 8, 1));
        assert_eq!(fields(EVP_des_ede_ecb()), (NID_des_ede_ecb, 8, 16, 0, 1));
        assert_eq!(fields(EVP_des_ede()), (NID_des_ede_ecb, 8, 16, 0, 1));
        assert_eq!(fields(EVP_des_ede3_cbc()), (NID_des_ede3_cbc, 8, 24, 8, 1));
        assert_eq!(fields(EVP_des_ede3_ecb()), (NID_des_ede3_ecb, 8, 24, 0, 1));
        assert_eq!(fields(EVP_des_ede()), (NID_des_ede_ecb, 8, 16, 0, 1));
        assert_eq!(fields(EVP_des_ede3()), (NID_des_ede3_ecb, 8, 24, 0, 1));
        assert_eq!(
            fields(EVP_des_ede3_wrap()),
            (NID_id_smime_alg_CMS3DESwrap, 8, 24, 0, 1)
        );
        assert_ne!(EVP_des_ede(), EVP_des_ede3());
    }
}
