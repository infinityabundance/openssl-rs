//! Phase 13.6c — `crypto/evp/e_des.c`: the deprecated `EVP_CIPHER` statics the single-DES modes
//! return.
//!
//! `EVP_des_cbc()` and its five siblings are one line each — `return &des_cbc;`
//! (`e_des.c:196-206`'s `BLOCK_CIPHER_defs` and the two `BLOCK_CIPHER_def_cfb` calls) — over a
//! `static const EVP_CIPHER` whose legacy half is the `des_init_key`/`des_*_cipher` callbacks and
//! the `des_ctrl` random-key arm. This module transcribes those objects field for field and the
//! callbacks with them.
//!
//! ## The SPARC `des_t4` arm is not modelled
//!
//! The authority selects `des_t4_cbc_encrypt`/`des_t4_cbc_decrypt` through `dat->stream.cbc` only
//! when `SPARC_DES_CAPABLE` (`e_des.c:215-225`). This crate's arm is portable, so `des_init_key`
//! leaves `stream.cbc` NULL and `des_cbc_cipher` runs the `DES_ncbc_encrypt` loop. The observable
//! is the portable encryption, which is the same bytes the SPARC accelerator computes.
//!
//! ## `EVP_des_cfb1` wraps an R1 CFB itself
//!
//! `e_des.c:144-147`'s comment is the reason this is not the generic `BLOCK_CIPHER_func_cfb`:
//! `DES_cfb_encrypt`'s bit input does not pack the way the macro expects, so the authority walks
//! the input bit by bit and re-serialises the output. This module transcribes that loop literally.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_des_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `DES-CBC`. Single DES is the **legacy**
//! provider's row (`legacyprov.c`), and only the default provider is activated by default, so the
//! fetch answers NULL and the call refuses — on the authority and in this crate alike. The
//! callbacks are transcribed for faithfulness — an engine is the only reachable caller.
//!
//! ## What this module does not define
//!
//! The `DES_*` primitives are Phase 8's (`src/des/`). Only the six accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_des.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::layout::Asn1Type;
use crate::des::{
    DES_cfb64_encrypt, DES_cfb_encrypt, DES_ecb_encrypt, DES_ncbc_encrypt, DES_ofb64_encrypt,
    DES_set_key_unchecked, DES_set_odd_parity, DesKeySchedule,
};
use crate::evp::cipher::{
    CipherLegacyAsn1Fn, CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_num,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_num, EVP_CIPHER_get_asn1_iv,
    EVP_CIPHER_set_asn1_iv, EvpCipherCtx,
};
use crate::rand::rand_lib::RAND_priv_bytes;
use crate::runtime::obj::{
    NID_des_cbc, NID_des_cfb1, NID_des_cfb64, NID_des_cfb8, NID_des_ecb, NID_des_ofb64,
};

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_ulong = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_ulong = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_RAND_KEY` — `include/openssl/evp.h:337`.
const EVP_CIPH_RAND_KEY: c_ulong = 0x200;

/// `EVP_CTRL_RAND_KEY` — `include/openssl/evp.h:385`.
const EVP_CTRL_RAND_KEY: c_int = 0x6;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// The `stream.cbc` function type — `e_des.c:31-34`. The SPARC arm's pointer; never set on this
/// profile.
type DesCbcF =
    unsafe extern "C" fn(*const c_void, *mut c_void, usize, *const DesKeySchedule, *mut u8);

/// `EVP_C_DATA(EVP_DES_KEY, ctx)` — `e_des.c:96`'s `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpDesKey {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpDesKey>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_des.c:26-35`
// ---------------------------------------------------------------------------------------------

/// `EVP_DES_KEY` — `e_des.c:26-35`. The `ks` union holds one schedule; the `stream` union holds
/// the SPARC CBC pointer that this profile never sets.
pub struct EvpDesKey {
    /// `DES_key_schedule ks`.
    pub ks: DesKeySchedule,
    /// `void (*stream.cbc)(...)`.
    pub stream_cbc: Option<DesCbcF>,
}

// ---------------------------------------------------------------------------------------------
// The mode callbacks — `e_des.c:60-194`
// ---------------------------------------------------------------------------------------------

/// `des_ecb_cipher` — `e_des.c:60-68`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ecb_cipher(
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
            DES_ecb_encrypt(
                in_.add(i).cast_mut().cast::<[u8; 8]>(),
                out.add(i).cast::<[u8; 8]>(),
                ptr::addr_of_mut!((*dat).ks),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        i += bl;
    }
    1
}

/// `des_ofb_cipher` — `e_des.c:70-91`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_ofb_cipher(
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
            DES_ofb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            DES_ofb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                &mut num,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `des_cbc_cipher` — `e_des.c:93-117`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_cbc_cipher(
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
                ptr::addr_of!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
            )
        };
        return 1;
    }
    while inl >= EVP_MAXCHUNK {
        // SAFETY: `dat`/`ctx` are live; the chunk is within the caller's buffers.
        unsafe {
            DES_ncbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            DES_ncbc_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `des_cfb64_cipher` — `e_des.c:119-142`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_cfb64_cipher(
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
            DES_cfb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            DES_cfb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `des_cfb1_cipher` — `e_des.c:148-174`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract; `inl` is a byte count.
unsafe extern "C" fn des_cfb1_cipher(
    ctx: *mut c_void,
    mut out: *mut u8,
    mut in_: *const u8,
    mut inl: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    let mut chunk = EVP_MAXCHUNK / 8;
    let mut c = [0u8; 1];
    let mut d = [0u8; 1];
    if inl < chunk {
        chunk = inl;
    }
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    while inl != 0 && inl >= chunk {
        let mut n = 0usize;
        while n < chunk * 8 {
            // SAFETY: the loop index stays within the chunk of `in_`.
            c[0] = if unsafe { *in_.add(n / 8) } & (1u8 << (7 - n % 8)) != 0 {
                0x80
            } else {
                0
            };
            // SAFETY: `dat`/`ctx` are live; `c`/`d` are one byte each.
            unsafe {
                DES_cfb_encrypt(
                    c.as_ptr(),
                    d.as_mut_ptr(),
                    1,
                    1,
                    ptr::addr_of_mut!((*dat).ks),
                    (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                    EVP_CIPHER_CTX_is_encrypting(ctx),
                )
            };
            // SAFETY: `out.add(n / 8)` is within the chunk of `out`.
            unsafe {
                let o = out.add(n / 8);
                *o = (*o & !(0x80u8 >> (n % 8))) | ((d[0] & 0x80) >> (n % 8));
            }
            n += 1;
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

/// `des_cfb8_cipher` — `e_des.c:176-194`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn des_cfb8_cipher(
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
            DES_cfb_encrypt(
                in_,
                out,
                8,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            DES_cfb_encrypt(
                in_,
                out,
                8,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr().cast::<[u8; 8]>(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The key and control callbacks — `e_des.c:208-243`
// ---------------------------------------------------------------------------------------------

/// `des_init_key` — `e_des.c:208-228`, portable arm.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn des_init_key(
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
    // SAFETY: `key` is readable for eight bytes and `ks` is writable.
    unsafe {
        DES_set_key_unchecked(
            key.cast_mut().cast::<[u8; 8]>(),
            ptr::addr_of_mut!((*dat).ks),
        )
    };
    1
}

/// `des_ctrl` — `e_des.c:230-243`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn des_ctrl(
    c: *mut c_void,
    type_: c_int,
    _arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let _ = c;
    match type_ {
        EVP_CTRL_RAND_KEY => {
            // SAFETY: `ptr_` is writable for eight bytes per the command's contract.
            if unsafe { RAND_priv_bytes(ptr_.cast::<u8>(), 8) } <= 0 {
                return 0;
            }
            // SAFETY: `ptr_` is an eight-byte `DES_cblock` per the command's contract.
            unsafe { DES_set_odd_parity(ptr_.cast::<[u8; 8]>()) };
            1
        }
        _ => -1,
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
/// `const fn`.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    ctx_size: c_int,
    set_asn1: Option<CipherLegacyAsn1Fn>,
    get_asn1: Option<CipherLegacyAsn1Fn>,
    ctrl: Option<CipherLegacyCtrlFn>,
) -> StaticCipher {
    StaticCipher(EvpCipher {
        nid,
        block_size,
        key_len: 8,
        iv_len,
        flags,
        origin: EVP_ORIG_GLOBAL,
        init,
        do_cipher,
        cleanup: None,
        ctx_size,
        set_asn1_parameters: set_asn1,
        get_asn1_parameters: get_asn1,
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
}

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_set_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn des_set_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_set_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `EVP_CIPHER_get_asn1_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn des_get_asn1_iv(ctx: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract; `ctx` is an `EVP_CIPHER_CTX` and `type_` an `ASN1_TYPE`.
    unsafe { EVP_CIPHER_get_asn1_iv(ctx.cast::<EvpCipherCtx>(), type_.cast::<Asn1Type>()) }
}

/// `des_ctrl` as the `ctrl` field.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn des_ctrl_fn(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { des_ctrl(c, type_, arg, ptr_) }
}

/// The shared flag word of the generic pack: `EVP_CIPH_RAND_KEY` (`e_des.c:196-206`).
const DES_BASE_FLAGS: c_ulong = EVP_CIPH_RAND_KEY;

// `BLOCK_CIPHER_defs(des, EVP_DES_KEY, NID_des, 8, 8, 8, 64, EVP_CIPH_RAND_KEY, des_init_key,
//     NULL, EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, des_ctrl)` — `e_des.c:196-206`.

static DES_CBC: StaticCipher = legacy_cipher(
    NID_des_cbc,
    8,
    8,
    DES_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(des_init_key),
    Some(des_cbc_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);
static DES_CFB64: StaticCipher = legacy_cipher(
    NID_des_cfb64,
    1,
    8,
    DES_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_init_key),
    Some(des_cfb64_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);
static DES_OFB: StaticCipher = legacy_cipher(
    NID_des_ofb64,
    1,
    8,
    DES_BASE_FLAGS | EVP_CIPH_OFB_MODE,
    Some(des_init_key),
    Some(des_ofb_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);
static DES_ECB: StaticCipher = legacy_cipher(
    NID_des_ecb,
    8,
    0,
    DES_BASE_FLAGS | EVP_CIPH_ECB_MODE,
    Some(des_init_key),
    Some(des_ecb_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);
// `BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 1, ...)` — `e_des.c:200-202`.
static DES_CFB1: StaticCipher = legacy_cipher(
    NID_des_cfb1,
    1,
    8,
    DES_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_init_key),
    Some(des_cfb1_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);
// `BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 8, ...)` — `e_des.c:204-206`.
static DES_CFB8: StaticCipher = legacy_cipher(
    NID_des_cfb8,
    1,
    8,
    DES_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(des_init_key),
    Some(des_cfb8_cipher),
    core::mem::size_of::<EvpDesKey>() as c_int,
    Some(des_set_asn1_iv),
    Some(des_get_asn1_iv),
    Some(des_ctrl_fn),
);

// ---------------------------------------------------------------------------------------------
// The six accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_des_cbc(void)` — `e_des.c:196`'s `BLOCK_CIPHER_defs`.
#[no_mangle]
pub extern "C" fn EVP_des_cbc() -> *const EvpCipher {
    ptr::addr_of!(DES_CBC.0)
}
/// `const EVP_CIPHER *EVP_des_cfb1(void)` — `e_des.c:200`.
#[no_mangle]
pub extern "C" fn EVP_des_cfb1() -> *const EvpCipher {
    ptr::addr_of!(DES_CFB1.0)
}
/// `const EVP_CIPHER *EVP_des_cfb64(void)` — `e_des.c:196`.
#[no_mangle]
pub extern "C" fn EVP_des_cfb64() -> *const EvpCipher {
    ptr::addr_of!(DES_CFB64.0)
}
/// `const EVP_CIPHER *EVP_des_cfb8(void)` — `e_des.c:204`.
#[no_mangle]
pub extern "C" fn EVP_des_cfb8() -> *const EvpCipher {
    ptr::addr_of!(DES_CFB8.0)
}
/// `const EVP_CIPHER *EVP_des_ecb(void)` — `e_des.c:196`.
#[no_mangle]
pub extern "C" fn EVP_des_ecb() -> *const EvpCipher {
    ptr::addr_of!(DES_ECB.0)
}
/// `const EVP_CIPHER *EVP_des_ofb(void)` — `e_des.c:196`.
#[no_mangle]
pub extern "C" fn EVP_des_ofb() -> *const EvpCipher {
    ptr::addr_of!(DES_OFB.0)
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
        assert_eq!(fields(EVP_des_cbc()), (NID_des_cbc, 8, 8, 8, 1));
        assert_eq!(fields(EVP_des_cfb1()), (NID_des_cfb1, 1, 8, 8, 1));
        assert_eq!(fields(EVP_des_cfb64()), (NID_des_cfb64, 1, 8, 8, 1));
        assert_eq!(fields(EVP_des_cfb8()), (NID_des_cfb8, 1, 8, 8, 1));
        assert_eq!(fields(EVP_des_ecb()), (NID_des_ecb, 8, 8, 0, 1));
        assert_eq!(fields(EVP_des_ofb()), (NID_des_ofb64, 1, 8, 8, 1));
        assert_ne!(EVP_des_cbc(), EVP_des_ecb());
    }
}
