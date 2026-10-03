//! Phase 13.6b — `crypto/evp/e_camellia.c`: the deprecated `EVP_CIPHER` statics the Camellia modes
//! return.
//!
//! `EVP_camellia_128_cbc()` and its twenty siblings are one line each —
//! `return &camellia_128_cbc;` (`e_camellia.c:179-182`, via `BLOCK_CIPHER_generic_pack`) — over a
//! `static const EVP_CIPHER` whose legacy half is the `camellia_init_key`/`camellia_*_cipher`
//! callbacks. This module transcribes those objects field for field and the callbacks with them.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_camellia_128_cbc()`'s object has no provider, so a caller that hands it
//! to `EVP_EncryptInit_ex` runs the Phase-8 provider Camellia-CBC, not these callbacks. The
//! callbacks are transcribed for faithfulness — an engine is the only reachable caller — exactly as
//! `src/evp/e_aes.rs` transcribes the AES ones.
//!
//! ## The SPARC `cmll_t4` arm is not modelled
//!
//! The authority's build selects `cmll_t4_*` objects only when `SPARC_CMLL_CAPABLE`
//! (`e_camellia.c:46-164`); the accessor is `SPARC_CMLL_CAPABLE ? &cmll_t4_… : &camellia_…`. This
//! crate's arm is portable, so the `camellia_*` object is the one returned, and its fields are
//! identical to the `cmll_t4_*` object's — same `nid`, sizes and `flags`, only the callback pointers
//! differ — so the observable surface is the authority's.
//!
//! ## What this module does not define
//!
//! The `Camellia_*` primitives are Phase 8's (`src/camellia.rs`). Only the twenty-one accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_camellia.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::camellia::{
    CamelliaKey, Camellia_cbc_encrypt, Camellia_decrypt, Camellia_encrypt, Camellia_set_key,
};
use crate::evp::cipher::{
    CipherLegacyCleanupFn, CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn,
    EVP_CIPHER_get_mode, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_buf_noconst, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data,
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_CTX_set_num, EVP_CIPHER_CTX_test_flags, EvpCipherCtx,
};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt,
    CRYPTO_cfb128_8_encrypt, CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt,
    CRYPTO_ctr128_encrypt_ctr32, CRYPTO_ofb128_encrypt, Cbc128F, Ctr128F,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_camellia_128_cbc, NID_camellia_128_cfb1, NID_camellia_128_cfb128, NID_camellia_128_cfb8,
    NID_camellia_128_ctr, NID_camellia_128_ecb, NID_camellia_128_ofb128, NID_camellia_192_cbc,
    NID_camellia_192_cfb1, NID_camellia_192_cfb128, NID_camellia_192_cfb8, NID_camellia_192_ctr,
    NID_camellia_192_ecb, NID_camellia_192_ofb128, NID_camellia_256_cbc, NID_camellia_256_cfb1,
    NID_camellia_256_cfb128, NID_camellia_256_cfb8, NID_camellia_256_ctr, NID_camellia_256_ecb,
    NID_camellia_256_ofb128,
};

// ---------------------------------------------------------------------------------------------
// `EVP_CIPH_*` — `include/openssl/evp.h`
// ---------------------------------------------------------------------------------------------

/// `EVP_CIPH_ECB_MODE` — `include/openssl/evp.h:311`.
const EVP_CIPH_ECB_MODE: c_int = 0x1;
/// `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h:312`.
const EVP_CIPH_CBC_MODE: c_int = 0x2;
/// `EVP_CIPH_CFB_MODE` — `include/openssl/evp.h:313`. The bit-width variants all carry it.
const EVP_CIPH_CFB_MODE: c_ulong = 0x3;
/// `EVP_CIPH_OFB_MODE` — `include/openssl/evp.h:314`.
const EVP_CIPH_OFB_MODE: c_ulong = 0x4;
/// `EVP_CIPH_CTR_MODE` — `include/openssl/evp.h:315`.
const EVP_CIPH_CTR_MODE: c_ulong = 0x5;
/// `EVP_CIPH_FLAG_LENGTH_BITS` — `include/openssl/evp.h:346`.
const EVP_CIPH_FLAG_LENGTH_BITS: c_int = 0x2000;

/// `MAXBITCHUNK` — `e_camellia.c:41`. The bit-width CFB wrapper's chunk bound.
const MAXBITCHUNK: usize = 1usize << (core::mem::size_of::<usize>() * 8 - 4);

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(EVP_CAMELLIA_KEY, ctx)` — `e_camellia.c:367-368`'s
/// `EVP_CIPHER_CTX_get_cipher_data(ctx)`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn cipher_data(ctx: *const EvpCipherCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }
}

/// `block128_f` view of [`Camellia_encrypt`] — `e_camellia.c:215`'s `(block128_f)Camellia_encrypt`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn camellia_encrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is a `CAMELLIA_KEY`.
    unsafe { Camellia_encrypt(input, out, key.cast::<CamelliaKey>()) }
}

/// `block128_f` view of [`Camellia_decrypt`] — `e_camellia.c:212`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn camellia_decrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract; `key` is a `CAMELLIA_KEY`.
    unsafe { Camellia_decrypt(input, out, key.cast::<CamelliaKey>()) }
}

/// `cbc128_f` view of [`Camellia_cbc_encrypt`] — `e_camellia.c:213/216`'s
/// `(cbc128_f)Camellia_cbc_encrypt`.
///
/// # Safety
/// The mode function's contract.
unsafe extern "C" fn camellia_cbc_stream(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract; `key` is a `CAMELLIA_KEY`.
    unsafe { Camellia_cbc_encrypt(input, out, len, key.cast::<CamelliaKey>(), ivec, enc) }
}

// ---------------------------------------------------------------------------------------------
// The context — `e_camellia.c:31-39`
// ---------------------------------------------------------------------------------------------

/// `EVP_CAMELLIA_KEY` — `e_camellia.c:32-39`. The `stream` union is split into its two arms,
/// because this crate's portable callbacks fill only one at a time (the authority's portable
/// `camellia_init_key` writes `stream.cbc` alone, so `stream.ctr` stays NULL).
pub struct EvpCamelliaKey {
    ks: CamelliaKey,
    block: Block128F,
    stream_cbc: Option<Cbc128F>,
    stream_ctr: Option<Ctr128F>,
}

// ---------------------------------------------------------------------------------------------
// The callbacks — `e_camellia.c:195-347`
// ---------------------------------------------------------------------------------------------

/// `camellia_init_key` — `e_camellia.c:196-220`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn camellia_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is the live context per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `ctx` is live.
    let bits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } * 8;
    // SAFETY: `key` is readable and `ks` writable per the contract.
    let ret = unsafe { Camellia_set_key(key, bits, ptr::addr_of_mut!((*dat).ks)) };
    if ret < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::E_CAMELLIA_205) };
        return 0;
    }
    // SAFETY: `ctx` is live and `cipher` is the method it borrowed.
    let mode = unsafe { EVP_CIPHER_get_mode((*ctx).cipher) };
    // SAFETY: `dat` is the context's own block.
    unsafe {
        if (mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && enc == 0 {
            (*dat).block = camellia_decrypt_block;
            (*dat).stream_cbc = if mode == EVP_CIPH_CBC_MODE {
                Some(camellia_cbc_stream)
            } else {
                None
            };
        } else {
            (*dat).block = camellia_encrypt_block;
            (*dat).stream_cbc = if mode == EVP_CIPH_CBC_MODE {
                Some(camellia_cbc_stream)
            } else {
                None
            };
        }
        (*dat).stream_ctr = None;
    }
    1
}

/// `camellia_cbc_cipher` — `e_camellia.c:222-236`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_cbc_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `dat` and `ctx` are live; the mode writes exactly the regions named.
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

/// `camellia_ecb_cipher` — `e_camellia.c:238-252`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_ecb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
    // SAFETY: `ctx` is live.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    if len < bl {
        return 1;
    }
    let mut i = 0usize;
    let last = len - bl;
    while i <= last {
        // SAFETY: `dat` is live and the loop stays within `len` bytes of both buffers.
        unsafe { ((*dat).block)(in_.add(i), out.add(i), ptr::addr_of!((*dat).ks).cast()) };
        i += bl;
    }
    1
}

/// `camellia_ofb_cipher` — `e_camellia.c:254-263`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_ofb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
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

/// `camellia_cfb_cipher` — `e_camellia.c:265-275`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_cfb_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
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

/// `camellia_cfb8_cipher` — `e_camellia.c:277-287`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_cfb8_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `ctx` is live.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    // SAFETY: `dat` and `ctx` are live; `num` is a local.
    unsafe {
        CRYPTO_cfb128_8_encrypt(
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

/// `camellia_cfb1_cipher` — `e_camellia.c:289-324`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_cfb1_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) } != 0 {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat` and `ctx` are live; `len` is a bit count here per the contract.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
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
        return 1;
    }
    let mut len = len;
    let mut out = out;
    let mut in_ = in_;
    while len >= MAXBITCHUNK {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` live; a whole chunk of bytes is converted to bits.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                MAXBITCHUNK * 8,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
                (*dat).block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
        len -= MAXBITCHUNK;
        // SAFETY: the chunk is within the caller's buffers.
        unsafe {
            out = out.add(MAXBITCHUNK);
            in_ = in_.add(MAXBITCHUNK);
        }
    }
    if len != 0 {
        // SAFETY: `ctx` is live.
        let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
        // SAFETY: `dat`/`ctx` live.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                in_,
                out,
                len * 8,
                ptr::addr_of!((*dat).ks).cast(),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
                EVP_CIPHER_CTX_is_encrypting(ctx),
                (*dat).block,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

/// `camellia_ctr_cipher` — `e_camellia.c:326-347`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn camellia_ctr_cipher(
    ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let snum = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    if snum < 0 {
        return 0;
    }
    let mut num = snum as c_uint;
    // SAFETY: `ctx` is live.
    let dat = unsafe { cipher_data(ctx) }.cast::<EvpCamelliaKey>();
    // SAFETY: `dat`/`ctx` live; `ecount_buf` is the context's own `buf`.
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

/// The common shape of `BLOCK_CIPHER_generic`'s initialiser — `e_camellia.c:168-182` — as a
/// `const fn`.
///
/// The authority's macro sets the ASN.1 pair, `ctrl` and `app_data` to `NULL, NULL, NULL, NULL`
/// (`e_camellia.c:176-177`), and everything in the provider half is zero.
#[allow(clippy::too_many_arguments)]
const fn legacy_cipher(
    nid: c_int,
    block_size: c_int,
    key_len: c_int,
    iv_len: c_int,
    flags: c_ulong,
    init: Option<CipherLegacyInitFn>,
    do_cipher: Option<CipherLegacyDoFn>,
    cleanup: Option<CipherLegacyCleanupFn>,
    ctx_size: c_int,
    ctrl: Option<CipherLegacyCtrlFn>,
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
        cleanup,
        ctx_size,
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
}

// `BLOCK_CIPHER_generic_pack(NID_camellia, keylen, 0)` — `e_camellia.c:349-351`.
// The flags are the mode flag alone: `EVP_CIPH_FLAG_DEFAULT_ASN1` is **0** in 3.6.4
// (`include/openssl/evp.h:343`).

static CAMELLIA_128_CBC: StaticCipher = legacy_cipher(
    NID_camellia_128_cbc,
    16,
    16,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_cbc_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_ECB: StaticCipher = legacy_cipher(
    NID_camellia_128_ecb,
    16,
    16,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_ecb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_OFB: StaticCipher = legacy_cipher(
    NID_camellia_128_ofb128,
    1,
    16,
    16,
    EVP_CIPH_OFB_MODE,
    Some(camellia_init_key),
    Some(camellia_ofb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_CFB128: StaticCipher = legacy_cipher(
    NID_camellia_128_cfb128,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_CFB1: StaticCipher = legacy_cipher(
    NID_camellia_128_cfb1,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb1_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_CFB8: StaticCipher = legacy_cipher(
    NID_camellia_128_cfb8,
    1,
    16,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb8_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_128_CTR: StaticCipher = legacy_cipher(
    NID_camellia_128_ctr,
    1,
    16,
    16,
    EVP_CIPH_CTR_MODE,
    Some(camellia_init_key),
    Some(camellia_ctr_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_CBC: StaticCipher = legacy_cipher(
    NID_camellia_192_cbc,
    16,
    24,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_cbc_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_ECB: StaticCipher = legacy_cipher(
    NID_camellia_192_ecb,
    16,
    24,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_ecb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_OFB: StaticCipher = legacy_cipher(
    NID_camellia_192_ofb128,
    1,
    24,
    16,
    EVP_CIPH_OFB_MODE,
    Some(camellia_init_key),
    Some(camellia_ofb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_CFB128: StaticCipher = legacy_cipher(
    NID_camellia_192_cfb128,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_CFB1: StaticCipher = legacy_cipher(
    NID_camellia_192_cfb1,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb1_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_CFB8: StaticCipher = legacy_cipher(
    NID_camellia_192_cfb8,
    1,
    24,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb8_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_192_CTR: StaticCipher = legacy_cipher(
    NID_camellia_192_ctr,
    1,
    24,
    16,
    EVP_CIPH_CTR_MODE,
    Some(camellia_init_key),
    Some(camellia_ctr_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_CBC: StaticCipher = legacy_cipher(
    NID_camellia_256_cbc,
    16,
    32,
    16,
    EVP_CIPH_CBC_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_cbc_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_ECB: StaticCipher = legacy_cipher(
    NID_camellia_256_ecb,
    16,
    32,
    0,
    EVP_CIPH_ECB_MODE as c_ulong,
    Some(camellia_init_key),
    Some(camellia_ecb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_OFB: StaticCipher = legacy_cipher(
    NID_camellia_256_ofb128,
    1,
    32,
    16,
    EVP_CIPH_OFB_MODE,
    Some(camellia_init_key),
    Some(camellia_ofb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_CFB128: StaticCipher = legacy_cipher(
    NID_camellia_256_cfb128,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_CFB1: StaticCipher = legacy_cipher(
    NID_camellia_256_cfb1,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb1_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_CFB8: StaticCipher = legacy_cipher(
    NID_camellia_256_cfb8,
    1,
    32,
    16,
    EVP_CIPH_CFB_MODE,
    Some(camellia_init_key),
    Some(camellia_cfb8_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);
static CAMELLIA_256_CTR: StaticCipher = legacy_cipher(
    NID_camellia_256_ctr,
    1,
    32,
    16,
    EVP_CIPH_CTR_MODE,
    Some(camellia_init_key),
    Some(camellia_ctr_cipher),
    None,
    core::mem::size_of::<EvpCamelliaKey>() as c_int,
    None,
);

// ---------------------------------------------------------------------------------------------
// The twenty-one accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_camellia_128_cbc(void)` — `e_camellia.c:349`'s `BLOCK_CIPHER_generic_pack`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_cbc() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_CBC.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_ecb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_ECB.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_ofb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_OFB.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_cfb128() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_CFB128.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_cfb1() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_CFB1.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_cfb8() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_CFB8.0)
}
/// `const EVP_CIPHER *EVP_camellia_128_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_128_ctr() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_128_CTR.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_cbc() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_CBC.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_ecb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_ECB.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_ofb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_OFB.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_cfb128() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_CFB128.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_cfb1() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_CFB1.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_cfb8() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_CFB8.0)
}
/// `const EVP_CIPHER *EVP_camellia_192_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_192_ctr() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_192_CTR.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_cbc(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_cbc() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_CBC.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_ecb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_ECB.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_ofb() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_OFB.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_cfb128(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_cfb128() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_CFB128.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_cfb1(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_cfb1() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_CFB1.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_cfb8(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_cfb8() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_CFB8.0)
}
/// `const EVP_CIPHER *EVP_camellia_256_ctr(void)`.
#[no_mangle]
pub extern "C" fn EVP_camellia_256_ctr() -> *const EvpCipher {
    ptr::addr_of!(CAMELLIA_256_CTR.0)
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
        assert_eq!(
            fields(EVP_camellia_128_cbc()),
            (NID_camellia_128_cbc, 16, 16, 16, 1)
        );
        assert_eq!(
            fields(EVP_camellia_128_ecb()),
            (NID_camellia_128_ecb, 16, 16, 0, 1)
        );
        assert_eq!(
            fields(EVP_camellia_128_ofb()),
            (NID_camellia_128_ofb128, 1, 16, 16, 1)
        );
        assert_eq!(
            fields(EVP_camellia_128_cfb1()),
            (NID_camellia_128_cfb1, 1, 16, 16, 1)
        );
        assert_eq!(
            fields(EVP_camellia_128_ctr()),
            (NID_camellia_128_ctr, 1, 16, 16, 1)
        );
        assert_eq!(
            fields(EVP_camellia_192_cbc()),
            (NID_camellia_192_cbc, 16, 24, 16, 1)
        );
        assert_eq!(
            fields(EVP_camellia_256_cbc()),
            (NID_camellia_256_cbc, 16, 32, 16, 1)
        );
        assert_ne!(EVP_camellia_128_cbc(), EVP_camellia_192_cbc());
        assert_ne!(EVP_camellia_128_cbc(), EVP_camellia_128_ecb());
    }
}
