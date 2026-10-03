//! Phase 13.6c — `crypto/evp/e_rc2.c`: the deprecated `EVP_CIPHER` statics the RC2 modes return.
//!
//! `EVP_rc2_cbc()` and its five siblings are one line each — `return &rc2_cbc;`
//! (`e_rc2.c:42-48`'s `IMPLEMENT_BLOCK_CIPHER`, and the two hand-written `r2_64_cbc_cipher`/
//! `r2_40_cbc_cipher` at `:82-90`) — over a `static const EVP_CIPHER` whose legacy half is the
//! `rc2_init_key`/`rc2_*_cipher` callbacks and the four ASN.1 and control helpers. This module
//! transcribes those objects field for field and the callbacks with them.
//!
//! ## The two fixed-length statics set `key_bits` through `EVP_CTRL_INIT`
//!
//! `r2_64_cbc_cipher` and `r2_40_cbc_cipher` publish `key_len` 8 and 5, and `rc2_ctrl`'s
//! `EVP_CTRL_INIT` arm records `key_bits = key_len * 8`; the ASN.1 helpers map that back to the
//! `0x3a`/`0x78`/`0xa0` magic the algorithm-identifier carries. All three statics share the one
//! `rc2_init_key`, which feeds `data(ctx)->key_bits` rather than the caller's `key_len` to
//! `RC2_set_key`.
//!
//! ## These objects are carriers, and the library replaces them before any callback runs
//!
//! `evp_cipher_init_internal` (`src/evp/cipher_ctx.rs`) opens with the test the AES slice's module
//! doc states: a method whose `prov` is NULL is **fetched by short name** and `type` is rebound to
//! the provider method. `EVP_rc2_cbc()`'s object has no provider, so a caller that hands it to
//! `EVP_EncryptInit_ex` asks the default provider for `RC2-CBC`. RC2 is the **legacy** provider's
//! row (`legacyprov.c`), and only the default provider is activated by default, so the fetch
//! answers NULL and the call refuses — on the authority and in this crate alike. The callbacks are
//! transcribed for faithfulness — an engine is the only reachable caller.
//!
//! ## What this module does not define
//!
//! The `RC2_*` primitives are Phase 8's (`src/rc2.rs`). Only the six accessors
//! `forensics/atlas/export-defining-units.json` assigns to `e_rc2.c` are exported here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;

use crate::asn1::evp_asn1::{ASN1_TYPE_get_int_octetstring, ASN1_TYPE_set_int_octetstring};
use crate::asn1::layout::Asn1Type;
use crate::evp::cipher::{
    CipherLegacyAsn1Fn, CipherLegacyCtrlFn, CipherLegacyDoFn, CipherLegacyInitFn, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_cipher_data,
    EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_num,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_set_key_length, EVP_CIPHER_CTX_set_num,
    EVP_CipherInit_ex, EvpCipherCtx,
};
use crate::rc2::{
    RC2_cbc_encrypt, RC2_cfb64_encrypt, RC2_ecb_encrypt, RC2_ofb64_encrypt, RC2_set_key, Rc2Key,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_rc2_cfb64, NID_rc2_ecb, NID_rc2_ofb64,
};

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
/// `EVP_CIPH_CTRL_INIT` — `include/openssl/evp.h:331`.
const EVP_CIPH_CTRL_INIT: c_ulong = 0x40;

/// `EVP_CTRL_INIT` — `include/openssl/evp.h:379`.
const EVP_CTRL_INIT: c_int = 0x0;
/// `EVP_CTRL_GET_RC2_KEY_BITS` — `include/openssl/evp.h:381`.
const EVP_CTRL_GET_RC2_KEY_BITS: c_int = 0x2;
/// `EVP_CTRL_SET_RC2_KEY_BITS` — `include/openssl/evp.h:382`.
const EVP_CTRL_SET_RC2_KEY_BITS: c_int = 0x3;

/// `RC2_40_MAGIC` — `e_rc2.c:49`.
const RC2_40_MAGIC: c_int = 0xa0;
/// `RC2_64_MAGIC` — `e_rc2.c:50`.
const RC2_64_MAGIC: c_int = 0x78;
/// `RC2_128_MAGIC` — `e_rc2.c:51`.
const RC2_128_MAGIC: c_int = 0x3a;
/// `RC2_KEY_LENGTH` — `include/openssl/rc2.h`.
const RC2_KEY_LENGTH: c_int = 16;

/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:295`.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `EVP_MAXCHUNK` — `include/crypto/evp.h:386`: `(size_t)1 << 30`.
const EVP_MAXCHUNK: usize = 1usize << 30;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h`. A method in read-only memory.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_C_DATA(EVP_RC2_KEY, ctx)` — `e_rc2.c:40`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX` whose method allocated a `cipher_data` block.
unsafe fn data(ctx: *const EvpCipherCtx) -> *mut EvpRc2Key {
    // SAFETY: the caller's contract.
    unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<EvpRc2Key>()
}

// ---------------------------------------------------------------------------------------------
// The context — `e_rc2.c:35-38`
// ---------------------------------------------------------------------------------------------

/// `EVP_RC2_KEY` — `e_rc2.c:35-38`. The effective bit count and the schedule.
pub struct EvpRc2Key {
    /// `int key_bits`.
    pub key_bits: c_int,
    /// `RC2_KEY ks`.
    pub ks: Rc2Key,
}

// ---------------------------------------------------------------------------------------------
// The mode callbacks — `e_rc2.c:42`'s `IMPLEMENT_BLOCK_CIPHER`
// ---------------------------------------------------------------------------------------------

/// `rc2_ecb_cipher` — `e_rc2.c:42`'s `BLOCK_CIPHER_func_ecb`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc2_ecb_cipher(
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
            RC2_ecb_encrypt(
                in_.add(i),
                out.add(i),
                ptr::addr_of_mut!((*dat).ks),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
        i += bl;
    }
    1
}

/// `rc2_cbc_cipher` — `e_rc2.c:42`'s `BLOCK_CIPHER_func_cbc`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc2_cbc_cipher(
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
            RC2_cbc_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            RC2_cbc_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                EVP_CIPHER_CTX_is_encrypting(ctx),
            )
        };
    }
    1
}

/// `rc2_cfb64_cipher` — `e_rc2.c:42`'s `BLOCK_CIPHER_func_cfb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc2_cfb64_cipher(
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
            RC2_cfb64_encrypt(
                in_,
                out,
                chunk as c_long,
                ptr::addr_of_mut!((*dat).ks),
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

/// `rc2_ofb64_cipher` — `e_rc2.c:42`'s `BLOCK_CIPHER_func_ofb` with `cbits == 64`.
///
/// # Safety
/// The `EVP_CIPHER::do_cipher` contract.
unsafe extern "C" fn rc2_ofb64_cipher(
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
            RC2_ofb64_encrypt(
                in_,
                out,
                EVP_MAXCHUNK as c_long,
                ptr::addr_of_mut!((*dat).ks),
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
            RC2_ofb64_encrypt(
                in_,
                out,
                inl as c_long,
                ptr::addr_of_mut!((*dat).ks),
                (*ctx).iv.as_mut_ptr(),
                &mut num,
            );
            EVP_CIPHER_CTX_set_num(ctx, num);
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The key, ASN.1 and control callbacks — `e_rc2.c:92-197`
// ---------------------------------------------------------------------------------------------

/// `rc2_init_key` — `e_rc2.c:92-98`.
///
/// # Safety
/// The `EVP_CIPHER::init` contract.
unsafe extern "C" fn rc2_init_key(
    ctx: *mut c_void,
    key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    let ctx = ctx.cast::<EvpCipherCtx>();
    // SAFETY: `ctx` is live per the contract.
    let dat = unsafe { data(ctx) };
    // SAFETY: `ctx` is live.
    let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    // SAFETY: `dat` is the context's own block and `key` is readable for `len` bytes.
    unsafe { RC2_set_key(ptr::addr_of_mut!((*dat).ks), len, key, (*dat).key_bits) };
    1
}

/// `rc2_meth_to_magic` — `e_rc2.c:100-114`.
///
/// # Safety
/// `e` must be a live `EVP_CIPHER_CTX`; its `ctrl` answers `EVP_CTRL_GET_RC2_KEY_BITS`.
unsafe fn rc2_meth_to_magic(e: *mut EvpCipherCtx) -> c_int {
    let mut i: c_int = 0;
    // SAFETY: `e` is live per the contract and `i` is a writable local.
    if unsafe { EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GET_RC2_KEY_BITS, 0, ptr::addr_of_mut!(i).cast()) }
        <= 0
    {
        return 0;
    }
    match i {
        128 => RC2_128_MAGIC,
        64 => RC2_64_MAGIC,
        40 => RC2_40_MAGIC,
        _ => 0,
    }
}

/// `rc2_magic_to_meth` — `e_rc2.c:116-128`.
unsafe fn rc2_magic_to_meth(i: c_int) -> c_int {
    match i {
        RC2_128_MAGIC => 128,
        RC2_64_MAGIC => 64,
        RC2_40_MAGIC => 40,
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::E_RC2_125) };
            0
        }
    }
}

/// `rc2_get_asn1_type_and_iv` — `e_rc2.c:130-156`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn rc2_get_asn1_type_and_iv(c: *mut c_void, type_: *mut c_void) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    let type_ = type_.cast::<Asn1Type>();
    let mut num: c_long = 0;
    let i: c_int = 0;
    let mut iv: [c_uchar; EVP_MAX_IV_LENGTH] = [0; EVP_MAX_IV_LENGTH];
    if !type_.is_null() {
        // SAFETY: `c` is live per the contract.
        let l = unsafe { EVP_CIPHER_CTX_get_iv_length(c) } as c_uint;
        // The authority asserts `l <= sizeof(iv)`; `EVP_MAX_IV_LENGTH` is the bound and the iv
        // length is checked by the caller.
        // SAFETY: `type_` is live; `iv` holds `EVP_MAX_IV_LENGTH` writable bytes and `l` is a
        // cipher IV length bounded by it.
        let got =
            unsafe { ASN1_TYPE_get_int_octetstring(type_, &mut num, iv.as_mut_ptr(), l as c_int) };
        if got != l as c_int {
            return -1;
        }
        // SAFETY: `num` is a plain integer and `rc2_magic_to_meth` only reads it.
        let key_bits = unsafe { rc2_magic_to_meth(num as c_int) };
        if key_bits == 0 {
            return -1;
        }
        if got > 0 {
            // SAFETY: `c` is live and `iv` is readable for `l` bytes; the direction is kept.
            if unsafe {
                EVP_CipherInit_ex(
                    c,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    iv.as_ptr(),
                    -1,
                )
            } == 0
            {
                return -1;
            }
        }
        // SAFETY: `c` is live; the control takes no pointer argument.
        if unsafe { EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_RC2_KEY_BITS, key_bits, ptr::null_mut()) } <= 0
            // SAFETY: `c` is live.
            || unsafe { EVP_CIPHER_CTX_set_key_length(c, key_bits / 8) } <= 0
        {
            return -1;
        }
    }
    i
}

/// `rc2_set_asn1_type_and_iv` — `e_rc2.c:158-169`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn rc2_set_asn1_type_and_iv(c: *mut c_void, type_: *mut c_void) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    let type_ = type_.cast::<Asn1Type>();
    let mut i: c_int = 0;
    if !type_.is_null() {
        // SAFETY: `c` is live per the contract.
        let num = unsafe { rc2_meth_to_magic(c) } as c_long;
        // SAFETY: `c` is live.
        let j = unsafe { EVP_CIPHER_CTX_get_iv_length(c) };
        // SAFETY: `type_` is live, `c` is live, and `oiv` is the context's own buffer of `j` bytes.
        i = unsafe { ASN1_TYPE_set_int_octetstring(type_, num, (*c).oiv.as_mut_ptr(), j) };
    }
    i
}

/// `rc2_ctrl` — `e_rc2.c:171-197`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn rc2_ctrl(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let c = c.cast::<EvpCipherCtx>();
    match type_ {
        EVP_CTRL_INIT => {
            // SAFETY: `c` is live per the contract.
            let kl = unsafe { EVP_CIPHER_CTX_get_key_length(c) };
            // SAFETY: `c` is live.
            let dat = unsafe { data(c) };
            // SAFETY: `dat` is the context's own block.
            unsafe { (*dat).key_bits = kl * 8 };
            1
        }
        EVP_CTRL_GET_RC2_KEY_BITS => {
            // SAFETY: `c` is live.
            let dat = unsafe { data(c) };
            // SAFETY: `ptr_` is the caller's `int *` per the command's contract.
            unsafe { *ptr_.cast::<c_int>() = (*dat).key_bits };
            1
        }
        EVP_CTRL_SET_RC2_KEY_BITS => {
            if arg > 0 {
                // SAFETY: `c` is live.
                let dat = unsafe { data(c) };
                // SAFETY: `dat` is the context's own block.
                unsafe { (*dat).key_bits = arg };
                return 1;
            }
            0
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
/// `const fn`. Every RC2 static carries the same ASN.1 pair and `ctrl`.
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

/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `rc2_set_asn1_type_and_iv`.
///
/// # Safety
/// The `EVP_CIPHER::set_asn1_parameters` contract.
unsafe extern "C" fn rc2_set_asn1_fn(c: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rc2_set_asn1_type_and_iv(c, type_) }
}

/// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)` as `rc2_get_asn1_type_and_iv`.
///
/// # Safety
/// The `EVP_CIPHER::get_asn1_parameters` contract.
unsafe extern "C" fn rc2_get_asn1_fn(c: *mut c_void, type_: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rc2_get_asn1_type_and_iv(c, type_) }
}

/// `int (*ctrl)(EVP_CIPHER_CTX *, int, int, void *)` as `rc2_ctrl`.
///
/// # Safety
/// The `EVP_CIPHER::ctrl` contract.
unsafe extern "C" fn rc2_ctrl_fn(
    c: *mut c_void,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { rc2_ctrl(c, type_, arg, ptr_) }
}

/// The shared flag word of the generic pack: `VARIABLE_LENGTH | CTRL_INIT` (`e_rc2.c:45`).
const RC2_BASE_FLAGS: c_ulong = EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT;

// `IMPLEMENT_BLOCK_CIPHER(rc2, ks, RC2, EVP_RC2_KEY, NID_rc2, 8, RC2_KEY_LENGTH, 8, 64,
//     EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT, rc2_init_key, NULL,
//     rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv, rc2_ctrl)` — `e_rc2.c:42-48`.

static RC2_CBC: StaticCipher = legacy_cipher(
    NID_rc2_cbc,
    8,
    RC2_KEY_LENGTH,
    8,
    RC2_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(rc2_init_key),
    Some(rc2_cbc_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);
static RC2_CFB64: StaticCipher = legacy_cipher(
    NID_rc2_cfb64,
    1,
    RC2_KEY_LENGTH,
    8,
    RC2_BASE_FLAGS | EVP_CIPH_CFB_MODE,
    Some(rc2_init_key),
    Some(rc2_cfb64_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);
static RC2_OFB: StaticCipher = legacy_cipher(
    NID_rc2_ofb64,
    1,
    RC2_KEY_LENGTH,
    8,
    RC2_BASE_FLAGS | EVP_CIPH_OFB_MODE,
    Some(rc2_init_key),
    Some(rc2_ofb64_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);
static RC2_ECB: StaticCipher = legacy_cipher(
    NID_rc2_ecb,
    8,
    RC2_KEY_LENGTH,
    0,
    RC2_BASE_FLAGS | EVP_CIPH_ECB_MODE,
    Some(rc2_init_key),
    Some(rc2_ecb_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);

// `r2_64_cbc_cipher` / `r2_40_cbc_cipher` — `e_rc2.c:52-80`.

static R2_64_CBC: StaticCipher = legacy_cipher(
    NID_rc2_64_cbc,
    8,
    8,
    8,
    RC2_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(rc2_init_key),
    Some(rc2_cbc_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);
static R2_40_CBC: StaticCipher = legacy_cipher(
    NID_rc2_40_cbc,
    8,
    5,
    8,
    RC2_BASE_FLAGS | EVP_CIPH_CBC_MODE,
    Some(rc2_init_key),
    Some(rc2_cbc_cipher),
    core::mem::size_of::<EvpRc2Key>() as c_int,
    Some(rc2_set_asn1_fn),
    Some(rc2_get_asn1_fn),
    Some(rc2_ctrl_fn),
);

// ---------------------------------------------------------------------------------------------
// The six accessors, in `legacy`-unit order.
// ---------------------------------------------------------------------------------------------

/// `const EVP_CIPHER *EVP_rc2_cbc(void)` — `e_rc2.c:42`'s `IMPLEMENT_BLOCK_CIPHER`.
#[no_mangle]
pub extern "C" fn EVP_rc2_cbc() -> *const EvpCipher {
    ptr::addr_of!(RC2_CBC.0)
}
/// `const EVP_CIPHER *EVP_rc2_cfb64(void)`.
#[no_mangle]
pub extern "C" fn EVP_rc2_cfb64() -> *const EvpCipher {
    ptr::addr_of!(RC2_CFB64.0)
}
/// `const EVP_CIPHER *EVP_rc2_ofb(void)`.
#[no_mangle]
pub extern "C" fn EVP_rc2_ofb() -> *const EvpCipher {
    ptr::addr_of!(RC2_OFB.0)
}
/// `const EVP_CIPHER *EVP_rc2_ecb(void)`.
#[no_mangle]
pub extern "C" fn EVP_rc2_ecb() -> *const EvpCipher {
    ptr::addr_of!(RC2_ECB.0)
}
/// `const EVP_CIPHER *EVP_rc2_64_cbc(void)` — `e_rc2.c:82-85`.
#[no_mangle]
pub extern "C" fn EVP_rc2_64_cbc() -> *const EvpCipher {
    ptr::addr_of!(R2_64_CBC.0)
}
/// `const EVP_CIPHER *EVP_rc2_40_cbc(void)` — `e_rc2.c:87-90`.
#[no_mangle]
pub extern "C" fn EVP_rc2_40_cbc() -> *const EvpCipher {
    ptr::addr_of!(R2_40_CBC.0)
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
        assert_eq!(fields(EVP_rc2_cbc()), (NID_rc2_cbc, 8, 16, 8, 1));
        assert_eq!(fields(EVP_rc2_cfb64()), (NID_rc2_cfb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_rc2_ofb()), (NID_rc2_ofb64, 1, 16, 8, 1));
        assert_eq!(fields(EVP_rc2_ecb()), (NID_rc2_ecb, 8, 16, 0, 1));
        assert_eq!(fields(EVP_rc2_64_cbc()), (NID_rc2_64_cbc, 8, 8, 8, 1));
        assert_eq!(fields(EVP_rc2_40_cbc()), (NID_rc2_40_cbc, 8, 5, 8, 1));
        assert_ne!(EVP_rc2_64_cbc(), EVP_rc2_40_cbc());
    }
}
