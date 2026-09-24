//! `crypto/ml_dsa/ml_dsa_hash.h` — the three SHAKE one-shot readers every unit includes.
//!
//! The header is a `static ossl_inline` block: `shake_xof`, `shake_xof_2` and `shake_xof_3`, each
//! an init/update/squeeze chain over a pre-fetched XOF. It is the one header shared by four units
//! (`ml_dsa_encoders.c`, `ml_dsa_key.c`, `ml_dsa_sample.c` and `ml_dsa_sign.c`), so like the three
//! layout headers it belongs to no unit and is transcribed once here rather than four times.
//!
//! The three bodies are the header's exactly, including that the `&&` chains short-circuit and that
//! the multi-part forms update in order.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::evp::digest::{
    EVP_DigestInit_ex2, EVP_DigestSqueeze, EVP_DigestUpdate, EvpMd, EvpMdCtx,
};

/// `shake_xof(ctx, md, in, in_len, out, out_len)` — `ml_dsa_hash.h:12-19`.
///
/// # Safety
/// `ctx` must be a live digest context, `md` a fetched XOF, `in_` readable for `in_len` bytes and
/// `out` writable for `out_len` bytes.
pub(crate) unsafe fn shake_xof(
    ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    in_: *const u8,
    in_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        (EVP_DigestInit_ex2(ctx, md, ptr::null()) == 1
            && EVP_DigestUpdate(ctx, in_.cast(), in_len) == 1
            && EVP_DigestSqueeze(ctx, out, out_len) == 1) as c_int
    }
}

/// `shake_xof_2(ctx, md, in1, in1_len, in2, in2_len, out, out_len)` — `ml_dsa_hash.h:21-29`.
///
/// # Safety
/// `ctx` must be a live digest context, `md` a fetched XOF, both inputs readable for their lengths
/// and `out` writable for `out_len` bytes.
#[allow(clippy::too_many_arguments)] // the header's own arity: two inputs plus out
pub(crate) unsafe fn shake_xof_2(
    ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    in1: *const u8,
    in1_len: usize,
    in2: *const u8,
    in2_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        (EVP_DigestInit_ex2(ctx, md, ptr::null()) == 1
            && EVP_DigestUpdate(ctx, in1.cast(), in1_len) == 1
            && EVP_DigestUpdate(ctx, in2.cast(), in2_len) == 1
            && EVP_DigestSqueeze(ctx, out, out_len) == 1) as c_int
    }
}

/// `shake_xof_3(ctx, md, in1, in1_len, in2, in2_len, in3, in3_len, out, out_len)` —
/// `ml_dsa_hash.h:31-41`.
///
/// # Safety
/// `ctx` must be a live digest context, `md` a fetched XOF, all three inputs readable for their
/// lengths and `out` writable for `out_len` bytes.
#[allow(clippy::too_many_arguments)] // the header's own arity: three inputs plus out
pub(crate) unsafe fn shake_xof_3(
    ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    in1: *const u8,
    in1_len: usize,
    in2: *const u8,
    in2_len: usize,
    in3: *const u8,
    in3_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        (EVP_DigestInit_ex2(ctx, md, ptr::null()) == 1
            && EVP_DigestUpdate(ctx, in1.cast(), in1_len) == 1
            && EVP_DigestUpdate(ctx, in2.cast(), in2_len) == 1
            && EVP_DigestUpdate(ctx, in3.cast(), in3_len) == 1
            && EVP_DigestSqueeze(ctx, out, out_len) == 1) as c_int
    }
}
