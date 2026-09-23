//! Phase 8 — `crypto/slh_dsa/slh_hash.c` and `slh_hash.h`: the six hash primitives of FIPS 205
//! in their SHAKE and SHA-2 forms.
//!
//! `slh_hash.c` is 300 lines and defines the eleven `static` functions behind the two method
//! tables of `ossl_slh_get_hash_fn` (`:283-300`): `H_MSG`, `PRF`, `PRF_MSG`, `F`, `H` and `T`
//! (`slh_hash.h:26-54`), once for SHAKE (`:64-134`) and once for SHA-2 (`:152-281`).
//!
//! ## The SHAKE arm is one XOF reader with three or four inputs
//!
//! Every SHAKE primitive is `xof_digest_3`/`xof_digest_4` (`:35-61`) over `ctx->md_ctx`, which is
//! a `SHAKE-256` context: `EVP_DigestInit_ex2(ctx, NULL, NULL)` to restart, the inputs, and
//! `EVP_DigestFinalXOF(ctx, out, out_len)`. The address length it feeds is `SLH_ADRS_SIZE` (32,
//! the uncompressed form), and the output length is `n` for everything but `H_MSG`, which is `m`.
//!
//! ## The SHA-2 arm is `do_hash` plus two one-offs
//!
//! `PRF`, `F`, `H` and `T` all funnel through `do_hash` (`:223-237`), which hashes
//! `pk_seed || zeros(b - n) || adrs[22] || m` with the context's own digest and truncates the
//! result to `n`. The `b - n` zero run is the FIPS 205 `H`/`T` padding: 64 byes for category 1
//! and 128 for categories 3 and 5 (`slh_params.h:16`, `slh_params.c:15`), so the *same* helper
//! serves `PRF`/`F` (always bound 1, `:246,255`) and `H`/`T` (the parameter set's own bound,
//! `:270,280`). `H_MSG` (`:152-175`) is `PKCS1_MGF1` over a `SHA-512`-or-`SHA-256` digest of
//! `r || pk_seed || pk_root || msg`, and `PRF_MSG` (`:177-216`) is a lazy-initialised HMAC whose
//! key is `SK_PRF` and whose message is `opt_rand || msg`, truncated to `n`.
//!
//! ## The scratch buffer is the hash context's, not this frame's
//!
//! `do_hash` writes its digest into `hctx->scratch` (`:230`) and reads it back truncated to `n`
//! (`:235`), rather than using a stack copy, so that the intermediate lives in one place and is
//! erased when the context is freed (`slh_dsa_local.h:57-64`). `H` keeps its two concatenated
//! children in `scratch + MAX_DIGEST_SIZE` (`:263`). Both offsets are reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The authority's C signatures carry the algorithm's parameters rather than a context struct, so
// several of them exceed clippy's seven-argument threshold. They are transcribed verbatim.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::evp::digest::{
    EVP_DigestFinalXOF, EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_get0_name,
    EVP_MD_get_size,
};
use crate::evp::mac::{EVP_MAC_final, EVP_MAC_init, EVP_MAC_update};
use crate::packet::{WPACKET_memcpy, Wpacket};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OsslParam};
use crate::rsa::PKCS1_MGF1;
use crate::runtime::mem::OPENSSL_cleanse;

use super::params::OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1;
use super::{SlhDsaHashCtx, MAX_DIGEST_SIZE, SLH_MAX_N};

/// `OSSL_MAC_PARAM_DIGEST` — `include/openssl/core_names.h`.
const OSSL_MAC_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_MAC_PARAM_PROPERTIES` — `include/openssl/core_names.h`.
const OSSL_MAC_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `SLH_HASH_FUNC` — `slh_hash.h:55-62`, the six primitives in declaration order.
#[repr(C)]
pub(crate) struct SlhHashFunc {
    pub(crate) h_msg: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) prf: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) prf_msg: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        usize,
        *mut Wpacket,
    ) -> c_int,
    pub(crate) f: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) h: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        *const u8,
        *mut u8,
        usize,
    ) -> c_int,
    pub(crate) t: unsafe extern "C" fn(
        *mut SlhDsaHashCtx,
        *const u8,
        *const u8,
        *const u8,
        usize,
        *mut u8,
        usize,
    ) -> c_int,
}

/// `static ossl_inline int xof_digest_3(...)` — `slh_hash.c:35-46`.
///
/// # Safety
/// The context is live and every input/output span is as the length arguments say.
unsafe fn xof_digest_3(
    ctx: *mut crate::evp::digest::EvpMdCtx,
    in1: *const u8,
    in1_len: usize,
    in2: *const u8,
    in2_len: usize,
    in3: *const u8,
    in3_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        c_int::from(
            EVP_DigestInit_ex2(ctx, ptr::null(), ptr::null()) == 1
                && EVP_DigestUpdate(ctx, in1.cast::<c_void>(), in1_len) == 1
                && EVP_DigestUpdate(ctx, in2.cast::<c_void>(), in2_len) == 1
                && EVP_DigestUpdate(ctx, in3.cast::<c_void>(), in3_len) == 1
                && EVP_DigestFinalXOF(ctx, out, out_len) == 1,
        )
    }
}

/// `static ossl_inline int xof_digest_4(...)` — `slh_hash.c:48-61`.
///
/// # Safety
/// The context is live and every input/output span is as the length arguments say.
unsafe fn xof_digest_4(
    ctx: *mut crate::evp::digest::EvpMdCtx,
    in1: *const u8,
    in1_len: usize,
    in2: *const u8,
    in2_len: usize,
    in3: *const u8,
    in3_len: usize,
    in4: *const u8,
    in4_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        c_int::from(
            EVP_DigestInit_ex2(ctx, ptr::null(), ptr::null()) == 1
                && EVP_DigestUpdate(ctx, in1.cast::<c_void>(), in1_len) == 1
                && EVP_DigestUpdate(ctx, in2.cast::<c_void>(), in2_len) == 1
                && EVP_DigestUpdate(ctx, in3.cast::<c_void>(), in3_len) == 1
                && EVP_DigestUpdate(ctx, in4.cast::<c_void>(), in4_len) == 1
                && EVP_DigestFinalXOF(ctx, out, out_len) == 1,
        )
    }
}

// --- the SHAKE primitives — `slh_hash.c:63-134` ---

/// `static int slh_hmsg_shake(...)` — `slh_hash.c:64-76`.
unsafe extern "C" fn slh_hmsg_shake(
    ctx: *mut SlhDsaHashCtx,
    r: *const u8,
    pk_seed: *const u8,
    pk_root: *const u8,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let _ = out_len;
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let params = (*(*ctx).key).params;
        let m = (*params).m as usize;
        let n = (*params).n as usize;
        xof_digest_4(
            (*ctx).md_ctx,
            r,
            n,
            pk_seed,
            n,
            pk_root,
            n,
            msg,
            msg_len,
            out,
            m,
        )
    }
}

/// `static int slh_prf_shake(...)` — `slh_hash.c:78-88`.
unsafe extern "C" fn slh_prf_shake(
    ctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    sk_seed: *const u8,
    adrs: *const u8,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let params = (*(*ctx).key).params;
        let n = (*params).n as usize;
        let _ = out_len;
        xof_digest_3(
            (*ctx).md_ctx,
            pk_seed,
            n,
            adrs,
            super::adrs::SLH_ADRS_SIZE,
            sk_seed,
            n,
            out,
            n,
        )
    }
}

/// `static int slh_prf_msg_shake(...)` — `slh_hash.c:90-104`.
unsafe extern "C" fn slh_prf_msg_shake(
    ctx: *mut SlhDsaHashCtx,
    sk_prf: *const u8,
    opt_rand: *const u8,
    msg: *const u8,
    msg_len: usize,
    pkt: *mut Wpacket,
) -> c_int {
    let mut out = [0u8; SLH_MAX_N];
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    let ret = unsafe {
        let params = (*(*ctx).key).params;
        let n = (*params).n as usize;
        xof_digest_3(
            (*ctx).md_ctx,
            sk_prf,
            n,
            opt_rand,
            n,
            msg,
            msg_len,
            out.as_mut_ptr(),
            n,
        ) != 0
            && WPACKET_memcpy(pkt, out.as_ptr().cast::<c_void>(), n) != 0
    };
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast::<c_void>(), out.len()) };
    c_int::from(ret)
}

/// `static int slh_f_shake(...)` — `slh_hash.c:106-114`.
unsafe extern "C" fn slh_f_shake(
    ctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    m1: *const u8,
    m1_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let params = (*(*ctx).key).params;
        let n = (*params).n as usize;
        let _ = out_len;
        xof_digest_3(
            (*ctx).md_ctx,
            pk_seed,
            n,
            adrs,
            super::adrs::SLH_ADRS_SIZE,
            m1,
            m1_len,
            out,
            n,
        )
    }
}

/// `static int slh_h_shake(...)` — `slh_hash.c:116-124`.
unsafe extern "C" fn slh_h_shake(
    ctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    m1: *const u8,
    m2: *const u8,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let params = (*(*ctx).key).params;
        let n = (*params).n as usize;
        let _ = out_len;
        xof_digest_4(
            (*ctx).md_ctx,
            pk_seed,
            n,
            adrs,
            super::adrs::SLH_ADRS_SIZE,
            m1,
            n,
            m2,
            n,
            out,
            n,
        )
    }
}

/// `static int slh_t_shake(...)` — `slh_hash.c:126-134`.
unsafe extern "C" fn slh_t_shake(
    ctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    ml: *const u8,
    ml_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let params = (*(*ctx).key).params;
        let n = (*params).n as usize;
        let _ = out_len;
        xof_digest_3(
            (*ctx).md_ctx,
            pk_seed,
            n,
            adrs,
            super::adrs::SLH_ADRS_SIZE,
            ml,
            ml_len,
            out,
            n,
        )
    }
}

// --- the SHA-2 primitives — `slh_hash.c:136-281` ---

/// `static ossl_inline int digest_4(...)` — `slh_hash.c:136-148`.
///
/// # Safety
/// The context is live and every span is as the length arguments say.
unsafe fn digest_4(
    ctx: *mut crate::evp::digest::EvpMdCtx,
    in1: *const u8,
    in1_len: usize,
    in2: *const u8,
    in2_len: usize,
    in3: *const u8,
    in3_len: usize,
    in4: *const u8,
    in4_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        c_int::from(
            EVP_DigestInit_ex2(ctx, ptr::null(), ptr::null()) == 1
                && EVP_DigestUpdate(ctx, in1.cast::<c_void>(), in1_len) == 1
                && EVP_DigestUpdate(ctx, in2.cast::<c_void>(), in2_len) == 1
                && EVP_DigestUpdate(ctx, in3.cast::<c_void>(), in3_len) == 1
                && EVP_DigestUpdate(ctx, in4.cast::<c_void>(), in4_len) == 1
                && EVP_DigestFinal_ex(ctx, out, ptr::null_mut()) == 1,
        )
    }
}

/// `static int slh_hmsg_sha2(...)` — `slh_hash.c:152-175`.
unsafe extern "C" fn slh_hmsg_sha2(
    hctx: *mut SlhDsaHashCtx,
    r: *const u8,
    pk_seed: *const u8,
    pk_root: *const u8,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let _ = out_len;
    let mut seed = [0u8; 2 * SLH_MAX_N + MAX_DIGEST_SIZE];
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    let ret = unsafe {
        let params = (*(*hctx).key).params;
        let m = (*params).m as usize;
        let n = (*params).n as usize;
        let md_big = (*(*hctx).key).md_big;
        let sz = EVP_MD_get_size(md_big);
        if sz <= 0 {
            return 0;
        }
        let seed_len = sz as usize + 2 * n;
        ptr::copy_nonoverlapping(r, seed.as_mut_ptr(), n);
        ptr::copy_nonoverlapping(pk_seed, seed.as_mut_ptr().add(n), n);
        c_int::from(
            digest_4(
                (*hctx).md_big_ctx,
                r,
                n,
                pk_seed,
                n,
                pk_root,
                n,
                msg,
                msg_len,
                seed.as_mut_ptr().add(2 * n),
            ) != 0
                && {
                    let _ = out_len;
                    PKCS1_MGF1(out, m as c_long, seed.as_ptr(), seed_len as c_long, md_big) == 0
                },
        )
    };
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(seed.as_mut_ptr().cast::<c_void>(), seed.len()) };
    ret
}

/// `static int slh_prf_msg_sha2(...)` — `slh_hash.c:177-216`.
unsafe extern "C" fn slh_prf_msg_sha2(
    hctx: *mut SlhDsaHashCtx,
    sk_prf: *const u8,
    opt_rand: *const u8,
    msg: *const u8,
    msg_len: usize,
    pkt: *mut Wpacket,
) -> c_int {
    let mut mac = [0u8; MAX_DIGEST_SIZE];
    let mut p: *const OsslParam = ptr::null();
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    let ret = unsafe {
        let key = (*hctx).key;
        let mctx = (*hctx).hmac_ctx;
        let prms = (*key).params;
        let n = (*prms).n as usize;
        let mut params = [
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
        ];

        if (*hctx).hmac_digest_used == 0 {
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST,
                EVP_MD_get0_name((*key).md_big).cast_mut(),
                0,
            );
            if !(*key).propq.is_null() {
                params[1] =
                    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES, (*key).propq, 0);
            }
            p = params.as_ptr();
            (*hctx).hmac_digest_used = 1;
        }

        c_int::from(
            EVP_MAC_init(mctx, sk_prf, n, p) == 1
                && EVP_MAC_update(mctx, opt_rand, n) == 1
                && EVP_MAC_update(mctx, msg, msg_len) == 1
                && EVP_MAC_final(mctx, mac.as_mut_ptr(), ptr::null_mut(), mac.len()) == 1
                && WPACKET_memcpy(pkt, mac.as_ptr().cast::<c_void>(), n) != 0,
        )
    };
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(mac.as_mut_ptr().cast::<c_void>(), mac.len()) };
    ret
}

/// `static ossl_inline int do_hash(...)` — `slh_hash.c:223-237`.
///
/// # Safety
/// The context is live; every span is as the length arguments say.
unsafe fn do_hash(
    hctx: *mut SlhDsaHashCtx,
    ctx: *mut crate::evp::digest::EvpMdCtx,
    n: usize,
    pk_seed: *const u8,
    adrs: *const u8,
    m: *const u8,
    m_len: usize,
    b: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let zeros = [0u8; 128];
    let _ = out_len;
    // SAFETY: `hctx` is live; `zeros` has `b - n` bytes available for every (b, n) this crate
    // builds, and `digest` points into the context's own scratch.
    unsafe {
        let digest = (*hctx).scratch.as_mut_ptr();
        let ret = digest_4(
            ctx,
            pk_seed,
            n,
            zeros.as_ptr(),
            b - n,
            adrs,
            super::adrs::SLH_ADRSC_SIZE,
            m,
            m_len,
            digest,
        );
        ptr::copy_nonoverlapping(digest, out, n);
        ret
    }
}

/// `static int slh_prf_sha2(...)` — `slh_hash.c:239-248`.
unsafe extern "C" fn slh_prf_sha2(
    hctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    sk_seed: *const u8,
    adrs: *const u8,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let n = (*(*(*hctx).key).params).n as usize;
        do_hash(
            hctx,
            (*hctx).md_ctx,
            n,
            pk_seed,
            adrs,
            sk_seed,
            n,
            OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1,
            out,
            out_len,
        )
    }
}

/// `static int slh_f_sha2(...)` — `slh_hash.c:250-256`.
unsafe extern "C" fn slh_f_sha2(
    hctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    m1: *const u8,
    m1_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let n = (*(*(*hctx).key).params).n as usize;
        do_hash(
            hctx,
            (*hctx).md_ctx,
            n,
            pk_seed,
            adrs,
            m1,
            m1_len,
            OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1,
            out,
            out_len,
        )
    }
}

/// `static int slh_h_sha2(...)` — `slh_hash.c:258-271`.
unsafe extern "C" fn slh_h_sha2(
    hctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    m1: *const u8,
    m2: *const u8,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let prms = (*(*hctx).key).params;
        let n = (*prms).n as usize;
        let m = (*hctx).scratch.as_mut_ptr().add(MAX_DIGEST_SIZE);
        ptr::copy_nonoverlapping(m1, m, n);
        ptr::copy_nonoverlapping(m2, m.add(n), n);
        do_hash(
            hctx,
            (*hctx).md_big_ctx,
            n,
            pk_seed,
            adrs,
            m,
            2 * n,
            (*prms).sha2_h_and_t_bound,
            out,
            out_len,
        )
    }
}

/// `static int slh_t_sha2(...)` — `slh_hash.c:273-281`.
unsafe extern "C" fn slh_t_sha2(
    hctx: *mut SlhDsaHashCtx,
    pk_seed: *const u8,
    adrs: *const u8,
    ml: *const u8,
    ml_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `hctx` is live and its `key`/`params` are the caller's.
    unsafe {
        let prms = (*(*hctx).key).params;
        do_hash(
            hctx,
            (*hctx).md_big_ctx,
            (*prms).n as usize,
            pk_seed,
            adrs,
            ml,
            ml_len,
            (*prms).sha2_h_and_t_bound,
            out,
            out_len,
        )
    }
}

/// `const SLH_HASH_FUNC *ossl_slh_get_hash_fn(int is_shake)` — `slh_hash.c:283-300`.
///
/// `is_shake != 0` answers the SHAKE table, zero the SHA-2 one — the authority's
/// `methods[is_shake ? 0 : 1]`.
pub(crate) unsafe fn ossl_slh_get_hash_fn(is_shake: c_int) -> *const SlhHashFunc {
    const METHODS: [SlhHashFunc; 2] = [
        SlhHashFunc {
            h_msg: slh_hmsg_shake,
            prf: slh_prf_shake,
            prf_msg: slh_prf_msg_shake,
            f: slh_f_shake,
            h: slh_h_shake,
            t: slh_t_shake,
        },
        SlhHashFunc {
            h_msg: slh_hmsg_sha2,
            prf: slh_prf_sha2,
            prf_msg: slh_prf_msg_sha2,
            f: slh_f_sha2,
            h: slh_h_sha2,
            t: slh_t_sha2,
        },
    ];
    if is_shake != 0 {
        &METHODS[0]
    } else {
        &METHODS[1]
    }
}
