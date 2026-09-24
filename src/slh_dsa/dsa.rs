//! Phase 8 — `crypto/slh_dsa/slh_dsa.c`: the SLH-DSA sign and verify algorithms
//! (FIPS 205 Section 9) and the pure-message encoding (Section 10).
//!
//! `slh_dsa.c` is 393 lines and defines the two entry points the provider signature unit calls —
//! `ossl_slh_dsa_sign` (Algorithm 22) and `ossl_slh_dsa_verify` (Algorithm 24) — over the two
//! internal drivers `slh_sign_internal`/`slh_verify_internal` (Algorithms 19 and 20), the
//! `msg_encode` pure-encoding helper (Section 10.2) and `get_tree_ids` (Algorithms 19 steps
//! 7-10).
//!
//! ## `opt_rand` is `PK_SEED` when the caller has none
//!
//! `slh_sign_internal` sets `opt_rand = pk_seed` when it is passed NULL (`:92-93`), so a
//! deterministic signature is the *same* code path with the randomness equal to the public seed.
//! The provider unit's `deterministic` parameter selects between passing its own `add_random` and
//! passing NULL; the substitution lives here.
//!
//! ## `r` and `sig_fors` are `WPACKET` cursors, not copies
//!
//! `r` is the packet's cursor *before* `PRF_MSG` writes the `n` random bytes (`:97`), and
//! `sig_fors` is the cursor before `fors_sign` (`:112`). Both are re-read after the write to seed
//! `H_MSG` and to re-init a `PACKET` over the FORS signature (`:100`, `:116`), so the signature is
//! consumed from the bytes just produced rather than from a second buffer.
//!
//! ## `msg_encode`'s two encodings
//!
//! `encode == 0` returns the raw message (`:250-254`); otherwise the pure encoding
//! `00 || ctx_len || ctx || msg` is written into `tmp` when it fits and into an allocation
//! otherwise (`:259-282`), and the caller frees that allocation only when it is neither the
//! message nor the stack buffer (`:307-312`). The nested tests are transcribed rather than
//! simplified, because the "is it ours to free" answer is exactly what they compute.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The authority's C signatures carry the algorithm's parameters rather than a context struct, so
// several of them exceed clippy's seven-argument threshold. They are transcribed verbatim.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::packet::{
    Packet, WPACKET_finish, WPACKET_get_curr, WPACKET_init_static_len, WPACKET_memcpy,
    WPACKET_put_bytes_u8, Wpacket,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc, OPENSSL_cleanse};

use super::adrs::SLH_ADRS_TYPE_FORS_TREE;
use super::fors::{ossl_slh_fors_pk_from_sig, ossl_slh_fors_sign};
use super::hypertree::{ossl_slh_ht_sign, ossl_slh_ht_verify};
use super::{SlhDsaHashCtx, SlhDsaKey, SLH_DSA_MAX_CONTEXT_STRING_LEN, SLH_MAX_N};

/// `SLH_MAX_M` — `slh_dsa.c:17`, the largest `H_MSG` output (see `slh_params.c`).
const SLH_MAX_M: usize = 49;
/// `MD_LEN(params)` — `slh_dsa.c:19`, `(k * a + 7) / 8`.
///
/// # Safety
/// `params` is live.
unsafe fn md_len(params: *const super::params::SlhDsaParams) -> usize {
    // SAFETY: `params` is live per the contract.
    unsafe { (((*params).k * (*params).a + 7) >> 3) as usize }
}

/// `static int slh_sign_internal(...)` — `slh_dsa.c:43-134`.
///
/// # Safety
/// `hctx` is live; `sig`/`sig_len`/`sig_size` are as the caller's contract.
unsafe fn slh_sign_internal(
    hctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    msg_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
    sig_size: usize,
    opt_rand: *const u8,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `hctx` is live per the contract.
    let priv_ = unsafe { (*hctx).key };
    // SAFETY: `priv_` is live and its method tables/params are the authority's.
    let (prf_msg, h_msg, zero, set_tree_address, set_type_and_clear, set_keypair_address, params) = unsafe {
        (
            (*(*priv_).hash_func).prf_msg,
            (*(*priv_).hash_func).h_msg,
            (*(*priv_).adrs_func).zero,
            (*(*priv_).adrs_func).set_tree_address,
            (*(*priv_).adrs_func).set_type_and_clear,
            (*(*priv_).adrs_func).set_keypair_address,
            (*priv_).params,
        )
    };
    let sig_len_expected = {
        // SAFETY: `params` is live; the read is one integer field.
        unsafe { (*params).sig_len as usize }
    };
    let mut m_digest = [0u8; SLH_MAX_M];
    // SAFETY: `params` is live.
    let md_len = unsafe { md_len(params) };
    let mut pk_fors = [0u8; SLH_MAX_N];
    let mut tree_id: u64 = 0;
    let mut leaf_id: u32 = 0;
    let mut adrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `Wpacket` is a packet builder of integers and pointers only, and the value is
    // initialised by the `WPACKET_init_static_len` immediately below before it is read.
    let mut w_packet = unsafe { core::mem::zeroed::<Wpacket>() };
    let wpkt = &mut w_packet;
    let mut opt_rand = opt_rand;

    if sig.is_null() {
        // SAFETY: `sig_len` is writable per the caller's contract.
        unsafe { *sig_len = sig_len_expected };
        return 1;
    }

    if sig_size < sig_len_expected {
        let mut buf = [0 as c_char; 128];
        // SAFETY: `buf` is writable for its length.
        unsafe {
            BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"is %zu, should be at least %zu".as_ptr(),
                sig_size,
                sig_len_expected,
            );
            raise_site_data(&err_sites::SLH_DSA_74, buf.as_ptr());
        }
        return 0;
    }
    /* Exit if private key is not set. */
    // SAFETY: `priv_` is the caller's live key.
    if unsafe { (*priv_).has_priv } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SLH_DSA_80) };
        return 0;
    }

    // SAFETY: `wpkt` is a live local; `sig` is writable for `sig_len_expected`.
    if unsafe { WPACKET_init_static_len(wpkt, sig, sig_len_expected, 0) } == 0 {
        return 0;
    }
    // SAFETY: the cursor is over `m_digest` for `params->m` bytes.
    let Some(mut rpkt) = (unsafe { Packet::buf_init(m_digest.as_ptr(), (*params).m as usize) })
    else {
        // SAFETY: the authority's `err:` label.
        unsafe {
            if WPACKET_finish(wpkt) == 0 {
                ret = 0;
            }
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    };

    // SAFETY: `priv_` is live with `params` set, which both accessors read through.
    let (pk_seed, sk_seed) = unsafe { (SlhDsaKey::pk_seed(priv_), SlhDsaKey::sk_seed(priv_)) };

    if opt_rand.is_null() {
        opt_rand = pk_seed;
    }

    // SAFETY: `adrs` is writable for its own size.
    unsafe { zero(adrs.as_mut_ptr()) };
    /* Calculate the randomness value r, and output it to the SLH-DSA signature. */
    // SAFETY: `wpkt` is live and `r` is a live local.
    let r = unsafe { WPACKET_get_curr(wpkt) };
    // SAFETY: `hctx` is live, `wpkt` is the live builder and each pointer is as the method
    // table's own signature says.
    let body_ok = unsafe {
        prf_msg(hctx, SlhDsaKey::sk_prf(priv_), opt_rand, msg, msg_len, wpkt) != 0
            && h_msg(
                hctx,
                r,
                pk_seed,
                SlhDsaKey::pk_root(priv_),
                msg,
                msg_len,
                m_digest.as_mut_ptr(),
                m_digest.len(),
            ) != 0
    };
    let md = if body_ok {
        // SAFETY: `rpkt` is a live cursor over `m_digest`.
        unsafe { rpkt.get_bytes(md_len) }
    } else {
        None
    };
    let ids_ok = md.is_some()
        // SAFETY: `rpkt` is a live cursor; the two out-parameters are this frame's.
        && unsafe { get_tree_ids(&mut rpkt, params, &mut tree_id, &mut leaf_id) } != 0;

    let Some(md) = md else {
        // SAFETY: the authority's `err:` label.
        unsafe {
            if WPACKET_finish(wpkt) == 0 {
                ret = 0;
            }
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    };
    if !ids_ok {
        // SAFETY: the authority's `err:` label.
        unsafe {
            if WPACKET_finish(wpkt) == 0 {
                ret = 0;
            }
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    }

    // SAFETY: `adrs` is writable for its own size.
    unsafe {
        set_tree_address(adrs.as_mut_ptr(), tree_id);
        set_type_and_clear(adrs.as_mut_ptr(), SLH_ADRS_TYPE_FORS_TREE);
        set_keypair_address(adrs.as_mut_ptr(), leaf_id);
    }

    // SAFETY: `sig_fors` is a `WPACKET` cursor, a live local.
    let sig_fors = unsafe { WPACKET_get_curr(wpkt) };
    // SAFETY: the three callees' own contracts; `wpkt` is the caller's builder.
    let ok =
        unsafe { ossl_slh_fors_sign(hctx, md, sk_seed, pk_seed, adrs.as_mut_ptr(), wpkt) != 0 };
    // SAFETY: `sig_fors` points into `wpkt`'s buffer; the span is the FORS signature just written.
    let sig_fors_len = unsafe { WPACKET_get_curr(wpkt).offset_from(sig_fors) } as usize;
    let mut rpkt2 = if ok {
        // SAFETY: `sig_fors` points into `wpkt`'s buffer for `sig_fors_len` bytes.
        unsafe { Packet::buf_init(sig_fors, sig_fors_len) }
    } else {
        None
    };
    if let Some(r) = rpkt2.as_mut() {
        // SAFETY: the two callees' own contracts.
        ret = unsafe {
            c_int::from(
                ossl_slh_fors_pk_from_sig(
                    hctx,
                    r,
                    md,
                    pk_seed,
                    adrs.as_mut_ptr(),
                    pk_fors.as_mut_ptr(),
                    pk_fors.len(),
                ) != 0
                    && ossl_slh_ht_sign(
                        hctx,
                        pk_fors.as_ptr(),
                        sk_seed,
                        pk_seed,
                        tree_id,
                        leaf_id,
                        wpkt,
                    ) != 0,
            )
        };
    }
    /* The authority's `err:` label. */
    // SAFETY: `wpkt` is live; both buffers are this frame's.
    unsafe {
        if WPACKET_finish(wpkt) == 0 {
            ret = 0;
        }
        OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
        OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
    }
    if ret != 0 {
        // SAFETY: `sig_len` is writable per the caller's contract.
        unsafe { *sig_len = sig_len_expected };
    } else {
        /* Erase any partial signature output. */
        // SAFETY: `sig` is writable for `sig_len_expected` per the guard above.
        unsafe { OPENSSL_cleanse(sig.cast::<c_void>(), sig_len_expected) };
    }
    ret
}

/// `static int slh_verify_internal(...)` — `slh_dsa.c:153-219`.
///
/// # Safety
/// `hctx` is live; `sig` is readable for `sig_len`.
unsafe fn slh_verify_internal(
    hctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `hctx` is live per the contract.
    let pub_ = unsafe { (*hctx).key };
    // SAFETY: `pub_` is live and its method tables/params are the authority's.
    let (h_msg, zero, set_tree_address, set_type_and_clear, set_keypair_address, params) = unsafe {
        (
            (*(*pub_).hash_func).h_msg,
            (*(*pub_).adrs_func).zero,
            (*(*pub_).adrs_func).set_tree_address,
            (*(*pub_).adrs_func).set_type_and_clear,
            (*(*pub_).adrs_func).set_keypair_address,
            (*pub_).params,
        )
    };
    let n = {
        // SAFETY: `params` is live; the read is one integer field.
        unsafe { (*params).n as usize }
    };
    let mut m_digest = [0u8; SLH_MAX_M];
    // SAFETY: `params` is live.
    let md_len = unsafe { md_len(params) };
    let mut pk_fors = [0u8; SLH_MAX_N];
    let mut tree_id: u64 = 0;
    let mut leaf_id: u32 = 0;
    let mut adrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];

    /* Exit if public key is not set. */
    // SAFETY: `pub_` is the caller's live key.
    if unsafe { (*pub_).pub_ }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SLH_DSA_177) };
        return 0;
    }

    /* Exit if signature is invalid size. */
    // SAFETY: `params` is live; the read is one integer field.
    if sig_len != unsafe { (*params).sig_len as usize } {
        return 0;
    }
    // SAFETY: the cursor is over `sig` for `sig_len` bytes.
    let Some(mut sig_rpkt) = (unsafe { Packet::buf_init(sig, sig_len) }) else {
        return 0;
    };
    // SAFETY: the cursor is a live local with `n` bytes, or this refuses.
    let Some(r) = (unsafe { sig_rpkt.get_bytes(n) }) else {
        return 0;
    };

    // SAFETY: `adrs` is writable for its own size.
    unsafe { zero(adrs.as_mut_ptr()) };

    // SAFETY: `pub_` is live with `params` set, which both accessors read through.
    let (pk_seed, pk_root) = unsafe { (SlhDsaKey::pk_seed(pub_), SlhDsaKey::pk_root(pub_)) };

    // SAFETY: the authority's `H_MSG`; every span is as the lengths say.
    if unsafe {
        h_msg(
            hctx,
            r,
            pk_seed,
            pk_root,
            msg,
            msg_len,
            m_digest.as_mut_ptr(),
            m_digest.len(),
        )
    } == 0
    {
        // SAFETY: the authority's `err:` label.
        unsafe {
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    }

    // SAFETY: the second cursor is over `m_digest` for its whole length.
    let Some(mut m_digest_rpkt) = (unsafe { Packet::buf_init(m_digest.as_ptr(), m_digest.len()) })
    else {
        // SAFETY: the authority's `err:` label.
        unsafe {
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    };
    // SAFETY: the cursor is a live local.
    let md = unsafe { m_digest_rpkt.get_bytes(md_len) };
    let ids_ok = md.is_some()
        // SAFETY: the cursor is live; the two out-parameters are this frame's.
        && unsafe { get_tree_ids(&mut m_digest_rpkt, params, &mut tree_id, &mut leaf_id) } != 0;
    let Some(md) = md else {
        // SAFETY: the authority's `err:` label.
        unsafe {
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    };
    if !ids_ok {
        // SAFETY: the authority's `err:` label.
        unsafe {
            OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
            OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
        }
        return ret;
    }

    // SAFETY: `adrs` is writable for its own size.
    unsafe {
        set_tree_address(adrs.as_mut_ptr(), tree_id);
        set_type_and_clear(adrs.as_mut_ptr(), SLH_ADRS_TYPE_FORS_TREE);
        set_keypair_address(adrs.as_mut_ptr(), leaf_id);
    }
    // SAFETY: the two callees' own contracts.
    ret = unsafe {
        c_int::from(
            ossl_slh_fors_pk_from_sig(
                hctx,
                &mut sig_rpkt,
                md,
                pk_seed,
                adrs.as_mut_ptr(),
                pk_fors.as_mut_ptr(),
                pk_fors.len(),
            ) != 0
                && ossl_slh_ht_verify(
                    hctx,
                    pk_fors.as_ptr(),
                    &mut sig_rpkt,
                    pk_seed,
                    tree_id,
                    leaf_id,
                    pk_root,
                ) != 0
                && sig_rpkt.remaining() == 0,
        )
    };
    /* The authority's `err:` label. */
    // SAFETY: two local buffers.
    unsafe {
        OPENSSL_cleanse(m_digest.as_mut_ptr().cast(), m_digest.len());
        OPENSSL_cleanse(pk_fors.as_mut_ptr().cast(), pk_fors.len());
    }
    ret
}

/// `static uint8_t *msg_encode(const uint8_t *msg, size_t msg_len, const uint8_t *ctx,`
/// `size_t ctx_len, int encode, uint8_t *tmp, size_t tmp_len, size_t *out_len)` —
/// `slh_dsa.c:242-283`.
///
/// # Safety
/// `msg` is readable for `msg_len`, `ctx` for `ctx_len`; `tmp` is writable for `tmp_len`;
/// `out_len` is writable.
unsafe fn msg_encode(
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    encode: c_int,
    tmp: *mut u8,
    tmp_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if encode == 0 {
        /* Raw message. */
        // SAFETY: `out_len` is writable per the contract.
        unsafe { *out_len = msg_len };
        return msg.cast_mut();
    }

    if ctx_len > SLH_DSA_MAX_CONTEXT_STRING_LEN {
        return ptr::null_mut();
    }

    /* Pure encoding. */
    let encoded_len = 1 + 1 + ctx_len + msg_len;
    if encoded_len < msg_len {
        /* Check for overflow. */
        return ptr::null_mut();
    }
    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = encoded_len };
    let mut cleanup_pkt = false;
    let encoded = if encoded_len <= tmp_len {
        tmp
    } else {
        let p = CRYPTO_zalloc(encoded_len, FILE, LINE_MSG_ENCODE).cast::<u8>();
        if p.is_null() {
            return ptr::null_mut();
        }
        cleanup_pkt = true;
        p
    };
    // SAFETY: `Wpacket` is a packet builder of integers and pointers only, and the value is
    // initialised by the `WPACKET_init_static_len` immediately below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };
    // SAFETY: `pkt` is a live local; `encoded` is writable for `encoded_len`.
    let ok = unsafe {
        WPACKET_init_static_len(&mut pkt, encoded, encoded_len, 0) != 0
            && WPACKET_put_bytes_u8(&mut pkt, 0) != 0
            && WPACKET_put_bytes_u8(&mut pkt, ctx_len as u8) != 0
            && WPACKET_memcpy(&mut pkt, ctx.cast::<c_void>(), ctx_len) != 0
            && WPACKET_memcpy(&mut pkt, msg.cast::<c_void>(), msg_len) != 0
            && WPACKET_finish(&mut pkt) != 0
    };
    if !ok {
        if cleanup_pkt {
            // SAFETY: `encoded` is this call's own allocation and `cleanup_pkt` says so.
            unsafe { CRYPTO_free(encoded.cast::<c_void>(), FILE, LINE_MSG_ENCODE) };
        }
        // SAFETY: `pkt` is a live local.
        unsafe { crate::packet::WPACKET_cleanup(&mut pkt) };
        return ptr::null_mut();
    }
    encoded
}

/// The unit's own `__FILE__` — `slh_dsa.c` is a plain `.c`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/slh_dsa/slh_dsa.c".as_ptr();
/// `slh_dsa.c:267`, the `OPENSSL_zalloc(encoded_len)` in `msg_encode`.
const LINE_MSG_ENCODE: c_int = 267;
/// `slh_dsa.c:309`/`:339`, the two `OPENSSL_clear_free(m, m_len)` call sites.
const LINE_CLEAR_FREE: c_int = 309;

/// `int ossl_slh_dsa_sign(SLH_DSA_HASH_CTX *slh_ctx, const uint8_t *msg, size_t msg_len,`
/// `const uint8_t *ctx, size_t ctx_len, const uint8_t *add_rand, int encode,`
/// `unsigned char *sig, size_t *siglen, size_t sigsize)` — `slh_dsa.c:289-314`.
///
/// # Safety
/// `slh_ctx` is live; every span is as the caller's contract.
pub(crate) unsafe fn ossl_slh_dsa_sign(
    slh_ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    add_rand: *const u8,
    encode: c_int,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let mut m_tmp = [0u8; 1024];
    let m_tmp_ptr = m_tmp.as_mut_ptr();
    let mut m = m_tmp_ptr;
    let mut m_len: usize = 0;

    if !sig.is_null() {
        // SAFETY: `msg`/`ctx` are as the caller's contract and `m_tmp` is this frame's.
        m = unsafe {
            msg_encode(
                msg,
                msg_len,
                ctx,
                ctx_len,
                encode,
                m_tmp_ptr,
                m_tmp.len(),
                &mut m_len,
            )
        };
        if m.is_null() {
            return 0;
        }
    }
    // SAFETY: the internal driver's own contract.
    let ret = unsafe { slh_sign_internal(slh_ctx, m, m_len, sig, siglen, sigsize, add_rand) };
    /* The encoded message may contain confidential message content. */
    if m != msg.cast_mut() {
        if m != m_tmp_ptr {
            // SAFETY: `m` is this call's own allocation and `m_len` its length.
            unsafe { CRYPTO_clear_free(m.cast::<c_void>(), m_len, FILE, LINE_CLEAR_FREE) };
        } else {
            // SAFETY: a local buffer.
            unsafe { OPENSSL_cleanse(m_tmp_ptr.cast::<c_void>(), m_tmp.len()) };
        }
    }
    ret
}

/// `int ossl_slh_dsa_verify(SLH_DSA_HASH_CTX *slh_ctx, const uint8_t *msg, size_t msg_len,`
/// `const uint8_t *ctx, size_t ctx_len, int encode, const uint8_t *sig, size_t sig_len)` —
/// `slh_dsa.c:320-344`.
///
/// # Safety
/// `slh_ctx` is live; every span is as the caller's contract.
pub(crate) unsafe fn ossl_slh_dsa_verify(
    slh_ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    encode: c_int,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    let mut m_tmp = [0u8; 1024];
    let m_tmp_ptr = m_tmp.as_mut_ptr();
    let mut m_len: usize = 0;

    // SAFETY: `msg`/`ctx` are as the caller's contract and `m_tmp` is this frame's.
    let m = unsafe {
        msg_encode(
            msg,
            msg_len,
            ctx,
            ctx_len,
            encode,
            m_tmp_ptr,
            m_tmp.len(),
            &mut m_len,
        )
    };
    if m.is_null() {
        return 0;
    }

    // SAFETY: the internal driver's own contract.
    let ret = unsafe { slh_verify_internal(slh_ctx, m, m_len, sig, sig_len) };
    /* The encoded message may contain confidential message content. */
    if m != msg.cast_mut() {
        if m != m_tmp_ptr {
            // SAFETY: `m` is this call's own allocation and `m_len` its length.
            unsafe { CRYPTO_clear_free(m.cast::<c_void>(), m_len, FILE, LINE_CLEAR_FREE) };
        } else {
            // SAFETY: a local buffer.
            unsafe { OPENSSL_cleanse(m_tmp_ptr.cast::<c_void>(), m_tmp.len()) };
        }
    }
    ret
}

/// `static uint64_t bytes_to_u64_be(const uint8_t *in, size_t in_len)` — `slh_dsa.c:350-359`.
///
/// FIPS 205 Algorithm 2's `toInt(X, n)`, written byte-by-byte because `in_len` may be less than
/// eight.
///
/// # Safety
/// `in_` is readable for `in_len` bytes.
unsafe fn bytes_to_u64_be(in_: *const u8, in_len: usize) -> u64 {
    let mut total: u64 = 0;
    // SAFETY: `in_` is readable for `in_len` per the contract.
    unsafe {
        for i in 0..in_len {
            total = (total << 8) + u64::from(*in_.add(i));
        }
    }
    total
}

/// `static int get_tree_ids(PACKET *rpkt, const SLH_DSA_PARAMS *params, uint64_t *tree_id,`
/// `uint32_t *leaf_id)` — `slh_dsa.c:366-393`.
///
/// Algorithm 19 steps 7-10: the bytes after `md` select the hypertree index and the leaf within
/// it, masked to the parameter set's own widths.
///
/// # Safety
/// `rpkt` is a live cursor; `params` is live; the two out-parameters are writable.
unsafe fn get_tree_ids(
    rpkt: &mut Packet,
    params: *const super::params::SlhDsaParams,
    tree_id: *mut u64,
    leaf_id: *mut u32,
) -> c_int {
    // SAFETY: `params` is live per the contract.
    let (h, hm) = unsafe { ((*params).h, (*params).hm) };
    let tree_id_len = ((h - hm + 7) >> 3) as usize; /* 7 or 8 bytes */
    let leaf_id_len = ((hm + 7) >> 3) as usize; /* 1 or 2 bytes */

    // SAFETY: `rpkt` is a live cursor, or this refuses.
    let tree_id_bytes = unsafe { rpkt.get_bytes(tree_id_len) };
    let Some(tree_id_bytes) = tree_id_bytes else {
        return 0;
    };
    // SAFETY: `rpkt` is a live cursor, or this refuses.
    let leaf_id_bytes = unsafe { rpkt.get_bytes(leaf_id_len) };
    let Some(leaf_id_bytes) = leaf_id_bytes else {
        return 0;
    };

    // SAFETY: two readable spans; the out-parameters are writable per the contract.
    unsafe {
        let tree_id_mask: u64 = u64::MAX >> (64 - (h - hm));
        let leaf_id_mask: u64 = (1u64 << hm) - 1;
        *tree_id = bytes_to_u64_be(tree_id_bytes, tree_id_len) & tree_id_mask;
        *leaf_id = (bytes_to_u64_be(leaf_id_bytes, leaf_id_len) & leaf_id_mask) as u32;
    }
    1
}
