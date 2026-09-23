//! Phase 8 — `crypto/slh_dsa/slh_wots.c`: the WOTS+ one-time signature (FIPS 205 Section 5).
//!
//! `slh_wots.c` is 319 lines and defines the three WOTS+ functions the tree units call —
//! `ossl_slh_wots_pk_gen` (Algorithm 6), `ossl_slh_wots_sign` (Algorithm 7) and
//! `ossl_slh_wots_pk_from_sig` (Algorithm 8) — over the chain function `slh_wots_chain`
//! (Algorithm 5) and the two nibble helpers.
//!
//! **`w = 16` for every parameter set**, so a `|n|`-byte message is `2n` nibbles followed by three
//! checksum nibbles (`slh_wots.c:16-22`), and `len = 2n + 3`. The checksum is the same
//! `0xF * len1 - sum` the FIPS `base_2^b` formulation computes, written directly as a 12-bit
//! value in three nibbles (`:51-70`).
//!
//! **The chain's write target is the caller's `WPACKET`, and the read target is the caller's
//! `PACKET`.** `slh_wots_chain` either copies the input straight through when `steps == 0`
//! (`:106-107`) or allocates `n` bytes *inside the packet* and iterates the hash in place
//! (`:109-121`), so a WOTS+ signature is written straight into the signature buffer with no
//! intermediate. The verify path mirrors it: `PACKET_get_bytes` for each chain's `n` bytes and a
//! scratch `WPACKET` for the reconstructed chains, then one `T()` to compress (`:296-312`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::packet::{
    Packet, WPACKET_allocate_bytes, WPACKET_finish, WPACKET_get_total_written,
    WPACKET_init_static_len, WPACKET_memcpy, Wpacket,
};
use crate::runtime::mem::OPENSSL_cleanse;

use super::adrs::{SlhAdrs, SLH_ADRS_TYPE_WOTS_PK, SLH_ADRS_TYPE_WOTS_PRF};
use super::{SlhDsaHashCtx, SLH_MAX_N};

/// `SLH_WOTS_LOGW` — `slh_wots.c:16`.
const SLH_WOTS_LOGW: usize = 4;
/// `SLH_WOTS_W` — `slh_wots.c:17`, the chain length.
const SLH_WOTS_W: usize = 16;
/// `SLH_WOTS_LEN2` — `slh_wots.c:19`, the three checksum nibbles.
const SLH_WOTS_LEN2: usize = 3;
/// `SLH_WOTS_LEN(n)` — `slh_dsa_local.h:26`, `2 * n + 3`.
const fn slh_wots_len(n: usize) -> usize {
    2 * n + SLH_WOTS_LEN2
}
/// `SLH_WOTS_LEN1(n)` — `slh_wots.c:18`, `2 * n`.
const fn slh_wots_len1(n: usize) -> usize {
    2 * n
}
/// `SLH_WOTS_LEN_MAX` — `slh_wots.c:21`, `SLH_WOTS_LEN(SLH_MAX_N)`.
const SLH_WOTS_LEN_MAX: usize = slh_wots_len(SLH_MAX_N);
/// `SLH_WOTS_CHECKSUM_LEN` — `slh_wots.c:20`, the checksum's byte length (unused here).
#[allow(dead_code)] // transcribed whole; the nibble path needs no byte length
const SLH_WOTS_CHECKSUM_LEN: usize = (SLH_WOTS_LEN2 + SLH_WOTS_LOGW).div_ceil(8);
/// `NIBBLE_MASK` — `slh_wots.c:22`.
const NIBBLE_MASK: u8 = 15;
/// `NIBBLE_SHIFT` — `slh_wots.c:23`.
const NIBBLE_SHIFT: u32 = 4;

/// `static ossl_inline void slh_bytes_to_nibbles(const uint8_t *in, size_t in_len, uint8_t *out)`
/// — `slh_wots.c:33-42`.
///
/// # Safety
/// `in` is readable for `in_len` bytes; `out` is writable for `2 * in_len`.
unsafe fn slh_bytes_to_nibbles(in_: *const u8, in_len: usize, out: *mut u8) {
    // SAFETY: both spans are as the contract says, and the loop stays inside them.
    unsafe {
        for i in 0..in_len {
            let b = *in_.add(i);
            *out.add(2 * i) = b >> NIBBLE_SHIFT;
            *out.add(2 * i + 1) = b & NIBBLE_MASK;
        }
    }
}

/// `static ossl_inline void compute_checksum_nibbles(const uint8_t *in, size_t in_len,`
/// `uint8_t *out)` — `slh_wots.c:51-70`.
///
/// # Safety
/// `in` is readable for `in_len` nibbles; `out` is writable for three.
unsafe fn compute_checksum_nibbles(in_: *const u8, in_len: usize, out: *mut u8) {
    let mut csum: u16 = 0;
    // SAFETY: `in_` is readable for `in_len` nibbles per the contract.
    unsafe {
        for i in 0..in_len {
            csum += *in_.add(i) as u16;
        }
    }
    csum = (NIBBLE_MASK as u16) * (in_len as u16) - csum;
    // SAFETY: `out` is writable for three nibbles per the contract.
    unsafe {
        *out = ((csum >> (2 * NIBBLE_SHIFT)) & NIBBLE_MASK as u16) as u8;
        *out.add(1) = ((csum >> NIBBLE_SHIFT) & NIBBLE_MASK as u16) as u8;
        *out.add(2) = (csum & NIBBLE_MASK as u16) as u8;
    }
}

/// `static int slh_wots_chain(SLH_DSA_HASH_CTX *ctx, const uint8_t *in,`
/// `uint8_t start_index, uint8_t steps, const uint8_t *pk_seed, uint8_t *adrs, WPACKET *wpkt)` —
/// `slh_wots.c:92-123`.
///
/// # Safety
/// `ctx` is live; `wpkt` is live; the method table the key names is the authority's.
unsafe fn slh_wots_chain(
    ctx: *mut SlhDsaHashCtx,
    in_: *const u8,
    start_index: u8,
    steps: u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    wpkt: *mut Wpacket,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (f, set_hash_address, n) = unsafe {
        (
            (*(*key).hash_func).f,
            (*(*key).adrs_func).set_hash_address,
            (*(*key).params).n as usize,
        )
    };
    let mut tmp: *mut u8 = ptr::null_mut();
    let tmp_len = n;

    if steps == 0 {
        // SAFETY: `wpkt` is live; `in_` is readable for `n` bytes.
        return unsafe { WPACKET_memcpy(wpkt, in_.cast::<c_void>(), n) };
    }

    // SAFETY: `wpkt` is live and `tmp` is a live local.
    if unsafe { WPACKET_allocate_bytes(wpkt, tmp_len, &mut tmp) } == 0 {
        return 0;
    }

    let mut j = start_index as usize;
    // SAFETY: `adrs` is writable for its own size.
    unsafe { set_hash_address(adrs, j as u32) };
    j += 1;
    // SAFETY: `tmp` is writable for `n` bytes; `in_` is readable for `n`.
    if unsafe { f(ctx, pk_seed, adrs, in_, n, tmp, tmp_len) } == 0 {
        return 0;
    }

    let end_index = start_index as usize + steps as usize;
    while j < end_index {
        // SAFETY: `adrs` is writable for its own size.
        unsafe { set_hash_address(adrs, j as u32) };
        // SAFETY: `tmp` is readable and writable for `n` bytes.
        if unsafe { f(ctx, pk_seed, adrs, tmp, n, tmp, tmp_len) } == 0 {
            return 0;
        }
        j += 1;
    }
    1
}

/// `int ossl_slh_wots_pk_gen(SLH_DSA_HASH_CTX *ctx, const uint8_t *sk_seed,`
/// `const uint8_t *pk_seed, uint8_t *adrs, uint8_t *pk_out, size_t pk_out_len)` —
/// `slh_wots.c:138-185`.
///
/// # Safety
/// `ctx` is live; every span is as the arguments say.
pub(crate) unsafe fn ossl_slh_wots_pk_gen(
    ctx: *mut SlhDsaHashCtx,
    sk_seed: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (prf, t, copy, set_type_and_clear, copy_keypair_address, set_chain_address, n) = unsafe {
        (
            (*(*key).hash_func).prf,
            (*(*key).hash_func).t,
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).copy_keypair_address,
            (*(*key).adrs_func).set_chain_address,
            (*(*key).params).n as usize,
        )
    };
    let len = slh_wots_len(n);
    let mut sk = [0u8; SLH_MAX_N];
    let mut tmp = [0u8; SLH_WOTS_LEN_MAX * SLH_MAX_N];
    let mut sk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    let mut wots_pk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `Wpacket` is a packet builder of integers and pointers only, and the value is
    // initialised by the `WPACKET_init_static_len` immediately below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };
    let tmp_wpkt = &mut pkt;
    let mut tmp_len: usize = 0;

    // SAFETY: `tmp_wpkt` is a live local; `tmp` is writable for its length.
    if unsafe { WPACKET_init_static_len(tmp_wpkt, tmp.as_mut_ptr(), tmp.len(), 0) } == 0 {
        return 0;
    }
    // SAFETY: `sk_adrs`/`wots_pk_adrs` are writable for their own sizes; `adrs` is readable.
    unsafe {
        copy(sk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(sk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_WOTS_PRF);
        copy_keypair_address(sk_adrs.as_mut_ptr(), adrs);
    }

    let mut i: usize = 0;
    while i < len {
        // SAFETY: `sk_adrs` is writable for its own size.
        unsafe { set_chain_address(sk_adrs.as_mut_ptr(), i as u32) };
        // SAFETY: the method table is the authority's; `sk` is writable for `n` bytes.
        if unsafe {
            prf(
                ctx,
                pk_seed,
                sk_seed,
                sk_adrs.as_ptr(),
                sk.as_mut_ptr(),
                sk.len(),
            )
        } == 0
        {
            // SAFETY: the authority's `end:` label.
            unsafe {
                WPACKET_finish(tmp_wpkt);
                OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
                OPENSSL_cleanse(sk.as_mut_ptr().cast::<c_void>(), n);
            }
            return ret;
        }
        // SAFETY: `adrs` is writable for its own size.
        unsafe { set_chain_address(adrs, i as u32) };
        // SAFETY: the chain reads `sk` for `n` and writes into `tmp_wpkt`.
        if unsafe { slh_wots_chain(ctx, sk.as_ptr(), 0, NIBBLE_MASK, pk_seed, adrs, tmp_wpkt) } == 0
        {
            // SAFETY: the authority's `end:` label.
            unsafe {
                WPACKET_finish(tmp_wpkt);
                OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
                OPENSSL_cleanse(sk.as_mut_ptr().cast::<c_void>(), n);
            }
            return ret;
        }
        i += 1;
    }

    // SAFETY: `tmp_wpkt` is live and `tmp_len` is a live local.
    if unsafe { WPACKET_get_total_written(tmp_wpkt, &mut tmp_len) } == 0 {
        // SAFETY: the authority's `end:` label.
        unsafe {
            WPACKET_finish(tmp_wpkt);
            OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
            OPENSSL_cleanse(sk.as_mut_ptr().cast::<c_void>(), n);
        }
        return ret;
    }
    // SAFETY: `wots_pk_adrs` is writable; `adrs` is readable.
    unsafe {
        copy(wots_pk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(wots_pk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_WOTS_PK);
        copy_keypair_address(wots_pk_adrs.as_mut_ptr(), adrs);
    }
    // SAFETY: `t` is the authority's; `tmp` is readable for `tmp_len`; `pk_out` writable.
    ret = unsafe {
        t(
            ctx,
            pk_seed,
            wots_pk_adrs.as_ptr(),
            tmp.as_ptr(),
            tmp_len,
            pk_out,
            pk_out_len,
        )
    };
    /* The authority's `end:` label. */
    // SAFETY: `tmp_wpkt` is live; the two buffers are this frame's.
    unsafe {
        WPACKET_finish(tmp_wpkt);
        OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
        OPENSSL_cleanse(sk.as_mut_ptr().cast::<c_void>(), n);
    }
    ret
}

/// `int ossl_slh_wots_sign(SLH_DSA_HASH_CTX *ctx, const uint8_t *msg,`
/// `const uint8_t *sk_seed, const uint8_t *pk_seed, uint8_t *adrs, WPACKET *sig_wpkt)` —
/// `slh_wots.c:203-250`.
///
/// # Safety
/// `ctx` is live; every span is as the arguments say.
pub(crate) unsafe fn ossl_slh_wots_sign(
    ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    sk_seed: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    sig_wpkt: *mut Wpacket,
) -> c_int {
    let mut msg_and_csum_nibbles = [0u8; SLH_WOTS_LEN_MAX];
    let mut sk = [0u8; SLH_MAX_N];
    let mut sk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (prf, copy, set_type_and_clear, copy_keypair_address, set_chain_address, n) = unsafe {
        (
            (*(*key).hash_func).prf,
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).copy_keypair_address,
            (*(*key).adrs_func).set_chain_address,
            (*(*key).params).n as usize,
        )
    };
    let len1 = slh_wots_len1(n);
    let len = len1 + SLH_WOTS_LEN2;

    // SAFETY: `msg` is readable for `n` and the out buffer for `2n`; nibbles fill `msg_and_csum`.
    unsafe {
        slh_bytes_to_nibbles(msg, n, msg_and_csum_nibbles.as_mut_ptr());
        compute_checksum_nibbles(
            msg_and_csum_nibbles.as_ptr(),
            len1,
            msg_and_csum_nibbles.as_mut_ptr().add(len1),
        );
        copy(sk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(sk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_WOTS_PRF);
        copy_keypair_address(sk_adrs.as_mut_ptr(), adrs);
    }

    let mut ret: c_int = 1;
    let mut i: usize = 0;
    while i < len {
        // SAFETY: `sk_adrs` is writable for its own size.
        unsafe { set_chain_address(sk_adrs.as_mut_ptr(), i as u32) };
        // SAFETY: the method table is the authority's; `sk` is writable for `n`.
        if unsafe {
            prf(
                ctx,
                pk_seed,
                sk_seed,
                sk_adrs.as_ptr(),
                sk.as_mut_ptr(),
                sk.len(),
            )
        } == 0
        {
            ret = 0;
            break;
        }
        // SAFETY: `adrs` is writable for its own size.
        unsafe { set_chain_address(adrs, i as u32) };
        // SAFETY: the chain writes into `sig_wpkt`, the caller's buffer.
        if unsafe {
            slh_wots_chain(
                ctx,
                sk.as_ptr(),
                0,
                msg_and_csum_nibbles[i],
                pk_seed,
                adrs,
                sig_wpkt,
            )
        } == 0
        {
            ret = 0;
            break;
        }
        i += 1;
    }
    /* The authority's `err:` label. */
    // SAFETY: two local buffers.
    unsafe {
        OPENSSL_cleanse(sk.as_mut_ptr().cast::<c_void>(), sk.len());
        OPENSSL_cleanse(
            msg_and_csum_nibbles.as_mut_ptr().cast::<c_void>(),
            msg_and_csum_nibbles.len(),
        );
    }
    ret
}

/// `int ossl_slh_wots_pk_from_sig(SLH_DSA_HASH_CTX *ctx, PACKET *sig_rpkt,`
/// `const uint8_t *msg, const uint8_t *pk_seed, uint8_t *adrs, uint8_t *pk_out,`
/// `size_t pk_out_len)` — `slh_wots.c:268-319`.
///
/// # Safety
/// `ctx` is live; `sig_rpkt` is a live cursor into the caller's signature buffer.
pub(crate) unsafe fn ossl_slh_wots_pk_from_sig(
    ctx: *mut SlhDsaHashCtx,
    sig_rpkt: *mut Packet,
    msg: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut msg_and_csum_nibbles = [0u8; SLH_WOTS_LEN_MAX];
    let mut tmp = [0u8; SLH_WOTS_LEN_MAX * SLH_MAX_N];
    let mut wots_pk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `Wpacket` is a packet builder of integers and pointers only, and the value is
    // initialised by the `WPACKET_init_static_len` immediately below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };
    let tmp_pkt = &mut pkt;
    let mut tmp_len: usize = 0;
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (t, copy, set_type_and_clear, copy_keypair_address, set_chain_address, n) = unsafe {
        (
            (*(*key).hash_func).t,
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).copy_keypair_address,
            (*(*key).adrs_func).set_chain_address,
            (*(*key).params).n as usize,
        )
    };
    let len1 = slh_wots_len1(n);
    let len = len1 + SLH_WOTS_LEN2;

    // SAFETY: `tmp_pkt` is a live local; `tmp` is writable for its length.
    if unsafe { WPACKET_init_static_len(tmp_pkt, tmp.as_mut_ptr(), tmp.len(), 0) } == 0 {
        return 0;
    }

    // SAFETY: `msg` is readable for `n`; the nibble buffer is writable for `lan + 3`.
    unsafe {
        slh_bytes_to_nibbles(msg, n, msg_and_csum_nibbles.as_mut_ptr());
        compute_checksum_nibbles(
            msg_and_csum_nibbles.as_ptr(),
            len1,
            msg_and_csum_nibbles.as_mut_ptr().add(len1),
        );
    }

    let mut i: usize = 0;
    while i < len {
        // SAFETY: `adrs` is writable for its own size.
        unsafe { set_chain_address(adrs, i as u32) };
        // SAFETY: `sig_rpkt` is a live cursor with at least `n` bytes, or this refuses.
        let sig_i = unsafe { (*sig_rpkt).get_bytes(n) };
        let Some(sig_i) = sig_i else {
            // SAFETY: the authority's `err:` label.
            unsafe {
                if WPACKET_finish(tmp_pkt) == 0 {
                    ret = 0;
                }
                OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
                OPENSSL_cleanse(
                    msg_and_csum_nibbles.as_mut_ptr().cast::<c_void>(),
                    msg_and_csum_nibbles.len(),
                );
            }
            return ret;
        };
        // SAFETY: the chain reads `sig_i` for `n` and writes into `tmp_pkt`.
        if unsafe {
            slh_wots_chain(
                ctx,
                sig_i,
                msg_and_csum_nibbles[i],
                NIBBLE_MASK - msg_and_csum_nibbles[i],
                pk_seed,
                adrs,
                tmp_pkt,
            )
        } == 0
        {
            // SAFETY: the authority's `err:` label.
            unsafe {
                if WPACKET_finish(tmp_pkt) == 0 {
                    ret = 0;
                }
                OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
                OPENSSL_cleanse(
                    msg_and_csum_nibbles.as_mut_ptr().cast::<c_void>(),
                    msg_and_csum_nibbles.len(),
                );
            }
            return ret;
        }
        i += 1;
    }

    // SAFETY: `wots_pk_adrs` is writable; `adrs` is readable.
    unsafe {
        copy(wots_pk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(wots_pk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_WOTS_PK);
        copy_keypair_address(wots_pk_adrs.as_mut_ptr(), adrs);
    }
    // SAFETY: `tmp_pkt` is live and `tmp_len` is a live local.
    if unsafe { WPACKET_get_total_written(tmp_pkt, &mut tmp_len) } == 0 {
        // SAFETY: the authority's `err:` label.
        unsafe {
            if WPACKET_finish(tmp_pkt) == 0 {
                ret = 0;
            }
            OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
            OPENSSL_cleanse(
                msg_and_csum_nibbles.as_mut_ptr().cast::<c_void>(),
                msg_and_csum_nibbles.len(),
            );
        }
        return ret;
    }
    // SAFETY: `t` is the authority's; `tmp` is readable for `tmp_len`; `pk_out` is writable.
    ret = unsafe {
        t(
            ctx,
            pk_seed,
            wots_pk_adrs.as_ptr(),
            tmp.as_ptr(),
            tmp_len,
            pk_out,
            pk_out_len,
        )
    };
    /* The authority's `err:` label. */
    // SAFETY: `tmp_pkt` is live; the two buffers are this frame's.
    unsafe {
        if WPACKET_finish(tmp_pkt) == 0 {
            ret = 0;
        }
        OPENSSL_cleanse(tmp.as_mut_ptr().cast::<c_void>(), tmp.len());
        OPENSSL_cleanse(
            msg_and_csum_nibbles.as_mut_ptr().cast::<c_void>(),
            msg_and_csum_nibbles.len(),
        );
    }
    ret
}

/// `SLH_WOTS_W` is read by no function above but is part of the header's constants; it is named
/// here so a reader sees the `w = 16` the checksum's `NIBBLE_MASK` stands for.
const _SLH_WOTS_W: usize = SLH_WOTS_W;
