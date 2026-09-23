//! Phase 8 — `crypto/slh_dsa/slh_hypertree.c`: the hypertree signature
//! (FIPS 205 Section 7).
//!
//! `slh_hypertree.c` is 144 lines and defines the two hypertree functions —
//! `ossl_slh_ht_sign` (Algorithm 12) and `ossl_slh_ht_verify` (Algorithm 13). A hypertree
//! signature is `d` XMSS signatures, one per layer: the first signs the message, and each later
//! one signs the previous tree's root (`:52-90`). The verify replays the chain of
//! `ossl_slh_xmss_pk_from_sig` calls and compares the top root against `PK_ROOT` (`:128-140`).
//!
//! **The sign moves the signature packet's cursor, not a copy.** It records `psig` before each
//! XMSS signature and re-inits a `PACKET` over exactly that span to derive the next layer's
//! message (`:72-86`), so the tree root is read back out of the bytes just written. The last
//! layer skips the read-back because nothing signs it (`:76-81`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::c_int;

use crate::packet::{Packet, WPACKET_get_curr, Wpacket};
use crate::runtime::mem::OPENSSL_cleanse;

use super::adrs::SlhAdrs;
use super::xmss::{ossl_slh_xmss_pk_from_sig, ossl_slh_xmss_sign};
use super::{SlhDsaHashCtx, SLH_MAX_N};

/// `int ossl_slh_ht_sign(SLH_DSA_HASH_CTX *ctx, const uint8_t *msg, const uint8_t *sk_seed,`
/// `const uint8_t *pk_seed, uint64_t tree_id, uint32_t leaf_id, WPACKET *sig_wpkt)` —
/// `slh_hypertree.c:32-96`.
///
/// # Safety
/// `ctx` is live; `msg` is readable for `n`; `sig_wpkt` is the signature builder.
pub(crate) unsafe fn ossl_slh_ht_sign(
    ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    sk_seed: *const u8,
    pk_seed: *const u8,
    mut tree_id: u64,
    mut leaf_id: u32,
    sig_wpkt: *mut Wpacket,
) -> c_int {
    let mut ret: c_int = 0;
    let mut adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    let mut root = [0u8; SLH_MAX_N];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables/params are the authority's.
    let (zero, set_layer_address, set_tree_address, n, d, hm) = unsafe {
        (
            (*(*key).adrs_func).zero,
            (*(*key).adrs_func).set_layer_address,
            (*(*key).adrs_func).set_tree_address,
            (*(*key).params).n,
            (*(*key).params).d,
            (*(*key).params).hm,
        )
    };
    let mask: u32 = (1u32 << hm) - 1;

    // SAFETY: `adrs` is writable for its own size.
    unsafe { zero(adrs.as_mut_ptr()) };
    // SAFETY: `msg` is readable for `n` bytes and `root` is writable for the same.
    unsafe { core::ptr::copy_nonoverlapping(msg, root.as_mut_ptr(), n as usize) };

    let mut layer_addr: u32 = 0;
    while layer_addr < d {
        /* type = SLH_ADRS_TYPE_WOTS_HASH is set inside xmss_sign. */
        // SAFETY: `adrs` is writable for its own size.
        unsafe {
            set_layer_address(adrs.as_mut_ptr(), layer_addr);
            set_tree_address(adrs.as_mut_ptr(), tree_id);
        }
        // SAFETY: `sig_wpkt` is live; `psig` is a live local.
        let psig = unsafe { WPACKET_get_curr(sig_wpkt) };
        // SAFETY: the XMSS signer's own contract.
        if unsafe {
            ossl_slh_xmss_sign(
                ctx,
                root.as_ptr(),
                sk_seed,
                leaf_id,
                pk_seed,
                adrs.as_mut_ptr(),
                sig_wpkt,
            )
        } == 0
        {
            // SAFETY: the authority's `err:` label.
            unsafe { OPENSSL_cleanse(root.as_mut_ptr().cast(), root.len()) };
            return ret;
        }
        if layer_addr < d - 1 {
            // SAFETY: `sig_wpkt` is live; the span is the XMSS signature just written.
            let siglen = unsafe { WPACKET_get_curr(sig_wpkt).offset_from(psig) } as usize;
            // SAFETY: `psig` points into `sig_wpkt`'s buffer, valid for `siglen`.
            let Some(mut xmss_sig_rpkt) = (unsafe { Packet::buf_init(psig, siglen) }) else {
                // SAFETY: the authority's `err:` label.
                unsafe { OPENSSL_cleanse(root.as_mut_ptr().cast(), root.len()) };
                return ret;
            };
            // SAFETY: the XMSS verifier's own contract.
            if unsafe {
                ossl_slh_xmss_pk_from_sig(
                    ctx,
                    leaf_id,
                    &mut xmss_sig_rpkt,
                    root.as_ptr(),
                    pk_seed,
                    adrs.as_mut_ptr(),
                    root.as_mut_ptr(),
                    root.len(),
                )
            } == 0
            {
                // SAFETY: the authority's `err:` label.
                unsafe { OPENSSL_cleanse(root.as_mut_ptr().cast(), root.len()) };
                return ret;
            }
            leaf_id = tree_id as u32 & mask;
            tree_id >>= hm;
        }
        layer_addr += 1;
    }
    ret = 1;
    /* The authority's `err:` label. */
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(root.as_mut_ptr().cast(), root.len()) };
    ret
}

/// `int ossl_slh_ht_verify(SLH_DSA_HASH_CTX *ctx, const uint8_t *msg, PACKET *sig_pkt,`
/// `const uint8_t *pk_seed, uint64_t tree_id, uint32_t leaf_id, const uint8_t *pk_root)` —
/// `slh_hypertree.c:112-144`.
///
/// # Safety
/// `ctx` is live; `sig_pkt` is a live cursor into the caller's signature buffer.
pub(crate) unsafe fn ossl_slh_ht_verify(
    ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    sig_pkt: *mut Packet,
    pk_seed: *const u8,
    mut tree_id: u64,
    mut leaf_id: u32,
    pk_root: *const u8,
) -> c_int {
    let mut ret: c_int = 0;
    let mut adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    let mut node = [0u8; SLH_MAX_N];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables/params are the authority's.
    let (zero, set_layer_address, set_tree_address, n, d) = unsafe {
        (
            (*(*key).adrs_func).zero,
            (*(*key).adrs_func).set_layer_address,
            (*(*key).adrs_func).set_tree_address,
            (*(*key).params).n,
            (*(*key).params).d,
        )
    };
    // SAFETY: `key` is live with `params` set; the read is one integer field.
    let tree_height = unsafe { (*(*key).params).hm };
    let mask: u32 = (1u32 << tree_height) - 1;

    // SAFETY: `adrs` is writable for its own size.
    unsafe { zero(adrs.as_mut_ptr()) };
    // SAFETY: `msg` is readable for `n` bytes and `node` is writable for the same.
    unsafe { core::ptr::copy_nonoverlapping(msg, node.as_mut_ptr(), n as usize) };

    let mut layer_addr: u32 = 0;
    while layer_addr < d {
        // SAFETY: `adrs` is writable for its own size.
        unsafe {
            set_layer_address(adrs.as_mut_ptr(), layer_addr);
            set_tree_address(adrs.as_mut_ptr(), tree_id);
        }
        // SAFETY: the XMSS verifier's own contract.
        if unsafe {
            ossl_slh_xmss_pk_from_sig(
                ctx,
                leaf_id,
                sig_pkt,
                node.as_ptr(),
                pk_seed,
                adrs.as_mut_ptr(),
                node.as_mut_ptr(),
                node.len(),
            )
        } == 0
        {
            // SAFETY: the authority's `err:` label.
            unsafe { OPENSSL_cleanse(node.as_mut_ptr().cast(), node.len()) };
            return ret;
        }
        leaf_id = tree_id as u32 & mask;
        tree_id >>= tree_height;
        layer_addr += 1;
    }
    // SAFETY: both spans are `n` bytes.
    ret = c_int::from(unsafe {
        core::slice::from_raw_parts(node.as_ptr(), n as usize)
            == core::slice::from_raw_parts(pk_root, n as usize)
    });
    /* The authority's `err:` label. */
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(node.as_mut_ptr().cast(), node.len()) };
    ret
}
