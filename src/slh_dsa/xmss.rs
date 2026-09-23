//! Phase 8 — `crypto/slh_dsa/slh_xmss.c`: the XMSS tree and its one-time signature
//! (FIPS 205 Section 6).
//!
//! `slh_xmss.c` is 200 lines and defines the three XMSS functions — `ossl_slh_xmss_node`
//! (Algorithm 9), `ossl_slh_xmss_sign` (Algorithm 10) and `ossl_slh_xmss_pk_from_sig`
//! (Algorithm 11). A node at height 0 is a WOTS+ public key (`:45-51`); every higher node is the
//! `TREE`-type `H()` of its two children (`:52-63`). A signature is one WOTS+ signature followed
//! by `hm` authentication-path nodes, and the verify walks the path the same way.
//!
//! **`xmss_sign` writes the WOTS+ signature first and then the path**, which the file's own
//! comment says is a reversal of the FIPS ordering to simplify the `WPACKET` writes
//! (`:101-104`). The verify reads them in that same order, so the two agree and the layout is
//! not the FIPS pseudocode's — it is the authority's.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The authority's C signatures carry the algorithm's parameters rather than a context struct, so
// several of them exceed clippy's seven-argument threshold. They are transcribed verbatim.
#![allow(clippy::too_many_arguments)]

use core::ffi::c_int;
use core::ptr;

use crate::packet::{Packet, WPACKET_allocate_bytes, Wpacket};
use crate::runtime::mem::OPENSSL_cleanse;

use super::adrs::{SlhAdrs, SLH_ADRS_TYPE_TREE, SLH_ADRS_TYPE_WOTS_HASH};
use super::wots::{ossl_slh_wots_pk_from_sig, ossl_slh_wots_pk_gen, ossl_slh_wots_sign};
use super::{SlhDsaHashCtx, SLH_MAX_N};

/// `int ossl_slh_xmss_node(SLH_DSA_HASH_CTX *ctx, const uint8_t *sk_seed, uint32_t node_id,`
/// `uint32_t h, const uint8_t *pk_seed, uint8_t *adrs, uint8_t *pk_out, size_t pk_out_len)` —
/// `slh_xmss.c:36-68`.
///
/// # Safety
/// `ctx` is live; every span is as the arguments say.
pub(crate) unsafe fn ossl_slh_xmss_node(
    ctx: *mut SlhDsaHashCtx,
    sk_seed: *const u8,
    node_id: u32,
    h: u32,
    pk_seed: *const u8,
    adrs: *mut u8,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (hash_h, set_type_and_clear, set_keypair_address, set_tree_height, set_tree_index) = unsafe {
        (
            (*(*key).hash_func).h,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).set_keypair_address,
            (*(*key).adrs_func).set_tree_height,
            (*(*key).adrs_func).set_tree_index,
        )
    };
    let mut ret: c_int = 0;

    if h == 0 {
        /* For leaf nodes generate the public key. */
        // SAFETY: `adrs` is writable for its own size.
        unsafe {
            set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
            set_keypair_address(adrs, node_id);
        }
        // SAFETY: the WOTS+ generator's own contract.
        if unsafe { ossl_slh_wots_pk_gen(ctx, sk_seed, pk_seed, adrs, pk_out, pk_out_len) } != 0 {
            ret = 1;
        }
    } else {
        let mut lnode = [0u8; SLH_MAX_N];
        let mut rnode = [0u8; SLH_MAX_N];

        // SAFETY: two recursive calls, each inside the buffer it is given.
        let ok = unsafe {
            ossl_slh_xmss_node(
                ctx,
                sk_seed,
                2 * node_id,
                h - 1,
                pk_seed,
                adrs,
                lnode.as_mut_ptr(),
                lnode.len(),
            ) != 0
                && ossl_slh_xmss_node(
                    ctx,
                    sk_seed,
                    2 * node_id + 1,
                    h - 1,
                    pk_seed,
                    adrs,
                    rnode.as_mut_ptr(),
                    rnode.len(),
                ) != 0
        };
        if ok {
            // SAFETY: `adrs` is writable for its own size.
            unsafe {
                set_type_and_clear(adrs, SLH_ADRS_TYPE_TREE);
                set_tree_height(adrs, h);
                set_tree_index(adrs, node_id);
            }
            // SAFETY: `hash_h` is the authority's and every span is as it says.
            ret = unsafe {
                hash_h(
                    ctx,
                    pk_seed,
                    adrs,
                    lnode.as_ptr(),
                    rnode.as_ptr(),
                    pk_out,
                    pk_out_len,
                )
            };
        }
        // SAFETY: two local buffers.
        unsafe {
            OPENSSL_cleanse(lnode.as_mut_ptr().cast(), lnode.len());
            OPENSSL_cleanse(rnode.as_mut_ptr().cast(), rnode.len());
        }
    }
    ret
}

/// `int ossl_slh_xmss_sign(SLH_DSA_HASH_CTX *ctx, const uint8_t *msg, const uint8_t *sk_seed,`
/// `uint32_t node_id, const uint8_t *pk_seed, uint8_t *adrs, WPACKET *sig_wpkt)` —
/// `slh_xmss.c:88-120`.
///
/// # Safety
/// `ctx` is live; `sig_wpkt` is the caller's signature builder.
pub(crate) unsafe fn ossl_slh_xmss_sign(
    ctx: *mut SlhDsaHashCtx,
    msg: *const u8,
    sk_seed: *const u8,
    node_id: u32,
    pk_seed: *const u8,
    adrs: *mut u8,
    sig_wpkt: *mut Wpacket,
) -> c_int {
    let mut tmp_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (copy, set_type_and_clear, set_keypair_address, n, hm) = unsafe {
        (
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).set_keypair_address,
            (*(*key).params).n as usize,
            (*(*key).params).hm,
        )
    };
    let mut id = node_id;

    // SAFETY: `tmp_adrs` is writable and `adrs` readable for their own sizes.
    unsafe {
        copy(tmp_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
        set_keypair_address(adrs, node_id);
    }
    // SAFETY: the WOTS+ signer's own contract.
    if unsafe { ossl_slh_wots_sign(ctx, msg, sk_seed, pk_seed, adrs, sig_wpkt) } == 0 {
        return 0;
    }

    // SAFETY: `adrs` is writable and `tmp_adrs` readable for their own sizes.
    unsafe { copy(adrs, tmp_adrs.as_ptr()) };
    let mut h: u32 = 0;
    while h < hm {
        let mut auth_path: *mut u8 = ptr::null_mut();
        // SAFETY: `sig_wpkt` is live and `auth_path` is a live local.
        if unsafe { WPACKET_allocate_bytes(sig_wpkt, n, &mut auth_path) } == 0 {
            return 0;
        }
        // SAFETY: the node computation writes into the allocated span.
        if unsafe { ossl_slh_xmss_node(ctx, sk_seed, id ^ 1, h, pk_seed, adrs, auth_path, n) } == 0
        {
            return 0;
        }
        id >>= 1;
        h += 1;
    }
    1
}

/// `int ossl_slh_xmss_pk_from_sig(SLH_DSA_HASH_CTX *ctx, uint32_t node_id, PACKET *sig_rpkt,`
/// `const uint8_t *msg, const uint8_t *pk_seed, uint8_t *adrs, uint8_t *pk_out,`
/// `size_t pk_out_len)` — `slh_xmss.c:142-184`.
///
/// # Safety
/// `ctx` is live; `sig_rpkt` is a live cursor into the caller's signature buffer.
pub(crate) unsafe fn ossl_slh_xmss_pk_from_sig(
    ctx: *mut SlhDsaHashCtx,
    mut node_id: u32,
    sig_rpkt: *mut Packet,
    msg: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (hash_h, set_type_and_clear, set_keypair_address, set_tree_index, set_tree_height, n, hm) = unsafe {
        (
            (*(*key).hash_func).h,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).set_keypair_address,
            (*(*key).adrs_func).set_tree_index,
            (*(*key).adrs_func).set_tree_height,
            (*(*key).params).n as usize,
            (*(*key).params).hm,
        )
    };
    let node = pk_out;

    // SAFETY: `adrs` is writable for its own size.
    unsafe {
        set_type_and_clear(adrs, SLH_ADRS_TYPE_WOTS_HASH);
        set_keypair_address(adrs, node_id);
    }
    // SAFETY: the WOTS+ verifier's own contract; `node` is `pk_out`, writable for `pk_out_len`.
    if unsafe { ossl_slh_wots_pk_from_sig(ctx, sig_rpkt, msg, pk_seed, adrs, node, pk_out_len) }
        == 0
    {
        return 0;
    }

    // SAFETY: `adrs` is writable for its own size.
    unsafe { set_type_and_clear(adrs, SLH_ADRS_TYPE_TREE) };

    let mut k: u32 = 0;
    while k < hm {
        // SAFETY: `sig_rpkt` is a live cursor with at least `n` bytes, or this refuses.
        let auth_path = unsafe { (*sig_rpkt).get_bytes(n) };
        let Some(auth_path) = auth_path else {
            return 0;
        };
        // SAFETY: `adrs` is writable for its own size.
        unsafe { set_tree_height(adrs, k + 1) };
        if (node_id & 1) == 0 {
            /* even */
            node_id >>= 1;
            // SAFETY: `adrs` is writable for its own size.
            unsafe { set_tree_index(adrs, node_id) };
            // SAFETY: the authority's `H`, in place; `node` is readable and writable for `n`.
            if unsafe { hash_h(ctx, pk_seed, adrs, node, auth_path, node, pk_out_len) } == 0 {
                return 0;
            }
        } else {
            /* odd */
            node_id = (node_id - 1) >> 1;
            // SAFETY: `adrs` is writable for its own size.
            unsafe { set_tree_index(adrs, node_id) };
            // SAFETY: the authority's `H`, in place.
            if unsafe { hash_h(ctx, pk_seed, adrs, auth_path, node, node, pk_out_len) } == 0 {
                return 0;
            }
        }
        k += 1;
    }
    1
}
