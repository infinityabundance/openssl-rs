//! Phase 8 — `crypto/slh_dsa/slh_fors.c`: the FORS few-time signature (FIPS 205 Section 8).
//!
//! `slh_fors.c` is 328 lines and defines the FORS signer (`ossl_slh_fors_sign`, Algorithm 16) and
//! verifier (`ossl_slh_fors_pk_from_sig`, Algorithm 17) over the secret generator
//! `slh_fors_sk_gen` (Algorithm 14), the tree walk `slh_fors_node` (Algorithm 18) and the
//! `base_2^b` splitter `slh_base_2b` (Algorithm 4).
//!
//! **`md` is split into `k` `a`-bit indices** (`:151`, `:245`), one per FORS tree, and each tree
//! gets its own contiguous range of the address space: tree `i` uses leaf indices
//! `2^a * i + (0..2^a - 1)` at the bottom and half as many at each layer up (`:156-164`). The sign
//! path recomputes the tree from the seed for each node of each path (`:178-187`), which the file
//! itself calls "really inefficient" and does not hide; the verify path reads the signature's
//! reveal and path nodes instead.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The authority's C signatures carry the algorithm's parameters rather than a context struct, so
// several of them exceed clippy's seven-argument threshold. They are transcribed verbatim.
#![allow(clippy::too_many_arguments)]

use core::ffi::c_int;
use core::ptr;

use crate::packet::{
    Packet, WPACKET_allocate_bytes, WPACKET_finish, WPACKET_get_total_written,
    WPACKET_init_static_len, WPACKET_memcpy, Wpacket,
};
use crate::runtime::mem::OPENSSL_cleanse;

use super::adrs::{SlhAdrs, SLH_ADRS_TYPE_FORS_PRF, SLH_ADRS_TYPE_FORS_ROOTS};
use super::{SlhDsaHashCtx, SLH_MAX_N};

/// `SLH_MAX_K` — `slh_fors.c:16`, the largest number of FORS trees.
const SLH_MAX_K: usize = 35;
/// `SLH_MAX_A` — `slh_fors.c:18`, the largest `a`.
#[allow(dead_code)] // a header bound; the twelve sets' `a` never indexes a fixed-size array alone
const SLH_MAX_A: usize = 9;
/// `SLH_MAX_ROOTS` — `slh_fors.c:21`, `SLH_MAX_K * SLH_MAX_N`.
const SLH_MAX_ROOTS: usize = SLH_MAX_K * SLH_MAX_N;

/// `static void slh_base_2b(const uint8_t *in, uint32_t b, uint32_t *out, size_t out_len)` —
/// `slh_fors.c:311-328`.
///
/// FIPS 205 Algorithm 4's `base_2^b`: the first `out_len * b` bits of `in`, most significant
/// first, as `out_len` `b`-bit integers.
///
/// # Safety
/// `in` is readable for at least `(out_len * b + 7) / 8` bytes; `out` is writable for `out_len`.
unsafe fn slh_base_2b(in_: *const u8, b: u32, out: *mut u32, out_len: usize) {
    let mask: u32 = (1u32 << b) - 1;
    let mut p = in_;
    let mut bits: u32 = 0;
    let mut total: u32 = 0;

    // SAFETY: the byte pointer advances only while `bits < b`, and `out_len * b / 8` bytes are
    // readable per the contract.
    unsafe {
        for i in 0..out_len {
            while bits < b {
                total <<= 8;
                total += u32::from(*p);
                p = p.add(1);
                bits += 8;
            }
            bits -= b;
            *out.add(i) = (total >> bits) & mask;
        }
    }
}

/// `static int slh_fors_sk_gen(SLH_DSA_HASH_CTX *ctx, const uint8_t *sk_seed,`
/// `const uint8_t *pk_seed, uint8_t *adrs, uint32_t id, uint8_t *pk_out, size_t pk_out_len)` —
/// `slh_fors.c:41-54`.
///
/// # Safety
/// `ctx` is live; every span is as the arguments say.
unsafe fn slh_fors_sk_gen(
    ctx: *mut SlhDsaHashCtx,
    sk_seed: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    id: u32,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    let mut sk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (prf, copy, set_type_and_clear, copy_keypair_address, set_tree_index) = unsafe {
        (
            (*(*key).hash_func).prf,
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).copy_keypair_address,
            (*(*key).adrs_func).set_tree_index,
        )
    };
    // SAFETY: `sk_adrs` is writable and `adrs` readable for their own sizes.
    unsafe {
        copy(sk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(sk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_FORS_PRF);
        copy_keypair_address(sk_adrs.as_mut_ptr(), adrs);
        set_tree_index(sk_adrs.as_mut_ptr(), id);
    }
    let _ = pk_out_len;
    // SAFETY: the authority's `PRF`; `pk_out` is writable for `pk_out_len`.
    unsafe { prf(ctx, pk_seed, sk_seed, sk_adrs.as_ptr(), pk_out, pk_out_len) }
}

/// `static int slh_fors_node(SLH_DSA_HASH_CTX *ctx, const uint8_t *sk_seed,`
/// `const uint8_t *pk_seed, uint8_t *adrs, uint32_t node_id, uint32_t height, uint8_t *node,`
/// `size_t node_len)` — `slh_fors.c:77-109`.
///
/// # Safety
/// `ctx` is live; every span is as the arguments say.
unsafe fn slh_fors_node(
    ctx: *mut SlhDsaHashCtx,
    sk_seed: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    node_id: u32,
    height: u32,
    node: *mut u8,
    node_len: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut sk = [0u8; SLH_MAX_N];
    let mut lnode = [0u8; SLH_MAX_N];
    let mut rnode = [0u8; SLH_MAX_N];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (hash_f, hash_h, set_tree_height, set_tree_index, n) = unsafe {
        (
            (*(*key).hash_func).f,
            (*(*key).hash_func).h,
            (*(*key).adrs_func).set_tree_height,
            (*(*key).adrs_func).set_tree_index,
            (*(*key).params).n,
        )
    };

    if height == 0 {
        /* Gets here for leaf nodes. */
        // SAFETY: `slh_fors_sk_gen`'s own contract; `sk` is writable for its length.
        if unsafe {
            slh_fors_sk_gen(
                ctx,
                sk_seed,
                pk_seed,
                adrs,
                node_id,
                sk.as_mut_ptr(),
                sk.len(),
            )
        } != 0
        {
            // SAFETY: `adrs` is writable for its own size.
            unsafe {
                set_tree_height(adrs, 0);
                set_tree_index(adrs, node_id);
            }
            // SAFETY: the authority's `F`; `sk`/`node` are as the lengths say.
            ret = unsafe { hash_f(ctx, pk_seed, adrs, sk.as_ptr(), n as usize, node, node_len) };
        }
        // SAFETY: a local buffer.
        unsafe { OPENSSL_cleanse(sk.as_mut_ptr().cast(), n as usize) };
    } else {
        // SAFETY: two recursive calls, each inside the buffer it is given.
        let ok = unsafe {
            slh_fors_node(
                ctx,
                sk_seed,
                pk_seed,
                adrs,
                2 * node_id,
                height - 1,
                lnode.as_mut_ptr(),
                lnode.len(),
            ) != 0
                && slh_fors_node(
                    ctx,
                    sk_seed,
                    pk_seed,
                    adrs,
                    2 * node_id + 1,
                    height - 1,
                    rnode.as_mut_ptr(),
                    rnode.len(),
                ) != 0
        };
        if ok {
            // SAFETY: `adrs` is writable for its own size.
            unsafe {
                set_tree_height(adrs, height);
                set_tree_index(adrs, node_id);
            }
            // SAFETY: the authority's `H`.
            ret = unsafe {
                hash_h(
                    ctx,
                    pk_seed,
                    adrs,
                    lnode.as_ptr(),
                    rnode.as_ptr(),
                    node,
                    node_len,
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

/// `int ossl_slh_fors_sign(SLH_DSA_HASH_CTX *ctx, const uint8_t *md, const uint8_t *sk_seed,`
/// `const uint8_t *pk_seed, uint8_t *adrs, WPACKET *sig_wpkt)` — `slh_fors.c:131-194`.
///
/// # Safety
/// `ctx` is live; `md` is readable for `(k * a + 7) / 8` bytes; `sig_wpkt` is the signature
/// builder.
pub(crate) unsafe fn ossl_slh_fors_sign(
    ctx: *mut SlhDsaHashCtx,
    md: *const u8,
    sk_seed: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    sig_wpkt: *mut Wpacket,
) -> c_int {
    let mut ret: c_int = 0;
    let mut ids = [0u32; SLH_MAX_K];
    let mut out = [0u8; SLH_MAX_N];
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its params are the caller's.
    let (n, k, a) = unsafe { ((*(*key).params).n, (*(*key).params).k, (*(*key).params).a) };
    let two_power_a: u32 = 1 << a;
    let mut tree_id_times_two_power_a: u32 = 0;

    // SAFETY: `md` is readable for `(k * a + 7) / 8` bytes; `ids` is writable for `k`.
    unsafe { slh_base_2b(md, a, ids.as_mut_ptr(), k as usize) };

    let mut tree_id: u32 = 0;
    while tree_id < k {
        let mut node_id = ids[tree_id as usize];
        let mut tree_offset = tree_id_times_two_power_a;

        // SAFETY: the secret generator's contract; `out` is writable for `n` bytes.
        if unsafe {
            slh_fors_sk_gen(
                ctx,
                sk_seed,
                pk_seed,
                adrs,
                node_id + tree_id_times_two_power_a,
                out.as_mut_ptr(),
                out.len(),
            )
        } == 0
            // SAFETY: `sig_wpkt` is live and `out` is readable for `n` bytes.
            || unsafe { WPACKET_memcpy(sig_wpkt, out.as_ptr().cast(), n as usize) } == 0
        {
            // SAFETY: a local buffer.
            unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len()) };
            return ret;
        }

        let mut layer_addr: u32 = 0;
        while layer_addr < a {
            let s = node_id ^ 1;
            // SAFETY: the node walk's contract; `out` is writable for `n` bytes.
            if unsafe {
                slh_fors_node(
                    ctx,
                    sk_seed,
                    pk_seed,
                    adrs,
                    s + tree_offset,
                    layer_addr,
                    out.as_mut_ptr(),
                    out.len(),
                )
            } == 0
            {
                // SAFETY: a local buffer.
                unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len()) };
                return ret;
            }
            node_id >>= 1;
            tree_offset >>= 1;
            // SAFETY: `sig_wpkt` is live; `out` is readable for `n`.
            if unsafe { WPACKET_memcpy(sig_wpkt, out.as_ptr().cast(), n as usize) } == 0 {
                // SAFETY: a local buffer.
                unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len()) };
                return ret;
            }
            layer_addr += 1;
        }
        tree_id_times_two_power_a += two_power_a;
        tree_id += 1;
    }
    ret = 1;
    /* The authority's `err:` label. */
    // SAFETY: a local buffer.
    unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast(), out.len()) };
    ret
}

/// `int ossl_slh_fors_pk_from_sig(SLH_DSA_HASH_CTX *ctx, PACKET *fors_sig_rpkt,`
/// `const uint8_t *md, const uint8_t *pk_seed, uint8_t *adrs, uint8_t *pk_out,`
/// `size_t pk_out_len)` — `slh_fors.c:214-298`.
///
/// # Safety
/// `ctx` is live; `fors_sig_rpkt` is a live cursor into the caller's signature buffer.
pub(crate) unsafe fn ossl_slh_fors_pk_from_sig(
    ctx: *mut SlhDsaHashCtx,
    fors_sig_rpkt: *mut Packet,
    md: *const u8,
    pk_seed: *const u8,
    adrs: *mut u8,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut ids = [0u32; SLH_MAX_K];
    let mut roots = [0u8; SLH_MAX_ROOTS];
    let mut roots_len: usize = 0;
    let mut pk_adrs: SlhAdrs = [0u8; super::adrs::SLH_ADRS_SIZE_MAX];
    // SAFETY: `Wpacket` is a packet builder of integers and pointers only, and the value is
    // initialised by the `WPACKET_init_static_len` immediately below before it is read.
    let mut root_pkt = unsafe { core::mem::zeroed::<Wpacket>() };
    let wroot_pkt = &mut root_pkt;
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    // SAFETY: `key` is live and its method tables are the authority's.
    let (
        hash_f,
        hash_h,
        copy,
        set_type_and_clear,
        copy_keypair_address,
        set_tree_index,
        set_tree_height,
        a,
        k,
        n,
    ) = unsafe {
        (
            (*(*key).hash_func).f,
            (*(*key).hash_func).h,
            (*(*key).adrs_func).copy,
            (*(*key).adrs_func).set_type_and_clear,
            (*(*key).adrs_func).copy_keypair_address,
            (*(*key).adrs_func).set_tree_index,
            (*(*key).adrs_func).set_tree_height,
            (*(*key).params).a,
            (*(*key).params).k,
            (*(*key).params).n,
        )
    };
    let two_power_a: u32 = 1 << a;
    let mut aoff: u32 = 0;

    // SAFETY: `wroot_pkt` is a live local; `roots` is writable for its length.
    if unsafe { WPACKET_init_static_len(wroot_pkt, roots.as_mut_ptr(), roots.len(), 0) } == 0 {
        return 0;
    }

    // SAFETY: `md` is readable for `(k * a + 7) / 8`; `ids` is writable for `k`.
    unsafe { slh_base_2b(md, a, ids.as_mut_ptr(), k as usize) };

    let mut i: u32 = 0;
    while i < k {
        let mut id = ids[i as usize];
        let mut node_id = id + aoff;

        // SAFETY: `adrs` is writable for its own size.
        unsafe {
            set_tree_height(adrs, 0);
            set_tree_index(adrs, node_id);
        }

        // SAFETY: `fors_sig_rpkt` is a live cursor with at least `n` bytes, or this refuses.
        let sk = unsafe { (*fors_sig_rpkt).get_bytes(n as usize) };
        let Some(sk) = sk else {
            return fors_err(wroot_pkt, &mut roots, k, n, ret);
        };
        let mut node0: *mut u8 = ptr::null_mut();
        // SAFETY: `wroot_pkt` is live and `node0` is a live local.
        if unsafe { WPACKET_allocate_bytes(wroot_pkt, n as usize, &mut node0) } == 0 {
            return fors_err(wroot_pkt, &mut roots, k, n, ret);
        }
        // SAFETY: the authority's `F`; `sk`/`node0` are as the lengths say.
        if unsafe { hash_f(ctx, pk_seed, adrs, sk, n as usize, node0, n as usize) } == 0 {
            return fors_err(wroot_pkt, &mut roots, k, n, ret);
        }

        /* This omits the copying of the nodes that the FIPS 205 code does. */
        let node1 = node0;
        let mut j: u32 = 0;
        while j < a {
            // SAFETY: `fors_sig_rpkt` is a live cursor with at least `n` bytes, or this refuses.
            let authj = unsafe { (*fors_sig_rpkt).get_bytes(n as usize) };
            let Some(authj) = authj else {
                return fors_err(wroot_pkt, &mut roots, k, n, ret);
            };
            // SAFETY: `adrs` is writable for its own size.
            unsafe { set_tree_height(adrs, j + 1) };
            if (id & 1) == 0 {
                node_id >>= 1;
                // SAFETY: `adrs` is writable for its own size.
                unsafe { set_tree_index(adrs, node_id) };
                // SAFETY: the authority's `H`, in place.
                if unsafe { hash_h(ctx, pk_seed, adrs, node0, authj, node1, n as usize) } == 0 {
                    return fors_err(wroot_pkt, &mut roots, k, n, ret);
                }
            } else {
                node_id = (node_id - 1) >> 1;
                // SAFETY: `adrs` is writable for its own size.
                unsafe { set_tree_index(adrs, node_id) };
                // SAFETY: the authority's `H`, in place.
                if unsafe { hash_h(ctx, pk_seed, adrs, authj, node0, node1, n as usize) } == 0 {
                    return fors_err(wroot_pkt, &mut roots, k, n, ret);
                }
            }
            id >>= 1;
            j += 1;
        }
        aoff += two_power_a;
        i += 1;
    }
    // SAFETY: `wroot_pkt` is live and `roots_len` is a live local.
    if unsafe { WPACKET_get_total_written(wroot_pkt, &mut roots_len) } == 0 {
        return fors_err(wroot_pkt, &mut roots, k, n, ret);
    }

    /* The public key is the hash of all the roots of the k trees. */
    // SAFETY: `pk_adrs` is writable and `adrs` readable for their own sizes.
    unsafe {
        copy(pk_adrs.as_mut_ptr(), adrs);
        set_type_and_clear(pk_adrs.as_mut_ptr(), SLH_ADRS_TYPE_FORS_ROOTS);
        copy_keypair_address(pk_adrs.as_mut_ptr(), adrs);
    }
    // SAFETY: the authority's `T`; `roots` is readable for `roots_len`; `pk_out` writable.
    let t = unsafe { (*(*key).hash_func).t };
    // SAFETY: `t` is the authority's own function pointer.
    ret = unsafe {
        t(
            ctx,
            pk_seed,
            pk_adrs.as_ptr(),
            roots.as_ptr(),
            roots_len,
            pk_out,
            pk_out_len,
        )
    };
    /* The authority's `err:` label. */
    // SAFETY: `wroot_pkt` is live and at most `k * n` bytes of `roots` were written.
    unsafe {
        if WPACKET_finish(wroot_pkt) == 0 {
            ret = 0;
        }
        OPENSSL_cleanse(roots.as_mut_ptr().cast(), (k as usize) * (n as usize));
    }
    ret
}

/// The authority's `err:` label of `ossl_slh_fors_pk_from_sig` — `slh_fors.c:292-297`.
///
/// A safe function: its two arguments are this frame's own cursor and its own array, so the
/// interior `WPACKET_finish`/cleanse are the only unsafe operations and they are encapsulated
/// here rather than at seven call sites.
fn fors_err(
    wroot_pkt: *mut Wpacket,
    roots: &mut [u8; SLH_MAX_ROOTS],
    k: u32,
    n: u32,
    ret: c_int,
) -> c_int {
    let mut ret = ret;
    // SAFETY: `wroot_pkt` is this frame's live cursor; the cleanse is inside `roots`.
    unsafe {
        if WPACKET_finish(wroot_pkt) == 0 {
            ret = 0;
        }
        OPENSSL_cleanse(roots.as_mut_ptr().cast(), (k as usize) * (n as usize));
    }
    ret
}
