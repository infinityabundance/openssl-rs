//! `crypto/ec/ec_mult.c` — the wNAF and Montgomery-ladder scalar multiplication, Phase 8.7.
//!
//! Six internals (`ossl_ec_wNAF_mul`, `_precompute_mult`, `_have_precompute_mult`,
//! `ossl_ec_scalar_mul_ladder`, `EC_ec_pre_comp_free`, `_dup`) plus the `ec_pre_comp_new` static
//! and the three `ec_local.h:762-798` `ossl_inline` ladder helpers [`ec_point_ladder_pre`],
//! [`ec_point_ladder_step`] and [`ec_point_ladder_post`]. The plan's §2a names `src/ec/mod.rs`
//! for those three; this module is where the task places them and where their only caller
//! (`ossl_ec_scalar_mul_ladder`) lives.
//!
//! The `ERR_raise` sites are named `err_sites::EC_MULT_<line>`; that stem is not in
//! `gen_err_raise_sites.py`'s `COVERED_FILES` yet.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{fence, AtomicI32, Ordering};

use crate::bn::arith::{BN_add, BN_mul, BN_nnmod};
use crate::bn::bignum::{
    bn_get_top, bn_wexpand, BN_consttime_swap, BN_copy, BN_is_bit_set, BN_is_negative, BN_is_zero,
    BN_set_flags, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new, BN_CTX_start, BnCtx};
use crate::bn::intern::bn_compute_wNAF;
use crate::ec::lib::{
    ossl_ec_point_blind_coordinates, EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_POINT_add,
    EC_POINT_clear_free, EC_POINT_cmp, EC_POINT_copy, EC_POINT_dbl, EC_POINT_free, EC_POINT_invert,
    EC_POINT_is_at_infinity, EC_POINT_new, EC_POINT_set_to_infinity, EC_pre_comp_free,
};
use crate::ec::{EcGroup, EcPoint, Pct};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_malloc_array, CRYPTO_zalloc};

/// The `crypto/ec/ec_mult.c` translation unit, as the allocator reports it.
const FILE: &core::ffi::CStr = c"crypto/ec/ec_mult.c";

/// `struct ec_pre_comp_st` — `crypto/ec/ec_mult.c:37-48`.
///
/// The generic precomputation [`ossl_ec_wNAF_precompute_mult`] builds and
/// [`ossl_ec_wNAF_mul`] reads. It is `EcPreCompSt` here rather than `EcPreComp` because that
/// name is the anonymous *union* `ec_local.h:276-283` in [`crate::ec`]; the authority's two
/// types are distinct and a collision would rename a landed shape.
#[repr(C)]
pub(crate) struct EcPreCompSt {
    /// `const EC_GROUP *group` — the parent group, borrowed not owned.
    pub(crate) group: *const EcGroup,
    /// `size_t blocksize` — block size for wNAF splitting.
    pub(crate) blocksize: usize,
    /// `size_t numblocks` — maximum number of blocks with precomputation.
    pub(crate) numblocks: usize,
    /// `size_t w` — window size.
    pub(crate) w: usize,
    /// `EC_POINT **points` — precomputed multiples of the generator, terminated by NULL.
    pub(crate) points: *mut *mut EcPoint,
    /// `size_t num` — `numblocks * 2^(w-1)`.
    pub(crate) num: usize,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` on this profile.
    pub(crate) references: AtomicI32,
}

/// `static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)` — `crypto/ec/ec_mult.c:50-70`.
///
/// # Safety
///
/// `group` is null or live; the returned pointer is null or owned by the caller.
unsafe fn ec_pre_comp_new(group: *const EcGroup) -> *mut EcPreCompSt {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            return ptr::null_mut();
        }

        let ret = CRYPTO_zalloc(core::mem::size_of::<EcPreCompSt>(), FILE.as_ptr(), 57)
            .cast::<EcPreCompSt>();
        if ret.is_null() {
            return ret;
        }

        (*ret).group = group;
        (*ret).blocksize = 8; /* default */
        (*ret).w = 4; /* default */

        // `if (!CRYPTO_NEW_REF(&ret->references, 1))` — this profile's header arm is the plain
        // store, which cannot fail, so the authority's free-and-answer-NULL limb is unreachable
        // and is not written. `src/dsa/object.rs` records the same reduction.
        (*ret).references.store(1, Ordering::Relaxed);
        ret
    }
}

/// `EC_PRE_COMP *EC_ec_pre_comp_dup(EC_PRE_COMP *pre)` — `crypto/ec/ec_mult.c:72-78`.
///
/// `#[allow(dead_code)]`'s reason: **its readers are `ec_lib.c`'s `EC_GROUP_copy` and the
/// `EC_PRE_COMP` wiring** it owes (`EC_pre_comp_dup`'s two call sites), which land with the
/// keystone rather than with this unit.
///
/// # Safety
///
/// `pre` is null or a live precomputation object; the returned pointer is `pre`.
#[allow(dead_code)] // read by `ec_lib.c`'s `EC_GROUP_copy` and `EC_pre_comp_dup`
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn EC_ec_pre_comp_dup(pre: *mut EcPreCompSt) -> *mut EcPreCompSt {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pre.is_null() {
            // `CRYPTO_UP_REF` is a relaxed fetch-add. The new count is not readable by this
            // caller, but the authority computes it and so does this.
            let _i = (*pre)
                .references
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
        }
        pre
    }
}

/// `void EC_ec_pre_comp_free(EC_PRE_COMP *pre)` — `crypto/ec/ec_mult.c:80-102`.
///
/// # Safety
///
/// `pre` is null or live, and must not be used again after this call unless a reference remains.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn EC_ec_pre_comp_free(pre: *mut EcPreCompSt) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if pre.is_null() {
            return;
        }

        // `CRYPTO_DOWN_REF(&pre->references, &i)`: release fetch-sub, then the header's
        // conditional acquire fence at zero.
        let i = (*pre)
            .references
            .fetch_sub(1, Ordering::Release)
            .wrapping_sub(1);
        if i == 0 {
            fence(Ordering::Acquire);
        }
        // `REF_PRINT_COUNT` is an `OSSL_TRACE3` omitted with this sentence as its record;
        // `REF_ASSERT_ISNT(i < 0)` is empty under this profile's `NDEBUG`.
        if i > 0 {
            return;
        }

        if !(*pre).points.is_null() {
            let mut pts = (*pre).points;

            while !(*pts).is_null() {
                EC_POINT_free(*pts);
                pts = pts.add(1);
            }
            CRYPTO_free((*pre).points.cast(), FILE.as_ptr(), 98);
        }
        // `CRYPTO_FREE_REF(&pre->references)` is empty on this profile's arm of the header.
        CRYPTO_free(pre.cast(), FILE.as_ptr(), 101);
    }
}

/// `static ossl_inline int ec_point_ladder_pre(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec_local.h:762-773`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is null or live.
pub(crate) unsafe fn ec_point_ladder_pre(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(ladder_pre) = (*(*group).meth).ladder_pre {
            return ladder_pre(group, r, s, p, ctx);
        }

        if EC_POINT_copy(s, p) == 0 || EC_POINT_dbl(group, r, s, ctx) == 0 {
            return 0;
        }

        1
    }
}

/// `static ossl_inline int ec_point_ladder_step(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec_local.h:775-786`.
///
/// # Safety
///
/// As [`ec_point_ladder_pre`]'s contract.
pub(crate) unsafe fn ec_point_ladder_step(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(ladder_step) = (*(*group).meth).ladder_step {
            return ladder_step(group, r, s, p, ctx);
        }

        if EC_POINT_add(group, s, r, s, ctx) == 0 || EC_POINT_dbl(group, r, r, ctx) == 0 {
            return 0;
        }

        1
    }
}

/// `static ossl_inline int ec_point_ladder_post(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec_local.h:788-798`.
///
/// # Safety
///
/// As [`ec_point_ladder_pre`]'s contract.
pub(crate) unsafe fn ec_point_ladder_post(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(ladder_post) = (*(*group).meth).ladder_post {
            return ladder_post(group, r, s, p, ctx);
        }

        1
    }
}

/// `EC_POINT_BN_set_flags(P, flags)` — `crypto/ec/ec_mult.c:104-109`.
///
/// # Safety
///
/// `p` is live and its three coordinates are live.
unsafe fn ec_point_bn_set_flags(p: *mut EcPoint, flags: c_int) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_set_flags((*p).x, flags);
        BN_set_flags((*p).y, flags);
        BN_set_flags((*p).z, flags);
    }
}

/// `EC_POINT_CSWAP(c, a, b, w, t)` — `crypto/ec/ec_mult.c:279-287`.
///
/// Both points' coordinates are conditionally swapped, and the two `Z_is_one` flags are
/// exchanged exactly when the flags differ and the condition is set; the answer is that
/// difference, which the authority stores in `t` and drops.
///
/// # Safety
///
/// `a` and `b` are live points with live coordinates.
unsafe fn ec_point_cswap(c: c_int, a: *mut EcPoint, b: *mut EcPoint, w: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_consttime_swap(c as core::ffi::c_ulong, (*a).x, (*b).x, w);
        BN_consttime_swap(c as core::ffi::c_ulong, (*a).y, (*b).y, w);
        BN_consttime_swap(c as core::ffi::c_ulong, (*a).z, (*b).z, w);
        let t = ((*a).z_is_one ^ (*b).z_is_one) & c;
        (*a).z_is_one ^= t;
        (*b).z_is_one ^= t;
        t
    }
}

/// `int ossl_ec_scalar_mul_ladder(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
/// const EC_POINT *point, BN_CTX *ctx)` — `crypto/ec/ec_mult.c:140-380`.
///
/// # Safety
///
/// `group` is live with a non-zero order and cofactor; `r` is live; `scalar` is live; `point` is
/// null or live; `ctx` is a live context.
pub(crate) unsafe extern "C" fn ossl_ec_scalar_mul_ladder(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
    point: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* early exit if the input point is the point at infinity */
        if !point.is_null() && EC_POINT_is_at_infinity(group, point) != 0 {
            return EC_POINT_set_to_infinity(group, r);
        }

        if BN_is_zero((*group).order) != 0 {
            raise_site(&err_sites::EC_MULT_157);
            return 0;
        }
        if BN_is_zero((*group).cofactor) != 0 {
            raise_site(&err_sites::EC_MULT_161);
            return 0;
        }

        BN_CTX_start(ctx);

        let p = EC_POINT_new(group);
        let s = EC_POINT_new(group);
        if p.is_null() || s.is_null() {
            raise_site(&err_sites::EC_MULT_169);
            EC_POINT_free(p);
            EC_POINT_clear_free(s);
            BN_CTX_end(ctx);
            return ret;
        }

        'err: {
            if point.is_null() {
                if EC_POINT_copy(p, (*group).generator) == 0 {
                    raise_site(&err_sites::EC_MULT_175);
                    break 'err;
                }
            } else if EC_POINT_copy(p, point) == 0 {
                raise_site(&err_sites::EC_MULT_180);
                break 'err;
            }

            ec_point_bn_set_flags(p, BN_FLG_CONSTTIME);
            ec_point_bn_set_flags(r, BN_FLG_CONSTTIME);
            ec_point_bn_set_flags(s, BN_FLG_CONSTTIME);

            let cardinality = BN_CTX_get(ctx);
            let lambda = BN_CTX_get(ctx);
            let k = BN_CTX_get(ctx);
            if k.is_null() {
                raise_site(&err_sites::EC_MULT_193);
                break 'err;
            }

            if BN_mul(cardinality, (*group).order, (*group).cofactor, ctx) == 0 {
                raise_site(&err_sites::EC_MULT_198);
                break 'err;
            }

            /*
             * Group cardinalities are often on a word boundary.
             * So when we pad the scalar, some timing diff might
             * pop if it needs to be expanded due to carries.
             * So expand ahead of time.
             */
            let cardinality_bits = crate::bn::bignum::BN_num_bits(cardinality);
            let mut group_top = bn_get_top(cardinality);
            if bn_wexpand(k, group_top + 2).is_null() || bn_wexpand(lambda, group_top + 2).is_null()
            {
                raise_site(&err_sites::EC_MULT_212);
                break 'err;
            }

            if BN_copy(k, scalar).is_null() {
                raise_site(&err_sites::EC_MULT_217);
                break 'err;
            }

            BN_set_flags(k, BN_FLG_CONSTTIME);

            if crate::bn::bignum::BN_num_bits(k) > cardinality_bits || BN_is_negative(k) != 0 {
                /*-
                 * this is an unusual input, and we don't guarantee
                 * constant-timeness
                 */
                if BN_nnmod(k, k, cardinality, ctx) == 0 {
                    raise_site(&err_sites::EC_MULT_229);
                    break 'err;
                }
            }

            if BN_add(lambda, k, cardinality) == 0 {
                raise_site(&err_sites::EC_MULT_235);
                break 'err;
            }
            BN_set_flags(lambda, BN_FLG_CONSTTIME);
            if BN_add(k, lambda, cardinality) == 0 {
                raise_site(&err_sites::EC_MULT_240);
                break 'err;
            }
            /*
             * lambda := scalar + cardinality
             * k := scalar + 2*cardinality
             */
            let kbit = BN_is_bit_set(lambda, cardinality_bits);
            BN_consttime_swap(kbit as core::ffi::c_ulong, k, lambda, group_top + 2);

            group_top = bn_get_top((*group).field);
            if bn_wexpand((*s).x, group_top).is_null()
                || bn_wexpand((*s).y, group_top).is_null()
                || bn_wexpand((*s).z, group_top).is_null()
                || bn_wexpand((*r).x, group_top).is_null()
                || bn_wexpand((*r).y, group_top).is_null()
                || bn_wexpand((*r).z, group_top).is_null()
                || bn_wexpand((*p).x, group_top).is_null()
                || bn_wexpand((*p).y, group_top).is_null()
                || bn_wexpand((*p).z, group_top).is_null()
            {
                raise_site(&err_sites::EC_MULT_260);
                break 'err;
            }

            /* ensure input point is in affine coords for ladder step efficiency */
            if (*p).z_is_one == 0 {
                match (*(*group).meth).make_affine {
                    Some(make_affine) => {
                        if make_affine(group, p, ctx) == 0 {
                            raise_site(&err_sites::EC_MULT_266);
                            break 'err;
                        }
                    }
                    None => {
                        raise_site(&err_sites::EC_MULT_266);
                        break 'err;
                    }
                }
            }

            /* Initialize the Montgomery ladder */
            if ec_point_ladder_pre(group, r, s, p, ctx) == 0 {
                raise_site(&err_sites::EC_MULT_272);
                break 'err;
            }

            /* top bit is a 1, in a fixed pos */
            let mut pbit = 1;

            /*-
             * The ladder step, with branches, is
             *
             * k[i] == 0: S = add(R, S), R = dbl(R)
             * k[i] == 1: R = add(S, R), S = dbl(S)
             *
             * Swapping R, S conditionally on k[i] leaves you with state
             *
             * k[i] == 0: T, U = R, S
             * k[i] == 1: T, U = S, R
             *
             * Then perform the ECC ops.
             *
             * U = add(T, U)
             * T = dbl(T)
             *
             * Which leaves you with state
             *
             * k[i] == 0: U = add(R, S), T = dbl(R)
             * k[i] == 1: U = add(S, R), T = dbl(S)
             *
             * Swapping T, U conditionally on k[i] leaves you with state
             *
             * k[i] == 0: R, S = T, U
             * k[i] == 1: R, S = U, T
             *
             * Which leaves you with state
             *
             * k[i] == 0: S = add(R, S), R = dbl(R)
             * k[i] == 1: R = add(S, R), S = dbl(S)
             *
             * So we get the same logic, but instead of a branch it's a
             * conditional swap, followed by ECC ops, then another conditional swap.
             *
             * Optimization: The end of iteration i and start of i-1 looks like
             *
             * ...
             * CSWAP(k[i], R, S)
             * ECC
             * CSWAP(k[i], R, S)
             * (next iteration)
             * CSWAP(k[i-1], R, S)
             * ECC
             * CSWAP(k[i-1], R, S)
             * ...
             *
             * So instead of two contiguous swaps, you can merge the condition
             * bits and do a single swap.
             *
             * k[i]   k[i-1]    Outcome
             * 0      0         No Swap
             * 0      1         Swap
             * 1      0         Swap
             * 1      1         No Swap
             *
             * This is XOR. pbit tracks the previous bit of k.
             */

            let mut i = cardinality_bits - 1;
            while i >= 0 {
                let kbit = BN_is_bit_set(k, i) ^ pbit;
                let _z_is_one = ec_point_cswap(kbit, r, s, group_top);

                /* Perform a single step of the Montgomery ladder */
                if ec_point_ladder_step(group, r, s, p, ctx) == 0 {
                    raise_site(&err_sites::EC_MULT_353);
                    break 'err;
                }
                /*
                 * pbit logic merges this cswap with that of the
                 * next iteration
                 */
                pbit ^= kbit;
                i -= 1;
            }
            /* one final cswap to move the right value into r */
            let _z_is_one = ec_point_cswap(pbit, r, s, group_top);

            /* Finalize ladder (and recover full point coordinates) */
            if ec_point_ladder_post(group, r, s, p, ctx) == 0 {
                raise_site(&err_sites::EC_MULT_368);
                break 'err;
            }

            ret = 1;
        }

        EC_POINT_free(p);
        EC_POINT_clear_free(s);
        BN_CTX_end(ctx);
    }
    ret
}

/// `EC_window_bits_for_scalar_size(b)` — `crypto/ec/ec_mult.c:389-394`.
///
/// The authority's `#define`, expanded at its two call sites.
fn ec_window_bits_for_scalar_size(b: usize) -> usize {
    if b >= 2000 {
        6
    } else if b >= 800 {
        5
    } else if b >= 300 {
        4
    } else if b >= 70 {
        3
    } else if b >= 20 {
        2
    } else {
        1
    }
}

/// `int ossl_ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num,
/// const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)` —
/// `crypto/ec/ec_mult.c:403-794`.
///
/// # Safety
///
/// `group` is live; `r` is live; `scalar` is null or live; `points` and `scalars` each hold `num`
/// live entries; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_wNAF_mul(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
    num: usize,
    points: *mut *const EcPoint,
    scalars: *mut *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut generator: *const EcPoint = ptr::null();
    let mut tmp: *mut EcPoint = ptr::null_mut();
    let mut totalnum: usize;
    let mut blocksize: usize = 0;
    let mut numblocks: usize = 0;
    let mut pre_points_per_block: usize = 0;
    let wsize: *mut usize;
    let wnaf: *mut *mut c_char;
    let wnaf_len: *mut usize;
    let mut max_len: usize = 0;
    let mut num_val: usize;
    let mut val: *mut *mut EcPoint = ptr::null_mut();
    let val_sub: *mut *mut *mut EcPoint;
    let mut pre_comp: *mut EcPreCompSt = ptr::null_mut();
    let mut num_scalar = 0;
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if BN_is_zero((*group).order) == 0 && BN_is_zero((*group).cofactor) == 0 {
            /*-
             * Handle the common cases where the scalar is secret, enforcing a
             * scalar multiplication implementation based on a Montgomery ladder,
             * with various timing attack defenses.
             */
            if scalar != (*group).order && !scalar.is_null() && num == 0 {
                /*-
                 * In this case we want to compute scalar * GeneratorPoint: this
                 * codepath is reached most prominently by (ephemeral) key
                 * generation of EC cryptosystems (i.e. ECDSA keygen and sign setup,
                 * ECDH keygen/first half), where the scalar is always secret. This
                 * is why we ignore if BN_FLG_CONSTTIME is actually set and we
                 * always call the ladder version.
                 */
                return ossl_ec_scalar_mul_ladder(group, r, scalar, ptr::null(), ctx);
            }
            if scalar.is_null() && num == 1 && *scalars != (*group).order {
                /*-
                 * In this case we want to compute scalar * VariablePoint: this
                 * codepath is reached most prominently by the second half of ECDH,
                 * where the secret scalar is multiplied by the peer's public point.
                 * To protect the secret scalar, we ignore if BN_FLG_CONSTTIME is
                 * actually set and we always call the ladder version.
                 */
                return ossl_ec_scalar_mul_ladder(group, r, *scalars, *points, ctx);
            }
        }

        if !scalar.is_null() {
            generator = EC_GROUP_get0_generator(group);
            if generator.is_null() {
                raise_site(&err_sites::EC_MULT_464);
                return ret;
            }

            /* look if we can use precomputed multiples of generator */

            let pre = (*group).pre_comp.ec.cast::<EcPreCompSt>();
            if !pre.is_null()
                && (*pre).numblocks != 0
                && EC_POINT_cmp(group, generator, *(*pre).points, ctx) == 0
            {
                pre_comp = pre;
                blocksize = (*pre_comp).blocksize;

                /*
                 * determine maximum number of blocks that wNAF splitting may
                 * yield (NB: maximum wNAF length is bit length plus one)
                 */
                numblocks = (crate::bn::bignum::BN_num_bits(scalar) as usize) / blocksize + 1;

                /*
                 * we cannot use more blocks than we have precomputation for
                 */
                if numblocks > (*pre_comp).numblocks {
                    numblocks = (*pre_comp).numblocks;
                }

                pre_points_per_block = 1usize << ((*pre_comp).w - 1);

                /* check that pre_comp looks sane */
                if (*pre_comp).num != (*pre_comp).numblocks * pre_points_per_block {
                    raise_site(&err_sites::EC_MULT_491);
                    return ret;
                }
            } else {
                /* can't use precomputation */
                pre_comp = ptr::null_mut();
                numblocks = 1;
                num_scalar = 1; /* treat 'scalar' like 'num'-th element of 'scalars' */
            }
        }

        totalnum = num + numblocks;

        wsize = CRYPTO_malloc_array(totalnum, core::mem::size_of::<usize>(), FILE.as_ptr(), 505)
            .cast::<usize>();
        wnaf_len = CRYPTO_malloc_array(totalnum, core::mem::size_of::<usize>(), FILE.as_ptr(), 506)
            .cast::<usize>();
        /* include space for pivot */
        wnaf = CRYPTO_malloc_array(
            totalnum + 1,
            core::mem::size_of::<*mut c_char>(),
            FILE.as_ptr(),
            508,
        )
        .cast::<*mut c_char>();
        val_sub = CRYPTO_malloc_array(
            totalnum,
            core::mem::size_of::<*mut *mut EcPoint>(),
            FILE.as_ptr(),
            509,
        )
        .cast::<*mut *mut EcPoint>();

        /* Ensure wNAF is initialised in case we end up going to err */
        if !wnaf.is_null() {
            *wnaf = ptr::null_mut(); /* preliminary pivot */
        }

        if wsize.is_null() || wnaf_len.is_null() || wnaf.is_null() || val_sub.is_null() {
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }

        /*
         * num_val will be the total number of temporarily precomputed points
         */
        num_val = 0;

        let mut i: usize = 0;
        while i < num + num_scalar as usize {
            let bits = if i < num {
                crate::bn::bignum::BN_num_bits(*scalars.add(i))
            } else {
                crate::bn::bignum::BN_num_bits(scalar)
            };
            *wsize.add(i) = ec_window_bits_for_scalar_size(bits as usize);
            num_val += 1usize << (*wsize.add(i) - 1);
            *wnaf.add(i + 1) = ptr::null_mut(); /* make sure we always have a pivot */
            *wnaf.add(i) = bn_compute_wNAF(
                if i < num { *scalars.add(i) } else { scalar },
                *wsize.add(i) as c_int,
                wnaf_len.add(i),
            );
            if (*wnaf.add(i)).is_null() {
                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
            }
            if *wnaf_len.add(i) > max_len {
                max_len = *wnaf_len.add(i);
            }
            i += 1;
        }

        if numblocks != 0 {
            /* we go here iff scalar != NULL */

            if pre_comp.is_null() {
                if num_scalar != 1 {
                    raise_site(&err_sites::EC_MULT_543);
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }
                /* we have already generated a wNAF for 'scalar' */
            } else {
                let mut tmp_len: usize = 0;

                if num_scalar != 0 {
                    raise_site(&err_sites::EC_MULT_552);
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }

                /*
                 * use the window size for which we have precomputation
                 */
                *wsize.add(num) = (*pre_comp).w;
                let tmp_wnaf = bn_compute_wNAF(scalar, *wsize.add(num) as c_int, &mut tmp_len);
                if tmp_wnaf.is_null() {
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }

                if tmp_len <= max_len {
                    /*
                     * One of the other wNAFs is at least as long as the wNAF
                     * belonging to the generator, so wNAF splitting will not buy
                     * us anything.
                     */

                    /* `numblocks` is not read again on this arm; the authority's own
                     * `numblocks = 1;` store here is dead and is not transcribed. */
                    totalnum = num + 1; /* don't use wNAF splitting */
                    *wnaf.add(num) = tmp_wnaf;
                    *wnaf.add(num + 1) = ptr::null_mut();
                    *wnaf_len.add(num) = tmp_len;
                    /*
                     * pre_comp->points starts with the points that we need here:
                     */
                    *val_sub.add(num) = (*pre_comp).points;
                } else {
                    /*
                     * don't include tmp_wNAF directly into wNAF array - use wNAF
                     * splitting and include the blocks
                     */

                    let mut pp = tmp_wnaf;
                    let mut tmp_points = (*pre_comp).points;

                    if tmp_len < numblocks * blocksize {
                        /*
                         * possibly we can do with fewer blocks than estimated
                         */
                        numblocks = tmp_len.div_ceil(blocksize);
                        if numblocks > (*pre_comp).numblocks {
                            raise_site(&err_sites::EC_MULT_595);
                            CRYPTO_free(tmp_wnaf.cast(), FILE.as_ptr(), 596);
                            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                        }
                        totalnum = num + numblocks;
                    }

                    /* split wNAF in 'numblocks' parts */
                    let mut ii = num;
                    while ii < totalnum {
                        if ii < totalnum - 1 {
                            *wnaf_len.add(ii) = blocksize;
                            if tmp_len < blocksize {
                                raise_site(&err_sites::EC_MULT_610);
                                CRYPTO_free(tmp_wnaf.cast(), FILE.as_ptr(), 611);
                                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                            }
                            tmp_len -= blocksize;
                        } else {
                            /*
                             * last block gets whatever is left (this could be
                             * more or less than 'blocksize'!)
                             */
                            *wnaf_len.add(ii) = tmp_len;
                        }

                        *wnaf.add(ii + 1) = ptr::null_mut();
                        *wnaf.add(ii) =
                            CRYPTO_malloc(*wnaf_len.add(ii), FILE.as_ptr(), 623).cast::<c_char>();
                        if (*wnaf.add(ii)).is_null() {
                            CRYPTO_free(tmp_wnaf.cast(), FILE.as_ptr(), 625);
                            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                        }
                        ptr::copy_nonoverlapping(pp, *wnaf.add(ii), *wnaf_len.add(ii));
                        if *wnaf_len.add(ii) > max_len {
                            max_len = *wnaf_len.add(ii);
                        }

                        if (*tmp_points).is_null() {
                            raise_site(&err_sites::EC_MULT_633);
                            CRYPTO_free(tmp_wnaf.cast(), FILE.as_ptr(), 634);
                            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                        }
                        *val_sub.add(ii) = tmp_points;
                        tmp_points = tmp_points.add(pre_points_per_block);
                        pp = pp.add(blocksize);
                        ii += 1;
                    }
                    CRYPTO_free(tmp_wnaf.cast(), FILE.as_ptr(), 641);
                }
            }
        }

        /*
         * All points we precompute now go into a single array 'val'.
         * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
         * subarray of 'pre_comp->points' if we already have precomputation.
         */
        val = CRYPTO_malloc_array(
            num_val + 1,
            core::mem::size_of::<*mut EcPoint>(),
            FILE.as_ptr(),
            651,
        )
        .cast::<*mut EcPoint>();
        if val.is_null() {
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }
        *val.add(num_val) = ptr::null_mut(); /* pivot element */

        /* allocate points for precomputation */
        let mut v = val;
        i = 0;
        while i < num + num_scalar as usize {
            *val_sub.add(i) = v;
            let mut j: usize = 0;
            while j < (1usize << (*wsize.add(i) - 1)) {
                *v = EC_POINT_new(group);
                if (*v).is_null() {
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }
                v = v.add(1);
                j += 1;
            }
            i += 1;
        }
        if v != val.add(num_val) {
            raise_site(&err_sites::EC_MULT_668);
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }

        tmp = EC_POINT_new(group);
        if tmp.is_null() {
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }

        /*-
         * prepare precomputed values:
         *    val_sub[i][0] :=     points[i]
         *    val_sub[i][1] := 3 * points[i]
         *    val_sub[i][2] := 5 * points[i]
         *    ...
         */
        i = 0;
        while i < num + num_scalar as usize {
            if i < num {
                if EC_POINT_copy(*(*val_sub.add(i)), *points.add(i)) == 0 {
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }
            } else if EC_POINT_copy(*(*val_sub.add(i)), generator) == 0 {
                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
            }

            if *wsize.add(i) > 1 {
                if EC_POINT_dbl(group, tmp, *(*val_sub.add(i)), ctx) == 0 {
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }
                let mut j: usize = 1;
                while j < (1usize << (*wsize.add(i) - 1)) {
                    if EC_POINT_add(
                        group,
                        *(*val_sub.add(i)).add(j),
                        *(*val_sub.add(i)).add(j - 1),
                        tmp,
                        ctx,
                    ) == 0
                    {
                        return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                    }
                    j += 1;
                }
            }
            i += 1;
        }

        match (*(*group).meth).points_make_affine {
            Some(points_make_affine) => {
                if points_make_affine(group, num_val, val, ctx) == 0 {
                    return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                }
            }
            None => return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub),
        }

        let mut r_is_at_infinity = 1;
        let mut r_is_inverted = 0;

        if max_len > c_int::MAX as usize {
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }
        let mut k = (max_len - 1) as c_int;
        while k >= 0 {
            if r_is_at_infinity == 0 && EC_POINT_dbl(group, r, r, ctx) == 0 {
                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
            }

            i = 0;
            while i < totalnum {
                if *wnaf_len.add(i) > k as usize {
                    let digit = *(*wnaf.add(i)).add(k as usize) as c_int;

                    if digit != 0 {
                        let is_neg = c_int::from(digit < 0);

                        let mut digit = digit;
                        if is_neg != 0 {
                            digit = -digit;
                        }

                        if is_neg != r_is_inverted {
                            if r_is_at_infinity == 0 && EC_POINT_invert(group, r, ctx) == 0 {
                                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                            }
                            r_is_inverted = c_int::from(r_is_inverted == 0);
                        }

                        /* digit > 0 */

                        if r_is_at_infinity != 0 {
                            if EC_POINT_copy(r, *(*val_sub.add(i)).add((digit >> 1) as usize)) == 0
                            {
                                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                            }

                            /*-
                             * Apply coordinate blinding for EC_POINT.
                             *
                             * The underlying EC_METHOD can optionally implement this function:
                             * ossl_ec_point_blind_coordinates() returns 0 in case of errors or 1 on
                             * success or if coordinate blinding is not implemented for this
                             * group.
                             */
                            if ossl_ec_point_blind_coordinates(group, r, ctx) == 0 {
                                raise_site(&err_sites::EC_MULT_749);
                                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                            }

                            r_is_at_infinity = 0;
                        } else if EC_POINT_add(
                            group,
                            r,
                            r,
                            *(*val_sub.add(i)).add((digit >> 1) as usize),
                            ctx,
                        ) == 0
                        {
                            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
                        }
                    }
                }
                i += 1;
            }
            k -= 1;
        }

        if r_is_at_infinity != 0 {
            if EC_POINT_set_to_infinity(group, r) == 0 {
                return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
            }
        } else if r_is_inverted != 0 && EC_POINT_invert(group, r, ctx) == 0 {
            return wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub);
        }

        ret = 1;

        wnaf_mul_err(ret, tmp, wsize, wnaf_len, wnaf, val, val_sub)
    }
}

/// The authority's `err:` label of [`ossl_ec_wNAF_mul`] — `crypto/ec/ec_mult.c:774-793`.
///
/// It releases every temporary the function allocated and answers `ret`.
///
/// # Safety
///
/// Every pointer is one the caller of [`ossl_ec_wNAF_mul`] allocated and has not yet released.
unsafe fn wnaf_mul_err(
    ret: c_int,
    tmp: *mut EcPoint,
    wsize: *mut usize,
    wnaf_len: *mut usize,
    wnaf: *mut *mut c_char,
    val: *mut *mut EcPoint,
    val_sub: *mut *mut *mut EcPoint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        EC_POINT_free(tmp);
        CRYPTO_free(wsize.cast(), FILE.as_ptr(), 776);
        CRYPTO_free(wnaf_len.cast(), FILE.as_ptr(), 777);
        if !wnaf.is_null() {
            let mut w = wnaf;

            while !(*w).is_null() {
                CRYPTO_free((*w).cast(), FILE.as_ptr(), 782);
                w = w.add(1);
            }

            CRYPTO_free(wnaf.cast(), FILE.as_ptr(), 784);
        }
        if !val.is_null() {
            let mut v = val;
            while !(*v).is_null() {
                EC_POINT_clear_free(*v);
                v = v.add(1);
            }

            CRYPTO_free(val.cast(), FILE.as_ptr(), 790);
        }
        CRYPTO_free(val_sub.cast(), FILE.as_ptr(), 792);
        ret
    }
}

/// `int ossl_ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ec_mult.c:816-973`.
///
/// `#[allow(dead_code)]`'s reason: **its reader is `ec_lib.c`'s `EC_GROUP_precompute_mult`**,
/// which lands with the keystone.
///
/// # Safety
///
/// `group` is live and writable; `ctx` is null or live.
#[allow(dead_code)] // read by `ec_lib.c`'s `EC_GROUP_precompute_mult`
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_wNAF_precompute_mult(
    group: *mut EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut used_ctx = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;
    let mut points: *mut *mut EcPoint = ptr::null_mut();
    let mut var: *mut *mut EcPoint;
    let mut tmp_point: *mut EcPoint = ptr::null_mut();
    let mut base: *mut EcPoint = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* if there is an old EC_PRE_COMP object, throw it away */
        EC_pre_comp_free(group);
        let mut pre_comp = ec_pre_comp_new(group);
        if pre_comp.is_null() {
            return 0;
        }

        'outer: {
            let generator = EC_GROUP_get0_generator(group);
            if generator.is_null() {
                raise_site(&err_sites::EC_MULT_837);
                break 'outer;
            }

            if ctx.is_null() {
                new_ctx = BN_CTX_new();
                ctx = new_ctx;
            }
            if ctx.is_null() {
                break 'outer;
            }

            BN_CTX_start(ctx);
            used_ctx = 1;

            let order = EC_GROUP_get0_order(group);
            if order.is_null() {
                break 'outer;
            }
            if BN_is_zero(order) != 0 {
                raise_site(&err_sites::EC_MULT_855);
                break 'outer;
            }

            let bits = crate::bn::bignum::BN_num_bits(order) as usize;
            /*
             * The following parameters mean we precompute (approximately) one point
             * per bit. TBD: The combination 8, 4 is perfect for 160 bits; for other
             * bit lengths, other parameter combinations might provide better
             * efficiency.
             */
            let blocksize: usize = 8;
            let mut w: usize = 4;
            if ec_window_bits_for_scalar_size(bits) > w {
                /* let's not make the window too small ... */
                w = ec_window_bits_for_scalar_size(bits);
            }

            let numblocks = bits.div_ceil(blocksize);

            let pre_points_per_block = 1usize << (w - 1);
            let num = pre_points_per_block * numblocks;

            points = CRYPTO_malloc_array(
                num + 1,
                core::mem::size_of::<*mut EcPoint>(),
                FILE.as_ptr(),
                881,
            )
            .cast::<*mut EcPoint>();
            if points.is_null() {
                break 'outer;
            }

            var = points;
            *var.add(num) = ptr::null_mut(); /* pivot */
            let mut i: usize = 0;
            while i < num {
                *var.add(i) = EC_POINT_new(group);
                if (*var.add(i)).is_null() {
                    raise_site(&err_sites::EC_MULT_889);
                    break 'outer;
                }
                i += 1;
            }

            tmp_point = EC_POINT_new(group);
            base = EC_POINT_new(group);
            if tmp_point.is_null() || base.is_null() {
                raise_site(&err_sites::EC_MULT_896);
                break 'outer;
            }

            if EC_POINT_copy(base, generator) == 0 {
                break 'outer;
            }

            /* do the precomputation */
            i = 0;
            while i < numblocks {
                if EC_POINT_dbl(group, tmp_point, base, ctx) == 0 {
                    break 'outer;
                }

                if EC_POINT_copy(*var, base) == 0 {
                    break 'outer;
                }
                var = var.add(1);
                let mut j: usize = 1;
                while j < pre_points_per_block {
                    /*
                     * calculate odd multiples of the current base point
                     */
                    if EC_POINT_add(group, *var, tmp_point, *var.sub(1), ctx) == 0 {
                        break 'outer;
                    }
                    var = var.add(1);
                    j += 1;
                }

                if i < numblocks - 1 {
                    /*
                     * get the next base (multiply current one by 2^blocksize)
                     */
                    if blocksize <= 2 {
                        raise_site(&err_sites::EC_MULT_928);
                        break 'outer;
                    }

                    if EC_POINT_dbl(group, base, tmp_point, ctx) == 0 {
                        break 'outer;
                    }
                    let mut kk: usize = 2;
                    while kk < blocksize {
                        if EC_POINT_dbl(group, base, base, ctx) == 0 {
                            break 'outer;
                        }
                        kk += 1;
                    }
                }
                i += 1;
            }

            match (*(*group).meth).points_make_affine {
                Some(points_make_affine) => {
                    if points_make_affine(group, num, points, ctx) == 0 {
                        break 'outer;
                    }
                }
                None => break 'outer,
            }

            (*pre_comp).group = group;
            (*pre_comp).blocksize = blocksize;
            (*pre_comp).numblocks = numblocks;
            (*pre_comp).w = w;
            (*pre_comp).points = points;
            points = ptr::null_mut();
            (*pre_comp).num = num;
            /* SETPRECOMP(group, ec, pre_comp) */
            (*group).pre_comp_type = Pct::Ec;
            (*group).pre_comp.ec = pre_comp.cast();
            pre_comp = ptr::null_mut();
            ret = 1;
        }

        if used_ctx != 0 {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(new_ctx);
        EC_ec_pre_comp_free(pre_comp);
        if !points.is_null() {
            let mut p = points;
            while !(*p).is_null() {
                EC_POINT_free(*p);
                p = p.add(1);
            }
            CRYPTO_free(points.cast(), FILE.as_ptr(), 968);
        }
        EC_POINT_free(tmp_point);
        EC_POINT_free(base);
    }
    ret
}

/// `int ossl_ec_wNAF_have_precompute_mult(const EC_GROUP *group)` —
/// `crypto/ec/ec_mult.c:975-978`.
///
/// The authority's `HAVEPRECOMP(group, ec)`.
///
/// `#[allow(dead_code)]`'s reason: **its reader is `ec_lib.c`'s
/// `EC_GROUP_have_precompute_mult`**, which lands with the keystone.
///
/// # Safety
///
/// `group` is live.
#[allow(dead_code)] // read by `ec_lib.c`'s `EC_GROUP_have_precompute_mult`
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_wNAF_have_precompute_mult(group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { c_int::from((*group).pre_comp_type == Pct::Ec && !(*group).pre_comp.ec.is_null()) }
}
