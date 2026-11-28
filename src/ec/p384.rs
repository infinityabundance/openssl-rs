//! PFP-59 — exact-group admission for the P-384 Solinas fast arm.
//!
//! This is the **same admission mechanism** PFP-11 introduced for P-521, not a
//! second one. The fast arm lives inside `BN_mod_mul_montgomery`, which only
//! receives a [`crate::bn::mont::MontCtx`]. That context holds the modulus but
//! not `a`, `b`, the generator, the order or the cofactor, so admission cannot
//! be decided from it alone. [`admits`] is the audited unsafe predicate at the
//! existing C ABI boundary (the `p256::fixed_base::admits` pattern); it is
//! evaluated by `EC_GROUP_set_generator` when the whole group is established,
//! and its verdict is stored as [`crate::bn::mont::SpecialReduction`] in the
//! opaque context. The kernel's dispatch then reads that flag and re-checks the
//! prepared modulus — it performs no unsafe operation and reads no curve
//! parameter.
//!
//! The setter is reached only through `ec::mont::mont_field_data` (boundary
//! `B-EC-MONT-FIELD-DATA1`), which establishes from the group's method identity
//! that `field_data1` is a `MontCtx` before the slot is interpreted. A group with
//! a foreign method therefore never has its `field_data1` read or written here,
//! even if that slot holds some other type.
//!
//! A modified generator, a modified order, a different curve sharing the same
//! `p`, and a foreign field method each keep their own semantics: [`admits`]
//! returns `false`, `EC_GROUP_set_generator` clears the flag, and the caller
//! stays on the generic Montgomery/CIOS path.
//!
//! ## Identity, not just the modulus
//!
//! Everything compared here is read from
//! [`crate::ec::curve_data::_EC_NIST_PRIME_384_DATA`] — the byte array the
//! generator read back from the authority's own `EC_CURVE_DATA` — so the
//! predicate does not restate the constants by hand. It is a full identity
//! check: `p`, `a`, `b`, the tracked affine generator `(Gx, Gy)`, the order and
//! the cofactor, plus the Montgomery field method.

use crate::bn::limbs::Limb;
use crate::ec::curve_data::_EC_NIST_PRIME_384_DATA;
use crate::ec::mont::ossl_ec_GFp_mont_field_mul;
use crate::ec::{EcFieldMulFn, EcGroup};

/// The `data[]` prefix: a 20-byte seed, then six 48-byte parameter fields.
const SEED_LEN: usize = 20;
const PARAM_LEN: usize = 48;
const P384_LIMBS: usize = crate::bn::solinas::P384_LIMBS;

/// Offsets of the six fields in `data[]`, in order.
const FIELD_P: usize = 0;
const FIELD_A: usize = 1;
const FIELD_B: usize = 2;
const FIELD_GX: usize = 3;
const FIELD_GY: usize = 4;
const FIELD_ORDER: usize = 5;

/// `c = 2^384 - p` in radix `2^64`; `2^384 ≡ c (mod p)`.
const C_LIMBS: [Limb; 3] = [0xFFFF_FFFF_0000_0001, 0x0000_0000_FFFF_FFFF, 1];

/// One tracked parameter as six little-endian limbs.
///
/// The stored bytes are big-endian and 48 bytes wide (384 bits), so reading
/// from the end places byte `k` of the reversed stream at bit `8·(k mod 8)` of
/// limb `k / 8`.
fn tracked(index: usize) -> [Limb; P384_LIMBS] {
    let start = SEED_LEN + index * PARAM_LEN;
    let bytes = &_EC_NIST_PRIME_384_DATA[start..start + PARAM_LEN];
    let mut out = [0u64; P384_LIMBS];
    for (k, &b) in bytes.iter().rev().enumerate() {
        out[k / 8] |= (b as u64) << (8 * (k % 8));
    }
    out
}

/// `x·R mod p` for a canonical `x`, where `R = 2^384` is the Montgomery radix.
///
/// The EC group stores `a`, `b` and the generator coordinates in Montgomery
/// form, so the identity predicate must compare them in that representation.
/// Since `2^384 ≡ c (mod p)` with `c = 2^128 + 2^96 - 2^32 + 1`, the encoding is
/// `x·c mod p`. This is deliberately *not* the fast kernel: it is a small,
/// independent cold-path multiply-and-fold used only here, and it is checked
/// against the group's stored values by `the_encoding_matches_the_stored_montgomery_form`.
fn encode(x: &[Limb; P384_LIMBS]) -> [Limb; P384_LIMBS] {
    // `t = x·c` in nine limbs. `x < 2^384`, `c < 2^129`, so `t < 2^513`.
    let mut t = [0u64; 9];
    for i in 0..P384_LIMBS {
        let mut carry: u128 = 0;
        let xi = x[i] as u128;
        for j in 0..C_LIMBS.len() {
            let v = xi * (C_LIMBS[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        let mut k = i + C_LIMBS.len();
        let mut c = carry as u64;
        while c != 0 {
            let s = (t[k] as u128) + (c as u128);
            t[k] = s as u64;
            c = (s >> 64) as u64;
            k += 1;
        }
    }

    // First fold: `t = L + H·2^384`, `2^384 ≡ c`, so `t ≡ L + H·c`. `H < 2^129`
    // gives `H·c < 2^258`, so the sum is below `2^384 + 2^258` (seven limbs).
    let mut y = [0u64; 7];
    y[..P384_LIMBS].copy_from_slice(&t[..P384_LIMBS]);
    for i in 0..C_LIMBS.len() {
        let mut carry: u128 = 0;
        let hi = t[P384_LIMBS + i] as u128;
        for j in 0..C_LIMBS.len() {
            let v = hi * (C_LIMBS[j] as u128) + (y[i + j] as u128) + carry;
            y[i + j] = v as u64;
            carry = v >> 64;
        }
        let mut k = i + C_LIMBS.len();
        let mut c = carry as u64;
        while c != 0 {
            let s = (y[k] as u128) + (c as u128);
            y[k] = s as u64;
            c = (s >> 64) as u64;
            k += 1;
        }
    }

    // Second fold: `y[6]` is bit 384 (0 or 1). When it is one the low six limbs
    // are below `2^258`, so adding `c` cannot overflow 384 bits.
    let mut z = [0u64; P384_LIMBS];
    z.copy_from_slice(&y[..P384_LIMBS]);
    if y[6] != 0 {
        let mut carry = 0u64;
        for (j, slot) in z.iter_mut().enumerate() {
            let c = if j < C_LIMBS.len() { C_LIMBS[j] } else { 0 };
            let (s, o1) = slot.overflowing_add(c);
            let (s, o2) = s.overflowing_add(carry);
            *slot = s;
            carry = u64::from(o1) | u64::from(o2);
        }
    }

    // One masked conditional subtraction leaves `[0, p)`.
    let mut diff = [0u64; P384_LIMBS];
    let mut borrow = 0u64;
    for j in 0..P384_LIMBS {
        let (d1, b1) = z[j].overflowing_sub(crate::bn::solinas::P384[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let take = borrow ^ 1;
    let mask = 0u64.wrapping_sub(take);
    let mut out = [0u64; P384_LIMBS];
    for j in 0..P384_LIMBS {
        out[j] = (z[j] & !mask) | (diff[j] & mask);
    }
    out
}

/// True only when this group **is** the standard P-384 group and its field path
/// is the Montgomery method this fast arm specializes.
///
/// # Safety
///
/// `group` is NULL or a live `EC_GROUP`.
pub(crate) unsafe fn admits(group: *const EcGroup) -> bool {
    // SAFETY: the caller guarantees `group` is NULL or live; every field and
    // member read below belongs to that group.
    unsafe {
        if group.is_null() {
            return false;
        }
        let group = &*group;

        // The fast arm is reached through the Montgomery `field_mul`; a foreign
        // method is refused even if every parameter happens to match.
        if group.meth.is_null() {
            return false;
        }
        let mont_mul = (*group.meth)
            .field_mul
            .is_some_and(|f| core::ptr::fn_addr_eq(f, ossl_ec_GFp_mont_field_mul as EcFieldMulFn));
        if !mont_mul {
            return false;
        }

        if group.field.is_null()
            || group.a.is_null()
            || group.b.is_null()
            || group.order.is_null()
            || group.cofactor.is_null()
            || group.generator.is_null()
        {
            return false;
        }

        // The prime and the order are stored raw; `a`, `b` and the generator
        // coordinates are stored in the Montgomery domain and are compared in
        // that domain.
        if (*group.field).d.as_slice() != tracked(FIELD_P).as_slice()
            || (*group.order).d.as_slice() != tracked(FIELD_ORDER).as_slice()
            || (*group.cofactor).d.as_slice() != [1u64].as_slice()
            || (*group.a).d.as_slice() != encode(&tracked(FIELD_A)).as_slice()
            || (*group.b).d.as_slice() != encode(&tracked(FIELD_B)).as_slice()
        {
            return false;
        }

        // The generator must be the tracked affine base point. A Jacobian or
        // multiplied point (`z_is_one == 0`) is refused here, so a caller that
        // replaces the generator with `2G` cannot inherit admission.
        let generator = &*group.generator;
        if generator.z_is_one == 0 || generator.x.is_null() || generator.y.is_null() {
            return false;
        }
        (*generator.x).d.as_slice() == encode(&tracked(FIELD_GX)).as_slice()
            && (*generator.y).d.as_slice() == encode(&tracked(FIELD_GY)).as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ffi::c_int;

    use crate::bn::bignum::{new_owned, BN_free, BN_new, BN_set_word};
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
    use crate::bn::mont::{solinas384_admission, BN_MONT_CTX_free, BN_mod_mul_montgomery};
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_do_sign, ECDSA_do_verify};
    use crate::ec::key::{EC_KEY_free, EC_KEY_generate_key, EC_KEY_new_by_curve_name};
    use crate::ec::lib::{
        EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get0_generator, EC_GROUP_set_curve,
        EC_GROUP_set_generator, EC_POINT_copy, EC_POINT_free, EC_POINT_mul, EC_POINT_new,
    };
    use crate::ec::smpl::EC_GFp_simple_method;
    use crate::runtime::obj::{NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1};

    fn word(w: core::ffi::c_ulong) -> *mut crate::bn::bignum::BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let b = unsafe { BN_new() };
        assert!(!b.is_null());
        // SAFETY: `b` is a live `BIGNUM` just returned by `BN_new`.
        let set = unsafe { BN_set_word(b, w) };
        assert_eq!(set, 1);
        b
    }

    fn bn(limbs: Vec<Limb>) -> *mut crate::bn::bignum::BigNum {
        new_owned(limbs, 0)
    }

    /// The flag on the group's field context, read through the method-gated
    /// accessor (`B-EC-MONT-FIELD-DATA1`). A group without a Montgomery method
    /// has no such context to read and answers `false`.
    unsafe fn flag(group: *const EcGroup) -> bool {
        // SAFETY: the caller guarantees `group` is live.
        unsafe {
            crate::ec::mont::mont_field_data(group).is_some_and(|mont| solinas384_admission(mont))
        }
    }

    /// A refused group must leave the flag clear **and** never reach the fast
    /// kernel when a field multiply runs.
    unsafe fn assert_refused(group: *const EcGroup) {
        // SAFETY: the caller guarantees `group` is live and owns its field data.
        unsafe {
            let Some(mont) = crate::ec::mont::mont_field_data(group) else {
                unreachable!("a refused Montgomery group must still own its field context")
            };
            assert!(!mont.is_null());
            assert!(!flag(group), "the admission flag must be clear");
            let a = word(3);
            let b = word(5);
            let r = BN_new();
            assert!(!r.is_null());
            let before = crate::bn::solinas::probe::count();
            assert_eq!(
                BN_mod_mul_montgomery(r, a, b, mont, core::ptr::null_mut()),
                1
            );
            assert_eq!(
                crate::bn::solinas::probe::count(),
                before,
                "the fast arm must not run"
            );
            BN_free(a);
            BN_free(b);
            BN_free(r);
        }
    }

    #[test]
    fn the_named_curve_is_admitted() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group), "the standard P-384 group is admitted");
            EC_GROUP_free(group);
        }
    }

    /// P-256 and P-521 are different identities (and P-256 a different field
    /// method): neither is admitted and neither reaches the P-384 kernel.
    #[test]
    fn other_curves_are_not_admitted_and_never_enter_the_fast_arm() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            for nid in [NID_X9_62_prime256v1, NID_secp521r1] {
                let group = EC_GROUP_new_by_curve_name(nid);
                assert!(!group.is_null());
                // P-521 uses Montgomery too, but its own admission is not this
                // one; P-256's method does not own a MontCtx at all.
                if let Some(mont) = crate::ec::mont::mont_field_data(group) {
                    assert!(!solinas384_admission(mont), "not the P-384 identity");
                }

                let ctx = BN_CTX_new();
                assert!(!ctx.is_null());
                let out = EC_POINT_new(group);
                assert!(!out.is_null());
                let scalar = word(7);
                let before = crate::bn::solinas::probe::count();
                assert_eq!(
                    EC_POINT_mul(
                        group,
                        out,
                        scalar,
                        core::ptr::null(),
                        core::ptr::null_mut(),
                        ctx
                    ),
                    1
                );
                assert_eq!(
                    crate::bn::solinas::probe::count(),
                    before,
                    "another curve must not enter the P-384 kernel"
                );

                EC_POINT_free(out);
                BN_free(scalar);
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
            }
        }
    }

    /// The independent cold-path encoding matches the Montgomery form the group
    /// actually stored for `a`, `b` and the generator, so the admission
    /// comparison is on the right representation.
    #[test]
    fn the_encoding_matches_the_stored_montgomery_form() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            let g = &*group;
            assert_eq!((*g.a).d.as_slice(), encode(&tracked(FIELD_A)).as_slice());
            assert_eq!((*g.b).d.as_slice(), encode(&tracked(FIELD_B)).as_slice());
            let gen = &*g.generator;
            assert_eq!((*gen.x).d.as_slice(), encode(&tracked(FIELD_GX)).as_slice());
            assert_eq!((*gen.y).d.as_slice(), encode(&tracked(FIELD_GY)).as_slice());
            EC_GROUP_free(group);
        }
    }

    #[test]
    fn a_modified_generator_is_refused() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let two = bn(vec![2]);
            let two_g = EC_POINT_new(group);
            assert!(!two_g.is_null());
            assert_eq!(
                EC_POINT_mul(
                    group,
                    two_g,
                    two,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    ctx
                ),
                1
            );
            assert_eq!(
                EC_GROUP_set_generator(group, two_g, (*group).order, (*group).cofactor),
                1
            );
            assert_refused(group);

            EC_POINT_free(two_g);
            BN_free(two);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
        }
    }

    #[test]
    fn a_modified_order_is_refused() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);
            let mut n_minus_1 = tracked(FIELD_ORDER);
            n_minus_1[0] -= 1;
            let order = bn(n_minus_1.to_vec());
            assert_eq!(
                EC_GROUP_set_generator(group, generator, order, (*group).cofactor),
                1
            );
            assert_refused(group);

            EC_POINT_free(generator);
            BN_free(order);
            EC_GROUP_free(group);
        }
    }

    #[test]
    fn a_different_curve_sharing_the_prime_is_refused() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());

            // Keep the tracked generator and order, then replace only `b`: the
            // prime and `a` are unchanged, so this is a different curve over
            // exactly the same field.
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);
            let order = bn(tracked(FIELD_ORDER).to_vec());
            let cofactor = bn(vec![1]);

            let p = bn(tracked(FIELD_P).to_vec());
            let a = bn(tracked(FIELD_A).to_vec());
            let mut b_limbs = tracked(FIELD_B);
            b_limbs[0] ^= 1;
            let b = bn(b_limbs.to_vec());
            assert_eq!(EC_GROUP_set_curve(group, p, a, b, ctx), 1);
            assert_eq!(EC_GROUP_set_generator(group, generator, order, cofactor), 1);
            assert_refused(group);

            EC_POINT_free(generator);
            BN_free(p);
            BN_free(a);
            BN_free(b);
            BN_free(order);
            BN_free(cofactor);
            EC_GROUP_free(group);
            BN_CTX_free(ctx);
        }
    }

    #[test]
    fn a_foreign_method_is_refused() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            // Install a foreign method on the same group. The group's field path
            // no longer reaches `ossl_ec_GFp_mont_field_mul`, so `admits` must
            // refuse and the method-gated setter must not interpret the slot.
            let mont_method = (*group).meth;
            (*group).meth = EC_GFp_simple_method();
            assert_eq!(
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor),
                1
            );
            assert!(
                !crate::ec::p384::admits(group),
                "a foreign field method is never admitted"
            );
            assert!(
                crate::ec::mont::mont_field_data(group).is_none(),
                "the foreign method does not establish `field_data1` as a MontCtx"
            );

            // Restore the method so the group releases its field data through
            // the Montgomery finish.
            (*group).meth = mont_method;
            EC_POINT_free(generator);
            EC_GROUP_free(group);
        }
    }

    /// A foreign method whose `field_data1` is **not** a `MontCtx` must never
    /// have that slot interpreted. The sentinel is a distinct aggregate, so a
    /// write through a `MontCtx` view would dirty its bytes; the canary catches
    /// that without relying on a crash.
    #[test]
    fn a_foreign_method_with_non_mont_field_data_is_never_interpreted() {
        #[repr(C, align(8))]
        struct Sentinel([u64; 32]);
        const PATTERN: u64 = 0xDEAD_BEEF_DEAD_BEEF;

        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let mut sentinel = Sentinel([PATTERN; 32]);
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));

            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            let mont_method = (*group).meth;
            let mont_data = (*group).field_data1;

            (*group).meth = EC_GFp_simple_method();
            (*group).field_data1 = (&mut sentinel as *mut Sentinel).cast::<core::ffi::c_void>();

            // The clear at entry and the re-admission at the successful tail must
            // both skip the slot: the method does not establish its type.
            assert_eq!(
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor),
                1
            );
            assert_eq!(
                sentinel.0, [PATTERN; 32],
                "`field_data1` was interpreted as a MontCtx"
            );
            assert!(!crate::ec::p384::admits(group));

            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let out = EC_POINT_new(group);
            assert!(!out.is_null());
            let scalar = word(7);
            let before = crate::bn::solinas::probe::count();
            let _ = EC_POINT_mul(
                group,
                out,
                scalar,
                core::ptr::null(),
                core::ptr::null_mut(),
                ctx,
            );
            assert_eq!(
                crate::bn::solinas::probe::count(),
                before,
                "the P-384 kernel must not be entered for foreign field data"
            );

            // Restore the genuine slot before release.
            (*group).meth = mont_method;
            (*group).field_data1 = mont_data;

            BN_free(scalar);
            EC_POINT_free(out);
            BN_CTX_free(ctx);
            EC_POINT_free(generator);
            EC_GROUP_free(group);
        }
    }

    /// A copy taken after admission carries the admitted context; a refused
    /// source stays refused. `EC_GROUP_copy` copies every parameter before
    /// `BN_MONT_CTX_copy`, so the flag travels with the identity it describes.
    #[test]
    fn a_group_copied_after_admission_keeps_the_right_verdict() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));

            let admitted_dup = EC_GROUP_dup(group);
            assert!(!admitted_dup.is_null());
            assert!(flag(admitted_dup), "the admitted context is copied");
            assert!(
                crate::ec::p384::admits(admitted_dup),
                "the copy is the same P-384 identity"
            );

            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);
            let mut wrong_order = tracked(FIELD_ORDER);
            wrong_order[0] -= 1;
            let order = bn(wrong_order.to_vec());
            assert_eq!(
                EC_GROUP_set_generator(group, generator, order, (*group).cofactor),
                1
            );
            assert!(!flag(group));

            let refused_dup = EC_GROUP_dup(group);
            assert!(!refused_dup.is_null());
            assert!(
                !flag(refused_dup),
                "a refused context stays refused across a copy"
            );

            EC_GROUP_free(refused_dup);
            EC_GROUP_free(admitted_dup);
            BN_free(order);
            EC_POINT_free(generator);
            EC_GROUP_free(group);
        }
    }

    /// `EC_GROUP_set_curve` installs a fresh Montgomery context whose flag starts
    /// clear; re-establishing the exact generator/order re-admits it.
    #[test]
    fn a_curve_change_clears_admission_until_the_generator_is_reset() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));

            let p = bn(tracked(FIELD_P).to_vec());
            let a = bn(tracked(FIELD_A).to_vec());
            let b = bn(tracked(FIELD_B).to_vec());
            assert_eq!(EC_GROUP_set_curve(group, p, a, b, ctx), 1);
            assert!(!flag(group), "a fresh field context starts unadmitted");

            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);
            assert_eq!(
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor),
                1
            );
            assert!(flag(group), "the exact identity re-admits");

            EC_POINT_free(generator);
            BN_free(p);
            BN_free(a);
            BN_free(b);
            EC_GROUP_free(group);
            BN_CTX_free(ctx);
        }
    }

    /// An allocation failure after the clear must leave the fast arm refused:
    /// the tail that could re-admit is never reached.
    #[test]
    fn a_generator_allocation_failure_leaves_admission_clear() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = (*group).generator;
            assert!(!generator.is_null());

            (*group).generator = core::ptr::null_mut();
            let ret = {
                let _guard = crate::bn::alloc::test_fail::fail_after(0);
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor)
            };
            assert_eq!(ret, 0, "the injected allocation failure is reported");
            assert!(
                !flag(group),
                "the pre-allocation clear must stand on the failure path"
            );

            (*group).generator = generator;
            EC_GROUP_free(group);
        }
    }

    /// A failure in the order-Montgomery setup, reached after the generator and
    /// order have been copied, must also leave the fast arm refused.
    #[test]
    fn an_order_montgomery_setup_failure_leaves_admission_clear() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp384r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            BN_MONT_CTX_free((*group).mont_data);
            (*group).mont_data = core::ptr::null_mut();
            let ret = {
                let _guard = crate::bn::alloc::test_fail::fail_after(0);
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor)
            };
            assert_eq!(ret, 0, "the injected setup failure is reported");
            assert!(
                !flag(group),
                "a mid-setup failure must not re-admit the group"
            );

            EC_POINT_free(generator);
            EC_GROUP_free(group);
        }
    }

    /// End-to-end: P-384 ECDSA sign and verify take the fast arm and agree with
    /// the defining equation over many digests.
    #[test]
    fn p384_ecdsa_sign_and_verify_take_the_fast_arm() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let key = EC_KEY_new_by_curve_name(NID_secp384r1);
            assert!(!key.is_null());
            assert_eq!(EC_KEY_generate_key(key), 1);

            let before = crate::bn::solinas::probe::count();
            let mut signed = 0u32;
            for round in 0..16u32 {
                let mut dgst = [0u8; 48];
                for (i, b) in dgst.iter_mut().enumerate() {
                    *b = (i as u8)
                        .wrapping_mul(37)
                        .wrapping_add(round as u8)
                        .wrapping_add(11);
                }
                let sig = ECDSA_do_sign(dgst.as_ptr(), dgst.len() as c_int, key);
                assert!(!sig.is_null(), "P-384 sign must succeed");
                assert_eq!(
                    ECDSA_do_verify(dgst.as_ptr(), dgst.len() as c_int, sig, key),
                    1,
                    "P-384 signature verifies against its key"
                );
                ECDSA_SIG_free(sig);
                signed += 1;
            }
            assert_eq!(signed, 16);
            assert!(
                crate::bn::solinas::probe::count() > before,
                "the P-384 fast arm must be entered"
            );

            EC_KEY_free(key);
        }
    }
}
