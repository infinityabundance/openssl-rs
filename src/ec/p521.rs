//! PFP-11 phase 2 — exact-group admission for the P-521 Mersenne fast arm.
//!
//! The fast arm lives inside `BN_mod_mul_montgomery`, which only receives a
//! [`crate::bn::mont::MontCtx`]. That context holds the modulus but not `a`, `b`,
//! the generator, the order or the cofactor, so admission cannot be decided
//! from it alone. [`admits`] is the one audited unsafe predicate at the existing
//! C ABI boundary (the `p256::fixed_base::admits` pattern); it is evaluated by
//! `EC_GROUP_set_generator` when the whole group is established, and its verdict
//! is stored as a plain `bool` in the opaque context. The kernel's dispatch then
//! reads that flag and re-checks the prepared modulus — it performs no unsafe
//! operation and reads no curve parameter.
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
//! [`crate::ec::curve_data::_EC_NIST_PRIME_521_DATA`] — the byte array the
//! generator read back from the authority's own `EC_CURVE_DATA` — so the
//! predicate does not restate the constants by hand. It is a full identity
//! check: `p`, `a`, `b`, the tracked affine generator `(Gx, Gy)`, the order and
//! the cofactor, plus the Montgomery field method.

use crate::bn::limbs::Limb;
use crate::ec::curve_data::_EC_NIST_PRIME_521_DATA;
use crate::ec::mont::ossl_ec_GFp_mont_field_mul;
use crate::ec::{EcFieldMulFn, EcGroup};

/// The `data[]` prefix: a 20-byte seed, then six 66-byte parameter fields.
const SEED_LEN: usize = 20;
const PARAM_LEN: usize = 66;
const P521_LIMBS: usize = crate::bn::mersenne::P521_LIMBS;

/// Offsets of the six fields in `data[]`, in order.
const FIELD_P: usize = 0;
const FIELD_A: usize = 1;
const FIELD_B: usize = 2;
const FIELD_GX: usize = 3;
const FIELD_GY: usize = 4;
const FIELD_ORDER: usize = 5;

/// One tracked parameter as nine little-endian limbs.
///
/// The stored bytes are big-endian and 66 bytes wide (528 bits); the value is at
/// most 521 bits, so the top limb holds the leading nine bits. Reading from the
/// end places byte `k` of the reversed stream at bit `8·(k mod 8)` of limb
/// `k / 8`.
fn tracked(index: usize) -> [Limb; P521_LIMBS] {
    let start = SEED_LEN + index * PARAM_LEN;
    let bytes = &_EC_NIST_PRIME_521_DATA[start..start + PARAM_LEN];
    let mut out = [0u64; P521_LIMBS];
    for (k, &b) in bytes.iter().rev().enumerate() {
        out[k / 8] |= (b as u64) << (8 * (k % 8));
    }
    out
}

/// `x·R mod p` for a canonical `x`, where `R = 2^576` is the Montgomery radix.
///
/// The EC group stores `a`, `b` and the generator coordinates in Montgomery
/// form, so the identity predicate must compare them in that representation.
/// Since `2^521 ≡ 1 (mod p)`, `R = 2^55·2^521 ≡ 2^55`, so the encoding is
/// `x << 55` folded at 521 bits. This is deliberately *not* the fast REDC: it is
/// a small, independent shift-and-fold used only here, and it is checked
/// against the group's stored values by the admission tests.
fn encode(x: &[Limb; P521_LIMBS]) -> [Limb; P521_LIMBS] {
    // `U = x << 55` (up to 576 bits, ten limbs).
    let mut u = [0u64; P521_LIMBS + 1];
    let mut carry: u64 = 0;
    for i in 0..P521_LIMBS {
        let v = ((x[i] as u128) << 55) | (carry as u128);
        u[i] = v as u64;
        carry = (v >> 64) as u64;
    }
    u[P521_LIMBS] = carry;

    // `U = L + H·2^521`; `2^521 ≡ 1`, so the residue is `L + H`.
    let h = (u[8] >> 9) | (u[9] << 55);
    let mut s = [0u64; P521_LIMBS];
    s[..8].copy_from_slice(&u[..8]);
    s[8] = u[8] & 0x1FF;
    let mut c = h;
    for limb in s.iter_mut() {
        let (v, overflow) = limb.overflowing_add(c);
        *limb = v;
        c = u64::from(overflow);
    }

    // One masked conditional subtraction: `s < 2^521 + 2^55`, so at most one
    // subtraction of `p` is needed.
    let mut diff = [0u64; P521_LIMBS];
    let mut borrow = 0u64;
    for i in 0..P521_LIMBS {
        let (d1, b1) = s[i].overflowing_sub(crate::bn::mersenne::P521[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[i] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let take = c | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(take);
    let mut out = [0u64; P521_LIMBS];
    for i in 0..P521_LIMBS {
        out[i] = (s[i] & !mask) | (diff[i] & mask);
    }
    out
}

/// True only when this group **is** the standard P-521 group and its field path
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
    use crate::bn::mont::{mersenne521_admission, BN_MONT_CTX_free, BN_mod_mul_montgomery};
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_do_sign, ECDSA_do_verify};
    use crate::ec::key::{EC_KEY_free, EC_KEY_generate_key, EC_KEY_new_by_curve_name};
    use crate::ec::lib::{
        EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get0_generator, EC_GROUP_set_asn1_flag,
        EC_GROUP_set_curve, EC_GROUP_set_generator, EC_POINT_copy, EC_POINT_free, EC_POINT_mul,
        EC_POINT_new,
    };
    use crate::ec::smpl::EC_GFp_simple_method;
    use crate::evp::pkey_ctx::OPENSSL_EC_EXPLICIT_CURVE;
    use crate::runtime::obj::{NID_X9_62_prime256v1, NID_secp521r1};

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
            crate::ec::mont::mont_field_data(group).is_some_and(|mont| mersenne521_admission(mont))
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
            let before = crate::bn::mersenne::probe::count();
            assert_eq!(
                BN_mod_mul_montgomery(r, a, b, mont, core::ptr::null_mut()),
                1
            );
            assert_eq!(
                crate::bn::mersenne::probe::count(),
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group), "the standard P-521 group is admitted");
            EC_GROUP_free(group);
        }
    }

    /// P-256 is a different modulus and a different field method: it is never
    /// admitted and never reaches the fast kernel, so its arithmetic is the
    /// previous path.
    #[test]
    fn p256_is_not_admitted_and_never_enters_the_fast_arm() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            // P-256 uses the plain field method, which never writes `field_data1`
            // and does not establish it as a `MontCtx`, so the method-gated
            // accessor refuses the slot outright.
            assert!(
                crate::ec::mont::mont_field_data(group).is_none(),
                "a non-Montgomery method must not expose a field MontCtx"
            );

            // A real P-256 multiplication exercises the field arithmetic and must
            // not enter the P-521 kernel.
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let out = EC_POINT_new(group);
            assert!(!out.is_null());
            let scalar = word(7);
            let before = crate::bn::mersenne::probe::count();
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
                crate::bn::mersenne::probe::count(),
                before,
                "P-256 must not enter the P-521 kernel"
            );

            EC_POINT_free(out);
            BN_free(scalar);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
        }
    }

    /// The independent shift-and-fold encoding matches the Montgomery form the
    /// group actually stored for `a`, `b` and the generator, so the admission
    /// comparison is on the right representation.
    #[test]
    fn the_encoding_matches_the_stored_montgomery_form() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            // Install a foreign method on the same group. The group's field path
            // no longer reaches `ossl_ec_GFp_mont_field_mul`, so `admits` must
            // refuse. The old context is still a `MontCtx`, but the *current*
            // method no longer establishes that (`B-EC-MONT-FIELD-DATA1`), so the
            // admission setter must not interpret the slot either.
            let mont_method = (*group).meth;
            (*group).meth = EC_GFp_simple_method();
            assert_eq!(
                EC_GROUP_set_generator(group, generator, (*group).order, (*group).cofactor),
                1
            );
            assert!(
                !crate::ec::p521::admits(group),
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));

            // A point built while the group is still Montgomery, so
            // `EC_POINT_copy`'s method check accepts it (the group's own
            // generator was built by the Montgomery method too).
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            // Save the genuine method and field context so the group can be
            // released through the Montgomery finish afterwards.
            let mont_method = (*group).meth;
            let mont_data = (*group).field_data1;

            // A foreign method plus a `field_data1` of a different type.
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
            assert!(!crate::ec::p521::admits(group));

            // A real group operation on the foreign method must not reach the
            // P-521 kernel either.
            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let out = EC_POINT_new(group);
            assert!(!out.is_null());
            let scalar = word(7);
            let before = crate::bn::mersenne::probe::count();
            let _ = EC_POINT_mul(
                group,
                out,
                scalar,
                core::ptr::null(),
                core::ptr::null_mut(),
                ctx,
            );
            assert_eq!(
                crate::bn::mersenne::probe::count(),
                before,
                "the P-521 kernel must not be entered for foreign field data"
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));

            let admitted_dup = EC_GROUP_dup(group);
            assert!(!admitted_dup.is_null());
            assert!(flag(admitted_dup), "the admitted context is copied");
            assert!(
                crate::ec::p521::admits(admitted_dup),
                "the copy is the same P-521 identity"
            );

            // Now refuse the source by replacing its order, and copy again.
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
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

    /// Presentation-only setters are not part of the group identity, so they do
    /// not disturb the admission verdict.
    #[test]
    fn presentation_setters_preserve_admission() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
            assert!(flag(group), "the ASN.1 flag is not a group parameter");
            EC_GROUP_free(group);
        }
    }

    /// An allocation failure after the clear must leave the fast arm refused:
    /// the tail that could re-admit is never reached.
    #[test]
    fn a_generator_allocation_failure_leaves_admission_clear() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = (*group).generator;
            assert!(!generator.is_null());

            // Make the group allocate a replacement generator and fail its first
            // `BIGNUM` allocation. The method is still Montgomery, so the clear
            // at entry runs; the failure returns before the re-admission tail.
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

            // Restore the saved generator so the group releases it.
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
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);
            assert!(!group.is_null());
            assert!(flag(group));
            let generator = EC_POINT_new(group);
            assert!(!generator.is_null());
            assert_eq!(EC_POINT_copy(generator, EC_GROUP_get0_generator(group)), 1);

            // Force `ec_precompute_mont_data` to allocate from scratch, then
            // fail the first intercepted allocation on the path. The clear at
            // entry must stand; the success tail is not reached.
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

    /// End-to-end: P-521 ECDSA sign and verify take the fast arm and agree with
    /// the defining equation over many digests.
    #[test]
    fn p521_ecdsa_sign_and_verify_take_the_fast_arm() {
        // SAFETY: all objects are live for the test and released here.
        unsafe {
            let key = EC_KEY_new_by_curve_name(NID_secp521r1);
            assert!(!key.is_null());
            assert_eq!(EC_KEY_generate_key(key), 1);

            let before = crate::bn::mersenne::probe::count();
            let mut signed = 0u32;
            for round in 0..16u32 {
                let mut dgst = [0u8; 64];
                for (i, b) in dgst.iter_mut().enumerate() {
                    *b = (i as u8)
                        .wrapping_mul(37)
                        .wrapping_add(round as u8)
                        .wrapping_add(11);
                }
                let sig = ECDSA_do_sign(dgst.as_ptr(), dgst.len() as c_int, key);
                assert!(!sig.is_null(), "P-521 sign must succeed");
                assert_eq!(
                    ECDSA_do_verify(dgst.as_ptr(), dgst.len() as c_int, sig, key),
                    1,
                    "P-521 signature verifies against its key"
                );
                ECDSA_SIG_free(sig);
                signed += 1;
            }
            assert_eq!(signed, 16);
            assert!(
                crate::bn::mersenne::probe::count() > before,
                "the P-521 fast arm must be entered"
            );

            EC_KEY_free(key);
        }
    }
}
