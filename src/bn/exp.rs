//! Phase 8 — `crypto/bn/bn_exp.c`'s one internal, which Phase 8.7's EC closure reaches.
//!
//! The authority file is 1,379 lines and eighteen definitions, of which **seventeen are
//! exports** — `BN_mod_exp`, `BN_mod_exp_recp`, `BN_mod_exp_mont`, `BN_mod_exp_mont_word`,
//! `BN_mod_exp_mont_consttime`, `BN_mod_exp_mont_consttime_x2`, `BN_mod_exp_simple` and the
//! `BN_mod_exp_mont*` engine entry points — and **one is an internal**:
//! `bn_mod_exp_mont_fixed_top` (`:604-943`). `forensics/atlas/internal-symbols.json`
//! records exactly that one name against this translation unit, which is why the unit can
//! be given a module here without moving a single ledger row: the ledger counts exports,
//! and every export of this file was 8.4's and 8.5's and is already implemented.
//!
//! ## Where the exports live, and why this module is the unit's *second* home
//!
//! `BN_mod_exp_mont` and `BN_mod_exp_mont_consttime` are in `src/bn/mont.rs`, whose dominant
//! unit is `crypto/bn/bn_mont.c`: they are the crate's three `bn_mod_exp_mont*` names over
//! one `mod_exp_core`. That is not a coincidence to be tidied away. `crypto/bn/bn_exp.c`
//! implements its own Montgomery exponentiation and `bn_mont.c` implements the Montgomery
//! *context*, and the crate's single core answers both, which is the substitution
//! `src/rsa/ossl.rs:35-43` records for the whole `bn_*_fixed_top` family. This module is
//! therefore a second crate module for the same authority unit, and it defines the one name
//! `mont.rs` does not.
//!
//! ## The caller, and a correction to the plan
//!
//! `crypto/ec/ec_lib.c:1271` — `ossl_ec_group_do_inverse_ord`, the Fermat inversion beside
//! `ossl_ec_group_simple_order_bits` — calls
//! `bn_mod_exp_mont_fixed_top(r, x, e, group->order, ctx, group->mont_data)`.
//! `docs/PHASE-8-EC-INTEGRATION-PLAN.md` §2e attributes that call to `ecp_smpl.c`'s
//! `field_inv`; `ecp_smpl.c`'s inversion reaches `BN_mod_inverse`, and the fixed-top
//! exponentiation is `ec_lib.c`'s. The module that lands it is the same either way, and the
//! correction is recorded rather than silently followed.
//!
//! ## What is written, and the representational half that is named
//!
//! The authority's own `BN_mod_exp_mont_consttime` is
//!
//! ```text
//! if (!bn_mod_exp_mont_fixed_top(rr, a, p, m, ctx, in_mont)) return 0;
//! bn_correct_top(rr);
//! return 1;
//! ```
//!
//! (`bn_exp.c:1146-1157`) — the wrapper is this function plus the normalisation this crate's
//! `BIGNUM` performs on every store (`src/bn/bignum.rs:67`). So the reachable half of
//! `bn_mod_exp_mont_fixed_top` is exactly the crate's `BN_mod_exp_mont_consttime`,
//! **including its even-modulus refusal at `bn_exp.c:622`**, and the fixed-top
//! representation is what that call substitutes — the same substitution
//! `src/bn/blinding.rs` and `src/rsa/ossl.rs` already make for their own `_fixed_top`
//! calls. Two things the authority's body does beyond the value are therefore named and not
//! written:
//!
//! * the `top > BN_CONSTTIME_SIZE_LIMIT` forward to `BN_mod_exp_mont` (`:624-627`), a bound
//!   on the constant-time window buffer's size and not on the answer — this crate's core has
//!   no window buffer, so every input takes the arm the authority takes for a small modulus;
//! * the fixed-top discipline itself, which keeps `a->top` wider than the value so the
//!   exponentiation's table scans do not depend on the exponent's length. A normalised
//!   `Vec<Limb>` cannot carry a wider top, so the *value* is the authority's and the *timing
//!   profile* is this implementation's — the class of divergence `src/bn/gf2m.rs` records for
//!   the `BN_GF2m_*` arithmetic (D-GF2M-2), recorded there rather than here because it is not
//!   new.
//!
//! Nothing is stubbed and nothing is invented: the refusal is the authority's own site, the
//! even-modulus test is the authority's own test, and the answer is the answer the authority
//! computes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::bn::bignum::BigNum;
use crate::bn::ctx::BnCtx;
use crate::bn::mont::{BN_mod_exp_mont_consttime, MontCtx};

/// `int bn_mod_exp_mont_fixed_top(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)` — `crypto/bn/bn_exp.c:604-943`.
///
/// `rr = a^p mod m` in the Montgomery domain, keeping `rr`'s fixed top. The even-modulus
/// refusal raises `BN_R_CALLED_WITH_EVEN_MODULUS` at this function's own coordinate
/// (`:622`), which is a *different* site from `BN_mod_exp_mont`'s (`:327`) and is the reason
/// the name exists at all rather than being folded into its public counterpart: a caller
/// that drains the error queue after an even modulus sees this site, and the unit tests
/// below assert the packed error value rather than the reason alone.
///
/// **This is a substitution, not a transcription.** See the module documentation: in this
/// representation the fixed-top discipline has no storage to live in, so the crate's
/// `BN_mod_exp_mont_consttime` — the authority's own wrapper around this function — is what
/// answers, and its refusal is the same site.
///
/// # Safety
///
/// `rr` must be null or a live, uniquely-owned `BIGNUM`; `a`, `p` and `m` must each be null
/// or live; `in_mont` must be null or a live `BN_MONT_CTX`. This is
/// `BN_mod_exp_mont_consttime`'s contract, whose body answers this call.
// The callers are `crypto/ec/ec_lib.c`'s `ossl_ec_group_do_inverse_ord`
// (`src/ec/lib.rs`) and `ossl_ec_GFp_mont_field_inv` (`src/ec/mont.rs`), which
// routes a secret field element through the fixed-pattern ladder while keeping
// the public exponent.
pub(crate) unsafe fn bn_mod_exp_mont_fixed_top(
    rr: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    in_mont: *mut MontCtx,
) -> c_int {
    // The authority's wrapper is this call plus `bn_correct_top`, and this representation
    // corrects top on every store, so the wrapper *is* the body. `BN_mod_exp_mont_consttime`
    // tests the modulus with the same `BN_is_odd` test this function's own body uses, and it
    // raises at `bn_exp.c:622` — this function's coordinate rather than the wrapper's.
    //
    // SAFETY: `rr`, `a`, `p`, `m` and `in_mont` are each the null-or-live pointer this
    // function's `# Safety` section promises, and `BN_mod_exp_mont_consttime` has exactly
    // that contract.
    unsafe { BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_ulong;

    use crate::bn::bignum::{as_ref, new_owned, parts, BN_free, BN_is_odd};
    use crate::runtime::err::{err_sites, ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site:
    /// `(lib & 0xff) << 23 | (reason & 0x7fffff)`, read from the generated table.
    fn packed(site: &err_sites::ErrSite) -> c_ulong {
        (((site.lib as c_ulong) & 0xff) << 23) | ((site.reason as c_ulong) & 0x7f_ffff)
    }

    /// The even-modulus refusal, and the **site** it is raised at: `bn_exp.c:622` is
    /// `bn_mod_exp_mont_fixed_top`'s own coordinate and `bn_exp.c:327` is
    /// `BN_mod_exp_mont`'s, so the packed value is what separates this name from its public
    /// counterpart.
    #[test]
    fn an_even_modulus_is_refused_at_the_fixed_top_coordinate() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![3], 0);
            let p = new_owned(vec![5], 0);
            let m = new_owned(vec![8], 0);
            let r = new_owned(vec![0], 0);
            assert_eq!(BN_is_odd(m), 0);
            ERR_clear_error();
            assert_eq!(
                bn_mod_exp_mont_fixed_top(r, a, p, m, core::ptr::null_mut(), core::ptr::null_mut()),
                0
            );
            assert_eq!(ERR_peek_error(), packed(&err_sites::BN_EXP_622));
            for b in [a, p, m, r] {
                BN_free(b);
            }
        }
    }

    /// The value: `bn_mod_exp_mont_fixed_top` answers what the public Montgomery
    /// exponentiation answers, which is the whole of the substitution's claim.
    #[test]
    fn the_answer_is_the_public_montgomery_answer() {
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![4], 0);
            let p = new_owned(vec![13], 0);
            let m = new_owned(vec![497], 0);
            let fixed = new_owned(vec![0], 0);
            let public = new_owned(vec![0], 0);
            ERR_clear_error();
            assert_eq!(
                bn_mod_exp_mont_fixed_top(
                    fixed,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                1
            );
            assert_eq!(ERR_peek_error(), 0);
            assert_eq!(
                crate::bn::mont::BN_mod_exp_mont(
                    public,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                1
            );
            assert_eq!(parts(as_ref(fixed)).0, parts(as_ref(public)).0);
            for b in [a, p, m, fixed, public] {
                BN_free(b);
            }
        }
    }

    /// The fixed-top entry point, which is the call shape `ec_lib.c`'s order
    /// inversion and `ecp_mont.c`'s field inversion use, must answer the same
    /// value whether or not the caller's prepared Montgomery context is supplied.
    #[test]
    fn the_fixed_top_answer_is_unchanged_by_a_prepared_context() {
        use crate::bn::mont::{BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set};

        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321], 0);
            let p = new_owned(vec![0x1111_2222_3333_4445, 0x0555_6666_7777_8889], 0);
            let m = new_owned(vec![0xffff_ffff_ffff_fffd, 0x0123_4567_89ab_cdef], 0);
            let without = new_owned(vec![0], 0);
            let with = new_owned(vec![0], 0);
            let mont = BN_MONT_CTX_new();
            assert!(!mont.is_null());
            assert_eq!(BN_MONT_CTX_set(mont, m, core::ptr::null_mut()), 1);

            assert_eq!(
                bn_mod_exp_mont_fixed_top(
                    without,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                1
            );
            assert_eq!(
                bn_mod_exp_mont_fixed_top(with, a, p, m, core::ptr::null_mut(), mont),
                1
            );
            assert_eq!(parts(as_ref(without)).0, parts(as_ref(with)).0);

            BN_MONT_CTX_free(mont);
            for b in [a, p, m, without, with] {
                BN_free(b);
            }
        }
    }

    /// PFP-56: the fixed-top entry point used by EC's field/order inversion keeps
    /// the modulus width. Its exponent is `p - 2` / `order - 2`, so that width is
    /// also the exponent's own length: the site is correct as written and is
    /// pinned here so the classification cannot drift.
    #[test]
    fn the_ec_inversion_entry_keeps_the_modulus_width() {
        use crate::bn::arith::ladder_probe;

        // A two-limb odd modulus and the full-width exponent `m - 2`.
        let m_limbs = vec![0xffff_ffff_ffff_fffd, 0x0123_4567_89ab_cdef];
        let e_limbs = vec![m_limbs[0] - 2, m_limbs[1]];
        // SAFETY: the test owns every object it passes.
        unsafe {
            let a = new_owned(vec![2], 0);
            let m = new_owned(m_limbs, 0);
            let e = new_owned(e_limbs, 0);
            let r = new_owned(vec![0], 0);
            ladder_probe::reset();
            assert_eq!(
                bn_mod_exp_mont_fixed_top(r, a, e, m, core::ptr::null_mut(), core::ptr::null_mut()),
                1
            );
            assert_eq!(
                ladder_probe::ladder_bits(),
                vec![128],
                "two-limb modulus, full-width public exponent"
            );
            assert_eq!(ladder_probe::vartime_bits(), Vec::<usize>::new());
            for b in [a, m, e, r] {
                BN_free(b);
            }
        }
    }
}
