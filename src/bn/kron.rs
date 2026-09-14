//! Phase 5 — `BN_kronecker`, the Kronecker symbol.
//!
//! Cohen's algorithm 1.4.10, which is the one the authority's `bn_kron.c` implements,
//! including its conventions for the degenerate cases: `(A/0)` is 1 when `|A| == 1`
//! and 0 otherwise; `(A/B)` is 0 when `A` and `B` are both even; and **-2** — not a
//! symbol value — is the error return, which is why the failure default here is -2
//! rather than 0.
//!
//! The one place the authority's spelling matters is the quadratic reciprocity sign.
//! It computes `(A->neg ? ~BN_lsw(A) : BN_lsw(A)) & BN_lsw(B) & 2`, which is a trick
//! for `((A-1)/2) * ((B-1)/2) mod 2` written without a division: for a negative `A`
//! the complement carries the borrow. Reproduced as written, because the sign is the
//! whole function.

use core::ffi::c_int;

use crate::bn::bignum::{as_ref, parts, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;

/// `(-1)^((n^2-1)/8)` for an odd `n`, indexed by `n & 7`.
///
/// Only the odd entries are ever read: the even ones are unreachable because the
/// caller has already established that the value is odd.
const TAB: [c_int; 8] = [0, 1, 0, -1, 0, -1, 0, 1];

/// The number of low zero bits of a magnitude, which is what the authority's
/// `while (!BN_is_bit_set(v, i)) i++` counts.
fn trailing_zeros(v: &[Limb]) -> usize {
    let mut n = 0;
    for &l in v {
        if l == 0 {
            n += 64;
        } else {
            return n + l.trailing_zeros() as usize;
        }
    }
    n
}

/// `int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// Answers -2 on failure, and otherwise the symbol itself.
///
/// # Safety
///
/// `a` and `b` must each be null or a live `BIGNUM`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_kronecker(
    a: *const BigNum,
    b: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(-2, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (x, y) = unsafe { (as_ref(a), as_ref(b)) };
        let (mut av, mut aneg) = parts(x);
        let (mut bv, bneg) = parts(y);

        // Cohen's step 1.
        if bv.is_empty() {
            return c_int::from(av.len() == 1 && av[0] == 1);
        }
        // Cohen's step 2: two even values have no symbol.
        if limbs::is_even(&av) && limbs::is_even(&bv) {
            return 0;
        }

        let mut ret: c_int = 1;

        // The 2-adic part of B. An odd `i` means B was even, and then A must be odd.
        let i = trailing_zeros(&bv);
        bv = limbs::shr(&bv, i);
        if i & 1 == 1 {
            ret = TAB[(limbs::low_u64(&av) & 7) as usize];
        }
        if bneg && aneg {
            // B's sign is only ever consulted for this one flip; after the swap
            // below both values are non-negative by construction.
            ret = -ret;
        }

        loop {
            // Cohen's step 3.
            if av.is_empty() {
                return if bv.len() == 1 && bv[0] == 1 { ret } else { 0 };
            }

            let j = trailing_zeros(&av);
            av = limbs::shr(&av, j);
            if j & 1 == 1 {
                ret *= TAB[(limbs::low_u64(&bv) & 7) as usize];
            }

            // Cohen's step 4: the reciprocity sign, spelled as the authority spells it.
            let alow = if aneg {
                !limbs::low_u64(&av)
            } else {
                limbs::low_u64(&av)
            };
            if (alow & limbs::low_u64(&bv) & 2) != 0 {
                ret = -ret;
            }

            // `(A, B) := (B mod |A|, |A|)`, after which both are non-negative: the
            // remainder is, and the authority explicitly clears the sign of the value
            // that becomes `B`.
            let next_a = limbs::rem(&bv, &av);
            let next_b = av.clone();
            av = next_a;
            bv = next_b;
            aneg = false;
        }
    })
}
