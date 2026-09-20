//! `crypto/rsa/rsa_mp.c` — the multi-prime `RSA` helpers.
//!
//! This module is Phase 8.4's. The authority's file is five functions: the two
//! destructors, the constructor that pairs with them, the pass that refreshes each extra
//! prime's accumulated product, and the ceiling [`ossl_rsa_multip_cap`] answers for a
//! modulus size. All five are on the integration plan's missing-callee list:
//! `RSA_set0_multi_prime_params` is the caller that reaches [`ossl_rsa_multip_info_new`]
//! and [`ossl_rsa_multip_calc_product`], and `RSA_security_bits` reads the cap
//! (`rsa_lib.c:387-401`).
//!
//! Three things about the file are the documentation rather than the detail:
//!
//! * **`RSA_PRIME_INFO` is not declared here.** It is [`RsaPrimeInfo`], beside
//!   [`Rsa`] in [`super`], because `rsa_lib.c`'s accessors and this file's functions both
//!   read and write it, and a second declaration would be a second layout for one object.
//! * **`_free_ex` is the shared tail.** [`ossl_rsa_multip_info_free`] releases the three
//!   primes [`ossl_rsa_multip_info_new`] allocated and then calls
//!   [`ossl_rsa_multip_info_free_ex`] for `pp` and the record, exactly as the authority
//!   does rather than repeating its two lines. The two exist separately because `r`, `d`
//!   and `t` have already been handed to the caller's key by the time a later failure in
//!   `RSA_set0_multi_prime_params` takes its `err:` label.
//! * **The destructor's ownership is the header's, not the struct's.** `_free_ex` frees
//!   only `pp` and the record; `_free` is the one that owns `r`/`d`/`t`, and that is the
//!   distinction the `set0_*` path depends on.
//!
//! The two `OPENSSL_sk_freefunc` adapters at the bottom stand in for the authority's
//! generated `sk_RSA_PRIME_INFO_pop_free`: this crate has no generated typed stacks, so
//! `OPENSSL_sk_pop_free` is handed the destructor directly.

use core::ffi::{c_char, c_int, c_void};

use crate::bn::arith::BN_mul;
use crate::bn::bignum::{BN_clear_free, BN_free, BN_secure_new, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BnCtx};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

use super::{Rsa, RsaPrimeInfo};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_mp.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `forensics/authorities/build/openssl-3.6.4-production/crypto/rsa/libcrypto-lib-rsa_mp.o`,
/// the same check D279 and D280 applied to the cipher units. It matters here for the same
/// reason it does in [`super`]: `file` reaches an application through
/// `CRYPTO_set_mem_functions`.
#[allow(dead_code)] // read by the four allocators below, whose first caller is the object layer
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_mp.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
#[allow(dead_code)] // as `FILE`
const LINE: c_int = 0;

/// `RSA_MAX_PRIME_NUM` — `crypto/rsa/rsa_local.h:16`. The ceiling
/// [`ossl_rsa_multip_cap`] clamps to, and therefore the largest number of extra primes
/// an object can be given while the cap still describes it.
#[allow(dead_code)] // read by `ossl_rsa_multip_cap`, whose first caller is `RSA_security_bits`
const RSA_MAX_PRIME_NUM: c_int = 5;

/// `void ossl_rsa_multip_info_free_ex(RSA_PRIME_INFO *pinfo)` —
/// `crypto/rsa/rsa_mp.c:15-19`.
///
/// "free pp and pinfo only": `r`, `d` and `t` belong to the caller's key by the time this
/// runs, which is why both `err:` labels that release a partially built record use it and
/// why [`ossl_rsa_multip_info_free`] is the destructor that owns the three.
///
/// # Safety
///
/// `pinfo` must be a live `RSA_PRIME_INFO` whose `pp` is NULL or a live `BIGNUM` this call
/// owns, and whose `r`/`d`/`t` are owned elsewhere. The pointer must not be used again.
#[allow(dead_code)] // reached through `ossl_rsa_multip_info_free` and the object layer's `err:` labels
pub(crate) unsafe fn ossl_rsa_multip_info_free_ex(pinfo: *mut RsaPrimeInfo) {
    // SAFETY: `pinfo` is live per this function's `# Safety` section, so both of its
    // accesses below are in bounds; `BN_clear_free` accepts NULL.
    unsafe {
        BN_clear_free((*pinfo).pp);
        CRYPTO_free(pinfo.cast::<c_void>(), FILE, LINE);
    }
}

/// `void ossl_rsa_multip_info_free(RSA_PRIME_INFO *pinfo)` —
/// `crypto/rsa/rsa_mp.c:22-29`.
///
/// The destructor an `OPENSSL_sk_pop_free` over a `STACK_OF(RSA_PRIME_INFO)` wants: it
/// releases the three primes [`ossl_rsa_multip_info_new`] allocated and then calls
/// [`ossl_rsa_multip_info_free_ex`] for `pp` and the record — it does not repeat its body,
/// because the authority does not.
///
/// # Safety
///
/// `pinfo` must be a live `RSA_PRIME_INFO` whose `r`, `d`, `t` and `pp` are each NULL or a
/// live `BIGNUM` this call owns. The pointer must not be used again.
#[allow(dead_code)] // installed as the stack destructor by the object layer
pub(crate) unsafe fn ossl_rsa_multip_info_free(pinfo: *mut RsaPrimeInfo) {
    // SAFETY: `pinfo` is live per this function's `# Safety` section; each of the three
    // `BN_clear_free`s takes a member that is NULL or owned by this call.
    unsafe {
        BN_clear_free((*pinfo).r);
        BN_clear_free((*pinfo).d);
        BN_clear_free((*pinfo).t);
        // SAFETY: `pinfo` is still live and this call owns it, which is exactly
        // `ossl_rsa_multip_info_free_ex`'s contract.
        ossl_rsa_multip_info_free_ex(pinfo);
    }
}

/// `RSA_PRIME_INFO *ossl_rsa_multip_info_new(void)` — `crypto/rsa/rsa_mp.c:31-56`.
///
/// A zeroed record with four **secure** `BIGNUM`s — `r`, `d`, `t` and the `pp` that
/// [`ossl_rsa_multip_calc_product`] fills in. `m` is left NULL: it is the cached
/// Montgomery context, and no function in this stratum writes it.
///
/// Each of the four allocations takes the authority's `err:` label, which releases all
/// four members and the record. `BN_free` accepts NULL, so the label is correct whatever
/// prefix of the four succeeded — which is why the four failures share one exit rather
/// than four.
///
/// # Safety
///
/// Takes no pointers. The returned record, when non-NULL, is owned by the caller and must
/// be released exactly once, with [`ossl_rsa_multip_info_free`] while the three primes are
/// still the record's, or with [`ossl_rsa_multip_info_free_ex`] once they are not.
#[allow(dead_code)] // the caller is `RSA_set0_multi_prime_params`, in the object layer
pub(crate) unsafe fn ossl_rsa_multip_info_new() -> *mut RsaPrimeInfo {
    // `CRYPTO_zalloc` is a safe function in this crate (D113), so this call is unguarded
    // and the result is a fresh, zeroed, exclusively-owned record.
    let pinfo =
        CRYPTO_zalloc(core::mem::size_of::<RsaPrimeInfo>(), FILE, LINE).cast::<RsaPrimeInfo>();
    if pinfo.is_null() {
        return core::ptr::null_mut();
    }

    let complete = 'err: {
        // SAFETY: `pinfo` is the fresh, zeroed record allocated above and is not aliased,
        // so each of the four writes below is to memory this call owns; each
        // `BN_secure_new` takes no pointers.
        unsafe {
            (*pinfo).r = BN_secure_new();
            if (*pinfo).r.is_null() {
                break 'err false;
            }
            (*pinfo).d = BN_secure_new();
            if (*pinfo).d.is_null() {
                break 'err false;
            }
            (*pinfo).t = BN_secure_new();
            if (*pinfo).t.is_null() {
                break 'err false;
            }
            (*pinfo).pp = BN_secure_new();
            if (*pinfo).pp.is_null() {
                break 'err false;
            }
        }
        true
    };

    if complete {
        return pinfo;
    }

    // The authority's `err:` label. Every member is NULL or one of the allocations above,
    // and `BN_free` accepts NULL, so the four calls are correct at any prefix.
    // SAFETY: `pinfo` is the record allocated above and is still live and unaliased.
    unsafe {
        BN_free((*pinfo).r);
        BN_free((*pinfo).d);
        BN_free((*pinfo).t);
        BN_free((*pinfo).pp);
        CRYPTO_free(pinfo.cast::<c_void>(), FILE, LINE);
    }
    core::ptr::null_mut()
}

/// `int ossl_rsa_multip_calc_product(RSA *rsa)` — `crypto/rsa/rsa_mp.c:59-96`.
///
/// "Refill products of primes": each extra prime's `pp` is the product of every prime
/// before it, so `p1` walks the accumulated product down the stack while `p2` walks the
/// extra primes themselves. The first element's `pp` is therefore `p * q`, the second's is
/// `p * q * r₁`, and so on.
///
/// Three details are the authority's and not the shape's:
///
/// * **An object with no extra primes is a failure, not a no-op.** `OPENSSL_sk_num` answers
///   **-1** for a NULL stack, so the `ex_primes <= 0` test covers "no stack" and "empty
///   stack" with one arm, and both answer 0.
/// * **`pp` is allocated here when it is NULL.** It usually is not — the constructor left a
///   placeholder and `RSA_set0_multi_prime_params` replaces it — but a record that has been
///   through `_free_ex`, which releases `pp`, is refillable.
/// * **There is one `BN_CTX_free`, at the `err:` label.** Every failure below the `BN_CTX_new`
///   leaves through it, which is why the `rv`-carrying block below has a single exit.
///
/// # Safety
///
/// `rsa` must be a live `RSA` whose `p` and `q` are live `BIGNUM`s, and whose `prime_infos`
/// is NULL or a live `STACK_OF(RSA_PRIME_INFO)` every element of which is a live
/// `RSA_PRIME_INFO` whose `pp` is NULL or a live `BIGNUM`, and whose `r` is a live `BIGNUM`.
/// Every `pp` written here is left owned by its record.
#[allow(dead_code)] // the caller is `RSA_set0_multi_prime_params`, in the object layer
pub(crate) unsafe fn ossl_rsa_multip_calc_product(rsa: *mut Rsa) -> c_int {
    let mut ctx: *mut BnCtx = core::ptr::null_mut();

    let rv = 'err: {
        // SAFETY: `rsa` is live per this function's `# Safety` section, so
        // `prime_infos` is NULL or a live stack; `OPENSSL_sk_num` accepts NULL.
        let ex_primes = unsafe { OPENSSL_sk_num((*rsa).prime_infos) };
        if ex_primes <= 0 {
            // invalid
            break 'err 0;
        }

        // SAFETY: `BN_CTX_new` takes no pointers.
        ctx = unsafe { BN_CTX_new() };
        if ctx.is_null() {
            break 'err 0;
        }

        // SAFETY: `rsa` and `ctx` are live per this function's `# Safety` section and the
        // check above; every stack element is a live `RSA_PRIME_INFO` by that contract,
        // and each `pp`/`r` read below is either NULL or a live `BIGNUM`. `BN_mul`
        // accepts a NULL-or-live `ctx` and writes only its first argument.
        unsafe {
            // calculate pinfo->pp = p * q for the first 'extra' prime
            let mut p1: *mut BigNum = (*rsa).p;
            let mut p2: *mut BigNum = (*rsa).q;

            for i in 0..ex_primes {
                let pinfo = OPENSSL_sk_value((*rsa).prime_infos, i).cast::<RsaPrimeInfo>();
                if (*pinfo).pp.is_null() {
                    (*pinfo).pp = BN_secure_new();
                    if (*pinfo).pp.is_null() {
                        break 'err 0;
                    }
                }
                if BN_mul((*pinfo).pp, p1, p2, ctx) == 0 {
                    break 'err 0;
                }
                // save the previous one
                p1 = (*pinfo).pp;
                p2 = (*pinfo).r;
            }
        }

        1
    };

    // SAFETY: `ctx` is NULL or the live context created above; `BN_CTX_free` accepts NULL,
    // and the loop above leaves no `BN_CTX`-held BIGNUM reachable from a return value.
    unsafe { BN_CTX_free(ctx) };
    rv
}

/// `int ossl_rsa_multip_cap(int bits)` — `crypto/rsa/rsa_mp.c:98-113`.
///
/// The largest number of extra primes a modulus of `bits` bits may be given: 2 below 1024,
/// 3 below 4096, 4 below 8192, and `RSA_MAX_PRIME_NUM` at or above it. The trailing clamp
/// is the authority's even though no arm above can exceed the ceiling — it is what makes
/// the constant authoritative rather than decorative, and the unit test below pins the
/// ladder's boundaries, where an off-by-one comparison would silently change the answer.
#[allow(dead_code)] // the caller is `RSA_security_bits`, in the object layer
pub(crate) fn ossl_rsa_multip_cap(bits: c_int) -> c_int {
    let mut cap = RSA_MAX_PRIME_NUM;

    if bits < 1024 {
        cap = 2;
    } else if bits < 4096 {
        cap = 3;
    } else if bits < 8192 {
        cap = 4;
    }

    if cap > RSA_MAX_PRIME_NUM {
        cap = RSA_MAX_PRIME_NUM;
    }

    cap
}

/// The `OPENSSL_sk_freefunc` shape `OPENSSL_sk_pop_free` takes, wrapping
/// [`ossl_rsa_multip_info_free`] — the destructor that releases `r`, `d`, `t`, `pp` and the
/// record. The authority's generated `sk_RSA_PRIME_INFO_pop_free` is what installs this
/// adapter; this crate's stacks take it directly.
///
/// # Safety
///
/// `pinfo` must be NULL or a live `RSA_PRIME_INFO` whose `r`, `d`, `t` and `pp` are each
/// NULL or a live `BIGNUM` this call owns.
#[allow(dead_code)] // installed as an `OPENSSL_sk_freefunc` by the object layer
pub(crate) unsafe extern "C" fn multip_info_free_thunk(pinfo: *mut c_void) {
    // SAFETY: the caller's contract is this function's, and
    // `ossl_rsa_multip_info_free` is called exactly as the authority's
    // `sk_RSA_PRIME_INFO_pop_free` calls it.
    unsafe { ossl_rsa_multip_info_free(pinfo.cast::<RsaPrimeInfo>()) };
}

/// The `OPENSSL_sk_freefunc` shape for [`ossl_rsa_multip_info_free_ex`] —
/// `crypto/rsa/rsa_mp.c:15-19`'s "free pp and pinfo only". It is the destructor both
/// `err:` labels use, precisely because `r`, `d` and `t` have already been handed to the
/// caller's key.
///
/// # Safety
///
/// `pinfo` must be NULL or a live `RSA_PRIME_INFO` whose `pp` is NULL or a live `BIGNUM`
/// this call owns, and whose `r`/`d`/`t` are owned elsewhere.
#[allow(dead_code)] // installed as an `OPENSSL_sk_freefunc` by the object layer
pub(crate) unsafe extern "C" fn multip_info_free_ex_thunk(pinfo: *mut c_void) {
    // SAFETY: the caller's contract is this function's, and
    // `ossl_rsa_multip_info_free_ex` is called exactly as the authority's
    // `sk_RSA_PRIME_INFO_pop_free` calls it.
    unsafe { ossl_rsa_multip_info_free_ex(pinfo.cast::<RsaPrimeInfo>()) };
}

/// A **test-only** `RSA` every one of whose fields is zero or NULL — the object a
/// constructor that had failed its first allocation would leave behind.
///
/// Only three tests need one, and each needs a different member: this module's
/// `ossl_rsa_multip_calc_product` reads `p`, `q` and `prime_infos`, and
/// [`super::ossl`]'s blinding pair reads `blindings_sa`. The fixture is written out field
/// by field rather than built with `zeroed`, which is this crate's convention for the
/// authority's `{ 0, }`: spelling the fields out is what makes a member added to the
/// object have to be considered here instead of silently becoming NULL. See
/// `crate::rand::sys::Stat::ZEROED` for the same argument made at length.
#[cfg(test)]
pub(crate) fn zeroed_rsa() -> Rsa {
    Rsa {
        dummy_zero: 0,
        libctx: core::ptr::null_mut(),
        version: 0,
        meth: core::ptr::null(),
        engine: core::ptr::null_mut(),
        n: core::ptr::null_mut(),
        e: core::ptr::null_mut(),
        d: core::ptr::null_mut(),
        p: core::ptr::null_mut(),
        q: core::ptr::null_mut(),
        dmp1: core::ptr::null_mut(),
        dmq1: core::ptr::null_mut(),
        iqmp: core::ptr::null_mut(),
        pss_params: crate::rsa::RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: crate::rsa::RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        },
        pss: core::ptr::null_mut(),
        prime_infos: core::ptr::null_mut(),
        ex_data: crate::runtime::ex_data::CryptoExData {
            ctx: core::ptr::null_mut(),
            sk: core::ptr::null_mut(),
        },
        references: core::sync::atomic::AtomicI32::new(0),
        flags: 0,
        _method_mod_n: core::ptr::null_mut(),
        _method_mod_p: core::ptr::null_mut(),
        _method_mod_q: core::ptr::null_mut(),
        blindings_sa: core::ptr::null_mut(),
        lock: core::ptr::null_mut(),
        dirty_cnt: 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::bn::bignum::{BN_get_word, BN_new, BN_num_bits, BN_set_word};
    use crate::runtime::stack::{
        OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    };

    use super::*;

    /// **The cap ladder, boundary by boundary.** The fail-closed arms are 1024 and 4096:
    /// writing either comparison as `<=` turns 1024 into 2 and 4096 into 3, and neither
    /// would be visible at a round number inside an arm.
    #[test]
    fn the_multip_cap_is_the_authoritys_ladder() {
        assert_eq!(ossl_rsa_multip_cap(1023), 2, "below 1024");
        assert_eq!(
            ossl_rsa_multip_cap(1024),
            3,
            "1024 is the first 3-prime size"
        );
        assert_eq!(ossl_rsa_multip_cap(4095), 3, "below 4096");
        assert_eq!(
            ossl_rsa_multip_cap(4096),
            4,
            "4096 is the first 4-prime size"
        );
        assert_eq!(ossl_rsa_multip_cap(8191), 4, "below 8192");
        assert_eq!(
            ossl_rsa_multip_cap(8192),
            5,
            "8192 is the first 5-prime size"
        );
        // The trailing clamp is a no-op for every arm, so the ceiling is answered by the
        // ladder itself:
        assert_eq!(ossl_rsa_multip_cap(c_int::MAX), RSA_MAX_PRIME_NUM);
        assert_eq!(RSA_MAX_PRIME_NUM, 5);
    }

    /// `info_new` gives a record with four live `BIGNUM`s and a NULL `m`; replacing `pp`
    /// the way `RSA_set0_multi_prime_params` does and then calling `info_free` releases
    /// all four and the record. The release is not directly observable — the crate has no
    /// allocation accounting — so what this pins is that every field is where it should be
    /// and that the destructor runs without faulting on a record whose `pp` it did not
    /// allocate.
    #[test]
    fn a_prime_info_owns_four_bignums_and_info_free_releases_them() {
        // SAFETY: `ossl_rsa_multip_info_new` takes no pointers, and the record it returns
        // is released by `ossl_rsa_multip_info_free` below.
        let pinfo = unsafe { ossl_rsa_multip_info_new() };
        assert!(!pinfo.is_null());
        // SAFETY: `pinfo` is the live record this test just created.
        unsafe {
            assert!(!(*pinfo).r.is_null());
            assert!(!(*pinfo).d.is_null());
            assert!(!(*pinfo).t.is_null());
            assert!(!(*pinfo).pp.is_null());
            assert!((*pinfo).m.is_null(), "no function in this stratum writes m");
            assert_eq!(BN_num_bits((*pinfo).r), 0, "the placeholder is zero");

            // The `set0` path releases the placeholder and installs the caller's prime:
            // the destructor must therefore free whatever `pp` holds when it runs.
            BN_clear_free((*pinfo).pp);
            (*pinfo).pp = BN_new();
            assert!(!(*pinfo).pp.is_null());
            assert_eq!(BN_set_word((*pinfo).pp, 11), 1);

            // SAFETY: `pinfo` is live, and every member is NULL or owned by this call.
            ossl_rsa_multip_info_free(pinfo);
        }
    }

    /// `info_free_ex` is "free `pp` and `pinfo` only": the three primes survive it, and
    /// releasing them is the caller's job — which is why the `err:` labels use this
    /// destructor rather than [`ossl_rsa_multip_info_free`].
    #[test]
    fn info_free_ex_leaves_the_three_primes_to_its_caller() {
        // SAFETY: as above.
        let pinfo = unsafe { ossl_rsa_multip_info_new() };
        assert!(!pinfo.is_null());
        // SAFETY: `pinfo` is live, so its three pointers can be read out before the
        // record is released.
        let (r, d, t) = unsafe { ((*pinfo).r, (*pinfo).d, (*pinfo).t) };
        assert!(!r.is_null() && !d.is_null() && !t.is_null());

        // SAFETY: `pinfo` is live and owns its `pp`; `r`/`d`/`t` are copied out above and
        // are not touched by this call, which is the behaviour under test.
        unsafe { ossl_rsa_multip_info_free_ex(pinfo) };

        // SAFETY: the three primes are still live if `_free_ex` honoured its contract; a
        // destructor that freed them would make the reads and the frees below a
        // double-release, which is the failure this test is here to catch.
        unsafe {
            assert_eq!(BN_num_bits(r), 0);
            assert_eq!(BN_num_bits(d), 0);
            assert_eq!(BN_num_bits(t), 0);
            BN_clear_free(r);
            BN_clear_free(d);
            BN_clear_free(t);
        }
    }

    /// An object with no extra primes is the `ex_primes <= 0` early `err`: `OPENSSL_sk_num`
    /// answers **-1** for a NULL stack, so "no stack" and "empty stack" are one arm and
    /// both answer 0 rather than faulting.
    #[test]
    fn calc_product_refuses_an_object_with_no_extra_primes() {
        let mut rsa = zeroed_rsa();
        // SAFETY: `rsa` is a live value of this test's, and `calc_product` only reads its
        // `prime_infos` (NULL here) on this path.
        assert_eq!(unsafe { ossl_rsa_multip_calc_product(&mut rsa) }, 0);

        let infos = OPENSSL_sk_new_null();
        assert!(!infos.is_null());
        rsa.prime_infos = infos;
        // SAFETY: `rsa` is live and its `prime_infos` is the empty stack created above.
        let rv = unsafe { ossl_rsa_multip_calc_product(&mut rsa) };
        assert_eq!(rv, 0, "an empty stack is still <= 0");
        // SAFETY: `infos` is the stack created above and is not used again.
        unsafe { OPENSSL_sk_free(infos) };
        // `rsa.prime_infos` now dangles, which is why the local is not read again: the
        // object is this test's stack value and dropping it releases nothing.
    }

    /// The running product, over two extra primes: the first record's `pp` becomes
    /// `p * q`, the second's `p * q * r₁`. Both `pp`s are NULL on entry, so this also
    /// exercises the re-allocation arm that `RSA_set0_multi_prime_params` normally
    /// leaves unreached.
    #[test]
    fn calc_product_builds_the_running_product_of_the_extra_primes() {
        let mut rsa = zeroed_rsa();

        // SAFETY: every pointer below is created by this test and released by it; the
        // stack's elements are `RSA_PRIME_INFO`s owned by `ossl_rsa_multip_info_new`,
        // which `multip_info_free_thunk` releases with them.
        unsafe {
            rsa.p = BN_new();
            rsa.q = BN_new();
            assert!(!rsa.p.is_null() && !rsa.q.is_null());
            assert_eq!(BN_set_word(rsa.p, 3), 1);
            assert_eq!(BN_set_word(rsa.q, 5), 1);

            let first = ossl_rsa_multip_info_new();
            let second = ossl_rsa_multip_info_new();
            assert!(!first.is_null() && !second.is_null());
            assert_eq!(BN_set_word((*first).r, 7), 1);
            assert_eq!(BN_set_word((*second).r, 11), 1);
            // A NULL `pp` is what `RSA_set0_multi_prime_params` sees before the
            // constructor's placeholder is replaced, and what `_free_ex` leaves behind.
            BN_clear_free((*first).pp);
            (*first).pp = core::ptr::null_mut();
            BN_clear_free((*second).pp);
            (*second).pp = core::ptr::null_mut();

            let infos = OPENSSL_sk_new_null();
            assert!(!infos.is_null());
            // `OPENSSL_sk_push` answers the count *after* the insert, as the authority's does.
            assert_eq!(OPENSSL_sk_push(infos, first.cast()), 1);
            assert_eq!(OPENSSL_sk_push(infos, second.cast()), 2);
            rsa.prime_infos = infos;

            // SAFETY: `rsa` is live, its `p`/`q` are the live BIGNUMs above, and every
            // element of `prime_infos` is a live record whose `pp` and `r` are as the
            // contract requires.
            assert_eq!(ossl_rsa_multip_calc_product(&mut rsa), 1);
            assert_eq!(BN_get_word((*first).pp), 15, "p * q");
            assert_eq!(BN_get_word((*second).pp), 105, "p * q * r1");
            assert!(!(*first).pp.is_null(), "pp was allocated, not left NULL");
            assert!(
                !core::ptr::eq((*first).pp, (*second).pp),
                "each record has its own product"
            );

            // The destructor owns `r`/`d`/`t`/`pp` of both records, and `pop_free` owns
            // the stack, so this releases everything the block created.
            // SAFETY: the stack is live and every element is a live record this test owns.
            OPENSSL_sk_pop_free(infos, Some(multip_info_free_thunk));
            rsa.prime_infos = core::ptr::null_mut();

            // SAFETY: `p` and `q` were created above and are not referenced by any record.
            BN_free(rsa.p);
            BN_free(rsa.q);
        }
    }

    /// `multip_info_free_ex_thunk` is the destructor the `err:` labels install, and it
    /// walks the whole stack whether or not a thunk was installed on it: a stack from
    /// `OPENSSL_sk_new_null` has none, so `OPENSSL_sk_pop_free` calls the function it was
    /// handed for each element and then releases the stack.
    #[test]
    fn the_free_ex_thunk_walks_a_stack_without_an_installed_thunk() {
        let infos = OPENSSL_sk_new_null();
        assert!(!infos.is_null());
        // SAFETY: the two records are created here and the three primes of each are
        // released explicitly below, because `_free_ex` does not own them.
        unsafe {
            let a = ossl_rsa_multip_info_new();
            let b = ossl_rsa_multip_info_new();
            assert!(!a.is_null() && !b.is_null());
            assert_eq!(OPENSSL_sk_push(infos, a.cast()), 1);
            assert_eq!(OPENSSL_sk_push(infos, b.cast()), 2);
            let (ar, ad, at) = ((*a).r, (*a).d, (*a).t);
            let (br, bd, bt) = ((*b).r, (*b).d, (*b).t);

            // SAFETY: `infos` is live and every element is a live record; the thunk owns
            // each `pp` and the record itself.
            OPENSSL_sk_pop_free(infos, Some(multip_info_free_ex_thunk));

            // SAFETY: the six primes were the caller's throughout, so they are released
            // here — exactly once.
            BN_clear_free(ar);
            BN_clear_free(ad);
            BN_clear_free(at);
            BN_clear_free(br);
            BN_clear_free(bd);
            BN_clear_free(bt);
        }
    }
}
