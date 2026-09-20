//! Phase 8 — `crypto/bn/bn_dh.c`: the constants `dh_named_groups[]` points at.
//!
//! Thirty-two `const BIGNUM` objects: the FFDHE (RFC 7919) and MODP (RFC 3526) families'
//! `p` and `q` sharing one `g` holding 2, the three RFC 5114 groups' `p`, `q` and `g`,
//! and that shared `g` itself. They are `crypto/bn/bn_dh.c`'s whole content — the file
//! defines nothing else — and the reason they are a module of their own is D327's rule:
//! a unit given a crate module makes every internal it names countable, so the unit is
//! transcribed whole or not at all.
//!
//! ## The bytes are generated; this module is the object model over them
//!
//! The values live in [`crate::bn::dh_data`], which `forensics/tools/gen_bn_dh.py`
//! **reads back from the admitted authority** — a probe linked against its own
//! `libcrypto` asks `DH_new_by_nid` and `DH_get_1024_160` for each group and prints
//! `BN_bn2hex` — rather than transposing `bn_dh.c`. D329 recorded why that matters: the
//! values are data only a comparison with the authority can check, and a typo in an
//! 8192-bit prime is invisible to everything else. The generator also checks this file's
//! table against `bn_dh.c`'s own `make_dh_bn` inventory, in order and with the line each
//! is expanded at, in **both** of its tiers, so the table below cannot drift from the
//! authority on a runner that has no authority at all.
//!
//! What is transcribed *here* is the part that is not data. The authority's objects are
//! `const BIGNUM` in `.rodata`; this crate's [`BigNum`] owns a heap `Vec`, so such an
//! object cannot be placed in static storage at all and is instead built once, lazily,
//! and cached — the crate's static-`BIGNUM` idiom, which
//! [`crate::bn::rsa_fips186_4::ossl_bn_inv_sqrt_2`] and [`crate::bn::primes`]'s
//! `BN_get0_nist_prime_*` family already use. Two reads of one accessor answer the same
//! pointer, which is what a `static` object means in C.
//!
//! ## `BN_FLG_STATIC_DATA`, which is not decoration here
//!
//! `make_dh_bn` (`bn_dh.c:1374-1381`) initialises every one of these with
//! `BN_FLG_STATIC_DATA`, and `ossl_ffc_named_group_set` hands them **into a `DH`'s
//! parameter block by pointer**. That block's owner is `ossl_ffc_params_cleanup`, which
//! `BN_free`s `p`, `q` and `g`, so `DH_new_by_nid(NID_ffdhe2048)` followed by `DH_free`
//! would free a shared constant if the flag were not honoured. It is:
//! [`crate::bn::bignum`]'s `BN_free` and `BN_clear_free` test it first and release
//! nothing, exactly as `crypto/bn/bn_lib.c:212-232` does, and `ffc_bn_cpy` therefore
//! *shares* the pointer when it copies a named group's parameters rather than
//! duplicating the number — the authority's own behaviour, and the reason copying a
//! `DH_new_by_nid` group is cheap.
//!
//! Each object is process-lifetime constant storage and is never released; the cache
//! leaks exactly one `BIGNUM` per constant, which is what `.rodata` costs in C.
//!
//! ## What the unit test asserts, and why it is this and not a value
//!
//! Every width in `bn_dh.c`'s own declaration is asserted, every safe-prime family's
//! `p mod 24 == 23` and `p = 2q + 1` are asserted, every shared `g` is asserted to be
//! `ossl_bignum_const_2`, and the three RFC 5114 subgroup orders go through the landed
//! [`BN_check_prime`]. **The eleven safe-prime moduli do not**: a 2048-bit
//! `BN_check_prime` is 64 Miller-Rabin rounds and an 8192-bit one is 128, which is
//! minutes of debug-mode arithmetic rather than a test. Their primality is what the
//! congruences and the exact widths are evidence *for*, and the value itself is the
//! authority's — read back rather than typed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::sync::atomic::AtomicPtr;

use crate::bn::bignum::{static_data_bignum, BigNum};
use crate::bn::dh_data as data;

// The lattice `dh_named_groups[]` points at: one accessor per `ossl_bignum_*` object, in
// `bn_dh.c`'s own definition order.
//
// Each is written out rather than produced by a `macro_rules!`, and that is a *measured*
// requirement rather than a preference. Two generators read this file lexically:
// `gen_prerequisite_atlas.py` derives the module-to-unit map from the symbols a module
// **defines**, and `prerequisite_gate.py` derives "the crate builds this name" the same
// way. Both look for a `fn NAME(` with an identifier after `fn`, which a macro body's
// `fn $symbol(` is not — so a table produced by a macro would leave `crypto/bn/bn_dh.c`
// with no crate module and all thirty-two names reported as `undefined_prerequisite`.
// `prototype_court.py` reads declarations the same way for the same reason (D98), and a
// macro invocation whose arguments begin with a bracket is one it reports as unreadable.
//
// Each function's cache is a `static` **inside its own body**, so the symbol's identity
// does not depend on a second identifier being kept in step with it, and each body names
// the generated array its symbol's uppercased name gives. `gen_bn_dh.py` checks the
// pairings, the order and the coordinates against the authority, in both of its tiers.

/// `const BIGNUM ossl_bignum_const_2` — `crypto/bn/bn_dh.c:1385`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_const_2() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_CONST_2_BYTES)
}

/// `const BIGNUM ossl_bignum_dh1024_160_p` — `crypto/bn/bn_dh.c:1389`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh1024_160_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH1024_160_P_BYTES)
}

/// `const BIGNUM ossl_bignum_dh1024_160_q` — `crypto/bn/bn_dh.c:1390`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh1024_160_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH1024_160_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_dh1024_160_g` — `crypto/bn/bn_dh.c:1391`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh1024_160_g() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH1024_160_G_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_224_p` — `crypto/bn/bn_dh.c:1392`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_224_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_224_P_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_224_q` — `crypto/bn/bn_dh.c:1393`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_224_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_224_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_224_g` — `crypto/bn/bn_dh.c:1394`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_224_g() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_224_G_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_256_p` — `crypto/bn/bn_dh.c:1395`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_256_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_256_P_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_256_q` — `crypto/bn/bn_dh.c:1396`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_256_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_256_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_dh2048_256_g` — `crypto/bn/bn_dh.c:1397`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_dh2048_256_g() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_DH2048_256_G_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe2048_p` — `crypto/bn/bn_dh.c:1399`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe2048_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE2048_P_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe2048_q` — `crypto/bn/bn_dh.c:1400`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe2048_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE2048_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe3072_p` — `crypto/bn/bn_dh.c:1401`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe3072_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE3072_P_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe3072_q` — `crypto/bn/bn_dh.c:1402`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe3072_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE3072_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe4096_p` — `crypto/bn/bn_dh.c:1403`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe4096_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE4096_P_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe4096_q` — `crypto/bn/bn_dh.c:1404`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe4096_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE4096_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe6144_p` — `crypto/bn/bn_dh.c:1405`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe6144_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE6144_P_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe6144_q` — `crypto/bn/bn_dh.c:1406`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe6144_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE6144_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe8192_p` — `crypto/bn/bn_dh.c:1407`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe8192_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE8192_P_BYTES)
}

/// `const BIGNUM ossl_bignum_ffdhe8192_q` — `crypto/bn/bn_dh.c:1408`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_ffdhe8192_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_FFDHE8192_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_1536_p` — `crypto/bn/bn_dh.c:1411`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_1536_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_1536_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_1536_q` — `crypto/bn/bn_dh.c:1412`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_1536_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_1536_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_2048_p` — `crypto/bn/bn_dh.c:1414`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_2048_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_2048_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_2048_q` — `crypto/bn/bn_dh.c:1415`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_2048_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_2048_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_3072_p` — `crypto/bn/bn_dh.c:1416`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_3072_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_3072_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_3072_q` — `crypto/bn/bn_dh.c:1417`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_3072_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_3072_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_4096_p` — `crypto/bn/bn_dh.c:1418`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_4096_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_4096_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_4096_q` — `crypto/bn/bn_dh.c:1419`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_4096_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_4096_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_6144_p` — `crypto/bn/bn_dh.c:1420`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_6144_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_6144_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_6144_q` — `crypto/bn/bn_dh.c:1421`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_6144_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_6144_Q_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_8192_p` — `crypto/bn/bn_dh.c:1422`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_8192_p() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_8192_P_BYTES)
}

/// `const BIGNUM ossl_bignum_modp_8192_q` — `crypto/bn/bn_dh.c:1423`.
///
/// # Safety
///
/// Takes no pointers. The result is the shared object behind the authority's own
/// `const BIGNUM`; it must not be modified or freed.
pub(crate) unsafe fn ossl_bignum_modp_8192_q() -> *const BigNum {
    static CACHE: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
    static_data_bignum(&CACHE, &data::OSSL_BIGNUM_MODP_8192_Q_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ptr;

    use crate::bn::arith::{BN_add_word, BN_cmp, BN_lshift1, BN_mod_word, BN_mul};
    use crate::bn::bignum::{
        BN_free, BN_get_flags, BN_is_odd, BN_is_word, BN_new, BN_num_bits, BN_FLG_MALLOCED,
        BN_FLG_STATIC_DATA,
    };
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
    use crate::bn::primes::BN_check_prime;

    /// One of the thirty-two accessors, as a value so a table can hold them.
    type Constant = unsafe fn() -> *const BigNum;

    /// `bn_dh.c`'s own widths, for all thirty-two objects.
    ///
    /// Each number is `BN_num_bits` of what the admitted `libcrypto` answers for that
    /// object, and the generator records the same value in
    /// `forensics/atlas/bn-dh.json`'s `constants[].bits`. They are asserted because a
    /// width is a property a test can check without the authority — and because two of
    /// these are *not* what the family name suggests: `ossl_bignum_dh2048_256_g` is
    /// **2046** bits, and that is the authority's own object.
    const WIDTHS: [(Constant, &str, i32); 32] = [
        (ossl_bignum_const_2, "const_2", 2),
        (ossl_bignum_dh1024_160_p, "dh1024_160_p", 1024),
        (ossl_bignum_dh1024_160_q, "dh1024_160_q", 160),
        (ossl_bignum_dh1024_160_g, "dh1024_160_g", 1024),
        (ossl_bignum_dh2048_224_p, "dh2048_224_p", 2048),
        (ossl_bignum_dh2048_224_q, "dh2048_224_q", 224),
        (ossl_bignum_dh2048_224_g, "dh2048_224_g", 2048),
        (ossl_bignum_dh2048_256_p, "dh2048_256_p", 2048),
        (ossl_bignum_dh2048_256_q, "dh2048_256_q", 256),
        (ossl_bignum_dh2048_256_g, "dh2048_256_g", 2046),
        (ossl_bignum_ffdhe2048_p, "ffdhe2048_p", 2048),
        (ossl_bignum_ffdhe2048_q, "ffdhe2048_q", 2047),
        (ossl_bignum_ffdhe3072_p, "ffdhe3072_p", 3072),
        (ossl_bignum_ffdhe3072_q, "ffdhe3072_q", 3071),
        (ossl_bignum_ffdhe4096_p, "ffdhe4096_p", 4096),
        (ossl_bignum_ffdhe4096_q, "ffdhe4096_q", 4095),
        (ossl_bignum_ffdhe6144_p, "ffdhe6144_p", 6144),
        (ossl_bignum_ffdhe6144_q, "ffdhe6144_q", 6143),
        (ossl_bignum_ffdhe8192_p, "ffdhe8192_p", 8192),
        (ossl_bignum_ffdhe8192_q, "ffdhe8192_q", 8191),
        (ossl_bignum_modp_1536_p, "modp_1536_p", 1536),
        (ossl_bignum_modp_1536_q, "modp_1536_q", 1535),
        (ossl_bignum_modp_2048_p, "modp_2048_p", 2048),
        (ossl_bignum_modp_2048_q, "modp_2048_q", 2047),
        (ossl_bignum_modp_3072_p, "modp_3072_p", 3072),
        (ossl_bignum_modp_3072_q, "modp_3072_q", 3071),
        (ossl_bignum_modp_4096_p, "modp_4096_p", 4096),
        (ossl_bignum_modp_4096_q, "modp_4096_q", 4095),
        (ossl_bignum_modp_6144_p, "modp_6144_p", 6144),
        (ossl_bignum_modp_6144_q, "modp_6144_q", 6143),
        (ossl_bignum_modp_8192_p, "modp_8192_p", 8192),
        (ossl_bignum_modp_8192_q, "modp_8192_q", 8191),
    ];

    /// The eleven `(p, q)` pairs that are a safe prime and its subgroup order, with the
    /// width of `p`.
    const SAFE_PRIMES: [(Constant, Constant, u32); 11] = [
        (ossl_bignum_ffdhe2048_p, ossl_bignum_ffdhe2048_q, 2048),
        (ossl_bignum_ffdhe3072_p, ossl_bignum_ffdhe3072_q, 3072),
        (ossl_bignum_ffdhe4096_p, ossl_bignum_ffdhe4096_q, 4096),
        (ossl_bignum_ffdhe6144_p, ossl_bignum_ffdhe6144_q, 6144),
        (ossl_bignum_ffdhe8192_p, ossl_bignum_ffdhe8192_q, 8192),
        (ossl_bignum_modp_1536_p, ossl_bignum_modp_1536_q, 1536),
        (ossl_bignum_modp_2048_p, ossl_bignum_modp_2048_q, 2048),
        (ossl_bignum_modp_3072_p, ossl_bignum_modp_3072_q, 3072),
        (ossl_bignum_modp_4096_p, ossl_bignum_modp_4096_q, 4096),
        (ossl_bignum_modp_6144_p, ossl_bignum_modp_6144_q, 6144),
        (ossl_bignum_modp_8192_p, ossl_bignum_modp_8192_q, 8192),
    ];

    /// Every object's width is `bn_dh.c`'s, and every one carries `BN_FLG_STATIC_DATA`
    /// without `BN_FLG_MALLOCED` — the pair `ffc_bn_cpy` tests and the reason a `DH`
    /// built from a named group does not free `.rodata` when it is released.
    #[test]
    fn the_constants_are_the_authoritys_widths_and_flags() {
        for (accessor, name, bits) in WIDTHS {
            // SAFETY: every accessor takes no pointers.
            let v = unsafe { accessor() };
            assert!(!v.is_null(), "{name} is not built");
            // SAFETY: `v` is the shared object, live for the process.
            unsafe {
                assert_eq!(BN_num_bits(v), bits, "{name} is the wrong width");
                assert_ne!(
                    BN_get_flags(v, BN_FLG_STATIC_DATA),
                    0,
                    "{name} is not static"
                );
                assert_eq!(
                    BN_get_flags(v, BN_FLG_MALLOCED),
                    0,
                    "{name} claims to be heap-allocated, which would make it freeable"
                );
            }
        }
    }

    /// Two reads of one constant answer the same object, and two different constants are
    /// two objects.
    ///
    /// The authority's are `static` objects, so this is the identity half of the contract
    /// rather than a nicety: `DH_get0_pqg` on two `DH_new_by_nid` objects must answer the
    /// same `p` pointer, which `RT-DH` observes, and a fresh object per call would not.
    #[test]
    fn each_constant_is_one_cached_object() {
        for (accessor, name, _bits) in WIDTHS {
            // SAFETY: every accessor takes no pointers.
            assert_eq!(unsafe { accessor() }, unsafe { accessor() }, "{name}");
        }
        // SAFETY: both take no pointers, and the two calls must not be one object.
        assert_ne!(unsafe { ossl_bignum_ffdhe2048_p() }, unsafe {
            ossl_bignum_ffdhe2048_q()
        });
    }

    /// The eleven safe-prime groups really are safe primes: odd, `p = 2q + 1`, and
    /// `p mod 24 == 23` — the congruence that makes 2 a **quadratic residue** mod `p`
    /// and therefore a member of the order-`q` subgroup. That is the property
    /// `dh_gen.c`'s `dh_builtin_genparams` generates for (`t1 = 23`, `t2 = 24` for
    /// `DH_GENERATOR_2`) and the reason the shared `g` can be the constant 2.
    ///
    /// **`23`, not `11`, and the difference is not cosmetic.** `p mod 24 == 23` means
    /// `p ≡ 7 (mod 8)`, so 2 is a residue and `2^q ≡ 1 (mod p)`; `p mod 24 == 11` would
    /// mean `p ≡ 3 (mod 8)`, where 2 is a non-residue and 2 would generate the *other*
    /// coset. `DH_check` tests exactly `g^q == 1 (mod p)`, so the wrong reading is a
    /// group the authority's own validator rejects.
    #[test]
    fn the_safe_prime_groups_are_safe_primes() {
        // SAFETY: the accessor takes no pointers.
        let two = unsafe { ossl_bignum_const_2() };
        for (p_of, q_of, bits) in SAFE_PRIMES {
            // SAFETY: both accessors take no pointers.
            let (p, q) = unsafe { (p_of(), q_of()) };
            // SAFETY: `p` and `q` are shared objects, live for the process; `q2` is this
            // test's own allocation. `p` is only ever read.
            unsafe {
                assert_eq!(BN_num_bits(p) as u32, bits);
                assert_eq!(
                    BN_num_bits(q) as u32,
                    bits - 1,
                    "q is not the width of (p-1)/2"
                );
                assert_ne!(BN_is_odd(p), 0);
                assert_ne!(BN_is_odd(q), 0);
                assert_eq!(BN_mod_word(p, 24), 23, "p mod 24");
                /* p == 2q + 1 */
                let q2 = BN_new();
                assert!(!q2.is_null());
                assert_eq!(BN_lshift1(q2, q), 1);
                assert_eq!(BN_add_word(q2, 1), 1);
                assert_eq!(BN_cmp(p, q2), 0, "p is not 2q + 1");
                BN_free(q2);
            }
        }
        // SAFETY: `two` is the shared object and the accessor takes no pointers.
        assert_eq!(two, unsafe { ossl_bignum_const_2() });
    }

    /// `ossl_bignum_const_2` is 2, which `ffc_dh.c` points the eleven safe-prime
    /// families' `g` at, and the three RFC 5114 groups do **not** use it.
    #[test]
    fn the_shared_generator_is_two_and_the_rfc5114_groups_have_their_own() {
        // SAFETY: the accessor takes no pointers.
        let two = unsafe { ossl_bignum_const_2() };
        // SAFETY: `two` is the shared object.
        unsafe {
            assert_eq!(BN_num_bits(two), 2);
            assert_ne!(BN_is_word(two, 2), 0);
        }
        // SAFETY: the three accessors take no pointers.
        for g in unsafe {
            [
                ossl_bignum_dh1024_160_g(),
                ossl_bignum_dh2048_224_g(),
                ossl_bignum_dh2048_256_g(),
            ]
        } {
            assert_ne!(
                g, two,
                "an RFC 5114 group must not share `ossl_bignum_const_2`"
            );
        }
    }

    /// The four small constants are prime, through the landed [`BN_check_prime`].
    ///
    /// The three RFC 5114 **subgroup orders** are the security-relevant ones and are 160,
    /// 224 and 256 bits, which is what makes a real primality test affordable here; the
    /// safe-prime moduli are 1536 bits and up, where 64 Miller-Rabin rounds is minutes of
    /// debug-mode arithmetic rather than a test. `ossl_bignum_const_2` is included
    /// because it is trivially prime and because a `2` that was not would make the
    /// previous test's `2q + 1` arithmetic a different statement.
    #[test]
    fn the_small_constants_are_prime() {
        // SAFETY: `BN_CTX_new_ex(NULL)` reads no caller pointer.
        let ctx = unsafe { BN_CTX_new_ex(ptr::null_mut()) };
        assert!(!ctx.is_null());
        for q in [
            ossl_bignum_const_2,
            ossl_bignum_dh1024_160_q,
            ossl_bignum_dh2048_224_q,
            ossl_bignum_dh2048_256_q,
        ] {
            // SAFETY: the accessor takes no pointers.
            let v = unsafe { q() };
            // SAFETY: `v` is shared storage and `ctx` is this test's own context.
            assert_eq!(unsafe { BN_check_prime(v, ctx, ptr::null_mut()) }, 1);
        }
        // SAFETY: `ctx` is this test's own and unreferenced after this.
        unsafe { BN_CTX_free(ctx) };
    }

    /// A composite built from a group's own order is rejected, which is what makes the
    /// primality assertions above load-bearing rather than a constant the crate could
    /// answer unconditionally. `q^2` is composite for every one of these.
    #[test]
    fn the_primality_test_rejects_a_composite_of_the_same_shape() {
        // SAFETY: `BN_CTX_new_ex(NULL)` reads no caller pointer.
        let ctx = unsafe { BN_CTX_new_ex(ptr::null_mut()) };
        assert!(!ctx.is_null());
        // SAFETY: the accessor takes no pointers.
        let q = unsafe { ossl_bignum_dh1024_160_q() };
        // SAFETY: `sq` is this test's own allocation; `q` is live and `ctx` is live.
        let sq = unsafe {
            let sq = BN_new();
            assert!(!sq.is_null());
            assert_eq!(BN_mul(sq, q, q, ctx), 1);
            sq
        };
        // SAFETY: `sq` is this test's own object and `ctx` is live.
        assert_eq!(unsafe { BN_check_prime(sq, ctx, ptr::null_mut()) }, 0);
        // SAFETY: `sq` and `ctx` are this test's own and unreferenced after this.
        unsafe {
            BN_free(sq);
            BN_CTX_free(ctx);
        }
    }

    /// Freeing a shared constant is a no-op, which is the property a `DH` built by
    /// `DH_new_by_nid` depends on: its parameter block `BN_free`s what it holds.
    ///
    /// The test would fail under a sanitizer rather than here if `BN_free` released the
    /// object, so it asserts the observable half: the object survives with its value.
    #[test]
    fn freeing_a_shared_constant_leaves_it_alone() {
        // SAFETY: the accessor takes no pointers.
        let p = unsafe { ossl_bignum_ffdhe2048_p() }.cast_mut();
        // SAFETY: `p` is one of the shared constants, which `BN_free` must leave alone.
        unsafe { BN_free(p) };
        // SAFETY: the accessor takes no pointers and `p` is the same object.
        assert_eq!(unsafe { ossl_bignum_ffdhe2048_p() }.cast_mut(), p);
        // SAFETY: `p` is live — that is the claim under test.
        assert_eq!(unsafe { BN_num_bits(p) }, 2048);
    }
}
