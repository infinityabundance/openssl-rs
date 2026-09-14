//! Phase 5 — the authority's named primes.
//!
//! The values live in `crate::bn::prime_data`, which is generated from the admitted
//! authority rather than transcribed (see `forensics/tools/gen_bn_primes.py` for why).
//! This module is the API over them, and it has two ownership shapes that are easy to
//! conflate:
//!
//! * `BN_get0_nist_prime_*` returns a pointer to **static storage**. The caller must
//!   not modify or free it, and two calls return the same pointer — which a caller can
//!   observe by comparison, so the object is built once and cached rather than built
//!   per call.
//! * `BN_get_rfc2409_prime_*`/`BN_get_rfc3526_prime_*` take a destination: a null one
//!   means "allocate and return", a non-null one means "write here and return it".
//!   That is the authority's `COPY_BN` macro, and it is the same asymmetry `BN_bin2bn`
//!   has.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::bignum::{as_mut, new_owned, store, BigNum};
use crate::bn::limbs::{self, Limb};
use crate::bn::prime_data::{
    BN_get0_nist_prime_192 as P192, BN_get0_nist_prime_224 as P224, BN_get0_nist_prime_256 as P256,
    BN_get0_nist_prime_384 as P384, BN_get0_nist_prime_521 as P521,
    BN_get_rfc2409_prime_1024 as RFC2409_1024, BN_get_rfc2409_prime_768 as RFC2409_768,
    BN_get_rfc3526_prime_1536 as RFC3526_1536, BN_get_rfc3526_prime_2048 as RFC3526_2048,
    BN_get_rfc3526_prime_3072 as RFC3526_3072, BN_get_rfc3526_prime_4096 as RFC3526_4096,
    BN_get_rfc3526_prime_6144 as RFC3526_6144, BN_get_rfc3526_prime_8192 as RFC3526_8192,
};
use crate::ffi::guard_ffi;

/// The big-endian byte arrays the authority's headers carry, as limbs.
fn limbs_from_be(bytes: &[u8]) -> Vec<Limb> {
    let mut out = vec![0u64; bytes.len().div_ceil(8)];
    for (i, &b) in bytes.iter().rev().enumerate() {
        out[i / 8] |= (b as u64) << (8 * (i % 8));
    }
    limbs::normalise(&mut out);
    out
}

/// The cached object for one of the static primes.
///
/// The authority returns the address of a `static const BIGNUM`, so two calls answer
/// the same pointer. Building the object lazily and caching it reproduces that: a
/// caller comparing two results for identity sees one object, and a caller that leaks
/// the pointer (it must not free it) leaks exactly one.
fn nist_prime(cache: &AtomicPtr<BigNum>, bytes: &[u8]) -> *const BigNum {
    let existing = cache.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let fresh = new_owned(limbs_from_be(bytes), 0);
    match cache.compare_exchange(
        core::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` is the object this call allocated and has not been
            // published, so dropping it here leaves the cached one alone.
            unsafe { crate::bn::bignum::BN_free(fresh) };
            winner
        }
    }
}

/// `BN_dup`/`BN_copy` behind the authority's `BN_get_rfc*_prime_*` entry points: a
/// null destination allocates, a live one is written and returned.
fn copy_named(bn: *mut BigNum, bytes: &[u8]) -> *mut BigNum {
    let value = limbs_from_be(bytes);
    // SAFETY: the caller guarantees `bn` is null or a live, uniquely-owned `BIGNUM`.
    match unsafe { as_mut(bn) } {
        None => new_owned(value, 0),
        Some(dst) => {
            if store(Some(dst), value, false) {
                bn
            } else {
                core::ptr::null_mut()
            }
        }
    }
}

/// The five static caches, one per NIST prime.
static NIST_192: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
/// The 224-bit NIST prime's cache.
static NIST_224: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
/// The 256-bit NIST prime's cache.
static NIST_256: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
/// The 384-bit NIST prime's cache.
static NIST_384: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());
/// The 521-bit NIST prime's cache.
static NIST_521: AtomicPtr<BigNum> = AtomicPtr::new(core::ptr::null_mut());

/// `const BIGNUM *BN_get0_nist_prime_192(void)`
///
/// # Safety
///
/// Takes no pointers. The result is shared static storage and must not be modified or
/// freed.
#[no_mangle]
pub unsafe extern "C" fn BN_get0_nist_prime_192() -> *const BigNum {
    guard_ffi(core::ptr::null(), || nist_prime(&NIST_192, &P192))
}

/// `const BIGNUM *BN_get0_nist_prime_224(void)`
///
/// # Safety
///
/// As `BN_get0_nist_prime_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_get0_nist_prime_224() -> *const BigNum {
    guard_ffi(core::ptr::null(), || nist_prime(&NIST_224, &P224))
}

/// `const BIGNUM *BN_get0_nist_prime_256(void)`
///
/// # Safety
///
/// As `BN_get0_nist_prime_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_get0_nist_prime_256() -> *const BigNum {
    guard_ffi(core::ptr::null(), || nist_prime(&NIST_256, &P256))
}

/// `const BIGNUM *BN_get0_nist_prime_384(void)`
///
/// # Safety
///
/// As `BN_get0_nist_prime_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_get0_nist_prime_384() -> *const BigNum {
    guard_ffi(core::ptr::null(), || nist_prime(&NIST_384, &P384))
}

/// `const BIGNUM *BN_get0_nist_prime_521(void)`
///
/// # Safety
///
/// As `BN_get0_nist_prime_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_get0_nist_prime_521() -> *const BigNum {
    guard_ffi(core::ptr::null(), || nist_prime(&NIST_521, &P521))
}

/// The eight `BN_get_rfc*_prime_*` entry points, which differ only in their value.
macro_rules! named_prime {
    ($( $name:ident => $bytes:ident ),* $(,)?) => {
        $(
            #[doc = concat!("`BIGNUM *", stringify!($name), "(BIGNUM *bn)`")]
            ///
            /// # Safety
            ///
            /// `bn` must be null or a live, uniquely-owned `BIGNUM`. A null argument
            /// allocates and returns a new object; a non-null one is written and
            /// returned.
            #[no_mangle]
            pub unsafe extern "C" fn $name(bn: *mut BigNum) -> *mut BigNum {
                guard_ffi(core::ptr::null_mut(), || copy_named(bn, &$bytes))
            }
        )*
    };
}

named_prime! {
    BN_get_rfc2409_prime_768 => RFC2409_768,
    BN_get_rfc2409_prime_1024 => RFC2409_1024,
    BN_get_rfc3526_prime_1536 => RFC3526_1536,
    BN_get_rfc3526_prime_2048 => RFC3526_2048,
    BN_get_rfc3526_prime_3072 => RFC3526_3072,
    BN_get_rfc3526_prime_4096 => RFC3526_4096,
    BN_get_rfc3526_prime_6144 => RFC3526_6144,
    BN_get_rfc3526_prime_8192 => RFC3526_8192,
}
