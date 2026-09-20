//! Phase 8 — `crypto/rsa/rsa_ossl.c`, the default `RSA_METHOD`'s entry points.
//!
//! This module is Phase 8.4's and it is where `crypto/rsa/rsa_ossl.c`'s symbols live: the
//! `rsa_pkcs1_ossl_meth` table, `RSA_PKCS1_OpenSSL` and the `rsa_ossl_*` entry points it
//! names, and the per-thread blinding helpers at the top of the file. For now it holds
//! **only the blinding allocator and its release** — [`ossl_rsa_alloc_blinding`] and
//! [`ossl_rsa_free_blinding`] — because those two are on the integration plan's
//! missing-callee list and both live outside the file: `rsa_new_intern` stores the array
//! the allocator returns (`rsa_lib.c:96`) and `RSA_free` releases it (`rsa_lib.c:189`). The
//! `RSA` object's constructor, which is the caller that makes them reachable in this
//! stratum, is a later commit.
//!
//! Two things about the pair are worth naming:
//!
//! * **The blinding lives in a sparse array, not in the object.** The authority stores a
//!   `SPARSE_ARRAY_OF(BN_BLINDING)` behind `rsa->blindings_sa`, and the two functions here
//!   are that member's lifetime: a fresh array, and a walk that releases every context
//!   before releasing the array itself. There is no second sparse array in this module —
//!   the crate's [`crate::runtime::sparse_array`] is the only one.
//! * **`ossl_rsa_free_blinding` does not clear the field.** The authority reads
//!   `rsa->blindings_sa` into a local, walks it and frees it, and leaves the member
//!   dangling; the caller either drops the object next or sets it again. That is
//!   transcribed rather than tidied up, because a NULL write here would be a behaviour the
//!   authority does not have.
//!
//! `ossl_rsa_get_thread_bn_blinding` and the family below it are Phase 9's: they reach
//! `RSA_setup_blinding`, which draws a new blinding with `BN_BLINDING_create_param` and
//! therefore needs the RAND stratum.

use core::ffi::c_void;
use core::ptr;

use crate::bn::blinding::BN_BLINDING_free;
use crate::runtime::sparse_array::{
    ossl_sa_doall_arg, ossl_sa_free, ossl_sa_new, OpenSslSa, OsslUintMax,
};

use super::Rsa;

/// `static void free_bn_blinding(ossl_uintmax_t idx, BN_BLINDING *b, void *arg)` —
/// `crypto/rsa/rsa_ossl.c:245-248`.
///
/// The leaf [`ossl_sa_doall_arg`] calls once per non-NULL slot: `BN_BLINDING_free`, with
/// the index and the argument ignored, exactly as the authority's static function ignores
/// them.
///
/// # Safety
///
/// `b` must be NULL or a live `BN_BLINDING` this array owns, and must not have been freed.
#[allow(dead_code)] // the leaf `ossl_rsa_free_blinding` walks with
unsafe fn free_bn_blinding(_idx: OsslUintMax, b: *mut c_void, _arg: *mut c_void) {
    // SAFETY: `b` is the value the walk found in the array, so it is a `BN_BLINDING *`
    // this array owns; `BN_BLINDING_free` accepts NULL.
    unsafe { BN_BLINDING_free(b.cast()) };
}

/// `void ossl_rsa_free_blinding(RSA *rsa)` — `crypto/rsa/rsa_ossl.c:250-256`.
///
/// Reads `rsa->blindings_sa` into a local, walks it releasing every context, then releases
/// the array. **The member is not cleared** — see the module note; the object is freed or
/// re-blinded by the caller, and this function does what the authority does and no more.
///
/// # Safety
///
/// `rsa` must be a live `RSA` whose `blindings_sa` is NULL or a live sparse array of
/// `BN_BLINDING` owned by this call, and no other reference to that array may be used
/// afterwards.
#[allow(dead_code)] // called by `RSA_free`, which the object layer lands
pub(crate) unsafe fn ossl_rsa_free_blinding(rsa: *mut Rsa) {
    // SAFETY: `rsa` is live per this function's `# Safety` section.
    let blindings = unsafe { (*rsa).blindings_sa }.cast::<OpenSslSa>();

    // SAFETY: `blindings` is NULL or the live array the object owns, and
    // `free_bn_blinding` is the destructor for every value in it; both entry points accept
    // NULL, so an object that was never blinded is released correctly as well.
    unsafe {
        ossl_sa_doall_arg(blindings, Some(free_bn_blinding), ptr::null_mut());
        ossl_sa_free(blindings);
    }
}

/// `void *ossl_rsa_alloc_blinding(void)` — `crypto/rsa/rsa_ossl.c:258-261`.
///
/// The authority's `ossl_sa_BN_BLINDING_new()`, returning an empty array typed as the
/// `void *` the object's member holds. It takes **no argument** — the array is not tied to
/// a key until it is stored in one.
///
/// # Safety
///
/// The returned pointer must be released with [`ossl_rsa_free_blinding`] (or
/// `ossl_sa_free` once its values are gone), and must be stored in the `RSA` object it was
/// allocated for, because that is the only place its type is recovered from.
#[allow(dead_code)] // called by the object's constructor, which the object layer lands
pub(crate) unsafe fn ossl_rsa_alloc_blinding() -> *mut c_void {
    // `ossl_sa_new` is a safe function in this crate, so this call is unguarded; its result
    // is an empty array that `ossl_sa_*` accepts until the object is freed.
    ossl_sa_new().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair round-trips through the object's member: an array allocated by
    /// [`ossl_rsa_alloc_blinding`] is what [`ossl_rsa_free_blinding`] releases, and the
    /// release leaves the member pointing where it did — the behaviour the module note
    /// records, pinned so that a later "tidying up" of the NULL write fails here.
    ///
    /// The object is `mp.rs`'s [`super::super::mp::zeroed_rsa`], the fixture whose fields
    /// are written out rather than zeroed for the reason recorded there.
    #[test]
    fn the_blinding_array_round_trips_through_the_object() {
        let mut rsa = super::super::mp::zeroed_rsa();
        // SAFETY: the array is created here and released here; the object is this test's.
        unsafe {
            let sa = ossl_rsa_alloc_blinding();
            assert!(!sa.is_null());
            rsa.blindings_sa = sa;

            let before = sa;
            ossl_rsa_free_blinding(&mut rsa);
            assert_eq!(
                rsa.blindings_sa, before,
                "the authority does not clear the member"
            );
        }
    }

    /// A NULL member is not a fault: `ossl_sa_doall_arg` and `ossl_sa_free` both accept
    /// NULL, so an object that was never blinded is released correctly.
    #[test]
    fn an_unblinded_object_is_released_without_faulting() {
        let mut rsa = super::super::mp::zeroed_rsa();
        assert!(rsa.blindings_sa.is_null());
        // SAFETY: `rsa` is live and its member is NULL, which both entry points accept.
        unsafe { ossl_rsa_free_blinding(&mut rsa) };
    }
}
