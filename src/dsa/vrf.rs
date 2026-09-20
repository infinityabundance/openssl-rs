//! Phase 8 — `crypto/dsa/dsa_vrf.c`: `DSA_do_verify`.
//!
//! One function, four lines, and it is a file of its own in the authority because the verification
//! half of the method table is a translation unit: `dsa_vrf.c` is `$COMMON` in
//! `crypto/dsa/build.info`, so the FIPS module gets it too, and its whole content is the dispatch
//! to `dsa->meth->dsa_do_verify`.
//!
//! The table's member is [`crate::dsa::ossl`]'s `dsa_do_verify`, which is where the arithmetic,
//! the three -1 refusals and the two 0 refusals live. This file answers **-1** for a table that
//! leaves the member NULL — the authority calls through the pointer unconditionally, and -1 is the
//! answer its own member uses for "not verified, and not because the signature was wrong".
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

use super::{Dsa, DsaSig};

/// `int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa)` —
/// `dsa_vrf.c:14-18`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len` bytes; `sig` is a live signature object; `dsa` is a live
/// object whose parameters and public key the caller set.
#[no_mangle]
pub unsafe extern "C" fn DSA_do_verify(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *mut DsaSig,
    dsa: *mut Dsa,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    // SAFETY: `meth` is the object's own table; the member is nullable and an absent one answers
    // -1, which is the answer this entry point's own member gives for a refusal that is not a
    // wrong signature.
    match unsafe { (*meth).dsa_do_verify } {
        // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
        Some(f) => unsafe { f(dgst, dgst_len, sig, dsa) },
        None => -1,
    }
}
