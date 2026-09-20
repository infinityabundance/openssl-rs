//! Phase 8 — `crypto/dsa/dsa_sign.c`: the `DSA_SIG` object, `DSA_do_sign` and `DSA_sign_setup`.
//!
//! Four definitions in authority order: [`DSA_do_sign`] (`dsa_sign.c:22-25`), [`DSA_sign_setup`]
//! (`:27-32`), [`DSA_SIG_new`] (`:34-39`), [`DSA_SIG_free`] (`:41-48`), and the two accessors
//! [`DSA_SIG_get0`] (`:143-150`) and [`DSA_SIG_set0`] (`:152-162`). The file's other definitions —
//! `d2i_DSA_SIG`, `i2d_DSA_SIG`, `DSA_size`, `ossl_dsa_sign_int`, `DSA_sign` and `DSA_verify` —
//! are **withheld**, and the paragraph below is the coordinate of the blocker.
//!
//! ## Why the file is transcribed in part, and what the missing half needs
//!
//! `DSA_size`, `DSA_sign` and `DSA_verify` are all thin, and all three reach
//! `i2d_DSA_SIG`/`d2i_DSA_SIG` — the DER `DSA-Sig-Value` codec. Those two are defined in **this**
//! file (it is one of `crypto/dsa/build.info`'s `$COMMON` units, so it is compiled into the FIPS
//! module too and cannot call the ASN.1 machinery), and their whole body is
//! `crypto/asn1_dsa.c`'s `ossl_encode_der_dsa_sig` / `ossl_decode_der_dsa_sig` over
//! `include/internal/packet.h`'s `WPACKET`/`PACKET`. **Neither translation unit has a crate
//! module and no stratum's plan row names one**: `crypto/packet.c` is the thirty `WPACKET_*`
//! symbols and `crypto/asn1_dsa.c` the six DER helpers, and this crate has no packet writer at
//! all. Writing either from scratch is a new unit rather than a transcription of this one, so the
//! five exports that need them stay `open` and are named here rather than approximated.
//!
//! `ossl_dsa_sign_int` — the internal the five share, and the one **internal** this unit defines
//! that is withheld — is recorded in `forensics/prerequisites.json` as a deferral with that
//! blocker, which is what keeps the prerequisite gate's view of this unit whole.
//!
//! ## What the six definitions here are
//!
//! `DSA_do_sign` and `DSA_sign_setup` are pure method dispatch, and the authority's own
//! `DSA_sign_setup` sits inside `#ifndef OPENSSL_NO_DEPRECATED_3_0` — which this profile does not
//! define (D172), so it is compiled and transcribed. The four `DSA_SIG` entry points are the
//! object's whole surface: `OPENSSL_zalloc` then two `BN_clear_free`s, which is why a caller that
//! replaces a signature's halves with [`DSA_SIG_set0`] finds the old ones **cleared** rather than
//! merely dropped.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};

use crate::bn::bignum::{BN_clear_free, BigNum};
use crate::bn::ctx::BnCtx;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::{Dsa, DsaSig};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dsa/dsa_sign.c` is a source-tree file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix. It reaches an application through
/// `CRYPTO_set_mem_functions`, so it is part of the contract and `RT-DSA` compares it.
const FILE_DSA_SIGN: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_sign.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)` — `dsa_sign.c:22-25`.
///
/// The method dispatch: `dsa->meth->dsa_do_sign(dgst, dlen, dsa)`. The authority's table supplies
/// the real entry point, so this is the way an application reaches
/// [`crate::dsa::ossl::ossl_dsa_do_sign_int`]; a table that leaves the member NULL answers a NULL
/// signature here, exactly as `DH_generate_key` answers 0 for its own nullable member.
///
/// # Safety
///
/// `dgst` is readable for `dlen` bytes; `dsa` is a live object whose parameters and private key the
/// caller set.
#[no_mangle]
pub unsafe extern "C" fn DSA_do_sign(
    dgst: *const c_uchar,
    dlen: c_int,
    dsa: *mut Dsa,
) -> *mut DsaSig {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    // SAFETY: `meth` is the object's own table; the header marks `dsa_do_sign` nullable and the
    // authority calls it without a test. An absent member answers NULL, the failure answer.
    match unsafe { (*meth).dsa_do_sign } {
        // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
        Some(f) => unsafe { f(dgst, dlen, dsa) },
        None => core::ptr::null_mut(),
    }
}

/// `int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `dsa_sign.c:27-32`. Inside `#ifndef OPENSSL_NO_DEPRECATED_3_0`, which this profile does not
/// define.
///
/// The method dispatch to `dsa->meth->dsa_sign_setup`. Note what the caller gets back: `r` through
/// `rp` and the **inverse of `k`** through `kinvp`, which is the whole reason the signature's two
/// halves are computed in two calls.
///
/// # Safety
///
/// `dsa` is a live object with a private key; `ctx_in` is NULL or live; `kinvp` and `rp` are live
/// out-parameters.
#[no_mangle]
pub unsafe extern "C" fn DSA_sign_setup(
    dsa: *mut Dsa,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    // SAFETY: `meth` is the object's own table; the member is nullable and an absent one answers 0.
    match unsafe { (*meth).dsa_sign_setup } {
        // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
        Some(f) => unsafe { f(dsa, ctx_in, kinvp, rp) },
        None => 0,
    }
}

/// `DSA_SIG *DSA_SIG_new(void)` — `dsa_sign.c:34-39`.
///
/// A zeroed 16-byte object: **both halves start NULL**, which is why [`DSA_SIG_set0`] is the only
/// way to fill one and why `DSA_SIG_free` may release either.
///
/// # Safety
///
/// Takes no pointer.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_new() -> *mut DsaSig {
    // SAFETY: `CRYPTO_zalloc` reads no caller pointer and is a safe function in this crate (D113).
    CRYPTO_zalloc(core::mem::size_of::<DsaSig>(), FILE_DSA_SIGN, LINE).cast::<DsaSig>()
}

/// `void DSA_SIG_free(DSA_SIG *sig)` — `dsa_sign.c:41-48`.
///
/// NULL is a no-op. **Both halves are *cleared* rather than freed** — `BN_clear_free` — because a
/// signature's `k`-derived values are secret-adjacent material; the release is in the authority's
/// order, `r` then `s` then the object.
///
/// # Safety
///
/// `sig` is NULL or a live signature.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_free(sig: *mut DsaSig) {
    if sig.is_null() {
        return;
    }
    // SAFETY: `sig` is live per the contract and each half is NULL or the object's own.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        CRYPTO_free(sig.cast(), FILE_DSA_SIGN, LINE);
    }
}

/// `void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)` —
/// `dsa_sign.c:143-150`.
///
/// # Safety
///
/// `sig` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_get0(
    sig: *const DsaSig,
    pr: *mut *const BigNum,
    ps: *mut *const BigNum,
) {
    // SAFETY: `sig` is live and each out-parameter is NULL or writable per the contract.
    unsafe {
        if !pr.is_null() {
            *pr = (*sig).r;
        }
        if !ps.is_null() {
            *ps = (*sig).s;
        }
    }
}

/// `int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)` — `dsa_sign.c:152-162`.
///
/// **A NULL in either half refuses before anything is released**, so a caller that passes one
/// value and a NULL keeps the signature it had. On success both old halves are cleared and the new
/// pointers stored, and the answer is 1.
///
/// # Safety
///
/// `sig` is live; each of `r` and `s` is NULL or a live `BIGNUM` whose ownership the caller
/// transfers on the success path.
#[no_mangle]
pub unsafe extern "C" fn DSA_SIG_set0(sig: *mut DsaSig, r: *mut BigNum, s: *mut BigNum) -> c_int {
    if r.is_null() || s.is_null() {
        return 0;
    }
    // SAFETY: `sig` is live and each old half is NULL or the object's own.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        (*sig).r = r;
        (*sig).s = s;
    }
    1
}
