//! `crypto/ec/ecdsa_sign.c` and `crypto/ec/ecdsa_vrf.c` — the `ECDSA_*` public surface, and the
//! `ECDSA_SIG` object's four accessors, Phase 8.7.
//!
//! The two unit files are fifty-seven and forty-nine lines and define **seven exports and no
//! internals**: `ECDSA_do_sign`/`_do_sign_ex`, `ECDSA_sign`/`_sign_ex` and `ECDSA_sign_setup` from
//! `ecdsa_sign.c`, and `ECDSA_do_verify`/`ECDSA_verify` from `ecdsa_vrf.c`. Each is a two-branch
//! dispatch over an `EC_KEY_METHOD` column — a table with the column runs it, one without raises
//! `EC_R_OPERATION_NOT_SUPPORTED` — so their whole content is the `meth` indirection the plan's
//! §2d lists beside [`crate::ec::kmeth`]'s default table.
//!
//! ## The four `ECDSA_SIG_*` accessors are `ec_asn1.c`'s, and land here deliberately
//!
//! `ECDSA_SIG_new`/`_free`/`_get0`/`_set0` are `crypto/ec/ec_asn1.c:1187-1297`, not
//! `ecdsa_sign.c`'s — they appear in this module because the `ECDSA_SIG` **object** is what every
//! function above returns, [`crate::ec::ecdsa_ossl`]'s sign path allocates it, and the object has no
//! other home in the crate: [`crate::ec::mod`] carries the `EcdsaSig` shape, and these four are its
//! constructor, destructor and accessors. The **codec** that also lives in `ec_asn1.c` —
//! `i2d_ECDSA_SIG`, `d2i_ECDSA_SIG` and `ECDSA_size` — is 8.8's and is deliberately **not** here;
//! [`crate::ec::ecdsa_ossl`] names the three as foreign declarations with their coordinates, which
//! is the same treatment every other absent callee of this tranche gets. The allocator file string
//! below is therefore `ec_asn1.c`'s, because that is where the one `OPENSSL_zalloc`/`OPENSSL_free`
//! pair runs.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint};
use core::ptr;

use crate::bn::bignum::{BN_clear_free, BigNum};
use crate::ec::{EcKey, EcdsaSig};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The translation-unit coordinate the `OPENSSL_zalloc`/`OPENSSL_free` pair in the four
/// `ECDSA_SIG_*` accessors is attributed to, as the allocator reports it.
const FILE: *const c_char = c"crypto/ec/ec_asn1.c".as_ptr();

/// `ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey)` —
/// `crypto/ec/ecdsa_sign.c:20-23`.
///
/// The two NULLs are the authority's: no pre-computed `(kinv, r)` values, so the table's `sign_sig`
/// generates them.
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_do_sign(
    dgst: *const c_uchar,
    dlen: c_int,
    eckey: *mut EcKey,
) -> *mut EcdsaSig {
    // SAFETY: this function's own contract.
    unsafe { ECDSA_do_sign_ex(dgst, dlen, ptr::null(), ptr::null(), eckey) }
}

/// `ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dlen, const BIGNUM *kinv,
/// const BIGNUM *rp, EC_KEY *eckey)` — `crypto/ec/ecdsa_sign.c:25-33`.
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `kinv`/`rp` are NULL or live; `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_do_sign_ex(
    dgst: *const c_uchar,
    dlen: c_int,
    kinv: *const BigNum,
    rp: *const BigNum,
    eckey: *mut EcKey,
) -> *mut EcdsaSig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*eckey).meth.as_ref().and_then(|m| m.sign_sig) {
            // SAFETY: the table's own callback, handed the caller's five arguments unchanged.
            Some(sign_sig) => sign_sig(dgst, dlen, kinv, rp, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_sign.c:31`,
                // EC_R_OPERATION_NOT_SUPPORTED).
                raise_site(&err_sites::ECDSA_SIGN_31);
                ptr::null_mut()
            }
        }
    }
}

/// `int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
/// unsigned int *siglen, EC_KEY *eckey)` — `crypto/ec/ecdsa_sign.c:35-38`.
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `sig` is NULL or writable; `siglen` is writable; `eckey` is a
/// live key.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_sign(
    type_: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: this function's own contract; the two NULLs are the authority's.
    unsafe {
        ECDSA_sign_ex(
            type_,
            dgst,
            dlen,
            sig,
            siglen,
            ptr::null(),
            ptr::null(),
            eckey,
        )
    }
}

/// `int ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
/// unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)` —
/// `crypto/ec/ecdsa_sign.c:40-48`.
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `sig` is NULL or writable; `siglen` is writable; `kinv`/`r` are
/// NULL or live; `eckey` is a live key.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // `ec.h`'s own prototype, `include/openssl/ec.h:1442`: the trailing `kinv`/`r` pair is the caller's precomputed nonce, and `ABI-PROTOTYPE` resolves the export by the exact parameter list, so a reader comparing this signature with the header needs both
pub unsafe extern "C" fn ECDSA_sign_ex(
    type_: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    kinv: *const BigNum,
    r: *const BigNum,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*eckey).meth.as_ref().and_then(|m| m.sign) {
            // SAFETY: the table's own callback, handed the caller's eight arguments unchanged.
            Some(sign) => sign(type_, dgst, dlen, sig, siglen, kinv, r, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_sign.c:46`,
                // EC_R_OPERATION_NOT_SUPPORTED).
                raise_site(&err_sites::ECDSA_SIGN_46);
                0
            }
        }
    }
}

/// `int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `crypto/ec/ecdsa_sign.c:50-57`.
///
/// This is the **`EC_KEY_METHOD`'s** `sign_setup` column, not the `EC_METHOD`'s
/// [`crate::ec::ecdsa_ossl::ossl_ecdsa_sign_setup`]; the default key method names the latter
/// through this column.
///
/// # Safety
///
/// `eckey` is a live key; `ctx_in` is NULL or a live `BN_CTX`; `kinvp`/`rp` are writable.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_sign_setup(
    eckey: *mut EcKey,
    ctx_in: *mut crate::bn::ctx::BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*eckey).meth.as_ref().and_then(|m| m.sign_setup) {
            // SAFETY: the table's own callback, handed the caller's four arguments unchanged.
            Some(sign_setup) => sign_setup(eckey, ctx_in, kinvp, rp),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_sign.c:55`,
                // EC_R_OPERATION_NOT_SUPPORTED).
                raise_site(&err_sites::ECDSA_SIGN_55);
                0
            }
        }
    }
}

/// `int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
/// EC_KEY *eckey)` — `crypto/ec/ecdsa_vrf.c:26-33`.
///
/// Answers **-1** for a table with no `verify_sig`, which is the authority's own distinction
/// between "the signature is wrong" (0) and "this key cannot verify" (-1).
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `sig` is a live signature; `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_do_verify(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *const EcdsaSig,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*eckey).meth.as_ref().and_then(|m| m.verify_sig) {
            // SAFETY: the table's own callback, handed the caller's four arguments unchanged.
            Some(verify_sig) => verify_sig(dgst, dgst_len, sig, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_vrf.c:31`,
                // EC_R_OPERATION_NOT_SUPPORTED).
                raise_site(&err_sites::ECDSA_VRF_31);
                -1
            }
        }
    }
}

/// `int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf,
/// int sig_len, EC_KEY *eckey)` — `crypto/ec/ecdsa_vrf.c:41-49`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `sigbuf` is readable for `sig_len`; `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_verify(
    type_: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    sig_len: c_int,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*eckey).meth.as_ref().and_then(|m| m.verify) {
            // SAFETY: the table's own callback, handed the caller's six arguments unchanged.
            Some(verify) => verify(type_, dgst, dgst_len, sigbuf, sig_len, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_vrf.c:47`,
                // EC_R_OPERATION_NOT_SUPPORTED).
                raise_site(&err_sites::ECDSA_VRF_47);
                -1
            }
        }
    }
}

/// `ECDSA_SIG *ECDSA_SIG_new(void)` — `crypto/ec/ec_asn1.c:1187-1191`.
///
/// A zero-allocated object: the two `BIGNUM` pointers are NULL until
/// [`crate::ec::ecdsa_ossl::ossl_ecdsa_simple_sign_sig`] sets them.
#[no_mangle]
pub extern "C" fn ECDSA_SIG_new() -> *mut EcdsaSig {
    // `OPENSSL_zalloc(sizeof(*sig))`, line 1189.
    CRYPTO_zalloc(core::mem::size_of::<EcdsaSig>(), FILE, 1189).cast::<EcdsaSig>()
}

/// `void ECDSA_SIG_free(ECDSA_SIG *sig)` — `crypto/ec/ec_asn1.c:1194-1200`.
///
/// NULL is a no-op; the two scalars are **cleared** before release, since either can be a signature
/// component.
///
/// # Safety
///
/// `sig` is NULL or a live object, and must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_free(sig: *mut EcdsaSig) {
    if sig.is_null() {
        return;
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        // `OPENSSL_free(sig)`, line 1198.
        CRYPTO_free(sig.cast(), FILE, 1198);
    }
}

/// `void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)` —
/// `crypto/ec/ec_asn1.c:1272-1278`.
///
/// Each output pointer is written only when it is non-NULL, so a caller may ask for just one
/// component.
///
/// # Safety
///
/// `sig` is a live object; `pr`/`ps` are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_get0(
    sig: *const EcdsaSig,
    pr: *mut *const BigNum,
    ps: *mut *const BigNum,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pr.is_null() {
            *pr = (*sig).r;
        }
        if !ps.is_null() {
            *ps = (*sig).s;
        }
    }
}

/// `int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)` — `crypto/ec/ec_asn1.c:1290-1300`.
///
/// Both scalars must be non-NULL, and the object **takes ownership** of them: the old pair is
/// cleared and freed first, and a failure leaves the object unchanged.
///
/// # Safety
///
/// `sig` is a live object; `r` and `s` are live `BIGNUM`s the caller gives up on success.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_set0(
    sig: *mut EcdsaSig,
    r: *mut BigNum,
    s: *mut BigNum,
) -> c_int {
    if r.is_null() || s.is_null() {
        return 0;
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*sig).r);
        BN_clear_free((*sig).s);
        (*sig).r = r;
        (*sig).s = s;
    }
    1
}
