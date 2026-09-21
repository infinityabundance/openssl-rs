//! `crypto/ec/ecdh_ossl.c` — the `ossl_ecdh_*` shared-secret entry points, Phase 8.7.
//!
//! One hundred and forty-seven lines: two internals, `ossl_ecdh_compute_key` and
//! `ossl_ecdh_simple_compute_key`. The first is the `ecdh_compute_key` column of the five landed
//! `EC_METHOD` tables and dispatches to the table's own callback; the second is the **group
//! method's** `ecdh_compute_key` that every one of those tables names, so it is the implementation
//! the four prime tables and the binary table actually run.
//!
//! ## The two steps, and the cofactor arm
//!
//! The body is IEEE 1363's ECKAS-DH1/ECSVDP-DH, which is SP800-56A r3's §5.7.1.2 cofactor CDH:
//! step (1) computes `tmp = cofactor * owners_private_key * peer_public_key`, multiplying the
//! private scalar by the cofactor first when [`crate::ec::key::EC_FLAG_COFACTOR_ECDH`] is set, and
//! step (3b) converts `tmp.x` to a fixed-width byte string with the field-element-to-byte-string
//! routine of Appendix C.2. The "point at infinity" case is not a branch: it is
//! `EC_POINT_get_affine_coordinates` answering 0, exactly as the authority's own comment says.
//!
//! The secret is written into a fresh `OPENSSL_malloc` buffer and handed to the caller, who owns
//! it. `BN_clear(x)` is the authority's step (4) and clears only the context temporary; the caller's
//! buffer is deliberately not cleared here.
//!
//! ## `BN_num_bytes` is the header's macro, not a symbol
//!
//! `bn.h`'s `#define BN_num_bytes(a) ((BN_num_bits(a) + 7) / 8)` is expanded at its one site
//! (`:119`) rather than written as a crate identifier, for the reason
//! [`crate::ec::curve`]'s module documentation gives: the gate counts a crate identifier naming an
//! authority macro as a language-surface entry, and expanding it keeps the count honest.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::arith::BN_mul;
use crate::bn::bignum::{BN_bn2bin, BN_clear, BN_num_bits, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::ec::key::{
    EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get_flags, EC_FLAG_COFACTOR_ECDH,
};
use crate::ec::lib::{
    EC_GROUP_get_cofactor, EC_GROUP_get_degree, EC_POINT_clear_free,
    EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new,
};
use crate::ec::{EcKey, EcPoint};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The translation-unit coordinate the one `OPENSSL_malloc`/`OPENSSL_free` pair in this unit is
/// attributed to, as the allocator reports it.
const FILE: *const c_char = c"crypto/ec/ecdh_ossl.c".as_ptr();

/// `int ossl_ecdh_compute_key(unsigned char **psec, size_t *pseclen, const EC_POINT *pub_key,
/// const EC_KEY *ecdh)` — `crypto/ec/ecdh_ossl.c:28-37`. Internal.
///
/// The `ecdh_compute_key` column of every landed `EC_METHOD`: a table without one raises
/// `EC_R_CURVE_DOES_NOT_SUPPORT_ECDH` rather than answering, and otherwise the table's own callback
/// decides the answer with its arguments passed through unchanged.
///
/// # Safety
///
/// `psec` and `pseclen` are writable; `pub_key` is a live point compatible with `ecdh`; `ecdh` is a
/// live key with a group behind a table that has an `ecdh_compute_key`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdh_compute_key(
    psec: *mut *mut core::ffi::c_uchar,
    pseclen: *mut usize,
    pub_key: *const EcPoint,
    ecdh: *const EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*(*ecdh).group)
            .meth
            .as_ref()
            .and_then(|m| m.ecdh_compute_key)
        {
            // SAFETY: the table's own callback, handed the caller's four arguments unchanged.
            Some(compute_key) => compute_key(psec, pseclen, pub_key, ecdh),
            None => {
                // SAFETY: a compile-time-constant site (`ecdh_ossl.c:32`,
                // EC_R_CURVE_DOES_NOT_SUPPORT_ECDH).
                raise_site(&err_sites::ECDH_OSSL_32);
                0
            }
        }
    }
}

/// `int ossl_ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
/// const EC_POINT *pub_key, const EC_KEY *ecdh)` — `crypto/ec/ecdh_ossl.c:49-147`. Internal.
///
/// IEEE 1363's ECSVDP-DH, which is SP800-56A r3's §5.7.1.2. The private scalar is the owner's; the
/// public point is the peer's. With `EC_FLAG_COFACTOR_ECDH` the scalar becomes `cofactor *
/// priv_key`, computed in the context temporary `x`, before the multiplication.
///
/// The output is `(EC_GROUP_get_degree(group) + 7) / 8` bytes wide — the field's element width —
/// left-zero-padded when `x` is narrower, which is what the `memset` before `BN_bn2bin` does. A
/// wider `x` raises `ERR_R_INTERNAL_ERROR` and the buffer is never allocated.
///
/// # Safety
///
/// `pout` and `poutlen` are writable; `pub_key` is a live point; `ecdh` is a live key with a group
/// and a private scalar.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdh_simple_compute_key(
    pout: *mut *mut core::ffi::c_uchar,
    poutlen: *mut usize,
    pub_key: *const EcPoint,
    ecdh: *const EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut tmp: *mut EcPoint = ptr::null_mut();
        let mut ret: c_int = 0;
        let mut buf: *mut core::ffi::c_uchar = ptr::null_mut();

        let ctx = BN_CTX_new_ex((*ecdh).libctx);
        if ctx.is_null() {
            return ret;
        }
        BN_CTX_start(ctx);
        let x: *mut BigNum = BN_CTX_get(ctx);
        if x.is_null() {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:66`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDH_OSSL_66);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        let mut priv_key = EC_KEY_get0_private_key(ecdh);
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:72`, EC_R_MISSING_PRIVATE_KEY).
            raise_site(&err_sites::ECDH_OSSL_72);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        let group = EC_KEY_get0_group(ecdh);

        /*
         * Step(1) - Compute the point tmp = cofactor * owners_private_key
         *                                   * peer_public_key.
         */
        if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) != 0 {
            if EC_GROUP_get_cofactor(group, x, ptr::null_mut()) == 0 {
                // SAFETY: a compile-time-constant site (`ecdh_ossl.c:84`, ERR_R_EC_LIB).
                raise_site(&err_sites::ECDH_OSSL_84);
                return err_simple(buf, tmp, x, ctx, ret);
            }
            if BN_mul(x, x, priv_key, ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ecdh_ossl.c:88`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDH_OSSL_88);
                return err_simple(buf, tmp, x, ctx, ret);
            }
            priv_key = x;
        }

        tmp = EC_POINT_new(group);
        if tmp.is_null() {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:95`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDH_OSSL_95);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        if EC_POINT_mul(group, tmp, ptr::null(), pub_key, priv_key, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:100`,
            // EC_R_POINT_ARITHMETIC_FAILURE).
            raise_site(&err_sites::ECDH_OSSL_100);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        /*
         * Step(2) : If point tmp is at infinity then clear intermediate values and exit. Note:
         * getting affine coordinates returns 0 if point is at infinity.
         * Step(3a) : Get x-coordinate of point x = tmp.x
         */
        if EC_POINT_get_affine_coordinates(group, tmp, x, ptr::null_mut(), ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:110`,
            // EC_R_POINT_ARITHMETIC_FAILURE).
            raise_site(&err_sites::ECDH_OSSL_110);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        /*
         * Step(3b) : convert x to a byte string, using the field-element-to-byte string conversion
         * routine defined in Appendix C.2
         */
        let buflen = (EC_GROUP_get_degree(group) + 7) / 8;
        // `BN_num_bytes(x)` — `bn.h:398`'s macro, expanded rather than named.
        let len = ((BN_num_bits(x) + 7) / 8) as usize;
        if len > buflen as usize {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:121`, ERR_R_INTERNAL_ERROR).
            raise_site(&err_sites::ECDH_OSSL_121);
            return err_simple(buf, tmp, x, ctx, ret);
        }
        buf = CRYPTO_malloc(buflen as usize, FILE, 124).cast::<core::ffi::c_uchar>();
        if buf.is_null() {
            return err_simple(buf, tmp, x, ctx, ret);
        }

        ptr::write_bytes(buf, 0, buflen as usize - len);
        if len != BN_bn2bin(x, buf.add(buflen as usize - len)) as usize {
            // SAFETY: a compile-time-constant site (`ecdh_ossl.c:129`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDH_OSSL_129);
            return err_simple(buf, tmp, x, ctx, ret);
        }

        *pout = buf;
        *poutlen = buflen as usize;
        // The buffer is handed to the caller; the `err:` label below must not release it.
        buf = ptr::null_mut();

        ret = 1;
        err_simple(buf, tmp, x, ctx, ret)
    }
}

/// The authority's `err:` label of [`ossl_ecdh_simple_compute_key`] (`ecdh_ossl.c:139-145`).
///
/// Step (4): the context temporary is cleared, the point cleared and freed, the context released,
/// and the output buffer freed **only when it has not been handed over** — which is why the caller
/// nulls `buf` on the success path.
///
/// # Safety
///
/// Each pointer is NULL or is the object [`ossl_ecdh_simple_compute_key`] holds.
unsafe fn err_simple(
    buf: *mut core::ffi::c_uchar,
    tmp: *mut EcPoint,
    x: *mut BigNum,
    ctx: *mut BnCtx,
    ret: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear(x);
        EC_POINT_clear_free(tmp);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        // `OPENSSL_free(buf)`, line 145.
        CRYPTO_free(buf.cast::<c_void>(), FILE, 145);
        ret
    }
}
