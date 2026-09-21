//! `crypto/ec/ecdsa_ossl.c` — the `ossl_ecdsa_*` signature entry points, Phase 8.7.
//!
//! Five hundred and forty-seven lines: **nine internals** plus the unit's static `ecdsa_sign_setup`.
//! Three of the nine are the `ecdsa_sign_setup`/`ecdsa_sign_sig`/`ecdsa_verify_sig` columns of every
//! landed `EC_METHOD`, and each dispatches to the table's own callback; the three `_simple_` ones
//! are the implementations those columns name; the remaining three — `ossl_ecdsa_sign`,
//! `ossl_ecdsa_deterministic_sign` and `ossl_ecdsa_verify` — are the `EC_KEY_METHOD` row's three
//! entry points, which take an `int type` the tables' columns do not have.
//!
//! ## The two things the crate reaches for and does not build, named with their coordinates
//!
//! * **The `top`-fixup BN family.** `ossl_ecdsa_simple_sign_sig` computes its signature through
//!   `bn_to_mont_fixed_top`, `bn_mul_mont_fixed_top` and `bn_mod_add_fixed_top`
//!   (`crypto/bn/bn_mont.c`, `crypto/bn/bn_mod.c`), which this crate models through the public
//!   wrappers the authority itself puts around them — `BN_to_montgomery`, `BN_mod_mul_montgomery`
//!   and `BN_mod_add`. The substitution is the one `src/rsa/ossl.rs:1652-1660` already records for
//!   `rsa_ossl_mod_exp`, and the reason is the same: the fixed-top discipline is a *representation*
//!   the crate's normalised `BIGNUM` does not have, not a different value.
//! * **The DER codec.** `ossl_ecdsa_sign` and `ossl_ecdsa_verify` reach `ECDSA_size`,
//!   `i2d_ECDSA_SIG` and `d2i_ECDSA_SIG`, all three of which are `crypto/ec/ec_asn1.c`'s — 8.8's
//!   stratum, and outside the plan's closure. They are **imported from their eventual crate path**
//!   ([`crate::ec::asn1`], following `ec_curve.c` -> [`crate::ec::curve`]) rather than stubbed, so
//!   the reference is a named one and its absence is an unresolved import rather than a link-time
//!   surprise. The `ECDSA_SIG` object's own four accessors (`ECDSA_SIG_new`/`_free`/`_set0`/`_get0`)
//!   are landed in [`crate::ec::ecdsa`] beside the sign/verify wrappers, because the object is what
//!   those wrappers return and nothing here builds a second definition of it.
//!
//! ## The deterministic-nonce arm is D333's recorded reduction
//!
//! `ecdsa_sign_setup`'s `nonce_type == 1` arm calls `ossl_gen_deterministic_nonce_rfc6979`
//! (`crypto/deterministic_nonce.c:181`), whose first act is a fetch of the `HMAC-DRBG-KDF` row this
//! crate's default provider does not publish. The arm therefore answers 0 through the authority's
//! own `EC_R_RANDOM_NUMBER_GENERATION_FAILED` refusal, exactly as `src/dsa/ossl.rs` does for
//! `dsa_sign_setup`, and the coordinate is named at the site rather than the arm being dropped.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::bn::arith::{BN_mod_add, BN_mod_mul, BN_nnmod, BN_rshift, BN_ucmp};
use crate::bn::bignum::{
    ossl_bn_is_word_fixed_top, BN_bin2bn, BN_clear_free, BN_copy, BN_is_negative, BN_is_zero,
    BN_new, BN_num_bits, BN_secure_new, BN_set_bit, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::mont::{BN_mod_mul_montgomery, BN_to_montgomery};
use crate::bn::rand::{ossl_bn_gen_dsa_nonce_fixed_top, ossl_bn_priv_rand_range_fixed_top};
use crate::ec::asn1::{d2i_ECDSA_SIG, i2d_ECDSA_SIG, ECDSA_size};
use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_SIG_new, ECDSA_do_sign_ex, ECDSA_do_verify};
use crate::ec::key::{
    EC_KEY_can_sign, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
};
use crate::ec::lib::{
    ossl_ec_group_do_inverse_ord, EC_GROUP_get0_order, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new,
};
use crate::ec::{EcKey, EcPoint, EcdsaSig};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;

/// The translation-unit coordinate the one `OPENSSL_free` in this unit is attributed to, as the
/// allocator reports it: `OPENSSL_free(der)` is a macro expanded at `ecdsa_ossl.c:437`, so
/// `OPENSSL_FILE` there is this unit's own path.
const FILE: *const c_char = c"crypto/ec/ecdsa_ossl.c".as_ptr();

/// `MIN_ECDSA_SIGN_ORDERBITS` — `crypto/ec/ecdsa_ossl.c:24`. The floor below which `ecdsa_sign_setup`
/// refuses rather than risking the pre-allocation loop never terminating.
const MIN_ECDSA_SIGN_ORDERBITS: c_int = 64;
/// `MAX_ECDSA_SIGN_RETRIES` — `crypto/ec/ecdsa_ossl.c:31`. "Multiple retries would indicate that
/// something is wrong with the group parameters (which would normally only happen with a bad custom
/// group)."
const MAX_ECDSA_SIGN_RETRIES: c_int = 8;

extern "C" {
    /// `int memcmp(const void *, const void *, size_t)`.
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
}

/// `int ossl_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `crypto/ec/ecdsa_ossl.c:39-48`. Internal.
///
/// The `ecdsa_sign_setup` column of every landed `EC_METHOD`: a table without one raises
/// `EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA` rather than answering.
///
/// # Safety
///
/// `eckey` is a live key with a group; `kinvp` and `rp` are writable; `ctx_in` is NULL or a live
/// `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_sign_setup(
    eckey: *mut EcKey,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*(*eckey).group)
            .meth
            .as_ref()
            .and_then(|m| m.ecdsa_sign_setup)
        {
            // SAFETY: the table's own callback, handed the caller's four arguments unchanged.
            Some(setup) => setup(eckey, ctx_in, kinvp, rp),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:43`,
                // EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA).
                raise_site(&err_sites::ECDSA_OSSL_43);
                0
            }
        }
    }
}

/// `ECDSA_SIG *ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len, const BIGNUM *in_kinv,
/// const BIGNUM *in_r, EC_KEY *eckey)` — `crypto/ec/ecdsa_ossl.c:50-61`. Internal.
///
/// The `ecdsa_sign_sig` column of every landed `EC_METHOD`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `in_kinv`/`in_r` are NULL or live; `eckey` is a live key with
/// a group behind a table that has an `ecdsa_sign_sig`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_sign_sig(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const BigNum,
    in_r: *const BigNum,
    eckey: *mut EcKey,
) -> *mut EcdsaSig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*(*eckey).group)
            .meth
            .as_ref()
            .and_then(|m| m.ecdsa_sign_sig)
        {
            // SAFETY: the table's own callback, handed the caller's five arguments unchanged.
            Some(sign_sig) => sign_sig(dgst, dgst_len, in_kinv, in_r, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:55`,
                // EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA).
                raise_site(&err_sites::ECDSA_OSSL_55);
                ptr::null_mut()
            }
        }
    }
}

/// `int ossl_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
/// EC_KEY *eckey)` — `crypto/ec/ecdsa_ossl.c:63-72`. Internal.
///
/// The `ecdsa_verify_sig` column of every landed `EC_METHOD`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `sig` is a live signature; `eckey` is a live key with a group
/// behind a table that has an `ecdsa_verify_sig`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_verify_sig(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *const EcdsaSig,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*(*eckey).group)
            .meth
            .as_ref()
            .and_then(|m| m.ecdsa_verify_sig)
        {
            // SAFETY: the table's own callback, handed the caller's four arguments unchanged.
            Some(verify_sig) => verify_sig(dgst, dgst_len, sig, eckey),
            None => {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:67`,
                // EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA).
                raise_site(&err_sites::ECDSA_OSSL_67);
                0
            }
        }
    }
}

/// `int ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
/// unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)` —
/// `crypto/ec/ecdsa_ossl.c:74-93`. Internal.
///
/// The `sign` column of `EC_KEY_METHOD`. `sig == NULL` with no `(kinv, r)` pair is the **sizing
/// call**: it writes `ECDSA_size(eckey)` into `*siglen` and answers 1 without signing anything.
///
/// `i2d_ECDSA_SIG(s, sig != NULL ? &sig : NULL)` passes the address of its own `sig` parameter
/// rather than the caller's buffer variable, which is the authority's spelling and is transcribed
/// with a local of the same name.
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `sig` is NULL or writable; `siglen` is writable; `eckey` is a live
/// key.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_sign(
    _type: c_int,
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
        if sig.is_null() && (kinv.is_null() || r.is_null()) {
            *siglen = ECDSA_size(eckey) as c_uint;
            return 1;
        }

        let s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
        if s.is_null() {
            *siglen = 0;
            return 0;
        }
        let mut sigp: *mut c_uchar = sig;
        *siglen = i2d_ECDSA_SIG(
            s,
            if !sig.is_null() {
                &raw mut sigp
            } else {
                ptr::null_mut()
            },
        ) as c_uint;
        ECDSA_SIG_free(s);
        1
    }
}

/// `int ossl_ecdsa_deterministic_sign(const unsigned char *dgst, int dlen, unsigned char *sig,
/// unsigned int *siglen, EC_KEY *eckey, unsigned int nonce_type, const char *digestname,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ec/ecdsa_ossl.c:95-130`. Internal.
///
/// The deterministic signature path the provider calls; it takes the long `ecdsa_sign_setup` with a
/// nonce type and a digest name, so its one reachable arm on this crate is D333's reduction (see
/// the module documentation).
///
/// # Safety
///
/// `dgst` is readable for `dlen`; `sig` is writable; `siglen` is writable; `eckey` is a live key;
/// `digestname`/`propq` are NULL or NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_deterministic_sign(
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    eckey: *mut EcKey,
    nonce_type: c_uint,
    digestname: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut kinv: *mut BigNum = ptr::null_mut();
        let mut r: *mut BigNum = ptr::null_mut();
        let mut ret: c_int = 0;

        if sig.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:106`,
            // ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::ECDSA_OSSL_106);
            return 0;
        }
        if digestname.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:110`, EC_R_INVALID_DIGEST).
            raise_site(&err_sites::ECDSA_OSSL_110);
            return 0;
        }

        *siglen = 0;
        if ecdsa_sign_setup(
            eckey,
            ptr::null_mut(),
            &raw mut kinv,
            &raw mut r,
            dgst,
            dlen,
            nonce_type,
            digestname,
            libctx,
            propq,
        ) == 0
        {
            return 0;
        }

        let s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
        if s.is_null() {
            BN_clear_free(kinv);
            BN_clear_free(r);
            return ret;
        }

        let mut sigp: *mut c_uchar = sig;
        *siglen = i2d_ECDSA_SIG(s, &raw mut sigp) as c_uint;
        ECDSA_SIG_free(s);
        ret = 1;
        BN_clear_free(kinv);
        BN_clear_free(r);
        ret
    }
}

/// `static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp,
/// const unsigned char *dgst, int dlen, unsigned int nonce_type, const char *digestname,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ec/ecdsa_ossl.c:132-259`. The unit's static.
///
/// The nonce's two nested loops: the inner one redraws while `k == 0` (`ossl_bn_is_word_fixed_top`),
/// the outer one recomputes while `r == 0`. Both temporaries are pre-grown to `order_bits` through
/// `BN_set_bit`, which allocates the words rather than setting a value — the authority's comment
/// says so and it is the reason `order_bits < MIN_ECDSA_SIGN_ORDERBITS` refuses before the loop.
///
/// The `dgst != NULL` arm splits on `nonce_type`: 1 is the RFC 6979 deterministic nonce (D333's
/// reduction), 0 the DSA-style random-from-digest nonce. A NULL `dgst` draws from the range.
///
/// # Safety
///
/// `eckey` is NULL or a live key; `ctx_in` is NULL or a live `BN_CTX`; `kinvp`/`rp` are writable;
/// `dgst` is NULL or readable for `dlen`; `digestname`/`propq` are NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // the authority's own static, `ecdsa_ossl.c:33`'s ten-parameter declaration, whose `digestname`/`libctx`/`propq` tail is read only in the `nonce_type == 1` arm -- and that arm is D333's recorded reduction, which is why three of the names are `_`-prefixed; the reader who lands `ossl_gen_deterministic_nonce_rfc6979` is the one who un-prefixes them
unsafe fn ecdsa_sign_setup(
    eckey: *mut EcKey,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
    dgst: *const c_uchar,
    dlen: c_int,
    nonce_type: c_uint,
    _digestname: *const c_char,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ctx: *mut BnCtx;
        let mut k: *mut BigNum;
        let mut r: *mut BigNum;
        let mut tmp_point: *mut EcPoint = ptr::null_mut();
        let mut ret: c_int = 0;

        if eckey.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:148`,
            // ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::ECDSA_OSSL_148);
            return 0;
        }
        let group = EC_KEY_get0_group(eckey);
        if group.is_null() {
            raise_site(&err_sites::ECDSA_OSSL_148);
            return 0;
        }
        let priv_key = EC_KEY_get0_private_key(eckey);
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:152`, EC_R_MISSING_PRIVATE_KEY).
            raise_site(&err_sites::ECDSA_OSSL_152);
            return 0;
        }

        if EC_KEY_can_sign(eckey) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:157`,
            // EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING).
            raise_site(&err_sites::ECDSA_OSSL_157);
            return 0;
        }

        ctx = ctx_in;
        if ctx.is_null() {
            ctx = BN_CTX_new_ex((*eckey).libctx);
            if ctx.is_null() {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:163`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDSA_OSSL_163);
                return 0;
            }
        }

        k = BN_secure_new(); /* this value is later returned in *kinvp */
        r = BN_new(); /* this value is later returned in *rp */
        let x: *mut BigNum = BN_new();
        if k.is_null() || r.is_null() || x.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:172`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_172);
            return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
        }
        tmp_point = EC_POINT_new(group);
        if tmp_point.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:176`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_176);
            return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
        }

        let order = EC_GROUP_get0_order(group);
        if order.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:181`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_181);
            return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
        }

        /* Preallocate space */
        let order_bits = BN_num_bits(order);
        /* Check the number of bits here so that an infinite loop is not possible */
        if order_bits < MIN_ECDSA_SIGN_ORDERBITS
            || BN_set_bit(k, order_bits) == 0
            || BN_set_bit(r, order_bits) == 0
            || BN_set_bit(x, order_bits) == 0
        {
            return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
        }

        loop {
            /* get random or deterministic value of k */
            loop {
                let res: c_int;

                if !dgst.is_null() {
                    if nonce_type == 1 {
                        // D333's recorded reduction: the authority calls
                        // `ossl_gen_deterministic_nonce_rfc6979` (`crypto/deterministic_nonce.c:181`)
                        // here, whose first act is a fetch of the HMAC-DRBG-KDF row this crate's
                        // default provider does not publish, so a faithful transcription answers 0
                        // through the same `EC_R_RANDOM_NUMBER_GENERATION_FAILED` refusal. See
                        // `src/dsa/ossl.rs`'s header and the module documentation above.
                        res = 0;
                    } else {
                        res = ossl_bn_gen_dsa_nonce_fixed_top(
                            k,
                            order,
                            priv_key,
                            dgst,
                            if dlen > 0 { dlen as usize } else { 0 },
                            ctx,
                        );
                    }
                } else {
                    res = ossl_bn_priv_rand_range_fixed_top(k, order, 0, ctx);
                }
                if res == 0 {
                    // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:214`,
                    // EC_R_RANDOM_NUMBER_GENERATION_FAILED).
                    raise_site(&err_sites::ECDSA_OSSL_214);
                    return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
                }
                if ossl_bn_is_word_fixed_top(k, 0) == 0 {
                    break;
                }
            }

            /* compute r the x-coordinate of generator * k */
            if EC_POINT_mul(group, tmp_point, k, ptr::null(), ptr::null(), ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:221`, ERR_R_EC_LIB).
                raise_site(&err_sites::ECDSA_OSSL_221);
                return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
            }

            if EC_POINT_get_affine_coordinates(group, tmp_point, x, ptr::null_mut(), ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:226`, ERR_R_EC_LIB).
                raise_site(&err_sites::ECDSA_OSSL_226);
                return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
            }

            if BN_nnmod(r, x, order, ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:231`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDSA_OSSL_231);
                return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
            }
            if BN_is_zero(r) == 0 {
                break;
            }
        }

        /* compute the inverse of k */
        if ossl_ec_group_do_inverse_ord(group, k, k, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:238`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_238);
            return setup_err(ctx, ctx_in, k, r, x, tmp_point, ret);
        }

        /* clear old values if necessary */
        BN_clear_free(*rp);
        BN_clear_free(*kinvp);
        /* save the pre-computed values  */
        *rp = r;
        *kinvp = k;
        // The two values are handed to the caller; the `err:` label below must not release them.
        k = ptr::null_mut();
        r = ptr::null_mut();
        ret = 1;
        setup_err(ctx, ctx_in, k, r, x, tmp_point, ret)
    }
}

/// The authority's `err:` label of [`ecdsa_sign_setup`] (`ecdsa_ossl.c:249-258`).
///
/// On failure the two nonce values are cleared and freed; the context is released **only when this
/// call made it** (`ctx != ctx_in`), which is what the `ctx_in` argument is carried for. The point
/// and `X` are always released.
///
/// # Safety
///
/// Each pointer is NULL or is an object [`ecdsa_sign_setup`] holds; `ctx_in` is the caller's.
unsafe fn setup_err(
    ctx: *mut BnCtx,
    ctx_in: *mut BnCtx,
    k: *mut BigNum,
    r: *mut BigNum,
    x: *mut BigNum,
    tmp_point: *mut EcPoint,
    ret: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ret == 0 {
            BN_clear_free(k);
            BN_clear_free(r);
        }
        if ctx != ctx_in {
            BN_CTX_free(ctx);
        }
        EC_POINT_free(tmp_point);
        BN_clear_free(x);
        ret
    }
}

/// `int ossl_ecdsa_simple_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)` —
/// `crypto/ec/ecdsa_ossl.c:261-266`. Internal. The `ecdsa_sign_setup` column every landed table
/// names: [`ecdsa_sign_setup`] with no digest and no nonce type.
///
/// # Safety
///
/// `eckey` is a live key with a private scalar; `ctx_in` is NULL or a live `BN_CTX`; `kinvp`/`rp`
/// are writable.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_simple_sign_setup(
    eckey: *mut EcKey,
    ctx_in: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe {
        ecdsa_sign_setup(
            eckey,
            ctx_in,
            kinvp,
            rp,
            ptr::null(),
            0,
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `ECDSA_SIG *ossl_ecdsa_simple_sign_sig(const unsigned char *dgst, int dgst_len,
/// const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)` — `crypto/ec/ecdsa_ossl.c:268-409`.
/// Internal. The `ecdsa_sign_sig` column every landed table names.
///
/// The digest is truncated to the order's bit length — whole bytes first, then a right shift of the
/// remaining bits — before `s` is formed. The signature arithmetic itself is the Montgomery-domain
/// chain `s = (m + r·priv)·k⁻¹ mod n`, computed through the fixed-top wrappers this crate models
/// with their public equivalents (see the module documentation). The outer `do … while (1)` retries
/// on `s == 0`, refusing after `MAX_ECDSA_SIGN_RETRIES` and refusing immediately when the caller
/// supplied its own `(kinv, r)`.
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `in_kinv`/`in_r` are NULL or live and are supplied together;
/// `eckey` is a live key with a group and a private scalar.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_simple_sign_sig(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const BigNum,
    in_r: *const BigNum,
    eckey: *mut EcKey,
) -> *mut EcdsaSig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok: c_int = 0;
        let mut retries: c_int = 0;
        let mut kinv: *mut BigNum = ptr::null_mut();
        let mut m: *mut BigNum = ptr::null_mut();
        let mut ctx: *mut BnCtx = ptr::null_mut();
        let mut dgst_len = dgst_len;

        let group = EC_KEY_get0_group(eckey);
        let priv_key = EC_KEY_get0_private_key(eckey);

        if group.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:285`,
            // ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::ECDSA_OSSL_285);
            return ptr::null_mut();
        }
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:289`, EC_R_MISSING_PRIVATE_KEY).
            raise_site(&err_sites::ECDSA_OSSL_289);
            return ptr::null_mut();
        }

        if EC_KEY_can_sign(eckey) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:294`,
            // EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING).
            raise_site(&err_sites::ECDSA_OSSL_294);
            return ptr::null_mut();
        }

        let ret = ECDSA_SIG_new();
        if ret.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:300`, ERR_R_ECDSA_LIB).
            raise_site(&err_sites::ECDSA_OSSL_300);
            return ptr::null_mut();
        }
        (*ret).r = BN_new();
        (*ret).s = BN_new();
        if (*ret).r.is_null() || (*ret).s.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:306`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_306);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }
        let s = (*ret).s;

        ctx = BN_CTX_new_ex((*eckey).libctx);
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:313`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_313);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }
        m = BN_new();
        if m.is_null() {
            raise_site(&err_sites::ECDSA_OSSL_313);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }

        let order = EC_GROUP_get0_order(group);
        if order.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:318`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_318);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }

        let i = BN_num_bits(order);
        /*
         * Need to truncate digest if it is too long: first truncate whole bytes.
         */
        if 8 * dgst_len > i {
            dgst_len = (i + 7) / 8;
        }
        if BN_bin2bn(dgst, dgst_len, m).is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:329`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_329);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }
        /* If still too long, truncate remaining bits with a shift */
        if (8 * dgst_len > i) && BN_rshift(m, m, 8 - (i & 0x7)) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:334`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_334);
            return sign_sig_err(ret, ctx, m, kinv, ok);
        }
        loop {
            let ckinv: *const BigNum;
            if in_kinv.is_null() || in_r.is_null() {
                let mut kinvp: *mut BigNum = kinv;
                let mut rp: *mut BigNum = (*ret).r;
                if ecdsa_sign_setup(
                    eckey,
                    ctx,
                    &raw mut kinvp,
                    &raw mut rp,
                    dgst,
                    dgst_len,
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                ) == 0
                {
                    // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:341`, ERR_R_ECDSA_LIB).
                    raise_site(&err_sites::ECDSA_OSSL_341);
                    return sign_sig_err(ret, ctx, m, kinv, ok);
                }
                kinv = kinvp;
                (*ret).r = rp;
                ckinv = kinv;
            } else {
                ckinv = in_kinv;
                if BN_copy((*ret).r, in_r).is_null() {
                    // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:348`, ERR_R_BN_LIB).
                    raise_site(&err_sites::ECDSA_OSSL_348);
                    return sign_sig_err(ret, ctx, m, kinv, ok);
                }
            }

            /*
             * With only one multiplicant being in Montgomery domain multiplication yields real
             * result without post-conversion. Also note that all operations but last are performed
             * with zero-padded vectors. Last operation, BN_mod_mul_montgomery below, returns
             * user-visible value with removed zero padding.
             *
             * `bn_to_mont_fixed_top`/`bn_mul_mont_fixed_top`/`bn_mod_add_fixed_top` are modelled
             * by `BN_to_montgomery`/`BN_mod_mul_montgomery`/`BN_mod_add`; see the module
             * documentation.
             */
            if BN_to_montgomery(s, (*ret).r, (*group).mont_data, ctx) == 0
                || BN_mod_mul_montgomery(s, s, priv_key, (*group).mont_data, ctx) == 0
            {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:362`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDSA_OSSL_362);
                return sign_sig_err(ret, ctx, m, kinv, ok);
            }
            if BN_mod_add(s, s, m, order, ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:366`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDSA_OSSL_366);
                return sign_sig_err(ret, ctx, m, kinv, ok);
            }
            /*
             * |s| can still be larger than modulus, because |m| can be. In such case we count on
             * Montgomery reduction to tie it up.
             */
            if BN_to_montgomery(s, s, (*group).mont_data, ctx) == 0
                || BN_mod_mul_montgomery(s, s, ckinv, (*group).mont_data, ctx) == 0
            {
                // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:375`, ERR_R_BN_LIB).
                raise_site(&err_sites::ECDSA_OSSL_375);
                return sign_sig_err(ret, ctx, m, kinv, ok);
            }

            if BN_is_zero(s) != 0 {
                /*
                 * if kinv and r have been supplied by the caller, don't generate new kinv and r
                 * values
                 */
                if !in_kinv.is_null() && !in_r.is_null() {
                    // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:385`,
                    // EC_R_NEED_NEW_SETUP_VALUES).
                    raise_site(&err_sites::ECDSA_OSSL_385);
                    return sign_sig_err(ret, ctx, m, kinv, ok);
                }
                /* Avoid infinite loops cause by invalid group parameters */
                if retries > MAX_ECDSA_SIGN_RETRIES {
                    // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:390`,
                    // EC_R_TOO_MANY_RETRIES).
                    raise_site(&err_sites::ECDSA_OSSL_390);
                    return sign_sig_err(ret, ctx, m, kinv, ok);
                }
                retries += 1;
            } else {
                /* s != 0 => we have a valid signature */
                break;
            }
        }

        ok = 1;
        sign_sig_err(ret, ctx, m, kinv, ok)
    }
}

/// The authority's `err:` label of [`ossl_ecdsa_simple_sign_sig`] (`ecdsa_ossl.c:400-408`).
///
/// A failure releases the half-built signature and answers NULL; the context and the two temporaries
/// are released either way.
///
/// # Safety
///
/// Each pointer is NULL or is an object the caller holds.
unsafe fn sign_sig_err(
    ret: *mut EcdsaSig,
    ctx: *mut BnCtx,
    m: *mut BigNum,
    kinv: *mut BigNum,
    ok: c_int,
) -> *mut EcdsaSig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = ret;
        if ok == 0 {
            ECDSA_SIG_free(ret);
            ret = ptr::null_mut();
        }
        BN_CTX_free(ctx);
        BN_clear_free(m);
        BN_clear_free(kinv);
        ret
    }
}

/// `int ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
/// const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)` — `crypto/ec/ecdsa_ossl.c:417-440`.
/// Internal. The `verify` column of `EC_KEY_METHOD`.
///
/// The DER encoding is decoded and then **re-encoded and compared byte for byte**, so a signature
/// with trailing garbage is refused before any arithmetic runs. The decode and encode are
/// `d2i_ECDSA_SIG`/`i2d_ECDSA_SIG`, which are `ec_asn1.c`'s (see the module documentation).
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `sigbuf` is readable for `sig_len`; `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_verify(
    _type: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    sig_len: c_int,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut p = sigbuf;
        let mut der: *mut c_uchar = ptr::null_mut();
        let mut ret: c_int = -1;

        let mut s = ECDSA_SIG_new();
        if s.is_null() {
            return ret;
        }
        if d2i_ECDSA_SIG(&raw mut s, &raw mut p, sig_len as c_long).is_null() {
            CRYPTO_free(der.cast::<c_void>(), FILE, 437);
            ECDSA_SIG_free(s);
            return ret;
        }
        /* Ensure signature uses DER and doesn't have trailing garbage */
        let derlen = i2d_ECDSA_SIG(s, &raw mut der);
        if derlen != sig_len || memcmp(sigbuf.cast(), der.cast(), derlen as usize) != 0 {
            CRYPTO_free(der.cast::<c_void>(), FILE, 437);
            ECDSA_SIG_free(s);
            return ret;
        }
        ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
        // `OPENSSL_free(der)`, line 437.
        CRYPTO_free(der.cast::<c_void>(), FILE, 437);
        ECDSA_SIG_free(s);
        ret
    }
}

/// `int ossl_ecdsa_simple_verify_sig(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
/// EC_KEY *eckey)` — `crypto/ec/ecdsa_ossl.c:442-547`. Internal. The `ecdsa_verify_sig` column
/// every landed table names.
///
/// The verification equation `u1·G + u2·Q` with `u1 = m·s⁻¹` and `u2 = r·s⁻¹`, and the range checks
/// on `r` and `s` before any of it — a signature whose `r` or `s` is zero, negative or not less than
/// the order raises `EC_R_BAD_SIGNATURE` and answers **0** rather than -1, which is the authority's
/// own distinction between "invalid" and "error".
///
/// # Safety
///
/// `dgst` is readable for `dgst_len`; `sig` is NULL or a live signature; `eckey` is a live key with
/// a group and a public point.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecdsa_simple_verify_sig(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *const EcdsaSig,
    eckey: *mut EcKey,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret: c_int = -1;
        let mut dgst_len = dgst_len;

        /* check input values */
        if eckey.is_null() || sig.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:455`, EC_R_MISSING_PARAMETERS).
            raise_site(&err_sites::ECDSA_OSSL_455);
            return -1;
        }
        let group = EC_KEY_get0_group(eckey);
        let pub_key = EC_KEY_get0_public_key(eckey);
        if group.is_null() || pub_key.is_null() {
            raise_site(&err_sites::ECDSA_OSSL_455);
            return -1;
        }

        if EC_KEY_can_sign(eckey) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:460`,
            // EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING).
            raise_site(&err_sites::ECDSA_OSSL_460);
            return -1;
        }

        let ctx = BN_CTX_new_ex((*eckey).libctx);
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:466`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_466);
            return -1;
        }
        BN_CTX_start(ctx);
        let u1 = BN_CTX_get(ctx);
        let u2 = BN_CTX_get(ctx);
        let m = BN_CTX_get(ctx);
        let x = BN_CTX_get(ctx);
        if x.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:475`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_475);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        let order = EC_GROUP_get0_order(group);
        if order.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:481`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_481);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        if BN_is_zero((*sig).r) != 0
            || BN_is_negative((*sig).r) != 0
            || BN_ucmp((*sig).r, order) >= 0
            || BN_is_zero((*sig).s) != 0
            || BN_is_negative((*sig).s) != 0
            || BN_ucmp((*sig).s, order) >= 0
        {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:486`, EC_R_BAD_SIGNATURE).
            raise_site(&err_sites::ECDSA_OSSL_486);
            ret = 0; /* signature is invalid */
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* calculate tmp1 = inv(S) mod order */
        if ossl_ec_group_do_inverse_ord(group, u2, (*sig).s, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:492`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_492);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* digest -> m */
        let i = BN_num_bits(order);
        /*
         * Need to truncate digest if it is too long: first truncate whole bytes.
         */
        if 8 * dgst_len > i {
            dgst_len = (i + 7) / 8;
        }
        if BN_bin2bn(dgst, dgst_len, m).is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:503`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_503);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* If still too long truncate remaining bits with a shift */
        if (8 * dgst_len > i) && BN_rshift(m, m, 8 - (i & 0x7)) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:508`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_508);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* u1 = m * tmp mod order */
        if BN_mod_mul(u1, m, u2, order, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:513`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_513);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* u2 = r * w mod q */
        if BN_mod_mul(u2, (*sig).r, u2, order, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:518`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_518);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        let point: *mut EcPoint = EC_POINT_new(group);
        if point.is_null() {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:523`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_523);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ret;
        }
        if EC_POINT_mul(group, point, u1, pub_key, u2, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:527`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_527);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ret;
        }

        if EC_POINT_get_affine_coordinates(group, point, x, ptr::null_mut(), ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:532`, ERR_R_EC_LIB).
            raise_site(&err_sites::ECDSA_OSSL_532);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ret;
        }

        if BN_nnmod(u1, x, order, ctx) == 0 {
            // SAFETY: a compile-time-constant site (`ecdsa_ossl.c:537`, ERR_R_BN_LIB).
            raise_site(&err_sites::ECDSA_OSSL_537);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ret;
        }
        /*  if the signature is correct u1 is equal to sig->r */
        ret = c_int::from(BN_ucmp(u1, (*sig).r) == 0);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(point);
        ret
    }
}
