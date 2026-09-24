//! Phase 8 — `crypto/sm2/sm2_sign.c`: the SM2 Z-digest and the sign/verify pair.
//!
//! Five hundred and forty-three lines, eight functions, transcribed whole (D327). The provider's
//! `SM2` signature unit (`src/provider/sm2_sig.rs`) reaches four of them:
//! `ossl_sm2_compute_z_digest`, `ossl_sm2_internal_sign`, `ossl_sm2_internal_verify` and the
//! `ossl_sm2_do_sign`/`ossl_sm2_do_verify` pair. The other three (`sm2_compute_msg_hash`,
//! `sm2_sig_gen`, `sm2_sig_verify`) are `static` in the authority and private here.
//!
//! ## What the unit is
//!
//! SM2's signature is ECDSA over the SM2 curve with two changes that are the whole unit: the
//! signed value is `e = H(Z || M)` where `Z = H(ENTL || ID || a || b || xG || yG || xA || yA)`
//! ([`ossl_sm2_compute_z_digest`]), and the signature equation uses `1/(1 + dA)` rather than
//! `1/k` ([`sm2_sig_gen`]). The EC half is landed (`ossl_ec_group_do_inverse_ord` is
//! `src/ec/lib.rs`, the `EC_GROUP`/`EC_POINT`/`ECDSA_SIG` accessors are in `src/ec/`), so this
//! unit is the two equations and the digest.
//!
//! ## The evidence is the authority's own published vectors
//!
//! `test/sm2_internal_test.c` carries the GM/T 0003.5-2012 (and GB/T 32918.5-2016) Annex A
//! signature known-answer values: a private key, the default user ID, a message and the expected
//! `(r, s)`. The test below drives that vector through [`ossl_sm2_do_verify`], which recomputes `Z`
//! and `e` from the same public inputs, so the **derived value `Z` is closed against the published
//! vector** rather than against a second transcription (D400/D401's rule). A differential court
//! would only prove the two implementations agree.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::bn::arith::{BN_add, BN_cmp, BN_mod_add, BN_mod_mul, BN_sub};
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_free, BN_is_zero, BN_new, BN_num_bits, BN_value_one, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::ec::asn1::{d2i_ECDSA_SIG, i2d_ECDSA_SIG};
use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_SIG_get0, ECDSA_SIG_new, ECDSA_SIG_set0};
use crate::ec::key::{
    ossl_ec_key_get0_propq, ossl_ec_key_get_libctx, EC_KEY_get0_group, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key,
};
use crate::ec::lib::{
    ossl_ec_group_do_inverse_ord, EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get_curve,
    EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new,
};
use crate::ec::{EcKey, EcPoint, EcdsaSig};
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The unit's own `__FILE__`. `sm2_sign.c` is a source-tree file, so the compiler records the
/// admitted build record's prefix.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/sm2/sm2_sign.c".as_ptr();

/// `UINT16_MAX` — `include/internal/numbers.h`'s `0xffff`. The guard is `id_len >= UINT16_MAX / 8`,
/// the largest user ID whose `ENTL = 8 * id_len` still fits a `uint16_t`.
const UINT16_MAX: usize = 0xffff;

/// `BN_num_bytes(a)` — `include/openssl/bn.h`'s macro `((BN_num_bits(a) + 7) / 8)`. A macro has no
/// symbol to call, so the expression is written out, the same way `src/ec/depr.rs` writes it.
///
/// # Safety
/// `a` is NULL or live.
#[inline]
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (BN_num_bits(a) + 7) / 8 }
}

/// `int ossl_sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest, const uint8_t *id,`
/// `const size_t id_len, const EC_KEY *key)` — `crypto/sm2/sm2_sign.c:23-149`.
///
/// `Z = H(ENTL || ID || a || b || xG || yG || xA || yA)`, where every field is `p_bytes` wide
/// (`p`'s own byte length) and `ENTL` is the 16-bit big-endian bit length of `ID`. The public key
/// is **required**: a key with no public half raises `ERR_R_PASSED_NULL_PARAMETER` (`:48`) rather
/// than hashing zeros.
///
/// # Safety
/// `out` has room for `digest`'s size; `digest` is live; `id` is NULL or `id_len` bytes; `key` is
/// live and has a public key.
pub(crate) unsafe fn ossl_sm2_compute_z_digest(
    out: *mut u8,
    digest: *const EvpMd,
    id: *const u8,
    id_len: usize,
    key: *const EcKey,
) -> c_int {
    let mut rc: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut hash: *mut EvpMdCtx = ptr::null_mut();
    let mut buf: *mut u8 = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let group = EC_KEY_get0_group(key);
        let pubkey = EC_KEY_get0_public_key(key);

        'done: {
            if pubkey.is_null() {
                raise_site(&err_sites::SM2_SIGN_48);
                break 'done;
            }
            hash = EVP_MD_CTX_new();
            if hash.is_null() {
                raise_site(&err_sites::SM2_SIGN_54);
                break 'done;
            }
            ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
            if ctx.is_null() {
                raise_site(&err_sites::SM2_SIGN_59);
                break 'done;
            }

            BN_CTX_start(ctx);
            let p = BN_CTX_get(ctx);
            let a = BN_CTX_get(ctx);
            let b = BN_CTX_get(ctx);
            let x_g = BN_CTX_get(ctx);
            let y_g = BN_CTX_get(ctx);
            let x_a = BN_CTX_get(ctx);
            let y_a = BN_CTX_get(ctx);

            if y_a.is_null() {
                raise_site(&err_sites::SM2_SIGN_73);
                break 'done;
            }

            if EVP_DigestInit(hash, digest) == 0 {
                raise_site(&err_sites::SM2_SIGN_78);
                break 'done;
            }

            if id_len >= UINT16_MAX / 8 {
                raise_site(&err_sites::SM2_SIGN_86);
                break 'done;
            }

            let entl = (8 * id_len) as u16;
            let mut e_byte = (entl >> 8) as u8;
            if EVP_DigestUpdate(hash, ptr::addr_of!(e_byte).cast::<c_void>(), 1) == 0 {
                raise_site(&err_sites::SM2_SIGN_94);
                break 'done;
            }
            e_byte = (entl & 0xff) as u8;
            if EVP_DigestUpdate(hash, ptr::addr_of!(e_byte).cast::<c_void>(), 1) == 0 {
                raise_site(&err_sites::SM2_SIGN_99);
                break 'done;
            }
            if id_len > 0 && EVP_DigestUpdate(hash, id.cast::<c_void>(), id_len) == 0 {
                raise_site(&err_sites::SM2_SIGN_104);
                break 'done;
            }

            if EC_GROUP_get_curve(group, p, a, b, ctx) == 0 {
                raise_site(&err_sites::SM2_SIGN_109);
                break 'done;
            }

            let p_bytes = bn_num_bytes(p);
            buf = CRYPTO_zalloc(p_bytes as usize, FILE, 114).cast::<u8>();
            if buf.is_null() {
                break 'done;
            }

            if BN_bn2binpad(a, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || BN_bn2binpad(b, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || EC_POINT_get_affine_coordinates(
                    group,
                    EC_GROUP_get0_generator(group),
                    x_g,
                    y_g,
                    ctx,
                ) == 0
                || BN_bn2binpad(x_g, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || BN_bn2binpad(y_g, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || EC_POINT_get_affine_coordinates(group, pubkey, x_a, y_a, ctx) == 0
                || BN_bn2binpad(x_a, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || BN_bn2binpad(y_a, buf, p_bytes) < 0
                || EVP_DigestUpdate(hash, buf.cast::<c_void>(), p_bytes as usize) == 0
                || EVP_DigestFinal(hash, out, ptr::null_mut()) == 0
            {
                raise_site(&err_sites::SM2_SIGN_137);
                break 'done;
            }

            rc = 1;
        }

        CRYPTO_free(buf.cast(), FILE, 144);
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
    }
    rc
}

/// `static BIGNUM *sm2_compute_msg_hash(...)` — `crypto/sm2/sm2_sign.c:151-207`. The message
/// digest `e = BN_bin2bn(H(Z || M))`.
///
/// # Safety
/// `digest` is live and names a fetchable digest; `id`/`msg` are NULL or their lengths; `key` is
/// live.
unsafe fn sm2_compute_msg_hash(
    digest: *const EvpMd,
    key: *const EcKey,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> *mut BigNum {
    let mut e: *mut BigNum = ptr::null_mut();
    let mut z: *mut u8 = ptr::null_mut();
    let mut fetched_digest: *mut EvpMd = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let md_size = EVP_MD_get_size(digest);
        let hash = EVP_MD_CTX_new();
        let libctx = ossl_ec_key_get_libctx(key);
        let propq = ossl_ec_key_get0_propq(key);

        'done: {
            if md_size <= 0 {
                raise_site(&err_sites::SM2_SIGN_166);
                break 'done;
            }
            if hash.is_null() {
                raise_site(&err_sites::SM2_SIGN_170);
                break 'done;
            }

            z = CRYPTO_zalloc(md_size as usize, FILE, 174).cast::<u8>();
            if z.is_null() {
                break 'done;
            }

            fetched_digest = EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
            if fetched_digest.is_null() {
                raise_site(&err_sites::SM2_SIGN_180);
                break 'done;
            }

            if ossl_sm2_compute_z_digest(z, fetched_digest, id, id_len, key) == 0 {
                /* SM2err already called */
                break 'done;
            }

            if EVP_DigestInit(hash, fetched_digest) == 0
                || EVP_DigestUpdate(hash, z.cast::<c_void>(), md_size as usize) == 0
                || EVP_DigestUpdate(hash, msg.cast::<c_void>(), msg_len) == 0
                /* reuse z buffer to hold H(Z || M) */
                || EVP_DigestFinal(hash, z, ptr::null_mut()) == 0
            {
                raise_site(&err_sites::SM2_SIGN_194);
                break 'done;
            }

            e = BN_bin2bn(z, md_size, ptr::null_mut());
            if e.is_null() {
                raise_site(&err_sites::SM2_SIGN_200);
            }
        }

        EVP_MD_free(fetched_digest);
        CRYPTO_free(z.cast(), FILE, 204);
        EVP_MD_CTX_free(hash);
    }
    e
}

/// `static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)` —
/// `crypto/sm2/sm2_sign.c:209-331`. The SM2 signature equation.
///
/// `r = (e + x1) mod n` and `s = (1/(1 + dA) * (k - r*dA)) mod n`, retried while `r == 0`,
/// `r + k == n` or `s == 0`. `r` and `s` are returned, so they are allocated with `BN_new` rather
/// than out of `ctx`, and the `done:` label frees them **only** when no signature was built (the
/// `ECDSA_SIG_set0` takes ownership otherwise).
///
/// # Safety
/// `key` is live with a private key; `e` is live.
#[allow(unused_assignments)] // `ctx`/`sig` are initialised for the shared `done:` cleanup
unsafe fn sm2_sig_gen(key: *const EcKey, e: *const BigNum) -> *mut EcdsaSig {
    let mut sig: *mut EcdsaSig = ptr::null_mut();
    let mut k_g: *mut EcPoint = ptr::null_mut();
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut r: *mut BigNum = ptr::null_mut();
    let mut s: *mut BigNum = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let d_a = EC_KEY_get0_private_key(key);
        let group = EC_KEY_get0_group(key);
        let order = EC_GROUP_get0_order(group);

        'done: {
            if d_a.is_null() {
                raise_site(&err_sites::SM2_SIGN_226);
                break 'done;
            }
            k_g = EC_POINT_new(group);
            if k_g.is_null() {
                raise_site(&err_sites::SM2_SIGN_231);
                break 'done;
            }
            ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
            if ctx.is_null() {
                raise_site(&err_sites::SM2_SIGN_236);
                break 'done;
            }

            BN_CTX_start(ctx);
            let k = BN_CTX_get(ctx);
            let rk = BN_CTX_get(ctx);
            let x1 = BN_CTX_get(ctx);
            let tmp = BN_CTX_get(ctx);
            if tmp.is_null() {
                raise_site(&err_sites::SM2_SIGN_246);
                break 'done;
            }

            /*
             * These values are returned and so should not be allocated out of the context.
             */
            r = BN_new();
            s = BN_new();

            if r.is_null() || s.is_null() {
                raise_site(&err_sites::SM2_SIGN_258);
                break 'done;
            }

            loop {
                if BN_priv_rand_range_ex(k, order, 0, ctx) == 0 {
                    raise_site(&err_sites::SM2_SIGN_273);
                    break 'done;
                }

                if EC_POINT_mul(group, k_g, k, ptr::null(), ptr::null(), ctx) == 0
                    || EC_POINT_get_affine_coordinates(group, k_g, x1, ptr::null_mut(), ctx) == 0
                    || BN_mod_add(r, e, x1, order, ctx) == 0
                {
                    raise_site(&err_sites::SM2_SIGN_281);
                    break 'done;
                }

                /* try again if r == 0 or r+k == n */
                if BN_is_zero(r) != 0 {
                    continue;
                }

                if BN_add(rk, r, k) == 0 {
                    raise_site(&err_sites::SM2_SIGN_290);
                    break 'done;
                }

                if BN_cmp(rk, order) == 0 {
                    continue;
                }

                if BN_add(s, d_a, BN_value_one()) == 0
                    || ossl_ec_group_do_inverse_ord(group, s, s, ctx) == 0
                    || BN_mod_mul(tmp, d_a, r, order, ctx) == 0
                    || BN_sub(tmp, k, tmp) == 0
                    || BN_mod_mul(s, s, tmp, order, ctx) == 0
                {
                    raise_site(&err_sites::SM2_SIGN_302);
                    break 'done;
                }

                /* try again if s == 0 */
                if BN_is_zero(s) != 0 {
                    continue;
                }

                sig = ECDSA_SIG_new();
                if sig.is_null() {
                    raise_site(&err_sites::SM2_SIGN_312);
                    break 'done;
                }

                /* takes ownership of r and s */
                ECDSA_SIG_set0(sig, r, s);
                r = ptr::null_mut();
                s = ptr::null_mut();
                break;
            }
        }

        if sig.is_null() {
            BN_free(r);
            BN_free(s);
        }
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        EC_POINT_free(k_g);
    }
    sig
}

/// `static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e)` —
/// `crypto/sm2/sm2_sign.c:333-415`.
///
/// Steps B1-B7 of GM/T 0003.2: the two range checks on `r` and `s`, `t = (r + s) mod n`,
/// `(x1', y1') = [s']G + [t]PA`, and `R = (e' + x1') mod n` compared against `r'`.
///
/// # Safety
/// `key` is live with a public key; `sig` and `e` are live.
#[allow(unused_assignments)] // `ctx`/`pt` are initialised for the shared `done:` cleanup
unsafe fn sm2_sig_verify(key: *const EcKey, sig: *const EcdsaSig, e: *const BigNum) -> c_int {
    let mut ret: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut pt: *mut EcPoint = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let group = EC_KEY_get0_group(key);
        let order = EC_GROUP_get0_order(group);

        'done: {
            ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
            if ctx.is_null() {
                raise_site(&err_sites::SM2_SIGN_349);
                break 'done;
            }
            BN_CTX_start(ctx);
            let t = BN_CTX_get(ctx);
            let x1 = BN_CTX_get(ctx);
            if x1.is_null() {
                raise_site(&err_sites::SM2_SIGN_356);
                break 'done;
            }

            pt = EC_POINT_new(group);
            if pt.is_null() {
                raise_site(&err_sites::SM2_SIGN_362);
                break 'done;
            }

            let mut r: *const BigNum = ptr::null();
            let mut s: *const BigNum = ptr::null();
            ECDSA_SIG_get0(sig, ptr::addr_of_mut!(r), ptr::addr_of_mut!(s));

            if BN_cmp(r, BN_value_one()) < 0
                || BN_cmp(s, BN_value_one()) < 0
                || BN_cmp(order, r) <= 0
                || BN_cmp(order, s) <= 0
            {
                raise_site(&err_sites::SM2_SIGN_382);
                break 'done;
            }

            if BN_mod_add(t, r, s, order, ctx) == 0 {
                raise_site(&err_sites::SM2_SIGN_387);
                break 'done;
            }

            if BN_is_zero(t) != 0 {
                raise_site(&err_sites::SM2_SIGN_392);
                break 'done;
            }

            if EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx) == 0
                || EC_POINT_get_affine_coordinates(group, pt, x1, ptr::null_mut(), ctx) == 0
            {
                raise_site(&err_sites::SM2_SIGN_398);
                break 'done;
            }

            if BN_mod_add(t, e, x1, order, ctx) == 0 {
                raise_site(&err_sites::SM2_SIGN_403);
                break 'done;
            }

            if BN_cmp(r, t) == 0 {
                ret = 1;
            }
        }

        EC_POINT_free(pt);
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
    }
    ret
}

/// `ECDSA_SIG *ossl_sm2_do_sign(const EC_KEY *key, const EVP_MD *digest, const uint8_t *id,`
/// `const size_t id_len, const uint8_t *msg, size_t msg_len)` — `crypto/sm2/sm2_sign.c:417-437`.
///
/// # Safety
/// `key` is live with a private key; `digest` is live; `id`/`msg` are NULL or their lengths.
///
/// Only the unit test below drives this pair on this profile: the authority's own callers are
/// `test/sm2_internal_test.c`, and the provider's `SM2` signature unit runs on
/// [`ossl_sm2_internal_sign`] instead. Transcribed whole (D327), marked rather than dropped.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn ossl_sm2_do_sign(
    key: *const EcKey,
    digest: *const EvpMd,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> *mut EcdsaSig {
    // SAFETY: the caller's contract is this function's `# Safety` section.
    unsafe {
        let e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
        if e.is_null() {
            /* SM2err already called */
            return ptr::null_mut();
        }

        let sig = sm2_sig_gen(key, e);

        BN_free(e);
        sig
    }
}

/// `int ossl_sm2_do_verify(const EC_KEY *key, const EVP_MD *digest, const ECDSA_SIG *sig,`
/// `const uint8_t *id, const size_t id_len, const uint8_t *msg, size_t msg_len)` —
/// `crypto/sm2/sm2_sign.c:439-460`.
///
/// # Safety
/// `key` is live with a public key; `digest` is live; `sig` is live; `id`/`msg` are NULL or their
/// lengths.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn ossl_sm2_do_verify(
    key: *const EcKey,
    digest: *const EvpMd,
    sig: *const EcdsaSig,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    // SAFETY: the caller's contract is this function's `# Safety` section.
    unsafe {
        let e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
        if e.is_null() {
            /* SM2err already called */
            return 0;
        }

        let ret = sm2_sig_verify(key, sig, e);

        BN_free(e);
        ret
    }
}

/// `int ossl_sm2_internal_sign(const unsigned char *dgst, int dgstlen, unsigned char *sig,`
/// `unsigned int *siglen, EC_KEY *eckey)` — `crypto/sm2/sm2_sign.c:462-501`.
///
/// `dgst` is already `H(Z || M)`; the function does not compute `Z`. The signature is encoded as
/// `ECDSA-Sig-Value` DER, which is why the size the caller must supply is `ECDSA_size`'s.
///
/// # Safety
/// `dgst` is `dgstlen` bytes; `sig` is live and holds room for an `ECDSA-Sig-Value`; `siglen` is
/// writable; `eckey` is live with a private key.
pub(crate) unsafe fn ossl_sm2_internal_sign(
    dgst: *const u8,
    dgstlen: c_int,
    sig: *mut u8,
    siglen: *mut c_uint,
    eckey: *mut EcKey,
) -> c_int {
    let mut e: *mut BigNum = ptr::null_mut();
    let mut s: *mut EcdsaSig = ptr::null_mut();
    let mut ret: c_int = -1;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        'done: {
            if sig.is_null() {
                raise_site(&err_sites::SM2_SIGN_472);
                break 'done;
            }

            e = BN_bin2bn(dgst, dgstlen, ptr::null_mut());
            if e.is_null() {
                raise_site(&err_sites::SM2_SIGN_478);
                break 'done;
            }

            s = sm2_sig_gen(eckey, e);
            if s.is_null() {
                raise_site(&err_sites::SM2_SIGN_484);
                break 'done;
            }

            let sigleni = {
                let mut out = sig;
                i2d_ECDSA_SIG(s, ptr::addr_of_mut!(out))
            };
            if sigleni < 0 {
                raise_site(&err_sites::SM2_SIGN_490);
                break 'done;
            }
            *siglen = sigleni as c_uint;

            ret = 1;
        }

        ECDSA_SIG_free(s);
        BN_free(e);
    }
    ret
}

/// `int ossl_sm2_internal_verify(const unsigned char *dgst, int dgstlen,`
/// `const unsigned char *sig, int sig_len, EC_KEY *eckey)` — `crypto/sm2/sm2_sign.c:503-543`.
///
/// The signature must be DER **and** free of trailing garbage: the authority re-encodes the decoded
/// value and requires the bytes to match (`:525`), so a BER-but-not-DER encoding is refused with
/// `SM2_R_INVALID_ENCODING` rather than accepted.
///
/// # Safety
/// `dgst` is `dgstlen` bytes; `sig` is `sig_len` bytes; `eckey` is live with a public key.
#[allow(unused_assignments)] // `s`/`e` are initialised for the shared `done:` cleanup
pub(crate) unsafe fn ossl_sm2_internal_verify(
    dgst: *const u8,
    dgstlen: c_int,
    sig: *const u8,
    sig_len: c_int,
    eckey: *mut EcKey,
) -> c_int {
    let mut e: *mut BigNum = ptr::null_mut();
    let mut s: *mut EcdsaSig = ptr::null_mut();
    let mut der: *mut u8 = ptr::null_mut();
    let mut ret: c_int = -1;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        'done: {
            s = ECDSA_SIG_new();
            if s.is_null() {
                raise_site(&err_sites::SM2_SIGN_516);
                break 'done;
            }

            let mut p = sig;
            if d2i_ECDSA_SIG(ptr::addr_of_mut!(s), ptr::addr_of_mut!(p), sig_len as i64).is_null() {
                raise_site(&err_sites::SM2_SIGN_520);
                break 'done;
            }
            /* Ensure signature uses DER and doesn't have trailing garbage */
            let derlen = i2d_ECDSA_SIG(s, ptr::addr_of_mut!(der));
            if derlen != sig_len
                || core::slice::from_raw_parts(sig, derlen as usize)
                    != core::slice::from_raw_parts(der, derlen as usize)
            {
                raise_site(&err_sites::SM2_SIGN_526);
                break 'done;
            }

            e = BN_bin2bn(dgst, dgstlen, ptr::null_mut());
            if e.is_null() {
                raise_site(&err_sites::SM2_SIGN_532);
                break 'done;
            }

            ret = sm2_sig_verify(eckey, s, e);
        }

        CRYPTO_free(der.cast(), FILE, 539);
        BN_free(e);
        ECDSA_SIG_free(s);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::BN_hex2bn;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use crate::ec::key::{
        ossl_ec_key_set0_libctx, EC_KEY_free, EC_KEY_new_by_curve_name, EC_KEY_set_private_key,
        EC_KEY_set_public_key,
    };
    use crate::runtime::obj::NID_sm2;

    /// The default user ID from GM/T 0009-2012 (Sec. 10), `crypto/sm2.h`'s `SM2_DEFAULT_USERID`.
    const SM2_DEFAULT_USERID: &[u8] = b"1234567812345678";

    /// The GM/T 0003.5-2012 / GB/T 32918.5-2016 Annex A vector, read back from the authority's own
    /// `test/sm2_internal_test.c:409-424`: the private key, the message, and the expected `(r, s)`.
    /// Every value is the authority's published one.
    const ANNEX_A_PRIV: &core::ffi::CStr =
        c"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    const ANNEX_A_MSG: &[u8] = b"message digest";
    const ANNEX_A_R: &core::ffi::CStr =
        c"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3";
    const ANNEX_A_S: &core::ffi::CStr =
        c"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA";

    /// Builds an `EC_KEY` on the SM2 curve from a hex private key, deriving its public half.
    ///
    /// # Safety
    /// The caller owns the returned key.
    unsafe fn key_from_hex(
        libctx: *mut core::ffi::c_void,
        priv_hex: &core::ffi::CStr,
    ) -> *mut EcKey {
        // SAFETY: this function's own contract.
        unsafe {
            let key = EC_KEY_new_by_curve_name(NID_sm2);
            assert!(!key.is_null());
            ossl_ec_key_set0_libctx(key, libctx);
            let group = EC_KEY_get0_group(key);
            assert!(!group.is_null());

            let mut priv_bn: *mut BigNum = ptr::null_mut();
            assert!(BN_hex2bn(ptr::addr_of_mut!(priv_bn), priv_hex.as_ptr()) != 0);
            assert_eq!(EC_KEY_set_private_key(key, priv_bn), 1);

            let pt = EC_POINT_new(group);
            assert!(!pt.is_null());
            assert_eq!(
                EC_POINT_mul(
                    group,
                    pt,
                    priv_bn,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(EC_KEY_set_public_key(key, pt), 1);
            EC_POINT_free(pt);
            BN_free(priv_bn);
            key
        }
    }

    /// The published Annex A signature verifies, which recomputes `Z` and `e` from the vector's
    /// own public inputs — the derived-value closure D400/D401 require.
    #[test]
    fn the_annex_a_signature_verifies() {
        // SAFETY: every pointer is this test's own, built below.
        unsafe {
            let libctx = OSSL_LIB_CTX_new();
            let key = key_from_hex(libctx, ANNEX_A_PRIV);
            let md = EVP_MD_fetch(libctx, c"SM3".as_ptr(), ptr::null());

            let mut r: *mut BigNum = ptr::null_mut();
            let mut s: *mut BigNum = ptr::null_mut();
            assert!(BN_hex2bn(ptr::addr_of_mut!(r), ANNEX_A_R.as_ptr()) != 0);
            assert!(BN_hex2bn(ptr::addr_of_mut!(s), ANNEX_A_S.as_ptr()) != 0);
            let sig = ECDSA_SIG_new();
            assert_eq!(ECDSA_SIG_set0(sig, r, s), 1);

            assert_eq!(
                ossl_sm2_do_verify(
                    key,
                    md,
                    sig,
                    SM2_DEFAULT_USERID.as_ptr(),
                    SM2_DEFAULT_USERID.len(),
                    ANNEX_A_MSG.as_ptr(),
                    ANNEX_A_MSG.len(),
                ),
                1
            );

            /* A one-byte message change must not verify. */
            let mut tampered = ANNEX_A_MSG.to_vec();
            tampered[0] ^= 1;
            assert_eq!(
                ossl_sm2_do_verify(
                    key,
                    md,
                    sig,
                    SM2_DEFAULT_USERID.as_ptr(),
                    SM2_DEFAULT_USERID.len(),
                    tampered.as_ptr(),
                    tampered.len(),
                ),
                0
            );

            ECDSA_SIG_free(sig);
            EVP_MD_free(md);
            EC_KEY_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
    }

    /// The internal sign/verify pair the provider unit runs on round-trips, and a flipped signature
    /// byte is refused.
    #[test]
    fn the_internal_pair_round_trips() {
        // SAFETY: every pointer is this test's own, built below.
        unsafe {
            let libctx = OSSL_LIB_CTX_new();
            let key = key_from_hex(libctx, ANNEX_A_PRIV);
            let mut dgst = [0u8; 32];
            for (i, b) in dgst.iter_mut().enumerate() {
                *b = i as u8;
            }

            let mut sig = [0u8; 96];
            let mut siglen: c_uint = 0;
            assert_eq!(
                ossl_sm2_internal_sign(
                    dgst.as_ptr(),
                    dgst.len() as c_int,
                    sig.as_mut_ptr(),
                    ptr::addr_of_mut!(siglen),
                    key,
                ),
                1
            );
            assert!(siglen > 0 && (siglen as usize) <= sig.len());

            assert_eq!(
                ossl_sm2_internal_verify(
                    dgst.as_ptr(),
                    dgst.len() as c_int,
                    sig.as_ptr(),
                    siglen as c_int,
                    key,
                ),
                1
            );

            sig[siglen as usize - 1] ^= 1;
            assert_eq!(
                ossl_sm2_internal_verify(
                    dgst.as_ptr(),
                    dgst.len() as c_int,
                    sig.as_ptr(),
                    siglen as c_int,
                    key,
                ),
                0
            );

            EC_KEY_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
    }

    /// A key with no public half is refused by the Z digest rather than hashing zeros.
    #[test]
    fn a_key_without_a_public_half_is_refused() {
        // SAFETY: every pointer is this test's own, built below.
        unsafe {
            let libctx = OSSL_LIB_CTX_new();
            let key = EC_KEY_new_by_curve_name(NID_sm2);
            ossl_ec_key_set0_libctx(key, libctx);
            let mut priv_bn: *mut BigNum = ptr::null_mut();
            assert!(BN_hex2bn(ptr::addr_of_mut!(priv_bn), ANNEX_A_PRIV.as_ptr()) != 0);
            assert_eq!(EC_KEY_set_private_key(key, priv_bn), 1);

            let md = EVP_MD_fetch(libctx, c"SM3".as_ptr(), ptr::null());
            let mut z = [0u8; 32];
            assert_eq!(
                ossl_sm2_compute_z_digest(
                    z.as_mut_ptr(),
                    md,
                    SM2_DEFAULT_USERID.as_ptr(),
                    SM2_DEFAULT_USERID.len(),
                    key,
                ),
                0
            );

            BN_free(priv_bn);
            EVP_MD_free(md);
            EC_KEY_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
    }
}
