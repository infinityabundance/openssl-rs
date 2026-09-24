//! `crypto/rsa/rsa_pss.c` — RSASSA-PSS: the two EMSA-PSS halves and the PSS *parameter*
//! object, Phase 8.4, transcribed whole.
//!
//! Four hundred and twenty-four lines and **eighteen definitions**: the two `rsa.h` exports and
//! their `_mgf1` siblings, the two internals the exports are one `int *` away from, the file's
//! eight zero octets, and the twelve `ossl_rsa_pss_params_30_*` accessors over
//! `default_RSASSA_PSS_params`.
//!
//! ## What this module is, and why it is a module of its own
//!
//! Until this commit the four exports and the two internals lived in [`crate::rsa`]'s `mod.rs`,
//! which the atlas measures as `crypto/rsa/rsa_meth.c`'s (`share 33/61`): a module that happened
//! to also hold a unit it was not the module for. The project's rule is one authority unit per
//! module and the atlas measures the map from the code, so the unit moves here and `mod.rs`
//! loses it — no behaviour changes, no symbol changes (all four exports stay `#[no_mangle]`),
//! and `src/rsa/mod.rs`'s dominant unit is unaffected.
//!
//! The other half of the unit — the twelve `ossl_rsa_pss_params_30_*` — is **new here**, and it
//! is the whole point of the landing: `crypto/rsa/rsa_ameth.c`'s callbacks and
//! `crypto/rsa/rsa_backend.c`'s two parameter codecs both call them, and until they exist the
//! provider-side PSS restriction has no object at all.
//!
//! ## The two halves share a file and nothing else
//!
//! The EMSA-PSS half is arithmetic over a caller's block: it reads `rsa->n` for `MSBits` and
//! `RSA_size` for `emLen`, draws a salt with `RAND_bytes_ex` **on the object's own libctx**, and
//! writes into the caller's `EM`. The parameter half is five `int`s in a struct: it never
//! touches an `RSA`, never allocates, and every one of its "setter" arms is a single store that
//! answers 1 — or 0 for a NULL object, which is the only refusal in the twelve.
//!
//! `ossl_rsa_pss_params_30_is_unrestricted` is the one function whose *mechanism* is worth
//! stating: the authority compares the object against a `static RSA_PSS_PARAMS_30 pss_params_cmp
//! = { 0, }` with `memcmp` and answers true when the comparison is **equal**. Since
//! [`RsaPssParams30`] is five four-byte `int`s with no padding — the layout is asserted in
//! `src/rsa/mod.rs` — the field-by-field form below is the same test.
//!
//! ## The defaults are RFC 8017 A.2.3's, and the comment in the authority is the whole reason
//!
//! `default_RSASSA_PSS_params` is SHA-1 with MGF1/SHA-1, a salt length of 20 and trailer field 1
//! — `trailerFieldBC`, which is why `EM`'s last octet is `0xbc` on both sides of this file. The
//! authority quotes the ASN.1 identifier that fixes those four values; the table below is that
//! identifier's contents and nothing else.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar};

use crate::bn::bignum::BN_num_bits;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::evp::pkey_ctx::{RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::rsa::object::RSA_size;
use crate::rsa::{
    Rsa, RsaPssMaskGen, RsaPssParams30, PKCS1_MGF1, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX,
    RSA_PSS_SALTLEN_MAX_SIGN,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_mgf1, NID_sha1};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_pss.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix, the same check `src/rsa/mod.rs` applies to `rsa_meth.c`.
/// It reaches an application through `CRYPTO_set_mem_functions`, which is why the string is
/// reproduced rather than normalised.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_pss.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h`, 64. Restated per module, as `src/mac/hmac.rs`
/// and seven other units of this crate restate it: it is a property of the digest interface and
/// not of any one of them.
const EVP_MAX_MD_SIZE: usize = 64;

/// `static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 }` — `rsa_pss.c:25`.
///
/// The eight octets PKCS #1 v2.2 section 9.1.1's `H = Hash(0x00 * 8 || mHash || salt)` starts
/// with, in both the add and the verifier. One file-scope copy is what the authority has, so
/// this is one `const` rather than a literal in each body.
const ZEROES: [u8; 8] = [0; 8];

// =============================================================================================
// The exports, and the internals they wrap
// =============================================================================================

/// `int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash, const EVP_MD *Hash, const
/// unsigned char *EM, int sLen)` — `rsa_pss.c:31-36`.
///
/// The `_mgf1` form with a NULL mask generation digest, which the internal turns into `Hash`.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is readable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` is NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_PKCS1_PSS(
    rsa: *mut Rsa,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    em: *const c_uchar,
    s_len: c_int,
) -> c_int {
    // SAFETY: the caller's contract; a NULL `mgf1Hash` means "the same as `Hash`".
    unsafe { RSA_verify_PKCS1_PSS_mgf1(rsa, m_hash, hash, core::ptr::null(), em, s_len) }
}

/// `int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash, const EVP_MD *Hash,
/// const EVP_MD *mgf1Hash, const unsigned char *EM, int sLen)` — `rsa_pss.c:38-43`.
///
/// The export is the internal with a one-`int` difference: the salt length travels *by value*, so
/// the value the internal resolved is discarded. That is what makes `RSA_PSS_SALTLEN_AUTO` a legal
/// argument here and an unobservable one -- a caller that wants the recovered length wants
/// `EVP_PKEY_CTX_get_rsa_pss_saltlen`'s modern spelling, not this one.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is readable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` and `mgf1Hash` are NULL or live digest
/// methods.
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_PKCS1_PSS_mgf1(
    rsa: *mut Rsa,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    mgf1_hash: *const EvpMd,
    em: *const c_uchar,
    s_len: c_int,
) -> c_int {
    let mut s_len = s_len;
    // SAFETY: the caller's contract, forwarded with a local `sLen` the callee may write back.
    unsafe { ossl_rsa_verify_PKCS1_PSS_mgf1(rsa, m_hash, hash, mgf1_hash, em, &mut s_len) }
}

/// `int ossl_rsa_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash, const EVP_MD *Hash,
/// const EVP_MD *mgf1Hash, const unsigned char *EM, int *sLenOut)` — `rsa_pss.c:45-156`.
/// Internal, declared in `include/crypto/rsa.h:45-48`.
///
/// RSASSA-PSS's EMSA-PSS-VERIFY as PKCS #1 v2.2 section 9.1.2 writes it, and the `sLenOut`
/// pointer is what makes it the internal rather than the export: `-2` (AUTO) and `-4`
/// (AUTO_DIGEST_MAX) are answered with the salt length the block actually encodes, which the two
/// exports above cannot return because their signatures carry an `int` by value.
///
/// **The `MSBits == 0` arm moves the pointer, exactly as in the add.** When `BN_num_bits(n) - 1`
/// is a multiple of 8 the first octet of `EM` must be zero, and the authority writes the test
/// before its consequence: `EM[0] & (0xFF << MSBits)` with `MSBits == 0` is `EM[0] & 0xFF`, a
/// *refusal* for a non-zero octet, and only then are `EM` advanced and `emLen` decremented.
///
/// **The comparison is `memcmp(H_, H, hLen) != 0`, so a mismatch is a `0` with
/// `RSA_R_BAD_SIGNATURE`** -- and `*sLenOut` is written on the success *and* the mismatch path,
/// because the authority's assignment sits after the `if`/`else` rather than in it.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is readable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` and `mgf1Hash` are NULL or live digest
/// methods; `sLenOut` is a live `int` the callee writes back.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_verify_PKCS1_PSS_mgf1(
    rsa: *mut Rsa,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    mgf1_hash: *const EvpMd,
    em: *const c_uchar,
    s_len_out: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut s_len: c_int = *s_len_out;
        let mut db: *mut c_uchar = core::ptr::null_mut();
        let mut h_: [u8; EVP_MAX_MD_SIZE] = [0; EVP_MAX_MD_SIZE];
        let ctx: *mut EvpMdCtx = EVP_MD_CTX_new();

        'body: {
            if ctx.is_null() {
                break 'body;
            }

            let mut mgf1_hash = mgf1_hash;
            if mgf1_hash.is_null() {
                mgf1_hash = hash;
            }

            // SAFETY: `hash` is NULL or live per this function's contract.
            let h_len: c_int = EVP_MD_get_size(hash);
            if h_len <= 0 {
                break 'body;
            }
            // The negative conventions. Unlike the add's, only `-1` is resolved here: `-2` and `-4`
            // stay as sentinels for the comparison below, and `-3` is resolved after `emLen` is
            // known.
            if s_len == RSA_PSS_SALTLEN_DIGEST {
                s_len = h_len;
            } else if s_len < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
                raise_site(&err_sites::RSA_PSS_78);
                break 'body;
            }

            // SAFETY: `rsa` is live with a live `n`.
            let msbits = (BN_num_bits((*rsa).n) - 1) & 0x7;
            // SAFETY: `rsa` is live.
            let mut em_len = RSA_size(rsa);
            // SAFETY: `em` is readable for `em_len` bytes.
            if (*em as c_int) & (0xff << msbits) != 0 {
                raise_site(&err_sites::RSA_PSS_85);
                break 'body;
            }
            let mut em = em;
            if msbits == 0 {
                em = em.offset(1);
                em_len -= 1;
            }
            if em_len < h_len + 2 {
                raise_site(&err_sites::RSA_PSS_93);
                break 'body;
            }
            if s_len == RSA_PSS_SALTLEN_MAX {
                s_len = em_len - h_len - 2;
            } else if s_len > em_len - h_len - 2 {
                // `sLen` can be a small negative here, which is why the test is `>` and not `>=`.
                raise_site(&err_sites::RSA_PSS_99);
                break 'body;
            }
            if *em.offset((em_len - 1) as isize) != 0xbc {
                raise_site(&err_sites::RSA_PSS_103);
                break 'body;
            }
            let masked_dblen = em_len - h_len - 1;
            let h = em.offset(masked_dblen as isize);
            db = CRYPTO_malloc(masked_dblen as usize, FILE, LINE).cast::<c_uchar>();
            if db.is_null() {
                break 'body;
            }
            // SAFETY: `db` is writable for `masked_dblen` bytes and `h` is readable for `h_len`.
            if PKCS1_MGF1(db, masked_dblen as c_long, h, h_len as c_long, mgf1_hash) < 0 {
                break 'body;
            }
            let mut i: c_int = 0;
            while i < masked_dblen {
                *db.offset(i as isize) ^= *em.offset(i as isize);
                i += 1;
            }
            if msbits != 0 {
                *db &= (0xff >> (8 - msbits)) as u8;
            }
            // `for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++)`: the loop stops one short of
            // the end, so an all-zero `DB` leaves `i` at `maskedDBLen - 1` and the octet read below
            // is the last one in the buffer -- a refusal, not an overrun.
            i = 0;
            while *db.offset(i as isize) == 0 && i < (masked_dblen - 1) {
                i += 1;
            }
            let sep = *db.offset(i as isize);
            i += 1;
            if sep != 0x1 {
                raise_site(&err_sites::RSA_PSS_120);
                break 'body;
            }
            if s_len != RSA_PSS_SALTLEN_AUTO
                && s_len != RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
                && (masked_dblen - i) != s_len
            {
                // The authority's only `ERR_raise_data` in this file, and the text is the whole
                // observation: both numbers the check compared, formatted into one message.
                let mut msg = [0 as c_char; 64];
                // SAFETY: `msg` is a 64-byte buffer and the format is the authority's own.
                crate::runtime::bio::print::BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"expected: %d retrieved: %d".as_ptr(),
                    s_len,
                    masked_dblen - i,
                );
                // SAFETY: a compile-time-constant site; the message is NUL-terminated.
                raise_site_data(&err_sites::RSA_PSS_126, msg.as_ptr());
                break 'body;
            } else {
                s_len = masked_dblen - i;
            }
            // SAFETY: `hash` is NULL or live and `m_hash` is readable for `h_len` bytes.
            if EVP_DigestInit_ex(ctx, hash, core::ptr::null_mut()) == 0
                || EVP_DigestUpdate(ctx, ZEROES.as_ptr().cast(), ZEROES.len()) == 0
                || EVP_DigestUpdate(ctx, m_hash.cast(), h_len as usize) == 0
            {
                break 'body;
            }
            if s_len != 0 {
                // SAFETY: `db` has `masked_dblen` bytes and `i + s_len <= masked_dblen`.
                if EVP_DigestUpdate(
                    ctx,
                    db.offset(i as isize).cast_const().cast(),
                    s_len as usize,
                ) == 0
                {
                    break 'body;
                }
            }
            // SAFETY: `h_` is `EVP_MAX_MD_SIZE` bytes, which is what the digest needs.
            if EVP_DigestFinal_ex(ctx, h_.as_mut_ptr(), core::ptr::null_mut()) == 0 {
                break 'body;
            }
            // SAFETY: `h` is readable for `h_len` bytes and `h_` for the same.
            if core::slice::from_raw_parts(h_.as_ptr(), h_len as usize)
                != core::slice::from_raw_parts(h.cast::<u8>(), h_len as usize)
            {
                // The authority's `if (memcmp(...)) { raise; ret = 0; } else { ret = 1; }`, whose
                // *else* arm is the only place `ret` becomes 1 -- and whose fall-through then
                // writes `*sLenOut` on **both** arms, which is why a bad signature still reports
                // the salt length the block encoded.
                raise_site(&err_sites::RSA_PSS_144);
            } else {
                ret = 1;
            }

            *s_len_out = s_len;
        }

        // The authority's `err:` label, reached by falling through and by every `goto err` above.
        // `DB` is NULL when the first one is taken, which `OPENSSL_free` tolerates.
        // SAFETY: `db` is NULL or this call's own allocation.
        crate::runtime::mem::CRYPTO_free(db.cast(), FILE, LINE);
        // SAFETY: `ctx` is NULL or this call's own object.
        EVP_MD_CTX_free(ctx);

        ret
    }
}

/// `int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM, const unsigned char *mHash,
/// const EVP_MD *Hash, int sLen)` — `rsa_pss.c:158-163`.
///
/// The `_mgf1` form with `mgf1Hash` NULL, which the internal turns into `Hash`. A caller that
/// wants a mask generation function other than the message digest wants the other name.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is writable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` is NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS(
    rsa: *mut Rsa,
    em: *mut c_uchar,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    s_len: c_int,
) -> c_int {
    // SAFETY: the caller's contract; a NULL `mgf1Hash` means "the same as `Hash`".
    unsafe { RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, m_hash, hash, core::ptr::null(), s_len) }
}

/// `int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM, const unsigned char *mHash,
/// const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen)` — `rsa_pss.c:165-171`.
///
/// The export is the same `sLen` convention on the outside and a *pointer* on the inside: the
/// internal takes `int *sLenOut` so that it can answer with the value it resolved. This wrapper is
/// the whole of that difference, plus the NULL context the header's signature does not carry.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is writable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` and `mgf1Hash` are NULL or live digest
/// methods.
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS_mgf1(
    rsa: *mut Rsa,
    em: *mut c_uchar,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    mgf1_hash: *const EvpMd,
    s_len: c_int,
) -> c_int {
    let mut s_len = s_len;
    // SAFETY: the caller's contract, forwarded with a local `sLen` the callee may write back.
    unsafe { ossl_rsa_padding_add_PKCS1_PSS_mgf1(rsa, em, m_hash, hash, mgf1_hash, &mut s_len) }
}

/// `int ossl_rsa_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM, const unsigned char
/// *mHash, const EVP_MD *Hash, const EVP_MD *mgf1Hash, int *sLenOut)` — `rsa_pss.c:173-290`.
/// Internal, declared in `include/crypto/rsa.h:52-55`.
///
/// RSASSA-PSS's EMSA-PSS encoding as PKCS #1 v2.2 section 9.1.1 writes it, and the two things a
/// reader gets wrong are both length decisions rather than bytes:
///
/// * **`sLen` is an in/out parameter and the negative values are conventions, not lengths.** `-1`
///   means "the digest length", `-2` and `-3` both mean "the maximum the modulus allows", and
///   `-4` means the maximum *capped at the digest length* -- which is the one that needs
///   `sLenMax`, because it is the only convention that is `min(hLen, maximum)` rather than one of
///   the two on its own. A value below `-4` is a refusal, not a clamp.
/// * **`MSBits` can be zero, and then the encoding moves.** When `BN_num_bits(n) - 1` is a
///   multiple of 8 the top octet of `EM` must be zero, so the authority writes it, advances `EM`
///   *and* decrements `emLen`. After that every offset in the function is relative to the advanced
///   pointer, including the `0xbc` trailer. A transcription that advanced without decrementing, or
///   the reverse, puts the trailer one octet out and the block still "looks" like a PSS encoding.
///
/// The salt is drawn with `RAND_bytes_ex(rsa->libctx, ...)` -- **the object's context, not a
/// parameter's** -- and only when `sLen > 0`, which is why `salt != NULL` implies `sLen > 0` and why
/// the cleanup can pass the resolved `sLen`.
///
/// # Safety
/// `rsa` is a live object with a live `n`; `EM` is writable for `RSA_size(rsa)` bytes; `mHash` is
/// readable for `EVP_MD_get_size(Hash)` bytes; `Hash` and `mgf1Hash` are NULL or live digest
/// methods; `sLenOut` is a live `int` the callee may write back.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_padding_add_PKCS1_PSS_mgf1(
    rsa: *mut Rsa,
    em: *mut c_uchar,
    m_hash: *const c_uchar,
    hash: *const EvpMd,
    mgf1_hash: *const EvpMd,
    s_len_out: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut s_len: c_int = *s_len_out;
        let mut s_len_max: c_int = -1;
        let mut salt: *mut c_uchar = core::ptr::null_mut();
        let mut ctx: *mut EvpMdCtx = core::ptr::null_mut();

        let mut mgf1_hash = mgf1_hash;
        if mgf1_hash.is_null() {
            mgf1_hash = hash;
        }

        // SAFETY: `hash` is NULL or live per this function's contract.
        let h_len: c_int = EVP_MD_get_size(hash);

        let completed = 'body: {
            if h_len <= 0 {
                break 'body false;
            }
            // The negative `sLen` conventions. The `-4` arm is the only one that keeps the digest
            // length as a *cap* rather than as the value, which is what `sLenMax` carries.
            if s_len == RSA_PSS_SALTLEN_DIGEST {
                s_len = h_len;
            } else if s_len == RSA_PSS_SALTLEN_MAX_SIGN || s_len == RSA_PSS_SALTLEN_AUTO {
                s_len = RSA_PSS_SALTLEN_MAX;
            } else if s_len == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
                s_len = RSA_PSS_SALTLEN_MAX;
                s_len_max = h_len;
            } else if s_len < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
                raise_site(&err_sites::RSA_PSS_216);
                break 'body false;
            }

            // SAFETY: `rsa` is live with a live `n`; `RSA_size` reads it as `BN_num_bytes` is
            // written out in `object.rs`.
            let msbits = (BN_num_bits((*rsa).n) - 1) & 0x7;
            let mut em_len = RSA_size(rsa);
            // The encoding moves when `MSBits` is zero: one octet of `EM` is spent on the leading
            // zero and `emLen` shrinks to match.
            let mut em = em;
            if msbits == 0 {
                *em = 0;
                em = em.offset(1);
                em_len -= 1;
            }
            if em_len < h_len + 2 {
                raise_site(&err_sites::RSA_PSS_227);
                break 'body false;
            }
            if s_len == RSA_PSS_SALTLEN_MAX {
                s_len = em_len - h_len - 2;
                if s_len_max >= 0 && s_len > s_len_max {
                    s_len = s_len_max;
                }
            } else if s_len > em_len - h_len - 2 {
                raise_site(&err_sites::RSA_PSS_235);
                break 'body false;
            }
            if s_len > 0 {
                salt = CRYPTO_malloc(s_len as usize, FILE, LINE).cast::<c_uchar>();
                if salt.is_null() {
                    break 'body false;
                }
                // SAFETY: `salt` is writable for `s_len` bytes and `rsa` is live; the context is
                // the object's own, which is the `_ex`-less half of the pair's whole point.
                if RAND_bytes_ex((*rsa).libctx, salt, s_len as usize, 0) <= 0 {
                    break 'body false;
                }
            }
            let masked_dblen = em_len - h_len - 1;
            let h = em.offset(masked_dblen as isize);

            ctx = EVP_MD_CTX_new();
            if ctx.is_null() {
                break 'body false;
            }
            if EVP_DigestInit_ex(ctx, hash, core::ptr::null_mut()) == 0
                || EVP_DigestUpdate(ctx, ZEROES.as_ptr().cast(), ZEROES.len()) == 0
                || EVP_DigestUpdate(ctx, m_hash.cast(), h_len as usize) == 0
            {
                break 'body false;
            }
            if s_len != 0 && EVP_DigestUpdate(ctx, salt.cast_const().cast(), s_len as usize) == 0 {
                break 'body false;
            }
            if EVP_DigestFinal_ex(ctx, h, core::ptr::null_mut()) == 0 {
                break 'body false;
            }

            // Generate dbMask in place then perform XOR on it.
            if PKCS1_MGF1(em, masked_dblen as c_long, h, h_len as c_long, mgf1_hash) != 0 {
                break 'body false;
            }

            let mut p = em;
            // Initial PS XORs with all zeroes which is a NOP so just update pointer. Note from a
            // test above this value is guaranteed to be non-negative.
            p = p.offset((em_len - s_len - h_len - 2) as isize);
            *p ^= 0x1;
            p = p.offset(1);
            if s_len > 0 {
                let mut i: c_int = 0;
                while i < s_len {
                    *p ^= *salt.offset(i as isize);
                    p = p.offset(1);
                    i += 1;
                }
            }
            if msbits != 0 {
                *em &= (0xff >> (8 - msbits)) as u8;
            }

            // H is already in place so just set final 0xbc.
            *em.offset((em_len - 1) as isize) = 0xbc;

            *s_len_out = s_len;
            true
        };

        // The authority's `err:` label. `sLen` here is the *resolved* value, which is what the
        // authority's `(size_t)sLen` sees too; `salt != NULL` implies it is positive.
        EVP_MD_CTX_free(ctx);
        CRYPTO_clear_free(salt.cast(), s_len as usize, FILE, LINE);
        if completed {
            1
        } else {
            0
        }
    }
}

// =============================================================================================
// The PSS parameter object
// =============================================================================================

/// `static const RSA_PSS_PARAMS_30 default_RSASSA_PSS_params` — `rsa_pss.c:314-322`.
///
/// RFC 8017 A.2.3's `rSASSA-PSS-Default-Identifier`: SHA-1 for `hashAlgorithm`, MGF1 with SHA-1
/// for `maskGenAlgorithm`, a salt length of 20 and `trailerFieldBC`. The authority's comment
/// quotes the ASN.1 identifier those four values come from, and every accessor below falls back
/// to this object when handed a NULL one — which is what makes
/// `ossl_rsa_pss_params_30_hashalg(NULL)` an answer rather than a refusal.
const DEFAULT_RSASSA_PSS_PARAMS: RsaPssParams30 = RsaPssParams30 {
    hash_algorithm_nid: NID_sha1,
    mask_gen: RsaPssMaskGen {
        algorithm_nid: NID_mgf1,
        hash_algorithm_nid: NID_sha1,
    },
    salt_len: 20,
    trailer_field: 1,
};

/// `int ossl_rsa_pss_params_30_set_defaults(RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:324-330`. Internal.
///
/// A NULL object is a **refusal** (0), unlike every accessor below: the setter has nothing to
/// write to, and the authority answers rather than silently succeeding.
///
/// `#[allow(dead_code)]`'s reason: **its readers are `crypto/rsa/rsa_backend.c`'s
/// `ossl_rsa_pss_params_30_fromdata` and `ossl_rsa_sync_to_pss_params_30`**, both of which this
/// commit lands — the chain is unreached until 8.8's method objects and the provider keymgmt
/// call them.
///
/// # Safety
/// `rsa_pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's PSS parameter codecs; unreached until 8.8
pub(crate) unsafe fn ossl_rsa_pss_params_30_set_defaults(
    rsa_pss_params: *mut RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 0;
    }
    // SAFETY: `rsa_pss_params` is writable per the contract.
    unsafe { *rsa_pss_params = DEFAULT_RSASSA_PSS_PARAMS };
    1
}

/// `int ossl_rsa_pss_params_30_is_unrestricted(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:332-342`. Internal.
///
/// **The authority's `memcmp` against a zeroed `static` is written out as the field test it is.**
/// `RSA_PSS_PARAMS_30` is five four-byte `int`s with no padding — `src/rsa/mod.rs` asserts the
/// twenty-byte layout — so a byte comparison against twenty zeroes is exactly "all five are
/// zero", and a NULL object is unrestricted by the first arm.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_is_unrestricted(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 1;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    let p = unsafe { &*rsa_pss_params };
    let zeroed = p.hash_algorithm_nid == 0
        && p.mask_gen.algorithm_nid == 0
        && p.mask_gen.hash_algorithm_nid == 0
        && p.salt_len == 0
        && p.trailer_field == 0;
    if zeroed {
        1
    } else {
        0
    }
}

/// `int ossl_rsa_pss_params_30_copy(RSA_PSS_PARAMS_30 *to, const RSA_PSS_PARAMS_30 *from)` —
/// `rsa_pss.c:344-349`. Internal.
///
/// The authority's body is a single `memcpy` and an unconditional `return 1` — **there is no NULL
/// check on either side**, which is recorded here rather than added: a caller that passes NULL is
/// undefined behaviour in the authority too, and a transcription that defended against it would
/// be a different function.
///
/// # Safety
/// `to` is writable and `from` readable, each for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by 8.8's rsa_ameth.c callbacks and the provider keymgmt
pub(crate) unsafe fn ossl_rsa_pss_params_30_copy(
    to: *mut RsaPssParams30,
    from: *const RsaPssParams30,
) -> c_int {
    // SAFETY: both sides are valid for the object's size per the contract.
    unsafe { *to = *from };
    1
}

/// `int ossl_rsa_pss_params_30_set_hashalg(RSA_PSS_PARAMS_30 *rsa_pss_params, int hashalg_nid)`
/// — `rsa_pss.c:351-358`. Internal. One store, or 0 for a NULL object.
///
/// # Safety
/// `rsa_pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by 8.8's rsa_ameth.c callbacks and the provider keymgmt
pub(crate) unsafe fn ossl_rsa_pss_params_30_set_hashalg(
    rsa_pss_params: *mut RsaPssParams30,
    hashalg_nid: c_int,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 0;
    }
    // SAFETY: `rsa_pss_params` is writable per the contract.
    unsafe { (*rsa_pss_params).hash_algorithm_nid = hashalg_nid };
    1
}

/// `int ossl_rsa_pss_params_30_set_maskgenhashalg(RSA_PSS_PARAMS_30 *rsa_pss_params, int
/// maskgenhashalg_nid)` — `rsa_pss.c:360-367`. Internal.
///
/// Note which member this writes: the MGF's **hash**, not its algorithm identifier — there is no
/// setter for `mask_gen.algorithm_nid` in the file at all, because MGF1 is the only mask
/// generation function RFC 8017 defines and the field is only ever read.
///
/// # Safety
/// `rsa_pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_sync_to_pss_params_30`
pub(crate) unsafe fn ossl_rsa_pss_params_30_set_maskgenhashalg(
    rsa_pss_params: *mut RsaPssParams30,
    maskgenhashalg_nid: c_int,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 0;
    }
    // SAFETY: `rsa_pss_params` is writable per the contract.
    unsafe { (*rsa_pss_params).mask_gen.hash_algorithm_nid = maskgenhashalg_nid };
    1
}

/// `int ossl_rsa_pss_params_30_set_saltlen(RSA_PSS_PARAMS_30 *rsa_pss_params, int saltlen)` —
/// `rsa_pss.c:369-376`. Internal.
///
/// # Safety
/// `rsa_pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by 8.8's rsa_ameth.c callbacks and the provider keymgmt
pub(crate) unsafe fn ossl_rsa_pss_params_30_set_saltlen(
    rsa_pss_params: *mut RsaPssParams30,
    saltlen: c_int,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 0;
    }
    // SAFETY: `rsa_pss_params` is writable per the contract.
    unsafe { (*rsa_pss_params).salt_len = saltlen };
    1
}

/// `int ossl_rsa_pss_params_30_set_trailerfield(RSA_PSS_PARAMS_30 *rsa_pss_params, int
/// trailerfield)` — `rsa_pss.c:378-385`. Internal.
///
/// # Safety
/// `rsa_pss_params` is NULL or writable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_sync_to_pss_params_30`
pub(crate) unsafe fn ossl_rsa_pss_params_30_set_trailerfield(
    rsa_pss_params: *mut RsaPssParams30,
    trailerfield: c_int,
) -> c_int {
    if rsa_pss_params.is_null() {
        return 0;
    }
    // SAFETY: `rsa_pss_params` is writable per the contract.
    unsafe { (*rsa_pss_params).trailer_field = trailerfield };
    1
}

/// `int ossl_rsa_pss_params_30_hashalg(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:387-392`. Internal.
///
/// **The defaults are read through the *constant*, not through a temporary.** A NULL object
/// answers `DEFAULT_RSASSA_PSS_PARAMS.hash_algorithm_nid`; the caller never sees NULL and never
/// sees a partially-initialised object.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_hashalg(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return DEFAULT_RSASSA_PSS_PARAMS.hash_algorithm_nid;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    unsafe { (*rsa_pss_params).hash_algorithm_nid }
}

/// `int ossl_rsa_pss_params_30_maskgenalg(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:394-399`. Internal. Always `NID_mgf1` in the authority, defaulted or stored.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_maskgenalg(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return DEFAULT_RSASSA_PSS_PARAMS.mask_gen.algorithm_nid;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    unsafe { (*rsa_pss_params).mask_gen.algorithm_nid }
}

/// `int ossl_rsa_pss_params_30_maskgenhashalg(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:401-406`. Internal.
///
/// **The default this returns is `hash_algorithm_nid`, not `mask_gen.hash_algorithm_nid`** --
/// `default_RSASSA_PSS_params.hash_algorithm_nid` is what the authority's body names, and in the
/// default object the two happen to be equal (both `NID_sha1`). A transcription that reached for
/// the more obvious-looking field would be right for this constant and wrong for the next.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_maskgenhashalg(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return DEFAULT_RSASSA_PSS_PARAMS.hash_algorithm_nid;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    unsafe { (*rsa_pss_params).mask_gen.hash_algorithm_nid }
}

/// `int ossl_rsa_pss_params_30_saltlen(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:408-413`. Internal.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_saltlen(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return DEFAULT_RSASSA_PSS_PARAMS.salt_len;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    unsafe { (*rsa_pss_params).salt_len }
}

/// `int ossl_rsa_pss_params_30_trailerfield(const RSA_PSS_PARAMS_30 *rsa_pss_params)` —
/// `rsa_pss.c:415-420`. Internal.
///
/// # Safety
/// `rsa_pss_params` is NULL or readable for `sizeof(RSA_PSS_PARAMS_30)` bytes.
#[allow(dead_code)] // read by rsa_backend.c's `ossl_rsa_pss_params_30_todata`
pub(crate) unsafe fn ossl_rsa_pss_params_30_trailerfield(
    rsa_pss_params: *const RsaPssParams30,
) -> c_int {
    if rsa_pss_params.is_null() {
        return DEFAULT_RSASSA_PSS_PARAMS.trailer_field;
    }
    // SAFETY: `rsa_pss_params` is readable per the contract.
    unsafe { (*rsa_pss_params).trailer_field }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default identifier's four values, read through each accessor with a NULL object —
    /// which is the arm every one of them must answer from. The trailer field is `1`
    /// (`trailerFieldBC`) and the salt length is `20`, and both are asserted because they are
    /// what a PSS-encoded block's last octet and salt width come from.
    #[test]
    fn the_defaults_are_rfc8017_a23s() {
        let null: *const RsaPssParams30 = core::ptr::null();
        // SAFETY: every accessor accepts NULL by contract.
        unsafe {
            assert_eq!(ossl_rsa_pss_params_30_hashalg(null), NID_sha1);
            assert_eq!(ossl_rsa_pss_params_30_maskgenalg(null), NID_mgf1);
            assert_eq!(ossl_rsa_pss_params_30_maskgenhashalg(null), NID_sha1);
            assert_eq!(ossl_rsa_pss_params_30_saltlen(null), 20);
            assert_eq!(ossl_rsa_pss_params_30_trailerfield(null), 1);
        }
        assert_eq!(DEFAULT_RSASSA_PSS_PARAMS.salt_len, 20);
    }

    /// A zeroed object is unrestricted and a defaulted one is not; a NULL one is. That is the
    /// `memcmp` the authority performs, checked in the three directions it can answer.
    #[test]
    fn unrestricted_is_the_all_zero_object_and_not_the_default_one() {
        let mut zeroed = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: 0,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut defaulted = DEFAULT_RSASSA_PSS_PARAMS;
        // SAFETY: both objects are live for the duration of the calls.
        unsafe {
            assert_eq!(ossl_rsa_pss_params_30_is_unrestricted(core::ptr::null()), 1);
            assert_eq!(ossl_rsa_pss_params_30_is_unrestricted(&zeroed), 1);
            assert_eq!(ossl_rsa_pss_params_30_is_unrestricted(&defaulted), 0);
            // One non-zero field is enough: the comparison is over the whole object.
            zeroed.salt_len = 1;
            assert_eq!(ossl_rsa_pss_params_30_is_unrestricted(&zeroed), 0);
            assert_eq!(ossl_rsa_pss_params_30_set_defaults(&mut defaulted), 1);
            assert_eq!(ossl_rsa_pss_params_30_saltlen(&defaulted), 20);
        }
    }

    /// The setter/accessor pairs, and the NULL-object refusal: the four setters speak 0 for a
    /// NULL object and 1 for a live one, while `copy` has no guard at all.
    #[test]
    fn the_setters_store_and_the_accessors_read_them_back() {
        let mut p = RsaPssParams30 {
            hash_algorithm_nid: 0,
            mask_gen: RsaPssMaskGen {
                algorithm_nid: NID_mgf1,
                hash_algorithm_nid: 0,
            },
            salt_len: 0,
            trailer_field: 0,
        };
        let mut dst = p;
        // SAFETY: both objects are live and every call is the setter's documented contract.
        unsafe {
            assert_eq!(ossl_rsa_pss_params_30_set_hashalg(&mut p, 672), 1);
            assert_eq!(ossl_rsa_pss_params_30_set_maskgenhashalg(&mut p, 673), 1);
            assert_eq!(ossl_rsa_pss_params_30_set_saltlen(&mut p, 32), 1);
            assert_eq!(ossl_rsa_pss_params_30_set_trailerfield(&mut p, 1), 1);
            assert_eq!(ossl_rsa_pss_params_30_hashalg(&p), 672);
            assert_eq!(ossl_rsa_pss_params_30_maskgenhashalg(&p), 673);
            assert_eq!(ossl_rsa_pss_params_30_maskgenalg(&p), NID_mgf1);
            assert_eq!(ossl_rsa_pss_params_30_saltlen(&p), 32);
            assert_eq!(ossl_rsa_pss_params_30_trailerfield(&p), 1);
            assert_eq!(ossl_rsa_pss_params_30_copy(&mut dst, &p), 1);
            assert_eq!(ossl_rsa_pss_params_30_hashalg(&dst), 672);
            assert_eq!(ossl_rsa_pss_params_30_saltlen(&dst), 32);
            // The `_30_` accessors' NULL refusals: the four setters answer 0.
            assert_eq!(
                ossl_rsa_pss_params_30_set_defaults(core::ptr::null_mut()),
                0
            );
            assert_eq!(
                ossl_rsa_pss_params_30_set_hashalg(core::ptr::null_mut(), 1),
                0
            );
            assert_eq!(
                ossl_rsa_pss_params_30_set_maskgenhashalg(core::ptr::null_mut(), 1),
                0
            );
            assert_eq!(
                ossl_rsa_pss_params_30_set_saltlen(core::ptr::null_mut(), 1),
                0
            );
            assert_eq!(
                ossl_rsa_pss_params_30_set_trailerfield(core::ptr::null_mut(), 1),
                0
            );
        }
    }
}
