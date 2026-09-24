//! `crypto/rsa/rsa_sign.c` and `crypto/rsa/rsa_saos.c` — the two signing entry points and the
//! DigestInfo encodings they share (Phase 8.4, slice D's remainder).
//!
//! **Six exports and three internals, over two translation units, and the dominant one is
//! `rsa_sign.c`.** `rsa_sign.c` defines `RSA_sign`, `RSA_verify` and the two internals
//! `ossl_rsa_digestinfo_encoding` and `ossl_rsa_verify`; `rsa_saos.c` defines
//! `RSA_sign_ASN1_OCTET_STRING` and `RSA_verify_ASN1_OCTET_STRING` and nothing else, and its two
//! bodies are the same shape as `rsa_sign.c`'s -- build an encoding, hand it to
//! `RSA_private_encrypt`, compare on the way back -- so they are written here rather than in a
//! module of their own, which is the `rsa_gen.c`/`rsa_depr.c` and
//! `rsa_sp800_56b_gen.c`/`rsa_sp800_56b_check.c` precedent.
//!
//! **`ossl_rsa_verify` is the internal, and `RSA_verify` is a two-line door onto it.** The door
//! exists for one reason the *reader* of this module needs to see: `rsa->meth->rsa_verify` is
//! consulted first, so an `RSA_METHOD` with a verify callback replaces the whole construction. The
//! default table leaves it `None` (`D284`), which is why the arithmetic below is what a caller of
//! `RSA_verify` actually runs.
//!
//! **The DigestInfo prefixes are DER built by hand, and the court proves them byte for byte.** Each
//! table is `SEQUENCE { SEQUENCE { OID, NULL } OCTET STRING(len) }` with the digest's content
//! appended by the caller, so the length octets are computed rather than typed: the outer length is
//! `0x11 + sz` for a SHA-2/SHA-3 OID and `0x10 + sz` for the three MD-syntax OIDs (`0x11` and `0x10`
//! are the same "twenty-one or twenty" the authority's macros write). A transcription error here
//! would still round-trip against itself, so it is `RT-RSA`'s **deterministic** signature arm --
//! a fixed key and a fixed message make `RSA_sign` a fixed byte string -- that is the check.
//!
//! **The hash-id NID digests are the same numbers `RSA_X931_hash_id` uses, and the two disagree on
//! purpose.** `RSA_X931_hash_id` maps BOTH `NID_sha1`-family ids *and* the `sha512_224`/`sha512_256`
//! ids that the X9.31 standard assigns, and it refuses everything it does not know; the tables here
//! add the SM3 and MD2/MD4 families, which X9.31 has no hash id for, and they refuse with
//! `RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD` rather than with an empty queue.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint};

use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::typ::{d2i_ASN1_OCTET_STRING, i2d_ASN1_OCTET_STRING};
use crate::digest::sha2::{
    SHA224_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_md2, NID_md4, NID_md5};
use crate::runtime::obj::{
    NID_md5_sha1, NID_mdc2, NID_ripemd160, NID_sha1, NID_sha224, NID_sha256, NID_sha384,
    NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha512, NID_sha512_224,
    NID_sha512_256, NID_sm3, NID_undef,
};

use crate::evp::pkey_ctx::RSA_PKCS1_PADDING;
use crate::rsa::object::{RSA_private_encrypt, RSA_public_decrypt, RSA_size};
use crate::rsa::{Rsa, RSA_PKCS1_PADDING_SIZE};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/rsa/rsa_sign.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — measured with `strings` on
/// `build/.../crypto/rsa/libcrypto-lib-rsa_sign.o`, the same check D279/D280 applied to the cipher
/// units. `RSA_sign`'s `encode_pkcs1` buffer and `ossl_rsa_verify`'s two are attributed here.
const FILE_SIGN: *const c_char = c"../../src/openssl-3.6.4/crypto/rsa/rsa_sign.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `MD2_DIGEST_LENGTH` — `include/openssl/md2.h:27`. Declared here rather than imported because
/// **the crate has no MD2 unit at all**: `crypto/md2/` is not one of 8.1's labels, and the object
/// table has no `md2.h` row, so no module defines this name. `rsa_sign.c` includes `<openssl/md2.h>`
/// for exactly this constant and nothing else, so the constant is what this file owes.
const MD2_DIGEST_LENGTH: usize = 16;

/// `MD4_DIGEST_LENGTH` — `include/openssl/md4.h`. Declared here for the same reason as
/// [`MD2_DIGEST_LENGTH`]: `rsa_sign.c` is that constant's first reader in this stratum, and no other
/// module declares it. (`MD4_DIGEST_LENGTH` is `MD4_CBLOCK`, sixteen, like every other MD-family
/// digest here.)
const MD4_DIGEST_LENGTH: usize = 16;

/// `RIPEMD160_DIGEST_LENGTH` — `include/openssl/ripemd.h:25`. `src/evp/legacy_ripemd.rs` declares it
/// privately for its own `EVP_ripemd160()` accessor, and `rsa_sign.c` gets it from `<openssl/ripemd.h>`
/// like every other digest length it uses; the crate's convention for such a constant is one
/// private copy per reader rather than one shared `pub(crate)`, which is what `RSA_PKCS1_PADDING_SIZE`
/// and `BN_FLG_CONSTTIME` also do.
const RIPEMD160_DIGEST_LENGTH: usize = 20;

// =============================================================================================
// The DigestInfo encodings — `rsa_sign.c:74-243`
// =============================================================================================
//
// The four `ASN1_*` tags the authority names before its two macros, kept as names because the
// tables below are read against the authority's text.
const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_OCTET_STRING: u8 = 0x04;
const ASN1_NULL: u8 = 0x05;
const ASN1_OID: u8 = 0x06;

/* SHA OIDs are of the form: (2 16 840 1 101 3 4 2 |n|) */
/* MD2, MD4 and MD5 OIDs are of the form: (1 2 840 113549 2 |n|) */

/// `ENCODE_DIGESTINFO_SHA(sha1, ...)`'s hand-written neighbour, `rsa_sign.c:141-148`. SHA-1's OID is
/// `1 3 14 3 2 26` — the one SHA-family OID that is *not* the `2 16 840 1 101 3 4 2 |n|` form, which
/// is why it is written out rather than produced by the macro the ten below it share.
static DIGESTINFO_SHA1_DER: [u8; 15] = [
    ASN1_SEQUENCE,
    0x0d + 20,
    ASN1_SEQUENCE,
    0x09,
    ASN1_OID,
    0x05,
    40 + 3, /* `1 * 40 + 3`; clippy's `identity_op` refuses the literal spelling */
    14,
    3,
    2,
    26,
    ASN1_NULL,
    0x00,
    ASN1_OCTET_STRING,
    20,
];

/// `ENCODE_DIGESTINFO_SHA(name, n, sz)` — `rsa_sign.c:80-87`, expanded ten times by the authority.
///
/// The macro is not reproduced as a macro: the crate has no macro layer over tables, and the
/// authority expands it at each use, so each table is written out with its own `n` and `sz`. The
/// OID's last octet is `n` and its length octets are `0x11 + sz` and `0x0d` — fixed, because the OID
/// and the `NULL` parameters are fixed and only the `OCTET STRING` header's length varies.
macro_rules! digestinfo_sha {
    ($name:ident, $n:expr, $sz:expr) => {
        static $name: [u8; 19] = [
            ASN1_SEQUENCE,
            0x11 + $sz,
            ASN1_SEQUENCE,
            0x0d,
            ASN1_OID,
            0x09,
            2 * 40 + 16,
            0x86,
            0x48,
            1,
            101,
            3,
            4,
            2,
            $n,
            ASN1_NULL,
            0x00,
            ASN1_OCTET_STRING,
            $sz,
        ];
    };
}

digestinfo_sha!(DIGESTINFO_SHA256_DER, 0x01, 32);
digestinfo_sha!(DIGESTINFO_SHA384_DER, 0x02, 48);
digestinfo_sha!(DIGESTINFO_SHA512_DER, 0x03, 64);
digestinfo_sha!(DIGESTINFO_SHA224_DER, 0x04, 28);
digestinfo_sha!(DIGESTINFO_SHA512_224_DER, 0x05, 28);
digestinfo_sha!(DIGESTINFO_SHA512_256_DER, 0x06, 32);
digestinfo_sha!(DIGESTINFO_SHA3_224_DER, 0x07, 28);
digestinfo_sha!(DIGESTINFO_SHA3_256_DER, 0x08, 32);
digestinfo_sha!(DIGESTINFO_SHA3_384_DER, 0x09, 48);
digestinfo_sha!(DIGESTINFO_SHA3_512_DER, 0x0a, 64);

/// `ENCODE_DIGESTINFO_MD(name, n, sz)` — `rsa_sign.c:90-97`, expanded three times by the authority.
/// Same shape as [`digestinfo_sha!`] with the `1 2 840 113549 2 |n|` OID and the `0x10 + sz` outer
/// length.
macro_rules! digestinfo_md {
    ($name:ident, $n:expr, $sz:expr) => {
        static $name: [u8; 18] = [
            ASN1_SEQUENCE,
            0x10 + $sz,
            ASN1_SEQUENCE,
            0x0c,
            ASN1_OID,
            0x08,
            40 + 2, /* `1 * 40 + 2`; see `DIGESTINFO_SHA1_DER` */
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            2,
            $n,
            ASN1_NULL,
            0x00,
            ASN1_OCTET_STRING,
            $sz,
        ];
    };
}

digestinfo_md!(DIGESTINFO_MD2_DER, 0x02, 16);
digestinfo_md!(DIGESTINFO_MD4_DER, 0x03, 16);
digestinfo_md!(DIGESTINFO_MD5_DER, 0x05, 16);

/// MDC-2 (2 5 8 3 101) — `rsa_sign.c:111-117`.
static DIGESTINFO_MDC2_DER: [u8; 14] = [
    ASN1_SEQUENCE,
    0x0c + 16,
    ASN1_SEQUENCE,
    0x08,
    ASN1_OID,
    0x04,
    2 * 40 + 5,
    8,
    3,
    101,
    ASN1_NULL,
    0x00,
    ASN1_OCTET_STRING,
    16,
];

/// RIPEMD160 (1 3 36 3 2 1) — `rsa_sign.c:121-127`.
static DIGESTINFO_RIPEMD160_DER: [u8; 15] = [
    ASN1_SEQUENCE,
    0x0d + 20,
    ASN1_SEQUENCE,
    0x09,
    ASN1_OID,
    0x05,
    40 + 3, /* `1 * 40 + 3`; see `DIGESTINFO_SHA1_DER` */
    36,
    3,
    2,
    1,
    ASN1_NULL,
    0x00,
    ASN1_OCTET_STRING,
    20,
];

/// SM3 (1 2 156 10197 1 401) — `rsa_sign.c:131-137`.
static DIGESTINFO_SM3_DER: [u8; 18] = [
    ASN1_SEQUENCE,
    0x10 + 32,
    ASN1_SEQUENCE,
    0x0c,
    ASN1_OID,
    0x08,
    40 + 2, /* `1 * 40 + 2`; see `DIGESTINFO_SHA1_DER` */
    0x81,
    0x1c,
    0xcf,
    0x55,
    1,
    0x83,
    0x78,
    ASN1_NULL,
    0x00,
    ASN1_OCTET_STRING,
    32,
];

/// `const unsigned char *ossl_rsa_digestinfo_encoding(int md_nid, size_t *len)` —
/// `rsa_sign.c:166-203`.
///
/// Internal, declared in `include/crypto/rsa.h`, and the one table both signing families read:
/// `encode_pkcs1` below is its caller for the `RSA_sign` path, and `rsa_ameth.c`'s own
/// `rsa_priv_encode`/`rsa_pub_encode` are its callers for the ASN.1 method path. It answers NULL for
/// a NID it has no table for, and the *caller* decides what that means (`encode_pkcs1` raises).
///
/// **The `#ifndef FIPS_MODULE` guard around the MD and SM3 cases is not reproduced**, and the reason
/// is the crate's: this build has no FIPS branch, so `FIPS_MODULE` is undefined and every case
/// compiles. The two `MD_CASE` arms for `sha1` and its neighbours sit outside the guard in the
/// authority and are unconditional here too.
///
/// **`len` is written even though the answer may be NULL**: the authority's `MD_CASE` stores the
/// size and returns the pointer, and the NULL path leaves `*len` untouched. Both are transcribed,
/// so a caller that reads `*len` after a NULL answer reads its own uninitialised value there as
/// well.
///
/// # Safety
/// `len` is a live `size_t` the callee writes on every non-NULL answer.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
pub(crate) unsafe fn ossl_rsa_digestinfo_encoding(
    md_nid: c_int,
    len: *mut usize,
) -> *const c_uchar {
    // SAFETY: the caller's contract; every pointer written into `len` is a static table.
    unsafe {
        macro_rules! md_case {
            ($nid:expr, $der:expr) => {
                if md_nid == $nid {
                    *len = $der.len();
                    return $der.as_ptr();
                }
            };
        }

        md_case!(NID_mdc2, DIGESTINFO_MDC2_DER);
        md_case!(NID_md2, DIGESTINFO_MD2_DER);
        md_case!(NID_md4, DIGESTINFO_MD4_DER);
        md_case!(NID_md5, DIGESTINFO_MD5_DER);
        md_case!(NID_ripemd160, DIGESTINFO_RIPEMD160_DER);
        md_case!(NID_sm3, DIGESTINFO_SM3_DER);
        md_case!(NID_sha1, DIGESTINFO_SHA1_DER);
        md_case!(NID_sha224, DIGESTINFO_SHA224_DER);
        md_case!(NID_sha256, DIGESTINFO_SHA256_DER);
        md_case!(NID_sha384, DIGESTINFO_SHA384_DER);
        md_case!(NID_sha512, DIGESTINFO_SHA512_DER);
        md_case!(NID_sha512_224, DIGESTINFO_SHA512_224_DER);
        md_case!(NID_sha512_256, DIGESTINFO_SHA512_256_DER);
        md_case!(NID_sha3_224, DIGESTINFO_SHA3_224_DER);
        md_case!(NID_sha3_256, DIGESTINFO_SHA3_256_DER);
        md_case!(NID_sha3_384, DIGESTINFO_SHA3_384_DER);
        md_case!(NID_sha3_512, DIGESTINFO_SHA3_512_DER);
        core::ptr::null()
    }
}

/// `static int digest_sz_from_nid(int nid)` — `rsa_sign.c:209-243`.
///
/// The *length* table, read by `ossl_rsa_verify` only when it is recovering a digest and therefore
/// has no caller-supplied length. It is a second table rather than a read of the first because the
/// authority wrote it that way, and the two disagree in one visible place: **`sha512_224` answers
/// `SHA224_DIGEST_LENGTH` and `sha512_256` answers `SHA256_DIGEST_LENGTH`**, not 64 — the truncated
/// variants are named for what they are, and their truncated code lengths are what the two
/// functions retrieve.
///
/// **SM3 is absent and MDC-2 is absent**, which is the authority's own asymmetry: the *encoding*
/// table has both, and this one does not, so `ossl_rsa_verify(..., rm != NULL)` refuses an SM3 or
/// MDC-2 recovery with `0` and an **empty queue** before `encode_pkcs1` is ever reached.
fn digest_sz_from_nid(nid: c_int) -> c_int {
    macro_rules! md_nid_case {
        ($nid:expr, $sz:expr) => {
            if nid == $nid {
                return $sz;
            }
        };
    }

    md_nid_case!(NID_mdc2, 16);
    md_nid_case!(NID_md2, MD2_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_md4, MD4_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_md5, 16);
    md_nid_case!(NID_ripemd160, RIPEMD160_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha1, 20);
    md_nid_case!(NID_sha224, SHA224_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha256, SHA256_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha384, SHA384_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha512, SHA512_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha512_224, SHA224_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha512_256, SHA256_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha3_224, SHA224_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha3_256, SHA256_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha3_384, SHA384_DIGEST_LENGTH as c_int);
    md_nid_case!(NID_sha3_512, SHA512_DIGEST_LENGTH as c_int);
    0
}

/// `static int encode_pkcs1(unsigned char **out, size_t *out_len, int type,`
/// `const unsigned char *m, size_t m_len)` — `rsa_sign.c:257-284`.
///
/// EMSA-PKCS1-v1_5-ENCODE's step 2 (RFC 3447 section 9.2): the DigestInfo *without* the padding, in
/// a freshly allocated buffer the caller releases with `OPENSSL_clear_free`. Two refusals, and they
/// are different reasons because `NID_undef` is a caller passing no algorithm at all while an
/// unknown nonzero NID is a caller passing one this build cannot encode.
///
/// **`NID_undef` is tested before the table is consulted**, so `ossl_rsa_digestinfo_encoding`'s NULL
/// answer and the `type == NID_undef` case do not share a reason: the first is
/// `RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD` and the second is
/// `RSA_R_UNKNOWN_ALGORITHM_TYPE`.
///
/// # Safety
/// `out` and `out_len` are live; `m` is readable for `m_len` bytes. On success `*out` is a caller
/// allocation of `*out_len` bytes and on failure it is left untouched.
unsafe fn encode_pkcs1(
    out: *mut *mut c_uchar,
    out_len: *mut usize,
    type_: c_int,
    m: *const c_uchar,
    m_len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut di_prefix_len: usize = 0;

        if type_ == NID_undef {
            raise_site(&err_sites::RSA_SIGN_265);
            return 0;
        }
        // SAFETY: `di_prefix_len` is a live local.
        let di_prefix = ossl_rsa_digestinfo_encoding(type_, &mut di_prefix_len);
        if di_prefix.is_null() {
            raise_site(&err_sites::RSA_SIGN_270);
            return 0;
        }
        let dig_info_len = di_prefix_len + m_len;
        let dig_info = CRYPTO_malloc(dig_info_len, FILE_SIGN, LINE).cast::<c_uchar>();
        if dig_info.is_null() {
            return 0;
        }
        // SAFETY: `dig_info` is writable for `dig_info_len` bytes, `di_prefix` is readable for
        // `di_prefix_len` and `m` for `m_len`.
        core::ptr::copy_nonoverlapping(di_prefix, dig_info, di_prefix_len);
        core::ptr::copy_nonoverlapping(m, dig_info.add(di_prefix_len), m_len);

        *out = dig_info;
        *out_len = dig_info_len;
        1
    }
}

/// `SSL_SIG_LENGTH` — `rsa_sign.c:246`. The MD5/SHA-1 concatenation's width, and the only message
/// length `NID_md5_sha1` accepts.
const SSL_SIG_LENGTH: usize = 36;

/// `int RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret,`
/// `unsigned int *siglen, RSA *rsa)` — `rsa_sign.c:286-333`.
///
/// **The method's callback wins, and that is the first statement.** `rsa->meth->rsa_sign` is the
/// integer `0` in the authority's two own tables (`D284`), so the arithmetic below is what runs for
/// every key this build can construct — but a table a caller installs replaces all of it, and the
/// callback's answer is *tested* rather than returned, so a callback that answers `-1` is a
/// success with `siglen` left alone.
///
/// **`NID_md5_sha1` has no DigestInfo and is the TLS 1.1 case.** It is
/// `RSASSA-PKCS1-v1_5` over the raw 36-octet concatenation, and the length is checked *before* any
/// allocation, which is why `RSA_R_INVALID_MESSAGE_LENGTH` is reachable with an empty heap.
///
/// **The size test compares `encoded_len + 11` against `RSA_size`, so the padding is counted.** A
/// digest exactly eleven octets shorter than the modulus is accepted, and one octet longer is
/// `RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY`. The `(size_t)` cast on `RSA_size` is the authority's and it
/// matters: `RSA_size` is an `int` and a negative `encoded_len` cannot occur, but the comparison is
/// unsigned in C.
///
/// # Safety
/// `rsa` is a live object whose method table is non-NULL; `m` is readable for `m_len` bytes;
/// `sigret` is writable for `RSA_size(rsa)` bytes; `siglen` is a live `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn RSA_sign(
    type_: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut encoded_len: usize = 0;
        let mut tmps: *mut c_uchar = core::ptr::null_mut();
        let encoded: *const c_uchar;

        // The authority's `#ifndef FIPS_MODULE` arm, which is this build's only arm.
        // SAFETY: `rsa` is live with a method table, whose member is `None` on both of the
        // authority's own tables.
        if let Some(f) = (*(*rsa).meth).rsa_sign {
            // SAFETY: `f` is the method's own callback with this signature's contract.
            return c_int::from(f(type_, m, m_len, sigret, siglen, rsa) > 0);
        }

        // Compute the encoded digest.
        if type_ == NID_md5_sha1 {
            if m_len as usize != SSL_SIG_LENGTH {
                raise_site(&err_sites::RSA_SIGN_307);
                return 0;
            }
            encoded_len = SSL_SIG_LENGTH;
            encoded = m;
        } else {
            // SAFETY: `tmps` and `encoded_len` are live locals.
            if encode_pkcs1(&mut tmps, &mut encoded_len, type_, m, m_len as usize) == 0 {
                // SAFETY: `tmps` is NULL here, which the release tolerates.
                CRYPTO_clear_free(tmps.cast(), encoded_len, FILE_SIGN, LINE);
                return ret;
            }
            encoded = tmps;
        }

        // SAFETY: `rsa` is live.
        if encoded_len + RSA_PKCS1_PADDING_SIZE as usize > RSA_size(rsa) as usize {
            raise_site(&err_sites::RSA_SIGN_319);
        } else {
            // SAFETY: `rsa` is live and `encoded` is readable for `encoded_len` bytes.
            let encrypt_len = RSA_private_encrypt(
                encoded_len as c_int,
                encoded,
                sigret,
                rsa,
                RSA_PKCS1_PADDING,
            );
            if encrypt_len > 0 {
                *siglen = encrypt_len as c_uint;
                ret = 1;
            }
        }

        // SAFETY: `tmps` is this call's own allocation, `encoded_len` its length.
        CRYPTO_clear_free(tmps.cast(), encoded_len, FILE_SIGN, LINE);
        ret
    }
}

/// `int ossl_rsa_verify(int type, const unsigned char *m, unsigned int m_len, unsigned char *rm,`
/// `size_t *prm_len, const unsigned char *sigbuf, size_t siglen, RSA *rsa)` — `rsa_sign.c:344-458`.
/// Internal, declared in `include/crypto/rsa.h`.
///
/// The verify half, and the `rm`/`prm_len` pair is what makes it the internal: a non-NULL `rm` is a
/// **digest recovery**, where the message is not the caller's but the tail of the decrypted block,
/// and the answer is the digest plus its length. `RSA_verify` passes NULL for both.
///
/// **The signature length is checked against `RSA_size` before anything is allocated**, so a wrong
/// length is a refusal with an empty heap. **The two oddball arms are compile-time-visible and
/// both are `#ifndef FIPS_MODULE`**, which is why they are here: `NID_md5_sha1`'s raw comparison and
/// the MDC-2 case where a signature may be a bare `OCTET STRING` (`04 10` then sixteen octets)
/// instead of a DigestInfo.
///
/// **`decrypt_len` is `size_t` and `len` is `int`**, and the authority reuses `len` for
/// `digest_sz_from_nid` in the recovery path. The two conversions are load-bearing: a negative
/// decrypt answer is refused before `decrypt_len` is set, and `m_len > decrypt_len` is an
/// unsigned-wide comparison.
///
/// # Safety
/// `rsa` is a live object; `m` is readable for `m_len` bytes (or NULL when `rm` is non-NULL);
/// `sigbuf` is readable for `siglen` bytes; `rm` is NULL or writable for the digest; `prm_len` is
/// NULL or a live `size_t`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_verify(
    type_: c_int,
    mut m: *const c_uchar,
    mut m_len: c_uint,
    rm: *mut c_uchar,
    prm_len: *mut usize,
    sigbuf: *const c_uchar,
    siglen: usize,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut encoded_len: usize = 0;
        /* Declared without an initialiser: the allocation is the first statement of the block below,
         * so every `break 'body` follows it and Rust's definite-assignment analysis is satisfied
         * -- and the cleanup after the block reads it on the allocation-failure path too. */
        let decrypt_buf: *mut c_uchar;
        let mut encoded: *mut c_uchar = core::ptr::null_mut();

        // SAFETY: `rsa` is live.
        if siglen != RSA_size(rsa) as usize {
            raise_site(&err_sites::RSA_SIGN_353);
            return 0;
        }

        'body: {
            // Recover the encoded digest.
            decrypt_buf = CRYPTO_malloc(siglen, FILE_SIGN, LINE).cast::<c_uchar>();
            if decrypt_buf.is_null() {
                break 'body;
            }

            // SAFETY: `decrypt_buf` is writable for `siglen` bytes.
            let len =
                RSA_public_decrypt(siglen as c_int, sigbuf, decrypt_buf, rsa, RSA_PKCS1_PADDING);
            if len <= 0 {
                break 'body;
            }
            let decrypt_len = len as usize;

            if type_ == NID_md5_sha1 {
                // `NID_md5_sha1` has no DigestInfo wrapper, exactly as in `RSA_sign`.
                if decrypt_len != SSL_SIG_LENGTH {
                    raise_site(&err_sites::RSA_SIGN_376);
                    break 'body;
                }

                if !rm.is_null() {
                    // SAFETY: `rm` is writable for the digest and `decrypt_buf` is readable for
                    // `SSL_SIG_LENGTH`.
                    core::ptr::copy_nonoverlapping(decrypt_buf, rm, SSL_SIG_LENGTH);
                    *prm_len = SSL_SIG_LENGTH;
                } else {
                    if m_len as usize != SSL_SIG_LENGTH {
                        raise_site(&err_sites::RSA_SIGN_385);
                        break 'body;
                    }
                    // SAFETY: `m` is readable for `m_len` bytes and `decrypt_buf` for the same.
                    if core::slice::from_raw_parts(decrypt_buf, SSL_SIG_LENGTH)
                        != core::slice::from_raw_parts(m, SSL_SIG_LENGTH)
                    {
                        raise_site(&err_sites::RSA_SIGN_390);
                        break 'body;
                    }
                }
            } else if type_ == NID_mdc2
                && decrypt_len == 2 + 16
                && *decrypt_buf == 0x04
                && *decrypt_buf.add(1) == 0x10
            {
                // Oddball MDC2 case: signature can be OCTET STRING. Check for correct tag and
                // length octets.
                if !rm.is_null() {
                    // SAFETY: `rm` is writable for sixteen octets and `decrypt_buf + 2` is
                    // readable for the same.
                    core::ptr::copy_nonoverlapping(decrypt_buf.add(2), rm, 16);
                    *prm_len = 16;
                } else {
                    if m_len != 16 {
                        raise_site(&err_sites::RSA_SIGN_405);
                        break 'body;
                    }
                    // SAFETY: `m` is readable for `m_len` bytes and `decrypt_buf + 2` for sixteen.
                    if core::slice::from_raw_parts(m, 16)
                        != core::slice::from_raw_parts(decrypt_buf.add(2), 16)
                    {
                        raise_site(&err_sites::RSA_SIGN_410);
                        break 'body;
                    }
                }
            } else {
                // If recovering the digest, extract a digest-sized output from the end of
                // `decrypt_buf` for `encode_pkcs1`, then compare the decryption output as in a
                // standard verification.
                if !rm.is_null() {
                    let len = digest_sz_from_nid(type_);
                    if len <= 0 {
                        break 'body;
                    }
                    m_len = len as c_uint;
                    if m_len as usize > decrypt_len {
                        raise_site(&err_sites::RSA_SIGN_429);
                        break 'body;
                    }
                    // SAFETY: `decrypt_len >= m_len`, so the offset is inside `decrypt_buf`.
                    m = decrypt_buf.add(decrypt_len - m_len as usize);
                }

                // Construct the encoded digest and ensure it matches.
                // SAFETY: `encoded` and `encoded_len` are live locals.
                if encode_pkcs1(&mut encoded, &mut encoded_len, type_, m, m_len as usize) == 0 {
                    break 'body;
                }

                // SAFETY: `encoded` is readable for `encoded_len` bytes and `decrypt_buf` for
                // `decrypt_len`.
                if encoded_len != decrypt_len
                    || core::slice::from_raw_parts(encoded, encoded_len)
                        != core::slice::from_raw_parts(decrypt_buf, encoded_len)
                {
                    raise_site(&err_sites::RSA_SIGN_441);
                    break 'body;
                }

                // Output the recovered digest.
                if !rm.is_null() {
                    // SAFETY: `rm` is writable for `m_len` bytes and `m` for the same.
                    core::ptr::copy_nonoverlapping(m, rm, m_len as usize);
                    *prm_len = m_len as usize;
                }
            }

            ret = 1;
        }

        // The authority's `err:` label. Both pointers are NULL when the first `goto err` is taken,
        // which `OPENSSL_clear_free` tolerates.
        // SAFETY: both are NULL or this call's own allocations of the stated lengths.
        CRYPTO_clear_free(encoded.cast(), encoded_len, FILE_SIGN, LINE);
        CRYPTO_clear_free(decrypt_buf.cast(), siglen, FILE_SIGN, LINE);
        ret
    }
}

/// `int RSA_verify(int type, const unsigned char *m, unsigned int m_len,`
/// `const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)` — `rsa_sign.c:460-468`.
///
/// Two arms and no arithmetic: the method's `rsa_verify` if it has one, otherwise the internal with
/// both recovery arguments NULL. **The callback's answer is returned directly, not tested**, which
/// is the asymmetry with `RSA_sign` that a comparison of the two doors has to reproduce: a method
/// that answers `-1` here returns `-1` to the caller.
///
/// # Safety
/// `rsa` is a live object whose method table is non-NULL; `m` is readable for `m_len` bytes;
/// `sigbuf` is readable for `siglen` bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_verify(
    type_: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigbuf: *const c_uchar,
    siglen: c_uint,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: `rsa` is live with a method table.
    unsafe {
        if let Some(f) = (*(*rsa).meth).rsa_verify {
            // SAFETY: `f` is the method's own callback with this signature's contract.
            return f(type_, m, m_len, sigbuf, siglen, rsa);
        }
        // SAFETY: the caller's contract, with both recovery arguments NULL.
        ossl_rsa_verify(
            type_,
            m,
            m_len,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            sigbuf,
            siglen as usize,
            rsa,
        )
    }
}

// =============================================================================================
// `crypto/rsa/rsa_saos.c` — the two ASN.1 OCTET STRING signing entry points
// =============================================================================================

/// `int RSA_sign_ASN1_OCTET_STRING(int type, const unsigned char *m, unsigned int m_len,`
/// `unsigned char *sigret, unsigned int *siglen, RSA *rsa)` — `rsa_saos.c:23-55`.
///
/// **`type` is unused, and that is the function's whole difference from `RSA_sign`.** There is no
/// DigestInfo and no algorithm: the message is wrapped in an `ASN1_OCTET_STRING` and the DER is
/// signed directly, which is the shape `X509_REQ` and the old `EVP_SignFinal`-adjacent paths use
/// for an "opaque blob" signature. The parameter is in the signature because the `rsa.h`
/// declaration has it and callers pass a NID; the body never reads it, which is why the
/// transcription binds it as `_type` and the court's two arms pass *different* NIDs to prove it.
///
/// **The two `i2d` calls are the two conventions of the same call.** The first has `out == NULL` and
/// answers the encoded length, which is what the size test compares against
/// `RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE`; the second has `out == &p` and writes the bytes. That
/// double encode is why the allocation is `RSA_size(rsa) + 1` and not `i + 1`.
///
/// **`sig.flags` is not initialised in the authority** — `ASN1_OCTET_STRING sig;` is a stack value
/// with three of its four members written. The primitive encoder reads `flags` only for
/// `V_ASN1_BIT_STRING` (it is that type's unused-bit count), so the uninitialised member is never
/// read for a `V_ASN1_OCTET_STRING`; this transcription writes zero and says so rather than leaving
/// the field undefined in Rust, which has no equivalent of "uninitialised but never read".
///
/// # Safety
/// `rsa` is a live object; `m` is readable for `m_len` bytes; `sigret` is writable for
/// `RSA_size(rsa)` bytes; `siglen` is a live `unsigned int`.
#[no_mangle]
pub unsafe extern "C" fn RSA_sign_ASN1_OCTET_STRING(
    _type: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 1;
        let sig = Asn1String {
            length: m_len as c_int,
            type_: crate::asn1::layout::V_ASN1_OCTET_STRING,
            data: m.cast_mut(),
            flags: 0,
        };

        // SAFETY: `sig` is a live value of the type the item describes; the NULL `out` is the
        // length-query convention.
        let i = i2d_ASN1_OCTET_STRING(&sig, core::ptr::null_mut());
        // SAFETY: `rsa` is live.
        let j = RSA_size(rsa);
        if i > (j - RSA_PKCS1_PADDING_SIZE) {
            raise_site(&err_sites::RSA_SAOS_39);
            return 0;
        }
        // SAFETY: a compile-time-constant site.
        let s = CRYPTO_malloc((j as usize) + 1, FILE_SIGN, LINE).cast::<c_uchar>();
        if s.is_null() {
            return 0;
        }
        let mut p = s;
        // SAFETY: `sig` is live and `p` points at the `j + 1` bytes just allocated, which the
        // length query above proved enough.
        i2d_ASN1_OCTET_STRING(&sig, &mut p);
        // SAFETY: `s` holds the encoding `i` octets long and `sigret` is writable for `RSA_size`.
        let i = RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
        if i <= 0 {
            ret = 0;
        } else {
            *siglen = i as c_uint;
        }

        // SAFETY: `s` is this call's own allocation of `j + 1` bytes.
        CRYPTO_clear_free(s.cast(), (j as usize) + 1, FILE_SIGN, LINE);
        ret
    }
}

/// `int RSA_verify_ASN1_OCTET_STRING(int dtype, const unsigned char *m, unsigned int m_len,`
/// `unsigned char *sigbuf, unsigned int siglen, RSA *rsa)` — `rsa_saos.c:57-94`.
///
/// The read half, and `dtype` is unused for the same reason `RSA_sign_ASN1_OCTET_STRING`'s `type` is.
///
/// **`sigbuf` is `unsigned char *` and not `const unsigned char *`**, which is the header's own
/// asymmetry with `RSA_verify` (where the same argument *is* const). It is read and never written,
/// and the prototype court is what pins the distinction: a transcription that const-qualified it
/// would be a different signature on the ABI surface.
///
/// **The decode is `d2i_ASN1_OCTET_STRING(NULL, &p, i)` and the answer is a *new* object**, freed on
/// both paths. The comparison is a length test *and* a `memcmp`, and only the mismatch raises
/// `RSA_R_BAD_SIGNATURE` — a decode failure leaves `sig == NULL` and goes to the release label with
/// whatever the `d2i` raised, which is why the two failures have different coordinates.
///
/// **`s` is uninitialised before its allocation, and the only path that reaches the release label
/// with it unset is the allocation failure itself.** The authority's early return for the wrong
/// signature length happens *before* `s` exists, so `OPENSSL_clear_free(s, siglen)` is never
/// reached with an indeterminate pointer; the transcription's `s` starts NULL and is set by the
/// allocation, which is the same set of reachable states.
///
/// # Safety
/// `rsa` is a live object; `m` is readable for `m_len` bytes; `sigbuf` is readable for `siglen`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_ASN1_OCTET_STRING(
    _dtype: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigbuf: *mut c_uchar,
    siglen: c_uint,
    rsa: *mut Rsa,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret: c_int = 0;
        let s: *mut c_uchar;
        let mut sig: *mut Asn1String = core::ptr::null_mut();

        // SAFETY: `rsa` is live.
        if siglen != RSA_size(rsa) as c_uint {
            raise_site(&err_sites::RSA_SAOS_68);
            return 0;
        }

        'body: {
            s = CRYPTO_malloc(siglen as usize, FILE_SIGN, LINE).cast::<c_uchar>();
            if s.is_null() {
                break 'body;
            }
            // SAFETY: `s` is writable for `siglen` bytes.
            let i = RSA_public_decrypt(siglen as c_int, sigbuf, s, rsa, RSA_PKCS1_PADDING);

            if i <= 0 {
                break 'body;
            }

            let mut p: *const c_uchar = s;
            // SAFETY: `p` points at `i` readable octets and `i` is positive.
            sig = d2i_ASN1_OCTET_STRING(core::ptr::null_mut(), &mut p, i as c_long);
            if sig.is_null() {
                break 'body;
            }

            // SAFETY: `sig` is a live decoded string whose `data` is readable for `length` bytes.
            if (*sig).length as c_uint != m_len
                || core::slice::from_raw_parts(m, m_len as usize)
                    != core::slice::from_raw_parts((*sig).data, m_len as usize)
            {
                raise_site(&err_sites::RSA_SAOS_86);
            } else {
                ret = 1;
            }
        }

        // SAFETY: `sig` is NULL or this call's own decoded object; `s` is NULL or this call's own
        // allocation of `siglen` bytes.
        ASN1_OCTET_STRING_free(sig);
        CRYPTO_clear_free(s.cast(), siglen as usize, FILE_SIGN, LINE);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four structure names the DER tables are read against, asserted once so the tables below
    /// and `RSA_sign`'s court arm are not the only readers.
    ///
    /// **The outer length counts the digest the caller has not appended yet**, which is the one
    /// thing a reader of these tables gets wrong: `0x11 + sz` is `17 + sz`, where the seventeen is
    /// the inner `SEQUENCE` element (15 bytes) plus the `OCTET STRING` header (2), and `sz` is the
    /// digest the *prefix* does not contain. So the length octet is `prefix.len() - 2 + digest` and
    /// never `prefix.len() - 2`.
    #[test]
    fn the_digestinfo_tables_are_der_sequences_of_the_lengths_they_claim() {
        // One NID per family: the MD syntax, the SHA syntax, the SHA-1 exception, the truncated
        // SHA-2 pair, an MDC-2 with a different OID syntax again, and SM3.
        let cases: [(c_int, usize, usize); 6] = [
            (NID_md5, 18, 16),
            (NID_sha256, 19, 32),
            (NID_sha1, 15, 20),
            (NID_sha512_224, 19, 28),
            (NID_mdc2, 14, 16),
            (NID_sm3, 18, 32),
        ];

        for (nid, total, digest) in cases {
            let mut len: usize = 0;
            // SAFETY: `len` is a live local of the type the callee writes.
            let der = unsafe { ossl_rsa_digestinfo_encoding(nid, &mut len) };
            assert!(!der.is_null(), "nid {nid} has a table");
            // SAFETY: the callee answered a static table of `len` bytes.
            let der = unsafe { core::slice::from_raw_parts(der, len) };
            assert_eq!(der.len(), total, "nid {nid} table width");
            // `SEQUENCE { SEQUENCE { OID, NULL } OCTET STRING(len) }`, with the outer length
            // counting the digest the caller appends.
            assert_eq!(der[0], ASN1_SEQUENCE);
            assert_eq!(
                der[1] as usize,
                total - 2 + digest,
                "nid {nid} outer length"
            );
            assert_eq!(der[2], ASN1_SEQUENCE);
            assert_eq!(der[4], ASN1_OID);
            // The four octets that make up the OCTET STRING header and the digest's length, and
            // the two `NULL` parameters immediately before them.
            assert_eq!(der[total - 4], ASN1_NULL);
            assert_eq!(der[total - 3], 0x00);
            assert_eq!(der[total - 2], ASN1_OCTET_STRING);
            assert_eq!(der[total - 1] as usize, digest, "nid {nid} digest length");
        }

        // The refusal: a NID with no table answers NULL and does not write `len`.
        let mut len: usize = 0;
        // SAFETY: `len` is a live local.
        assert!(unsafe { ossl_rsa_digestinfo_encoding(0x3fff, &mut len) }.is_null());
        assert_eq!(len, 0, "a refusal leaves the length untouched");
    }

    /// The length table and the encoding table are different tables, and the difference is one
    /// family.
    #[test]
    fn the_digest_length_table_is_the_authoritys_second_table() {
        assert_eq!(digest_sz_from_nid(NID_sha1), 20);
        assert_eq!(digest_sz_from_nid(NID_sha256), 32);
        assert_eq!(digest_sz_from_nid(NID_sha512), 64);
        // The truncated pair is named for the code length it produces, not for the length of the
        // function's name.
        assert_eq!(digest_sz_from_nid(NID_sha512_224), 28);
        assert_eq!(digest_sz_from_nid(NID_sha512_256), 32);
        // The asymmetry: both have an encoding and only one of them has a length here.
        assert_eq!(digest_sz_from_nid(NID_sm3), 0);
        assert_eq!(digest_sz_from_nid(NID_undef), 0);
    }

    /// `encode_pkcs1`'s two refusals, whose reasons differ.
    #[test]
    fn encode_pkcs1_refuses_undef_and_an_unknown_algorithm_differently() {
        let m = [0u8; 32];
        let mut out: *mut c_uchar = core::ptr::null_mut();
        let mut out_len: usize = 0;

        crate::runtime::err::ERR_clear_error();
        // SAFETY: `out` and `out_len` are live locals; `m` is readable for 32 bytes.
        let ret = unsafe { encode_pkcs1(&mut out, &mut out_len, NID_undef, m.as_ptr(), m.len()) };
        assert_eq!(ret, 0);
        assert!(out.is_null(), "a refusal allocates nothing");
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);

        crate::runtime::err::ERR_clear_error();
        // SAFETY: as above, with a NID the table does not have.
        let ret = unsafe { encode_pkcs1(&mut out, &mut out_len, 0x3fff, m.as_ptr(), m.len()) };
        assert_eq!(ret, 0);
        assert_ne!(crate::runtime::err::ERR_peek_error(), 0);

        // And one success, whose answer is the prefix plus the digest.
        crate::runtime::err::ERR_clear_error();
        // SAFETY: as above, with a NID the table has.
        let ret = unsafe { encode_pkcs1(&mut out, &mut out_len, NID_sha256, m.as_ptr(), m.len()) };
        assert_eq!(ret, 1);
        assert_eq!(out_len, 19 + 32);
        // SAFETY: `out` is the allocation the callee made, `out_len` its length.
        let encoded = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(encoded[0], ASN1_SEQUENCE);
        assert_eq!(encoded[19..], m[..]);
        // SAFETY: `out` is this test's own allocation from the callee.
        unsafe { crate::runtime::mem::CRYPTO_clear_free(out.cast(), out_len, FILE_SIGN, LINE) };
        crate::runtime::err::ERR_clear_error();
    }
}
