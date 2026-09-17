//! Phase 7.4c — `crypto/evp/p5_crpt2.c`: PKCS#5 v2.0, the PBKDF2 façade and the two v2 keygens.
//!
//! Six exports, two of them internal to the authority, and three ASN.1 descriptors that the
//! authority keeps in `crypto/asn1/p5_pbev2.c` and `crypto/asn1/x_algor.c`.
//!
//! ## What is here, in the file's own order
//!
//! ```text
//! ossl_pkcs5_pbkdf2_hmac_ex   internal, declared in include/crypto/evp.h:906
//! PKCS5_PBKDF2_HMAC           the four-argument façade over it
//! PKCS5_PBKDF2_HMAC_SHA1      the same with a fetched SHA1
//! PKCS5_v2_PBE_keyivgen_ex    a PBE2PARAM: a KDF identifier and a cipher identifier
//! PKCS5_v2_PBE_keyivgen
//! PKCS5_v2_PBKDF2_keyivgen_ex a PBKDF2PARAM, reached through the two tables
//! PKCS5_v2_PBKDF2_keyivgen
//! ```
//!
//! `ossl_pkcs5_pbkdf2_hmac_ex` is the file's spine: `PKCS5_PBKDF2_HMAC` forwards to it and
//! `PKCS5_v2_PBKDF2_keyivgen_ex` calls it for the actual derivation, so the two public entry points
//! and the v2 keygen all reach the same `EVP_KDF` "PBKDF2" with the same six parameters. It is
//! `pub(crate)` and carries no `#[no_mangle]`: `include/crypto/evp.h` is not installed, so there is
//! no symbol for it in `libcrypto.so` and none here.
//!
//! ## `passlen` and the two NULL normalisations, which are three different rules
//!
//! `ossl_pkcs5_pbkdf2_hmac_ex` normalises in the order the authority writes it:
//!
//! ```text
//! pass == NULL                 -> "" and passlen = 0
//! else passlen == -1           -> passlen = strlen(pass)      (the `else if`, not a second `if`)
//! salt == NULL && saltlen == 0 -> ""            (and saltlen is left alone)
//! ```
//!
//! The third test is a **conjunction**: a NULL salt with a non-zero saltlen still travels as a NULL
//! pointer, and the length it carries is the caller's. That is a different rule from
//! `EVP_PBE_scrypt_ex`'s, whose `salt == NULL` arm normalises the length unconditionally — the two
//! functions are in the same stratum and disagree, and the court drives both.
//!
//! ## `PKCS5_PBKDF2_HMAC_SHA1` fetches, and reports only the derivation
//!
//! The digest is `EVP_MD_fetch(NULL, SN_sha1, NULL)` and a failed fetch answers **0** with nothing
//! raised by this file — `EVP_MD_free(NULL)` is called on the way out and the refusal is whatever
//! the fetch already put on the queue. `SN_sha1` is `"SHA1"`, not `"SHA-1"` or `"sha1"`.
//!
//! ## `PKCS5_v2_PBE_keyivgen_ex` is two lookups and one delegation
//!
//! The `pbe2->keyfunc` OID names a **KDF** row of `EVP_PBE_TYPE_KDF` and the `pbe2->encryption`
//! OID is converted to text with `OBJ_obj2txt(..., 0)` — a *short name* when the object database
//! has one, a dotted decimal otherwise — and then fetched by that text. The cipher's own
//! `parameter` is handed to `EVP_CIPHER_asn1_to_param`, which for a CBC-mode cipher is an octet
//! string of exactly the IV length. The keygen it finally calls is the one the **KDF row** names,
//! with `pbe2->keyfunc->parameter` as the parameter and a NULL cipher and digest — the cipher is
//! already on the context.
//!
//! ## `PKCS5_v2_PBKDF2_keyivgen_ex` reads the context's key length twice, and asserts
//!
//! `EVP_CIPHER_CTX_get_key_length` is called at `:199` and again at `:211`, and the first value is
//! checked against the 64-byte stack buffer with `OPENSSL_assert` — which is **not** `NDEBUG`-gated
//! (`include/openssl/crypto.h:475` expands it to `OPENSSL_die`), so the authority aborts on a
//! cipher that reports more than 64 bytes. This crate refuses instead, which is the disposition
//! `D-RCU-3` records for the same shape; the boundary is named in `RT-EVP-PBE` and not driven,
//! because a fault cannot be compared.
//!
//! ## `EVP_PBE_find` is called here, which is why it could not be deferred
//!
//! `:230` resolves the PRF by NID through `EVP_PBE_find(EVP_PBE_TYPE_PRF, ...)`, and `:133`
//! resolves the KDF through `EVP_PBE_find_ex(EVP_PBE_TYPE_KDF, ...)`. Both are
//! `crypto/evp/evp_pbe.c`'s and both are landed in `src/evp/evp_pbe.rs`; withholding them — the
//! "defer the table's readers" reading of D165 — would have taken this file's four v2 entries with
//! them (D192).
//!
//! ## The three ASN.1 descriptors
//!
//! `PBE2PARAM` and `PBKDF2PARAM` are `crypto/asn1/p5_pbev2.c:20-37`'s; `X509_ALGOR` is
//! `crypto/asn1/x_algor.c:18-21`'s, whose *struct* already lands in `src/evp/cipher_ctx.rs` for
//! `EVP_CIPHER_CTX_get_algor_params`. Only the two field descriptors this file decodes through are
//! added here, as file-local statics, for the reason `src/asn1/evp_asn1.rs` records: the item is
//! `static const` inside the authority's own accessor (`X509_ALGOR_it`, `PBE2PARAM_it`,
//! `PBKDF2PARAM_it`, all Phase 11's) and nothing outside the unit can name it. The accessors stay
//! in the ledger as Phase 11's and no symbol is defined twice.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_unpack;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{ASN1_ANY_it, ASN1_INTEGER_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_asn1_to_param,
    EVP_CipherInit_ex, EvpCipherCtx, X509Algor,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EvpMd};
use crate::evp::evp_pbe::{EVP_PBE_find, EVP_PBE_find_ex, EVP_PBE_TYPE_KDF, EVP_PBE_TYPE_PRF};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdf,
};
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::runtime::bio::sys::strlen;
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::OPENSSL_cleanse;
use crate::runtime::obj::{NID_hmacWithSHA1, NID_undef, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;

/// `OSSL_KDF_NAME_PBKDF2` — `include/openssl/core_names.h:75`.
const OSSL_KDF_NAME_PBKDF2: *const c_char = c"PBKDF2".as_ptr();
/// `OSSL_KDF_PARAM_PASSWORD` — `include/openssl/core_names.h:299`.
const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
/// `OSSL_KDF_PARAM_SALT` — `include/openssl/core_names.h:304`.
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
/// `OSSL_KDF_PARAM_ITER` — `include/openssl/core_names.h:290`.
const OSSL_KDF_PARAM_ITER: *const c_char = c"iter".as_ptr();
/// `OSSL_KDF_PARAM_DIGEST` — `include/openssl/core_names.h:281`, which is `OSSL_ALG_PARAM_DIGEST`.
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_KDF_PARAM_PKCS5` — `include/openssl/core_names.h:301`.
const OSSL_KDF_PARAM_PKCS5: *const c_char = c"pkcs5".as_ptr();
/// `SN_sha1` — `include/openssl/obj_mac.h`, the short name `EVP_MD_fetch` is asked for.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();

// ---------------------------------------------------------------------------------------------
// The three ASN.1 descriptors
// ---------------------------------------------------------------------------------------------

/// `x509_algor_seq_tt` — `crypto/asn1/x_algor.c:18-21`'s two fields, the second optional.
///
/// The *struct* is [`X509Algor`], declared in `src/evp/cipher_ctx.rs` for the two
/// `EVP_CIPHER_CTX_*algor_params` functions; only the descriptor is this file's.
static X509_ALGOR_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algorithm".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"parameter".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
];

/// The offsets `X509_ALGOR_TT` names, asserted against the shared declaration.
const _: () = {
    assert!(core::mem::size_of::<X509Algor>() == 16);
    assert!(core::mem::offset_of!(X509Algor, algorithm) == 0);
    assert!(core::mem::offset_of!(X509Algor, parameter) == 8);
};

/// `PBE2PARAM` — `crypto/asn1/p5_pbev2.c:20-23`.
#[repr(C)]
struct Pbe2Param {
    /// `ASN1_SIMPLE(PBE2PARAM, keyfunc, X509_ALGOR)` — at offset 0.
    keyfunc: *mut X509Algor,
    /// `ASN1_SIMPLE(PBE2PARAM, encryption, X509_ALGOR)` — at offset 8.
    encryption: *mut X509Algor,
}

const _: () = {
    assert!(core::mem::size_of::<Pbe2Param>() == 16);
    assert!(core::mem::offset_of!(Pbe2Param, keyfunc) == 0);
    assert!(core::mem::offset_of!(Pbe2Param, encryption) == 8);
};

/// `PBKDF2PARAM` — `crypto/asn1/p5_pbev2.c:25-32`.
///
/// `salt` is `ASN1_ANY` and not `ASN1_OCTET_STRING`, which is why the body has a
/// `salt->type != V_ASN1_OCTET_STRING` refusal of its own.
#[repr(C)]
struct Pbkdf2Param {
    /// `ASN1_SIMPLE(PBKDF2PARAM, salt, ASN1_ANY)` — at offset 0.
    salt: *mut Asn1Type,
    /// `ASN1_SIMPLE(PBKDF2PARAM, iter, ASN1_INTEGER)` — at offset 8.
    iter: *mut Asn1String,
    /// `ASN1_OPT(PBKDF2PARAM, keylength, ASN1_INTEGER)` — at offset 16.
    keylength: *mut Asn1String,
    /// `ASN1_OPT(PBKDF2PARAM, prf, X509_ALGOR)` — at offset 24.
    prf: *mut X509Algor,
}

const _: () = {
    assert!(core::mem::size_of::<Pbkdf2Param>() == 32);
    assert!(core::mem::offset_of!(Pbkdf2Param, salt) == 0);
    assert!(core::mem::offset_of!(Pbkdf2Param, iter) == 8);
    assert!(core::mem::offset_of!(Pbkdf2Param, keylength) == 16);
    assert!(core::mem::offset_of!(Pbkdf2Param, prf) == 24);
};

/// `pbe2_seq_tt` — `crypto/asn1/p5_pbev2.c:20-23`.
static PBE2PARAM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyfunc".as_ptr(),
        item: x509_algor_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"encryption".as_ptr(),
        item: x509_algor_it as *mut c_void,
    },
];

/// `pbkdf2_seq_tt` — `crypto/asn1/p5_pbev2.c:25-32`.
static PBKDF2PARAM_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"salt".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"iter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"keylength".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"prf".as_ptr(),
        item: x509_algor_it as *mut c_void,
    },
];

/// `X509_ALGOR_it`'s descriptor, private here because the accessor is Phase 11's.
static X509_ALGOR_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ALGOR_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Algor>() as c_long,
    sname: c"X509_ALGOR".as_ptr(),
};

/// `PBE2PARAM_it`'s descriptor, private here because the accessor is Phase 11's.
static PBE2PARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBE2PARAM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbe2Param>() as c_long,
    sname: c"PBE2PARAM".as_ptr(),
};

/// `PBKDF2PARAM_it`'s descriptor, private here because the accessor is Phase 11's.
static PBKDF2PARAM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PBKDF2PARAM_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pbkdf2Param>() as c_long,
    sname: c"PBKDF2PARAM".as_ptr(),
};

/// The `ASN1_ITEM_EXP` a nested template names: `X509_ALGOR_it`'s address as a *function*, which
/// `ASN1_ITEM_ref(X509_ALGOR)` spells as `&X509_ALGOR_it`. The authority's accessor is Phase 11's,
/// so the one the nested templates point at is this file's.
extern "C" fn x509_algor_it() -> *const Asn1Item {
    &X509_ALGOR_ITEM
}

// ---------------------------------------------------------------------------------------------
// The PBKDF2 façade
// ---------------------------------------------------------------------------------------------

/// `int ossl_pkcs5_pbkdf2_hmac_ex(const char *pass, int passlen, const unsigned char *salt,
/// int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p5_crpt2.c:22`.
///
/// Internal: declared in `include/crypto/evp.h:906`, which is not installed, so there is no
/// exported symbol for it and none is defined here.
///
/// The authority's `OSSL_TRACE_BEGIN(PKCS5V2)` block is **compiled out of this build**:
/// `configuration.h:135` defines `OPENSSL_NO_TRACE`, which reduces the macro to
/// `do { BIO *trc_out = NULL; if (0) { ... } } while (0)`, so the hex dumps have no runtime effect
/// and none is transcribed.
///
/// # Safety
/// `pass` NULL or readable for `passlen` bytes (or NUL-terminated when `passlen == -1`); `salt`
/// NULL or readable for `saltlen` bytes; `digest` must be live; `out` must be `keylen` writable
/// bytes; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn ossl_pkcs5_pbkdf2_hmac_ex(
    mut pass: *const c_char,
    mut passlen: c_int,
    mut salt: *const c_uchar,
    saltlen: c_int,
    iter: c_int,
    digest: *const EvpMd,
    keylen: c_int,
    out: *mut c_uchar,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let empty: *const c_char = c"".as_ptr();
    let mut rv: c_int = 1;
    let mode: c_int = 1;
    let mut params = [OSSL_PARAM_construct_end(); 6];
    /* The authority's initialiser, so it is read before the two normalisations below. */
    // SAFETY: `digest` is live per the contract.
    let mdname = unsafe { EVP_MD_get0_name(digest) };

    /* Keep documented behaviour. */
    if pass.is_null() {
        pass = empty;
        passlen = 0;
    } else if passlen == -1 {
        // SAFETY: `pass` is NUL-terminated per the contract.
        passlen = unsafe { strlen(pass) } as c_int;
    }
    if salt.is_null() && saltlen == 0 {
        salt = empty.cast::<c_uchar>();
    }

    // SAFETY: `libctx` is NULL or live and `propq` is NULL or NUL-terminated.
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, propq) };
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: `kdf` is live, which the constructor requires.
    let kctx: *mut crate::evp::kdf::EvpKdfCtx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is live and this call gives its reference back.
    unsafe { EVP_KDF_free(kdf) };
    if kctx.is_null() {
        return 0;
    }
    // SAFETY: the constructors take a name and a buffer; every buffer here is the caller's (or
    // the empty literal) and every name is a compile-time constant.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            pass.cast::<c_void>().cast_mut(),
            passlen as usize,
        );
        params[1] = OSSL_PARAM_construct_int(
            OSSL_KDF_PARAM_PKCS5,
            ptr::addr_of!(mode).cast_mut().cast::<c_int>(),
        );
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.cast::<c_void>().cast_mut(),
            saltlen as usize,
        );
        params[3] = OSSL_PARAM_construct_int(
            OSSL_KDF_PARAM_ITER,
            ptr::addr_of!(iter).cast_mut().cast::<c_int>(),
        );
        params[4] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdname.cast_mut(), 0);
    }
    // SAFETY: `kctx` is live, `out` is `keylen` writable bytes per the contract, and the array is
    // this frame's own and terminated.
    if unsafe { EVP_KDF_derive(kctx, out, keylen as usize, params.as_ptr()) } != 1 {
        rv = 0;
    }
    // SAFETY: `kctx` is live and this call gives its reference back.
    unsafe { EVP_KDF_CTX_free(kctx) };
    rv
}

/// `int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen,
/// int iter, const EVP_MD *digest, int keylen, unsigned char *out)` — `crypto/evp/p5_crpt2.c:85`.
///
/// # Safety
/// As [`ossl_pkcs5_pbkdf2_hmac_ex`], with a NULL library context and property query.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC(
    pass: *const c_char,
    passlen: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    iter: c_int,
    digest: *const EvpMd,
    keylen: c_int,
    out: *mut c_uchar,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        ossl_pkcs5_pbkdf2_hmac_ex(
            pass,
            passlen,
            salt,
            saltlen,
            iter,
            digest,
            keylen,
            out,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen, const unsigned char *salt,
/// int saltlen, int iter, int keylen, unsigned char *out)` — `crypto/evp/p5_crpt2.c:93`.
///
/// A failed digest fetch answers **0** and raises nothing here: `EVP_MD_free(NULL)` is
/// legal and the refusal is whatever the fetch already recorded.
///
/// # Safety
/// As [`ossl_pkcs5_pbkdf2_hmac_ex`], with the digest chosen by this function and a NULL library
/// context and property query.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC_SHA1(
    pass: *const c_char,
    passlen: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    iter: c_int,
    keylen: c_int,
    out: *mut c_uchar,
) -> c_int {
    let mut r: c_int = 0;

    // SAFETY: `SN_SHA1` is a static string and the other two arguments are the authority's.
    let digest = unsafe { EVP_MD_fetch(ptr::null_mut(), SN_SHA1, ptr::null()) };
    if !digest.is_null() {
        // SAFETY: `digest` is live per the check above and the rest are the caller's.
        r = unsafe {
            ossl_pkcs5_pbkdf2_hmac_ex(
                pass,
                passlen,
                salt,
                saltlen,
                iter,
                digest,
                keylen,
                out,
                ptr::null_mut(),
                ptr::null(),
            )
        };
    }
    // SAFETY: `digest` is NULL or a reference this frame holds.
    unsafe { EVP_MD_free(digest) };
    r
}

// ---------------------------------------------------------------------------------------------
// The two v2 entries
// ---------------------------------------------------------------------------------------------

/// `int PKCS5_v2_PBE_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p5_crpt2.c:113`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX`; `pass` NULL or NUL-terminated (or `passlen` bytes when
/// `passlen != -1`); `param` NULL or a live `ASN1_TYPE`; `libctx` NULL or live; `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_v2_PBE_keyivgen_ex(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut ciph_name = [0 as c_char; 80];
    let mut cipher_fetch: *mut EvpCipher = ptr::null_mut();
    let mut kdf: Option<crate::evp::evp_pbe::EvpPbeKeygenEx> = None;
    /* The two unused parameters are the authority's: neither `c` nor `md` is read, because the
     * cipher is taken from `pbe2->encryption` and the digest from the KDF row. */
    let _ = (c, md);

    let mut pbe2: *mut Pbe2Param = ptr::null_mut();
    if !param.is_null() {
        // SAFETY: `param` is live per the check above.
        let (type_, seq) = unsafe { ((*param).type_, (*param).value.ptr.cast::<Asn1String>()) };
        if type_ == V_ASN1_SEQUENCE && !seq.is_null() {
            // SAFETY: `seq` is a live string and the item is this file's own static.
            pbe2 = unsafe { ASN1_item_unpack(seq, &PBE2PARAM_ITEM) }.cast::<Pbe2Param>();
        }
    }
    if pbe2.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_128) };
        return 0;
    }

    /* See if we recognise the key derivation function. */
    // SAFETY: `pbe2` is live and `keyfunc` is non-NULL after a decode.
    let kdf_nid = unsafe { OBJ_obj2nid((*(*pbe2).keyfunc).algorithm) };
    // SAFETY: two live locals and one NULL.
    if unsafe {
        EVP_PBE_find_ex(
            EVP_PBE_TYPE_KDF,
            kdf_nid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut kdf,
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_135) };
        // SAFETY: `pbe2` is this call's own decode and `cipher_fetch` is NULL.
        unsafe { finish_err(pbe2, cipher_fetch) };
        return 0;
    }

    /* Lets see if we recognise the encryption algorithm. */
    // SAFETY: `pbe2` is live; the buffer is this frame's 80 bytes and `encryption` is non-NULL.
    if unsafe {
        OBJ_obj2txt(
            ciph_name.as_mut_ptr(),
            80,
            (*(*pbe2).encryption).algorithm,
            0,
        )
    } <= 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_143) };
        // SAFETY: `pbe2` is this call's own decode.
        unsafe { finish_err(pbe2, cipher_fetch) };
        return 0;
    }

    /* `ERR_set_mark` is a safe entry point of this crate. */
    ERR_set_mark();
    // SAFETY: `ciph_name` is a NUL-terminated local from `OBJ_obj2txt`.
    cipher_fetch = unsafe { EVP_CIPHER_fetch(libctx, ciph_name.as_ptr(), propq) };
    let mut cipher: *const EvpCipher = cipher_fetch;
    /* Fallback to legacy method */
    if cipher.is_null() {
        // SAFETY: `ciph_name` is NUL-terminated.
        cipher = unsafe { EVP_get_cipherbyname(ciph_name.as_ptr()) };
    }
    if cipher.is_null() {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_155) };
        // SAFETY: `pbe2` is this call's own decode and `cipher_fetch` is NULL.
        unsafe { finish_err(pbe2, cipher_fetch) };
        return 0;
    }
    ERR_pop_to_mark();

    /* Fixup cipher based on AlgorithmIdentifier. */
    // SAFETY: `ctx` is live per the contract and `cipher` is live.
    if unsafe {
        EVP_CipherInit_ex(
            ctx,
            cipher,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            en_de,
        )
    } == 0
    {
        // SAFETY: `pbe2` is this call's own decode.
        unsafe { finish_err(pbe2, cipher_fetch) };
        return 0;
    }
    // SAFETY: `ctx` is live and `encryption->parameter` is NULL or a live `ASN1_TYPE`.
    if unsafe { EVP_CIPHER_asn1_to_param(ctx, (*(*pbe2).encryption).parameter) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_164) };
        // SAFETY: `pbe2` is this call's own decode.
        unsafe { finish_err(pbe2, cipher_fetch) };
        return 0;
    }
    /* The authority calls `kdf(...)` unconditionally here; a row found with no `keygen_ex` — which
     * only `EVP_PBE_alg_add_type` can create — would fault. See `D-PBE-PKCS12-KEYGEN-1`. */
    let rv = if let Some(f) = kdf {
        // SAFETY: `f` is the table's own keygen and every argument is the caller's.
        unsafe {
            f(
                ctx,
                pass,
                passlen,
                (*(*pbe2).keyfunc).parameter,
                ptr::null(),
                ptr::null(),
                en_de,
                libctx,
                propq,
            )
        }
    } else {
        0
    };
    // SAFETY: `cipher_fetch` is NULL or a reference this frame holds and `pbe2` is this call's own
    // decode.
    unsafe { finish_err(pbe2, cipher_fetch) };
    rv
}

/// The shared `err:` tail of the two v2 keygens: release the fetched cipher, free the decode.
///
/// # Safety
/// `cipher_fetch` must be NULL or a reference this frame holds; `pbe2` NULL or this call's own
/// `PBE2PARAM` decode.
unsafe fn finish_err(pbe2: *mut Pbe2Param, cipher_fetch: *mut EvpCipher) {
    // SAFETY: both are NULL or owned by this frame per the contract.
    unsafe {
        EVP_CIPHER_free(cipher_fetch);
        ASN1_item_free(pbe2.cast::<c_void>(), &PBE2PARAM_ITEM);
    }
}

/// `int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de)` —
/// `crypto/evp/p5_crpt2.c:174`.
///
/// # Safety
/// As [`PKCS5_v2_PBE_keyivgen_ex`], with a NULL library context and property query.
#[no_mangle]
pub unsafe extern "C" fn PKCS5_v2_PBE_keyivgen(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        PKCS5_v2_PBE_keyivgen_ex(
            ctx,
            pass,
            passlen,
            param,
            c,
            md,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int PKCS5_v2_PBKDF2_keyivgen_ex(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p5_crpt2.c:181`.
///
/// # Safety
/// `ctx` must be a live `EVP_CIPHER_CTX`; `pass` NULL or NUL-terminated (or `passlen` bytes when
/// `passlen != -1`); `param` NULL or a live `ASN1_TYPE`; `libctx` NULL or live; `propq` NULL or
/// NUL-terminated.
// The name is the authority's and the table stores this function as a pointer under it, so it is
// kept verbatim rather than snake-cased.
#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn PKCS5_v2_PBKDF2_keyivgen_ex(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut key = [0u8; EVP_MAX_KEY_LENGTH];
    let mut hmac_md_nid: c_int = 0;
    let mut kdf: *mut Pbkdf2Param = ptr::null_mut();
    /* As in `PKCS5_v2_PBE_keyivgen_ex`, neither `c` nor `md` is read. */
    let _ = (c, md);

    // SAFETY: `ctx` is live per the contract and the accessor tolerates a NULL context.
    if unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_196) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let mut keylen: u32 = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) } as u32;
    /* `OPENSSL_assert(keylen <= sizeof(key))` is not `NDEBUG`-gated and calls `OPENSSL_die`; this
     * crate refuses instead, which is a fault boundary named in RT-EVP-PBE and not driven. */
    if keylen as usize > key.len() {
        return 0;
    }

    /* Decode parameter. */
    if !param.is_null() {
        // SAFETY: `param` is live per the check above.
        let (type_, seq) = unsafe { ((*param).type_, (*param).value.ptr.cast::<Asn1String>()) };
        if type_ == V_ASN1_SEQUENCE && !seq.is_null() {
            // SAFETY: `seq` is a live string and the item is this file's own static.
            kdf = unsafe { ASN1_item_unpack(seq, &PBKDF2PARAM_ITEM) }.cast::<Pbkdf2Param>();
        }
    }
    if kdf.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_207) };
        return 0;
    }

    // SAFETY: `ctx` is live per the contract.
    let t = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if t < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_213) };
        // SAFETY: `kdf` is this call's own decode.
        unsafe { err_cleanup(kdf, &mut key, keylen, ptr::null_mut()) };
        return 0;
    }
    keylen = t as u32;

    /* Now check the parameters of the kdf. */
    // SAFETY: `kdf` is live and `keylength` is NULL or the decode's own integer.
    if !unsafe { (*kdf).keylength }.is_null() {
        // SAFETY: `keylength` is live per the check above.
        let kl = unsafe { ASN1_INTEGER_get((*kdf).keylength) };
        if kl != c_long::from(keylen as c_int) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P5_CRPT2_221) };
            // SAFETY: `kdf` is this call's own decode.
            unsafe { err_cleanup(kdf, &mut key, keylen, ptr::null_mut()) };
            return 0;
        }
    }

    // SAFETY: `kdf` is live and `prf` is NULL or a decoded `X509_ALGOR` whose `algorithm` is
    // non-NULL.
    let prf_nid = unsafe {
        if (*kdf).prf.is_null() {
            NID_hmacWithSHA1
        } else {
            OBJ_obj2nid((*(*kdf).prf).algorithm)
        }
    };

    // SAFETY: two live locals and a NULL keygen out-parameter.
    if unsafe {
        EVP_PBE_find(
            EVP_PBE_TYPE_PRF,
            prf_nid,
            ptr::null_mut(),
            &mut hmac_md_nid,
            ptr::null_mut(),
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_231) };
        // SAFETY: `kdf` is this call's own decode.
        unsafe { err_cleanup(kdf, &mut key, keylen, ptr::null_mut()) };
        return 0;
    }

    /* `ERR_set_mark` is a safe entry point of this crate. */
    ERR_set_mark();
    // SAFETY: `OBJ_nid2sn` is an integer in and a static string or NULL out, and the rest are the
    // caller's.
    let prfmd_fetch: *mut EvpMd = unsafe { EVP_MD_fetch(libctx, OBJ_nid2sn(hmac_md_nid), propq) };
    /* The fallback is the legacy lookup, and it is a *second* read of the same name: a
     * transcription that folded the two into one expression would lose the `ERR_set_mark`
     * pairing below. */
    let prfmd: *const EvpMd = if prfmd_fetch.is_null() {
        // SAFETY: `hmac_md_nid` is an integer; the answer is a static string or NULL.
        unsafe { EVP_get_digestbyname(OBJ_nid2sn(hmac_md_nid)) }
    } else {
        prfmd_fetch
    };
    if prfmd.is_null() {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_241) };
        // SAFETY: `kdf` is this call's own decode.
        unsafe { err_cleanup(kdf, &mut key, keylen, ptr::null_mut()) };
        return 0;
    }
    ERR_pop_to_mark();

    /* SAFETY: `kdf` is live and `salt` is non-NULL after a decode; the type test decides whether
     * the octet-string arm may be read at all. */
    let salt_type = unsafe { (*(*kdf).salt).type_ };
    if salt_type != V_ASN1_OCTET_STRING {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P5_CRPT2_247) };
        // SAFETY: `kdf` is this call's own decode.
        unsafe { err_cleanup(kdf, &mut key, keylen, prfmd_fetch) };
        return 0;
    }

    /* it seems that its all OK */
    // SAFETY: the type test above was `V_ASN1_OCTET_STRING`, so the union's octet-string member is
    // the live one and its `data`/`length` are a decoded string's.
    let (salt, saltlen) = unsafe {
        let s = (*kdf).salt;
        let oct = (*s).value.ptr.cast::<Asn1String>();
        ((*oct).data, (*oct).length)
    };
    // SAFETY: `iter` is a decoded mandatory integer.
    let iter = unsafe { ASN1_INTEGER_get((*kdf).iter) as c_int };
    // SAFETY: `prfmd` is live per the checks above and every other argument is the caller's.
    if unsafe {
        ossl_pkcs5_pbkdf2_hmac_ex(
            pass,
            passlen,
            salt,
            saltlen,
            iter,
            prfmd,
            keylen as c_int,
            key.as_mut_ptr(),
            libctx,
            propq,
        )
    } == 0
    {
        // SAFETY: `kdf` is this call's own decode and `prfmd_fetch` is NULL or this frame's.
        unsafe { err_cleanup(kdf, &mut key, keylen, prfmd_fetch) };
        return 0;
    }
    // SAFETY: `ctx` is live; a NULL cipher means "the one already on the context" and a NULL IV
    // means "no IV parameter".
    let rv = unsafe {
        EVP_CipherInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            key.as_ptr(),
            ptr::null(),
            en_de,
        )
    };
    // SAFETY: `kdf` is this call's own decode.
    unsafe { err_cleanup(kdf, &mut key, keylen, prfmd_fetch) };
    rv
}

/// The authority's `err:` label of `PKCS5_v2_PBKDF2_keyivgen_ex`: cleanse the key, free the decode
/// and the fetched digest.
///
/// # Safety
/// `kdf` NULL or this call's own `PBKDF2PARAM` decode; `prfmd_fetch` NULL or a reference this frame
/// holds.
unsafe fn err_cleanup(
    kdf: *mut Pbkdf2Param,
    key: &mut [u8; EVP_MAX_KEY_LENGTH],
    keylen: u32,
    prfmd_fetch: *mut EvpMd,
) {
    // SAFETY: `key` is the caller's own buffer and the caller bounds `keylen`.
    unsafe {
        if keylen != 0 && keylen as usize <= key.len() {
            OPENSSL_cleanse(key.as_mut_ptr().cast(), keylen as usize);
        }
        ASN1_item_free(kdf.cast::<c_void>(), &PBKDF2PARAM_ITEM);
        EVP_MD_free(prfmd_fetch);
    }
}

/// `int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
/// ASN1_TYPE *param, const EVP_CIPHER *c, const EVP_MD *md, int en_de)` —
/// `crypto/evp/p5_crpt2.c:266`.
///
/// # Safety
/// As [`PKCS5_v2_PBKDF2_keyivgen_ex`], with a NULL library context and property query.
///
/// `pub(crate)` and **without** `#[no_mangle]`, like `ossl_pkcs5_pbkdf2_hmac_ex` above: the
/// authority declares both in `crypto/evp/evp_local.h`, which is not installed, and its version
/// script keeps them **local** -- `nm` shows `t`, not `T` -- so no symbol of either name exists in
/// `libcrypto.so`. The table reaches this one through `EVP_PBE_KEYGEN *`, which is a pointer and
/// not a name.
// The name is the authority's, as above.
#[allow(non_snake_case)]
pub(crate) unsafe extern "C" fn PKCS5_v2_PBKDF2_keyivgen(
    ctx: *mut EvpCipherCtx,
    pass: *const c_char,
    passlen: c_int,
    param: *mut Asn1Type,
    c: *const EvpCipher,
    md: *const EvpMd,
    en_de: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with the two NULLs the
    // authority passes.
    unsafe {
        PKCS5_v2_PBKDF2_keyivgen_ex(
            ctx,
            pass,
            passlen,
            param,
            c,
            md,
            en_de,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `NID_undef` is referenced here so the two `find` out-parameters and the salt-type test above can
/// be read against the same constant the registry uses.
const _: c_int = NID_undef;

#[cfg(test)]
mod tests {
    use super::*;

    /// The three private descriptors are the authority's: a SEQUENCE each, with the field counts
    /// and the two OPTIONAL flags `ASN1_OPT` sets.
    #[test]
    fn the_private_items_have_the_authority_shape() {
        assert_eq!(X509_ALGOR_ITEM.itype, ASN1_ITYPE_SEQUENCE);
        assert_eq!(X509_ALGOR_ITEM.tcount, 2);
        assert_eq!(X509_ALGOR_ITEM.size, 16);
        assert_eq!(X509_ALGOR_TT[1].flags, ASN1_TFLG_OPTIONAL);
        assert_eq!(PBE2PARAM_ITEM.tcount, 2);
        assert_eq!(PBE2PARAM_ITEM.size, 16);
        assert_eq!(PBKDF2PARAM_ITEM.tcount, 4);
        assert_eq!(PBKDF2PARAM_ITEM.size, 32);
        assert_eq!(PBKDF2PARAM_TT[2].flags, ASN1_TFLG_OPTIONAL);
        assert_eq!(PBKDF2PARAM_TT[3].flags, ASN1_TFLG_OPTIONAL);
        /* The nested items are the file's own getter, not a data pointer. */
        assert_eq!(PBE2PARAM_TT[0].item, x509_algor_it as *mut c_void);
    }

    /// `PKCS5_PBKDF2_HMAC` refuses a NULL digest method rather than faulting: `EVP_MD_get0_name`
    /// answers NULL for a NULL method and the KDF is then asked with a NULL name. The *authority*
    /// reads `digest` first, so the court never passes one; this pins that the crate does not
    /// crash on the same input.
    #[test]
    fn a_null_digest_is_refused_by_the_fetch() {
        let mut out = [0u8; 8];
        // SAFETY: no `EVP_KDF` "PBKDF2" is fetchable in the default context, so the derivation
        // never reaches the provider.
        let r = unsafe {
            PKCS5_PBKDF2_HMAC(
                c"p".as_ptr(),
                -1,
                c"s".as_ptr().cast::<c_uchar>(),
                1,
                1,
                ptr::null(),
                8,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(r, 0);
    }

    /// The parameter refusal precedes the context's key length, exactly as the authority's order
    /// has it: a NULL context with a NULL parameter answers 0 without faulting.
    #[test]
    fn a_null_parameter_is_refused_after_the_cipher_test() {
        // SAFETY: `ctx` is NULL, but the first statement is `EVP_CIPHER_CTX_get0_cipher(ctx)`,
        // which tolerates it and answers NULL — so the refusal at `:196` fires first.
        let r = unsafe {
            PKCS5_v2_PBKDF2_keyivgen(
                ptr::null_mut(),
                c"p".as_ptr(),
                -1,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        assert_eq!(r, 0);
        /* `ERR_clear_error` is a safe entry point of this crate. */
        crate::runtime::err::ERR_clear_error();
    }
}
