//! Phase 10.14.2 — `crypto/x509/x_all.c`: the certificate encode/decode faces and the defaults.
//!
//! `crypto/x509/x_all.c` is 881 lines and publishes ninety-eight functions: the sign/verify
//! front doors, the `d2i_*`/`i2d_*` stream faces for the certificate object graph and the key
//! containers around it, and the digest family. **This module lands the reachable ones** and
//! withholds the rest by name, each with its blocker — the D451/D457 rule, applied at function
//! granularity.
//!
//! ## What lands
//!
//! * **The sign/verify doors** — `X509_verify` (`:33-41`), `X509_sign` (`:77-98`),
//!   `X509_sign_ctx` (`:100-113`), `X509_CRL_sign` (`:164-174`) and `X509_CRL_sign_ctx`
//!   (`:176-186`). They reach `ASN1_item_verify_ex`/`ASN1_item_sign_ex`/`_ctx` (10.10/10.11),
//!   `X509_ALGOR_cmp` (`crypto/asn1/x_algor.c`) and `X509_get0_extensions`
//!   (`crypto/x509/x509_set.c`, un-withheld with this subphase because `X509_sign` reads it).
//! * **The certificate/CRL stream faces** — `d2i_X509_fp`/`i2d_X509_fp`/`d2i_X509_bio`/
//!   `i2d_X509_bio` (`:216-235`) and the four `X509_CRL` twins (`:238-257`), each one
//!   `ASN1_item_*` call on 10.8's items.
//! * **The digest family** — `X509_pubkey_digest` (`:488`),
//!   `X509_digest` (`:498`), `X509_digest_sig` (`:514`), `X509_CRL_digest` (`:608`) and
//!   `X509_NAME_digest` (`:635`). `X509_pubkey_digest` reads `X509_get0_pubkey_bitstr`
//!   (`crypto/x509/x_pubkey.c`, un-withheld here); the rest reach
//!   `ossl_asn1_item_digest_ex`/`ASN1_item_digest` (10.9/10.10) and, for `X509_digest_sig`,
//!   `ossl_rsa_pss_decode`/`ossl_rsa_pss_get_param_unverified` (`crypto/rsa/rsa_backend.c`).
//! * **The PKCS#8 / `X509_PUBKEY` / private-key / public-key stream faces** (`:651-859`), the
//!   `ASN1_d2i_*_of`/`ASN1_i2d_*_of` containers over `d2i_X509_SIG`, `d2i_X509_PUBKEY`,
//!   `d2i_PKCS8_PRIV_KEY_INFO`, `d2i_AutoPrivateKey`, `d2i_PUBKEY` and their encoders.
//! * **The RSA/DSA/EC key stream faces** (`:336-485`), the same `_fp`/`_bio` shape over the
//!   algorithm strata's own `d2i_RSAPrivateKey`/`d2i_RSA_PUBKEY`/… entry points.
//! * **The PKCS#7 stream faces and digest** (12.9) — `d2i_PKCS7_fp`/`_bio` (`:260`,`:283`) and
//!   `i2d_PKCS7_fp`/`_bio` (`:277`,`:300`), each one `ASN1_item_*` call on `PKCS7_it` with the
//!   existing object's library context and property query threaded through the `_ex` decoders and
//!   `ossl_pkcs7_resolve_libctx` run on success; and `PKCS7_ISSUER_AND_SERIAL_digest` (`:642`),
//!   one `ASN1_item_digest` on `PKCS7_ISSUER_AND_SERIAL_it`.
//! * **The HTTP loaders** (12.9) — `X509_load_http` (`:134`), `X509_CRL_load_http` (`:188`) and
//!   their `static simple_get_asn1` helper (`:115`), over `OSSL_HTTP_get`
//!   (`crypto/http/http_client.c`) and the two `OSSL_HTTP_DEFAULT_MAX_*` response caps
//!   (`include/openssl/http.h:43-44`).
//!
//! `i2d_X509_PUBKEY_bio` (`:685-689`) is **already landed** — 10.3 pulled it forward into
//! `src/x509/x_pubkey.rs` because `encode_key2any.c`'s `SubjectPublicKeyInfo` writer reaches it —
//! so it is not transcribed a second time; a second `#[no_mangle]` definition would be a
//! duplicate symbol.
//!
//! ## Nothing is withheld
//!
//! The three groups this module once withheld by name landed once their objects did. The four
//! PKCS#7 stream faces and `PKCS7_ISSUER_AND_SERIAL_digest` waited on `crypto/pkcs7/pk7_asn1.c`'s
//! items (`PKCS7_it`, `PKCS7_ISSUER_AND_SERIAL_it`, `d2i_PKCS7`/`i2d_PKCS7`), which 12.2 pulled
//! forward; the two HTTP loaders and their `simple_get_asn1` helper waited on `OSSL_HTTP_get`
//! (`crypto/http/http_client.c`), which 12 lands. With both available 12.9 transcribes them
//! rather than withholding them, so every definition of `crypto/x509/x_all.c` is accounted for
//! here, in `src/x509/x_pubkey.rs` or in the `X509_REQ`/`X509_ACERT` faces section 7 names.
//!
//! `NETSCAPE_SPKI_verify` (`:71`) and `NETSCAPE_SPKI_sign` (`:209`) were withheld when this
//! module was drafted, on the `NETSCAPE_SPKI` object; this subphase lands that object
//! (`src/asn1/x_spki.rs`, `src/x509/x509spki.rs`), so both are **landed** here rather than
//! stubbed or deferred.
//!
//! **The `X509_REQ` and `X509_ACERT` faces, landed by 11.4/11.3.** Those two groups were the
//! forward dependency section 7 names for this subphase ("`v3_genn`/`x509_req` items for
//! `x_all`'s faces"), withheld here while their objects were unlanded. Both objects have since
//! landed -- `X509_REQ` as `src/x509/x509_req.rs`/`x_req.rs` (11.4) and `X509_ACERT` as
//! `src/x509/x509_acert.rs` (11.3) -- so `X509_REQ_verify_ex`/`_verify` (`:43`,`:56`),
//! `X509_REQ_sign`/`_sign_ctx` (`:140`,`:152`), the four `X509_REQ` `_fp`/`_bio` stream faces
//! (`:306-333`), `X509_REQ_digest` (`:628`), `X509_ACERT_verify` (`:61`),
//! `X509_ACERT_sign`/`_sign_ctx` (`:194`,`:202`) and the four `X509_ACERT` `_fp`/`_bio` faces
//! (`:862-881`) are **landed** here rather than stubbed or deferred.
//!
//! ## The stream faces are the `_of` macros, expanded
//!
//! The authority's `d2i_*_fp`/`_bio` faces are `ASN1_d2i_fp_of`/`ASN1_d2i_bio_of` expansions:
//! `ASN1_d2i_fp((void *(*)(void))X_new, (d2i_of_void *)d2i_X, fp, (void **)x)`. The
//! transcription expands them the same way rather than calling the item layer, because the two
//! differ in their failure classification. The first argument, the "new" function, is **never
//! called** by `ASN1_d2i_fp`/`ASN1_d2i_bio` — not here and not in the authority
//! (`src/asn1/a_d2i_fp.rs:106-111`) — so [`unused_new`] stands in for it and the cast is
//! observable only through the arity. The typed `d2i`/`i2d` function is restated as the untyped
//! `D2iOfVoid`/`I2dOfVoid` by [`d2i_of`]/[`i2d_of`], the way the authority's `(d2i_of_void *)`
//! cast does.
//!
//! ## The raise sites
//!
//! Twelve `ERR_raise*` sites in the unit; with 11.3/11.4 **all twelve are now reachable** --
//! `X509_REQ_verify_ex` (`:47`), `X509_REQ_sign` (`:143`) and `X509_REQ_sign_ctx` (`:155`) were
//! in the previously-withheld `X509_REQ` faces and are landed with them. The other nine were
//! already reachable: `X509_sign` (`:80`), `X509_sign_ctx` (`:103`), `X509_CRL_sign` (`:167`),
//! `X509_CRL_sign_ctx` (`:179`), `X509_digest_sig`'s five refusals (`:530`, `:535`, `:551`,
//! `:582`, `:589`), `X509_CRL_digest` (`:612`) and the two `_ex_fp` BIO-new failures
//! (`:740`, `:761`) -- and are the generated `X509_ALL_*` constants in
//! [`crate::runtime::err::err_sites`]. `crypto/x509/x_all.c` therefore joins
//! `gen_err_raise_sites.py`'s covered set with `:47`/`:143`/`:155` also exercised by this
//! slice.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::{
    asn1_d2i_read_bio, ASN1_d2i_bio, ASN1_d2i_fp, ASN1_item_d2i_bio, ASN1_item_d2i_bio_ex,
    ASN1_item_d2i_fp, ASN1_item_d2i_fp_ex,
};
use crate::asn1::a_digest::{ossl_asn1_item_digest_ex, ASN1_item_digest};
use crate::asn1::a_i2d_fp::{ASN1_i2d_bio, ASN1_i2d_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp};
use crate::asn1::a_sign::{ASN1_item_sign_ctx, ASN1_item_sign_ex};
use crate::asn1::a_verify::{ASN1_item_verify, ASN1_item_verify_ex};
use crate::asn1::d2i_pr::{d2i_AutoPrivateKey, d2i_AutoPrivateKey_ex};
use crate::asn1::i2d_evp::i2d_PrivateKey;
use crate::asn1::layout::{Asn1Item, Asn1String, D2iOfVoid, I2dOfVoid};
use crate::asn1::p8_pkey::{
    d2i_PKCS8_PRIV_KEY_INFO, i2d_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, Pkcs8PrivKeyInfo,
};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::x_algor::X509_ALGOR_cmp;
use crate::asn1::x_sig::{d2i_X509_SIG, i2d_X509_SIG, X509Sig};
use crate::asn1::x_spki::{NETSCAPE_SPKAC_it, NetScapeSpki};
use crate::dsa::asn1::{d2i_DSAPrivateKey, i2d_DSAPrivateKey};
use crate::dsa::Dsa;
use crate::ec::asn1::{d2i_ECPrivateKey, i2d_ECPrivateKey};
use crate::ec::EcKey;
use crate::evp::digest::{
    EVP_Digest, EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_is_a, EvpMd,
};
use crate::evp::evp_pkey::EVP_PKEY2PKCS8;
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::EvpPkey;
use crate::evp::pkey_ctx::EVP_PKEY_RSA_PSS;
use crate::http::http_client::OSSL_HTTP_get;
use crate::pkcs7::{
    ossl_pkcs7_resolve_libctx, PKCS7_ISSUER_AND_SERIAL_it, PKCS7_it, Pkcs7, Pkcs7IssuerAndSerial,
};
use crate::rsa::asn1::{RSAPrivateKey_it, RSAPublicKey_it, RSA_PSS_PARAMS_free};
use crate::rsa::backend::{ossl_rsa_pss_decode, ossl_rsa_pss_get_param_unverified};
use crate::rsa::Rsa;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::buffer::{BUF_MEM_free, BufMem};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{NID_undef, OBJ_find_sigid_algs, OBJ_nid2sn, NID_ED25519, NID_ED448};
use crate::runtime::stack::OPENSSL_sk_num;
use crate::x509::x509_acert::{X509Acert, X509_ACERT_INFO_it, X509_ACERT_it};
use crate::x509::x509_req::{X509Req, X509_REQ_get_version, X509_REQ_VERSION_1};
use crate::x509::x509_set::{X509_get0_extensions, X509_set_version};
use crate::x509::x_crl::{X509Crl, X509_CRL_INFO_it, X509_CRL_it};
use crate::x509::x_pubkey::{
    d2i_DSA_PUBKEY, d2i_EC_PUBKEY, d2i_PUBKEY, d2i_PUBKEY_ex, d2i_RSA_PUBKEY, d2i_X509_PUBKEY,
    i2d_DSA_PUBKEY, i2d_EC_PUBKEY, i2d_PUBKEY, i2d_RSA_PUBKEY, i2d_X509_PUBKEY, X509Pubkey,
    X509_get0_pubkey_bitstr,
};
use crate::x509::x_req::{X509_REQ_INFO_it, X509_REQ_it};
use crate::x509::x_x509::{X509_CINF_it, X509_get_signature_nid, X509_it, X509};

/// `EXFLAG_SET` — `include/openssl/x509v3.h:678`, the word `X509_digest`/`X509_CRL_digest` test
/// before trusting the cached SHA-1 fingerprint.
const EXFLAG_SET: c_uint = 0x100;
/// `EXFLAG_NO_FINGERPRINT` — `include/openssl/x509v3.h:690`, the word that says the cached
/// fingerprint must not be used.
const EXFLAG_NO_FINGERPRINT: c_uint = 0x100000;
/// `X509_VERSION_3` — `include/openssl/x509.h:847`, the version `X509_sign`/`X509_sign_ctx`
/// force when the certificate carries extensions.
const X509_VERSION_3: c_long = 2;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`, the bound of the stack hash buffer
/// `X509_digest_sig` fills.
const EVP_MAX_MD_SIZE: usize = 64;
/// `SN_sha1` — the short name `X509_digest`/`X509_CRL_digest` compare their method with.
const SN_SHA1: &core::ffi::CStr = c"SHA1";
/// `OSSL_HTTP_DEFAULT_MAX_RESP_LEN` — `include/openssl/http.h:43`, the response cap
/// `simple_get_asn1` passes for every item but `X509_CRL`.
const OSSL_HTTP_DEFAULT_MAX_RESP_LEN: usize = 100 * 1024;
/// `OSSL_HTTP_DEFAULT_MAX_CRL_LEN` — `include/openssl/http.h:44`, the larger cap a CRL
/// download is allowed.
const OSSL_HTTP_DEFAULT_MAX_CRL_LEN: usize = 32 * 1024 * 1024;

/// The "new" function `ASN1_d2i_fp`/`ASN1_d2i_bio` take as their first argument and **never
/// call** (`src/asn1/a_d2i_fp.rs:106-111`; the authority's own `ASN1_d2i_bio` does not call it
/// either). It exists so the arity of the `ASN1_d2i_*_of` expansion is preserved; the typed
/// `X_new` the authority passes would be dead code here for the same reason.
unsafe extern "C" fn unused_new() -> *mut c_void {
    ptr::null_mut()
}

/// Restate a typed decoder as the untyped [`D2iOfVoid`], the way the authority's
/// `(d2i_of_void *)d2i_X` cast does. Both are `unsafe extern "C"` function pointers, so the cast
/// preserves the ABI and erases only the pointee type.
fn d2i_of<T>(
    f: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T,
) -> D2iOfVoid {
    // SAFETY: both are function pointers of the same size and ABI; the callee re-types the
    // erased pointee.
    unsafe { core::mem::transmute(f) }
}

/// Restate a typed encoder as the untyped [`I2dOfVoid`], as in [`d2i_of`].
fn i2d_of<T>(f: unsafe extern "C" fn(*const T, *mut *mut c_uchar) -> c_int) -> I2dOfVoid {
    // SAFETY: as [`d2i_of`], the other direction.
    unsafe { core::mem::transmute(f) }
}

// ---------------------------------------------------------------------------------------------
// The sign / verify doors — `x_all.c:33-213`
// ---------------------------------------------------------------------------------------------

/// `int X509_verify(X509 *a, EVP_PKEY *r)` — `crypto/x509/x_all.c:33-41`.
///
/// The TBS signature algorithm must equal the outer one, then `ASN1_item_verify_ex` verifies the
/// signature over the `X509_CINF` item with the certificate's own distinguishing id, library
/// context and property query.
///
/// # Safety
///
/// `a` must be a live `X509`; `r` must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn X509_verify(a: *mut X509, r: *mut EvpPkey) -> c_int {
    // SAFETY: `a` is live per the contract.
    if unsafe { X509_ALGOR_cmp(&raw const (*a).sig_alg, &raw const (*a).cert_info.signature) } != 0
    {
        return 0;
    }
    // SAFETY: `a` is live and `X509_CINF_it()` is the crate's static item.
    unsafe {
        ASN1_item_verify_ex(
            X509_CINF_it(),
            &raw const (*a).sig_alg,
            &raw const (*a).signature,
            (&raw const (*a).cert_info).cast::<c_void>(),
            (*a).distinguishing_id,
            r,
            (*a).libctx,
            (*a).propq,
        )
    }
}

/// `int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r)` — `crypto/x509/x_all.c:71-75`.
///
/// The `_ex`-less `ASN1_item_verify` over the `NETSCAPE_SPKAC` item, against `a->sig_algor` and
/// `a->signature`. The object lands in this subphase (`src/asn1/x_spki.rs`).
///
/// # Safety
///
/// `a` must be a live `NETSCAPE_SPKI`; `r` a live key.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_verify(a: *mut NetScapeSpki, r: *mut EvpPkey) -> c_int {
    // SAFETY: `a` is live per the contract; `NETSCAPE_SPKAC_it()` is the crate's static item.
    unsafe {
        ASN1_item_verify(
            NETSCAPE_SPKAC_it(),
            &raw const (*a).sig_algor,
            (*a).signature,
            (*a).spkac.cast::<c_void>(),
            r,
        )
    }
}

/// `int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md)` —
/// `crypto/x509/x_all.c:209-213`.
///
/// # Safety
///
/// `x` must be a live `NETSCAPE_SPKI`; `pkey` a live key; `md` a live or NULL method.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_sign(
    x: *mut NetScapeSpki,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `x` is live per the contract; `NETSCAPE_SPKAC_it()` is the crate's static item.
    unsafe {
        ASN1_item_sign_ex(
            NETSCAPE_SPKAC_it(),
            &raw mut (*x).sig_algor,
            ptr::null_mut(),
            (*x).signature,
            (*x).spkac.cast::<c_void>(),
            ptr::null(),
            pkey,
            md,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int X509_REQ_verify_ex(X509_REQ *a, EVP_PKEY *r, OSSL_LIB_CTX *libctx, const char *propq)` --
/// `crypto/x509/x_all.c:43-54`.
///
/// A request whose version is not v1 is refused with `X509_R_UNSUPPORTED_VERSION` and answers
/// `-1`; otherwise the signature over `X509_REQ_INFO` is verified with the request's own
/// distinguishing id and the caller's library context/property query.
///
/// # Safety
///
/// `a` must be a live `X509_REQ`; `r` a live key; `libctx` NULL or live and `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_verify_ex(
    a: *mut X509Req,
    r: *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `a` is live per the contract.
    if unsafe { X509_REQ_get_version(a) } != X509_REQ_VERSION_1 {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_47) };
        return -1;
    }
    // SAFETY: `a` is live and `X509_REQ_INFO_it()` is the crate's static item.
    unsafe {
        ASN1_item_verify_ex(
            X509_REQ_INFO_it(),
            &raw const (*a).sig_alg,
            (*a).signature,
            (&raw const (*a).req_info).cast::<c_void>(),
            (*a).distinguishing_id,
            r,
            libctx,
            propq,
        )
    }
}

/// `int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r)` -- `crypto/x509/x_all.c:56-59`.
///
/// # Safety
///
/// `a` must be a live `X509_REQ`; `r` a live key.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_verify(a: *mut X509Req, r: *mut EvpPkey) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { X509_REQ_verify_ex(a, r, ptr::null_mut(), ptr::null()) }
}

/// `int X509_ACERT_verify(X509_ACERT *a, EVP_PKEY *r)` -- `crypto/x509/x_all.c:61-69`.
///
/// The TBS signature algorithm must equal the outer one, then `ASN1_item_verify_ex` verifies the
/// signature over the `X509_ACERT_INFO` item with a NULL distinguishing id and NULL
/// context/property query -- the attribute certificate carries neither.
///
/// # Safety
///
/// `a` must be a live `X509_ACERT`; `r` a live key.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_verify(a: *mut X509Acert, r: *mut EvpPkey) -> c_int {
    // SAFETY: `a` is live per the contract.
    if unsafe { X509_ALGOR_cmp(&raw const (*a).sig_alg, &raw const (*(*a).acinfo).signature) } != 0
    {
        return 0;
    }
    // SAFETY: `a` is live and `X509_ACERT_INFO_it()` is the crate's static item.
    unsafe {
        ASN1_item_verify_ex(
            X509_ACERT_INFO_it(),
            &raw const (*a).sig_alg,
            &raw const (*a).signature,
            (*a).acinfo.cast::<c_void>(),
            ptr::null(),
            r,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)` -- `crypto/x509/x_all.c:140-150`.
///
/// A NULL request is refused with `ERR_R_PASSED_NULL_PARAMETER`; the cached encoding is marked
/// stale before `ASN1_item_sign_ex` signs the `X509_REQ_INFO` item with the request's own library
/// context and property query.
///
/// # Safety
///
/// `x` must be NULL or live; `pkey` a live key; `md` a live or NULL method.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_sign(
    x: *mut X509Req,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_143) };
        return 0;
    }
    // SAFETY: `x` is live per the check above and its body is writable.
    unsafe {
        (*x).req_info.enc.modified = 1;
        ASN1_item_sign_ex(
            X509_REQ_INFO_it(),
            &raw mut (*x).sig_alg,
            ptr::null_mut(),
            (*x).signature,
            (&raw const (*x).req_info).cast::<c_void>(),
            ptr::null(),
            pkey,
            md,
            (*x).libctx,
            (*x).propq,
        )
    }
}

/// `int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx)` -- `crypto/x509/x_all.c:152-162`.
///
/// As [`X509_REQ_sign`] but the digest context carries the key and method.
///
/// # Safety
///
/// `x` must be NULL or live; `ctx` a live initialised signing context.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_sign_ctx(
    x: *mut X509Req,
    ctx: *mut crate::evp::digest::EvpMdCtx,
) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_155) };
        return 0;
    }
    // SAFETY: `x` is live per the check above and its body is writable.
    unsafe {
        (*x).req_info.enc.modified = 1;
        ASN1_item_sign_ctx(
            X509_REQ_INFO_it(),
            &raw mut (*x).sig_alg,
            ptr::null_mut(),
            (*x).signature,
            (&raw const (*x).req_info).cast::<c_void>(),
            ctx,
        )
    }
}

/// `int X509_ACERT_sign(X509_ACERT *x, EVP_PKEY *pkey, const EVP_MD *md)` --
/// `crypto/x509/x_all.c:194-200`.
///
/// Signs the `X509_ACERT_INFO` item, writing the signature algorithm into both the outer
/// `sig_alg` and the info's `signature`, with a NULL library context and property query.
///
/// # Safety
///
/// `x` must be a live `X509_ACERT`; `pkey` a live key; `md` a live or NULL method.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_sign(
    x: *mut X509Acert,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `x` is live per the contract and its body is writable.
    unsafe {
        ASN1_item_sign_ex(
            X509_ACERT_INFO_it(),
            &raw mut (*x).sig_alg,
            &raw mut (*(*x).acinfo).signature,
            &raw mut (*x).signature,
            (*x).acinfo.cast::<c_void>(),
            ptr::null(),
            pkey,
            md,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int X509_ACERT_sign_ctx(X509_ACERT *x, EVP_MD_CTX *ctx)` -- `crypto/x509/x_all.c:202-207`.
///
/// # Safety
///
/// `x` must be a live `X509_ACERT`; `ctx` a live initialised signing context.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_sign_ctx(
    x: *mut X509Acert,
    ctx: *mut crate::evp::digest::EvpMdCtx,
) -> c_int {
    // SAFETY: `x` is live per the contract and its body is writable.
    unsafe {
        ASN1_item_sign_ctx(
            X509_ACERT_INFO_it(),
            &raw mut (*x).sig_alg,
            &raw mut (*(*x).acinfo).signature,
            &raw mut (*x).signature,
            (*x).acinfo.cast::<c_void>(),
            ctx,
        )
    }
}

/// `int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)` -- `crypto/x509/x_all.c:77-98`.
///
/// A NULL certificate is refused with `ERR_R_PASSED_NULL_PARAMETER`; a certificate with
/// extensions is forced to v3; the cached encoding is marked stale before signing, so a changed
/// field is signed correctly.
///
/// # Safety
///
/// `x` must be NULL or live; `pkey` a live key; `md` a live or NULL method.
#[no_mangle]
pub unsafe extern "C" fn X509_sign(x: *mut X509, pkey: *mut EvpPkey, md: *const EvpMd) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_80) };
        return 0;
    }
    // SAFETY: `x` is live per the check above, so both the read and the setter are sound.
    let needs_v3 = unsafe {
        OPENSSL_sk_num(X509_get0_extensions(x)) > 0 && X509_set_version(x, X509_VERSION_3) == 0
    };
    if needs_v3 {
        return 0;
    }
    // SAFETY: `x` is live and its body is writable.
    unsafe {
        (*x).cert_info.enc.modified = 1;
        ASN1_item_sign_ex(
            X509_CINF_it(),
            &raw mut (*x).cert_info.signature,
            &raw mut (*x).sig_alg,
            &raw mut (*x).signature,
            (&raw const (*x).cert_info).cast::<c_void>(),
            ptr::null(),
            pkey,
            md,
            (*x).libctx,
            (*x).propq,
        )
    }
}

/// `int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx)` — `crypto/x509/x_all.c:100-113`.
///
/// As [`X509_sign`] but the digest context carries the key and method.
///
/// # Safety
///
/// `x` must be NULL or live; `ctx` a live initialised signing context.
#[no_mangle]
pub unsafe extern "C" fn X509_sign_ctx(
    x: *mut X509,
    ctx: *mut crate::evp::digest::EvpMdCtx,
) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_103) };
        return 0;
    }
    // SAFETY: `x` is live per the check above, so both the read and the setter are sound.
    let needs_v3 = unsafe {
        OPENSSL_sk_num(X509_get0_extensions(x)) > 0 && X509_set_version(x, X509_VERSION_3) == 0
    };
    if needs_v3 {
        return 0;
    }
    // SAFETY: `x` is live and its body is writable.
    unsafe {
        (*x).cert_info.enc.modified = 1;
        ASN1_item_sign_ctx(
            X509_CINF_it(),
            &raw mut (*x).cert_info.signature,
            &raw mut (*x).sig_alg,
            &raw mut (*x).signature,
            (&raw const (*x).cert_info).cast::<c_void>(),
            ctx,
        )
    }
}

/// `int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md)` —
/// `crypto/x509/x_all.c:164-174`.
///
/// # Safety
///
/// `x` must be NULL or live; `pkey` a live key; `md` a live or NULL method.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_sign(
    x: *mut X509Crl,
    pkey: *mut EvpPkey,
    md: *const EvpMd,
) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_167) };
        return 0;
    }
    // SAFETY: `x` is live and its body is writable.
    unsafe {
        (*x).crl.enc.modified = 1;
        ASN1_item_sign_ex(
            X509_CRL_INFO_it(),
            &raw mut (*x).crl.sig_alg,
            &raw mut (*x).sig_alg,
            &raw mut (*x).signature,
            (&raw const (*x).crl).cast::<c_void>(),
            ptr::null(),
            pkey,
            md,
            (*x).libctx,
            (*x).propq,
        )
    }
}

/// `int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx)` — `crypto/x509/x_all.c:176-186`.
///
/// # Safety
///
/// `x` must be NULL or live; `ctx` a live initialised signing context.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_sign_ctx(
    x: *mut X509Crl,
    ctx: *mut crate::evp::digest::EvpMdCtx,
) -> c_int {
    if x.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_179) };
        return 0;
    }
    // SAFETY: `x` is live and its body is writable.
    unsafe {
        (*x).crl.enc.modified = 1;
        ASN1_item_sign_ctx(
            X509_CRL_INFO_it(),
            &raw mut (*x).crl.sig_alg,
            &raw mut (*x).sig_alg,
            &raw mut (*x).signature,
            (&raw const (*x).crl).cast::<c_void>(),
            ctx,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The HTTP loaders — `x_all.c:114-138`, `:188-192`
// ---------------------------------------------------------------------------------------------

/// `static ASN1_VALUE *simple_get_asn1(const char *url, BIO *bio, BIO *rbio, int timeout,
/// const ASN1_ITEM *it)` — `crypto/x509/x_all.c:115-132`.
///
/// One `GET` through [`OSSL_HTTP_get`], with the authority's fixed `1024`-byte request buffer,
/// `NULL` proxy/no-proxy/headers/expected content type, redirects enabled and ASN.1 expected;
/// the response cap is [`OSSL_HTTP_DEFAULT_MAX_CRL_LEN`] for a CRL and
/// [`OSSL_HTTP_DEFAULT_MAX_RESP_LEN`] for everything else. The response BIO is decoded with
/// [`ASN1_item_d2i_bio`] and released before answering.
///
/// # Safety
///
/// `url` must be NUL-terminated; `bio`/`rbio` NULL or live; `it` a live item.
unsafe fn simple_get_asn1(
    url: *const c_char,
    bio: *mut Bio,
    rbio: *mut Bio,
    timeout: c_int,
    it: *const Asn1Item,
) -> *mut c_void {
    let max_resp_len = if it == X509_CRL_it() {
        OSSL_HTTP_DEFAULT_MAX_CRL_LEN
    } else {
        OSSL_HTTP_DEFAULT_MAX_RESP_LEN
    };
    // SAFETY: `url` is NUL-terminated per the contract and `bio`/`rbio` are the caller's; the
    // NULL proxy, no-proxy, callback, argument, headers and expected-content-type arguments and
    // the fixed buffer size and expectations are the authority's own.
    let mem = unsafe {
        OSSL_HTTP_get(
            url,
            ptr::null(), /* proxy */
            ptr::null(), /* no_proxy */
            bio,
            rbio,
            None,            /* cb */
            ptr::null_mut(), /* arg */
            1024,            /* buf_size */
            ptr::null(),     /* headers */
            ptr::null(),     /* expected_ct */
            1,               /* expect_asn1 */
            max_resp_len,
            timeout,
        )
    };
    // SAFETY: `it` is a live item and `mem` is NULL or a live BIO per `OSSL_HTTP_get`.
    let res = unsafe { ASN1_item_d2i_bio(it, mem, ptr::null_mut()) };
    // SAFETY: `mem` is this call's BIO or NULL, which `BIO_free` accepts.
    unsafe { BIO_free(mem) };
    res
}

/// `X509 *X509_load_http(const char *url, BIO *bio, BIO *rbio, int timeout)` —
/// `crypto/x509/x_all.c:134-138`.
///
/// # Safety
///
/// `url` must be NUL-terminated; `bio`/`rbio` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_load_http(
    url: *const c_char,
    bio: *mut Bio,
    rbio: *mut Bio,
    timeout: c_int,
) -> *mut X509 {
    // SAFETY: the caller's contract, forwarded; `X509_it()` is a static item.
    unsafe { simple_get_asn1(url, bio, rbio, timeout, X509_it()).cast::<X509>() }
}

/// `X509_CRL *X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout)` —
/// `crypto/x509/x_all.c:188-192`.
///
/// # Safety
///
/// `url` must be NUL-terminated; `bio`/`rbio` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_load_http(
    url: *const c_char,
    bio: *mut Bio,
    rbio: *mut Bio,
    timeout: c_int,
) -> *mut X509Crl {
    // SAFETY: the caller's contract, forwarded; `X509_CRL_it()` is a static item.
    unsafe { simple_get_asn1(url, bio, rbio, timeout, X509_CRL_it()).cast::<X509Crl>() }
}

// ---------------------------------------------------------------------------------------------
// The certificate and CRL stream faces — `x_all.c:216-257`
// ---------------------------------------------------------------------------------------------

/// `X509 *d2i_X509_fp(FILE *fp, X509 **x509)` — `crypto/x509/x_all.c:216-219`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `x509` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_fp(fp: *mut FILE, x509: *mut *mut X509) -> *mut X509 {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(X509_it(), fp, x509.cast::<c_void>()).cast::<X509>() }
}

/// `int i2d_X509_fp(FILE *fp, const X509 *x509)` — `crypto/x509/x_all.c:221-224`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `x509` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_fp(fp: *mut FILE, x509: *const X509) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(X509_it(), fp, x509.cast::<c_void>()) }
}

/// `X509 *d2i_X509_bio(BIO *bp, X509 **x509)` — `crypto/x509/x_all.c:227-230`.
///
/// # Safety
///
/// `bp` must be a live BIO; `x509` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_bio(bp: *mut Bio, x509: *mut *mut X509) -> *mut X509 {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(X509_it(), bp, x509.cast::<c_void>()).cast::<X509>() }
}

/// `int i2d_X509_bio(BIO *bp, const X509 *x509)` — `crypto/x509/x_all.c:232-235`.
///
/// # Safety
///
/// `bp` must be a live BIO; `x509` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_bio(bp: *mut Bio, x509: *const X509) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(X509_it(), bp, x509.cast::<c_void>()) }
}

/// `X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl)` — `crypto/x509/x_all.c:238-241`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `crl` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL_fp(fp: *mut FILE, crl: *mut *mut X509Crl) -> *mut X509Crl {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(X509_CRL_it(), fp, crl.cast::<c_void>()).cast::<X509Crl>() }
}

/// `int i2d_X509_CRL_fp(FILE *fp, const X509_CRL *crl)` — `crypto/x509/x_all.c:243-246`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `crl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL_fp(fp: *mut FILE, crl: *const X509Crl) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(X509_CRL_it(), fp, crl.cast::<c_void>()) }
}

/// `X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl)` — `crypto/x509/x_all.c:249-252`.
///
/// # Safety
///
/// `bp` must be a live BIO; `crl` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL_bio(bp: *mut Bio, crl: *mut *mut X509Crl) -> *mut X509Crl {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(X509_CRL_it(), bp, crl.cast::<c_void>()).cast::<X509Crl>() }
}

/// `int i2d_X509_CRL_bio(BIO *bp, const X509_CRL *crl)` — `crypto/x509/x_all.c:254-257`.
///
/// # Safety
///
/// `bp` must be a live BIO; `crl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL_bio(bp: *mut Bio, crl: *const X509Crl) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(X509_CRL_it(), bp, crl.cast::<c_void>()) }
}

// ---------------------------------------------------------------------------------------------
// The PKCS#7 stream faces — `x_all.c:260-303`
// ---------------------------------------------------------------------------------------------

/// `PKCS7 *d2i_PKCS7_fp(FILE *fp, PKCS7 **p7)` — `crypto/x509/x_all.c:260-275`.
///
/// When `*p7` is non-NULL its library context and property query are threaded into
/// `ASN1_item_d2i_fp_ex`, and a successful decode resolves the result's own context.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p7` NULL or a writable slot holding NULL or a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_fp(fp: *mut FILE, p7: *mut *mut Pkcs7) -> *mut Pkcs7 {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    if !p7.is_null() {
        // SAFETY: `p7` is a non-null writable slot per the contract.
        let existing = unsafe { *p7 };
        if !existing.is_null() {
            // SAFETY: `existing` is live per the check above.
            libctx = unsafe { (*existing).ctx.libctx };
            // SAFETY: as above.
            propq = unsafe { (*existing).ctx.propq };
        }
    }
    // SAFETY: `fp`/`p7` are the caller's and the context/property query come from the object.
    let ret = unsafe {
        ASN1_item_d2i_fp_ex(PKCS7_it(), fp, p7.cast::<c_void>(), libctx, propq).cast::<Pkcs7>()
    };
    if !ret.is_null() {
        // SAFETY: `ret` is the just-decoded live `PKCS7`.
        unsafe { ossl_pkcs7_resolve_libctx(ret) };
    }
    ret
}

/// `int i2d_PKCS7_fp(FILE *fp, const PKCS7 *p7)` — `crypto/x509/x_all.c:277-280`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p7` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_fp(fp: *mut FILE, p7: *const Pkcs7) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(PKCS7_it(), fp, p7.cast::<c_void>()) }
}

/// `PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7)` — `crypto/x509/x_all.c:283-298`.
///
/// The `_bio` twin of [`d2i_PKCS7_fp`], with the same context threading.
///
/// # Safety
///
/// `bp` must be a live BIO; `p7` NULL or a writable slot holding NULL or a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_bio(bp: *mut Bio, p7: *mut *mut Pkcs7) -> *mut Pkcs7 {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    if !p7.is_null() {
        // SAFETY: `p7` is a non-null writable slot per the contract.
        let existing = unsafe { *p7 };
        if !existing.is_null() {
            // SAFETY: `existing` is live per the check above.
            libctx = unsafe { (*existing).ctx.libctx };
            // SAFETY: as above.
            propq = unsafe { (*existing).ctx.propq };
        }
    }
    // SAFETY: `bp`/`p7` are the caller's and the context/property query come from the object.
    let ret = unsafe {
        ASN1_item_d2i_bio_ex(PKCS7_it(), bp, p7.cast::<c_void>(), libctx, propq).cast::<Pkcs7>()
    };
    if !ret.is_null() {
        // SAFETY: `ret` is the just-decoded live `PKCS7`.
        unsafe { ossl_pkcs7_resolve_libctx(ret) };
    }
    ret
}

/// `int i2d_PKCS7_bio(BIO *bp, const PKCS7 *p7)` — `crypto/x509/x_all.c:300-303`.
///
/// # Safety
///
/// `bp` must be a live BIO; `p7` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_bio(bp: *mut Bio, p7: *const Pkcs7) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(PKCS7_it(), bp, p7.cast::<c_void>()) }
}

// ---------------------------------------------------------------------------------------------
// The request and attribute-certificate stream faces -- `x_all.c:306-333`, `:861-881`
// ---------------------------------------------------------------------------------------------

/// `X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req)` -- `crypto/x509/x_all.c:306-309`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `req` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ_fp(fp: *mut FILE, req: *mut *mut X509Req) -> *mut X509Req {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(X509_REQ_it(), fp, req.cast::<c_void>()).cast::<X509Req>() }
}

/// `int i2d_X509_REQ_fp(FILE *fp, const X509_REQ *req)` -- `crypto/x509/x_all.c:311-314`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `req` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ_fp(fp: *mut FILE, req: *const X509Req) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(X509_REQ_it(), fp, req.cast::<c_void>()) }
}

/// `X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req)` -- `crypto/x509/x_all.c:317-328`.
///
/// Unlike the other `_bio` faces this one binds the existing request's library context and
/// property query into `ASN1_item_d2i_bio_ex` when `*req` is non-NULL.
///
/// # Safety
///
/// `bp` must be a live BIO; `req` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ_bio(bp: *mut Bio, req: *mut *mut X509Req) -> *mut X509Req {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    if !req.is_null() {
        // SAFETY: `req` is a non-null writable slot per the contract.
        let existing = unsafe { *req };
        if !existing.is_null() {
            // SAFETY: `existing` is live per the check above.
            libctx = unsafe { (*existing).libctx };
            // SAFETY: as above.
            propq = unsafe { (*existing).propq };
        }
    }
    // SAFETY: `bp`/`req` are the caller's and the context/property query come from the request.
    unsafe {
        ASN1_item_d2i_bio_ex(X509_REQ_it(), bp, req.cast::<c_void>(), libctx, propq)
            .cast::<X509Req>()
    }
}

/// `int i2d_X509_REQ_bio(BIO *bp, const X509_REQ *req)` -- `crypto/x509/x_all.c:330-333`.
///
/// # Safety
///
/// `bp` must be a live BIO; `req` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ_bio(bp: *mut Bio, req: *const X509Req) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(X509_REQ_it(), bp, req.cast::<c_void>()) }
}

/// `X509_ACERT *d2i_X509_ACERT_fp(FILE *fp, X509_ACERT **acert)` -- `crypto/x509/x_all.c:862-865`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `acert` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ACERT_fp(
    fp: *mut FILE,
    acert: *mut *mut X509Acert,
) -> *mut X509Acert {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(X509_ACERT_it(), fp, acert.cast::<c_void>()).cast::<X509Acert>() }
}

/// `int i2d_X509_ACERT_fp(FILE *fp, const X509_ACERT *acert)` -- `crypto/x509/x_all.c:867-870`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `acert` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ACERT_fp(fp: *mut FILE, acert: *const X509Acert) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(X509_ACERT_it(), fp, acert.cast::<c_void>()) }
}

/// `X509_ACERT *d2i_X509_ACERT_bio(BIO *bp, X509_ACERT **acert)` -- `crypto/x509/x_all.c:873-876`.
///
/// # Safety
///
/// `bp` must be a live BIO; `acert` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ACERT_bio(
    bp: *mut Bio,
    acert: *mut *mut X509Acert,
) -> *mut X509Acert {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(X509_ACERT_it(), bp, acert.cast::<c_void>()).cast::<X509Acert>() }
}

/// `int i2d_X509_ACERT_bio(BIO *bp, const X509_ACERT *acert)` -- `crypto/x509/x_all.c:878-881`.
///
/// # Safety
///
/// `bp` must be a live BIO; `acert` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ACERT_bio(bp: *mut Bio, acert: *const X509Acert) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(X509_ACERT_it(), bp, acert.cast::<c_void>()) }
}

// ---------------------------------------------------------------------------------------------
// The RSA key stream faces — `x_all.c:336-398`
// ---------------------------------------------------------------------------------------------

/// `RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa)` — `crypto/x509/x_all.c:336-339`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPrivateKey_fp(fp: *mut FILE, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(RSAPrivateKey_it(), fp, rsa.cast::<c_void>()).cast::<Rsa>() }
}

/// `int i2d_RSAPrivateKey_fp(FILE *fp, const RSA *rsa)` — `crypto/x509/x_all.c:341-344`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPrivateKey_fp(fp: *mut FILE, rsa: *const Rsa) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(RSAPrivateKey_it(), fp, rsa.cast::<c_void>()) }
}

/// `RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa)` — `crypto/x509/x_all.c:346-349`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPublicKey_fp(fp: *mut FILE, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(RSAPublicKey_it(), fp, rsa.cast::<c_void>()).cast::<Rsa>() }
}

/// `RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa)` — `crypto/x509/x_all.c:351-357`, the
/// `ASN1_d2i_fp((void *(*)(void))RSA_new, (d2i_of_void *)d2i_RSA_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_PUBKEY_fp(fp: *mut FILE, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: `fp`/`rsa` are the caller's; `d2i_of` restates `d2i_RSA_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<Rsa>(d2i_RSA_PUBKEY),
            fp,
            rsa.cast::<*mut c_void>(),
        )
        .cast::<Rsa>()
    }
}

/// `int i2d_RSAPublicKey_fp(FILE *fp, const RSA *rsa)` — `crypto/x509/x_all.c:359-362`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPublicKey_fp(fp: *mut FILE, rsa: *const Rsa) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(RSAPublicKey_it(), fp, rsa.cast::<c_void>()) }
}

/// `int i2d_RSA_PUBKEY_fp(FILE *fp, const RSA *rsa)` — `crypto/x509/x_all.c:364-367`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_PUBKEY_fp(fp: *mut FILE, rsa: *const Rsa) -> c_int {
    // SAFETY: `fp`/`rsa` are the caller's; `i2d_of` restates `i2d_RSA_PUBKEY`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<Rsa>(i2d_RSA_PUBKEY), fp, rsa.cast::<c_void>()) }
}

/// `RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa)` — `crypto/x509/x_all.c:370-373`.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPrivateKey_bio(bp: *mut Bio, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(RSAPrivateKey_it(), bp, rsa.cast::<c_void>()).cast::<Rsa>() }
}

/// `int i2d_RSAPrivateKey_bio(BIO *bp, const RSA *rsa)` — `crypto/x509/x_all.c:375-378`.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPrivateKey_bio(bp: *mut Bio, rsa: *const Rsa) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(RSAPrivateKey_it(), bp, rsa.cast::<c_void>()) }
}

/// `RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa)` — `crypto/x509/x_all.c:380-383`.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPublicKey_bio(bp: *mut Bio, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(RSAPublicKey_it(), bp, rsa.cast::<c_void>()).cast::<Rsa>() }
}

/// `RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa)` — `crypto/x509/x_all.c:385-388`, the
/// `ASN1_d2i_bio_of(RSA, RSA_new, d2i_RSA_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_PUBKEY_bio(bp: *mut Bio, rsa: *mut *mut Rsa) -> *mut Rsa {
    // SAFETY: `bp`/`rsa` are the caller's; `d2i_of` restates `d2i_RSA_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<Rsa>(d2i_RSA_PUBKEY),
            bp,
            rsa.cast::<*mut c_void>(),
        )
        .cast::<Rsa>()
    }
}

/// `int i2d_RSAPublicKey_bio(BIO *bp, const RSA *rsa)` — `crypto/x509/x_all.c:390-393`.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPublicKey_bio(bp: *mut Bio, rsa: *const Rsa) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(RSAPublicKey_it(), bp, rsa.cast::<c_void>()) }
}

/// `int i2d_RSA_PUBKEY_bio(BIO *bp, const RSA *rsa)` — `crypto/x509/x_all.c:395-398`.
///
/// # Safety
///
/// `bp` must be a live BIO; `rsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_PUBKEY_bio(bp: *mut Bio, rsa: *const Rsa) -> c_int {
    // SAFETY: `bp`/`rsa` are the caller's; `i2d_of` restates `i2d_RSA_PUBKEY`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<Rsa>(i2d_RSA_PUBKEY), bp, rsa.cast::<c_void>()) }
}

// ---------------------------------------------------------------------------------------------
// The DSA key stream faces — `x_all.c:402-441`
// ---------------------------------------------------------------------------------------------

/// `DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)` — `crypto/x509/x_all.c:402-405`, the
/// `ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSAPrivateKey, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `dsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSAPrivateKey_fp(fp: *mut FILE, dsa: *mut *mut Dsa) -> *mut Dsa {
    // SAFETY: `fp`/`dsa` are the caller's; `d2i_of` restates `d2i_DSAPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<Dsa>(d2i_DSAPrivateKey),
            fp,
            dsa.cast::<*mut c_void>(),
        )
        .cast::<Dsa>()
    }
}

/// `int i2d_DSAPrivateKey_fp(FILE *fp, const DSA *dsa)` — `crypto/x509/x_all.c:407-410`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `dsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSAPrivateKey_fp(fp: *mut FILE, dsa: *const Dsa) -> c_int {
    // SAFETY: `fp`/`dsa` are the caller's; `i2d_of` restates `i2d_DSAPrivateKey`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<Dsa>(i2d_DSAPrivateKey), fp, dsa.cast::<c_void>()) }
}

/// `DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa)` — `crypto/x509/x_all.c:412-415`, the
/// `ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSA_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `dsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSA_PUBKEY_fp(fp: *mut FILE, dsa: *mut *mut Dsa) -> *mut Dsa {
    // SAFETY: `fp`/`dsa` are the caller's; `d2i_of` restates `d2i_DSA_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<Dsa>(d2i_DSA_PUBKEY),
            fp,
            dsa.cast::<*mut c_void>(),
        )
        .cast::<Dsa>()
    }
}

/// `int i2d_DSA_PUBKEY_fp(FILE *fp, const DSA *dsa)` — `crypto/x509/x_all.c:417-420`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `dsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSA_PUBKEY_fp(fp: *mut FILE, dsa: *const Dsa) -> c_int {
    // SAFETY: `fp`/`dsa` are the caller's; `i2d_of` restates `i2d_DSA_PUBKEY`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<Dsa>(i2d_DSA_PUBKEY), fp, dsa.cast::<c_void>()) }
}

/// `DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa)` — `crypto/x509/x_all.c:423-426`.
///
/// # Safety
///
/// `bp` must be a live BIO; `dsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSAPrivateKey_bio(bp: *mut Bio, dsa: *mut *mut Dsa) -> *mut Dsa {
    // SAFETY: `bp`/`dsa` are the caller's; `d2i_of` restates `d2i_DSAPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<Dsa>(d2i_DSAPrivateKey),
            bp,
            dsa.cast::<*mut c_void>(),
        )
        .cast::<Dsa>()
    }
}

/// `int i2d_DSAPrivateKey_bio(BIO *bp, const DSA *dsa)` — `crypto/x509/x_all.c:428-431`.
///
/// # Safety
///
/// `bp` must be a live BIO; `dsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSAPrivateKey_bio(bp: *mut Bio, dsa: *const Dsa) -> c_int {
    // SAFETY: `bp`/`dsa` are the caller's; `i2d_of` restates `i2d_DSAPrivateKey`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<Dsa>(i2d_DSAPrivateKey), bp, dsa.cast::<c_void>()) }
}

/// `DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa)` — `crypto/x509/x_all.c:433-436`.
///
/// # Safety
///
/// `bp` must be a live BIO; `dsa` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_DSA_PUBKEY_bio(bp: *mut Bio, dsa: *mut *mut Dsa) -> *mut Dsa {
    // SAFETY: `bp`/`dsa` are the caller's; `d2i_of` restates `d2i_DSA_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<Dsa>(d2i_DSA_PUBKEY),
            bp,
            dsa.cast::<*mut c_void>(),
        )
        .cast::<Dsa>()
    }
}

/// `int i2d_DSA_PUBKEY_bio(BIO *bp, const DSA *dsa)` — `crypto/x509/x_all.c:438-441`.
///
/// # Safety
///
/// `bp` must be a live BIO; `dsa` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_DSA_PUBKEY_bio(bp: *mut Bio, dsa: *const Dsa) -> c_int {
    // SAFETY: `bp`/`dsa` are the caller's; `i2d_of` restates `i2d_DSA_PUBKEY`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<Dsa>(i2d_DSA_PUBKEY), bp, dsa.cast::<c_void>()) }
}

// ---------------------------------------------------------------------------------------------
// The EC key stream faces — `x_all.c:447-485`
// ---------------------------------------------------------------------------------------------

/// `EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)` — `crypto/x509/x_all.c:447-450`, the
/// `ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `eckey` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_EC_PUBKEY_fp(fp: *mut FILE, eckey: *mut *mut EcKey) -> *mut EcKey {
    // SAFETY: `fp`/`eckey` are the caller's; `d2i_of` restates `d2i_EC_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<EcKey>(d2i_EC_PUBKEY),
            fp,
            eckey.cast::<*mut c_void>(),
        )
        .cast::<EcKey>()
    }
}

/// `int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *eckey)` — `crypto/x509/x_all.c:452-455`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `eckey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_EC_PUBKEY_fp(fp: *mut FILE, eckey: *const EcKey) -> c_int {
    // SAFETY: `fp`/`eckey` are the caller's; `i2d_of` restates `i2d_EC_PUBKEY`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<EcKey>(i2d_EC_PUBKEY), fp, eckey.cast::<c_void>()) }
}

/// `EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)` — `crypto/x509/x_all.c:457-460`, the
/// `ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `eckey` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECPrivateKey_fp(fp: *mut FILE, eckey: *mut *mut EcKey) -> *mut EcKey {
    // SAFETY: `fp`/`eckey` are the caller's; `d2i_of` restates `d2i_ECPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<EcKey>(d2i_ECPrivateKey),
            fp,
            eckey.cast::<*mut c_void>(),
        )
        .cast::<EcKey>()
    }
}

/// `int i2d_ECPrivateKey_fp(FILE *fp, const EC_KEY *eckey)` — `crypto/x509/x_all.c:462-465`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `eckey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECPrivateKey_fp(fp: *mut FILE, eckey: *const EcKey) -> c_int {
    // SAFETY: `fp`/`eckey` are the caller's; `i2d_of` restates `i2d_ECPrivateKey`'s contract.
    unsafe {
        ASN1_i2d_fp(
            i2d_of::<EcKey>(i2d_ECPrivateKey),
            fp,
            eckey.cast::<c_void>(),
        )
    }
}

/// `EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)` — `crypto/x509/x_all.c:467-470`.
///
/// # Safety
///
/// `bp` must be a live BIO; `eckey` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_EC_PUBKEY_bio(bp: *mut Bio, eckey: *mut *mut EcKey) -> *mut EcKey {
    // SAFETY: `bp`/`eckey` are the caller's; `d2i_of` restates `d2i_EC_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<EcKey>(d2i_EC_PUBKEY),
            bp,
            eckey.cast::<*mut c_void>(),
        )
        .cast::<EcKey>()
    }
}

/// `int i2d_EC_PUBKEY_bio(BIO *bp, const EC_KEY *eckey)` — `crypto/x509/x_all.c:472-475`.
///
/// # Safety
///
/// `bp` must be a live BIO; `eckey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_EC_PUBKEY_bio(bp: *mut Bio, eckey: *const EcKey) -> c_int {
    // SAFETY: `bp`/`eckey` are the caller's; `i2d_of` restates `i2d_EC_PUBKEY`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<EcKey>(i2d_EC_PUBKEY), bp, eckey.cast::<c_void>()) }
}

/// `EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)` — `crypto/x509/x_all.c:477-480`.
///
/// # Safety
///
/// `bp` must be a live BIO; `eckey` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECPrivateKey_bio(bp: *mut Bio, eckey: *mut *mut EcKey) -> *mut EcKey {
    // SAFETY: `bp`/`eckey` are the caller's; `d2i_of` restates `d2i_ECPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<EcKey>(d2i_ECPrivateKey),
            bp,
            eckey.cast::<*mut c_void>(),
        )
        .cast::<EcKey>()
    }
}

/// `int i2d_ECPrivateKey_bio(BIO *bp, const EC_KEY *eckey)` — `crypto/x509/x_all.c:482-485`.
///
/// # Safety
///
/// `bp` must be a live BIO; `eckey` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECPrivateKey_bio(bp: *mut Bio, eckey: *const EcKey) -> c_int {
    // SAFETY: `bp`/`eckey` are the caller's; `i2d_of` restates `i2d_ECPrivateKey`'s contract.
    unsafe {
        ASN1_i2d_bio(
            i2d_of::<EcKey>(i2d_ECPrivateKey),
            bp,
            eckey.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The digest family — `x_all.c:488-648`
// ---------------------------------------------------------------------------------------------

/// `int X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char *md,
/// unsigned int *len)` — `crypto/x509/x_all.c:488-496`.
///
/// Digests the certificate's `subjectPublicKey` **bit string** — the raw key octets, not the
/// `SubjectPublicKeyInfo` DER. A certificate with no key bit string answers 0.
///
/// # Safety
///
/// `data` must be a live `X509`; `type` a live method; `md` writable for the digest size and
/// `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_pubkey_digest(
    data: *const X509,
    type_: *const EvpMd,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: `data` is live per the contract.
    let key = unsafe { X509_get0_pubkey_bitstr(data) };
    if key.is_null() {
        return 0;
    }
    // SAFETY: `key` is live per the check above; the digest writes `md`/`len`.
    unsafe {
        EVP_Digest(
            (*key).data.cast::<c_void>(),
            (*key).length as usize,
            md,
            len,
            type_,
            ptr::null_mut(),
        )
    }
}

/// `int X509_digest(const X509 *cert, const EVP_MD *md, unsigned char *data,
/// unsigned int *len)` — `crypto/x509/x_all.c:498-511`.
///
/// Asking for SHA-1 on a certificate whose extension cache is built and whose fingerprint is
/// present answers from the cached `sha1_hash`; every other request DER-encodes the whole
/// certificate and digests that through `ossl_asn1_item_digest_ex`.
///
/// # Safety
///
/// `cert` must be a live `X509`; `md` a live method; `data` writable for the digest size and
/// `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_digest(
    cert: *const X509,
    md: *const EvpMd,
    data: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: `cert` is live per the contract.
    unsafe {
        if EVP_MD_is_a(md, SN_SHA1.as_ptr()) != 0
            && ((*cert).ex_flags & EXFLAG_SET) != 0
            && ((*cert).ex_flags & EXFLAG_NO_FINGERPRINT) == 0
        {
            if !len.is_null() {
                *len = 20;
            }
            ptr::copy_nonoverlapping((*cert).sha1_hash.as_ptr(), data, 20);
            return 1;
        }
        ossl_asn1_item_digest_ex(
            X509_it(),
            md,
            cert.cast_mut().cast::<c_void>(),
            data,
            len,
            (*cert).libctx,
            (*cert).propq,
        )
    }
}

/// `ASN1_OCTET_STRING *X509_digest_sig(const X509 *cert, EVP_MD **md_used,
/// int *md_is_fallback)` — `crypto/x509/x_all.c:514-606`.
///
/// Digests the certificate with the algorithm named by its own signature. A PSS signature
/// resolves its digest out of the `RSASSA-PSS-params`; a signature with a known public-key
/// algorithm but no digest follows the RFC 8419 default for Ed25519/Ed448 (SHA-512/SHAKE-256)
/// or falls back to SHA-256; a completely unknown one is refused
/// (`X509_R_UNSUPPORTED_ALGORITHM`). `*md_used`, when non-NULL, receives the fetched method —
/// the caller then owns it — otherwise this call releases it.
///
/// # Safety
///
/// `cert` must be NULL or a live `X509`; `md_used` NULL or a writable method slot;
/// `md_is_fallback` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_digest_sig(
    cert: *const X509,
    md_used: *mut *mut EvpMd,
    md_is_fallback: *mut c_int,
) -> *mut Asn1String {
    let mut hash = [0u8; EVP_MAX_MD_SIZE];
    let mut len: c_uint = 0;
    let mut mdnid: c_int = 0;
    let mut pknid: c_int = 0;
    let mut md: *mut EvpMd;
    let md_name: *const c_char;

    if !md_used.is_null() {
        // SAFETY: `md_used` is writable per the contract.
        unsafe { *md_used = ptr::null_mut() };
    }
    if !md_is_fallback.is_null() {
        // SAFETY: `md_is_fallback` is writable per the contract.
        unsafe { *md_is_fallback = 0 };
    }
    if cert.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_530) };
        return ptr::null_mut();
    }

    // SAFETY: `cert` is live per the check above.
    unsafe {
        if OBJ_find_sigid_algs(X509_get_signature_nid(cert), &raw mut mdnid, &raw mut pknid) == 0 {
            raise_site(&err_sites::X509_ALL_535);
            return ptr::null_mut();
        }

        if mdnid == NID_undef {
            if pknid == EVP_PKEY_RSA_PSS {
                let pss = ossl_rsa_pss_decode(&raw const (*cert).sig_alg);
                let mut mgf1md: *const EvpMd = ptr::null();
                let mut mmd: *const EvpMd = ptr::null();
                let mut saltlen: c_int = 0;
                let mut trailerfield: c_int = 0;
                if pss.is_null()
                    || ossl_rsa_pss_get_param_unverified(
                        pss,
                        &raw mut mmd,
                        &raw mut mgf1md,
                        &raw mut saltlen,
                        &raw mut trailerfield,
                    ) == 0
                    || mmd.is_null()
                {
                    RSA_PSS_PARAMS_free(pss);
                    raise_site(&err_sites::X509_ALL_551);
                    return ptr::null_mut();
                }
                RSA_PSS_PARAMS_free(pss);
                /* Fetch explicitly and do not fall back. */
                md = EVP_MD_fetch((*cert).libctx, EVP_MD_get0_name(mmd), (*cert).propq);
                if md.is_null() {
                    return ptr::null_mut();
                }
            } else if pknid != NID_undef {
                md_name = match pknid {
                    NID_ED25519 => c"SHA512".as_ptr(),
                    NID_ED448 => c"SHAKE256".as_ptr(),
                    _ => c"SHA256".as_ptr(),
                };
                md = EVP_MD_fetch((*cert).libctx, md_name, (*cert).propq);
                if md.is_null() {
                    return ptr::null_mut();
                }
                if !md_is_fallback.is_null() {
                    *md_is_fallback = 1;
                }
            } else {
                raise_site(&err_sites::X509_ALL_582);
                return ptr::null_mut();
            }
        } else {
            md = EVP_MD_fetch((*cert).libctx, OBJ_nid2sn(mdnid), (*cert).propq);
            if md.is_null() {
                /* `EVP_get_digestbynid(mdnid)` — `include/openssl/evp.h`, the macro
                 * `EVP_get_digestbyname(OBJ_nid2sn(nid))`. */
                md = EVP_get_digestbyname(OBJ_nid2sn(mdnid)) as *mut EvpMd;
                if md.is_null() {
                    raise_site(&err_sites::X509_ALL_589);
                    return ptr::null_mut();
                }
            }
        }

        if X509_digest(cert, md, hash.as_mut_ptr(), &raw mut len) == 0 {
            EVP_MD_free(md);
            return ptr::null_mut();
        }
        let new = ASN1_OCTET_STRING_new();
        if new.is_null() {
            EVP_MD_free(md);
            return ptr::null_mut();
        }
        if ASN1_OCTET_STRING_set(new, hash.as_ptr(), len as c_int) != 0 {
            if !md_used.is_null() {
                *md_used = md;
            } else {
                EVP_MD_free(md);
            }
            return new;
        }
        ASN1_OCTET_STRING_free(new);
        EVP_MD_free(md);
        ptr::null_mut()
    }
}

/// `int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type, unsigned char *md,
/// unsigned int *len)` — `crypto/x509/x_all.c:608-626`.
///
/// A NULL method is refused with `ERR_R_PASSED_NULL_PARAMETER`; a SHA-1 request on a CRL whose
/// fingerprint is cached answers from `sha1_hash`; otherwise the CRL is DER-encoded and
/// digested.
///
/// # Safety
///
/// `data` must be a live `X509_CRL`; `type` NULL or a live method; `md` writable for the digest
/// size and `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_digest(
    data: *const X509Crl,
    type_: *const EvpMd,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    if type_.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_612) };
        return 0;
    }
    // SAFETY: `data` is live per the contract.
    unsafe {
        if EVP_MD_is_a(type_, SN_SHA1.as_ptr()) != 0
            && ((*data).flags as c_uint & EXFLAG_SET) != 0
            && ((*data).flags as c_uint & EXFLAG_NO_FINGERPRINT) == 0
        {
            if !len.is_null() {
                *len = 20;
            }
            ptr::copy_nonoverlapping((*data).sha1_hash.as_ptr(), md, 20);
            return 1;
        }
        ossl_asn1_item_digest_ex(
            X509_CRL_it(),
            type_,
            data.cast_mut().cast::<c_void>(),
            md,
            len,
            (*data).libctx,
            (*data).propq,
        )
    }
}

/// `int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type, unsigned char *md,
/// unsigned int *len)` -- `crypto/x509/x_all.c:628-633`.
///
/// Unlike `X509_digest`/`X509_CRL_digest` there is no cached-fingerprint shortcut: the request is
/// always DER-encoded and digested through `ossl_asn1_item_digest_ex` with its own library
/// context and property query.
///
/// # Safety
///
/// `data` must be a live `X509_REQ`; `type_` a live method; `md` writable for the digest size and
/// `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_digest(
    data: *const X509Req,
    type_: *const EvpMd,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe {
        ossl_asn1_item_digest_ex(
            X509_REQ_it(),
            type_,
            data.cast_mut().cast::<c_void>(),
            md,
            len,
            (*data).libctx,
            (*data).propq,
        )
    }
}

/// `int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type, unsigned char *md,
/// unsigned int *len)` — `crypto/x509/x_all.c:635-640`.
///
/// # Safety
///
/// `data` must be a live `X509_NAME`; `type` a live method; `md` writable for the digest size
/// and `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_digest(
    data: *const crate::x509::x_name::X509Name,
    type_: *const EvpMd,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: the caller's contract, forwarded; `X509_NAME_it()` is the crate's static item.
    unsafe {
        ASN1_item_digest(
            crate::x509::x_name::X509_NAME_it(),
            type_,
            data.cast_mut().cast::<c_void>(),
            md,
            len,
        )
    }
}

/// `int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data, const EVP_MD *type,
/// unsigned char *md, unsigned int *len)` — `crypto/x509/x_all.c:642-648`.
///
/// # Safety
///
/// `data` must be a live `PKCS7_ISSUER_AND_SERIAL`; `type` a live method; `md` writable for the
/// digest size and `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_digest(
    data: *mut Pkcs7IssuerAndSerial,
    type_: *const EvpMd,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    // SAFETY: the caller's contract, forwarded; `PKCS7_ISSUER_AND_SERIAL_it()` is a static item.
    unsafe {
        ASN1_item_digest(
            PKCS7_ISSUER_AND_SERIAL_it(),
            type_,
            data.cast::<c_void>(),
            md,
            len,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The PKCS#8 / X509_PUBKEY / private-key / public-key stream faces — `x_all.c:651-859`
// ---------------------------------------------------------------------------------------------

/// `X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8)` — `crypto/x509/x_all.c:651-654`, the
/// `ASN1_d2i_fp_of(X509_SIG, X509_SIG_new, d2i_X509_SIG, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p8` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8_fp(fp: *mut FILE, p8: *mut *mut X509Sig) -> *mut X509Sig {
    // SAFETY: `fp`/`p8` are the caller's; `d2i_of` restates `d2i_X509_SIG`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<X509Sig>(d2i_X509_SIG),
            fp,
            p8.cast::<*mut c_void>(),
        )
        .cast::<X509Sig>()
    }
}

/// `int i2d_PKCS8_fp(FILE *fp, const X509_SIG *p8)` — `crypto/x509/x_all.c:656-659`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p8` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8_fp(fp: *mut FILE, p8: *const X509Sig) -> c_int {
    // SAFETY: `fp`/`p8` are the caller's; `i2d_of` restates `i2d_X509_SIG`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<X509Sig>(i2d_X509_SIG), fp, p8.cast::<c_void>()) }
}

/// `X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8)` — `crypto/x509/x_all.c:662-665`.
///
/// # Safety
///
/// `bp` must be a live BIO; `p8` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8_bio(bp: *mut Bio, p8: *mut *mut X509Sig) -> *mut X509Sig {
    // SAFETY: `bp`/`p8` are the caller's; `d2i_of` restates `d2i_X509_SIG`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<X509Sig>(d2i_X509_SIG),
            bp,
            p8.cast::<*mut c_void>(),
        )
        .cast::<X509Sig>()
    }
}

/// `int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8)` — `crypto/x509/x_all.c:667-670`.
///
/// # Safety
///
/// `bp` must be a live BIO; `p8` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8_bio(bp: *mut Bio, p8: *const X509Sig) -> c_int {
    // SAFETY: `bp`/`p8` are the caller's; `i2d_of` restates `i2d_X509_SIG`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<X509Sig>(i2d_X509_SIG), bp, p8.cast::<c_void>()) }
}

/// `X509_PUBKEY *d2i_X509_PUBKEY_fp(FILE *fp, X509_PUBKEY **xpk)` — `crypto/x509/x_all.c:673-677`,
/// the `ASN1_d2i_fp_of(X509_PUBKEY, X509_PUBKEY_new, d2i_X509_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `xpk` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_PUBKEY_fp(
    fp: *mut FILE,
    xpk: *mut *mut X509Pubkey,
) -> *mut X509Pubkey {
    // SAFETY: `fp`/`xpk` are the caller's; `d2i_of` restates `d2i_X509_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<X509Pubkey>(d2i_X509_PUBKEY),
            fp,
            xpk.cast::<*mut c_void>(),
        )
        .cast::<X509Pubkey>()
    }
}

/// `int i2d_X509_PUBKEY_fp(FILE *fp, const X509_PUBKEY *xpk)` — `crypto/x509/x_all.c:679-682`.
///
/// (`i2d_X509_PUBKEY_bio`, the unit's other encoder, is already landed in `src/x509/x_pubkey.rs`
/// since 10.3 and is not defined a second time.)
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `xpk` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_PUBKEY_fp(fp: *mut FILE, xpk: *const X509Pubkey) -> c_int {
    // SAFETY: `fp`/`xpk` are the caller's; `i2d_of` restates `i2d_X509_PUBKEY`'s contract.
    unsafe {
        ASN1_i2d_fp(
            i2d_of::<X509Pubkey>(i2d_X509_PUBKEY),
            fp,
            xpk.cast::<c_void>(),
        )
    }
}

/// `X509_PUBKEY *d2i_X509_PUBKEY_bio(BIO *bp, X509_PUBKEY **xpk)` — `crypto/x509/x_all.c:685-689`.
///
/// # Safety
///
/// `bp` must be a live BIO; `xpk` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_PUBKEY_bio(
    bp: *mut Bio,
    xpk: *mut *mut X509Pubkey,
) -> *mut X509Pubkey {
    // SAFETY: `bp`/`xpk` are the caller's; `d2i_of` restates `d2i_X509_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<X509Pubkey>(d2i_X509_PUBKEY),
            bp,
            xpk.cast::<*mut c_void>(),
        )
        .cast::<X509Pubkey>()
    }
}

/// `PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO **p8inf)` —
/// `crypto/x509/x_all.c:697-702`, the `ASN1_d2i_fp_of(PKCS8_PRIV_KEY_INFO,
/// PKCS8_PRIV_KEY_INFO_new, d2i_PKCS8_PRIV_KEY_INFO, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p8inf` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_fp(
    fp: *mut FILE,
    p8inf: *mut *mut Pkcs8PrivKeyInfo,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: `fp`/`p8inf` are the caller's; `d2i_of` restates `d2i_PKCS8_PRIV_KEY_INFO`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<Pkcs8PrivKeyInfo>(d2i_PKCS8_PRIV_KEY_INFO),
            fp,
            p8inf.cast::<*mut c_void>(),
        )
        .cast::<Pkcs8PrivKeyInfo>()
    }
}

/// `int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, const PKCS8_PRIV_KEY_INFO *p8inf)` —
/// `crypto/x509/x_all.c:704-708`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `p8inf` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_fp(
    fp: *mut FILE,
    p8inf: *const Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: `fp`/`p8inf` are the caller's; `i2d_of` restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract.
    unsafe {
        ASN1_i2d_fp(
            i2d_of::<Pkcs8PrivKeyInfo>(i2d_PKCS8_PRIV_KEY_INFO),
            fp,
            p8inf.cast::<c_void>(),
        )
    }
}

/// `int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, const EVP_PKEY *key)` —
/// `crypto/x509/x_all.c:710-721`.
///
/// Wraps the key with `EVP_PKEY2PKCS8`, writes the `PrivateKeyInfo` to `fp`, and frees the
/// wrapper whether the write succeeded or not.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `key` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_fp(fp: *mut FILE, key: *const EvpPkey) -> c_int {
    // SAFETY: `key` is live per the contract.
    let p8inf = unsafe { EVP_PKEY2PKCS8(key) };
    if p8inf.is_null() {
        return 0;
    }
    // SAFETY: `p8inf` is this call's own live value.
    let ret = unsafe { i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8inf) };
    // SAFETY: `p8inf` is this call's own and is not owned elsewhere.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    ret
}

/// `int i2d_PrivateKey_fp(FILE *fp, const EVP_PKEY *pkey)` — `crypto/x509/x_all.c:723-726`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PrivateKey_fp(fp: *mut FILE, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `fp`/`pkey` are the caller's; `i2d_of` restates `i2d_PrivateKey`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<EvpPkey>(i2d_PrivateKey), fp, pkey.cast::<c_void>()) }
}

/// `EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a)` — `crypto/x509/x_all.c:728-731`, the
/// `ASN1_d2i_fp_of(EVP_PKEY, EVP_PKEY_new, d2i_AutoPrivateKey, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey_fp(fp: *mut FILE, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `fp`/`a` are the caller's; `d2i_of` restates `d2i_AutoPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<EvpPkey>(d2i_AutoPrivateKey),
            fp,
            a.cast::<*mut c_void>(),
        )
        .cast::<EvpPkey>()
    }
}

/// `EVP_PKEY *d2i_PrivateKey_ex_fp(FILE *fp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/x509/x_all.c:733-747`.
///
/// Wraps `fp` in a file BIO and delegates to `d2i_PrivateKey_ex_bio`; a BIO allocation failure
/// raises `ERR_R_BUF_LIB`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `a` NULL or a writable slot; `libctx` NULL or live and `propq`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey_ex_fp(
    fp: *mut FILE,
    a: *mut *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: no preconditions.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_740) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is this call's own live BIO and `fp` the caller's `FILE`.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_FILE_PTR,
            c_long::from(BIO_NOCLOSE),
            fp.cast::<c_void>(),
        );
    }
    // SAFETY: `b` is live and the remaining arguments are the caller's.
    let ret = unsafe { d2i_PrivateKey_ex_bio(b, a, libctx, propq) };
    // SAFETY: `b` is this call's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int i2d_PUBKEY_fp(FILE *fp, const EVP_PKEY *pkey)` — `crypto/x509/x_all.c:749-752`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PUBKEY_fp(fp: *mut FILE, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `fp`/`pkey` are the caller's; `i2d_of` restates `i2d_PUBKEY`'s contract.
    unsafe { ASN1_i2d_fp(i2d_of::<EvpPkey>(i2d_PUBKEY), fp, pkey.cast::<c_void>()) }
}

/// `EVP_PKEY *d2i_PUBKEY_ex_fp(FILE *fp, EVP_PKEY **a, OSSL_LIB_CTX *libctx, const char *propq)`
/// — `crypto/x509/x_all.c:754-768`.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `a` NULL or a writable slot; `libctx` NULL or live and `propq`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY_ex_fp(
    fp: *mut FILE,
    a: *mut *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: no preconditions.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&err_sites::X509_ALL_761) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is this call's own live BIO and `fp` the caller's `FILE`.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_FILE_PTR,
            c_long::from(BIO_NOCLOSE),
            fp.cast::<c_void>(),
        );
    }
    // SAFETY: `b` is live and the remaining arguments are the caller's.
    let ret = unsafe { d2i_PUBKEY_ex_bio(b, a, libctx, propq) };
    // SAFETY: `b` is this call's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a)` — `crypto/x509/x_all.c:770-773`, the
/// `ASN1_d2i_fp_of(EVP_PKEY, EVP_PKEY_new, d2i_PUBKEY, …)` expansion.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY_fp(fp: *mut FILE, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `fp`/`a` are the caller's; `d2i_of` restates `d2i_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_fp(
            unused_new,
            d2i_of::<EvpPkey>(d2i_PUBKEY),
            fp,
            a.cast::<*mut c_void>(),
        )
        .cast::<EvpPkey>()
    }
}

/// `PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO **p8inf)` —
/// `crypto/x509/x_all.c:777-782`.
///
/// # Safety
///
/// `bp` must be a live BIO; `p8inf` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_bio(
    bp: *mut Bio,
    p8inf: *mut *mut Pkcs8PrivKeyInfo,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: `bp`/`p8inf` are the caller's; `d2i_of` restates `d2i_PKCS8_PRIV_KEY_INFO`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<Pkcs8PrivKeyInfo>(d2i_PKCS8_PRIV_KEY_INFO),
            bp,
            p8inf.cast::<*mut c_void>(),
        )
        .cast::<Pkcs8PrivKeyInfo>()
    }
}

/// `int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, const PKCS8_PRIV_KEY_INFO *p8inf)` —
/// `crypto/x509/x_all.c:784-788`.
///
/// # Safety
///
/// `bp` must be a live BIO; `p8inf` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_bio(
    bp: *mut Bio,
    p8inf: *const Pkcs8PrivKeyInfo,
) -> c_int {
    // SAFETY: `bp`/`p8inf` are the caller's; `i2d_of` restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract.
    unsafe {
        ASN1_i2d_bio(
            i2d_of::<Pkcs8PrivKeyInfo>(i2d_PKCS8_PRIV_KEY_INFO),
            bp,
            p8inf.cast::<c_void>(),
        )
    }
}

/// `int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, const EVP_PKEY *key)` —
/// `crypto/x509/x_all.c:790-801`.
///
/// # Safety
///
/// `bp` must be a live BIO; `key` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_bio(bp: *mut Bio, key: *const EvpPkey) -> c_int {
    // SAFETY: `key` is live per the contract.
    let p8inf = unsafe { EVP_PKEY2PKCS8(key) };
    if p8inf.is_null() {
        return 0;
    }
    // SAFETY: `p8inf` is this call's own live value.
    let ret = unsafe { i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf) };
    // SAFETY: `p8inf` is this call's own and is not owned elsewhere.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    ret
}

/// `int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey)` — `crypto/x509/x_all.c:803-806`.
///
/// # Safety
///
/// `bp` must be a live BIO; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PrivateKey_bio(bp: *mut Bio, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `bp`/`pkey` are the caller's; `i2d_of` restates `i2d_PrivateKey`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<EvpPkey>(i2d_PrivateKey), bp, pkey.cast::<c_void>()) }
}

/// `EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a)` — `crypto/x509/x_all.c:808-811`.
///
/// # Safety
///
/// `bp` must be a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey_bio(bp: *mut Bio, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `bp`/`a` are the caller's; `d2i_of` restates `d2i_AutoPrivateKey`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<EvpPkey>(d2i_AutoPrivateKey),
            bp,
            a.cast::<*mut c_void>(),
        )
        .cast::<EvpPkey>()
    }
}

/// `EVP_PKEY *d2i_PrivateKey_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/x509/x_all.c:813-830`.
///
/// Reads one DER object with `asn1_d2i_read_bio` and hands the buffer to
/// `d2i_AutoPrivateKey_ex`; the buffer is released on both paths.
///
/// # Safety
///
/// `bp` must be a live BIO; `a` NULL or a writable slot; `libctx` NULL or live and `propq` NULL
/// or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_PrivateKey_ex_bio(
    bp: *mut Bio,
    a: *mut *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut b: *mut BufMem = ptr::null_mut();
    // SAFETY: `bp` is a live BIO and `b` is a null slot.
    let len = unsafe { asn1_d2i_read_bio(bp, &raw mut b) };
    let ret = if len < 0 {
        ptr::null_mut()
    } else {
        // SAFETY: `b` is the buffer the read just filled.
        let p = unsafe { (*b).data }.cast::<c_uchar>().cast_const();
        let mut p = p;
        // SAFETY: `p` is readable for `len` bytes and `libctx`/`propq` are the caller's.
        unsafe { d2i_AutoPrivateKey_ex(a, &raw mut p, c_long::from(len), libctx, propq) }
    };
    // SAFETY: `b` is this call's buffer or null.
    unsafe { BUF_MEM_free(b) };
    ret
}

/// `int i2d_PUBKEY_bio(BIO *bp, const EVP_PKEY *pkey)` — `crypto/x509/x_all.c:832-835`.
///
/// # Safety
///
/// `bp` must be a live BIO; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn i2d_PUBKEY_bio(bp: *mut Bio, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `bp`/`pkey` are the caller's; `i2d_of` restates `i2d_PUBKEY`'s contract.
    unsafe { ASN1_i2d_bio(i2d_of::<EvpPkey>(i2d_PUBKEY), bp, pkey.cast::<c_void>()) }
}

/// `EVP_PKEY *d2i_PUBKEY_ex_bio(BIO *bp, EVP_PKEY **a, OSSL_LIB_CTX *libctx, const char *propq)`
/// — `crypto/x509/x_all.c:837-854`.
///
/// # Safety
///
/// `bp` must be a live BIO; `a` NULL or a writable slot; `libctx` NULL or live and `propq` NULL
/// or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY_ex_bio(
    bp: *mut Bio,
    a: *mut *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut b: *mut BufMem = ptr::null_mut();
    // SAFETY: `bp` is a live BIO and `b` is a null slot.
    let len = unsafe { asn1_d2i_read_bio(bp, &raw mut b) };
    let ret = if len < 0 {
        ptr::null_mut()
    } else {
        // SAFETY: `b` is the buffer the read just filled.
        let p = unsafe { (*b).data }.cast::<c_uchar>().cast_const();
        let mut p = p;
        // SAFETY: `p` is readable for `len` bytes and `libctx`/`propq` are the caller's.
        unsafe { d2i_PUBKEY_ex(a, &raw mut p, c_long::from(len), libctx, propq) }
    };
    // SAFETY: `b` is this call's buffer or null.
    unsafe { BUF_MEM_free(b) };
    ret
}

/// `EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a)` — `crypto/x509/x_all.c:856-859`.
///
/// # Safety
///
/// `bp` must be a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn d2i_PUBKEY_bio(bp: *mut Bio, a: *mut *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `bp`/`a` are the caller's; `d2i_of` restates `d2i_PUBKEY`'s contract.
    unsafe {
        ASN1_d2i_bio(
            unused_new,
            d2i_of::<EvpPkey>(d2i_PUBKEY),
            bp,
            a.cast::<*mut c_void>(),
        )
        .cast::<EvpPkey>()
    }
}

// The `X509_CINF_it`/`X509_it`/`X509_CRL_it`/`X509_CRL_INFO_it` used above are 10.8's items, in
// `src/x509/x_x509.rs` and `src/x509/x_crl.rs`; `X509_get0_extensions` is `crypto/x509/x509_set.c`
// and `X509_get0_pubkey_bitstr` is `crypto/x509/x_pubkey.c`, both un-withheld by this subphase.
