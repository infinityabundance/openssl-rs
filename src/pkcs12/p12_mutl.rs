//! `crypto/pkcs12/p12_mutl.c` — the `MacData` accessors and the MAC setup. Phase 10 (10.3,
//! re-opened by the `PKCS7` subset).
//!
//! The unit is 552 lines and fifteen exports, and **all fifteen land here**. The two accessors
//! ([`PKCS12_mac_present`], [`PKCS12_get0_mac`]) and [`PKCS12_setup_mac`] landed with the pulled-
//! forward `PKCS7` subset. The four MAC names ([`PKCS12_gen_mac`], [`PKCS12_verify_mac`],
//! [`PKCS12_set_mac`], [`PKCS12_set_pbmac1_pbkdf2`]) waited on 10.4's
//! [`PKCS12_key_gen_utf8_ex`](crate::pkcs12::p12_key::PKCS12_key_gen_utf8_ex) — the PKCS#12 KDF —
//! and that subphase landed it, so the four land now, together with the four internal helpers
//! they call: `PBMAC1_get1_pbkdf2_param`, `PBMAC1_PBKDF2_HMAC`, `pkcs12_gen_gost_mac_key` and the
//! `pkcs12_pbmac1_pbkdf2_key_gen` callback.
//!
//! **Their closure was measured, not assumed.** `nm --undefined-only` over the authority's own
//! `libcrypto-lib-p12_mutl.o` lists every name the unit reaches; every one is a landed crate
//! symbol (`EVP_MD_fetch`/`_free`/`_get_size`/`_get_type`, `EVP_get_digestbyname`, the five
//! `HMAC_*`, `PKCS5_PBKDF2_HMAC`/`PKCS5_pbkdf2_set`, `PKCS12_key_gen_utf8_ex`, the
//! `PBMAC1PARAM`/`PBKDF2PARAM` items, `X509_ALGOR_*`, `X509_SIG_get0`/`_getm`, `OBJ_*`,
//! `RAND_bytes_ex`, `CRYPTO_memcmp`, `OPENSSL_cleanse`, `ossl_safe_getenv`,
//! `ossl_hmac2mdnid`/`ossl_md2hmacnid`). Nothing in the unit is blocked.
//!
//! `setup_mac`'s closure was measured rather than assumed: it reaches `PKCS12_MAC_DATA_free`/
//! `_new` (this crate's `p12_asn.rs`), `ASN1_INTEGER_new`/`ASN1_INTEGER_set`, `RAND_bytes_ex`
//! (Phase 9, landed), `X509_SIG_getm`, `X509_ALGOR_set0` and `OBJ_nid2obj` — no `PKCS7` container
//! operation at all. What it needed from the pulled-forward subset is only that `PKCS12_new` can
//! build the object at all, which the `authsafes` column's `PKCS7` had blocked.
//!
//! `setup_mac`'s `salt == NULL` arm draws through `p12->authsafes->ctx.libctx`, so the `PKCS7`
//! context is read here even though no `PKCS7` item operation runs; the drawn salt is observable
//! only as "not the caller's" and the court drives the caller-supplied arm so the bytes stay
//! fixed. The same is true of `pkcs12_gen_mac`'s digest fetch and `PKCS12_set_pbmac1_pbkdf2`'s
//! `RAND` draw, so the court supplies a fixed salt to each. The file is covered by
//! `gen_err_raise_sites.py` under the `PKCS12_MUTL` stem, which already carries every
//! `ERR_raise*` coordinate the four names above need.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_pack_sequence, ASN1_TYPE_unpack_sequence};
use crate::asn1::layout::{Asn1String, V_ASN1_NULL, V_ASN1_OCTET_STRING};
use crate::asn1::p5_pbev2::{
    PBKDF2PARAM_free, PBKDF2PARAM_it, PBMAC1PARAM_free, PBMAC1PARAM_it, PBMAC1PARAM_new,
    PKCS5_pbkdf2_set, Pbkdf2Param, Pbmac1Param,
};
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_INTEGER_new, ASN1_OCTET_STRING_set, ASN1_STRING_get0_data, ASN1_STRING_length,
};
use crate::asn1::x_algor::{
    X509Algor, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_new, X509_ALGOR_set0,
};
use crate::asn1::x_sig::{X509_SIG_get0, X509_SIG_getm};
use crate::evp::digest::{
    ossl_hmac2mdnid, ossl_md2hmacnid, EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get_type,
    EvpMd,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha256;
use crate::evp::p5_crpt2::PKCS5_PBKDF2_HMAC;
use crate::mac::hmac::{
    HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HmacCtx,
};
use crate::pkcs12::p12_add::pkcs7_type_is_data;
use crate::pkcs12::p12_asn::{PKCS12_MAC_DATA_free, PKCS12_MAC_DATA_new, Pkcs12};
use crate::pkcs12::p12_key::PKCS12_key_gen_utf8_ex;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, OPENSSL_cleanse};
use crate::runtime::obj::{
    Asn1Object, NID_hmacWithSHA1, NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512,
    NID_id_GostR3411_94, NID_id_pbkdf2, NID_pbmac1, NID_undef, OBJ_nid2obj, OBJ_nid2sn,
    OBJ_obj2nid, OBJ_obj2txt, OBJ_txt2nid,
};

/// The authority translation unit for this module.
const FILE: &core::ffi::CStr = c"crypto/pkcs12/p12_mutl.c";

/// `PKCS12_SALT_LEN` — `include/openssl/pkcs12.h.in:56`.
const PKCS12_SALT_LEN: c_int = 16;

/// `PKCS12_MAC_ID` — `include/openssl/pkcs12.h:40`. The PKCS#12 KDF's MAC-identifier byte.
const PKCS12_MAC_ID: c_int = 3;

/// `PKCS12_DEFAULT_ITER` — `include/openssl/pkcs12.h:44` (`PKCS5_DEFAULT_ITER`).
const PKCS12_DEFAULT_ITER: c_int = 2048;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`. The width of the MAC scratch and the `PBMAC1`
/// key-length ceiling.
const EVP_MAX_MD_SIZE: c_int = 64;

/// `TK26_MAC_KEY_LEN` — `crypto/pkcs12/p12_mutl.c:60`. The GOST MAC key's fixed length.
const TK26_MAC_KEY_LEN: c_int = 32;

/// `PKCS12_ERROR` — `pkcs12.h.in:82`. `setup_mac` answers it when the `MacData` cannot be built.
const PKCS12_ERROR: c_int = 0;

/// `int PKCS12_mac_present(const PKCS12 *p12)` — `crypto/pkcs12/p12_mutl.c:31-34`.
///
/// # Safety
/// `p12` is a live `PKCS12`.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_mac_present(p12: *const Pkcs12) -> c_int {
    // SAFETY: `p12` is live per the caller's contract.
    if unsafe { (*p12).mac }.is_null() {
        0
    } else {
        1
    }
}

/// `void PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac, const X509_ALGOR **pmacalg,
/// const ASN1_OCTET_STRING **psalt, const ASN1_INTEGER **piter, const PKCS12 *p12)` —
/// `crypto/pkcs12/p12_mutl.c:36-58`.
///
/// Each out-parameter is independently optional. With a `MacData` present the digest and its
/// algorithm come from the `X509_SIG` and the salt/iterations are borrowed straight off the
/// object; without one every requested slot is cleared to null.
///
/// # Safety
/// `p12` is a live `PKCS12`; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_get0_mac(
    pmac: *mut *const Asn1String,
    pmacalg: *mut *const X509Algor,
    psalt: *mut *const Asn1String,
    piter: *mut *const Asn1String,
    p12: *const Pkcs12,
) {
    // SAFETY: `p12` is live per the caller's contract; each out-pointer is checked before use.
    unsafe {
        let mac = (*p12).mac;
        if !mac.is_null() {
            X509_SIG_get0((*mac).dinfo, pmacalg, pmac);
            if !psalt.is_null() {
                *psalt = (*mac).salt;
            }
            if !piter.is_null() {
                *piter = (*mac).iter;
            }
        } else {
            if !pmac.is_null() {
                *pmac = ptr::null();
            }
            if !pmacalg.is_null() {
                *pmacalg = ptr::null();
            }
            if !psalt.is_null() {
                *psalt = ptr::null();
            }
            if !piter.is_null() {
                *piter = ptr::null();
            }
        }
    }
}

/// `static int pkcs12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen, int nid)`
/// — `crypto/pkcs12/p12_mutl.c:403-445`.
///
/// Builds a fresh `PKCS12_MAC_DATA` over the already-selected digest `nid`, optionally sets the
/// iteration count, and fills the salt: from the caller when one is supplied, otherwise drawn.
/// A `saltlen` of 0 means `PKCS12_SALT_LEN`; a negative one is refused without raising, while the
/// three allocation/set failures raise `ERR_R_ASN1_LIB` — the same arms the authority has.
///
/// # Safety
/// `p12` is a live `PKCS12`; `salt` is NULL or `saltlen` readable bytes.
unsafe fn pkcs12_setup_mac(
    p12: *mut Pkcs12,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    nid: c_int,
) -> c_int {
    // SAFETY: `p12` is live per the caller's contract.
    unsafe {
        PKCS12_MAC_DATA_free((*p12).mac);
        (*p12).mac = ptr::null_mut();

        let mac = PKCS12_MAC_DATA_new();
        if mac.is_null() {
            return PKCS12_ERROR;
        }
        (*p12).mac = mac;

        if iter > 1 {
            let it = ASN1_INTEGER_new();
            if it.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_415);
                return 0;
            }
            (*mac).iter = it;
            if ASN1_INTEGER_set((*mac).iter, c_long::from(iter)) == 0 {
                raise_site(&err_sites::PKCS12_MUTL_419);
                return 0;
            }
        }

        let saltlen = if saltlen == 0 {
            PKCS12_SALT_LEN
        } else if saltlen < 0 {
            return 0;
        } else {
            saltlen
        };

        let data = CRYPTO_malloc(saltlen as usize, FILE.as_ptr(), 427).cast::<c_uchar>();
        if data.is_null() {
            return 0;
        }
        (*(*mac).salt).data = data;
        (*(*mac).salt).length = saltlen;

        if salt.is_null() {
            let libctx = (*(*p12).authsafes).ctx.libctx;
            if RAND_bytes_ex(libctx, (*(*mac).salt).data, saltlen as usize, 0) <= 0 {
                return 0;
            }
        } else {
            ptr::copy_nonoverlapping(salt, (*(*mac).salt).data, saltlen as usize);
        }

        let mut macalg: *mut X509Algor = ptr::null_mut();
        X509_SIG_getm((*mac).dinfo, &mut macalg, ptr::null_mut());
        if X509_ALGOR_set0(macalg, OBJ_nid2obj(nid), V_ASN1_NULL, ptr::null_mut()) == 0 {
            raise_site(&err_sites::PKCS12_MUTL_440);
            return 0;
        }
    }
    1
}

/// `int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen,
/// const EVP_MD *md_type)` — `crypto/pkcs12/p12_mutl.c:448-452`.
///
/// # Safety
/// `p12` is a live `PKCS12`; `salt` is NULL or `saltlen` readable bytes; `md_type` is a live
/// digest method.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_setup_mac(
    p12: *mut Pkcs12,
    iter: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    md_type: *const crate::evp::digest::EvpMd,
) -> c_int {
    // SAFETY: `md_type` is live per the caller's contract; the rest is forwarded.
    let nid = unsafe { crate::evp::digest::EVP_MD_get_type(md_type) };
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { pkcs12_setup_mac(p12, iter, salt, saltlen, nid) }
}

/// `PBKDF2PARAM *PBMAC1_get1_pbkdf2_param(const X509_ALGOR *macalg)` —
/// `crypto/pkcs12/p12_mutl.c:82-106`.
///
/// Unpacks the `PBMAC1PARAM` an RFC 9879 MAC's algorithm identifier carries, requires its
/// `keyDerivationFunc` to be `id-pbkdf2`, and answers the unpacked `PBKDF2PARAM`. Either refusal
/// raises `ERR_R_PASSED_INVALID_ARGUMENT`, and the adapter is released on the second.
///
/// # Safety
/// `macalg` is a live `X509_ALGOR`. The answer is owned by the caller.
unsafe fn pbmac1_get1_pbkdf2_param(macalg: *const X509Algor) -> *mut Pbkdf2Param {
    // SAFETY: `macalg` is live per the caller's contract; the item is crate-owned.
    let param = unsafe {
        ASN1_TYPE_unpack_sequence(PBMAC1PARAM_it(), (*macalg).parameter).cast::<Pbmac1Param>()
    };
    if param.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_MUTL_90) };
        return ptr::null_mut();
    }

    let mut kdf_oid: *const Asn1Object = ptr::null();
    // SAFETY: `param` is live and `kdf_oid` is this frame's slot.
    unsafe {
        X509_ALGOR_get0(
            &raw mut kdf_oid,
            ptr::null_mut(),
            ptr::null_mut(),
            (*param).key_derivation_func,
        )
    };
    // SAFETY: `kdf_oid` is the algorithm's own object.
    if unsafe { OBJ_obj2nid(kdf_oid) } != NID_id_pbkdf2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_MUTL_96) };
        // SAFETY: `param` is this frame's own.
        unsafe { PBMAC1PARAM_free(param) };
        return ptr::null_mut();
    }

    // SAFETY: `param` is live and its `keyDerivationFunc` holds the PBKDF2 parameters.
    let pbkdf2_param = unsafe {
        ASN1_TYPE_unpack_sequence(PBKDF2PARAM_it(), (*(*param).key_derivation_func).parameter)
            .cast::<Pbkdf2Param>()
    };
    // SAFETY: `param` is this frame's own.
    unsafe { PBMAC1PARAM_free(param) };
    pbkdf2_param
}

/// `static int PBMAC1_PBKDF2_HMAC(OSSL_LIB_CTX *ctx, const char *propq, const char *pass,
/// int passlen, const X509_ALGOR *macalg, unsigned char *key)` —
/// `crypto/pkcs12/p12_mutl.c:108-170`.
///
/// Derives the `PBMAC1` MAC key with PBKDF2 over the parameters the algorithm identifier carries,
/// and answers the key length or −1. The refusals raise `ERR_R_UNSUPPORTED`,
/// `ERR_R_FETCH_FAILED`, `PKCS12_R_PARSE_ERROR` (twice, the second carrying the formatted length)
/// and `ERR_R_INTERNAL_ERROR`.
///
/// # Safety
/// `macalg` is a live `X509_ALGOR`; `pass` is NULL or a string of `passlen` bytes; `key` is
/// writable for up to `EVP_MAX_MD_SIZE` bytes; `ctx`/`propq` are the digest fetch's.
unsafe fn pbmac1_pbkdf2_hmac(
    ctx: *mut c_void,
    propq: *const c_char,
    pass: *const c_char,
    passlen: c_int,
    macalg: *const X509Algor,
    key: *mut c_uchar,
) -> c_int {
    let mut ret: c_int = -1;
    let mut keylen: c_int = 0;
    let mut kdf_md: *mut EvpMd = ptr::null_mut();

    // SAFETY: `macalg` is live per the caller's contract.
    let pbkdf2_param = unsafe { pbmac1_get1_pbkdf2_param(macalg) };

    'body: {
        // SAFETY: `pbkdf2_param` is live or NULL; every pointer below is checked before use.
        unsafe {
            if pbkdf2_param.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_122);
                break 'body;
            }
            let mut kdf_hmac_oid: *const Asn1Object = ptr::null();
            let kdf_hmac_nid = if (*pbkdf2_param).prf.is_null() {
                NID_hmacWithSHA1
            } else {
                X509_ALGOR_get0(
                    &raw mut kdf_hmac_oid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    (*pbkdf2_param).prf,
                );
                OBJ_obj2nid(kdf_hmac_oid)
            };
            // `OBJ_nid2sn` answers a static short name and `ossl_hmac2mdnid` the digest NID.
            kdf_md = EVP_MD_fetch(ctx, OBJ_nid2sn(ossl_hmac2mdnid(kdf_hmac_nid)), propq);
            if kdf_md.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_135);
                break 'body;
            }
            let slt = (*pbkdf2_param).salt;
            if slt.is_null() || (*slt).type_ != V_ASN1_OCTET_STRING {
                raise_site(&err_sites::PKCS12_MUTL_142);
                break 'body;
            }
            let oct = (*slt).value.ptr.cast::<Asn1String>();
            if !(*pbkdf2_param).keylength.is_null() {
                keylen = ASN1_INTEGER_get((*pbkdf2_param).keylength) as c_int;
            }
            if !(20..=EVP_MAX_MD_SIZE).contains(&keylen) {
                let mut msg = [0 as c_char; 64];
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"Invalid Key length (%d is not in the range 20..64)".as_ptr(),
                    keylen,
                );
                raise_site_data(&err_sites::PKCS12_MUTL_152, msg.as_ptr());
                break 'body;
            }
            let rc = PKCS5_PBKDF2_HMAC(
                pass,
                passlen,
                (*oct).data,
                (*oct).length,
                ASN1_INTEGER_get((*pbkdf2_param).iter) as c_int,
                kdf_md,
                keylen,
                key,
            );
            if rc <= 0 {
                raise_site(&err_sites::PKCS12_MUTL_160);
                break 'body;
            }
            ret = keylen;
        }
    }
    // SAFETY: both are NULL or this frame's own.
    unsafe {
        EVP_MD_free(kdf_md);
        PBKDF2PARAM_free(pbkdf2_param);
    }
    ret
}

/// `static int pkcs12_gen_gost_mac_key(const char *pass, int passlen, const unsigned char *salt,
/// int saltlen, int iter, int keylen, unsigned char *key, const EVP_MD *digest)` —
/// `crypto/pkcs12/p12_mutl.c:62-80`.
///
/// The GOST MAC's key is `TK26_MAC_KEY_LEN` bytes: PBKDF2 expands to 96 and the **trailing** 32
/// are the key. Any other requested length is refused without raising, and the 96-byte scratch is
/// cleansed before release.
///
/// # Safety
/// `salt` is readable for `saltlen` bytes; `key` is writable for `TK26_MAC_KEY_LEN` bytes;
/// `digest` is a live digest method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pkcs12_gen_gost_mac_key(
    pass: *const c_char,
    passlen: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    iter: c_int,
    keylen: c_int,
    key: *mut c_uchar,
    digest: *const EvpMd,
) -> bool {
    let mut out = [0 as c_uchar; 96];
    if keylen != TK26_MAC_KEY_LEN {
        return false;
    }
    // SAFETY: `out` is a 96-byte buffer; the rest of the arguments are forwarded.
    if unsafe {
        PKCS5_PBKDF2_HMAC(
            pass,
            passlen,
            salt,
            saltlen,
            iter,
            digest,
            out.len() as c_int,
            out.as_mut_ptr(),
        )
    } == 0
    {
        return false;
    }
    // SAFETY: both buffers are live and the copy is within `out` and `key`.
    unsafe {
        ptr::copy_nonoverlapping(
            out.as_ptr().add(out.len() - TK26_MAC_KEY_LEN as usize),
            key,
            TK26_MAC_KEY_LEN as usize,
        )
    };
    // SAFETY: `out` is this frame's own scratch and holds key material.
    unsafe { OPENSSL_cleanse(out.as_mut_ptr().cast::<c_void>(), out.len()) };
    true
}

/// `static int pkcs12_gen_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *mac,
/// unsigned int *maclen, int pbmac1_md_nid, int pbmac1_kdf_nid, int (*pkcs12_key_gen)(...))` —
/// `crypto/pkcs12/p12_mutl.c:173-303`.
///
/// The one worker behind [`PKCS12_gen_mac`] and [`PKCS12_verify_mac`]: it picks the digest from
/// the `MacData`'s algorithm identifier (or, for RFC 9879, from `pbmac1_md_nid`), derives the MAC
/// key — through `PBMAC1_PBKDF2_HMAC`, the GOST 26-byte key, the caller's callback, or the default
/// UTF-8 PKCS#12 KDF — and HMACs the authsafes' octets into `mac`. A non-`data` container, a null
/// octet string and an unresolvable digest each raise their `PKCS12_R_*` coordinate.
///
/// # Safety
/// `p12` is a live `PKCS12` whose `MacData` is present; `pass` is NULL or a string of `passlen`
/// bytes; `mac` is writable for `*maclen` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn pkcs12_gen_mac(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
    mac: *mut c_uchar,
    maclen: *mut c_uint,
    pbmac1_md_nid: c_int,
    pbmac1_kdf_nid: c_int,
    // The authority's `int (*pkcs12_key_gen)(...)` at `crypto/pkcs12/p12_mutl.c:176-180`,
    // written inline so no named function-type alias is introduced for it.
    pkcs12_key_gen: Option<
        unsafe extern "C" fn(
            pass: *const c_char,
            passlen: c_int,
            salt: *mut c_uchar,
            slen: c_int,
            id: c_int,
            iter: c_int,
            n: c_int,
            out: *mut c_uchar,
            md_type: *const EvpMd,
        ) -> c_int,
    >,
) -> c_int {
    let mut ret: c_int = 0;
    let mut md_fetch: *mut EvpMd = ptr::null_mut();
    let mut hmac: *mut HmacCtx = ptr::null_mut();
    let mut key = [0 as c_uchar; EVP_MAX_MD_SIZE as usize];
    let mut md_name = [0 as c_char; 80];

    'body: {
        // SAFETY: `p12` is live per the caller's contract; each pointer is checked before use.
        unsafe {
            let authsafes = (*p12).authsafes;
            if !pkcs7_type_is_data(authsafes) {
                raise_site(&err_sites::PKCS12_MUTL_195);
                break 'body;
            }
            if (*authsafes).d.data.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_200);
                break 'body;
            }

            let salt = (*(*p12).mac).salt;
            let saltdata = (*salt).data;
            let saltlen = (*salt).length;
            let iter = if (*(*p12).mac).iter.is_null() {
                1
            } else {
                ASN1_INTEGER_get((*(*p12).mac).iter) as c_int
            };
            let mut macalg: *const X509Algor = ptr::null();
            X509_SIG_get0((*(*p12).mac).dinfo, &raw mut macalg, ptr::null_mut());
            let mut macoid: *const Asn1Object = ptr::null();
            X509_ALGOR_get0(&raw mut macoid, ptr::null_mut(), ptr::null_mut(), macalg);
            let md_name_len = md_name.len() as c_int;
            if OBJ_obj2nid(macoid) == NID_pbmac1 {
                if OBJ_obj2txt(
                    md_name.as_mut_ptr(),
                    md_name_len,
                    OBJ_nid2obj(pbmac1_md_nid),
                    0,
                ) < 0
                {
                    break 'body;
                }
            } else if OBJ_obj2txt(md_name.as_mut_ptr(), md_name_len, macoid, 0) < 0 {
                break 'body;
            }
            let _ = ERR_set_mark();
            md_fetch = EVP_MD_fetch(
                (*authsafes).ctx.libctx,
                md_name.as_ptr(),
                (*authsafes).ctx.propq,
            );
            let mut md: *const EvpMd = md_fetch;
            if md.is_null() {
                md = EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(macoid)));
            }
            if md.is_null() {
                let _ = ERR_clear_last_mark();
                raise_site(&err_sites::PKCS12_MUTL_227);
                break 'body;
            }
            let _ = ERR_pop_to_mark();

            let mut keylen = EVP_MD_get_size(md);
            let md_nid = EVP_MD_get_type(md);
            if keylen <= 0 {
                break 'body;
            }
            if pbmac1_md_nid != NID_undef && pkcs12_key_gen.is_none() {
                keylen = pbmac1_pbkdf2_hmac(
                    (*authsafes).ctx.libctx,
                    (*authsafes).ctx.propq,
                    pass,
                    passlen,
                    macalg,
                    key.as_mut_ptr(),
                );
                if keylen < 0 {
                    break 'body;
                }
            } else if (md_nid == NID_id_GostR3411_94
                || md_nid == NID_id_GostR3411_2012_256
                || md_nid == NID_id_GostR3411_2012_512)
                && ossl_safe_getenv(c"LEGACY_GOST_PKCS12".as_ptr()).is_null()
            {
                keylen = TK26_MAC_KEY_LEN;
                if !pkcs12_gen_gost_mac_key(
                    pass,
                    passlen,
                    saltdata,
                    saltlen,
                    iter,
                    keylen,
                    key.as_mut_ptr(),
                    md,
                ) {
                    raise_site(&err_sites::PKCS12_MUTL_250);
                    break 'body;
                }
            } else {
                let mut hmac_md: *const EvpMd = md;
                let mut fetched_md: *mut EvpMd = ptr::null_mut();
                if pbmac1_kdf_nid != NID_undef {
                    let mut kdf_name = [0 as c_char; 128];
                    let kdf_name_len = kdf_name.len() as c_int;
                    if OBJ_obj2txt(
                        kdf_name.as_mut_ptr(),
                        kdf_name_len,
                        OBJ_nid2obj(pbmac1_kdf_nid),
                        0,
                    ) < 0
                    {
                        break 'body;
                    }
                    fetched_md = EVP_MD_fetch(ptr::null_mut(), kdf_name.as_ptr(), ptr::null());
                    if fetched_md.is_null() {
                        break 'body;
                    }
                    hmac_md = fetched_md;
                }
                if let Some(kgen) = pkcs12_key_gen {
                    let res = kgen(
                        pass,
                        passlen,
                        saltdata,
                        saltlen,
                        PKCS12_MAC_ID,
                        iter,
                        keylen,
                        key.as_mut_ptr(),
                        hmac_md,
                    );
                    if !fetched_md.is_null() {
                        EVP_MD_free(fetched_md);
                    }
                    if res != 1 {
                        raise_site(&err_sites::PKCS12_MUTL_274);
                        break 'body;
                    }
                } else {
                    if !fetched_md.is_null() {
                        EVP_MD_free(fetched_md);
                    }
                    if PKCS12_key_gen_utf8_ex(
                        pass,
                        passlen,
                        saltdata,
                        saltlen,
                        PKCS12_MAC_ID,
                        iter,
                        keylen,
                        key.as_mut_ptr(),
                        md,
                        (*authsafes).ctx.libctx,
                        (*authsafes).ctx.propq,
                    ) == 0
                    {
                        raise_site(&err_sites::PKCS12_MUTL_284);
                        break 'body;
                    }
                }
            }
            hmac = HMAC_CTX_new();
            let data = (*(*authsafes).d.data).data;
            let data_len = (*(*authsafes).d.data).length as usize;
            if hmac.is_null()
                || HMAC_Init_ex(
                    hmac,
                    key.as_ptr().cast::<c_void>(),
                    keylen,
                    md,
                    ptr::null_mut(),
                ) == 0
                || HMAC_Update(hmac, data, data_len) == 0
                || HMAC_Final(hmac, mac, maclen) == 0
            {
                break 'body;
            }
            ret = 1;
        }
    }
    // SAFETY: `key` is this frame's own; the other two are NULL or this frame's own.
    unsafe {
        OPENSSL_cleanse(key.as_mut_ptr().cast::<c_void>(), key.len());
        HMAC_CTX_free(hmac);
        EVP_MD_free(md_fetch);
    }
    ret
}

/// `int PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *mac,
/// unsigned int *maclen)` — `crypto/pkcs12/p12_mutl.c:305-309`.
///
/// # Safety
/// `p12` is a live `PKCS12`; `pass` is NULL or a string of `passlen` bytes; `mac` is writable for
/// `*maclen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_gen_mac(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
    mac: *mut c_uchar,
    maclen: *mut c_uint,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { pkcs12_gen_mac(p12, pass, passlen, mac, maclen, NID_undef, NID_undef, None) }
}

/// `int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen)` —
/// `crypto/pkcs12/p12_mutl.c:312-358`.
///
/// A container with no `MacData` raises `PKCS12_R_MAC_ABSENT`; an RFC 9879 MAC reads its
/// `pbmac1_md_nid` out of the parameter first. The recomputed MAC is compared against the stored
/// octets with `CRYPTO_memcmp`, and a length or content mismatch answers 0 **without** raising.
///
/// # Safety
/// `p12` is a live `PKCS12`; `pass` is NULL or a string of `passlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_verify_mac(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
) -> c_int {
    let mut mac = [0 as c_uchar; EVP_MAX_MD_SIZE as usize];
    let mut maclen: c_uint = 0;

    // SAFETY: `p12` is live per the caller's contract; every pointer is checked before use.
    unsafe {
        if (*p12).mac.is_null() {
            raise_site(&err_sites::PKCS12_MUTL_321);
            return 0;
        }
        let mut macalg: *const X509Algor = ptr::null();
        X509_SIG_get0((*(*p12).mac).dinfo, &raw mut macalg, ptr::null_mut());
        let mut macoid: *const Asn1Object = ptr::null();
        X509_ALGOR_get0(&raw mut macoid, ptr::null_mut(), ptr::null_mut(), macalg);
        if OBJ_obj2nid(macoid) == NID_pbmac1 {
            let param = ASN1_TYPE_unpack_sequence(PBMAC1PARAM_it(), (*macalg).parameter)
                .cast::<Pbmac1Param>();
            if param.is_null() {
                raise_site(&err_sites::PKCS12_MUTL_334);
                return 0;
            }
            let mut hmac_oid: *const Asn1Object = ptr::null();
            X509_ALGOR_get0(
                &raw mut hmac_oid,
                ptr::null_mut(),
                ptr::null_mut(),
                (*param).message_auth_scheme,
            );
            let md_nid = ossl_hmac2mdnid(OBJ_obj2nid(hmac_oid));
            if pkcs12_gen_mac(
                p12,
                pass,
                passlen,
                mac.as_mut_ptr(),
                &raw mut maclen,
                md_nid,
                NID_undef,
                None,
            ) == 0
            {
                raise_site(&err_sites::PKCS12_MUTL_341);
                PBMAC1PARAM_free(param);
                return 0;
            }
            PBMAC1PARAM_free(param);
        } else if pkcs12_gen_mac(
            p12,
            pass,
            passlen,
            mac.as_mut_ptr(),
            &raw mut maclen,
            NID_undef,
            NID_undef,
            None,
        ) == 0
        {
            raise_site(&err_sites::PKCS12_MUTL_348);
            return 0;
        }
        let mut macoct: *const Asn1String = ptr::null();
        X509_SIG_get0((*(*p12).mac).dinfo, ptr::null_mut(), &raw mut macoct);
        if maclen != ASN1_STRING_length(macoct) as c_uint
            || CRYPTO_memcmp(
                mac.as_ptr().cast::<c_void>(),
                ASN1_STRING_get0_data(macoct).cast::<c_void>(),
                maclen as usize,
            ) != 0
        {
            return 0;
        }
    }
    1
}

/// `int PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt,
/// int saltlen, int iter, const EVP_MD *md_type)` — `crypto/pkcs12/p12_mutl.c:361-391`.
///
/// A null `md_type` defaults to SHA-256 and a zero `iter` to `PKCS12_DEFAULT_ITER`, then
/// `PKCS12_setup_mac` builds the `MacData` and the MAC is written into its digest octets.
///
/// # Safety
/// `p12` is a live `PKCS12`; `pass` is NULL or a string of `passlen` bytes; `salt` is NULL or
/// `saltlen` readable bytes; `md_type` is NULL or a live digest method.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_set_mac(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    iter: c_int,
    md_type: *const EvpMd,
) -> c_int {
    let mut mac = [0 as c_uchar; EVP_MAX_MD_SIZE as usize];
    let mut maclen: c_uint = 0;

    // SAFETY: `md_type` is NULL or live per the caller's contract; `EVP_sha256` is safe.
    let md_type = if md_type.is_null() {
        EVP_sha256()
    } else {
        md_type
    };
    let iter = if iter == 0 { PKCS12_DEFAULT_ITER } else { iter };
    // SAFETY: `p12` is live; `salt`/`saltlen` describe the caller's buffer or are NULL/0.
    unsafe {
        if PKCS12_setup_mac(p12, iter, salt, saltlen, md_type) == PKCS12_ERROR {
            raise_site(&err_sites::PKCS12_MUTL_375);
            return 0;
        }
        if pkcs12_gen_mac(
            p12,
            pass,
            passlen,
            mac.as_mut_ptr(),
            &raw mut maclen,
            NID_undef,
            NID_undef,
            None,
        ) == 0
        {
            raise_site(&err_sites::PKCS12_MUTL_382);
            return 0;
        }
        let mut macoct: *mut Asn1String = ptr::null_mut();
        X509_SIG_getm((*(*p12).mac).dinfo, ptr::null_mut(), &raw mut macoct);
        if ASN1_OCTET_STRING_set(macoct, mac.as_ptr(), maclen as c_int) == 0 {
            raise_site(&err_sites::PKCS12_MUTL_387);
            return 0;
        }
    }
    1
}

/// `static int pkcs12_pbmac1_pbkdf2_key_gen(const char *pass, int passlen, unsigned char *salt,
/// int saltlen, int id, int iter, int keylen, unsigned char *out, const EVP_MD *md_type)` —
/// `crypto/pkcs12/p12_mutl.c:393-401`. The `PBMAC1` MAC's keygen callback: PBKDF2 directly,
/// ignoring the `id`.
///
/// # Safety
/// As [`PKCS5_PBKDF2_HMAC`].
unsafe extern "C" fn pkcs12_pbmac1_pbkdf2_key_gen(
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    keylen: c_int,
    out: *mut c_uchar,
    md_type: *const EvpMd,
) -> c_int {
    let _ = id;
    // SAFETY: the arguments are forwarded under this callback's contract.
    unsafe { PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, md_type, keylen, out) }
}

/// `int PKCS12_set_pbmac1_pbkdf2(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt,
/// int saltlen, int iter, const EVP_MD *md_type, const char *prf_md_name)` —
/// `crypto/pkcs12/p12_mutl.c:454-552`.
///
/// Builds the RFC 9879 `PBMAC1PARAM` (PBKDF2 over the PRF, and an HMAC scheme), installs it as
/// the `MacData`'s parameter, and MACs the authsafes with the PBKDF2 callback. A null `md_type`
/// defaults to SHA-256, a zero `iter` to `PKCS12_DEFAULT_ITER`, and an unknown PRF or HMAC names
/// raise `PKCS12_R_UNKNOWN_DIGEST_ALGORITHM`; without a caller salt one is drawn.
///
/// # Safety
/// `p12` is a live `PKCS12`; `pass` is NULL or a string of `passlen` bytes; `salt` is NULL or
/// `saltlen` readable bytes; `md_type`/`prf_md_name` are NULL or live.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn PKCS12_set_pbmac1_pbkdf2(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    iter: c_int,
    md_type: *const EvpMd,
    prf_md_name: *const c_char,
) -> c_int {
    let mut mac = [0 as c_uchar; EVP_MAX_MD_SIZE as usize];
    let mut maclen: c_uint = 0;
    let mut alg: *mut X509Algor = ptr::null_mut();
    let mut ret: c_int = 0;
    let mut known_salt: *mut c_uchar = ptr::null_mut();
    let mut param: *mut Pbmac1Param = ptr::null_mut();
    let mut hmac_alg: *mut X509Algor = ptr::null_mut();

    // SAFETY: `md_type` is NULL or live per the caller's contract; `EVP_sha256` is safe.
    let md_type = if md_type.is_null() {
        EVP_sha256()
    } else {
        md_type
    };
    // SAFETY: `md_type` is live and `prf_md_name` is NULL or NUL-terminated.
    let prf_md_nid = unsafe {
        if prf_md_name.is_null() {
            EVP_MD_get_type(md_type)
        } else {
            OBJ_txt2nid(prf_md_name)
        }
    };
    let iter = if iter == 0 { PKCS12_DEFAULT_ITER } else { iter };
    // SAFETY: `md_type` is live.
    let keylen = unsafe { EVP_MD_get_size(md_type) };
    // Both conversions are pure table lookups.
    let prf_nid = ossl_md2hmacnid(prf_md_nid);
    // SAFETY: `md_type` is live.
    let hmac_nid = unsafe { ossl_md2hmacnid(EVP_MD_get_type(md_type)) };

    'body: {
        // SAFETY: `p12` is live; every allocation is checked before use.
        unsafe {
            if prf_nid == NID_undef || hmac_nid == NID_undef {
                raise_site(&err_sites::PKCS12_MUTL_487);
                break 'body;
            }
            let saltsrc = if salt.is_null() {
                known_salt = CRYPTO_malloc(saltlen as usize, FILE.as_ptr(), 492).cast::<c_uchar>();
                if known_salt.is_null() {
                    break 'body;
                }
                if RAND_bytes_ex(ptr::null_mut(), known_salt, saltlen as usize, 0) <= 0 {
                    raise_site(&err_sites::PKCS12_MUTL_497);
                    break 'body;
                }
                known_salt
            } else {
                salt
            };
            param = PBMAC1PARAM_new();
            hmac_alg = X509_ALGOR_new();
            alg = PKCS5_pbkdf2_set(iter, saltsrc, saltlen, prf_nid, keylen);
            if param.is_null() || hmac_alg.is_null() || alg.is_null() {
                break 'body;
            }
            if pkcs12_setup_mac(p12, iter, saltsrc, saltlen, NID_pbmac1) == PKCS12_ERROR {
                raise_site(&err_sites::PKCS12_MUTL_511);
                break 'body;
            }
            if X509_ALGOR_set0(
                hmac_alg,
                OBJ_nid2obj(hmac_nid),
                V_ASN1_NULL,
                ptr::null_mut(),
            ) == 0
            {
                raise_site(&err_sites::PKCS12_MUTL_516);
                break 'body;
            }
            X509_ALGOR_free((*param).key_derivation_func);
            X509_ALGOR_free((*param).message_auth_scheme);
            (*param).key_derivation_func = alg;
            (*param).message_auth_scheme = hmac_alg;
            alg = ptr::null_mut();
            hmac_alg = ptr::null_mut();

            let mut macalg: *mut X509Algor = ptr::null_mut();
            let mut macoct: *mut Asn1String = ptr::null_mut();
            X509_SIG_getm((*(*p12).mac).dinfo, &raw mut macalg, &raw mut macoct);
            if ASN1_TYPE_pack_sequence(
                PBMAC1PARAM_it(),
                param.cast::<c_void>(),
                &raw mut (*macalg).parameter,
            )
            .is_null()
            {
                break 'body;
            }
            if pkcs12_gen_mac(
                p12,
                pass,
                passlen,
                mac.as_mut_ptr(),
                &raw mut maclen,
                EVP_MD_get_type(md_type),
                prf_md_nid,
                Some(pkcs12_pbmac1_pbkdf2_key_gen),
            ) == 0
            {
                raise_site(&err_sites::PKCS12_MUTL_537);
                break 'body;
            }
            if ASN1_OCTET_STRING_set(macoct, mac.as_ptr(), maclen as c_int) == 0 {
                raise_site(&err_sites::PKCS12_MUTL_541);
                break 'body;
            }
            ret = 1;
        }
    }
    // SAFETY: each is NULL or this frame's own.
    unsafe {
        X509_ALGOR_free(alg);
        X509_ALGOR_free(hmac_alg);
        PBMAC1PARAM_free(param);
        CRYPTO_free(known_salt.cast::<c_void>(), FILE.as_ptr(), 550);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs12::p12_asn::{PKCS12_free, PKCS12_new};
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site.
    fn packed(site: &err_sites::ErrSite) -> core::ffi::c_ulong {
        (((site.lib as core::ffi::c_ulong) & 0xff) << 23)
            | ((site.reason as core::ffi::c_ulong) & 0x7f_ffff)
    }

    /// The GOST keygen refuses any length but 32 **before** it reaches PBKDF2, so this arm is a
    /// pure length check and touches no process-global state.
    #[test]
    fn gost_keygen_refuses_a_wrong_length() {
        let mut out = [0 as c_uchar; 64];
        // SAFETY: `out` is writable for 64 bytes; the length check returns before the digest is
        // used, so the NULL digest is never dereferenced.
        let ok = unsafe {
            pkcs12_gen_gost_mac_key(
                ptr::null(),
                -1,
                ptr::null(),
                0,
                1,
                TK26_MAC_KEY_LEN - 1,
                out.as_mut_ptr(),
                ptr::null(),
            )
        };
        assert!(!ok);
    }

    /// `PKCS12_verify_mac` on a container with no `MacData` raises `PKCS12_R_MAC_ABSENT` and
    /// answers 0. The error queue and object table are process-global, so the test runs alone.
    #[test]
    fn verify_mac_refuses_a_container_without_macdata() {
        let _guard = crate::test_support::lock_global_state();
        let p12 = PKCS12_new();
        assert!(!p12.is_null());
        ERR_clear_error();
        // SAFETY: `p12` is live; the null `MacData` is the arm under test.
        let ret = unsafe { PKCS12_verify_mac(p12, c"pw".as_ptr(), -1) };
        assert_eq!(ret, 0);
        assert_eq!(ERR_peek_error(), packed(&err_sites::PKCS12_MUTL_321));
        ERR_clear_error();
        // SAFETY: `p12` is this frame's own.
        unsafe { PKCS12_free(p12) };
    }
}
