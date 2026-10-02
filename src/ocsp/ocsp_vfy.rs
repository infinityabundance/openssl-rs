//! `crypto/ocsp/ocsp_vfy.c` — the OCSP response verifier's signer/id helpers. Phase 11.2b's fourth
//! OCSP-function unit, landed as an **internal** transcription: every name is `pub(crate)` and none
//! carries `#[no_mangle]`, because the `OCSP_*` exports are Phase 12's.
//!
//! `crypto/ocsp/ocsp_vfy.c` is 438 lines. The requested set is `OCSP_basic_verify` (`:98`) and the
//! statics it reaches. **Two of them are held by name**, because the path engine they call is itself
//! withheld (see below); the seven that close over only landed names are transcribed:
//!
//! * [`ocsp_verify`] (`:76-95`) — verify the request or basic-response signature over the signer's
//!   public key, unless `OCSP_NOSIGS`.
//! * [`ocsp_find_signer`] (`:168-186`) — the response's `ResponderID` resolved against the extra
//!   `certs` (answer 2), then against the response's own `certs` (answer 1), or NULL.
//! * [`ocsp_find_signer_sk`] (`:188-219`) — by subject name, or by SHA-1 public-key hash.
//! * [`ocsp_check_issuer`] (`:221-257`) — match the response's issuer id against the chain.
//! * [`ocsp_check_ids`] (`:266-296`) — reduce the several `CertID`s to one, or report a mismatch.
//! * [`ocsp_match_issuerid`] (`:302-367`) — hash the candidate certificate's subject and public key
//!   with the `CertID`'s own algorithm and compare.
//! * [`ocsp_check_delegated`] (`:369-376`) — the responder certificate's `OCSP Signing` usage.
//!
//! ## Held by name
//!
//! * `ocsp_verify_signer` (`:30-74`) and `OCSP_basic_verify` (`:98-160`).
//!
//! `ocsp_verify_signer` calls `X509_STORE_CTX_init` and `X509_verify_cert`, and
//! `crate::x509::x509_vfy` withholds both by name (its module doc, `:48-57`): they install and run
//! the path engine, whose `check_revocation` half is this very OCSP arm. There is no
//! `crate::x509::x509_vfy::X509_verify_cert` in the crate to reference, so `ocsp_verify_signer`
//! cannot compile; and because `OCSP_basic_verify` calls it, neither can that. Both land together
//! with the engine slice (11.2c), which is also where this file's `#![allow(dead_code)]` retires.
//!
//! ## The raise sites
//!
//! `crypto/ocsp/ocsp_vfy.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the
//! coordinates on the landed paths are **declared locally** in the `err_sites::ErrSite` shape, as
//! `v3_ocsp.rs` does. The reasons are read from the authority's own `include/openssl/ocsperr.h`
//! (`130`, `117`, `105`, `111`, `119`, `107`, `102`, `103`) against `ERR_LIB_OCSP` = 39
//! (`include/openssl/err.h.in:104`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)] // reached only from the Phase-11 engine's OCSP arm (11.2c)

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong};
use core::ptr;

use crate::asn1::a_verify::ASN1_item_verify_ex;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::ocsp::ocsp_asn::{
    OCSP_REQINFO_it, OCSP_RESPDATA_it, OcspBasicResp, OcspCertId, OcspRequest, OcspRespid,
    OcspSingleResp,
};
use crate::ocsp::ocsp_lib::OCSP_id_issuer_cmp;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::obj::{OBJ_cmp, OBJ_obj2txt};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_purp::{X509_get_extended_key_usage, X509_get_extension_flags};
use crate::x509::x509_cmp::{X509_find_by_subject, X509_get0_pubkey, X509_get_subject_name};
use crate::x509::x_all::{X509_NAME_digest, X509_pubkey_digest};
use crate::x509::x_x509::X509;

/// `ERR_LIB_OCSP` — `include/openssl/err.h.in:104`.
const ERR_LIB_OCSP: c_int = 39;
/// `OCSP_R_NO_SIGNER_KEY` — `include/openssl/ocsperr.h:36`.
const OCSP_R_NO_SIGNER_KEY: c_int = 130;
/// `OCSP_R_SIGNATURE_FAILURE` — `include/openssl/ocsperr.h:41`.
const OCSP_R_SIGNATURE_FAILURE: c_int = 117;
/// `OCSP_R_NO_CERTIFICATES_IN_CHAIN` — `include/openssl/ocsperr.h:33`.
const OCSP_R_NO_CERTIFICATES_IN_CHAIN: c_int = 105;
/// `OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA` — `include/openssl/ocsperr.h:39`.
const OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA: c_int = 111;
/// `OCSP_R_UNKNOWN_MESSAGE_DIGEST` — `include/openssl/ocsperr.h:46`.
const OCSP_R_UNKNOWN_MESSAGE_DIGEST: c_int = 119;
/// `OCSP_R_DIGEST_SIZE_ERR` — `include/openssl/ocsperr.h:27`.
const OCSP_R_DIGEST_SIZE_ERR: c_int = 107;
/// `OCSP_R_DIGEST_ERR` — `include/openssl/ocsperr.h:25`.
const OCSP_R_DIGEST_ERR: c_int = 102;
/// `OCSP_R_MISSING_OCSPSIGNING_USAGE` — `include/openssl/ocsperr.h:30`.
const OCSP_R_MISSING_OCSPSIGNING_USAGE: c_int = 103;

/// `OCSP_NOSIGS` — `include/openssl/ocsp.h.in:79`.
const OCSP_NOSIGS: c_ulong = 0x4;
/// `OCSP_NOINTERN` — `include/openssl/ocsp.h.in:78`.
const OCSP_NOINTERN: c_ulong = 0x2;
/// `V_OCSP_RESPID_NAME` — `include/openssl/ocsp.h.in:113`.
const V_OCSP_RESPID_NAME: c_int = 0;
/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`, `20`; the `ResponderID byKey` width.
const SHA_DIGEST_LENGTH: c_int = 20;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`; the algorithm-name scratch width.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`; the digest scratch width.
const EVP_MAX_MD_SIZE: usize = 64;
/// `EXFLAG_XKUSAGE` — `include/openssl/x509v3.h:670`.
const EXFLAG_XKUSAGE: c_uint = 0x4;
/// `XKU_OCSP_SIGN` — `include/openssl/x509v3.h:717`.
const XKU_OCSP_SIGN: c_uint = 0x20;
/// `SN_sha1` — `include/openssl/obj_mac.h`, the short name `EVP_MD_fetch` is asked for.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();

/// One `ocsp_vfy.c` raise coordinate, declared locally (see the module doc).
const fn ocsp_vfy_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ocsp/ocsp_vfy.c",
        line,
        func,
        lib: ERR_LIB_OCSP,
        reason,
        dynamic_reason: false,
    }
}

/// `ocsp_verify`'s missing-public-key arm at `ocsp_vfy.c:84`.
const OCSP_VFY_84: ErrSite = ocsp_vfy_site(84, c"ocsp_verify", OCSP_R_NO_SIGNER_KEY);
/// `ocsp_verify`'s signature-failure arm at `ocsp_vfy.c:92`.
const OCSP_VFY_92: ErrSite = ocsp_vfy_site(92, c"ocsp_verify", OCSP_R_SIGNATURE_FAILURE);
/// `ocsp_check_issuer`'s empty-chain arm at `ocsp_vfy.c:229`.
const OCSP_VFY_229: ErrSite =
    ocsp_vfy_site(229, c"ocsp_check_issuer", OCSP_R_NO_CERTIFICATES_IN_CHAIN);
/// `ocsp_check_ids`'s empty-response arm at `ocsp_vfy.c:273`.
const OCSP_VFY_273: ErrSite = ocsp_vfy_site(
    273,
    c"ocsp_check_ids",
    OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA,
);
/// `ocsp_match_issuerid`'s unknown-digest arm at `ocsp_vfy.c:324`.
const OCSP_VFY_324: ErrSite =
    ocsp_vfy_site(324, c"ocsp_match_issuerid", OCSP_R_UNKNOWN_MESSAGE_DIGEST);
/// `ocsp_match_issuerid`'s bad-digest-size arm at `ocsp_vfy.c:331`.
const OCSP_VFY_331: ErrSite = ocsp_vfy_site(331, c"ocsp_match_issuerid", OCSP_R_DIGEST_SIZE_ERR);
/// `ocsp_match_issuerid`'s key-digest-failure arm at `ocsp_vfy.c:346`.
const OCSP_VFY_346: ErrSite = ocsp_vfy_site(346, c"ocsp_match_issuerid", OCSP_R_DIGEST_ERR);
/// `ocsp_check_delegated`'s missing-usage arm at `ocsp_vfy.c:374`.
const OCSP_VFY_374: ErrSite = ocsp_vfy_site(
    374,
    c"ocsp_check_delegated",
    OCSP_R_MISSING_OCSPSIGNING_USAGE,
);

/// `memcmp` — `<string.h>`; answers the difference of the first differing octets, or 0.
///
/// # Safety
/// `a` and `b` must each point to `n` readable bytes.
unsafe fn memcmp(a: *const c_uchar, b: *const c_uchar, n: c_int) -> c_int {
    let mut i = 0;
    while i < n {
        // SAFETY: `0 <= i < n`, so both offsets are within the readable ranges.
        let (x, y) = unsafe { (*a.add(i as usize), *b.add(i as usize)) };
        if x != y {
            return c_int::from(x) - c_int::from(y);
        }
        i += 1;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// The functions
// ---------------------------------------------------------------------------------------------

/// `static int ocsp_verify(OCSP_REQUEST *req, OCSP_BASICRESP *bs, X509 *signer, unsigned long
/// flags)` — `crypto/ocsp/ocsp_vfy.c:76-95`.
///
/// Unless `OCSP_NOSIGS` is set, verifies `req`'s `TBSRequest` signature (or `bs`'s
/// `ResponseData` signature) with the signer's public key through the `OCSP_REQUEST_verify` /
/// `OCSP_BASICRESP_verify` macros, i.e. `ASN1_item_verify_ex` over `OCSP_REQINFO` /
/// `OCSP_RESPDATA`. A missing key answers -1; a failing signature raises
/// `OCSP_R_SIGNATURE_FAILURE` and answers the non-positive verify result.
///
/// # Safety
/// `req` and `bs` must be NULL or live of their types, and exactly the one the caller selected must
/// be live (`bs` when `req` is NULL, `req` otherwise); `signer` must be a live `X509`.
pub(crate) unsafe extern "C" fn ocsp_verify(
    req: *mut OcspRequest,
    bs: *mut OcspBasicResp,
    signer: *mut X509,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the pointers are live per the contract; `ASN1_item_verify_ex` and the getters obey
    // their own contracts.
    unsafe {
        let mut ret = 1;
        if (flags & OCSP_NOSIGS) == 0 {
            let skey = X509_get0_pubkey(signer);
            if skey.is_null() {
                raise_site(&OCSP_VFY_84);
                return -1;
            }
            ret = if !req.is_null() {
                // `OCSP_REQUEST_verify(req, skey, signer->libctx, signer->propq)`.
                ASN1_item_verify_ex(
                    OCSP_REQINFO_it(),
                    &(*(*req).optionalSignature).signatureAlgorithm,
                    (*(*req).optionalSignature).signature,
                    ptr::addr_of!((*req).tbsRequest).cast(),
                    ptr::null(),
                    skey,
                    (*signer).libctx,
                    (*signer).propq,
                )
            } else {
                // `OCSP_BASICRESP_verify(bs, skey, signer->libctx, signer->propq)`.
                ASN1_item_verify_ex(
                    OCSP_RESPDATA_it(),
                    &(*bs).signatureAlgorithm,
                    (*bs).signature,
                    ptr::addr_of!((*bs).tbsResponseData).cast(),
                    ptr::null(),
                    skey,
                    (*signer).libctx,
                    (*signer).propq,
                )
            };
            if ret <= 0 {
                raise_site(&OCSP_VFY_92);
            }
        }
        ret
    }
}

/// `static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
/// unsigned long flags)` — `crypto/ocsp/ocsp_vfy.c:168-186`.
///
/// Answers 2 for a match among the caller's extra `certs`, 1 for a match among the response's own
/// `certs` (unless `OCSP_NOINTERN`), or 0 after storing NULL.
///
/// # Safety
/// `psigner` must be writable; `bs` must be a live `OCSP_BASICRESP`; `certs` must be a live or NULL
/// stack of live `X509`s.
pub(crate) unsafe extern "C" fn ocsp_find_signer(
    psigner: *mut *mut X509,
    bs: *mut OcspBasicResp,
    certs: *mut OpenSslStack,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the pointers are live per the contract; the lookup helpers obey their own contracts.
    unsafe {
        let rid: *mut OcspRespid = &mut (*bs).tbsResponseData.responderId;
        let signer = ocsp_find_signer_sk(certs, rid);
        if !signer.is_null() {
            *psigner = signer;
            return 2;
        }
        if (flags & OCSP_NOINTERN) == 0 {
            let signer = ocsp_find_signer_sk((*bs).certs, rid);
            if !signer.is_null() {
                *psigner = signer;
                return 1;
            }
        }
        *psigner = ptr::null_mut();
        0
    }
}

/// `static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)` —
/// `crypto/ocsp/ocsp_vfy.c:188-219`.
///
/// A `byName` id is resolved with `X509_find_by_subject`; a `byKey` id must be exactly
/// `SHA_DIGEST_LENGTH` octets, and each certificate is matched by fetching `SHA1` (through the
/// certificate's own library context and property query) and hashing its public key. A fetch or
/// digest failure ends the scan.
///
/// # Safety
/// `certs` must be a live or NULL stack of live `X509`s; `id` must be a live `OCSP_RESPID` whose
/// chosen arm is set.
pub(crate) unsafe extern "C" fn ocsp_find_signer_sk(
    certs: *mut OpenSslStack,
    id: *mut OcspRespid,
) -> *mut X509 {
    // SAFETY: `id` and `certs` are live per the contract; every union arm that is read is the one
    // the `type_` selector names.
    unsafe {
        if (*id).type_ == V_OCSP_RESPID_NAME {
            return X509_find_by_subject(certs, (*id).value.byName);
        }

        // Lookup by key hash. If it isn't SHA1 length then forget it.
        let bykey = (*id).value.byKey;
        if (*bykey).length != SHA_DIGEST_LENGTH {
            return ptr::null_mut();
        }
        let keyhash = (*bykey).data;
        let n = OPENSSL_sk_num(certs);
        let mut i = 0;
        while i < n {
            let x = OPENSSL_sk_value(certs, i).cast::<X509>();
            if !x.is_null() {
                let md = EVP_MD_fetch((*x).libctx, SN_SHA1, (*x).propq);
                if md.is_null() {
                    break;
                }
                let mut tmphash = [0u8; SHA_DIGEST_LENGTH as usize];
                let r = X509_pubkey_digest(x, md, tmphash.as_mut_ptr(), ptr::null_mut());
                EVP_MD_free(md);
                if r == 0 {
                    break;
                }
                if memcmp(keyhash, tmphash.as_ptr(), SHA_DIGEST_LENGTH) == 0 {
                    return x;
                }
            }
            i += 1;
        }
        ptr::null_mut()
    }
}

/// `static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain)` —
/// `crypto/ocsp/ocsp_vfy.c:221-257`.
///
/// Reduces the response's `CertID`s with [`ocsp_check_ids`], then matches the chain: a
/// two-or-more-deep chain is checked with its second element as the responder CA and, on a match,
/// requires the signer to carry `OCSP Signing`; otherwise the signer itself is matched directly.
///
/// # Safety
/// `bs` must be a live `OCSP_BASICRESP`; `chain` must be a live stack of live `X509`s.
pub(crate) unsafe extern "C" fn ocsp_check_issuer(
    bs: *mut OcspBasicResp,
    chain: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `bs` and `chain` are live per the contract; the helpers obey their own contracts.
    unsafe {
        let sresp = (*bs).tbsResponseData.responses;
        if OPENSSL_sk_num(chain) <= 0 {
            raise_site(&OCSP_VFY_229);
            return -1;
        }

        // See if the issuer IDs match.
        let mut caid: *mut OcspCertId = ptr::null_mut();
        let ret = ocsp_check_ids(sresp, &mut caid);
        if ret <= 0 {
            return ret;
        }

        let signer = OPENSSL_sk_value(chain, 0).cast::<X509>();
        // Check to see if OCSP responder CA matches request CA.
        if OPENSSL_sk_num(chain) > 1 {
            let sca = OPENSSL_sk_value(chain, 1).cast::<X509>();
            let ret = ocsp_match_issuerid(sca, caid, sresp);
            if ret < 0 {
                return ret;
            }
            if ret != 0 {
                // We have a match, if extensions OK then success.
                if ocsp_check_delegated(signer) != 0 {
                    return 1;
                }
                return 0;
            }
        }

        // Otherwise check if OCSP request signed directly by request CA.
        ocsp_match_issuerid(signer, caid, sresp)
    }
}

/// `static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret)` —
/// `crypto/ocsp/ocsp_vfy.c:266-296`.
///
/// With no responses raises `OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA` and answers -1. If every
/// `CertID` matches the first, stores the first and answers 1; an algorithm mismatch answers 2 and
/// any other mismatch answers 0.
///
/// # Safety
/// `sresp` must be a live stack of live `OCSP_SINGLERESP`s; `ret` must be writable.
pub(crate) unsafe extern "C" fn ocsp_check_ids(
    sresp: *mut OpenSslStack,
    ret: *mut *mut OcspCertId,
) -> c_int {
    // SAFETY: `sresp` and `ret` are live per the contract; the comparator accepts live operands.
    unsafe {
        let idcount = OPENSSL_sk_num(sresp);
        if idcount <= 0 {
            raise_site(&OCSP_VFY_273);
            return -1;
        }

        let cid = (*OPENSSL_sk_value(sresp, 0).cast::<OcspSingleResp>()).certId;

        *ret = ptr::null_mut();
        let mut i = 1;
        while i < idcount {
            let tmpid = (*OPENSSL_sk_value(sresp, i).cast::<OcspSingleResp>()).certId;
            // Check to see if IDs match.
            if OCSP_id_issuer_cmp(cid, tmpid) != 0 {
                // If algorithm mismatch let caller deal with it.
                if OBJ_cmp(
                    (*tmpid).hashAlgorithm.algorithm,
                    (*cid).hashAlgorithm.algorithm,
                ) != 0
                {
                    return 2;
                }
                // Else mismatch.
                return 0;
            }
            i += 1;
        }

        // All IDs match: only need to check one ID.
        *ret = cid;
        1
    }
}

/// `static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP)
/// *sresp)` — `crypto/ocsp/ocsp_vfy.c:302-367`.
///
/// Returns -1 on a fatal error, 0 on no match and 1 on a match. With a single `cid` it fetches the
/// digest named by the id's algorithm OID (a marked fetch, then the legacy lookup), checks the two
/// hash lengths, and compares the certificate's subject-name and public-key digests. With a NULL
/// `cid` it recurses over every single response.
///
/// # Safety
/// `cert` must be a live `X509`; `cid` must be NULL or a live `OCSP_CERTID`; `sresp` must be a live
/// stack of live `OCSP_SINGLERESP`s when `cid` is NULL.
pub(crate) unsafe extern "C" fn ocsp_match_issuerid(
    cert: *mut X509,
    cid: *mut OcspCertId,
    sresp: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `cert`, `cid` and `sresp` are live per the contract; every helper obeys its own.
    unsafe {
        let mut ret = -1;

        if !cid.is_null() {
            let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];
            let mut md = [0u8; EVP_MAX_MD_SIZE];

            OBJ_obj2txt(
                name.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                (*cid).hashAlgorithm.algorithm,
                0,
            );

            ERR_set_mark();
            let mut dgst: *mut EvpMd = EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null());
            if dgst.is_null() {
                dgst = EVP_get_digestbyname(name.as_ptr()).cast_mut();
            }

            if dgst.is_null() {
                ERR_clear_last_mark();
                raise_site(&OCSP_VFY_324);
                EVP_MD_free(dgst);
                return ret;
            }
            ERR_pop_to_mark();

            let mdlen = EVP_MD_get_size(dgst);
            if mdlen <= 0 {
                raise_site(&OCSP_VFY_331);
                EVP_MD_free(dgst);
                return ret;
            }
            if (*cid).issuerNameHash.length != mdlen || (*cid).issuerKeyHash.length != mdlen {
                ret = 0;
                EVP_MD_free(dgst);
                return ret;
            }
            let iname = X509_get_subject_name(cert);
            if X509_NAME_digest(iname, dgst, md.as_mut_ptr(), ptr::null_mut()) == 0 {
                EVP_MD_free(dgst);
                return ret;
            }
            if memcmp(md.as_ptr(), (*cid).issuerNameHash.data, mdlen) != 0 {
                ret = 0;
                EVP_MD_free(dgst);
                return ret;
            }
            if X509_pubkey_digest(cert, dgst, md.as_mut_ptr(), ptr::null_mut()) == 0 {
                raise_site(&OCSP_VFY_346);
                EVP_MD_free(dgst);
                return ret;
            }
            ret = c_int::from(memcmp(md.as_ptr(), (*cid).issuerKeyHash.data, mdlen) == 0);
            EVP_MD_free(dgst);
            return ret;
        }

        // We have to match the whole lot.
        let mut i = 0;
        while i < OPENSSL_sk_num(sresp) {
            let tmpid = (*OPENSSL_sk_value(sresp, i).cast::<OcspSingleResp>()).certId;
            ret = ocsp_match_issuerid(cert, tmpid, ptr::null_mut());
            if ret <= 0 {
                return ret;
            }
            i += 1;
        }
        1
    }
}

/// `static int ocsp_check_delegated(X509 *x)` — `crypto/ocsp/ocsp_vfy.c:369-376`.
///
/// Answers 1 when `x` carries the extended-key-usage extension with `OCSP Signing`; otherwise
/// raises `OCSP_R_MISSING_OCSPSIGNING_USAGE` and answers 0.
///
/// # Safety
/// `x` must be a live `X509`.
pub(crate) unsafe extern "C" fn ocsp_check_delegated(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract; the two getters cache and read its extensions.
    unsafe {
        if (X509_get_extension_flags(x) & EXFLAG_XKUSAGE) != 0
            && (X509_get_extended_key_usage(x) & XKU_OCSP_SIGN) != 0
        {
            return 1;
        }
        raise_site(&OCSP_VFY_374);
        0
    }
}

// ---------------------------------------------------------------------------------------------
// Held by name — the engine slice (11.2c) lands these with `X509_verify_cert`
// ---------------------------------------------------------------------------------------------
//
// `ocsp_verify_signer` (`crypto/ocsp/ocsp_vfy.c:30-74`) and `OCSP_basic_verify` (`:98-160`) are not
// transcribed here. `ocsp_verify_signer` calls `X509_STORE_CTX_init` and `X509_verify_cert`, and
// `crate::x509::x509_vfy` withholds both by name (its module doc, `:48-57`): they install and run
// the path engine, whose `check_revocation` half is this very OCSP arm. There is no
// `crate::x509::x509_vfy::X509_verify_cert` to reference, so `ocsp_verify_signer` cannot compile;
// and because `OCSP_basic_verify` calls it, neither can that.
//
// TODO(11.2c): transcribe `ocsp_verify_signer` and `OCSP_basic_verify` once
// `crate::x509::x509_vfy::{X509_STORE_CTX_init, X509_verify_cert}` exist, then remove this file's
// `#![allow(dead_code)]` and the ones in `ocsp_lib.rs`/`ocsp_srv.rs`/`ocsp_cl.rs` this staging put
// in place.
