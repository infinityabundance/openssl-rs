//! `crypto/pkcs7/pk7_lib.c` — the parts of the `PKCS7` object layer the PKCS#12 container
//! reaches: `PKCS7_set_type` and the five `ossl_pkcs7_*` context helpers. Phase 10 (the PKCS#12
//! landing D441 blocked).
//!
//! ## `PKCS7_set_type`'s arms
//!
//! The authority's `match` (`pk7_lib.c:125-181`) has six arms. `data`, `digest` and `encrypted`
//! are transcribed; `signed`, `signedAndEnveloped` and `enveloped` allocate `PKCS7_SIGNED`,
//! `PKCS7_SIGN_ENVELOPE` and `PKCS7_ENVELOPE`, whose item groups name Phase 11's `X509_it`,
//! `X509_CRL_it` and `X509_NAME_it` and are therefore not carried. A caller that asks for one of
//! those three reaches the authority's own `default:` arm, which raises
//! `PKCS7_R_UNSUPPORTED_CONTENT_TYPE` — the reason the site below is the authority's line 179.
//! PKCS#12 never asks: its only `PKCS7_set_type` call is `PKCS12_pack_p7encdata_ex`'s
//! `NID_pkcs7_encrypted` (`p12_add.c:108`).
//!
//! ## The context helpers
//!
//! `ossl_pkcs7_set0_libctx`, `ossl_pkcs7_set1_propq`, `ossl_pkcs7_ctx_get0_libctx`,
//! `ossl_pkcs7_ctx_get0_propq` and `ossl_pkcs7_ctx_propagate` are transcribed whole.
//! `ossl_pkcs7_ctx_propagate` also calls `ossl_pkcs7_resolve_libctx`, which walks the received
//! structure's X509, recipient-info and signer-info stacks; that walk is withheld with the
//! withheld arms, and its observable effect for the three arms this subset carries is nothing —
//! all three stacks are null **by the arm's own type**, so the authority's loops iterate zero
//! times. The function below records that rather than guessing.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::pkcs7::pk7_asn1::{PKCS7_DIGEST_new, PKCS7_ENCRYPT_new, Pkcs7, Pkcs7Ctx};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::{NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, OBJ_nid2obj};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_lib.c";

/// `int PKCS7_set_type(PKCS7 *p7, int type)` — `pk7_lib.c:116-185`.
///
/// The `type` OID is looked up first (the authority's comment records that it cannot fail), then
/// the arm builds the content union. The three arms this subset carries are `data`
/// (`ASN1_OCTET_STRING_new`), `digest` (`PKCS7_DIGEST_new`, version 0) and `encrypted`
/// (`PKCS7_ENCRYPT_new`, version 0, content type `pkcs7-data`). The other three reach the
/// authority's `default:` arm and raise `PKCS7_R_UNSUPPORTED_CONTENT_TYPE`.
///
/// # Safety
/// `p7` is a live `PKCS7` whose content union has no arm yet.
#[allow(non_upper_case_globals)] // the authority's own `NID_pkcs7_*` spellings
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_type(p7: *mut Pkcs7, type_: c_int) -> c_int {
    // SAFETY: no preconditions.
    let obj = OBJ_nid2obj(type_);

    match type_ {
        NID_pkcs7_data => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: as above; the `data` arm is the union's storage.
            let os = ASN1_OCTET_STRING_new();
            if os.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable.
            unsafe { (*p7).d.data = os };
            1
        }
        NID_pkcs7_encrypted => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let enc = PKCS7_ENCRYPT_new();
            if enc.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable; `enc` is the fresh arm.
            unsafe {
                (*p7).d.encrypted = enc;
                if ASN1_INTEGER_set((*enc).version, 0) == 0 {
                    return 0;
                }
                (*(*enc).enc_data).content_type = OBJ_nid2obj(NID_pkcs7_data);
            }
            1
        }
        NID_pkcs7_digest => {
            // SAFETY: `p7` is the caller's live object.
            unsafe { (*p7).type_ = obj };
            // SAFETY: no preconditions.
            let digest = PKCS7_DIGEST_new();
            if digest.is_null() {
                return 0;
            }
            // SAFETY: `p7` is live and its `d` union is writable; `digest` is the fresh arm.
            unsafe {
                (*p7).d.digest = digest;
                if ASN1_INTEGER_set((*digest).version, 0) == 0 {
                    return 0;
                }
            }
            1
        }
        _ => {
            // The authority's `default:` arm, at its own line. The three withheld arms —
            // `signed`, `signedAndEnveloped` and `enveloped` — are all there.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS7_LIB_179) };
            0
        }
    }
}

/// `const PKCS7_CTX *ossl_pkcs7_get0_ctx(const PKCS7 *p7)` — `pk7_lib.c:484-487`.
///
/// # Safety
/// `p7` is null or a live `PKCS7`; a non-null answer borrows its context.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_get0_ctx(p7: *const Pkcs7) -> *const Pkcs7Ctx {
    if p7.is_null() {
        ptr::null()
    } else {
        // SAFETY: `p7` is live per the caller's contract.
        unsafe { ptr::addr_of!((*p7).ctx) }
    }
}

/// `OSSL_LIB_CTX *ossl_pkcs7_ctx_get0_libctx(const PKCS7_CTX *ctx)` — `pk7_lib.c:518-521`.
///
/// # Safety
/// `ctx` is null or a live `PKCS7_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_get0_libctx(ctx: *const Pkcs7Ctx) -> *mut c_void {
    if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).libctx }
    }
}

/// `const char *ossl_pkcs7_ctx_get0_propq(const PKCS7_CTX *ctx)` — `pk7_lib.c:522-525`.
///
/// # Safety
/// `ctx` is null or a live `PKCS7_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_get0_propq(ctx: *const Pkcs7Ctx) -> *const c_char {
    if ctx.is_null() {
        ptr::null()
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).propq }
    }
}

/// `void ossl_pkcs7_set0_libctx(PKCS7 *p7, OSSL_LIB_CTX *ctx)` — `pk7_lib.c:489-492`.
///
/// # Safety
/// `p7` is a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_set0_libctx(p7: *mut Pkcs7, ctx: *mut c_void) {
    // SAFETY: `p7` is live per the caller's contract.
    unsafe { (*p7).ctx.libctx = ctx };
}

/// `int ossl_pkcs7_set1_propq(PKCS7 *p7, const char *propq)` — `pk7_lib.c:494-506`.
///
/// Takes a **copy** of `propq`, releasing any query already held; a null `propq` clears the slot.
/// A failed copy answers 0 and leaves the slot null.
///
/// # Safety
/// `p7` is a live `PKCS7`; `propq` is null or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_set1_propq(p7: *mut Pkcs7, propq: *const c_char) -> c_int {
    // SAFETY: `p7` is live; its `ctx.propq` is either null or this object's own copy.
    unsafe {
        if !(*p7).ctx.propq.is_null() {
            CRYPTO_free((*p7).ctx.propq.cast(), FILE.as_ptr(), 497);
            (*p7).ctx.propq = ptr::null_mut();
        }
    }
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the caller's contract.
        let copy = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 501) };
        if copy.is_null() {
            return 0;
        }
        // SAFETY: `p7` is live and its `ctx.propq` slot is writable.
        unsafe { (*p7).ctx.propq = copy };
    }
    1
}

/// `void ossl_pkcs7_resolve_libctx(PKCS7 *p7)` — `pk7_lib.c:450-482`, transcribed for the three
/// arms this subset carries.
///
/// The authority's body sets up the context, returns early when it or the content union is null,
/// then propagates the context into every certificate, recipient info and signer info the
/// structure holds. Those three walks call Phase 11's `ossl_x509_set0_libctx` and are withheld
/// with the three withheld arms; for `data`, `digest` and `encrypted` all three stacks are null
/// **by the arm's type**, so the authority's loops iterate zero times and its observable effect
/// is exactly what is below — the early return.
///
/// # Safety
/// `p7` is a live `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_resolve_libctx(p7: *mut Pkcs7) {
    // SAFETY: `p7` is live per the caller's contract.
    unsafe {
        let ctx = ossl_pkcs7_get0_ctx(p7);
        if ctx.is_null() || (*p7).d.ptr.is_null() {
            return;
        }
        // The withheld propagation walks (`pk7_lib.c:467-481`) stood here. See the module note.
        let _ = ossl_pkcs7_ctx_get0_libctx(ctx);
        let _ = ossl_pkcs7_ctx_get0_propq(ctx);
    }
}

/// `int ossl_pkcs7_ctx_propagate(const PKCS7 *from, PKCS7 *to)` — `pk7_lib.c:508-516`.
///
/// Copies the library context by assignment and the property query by value, then resolves the
/// target. A failed property-query copy answers 0 without resolving.
///
/// # Safety
/// `from` and `to` are live `PKCS7`s.
#[no_mangle]
pub unsafe extern "C" fn ossl_pkcs7_ctx_propagate(from: *const Pkcs7, to: *mut Pkcs7) -> c_int {
    // SAFETY: both are live per the caller's contract.
    unsafe {
        ossl_pkcs7_set0_libctx(to, (*from).ctx.libctx);
        if ossl_pkcs7_set1_propq(to, (*from).ctx.propq) == 0 {
            return 0;
        }
        ossl_pkcs7_resolve_libctx(to);
    }
    1
}
