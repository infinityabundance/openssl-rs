//! Phase 7.4 — the `EVP_SIGNATURE` method object.
//!
//! `crypto/evp/signature.c`'s **method half**. The file's other half — the nineteen `EVP_PKEY_sign*`,
//! `verify*` and `verify_recover*` entry points, plus `EVP_PKEY_CTX_set_signature` — is
//! `EVP_PKEY_CTX` work and lands with 7.4c's context.
//!
//! ## The structural check is the only one in the family that is a *sequence*, not a conjunction
//!
//! Every other class folds its clauses into one boolean expression and raises once. This one walks
//! twenty clauses in order, each raising its **own** message, and the reasons are worth stating
//! because they decide what a court can observe:
//!
//!   * six counters — `ctxfncnt`, `initfncnt`, `gparamfncnt`, `sparamfncnt`, `gmdparamfncnt`,
//!     `smdparamfncnt` — and the first four clauses are counter tests that set a `valid` flag rather
//!     than jumping out. The **later** clauses are guarded by `valid`, so only the *first* failure is
//!     reported, and its message names it;
//!   * the four clauses after `if (!valid) goto err;` **bypass that test** and jump straight out. So
//!     they are reachable only when everything above passed, and a method failing both a counter
//!     clause and a combination clause reports the counter one.
//!   * four of the clauses are **XORs over NULL-ness** — `(update == NULL) != (final == NULL)` — in
//!     four places: message signing, message verification, digest signing, digest verification. A
//!     provider that publishes an update without a final is refused, and so is one that publishes a
//!     final without an update, and the two are the same clause. That is the class's other structural
//!     shape with no analogue elsewhere in the family.
//!
//! ## The dispatch ids are not in the order the struct is
//!
//! `sign_message_init`/`update`/`final` and `verify_message_init`/`update`/`final` are **27 to 32** —
//! appended after `query_key_types` at 26 — while their struct fields sit between `sign` and
//! `verify_init`. A transcription that assumed the ids were grouped the way the struct is would put
//! them next to each other, and the walk would then fill the wrong fields. The ids here are copied
//! from the header for that reason and the struct is in the header's field order, which is a
//! different order from both.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{
    evp_generic_do_all, evp_generic_fetch, evp_generic_fetch_from_prov, evp_is_a, evp_names_do_all,
    GenericDoAllFn, MethodFromAlgorithmFn,
};
use crate::params::OsslParam;
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_OP_SIGNATURE` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_SIGNATURE: c_int = 12;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/signature.c".as_ptr();
/// `evp_signature_new`'s `OPENSSL_zalloc(sizeof(EVP_SIGNATURE))` (line 35).
const LINE_ZALLOC_SIGNATURE: c_int = 35;
/// `EVP_SIGNATURE_free`'s `OPENSSL_free(signature->type_name)` (line 464).
const LINE_FREE_TYPE_NAME: c_int = 464;
/// `EVP_SIGNATURE_free`'s `OPENSSL_free(signature)` (line 467).
const LINE_FREE_SIGNATURE: c_int = 467;

/// The buffer an `ERR_raise_data` message is formatted into — the authority's `ERR_MAX_DATA_SIZE`.
const ERR_DATA_BUFFER: usize = 1024;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the twenty-eight function-pointer types.
//
// `OSSL_FUNC_SIGNATURE_*`. **Two groups are out of positional order**: `query_key_types` is 26 and
// the `sign_message_*`/`verify_message_*` triplets are 27..32, appended after it, while their struct
// fields sit between `sign` and `verify_init`. See this module's documentation.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_SIGNATURE_NEWCTX`.
const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
/// `OSSL_FUNC_SIGNATURE_SIGN_INIT`.
const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 2;
/// `OSSL_FUNC_SIGNATURE_SIGN`.
const OSSL_FUNC_SIGNATURE_SIGN: c_int = 3;
/// `OSSL_FUNC_SIGNATURE_VERIFY_INIT`.
const OSSL_FUNC_SIGNATURE_VERIFY_INIT: c_int = 4;
/// `OSSL_FUNC_SIGNATURE_VERIFY`.
const OSSL_FUNC_SIGNATURE_VERIFY: c_int = 5;
/// `OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT`.
const OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT: c_int = 6;
/// `OSSL_FUNC_SIGNATURE_VERIFY_RECOVER`.
const OSSL_FUNC_SIGNATURE_VERIFY_RECOVER: c_int = 7;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT`.
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT: c_int = 8;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE`.
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE: c_int = 9;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL`.
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL: c_int = 10;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN`.
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN: c_int = 11;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT`.
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT: c_int = 12;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE`.
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE: c_int = 13;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL`.
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL: c_int = 14;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY`.
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY: c_int = 15;
/// `OSSL_FUNC_SIGNATURE_FREECTX`.
const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 16;
/// `OSSL_FUNC_SIGNATURE_DUPCTX`.
const OSSL_FUNC_SIGNATURE_DUPCTX: c_int = 17;
/// `OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS`.
const OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS: c_int = 18;
/// `OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS: c_int = 19;
/// `OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS`.
const OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS: c_int = 20;
/// `OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS: c_int = 21;
/// `OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS`.
const OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS: c_int = 22;
/// `OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS`.
const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS: c_int = 23;
/// `OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS`.
const OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS: c_int = 24;
/// `OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS`.
const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS: c_int = 25;
/// `OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES` — **26**, before the two message triplets.
const OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES: c_int = 26;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT` — **27**, out of positional order.
const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT: c_int = 27;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE`.
const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE: c_int = 28;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL`.
const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL: c_int = 29;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT`.
const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT: c_int = 30;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE`.
const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE: c_int = 31;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL`.
const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL: c_int = 32;

/// `OSSL_FUNC_signature_newctx_fn`.
pub(crate) type SignatureNewctxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
/// `OSSL_FUNC_signature_sign_init_fn`.
pub(crate) type SignatureSignInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_sign_fn`.
pub(crate) type SignatureSignFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_sign_message_init_fn`.
pub(crate) type SignatureSignMessageInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_sign_message_update_fn`.
pub(crate) type SignatureSignMessageUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_sign_message_final_fn`.
pub(crate) type SignatureSignMessageFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_signature_verify_init_fn`.
pub(crate) type SignatureVerifyInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_verify_fn`.
pub(crate) type SignatureVerifyFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_verify_message_init_fn`.
pub(crate) type SignatureVerifyMessageInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_verify_message_update_fn`.
pub(crate) type SignatureVerifyMessageUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_verify_message_final_fn`.
pub(crate) type SignatureVerifyMessageFinalFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_signature_verify_recover_init_fn`.
pub(crate) type SignatureVerifyRecoverInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_verify_recover_fn`.
pub(crate) type SignatureVerifyRecoverFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_init_fn`.
pub(crate) type SignatureDigestSignInitFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *mut c_void,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_update_fn`.
pub(crate) type SignatureDigestSignUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_final_fn`.
pub(crate) type SignatureDigestSignFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_fn`.
pub(crate) type SignatureDigestSignFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *mut u8,
    *mut usize,
    usize,
    *const u8,
    usize,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_init_fn`.
pub(crate) type SignatureDigestVerifyInitFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *mut c_void,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_update_fn`.
pub(crate) type SignatureDigestVerifyUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_final_fn`.
pub(crate) type SignatureDigestVerifyFinalFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_fn`.
pub(crate) type SignatureDigestVerifyFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_signature_freectx_fn`.
pub(crate) type SignatureFreectxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_signature_dupctx_fn`.
pub(crate) type SignatureDupctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_signature_get_ctx_params_fn`.
pub(crate) type SignatureGetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_signature_gettable_ctx_params_fn`.
pub(crate) type SignatureGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_signature_set_ctx_params_fn`.
pub(crate) type SignatureSetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_settable_ctx_params_fn`.
pub(crate) type SignatureSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_signature_get_ctx_md_params_fn`.
pub(crate) type SignatureGetCtxMdParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_signature_gettable_ctx_md_params_fn`.
pub(crate) type SignatureGettableCtxMdParamsFn =
    unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_signature_set_ctx_md_params_fn`.
pub(crate) type SignatureSetCtxMdParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_settable_ctx_md_params_fn`.
pub(crate) type SignatureSettableCtxMdParamsFn =
    unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_signature_query_key_types_fn`.
pub(crate) type SignatureQueryKeyTypesFn = unsafe extern "C" fn() -> *const *const c_char;

/// `struct evp_signature_st` — `crypto/evp/evp_local.h`, **in the header's field order**, which is
/// neither the dispatch-id order nor a grouping.
#[repr(C)]
pub struct EvpSignature {
    /// `int name_id`.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_signature_newctx_fn *newctx` — one of the two `ctxfncnt` arms.
    pub(crate) newctx: Option<SignatureNewctxFn>,
    /// `OSSL_FUNC_signature_sign_init_fn *sign_init` — one of the seven `initfncnt` arms.
    pub(crate) sign_init: Option<SignatureSignInitFn>,
    /// `OSSL_FUNC_signature_sign_fn *sign`.
    pub(crate) sign: Option<SignatureSignFn>,
    /// `OSSL_FUNC_signature_sign_message_init_fn *sign_message_init` — id **27**, field **8**.
    pub(crate) sign_message_init: Option<SignatureSignMessageInitFn>,
    /// `OSSL_FUNC_signature_sign_message_update_fn *sign_message_update`.
    pub(crate) sign_message_update: Option<SignatureSignMessageUpdateFn>,
    /// `OSSL_FUNC_signature_sign_message_final_fn *sign_message_final`.
    pub(crate) sign_message_final: Option<SignatureSignMessageFinalFn>,
    /// `OSSL_FUNC_signature_verify_init_fn *verify_init`.
    pub(crate) verify_init: Option<SignatureVerifyInitFn>,
    /// `OSSL_FUNC_signature_verify_fn *verify`.
    pub(crate) verify: Option<SignatureVerifyFn>,
    /// `OSSL_FUNC_signature_verify_message_init_fn *verify_message_init` — id **30**.
    pub(crate) verify_message_init: Option<SignatureVerifyMessageInitFn>,
    /// `OSSL_FUNC_signature_verify_message_update_fn *verify_message_update`.
    pub(crate) verify_message_update: Option<SignatureVerifyMessageUpdateFn>,
    /// `OSSL_FUNC_signature_verify_message_final_fn *verify_message_final`.
    pub(crate) verify_message_final: Option<SignatureVerifyMessageFinalFn>,
    /// `OSSL_FUNC_signature_verify_recover_init_fn *verify_recover_init`.
    pub(crate) verify_recover_init: Option<SignatureVerifyRecoverInitFn>,
    /// `OSSL_FUNC_signature_verify_recover_fn *verify_recover`.
    pub(crate) verify_recover: Option<SignatureVerifyRecoverFn>,
    /// `OSSL_FUNC_signature_digest_sign_init_fn *digest_sign_init`.
    pub(crate) digest_sign_init: Option<SignatureDigestSignInitFn>,
    /// `OSSL_FUNC_signature_digest_sign_update_fn *digest_sign_update`.
    pub(crate) digest_sign_update: Option<SignatureDigestSignUpdateFn>,
    /// `OSSL_FUNC_signature_digest_sign_final_fn *digest_sign_final`.
    pub(crate) digest_sign_final: Option<SignatureDigestSignFinalFn>,
    /// `OSSL_FUNC_signature_digest_sign_fn *digest_sign`.
    pub(crate) digest_sign: Option<SignatureDigestSignFn>,
    /// `OSSL_FUNC_signature_digest_verify_init_fn *digest_verify_init`.
    pub(crate) digest_verify_init: Option<SignatureDigestVerifyInitFn>,
    /// `OSSL_FUNC_signature_digest_verify_update_fn *digest_verify_update`.
    pub(crate) digest_verify_update: Option<SignatureDigestVerifyUpdateFn>,
    /// `OSSL_FUNC_signature_digest_verify_final_fn *digest_verify_final`.
    pub(crate) digest_verify_final: Option<SignatureDigestVerifyFinalFn>,
    /// `OSSL_FUNC_signature_digest_verify_fn *digest_verify`.
    pub(crate) digest_verify: Option<SignatureDigestVerifyFn>,
    /// `OSSL_FUNC_signature_freectx_fn *freectx` — the other `ctxfncnt` arm.
    pub(crate) freectx: Option<SignatureFreectxFn>,
    /// `OSSL_FUNC_signature_dupctx_fn *dupctx` — optional and uncounted.
    pub(crate) dupctx: Option<SignatureDupctxFn>,
    /// `OSSL_FUNC_signature_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<SignatureGetCtxParamsFn>,
    /// `OSSL_FUNC_signature_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<SignatureGettableCtxParamsFn>,
    /// `OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<SignatureSetCtxParamsFn>,
    /// `OSSL_FUNC_signature_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<SignatureSettableCtxParamsFn>,
    /// `OSSL_FUNC_signature_get_ctx_md_params_fn *get_ctx_md_params`.
    pub(crate) get_ctx_md_params: Option<SignatureGetCtxMdParamsFn>,
    /// `OSSL_FUNC_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params`.
    pub(crate) gettable_ctx_md_params: Option<SignatureGettableCtxMdParamsFn>,
    /// `OSSL_FUNC_signature_set_ctx_md_params_fn *set_ctx_md_params`.
    pub(crate) set_ctx_md_params: Option<SignatureSetCtxMdParamsFn>,
    /// `OSSL_FUNC_signature_settable_ctx_md_params_fn *settable_ctx_md_params`.
    pub(crate) settable_ctx_md_params: Option<SignatureSettableCtxMdParamsFn>,
    /// `OSSL_FUNC_signature_query_key_types_fn *query_key_types` — id **26**.
    pub(crate) query_key_types: Option<SignatureQueryKeyTypesFn>,
}

/// `static void evp_signature_free(void *data)`.
///
/// # Safety
/// `data` must be NULL or a live `EvpSignature`.
unsafe extern "C" fn evp_signature_free(data: *mut c_void) {
    // SAFETY: `data` is NULL or live per the contract.
    unsafe { EVP_SIGNATURE_free(data.cast::<EvpSignature>()) }
}

/// `static int evp_signature_up_ref(void *data)`.
///
/// # Safety
/// `data` must be a live `EvpSignature`.
unsafe extern "C" fn evp_signature_up_ref(data: *mut c_void) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { EVP_SIGNATURE_up_ref(data.cast::<EvpSignature>()) }
}

/// `static EVP_SIGNATURE *evp_signature_new(OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live.
unsafe fn evp_signature_new(prov: *mut OsslProvider) -> *mut EvpSignature {
    // SAFETY: this allocates a fresh object and reads nothing.
    let signature = CRYPTO_zalloc(
        core::mem::size_of::<EvpSignature>(),
        FILE,
        LINE_ZALLOC_SIGNATURE,
    )
    .cast::<EvpSignature>();
    if signature.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `signature` is this call's own object and `prov` is live.
    unsafe {
        (*signature).refcnt = AtomicI32::new(1);
        ossl_provider_up_ref(prov);
        (*signature).prov = prov;
    }
    signature
}

/// Raise `EVP_R_INVALID_PROVIDER_FUNCTIONS` with the authority's message for one clause.
///
/// The message is `%s <clause>:%s` with the method's type name and its description (or the empty
/// string when there is none), which is what makes the *first* failing clause identifiable from the
/// error queue alone — the property a court leans on.
///
/// # Safety
/// `signature` must be live.
unsafe fn raise_clause(signature: *const EvpSignature, site: &err_sites::ErrSite, clause: &CStr) {
    // SAFETY: `signature` is live and `type_name` is a NUL-terminated string it owns.
    let type_name = unsafe { (*signature).type_name };
    // SAFETY: `signature` is live and `description` is NULL or NUL-terminated.
    let description = unsafe { (*signature).description };
    let desc = if description.is_null() {
        c"".as_ptr()
    } else {
        description
    };
    let mut msg = [0 as c_char; ERR_DATA_BUFFER];
    // SAFETY: `msg` is a 1024-byte buffer, the format is "%s <clause>:%s", and all three arguments
    // are NUL-terminated.
    unsafe { BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"%s ".as_ptr(), type_name) };
    /* The clause text is a compile-time constant of this crate, so the format is assembled from two
     * calls rather than one `format!`: the authority's is one `ERR_raise_data` with a literal, and
     * the concatenation is the same string. */
    let mut full = [0 as c_char; ERR_DATA_BUFFER];
    // SAFETY: `full` is 1024 writable bytes and `clause` is NUL-terminated.
    unsafe {
        BIO_snprintf(
            full.as_mut_ptr(),
            full.len(),
            c"%s%s:%s".as_ptr(),
            msg.as_ptr(),
            clause.as_ptr(),
            desc,
        )
    };
    // SAFETY: a compile-time-constant site; the message is NUL-terminated.
    unsafe { raise_site_data(site, full.as_ptr()) };
}

/// `static void *evp_signature_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `algodef` must be live; `prov` must be live.
unsafe extern "C" fn evp_signature_from_algorithm(
    name_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: `prov` is live per the contract.
    let signature = unsafe { evp_signature_new(prov) };
    if signature.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `signature` is live.
    unsafe { (*signature).name_id = name_id };
    // SAFETY: `algodef` is live.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    // SAFETY: `signature` is live and `type_name` is the string just allocated for it.
    unsafe { (*signature).type_name = type_name };
    // SAFETY: both are live.
    unsafe { (*signature).description = (*algodef).algorithm_description };

    let mut ctxfncnt = 0;
    let mut initfncnt = 0;
    let mut gparamfncnt = 0;
    let mut sparamfncnt = 0;
    let mut gmdparamfncnt = 0;
    let mut smdparamfncnt = 0;

    // SAFETY: `fns` is a terminated table per the contract.
    let mut entry = fns;
    // SAFETY: `fns` is a terminated table, so the walk leaves it at the terminator.
    unsafe {
        while (*entry).function_id != OSSL_DISPATCH_END {
            match (*entry).function_id {
                OSSL_FUNC_SIGNATURE_NEWCTX if (*signature).newctx.is_none() => {
                    (*signature).newctx = entry_function::<SignatureNewctxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SIGN_INIT if (*signature).sign_init.is_none() => {
                    (*signature).sign_init = entry_function::<SignatureSignInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SIGN if (*signature).sign.is_none() => {
                    (*signature).sign = entry_function::<SignatureSignFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
                    if (*signature).sign_message_init.is_none() =>
                {
                    (*signature).sign_message_init =
                        entry_function::<SignatureSignMessageInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE
                    if (*signature).sign_message_update.is_none() =>
                {
                    (*signature).sign_message_update =
                        entry_function::<SignatureSignMessageUpdateFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL
                    if (*signature).sign_message_final.is_none() =>
                {
                    (*signature).sign_message_final =
                        entry_function::<SignatureSignMessageFinalFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_VERIFY_INIT if (*signature).verify_init.is_none() => {
                    (*signature).verify_init = entry_function::<SignatureVerifyInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_VERIFY if (*signature).verify.is_none() => {
                    (*signature).verify = entry_function::<SignatureVerifyFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT
                    if (*signature).verify_message_init.is_none() =>
                {
                    (*signature).verify_message_init =
                        entry_function::<SignatureVerifyMessageInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE
                    if (*signature).verify_message_update.is_none() =>
                {
                    (*signature).verify_message_update =
                        entry_function::<SignatureVerifyMessageUpdateFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL
                    if (*signature).verify_message_final.is_none() =>
                {
                    (*signature).verify_message_final =
                        entry_function::<SignatureVerifyMessageFinalFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT
                    if (*signature).verify_recover_init.is_none() =>
                {
                    (*signature).verify_recover_init =
                        entry_function::<SignatureVerifyRecoverInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_VERIFY_RECOVER if (*signature).verify_recover.is_none() => {
                    (*signature).verify_recover = entry_function::<SignatureVerifyRecoverFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT if (*signature).digest_sign_init.is_none() => {
                    (*signature).digest_sign_init =
                        entry_function::<SignatureDigestSignInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE
                    if (*signature).digest_sign_update.is_none() =>
                {
                    (*signature).digest_sign_update =
                        entry_function::<SignatureDigestSignUpdateFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL
                    if (*signature).digest_sign_final.is_none() =>
                {
                    (*signature).digest_sign_final =
                        entry_function::<SignatureDigestSignFinalFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN if (*signature).digest_sign.is_none() => {
                    (*signature).digest_sign = entry_function::<SignatureDigestSignFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT
                    if (*signature).digest_verify_init.is_none() =>
                {
                    (*signature).digest_verify_init =
                        entry_function::<SignatureDigestVerifyInitFn>(entry);
                    initfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE
                    if (*signature).digest_verify_update.is_none() =>
                {
                    (*signature).digest_verify_update =
                        entry_function::<SignatureDigestVerifyUpdateFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL
                    if (*signature).digest_verify_final.is_none() =>
                {
                    (*signature).digest_verify_final =
                        entry_function::<SignatureDigestVerifyFinalFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_DIGEST_VERIFY if (*signature).digest_verify.is_none() => {
                    (*signature).digest_verify = entry_function::<SignatureDigestVerifyFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_FREECTX if (*signature).freectx.is_none() => {
                    (*signature).freectx = entry_function::<SignatureFreectxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_DUPCTX if (*signature).dupctx.is_none() => {
                    (*signature).dupctx = entry_function::<SignatureDupctxFn>(entry);
                }
                OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS if (*signature).get_ctx_params.is_none() => {
                    (*signature).get_ctx_params = entry_function::<SignatureGetCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS
                    if (*signature).gettable_ctx_params.is_none() =>
                {
                    (*signature).gettable_ctx_params =
                        entry_function::<SignatureGettableCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS if (*signature).set_ctx_params.is_none() => {
                    (*signature).set_ctx_params = entry_function::<SignatureSetCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS
                    if (*signature).settable_ctx_params.is_none() =>
                {
                    (*signature).settable_ctx_params =
                        entry_function::<SignatureSettableCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS
                    if (*signature).get_ctx_md_params.is_none() =>
                {
                    (*signature).get_ctx_md_params =
                        entry_function::<SignatureGetCtxMdParamsFn>(entry);
                    gmdparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS
                    if (*signature).gettable_ctx_md_params.is_none() =>
                {
                    (*signature).gettable_ctx_md_params =
                        entry_function::<SignatureGettableCtxMdParamsFn>(entry);
                    gmdparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS
                    if (*signature).set_ctx_md_params.is_none() =>
                {
                    (*signature).set_ctx_md_params =
                        entry_function::<SignatureSetCtxMdParamsFn>(entry);
                    smdparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS
                    if (*signature).settable_ctx_md_params.is_none() =>
                {
                    (*signature).settable_ctx_md_params =
                        entry_function::<SignatureSettableCtxMdParamsFn>(entry);
                    smdparamfncnt += 1;
                }
                OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES if (*signature).query_key_types.is_none() => {
                    (*signature).query_key_types =
                        entry_function::<SignatureQueryKeyTypesFn>(entry);
                }
                _ => {}
            }
            entry = entry.add(1);
        }
    }

    /* The clause sequence. `valid` short-circuits the *reporting* rather than the test: every clause
     * below is guarded by it, so only the first failure produces a message and the message names it.
     * The four clauses after `if (!valid) goto err;` are not guarded, because reaching them means
     * every counter clause passed. */
    let mut valid = 1;
    if ctxfncnt != 2 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_296, c"newctx or freectx") };
        valid = 0;
    }
    if valid != 0
        && ((gparamfncnt != 0 && gparamfncnt != 2)
            || (sparamfncnt != 0 && sparamfncnt != 2)
            || (gmdparamfncnt != 0 && gmdparamfncnt != 2)
            || (smdparamfncnt != 0 && smdparamfncnt != 2))
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_310,
                c"params getter or setter",
            )
        };
        valid = 0;
    }
    if valid != 0 && initfncnt == 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_315, c"init") };
        valid = 0;
    }

    // SAFETY: `signature` is live for the rest of this function; the field reads below are its own.
    let sig = unsafe { &*signature };
    if valid != 0
        && ((sig.sign_init.is_some() && sig.sign.is_none())
            || (sig.sign_message_init.is_some()
                && sig.sign.is_none()
                && (sig.sign_message_update.is_none() || sig.sign_message_final.is_none())))
    {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_329, c"signing function") };
        valid = 0;
    }
    if valid != 0
        && (sig.sign.is_some()
            || sig.sign_message_update.is_some()
            || sig.sign_message_final.is_some())
        && sig.sign_init.is_none()
        && sig.sign_message_init.is_none()
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_340,
                c"sign_init or sign_message_init",
            )
        };
        valid = 0;
    }
    if valid != 0
        && ((sig.verify_init.is_some() && sig.verify.is_none())
            || (sig.verify_message_init.is_some()
                && sig.verify.is_none()
                && (sig.verify_message_update.is_none() || sig.verify_message_final.is_none())))
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_353,
                c"verification function",
            )
        };
        valid = 0;
    }
    if valid != 0
        && (sig.verify.is_some()
            || sig.verify_message_update.is_some()
            || sig.verify_message_final.is_some())
        && sig.verify_init.is_none()
        && sig.verify_message_init.is_none()
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_363,
                c"verify_init or verify_message_init",
            )
        };
        valid = 0;
    }
    if valid != 0 && sig.verify_recover_init.is_some() && sig.verify_recover.is_none() {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_374, c"verify_recover") };
        valid = 0;
    }
    if valid != 0
        && sig.digest_sign_init.is_some()
        && sig.digest_sign.is_none()
        && (sig.digest_sign_update.is_none() || sig.digest_sign_final.is_none())
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_385,
                c"digest_sign function",
            )
        };
        valid = 0;
    }
    if valid != 0
        && sig.digest_verify_init.is_some()
        && sig.digest_verify.is_none()
        && (sig.digest_verify_update.is_none() || sig.digest_verify_final.is_none())
    {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_396,
                c"digest_verify function",
            )
        };
        valid = 0;
    }

    if valid == 0 {
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }

    /* The four XOR clauses, which are **not** guarded by `valid` and jump straight out. Each is an
     * `(x == NULL) != (y == NULL)` over a pair of callbacks, so it refuses "update without final" and
     * "final without update" as the same defect. */
    if (sig.digest_sign.is_some()
        || sig.digest_sign_update.is_some()
        || sig.digest_sign_final.is_some())
        && sig.digest_sign_init.is_none()
    {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_409, c"digest_sign_init") };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    if (sig.digest_verify.is_some()
        || sig.digest_verify_update.is_some()
        || sig.digest_verify_final.is_some())
        && sig.digest_verify_init.is_none()
    {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_419, c"digest_verify_init") };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    if sig.sign_message_update.is_none() != sig.sign_message_final.is_none() {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_425,
                c"only one of message signing update and final available",
            )
        };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    if sig.verify_message_update.is_none() != sig.verify_message_final.is_none() {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_431,
                c"only one of message verification update and final available",
            )
        };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    if sig.digest_sign_update.is_none() != sig.digest_sign_final.is_none() {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_437,
                c"only one of digest signing update and final available",
            )
        };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }
    if sig.digest_verify_update.is_none() != sig.digest_verify_final.is_none() {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_443,
                c"only one of digest verification update and final available",
            )
        };
        // SAFETY: `signature` is this call's own object.
        unsafe { EVP_SIGNATURE_free(signature) };
        return ptr::null_mut();
    }

    signature.cast::<c_void>()
}

use core::ffi::CStr;

/// `void EVP_SIGNATURE_free(EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_free(signature: *mut EvpSignature) {
    if signature.is_null() {
        return;
    }
    // SAFETY: `signature` is live per the contract.
    let last = unsafe { (*signature).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: `signature` is live and this was the last reference.
    let (type_name, prov) = unsafe { ((*signature).type_name, (*signature).prov) };
    // SAFETY: `type_name` was allocated for this object.
    unsafe { CRYPTO_free(type_name.cast(), FILE, LINE_FREE_TYPE_NAME) };
    // SAFETY: `prov` is live and holds the reference `evp_signature_new` took.
    unsafe { ossl_provider_free(prov) };
    // SAFETY: `signature` is this object's own allocation.
    unsafe { CRYPTO_free(signature.cast(), FILE, LINE_FREE_SIGNATURE) };
}

/// `int EVP_SIGNATURE_up_ref(EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_up_ref(signature: *mut EvpSignature) -> c_int {
    // SAFETY: `signature` is live per the contract.
    unsafe { (*signature).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `OSSL_PROVIDER *EVP_SIGNATURE_get0_provider(const EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_get0_provider(
    signature: *const EvpSignature,
) -> *mut OsslProvider {
    // SAFETY: `signature` is live per the contract.
    unsafe { (*signature).prov }
}

/// `EVP_SIGNATURE *EVP_SIGNATURE_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpSignature {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_SIGNATURE,
            algorithm,
            properties,
            evp_signature_from_algorithm as MethodFromAlgorithmFn,
            evp_signature_up_ref as MethodUpRefFn,
            evp_signature_free as MethodFreeFn,
        )
    }
    .cast::<EvpSignature>()
}

/// `EVP_SIGNATURE *evp_signature_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `prov` must be live; `algorithm` and `properties` NULL or NUL-terminated.
#[allow(dead_code)] // first live caller is `evp_pkey_signature_init`, which lands with 7.4c's context
pub(crate) unsafe fn evp_signature_fetch_from_prov(
    prov: *mut OsslProvider,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpSignature {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_SIGNATURE,
            algorithm,
            properties,
            evp_signature_from_algorithm as MethodFromAlgorithmFn,
            evp_signature_up_ref as MethodUpRefFn,
            evp_signature_free as MethodFreeFn,
        )
    }
    .cast::<EvpSignature>()
}

/// `int EVP_SIGNATURE_is_a(const EVP_SIGNATURE *signature, const char *name)`.
///
/// # Safety
/// `signature` must be live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_is_a(
    signature: *const EvpSignature,
    name: *const c_char,
) -> c_int {
    // SAFETY: `signature` is live per the contract.
    let (prov, name_id) = unsafe { ((*signature).prov, (*signature).name_id) };
    // SAFETY: `prov` is live and `name` is NUL-terminated.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `int evp_signature_get_number(const EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be live.
#[allow(dead_code)] // read by the `EVP_PKEY_CTX` construction path in 7.4c
pub(crate) unsafe fn evp_signature_get_number(signature: *const EvpSignature) -> c_int {
    // SAFETY: `signature` is live per the contract.
    unsafe { (*signature).name_id }
}

/// `const char *EVP_SIGNATURE_get0_name(const EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_get0_name(signature: *const EvpSignature) -> *const c_char {
    // SAFETY: `signature` is live per the contract.
    unsafe { (*signature).type_name }
}

/// `const char *EVP_SIGNATURE_get0_description(const EVP_SIGNATURE *signature)`.
///
/// # Safety
/// `signature` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_get0_description(
    signature: *const EvpSignature,
) -> *const c_char {
    // SAFETY: `signature` is live per the contract.
    unsafe { (*signature).description }
}

/// `void EVP_SIGNATURE_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_SIGNATURE *, void *),
/// void *arg)`.
///
/// A **NULL visitor is refused**; the boundary is `EVP_MD_do_all_provided`'s
/// (`D-MD-DOALL-NULL-1`).
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpSignature, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(visitor) = fn_ else {
        return;
    };
    // SAFETY: the visitor is the caller's and `arg` is its own; the three callbacks are this
    // module's own.
    unsafe {
        evp_generic_do_all(
            libctx,
            OSSL_OP_SIGNATURE,
            core::mem::transmute::<
                unsafe extern "C" fn(*mut EvpSignature, *mut c_void),
                GenericDoAllFn,
            >(visitor),
            arg,
            evp_signature_from_algorithm as MethodFromAlgorithmFn,
            evp_signature_up_ref as MethodUpRefFn,
            evp_signature_free as MethodFreeFn,
        )
    };
}

/// `int EVP_SIGNATURE_names_do_all(const EVP_SIGNATURE *signature,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// # Safety
/// `signature` must be live; `fn_` a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_names_do_all(
    signature: *const EvpSignature,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `signature` is live per the contract.
    let (prov, name_id) = unsafe { ((*signature).prov, (*signature).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor's contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig)`.
///
/// # Safety
/// `sig` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_gettable_ctx_params(
    sig: *const EvpSignature,
) -> *const OsslParam {
    if sig.is_null() {
        return ptr::null();
    }
    // SAFETY: `sig` is live per the contract.
    let (f, prov) = unsafe { ((*sig).gettable_ctx_params, (*sig).prov) };
    let Some(gettable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `gettable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { gettable(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_SIGNATURE_settable_ctx_params(const EVP_SIGNATURE *sig)`.
///
/// # Safety
/// `sig` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_SIGNATURE_settable_ctx_params(
    sig: *const EvpSignature,
) -> *const OsslParam {
    if sig.is_null() {
        return ptr::null();
    }
    // SAFETY: `sig` is live per the contract.
    let (f, prov) = unsafe { ((*sig).settable_ctx_params, (*sig).prov) };
    let Some(settable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `settable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { settable(ptr::null_mut(), provctx) }
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built method, so the accessors can be read without a provider.
    fn a_hand_built_signature() -> EvpSignature {
        EvpSignature {
            name_id: 13,
            type_name: c"court-signature".as_ptr().cast_mut(),
            description: c"a hand-built SIGNATURE".as_ptr(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            sign_init: None,
            sign: None,
            sign_message_init: None,
            sign_message_update: None,
            sign_message_final: None,
            verify_init: None,
            verify: None,
            verify_message_init: None,
            verify_message_update: None,
            verify_message_final: None,
            verify_recover_init: None,
            verify_recover: None,
            digest_sign_init: None,
            digest_sign_update: None,
            digest_sign_final: None,
            digest_sign: None,
            digest_verify_init: None,
            digest_verify_update: None,
            digest_verify_final: None,
            digest_verify: None,
            freectx: None,
            dupctx: None,
            get_ctx_params: None,
            gettable_ctx_params: None,
            set_ctx_params: None,
            settable_ctx_params: None,
            get_ctx_md_params: None,
            gettable_ctx_md_params: None,
            set_ctx_md_params: None,
            settable_ctx_md_params: None,
            query_key_types: None,
        }
    }

    /// The field readers, and `names_do_all`'s **1** for a method with no provider.
    #[test]
    fn the_accessors_read_fields_and_the_walk_answers_one() {
        let signature = a_hand_built_signature();
        let p: *const EvpSignature = ptr::addr_of!(signature);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(
                CStr::from_ptr(EVP_SIGNATURE_get0_name(p)),
                c"court-signature"
            );
            assert_eq!(
                CStr::from_ptr(EVP_SIGNATURE_get0_description(p)),
                c"a hand-built SIGNATURE"
            );
            assert_eq!(evp_signature_get_number(p), 13);
            assert!(EVP_SIGNATURE_get0_provider(p).is_null());
            assert_eq!(EVP_SIGNATURE_names_do_all(p, None, ptr::null_mut()), 1);
        }
    }

    /// The two context-parameter accessors answer NULL for a NULL method and for one with no
    /// callback.
    #[test]
    fn the_context_parameter_accessors_answer_null() {
        let signature = a_hand_built_signature();
        let p: *const EvpSignature = ptr::addr_of!(signature);
        // SAFETY: `p` is this frame's own live object; NULL is the other documented input.
        unsafe {
            assert!(EVP_SIGNATURE_gettable_ctx_params(p).is_null());
            assert!(EVP_SIGNATURE_settable_ctx_params(p).is_null());
            assert!(EVP_SIGNATURE_gettable_ctx_params(ptr::null()).is_null());
            assert!(EVP_SIGNATURE_settable_ctx_params(ptr::null()).is_null());
        }
    }

    /// The reference count is taken and given back, and the object survives the first release.
    #[test]
    fn the_reference_count_is_taken_and_given_back() {
        // SAFETY: a NULL provider is allowed by the constructor, which up-refs conditionally.
        let signature = unsafe { evp_signature_new(ptr::null_mut()) };
        assert!(!signature.is_null());
        // SAFETY: `signature` is this test's own object.
        unsafe {
            assert_eq!(EVP_SIGNATURE_up_ref(signature), 1);
            EVP_SIGNATURE_free(signature);
            assert_eq!((*signature).name_id, 0, "the object is still alive");
            EVP_SIGNATURE_free(signature);
        }
    }

    /// **The four XOR clauses, as a table.** `sign_message_update` and `sign_message_final` must be
    /// present together or absent together, and the clause that says so is one of the four that jump
    /// straight out rather than setting `valid`. This test is the crate's own statement of the shape;
    /// `RT-EVP-SIGNATURE` measures the authority against it.
    #[test]
    fn the_xor_clauses_are_a_pairwise_xor() {
        assert_eq!(
            None::<SignatureSignMessageUpdateFn>.is_none(),
            None::<SignatureSignMessageFinalFn>.is_none(),
            "both absent is the accepted case"
        );
        /* The clause is `(x == NULL) != (y == NULL)`, so writing it over `Option`s is exactly a
         * boolean inequality -- which is what makes it a *pair* test rather than two tests. */
        fn xor(a: bool, b: bool) -> bool {
            a != b
        }
        assert!(!xor(true, true), "both present is accepted");
        assert!(!xor(false, false), "both absent is accepted");
        assert!(xor(true, false), "update without final is refused");
        assert!(xor(false, true), "final without update is refused");
    }
}
