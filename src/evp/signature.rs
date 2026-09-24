//! Phase 7.4 — the `EVP_SIGNATURE` method object, and the eighteen entry points over it.
//!
//! `crypto/evp/signature.c`, both halves. The **method half** is the object, its lifetime and the
//! eleven exports that reach it. The **operation half** is `evp_pkey_signature_init` and the
//! eighteen `EVP_PKEY_sign*`, `verify*` and `verify_recover*` entry points, and it is written here
//! rather than beside the method object because every one of the eighteen begins by reading
//! `ctx->operation` and `ctx->op.sig.algctx` — the `EVP_PKEY_CTX` object that landed with 7.4c. The
//! file's nineteenth `EVP_PKEY_*` name, `EVP_PKEY_CTX_set_signature`, is `pmeth_lib.c`'s and
//! belongs to that unit rather than to this one.
//!
//! ## The operation half's own shape
//!
//! Three things about the entry points are worth stating before reading them, because each is a
//! place a plausible transcription goes wrong:
//!
//!   * **`evp_pkey_signature_init` has three exits and only one of them is `err:`.** `legacy:`
//!     returns `-2` **without** resetting `ctx->operation`, so a context whose init fell through to
//!     the legacy half is left *armed* with no algorithm context; and `end:` frees the keymgmt and
//!     replays the cached data only when the result is positive. That asymmetry is what makes the
//!     `algctx == NULL` arm of `EVP_PKEY_sign`, `EVP_PKEY_verify` and `EVP_PKEY_verify_recover`
//!     reachable at all from this crate, and `RT-EVP-PKEY` measures it rather than asserting it.
//!   * **the `query_key_types` walk exists only in the pre-fetched branch.** A method handed to
//!     `EVP_PKEY_sign_init_ex2` and its siblings is checked against the key by the *caller's own
//!     method*; a method the init fetched itself is checked by the two name fallbacks instead. A
//!     court that only used the fetching spellings would never call `query_key_types`.
//!   * **the one-shot and the stream entry points differ in exactly one test.** `EVP_PKEY_sign` and
//!     `EVP_PKEY_verify` accept either an armed one-shot operation or its message spelling, while
//!     the four stream entry points accept one operation each — and none of the four tests the
//!     algorithm context before it dereferences the method.
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
use crate::evp::keymgmt::{
    evp_keymgmt_fetch_from_prov, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name,
    EVP_KEYMGMT_get0_provider, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::evp_keymgmt_util_query_operation_name;
use crate::evp::pkey::evp_pkey_export_to_provider;
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_free_old_ops, evp_pkey_ctx_use_cached_data, EVP_PKEY_CTX_is_a, EvpPkeyCtx,
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_UNDEFINED, EVP_PKEY_OP_VERIFY,
    EVP_PKEY_OP_VERIFYMSG, EVP_PKEY_OP_VERIFYRECOVER,
};
use crate::params::OsslParam;
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::raise_site_data;
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
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
pub(crate) const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
/// `OSSL_FUNC_SIGNATURE_SIGN_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 2;
/// `OSSL_FUNC_SIGNATURE_SIGN`.
pub(crate) const OSSL_FUNC_SIGNATURE_SIGN: c_int = 3;
/// `OSSL_FUNC_SIGNATURE_VERIFY_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_INIT: c_int = 4;
/// `OSSL_FUNC_SIGNATURE_VERIFY`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY: c_int = 5;
/// `OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT: c_int = 6;
/// `OSSL_FUNC_SIGNATURE_VERIFY_RECOVER`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_RECOVER: c_int = 7;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT: c_int = 8;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE: c_int = 9;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL: c_int = 10;
/// `OSSL_FUNC_SIGNATURE_DIGEST_SIGN`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_SIGN: c_int = 11;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT: c_int = 12;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE: c_int = 13;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL: c_int = 14;
/// `OSSL_FUNC_SIGNATURE_DIGEST_VERIFY`.
pub(crate) const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY: c_int = 15;
/// `OSSL_FUNC_SIGNATURE_FREECTX`.
pub(crate) const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 16;
/// `OSSL_FUNC_SIGNATURE_DUPCTX`.
pub(crate) const OSSL_FUNC_SIGNATURE_DUPCTX: c_int = 17;
/// `OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS: c_int = 18;
/// `OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS: c_int = 19;
/// `OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS: c_int = 20;
/// `OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS: c_int = 21;
/// `OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS: c_int = 22;
/// `OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS: c_int = 23;
/// `OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS: c_int = 24;
/// `OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS`.
pub(crate) const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS: c_int = 25;
/// `OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES` — **26**, before the two message triplets.
pub(crate) const OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES: c_int = 26;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT` — **27**, out of positional order.
pub(crate) const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT: c_int = 27;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE`.
pub(crate) const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE: c_int = 28;
/// `OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL`.
pub(crate) const OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL: c_int = 29;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT: c_int = 30;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE: c_int = 31;
/// `OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL`.
pub(crate) const OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL: c_int = 32;

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
pub(crate) type SignatureDigestSignInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_update_fn`.
pub(crate) type SignatureDigestSignUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_final_fn`.
pub(crate) type SignatureDigestSignFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_sign_fn`.
pub(crate) type SignatureDigestSignFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_init_fn`.
pub(crate) type SignatureDigestVerifyInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_update_fn`.
pub(crate) type SignatureDigestVerifyUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_final_fn`.
pub(crate) type SignatureDigestVerifyFinalFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
/// `OSSL_FUNC_signature_digest_verify_fn`.
pub(crate) type SignatureDigestVerifyFn =
    unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int;
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
pub(crate) type SignatureQueryKeyTypesFn = unsafe extern "C" fn() -> *mut *const c_char;

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

// ---------------------------------------------------------------------------------------------
// The operation half — `evp_pkey_signature_init` and the eighteen exports over it.
//
// These read `ctx->operation` and `ctx->op.sig.algctx`, which is why they land after the
// `EVP_PKEY_CTX` object rather than with the method object above.
// ---------------------------------------------------------------------------------------------

/// The authority's `err:` label — `crypto/evp/signature.c:896`.
///
/// **Not guarded by `ret`**, unlike the asymmetric cipher's: every arrival tears the operation down
/// and answers with the caller's running result, so a failed init leaves the context `UNDEFINED`
/// and re-initialisable rather than half-bound.
///
/// The authority's own `signature->freectx(ctx->op.sig.algctx)` — the one it writes after a
/// callback answered non-positive — is not duplicated here, and it does not need to be:
/// `evp_pkey_ctx_free_old_ops` releases the algorithm context through the method's own `freectx`
/// before it releases the method, so the provider sees exactly one `freectx` for one successful
/// `newctx` either way. The authority's call is unguarded and this crate's release is guarded by
/// both pointers being non-NULL, which differs only for a state no `newctx` can produce.
///
/// # Safety
/// `ctx` must be live; `tmp_keymgmt` NULL or live.
unsafe fn signature_init_err(
    ctx: *mut EvpPkeyCtx,
    tmp_keymgmt: *mut EvpKeyMgmt,
    ret: c_int,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    ret
}

/// The authority's `end:` label — `crypto/evp/signature.c:888`.
///
/// The cached-data replay is guarded by `ret > 0` rather than by "did we arrive happily". Two
/// arrivals have a non-positive `ret`: the pre-fetched branch when the key could not be exported
/// (still 0, and *no error raised of its own*), and an incompatible key type (`-2`). Neither may
/// replay a distinguishing identifier into an operation that was never armed, and the guard is what
/// says so.
///
/// # Safety
/// `ctx` must be live; `tmp_keymgmt` NULL or live.
unsafe fn signature_init_end(
    ctx: *mut EvpPkeyCtx,
    tmp_keymgmt: *mut EvpKeyMgmt,
    ret: c_int,
) -> c_int {
    let mut ret = ret;
    if ret > 0 {
        // SAFETY: `ctx` is live.
        ret = unsafe { evp_pkey_ctx_use_cached_data(ctx) };
    }
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    ret
}

/// The authority's `legacy:` label — `crypto/evp/signature.c:848`.
///
/// **The label does not reset `ctx->operation`.** The non-guarded part of its body ends in
/// `return -2`, not in a `goto err`, so a context whose init fell through to the legacy half is
/// left with the operation still *armed* and no algorithm context. That is not an artefact of the
/// transcription and it is observable: a following `EVP_PKEY_sign` on such a context takes its own
/// `algctx == NULL` arm, which is how this crate reaches that arm at all — the crate cannot build a
/// context whose `keymgmt` is NULL, so `evp_pkey_ctx_is_legacy` never sends an init here directly.
///
/// The `if (ctx->pmeth == NULL || ...)` test is satisfied on every arrival: `ctx->pmeth` belongs to
/// `EVP_PKEY_METHOD`, which is Phase 8's, so the arm it guards — handing the operation to a legacy
/// method — is the branch this crate cannot represent. The `switch` after it is therefore
/// unreachable and is not written: every one of its arms reads `ctx->pmeth`, and the same statement
/// covers its `default:` arm.
///
/// # Safety
/// `tmp_keymgmt` NULL or live.
unsafe fn signature_init_legacy(tmp_keymgmt: *mut EvpKeyMgmt) -> c_int {
    ERR_pop_to_mark();
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::SIGNATURE_862) };
    -2
}

/// `static int evp_pkey_signature_init(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *signature, int operation,
/// const OSSL_PARAM params[])` — `crypto/evp/signature.c:568`.
///
/// The unit's heart, and it is **two different functions in one body**, chosen by whether the
/// caller handed it a method:
///
///   * **pre-fetched** (`signature != NULL`, the `_ex2` and message spellings). The key is exported
///     to the method's provider and then checked: `query_key_types`' NUL-terminated array is walked
///     and the first spelling the context's key answers to is the match. When the method publishes
///     no such callback the check falls back twice — the key's *type name* against the method's
///     names, then the key's *preferred operation name* against the same — and **both fallbacks
///     answer -2 from `end:`, not from `err:`**, so the context keeps the operation the caller
///     asked for and no algorithm context. A key that cannot be exported at all is not a refusal:
///     it arrives at `end:` with `ret` still 0.
///   * **fetched** (`signature == NULL`, the plain spellings). The name comes from the *key*, and
///     the method is fetched twice: once through `EVP_SIGNATURE_fetch` under the context's
///     property query, and once through `evp_signature_fetch_from_prov` from the key's own
///     provider. The second is not a retry — it is how an algorithm a property query would reject
///     is still reachable when the key's provider publishes it. Each iteration re-derives the
///     keymgmt from the *method's* provider and re-exports the key into it, and three arrivals
///     leave for `legacy:`: a key whose provider cannot produce the algorithm at all, and two more
///     below.
///
/// The common tail arms the operation: it stores the method and its context, passes the caller's
/// **property query** on to `newctx` as its second argument, and dispatches on `operation` to one
/// of five init callbacks. A missing callback is `PROVIDER_SIGNATURE_NOT_SUPPORTED` with the
/// method's own type name and description in the message — which is what makes the failing clause
/// identifiable from a transcript — and an operation outside the five is
/// `INITIALIZATION_ERROR`.
///
/// # Safety
/// `ctx` NULL or live; `signature` NULL or live; `params` NULL or a terminated array.
unsafe fn evp_pkey_signature_init(
    ctx: *mut EvpPkeyCtx,
    signature: *mut EvpSignature,
    operation: c_int,
    params: *const OsslParam,
) -> c_int {
    let mut ret: c_int = 0;
    let mut provkey: *mut c_void = ptr::null_mut();
    let mut tmp_keymgmt: *mut EvpKeyMgmt = ptr::null_mut();
    let mut tmp_prov: *const OsslProvider = ptr::null();

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SIGNATURE_580) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = operation };

    let mut signature = signature;
    if !signature.is_null() {
        /* A caller-supplied method has to be checked against the key, and the check is done after
         * the export for a reason the authority states in its own comment: the comparison is not
         * designed to work with a key that has not been made provider-side. */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).pkey }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::SIGNATURE_596) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }

        /* `evp_pkey_export_to_provider` is documented as a no-op when the keymgmt it is handed is
         * already the key's own, which is why the two steps are written out rather than skipped. */
        // SAFETY: `signature` is live.
        tmp_prov = unsafe { EVP_SIGNATURE_get0_provider(signature) };
        // SAFETY: `ctx` is live, `tmp_prov` is live, and the context's keymgmt has a
        // NUL-terminated name.
        let tmp_keymgmt_tofree = unsafe {
            evp_keymgmt_fetch_from_prov(
                tmp_prov.cast_mut(),
                EVP_KEYMGMT_get0_name((*ctx).keymgmt),
                (*ctx).propquery,
            )
        };
        tmp_keymgmt = tmp_keymgmt_tofree;
        if !tmp_keymgmt.is_null() {
            // SAFETY: `ctx` is live, and `tmp_keymgmt`'s address is valid for the call — which may
            // replace it, and is the whole reason it is passed by address rather than by value.
            provkey = unsafe {
                evp_pkey_export_to_provider(
                    (*ctx).pkey,
                    (*ctx).libctx,
                    ptr::addr_of_mut!(tmp_keymgmt),
                    (*ctx).propquery,
                )
            };
        }
        if tmp_keymgmt.is_null() {
            // SAFETY: `tmp_keymgmt_tofree` is NULL or live and the caller just dropped it.
            unsafe { EVP_KEYMGMT_free(tmp_keymgmt_tofree) };
        }

        if provkey.is_null() {
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_end(ctx, tmp_keymgmt, ret) };
        }

        // SAFETY: `signature` is live.
        if let Some(query_key_types) = unsafe { (*signature).query_key_types } {
            /* The callback answers a **NUL-terminated array** and the walk stops at the first
             * spelling the context's key answers to. The array's own terminator is what reports "no
             * match", so an empty array is a refusal rather than a vacuous success — the distinction
             * the court measures with two arms. */
            // SAFETY: the callback is the provider's own and takes no arguments.
            let keytypes = unsafe { query_key_types() };
            // SAFETY: `keytypes` is a NUL-terminated array of NUL-terminated names per the
            // callback's contract, and `ctx` is live.
            let mut cursor = keytypes;
            // SAFETY: `keytypes` is a NUL-terminated array of NUL-terminated names, `ctx` is live, and `cursor` walks inside it.
            unsafe {
                while !(*cursor).is_null() {
                    if EVP_PKEY_CTX_is_a(ctx, *cursor) != 0 {
                        break;
                    }
                    cursor = cursor.add(1);
                }
            }
            // SAFETY: `cursor` points inside that array, so it names a readable entry.
            if unsafe { *cursor }.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::SIGNATURE_637) };
                ret = -2;
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_end(ctx, tmp_keymgmt, ret) };
            }
        } else {
            /* Fallback 1: the key's type name and the method's name are the same spelling. */
            // SAFETY: `ctx` is live.
            let keytype = unsafe { EVP_KEYMGMT_get0_name((*ctx).keymgmt) };
            // SAFETY: `signature` is live and `keytype` is NUL-terminated.
            let mut ok = unsafe { EVP_SIGNATURE_is_a(signature, keytype) };

            /* Fallback 2: the **key** names the signature algorithm it wants, and the two are
             * compared by identity rather than by spelling.
             * `evp_keymgmt_util_query_operation_name` answers the method's own name when the
             * provider publishes no `query_operation_name`, so this arm is reached with a name
             * rather than with NULL — which is what keeps the `EVP_SIGNATURE_is_a` below honest. */
            if ok == 0 {
                // SAFETY: `ctx` is live and its keymgmt is a live method.
                let signame = unsafe {
                    evp_keymgmt_util_query_operation_name((*ctx).keymgmt, OSSL_OP_SIGNATURE)
                };
                // SAFETY: `signature` is live and `signame` is NULL or NUL-terminated.
                ok = unsafe { EVP_SIGNATURE_is_a(signature, signame) };
            }

            if ok == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::SIGNATURE_664) };
                ret = -2;
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_end(ctx, tmp_keymgmt, ret) };
            }
        }

        /* The context takes a reference on the caller's method, so the caller may release its own
         * copy while the operation is armed. */
        // SAFETY: `signature` is live.
        if unsafe { EVP_SIGNATURE_up_ref(signature) } == 0 {
            // SAFETY: `signature` is live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }
    } else {
        /* Without a method, one has to be derived from the key. The mark covers exactly the
         * *probing* part of that derivation: a fetch that fails while looking for a signature the
         * key does not support leaves nothing behind once the legacy half is entered, and the
         * success path pops the mark so the caller sees only the operation's own errors. */
        ERR_set_mark();

        // SAFETY: `ctx` is live.
        if unsafe { &*ctx }.is_legacy() {
            /* Reached from *inside* the mark, which is why the label pops it. */
            // SAFETY: `tmp_keymgmt` is a literal NULL here.
            return unsafe { signature_init_legacy(ptr::null_mut()) };
        }

        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).pkey }.is_null() {
            ERR_clear_last_mark();
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::SIGNATURE_681) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }

        /* `ossl_assert` under `NDEBUG` is `(x) != 0`, so this is a live refusal and not a
         * debug-only abort (`docs/DECISIONS.md` D167). */
        // SAFETY: `ctx` is live and its `pkey` is non-NULL.
        let pkey_keymgmt = unsafe { (*(*ctx).pkey).keymgmt };
        // SAFETY: `ctx` is live.
        if !(pkey_keymgmt.is_null() || pkey_keymgmt == unsafe { (*ctx).keymgmt }) {
            ERR_clear_last_mark();
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::SIGNATURE_691) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }

        // SAFETY: `ctx` is live.
        let ctx_keymgmt = unsafe { (*ctx).keymgmt };
        /* The name of the signature the **key** wants, and a NULL answer here is an error rather
         * than a fallback: the two fallbacks above are about the *method*, and this one is about
         * the key. */
        // SAFETY: `ctx_keymgmt` is live.
        let supported_sig =
            unsafe { evp_keymgmt_util_query_operation_name(ctx_keymgmt, OSSL_OP_SIGNATURE) };
        if supported_sig.is_null() {
            ERR_clear_last_mark();
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::SIGNATURE_699) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }

        /* Two iterations of one fetch. Each iteration drops the previous iteration's method and
         * keymgmt first, because the pair is re-derived as a unit and iteration 1's keymgmt came
         * from a provider that may not be the key's. */
        let mut iter: c_int = 1;
        while iter < 3 && provkey.is_null() {
            /* The authority nulls `signature` beside the release. That store is not written here
             * because both arms of the switch below assign it before anything can read it, so it
             * has no observable effect — the `EVP_SIGNATURE_free` is the whole of the pair. */
            // SAFETY: `signature` is NULL or live.
            unsafe { EVP_SIGNATURE_free(signature) };
            // SAFETY: `tmp_keymgmt` is NULL or live.
            unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
            tmp_keymgmt = ptr::null_mut();

            if iter == 1 {
                // SAFETY: `ctx` is live.
                let (libctx, propquery) = unsafe { ((*ctx).libctx, (*ctx).propquery) };
                // SAFETY: `libctx` is live and `supported_sig` is NUL-terminated.
                signature = unsafe { EVP_SIGNATURE_fetch(libctx, supported_sig, propquery) };
                if !signature.is_null() {
                    // SAFETY: `signature` is live.
                    tmp_prov = unsafe { EVP_SIGNATURE_get0_provider(signature) };
                }
            } else {
                // SAFETY: `ctx_keymgmt` is live.
                tmp_prov = unsafe { EVP_KEYMGMT_get0_provider(ctx_keymgmt) };
                // SAFETY: `ctx` is live.
                let propquery = unsafe { (*ctx).propquery };
                // SAFETY: `tmp_prov` is live and `supported_sig` is NUL-terminated.
                signature = unsafe {
                    evp_signature_fetch_from_prov(tmp_prov.cast_mut(), supported_sig, propquery)
                };
                if signature.is_null() {
                    /* The second iteration is the last chance: the key's own provider cannot
                     * produce the algorithm, so no provider can. `tmp_keymgmt` is NULL here — the
                     * iteration cleared it at the top. */
                    // SAFETY: `tmp_keymgmt` is a literal NULL at this point of the iteration.
                    return unsafe { signature_init_legacy(ptr::null_mut()) };
                }
            }
            if signature.is_null() {
                iter += 1;
                continue;
            }

            // SAFETY: `ctx_keymgmt` is live and its name is NUL-terminated; `ctx` is live.
            let (name, propquery) =
                unsafe { (EVP_KEYMGMT_get0_name(ctx_keymgmt), (*ctx).propquery) };
            // SAFETY: `tmp_prov` is live and `name` is NUL-terminated.
            let tmp_keymgmt_tofree =
                unsafe { evp_keymgmt_fetch_from_prov(tmp_prov.cast_mut(), name, propquery) };
            tmp_keymgmt = tmp_keymgmt_tofree;
            if !tmp_keymgmt.is_null() {
                // SAFETY: `ctx` is live and `tmp_keymgmt`'s address is valid for the call.
                provkey = unsafe {
                    evp_pkey_export_to_provider(
                        (*ctx).pkey,
                        (*ctx).libctx,
                        ptr::addr_of_mut!(tmp_keymgmt),
                        propquery,
                    )
                };
            }
            if tmp_keymgmt.is_null() {
                // SAFETY: `tmp_keymgmt_tofree` is NULL or live and the caller just dropped it.
                unsafe { EVP_KEYMGMT_free(tmp_keymgmt_tofree) };
            }
            iter += 1;
        }

        if provkey.is_null() {
            // SAFETY: `signature` is NULL or live.
            unsafe { EVP_SIGNATURE_free(signature) };
            /* The post-loop entry to `legacy:` is the one that has a live keymgmt to release: the
             * loop's own two entries cleared it before they left. */
            // SAFETY: `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_legacy(tmp_keymgmt) };
        }

        ERR_pop_to_mark();
    }

    /* No more legacy from here down to the `legacy:` label. */

    // SAFETY: `ctx` is live and `signature` is live.
    unsafe { (*ctx).op_sig_signature = signature };
    /* `newctx` is mandatory: `evp_signature_from_algorithm` refuses a provider that publishes no
     * `OSSL_FUNC_SIGNATURE_NEWCTX`, so a fetched method always has one and the `else` below is
     * unreachable. It is written out rather than `unwrap`ped because the crate denies `unwrap_used`
     * and because the answer it gives is the authority's own INITIALIZATION_ERROR. */
    // SAFETY: `signature` is live.
    let Some(newctx) = (unsafe { (*signature).newctx }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SIGNATURE_786) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
    };
    /* The context's property query is passed **on to the method**, and this is the only place it
     * reaches the algorithm context: the method sees the same string the fetch used, or NULL when
     * the caller supplied none. */
    // SAFETY: `newctx` is the provider's own callback and `(*signature).prov` is live.
    let algctx = unsafe { newctx(ossl_provider_ctx((*signature).prov), (*ctx).propquery) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).op_sig_algctx = algctx };
    if algctx.is_null() {
        /* The provider key can stay in the cache. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SIGNATURE_786) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
    }

    match operation {
        EVP_PKEY_OP_SIGN => {
            // SAFETY: `signature` is live.
            let Some(sign_init) = (unsafe { (*signature).sign_init }) else {
                // SAFETY: `signature` is live.
                unsafe { raise_clause(signature, &err_sites::SIGNATURE_793, c"sign_init") };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: `algctx` is non-NULL, `provkey` is non-NULL and `params` is NULL or a
            // terminated array — the provider's own callback contract.
            ret = unsafe { sign_init(algctx, provkey, params) };
        }
        EVP_PKEY_OP_SIGNMSG => {
            // SAFETY: `signature` is live.
            let Some(sign_message_init) = (unsafe { (*signature).sign_message_init }) else {
                // SAFETY: `signature` is live.
                unsafe { raise_clause(signature, &err_sites::SIGNATURE_802, c"sign_message_init") };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: as above.
            ret = unsafe { sign_message_init(algctx, provkey, params) };
        }
        EVP_PKEY_OP_VERIFY => {
            // SAFETY: `signature` is live.
            let Some(verify_init) = (unsafe { (*signature).verify_init }) else {
                // SAFETY: `signature` is live.
                unsafe { raise_clause(signature, &err_sites::SIGNATURE_811, c"verify_init") };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: as above.
            ret = unsafe { verify_init(algctx, provkey, params) };
        }
        EVP_PKEY_OP_VERIFYMSG => {
            // SAFETY: `signature` is live.
            let Some(verify_message_init) = (unsafe { (*signature).verify_message_init }) else {
                // SAFETY: `signature` is live.
                unsafe {
                    raise_clause(signature, &err_sites::SIGNATURE_820, c"verify_message_init")
                };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: as above.
            ret = unsafe { verify_message_init(algctx, provkey, params) };
        }
        EVP_PKEY_OP_VERIFYRECOVER => {
            // SAFETY: `signature` is live.
            let Some(verify_recover_init) = (unsafe { (*signature).verify_recover_init }) else {
                // SAFETY: `signature` is live.
                unsafe {
                    raise_clause(signature, &err_sites::SIGNATURE_829, c"verify_recover_init")
                };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { signature_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: as above.
            ret = unsafe { verify_recover_init(algctx, provkey, params) };
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::SIGNATURE_837) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
        }
    }

    if ret <= 0 {
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { signature_init_err(ctx, tmp_keymgmt, ret) };
    }
    // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
    unsafe { signature_init_end(ctx, tmp_keymgmt, ret) }
}

/// `int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_SIGN, ptr::null()) }
}

/// `int EVP_PKEY_sign_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_SIGN, params) }
}

/// `int EVP_PKEY_sign_init_ex2(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo,
/// const OSSL_PARAM params[])` — the only `sign` spelling that reaches the pre-fetched branch.
///
/// # Safety
/// `ctx` must be live; `algo` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_init_ex2(
    ctx: *mut EvpPkeyCtx,
    algo: *mut EvpSignature,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, algo, EVP_PKEY_OP_SIGN, params) }
}

/// `int EVP_PKEY_sign_message_init(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `algo` NULL or live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_message_init(
    ctx: *mut EvpPkeyCtx,
    algo: *mut EvpSignature,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, algo, EVP_PKEY_OP_SIGNMSG, params) }
}

/// `int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_VERIFY, ptr::null()) }
}

/// `int EVP_PKEY_verify_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_VERIFY, params) }
}

/// `int EVP_PKEY_verify_init_ex2(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `algo` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_init_ex2(
    ctx: *mut EvpPkeyCtx,
    algo: *mut EvpSignature,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, algo, EVP_PKEY_OP_VERIFY, params) }
}

/// `int EVP_PKEY_verify_message_init(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `algo` NULL or live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_message_init(
    ctx: *mut EvpPkeyCtx,
    algo: *mut EvpSignature,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, algo, EVP_PKEY_OP_VERIFYMSG, params) }
}

/// `int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_VERIFYRECOVER, ptr::null()) }
}

/// `int EVP_PKEY_verify_recover_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, ptr::null_mut(), EVP_PKEY_OP_VERIFYRECOVER, params) }
}

/// `int EVP_PKEY_verify_recover_init_ex2(EVP_PKEY_CTX *ctx, EVP_SIGNATURE *algo,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `algo` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover_init_ex2(
    ctx: *mut EvpPkeyCtx,
    algo: *mut EvpSignature,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_signature_init(ctx, algo, EVP_PKEY_OP_VERIFYRECOVER, params) }
}

/// The prologue the seven non-init entry points share.
///
/// `Ok` carries the method the operation is armed with; `Err` carries the code the entry point must
/// return, with the reason already raised. The order is the authority's and it is observable: a
/// context in the *wrong* operation answers `OPERATION_NOT_INITIALIZED` even when its algorithm
/// context is NULL, because the operation test comes first — and the court uses a context in
/// exactly that state.
///
/// `mask` is the set of operations the entry point accepts, and the authority spells the two shapes
/// it has as `a != X && a != Y` and as `a != X`. The bit test below is the same test for every
/// value the exports can leave in `ctx->operation` — each of the five inits stores one constant and
/// nothing else writes the field — and it is written once rather than five times.
///
/// `check_algctx` is `Some(site)` for the three one-shot entry points, whose arm for a NULL
/// algorithm context is the authority's `goto legacy`: `ctx->pmeth` is Phase 8's and always NULL
/// here, so that arm answers `OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` and `-2`. It is `None` for
/// the four stream entry points, which read `ctx->op.sig.signature` **without any test at all** —
/// a stream call on a context whose init refused dereferences a NULL method in the authority, which
/// is why nothing here walks into that state; the module's boundary note says so rather than
/// pretending the arm is guarded.
///
/// # Safety
/// `ctx` NULL or live.
unsafe fn signature_op_prelude(
    ctx: *mut EvpPkeyCtx,
    mask: c_int,
    null_site: &err_sites::ErrSite,
    not_init_site: &err_sites::ErrSite,
    legacy_site: Option<&err_sites::ErrSite>,
) -> Result<*mut EvpSignature, c_int> {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(null_site) };
        return Err(-1);
    }

    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).operation } & mask) == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(not_init_site) };
        return Err(-1);
    }

    if let Some(site) = legacy_site {
        // SAFETY: `ctx` is live and the operation is armed.
        if unsafe { (*ctx).op_sig_algctx }.is_null() {
            /* The authority's `goto legacy`. Its `ctx->pmeth == NULL` clause is satisfied on every
             * arrival, so the answer this arm gives is fixed. */
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(site) };
            return Err(-2);
        }
    }

    // SAFETY: `ctx` is live and the operation is armed, so the method it names is live.
    Ok(unsafe { (*ctx).op_sig_signature })
}

/// `int EVP_PKEY_sign_message_update(EVP_PKEY_CTX *ctx, const unsigned char *in, size_t inlen)`.
///
/// The **equality** operation test is this function's own and not the one-shot's: a stream update
/// belongs to `EVP_PKEY_OP_SIGNMSG` alone, so a context armed for a one-shot sign answers
/// `OPERATION_NOT_INITIALIZED` here.
///
/// # Safety
/// `ctx` NULL or live; `in` NULL or `inlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_message_update(
    ctx: *mut EvpPkeyCtx,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_SIGNMSG,
            &err_sites::SIGNATURE_933,
            &err_sites::SIGNATURE_938,
            None,
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live — that is the prelude's postcondition.
    let Some(update) = (unsafe { (*signature).sign_message_update }) else {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_945, c"sign_message_update") };
        return -2;
    };
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`; `input`
    // is NULL or `inlen` readable bytes.
    let ret = unsafe { update((*ctx).op_sig_algctx, input, inlen) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_952, c"sign_message_update") };
    }
    ret
}

/// `int EVP_PKEY_sign_message_final(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen)`.
///
/// The length the provider is handed is the same "or zero" the one-shot entries use: a NULL output
/// buffer means the provider sees **0**, not that the call is skipped.
///
/// # Safety
/// `ctx` NULL or live; `sig` NULL or `*siglen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_message_final(
    ctx: *mut EvpPkeyCtx,
    sig: *mut u8,
    siglen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_SIGNMSG,
            &err_sites::SIGNATURE_965,
            &err_sites::SIGNATURE_970,
            None,
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(finalise) = (unsafe { (*signature).sign_message_final }) else {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_977, c"sign_message_final") };
        return -2;
    };
    let mut siglen_in: usize = 0;
    if !sig.is_null() {
        // SAFETY: `sig` is non-NULL, so `siglen` is the caller's valid buffer length.
        siglen_in = unsafe { *siglen };
    }
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`.
    let ret = unsafe { finalise((*ctx).op_sig_algctx, sig, siglen, siglen_in) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_985, c"sign_message_final") };
    }
    ret
}

/// `int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
/// const unsigned char *tbs, size_t tbslen)`.
///
/// The one-shot entry accepts **either** a one-shot operation or the message spelling, which is
/// what lets a provider that publishes only the message triple be driven through this call — and
/// what makes this function's `signature->sign == NULL` arm reachable at all: such a provider's
/// method has no `sign`, and the structural check admits it.
///
/// The legacy arm is entered from the prelude when the algorithm context is NULL, which a context
/// left armed by a `legacy:` refusal has. That state is reachable and the court drives it.
///
/// # Safety
/// `ctx` NULL or live; `sig` NULL or `*siglen` writable bytes; `tbs` NULL or `tbslen` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign(
    ctx: *mut EvpPkeyCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_SIGN | EVP_PKEY_OP_SIGNMSG,
            &err_sites::SIGNATURE_999,
            &err_sites::SIGNATURE_1005,
            Some(&err_sites::SIGNATURE_1029),
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(sign) = (unsafe { (*signature).sign }) else {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1015, c"sign") };
        return -2;
    };
    let mut siglen_in: usize = 0;
    if !sig.is_null() {
        // SAFETY: `sig` is non-NULL, so `siglen` is the caller's valid buffer length.
        siglen_in = unsafe { *siglen };
    }
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`.
    let ret = unsafe { sign((*ctx).op_sig_algctx, sig, siglen, siglen_in, tbs, tbslen) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1023, c"sign") };
    }
    ret
}

/// `int EVP_PKEY_verify_message_update(EVP_PKEY_CTX *ctx, const unsigned char *in, size_t inlen)`.
///
/// # Safety
/// `ctx` NULL or live; `in` NULL or `inlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_message_update(
    ctx: *mut EvpPkeyCtx,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_VERIFYMSG,
            &err_sites::SIGNATURE_1087,
            &err_sites::SIGNATURE_1092,
            None,
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(update) = (unsafe { (*signature).verify_message_update }) else {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_1099,
                c"verify_message_update",
            )
        };
        return -2;
    };
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`; `input`
    // is NULL or `inlen` readable bytes.
    let ret = unsafe { update((*ctx).op_sig_algctx, input, inlen) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_1106,
                c"verify_message_update",
            )
        };
    }
    ret
}

/// `int EVP_PKEY_verify_message_final(EVP_PKEY_CTX *ctx)`.
///
/// The signature was set with `EVP_PKEY_CTX_set_signature`, which is `pmeth_lib.c`'s and not this
/// unit's; nothing on this path reads it back.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_message_final(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_VERIFYMSG,
            &err_sites::SIGNATURE_1118,
            &err_sites::SIGNATURE_1123,
            None,
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(finalise) = (unsafe { (*signature).verify_message_final }) else {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_1130,
                c"verify_message_final",
            )
        };
        return -2;
    };
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`.
    let ret = unsafe { finalise((*ctx).op_sig_algctx) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe {
            raise_clause(
                signature,
                &err_sites::SIGNATURE_1138,
                c"verify_message_final",
            )
        };
    }
    ret
}

/// `int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
/// const unsigned char *tbs, size_t tbslen)`.
///
/// Note the authority's own inconsistency, and it is transcribed rather than tidied: this body
/// calls `ctx->op.sig.signature->verify(...)` where its sibling `EVP_PKEY_sign` reads the local it
/// had already stored. The two are the same pointer, so nothing is observable; the line is the
/// authority's.
///
/// # Safety
/// `ctx` NULL or live; `sig` NULL or `siglen` readable bytes; `tbs` NULL or `tbslen` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify(
    ctx: *mut EvpPkeyCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG,
            &err_sites::SIGNATURE_1152,
            &err_sites::SIGNATURE_1158,
            Some(&err_sites::SIGNATURE_1182),
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(verify) = (unsafe { (*signature).verify }) else {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1168, c"verify") };
        return -2;
    };
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`; `sig`
    // is NULL or `siglen` readable bytes and `tbs` is NULL or `tbslen` readable bytes.
    let ret = unsafe { verify((*ctx).op_sig_algctx, sig, siglen, tbs, tbslen) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1176, c"verify") };
    }
    ret
}

/// `int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen,
/// const unsigned char *sig, size_t siglen)`.
///
/// The fourth argument is `(rout == NULL ? 0 : *routlen)` — the same "or zero" convention, and its
/// comparison is written the other way round from every sibling's for no reason the authority
/// gives. It is transcribed as written.
///
/// The `verify_recover == NULL` arm is **unreachable through this unit's exports** and that is a
/// fact about the structural check rather than about the call: an armed `EVP_PKEY_OP_VERIFYRECOVER`
/// operation requires `verify_recover_init` to be present, and `evp_signature_from_algorithm`
/// refuses a method that publishes an init without its operation callback. So the arm exists in the
/// authority and cannot be driven; the crate answers the same `-2` for it, because the code path is
/// written identically.
///
/// # Safety
/// `ctx` NULL or live; `rout` NULL or `*routlen` writable bytes; `sig` NULL or `siglen` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover(
    ctx: *mut EvpPkeyCtx,
    rout: *mut u8,
    routlen: *mut usize,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    // SAFETY: `ctx` NULL or live per the contract; the sites are compile-time constants.
    let signature = match unsafe {
        signature_op_prelude(
            ctx,
            EVP_PKEY_OP_VERIFYRECOVER,
            &err_sites::SIGNATURE_1215,
            &err_sites::SIGNATURE_1220,
            Some(&err_sites::SIGNATURE_1243),
        )
    } {
        Ok(signature) => signature,
        Err(ret) => return ret,
    };

    // SAFETY: `signature` is live.
    let Some(recover) = (unsafe { (*signature).verify_recover }) else {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1230, c"verify_recover") };
        return -2;
    };
    let mut routlen_in: usize = 0;
    if !rout.is_null() {
        // SAFETY: `rout` is non-NULL, so `routlen` is the caller's valid buffer length.
        routlen_in = unsafe { *routlen };
    }
    // SAFETY: `ctx` is live and the operation is armed, so `algctx` belongs to `signature`.
    let ret = unsafe { recover((*ctx).op_sig_algctx, rout, routlen, routlen_in, sig, siglen) };
    if ret <= 0 {
        // SAFETY: `signature` is live.
        unsafe { raise_clause(signature, &err_sites::SIGNATURE_1238, c"verify_recover") };
    }
    ret
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
