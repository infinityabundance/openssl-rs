//! Phase 7.3b — the `EVP_CIPHER` object: `crypto/evp/evp_enc.c`'s method half, `evp_lib.c`'s
//! method-object accessors, and `crypto/evp/cmeth_lib.c` whole.
//!
//! This is 7.3a's shape applied to the second method class, and the reason the two are separate
//! subphases rather than one is that a cipher has a **context** and a digest has one too, but the
//! cipher's context is where the operation lives: `EVP_EncryptUpdate` is the API, and the method
//! object is only what it is reached through. So `EVP_CIPHER` lands here — the object, the fetch
//! that builds it, the accessors that read it, and the legacy constructors that build one by hand
//! — and `EVP_CIPHER_CTX` and the whole `EVP_Encrypt*`/`EVP_Decrypt*`/`EVP_Cipher*` family land in
//! 7.3c, which is why every `EVP_CIPHER_CTX_*` name in this file is a *parameter* and none is an
//! export.
//!
//! ## The structural check is a different shape from a digest's, and that is the point
//!
//! `evp_md_from_algorithm` counts six functions and accepts five or six or the standalone
//! one-shot. `evp_cipher_from_algorithm` counts three things at once and its test is a four-clause
//! conjunction:
//!
//! ```text
//! fnciphcnt = encrypt_init? + decrypt_init? + update? + final?
//! fnctxcnt  = newctx? + freectx?
//! fnpipecnt = pipeline_encrypt_init? + pipeline_decrypt_init? + pipeline_update? + pipeline_final?
//!
//! refuse when  (fnciphcnt != 0 && fnciphcnt != 3 && fnciphcnt != 4)
//!           or  (fnciphcnt == 0 && ccipher == NULL && fnpipecnt == 0)
//!           or  (fnpipecnt != 0 && (fnpipecnt < 3 || p_cupdate == NULL || p_cfinal == NULL))
//!           or  (fnctxcnt != 2)
//! ```
//!
//! Two consequences a transcription gets wrong by simplifying: **`fnctxcnt != 2` means `newctx`
//! and `freectx` are both required and neither alone suffices** — a digest has no such rule — and
//! **an implementation with only a one-shot `ccipher` is legal** while one with an `update` and no
//! `final` is not, because 1 and 2 are not in the accepted set. The `fnpipecnt < 3` clause is
//! checked in addition to two named fields, so it is redundant-looking but not redundant: it
//! refuses a provider that publishes four pipeline functions with a NULL among them.
//!
//! ## `EVP_CIPHER_get_type` is eight aliases and an OID test
//!
//! The eight `switch` arms map aliases of one cipher onto a canonical NID — the three `rc2`
//! variants onto `NID_rc2_cbc`, the six `cfb` bit-widths of AES onto their `cfb128` — and
//! everything else falls through to "does this NID have an OID at all", answering `NID_undef` when
//! it does not. That second half is why the function is not a plain table lookup: a NID the object
//! database knows but declares with no OID is not a cipher type a caller can use.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::context::dispatch::{entry_function, OsslDispatch};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{
    evp_generic_do_all, evp_generic_fetch, evp_is_a, evp_names_do_all, GenericDoAllFn,
    MethodFromAlgorithmFn,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_construct_uint, OSSL_PARAM_locate_const, OsslParam,
};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_ADD_ALL_CIPHERS};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_undef, OBJ_NAME_do_all, OBJ_NAME_do_all_sorted, OBJ_NAME_get, OBJ_get0_data, OBJ_nid2ln,
    OBJ_nid2obj, OBJ_nid2sn, ObjName,
};

/// `EVP_CTRL_RET_UNSUPPORTED`, from `crypto/evp/evp_local.h`.
///
/// The answer `evp_do_ciph_getparams` gives for an object that has **no provider** — the legacy
/// half's signal that the caller should take another path, and not a failure. The same value as
/// `digest.rs`'s copy of the constant, and private for the same reason: it is not an `EVP_CIPHER`
/// fact, it is the parameter macros' convention.
const EVP_CTRL_RET_UNSUPPORTED: c_int = -1;

/// `EVP_ORIG_DYNAMIC` — `include/crypto/evp.h`. A method this crate allocated and owns.
const EVP_ORIG_DYNAMIC: c_int = 0;

/// `EVP_ORIG_GLOBAL` — a method in read-only memory, which is what a `e_*.c` wrapper returns.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_ORIG_METH` — a method `EVP_CIPHER_meth_new` allocated for a caller.
///
/// `pub(crate)` because `evp_cipher_init_internal` (7.3c-i) is the second place that has to
/// branch on it, and the constant's value is an authority fact that should be written once.
pub(crate) const EVP_ORIG_METH: c_int = 2;

/// `OSSL_OP_CIPHER` — `include/openssl/core_dispatch.h`. The second operation the walk visits.
const OSSL_OP_CIPHER: c_int = 2;

/// `OBJ_NAME_TYPE_CIPHER_METH` — `include/openssl/objects.h`. **0x02**, and the sibling of the
/// type `digest.rs` uses. The legacy table's `EVP_CIPHER` entries, which is what `set_legacy_nid`
/// asks about.
pub(crate) const OBJ_NAME_TYPE_CIPHER_METH: c_int = 0x02;

// ---------------------------------------------------------------------------------------------
// `EVP_CIPH_*` — `include/openssl/evp.h`
// ---------------------------------------------------------------------------------------------

/// `EVP_CIPH_MODE` — the mask `EVP_CIPHER_get_mode` applies.
const EVP_CIPH_MODE: c_ulong = 0xF_0007;
/// `EVP_CIPH_CUSTOM_IV`.
const EVP_CIPH_CUSTOM_IV: c_ulong = 0x10;
/// `EVP_CIPH_RAND_KEY`.
const EVP_CIPH_RAND_KEY: c_ulong = 0x200;
/// `EVP_CIPH_FLAG_CTS`.
const EVP_CIPH_FLAG_CTS: c_ulong = 0x4000;
/// `EVP_CIPH_FLAG_CUSTOM_CIPHER`.
const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_ulong = 0x10_0000;
/// `EVP_CIPH_FLAG_AEAD_CIPHER`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x20_0000;
/// `EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK`.
const EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK: c_ulong = 0x40_0000;
/// `EVP_CIPH_FLAG_CUSTOM_ASN1`.
const EVP_CIPH_FLAG_CUSTOM_ASN1: c_ulong = 0x100_0000;
/// `EVP_CIPH_FLAG_ENC_THEN_MAC`.
const EVP_CIPH_FLAG_ENC_THEN_MAC: c_ulong = 0x1000_0000;

/// `OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS` — `core_names.h`, aliased to
/// `OSSL_ALG_PARAM_ALGORITHM_ID_PARAMS`. The one parameter whose *presence* in a provider's
/// gettable-ctx list sets a flag rather than being read.
const OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS: *const c_char = c"algorithm-id-params".as_ptr();

// ---------------------------------------------------------------------------------------------
// Sites this file raises at, all of them `crypto/evp/`'s
// ---------------------------------------------------------------------------------------------

/// The authority's translation unit, as the compiler spelled it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c".as_ptr();

/// `OPENSSL_zalloc(sizeof(EVP_CIPHER))` in `evp_cipher_new`.
const LINE_ZALLOC_CIPHER: c_int = 1849;
/// `OPENSSL_free(cipher->type_name)` in `evp_cipher_free_int`.
const LINE_FREE_TYPE_NAME: c_int = 2115;
/// `OPENSSL_free(cipher)` in `evp_cipher_free_int`.
const LINE_FREE_CIPHER: c_int = 2118;

// ---------------------------------------------------------------------------------------------
// The provider's `OSSL_FUNC_CIPHER_*` ids, from `include/openssl/core_dispatch.h`
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_CIPHER_NEWCTX`.
pub(crate) const OSSL_FUNC_CIPHER_NEWCTX: c_int = 1;
/// `OSSL_FUNC_CIPHER_ENCRYPT_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_ENCRYPT_INIT: c_int = 2;
/// `OSSL_FUNC_CIPHER_DECRYPT_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_DECRYPT_INIT: c_int = 3;
/// `OSSL_FUNC_CIPHER_UPDATE`.
pub(crate) const OSSL_FUNC_CIPHER_UPDATE: c_int = 4;
/// `OSSL_FUNC_CIPHER_FINAL`.
pub(crate) const OSSL_FUNC_CIPHER_FINAL: c_int = 5;
/// `OSSL_FUNC_CIPHER_CIPHER`.
pub(crate) const OSSL_FUNC_CIPHER_CIPHER: c_int = 6;
/// `OSSL_FUNC_CIPHER_FREECTX`.
pub(crate) const OSSL_FUNC_CIPHER_FREECTX: c_int = 7;
/// `OSSL_FUNC_CIPHER_DUPCTX`.
pub(crate) const OSSL_FUNC_CIPHER_DUPCTX: c_int = 8;
/// `OSSL_FUNC_CIPHER_GET_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_GET_PARAMS: c_int = 9;
/// `OSSL_FUNC_CIPHER_GET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_GET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_CIPHER_SET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_SET_CTX_PARAMS: c_int = 11;
/// `OSSL_FUNC_CIPHER_GETTABLE_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_GETTABLE_PARAMS: c_int = 12;
/// `OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS: c_int = 13;
/// `OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS: c_int = 14;
/// `OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT: c_int = 15;
/// `OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT: c_int = 16;
/// `OSSL_FUNC_CIPHER_PIPELINE_UPDATE`.
pub(crate) const OSSL_FUNC_CIPHER_PIPELINE_UPDATE: c_int = 17;
/// `OSSL_FUNC_CIPHER_PIPELINE_FINAL`.
pub(crate) const OSSL_FUNC_CIPHER_PIPELINE_FINAL: c_int = 18;
/// `OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT: c_int = 19;
/// `OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT`.
pub(crate) const OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT: c_int = 20;

// ---------------------------------------------------------------------------------------------
// The provider-side function types, from the headers' `OSSL_CORE_MAKE_FUNC` declarations
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_cipher_newctx_fn`.
pub(crate) type CipherNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_cipher_encrypt_init_fn` / `_decrypt_init_fn`.
pub(crate) type CipherInitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_cipher_update_fn`.
pub(crate) type CipherUpdateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_cipher_final_fn`.
pub(crate) type CipherFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_cipher_cipher_fn`.
pub(crate) type CipherCipherFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_cipher_freectx_fn`.
pub(crate) type CipherFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_cipher_dupctx_fn`.
pub(crate) type CipherDupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_cipher_get_params_fn` — no context, because the parameters are the *method's*.
pub(crate) type CipherGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `OSSL_FUNC_cipher_get_ctx_params_fn`.
pub(crate) type CipherGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_cipher_set_ctx_params_fn`.
pub(crate) type CipherSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_cipher_gettable_params_fn` — takes the provider context, which is why
/// `EVP_CIPHER_gettable_params` reaches for `ossl_provider_ctx`.
pub(crate) type CipherGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_cipher_gettable_ctx_params_fn`.
pub(crate) type CipherGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_cipher_settable_ctx_params_fn`.
pub(crate) type CipherSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_cipher_pipeline_encrypt_init_fn` / `_pipeline_decrypt_init_fn`. The two differ
/// only in name; the authority's dispatch walk sets two separate fields from them.
pub(crate) type CipherPipelineInitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    usize,
    *mut *const u8,
    usize,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_cipher_pipeline_update_fn`.
pub(crate) type CipherPipelineUpdateFn = unsafe extern "C" fn(
    *mut c_void,
    usize,
    *mut *mut u8,
    *mut usize,
    *const usize,
    *mut *const u8,
    *const usize,
) -> c_int;
/// `OSSL_FUNC_cipher_pipeline_final_fn`.
pub(crate) type CipherPipelineFinalFn =
    unsafe extern "C" fn(*mut c_void, usize, *mut *mut u8, *mut usize, *const usize) -> c_int;
/// `OSSL_FUNC_cipher_encrypt_skey_init_fn` / `_decrypt_skey_init_fn`.
pub(crate) type CipherSkeyInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const u8, usize, *const OsslParam) -> c_int;

// ---------------------------------------------------------------------------------------------
// The legacy half's function types — `EVP_CIPHER_CTX *` is `*mut c_void` here for the reason
// `digest.rs` gives for `EVP_MD_CTX *`: the context type is 7.3c's, nothing in this file
// dereferences one, and a function pointer is a pointer on both sides of the ABI.
// ---------------------------------------------------------------------------------------------

/// `int (*init)(EVP_CIPHER_CTX *, const unsigned char *, const unsigned char *, int)`.
pub(crate) type CipherLegacyInitFn =
    unsafe extern "C" fn(*mut c_void, *const u8, *const u8, c_int) -> c_int;
/// `int (*do_cipher)(EVP_CIPHER_CTX *, unsigned char *, const unsigned char *, size_t)`.
pub(crate) type CipherLegacyDoFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *const u8, usize) -> c_int;
/// `int (*cleanup)(EVP_CIPHER_CTX *)`.
pub(crate) type CipherLegacyCleanupFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)`.
pub(crate) type CipherLegacyAsn1Fn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `int (*ctrl)(EVP_CIPHER_CTX *, int, int, void *)`.
pub(crate) type CipherLegacyCtrlFn =
    unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;

/// `struct evp_cipher_st` — `EVP_CIPHER`, from `include/crypto/evp.h`.
///
/// The authority's field order, with the same boundary `EvpMd` has: everything above `name_id` is
/// the legacy method object and everything below is the provider-side one, and `origin` says which
/// is live. **`EVP_CIPH_FLAG_PIPELINE` is not a local field** — a provider that wants it says so in
/// the `mode` parameter `evp_cipher_cache_constants` asks for, because `flags` is assigned from
/// `mode` wholesale rather than OR-ed into.
///
/// Every function-pointer field is an `Option` because the authority tests each for NULL: the
/// dispatch walk fills a field only if it is still NULL, which is how the first entry for an id
/// wins, and `EVP_CIPHER_can_pipeline` reads three of them.
///
/// **`pub` for the reason every internal type in an exported signature is**: `EVP_CIPHER_fetch` and
/// its siblings are exported, Rust requires an exported parameter's type to be at least as visible,
/// and the authority keeps `evp_cipher_st` in `include/crypto/evp.h`, which is not installed.
/// Every field is `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpCipher {
    /// `int nid` — the legacy NID, or `NID_undef` for a provider method whose names match no
    /// legacy entry.
    pub(crate) nid: c_int,
    /// `int block_size` — filled by `evp_cipher_cache_constants` from the provider.
    pub(crate) block_size: c_int,
    /// `int key_len` — the *default* for a variable-length cipher.
    pub(crate) key_len: c_int,
    /// `int iv_len` — filled by `evp_cipher_cache_constants`.
    pub(crate) iv_len: c_int,
    /// `unsigned long flags` — `EVP_CIPH_*`. Assigned from the provider's `mode` parameter, then
    /// OR-ed with the flags that parameter cannot express.
    pub(crate) flags: c_ulong,
    /// `int origin` — `EVP_ORIG_DYNAMIC`, `EVP_ORIG_GLOBAL` or `EVP_ORIG_METH`.
    pub(crate) origin: c_int,
    /// `int (*init)(EVP_CIPHER_CTX *, const unsigned char *, const unsigned char *, int)`.
    pub(crate) init: Option<CipherLegacyInitFn>,
    /// `int (*do_cipher)(EVP_CIPHER_CTX *, unsigned char *, const unsigned char *, size_t)`.
    pub(crate) do_cipher: Option<CipherLegacyDoFn>,
    /// `int (*cleanup)(EVP_CIPHER_CTX *)`.
    pub(crate) cleanup: Option<CipherLegacyCleanupFn>,
    /// `int ctx_size` — how big `ctx->cipher_data` must be; the legacy half's business.
    pub(crate) ctx_size: c_int,
    /// `int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)`.
    pub(crate) set_asn1_parameters: Option<CipherLegacyAsn1Fn>,
    /// `int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *)`.
    pub(crate) get_asn1_parameters: Option<CipherLegacyAsn1Fn>,
    /// `int (*ctrl)(EVP_CIPHER_CTX *, int, int, void *)`.
    pub(crate) ctrl: Option<CipherLegacyCtrlFn>,
    /// `void *app_data` — the method's own pointer, never touched by this crate.
    pub(crate) app_data: *mut c_void,
    /// `int name_id` — the namemap identity the method was fetched under.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — the provider that published it, holding a reference. NULL for
    /// every legacy method, which is what every accessor tests.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_cipher_newctx_fn *newctx`.
    pub(crate) newctx: Option<CipherNewCtxFn>,
    /// `OSSL_FUNC_cipher_encrypt_init_fn *einit`.
    pub(crate) einit: Option<CipherInitFn>,
    /// `OSSL_FUNC_cipher_decrypt_init_fn *dinit`.
    pub(crate) dinit: Option<CipherInitFn>,
    /// `OSSL_FUNC_cipher_update_fn *cupdate`.
    pub(crate) cupdate: Option<CipherUpdateFn>,
    /// `OSSL_FUNC_cipher_final_fn *cfinal`.
    pub(crate) cfinal: Option<CipherFinalFn>,
    /// `OSSL_FUNC_cipher_cipher_fn *ccipher`.
    pub(crate) ccipher: Option<CipherCipherFn>,
    /// `OSSL_FUNC_cipher_pipeline_encrypt_init_fn *p_einit`.
    pub(crate) p_einit: Option<CipherPipelineInitFn>,
    /// `OSSL_FUNC_cipher_pipeline_decrypt_init_fn *p_dinit`.
    pub(crate) p_dinit: Option<CipherPipelineInitFn>,
    /// `OSSL_FUNC_cipher_pipeline_update_fn *p_cupdate`.
    pub(crate) p_cupdate: Option<CipherPipelineUpdateFn>,
    /// `OSSL_FUNC_cipher_pipeline_final_fn *p_cfinal`.
    pub(crate) p_cfinal: Option<CipherPipelineFinalFn>,
    /// `OSSL_FUNC_cipher_freectx_fn *freectx`.
    pub(crate) freectx: Option<CipherFreeCtxFn>,
    /// `OSSL_FUNC_cipher_dupctx_fn *dupctx`.
    pub(crate) dupctx: Option<CipherDupCtxFn>,
    /// `OSSL_FUNC_cipher_get_params_fn *get_params`.
    pub(crate) get_params: Option<CipherGetParamsFn>,
    /// `OSSL_FUNC_cipher_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<CipherGetCtxParamsFn>,
    /// `OSSL_FUNC_cipher_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<CipherSetCtxParamsFn>,
    /// `OSSL_FUNC_cipher_gettable_params_fn *gettable_params`.
    pub(crate) gettable_params: Option<CipherGettableParamsFn>,
    /// `OSSL_FUNC_cipher_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<CipherGettableCtxParamsFn>,
    /// `OSSL_FUNC_cipher_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<CipherSettableCtxParamsFn>,
    /// `OSSL_FUNC_cipher_encrypt_skey_init_fn *einit_skey`.
    pub(crate) einit_skey: Option<CipherSkeyInitFn>,
    /// `OSSL_FUNC_cipher_decrypt_skey_init_fn *dinit_skey`.
    pub(crate) dinit_skey: Option<CipherSkeyInitFn>,
}

// SAFETY: a `static` `EVP_CIPHER` is fully initialised at compile time and is never mutated —
// every accessor's mutating arm is guarded by `origin`, and `EVP_ORIG_GLOBAL` is not
// `EVP_ORIG_DYNAMIC`, so `EVP_CIPHER_up_ref` and `EVP_CIPHER_free` both refuse it. Sharing
// `&EvpCipher` across threads therefore introduces no data race.
//
// It is claimed for the wrapper rather than for `EvpCipher` itself, because the claim is only true
// of the read-only globals: a heap `EvpCipher` is mutable and is synchronised by its own reference
// count, which is an `AtomicI32` and not this trait.
struct StaticCipher(EvpCipher);

// SAFETY: see the note on `StaticCipher`: the inner value is a compile-time constant that nothing
// writes.
unsafe impl Sync for StaticCipher {}

/// `EVP_CIPHER *evp_cipher_new(void)`.
///
/// A zeroed block and a reference count of 1. **The zeroing is what makes a fetched method's legacy
/// half inert**: every function pointer in it starts NULL and `origin` starts `EVP_ORIG_DYNAMIC`,
/// so a fresh object is releasable before anything has been filled in.
pub(crate) fn evp_cipher_new() -> *mut EvpCipher {
    let cipher = CRYPTO_zalloc(core::mem::size_of::<EvpCipher>(), FILE, LINE_ZALLOC_CIPHER)
        .cast::<EvpCipher>();
    if !cipher.is_null() {
        // SAFETY: `cipher` is a fresh zeroed block this call owns.
        unsafe { (*cipher).refcnt = AtomicI32::new(1) };
    }
    cipher
}

/// `static void set_legacy_nid(const char *name, void *vlegacy_nid)`.
///
/// `digest.rs`'s visitor for the cipher table, and the three-way answer is the same: not a legacy
/// name, a legacy name whose NID agrees, or a legacy name whose NID **disagrees** — which sets the
/// clash marker `-1` that `evp_cipher_from_algorithm` turns into a refusal.
///
/// # Safety
/// `name` must be NUL-terminated and `vlegacy_nid` a writable `c_int`.
unsafe extern "C" fn set_legacy_nid(name: *const c_char, vlegacy_nid: *mut c_void) {
    let legacy_nid = vlegacy_nid.cast::<c_int>();
    // SAFETY: `name` is NUL-terminated per the contract.
    let legacy_method = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH) };
    // SAFETY: `legacy_nid` is writable per the contract.
    if unsafe { *legacy_nid } == -1 {
        return;
    }
    if legacy_method.is_null() {
        return;
    }
    // SAFETY: the table's data pointer is an `EVP_CIPHER` for this name type, which is what the
    // authority casts it to.
    let nid = unsafe { (*legacy_method.cast::<EvpCipher>()).nid };
    // SAFETY: `legacy_nid` is writable per the contract.
    unsafe {
        if *legacy_nid != NID_undef && *legacy_nid != nid {
            *legacy_nid = -1;
            return;
        }
        *legacy_nid = nid;
    }
}

/// `int evp_do_ciph_getparams(const EVP_CIPHER *cipher, OsslParam params[])`.
///
/// The `PARAM_CHECK` macro's three arms: NULL is 0, **no provider is `EVP_CTRL_RET_UNSUPPORTED`**
/// — the legacy signal, not a failure — and a missing callback raises and answers 0.
///
/// # Safety
/// `cipher` must be NULL or live; `params` a terminated array.
pub(crate) unsafe fn evp_do_ciph_getparams(
    cipher: *const EvpCipher,
    params: *mut OsslParam,
) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    let (prov, get_params) = unsafe { ((*cipher).prov, (*cipher).get_params) };
    if prov.is_null() {
        return EVP_CTRL_RET_UNSUPPORTED;
    }
    let Some(f) = get_params else {
        // The authority's `geterr()`: `ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_GET_PARAMETERS)`.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_UTILS_65) };
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `int evp_do_ciph_ctx_getparams(const EVP_CIPHER *cipher, void *algctx, OsslParam params[])`.
///
/// The second of the three `PARAM_FUNCTIONS(EVP_CIPHER, ...)` expansions, and it is transcribed
/// here rather than in 7.3c with its callers because a macro expansion is one authority fact: the
/// three names come from one `PARAM_FUNCTIONS` invocation in `crypto/evp/evp_utils.c` and keeping
/// them apart would split a single expansion across two subphases.
///
/// `#[allow(dead_code)]`'s reason: **the caller is 7.3c's.** `EVP_CIPHER_CTX_get_params`,
/// `EVP_CIPHER_CTX_get_key_length` and `EVP_CIPHER_CTX_get_tag_length` are the three callers in
/// the authority, and every one of them takes a context.
///
/// # Safety
/// `cipher` NULL or live; `algctx` the callback's own context; `params` a terminated array.
#[allow(dead_code)]
pub(crate) unsafe fn evp_do_ciph_ctx_getparams(
    cipher: *const EvpCipher,
    algctx: *mut c_void,
    params: *mut OsslParam,
) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    let (prov, get_ctx_params) = unsafe { ((*cipher).prov, (*cipher).get_ctx_params) };
    if prov.is_null() {
        return EVP_CTRL_RET_UNSUPPORTED;
    }
    let Some(f) = get_ctx_params else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_UTILS_65) };
        return 0;
    };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f(algctx, params) }
}

/// `int evp_do_ciph_ctx_setparams(const EVP_CIPHER *cipher, void *algctx,
/// const OsslParam params[])`.
///
/// The third of the family, and the one that raises a **different** reason when its callback is
/// missing: `seterr()`, not `geterr()`.
///
/// `#[allow(dead_code)]` for the same reason as its sibling: `EVP_CIPHER_CTX_set_params` and
/// `EVP_CIPHER_CTX_ctrl` are its callers, and both are 7.3c's.
///
/// # Safety
/// `cipher` NULL or live; `algctx` the callback's own context; `params` a terminated array.
#[allow(dead_code)]
pub(crate) unsafe fn evp_do_ciph_ctx_setparams(
    cipher: *const EvpCipher,
    algctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    let (prov, set_ctx_params) = unsafe { ((*cipher).prov, (*cipher).set_ctx_params) };
    if prov.is_null() {
        return EVP_CTRL_RET_UNSUPPORTED;
    }
    let Some(f) = set_ctx_params else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_UTILS_70) };
        return 0;
    };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f(algctx, params) }
}

/// `int evp_cipher_cache_constants(EVP_CIPHER *cipher)`.
///
/// Ten parameters asked in **one** call, and every flag the provider can express is a parameter
/// rather than a dispatch entry — which is why a cipher method can be complete with four
/// functions. The assignment `cipher->flags = mode` is *not* an OR: whatever the provider answers
/// is the starting value, and the eight ORs below it are the facts the `mode` parameter cannot
/// carry (a `custom-iv` the provider declared, a one-shot `ccipher`, and so on).
///
/// The last one is a lookup rather than a value: `alg_id_param` in the provider's
/// gettable-ctx list is what says "this cipher's parameters have their own ASN.1 form", and the
/// flag is set from the *presence* of the name.
///
/// # Safety
/// `cipher` must be a live `EvpCipher` whose `prov` is live.
unsafe fn evp_cipher_cache_constants(cipher: *mut EvpCipher) -> c_int {
    let mut blksz: usize = 0;
    let mut ivlen: usize = 0;
    let mut keylen: usize = 0;
    let mut mode: c_uint = 0;
    let mut aead: c_int = 0;
    let mut custom_iv: c_int = 0;
    let mut cts: c_int = 0;
    let mut multiblock: c_int = 0;
    let mut randkey: c_int = 0;
    let mut encrypt_then_mac: c_int = 0;
    // A stack array whose address the provider writes through, so its eleven slots live for the
    // duration of the call. `OsslParam` is `Copy` and has no `Default`, so the array is built from
    // the terminator and then overwritten -- which is what the authority's sequence of
    // `OSSL_PARAM_construct_*` calls produces.
    let mut params: [OsslParam; 11] = [OSSL_PARAM_construct_end(); 11];
    // SAFETY: each constructor writes one entry and `params` has room for all eleven; the string
    // arguments are literals.
    unsafe {
        params[0] = OSSL_PARAM_construct_size_t(c"blocksize".as_ptr(), &mut blksz);
        params[1] = OSSL_PARAM_construct_size_t(c"ivlen".as_ptr(), &mut ivlen);
        params[2] = OSSL_PARAM_construct_size_t(c"keylen".as_ptr(), &mut keylen);
        params[3] = OSSL_PARAM_construct_uint(c"mode".as_ptr(), &mut mode);
        params[4] = OSSL_PARAM_construct_int(c"aead".as_ptr(), &mut aead);
        params[5] = OSSL_PARAM_construct_int(c"custom-iv".as_ptr(), &mut custom_iv);
        params[6] = OSSL_PARAM_construct_int(c"cts".as_ptr(), &mut cts);
        params[7] = OSSL_PARAM_construct_int(c"tls-multi".as_ptr(), &mut multiblock);
        params[8] = OSSL_PARAM_construct_int(c"has-randkey".as_ptr(), &mut randkey);
        params[9] = OSSL_PARAM_construct_int(c"encrypt-then-mac".as_ptr(), &mut encrypt_then_mac);
        params[10] = OSSL_PARAM_construct_end();
    }
    // SAFETY: `cipher` is live and `params` is this frame's own array.
    let ok = unsafe { evp_do_ciph_getparams(cipher, params.as_mut_ptr()) } > 0;
    if ok {
        // SAFETY: `cipher` is live.
        unsafe {
            (*cipher).block_size = blksz as c_int;
            (*cipher).iv_len = ivlen as c_int;
            (*cipher).key_len = keylen as c_int;
            (*cipher).flags = mode as c_ulong;
            if aead != 0 {
                (*cipher).flags |= EVP_CIPH_FLAG_AEAD_CIPHER;
            }
            if custom_iv != 0 {
                (*cipher).flags |= EVP_CIPH_CUSTOM_IV;
            }
            if cts != 0 {
                (*cipher).flags |= EVP_CIPH_FLAG_CTS;
            }
            if multiblock != 0 {
                (*cipher).flags |= EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK;
            }
            if (*cipher).ccipher.is_some() {
                (*cipher).flags |= EVP_CIPH_FLAG_CUSTOM_CIPHER;
            }
            if randkey != 0 {
                (*cipher).flags |= EVP_CIPH_RAND_KEY;
            }
            if encrypt_then_mac != 0 {
                (*cipher).flags |= EVP_CIPH_FLAG_ENC_THEN_MAC;
            }
        }
        // The one flag read from a *list* rather than a value. `EVP_CIPHER_gettable_ctx_params`
        // answers NULL for a method with no such callback, and `OSSL_PARAM_locate_const(NULL, ...)`
        // is NULL -- so a method with neither gets no flag, which is the authority's behaviour.
        // SAFETY: `cipher` is live.
        let libres = unsafe { EVP_CIPHER_gettable_ctx_params(cipher) };
        // SAFETY: `libres` is NULL or a terminated array per that call's contract.
        if !unsafe { OSSL_PARAM_locate_const(libres, OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS) }
            .is_null()
        {
            // SAFETY: `cipher` is live.
            unsafe { (*cipher).flags |= EVP_CIPH_FLAG_CUSTOM_ASN1 };
        }
    }
    c_int::from(ok)
}

/// `static void *evp_cipher_from_algorithm(const int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// The dispatch walk, the structural check and the two parameters — `digest.rs`'s shape with a
/// different check, and the four clauses of that check are documented at the top of this file
/// because reading them off the code is exactly how a transcription gets them wrong.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live.
unsafe extern "C" fn evp_cipher_from_algorithm(
    name_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let mut fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let cipher = evp_cipher_new();
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1898) };
        return ptr::null_mut();
    }

    // The legacy NID, if any of the method's names is a legacy name. A clash is -1.
    // SAFETY: `cipher` is live.
    unsafe { (*cipher).nid = NID_undef };
    // SAFETY: `cipher` is live, so its `nid` field is writable, and the visitor contract is the
    // namemap's.
    let named = unsafe {
        evp_names_do_all(
            prov,
            name_id,
            Some(set_legacy_nid),
            ptr::addr_of_mut!((*cipher).nid).cast::<c_void>(),
        )
    };
    // SAFETY: `cipher` is live.
    if named == 0 || unsafe { (*cipher).nid } == -1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1906) };
        // SAFETY: `cipher` is this call's own object.
        unsafe { EVP_CIPHER_free(cipher) };
        return ptr::null_mut();
    }

    // SAFETY: `cipher` is live.
    unsafe {
        (*cipher).name_id = name_id;
        (*cipher).type_name = ossl_algorithm_get1_first_name(algodef);
    }
    // SAFETY: `cipher` is live.
    if unsafe { (*cipher).type_name }.is_null() {
        // SAFETY: `cipher` is this call's own object.
        unsafe { EVP_CIPHER_free(cipher) };
        return ptr::null_mut();
    }
    // SAFETY: `cipher` and `algodef` are live.
    unsafe {
        (*cipher).description = (*algodef).algorithm_description;
    }

    // The dispatch walk. Each arm fills its field only if it is still NULL, so the first entry for
    // an id wins and a later duplicate is ignored rather than refused.
    let mut fnciphcnt: c_int = 0;
    let mut encinit: c_int = 0;
    let mut decinit: c_int = 0;
    let mut fnpipecnt: c_int = 0;
    let mut fnctxcnt: c_int = 0;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator.
    unsafe {
        while (*fns).function_id != crate::context::dispatch::OSSL_DISPATCH_END {
            let id = (*fns).function_id;
            match id {
                OSSL_FUNC_CIPHER_NEWCTX if (*cipher).newctx.is_none() => {
                    (*cipher).newctx = entry_function::<CipherNewCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_CIPHER_ENCRYPT_INIT if (*cipher).einit.is_none() => {
                    (*cipher).einit = entry_function::<CipherInitFn>(fns);
                    encinit = 1;
                }
                OSSL_FUNC_CIPHER_DECRYPT_INIT if (*cipher).dinit.is_none() => {
                    (*cipher).dinit = entry_function::<CipherInitFn>(fns);
                    decinit = 1;
                }
                OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT if (*cipher).einit_skey.is_none() => {
                    (*cipher).einit_skey = entry_function::<CipherSkeyInitFn>(fns);
                    encinit = 1;
                }
                OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT if (*cipher).dinit_skey.is_none() => {
                    (*cipher).dinit_skey = entry_function::<CipherSkeyInitFn>(fns);
                    decinit = 1;
                }
                OSSL_FUNC_CIPHER_UPDATE if (*cipher).cupdate.is_none() => {
                    (*cipher).cupdate = entry_function::<CipherUpdateFn>(fns);
                    fnciphcnt += 1;
                }
                OSSL_FUNC_CIPHER_FINAL if (*cipher).cfinal.is_none() => {
                    (*cipher).cfinal = entry_function::<CipherFinalFn>(fns);
                    fnciphcnt += 1;
                }
                OSSL_FUNC_CIPHER_CIPHER if (*cipher).ccipher.is_none() => {
                    // Not counted: the one-shot form stands alone.
                    (*cipher).ccipher = entry_function::<CipherCipherFn>(fns);
                }
                OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT if (*cipher).p_einit.is_none() => {
                    (*cipher).p_einit = entry_function::<CipherPipelineInitFn>(fns);
                    fnpipecnt += 1;
                }
                OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT if (*cipher).p_dinit.is_none() => {
                    (*cipher).p_dinit = entry_function::<CipherPipelineInitFn>(fns);
                    fnpipecnt += 1;
                }
                OSSL_FUNC_CIPHER_PIPELINE_UPDATE if (*cipher).p_cupdate.is_none() => {
                    (*cipher).p_cupdate = entry_function::<CipherPipelineUpdateFn>(fns);
                    fnpipecnt += 1;
                }
                OSSL_FUNC_CIPHER_PIPELINE_FINAL if (*cipher).p_cfinal.is_none() => {
                    (*cipher).p_cfinal = entry_function::<CipherPipelineFinalFn>(fns);
                    fnpipecnt += 1;
                }
                OSSL_FUNC_CIPHER_FREECTX if (*cipher).freectx.is_none() => {
                    (*cipher).freectx = entry_function::<CipherFreeCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_CIPHER_DUPCTX if (*cipher).dupctx.is_none() => {
                    (*cipher).dupctx = entry_function::<CipherDupCtxFn>(fns);
                }
                OSSL_FUNC_CIPHER_GET_PARAMS if (*cipher).get_params.is_none() => {
                    (*cipher).get_params = entry_function::<CipherGetParamsFn>(fns);
                }
                OSSL_FUNC_CIPHER_GET_CTX_PARAMS if (*cipher).get_ctx_params.is_none() => {
                    (*cipher).get_ctx_params = entry_function::<CipherGetCtxParamsFn>(fns);
                }
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS if (*cipher).set_ctx_params.is_none() => {
                    (*cipher).set_ctx_params = entry_function::<CipherSetCtxParamsFn>(fns);
                }
                OSSL_FUNC_CIPHER_GETTABLE_PARAMS if (*cipher).gettable_params.is_none() => {
                    (*cipher).gettable_params = entry_function::<CipherGettableParamsFn>(fns);
                }
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS if (*cipher).gettable_ctx_params.is_none() => {
                    (*cipher).gettable_ctx_params =
                        entry_function::<CipherGettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS if (*cipher).settable_ctx_params.is_none() => {
                    (*cipher).settable_ctx_params =
                        entry_function::<CipherSettableCtxParamsFn>(fns);
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }

    fnciphcnt += encinit + decinit;
    // The structural check, verbatim, including the clause that looks redundant and is not.
    // SAFETY: `cipher` is live.
    let (ccipher, p_cupdate, p_cfinal) = unsafe {
        (
            (*cipher).ccipher.is_some(),
            (*cipher).p_cupdate.is_some(),
            (*cipher).p_cfinal.is_some(),
        )
    };
    if (fnciphcnt != 0 && fnciphcnt != 3 && fnciphcnt != 4)
        || (fnciphcnt == 0 && !ccipher && fnpipecnt == 0)
        || (fnpipecnt != 0 && (fnpipecnt < 3 || !p_cupdate || !p_cfinal))
        || fnctxcnt != 2
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_2044) };
        // SAFETY: `cipher` is this call's own object.
        unsafe { EVP_CIPHER_free(cipher) };
        return ptr::null_mut();
    }

    if !prov.is_null() {
        // SAFETY: `prov` is live per the contract.
        if unsafe { ossl_provider_up_ref(prov) } == 0 {
            // SAFETY: `cipher` is this call's own object.
            unsafe { EVP_CIPHER_free(cipher) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `cipher` is live.
    unsafe { (*cipher).prov = prov };

    // SAFETY: `cipher` is live and its provider is the one just referenced.
    if unsafe { evp_cipher_cache_constants(cipher) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_2053) };
        // SAFETY: `cipher` is this call's own object; its reference to `prov` is dropped with it.
        unsafe { EVP_CIPHER_free(cipher) };
        return ptr::null_mut();
    }

    cipher.cast::<c_void>()
}

/// `static int evp_cipher_up_ref(void *cipher)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
unsafe extern "C" fn evp_cipher_up_ref(cipher: *mut c_void) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { EVP_CIPHER_up_ref(cipher.cast::<EvpCipher>()) }
}

/// `static void evp_cipher_free(void *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher` this module owns a reference to.
unsafe extern "C" fn evp_cipher_free(cipher: *mut c_void) {
    // SAFETY: `cipher` is NULL or live per the contract.
    unsafe { EVP_CIPHER_free(cipher.cast::<EvpCipher>()) };
}

/// `void evp_cipher_free_int(EVP_CIPHER *cipher)` — the releaser, which the destructor and the
/// legacy `EVP_CIPHER_meth_free` share.
///
/// The authority's order: the name, the provider reference, the reference count, the block.
/// Nothing in the legacy half is released, because nothing in it was ever allocated by this crate
/// — `type_name` is the only owned string and `description` is the provider's own.
///
/// # Safety
/// `cipher` must be a live `EvpCipher` with no references left.
unsafe fn evp_cipher_free_int(cipher: *mut EvpCipher) {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        CRYPTO_free(
            (*cipher).type_name.cast::<c_void>(),
            FILE,
            LINE_FREE_TYPE_NAME,
        );
        ossl_provider_free((*cipher).prov);
        CRYPTO_free(cipher.cast::<c_void>(), FILE, LINE_FREE_CIPHER);
    }
}

/// `EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpCipher {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_CIPHER,
            algorithm,
            properties,
            evp_cipher_from_algorithm as MethodFromAlgorithmFn,
            evp_cipher_up_ref as MethodUpRefFn,
            evp_cipher_free as MethodFreeFn,
        )
    }
    .cast::<EvpCipher>()
}

/// `EVP_CIPHER *evp_cipher_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
/// const char *properties)`.
///
/// Internal, and the reason it exists rather than being inlined: a caller that already holds the
/// provider it wants does not want a walk over all of them. No `secure_getenv`-style escape, no
/// property merge — a provider-scoped fetch matches inside that provider only.
///
/// # Safety
/// `prov` live; `algorithm` and `properties` NULL or NUL-terminated.
#[allow(dead_code)]
pub(crate) unsafe fn evp_cipher_fetch_from_prov(
    prov: *mut OsslProvider,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpCipher {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        crate::evp::fetch::evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_CIPHER,
            algorithm,
            properties,
            evp_cipher_from_algorithm as MethodFromAlgorithmFn,
            evp_cipher_up_ref as MethodUpRefFn,
            evp_cipher_free as MethodFreeFn,
        )
    }
    .cast::<EvpCipher>()
}

/// `int EVP_CIPHER_can_pipeline(const EVP_CIPHER *cipher, int enc)`.
///
/// A *pure* query of three fields, and the authority's expression is an OR of two pairs rather
/// than a switch on `enc`: encrypting needs `p_einit` and decrypting needs `p_dinit`, and either
/// way the update and the final must both be there.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_can_pipeline(cipher: *const EvpCipher, enc: c_int) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    let (p_einit, p_dinit, p_cupdate, p_cfinal) = unsafe {
        (
            (*cipher).p_einit.is_some(),
            (*cipher).p_dinit.is_some(),
            (*cipher).p_cupdate.is_some(),
            (*cipher).p_cfinal.is_some(),
        )
    };
    if ((enc != 0 && p_einit) || (enc == 0 && p_dinit)) && p_cupdate && p_cfinal {
        return 1;
    }
    0
}

/// `int EVP_CIPHER_up_ref(EVP_CIPHER *cipher)`.
///
/// **Answers 1 for a legacy method too**, where nothing is incremented: the global and `METH`
/// halves are owned by read-only memory and by their creator respectively, and a caller taking a
/// reference to one is asking for a guarantee it already has.
///
/// `cipher` is dereferenced unconditionally, as the authority's is.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_up_ref(cipher: *mut EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).origin == EVP_ORIG_DYNAMIC {
            (*cipher).refcnt.fetch_add(1, Ordering::AcqRel);
        }
    }
    1
}

/// `void EVP_CIPHER_free(EVP_CIPHER *cipher)`.
///
/// Two refusals before anything happens: NULL, and **any origin that is not `EVP_ORIG_DYNAMIC`**.
/// The second is the one that matters — `EVP_enc_null()` answers a pointer into read-only memory
/// and freeing it would be freeing a static.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_free(cipher: *mut EvpCipher) {
    if cipher.is_null() {
        return;
    }
    // SAFETY: `cipher` is live per the contract.
    if unsafe { (*cipher).origin } != EVP_ORIG_DYNAMIC {
        return;
    }
    // SAFETY: `cipher` is live.
    let last = unsafe { (*cipher).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference.
    unsafe { evp_cipher_free_int(cipher) };
}

/// `void EVP_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
/// void (*fn)(EVP_CIPHER *cipher, void *arg), void *arg)`.
///
/// The callback the caller supplies takes an `EVP_CIPHER *` and the walk hands it a `void *`, so
/// the cast is the authority's own. Nothing here is a snapshot: the walk builds each method on
/// the fly, which is why the same constructor is passed in.
///
/// # Safety
/// `libctx` NULL or live; `fn` may be NULL, and a NULL there means the walk still runs.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpCipher, *mut c_void)>,
    arg: *mut c_void,
) {
    // SAFETY: the arguments are forwarded under this function's contract. `fn_` is transmuted
    // rather than wrapped: the authority casts a two-argument callback to the walk's
    // `void (*)(void *, void *)`, and a shim would change which function a caller's debugger sees
    // while changing nothing else.
    let user_fn = unsafe {
        core::mem::transmute::<
            Option<unsafe extern "C" fn(*mut EvpCipher, *mut c_void)>,
            Option<GenericDoAllFn>,
        >(fn_)
    };
    if let Some(f) = user_fn {
        // SAFETY: `libctx` is NULL or live, `f` is the caller's callback, and the three
        // callbacks are this module's own.
        unsafe {
            evp_generic_do_all(
                libctx,
                OSSL_OP_CIPHER,
                f,
                arg,
                evp_cipher_from_algorithm as MethodFromAlgorithmFn,
                evp_cipher_up_ref as MethodUpRefFn,
                evp_cipher_free as MethodFreeFn,
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/evp_lib.c` — the method object's accessors
// ---------------------------------------------------------------------------------------------

/// `int EVP_CIPHER_get_type(const EVP_CIPHER *cipher)`.
///
/// Eight `switch` arms that fold aliases onto a canonical NID, then an OID test for everything
/// else. The `FIPS_MODULE` alternative is not this build's, so the fall-through is the OID test:
/// `OBJ_nid2obj` on a NID the object database does not know answers an object with no data, and
/// `NID_undef` is the answer a caller can compare against.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_type(cipher: *const EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    let mut nid = unsafe { EVP_CIPHER_get_nid(cipher) };

    match nid {
        crate::runtime::obj::NID_rc2_cbc
        | crate::runtime::obj::NID_rc2_64_cbc
        | crate::runtime::obj::NID_rc2_40_cbc => return crate::runtime::obj::NID_rc2_cbc,
        crate::runtime::obj::NID_rc4 | crate::runtime::obj::NID_rc4_40 => {
            return crate::runtime::obj::NID_rc4;
        }
        crate::runtime::obj::NID_aes_128_cfb128
        | crate::runtime::obj::NID_aes_128_cfb8
        | crate::runtime::obj::NID_aes_128_cfb1 => return crate::runtime::obj::NID_aes_128_cfb128,
        crate::runtime::obj::NID_aes_192_cfb128
        | crate::runtime::obj::NID_aes_192_cfb8
        | crate::runtime::obj::NID_aes_192_cfb1 => return crate::runtime::obj::NID_aes_192_cfb128,
        crate::runtime::obj::NID_aes_256_cfb128
        | crate::runtime::obj::NID_aes_256_cfb8
        | crate::runtime::obj::NID_aes_256_cfb1 => return crate::runtime::obj::NID_aes_256_cfb128,
        crate::runtime::obj::NID_des_cfb64
        | crate::runtime::obj::NID_des_cfb8
        | crate::runtime::obj::NID_des_cfb1 => return crate::runtime::obj::NID_des_cfb64,
        crate::runtime::obj::NID_des_ede3_cfb64
        | crate::runtime::obj::NID_des_ede3_cfb8
        | crate::runtime::obj::NID_des_ede3_cfb1 => return crate::runtime::obj::NID_des_ede3_cfb64,
        _ => {}
    }

    // A NID the object database knows, with an OID: that is the type. One without is not.
    let otmp = OBJ_nid2obj(nid);
    // SAFETY: `OBJ_nid2obj` answers NULL or a live object.
    if unsafe { OBJ_get0_data(otmp) }.is_null() {
        nid = NID_undef;
    }
    // SAFETY: `otmp` is NULL or a live object this call owns, per `OBJ_nid2obj`'s contract.
    unsafe { ASN1_OBJECT_free(otmp) };
    nid
}

/// `int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_block_size(cipher: *const EvpCipher) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).block_size }
}

/// `int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *e)`.
///
/// **No NULL test**, unlike its neighbours: the authority dereferences unconditionally.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_impl_ctx_size(cipher: *const EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).ctx_size }
}

/// `unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_flags(cipher: *const EvpCipher) -> c_ulong {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).flags }
}

/// `int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_iv_length(cipher: *const EvpCipher) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).iv_len }
}

/// `int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher)`.
///
/// **No NULL test** here either, and the asymmetry with `get_iv_length` above is the authority's.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_key_length(cipher: *const EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).key_len }
}

/// `int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_nid(cipher: *const EvpCipher) -> c_int {
    if cipher.is_null() {
        return NID_undef;
    }
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).nid }
}

/// `int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name)`.
///
/// Two paths, and which one is taken is `prov`: a provider method is asked through the namemap
/// with its `name_id`, and a legacy one by comparing the caller's name against the method's *own*
/// name — which is why the legacy arm passes `NULL` and `0` for the provider and the id.
///
/// # Safety
/// `cipher` must be NULL or live; `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_is_a(cipher: *const EvpCipher, name: *const c_char) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    let (prov, name_id, type_name) =
        unsafe { ((*cipher).prov, (*cipher).name_id, (*cipher).type_name) };
    if !prov.is_null() {
        // SAFETY: `prov` is live, `name` is NUL-terminated, and the other two arguments are the
        // method's own identity.
        return unsafe { evp_is_a(prov, name_id, ptr::null(), name) };
    }
    // SAFETY: `name` is NUL-terminated; `type_name` is this method's own string, NULL for a
    // method built by `EVP_CIPHER_meth_new`, which `evp_is_a` accepts as a legacy name.
    unsafe { evp_is_a(ptr::null_mut(), 0, type_name, name) }
}

/// `int evp_cipher_get_number(const EVP_CIPHER *cipher)`.
///
/// The namemap identity, which is what the *fetch* machinery calls a "number" and not an NID.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[allow(dead_code)]
pub(crate) unsafe fn evp_cipher_get_number(cipher: *const EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).name_id }
}

/// `const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher)`.
///
/// The provider's first alias, or the legacy short name for a method that has none. It does
/// **not** test NULL: the authority dereferences, and a caller with a NULL has already broken the
/// contract.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get0_name(cipher: *const EvpCipher) -> *const c_char {
    // SAFETY: `cipher` is live per the contract.
    let type_name = unsafe { (*cipher).type_name };
    if !type_name.is_null() {
        return type_name;
    }
    // SAFETY: `cipher` is live per the contract.
    let nid = unsafe { EVP_CIPHER_get_nid(cipher) };
    OBJ_nid2sn(nid)
}

/// `const char *EVP_CIPHER_get0_description(const EVP_CIPHER *cipher)`.
///
/// The provider's own description, or the legacy *long* name for a method that has none — the one
/// difference from `get0_name`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get0_description(cipher: *const EvpCipher) -> *const c_char {
    // SAFETY: `cipher` is live per the contract.
    let description = unsafe { (*cipher).description };
    if !description.is_null() {
        return description;
    }
    // SAFETY: `cipher` is live per the contract.
    let nid = unsafe { EVP_CIPHER_get_nid(cipher) };
    OBJ_nid2ln(nid)
}

/// `int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// A legacy method has no namemap entry to walk, so the authority answers **1** without calling
/// the visitor — a success with nothing visited, not a failure.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`; `fn` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_names_do_all(
    cipher: *const EvpCipher,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    let (prov, name_id) = unsafe { ((*cipher).prov, (*cipher).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get0_provider(cipher: *const EvpCipher) -> *const OsslProvider {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).prov }
}

/// `int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher)`.
///
/// The four low bits of the flags, which is why `EVP_CIPH_MODE` is a mask and the mode constants
/// are small integers — except the four that are not, and the mask is what makes them fit anyway.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_mode(cipher: *const EvpCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_MODE) as c_int
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/evp_enc.c` — the four parameter entry points whose subject is the method object
// ---------------------------------------------------------------------------------------------

/// `int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[])`.
///
/// Answers 0 rather than refusing when there is nothing to ask: the authority's test is on the
/// *callback*, not on an error path.
///
/// # Safety
/// `cipher` NULL or live; `params` a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_params(
    cipher: *mut EvpCipher,
    params: *mut OsslParam,
) -> c_int {
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live per the contract.
    let Some(f) = (unsafe { (*cipher).get_params }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher)`.
///
/// The callback takes the **provider context**, not the method, which is why this reaches for
/// `ossl_provider_ctx` — and why a legacy method's answer is NULL: it has no provider.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_gettable_params(cipher: *const EvpCipher) -> *const OsslParam {
    if cipher.is_null() {
        return ptr::null();
    }
    // SAFETY: `cipher` is live per the contract.
    let Some(f) = (unsafe { (*cipher).gettable_params }) else {
        return ptr::null();
    };
    // SAFETY: `cipher` is live per the contract.
    let provctx = unsafe { ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher)) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher)`.
///
/// A **NULL** context and the provider context, in that order: the method-level question has no
/// context to describe.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_settable_ctx_params(
    cipher: *const EvpCipher,
) -> *const OsslParam {
    if cipher.is_null() {
        return ptr::null();
    }
    // SAFETY: `cipher` is live per the contract.
    let Some(f) = (unsafe { (*cipher).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `cipher` is live per the contract.
    let provctx = unsafe { ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher)) };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_gettable_ctx_params(
    cipher: *const EvpCipher,
) -> *const OsslParam {
    if cipher.is_null() {
        return ptr::null();
    }
    // SAFETY: `cipher` is live per the contract.
    let Some(f) = (unsafe { (*cipher).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `cipher` is live per the contract.
    let provctx = unsafe { ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher)) };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f(ptr::null_mut(), provctx) }
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/cmeth_lib.c` — the legacy method constructors
//
// Every setter refuses when the field is already set: `if (cipher->init != NULL) return 0;` is
// the authority's, and it is what makes a method built by hand **append-only** -- a caller cannot
// replace a function once it has been given.
//
// The setters dereference their subject unconditionally, and that is the authority's shape too:
// `EVP_CIPHER_meth_set_*` has no NULL arm, so a caller passing NULL has already broken the
// contract. The two functions that *do* test are `EVP_CIPHER_meth_dup` and `EVP_CIPHER_meth_free`,
// and the tests are in their own comments.
// ---------------------------------------------------------------------------------------------

/// `EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)`.
///
/// The one constructor that marks the object `EVP_ORIG_METH`, which is what makes
/// `EVP_CIPHER_meth_free` free it and `EVP_CIPHER_free` refuse it.
///
/// # Safety
/// No preconditions: the function allocates and writes three fields.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_new(
    cipher_type: c_int,
    block_size: c_int,
    key_len: c_int,
) -> *mut EvpCipher {
    let cipher = evp_cipher_new();
    if !cipher.is_null() {
        // SAFETY: `cipher` is a fresh block this call owns.
        unsafe {
            (*cipher).nid = cipher_type;
            (*cipher).block_size = block_size;
            (*cipher).key_len = key_len;
            (*cipher).origin = EVP_ORIG_METH;
        }
    }
    cipher
}

/// `EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher)`.
///
/// Two refusals and one subtlety. The refusal: **a provider method cannot be duplicated this
/// way** — `EVP_CIPHER_up_ref` is what a caller wants there, and the answer is NULL rather than a
/// copy, because a copy of a provider method would be a second object with the same provider and
/// no reference to it. The subtlety: the reference count is saved *before* the copy and restored
/// after it, so the duplicate does not inherit the original's count.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_dup(cipher: *const EvpCipher) -> *mut EvpCipher {
    // SAFETY: `cipher` is live per the contract.
    if !unsafe { (*cipher).prov }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cipher` is live per the contract.
    let to = unsafe { EVP_CIPHER_meth_new((*cipher).nid, (*cipher).block_size, (*cipher).key_len) };
    if !to.is_null() {
        // SAFETY: `to` is a fresh live object this call owns.
        let refcnt = unsafe { (*to).refcnt.load(Ordering::Acquire) };
        // SAFETY: `to` and `cipher` are both live and `to` is this call's own block, so the copy
        // is into memory nothing else can see.
        unsafe {
            ptr::copy_nonoverlapping(
                cipher.cast::<u8>(),
                to.cast::<u8>(),
                core::mem::size_of::<EvpCipher>(),
            );
            (*to).refcnt = AtomicI32::new(refcnt);
            // The copy above brought the *original's* origin across, so it is set again: a
            // duplicate of a `METH` method is a `METH` method.
            (*to).origin = EVP_ORIG_METH;
        }
    }
    to
}

/// `void EVP_CIPHER_meth_free(EVP_CIPHER *cipher)`.
///
/// Frees `EVP_ORIG_METH` and nothing else: a global is read-only memory and a dynamic method
/// belongs to `EVP_CIPHER_free`, whose reference count this function does not consult.
///
/// # Safety
/// `cipher` must be NULL or a live `EvpCipher` this module owns.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_free(cipher: *mut EvpCipher) {
    if cipher.is_null() {
        return;
    }
    // SAFETY: `cipher` is live per the contract.
    if unsafe { (*cipher).origin } != EVP_ORIG_METH {
        return;
    }
    // SAFETY: `cipher` is a live `METH` method, which this function alone releases.
    unsafe { evp_cipher_free_int(cipher) };
}

/// `int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_iv_length(
    cipher: *mut EvpCipher,
    iv_len: c_int,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).iv_len != 0 {
            return 0;
        }
        (*cipher).iv_len = iv_len;
    }
    1
}

/// `int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_flags(
    cipher: *mut EvpCipher,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).flags != 0 {
            return 0;
        }
        (*cipher).flags = flags;
    }
    1
}

/// `int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_impl_ctx_size(
    cipher: *mut EvpCipher,
    ctx_size: c_int,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).ctx_size != 0 {
            return 0;
        }
        (*cipher).ctx_size = ctx_size;
    }
    1
}

/// `int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher, int (*init)(EVP_CIPHER_CTX *,
/// const unsigned char *, const unsigned char *, int))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_init(
    cipher: *mut EvpCipher,
    init: Option<CipherLegacyInitFn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).init.is_some() {
            return 0;
        }
        (*cipher).init = init;
    }
    1
}

/// `int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher, int (*do_cipher)(EVP_CIPHER_CTX *,
/// unsigned char *, const unsigned char *, size_t))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_do_cipher(
    cipher: *mut EvpCipher,
    do_cipher: Option<CipherLegacyDoFn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).do_cipher.is_some() {
            return 0;
        }
        (*cipher).do_cipher = do_cipher;
    }
    1
}

/// `int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher, int (*cleanup)(EVP_CIPHER_CTX *))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_cleanup(
    cipher: *mut EvpCipher,
    cleanup: Option<CipherLegacyCleanupFn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).cleanup.is_some() {
            return 0;
        }
        (*cipher).cleanup = cleanup;
    }
    1
}

/// `int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
/// int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_set_asn1_params(
    cipher: *mut EvpCipher,
    set_asn1_parameters: Option<CipherLegacyAsn1Fn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).set_asn1_parameters.is_some() {
            return 0;
        }
        (*cipher).set_asn1_parameters = set_asn1_parameters;
    }
    1
}

/// `int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
/// int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_get_asn1_params(
    cipher: *mut EvpCipher,
    get_asn1_parameters: Option<CipherLegacyAsn1Fn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).get_asn1_parameters.is_some() {
            return 0;
        }
        (*cipher).get_asn1_parameters = get_asn1_parameters;
    }
    1
}

/// `int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher, int (*ctrl)(EVP_CIPHER_CTX *, int, int,
/// void *))`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_set_ctrl(
    cipher: *mut EvpCipher,
    ctrl: Option<CipherLegacyCtrlFn>,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe {
        if (*cipher).ctrl.is_some() {
            return 0;
        }
        (*cipher).ctrl = ctrl;
    }
    1
}

/// `int (*EVP_CIPHER_meth_get_init(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
/// const unsigned char *, const unsigned char *, int)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_init(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyInitFn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).init }
}

/// `int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
/// unsigned char *, const unsigned char *, size_t)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_do_cipher(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyDoFn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).do_cipher }
}

/// `int (*EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_cleanup(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyCleanupFn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).cleanup }
}

/// `int (*EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
/// ASN1_TYPE *)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_set_asn1_params(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyAsn1Fn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).set_asn1_parameters }
}

/// `int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
/// ASN1_TYPE *)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_get_asn1_params(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyAsn1Fn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).get_asn1_parameters }
}

/// `int (*EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *, int, int,
/// void *)`.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_meth_get_ctrl(
    cipher: *const EvpCipher,
) -> Option<CipherLegacyCtrlFn> {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).ctrl }
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/e_null.c` — the one legacy cipher with no primitive under it
// ---------------------------------------------------------------------------------------------

/// `NID_undef`'s zero, the block size 1, and nothing else: `e_null.c`'s initialiser list, field
/// for field, with the provider half left zero exactly as the authority leaves it.
///
/// `refcnt` is **0**, not 1, because the authority's initialiser stops before it — and it is never
/// read, because every arm that would read it is guarded by `origin != EVP_ORIG_DYNAMIC`.
static N_CIPHER: StaticCipher = StaticCipher(EvpCipher {
    nid: NID_undef,
    block_size: 1,
    key_len: 0,
    iv_len: 0,
    flags: 0,
    origin: EVP_ORIG_GLOBAL,
    init: Some(null_init_key),
    do_cipher: Some(null_cipher),
    cleanup: None,
    ctx_size: 0,
    set_asn1_parameters: None,
    get_asn1_parameters: None,
    ctrl: None,
    app_data: ptr::null_mut(),
    name_id: 0,
    type_name: ptr::null_mut(),
    description: ptr::null(),
    prov: ptr::null_mut(),
    refcnt: AtomicI32::new(0),
    newctx: None,
    einit: None,
    dinit: None,
    cupdate: None,
    cfinal: None,
    ccipher: None,
    p_einit: None,
    p_dinit: None,
    p_cupdate: None,
    p_cfinal: None,
    freectx: None,
    dupctx: None,
    get_params: None,
    get_ctx_params: None,
    set_ctx_params: None,
    gettable_params: None,
    gettable_ctx_params: None,
    settable_ctx_params: None,
    einit_skey: None,
    dinit_skey: None,
});

/// `const EVP_CIPHER *EVP_enc_null(void)`.
///
/// The same address on every call, which is the property a method object needs and a `const` item
/// cannot provide — a `const` is inlined at each use, so `&CONST` is a different address in every
/// function that names it.
#[no_mangle]
pub extern "C" fn EVP_enc_null() -> *const EvpCipher {
    &N_CIPHER.0
}

/// `static int null_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
/// const unsigned char *iv, int enc)` — answers 1 without touching anything.
///
/// # Safety
/// The ABI is the authority's; no argument is read.
unsafe extern "C" fn null_init_key(
    _ctx: *mut c_void,
    _key: *const u8,
    _iv: *const u8,
    _enc: c_int,
) -> c_int {
    1
}

/// `static int null_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
/// size_t inl)` — a `memcpy` that is skipped when the buffers are the same, which is the one
/// behaviour of this method that is observable.
///
/// # Safety
/// `out` must be writable for `inl` bytes and `in` readable for `inl` bytes when they differ.
unsafe extern "C" fn null_cipher(
    _ctx: *mut c_void,
    out: *mut u8,
    in_: *const u8,
    inl: usize,
) -> c_int {
    if in_ != out && !in_.is_null() && inl != 0 {
        // SAFETY: the caller guarantees both buffers hold `inl` bytes and they do not overlap.
        unsafe { ptr::copy_nonoverlapping(in_, out, inl) };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// `names.c`'s two cipher walkers
//
// The legacy table, not the providers: `EVP_CIPHER_do_all` visits every entry a caller could reach
// through `EVP_get_cipherbyname`, which is the `OBJ_NAME` database the *adders* fill. The two
// providers' algorithms are `EVP_CIPHER_do_all_provided`'s and are a different walk over a
// different structure -- a distinction the name does not make and the implementation does.
//
// Both take the same shape, and the shape is the observation: an entry that is an alias is
// reported with a **NULL cipher** and its target in `to`, where a real entry is reported with its
// cipher in `from` and a NULL `to`. A transcription that passed the alias's data as the cipher
// would hand the caller a `char *` where an `EVP_CIPHER *` belongs.
// ---------------------------------------------------------------------------------------------

/// `struct doall_cipher { void *arg; void (*fn)(const EVP_CIPHER *ciph, const char *from,
/// const char *to, void *arg); }`.
#[repr(C)]
struct DoAllCipher {
    /// `void *arg` — the caller's argument, passed through unchanged.
    arg: *mut c_void,
    /// The caller's visitor.
    fn_: Option<CipherDoAllFn>,
}

/// `void (*)(const EVP_CIPHER *ciph, const char *from, const char *to, void *x)`.
pub(crate) type CipherDoAllFn =
    unsafe extern "C" fn(*const EvpCipher, *const c_char, *const c_char, *mut c_void);

/// `static void do_all_cipher_fn(const OBJ_NAME *nm, void *arg)`.
///
/// The `OBJ_NAME` callback both walkers install, and the whole of the two-pass story: an alias row
/// has `alias` set and its `data` is the *name* of what it points at, a real row has `data` as the
/// method. The two are reported through different arguments of the caller's visitor.
///
/// # Safety
/// `nm` must be a live `ObjName` and `arg` must point at a live `DoAllCipher`.
unsafe extern "C" fn do_all_cipher_fn(nm: *const ObjName, arg: *mut c_void) {
    let dc = arg.cast::<DoAllCipher>();
    if nm.is_null() || dc.is_null() {
        return;
    }
    // SAFETY: `dc` is live per the contract.
    let (fn_, dc_arg) = unsafe { ((*dc).fn_, (*dc).arg) };
    let Some(f) = fn_ else {
        return;
    };
    // SAFETY: `nm` is live per the contract.
    let (alias, name, data) = unsafe { ((*nm).alias, (*nm).name, (*nm).data) };
    if alias != 0 {
        // SAFETY: `f` is the caller's visitor; an alias row reports a NULL cipher and the target
        // name in `to`, which is `data`.
        unsafe { f(ptr::null(), name, data, dc_arg) };
    } else {
        // SAFETY: `f` is the caller's visitor and `data` is the method the adder stored.
        unsafe { f(data.cast::<EvpCipher>(), name, ptr::null(), dc_arg) };
    }
}

/// The shared body of the two walkers: arm the legacy table, then visit it in the order asked for.
///
/// `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)` is called and its **answer is
/// ignored**, which is the authority's own `/* Ignore errors */` comment: a table that could not be
/// populated is a walk that visits nothing, not a failure the caller can do anything about.
///
/// # Safety
/// `fn_` may be NULL, in which case nothing happens; otherwise it must be a valid visitor for the
/// signature it is declared with.
unsafe fn cipher_names_do_all(fn_: Option<CipherDoAllFn>, arg: *mut c_void, sorted: bool) {
    // SAFETY: `arg` is the caller's own and is passed through unchanged.
    let mut dc = DoAllCipher { arg, fn_ };
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, ptr::null());
    if sorted {
        // SAFETY: `dc` is this frame's own live object and `do_all_cipher_fn` is the visitor the
        // table's contract asks for.
        unsafe {
            OBJ_NAME_do_all_sorted(
                OBJ_NAME_TYPE_CIPHER_METH,
                Some(do_all_cipher_fn),
                ptr::addr_of_mut!(dc).cast::<c_void>(),
            )
        };
    } else {
        // SAFETY: as above.
        unsafe {
            OBJ_NAME_do_all(
                OBJ_NAME_TYPE_CIPHER_METH,
                Some(do_all_cipher_fn),
                ptr::addr_of_mut!(dc).cast::<c_void>(),
            )
        };
    }
}

/// `void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph, const char *from, const char *to,
/// void *x), void *arg)`.
///
/// # Safety
/// `fn_` NULL or a valid visitor; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_do_all(fn_: Option<CipherDoAllFn>, arg: *mut c_void) {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { cipher_names_do_all(fn_, arg, false) };
}

/// `void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph, const char *from,
/// const char *to, void *x), void *arg)`.
///
/// The same walk with the names ordered by `strcmp` -- the only difference, and the reason the
/// authority has two entry points rather than a flag.
///
/// # Safety
/// `fn_` NULL or a valid visitor; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_do_all_sorted(fn_: Option<CipherDoAllFn>, arg: *mut c_void) {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { cipher_names_do_all(fn_, arg, true) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EVP_CIPH_ECB_MODE` and `EVP_CIPH_CBC_MODE` — `include/openssl/evp.h`.
    ///
    /// Declared here rather than beside `EVP_CIPH_MODE` because nothing in this module's own code
    /// names a specific mode: `evp_cipher_cache_constants` takes `mode` from the provider and
    /// `EVP_CIPHER_get_mode` masks it. The two values are what makes the mask's job visible in the
    /// test below, and a header fact a test needs belongs with the test.
    const EVP_CIPH_ECB_MODE: c_ulong = 0x1;
    const EVP_CIPH_CBC_MODE: c_ulong = 0x2;

    /// `EVP_enc_null()` answers the *same* address every time, which is the whole reason it is a
    /// `static` rather than a `const`: a caller may compare it against what a context holds.
    #[test]
    fn the_null_cipher_is_one_object_with_the_global_origin() {
        let a = EVP_enc_null();
        let b = EVP_enc_null();
        assert_eq!(a, b, "one object, not one per call");
        // SAFETY: `a` is the static this module owns.
        unsafe {
            assert_eq!((*a).origin, EVP_ORIG_GLOBAL);
            assert_eq!((*a).nid, NID_undef);
            assert_eq!((*a).block_size, 1);
        }
    }

    /// The free path refuses a global and the reference path does not increment one — the two
    /// halves of "a method from read-only memory is not this crate's to release".
    #[test]
    fn freeing_a_global_method_is_a_no_op() {
        let a = EVP_enc_null().cast_mut();
        // SAFETY: `a` is the static, which the authority also hands out as non-const.
        unsafe {
            assert_eq!(EVP_CIPHER_up_ref(a), 1);
            assert_eq!((*a).refcnt.load(Ordering::Acquire), 0, "not incremented");
            EVP_CIPHER_free(a);
            // Still the same object with the same fields: nothing was released.
            assert_eq!((*a).origin, EVP_ORIG_GLOBAL);
            assert_eq!((*a).block_size, 1);
        }
    }

    /// A `METH` method is built by hand, read back, and released by the legacy destructor — and
    /// the setters refuse a second write, which is what makes the object append-only.
    #[test]
    fn a_method_built_by_hand_is_append_only_and_released_by_meth_free() {
        // SAFETY: this test owns everything it touches.
        unsafe {
            let m = EVP_CIPHER_meth_new(7, 16, 32);
            assert!(!m.is_null(), "the constructor allocated");
            assert_eq!((*m).origin, EVP_ORIG_METH);
            assert_eq!((*m).nid, 7);
            assert_eq!((*m).block_size, 16);
            assert_eq!((*m).key_len, 32);
            assert_eq!(
                (*m).prov,
                ptr::null_mut(),
                "a hand-built method has no provider"
            );

            assert_eq!(
                EVP_CIPHER_meth_set_iv_length(m, 16),
                1,
                "the first write is taken"
            );
            assert_eq!(
                EVP_CIPHER_meth_set_iv_length(m, 8),
                0,
                "the second is refused"
            );
            assert_eq!((*m).iv_len, 16, "and the first value stands");

            assert_eq!(
                EVP_CIPHER_meth_set_flags(m, EVP_CIPH_CBC_MODE),
                1,
                "the first flags write is taken"
            );
            assert_eq!(
                EVP_CIPHER_meth_set_flags(m, EVP_CIPH_ECB_MODE),
                0,
                "the second is refused"
            );

            assert_eq!(EVP_CIPHER_meth_set_do_cipher(m, Some(null_cipher)), 1);
            assert_eq!(EVP_CIPHER_meth_set_do_cipher(m, Some(null_cipher)), 0);
            assert_eq!(
                EVP_CIPHER_meth_get_do_cipher(m).map(|f| f as usize),
                Some(null_cipher as *const () as usize),
                "the getter answers what the setter stored"
            );

            // The legacy accessors read the legacy half, and the mode mask reads the flags.
            assert_eq!(EVP_CIPHER_get_nid(m), 7);
            assert_eq!(EVP_CIPHER_get_block_size(m), 16);
            assert_eq!(EVP_CIPHER_get_key_length(m), 32);
            assert_eq!(EVP_CIPHER_get_iv_length(m), 16);
            assert_eq!(EVP_CIPHER_get_mode(m), EVP_CIPH_CBC_MODE as c_int);
            assert_eq!(EVP_CIPHER_get0_provider(m), ptr::null(), "no provider");

            // `EVP_CIPHER_free` refuses it -- the origin is not dynamic -- so the legacy
            // destructor is the only one that releases it, and it is called once.
            EVP_CIPHER_free(m);
            assert_eq!(
                (*m).origin,
                EVP_ORIG_METH,
                "not released by the public destructor"
            );
            EVP_CIPHER_meth_free(m);
        }
    }

    /// A duplicate copies every field and holds **one** reference of its own — and the
    /// reference-count manoeuvre in the middle of the authority's function turns out to be
    /// unreachable for anything that function accepts.
    ///
    /// `CRYPTO_REF_COUNT refcnt = to->refcnt;` reads the *new* object's count and restores it
    /// after the `memcpy`. For that to matter, the count it restores would have to differ from the
    /// original's — but the only methods whose count can be raised are provider ones, because
    /// `EVP_CIPHER_up_ref` increments only `EVP_ORIG_DYNAMIC`, and `EVP_CIPHER_meth_dup` answers
    /// NULL for those. So both counts are one on every path that reaches the copy, and a test that
    /// manufactured a difference would be asserting a state the authority cannot produce. That is
    /// what this test asserts instead: the invariant, and the refusal that makes it hold.
    #[test]
    fn a_duplicate_copies_the_fields_and_each_object_holds_one_reference() {
        /// Any non-NULL address. `EVP_CIPHER_meth_dup` *tests* `prov` and never dereferences it,
        /// so the refusal arm is reachable without building a provider.
        static MARKER: u8 = 0;

        // SAFETY: this test owns everything it touches.
        unsafe {
            let m = EVP_CIPHER_meth_new(9, 8, 16);
            assert_eq!(EVP_CIPHER_meth_set_iv_length(m, 8), 1);

            // A `METH` method cannot have its count raised: answers 1, counts nothing.
            assert_eq!(EVP_CIPHER_up_ref(m), 1);
            assert_eq!(
                (*m).refcnt.load(Ordering::Acquire),
                1,
                "only a dynamic method is counted"
            );

            let d = EVP_CIPHER_meth_dup(m);
            assert!(!d.is_null(), "the duplicate was built");
            assert_eq!((*d).origin, EVP_ORIG_METH);
            assert_eq!((*d).nid, 9);
            assert_eq!((*d).block_size, 8);
            assert_eq!((*d).iv_len, 8, "the copy took the field the original had");
            assert_eq!(
                (*m).refcnt.load(Ordering::Acquire),
                1,
                "the original kept the count it had"
            );
            assert_eq!(
                (*d).refcnt.load(Ordering::Acquire),
                1,
                "and the duplicate has its own, not a share of the original's"
            );

            // The refusal: a method that has a provider is not duplicable this way, and the
            // pointer is only tested, which is why a marker address is enough to take the arm.
            (*m).prov = (&raw const MARKER).cast::<OsslProvider>() as *mut OsslProvider;
            assert!(
                EVP_CIPHER_meth_dup(m).is_null(),
                "a provider method is refused rather than copied"
            );
            (*m).prov = ptr::null_mut();

            // Neither public destructor touches either object: both are `EVP_ORIG_METH`, and
            // `EVP_CIPHER_free` refuses anything that is not dynamic.
            EVP_CIPHER_free(m);
            EVP_CIPHER_free(d);
            assert_eq!(
                (*m).refcnt.load(Ordering::Acquire),
                1,
                "the count is untouched"
            );
            assert_eq!(
                (*d).refcnt.load(Ordering::Acquire),
                1,
                "and so is the duplicate's"
            );

            EVP_CIPHER_meth_free(d);
            EVP_CIPHER_meth_free(m);
        }
    }

    /// Every accessor that has a NULL arm answers its own identity rather than a shared zero, and
    /// the two that do not are marked in the module. This is the arm a caller meets first.
    #[test]
    fn the_null_arms_answer_their_own_identity() {
        // SAFETY: every argument is NULL, which is what each of these functions checks for.
        unsafe {
            assert_eq!(EVP_CIPHER_get_block_size(ptr::null()), 0);
            assert_eq!(EVP_CIPHER_get_flags(ptr::null()), 0);
            assert_eq!(EVP_CIPHER_get_iv_length(ptr::null()), 0);
            assert_eq!(EVP_CIPHER_get_nid(ptr::null()), NID_undef);
            assert_eq!(EVP_CIPHER_is_a(ptr::null(), c"aes-128-cbc".as_ptr()), 0);
            assert!(EVP_CIPHER_gettable_params(ptr::null()).is_null());
            assert!(EVP_CIPHER_settable_ctx_params(ptr::null()).is_null());
            assert!(EVP_CIPHER_gettable_ctx_params(ptr::null()).is_null());
        }
    }

    /// The type folding: the eight arms are one function's business and the fall-through is the
    /// other's. `NID_aes_128_cfb8` is not a type a caller should see; `NID_aes_128_cfb128` is.
    #[test]
    fn the_cipher_type_folds_the_aliases_and_tests_the_oid() {
        // SAFETY: this test owns the method it builds.
        unsafe {
            let m = EVP_CIPHER_meth_new(crate::runtime::obj::NID_aes_128_cfb8, 1, 16);
            assert_eq!(
                EVP_CIPHER_get_type(m),
                crate::runtime::obj::NID_aes_128_cfb128,
                "the cfb8 spelling is folded onto cfb128"
            );
            EVP_CIPHER_meth_free(m);

            // A NID the object database does not know has no OID, so the answer is `NID_undef`
            // rather than the value that was stored.
            let unknown = EVP_CIPHER_meth_new(1_000_000, 8, 8);
            assert_eq!(
                EVP_CIPHER_get_type(unknown),
                NID_undef,
                "an unknown NID has no OID and therefore no type"
            );
            EVP_CIPHER_meth_free(unknown);
        }
    }
}
