//! Phase 7.4 — the `EVP_PKEY_CTX` object.
//!
//! `crypto/evp/pmeth_lib.c`'s **object and registry halves**: the `EVP_PKEY_CTX` struct, its four
//! constructors, its lifetime, the operation-state test every operation init starts from, the
//! cached-data trio and the accessors — and, below those, the `EVP_PKEY_METHOD` struct with its
//! registry (`_new`, `_free`, `_copy`, `_get0_info`, `_add0`, `_remove`) and the forty
//! `EVP_PKEY_meth_get_*`/`set_*` accessors.
//!
//! **What is not here is the three exports that read `standard_methods[]`** —
//! `EVP_PKEY_meth_find`, `_get0` and `_get_count` — which are 7.4l's, because that table's
//! contents are Phase 8's `ossl_<alg>_pkey_method` objects (`docs/DECISIONS.md` D163, D165). The
//! *application* half of the registry landed here: `evp_pkey_meth_find_added_by_application` is
//! written and has no caller until `EVP_PKEY_meth_find` and `int_ctx_new`'s `app_pmeth` arm land,
//! so a caller that installs its own method with `EVP_PKEY_meth_add0` is reachable today while the
//! twelve built-in types are not.
//!
//! ## A context is one object with two halves, and `evp_pkey_ctx_state` is the switch
//!
//! `EVP_PKEY_CTX` carries a provider half (`keymgmt`, an `op` union holding one method object and
//! its algorithm context) and a legacy half (`pmeth`, `engine`, `data`). Which half is live is
//! decided *per operation* by `evp_pkey_ctx_state`, and it answers in three values:
//!
//! ```text
//! EVP_PKEY_STATE_UNKNOWN    operation == EVP_PKEY_OP_UNDEFINED
//! EVP_PKEY_STATE_PROVIDER   the operation has an algorithm context
//! EVP_PKEY_STATE_LEGACY     there is an operation but no algorithm context
//! ```
//!
//! The middle test is **five `&&`s over one union**, one per operation family, and the union member
//! it reads is the one that family uses. So a context whose operation is `EVP_PKEY_OP_SIGN` and
//! whose `op.sig.algctx` is set is PROVIDER, and the same context with the operation changed to
//! `EVP_PKEY_OP_UNDEFINED` is UNKNOWN — which is why every failed init resets the operation rather
//! than leaving the context in a half-built state.
//!
//! **The union is flattened here**, and the reason is worth stating: the authority overlaps the five
//! family members in one `union`, and nothing in the crate's reach ever observes the overlap — every
//! reader dispatches on `operation` first, and the fields are pointers whose *values* are what
//! matters. Flattening keeps the field names, which are the whole of what a reader needs, and gives
//! up a layout claim nothing makes. It is the one place in this file where the transcription is a
//! deliberate structural simplification rather than a copy.
//!
//! ## The cached data is three functions and one parameter
//!
//! `EVP_PKEY_CTRL_SET1_ID` is the only command whose value cannot be handed to a provider at the
//! time it is set: the operation has not been chosen yet, so there is nothing to send it to. The
//! context therefore **stores** it — `dist_id_name`, `dist_id`, `dist_id_len`, and a `dist_id_set`
//! bit — and replays it from the operation's init once the operation exists. The bit is the
//! contract: `evp_pkey_ctx_use_cached_data` tests it, and `evp_pkey_ctx_free_all_cached_data`
//! clears the two allocations it guards. A transcription that dropped the bit would replay a
//! distinguishing identifier of length zero on every init.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::bn::bignum::{BN_bn2nativepad, BN_num_bits, BigNum};
use crate::evp::asymcipher::{EVP_ASYM_CIPHER_get0_provider, EvpAsymCipher};
use crate::evp::cipher::{EVP_CIPHER_get0_name, EvpCipher};
use crate::evp::digest::{EVP_MD_get0_name, EvpMdCtx};
use crate::evp::exchange::{EVP_KEYEXCH_get0_provider, EvpKeyExch};
use crate::evp::kem::{EVP_KEM_get0_provider, EvpKem};
use crate::evp::keymgmt::{
    evp_keymgmt_get_legacy_alg, EVP_KEYMGMT_fetch, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_provider,
    EVP_KEYMGMT_is_a, EvpKeyMgmt,
};
use crate::evp::legacy_evp::{evp_get_cipherbyname_ex, evp_get_digestbyname_ex};
use crate::evp::pkey::{evp_pkey_name2type, EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::evp::pkey_asn1::Engine;
use crate::evp::signature::{EVP_SIGNATURE_get0_provider, EvpSignature};
use crate::params::from_text::OSSL_PARAM_allocate_from_text;
use crate::params::{
    OSSL_PARAM_construct_BN, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint, OSSL_PARAM_construct_utf8_ptr,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_BN, OSSL_PARAM_get_int,
    OSSL_PARAM_get_octet_ptr, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_set_BN, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string, OsslParam,
};
use crate::params::{
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::{ossl_provider_ctx, OsslProvider};
use crate::runtime::bio::sys::strlen;
use crate::runtime::err::raise_site_data;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_undef, OBJ_nid2sn};
use crate::runtime::obj::{OBJ_obj2txt, OBJ_txt2obj};
use crate::runtime::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::runtime::str::OPENSSL_strlcat;
use core::ffi::c_uint;

// ---------------------------------------------------------------------------------------------
// The operation bits and the state values.
//
// `include/openssl/evp.h` and `include/crypto/evp.h`. The operation field is a **bit set**, not an
// enumeration: an init stores one bit, and the `EVP_PKEY_CTX_IS_*_OP` tests are masks over several,
// which is what lets `EVP_PKEY_OP_TYPE_SIG` cover sign, signmsg, verify, verifymsg and the two
// context forms at once.
// ---------------------------------------------------------------------------------------------

/// `EVP_PKEY_OP_UNDEFINED` — and the only value for which the state is UNKNOWN.
pub(crate) const EVP_PKEY_OP_UNDEFINED: c_int = 0;
/// `EVP_PKEY_OP_PARAMGEN`.
pub(crate) const EVP_PKEY_OP_PARAMGEN: c_int = 1 << 1;
/// `EVP_PKEY_OP_KEYGEN`.
pub(crate) const EVP_PKEY_OP_KEYGEN: c_int = 1 << 2;
/// `EVP_PKEY_OP_FROMDATA`.
pub(crate) const EVP_PKEY_OP_FROMDATA: c_int = 1 << 3;
/// `EVP_PKEY_OP_SIGN`.
pub(crate) const EVP_PKEY_OP_SIGN: c_int = 1 << 4;
/// `EVP_PKEY_OP_VERIFY`.
pub(crate) const EVP_PKEY_OP_VERIFY: c_int = 1 << 5;
/// `EVP_PKEY_OP_VERIFYRECOVER`.
pub(crate) const EVP_PKEY_OP_VERIFYRECOVER: c_int = 1 << 6;
/// `EVP_PKEY_OP_SIGNCTX`.
pub(crate) const EVP_PKEY_OP_SIGNCTX: c_int = 1 << 7;
/// `EVP_PKEY_OP_VERIFYCTX`.
pub(crate) const EVP_PKEY_OP_VERIFYCTX: c_int = 1 << 8;
/// `EVP_PKEY_OP_ENCRYPT`.
pub(crate) const EVP_PKEY_OP_ENCRYPT: c_int = 1 << 9;
/// `EVP_PKEY_OP_DECRYPT`.
pub(crate) const EVP_PKEY_OP_DECRYPT: c_int = 1 << 10;
/// `EVP_PKEY_OP_DERIVE`.
pub(crate) const EVP_PKEY_OP_DERIVE: c_int = 1 << 11;
/// `EVP_PKEY_OP_ENCAPSULATE`.
pub(crate) const EVP_PKEY_OP_ENCAPSULATE: c_int = 1 << 12;
/// `EVP_PKEY_OP_DECAPSULATE`.
pub(crate) const EVP_PKEY_OP_DECAPSULATE: c_int = 1 << 13;
/// `EVP_PKEY_OP_SIGNMSG`.
pub(crate) const EVP_PKEY_OP_SIGNMSG: c_int = 1 << 14;
/// `EVP_PKEY_OP_VERIFYMSG`.
pub(crate) const EVP_PKEY_OP_VERIFYMSG: c_int = 1 << 15;
#[allow(dead_code)] // read by `EVP_PKEY_OP_TYPE_NOGEN`, which 7.4c-ii's ctrl path tests
/// `EVP_PKEY_OP_ALL` — every bit above, and the mask `EVP_PKEY_OP_TYPE_NOGEN` is built from.
pub(crate) const EVP_PKEY_OP_ALL: c_int = (1 << 16) - 1;
/// `EVP_PKEY_OP_TYPE_SIG` — six bits, and the reason the tests are masks.
pub(crate) const EVP_PKEY_OP_TYPE_SIG: c_int = EVP_PKEY_OP_SIGN
    | EVP_PKEY_OP_SIGNMSG
    | EVP_PKEY_OP_VERIFY
    | EVP_PKEY_OP_VERIFYMSG
    | EVP_PKEY_OP_VERIFYRECOVER
    | EVP_PKEY_OP_SIGNCTX
    | EVP_PKEY_OP_VERIFYCTX;
/// `EVP_PKEY_OP_TYPE_CRYPT`.
pub(crate) const EVP_PKEY_OP_TYPE_CRYPT: c_int = EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT;
/// `EVP_PKEY_OP_TYPE_DERIVE`.
pub(crate) const EVP_PKEY_OP_TYPE_DERIVE: c_int = EVP_PKEY_OP_DERIVE;
/// `EVP_PKEY_OP_TYPE_DATA`.
pub(crate) const EVP_PKEY_OP_TYPE_DATA: c_int = EVP_PKEY_OP_FROMDATA;
/// `EVP_PKEY_OP_TYPE_KEM`.
pub(crate) const EVP_PKEY_OP_TYPE_KEM: c_int = EVP_PKEY_OP_ENCAPSULATE | EVP_PKEY_OP_DECAPSULATE;
/// `EVP_PKEY_OP_TYPE_GEN`.
pub(crate) const EVP_PKEY_OP_TYPE_GEN: c_int = EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN;
#[allow(dead_code)] // read by `EVP_PKEY_CTX_ctrl`'s operation filter, which lands in 7.4c-ii
/// `EVP_PKEY_OP_TYPE_NOGEN` — every operation *except* the two generation ones.
pub(crate) const EVP_PKEY_OP_TYPE_NOGEN: c_int = EVP_PKEY_OP_ALL & !EVP_PKEY_OP_TYPE_GEN;

#[allow(dead_code)] // read by the operation inits' state tests, which land in 7.4b-iii and 7.4c-ii
/// `EVP_PKEY_STATE_UNKNOWN` — `include/crypto/evp.h`.
pub(crate) const EVP_PKEY_STATE_UNKNOWN: c_int = 0;
#[allow(dead_code)] // read by the operation inits' state tests, which land in 7.4b-iii and 7.4c-ii
/// `EVP_PKEY_STATE_LEGACY`.
pub(crate) const EVP_PKEY_STATE_LEGACY: c_int = 1;
#[allow(dead_code)] // read by the operation inits' state tests, which land in 7.4b-iii and 7.4c-ii
/// `EVP_PKEY_STATE_PROVIDER`.
pub(crate) const EVP_PKEY_STATE_PROVIDER: c_int = 2;

#[allow(dead_code)] // read by the cached-data store, whose caller `EVP_PKEY_CTX_ctrl_str` lands in 7.4c-ii
/// `EVP_PKEY_CTRL_SET1_ID` — the one command the cached-data machinery handles.
pub(crate) const EVP_PKEY_CTRL_SET1_ID: c_int = 13;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c".as_ptr();
/// `int_ctx_new`'s `OPENSSL_zalloc(sizeof(*ret))` (line 297).
const LINE_ZALLOC_CTX: c_int = 297;
/// `int_ctx_new`'s `OPENSSL_free(ret)` after a failed `OPENSSL_strdup` (line 312).
const LINE_FREE_CTX: c_int = 312;

/// `struct evp_pkey_ctx_st`'s `cached_parameters` member.
#[repr(C)]
pub struct CachedParameters {
    /// `char *dist_id_name` — the name the caller used, or NULL.
    pub(crate) dist_id_name: *mut c_char,
    /// `void *dist_id`.
    pub(crate) dist_id: *mut c_void,
    /// `size_t dist_id_len`.
    pub(crate) dist_id_len: usize,
    /// `unsigned int dist_id_set : 1` — the bit the replay test reads.
    pub(crate) dist_id_set: c_int,
}

/// `EVP_PKEY_gen_cb` — `typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx)`,
/// `include/openssl/evp.h:2076`.
///
/// A **named** alias rather than an inline `Option<unsafe extern "C" fn(...) -> c_int>`, and the
/// reason is measurable: `ABI-PROTOTYPE`'s Rust-side reader resolves a function-pointer return
/// through an alias it can name, and an inline spelling of the same type was rendered as
/// `fptr(void; ptr(opaque))` — a `void` return — and reported as a mismatch on
/// `EVP_PKEY_CTX_get_cb`. `BIO_meth_get_read -> Option<BioReadFn>` is the crate's precedent.
pub(crate) type EvpPkeyGenCb = unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int;

/// `struct evp_pkey_ctx_st` — `EVP_PKEY_CTX`, with the `op` union **flattened**.
///
/// See this module's documentation for why the flattening is a deliberate simplification: every
/// reader dispatches on `operation` before touching a family's members, so the overlap is
/// unobservable, and the field names are what a reader needs.
///
/// The legacy half is here as far as it can be — `legacy_keytype`, `data`, `app_data`,
/// `keygen_info`, `keygen_info_count`, `peerkey` — and `pmeth` and `engine` are absent because
/// `EVP_PKEY_METHOD` is 7.4l's and `ENGINE` is Phase 13's. Both are only ever read behind a
/// `pmeth != NULL` or `engine != NULL` test, so their absence makes those arms unreachable rather
/// than wrong, and each site says so.
#[repr(C)]
pub struct EvpPkeyCtx {
    /// `int operation` — the bit set `EVP_PKEY_OP_*` names.
    pub(crate) operation: c_int,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propquery` — owned.
    pub(crate) propquery: *mut c_char,
    /// `const char *keytype` — **not** owned; it points at the caller's name or at a method's.
    pub(crate) keytype: *const c_char,
    /// `EVP_KEYMGMT *keymgmt` — holding a reference.
    pub(crate) keymgmt: *mut EvpKeyMgmt,

    /// `op.keymgmt.genctx` — the generation context, when the operation is a generation one.
    pub(crate) op_keymgmt_genctx: *mut c_void,
    /// `op.kex.exchange` — the key exchange method, holding a reference.
    pub(crate) op_kex_exchange: *mut EvpKeyExch,
    /// `op.kex.algctx`.
    pub(crate) op_kex_algctx: *mut c_void,
    /// `op.sig.signature` — the signature method, holding a reference.
    pub(crate) op_sig_signature: *mut EvpSignature,
    /// `op.sig.algctx`.
    pub(crate) op_sig_algctx: *mut c_void,
    /// `op.ciph.cipher` — the asymmetric cipher method, holding a reference.
    pub(crate) op_ciph_cipher: *mut EvpAsymCipher,
    /// `op.ciph.algctx`.
    pub(crate) op_ciph_algctx: *mut c_void,
    /// `op.encap.kem` — the KEM method, holding a reference.
    pub(crate) op_encap_kem: *mut EvpKem,
    /// `op.encap.algctx`.
    pub(crate) op_encap_algctx: *mut c_void,

    /// `cached_parameters`.
    pub(crate) cached_parameters: CachedParameters,
    /// `void *app_data`.
    pub(crate) app_data: *mut c_void,
    /// `EVP_PKEY_gen_cb *pkey_gencb`.
    pub(crate) pkey_gencb: Option<EvpPkeyGenCb>,
    /// `int *keygen_info` — the caller's array, **not** owned.
    pub(crate) keygen_info: *mut c_int,
    /// `int keygen_info_count`.
    pub(crate) keygen_info_count: c_int,
    /// `int legacy_keytype`.
    pub(crate) legacy_keytype: c_int,
    /// `EVP_PKEY *pkey` — holding a reference, or NULL.
    pub(crate) pkey: *mut EvpPkey,
    /// `EVP_PKEY *peerkey` — holding a reference, or NULL.
    pub(crate) peerkey: *mut EvpPkey,
    /// `void *data` — algorithm-specific, owned by whoever set it.
    pub(crate) data: *mut c_void,
}

impl EvpPkeyCtx {
    /// `EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)`.
    fn is_signature_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_SIG) != 0
    }

    /// `EVP_PKEY_CTX_IS_DERIVE_OP(ctx)`.
    pub(crate) fn is_derive_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_DERIVE) != 0
    }

    /// `EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)`.
    fn is_asym_cipher_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_CRYPT) != 0
    }

    /// `EVP_PKEY_CTX_IS_GEN_OP(ctx)`.
    fn is_gen_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_GEN) != 0
    }

    /// `EVP_PKEY_CTX_IS_KEM_OP(ctx)`.
    pub(crate) fn is_kem_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_KEM) != 0
    }

    /// `#define evp_pkey_ctx_is_legacy(ctx)` — `include/crypto/evp.h:35`.
    ///
    /// **A header macro, and not what its name suggests**: its body is `((ctx)->keymgmt == NULL)`,
    /// not `pmeth != NULL`. That distinction is what makes the test *reachable* in this crate, whose
    /// `pmeth` is always NULL while its `keymgmt` is not always set — so a branch guarded by this
    /// macro is live here even though the label it jumps to, which builds a legacy `EVP_PKEY_CTX`,
    /// is not representable at all. `docs/DECISIONS.md` D168 records what reading it by its name
    /// would have cost.
    pub(crate) fn is_legacy(&self) -> bool {
        self.keymgmt.is_null()
    }

    /// `EVP_PKEY_CTX_IS_FROMDATA_OP(ctx)`.
    #[allow(dead_code)] // read by `evp_keymgmt_util_fromdata`'s caller in 7.4c-ii
    fn is_fromdata_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_DATA) != 0
    }
}

#[allow(dead_code)] // read by the cached-data store and every operation init; the first lands in 7.4c-ii
/// `int evp_pkey_ctx_state(const EVP_PKEY_CTX *ctx)`.
///
/// Three values, and the middle test is **five families over one union**: the context is PROVIDER
/// when the operation's own family has an algorithm context and LEGACY otherwise. The `&&` in each
/// clause is what makes an operation bit without a context a *legacy* state rather than an error —
/// which is the state a failed provider init leaves behind before it resets the operation.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn evp_pkey_ctx_state(ctx: *const EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let ctx = unsafe { &*ctx };
    if ctx.operation == EVP_PKEY_OP_UNDEFINED {
        return EVP_PKEY_STATE_UNKNOWN;
    }

    if (ctx.is_derive_op() && !ctx.op_kex_algctx.is_null())
        || (ctx.is_signature_op() && !ctx.op_sig_algctx.is_null())
        || (ctx.is_asym_cipher_op() && !ctx.op_ciph_algctx.is_null())
        || (ctx.is_gen_op() && !ctx.op_keymgmt_genctx.is_null())
        || (ctx.is_kem_op() && !ctx.op_encap_algctx.is_null())
    {
        return EVP_PKEY_STATE_PROVIDER;
    }

    EVP_PKEY_STATE_LEGACY
}

/// `static EVP_PKEY_CTX *int_ctx_new(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey, ENGINE *e,
/// const char *keytype, const char *propquery, int id)`.
///
/// The **provider path only**, and the parts that are absent are absent for three different reasons
/// that are worth separating because a reader will meet all three again:
///
///   * **`ENGINE`** is Phase 13's, so the four `e`-dependent clauses — the engine lookup, the
///     `ENGINE_init`, the `ENGINE_get_pkey_meth_engine`, and the `ENGINE_finish` on the failure path
///     — are all unreachable. `e == NULL` is the only call this crate can make, and with it the
///     authority's own `if (e != NULL)` guards are dead.
///   * **`EVP_PKEY_METHOD`** is 7.4l's (`evp_pkey_meth_find_added_by_application`, `EVP_PKEY_meth_find`,
///     and the `pmeth->init` call at the end), so `pmeth` stays NULL and the `app_pmeth == NULL` test
///     that gates the fetch is always true.
///   * **`pkey->foreign`** is a legacy attribute and is always 0 here, which is what makes
///     `keytype = OBJ_nid2sn(id)` reachable for a key whose type is known.
///
/// What remains is the real shape, and three of its statements are contract:
///
///   1. **`id == -1` with a provided `pkey` takes the key's own method name**, so
///      `EVP_PKEY_CTX_new_from_pkey` asks for the key's *type name* rather than for a new method.
///   2. the fetch is **`EVP_KEYMGMT_fetch(libctx, keytype, propquery)`**, and a failure returns
///      immediately — `EVP_KEYMGMT_fetch` has already recorded the error, and this function adds
///      none.
///   3. `ossl_assert(id == tmp_id)` is `(id == tmp_id) != 0` under `NDEBUG`, so the released
///      authority **refuses** a disagreement between the caller's `id` and the method's
///      `legacy_alg`: `ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR)`, the method freed, NULL. The
///      crate raises the same site and takes the same cleanup, so the two agree. An earlier
///      revision of this comment claimed the released authority *accepted* the disagreement and
///      that the crate diverged; the authority binary disagrees, and the measurement is in
///      `docs/DECISIONS.md` D167.
///
/// # Safety
/// `libctx` NULL or live; `pkey` NULL or live; `keytype` and `propquery` NULL or NUL-terminated.
unsafe fn int_ctx_new(
    libctx: *mut c_void,
    pkey: *mut EvpPkey,
    keytype: *const c_char,
    propquery: *const c_char,
    id: c_int,
) -> *mut EvpPkeyCtx {
    let mut id = id;
    let mut keytype = keytype;
    let mut keymgmt: *mut EvpKeyMgmt = ptr::null_mut();

    if id == -1 {
        if !pkey.is_null() {
            // SAFETY: `pkey` is live; with no legacy origin, "not provided" is unreachable.
            let pkey_keymgmt = unsafe { (*pkey).keymgmt };
            if !pkey_keymgmt.is_null() {
                // SAFETY: `pkey_keymgmt` is live.
                keytype = unsafe { crate::evp::keymgmt::EVP_KEYMGMT_get0_name(pkey_keymgmt) };
            }
        }
        if !keytype.is_null() {
            // SAFETY: `keytype` is NUL-terminated.
            id = unsafe { evp_pkey_name2type(keytype) };
            if id == NID_undef {
                id = -1;
            }
        }
    }

    if id != -1 {
        /* `e == NULL` and not foreign, so the authority's `keytype = OBJ_nid2sn(id)` runs for every
         * key this crate can build; the test that guards it there is a legacy attribute. */
        keytype = OBJ_nid2sn(id);
        /* `app_pmeth = pmeth = evp_pkey_meth_find_added_by_application(id)` is 7.4l's, so `app_pmeth`
         * stays NULL — which is what makes the fetch below unconditional. */
    }

    /* `common:` — fetch a provider implementation when there is no engine, no application-supplied
     * method and a name. */
    if !keytype.is_null() {
        // SAFETY: `pkey` is NULL or live per this function's contract.
        let pkey_is_provided = unsafe { !pkey.is_null() && !(*pkey).keymgmt.is_null() };
        if pkey_is_provided {
            // SAFETY: `pkey` is live.
            let pkey_keymgmt = unsafe { (*pkey).keymgmt };
            // SAFETY: `pkey_keymgmt` is live.
            if unsafe { crate::evp::keymgmt::EVP_KEYMGMT_up_ref(pkey_keymgmt) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PMETH_LIB_255) };
            } else {
                keymgmt = pkey_keymgmt;
            }
        } else {
            // SAFETY: `libctx` is NULL or live and `keytype`/`propquery` are NULL or NUL-terminated.
            keymgmt = unsafe { EVP_KEYMGMT_fetch(libctx, keytype, propquery) };
        }
        if keymgmt.is_null() {
            /* `EVP_KEYMGMT_fetch()` recorded an error. */
            return ptr::null_mut();
        }

        // SAFETY: `keymgmt` is live.
        let tmp_id = unsafe { evp_keymgmt_get_legacy_alg(keymgmt) };
        if tmp_id != NID_undef {
            if id == -1 {
                id = tmp_id;
            } else if id != tmp_id {
                /* `!ossl_assert(id == tmp_id)` under `NDEBUG` is `id != tmp_id`, so the released
                 * authority refuses here too: this raise, then the free below, then NULL. It is
                 * the authority's behaviour and not a divergence from it (`docs/DECISIONS.md`
                 * D167). */
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PMETH_LIB_284) };
                // SAFETY: `keymgmt` is live and holds the reference taken above.
                unsafe { EVP_KEYMGMT_free(keymgmt) };
                return ptr::null_mut();
            }
        }
    }

    if keymgmt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_295) };
        return ptr::null_mut();
    }

    /* SAFETY: this allocates a fresh object and reads nothing. */
    let ret = CRYPTO_zalloc(core::mem::size_of::<EvpPkeyCtx>(), FILE, LINE_ZALLOC_CTX)
        .cast::<EvpPkeyCtx>();
    if ret.is_null() {
        // SAFETY: `keymgmt` is live and holds the reference taken above.
        unsafe { EVP_KEYMGMT_free(keymgmt) };
        return ptr::null_mut();
    }
    if !propquery.is_null() {
        // SAFETY: `propquery` is NUL-terminated.
        // SAFETY: `propquery` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(propquery, FILE, LINE_FREE_CTX) };
        if dup.is_null() {
            // SAFETY: `ret` is this call's own allocation.
            unsafe { CRYPTO_free(ret.cast(), FILE, LINE_FREE_CTX) };
            // SAFETY: `keymgmt` is live and holds the reference taken above.
            unsafe { EVP_KEYMGMT_free(keymgmt) };
            return ptr::null_mut();
        }
        // SAFETY: `ret` is live.
        unsafe { (*ret).propquery = dup };
    }
    // SAFETY: `ret` is this call's own object and every field is private to it.
    unsafe {
        (*ret).libctx = libctx;
        (*ret).keytype = keytype;
        (*ret).keymgmt = keymgmt;
        (*ret).legacy_keytype = id;
        (*ret).operation = EVP_PKEY_OP_UNDEFINED;
    }

    if !pkey.is_null() {
        // SAFETY: `pkey` is live.
        if unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
            // SAFETY: `ret` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: `ret` is live.
        unsafe { (*ret).pkey = pkey };
    }

    /* `if (pmeth != NULL && pmeth->init != NULL)` is 7.4l's: `pmeth` is always NULL here. */
    ret
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)` —
/// `crypto/evp/pmeth_lib.c:442`.
///
/// `int_ctx_new(NULL, pkey, e, NULL, NULL, -1)` — the authority's own six arguments, three of them
/// NULL and the id `-1`, which is the "take the method from the key" case. The `-1` is the
/// authority's and not a stand-in: `int_ctx_new` reads it as "no explicit id" and falls through to
/// the key's own type.
///
/// `e` **is not forwarded**, because there is no engine: `ENGINE` is Phase 13's, so nothing in this
/// crate can pass a non-NULL one, and the authority's own `int_ctx_new` reaches the same state with
/// NULL. See the module doc's note on the engine arm of the two `asn1_find` functions for the same
/// argument.
///
/// # Safety
/// `pkey` NULL or live; `e` NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new(pkey: *mut EvpPkey, e: *mut Engine) -> *mut EvpPkeyCtx {
    /* `e` is read only to be discarded, which is what keeps the signature the authority's. A
     * non-NULL engine cannot occur: nothing in this crate can construct an `ENGINE`. */
    let _ = e;
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { int_ctx_new(ptr::null_mut(), pkey, ptr::null(), ptr::null(), -1) }
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e)` — `crypto/evp/pmeth_lib.c:447`.
///
/// `int_ctx_new(NULL, NULL, e, NULL, NULL, id)` — a NULL key and an explicit id, which is the
/// "build the method from the type" case. The engine arm is absent for the reason `EVP_PKEY_CTX_new`
/// gives.
///
/// # Safety
/// `e` NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut Engine) -> *mut EvpPkeyCtx {
    let _ = e;
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        int_ctx_new(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            id,
        )
    }
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name,
/// const char *propquery)`.
///
/// # Safety
/// `libctx` NULL or live; `name` and `propquery` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_name(
    libctx: *mut c_void,
    name: *const c_char,
    propquery: *const c_char,
) -> *mut EvpPkeyCtx {
    // SAFETY: the arguments are forwarded under this function's contract; the `-1` id is the
    // authority's own for this constructor.
    unsafe { int_ctx_new(libctx, ptr::null_mut(), name, propquery, -1) }
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
/// const char *propquery)`.
///
/// # Safety
/// `libctx` NULL or live; `pkey` NULL or live; `propquery` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_from_pkey(
    libctx: *mut c_void,
    pkey: *mut EvpPkey,
    propquery: *const c_char,
) -> *mut EvpPkeyCtx {
    // SAFETY: the arguments are forwarded under this function's contract; the NULL `keytype` is
    // what makes the constructor take the key's own method name.
    unsafe { int_ctx_new(libctx, pkey, ptr::null(), propquery, -1) }
}

/// `void evp_pkey_ctx_free_old_ops(EVP_PKEY_CTX *ctx)`.
///
/// The five-arm release, and **the operation selects the arm** — which is why the arms are `else if`
/// rather than independent tests: a context has exactly one live family, and releasing two would
/// release the same union twice. Four of the arms release a method object and its algorithm context
/// in that order, and the fifth releases the *keymgmt* generation context through the method's own
/// `gen_cleanup`, because a generation context belongs to the keymgmt rather than to a method of its
/// own.
///
/// Note that only the **KEM** and **asym cipher** arms test both pointers before calling `freectx`;
/// the key exchange and signature arms test the algorithm context and then the method. The asymmetry
/// is the authority's and it is harmless in the same way for all four — a `freectx` with a NULL
/// context is not called — but the arms are transcribed as written rather than normalised.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn evp_pkey_ctx_free_old_ops(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let c = unsafe { &mut *ctx };
    if c.is_signature_op() {
        if !c.op_sig_algctx.is_null() && !c.op_sig_signature.is_null() {
            // SAFETY: both are live and the method's `freectx` is the provider's own.
            unsafe { signature_freectx(c.op_sig_signature, c.op_sig_algctx) };
        }
        // SAFETY: `op_sig_signature` is live or NULL.
        unsafe { crate::evp::signature::EVP_SIGNATURE_free(c.op_sig_signature) };
        c.op_sig_algctx = ptr::null_mut();
        c.op_sig_signature = ptr::null_mut();
    } else if c.is_derive_op() {
        if !c.op_kex_algctx.is_null() && !c.op_kex_exchange.is_null() {
            // SAFETY: both are live and the method's `freectx` is the provider's own.
            unsafe { keyexch_freectx(c.op_kex_exchange, c.op_kex_algctx) };
        }
        // SAFETY: `op_kex_exchange` is live or NULL.
        unsafe { crate::evp::exchange::EVP_KEYEXCH_free(c.op_kex_exchange) };
        c.op_kex_algctx = ptr::null_mut();
        c.op_kex_exchange = ptr::null_mut();
    } else if c.is_kem_op() {
        if !c.op_encap_algctx.is_null() && !c.op_encap_kem.is_null() {
            // SAFETY: both are live and the method's `freectx` is the provider's own.
            unsafe { kem_freectx(c.op_encap_kem, c.op_encap_algctx) };
        }
        // SAFETY: `op_encap_kem` is live or NULL.
        unsafe { crate::evp::kem::EVP_KEM_free(c.op_encap_kem) };
        c.op_encap_algctx = ptr::null_mut();
        c.op_encap_kem = ptr::null_mut();
    } else if c.is_asym_cipher_op() {
        if !c.op_ciph_algctx.is_null() && !c.op_ciph_cipher.is_null() {
            // SAFETY: both are live and the method's `freectx` is the provider's own.
            unsafe { asym_cipher_freectx(c.op_ciph_cipher, c.op_ciph_algctx) };
        }
        // SAFETY: `op_ciph_cipher` is live or NULL.
        unsafe { crate::evp::asymcipher::EVP_ASYM_CIPHER_free(c.op_ciph_cipher) };
        c.op_ciph_algctx = ptr::null_mut();
        c.op_ciph_cipher = ptr::null_mut();
    } else if c.is_gen_op() && !c.op_keymgmt_genctx.is_null() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live and `op_keymgmt_genctx` belongs to it.
        unsafe { crate::evp::keymgmt::evp_keymgmt_gen_cleanup(c.keymgmt, c.op_keymgmt_genctx) };
    }
}

/// Call a signature method's `freectx`, which the provider may not publish.
///
/// # Safety
/// `signature` and `algctx` must be live and the context must belong to the method.
unsafe fn signature_freectx(signature: *const EvpSignature, algctx: *mut c_void) {
    // SAFETY: `signature` is live per the contract.
    if let Some(f) = unsafe { (*signature).freectx } {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f(algctx) };
    }
}

/// Call a key exchange method's `freectx`.
///
/// # Safety
/// See [`signature_freectx`].
unsafe fn keyexch_freectx(exchange: *const EvpKeyExch, algctx: *mut c_void) {
    // SAFETY: `exchange` is live per the contract.
    if let Some(f) = unsafe { (*exchange).freectx } {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f(algctx) };
    }
}

/// Call a KEM method's `freectx`.
///
/// # Safety
/// See [`signature_freectx`].
unsafe fn kem_freectx(kem: *const EvpKem, algctx: *mut c_void) {
    // SAFETY: `kem` is live per the contract.
    if let Some(f) = unsafe { (*kem).freectx } {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f(algctx) };
    }
}

/// Call an asymmetric cipher method's `freectx`.
///
/// # Safety
/// See [`signature_freectx`].
unsafe fn asym_cipher_freectx(cipher: *const EvpAsymCipher, algctx: *mut c_void) {
    // SAFETY: `cipher` is live per the contract.
    if let Some(f) = unsafe { (*cipher).freectx } {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f(algctx) };
    }
}

/// `static void evp_pkey_ctx_free_cached_data(EVP_PKEY_CTX *ctx, int cmd, const char *name)`.
///
/// One command, and the free is **unconditional on both pointers**: `CRYPTO_free` tolerates NULL, so
/// a store that failed half way leaves no state to check. The two fields are cleared as well as
/// freed, because the `dist_id_set` bit is *not* cleared here — that is the caller's, and
/// `evp_pkey_ctx_free_all_cached_data` deliberately leaves the bit alone too.
///
/// # Safety
/// `ctx` must be live.
unsafe fn evp_pkey_ctx_free_cached_data(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    let c = unsafe { &mut *ctx };
    // SAFETY: both pointers are NULL or allocations this context owns.
    unsafe {
        CRYPTO_free(c.cached_parameters.dist_id, FILE, LINE_FREE_CTX);
        CRYPTO_free(c.cached_parameters.dist_id_name.cast(), FILE, LINE_FREE_CTX);
    }
    c.cached_parameters.dist_id = ptr::null_mut();
    c.cached_parameters.dist_id_name = ptr::null_mut();
}

/// `static void evp_pkey_ctx_free_all_cached_data(EVP_PKEY_CTX *ctx)` — the whole of it, and it does
/// **not** clear `dist_id_set`; see `evp_pkey_ctx_free_cached_data`.
///
/// # Safety
/// `ctx` must be live.
#[allow(dead_code)] // reached only from `EVP_PKEY_CTX_free` below and from the operation inits of 7.4c-ii
pub(crate) unsafe fn evp_pkey_ctx_free_all_cached_data(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_ctx_free_cached_data(ctx) };
}

/// `void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)`.
///
/// The release order is the authority's and two of its steps are load-bearing:
///
///   * **the old operations are released before the cached data**, so a `ctrl_str` that would replay
///     the distinguishing identifier has nothing left to replay it into;
///   * **the cached data is released before the keymgmt**, and `peerkey` before `pkey` — the second
///     because a peer key may hold a reference to the pkey's data and the authority documents the
///     order by writing it that way.
///
/// `ctx->pmeth->cleanup` and `ENGINE_finish(ctx->engine)` are absent: the first is 7.4l's and the
/// second is Phase 13's, and both are guarded by a NULL test in the authority.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_free(ctx: *mut EvpPkeyCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_cached_data(ctx) };
    // SAFETY: `ctx` is live.
    let (keymgmt, propquery, pkey, peerkey) = unsafe {
        (
            (*ctx).keymgmt,
            (*ctx).propquery,
            (*ctx).pkey,
            (*ctx).peerkey,
        )
    };
    // SAFETY: `keymgmt` is NULL or a method holding this context's reference.
    unsafe { EVP_KEYMGMT_free(keymgmt) };
    // SAFETY: `propquery` is NULL or an allocation this context owns.
    unsafe { CRYPTO_free(propquery.cast(), FILE, LINE_FREE_CTX) };
    // SAFETY: both keys are NULL or hold a reference taken by `int_ctx_new` or by the peer setter.
    unsafe {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peerkey);
    }
    /* `BN_free(ctx->rsa_pubexp)` is dead here: nothing in this crate sets it, and its only setter is
     * the deprecated `EVP_PKEY_CTX_set_rsa_keygen_pubexp`, which is Phase 8's. */
    // SAFETY: `ctx` is this object's own allocation.
    unsafe { CRYPTO_free(ctx.cast(), FILE, LINE_FREE_CTX) };
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_dup(const EVP_PKEY_CTX *pctx)`.
///
/// The **five-arm** duplication, and it is a different five from `free_old_ops`': the generation arm
/// is a refusal ("Not supported - This would need a `gen_dupctx()` to work") and there is no arm for
/// the `FROMDATA` operation at all. A context mid-operation whose family publishes a duplicator is
/// returned **immediately** from inside its arm, because the copy has already happened; a context
/// mid-operation whose family publishes *none* is a failure, not a shallow copy.
///
/// The two paths that do not return early are the interesting ones:
///
///   * a provider context with **no live operation** re-exports the key through
///     `evp_pkey_export_to_provider` and installs the resulting method, which is why duplicating an
///     unused context can *change* its method;
///   * a context whose `pkey` is NULL returns the copy as it stands.
///
/// `pctx->pmeth->copy(rctx, pctx)` and the `ENGINE_init(pctx->engine)` guard are absent: the first
/// is 7.4l's and the second is Phase 13's.
///
/// # Safety
/// `pctx` must be NULL or live; the answer, if non-NULL, is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_dup(pctx: *const EvpPkeyCtx) -> *mut EvpPkeyCtx {
    if pctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pctx` is live per the contract.
    let src = unsafe { &*pctx };

    // SAFETY: this allocates a fresh object and reads nothing.
    let rctx = CRYPTO_zalloc(core::mem::size_of::<EvpPkeyCtx>(), FILE, LINE_ZALLOC_CTX)
        .cast::<EvpPkeyCtx>();
    if rctx.is_null() {
        return ptr::null_mut();
    }

    if !src.pkey.is_null() {
        // SAFETY: `pkey` is live.
        if unsafe { EVP_PKEY_up_ref(src.pkey) } == 0 {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `rctx` is this call's own object.
    unsafe {
        (*rctx).pkey = src.pkey;
        (*rctx).operation = src.operation;
        (*rctx).libctx = src.libctx;
        (*rctx).keytype = src.keytype;
        (*rctx).legacy_keytype = src.legacy_keytype;
    }
    if !src.propquery.is_null() {
        // SAFETY: `propquery` is NUL-terminated.
        // SAFETY: `propquery` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(src.propquery, FILE, LINE_FREE_CTX) };
        if dup.is_null() {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
        // SAFETY: `rctx` is live.
        unsafe { (*rctx).propquery = dup };
    }

    if !src.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        if unsafe { crate::evp::keymgmt::EVP_KEYMGMT_up_ref(src.keymgmt) } == 0 {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
        // SAFETY: `rctx` is live.
        unsafe { (*rctx).keymgmt = src.keymgmt };
    }

    if src.is_derive_op() {
        // SAFETY: `rctx` is this call's own object.
        let r = unsafe { &mut *rctx };
        if !src.op_kex_exchange.is_null() {
            r.op_kex_exchange = src.op_kex_exchange;
            // SAFETY: `op_kex_exchange` is live.
            if unsafe { crate::evp::exchange::EVP_KEYEXCH_up_ref(r.op_kex_exchange) } == 0 {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
        }
        if !src.op_kex_algctx.is_null() {
            /* `!ossl_assert(pctx->op.kex.exchange != NULL)` under `NDEBUG` is `exchange == NULL`,
             * so the authority refuses here -- `goto err` -- and never reaches the duplicator. The
             * crate refuses at the same point, with the same result (`docs/DECISIONS.md` D167). */
            if src.op_kex_exchange.is_null() {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            // SAFETY: both are live and the duplicator is the provider's own.
            r.op_kex_algctx = unsafe { keyexch_dupctx(src.op_kex_exchange, src.op_kex_algctx) };
            if r.op_kex_algctx.is_null() {
                // SAFETY: `r.op_kex_exchange` is live and holds the reference taken above.
                unsafe { crate::evp::exchange::EVP_KEYEXCH_free(r.op_kex_exchange) };
                r.op_kex_exchange = ptr::null_mut();
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            return rctx;
        }
    } else if src.is_signature_op() {
        // SAFETY: `rctx` is this call's own object.
        let r = unsafe { &mut *rctx };
        if !src.op_sig_signature.is_null() {
            r.op_sig_signature = src.op_sig_signature;
            // SAFETY: `op_sig_signature` is live.
            if unsafe { crate::evp::signature::EVP_SIGNATURE_up_ref(r.op_sig_signature) } == 0 {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
        }
        if !src.op_sig_algctx.is_null() {
            if src.op_sig_signature.is_null() {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            // SAFETY: both are live and the duplicator is the provider's own.
            r.op_sig_algctx = unsafe { signature_dupctx(src.op_sig_signature, src.op_sig_algctx) };
            if r.op_sig_algctx.is_null() {
                // SAFETY: `r.op_sig_signature` is live and holds the reference taken above.
                unsafe { crate::evp::signature::EVP_SIGNATURE_free(r.op_sig_signature) };
                r.op_sig_signature = ptr::null_mut();
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            return rctx;
        }
    } else if src.is_asym_cipher_op() {
        // SAFETY: `rctx` is this call's own object.
        let r = unsafe { &mut *rctx };
        if !src.op_ciph_cipher.is_null() {
            r.op_ciph_cipher = src.op_ciph_cipher;
            // SAFETY: `op_ciph_cipher` is live.
            if unsafe { crate::evp::asymcipher::EVP_ASYM_CIPHER_up_ref(r.op_ciph_cipher) } == 0 {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
        }
        if !src.op_ciph_algctx.is_null() {
            if src.op_ciph_cipher.is_null() {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            // SAFETY: both are live and the duplicator is the provider's own.
            r.op_ciph_algctx =
                unsafe { asym_cipher_dupctx(src.op_ciph_cipher, src.op_ciph_algctx) };
            if r.op_ciph_algctx.is_null() {
                // SAFETY: `r.op_ciph_cipher` is live and holds the reference taken above.
                unsafe { crate::evp::asymcipher::EVP_ASYM_CIPHER_free(r.op_ciph_cipher) };
                r.op_ciph_cipher = ptr::null_mut();
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            return rctx;
        }
    } else if src.is_kem_op() {
        // SAFETY: `rctx` is this call's own object.
        let r = unsafe { &mut *rctx };
        if !src.op_encap_kem.is_null() {
            r.op_encap_kem = src.op_encap_kem;
            // SAFETY: `op_encap_kem` is live.
            if unsafe { crate::evp::kem::EVP_KEM_up_ref(r.op_encap_kem) } == 0 {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
        }
        if !src.op_encap_algctx.is_null() {
            if src.op_encap_kem.is_null() {
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            // SAFETY: both are live and the duplicator is the provider's own.
            r.op_encap_algctx = unsafe { kem_dupctx(src.op_encap_kem, src.op_encap_algctx) };
            if r.op_encap_algctx.is_null() {
                // SAFETY: `r.op_encap_kem` is live and holds the reference taken above.
                unsafe { crate::evp::kem::EVP_KEM_free(r.op_encap_kem) };
                r.op_encap_kem = ptr::null_mut();
                // SAFETY: `rctx` is this call's own object.
                unsafe { EVP_PKEY_CTX_free(rctx) };
                return ptr::null_mut();
            }
            return rctx;
        }
    } else if src.is_gen_op() {
        /* "Not supported - This would need a gen_dupctx() to work." */
        // SAFETY: `rctx` is this call's own object.
        unsafe { EVP_PKEY_CTX_free(rctx) };
        return ptr::null_mut();
    }

    if !src.peerkey.is_null() {
        // SAFETY: `peerkey` is live.
        if unsafe { EVP_PKEY_up_ref(src.peerkey) } == 0 {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `rctx` is this call's own object.
    unsafe { (*rctx).peerkey = src.peerkey };

    if src.operation == EVP_PKEY_OP_UNDEFINED && !src.pkey.is_null() {
        let mut tmp_keymgmt = src.keymgmt;
        // SAFETY: `pkey` is live and `tmp_keymgmt` is live; the out-parameter is a live local.
        let provkey = unsafe {
            crate::evp::pkey::evp_pkey_export_to_provider(
                src.pkey,
                src.libctx,
                ptr::addr_of_mut!(tmp_keymgmt),
                src.propquery,
            )
        };
        if provkey.is_null() {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
        // SAFETY: `tmp_keymgmt` is live.
        if unsafe { crate::evp::keymgmt::EVP_KEYMGMT_up_ref(tmp_keymgmt) } == 0 {
            // SAFETY: `rctx` is this call's own object.
            unsafe { EVP_PKEY_CTX_free(rctx) };
            return ptr::null_mut();
        }
        // SAFETY: `rctx` is live.
        let previous = unsafe { (*rctx).keymgmt };
        // SAFETY: `previous` is NULL or holds the reference taken above.
        unsafe { EVP_KEYMGMT_free(previous) };
        // SAFETY: `rctx` is live.
        unsafe { (*rctx).keymgmt = tmp_keymgmt };
        return rctx;
    }
    if !src.pkey.is_null() && src.operation == EVP_PKEY_OP_UNDEFINED {
        return rctx;
    }

    /* `pctx->pmeth->copy(rctx, pctx)` is 7.4l's. With no `pmeth`, the authority reaches `err:` only
     * through a legacy context, which this crate cannot construct. */
    // SAFETY: `rctx` is this call's own object.
    unsafe { EVP_PKEY_CTX_free(rctx) };
    ptr::null_mut()
}

/// Call a key exchange method's `dupctx`.
///
/// # Safety
/// `exchange` and `algctx` must be live and the context must belong to the method.
unsafe fn keyexch_dupctx(exchange: *const EvpKeyExch, algctx: *mut c_void) -> *mut c_void {
    // SAFETY: `exchange` is live per the contract.
    match unsafe { (*exchange).dupctx } {
        // SAFETY: the duplicator is the provider's own and `algctx` is its context.
        Some(f) => unsafe { f(algctx) },
        None => ptr::null_mut(),
    }
}

/// Call a signature method's `dupctx`.
///
/// # Safety
/// See [`keyexch_dupctx`].
unsafe fn signature_dupctx(signature: *const EvpSignature, algctx: *mut c_void) -> *mut c_void {
    // SAFETY: `signature` is live per the contract.
    match unsafe { (*signature).dupctx } {
        // SAFETY: the duplicator is the provider's own and `algctx` is its context.
        Some(f) => unsafe { f(algctx) },
        None => ptr::null_mut(),
    }
}

/// Call an asymmetric cipher method's `dupctx`.
///
/// # Safety
/// See [`keyexch_dupctx`].
unsafe fn asym_cipher_dupctx(cipher: *const EvpAsymCipher, algctx: *mut c_void) -> *mut c_void {
    // SAFETY: `cipher` is live per the contract.
    match unsafe { (*cipher).dupctx } {
        // SAFETY: the duplicator is the provider's own and `algctx` is its context.
        Some(f) => unsafe { f(algctx) },
        None => ptr::null_mut(),
    }
}

/// Call a KEM method's `dupctx`.
///
/// # Safety
/// See [`keyexch_dupctx`].
unsafe fn kem_dupctx(kem: *const EvpKem, algctx: *mut c_void) -> *mut c_void {
    // SAFETY: `kem` is live per the contract.
    match unsafe { (*kem).dupctx } {
        // SAFETY: the duplicator is the provider's own and `algctx` is its context.
        Some(f) => unsafe { f(algctx) },
        None => ptr::null_mut(),
    }
}

/// `void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen)`.
///
/// The array is the **caller's** and is stored without a copy, which is why the setter is `set0`:
/// the caller must keep it alive for the context's lifetime.
///
/// # Safety
/// `ctx` must be live; `dat` NULL or an array of `datlen` ints.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_keygen_info(
    ctx: *mut EvpPkeyCtx,
    dat: *mut c_int,
    datlen: c_int,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).keygen_info = dat;
        (*ctx).keygen_info_count = datlen;
    }
}

/// `void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_app_data(ctx: *mut EvpPkeyCtx, data: *mut c_void) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).app_data = data };
}

/// `void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_app_data(ctx: *mut EvpPkeyCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).app_data }
}

/// `void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_data(ctx: *mut EvpPkeyCtx, data: *mut c_void) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).data = data };
}

/// `void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_data(ctx: *const EvpPkeyCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).data }
}

/// `EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EvpPkeyCtx) -> *mut EvpPkey {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).pkey }
}

/// `EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_peerkey(ctx: *mut EvpPkeyCtx) -> *mut EvpPkey {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).peerkey }
}

/// `OSSL_LIB_CTX *EVP_PKEY_CTX_get0_libctx(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_libctx(ctx: *mut EvpPkeyCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).libctx }
}

/// `const char *EVP_PKEY_CTX_get0_propq(const EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_propq(ctx: *const EvpPkeyCtx) -> *const c_char {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).propquery }
}

/// `const OSSL_PROVIDER *EVP_PKEY_CTX_get0_provider(const EVP_PKEY_CTX *ctx)`.
///
/// The five-arm switch, and the **generation arm is different from the other four**: it answers the
/// provider of `ctx->keymgmt` rather than of an `op` method, because a generation context belongs to
/// the keymgmt. A context with no live operation answers NULL, which is the one arm that is not a
/// family.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_provider(ctx: *const EvpPkeyCtx) -> *const OsslProvider {
    // SAFETY: `ctx` is live per the contract.
    let c = unsafe { &*ctx };
    if c.is_signature_op() {
        if !c.op_sig_signature.is_null() {
            // SAFETY: `op_sig_signature` is live.
            return unsafe {
                crate::evp::signature::EVP_SIGNATURE_get0_provider(c.op_sig_signature)
            };
        }
    } else if c.is_derive_op() {
        if !c.op_kex_exchange.is_null() {
            // SAFETY: `op_kex_exchange` is live.
            return unsafe { crate::evp::exchange::EVP_KEYEXCH_get0_provider(c.op_kex_exchange) };
        }
    } else if c.is_kem_op() {
        if !c.op_encap_kem.is_null() {
            // SAFETY: `op_encap_kem` is live.
            return unsafe { crate::evp::kem::EVP_KEM_get0_provider(c.op_encap_kem) };
        }
    } else if c.is_asym_cipher_op() {
        if !c.op_ciph_cipher.is_null() {
            // SAFETY: `op_ciph_cipher` is live.
            return unsafe {
                crate::evp::asymcipher::EVP_ASYM_CIPHER_get0_provider(c.op_ciph_cipher)
            };
        }
    } else if c.is_gen_op() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        return unsafe { crate::evp::keymgmt::EVP_KEYMGMT_get0_provider(c.keymgmt) };
    }

    ptr::null()
}

/// `void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)` — the internal spelling `crypto/evp/digest.c` calls,
/// from `evp_md_ctx_reset_ex` and `EVP_MD_CTX_set_pkey_ctx`.
///
/// A wrapper rather than a second implementation, for the reason the shell this replaces recorded:
/// the digest stratum needs exactly these two operations, and a divergent copy of either would be a
/// defect no court could see.
///
/// # Safety
/// `pctx` must be NULL or live.
pub(crate) unsafe fn evp_pkey_ctx_free(pctx: *mut EvpPkeyCtx) {
    // SAFETY: `pctx` is NULL or live per the contract.
    unsafe { EVP_PKEY_CTX_free(pctx) };
}

/// `EVP_PKEY_CTX *EVP_PKEY_CTX_dup(const EVP_PKEY_CTX *ctx)` — the internal spelling.
///
/// # Safety
/// `pctx` must be NULL or live; the answer, if non-NULL, is owned by the caller.
pub(crate) unsafe fn evp_pkey_ctx_dup(pctx: *const EvpPkeyCtx) -> *mut EvpPkeyCtx {
    // SAFETY: `pctx` is NULL or live per the contract.
    unsafe { EVP_PKEY_CTX_dup(pctx) }
}

/// `int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_operation(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).operation }
}

// ---------------------------------------------------------------------------------------------
// The two descriptor-table accessors and the type test.
//
// These three are 7.4c-ii's first exports, and they land ahead of the rest of that subphase because
// `EVP_PKEY_CTX_set_params` and `EVP_PKEY_CTX_get_params` cannot be written without
// `ctrl_params_translate.c` -- their `EVP_PKEY_STATE_LEGACY` arm *is* the params-to-ctrl translation,
// which is that file's 2,959 lines. These three have no legacy arm at all, so they are exactly as
// complete as the authority's.
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX *ctx, const char *keytype)` — `crypto/evp/pmeth_lib.c:668`.
///
/// The authority's legacy arm is `ctx->pmeth->pkey_id == evp_pkey_name2type(keytype)`, and it is
/// guarded by `evp_pkey_ctx_is_legacy(ctx)` — which is `keymgmt == NULL` (D168). So the arm is
/// reached only by a context whose `keymgmt` is NULL, and in the authority such a context is one
/// built through the legacy constructors, which always carry a `pmeth`.
///
/// **Note the NULL test the authority does not make**: unlike every other accessor in this file, this
/// one dereferences `ctx` without checking it, in the provided path *and* in the legacy path. A NULL
/// context faults the authority here, so the crate does not invent an answer for one.
///
/// # Safety
/// `ctx` must be live; `keytype` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_is_a(ctx: *mut EvpPkeyCtx, keytype: *const c_char) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let keymgmt = unsafe { (*ctx).keymgmt };
    /* The legacy arm above is unreachable: it needs `keymgmt == NULL`, and every context this crate
     * can build with a NULL `keymgmt` is refused before it exists (`int_ctx_new` always fetches a
     * method). Reading the context is what keeps that statement checkable at the site rather than in
     * a comment. */
    // SAFETY: `keymgmt` is live — the context is provided-side.
    unsafe { EVP_KEYMGMT_is_a(keymgmt, keytype) }
}

/// `const OSSL_PARAM *EVP_PKEY_CTX_gettable_params(const EVP_PKEY_CTX *ctx)` —
/// `crypto/evp/pmeth_lib.c:758`.
///
/// **No state test and no legacy arm**: the five blocks are tried in order and NULL is the answer
/// when none matches, so a legacy context and an uninitialised one both get NULL rather than an
/// error. Each block passes the provider's own context — `ossl_provider_ctx` of **the method's**
/// provider, not the libctx — because the descriptor table is a property of the method.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_gettable_params(ctx: *const EvpPkeyCtx) -> *const OsslParam {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: `ctx` is live.
    let c = unsafe { &*ctx };

    if c.is_derive_op() && !c.op_kex_exchange.is_null() {
        // SAFETY: `op_kex_exchange` is live.
        let f = unsafe { (*c.op_kex_exchange).gettable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_kex_exchange` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_KEYEXCH_get0_provider(c.op_kex_exchange)) };
            // SAFETY: `f` is the provider's own callback and `op_kex_algctx` is its context.
            return unsafe { f(c.op_kex_algctx, provctx) };
        }
    }
    if c.is_signature_op() && !c.op_sig_signature.is_null() {
        // SAFETY: `op_sig_signature` is live.
        let f = unsafe { (*c.op_sig_signature).gettable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_sig_signature` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_SIGNATURE_get0_provider(c.op_sig_signature)) };
            // SAFETY: `f` is the provider's own callback and `op_sig_algctx` is its context.
            return unsafe { f(c.op_sig_algctx, provctx) };
        }
    }
    if c.is_asym_cipher_op() && !c.op_ciph_cipher.is_null() {
        // SAFETY: `op_ciph_cipher` is live.
        let f = unsafe { (*c.op_ciph_cipher).gettable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_ciph_cipher` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_ASYM_CIPHER_get0_provider(c.op_ciph_cipher)) };
            // SAFETY: `f` is the provider's own callback and `op_ciph_algctx` is its context.
            return unsafe { f(c.op_ciph_algctx, provctx) };
        }
    }
    if c.is_kem_op() && !c.op_encap_kem.is_null() {
        // SAFETY: `op_encap_kem` is live.
        let f = unsafe { (*c.op_encap_kem).gettable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_encap_kem` is live, so its provider is readable.
            let provctx = unsafe { ossl_provider_ctx(EVP_KEM_get0_provider(c.op_encap_kem)) };
            // SAFETY: `f` is the provider's own callback and `op_encap_algctx` is its context.
            return unsafe { f(c.op_encap_algctx, provctx) };
        }
    }
    if c.is_gen_op() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        let f = unsafe { (*c.keymgmt).gen_gettable_params };
        if let Some(f) = f {
            // SAFETY: `keymgmt` is live, so its provider is readable.
            let provctx = unsafe { ossl_provider_ctx(EVP_KEYMGMT_get0_provider(c.keymgmt)) };
            // SAFETY: `f` is the provider's own callback and `op_keymgmt_genctx` is its context.
            return unsafe { f(c.op_keymgmt_genctx, provctx) };
        }
    }
    ptr::null()
}

/// `const OSSL_PARAM *EVP_PKEY_CTX_settable_params(const EVP_PKEY_CTX *ctx)` —
/// `crypto/evp/pmeth_lib.c:802`.
///
/// The same five blocks as the getter, and **a different order**: the authority tries the key
/// generation family *before* the KEM family here and after it in `gettable`. Nothing observable
/// depends on the order, because a context carries one operation at a time — which is precisely why
/// copying the order rather than sorting it is the right transcription. A reader who "normalised"
/// the two would be editing the authority.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_settable_params(ctx: *const EvpPkeyCtx) -> *const OsslParam {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: `ctx` is live.
    let c = unsafe { &*ctx };

    if c.is_derive_op() && !c.op_kex_exchange.is_null() {
        // SAFETY: `op_kex_exchange` is live.
        let f = unsafe { (*c.op_kex_exchange).settable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_kex_exchange` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_KEYEXCH_get0_provider(c.op_kex_exchange)) };
            // SAFETY: `f` is the provider's own callback and `op_kex_algctx` is its context.
            return unsafe { f(c.op_kex_algctx, provctx) };
        }
    }
    if c.is_signature_op() && !c.op_sig_signature.is_null() {
        // SAFETY: `op_sig_signature` is live.
        let f = unsafe { (*c.op_sig_signature).settable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_sig_signature` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_SIGNATURE_get0_provider(c.op_sig_signature)) };
            // SAFETY: `f` is the provider's own callback and `op_sig_algctx` is its context.
            return unsafe { f(c.op_sig_algctx, provctx) };
        }
    }
    if c.is_asym_cipher_op() && !c.op_ciph_cipher.is_null() {
        // SAFETY: `op_ciph_cipher` is live.
        let f = unsafe { (*c.op_ciph_cipher).settable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_ciph_cipher` is live, so its provider is readable.
            let provctx =
                unsafe { ossl_provider_ctx(EVP_ASYM_CIPHER_get0_provider(c.op_ciph_cipher)) };
            // SAFETY: `f` is the provider's own callback and `op_ciph_algctx` is its context.
            return unsafe { f(c.op_ciph_algctx, provctx) };
        }
    }
    if c.is_gen_op() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        let f = unsafe { (*c.keymgmt).gen_settable_params };
        if let Some(f) = f {
            // SAFETY: `keymgmt` is live, so its provider is readable.
            let provctx = unsafe { ossl_provider_ctx(EVP_KEYMGMT_get0_provider(c.keymgmt)) };
            // SAFETY: `f` is the provider's own callback and `op_keymgmt_genctx` is its context.
            return unsafe { f(c.op_keymgmt_genctx, provctx) };
        }
    }
    if c.is_kem_op() && !c.op_encap_kem.is_null() {
        // SAFETY: `op_encap_kem` is live.
        let f = unsafe { (*c.op_encap_kem).settable_ctx_params };
        if let Some(f) = f {
            // SAFETY: `op_encap_kem` is live, so its provider is readable.
            let provctx = unsafe { ossl_provider_ctx(EVP_KEM_get0_provider(c.op_encap_kem)) };
            // SAFETY: `f` is the provider's own callback and `op_encap_algctx` is its context.
            return unsafe { f(c.op_encap_algctx, provctx) };
        }
    }
    ptr::null()
}

// SPDX-License-Identifier: Apache-2.0

// ---------------------------------------------------------------------------------------------
// The `EVP_PKEY_METHOD` registry — the same shape as `EVP_PKEY_ASN1_METHOD`'s, one file over.
//
// `EVP_PKEY_METHOD` is `include/crypto/evp.h:145-192`'s `struct evp_pkey_method_st`: thirty-two
// members, twenty-seven of them function pointers, and the order is the ABI. It is the **legacy**
// method object — the one a caller builds with `EVP_PKEY_meth_new` and installs with `_add0` — and
// it is distinct from `EVP_PKEY_ASN1_METHOD`, which is the encoding side. Both are read by the
// legacy `EVP_PKEY_CTX` paths and by `p_legacy.c`.
//
// The typedef is in `include/openssl/types.h`, the **body** is in an internal header that is not
// installed, and the accessors are declared in `evp.h`, so the ownership atlas assigns the
// accessors to this stratum and this stratum defines the struct — the argument D176 made for the
// ASN.1 one, and the same one applies here.
//
// Twenty-seven members name eighteen distinct callback shapes, so there are eighteen aliases rather
// than twenty-seven: `EVP_PKEY_meth`'s nine `*_init` members are one type, its three `*_check`
// members are one type, and `sign` and `encrypt` are the same shape under two names because the
// authority declares them twice and the crate names by role (`KeyexchDeriveFn` and `KdfDeriveFn`
// are the same shape and are also distinct).
// ---------------------------------------------------------------------------------------------

/// `int (*)(EVP_PKEY_CTX *) — the nine `*_init` members`.
pub(crate) type PkeyMethInitFn = unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int;
/// `void (*)(EVP_PKEY_CTX *)`.
pub(crate) type PkeyMethCleanupFn = unsafe extern "C" fn(*mut EvpPkeyCtx);
/// `int (*)(EVP_PKEY_CTX *, const EVP_PKEY_CTX *)`.
pub(crate) type PkeyMethCopyFn = unsafe extern "C" fn(*mut EvpPkeyCtx, *const EvpPkeyCtx) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, EVP_PKEY *)`.
pub(crate) type PkeyMethParamgenFn = unsafe extern "C" fn(*mut EvpPkeyCtx, *mut EvpPkey) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t)`.
pub(crate) type PkeyMethSignFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut u8, *mut usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t)`.
pub(crate) type PkeyMethCryptFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut u8, *mut usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t)`.
pub(crate) type PkeyMethVerifyFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *const u8, usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t)`.
pub(crate) type PkeyMethVerifyRecoverFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut u8, *mut usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, EVP_MD_CTX *)`.
pub(crate) type PkeyMethSignctxInitFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut EvpMdCtx) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, unsigned char *, size_t *, EVP_MD_CTX *)`.
pub(crate) type PkeyMethSignctxFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut u8, *mut usize, *mut EvpMdCtx) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, const unsigned char *, int, EVP_MD_CTX *)`.
pub(crate) type PkeyMethVerifyctxFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *const u8, c_int, *mut EvpMdCtx) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, unsigned char *, size_t *)`.
pub(crate) type PkeyMethDeriveFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut u8, *mut usize) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, int, int, void *)`.
pub(crate) type PkeyMethCtrlFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, c_int, c_int, *mut c_void) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, const char *, const char *)`.
pub(crate) type PkeyMethCtrlStrFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *const c_char, *const c_char) -> c_int;
/// `int (*)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t)`.
pub(crate) type PkeyMethDigestsignFn =
    unsafe extern "C" fn(*mut EvpMdCtx, *mut u8, *mut usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_MD_CTX *, const unsigned char *, size_t, const unsigned char *, size_t)`.
pub(crate) type PkeyMethDigestverifyFn =
    unsafe extern "C" fn(*mut EvpMdCtx, *const u8, usize, *const u8, usize) -> c_int;
/// `int (*)(EVP_PKEY *)`.
pub(crate) type PkeyMethCheckFn = unsafe extern "C" fn(*mut EvpPkey) -> c_int;
/// `int (*)(EVP_PKEY_CTX *, EVP_MD_CTX *)`.
pub(crate) type PkeyMethDigestCustomFn =
    unsafe extern "C" fn(*mut EvpPkeyCtx, *mut EvpMdCtx) -> c_int;

/// `struct evp_pkey_method_st` — `include/crypto/evp.h:145-192`, thirty-two members in ABI order.
///
/// `pkey_id` and `flags` first, then the twenty-seven callbacks in the header's order, then
/// `digest_custom` last — which is *after* the three `*_check` members, so a transcription that
/// sorted by role would put it a member early.
#[repr(C)]
pub struct EvpPkeyMethod {
    /// `int pkey_id`.
    pub(crate) pkey_id: c_int,
    /// `int flags`.
    pub(crate) flags: c_int,
    /// `int (*init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) init: Option<PkeyMethInitFn>,
    /// `int (*copy)(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)`.
    pub(crate) copy: Option<PkeyMethCopyFn>,
    /// `void (*cleanup)(EVP_PKEY_CTX *ctx)`.
    pub(crate) cleanup: Option<PkeyMethCleanupFn>,
    /// `int (*paramgen_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) paramgen_init: Option<PkeyMethInitFn>,
    /// `int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)`.
    pub(crate) paramgen: Option<PkeyMethParamgenFn>,
    /// `int (*keygen_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) keygen_init: Option<PkeyMethInitFn>,
    /// `int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)`.
    pub(crate) keygen: Option<PkeyMethParamgenFn>,
    /// `int (*sign_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) sign_init: Option<PkeyMethInitFn>,
    /// `int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)`.
    pub(crate) sign: Option<PkeyMethSignFn>,
    /// `int (*verify_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) verify_init: Option<PkeyMethInitFn>,
    /// `int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)`.
    pub(crate) verify: Option<PkeyMethVerifyFn>,
    /// `int (*verify_recover_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) verify_recover_init: Option<PkeyMethInitFn>,
    /// `int (*verify_recover)(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig, size_t siglen)`.
    pub(crate) verify_recover: Option<PkeyMethVerifyRecoverFn>,
    /// `int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)`.
    pub(crate) signctx_init: Option<PkeyMethSignctxInitFn>,
    /// `int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)`.
    pub(crate) signctx: Option<PkeyMethSignctxFn>,
    /// `int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)`.
    pub(crate) verifyctx_init: Option<PkeyMethSignctxInitFn>,
    /// `int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx)`.
    pub(crate) verifyctx: Option<PkeyMethVerifyctxFn>,
    /// `int (*encrypt_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) encrypt_init: Option<PkeyMethInitFn>,
    /// `int (*encrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)`.
    pub(crate) encrypt: Option<PkeyMethCryptFn>,
    /// `int (*decrypt_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) decrypt_init: Option<PkeyMethInitFn>,
    /// `int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)`.
    pub(crate) decrypt: Option<PkeyMethCryptFn>,
    /// `int (*derive_init)(EVP_PKEY_CTX *ctx)`.
    pub(crate) derive_init: Option<PkeyMethInitFn>,
    /// `int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)`.
    pub(crate) derive: Option<PkeyMethDeriveFn>,
    /// `int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)`.
    pub(crate) ctrl: Option<PkeyMethCtrlFn>,
    /// `int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value)`.
    pub(crate) ctrl_str: Option<PkeyMethCtrlStrFn>,
    /// `int (*digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)`.
    pub(crate) digestsign: Option<PkeyMethDigestsignFn>,
    /// `int (*digestverify)(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)`.
    pub(crate) digestverify: Option<PkeyMethDigestverifyFn>,
    /// `int (*check)(EVP_PKEY *pkey)`.
    pub(crate) check: Option<PkeyMethCheckFn>,
    /// `int (*public_check)(EVP_PKEY *pkey)`.
    pub(crate) public_check: Option<PkeyMethCheckFn>,
    /// `int (*param_check)(EVP_PKEY *pkey)`.
    pub(crate) param_check: Option<PkeyMethCheckFn>,
    /// `int (*digest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)`.
    pub(crate) digest_custom: Option<PkeyMethDigestCustomFn>,
}

/// `EVP_PKEY_FLAG_DYNAMIC` — `include/crypto/evp.h:143`.
///
/// Vanishingly easy to miss and load-bearing in two places: `EVP_PKEY_meth_new` **or**s it into the
/// caller's flags, and `EVP_PKEY_meth_free` frees on nothing else. A method a caller built
/// statically — which every one of Phase 8's `ossl_<alg>_pkey_method` objects is — must survive
/// `EVP_PKEY_meth_free`, so a transcription that freed unconditionally would free a
/// `static const` object.
const EVP_PKEY_FLAG_DYNAMIC: c_int = 1;

/// `app_pkey_methods` — the application-registered methods, sorted by `pmeth_cmp`.
static mut APP_PKEY_METHODS: *mut OpenSslStack = ptr::null_mut();

/// `EVP_PKEY_meth_new`'s `OPENSSL_zalloc(sizeof(*pmeth))` (line 128).
const LINE_ZALLOC_PMETH: c_int = 128;
/// `EVP_PKEY_meth_free`'s `OPENSSL_free(pmeth)` (line 439).
const LINE_FREE_PMETH: c_int = 439;
/// A slice-(4) coordinate: `default_fixup_args`'s BIGNUM buffer is allocated here and freed by
/// `cleanup_translation_ctx`.
#[allow(dead_code)] // slice (3)-(4): the `PRE_CTRL_TO_PARAMS` BIGNUM arm is in `default_fixup_args`
/// `cleanup_translation_ctx`'s `OPENSSL_free(ctx->allocated_buf)` — the authority's line 718.
const LINE_FREE_XLAT_CTX: c_int = 718;
/// `default_fixup_args`'s `OPENSSL_malloc(ctx->buflen)` for the BIGNUM buffer — the authority's
/// lines 473 and 480, which is one allocation site and one free of it.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
const LINE_XLAT_BN_BUF: c_int = 473;

/// `static int pmeth_cmp(const EVP_PKEY_METHOD *const *a, const EVP_PKEY_METHOD *const *b)` —
/// `crypto/asn1/ameth_lib.c:31`'s counterpart in `crypto/evp/pmeth_lib.c:86`.
///
/// # Safety
/// Both arguments must point at live `*const EvpPkeyMethod` slots.
unsafe extern "C" fn pmeth_cmp(a: *const c_void, b: *const c_void) -> c_int {
    /* The stack stores the elements themselves and hands the comparator the addresses of the slots
     * they live in -- what the authority's `DECLARE_OBJ_BSEARCH_CMP_FN` macro spells as a
     * `*const *const` pair, and what the crate's `CompFn` erases to a `*const c_void` pair. */
    let a = a.cast::<*const EvpPkeyMethod>();
    let b = b.cast::<*const EvpPkeyMethod>();
    // SAFETY: both arguments are slots holding live methods per the contract.
    let (x, y) = unsafe { ((**a).pkey_id, (**b).pkey_id) };
    x - y
}

/// `static const EVP_PKEY_METHOD *evp_pkey_meth_find_added_by_application(int type)` —
/// `crypto/evp/pmeth_lib.c:92`.
///
/// The application table alone, which is why it is separate from `EVP_PKEY_meth_find`: that one
/// asks this first and only then searches `standard_methods[]`. `int_ctx_new` and
/// `EVP_PKEY_CTX_dup` call **this** one, so a caller that installed its own method reaches it
/// without the Phase-8 table being present at all.
///
/// **No caller in this crate yet.** Two land later in this stratum and neither is here:
/// `EVP_PKEY_meth_find` (7.4l, which asks this first and only then searches `standard_methods[]`)
/// and `int_ctx_new`'s `app_pmeth` arm (7.4c, which the crate currently records as absent because
/// `ctx->pmeth` does not exist until then).
///
/// # Safety
/// Nothing: the table is this module's own.
#[allow(dead_code)] // called by `EVP_PKEY_meth_find` (7.4l) and `int_ctx_new` (7.4c)
pub(crate) unsafe fn evp_pkey_meth_find_added_by_application(type_: c_int) -> *const EvpPkeyMethod {
    // SAFETY: `APP_PKEY_METHODS` is NULL or a stack this module owns.
    if unsafe { APP_PKEY_METHODS }.is_null() {
        return ptr::null();
    }
    /* The comparator reads `pkey_id` alone, so a zeroed probe of the right shape is a legal
     * argument; see `EVP_PKEY_asn1_add0`'s duplicate test for the same construction. */
    // SAFETY: every field is a scalar, a raw pointer or an `Option` of a function pointer, so the
    // all-zero bit pattern is valid, and `pkey_id` is assigned on the next line.
    let mut probe: EvpPkeyMethod = unsafe { core::mem::zeroed() };
    probe.pkey_id = type_;
    // SAFETY: `APP_PKEY_METHODS` is live and `probe` is a live local the comparator reads as a
    // method.
    let idx = unsafe { OPENSSL_sk_find(APP_PKEY_METHODS, ptr::addr_of!(probe).cast::<c_void>()) };
    if idx < 0 {
        return ptr::null();
    }
    // SAFETY: `idx` is a valid index into `APP_PKEY_METHODS`.
    unsafe { OPENSSL_sk_value(APP_PKEY_METHODS, idx) }.cast::<EvpPkeyMethod>()
}

/// `EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags)` — `crypto/evp/pmeth_lib.c:124`.
///
/// `OPENSSL_zalloc`, then the id, then `flags | EVP_PKEY_FLAG_DYNAMIC`. The **or** is what makes
/// `EVP_PKEY_meth_free` able to release the object later, and it is the one thing this constructor
/// does that a caller could not do itself.
///
/// # Safety
/// Nothing: both arguments are integers.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> *mut EvpPkeyMethod {
    /* `CRYPTO_zalloc` is one of the safe entry points of this crate: it validates its own argument
     * and answers NULL rather than reading anything of the caller's. */
    let pmeth = CRYPTO_zalloc(
        core::mem::size_of::<EvpPkeyMethod>(),
        FILE,
        LINE_ZALLOC_PMETH,
    )
    .cast::<EvpPkeyMethod>();
    if pmeth.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pmeth` is this call's own allocation.
    unsafe {
        (*pmeth).pkey_id = id;
        (*pmeth).flags = flags | EVP_PKEY_FLAG_DYNAMIC;
    }
    pmeth
}

/// `void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth)` — `crypto/evp/pmeth_lib.c:436`.
///
/// **Only frees a `DYNAMIC` method**, and that is not a fast path: a method the caller owns
/// statically — which is every one of Phase 8's `ossl_<alg>_pkey_method` objects — must survive a
/// `free` call.
///
/// # Safety
/// `pmeth` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_free(pmeth: *mut EvpPkeyMethod) {
    if pmeth.is_null() {
        return;
    }
    // SAFETY: `pmeth` is live per the contract.
    if (unsafe { (*pmeth).flags } & EVP_PKEY_FLAG_DYNAMIC) == 0 {
        return;
    }
    // SAFETY: `pmeth` is live and `DYNAMIC` is set, so this object is this module's own.
    unsafe { CRYPTO_free(pmeth.cast::<c_void>(), FILE, LINE_FREE_PMETH) };
}

/// `void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)` —
/// `crypto/evp/pmeth_lib.c:424`.
///
/// `*dst = *src` and then **two** restores, where the ASN.1 counterpart restores five: `dst` keeps
/// its own `pkey_id` and `flags` and takes the twenty-seven callbacks from `src`. The authority's
/// comment is the same sentence as the ASN.1 one — "We only copy the function pointers so restore
/// the other values" — and here it means exactly two fields, because this struct has no owned
/// strings.
///
/// # Safety
/// `dst` and `src` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_copy(dst: *mut EvpPkeyMethod, src: *const EvpPkeyMethod) {
    // SAFETY: `dst` is live per the contract.
    let (pkey_id, flags) = unsafe { ((*dst).pkey_id, (*dst).flags) };

    // SAFETY: both are live and non-overlapping per the contract.
    unsafe { ptr::copy_nonoverlapping(src, dst, 1) };

    // SAFETY: `dst` is live.
    unsafe {
        (*dst).pkey_id = pkey_id;
        (*dst).flags = flags;
    }
}

/// `void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags, const EVP_PKEY_METHOD *meth)` —
/// `crypto/evp/pmeth_lib.c:415`.
///
/// Two out-parameters, each written **only if the caller passed one** — unlike its ASN.1
/// counterpart, which has five and also writes the method's own string pointers.
///
/// # Safety
/// `meth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get0_info(
    ppkey_id: *mut c_int,
    pflags: *mut c_int,
    meth: *const EvpPkeyMethod,
) {
    if !ppkey_id.is_null() {
        // SAFETY: `ppkey_id` is writable per the contract and `meth` is live.
        unsafe { *ppkey_id = (*meth).pkey_id };
    }
    if !pflags.is_null() {
        // SAFETY: `pflags` is writable per the contract and `meth` is live.
        unsafe { *pflags = (*meth).flags };
    }
}

/// `int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth)` — `crypto/evp/pmeth_lib.c:614`.
///
/// **No validation at all**, which is the difference from `EVP_PKEY_asn1_add0`: no alias/null rule,
/// no duplicate check, and a duplicate `pkey_id` is pushed and the stack sorted with both present.
/// The two allocation failures are the file's only recorded sites, and both take `ERR_R_CRYPTO_LIB`
/// rather than a reason of this unit's own.
///
/// # Safety
/// `pmeth` must be a live method, and it must outlive the registry.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_add0(pmeth: *const EvpPkeyMethod) -> c_int {
    // SAFETY: `APP_PKEY_METHODS` is NULL or a stack this module owns.
    if unsafe { APP_PKEY_METHODS }.is_null() {
        // SAFETY: the comparator reads only `pkey_id`, which every pushed method has.
        /* `OPENSSL_sk_new` is a safe entry point of this crate. */
        let st = OPENSSL_sk_new(Some(pmeth_cmp));
        if st.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PMETH_LIB_619) };
            return 0;
        }
        // SAFETY: this module owns the pointer and nothing else writes it.
        unsafe { APP_PKEY_METHODS = st };
    }
    // SAFETY: `APP_PKEY_METHODS` is live and `pmeth` outlives the registry per the contract.
    if unsafe { OPENSSL_sk_push(APP_PKEY_METHODS, pmeth.cast::<c_void>()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_624) };
        return 0;
    }
    // SAFETY: `APP_PKEY_METHODS` is live.
    unsafe { OPENSSL_sk_sort(APP_PKEY_METHODS) };
    1
}

/// `int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth)` — `crypto/evp/pmeth_lib.c:637`.
///
/// `sk_EVP_PKEY_METHOD_delete_ptr`, which compares **pointer identity** rather than `pkey_id` — so
/// it removes the one object the caller holds, not the first with the same id. The authority calls
/// it with no NULL test on the stack and no NULL test on `pmeth`; `OPENSSL_sk_delete_ptr` answers
/// NULL for a NULL stack, so a caller that removes before adding gets 0 rather than a fault, and
/// that is reproduced rather than guarded.
///
/// # Safety
/// `pmeth` must be the pointer that was pushed, or NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_remove(pmeth: *const EvpPkeyMethod) -> c_int {
    // SAFETY: `pmeth` is the caller's own pointer per the contract; the stack is this module's own
    // and `OPENSSL_sk_delete_ptr` answers NULL for a NULL one.
    let ret = unsafe { OPENSSL_sk_delete_ptr(APP_PKEY_METHODS, pmeth.cast::<c_void>()) };
    if ret.is_null() {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------------------------
// The forty `get`/`set` accessors.
//
// Every setter is a list of field assignments and every getter is a list of guarded stores, so the
// whole of their contract is the **parameter list** — and twenty of them take *two* output
// parameters, which is the part a reader is most likely to drop. `get_encrypt`'s second parameter
// is spelled `pencryptfn` and its member is `encrypt`, and the three `get_*_check` functions all
// name their parameter `pcheck` while writing three different members; both are the authority's own
// spellings, copied rather than tidied.
//
// The getter's guard is a NULL test and not a validity test: `if (pinit) *pinit = ...`. A caller
// that wants only the second of two callbacks passes NULL for the first, which is why the pair
// cannot be collapsed.
// ---------------------------------------------------------------------------------------------

/// `void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_init` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_init(
    pmeth: *mut EvpPkeyMethod,
    init: Option<PkeyMethInitFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).init = init;
    }
}

/// `void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_init` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_init(
    pmeth: *const EvpPkeyMethod,
    pinit: *mut Option<PkeyMethInitFn>,
) {
    if !pinit.is_null() {
        // SAFETY: `pinit` is writable per the contract and `pmeth` is live.
        unsafe { *pinit = (*pmeth).init };
    }
}

/// `void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_copy` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_copy(
    pmeth: *mut EvpPkeyMethod,
    copy: Option<PkeyMethCopyFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).copy = copy;
    }
}

/// `void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_copy` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_copy(
    pmeth: *const EvpPkeyMethod,
    pcopy: *mut Option<PkeyMethCopyFn>,
) {
    if !pcopy.is_null() {
        // SAFETY: `pcopy` is writable per the contract and `pmeth` is live.
        unsafe { *pcopy = (*pmeth).copy };
    }
}

/// `void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_cleanup` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_cleanup(
    pmeth: *mut EvpPkeyMethod,
    cleanup: Option<PkeyMethCleanupFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).cleanup = cleanup;
    }
}

/// `void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_cleanup` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_cleanup(
    pmeth: *const EvpPkeyMethod,
    pcleanup: *mut Option<PkeyMethCleanupFn>,
) {
    if !pcleanup.is_null() {
        // SAFETY: `pcleanup` is writable per the contract and `pmeth` is live.
        unsafe { *pcleanup = (*pmeth).cleanup };
    }
}

/// `void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_paramgen` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_paramgen(
    pmeth: *mut EvpPkeyMethod,
    paramgen_init: Option<PkeyMethInitFn>,
    paramgen: Option<PkeyMethParamgenFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).paramgen_init = paramgen_init;
        (*pmeth).paramgen = paramgen;
    }
}

/// `void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_paramgen` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_paramgen(
    pmeth: *const EvpPkeyMethod,
    pparamgen_init: *mut Option<PkeyMethInitFn>,
    pparamgen: *mut Option<PkeyMethParamgenFn>,
) {
    if !pparamgen_init.is_null() {
        // SAFETY: `pparamgen_init` is writable per the contract and `pmeth` is live.
        unsafe { *pparamgen_init = (*pmeth).paramgen_init };
    }
    if !pparamgen.is_null() {
        // SAFETY: `pparamgen` is writable per the contract and `pmeth` is live.
        unsafe { *pparamgen = (*pmeth).paramgen };
    }
}

/// `void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_keygen` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_keygen(
    pmeth: *mut EvpPkeyMethod,
    keygen_init: Option<PkeyMethInitFn>,
    keygen: Option<PkeyMethParamgenFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).keygen_init = keygen_init;
        (*pmeth).keygen = keygen;
    }
}

/// `void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_keygen` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_keygen(
    pmeth: *const EvpPkeyMethod,
    pkeygen_init: *mut Option<PkeyMethInitFn>,
    pkeygen: *mut Option<PkeyMethParamgenFn>,
) {
    if !pkeygen_init.is_null() {
        // SAFETY: `pkeygen_init` is writable per the contract and `pmeth` is live.
        unsafe { *pkeygen_init = (*pmeth).keygen_init };
    }
    if !pkeygen.is_null() {
        // SAFETY: `pkeygen` is writable per the contract and `pmeth` is live.
        unsafe { *pkeygen = (*pmeth).keygen };
    }
}

/// `void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_sign` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_sign(
    pmeth: *mut EvpPkeyMethod,
    sign_init: Option<PkeyMethInitFn>,
    sign: Option<PkeyMethSignFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).sign_init = sign_init;
        (*pmeth).sign = sign;
    }
}

/// `void EVP_PKEY_meth_get_sign(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_sign` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_sign(
    pmeth: *const EvpPkeyMethod,
    psign_init: *mut Option<PkeyMethInitFn>,
    psign: *mut Option<PkeyMethSignFn>,
) {
    if !psign_init.is_null() {
        // SAFETY: `psign_init` is writable per the contract and `pmeth` is live.
        unsafe { *psign_init = (*pmeth).sign_init };
    }
    if !psign.is_null() {
        // SAFETY: `psign` is writable per the contract and `pmeth` is live.
        unsafe { *psign = (*pmeth).sign };
    }
}

/// `void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_verify` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_verify(
    pmeth: *mut EvpPkeyMethod,
    verify_init: Option<PkeyMethInitFn>,
    verify: Option<PkeyMethVerifyFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).verify_init = verify_init;
        (*pmeth).verify = verify;
    }
}

/// `void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_verify` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_verify(
    pmeth: *const EvpPkeyMethod,
    pverify_init: *mut Option<PkeyMethInitFn>,
    pverify: *mut Option<PkeyMethVerifyFn>,
) {
    if !pverify_init.is_null() {
        // SAFETY: `pverify_init` is writable per the contract and `pmeth` is live.
        unsafe { *pverify_init = (*pmeth).verify_init };
    }
    if !pverify.is_null() {
        // SAFETY: `pverify` is writable per the contract and `pmeth` is live.
        unsafe { *pverify = (*pmeth).verify };
    }
}

/// `void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_verify_recover` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_verify_recover(
    pmeth: *mut EvpPkeyMethod,
    verify_recover_init: Option<PkeyMethInitFn>,
    verify_recover: Option<PkeyMethVerifyRecoverFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).verify_recover_init = verify_recover_init;
        (*pmeth).verify_recover = verify_recover;
    }
}

/// `void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_verify_recover` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_verify_recover(
    pmeth: *const EvpPkeyMethod,
    pverify_recover_init: *mut Option<PkeyMethInitFn>,
    pverify_recover: *mut Option<PkeyMethVerifyRecoverFn>,
) {
    if !pverify_recover_init.is_null() {
        // SAFETY: `pverify_recover_init` is writable per the contract and `pmeth` is live.
        unsafe { *pverify_recover_init = (*pmeth).verify_recover_init };
    }
    if !pverify_recover.is_null() {
        // SAFETY: `pverify_recover` is writable per the contract and `pmeth` is live.
        unsafe { *pverify_recover = (*pmeth).verify_recover };
    }
}

/// `void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_signctx` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_signctx(
    pmeth: *mut EvpPkeyMethod,
    signctx_init: Option<PkeyMethSignctxInitFn>,
    signctx: Option<PkeyMethSignctxFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).signctx_init = signctx_init;
        (*pmeth).signctx = signctx;
    }
}

/// `void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_signctx` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_signctx(
    pmeth: *const EvpPkeyMethod,
    psignctx_init: *mut Option<PkeyMethSignctxInitFn>,
    psignctx: *mut Option<PkeyMethSignctxFn>,
) {
    if !psignctx_init.is_null() {
        // SAFETY: `psignctx_init` is writable per the contract and `pmeth` is live.
        unsafe { *psignctx_init = (*pmeth).signctx_init };
    }
    if !psignctx.is_null() {
        // SAFETY: `psignctx` is writable per the contract and `pmeth` is live.
        unsafe { *psignctx = (*pmeth).signctx };
    }
}

/// `void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_verifyctx` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_verifyctx(
    pmeth: *mut EvpPkeyMethod,
    verifyctx_init: Option<PkeyMethSignctxInitFn>,
    verifyctx: Option<PkeyMethVerifyctxFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).verifyctx_init = verifyctx_init;
        (*pmeth).verifyctx = verifyctx;
    }
}

/// `void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_verifyctx` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_verifyctx(
    pmeth: *const EvpPkeyMethod,
    pverifyctx_init: *mut Option<PkeyMethSignctxInitFn>,
    pverifyctx: *mut Option<PkeyMethVerifyctxFn>,
) {
    if !pverifyctx_init.is_null() {
        // SAFETY: `pverifyctx_init` is writable per the contract and `pmeth` is live.
        unsafe { *pverifyctx_init = (*pmeth).verifyctx_init };
    }
    if !pverifyctx.is_null() {
        // SAFETY: `pverifyctx` is writable per the contract and `pmeth` is live.
        unsafe { *pverifyctx = (*pmeth).verifyctx };
    }
}

/// `void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_encrypt` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_encrypt(
    pmeth: *mut EvpPkeyMethod,
    encrypt_init: Option<PkeyMethInitFn>,
    encryptfn: Option<PkeyMethCryptFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).encrypt_init = encrypt_init;
        (*pmeth).encrypt = encryptfn;
    }
}

/// `void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_encrypt` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_encrypt(
    pmeth: *const EvpPkeyMethod,
    pencrypt_init: *mut Option<PkeyMethInitFn>,
    pencryptfn: *mut Option<PkeyMethCryptFn>,
) {
    if !pencrypt_init.is_null() {
        // SAFETY: `pencrypt_init` is writable per the contract and `pmeth` is live.
        unsafe { *pencrypt_init = (*pmeth).encrypt_init };
    }
    if !pencryptfn.is_null() {
        // SAFETY: `pencryptfn` is writable per the contract and `pmeth` is live.
        unsafe { *pencryptfn = (*pmeth).encrypt };
    }
}

/// `void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_decrypt` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_decrypt(
    pmeth: *mut EvpPkeyMethod,
    decrypt_init: Option<PkeyMethInitFn>,
    decrypt: Option<PkeyMethCryptFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).decrypt_init = decrypt_init;
        (*pmeth).decrypt = decrypt;
    }
}

/// `void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_decrypt` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_decrypt(
    pmeth: *const EvpPkeyMethod,
    pdecrypt_init: *mut Option<PkeyMethInitFn>,
    pdecrypt: *mut Option<PkeyMethCryptFn>,
) {
    if !pdecrypt_init.is_null() {
        // SAFETY: `pdecrypt_init` is writable per the contract and `pmeth` is live.
        unsafe { *pdecrypt_init = (*pmeth).decrypt_init };
    }
    if !pdecrypt.is_null() {
        // SAFETY: `pdecrypt` is writable per the contract and `pmeth` is live.
        unsafe { *pdecrypt = (*pmeth).decrypt };
    }
}

/// `void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_derive` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_derive(
    pmeth: *mut EvpPkeyMethod,
    derive_init: Option<PkeyMethInitFn>,
    derive: Option<PkeyMethDeriveFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).derive_init = derive_init;
        (*pmeth).derive = derive;
    }
}

/// `void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_derive` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_derive(
    pmeth: *const EvpPkeyMethod,
    pderive_init: *mut Option<PkeyMethInitFn>,
    pderive: *mut Option<PkeyMethDeriveFn>,
) {
    if !pderive_init.is_null() {
        // SAFETY: `pderive_init` is writable per the contract and `pmeth` is live.
        unsafe { *pderive_init = (*pmeth).derive_init };
    }
    if !pderive.is_null() {
        // SAFETY: `pderive` is writable per the contract and `pmeth` is live.
        unsafe { *pderive = (*pmeth).derive };
    }
}

/// `void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_ctrl` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_ctrl(
    pmeth: *mut EvpPkeyMethod,
    ctrl: Option<PkeyMethCtrlFn>,
    ctrl_str: Option<PkeyMethCtrlStrFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).ctrl = ctrl;
        (*pmeth).ctrl_str = ctrl_str;
    }
}

/// `void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_ctrl` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_ctrl(
    pmeth: *const EvpPkeyMethod,
    pctrl: *mut Option<PkeyMethCtrlFn>,
    pctrl_str: *mut Option<PkeyMethCtrlStrFn>,
) {
    if !pctrl.is_null() {
        // SAFETY: `pctrl` is writable per the contract and `pmeth` is live.
        unsafe { *pctrl = (*pmeth).ctrl };
    }
    if !pctrl_str.is_null() {
        // SAFETY: `pctrl_str` is writable per the contract and `pmeth` is live.
        unsafe { *pctrl_str = (*pmeth).ctrl_str };
    }
}

/// `void EVP_PKEY_meth_set_digestsign(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_digestsign` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_digestsign(
    pmeth: *mut EvpPkeyMethod,
    digestsign: Option<PkeyMethDigestsignFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).digestsign = digestsign;
    }
}

/// `void EVP_PKEY_meth_get_digestsign(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_digestsign` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_digestsign(
    pmeth: *const EvpPkeyMethod,
    digestsign: *mut Option<PkeyMethDigestsignFn>,
) {
    if !digestsign.is_null() {
        // SAFETY: `digestsign` is writable per the contract and `pmeth` is live.
        unsafe { *digestsign = (*pmeth).digestsign };
    }
}

/// `void EVP_PKEY_meth_set_digestverify(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_digestverify` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_digestverify(
    pmeth: *mut EvpPkeyMethod,
    digestverify: Option<PkeyMethDigestverifyFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).digestverify = digestverify;
    }
}

/// `void EVP_PKEY_meth_get_digestverify(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_digestverify` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_digestverify(
    pmeth: *const EvpPkeyMethod,
    digestverify: *mut Option<PkeyMethDigestverifyFn>,
) {
    if !digestverify.is_null() {
        // SAFETY: `digestverify` is writable per the contract and `pmeth` is live.
        unsafe { *digestverify = (*pmeth).digestverify };
    }
}

/// `void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_check` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_check(
    pmeth: *mut EvpPkeyMethod,
    check: Option<PkeyMethCheckFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).check = check;
    }
}

/// `void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_check` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_check(
    pmeth: *const EvpPkeyMethod,
    pcheck: *mut Option<PkeyMethCheckFn>,
) {
    if !pcheck.is_null() {
        // SAFETY: `pcheck` is writable per the contract and `pmeth` is live.
        unsafe { *pcheck = (*pmeth).check };
    }
}

/// `void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_public_check` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_public_check(
    pmeth: *mut EvpPkeyMethod,
    check: Option<PkeyMethCheckFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).public_check = check;
    }
}

/// `void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_public_check` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_public_check(
    pmeth: *const EvpPkeyMethod,
    pcheck: *mut Option<PkeyMethCheckFn>,
) {
    if !pcheck.is_null() {
        // SAFETY: `pcheck` is writable per the contract and `pmeth` is live.
        unsafe { *pcheck = (*pmeth).public_check };
    }
}

/// `void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_param_check` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_param_check(
    pmeth: *mut EvpPkeyMethod,
    check: Option<PkeyMethCheckFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).param_check = check;
    }
}

/// `void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_param_check` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_param_check(
    pmeth: *const EvpPkeyMethod,
    pcheck: *mut Option<PkeyMethCheckFn>,
) {
    if !pcheck.is_null() {
        // SAFETY: `pcheck` is writable per the contract and `pmeth` is live.
        unsafe { *pcheck = (*pmeth).param_check };
    }
}

/// `void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `set_digest_custom` arm.
///
/// # Safety
/// `pmeth` must be live; every callback is the caller's and must outlive the method.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_set_digest_custom(
    pmeth: *mut EvpPkeyMethod,
    digest_custom: Option<PkeyMethDigestCustomFn>,
) {
    // SAFETY: `pmeth` is live per the contract.
    unsafe {
        (*pmeth).digest_custom = digest_custom;
    }
}

/// `void EVP_PKEY_meth_get_digest_custom(const EVP_PKEY_METHOD *pmeth, ...)` — `crypto/evp/pmeth_lib.c`, the `get_digest_custom` arm.
///
/// # Safety
/// `pmeth` must be live; each out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_meth_get_digest_custom(
    pmeth: *const EvpPkeyMethod,
    pdigest_custom: *mut Option<PkeyMethDigestCustomFn>,
) {
    if !pdigest_custom.is_null() {
        // SAFETY: `pdigest_custom` is writable per the contract and `pmeth` is live.
        unsafe { *pdigest_custom = (*pmeth).digest_custom };
    }
}

// ---------------------------------------------------------------------------------------------
// `crypto/evp/ctrl_params_translate.c` — the ctrl/params translation layer (7.4c-v, in progress)
//
// This is the file that makes the *legacy* control interface and the *provider* parameter interface
// the same interface. An `EVP_PKEY_CTX_ctrl` call carries a command number and two arguments of no
// declared type; a provider carries an `OSSL_PARAM` array with a declared data type and a key string.
// The translation is a table of entries, each of which may name a `fixup_args` function that runs
// before and after the actual call, and the states those functions are called in are the whole of
// the contract — which is why the enum's values are pinned here rather than left to declaration
// order: they are printed into `ERR_raise_data`'s `"[action:%d, state:%d]"` text, so the *number* is
// observable.
//
// **Slices (1) and (2) are landed; (3), (4) and (5) are next.** The type layer, `default_check` and
// `cleanup_translation_ctx` are here; the ~40 `fix_*`/`get_payload_*` functions, the two tables and
// the seven entry points follow. Nothing in the file is observable until the last slice, because the
// entry points read the tables and the tables name the fix functions — `docs/DECISIONS.md` D187
// records the measurement that says so, and why the slices are not a size boundary.
// ---------------------------------------------------------------------------------------------

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
///
/// The authority's `ctx->name_buf[OSSL_MAX_NAME_SIZE]`, and the bound `OPENSSL_strlcat` is given when
/// the `hex` prefix is prepended to a parameter key.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `enum state` — `crypto/evp/ctrl_params_translate.c:144-154`, ten values.
///
/// **The discriminants are pinned and are not decoration.** `default_fixup_args`'s default arm raises
/// `ERR_raise_data(..., "[action:%d, state:%d]", ctx->action_type, state)`, so the *number* a state
/// carries is part of an observable error's data text. C numbers an enum from zero in declaration
/// order, which is what these are, and writing them out is what keeps a variant inserted in the
/// middle from shifting every later one.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)] // slices (3)-(5): the fixup functions, the two tables and the seven entry points
pub(crate) enum XlatState {
    /// `PKEY` — the caller is an `EVP_PKEY` payload getter/setter and is fully responsible.
    Pkey = 0,
    /// `PRE_CTRL_TO_PARAMS` — prepare `*params` from the ctrl arguments.
    PreCtrlToParams = 1,
    /// `POST_CTRL_TO_PARAMS` — bring the result back to `*p2` and the return value.
    PostCtrlToParams = 2,
    /// `CLEANUP_CTRL_TO_PARAMS`.
    CleanupCtrlToParams = 3,
    /// `PRE_CTRL_STR_TO_PARAMS`.
    PreCtrlStrToParams = 4,
    /// `POST_CTRL_STR_TO_PARAMS`.
    PostCtrlStrToParams = 5,
    /// `CLEANUP_CTRL_STR_TO_PARAMS`.
    CleanupCtrlStrToParams = 6,
    /// `PRE_PARAMS_TO_CTRL` — prepare `p1` and `p2` from `*params`.
    PreParamsToCtrl = 7,
    /// `POST_PARAMS_TO_CTRL` — bring the return value and `p2` back to `*params`.
    PostParamsToCtrl = 8,
    /// `CLEANUP_PARAMS_TO_CTRL`.
    CleanupParamsToCtrl = 9,
}

/// `enum action` — `crypto/evp/ctrl_params_translate.c:155-159`. The values are the authority's own
/// explicit ones, and `NONE` is 0 rather than absent: an item may leave the action undetermined and
/// let its `fixup_args` function decide, which is what makes the ctrls whose direction depends on
/// `p1` or `p2` expressible.
///
/// `None` is a Rust keyword, so the variant takes the project's trailing-underscore spelling.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)] // slices (3)-(5), as above; `None_` is additionally the unset action type
pub(crate) enum XlatAction {
    /// `OSSL_ACTION_NONE`.
    None_ = 0,
    /// `OSSL_ACTION_GET`.
    Get = 1,
    /// `OSSL_ACTION_SET`.
    Set = 2,
}

/// `struct translation_ctx_st` — `crypto/evp/ctrl_params_translate.c:160-215`.
///
/// The eleven fields the caller fills in, then the four the `fixup_args` functions own. The split is
/// the contract: "The following are used entirely internally by the fixup_args functions and should
/// not be touched by the callers, at all."
///
/// `#[repr(C)]` rather than the default layout, for one reason that is about the reader rather than
/// the ABI: the field order is the header's, so a comparison against the authority is line by line.
/// Nothing outside this crate ever sees the layout — the struct is internal and no table is exported.
#[repr(C)]
#[allow(dead_code)] // slices (3)-(5): every field is read or written by a fixup function
pub(crate) struct XlatCtx {
    /// `EVP_PKEY_CTX *pctx` — to be pilfered for data as necessary.
    pub(crate) pctx: *mut EvpPkeyCtx,
    /// `enum action action_type` — may be 0 on entry, and the `PRE` states set it.
    pub(crate) action_type: XlatAction,
    /// `int ctrl_cmd` — the ctrl number for ctrl-to-params, and 0 for params-to-ctrl.
    pub(crate) ctrl_cmd: c_int,
    /// `const char *ctrl_str` — the ctrl string for ctrl_str-to-params, and NULL otherwise. The
    /// *value* is always passed as `p2`.
    pub(crate) ctrl_str: *const c_char,
    /// `int ishex` — whether the string matched `ctrl_hexstr` rather than `ctrl_str`.
    pub(crate) ishex: c_int,
    /// `int p1` — the ctrl-style integer argument.
    pub(crate) p1: c_int,
    /// `void *p2` — the ctrl-style pointer argument.
    pub(crate) p2: *mut c_void,
    /// `size_t sz` — a size, for passing back the `p2` size where applicable.
    pub(crate) sz: usize,
    /// `OSSL_PARAM *params` — the parameter-array side.
    pub(crate) params: *mut OsslParam,
    /// `void *orig_p2` — the original `p2`, when a fixup has to move it and remember.
    pub(crate) orig_p2: *mut c_void,
    /// `char name_buf[OSSL_MAX_NAME_SIZE]` — where the `hex`-prefixed key is built.
    pub(crate) name_buf: [c_char; OSSL_MAX_NAME_SIZE],
    /// `void *allocated_buf` — storage a fixup allocated, which the cleanup frees.
    pub(crate) allocated_buf: *mut c_void,
    /// `void *bufp` — the `OSSL_PARAM_OCTET_PTR` get path's indirection slot.
    pub(crate) bufp: *mut c_void,
    /// `size_t buflen` — `allocated_buf`'s length.
    pub(crate) buflen: usize,
}

/// `typedef int fixup_args_fn(enum state, const struct translation_st *,
/// struct translation_ctx_st *)` — `crypto/evp/ctrl_params_translate.c:161-163`.
///
/// A function *type*, so a table field spelled `fixup_args_fn *` is a bare function pointer.
#[allow(dead_code)] // slices (4)-(5): the tables' `fixup_args` slots and the entry points
pub(crate) type FixupArgsFn =
    unsafe extern "C" fn(XlatState, *const XlatEntry, *mut XlatCtx) -> c_int;

/// `typedef int cleanup_args_fn(enum state, const struct translation_st *,
/// struct translation_ctx_st *)` — `crypto/evp/ctrl_params_translate.c:164-166`.
///
/// The same shape as [`FixupArgsFn`] and a distinct name, because the authority declares it twice:
/// the two are called at different points and a table that mixed them up would call a cleanup where
/// it wanted a fixup. Kept separate for the same reason `KeyexchDeriveFn` and `KdfDeriveFn` are.
#[allow(dead_code)] // slice (4): installed in the three `CLEANUP_*` arms of both tables
pub(crate) type CleanupArgsFn =
    unsafe extern "C" fn(XlatState, *const XlatEntry, *mut XlatCtx) -> c_int;

/// `struct translation_st` — `crypto/evp/ctrl_params_translate.c:217-295` — one table entry.
///
/// Ten fields in the header's order: the action type, the three conditions, the four lookup
/// attributes, the parameter data type, and the fixer. `ctrl_num` may be 0 **or** `param_key` may be
/// NULL but not both, a `ctrl_hexstr` with a NULL `ctrl_str` means "always interpret as hex", and a
/// `param_data_type` of 0 means the type depends on the input — three rules that are documented in the
/// authority's comment above the struct and that the fixup functions rely on rather than check.
#[repr(C)]
#[allow(dead_code)] // slices (4)-(5): the two tables and the lookups that read them
pub(crate) struct XlatEntry {
    /// `enum action action_type` — 0 means both directions are supported and `fixup_args` decides.
    pub(crate) action_type: XlatAction,
    /// `int keytype1` — an `EVP_PKEY_XXX` NID, or -1 for all types, or 0 for unset.
    pub(crate) keytype1: c_int,
    /// `int keytype2` — another NID, used for aliases.
    pub(crate) keytype2: c_int,
    /// `int optype` — the operation type.
    pub(crate) optype: c_int,
    /// `int ctrl_num` — the `EVP_PKEY_CTRL_xxx` number. 0 means no ctrl is called.
    pub(crate) ctrl_num: c_int,
    /// `const char *ctrl_str` — the corresponding ctrl string.
    pub(crate) ctrl_str: *const c_char,
    /// `const char *ctrl_hexstr` — the `hex{str}` alternative.
    pub(crate) ctrl_hexstr: *const c_char,
    /// `const char *param_key` — the corresponding `OSSL_PARAM` key. NULL means no setter/getter.
    pub(crate) param_key: *const c_char,
    /// `unsigned int param_data_type` — the `OSSL_PARAM_*` data type, or 0 for "depends".
    pub(crate) param_data_type: c_uint,
    /// `fixup_args_fn *fixup_args` — always called before a `SET` and after a `GET`.
    pub(crate) fixup_args: Option<FixupArgsFn>,
}

/// `static int default_check(enum state state, const struct translation_st *translation,
/// const struct translation_ctx_st *ctx)` — `crypto/evp/ctrl_params_translate.c:297`.
///
/// Not a fixer: the standard preconditions, called by every fixup function through
/// `default_fixup_args` and directly by the ones that replace it. Four arms and one fall-through, and
/// the return values are three different things — `-2` for "this command is not supported", `-1` for
/// "the table entry is malformed" (an internal error), `0` for one specific arm, `1` for pass —
/// which the callers distinguish because `-2` is handed back to the caller of
/// `EVP_PKEY_CTX_ctrl` unchanged.
///
/// `ctx` is **not read**: the authority passes it and no arm uses it. It is named `_ctx` so the
/// signature is the authority's without an unused-binding warning, and the omission is one the
/// authority makes rather than one this transcription makes.
///
/// `ossl_assert` is a **live** guard, not a debug one — D167: under `NDEBUG` it is
/// `ossl_likely((x) != 0)`, the identity on a boolean, so `if (!ossl_assert(C))` is `if (!C)`. Each
/// of the six sites is therefore a plain negation here, and the two-condition tests are `||` of two
/// negations rather than a conjunction.
///
/// # Safety
/// `translation` NULL or live; `ctx` NULL or live.
#[allow(dead_code)] // slices (3)-(5): called by `default_fixup_args` and the seven entry points
pub(crate) unsafe fn default_check(
    state: XlatState,
    translation: *const XlatEntry,
    _ctx: *const XlatCtx,
) -> c_int {
    match state {
        XlatState::PreCtrlToParams => {
            if translation.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_306) };
                return -2;
            }
            // SAFETY: `translation` is non-null here.
            let (param_key, param_data_type) =
                unsafe { ((*translation).param_key, (*translation).param_data_type) };
            if param_key.is_null() || param_data_type == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_311) };
                return -1;
            }
        }
        XlatState::PreCtrlStrToParams => {
            /* For ctrl_str to params translation a direct `OSSL_PARAM` key is allowed as the ctrl_str
             * key, so a NULL `translation` is legal here and the fixup function deals with it. */
            if !translation.is_null() {
                // SAFETY: `translation` is non-null here.
                let (action_type, param_key, param_data_type) = unsafe {
                    (
                        (*translation).action_type,
                        (*translation).param_key,
                        (*translation).param_data_type,
                    )
                };
                if action_type == XlatAction::Get {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_324) };
                    return -2;
                }
                if param_key.is_null() || param_data_type == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_329) };
                    return 0;
                }
            }
        }
        XlatState::PreParamsToCtrl | XlatState::PostParamsToCtrl => {
            if translation.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_337) };
                return -2;
            }
            // SAFETY: `translation` is non-null here.
            let (ctrl_num, param_data_type) =
                unsafe { ((*translation).ctrl_num, (*translation).param_data_type) };
            if ctrl_num == 0 || param_data_type == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_342) };
                return -1;
            }
        }
        // The remaining six states have nothing to check.
        XlatState::Pkey
        | XlatState::PostCtrlToParams
        | XlatState::CleanupCtrlToParams
        | XlatState::PostCtrlStrToParams
        | XlatState::CleanupCtrlStrToParams
        | XlatState::CleanupParamsToCtrl => {}
    }
    1
}

/// `static int cleanup_translation_ctx(enum state state, const struct translation_st *translation,
/// struct translation_ctx_st *ctx)` — `crypto/evp/ctrl_params_translate.c:713`.
///
/// Frees `allocated_buf` if a fixup allocated one and always answers 1 — and it is installed in the
/// tables' `fixup_args` slot for the three `CLEANUP_*` states rather than being called by the
/// translation loop, which is why its return value is a `c_int` it never varies. The two `state` and
/// `translation` parameters are unread, as in the authority.
///
/// # Safety
/// `ctx` must be live; `allocated_buf` must be NULL or a block this module allocated.
#[allow(dead_code)] // installed in the two translation tables, which land with slices (3) and (4)
pub(crate) unsafe fn cleanup_translation_ctx(
    _state: XlatState,
    _translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let allocated = unsafe { (*ctx).allocated_buf };
    if !allocated.is_null() {
        // SAFETY: `allocated` is this module's own block per the contract.
        unsafe { CRYPTO_free(allocated, FILE, LINE_FREE_XLAT_CTX) };
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).allocated_buf = ptr::null_mut() };
    1
}

// ---------------------------------------------------------------------------------------------
// The `fix_*` functions — slice (2) of `ctrl_params_translate.c`, and the first half of it.
//
// A `fixup_args` function runs *around* the real call: before it for a `SET`, after it for a `GET`,
// and in both cases it may move `p1`, `p2` and `*params` so that the ctrl arguments and the parameter
// element line up. The four helpers below are the authority's own `static` wrappers over the real
// lookups, and they exist because the tables store **function pointers of one type** while the real
// functions return `const EVP_CIPHER *` and `const EVP_MD *`: `fix_cipher_md` is written once and
// parameterised by the two names, which is what lets `fix_cipher` and `fix_md` be three lines each.
// ---------------------------------------------------------------------------------------------

/// `static const char *get_cipher_name(void *cipher)` — `crypto/evp/ctrl_params_translate.c:728`.
///
/// # Safety
/// `cipher` must be NULL or a live `EVP_CIPHER`.
#[allow(dead_code)] // slices (3)-(5): `fix_cipher` is the caller, and the tables name it in slice (4)
unsafe extern "C" fn get_cipher_name(cipher: *mut c_void) -> *const c_char {
    // SAFETY: `cipher` is NULL or live per the contract.
    unsafe { EVP_CIPHER_get0_name(cipher.cast::<EvpCipher>()) }
}

/// `static const char *get_md_name(void *md)` — `crypto/evp/ctrl_params_translate.c:733`.
///
/// # Safety
/// `md` must be NULL or a live `EVP_MD`.
#[allow(dead_code)] // as above, for `fix_md`
unsafe extern "C" fn get_md_name(md: *mut c_void) -> *const c_char {
    // SAFETY: `md` is NULL or live per the contract.
    unsafe { EVP_MD_get0_name(md.cast::<crate::evp::digest::EvpMd>()) }
}

/// `static const void *get_cipher_by_name(OSSL_LIB_CTX *libctx, const char *name)` —
/// `crypto/evp/ctrl_params_translate.c:738`.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
#[allow(dead_code)] // as above, for `fix_cipher`
unsafe extern "C" fn get_cipher_by_name(libctx: *mut c_void, name: *const c_char) -> *const c_void {
    // SAFETY: both are forwarded under this function's contract.
    unsafe { evp_get_cipherbyname_ex(libctx, name) }.cast::<c_void>()
}

/// `static const void *get_md_by_name(OSSL_LIB_CTX *libctx, const char *name)` —
/// `crypto/evp/ctrl_params_translate.c:743`.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
#[allow(dead_code)] // as above, for `fix_md`
unsafe extern "C" fn get_md_by_name(libctx: *mut c_void, name: *const c_char) -> *const c_void {
    // SAFETY: both are forwarded under this function's contract.
    unsafe { evp_get_digestbyname_ex(libctx, name) }.cast::<c_void>()
}

/// The shape of the authority's `(*get_name)(void *algo)` parameter of `fix_cipher_md`.
#[allow(dead_code)] // slices (3)-(4): `fix_cipher_md`'s parameter, and the tables' instantiations
pub(crate) type XlatGetNameFn = unsafe extern "C" fn(*mut c_void) -> *const c_char;
/// The shape of its `(*get_algo_by_name)(OSSL_LIB_CTX *, const char *)` parameter.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) type XlatGetByNameFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_void;

/// `static int fix_cipher_md(enum state state, const struct translation_st *translation,
/// struct translation_ctx_st *ctx, const char *(*get_name)(void *algo),
/// const void *(*get_algo_by_name)(OSSL_LIB_CTX *libctx, const char *name))` —
/// `crypto/evp/ctrl_params_translate.c:748`.
///
/// The `EVP_CIPHER`/`EVP_MD` translation, and the reason it is a *parameterised* function rather than
/// two: the ctrl passes the algorithm either as a NID in `p1` or as a pointer in `p2`, while the
/// parameter passes it as its **name**. So a `SET` turns one of the two into a name and a length, and a
/// `GET` has to do the reverse — and the `GET` is the intricate half, because the ctrl's output
/// parameter is a pointer *to* the caller's slot. `orig_p2` remembers the slot before `p2` is
/// redirected at `name_buf`, and the `POST_CTRL_TO_PARAMS` arm writes the looked-up algorithm back
/// through it.
///
/// Three details are copied rather than tidied. `p2 == NULL` in the `PRE_CTRL_TO_PARAMS` `SET` arm
/// means "the caller passed a NID", so `OBJ_nid2sn(p1)` answers the name and a non-NULL `p2` is taken
/// as an algorithm pointer. The `POST_PARAMS_TO_CTRL` `GET` arm substitutes `""` for a NULL `p2` and
/// **still** calls `strlen` on the result, which is why the empty string and not NULL is the
/// placeholder. And `ctx->p1` is 1 or 0 and not a length in the two final arms: the caller of the ctrl
/// reads it as success/failure there, not as a size.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with a live `pctx`; `get_name` and `get_algo_by_name` are the
/// authority's own helpers, which is what their contract is.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_cipher_md(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    get_name: XlatGetNameFn,
    get_algo_by_name: XlatGetByNameFn,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let (action_type, p1, p2) = unsafe { ((*ctx).action_type, (*ctx).p1, (*ctx).p2) };

    if state == XlatState::PreCtrlToParams && action_type == XlatAction::Get {
        /* `p2` holds the address of the caller's `EVP_CIPHER *`/`EVP_MD *`. Remember it, point `p2` at
         * the name buffer, and set `p1` to that buffer's size; `default_fixup_args` does the rest. */
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).orig_p2 = p2;
            (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
            (*ctx).p1 = OSSL_MAX_NAME_SIZE as c_int;
        }
    } else if state == XlatState::PreCtrlToParams && action_type == XlatAction::Set {
        /* This ctrl is used two ways in different parts of OpenSSL: some callers pass a NID as `p1`,
         * others an algorithm pointer as `p2`. */
        // SAFETY: `get_name` is the authority's own helper and `p2` is either NULL or the live
        // algorithm it documents.
        let name = unsafe {
            if p2.is_null() {
                OBJ_nid2sn(p1)
            } else {
                get_name(p2)
            }
        };
        // SAFETY: `name` is NUL-terminated: `OBJ_nid2sn` answers a static short name and `get_name`
        // answers the algorithm's own name.
        unsafe {
            (*ctx).p2 = name.cast_mut().cast::<c_void>();
            (*ctx).p1 = strlen(name) as c_int;
        }
    } else if state == XlatState::PostParamsToCtrl && action_type == XlatAction::Get {
        /* The NULL `p2` placeholder is the empty string, and `strlen` is called on it either way. */
        // SAFETY: `get_name` is the authority's own helper; `p2` is NULL or the live algorithm.
        let name = unsafe {
            if p2.is_null() {
                c"".as_ptr()
            } else {
                get_name(p2)
            }
        };
        // SAFETY: `name` is NUL-terminated.
        unsafe {
            (*ctx).p2 = name.cast_mut().cast::<c_void>();
            (*ctx).p1 = strlen(name) as c_int;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if state == XlatState::PostCtrlToParams && action_type == XlatAction::Get {
        /* `orig_p2`, set in the `PRE_CTRL_TO_PARAMS` arm above, is the caller's own slot. */
        // SAFETY: `ctx` is live and `orig_p2` is the live slot the caller passed.
        unsafe {
            let name = (*ctx).p2 as *const c_char;
            let found = get_algo_by_name((*(*ctx).pctx).libctx, name);
            *(*ctx).orig_p2.cast::<*mut c_void>() = found.cast_mut();
            (*ctx).p1 = 1;
        }
    } else if state == XlatState::PreParamsToCtrl && action_type == XlatAction::Set {
        // SAFETY: `ctx` is live and `pctx` is live per the contract.
        unsafe {
            let name = (*ctx).p2 as *const c_char;
            (*ctx).p2 = get_algo_by_name((*(*ctx).pctx).libctx, name)
                .cast_mut()
                .cast::<c_void>();
            (*ctx).p1 = 0;
        }
    }

    ret
}

/// `static int fix_cipher(...)` — `crypto/evp/ctrl_params_translate.c:804`.
///
/// # Safety
/// As [`fix_cipher_md`].
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_cipher(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: the two helpers are this module's own statics with the documented contracts.
    unsafe { fix_cipher_md(state, translation, ctx, get_cipher_name, get_cipher_by_name) }
}

/// `static int fix_md(...)` — `crypto/evp/ctrl_params_translate.c:812`.
///
/// # Safety
/// As [`fix_cipher_md`].
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_md(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: the two helpers are this module's own statics with the documented contracts.
    unsafe { fix_cipher_md(state, translation, ctx, get_md_name, get_md_by_name) }
}

/// `static int fix_distid_len(...)` — `crypto/evp/ctrl_params_translate.c:820`.
///
/// The shortest fixer, and the one that shows the shape: `default_fixup_args` first, then the
/// caller's own work. It answers **0** in every state but the two `POST_*` `GET` arms, so a caller
/// reading its return value sees "written" or nothing — and the `sz` it writes is
/// `default_fixup_args`'s, not this function's.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with a writable `p2` in the two `POST_*` `GET` arms.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_distid_len(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_fixup_args(state, translation, ctx) };

    if ret > 0 {
        ret = 0;
        // SAFETY: `ctx` is live.
        let action_type = unsafe { (*ctx).action_type };
        if (state == XlatState::PostCtrlToParams || state == XlatState::PostCtrlStrToParams)
            && action_type == XlatAction::Get
        {
            // SAFETY: `p2` is the caller's writable `size_t *` in this arm.
            unsafe {
                *(*ctx).p2.cast::<usize>() = (*ctx).sz;
            }
            ret = 1;
        }
    }
    ret
}

/// `struct kdf_type_map_st` — `crypto/evp/ctrl_params_translate.c:834`.
///
/// **The name is `Option<&CStr>` where the authority has `const char *`, and the terminator is why.**
/// The table is walked until the string is NULL, so the field has to be nullable; the *empty* string is
/// a value the DH map uses for "no KDF", so NULL and `""` must stay distinct; and `&'static CStr` is
/// `Sync`, which a bare `*const c_char` is not, so a `static` table of this shape would not compile
/// with the authority's spelling. `ErrSite` carries its strings the same way.
#[repr(C)]
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) struct KdfTypeMap {
    /// `int kdf_type_num`.
    kdf_type_num: c_int,
    /// `const char *kdf_type_str` — NULL terminates the table.
    kdf_type_str: Option<&'static CStr>,
}

/// `EVP_PKEY_DH_KDF_NONE` — `include/openssl/dh.h:83`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
const EVP_PKEY_DH_KDF_NONE: c_int = 1;
/// `EVP_PKEY_DH_KDF_X9_42` — `include/openssl/dh.h:84`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
const EVP_PKEY_DH_KDF_X9_42: c_int = 2;
/// `EVP_PKEY_ECDH_KDF_NONE` — `include/openssl/ec.h:66`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
const EVP_PKEY_ECDH_KDF_NONE: c_int = 1;
/// `EVP_PKEY_ECDH_KDF_X9_63` — `include/openssl/ec.h:67`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
const EVP_PKEY_ECDH_KDF_X9_63: c_int = 2;

/// `fix_dh_kdf_type`'s table — `crypto/evp/ctrl_params_translate.c:927`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
static KDF_TYPE_MAP_DH: [KdfTypeMap; 3] = [
    KdfTypeMap {
        kdf_type_num: EVP_PKEY_DH_KDF_NONE,
        kdf_type_str: Some(c""),
    },
    KdfTypeMap {
        kdf_type_num: EVP_PKEY_DH_KDF_X9_42,
        kdf_type_str: Some(c"X942KDF-ASN1"),
    },
    KdfTypeMap {
        kdf_type_num: 0,
        kdf_type_str: None,
    },
];

/// `fix_ec_kdf_type`'s table — `crypto/evp/ctrl_params_translate.c:941`.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
static KDF_TYPE_MAP_EC: [KdfTypeMap; 3] = [
    KdfTypeMap {
        kdf_type_num: EVP_PKEY_ECDH_KDF_NONE,
        kdf_type_str: Some(c""),
    },
    KdfTypeMap {
        kdf_type_num: EVP_PKEY_ECDH_KDF_X9_63,
        kdf_type_str: Some(c"X963KDF"),
    },
    KdfTypeMap {
        kdf_type_num: 0,
        kdf_type_str: None,
    },
];

/// `static int fix_kdf_type(enum state state, ... const struct kdf_type_map_st *kdf_type_map)` —
/// `crypto/evp/ctrl_params_translate.c:843`.
///
/// `EVP_PKEY_CTRL_DH_KDF_TYPE` is **bidirectional in one ctrl**, which is the whole reason this
/// function exists separately: it answers the current type into `p2` when `p1` is `-2`, and sets the
/// type from `p1` otherwise. So the `PRE_CTRL_TO_PARAMS` arm reads `p1` to decide the action type —
/// the case `enum action`'s 0 exists for — and a `GET` needs somewhere to put the *string*, which is
/// why it points `p2` at `name_buf` and sets `p1` to that buffer's size. The authority's own comment
/// says that would be unnecessary if the parameter's data type were `UTF8_PTR`.
///
/// **Two details are copied.** `default_check` is called **twice** — once before the action type is
/// decided and once after — and the second call is not redundant, because the first ran with
/// `action_type == NONE` in the one state where the assertion demands it. And the second table walk
/// starts from wherever the first left the pointer: the two walks are in mutually exclusive
/// state/action pairs, so the pointer is always at the table's head when either runs, and the source
/// reuses the parameter rather than resetting it.
///
/// # Safety
/// `translation` NULL or live; `ctx` live; `kdf_type_map` points at a NULL-terminated table of live
/// entries.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_kdf_type(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    kdf_type_map: *const KdfTypeMap,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    let mut map = kdf_type_map;

    if state == XlatState::PreCtrlToParams {
        /* The table's initial `action_type` must be `NONE`; `ossl_assert` is a live guard (D167). */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).action_type } != XlatAction::None_ {
            return 0;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).p1 } == -2 {
            /* The getter needs space for a copy of the type *string*, and `name_buf` has it. */
            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
                (*ctx).p1 = OSSL_MAX_NAME_SIZE as c_int;
                (*ctx).action_type = XlatAction::Get;
            }
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).action_type = XlatAction::Set };
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let action_type = unsafe { (*ctx).action_type };

    if (state == XlatState::PreCtrlToParams && action_type == XlatAction::Set)
        || (state == XlatState::PostParamsToCtrl && action_type == XlatAction::Get)
    {
        /* Numbers to strings. */
        ret = -2;
        // SAFETY: `map` walks a NULL-terminated table of live entries.
        loop {
            // SAFETY: `map` walks a NULL-terminated table of live entries.
            let entry = unsafe { &*map };
            let Some(s) = entry.kdf_type_str else {
                break;
            };
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).p1 } == entry.kdf_type_num {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).p2 = s.as_ptr().cast_mut().cast::<c_void>() };
                ret = 1;
                break;
            }
            // SAFETY: the table is NULL-terminated, so the next entry is inside it or is the
            // terminator.
            map = unsafe { map.add(1) };
        }
        if ret <= 0 {
            return ret;
        }
        // SAFETY: `p2` was just set to a NUL-terminated static string.
        unsafe { (*ctx).p1 = strlen((*ctx).p2.cast::<c_char>()) as c_int };
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let action_type = unsafe { (*ctx).action_type };

    if (state == XlatState::PostCtrlToParams && action_type == XlatAction::Get)
        || (state == XlatState::PreParamsToCtrl && action_type == XlatAction::Set)
    {
        /* Strings to numbers. */
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p1 = -1 };
        ret = -1;
        // SAFETY: `map` walks the same NULL-terminated table.
        loop {
            // SAFETY: `map` walks a NULL-terminated table of live entries.
            let entry = unsafe { &*map };
            let Some(s) = entry.kdf_type_str else {
                break;
            };
            // SAFETY: `ctx` is live and `s` is a NUL-terminated static string.
            if unsafe { OPENSSL_strcasecmp((*ctx).p2.cast::<c_char>(), s.as_ptr()) } == 0 {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).p1 = entry.kdf_type_num };
                ret = 1;
                break;
            }
            // SAFETY: as above.
            map = unsafe { map.add(1) };
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p2 = ptr::null_mut() };
    } else if state == XlatState::PreParamsToCtrl && action_type == XlatAction::Get {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p1 = -2 };
    }

    ret
}

/// `static int fix_dh_kdf_type(...)` — `crypto/evp/ctrl_params_translate.c:927`.
///
/// # Safety
/// As [`fix_kdf_type`]; the table is this module's own static.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_dh_kdf_type(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: the table is a `static` whose last entry is the NULL terminator.
    unsafe { fix_kdf_type(state, translation, ctx, KDF_TYPE_MAP_DH.as_ptr()) }
}

/// `static int fix_ec_kdf_type(...)` — `crypto/evp/ctrl_params_translate.c:941`.
///
/// # Safety
/// As [`fix_kdf_type`]; the table is this module's own static.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_ec_kdf_type(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: the table is a `static` whose last entry is the NULL terminator.
    unsafe { fix_kdf_type(state, translation, ctx, KDF_TYPE_MAP_EC.as_ptr()) }
}

/// `static int fix_oid(...)` — `crypto/evp/ctrl_params_translate.c:955`.
///
/// `EVP_PKEY_CTRL_DH_KDF_OID` and its getter, and the one fixer whose two halves are symmetric: a ctrl
/// passes an `ASN1_OBJECT`, a parameter passes the object's **text**, so the `SET` from a ctrl and the
/// `GET` into a parameter both call `OBJ_obj2txt` into `name_buf`, and the other two directions both
/// call `OBJ_txt2obj`. `p1` is set to 0 before `default_fixup_args` so that *it* computes the length
/// from the string rather than being told one.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` an `ASN1_OBJECT` in the first arm and a
/// NUL-terminated name in the second.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn fix_oid(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let action_type = unsafe { (*ctx).action_type };

    if (state == XlatState::PreCtrlToParams && action_type == XlatAction::Set)
        || (state == XlatState::PostParamsToCtrl && action_type == XlatAction::Get)
    {
        /* `p2` points at an `ASN1_OBJECT`; replace it with the object's text. */
        // SAFETY: `ctx` is live and `p2` is the live object the two arms document.
        unsafe {
            OBJ_obj2txt(
                (*ctx).name_buf.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                (*ctx).p2.cast::<crate::runtime::obj::Asn1Object>(),
                0,
            );
            (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
            /* 0 tells `default_fixup_args` to figure the length out. */
            (*ctx).p1 = 0;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let action_type = unsafe { (*ctx).action_type };

    if (state == XlatState::PreParamsToCtrl && action_type == XlatAction::Set)
        || (state == XlatState::PostCtrlToParams && action_type == XlatAction::Get)
    {
        /* `default_fixup_args` put the object's name in `p2`; replace it with the parsed object. */
        // SAFETY: `ctx` is live and `p2` is the NUL-terminated name the two arms document.
        unsafe {
            (*ctx).p2 = OBJ_txt2obj((*ctx).p2.cast::<c_char>(), 0).cast::<c_void>();
        }
    }

    ret
}

// ---------------------------------------------------------------------------------------------
// Error data text — the `"[action:%d, state:%d]"` prefix the eight data-carrying sites share
// ---------------------------------------------------------------------------------------------

/// Append a decimal `int` to `m`, the way `%d` does — sign, then digits, with no leading zeros and
/// no plus sign.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
fn push_int(m: &mut Vec<u8>, v: c_int) {
    if v < 0 {
        m.push(b'-');
    }
    /* `unsigned_abs` so that `i32::MIN` does not overflow, which the C does not have to think about
     * because it formats an `int` through a widened conversion. */
    let mut digits = [0u8; 10];
    let mut n = 0;
    let mut u = v.unsigned_abs();
    loop {
        digits[n] = b'0' + (u % 10) as u8;
        n += 1;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    while n > 0 {
        n -= 1;
        m.push(digits[n]);
    }
}

/// The authority's `ERR_raise_data(..., "[action:%d, state:%d]...", ...)` text.
///
/// `tail` is the site's own suffix, which differs at all eight of them — one of them says "trying to
/// get a BIGNUM via ctrl call", one "only setting allowed", one "name=%s, value=%s", and two differ
/// only in that one says "unknown" where the other says "unsupported". Reproducing the whole of each
/// string is what makes the message text the authority's rather than approximate, which is why the
/// two near-identical ones are two constants rather than one.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
fn action_state_prefix(action: XlatAction, state: XlatState) -> Vec<u8> {
    let mut m = b"[action:".to_vec();
    push_int(&mut m, action as c_int);
    m.extend_from_slice(b", state:");
    push_int(&mut m, state as c_int);
    m.push(b']');
    m
}

/// Raise at `site` with the prefix and nothing else.
///
/// # Safety
/// The site is a compile-time constant whose pointers are static.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
unsafe fn raise_action_state(site: &err_sites::ErrSite, action: XlatAction, state: XlatState) {
    let mut m = action_state_prefix(action, state);
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `default_fixup_args`'s BIGNUM arm is the one data site whose text stops before a `%d`, so it is
/// built from the prefix plus a literal.
///
/// # Safety
/// As [`raise_action_state`].
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
unsafe fn raise_action_state_tail(
    site: &err_sites::ErrSite,
    action: XlatAction,
    state: XlatState,
    tail: &[u8],
) {
    let mut m = action_state_prefix(action, state);
    m.push(b' ');
    m.extend_from_slice(tail);
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// The two `%d`-terminated data sites, whose text ends in the offending `param_data_type`.
///
/// # Safety
/// As [`raise_action_state`].
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
unsafe fn raise_action_state_tail_int(
    site: &err_sites::ErrSite,
    action: XlatAction,
    state: XlatState,
    tail: &[u8],
    value: c_int,
) {
    let mut m = action_state_prefix(action, state);
    m.push(b' ');
    m.extend_from_slice(tail);
    m.push(b' ');
    push_int(&mut m, value);
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `default_fixup_args`'s `name=%s, value=%s` site.
///
/// # Safety
/// Both arguments must be NULL or NUL-terminated.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
unsafe fn raise_action_state_names(
    site: &err_sites::ErrSite,
    action: XlatAction,
    state: XlatState,
    name: *const c_char,
    value: *const c_char,
) {
    let mut m = action_state_prefix(action, state);
    m.extend_from_slice(b" name=");
    if !name.is_null() {
        // SAFETY: `name` is NUL-terminated per the contract.
        m.extend_from_slice(unsafe { CStr::from_ptr(name) }.to_bytes());
    }
    m.extend_from_slice(b", value=");
    if !value.is_null() {
        // SAFETY: `value` is NUL-terminated per the contract.
        m.extend_from_slice(unsafe { CStr::from_ptr(value) }.to_bytes());
    }
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

// ---------------------------------------------------------------------------------------------
// `default_fixup_args` — the file's core
// ---------------------------------------------------------------------------------------------

/// The `PRE_PARAMS_TO_CTRL` body, reached by `PKEY` and `POST_PARAMS_TO_CTRL` too.
///
/// The authority reaches it by **fallthrough** — `case PKEY: case POST_PARAMS_TO_CTRL: ret = ctx->p1;`
/// then straight into `case PRE_PARAMS_TO_CTRL:` — and Rust has no fallthrough, so the shared body is
/// one function called from all three arms. `ret` is a parameter because the `PKEY` arm seeds it from
/// `ctx->p1` and `PRE_PARAMS_TO_CTRL` leaves it at `default_check`'s 1.
///
/// # Safety
/// As [`default_fixup_args`].
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
unsafe fn default_fixup_args_params_to_ctrl(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    ret: c_int,
) -> c_int {
    // SAFETY: `ctx` is live and `translation` is live — both checked by `default_check`.
    let action_type = unsafe { (*ctx).action_type };

    if state == XlatState::PreParamsToCtrl && action_type == XlatAction::Set {
        /* Setting is the only direction that needs work in the `PRE` state: `p1` and `p2` are
         * populated from `*params`. */
        // SAFETY: `translation` is live.
        let param_data_type = unsafe { (*translation).param_data_type };
        match param_data_type {
            OSSL_PARAM_INTEGER => {
                // SAFETY: `ctx` is live and its `params` is the caller's element.
                return unsafe { OSSL_PARAM_get_int((*ctx).params, ptr::addr_of_mut!((*ctx).p1)) };
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: `ctx` is live.
                if !unsafe { (*ctx).p2 }.is_null() {
                    /* A BIGNUM was passed down with `p2`. */
                    // SAFETY: `params` is the caller's element and `p2` is the BIGNUM slot.
                    if unsafe { OSSL_PARAM_get_BN((*ctx).params, (*ctx).p2.cast::<*mut BigNum>()) }
                        == 0
                    {
                        return 0;
                    }
                } else {
                    /* A plain C unsigned int was passed down. */
                    // SAFETY: `params` is the caller's element.
                    if unsafe {
                        OSSL_PARAM_get_uint((*ctx).params, ptr::addr_of_mut!((*ctx).p1).cast())
                    } == 0
                    {
                        return 0;
                    }
                }
                return 1;
            }
            OSSL_PARAM_UTF8_STRING => {
                // SAFETY: `params` is the caller's element and `p2`/`sz` are the caller's buffer.
                return unsafe {
                    OSSL_PARAM_get_utf8_string(
                        (*ctx).params,
                        (*ctx).p2.cast::<*mut c_char>(),
                        (*ctx).sz,
                    )
                };
            }
            OSSL_PARAM_OCTET_STRING => {
                // SAFETY: as above, with `p1` receiving the length.
                return unsafe {
                    OSSL_PARAM_get_octet_string(
                        (*ctx).params,
                        (*ctx).p2.cast::<*mut c_void>(),
                        (*ctx).sz,
                        ptr::addr_of_mut!((*ctx).p1).cast::<usize>(),
                    )
                };
            }
            OSSL_PARAM_OCTET_PTR => {
                // SAFETY: `params` is the caller's element and `sz` is its writable length slot.
                return unsafe {
                    OSSL_PARAM_get_octet_ptr(
                        (*ctx).params,
                        (*ctx).p2.cast::<*const c_void>(),
                        ptr::addr_of_mut!((*ctx).sz),
                    )
                };
            }
            _ => {
                // SAFETY: a compile-time-constant site; the `%d` is the offending data type.
                unsafe {
                    raise_action_state_tail_int(
                        &err_sites::CTRL_PARAMS_TRANSLATE_649,
                        action_type,
                        state,
                        b"unknown OSSL_PARAM data type",
                        param_data_type as c_int,
                    )
                };
                return 0;
            }
        }
    } else if (state == XlatState::PostParamsToCtrl || state == XlatState::Pkey)
        && action_type == XlatAction::Get
    {
        /* Getting is the only direction that needs work in the `POST` state: `*params` is populated
         * from `p1` and `p2`. */
        // SAFETY: `translation` is live.
        let mut param_data_type = unsafe { (*translation).param_data_type };
        // SAFETY: `ctx` is live.
        let mut size = unsafe { (*ctx).p1 } as usize;

        if state == XlatState::Pkey {
            // SAFETY: `ctx` is live.
            size = unsafe { (*ctx).sz };
        }
        if param_data_type == 0 {
            /* No declared type means the entry must carry a fixup function to have decided one. */
            // SAFETY: `translation` is live.
            if unsafe { (*translation).fixup_args }.is_none() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_667) };
                return 0;
            }
            // SAFETY: `ctx` is live and `params` is the caller's element.
            param_data_type = unsafe { (*(*ctx).params).data_type };
        }
        match param_data_type {
            OSSL_PARAM_INTEGER => {
                // SAFETY: `ctx` is live and `params` is the caller's element.
                return unsafe { OSSL_PARAM_set_int((*ctx).params, (*ctx).p1) };
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: `ctx` is live.
                if !unsafe { (*ctx).p2 }.is_null() {
                    /* A BIGNUM is passed back. */
                    // SAFETY: `params` is the caller's element and `p2` is the BIGNUM.
                    return unsafe { OSSL_PARAM_set_BN((*ctx).params, (*ctx).p2.cast::<BigNum>()) };
                }
                /* A plain C unsigned int is passed back. */
                // SAFETY: `params` is the caller's element.
                return unsafe { OSSL_PARAM_set_uint((*ctx).params, (*ctx).p1 as c_uint) };
            }
            OSSL_PARAM_UTF8_STRING => {
                // SAFETY: `params` is the caller's element and `p2` is the string.
                return unsafe { OSSL_PARAM_set_utf8_string((*ctx).params, (*ctx).p2.cast()) };
            }
            OSSL_PARAM_OCTET_STRING => {
                // SAFETY: as above, with the length the caller's own return value carries.
                return unsafe { OSSL_PARAM_set_octet_string((*ctx).params, (*ctx).p2, size) };
            }
            OSSL_PARAM_OCTET_PTR => {
                // SAFETY: `params` is the caller's element; `p2` is a pointer *to* the pointer the
                // authority hands on, which is what the deref is.
                return unsafe {
                    OSSL_PARAM_set_octet_ptr(
                        (*ctx).params,
                        *(*ctx).p2.cast::<*const c_void>(),
                        size,
                    )
                };
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_action_state_tail_int(
                        &err_sites::CTRL_PARAMS_TRANSLATE_695,
                        action_type,
                        state,
                        b"unsupported OSSL_PARAM data type",
                        // SAFETY: `translation` is live.
                        (*translation).param_data_type as c_int,
                    )
                };
                return 0;
            }
        }
    } else if state == XlatState::PreParamsToCtrl && action_type == XlatAction::Get {
        // SAFETY: `translation` is live.
        if unsafe { (*translation).param_data_type } == OSSL_PARAM_OCTET_PTR {
            // SAFETY: `ctx` is live; `bufp` is the indirection slot the `POST` arm reads.
            unsafe { (*ctx).p2 = ptr::addr_of_mut!((*ctx).bufp).cast::<c_void>() };
        }
    }
    ret
}

/// `static int default_fixup_args(enum state state, const struct translation_st *translation,
/// struct translation_ctx_st *ctx)` — `crypto/evp/ctrl_params_translate.c:395`.
///
/// The file's core: every table entry that does not name a fixup of its own names this one, and every
/// fixup that does name its own calls this one in the middle. Three states do real work for a `SET`,
/// two for a `GET`, and the rest are pass-through.
///
/// **`ret` is the function's own return value and is not reset by the middle arms.** It starts as
/// `default_check`'s 1, becomes `ctx->p1` in the `PKEY`/`POST_PARAMS_TO_CTRL` arm — which is how a
/// ctrl's return value becomes this function's — and every other arm returns directly instead of
/// falling out. So a transcription that returned a fresh 1 at the end would lose the ctrl's own
/// answer on the `PKEY` path, which is the path `EVP_PKEY_get_params` uses.
///
/// **`PRE_CTRL_STR_TO_PARAMS` is the only arm that can be entered with `translation == NULL`**, and
/// the comment in the authority says why: a ctrl_str key may *be* an `OSSL_PARAM` key, in which case
/// there is no table entry at all and the string is passed through unmodified. That is also why
/// `default_check` allows NULL there and nowhere else.
///
/// The `ishex` arm builds `"hex"` + the parameter key into `name_buf` and checks
/// `OPENSSL_strlcat(...) <= 3` — a *truncation* test, not a failure test: `strlcat` returns the total
/// length it would have written, so `<= 3` means the buffer could not even hold `"hex"` plus the
/// terminator, which is an internal error rather than a caller error.
///
/// # Safety
/// `ctx` must be live; `translation` NULL or live, and non-NULL except in
/// `PRE_CTRL_STR_TO_PARAMS`; every pointer `ctx` carries must be valid for the state and action.
#[allow(dead_code)] // WIP 7.4c-v slices (3)-(5): the two translation tables and the seven entry points are the callers
pub(crate) unsafe fn default_fixup_args(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `state`, `translation` and `ctx` are as the contract states.
    let ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live.
    let action_type = unsafe { (*ctx).action_type };

    match state {
        XlatState::PreCtrlToParams => {
            if action_type == XlatAction::None_ {
                /* No action type here is an error: that case belongs to a special fixup function. */
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_action_state(&err_sites::CTRL_PARAMS_TRANSLATE_424, action_type, state)
                };
                return 0;
            }

            // SAFETY: `translation` is live.
            if unsafe { (*translation).optype } != 0 {
                // SAFETY: `ctx` is live and `pctx` is live per the contract.
                let missing = unsafe {
                    let c = &*(*ctx).pctx;
                    (c.is_signature_op() && c.op_sig_algctx.is_null())
                        || (c.is_derive_op() && c.op_kex_algctx.is_null())
                        || (c.is_asym_cipher_op() && c.op_ciph_algctx.is_null())
                        || (c.is_kem_op() && c.op_encap_algctx.is_null())
                        /* The last two are the authority's "for good measure" pair. */
                        || (c.is_gen_op() && c.op_keymgmt_genctx.is_null())
                        || (c.is_fromdata_op() && c.op_keymgmt_genctx.is_null())
                };
                if missing {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_446) };
                    /* The same return values `EVP_PKEY_CTX_ctrl` uses. */
                    return -2;
                }
            }

            /* `OSSL_PARAM_construct_TYPE` works equally well for `SET` and `GET`. */
            // SAFETY: `translation` is live, and `ctx`'s pointers are the caller's.
            unsafe {
                let key = (*translation).param_key;
                match (*translation).param_data_type {
                    OSSL_PARAM_INTEGER => {
                        *(*ctx).params =
                            OSSL_PARAM_construct_int(key, ptr::addr_of_mut!((*ctx).p1));
                    }
                    OSSL_PARAM_UNSIGNED_INTEGER => {
                        if !(*ctx).p2.is_null() {
                            if action_type == XlatAction::Set {
                                /* BIGNUMs travel in `p2`; the buffer this allocates is the cleanup's.
                                 * `BN_num_bytes(a)` is a macro in the authority --
                                 * `((BN_num_bits(a) + 7) / 8)` -- so it is that expression here, as
                                 * `params/build.rs` writes it. */
                                let bits = BN_num_bits((*ctx).p2.cast::<BigNum>()) as usize;
                                (*ctx).buflen = bits.div_ceil(8);
                                let buf = CRYPTO_malloc((*ctx).buflen, FILE, LINE_XLAT_BN_BUF);
                                if buf.is_null() {
                                    return 0;
                                }
                                (*ctx).allocated_buf = buf;
                                if BN_bn2nativepad(
                                    (*ctx).p2.cast(),
                                    buf.cast::<u8>(),
                                    (*ctx).buflen as c_int,
                                ) < 0
                                {
                                    CRYPTO_free((*ctx).allocated_buf, FILE, LINE_XLAT_BN_BUF);
                                    (*ctx).allocated_buf = ptr::null_mut();
                                    return 0;
                                }
                                *(*ctx).params =
                                    OSSL_PARAM_construct_BN(key, buf.cast::<u8>(), (*ctx).buflen);
                            } else {
                                /* Getting a BIGNUM through a ctrl needs a fixup function's help. */
                                raise_action_state_tail(
                                    &err_sites::CTRL_PARAMS_TRANSLATE_492,
                                    action_type,
                                    state,
                                    b"trying to get a BIGNUM via ctrl call",
                                );
                                return 0;
                            }
                        } else {
                            *(*ctx).params = OSSL_PARAM_construct_uint(
                                key,
                                ptr::addr_of_mut!((*ctx).p1).cast::<c_uint>(),
                            );
                        }
                    }
                    OSSL_PARAM_UTF8_STRING => {
                        *(*ctx).params = OSSL_PARAM_construct_utf8_string(
                            key,
                            (*ctx).p2.cast::<c_char>(),
                            (*ctx).p1 as usize,
                        );
                    }
                    OSSL_PARAM_UTF8_PTR => {
                        *(*ctx).params = OSSL_PARAM_construct_utf8_ptr(
                            key,
                            (*ctx).p2.cast::<*mut c_char>(),
                            (*ctx).p1 as usize,
                        );
                    }
                    OSSL_PARAM_OCTET_STRING => {
                        *(*ctx).params =
                            OSSL_PARAM_construct_octet_string(key, (*ctx).p2, (*ctx).p1 as usize);
                    }
                    OSSL_PARAM_OCTET_PTR => {
                        *(*ctx).params = OSSL_PARAM_construct_octet_ptr(
                            key,
                            (*ctx).p2.cast(),
                            (*ctx).p1 as usize,
                        );
                    }
                    _ => {}
                }
            }
        }

        XlatState::PostCtrlToParams => {
            /* The ctrl returns the length of certain objects, so this arm copies the parameter's
             * own `return_size` back into `p1` for the data types where that makes sense. */
            if action_type == XlatAction::Get {
                // SAFETY: `translation` is live.
                let param_data_type = unsafe { (*translation).param_data_type };
                if matches!(
                    param_data_type,
                    OSSL_PARAM_UTF8_STRING
                        | OSSL_PARAM_UTF8_PTR
                        | OSSL_PARAM_OCTET_STRING
                        | OSSL_PARAM_OCTET_PTR
                ) {
                    // SAFETY: `ctx` is live and `params` points at the caller's element.
                    unsafe { (*ctx).p1 = (*(*ctx).params).return_size as c_int };
                }
            }
        }

        XlatState::PreCtrlStrToParams => {
            /* Only setting is supported here. */
            if action_type != XlatAction::Set {
                // SAFETY: a compile-time-constant site.
                unsafe {
                    raise_action_state_tail(
                        &err_sites::CTRL_PARAMS_TRANSLATE_555,
                        action_type,
                        state,
                        b"only setting allowed",
                    )
                };
                return 0;
            }

            // SAFETY: `ctx` is live.
            let orig_ctrl_str = unsafe { (*ctx).ctrl_str };
            // SAFETY: `ctx` is live.
            let orig_value = unsafe { (*ctx).p2 };
            let mut tmp_ctrl_str = orig_ctrl_str;

            /* With no table entry the control string is passed through unmodified. */
            if !translation.is_null() {
                // SAFETY: `translation` is non-null here.
                let param_key = unsafe { (*translation).param_key };
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).ctrl_str = param_key };
                tmp_ctrl_str = param_key;

                // SAFETY: `ctx` is live.
                if unsafe { (*ctx).ishex } != 0 {
                    // SAFETY: `ctx` is live and `name_buf` is its own array.
                    unsafe {
                        (*ctx).name_buf[0] = b'h' as c_char;
                        (*ctx).name_buf[1] = b'e' as c_char;
                        (*ctx).name_buf[2] = b'x' as c_char;
                        (*ctx).name_buf[3] = 0;
                        if OPENSSL_strlcat(
                            (*ctx).name_buf.as_mut_ptr(),
                            tmp_ctrl_str,
                            OSSL_MAX_NAME_SIZE,
                        ) <= 3
                        {
                            raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_573);
                            return -1;
                        }
                        tmp_ctrl_str = (*ctx).name_buf.as_ptr();
                    }
                }
            }

            // SAFETY: `ctx` is live and `pctx` is live per the contract.
            let settable = unsafe { EVP_PKEY_CTX_settable_params((*ctx).pctx) };
            let mut exists: c_int = 0;
            // SAFETY: `ctx`'s `params`, `settable` and `tmp_ctrl_str` are the caller's element and
            // this context's own strings; `p2` is the NUL-terminated value.
            let ok = unsafe {
                OSSL_PARAM_allocate_from_text(
                    (*ctx).params,
                    settable,
                    tmp_ctrl_str,
                    (*ctx).p2.cast::<c_char>(),
                    strlen((*ctx).p2.cast::<c_char>()),
                    ptr::addr_of_mut!(exists),
                )
            };
            if ok == 0 {
                if exists == 0 {
                    /* The name is not an `OSSL_PARAM` key either: a caller error, and the text
                     * carries which name and which value. */
                    // SAFETY: a compile-time-constant site.
                    unsafe {
                        raise_action_state_names(
                            &err_sites::CTRL_PARAMS_TRANSLATE_586,
                            action_type,
                            state,
                            orig_ctrl_str,
                            orig_value.cast::<c_char>(),
                        )
                    };
                    return -2;
                }
                return 0;
            }
            // SAFETY: `ctx` is live and `params` now points at the element built for us.
            unsafe {
                (*ctx).allocated_buf = (*(*ctx).params).data;
                (*ctx).buflen = (*(*ctx).params).data_size;
            }
        }

        XlatState::PostCtrlStrToParams => {
            /* Nothing to be done: there is no support for getting data through ctrl_str. */
        }

        XlatState::Pkey | XlatState::PostParamsToCtrl => {
            /* The authority falls through into `PRE_PARAMS_TO_CTRL` from here with `ret` seeded from
             * the ctrl's own return value. */
            // SAFETY: `ctx` is live.
            let seeded = unsafe { (*ctx).p1 };
            // SAFETY: `state`, `translation` and `ctx` are as the contract states.
            return unsafe { default_fixup_args_params_to_ctrl(state, translation, ctx, seeded) };
        }

        XlatState::PreParamsToCtrl => {
            // SAFETY: `state`, `translation` and `ctx` are as the contract states.
            return unsafe { default_fixup_args_params_to_ctrl(state, translation, ctx, ret) };
        }

        XlatState::CleanupCtrlToParams
        | XlatState::CleanupCtrlStrToParams
        | XlatState::CleanupParamsToCtrl => {
            /* The three cleanup states never reach this function: `default_check` passes them and
             * the table installs `cleanup_translation_ctx` in their slot. The authority's switch has
             * no case for them either, so they reach its `default:` arm -- which raises. Reproduced
             * rather than silently passed. */
            // SAFETY: a compile-time-constant site.
            unsafe {
                raise_action_state(&err_sites::CTRL_PARAMS_TRANSLATE_407, action_type, state)
            };
            return 0;
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context built by hand, so the state test can be read without a provider.
    fn a_hand_built_ctx() -> EvpPkeyCtx {
        EvpPkeyCtx {
            operation: EVP_PKEY_OP_UNDEFINED,
            libctx: ptr::null_mut(),
            propquery: ptr::null_mut(),
            keytype: ptr::null(),
            keymgmt: ptr::null_mut(),
            op_keymgmt_genctx: ptr::null_mut(),
            op_kex_exchange: ptr::null_mut(),
            op_kex_algctx: ptr::null_mut(),
            op_sig_signature: ptr::null_mut(),
            op_sig_algctx: ptr::null_mut(),
            op_ciph_cipher: ptr::null_mut(),
            op_ciph_algctx: ptr::null_mut(),
            op_encap_kem: ptr::null_mut(),
            op_encap_algctx: ptr::null_mut(),
            cached_parameters: CachedParameters {
                dist_id_name: ptr::null_mut(),
                dist_id: ptr::null_mut(),
                dist_id_len: 0,
                dist_id_set: 0,
            },
            app_data: ptr::null_mut(),
            pkey_gencb: None,
            keygen_info: ptr::null_mut(),
            keygen_info_count: 0,
            legacy_keytype: 0,
            pkey: ptr::null_mut(),
            peerkey: ptr::null_mut(),
            data: ptr::null_mut(),
        }
    }

    /// The three states, and the two transitions between them that matter: an operation bit with no
    /// algorithm context is LEGACY, and clearing the operation is UNKNOWN regardless of the context.
    #[test]
    fn the_state_test_is_a_switch_over_the_operation_and_one_union() {
        let mut ctx = a_hand_built_ctx();

        // SAFETY: `ctx` is this frame's own live object.
        unsafe {
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_UNKNOWN,
                "an undefined operation is unknown"
            );

            ctx.operation = EVP_PKEY_OP_SIGN;
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_LEGACY,
                "a signature operation with no algorithm context is legacy"
            );

            ctx.op_sig_algctx = ptr::addr_of_mut!(ctx).cast::<c_void>();
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_PROVIDER,
                "the same operation with a context is provider"
            );

            /* The context is read by the *family* the operation names, so a DERIVE operation
             * ignores the signature context entirely. */
            ctx.operation = EVP_PKEY_OP_DERIVE;
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_LEGACY,
                "a different family's context is not this one's"
            );

            /* And clearing the operation makes the state UNKNOWN whatever is set, which is why a
             * failed init resets the operation rather than the context. */
            ctx.operation = EVP_PKEY_OP_UNDEFINED;
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_UNKNOWN
            );
        }
    }

    /// The operation bits are a **bit set** and the family masks overlap them: `SIGNMSG` is inside
    /// `TYPE_SIG`, and `TYPE_NOGEN` is everything but the two generation bits.
    #[test]
    fn the_operation_bits_are_masks_and_not_an_enumeration() {
        let mut ctx = a_hand_built_ctx();
        // SAFETY: `ctx` is this frame's own live object.
        unsafe {
            ctx.operation = EVP_PKEY_OP_SIGNMSG;
            assert_eq!(
                evp_pkey_ctx_state(ptr::addr_of!(ctx)),
                EVP_PKEY_STATE_LEGACY
            );
            assert!((*ptr::addr_of!(ctx)).is_signature_op());
            assert!(!(*ptr::addr_of!(ctx)).is_gen_op());

            ctx.operation = EVP_PKEY_OP_TYPE_NOGEN;
            assert!(!(*ptr::addr_of!(ctx)).is_gen_op());
            ctx.operation = EVP_PKEY_OP_KEYGEN;
            assert!((*ptr::addr_of!(ctx)).is_gen_op());
        }
        assert_eq!(
            EVP_PKEY_OP_TYPE_NOGEN,
            EVP_PKEY_OP_ALL & !EVP_PKEY_OP_TYPE_GEN
        );
    }

    /// A NULL context is the whole of the reachable contract for the two **lifetime** functions, and
    /// each answers the way the authority's does: nothing to release, and a NULL copy of nothing.
    ///
    /// `EVP_PKEY_CTX_get0_pkey(NULL)` and `get0_peerkey(NULL)` are deliberately **not** called. Both
    /// read `ctx->pkey` with no NULL test, so they fault the authority *and* the crate -- a mutual
    /// fault, which is neither a divergence nor a comparison. `RT-EVP-PKEY` prints the boundary;
    /// nothing here pretends to measure it.
    #[test]
    fn null_is_reachable_and_releases_nothing() {
        // SAFETY: NULL is the documented argument for both.
        unsafe {
            EVP_PKEY_CTX_free(ptr::null_mut());
            assert!(EVP_PKEY_CTX_dup(ptr::null()).is_null());
        }
    }

    /// The accessors read fields and the two setters store the caller's pointer rather than a copy.
    #[test]
    fn the_accessors_read_and_the_setters_do_not_copy() {
        let mut ctx = a_hand_built_ctx();
        let p: *mut EvpPkeyCtx = ptr::addr_of_mut!(ctx);
        let mut marker: c_int = 7;

        // SAFETY: `ctx` is this frame's own live object and `marker` is a live local.
        unsafe {
            EVP_PKEY_CTX_set0_keygen_info(p, ptr::addr_of_mut!(marker), 1);
            assert_eq!((*p).keygen_info, ptr::addr_of_mut!(marker));
            assert_eq!((*p).keygen_info_count, 1);
            assert_eq!(*ptr::addr_of!(marker), 7, "no copy was taken");

            EVP_PKEY_CTX_set_data(p, ptr::addr_of_mut!(marker).cast::<c_void>());
            assert_eq!(
                EVP_PKEY_CTX_get_data(p),
                ptr::addr_of_mut!(marker).cast::<c_void>()
            );

            assert_eq!(EVP_PKEY_CTX_get_operation(p), EVP_PKEY_OP_UNDEFINED);
            assert!(EVP_PKEY_CTX_get0_libctx(p).is_null());
            assert!(EVP_PKEY_CTX_get0_propq(p).is_null());
            assert!(EVP_PKEY_CTX_get0_provider(p).is_null(), "no live operation");
        }
    }
}
