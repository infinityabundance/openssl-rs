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
use crate::evp::digest::{EVP_MD_get0_name, EvpMd, EvpMdCtx};
use crate::evp::exchange::{EVP_KEYEXCH_get0_provider, EvpKeyExch};
use crate::evp::kdf::OSSL_KDF_PARAM_KEY;
use crate::evp::kem::{EVP_KEM_get0_provider, EvpKem};
use crate::evp::keymgmt::{
    evp_keymgmt_gen_get_params, evp_keymgmt_gen_set_params, evp_keymgmt_get_legacy_alg,
    EVP_KEYMGMT_fetch, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_provider, EVP_KEYMGMT_is_a, EvpKeyMgmt,
};
use crate::evp::legacy_evp::{
    evp_get_cipherbyname_ex, evp_get_digestbyname_ex, EVP_get_digestbyname,
};
use crate::evp::mac::OSSL_MAC_PARAM_SIZE;
use crate::evp::pbe::{
    OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_SALT, OSSL_KDF_PARAM_SCRYPT_MAXMEM,
    OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P, OSSL_KDF_PARAM_SCRYPT_R,
};
use crate::evp::pkey::{
    evp_pkey_name2type, evp_pkey_type2name, EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_asn1::Engine;
use crate::evp::signature::{EVP_SIGNATURE_get0_provider, EvpSignature};
use crate::params::from_text::OSSL_PARAM_allocate_from_text;
use crate::params::{
    OSSL_PARAM_construct_BN, OSSL_PARAM_construct_end, OSSL_PARAM_construct_int,
    OSSL_PARAM_construct_octet_ptr, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint,
    OSSL_PARAM_construct_uint64, OSSL_PARAM_construct_utf8_ptr, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_get_octet_ptr, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_uint, OSSL_PARAM_get_utf8_string, OSSL_PARAM_get_utf8_string_ptr,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_BN, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string, OsslParam,
};
use crate::params::{
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNMODIFIED,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::{ossl_provider_ctx, OsslProvider};
use crate::runtime::bio::sys::{strcmp, strlen, strtol};
use crate::runtime::err::raise_site_data;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::obj::{
    NID_X9_62_id_ecPublicKey, NID_dhKeyAgreement, NID_dhpublicnumber, NID_dsa, NID_rsaEncryption,
    NID_rsassaPss, NID_sm2, NID_undef, NID_X25519, NID_X448,
};
use crate::runtime::obj::{OBJ_nid2sn, OBJ_sn2nid};
use crate::runtime::obj::{OBJ_obj2txt, OBJ_txt2obj};
use crate::runtime::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::{OPENSSL_hexstr2buf, OPENSSL_strcasecmp, OPENSSL_strlcat};
use core::ffi::c_long;
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
/// `EVP_PKEY_OP_ALL` — every bit above, and the mask `EVP_PKEY_OP_TYPE_NOGEN` is built from.
#[allow(dead_code)] // read only by the unit test below and by `EVP_PKEY_OP_TYPE_NOGEN`
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
/// `EVP_PKEY_OP_TYPE_NOGEN` — every operation *except* the two generation ones.
#[allow(dead_code)] // read only by the unit test below; its authority readers are Phase 8's callbacks
pub(crate) const EVP_PKEY_OP_TYPE_NOGEN: c_int = EVP_PKEY_OP_ALL & !EVP_PKEY_OP_TYPE_GEN;

/// `EVP_PKEY_STATE_UNKNOWN` — `include/crypto/evp.h`.
pub(crate) const EVP_PKEY_STATE_UNKNOWN: c_int = 0;
/// `EVP_PKEY_STATE_LEGACY`.
pub(crate) const EVP_PKEY_STATE_LEGACY: c_int = 1;
/// `EVP_PKEY_STATE_PROVIDER`.
pub(crate) const EVP_PKEY_STATE_PROVIDER: c_int = 2;

/// `EVP_PKEY_CTRL_SET1_ID` — `include/openssl/evp.h:1824`. The one command the cached-data
/// machinery handles, and **not 13**: 13 is `EVP_PKEY_CTRL_GET_MD`. The crate carried 13 here until
/// this slice, which was invisible while nothing compared a caller's ctrl number against it and is
/// not invisible now that `EVP_PKEY_CTX_ctrl` does — a C caller passing the header's 15 would have
/// been answered `EVP_R_COMMAND_NOT_SUPPORTED`.
pub(crate) const EVP_PKEY_CTRL_SET1_ID: c_int = 15;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c".as_ptr();
/// `int_ctx_new`'s `OPENSSL_zalloc(sizeof(*ret))` (line 297).
const LINE_ZALLOC_CTX: c_int = 297;
/// `int_ctx_new`'s `OPENSSL_free(ret)` after a failed `OPENSSL_strdup` (line 312).
const LINE_FREE_CTX: c_int = 312;
/// `evp_pkey_ctx_add1_octet_string`'s `OPENSSL_zalloc(info_alloc)` (line 1069).
const LINE_ZALLOC_XLAT_BN_BUF: c_int = 1069;
/// Its `OPENSSL_clear_free(info, info_alloc)`, at both the error label and the success exit
/// (line 1087).
const LINE_FREE_XLAT_ADD1: c_int = 1087;
/// `evp_pkey_ctx_store_cached_data`'s `OPENSSL_strdup(name)` (line 1499).
const LINE_STRDUP_DIST_ID: c_int = 1499;
/// Its `OPENSSL_memdup(data, data_len)` (line 1504).
const LINE_MEMDUP_DIST_ID: c_int = 1504;
/// `EVP_PKEY_CTX_hex2ctrl`'s `OPENSSL_free(bin)` (line 1605).
const LINE_FREE_HEXCTRL: c_int = 1605;

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
    fn is_fromdata_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_DATA) != 0
    }
}

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
/// Its authority caller is `EVP_PKEY_CTX_free`, which calls *this* one rather than the pair's other
/// half; `EVP_PKEY_CTX_free` above does the same. The `_free_cached_data` singletons that the rest of
/// this file needs are `decode_cmd`'s one command, which is why the pair exists at all.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn evp_pkey_ctx_free_all_cached_data(ctx: *mut EvpPkeyCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_ctx_free_cached_data(ctx) };
}

/// `int evp_pkey_ctx_use_cached_data(EVP_PKEY_CTX *ctx)` — `crypto/evp/pmeth_lib.c:1534`.
///
/// The **replay** half of the cached-data trio: `evp_pkey_ctx_store_cached_data` remembers what a
/// `ctrl_str` could not deliver, and this hands it to the operation once the operation exists. Its
/// only two authority callers are the `end:` labels of `evp_pkey_signature_init`
/// (`crypto/evp/signature.c`) and of `evp_digest_signverify_init` (`crypto/evp/m_sigver.c`), and
/// both guard the call with `ret > 0`, so an init that refused does not replay. The row this
/// discharges in `forensics/prerequisites.json` named three callers — `signature.c`, `exchange.c`
/// and `pmeth_gn.c` — and **only the first of the three calls it**; `exchange.c`'s derive init and
/// `pmeth_gn.c` have no cached-data step at all. That is recorded in `docs/DECISIONS.md` D189.
///
/// Two things are the authority's shape rather than an obvious choice:
///
///   * `ret` starts at **1** and the test is `ret && dist_id_set`, so a context with no cached
///     identifier answers 1: "nothing to replay" and "the replay succeeded" are the same answer,
///     which is what lets each caller use this as a suffix rather than as a step;
///   * the two arms are chosen by `dist_id_name`, not by the command. A name exists when the
///     identifier arrived through `ctrl_str` and is replayed as a *string*; a nameless store (the
///     `ctrl` path) replays through the numeric ctrl, with the **live** `ctx->operation` rather
///     than a stored one — the operation is only ever read at replay time because the store time
///     had no operation to record.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn evp_pkey_ctx_use_cached_data(ctx: *mut EvpPkeyCtx) -> c_int {
    let mut ret = 1;

    // SAFETY: `ctx` is live per the contract.
    let c = unsafe { &*ctx };
    if ret != 0 && c.cached_parameters.dist_id_set != 0 {
        let name = c.cached_parameters.dist_id_name;
        let val = c.cached_parameters.dist_id;
        let len = c.cached_parameters.dist_id_len;

        if !name.is_null() {
            // SAFETY: `name` is NUL-terminated, and `val` is the NUL-terminated string the
            // `ctrl_str` path duplicated into `dist_id`.
            ret = unsafe { evp_pkey_ctx_ctrl_str_int(ctx, name, val.cast()) };
        } else {
            // SAFETY: `ctx` is live and `val` is NULL or `len` readable bytes.
            ret = unsafe {
                evp_pkey_ctx_ctrl_int(
                    ctx,
                    -1,
                    c.operation,
                    EVP_PKEY_CTRL_SET1_ID,
                    len as c_int,
                    val,
                )
            };
        }
    }

    ret
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
/// **The cached-data step calls `evp_pkey_ctx_free_all_cached_data`, not `_free_cached_data`, and
/// this slice is where that distinction acquired a reader.** The authority's line 399 is the *all*
/// variant; the crate called the one-command variant here since 7.4c-i, which is behaviourally
/// identical because the all-variant's body is one call to it, and wrong in the one way that
/// matters to a reader: it made the all-variant look uncalled and its `#[allow(dead_code)]` look
/// load-bearing. The call is the authority's now.
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
    unsafe { evp_pkey_ctx_free_all_cached_data(ctx) };
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
/// `cleanup_translation_ctx`'s `OPENSSL_free(ctx->allocated_buf)` — the authority's line 718.
const LINE_FREE_XLAT_CTX: c_int = 718;
/// `default_fixup_args`'s `OPENSSL_malloc(ctx->buflen)` for the BIGNUM buffer — the authority's
/// lines 473 and 480, which is one allocation site and one free of it.
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
/// `EVP_PKEY_meth_find_added_by_application` — the application half of the registry.
///
/// # Safety
/// `type_` is a legacy NID.
#[allow(dead_code)] // first live callers are `EVP_PKEY_meth_find` (7.4l) and `int_ctx_new` (7.4c)
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
pub(crate) enum XlatState {
    /// `PKEY` — the caller is an `EVP_PKEY` payload getter/setter and is fully responsible.
    Pkey = 0,
    /// `PRE_CTRL_TO_PARAMS` — prepare `*params` from the ctrl arguments.
    PreCtrlToParams = 1,
    /// `POST_CTRL_TO_PARAMS` — bring the result back to `*p2` and the return value.
    PostCtrlToParams = 2,
    /// `CLEANUP_CTRL_TO_PARAMS`.
    ///
    /// **Never constructed, and never constructed by the authority either.** Three of the ten states
    /// name a cleanup pass — one per direction — and the two entry points that could take this one
    /// pass `POST_CTRL_TO_PARAMS` to `cleanup_translation_ctx` instead, because that is what the
    /// authority's own `evp_pkey_ctx_ctrl_to_param` passes. So the value exists because the enum has
    /// it and nothing reads it, which is the authority's state and not a gap here.
    #[allow(dead_code)] // as the authority: no call site passes this state to a cleanup
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
pub(crate) type FixupArgsFn =
    unsafe extern "C" fn(XlatState, *const XlatEntry, *mut XlatCtx) -> c_int;

/// `typedef int cleanup_args_fn(enum state, const struct translation_st *,
/// struct translation_ctx_st *)` — `crypto/evp/ctrl_params_translate.c:164-166`.
///
/// The same shape as [`FixupArgsFn`] and a distinct name, because the authority declares it twice:
/// the two are called at different points and a table that mixed them up would call a cleanup where
/// it wanted a fixup. Kept separate for the same reason `KeyexchDeriveFn` and `KdfDeriveFn` are.
///
/// **It is unused here, and that is the ABI being copied rather than a name kept for show.** In C a
/// table slot declared `fixup_args_fn *` accepts `cleanup_translation_ctx` because the two typedefs
/// have the same signature; Rust has no such tolerance, so the three `CLEANUP_*` arms below store it
/// in an `Option<FixupArgsFn>` slot and this alias has no expression that could name it. It stays
/// because the authority's second typedef is part of what the file is, and the dispatch court checks
/// it.
#[allow(dead_code)] // the two typedefs are one signature; the tables' slot is the fixup one
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

// SAFETY: `XlatEntry` is read-only in every use: the two tables below are `static` arrays that are
// never written after their initialiser runs, and every field the lookup and the translation loop
// read is either a plain integer, a function pointer, or a pointer to one of two things that
// outlive the program -- a `c"..."` literal's bytes and a `static` map or table in this file. A
// shared `&XlatEntry` therefore cannot be used to reach a `&mut` of anything, which is what `Sync`
// requires. The `unsafe impl` is needed because a raw pointer is `!Sync` by default, so the
// authority's spelling of this table cannot be a `static` in Rust without it.
unsafe impl Sync for XlatEntry {}

impl XlatCtx {
    /// The authority's `struct translation_ctx_st ctx = { 0, };`, written out field by field.
    ///
    /// `mem::zeroed` would be shorter and is deliberately not used: a `{ 0, }` initialiser in C is a
    /// *statement about every field*, and spelling them out is what makes a field added to the
    /// authority's struct have to be considered here rather than silently defaulting to a null
    /// pointer that a fixup would then dereference.
    const ZEROED: XlatCtx = XlatCtx {
        pctx: ptr::null_mut(),
        action_type: XlatAction::None_,
        ctrl_cmd: 0,
        ctrl_str: ptr::null(),
        ishex: 0,
        p1: 0,
        p2: ptr::null_mut(),
        sz: 0,
        params: ptr::null_mut(),
        orig_p2: ptr::null_mut(),
        name_buf: [0; OSSL_MAX_NAME_SIZE],
        allocated_buf: ptr::null_mut(),
        bufp: ptr::null_mut(),
        buflen: 0,
    };
}

impl XlatEntry {
    /// The authority's `struct translation_st tmpl = { 0, };`, written out field by field for the
    /// reason [`XlatCtx::ZEROED`] records.
    ///
    /// The three `-1`s are worth noting because they are **not** the zero of this struct and the
    /// callers set them: a template's `optype` and keytypes stay 0 until the entry point fills them
    /// in, and a `-1` in a *row* means "any". A caller that forgot to fill them in would search with
    /// `optype == 0`, which matches no row (every row's optype is a real bit or `-1`), so the failure
    /// mode is a NULL lookup rather than a wrong row.
    const ZEROED: XlatEntry = XlatEntry {
        action_type: XlatAction::None_,
        keytype1: 0,
        keytype2: 0,
        optype: 0,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: ptr::null(),
        param_data_type: 0,
        fixup_args: None,
    };
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
pub(crate) unsafe extern "C" fn cleanup_translation_ctx(
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
unsafe extern "C" fn get_cipher_name(cipher: *mut c_void) -> *const c_char {
    // SAFETY: `cipher` is NULL or live per the contract.
    unsafe { EVP_CIPHER_get0_name(cipher.cast::<EvpCipher>()) }
}

/// `static const char *get_md_name(void *md)` — `crypto/evp/ctrl_params_translate.c:733`.
///
/// # Safety
/// `md` must be NULL or a live `EVP_MD`.
unsafe extern "C" fn get_md_name(md: *mut c_void) -> *const c_char {
    // SAFETY: `md` is NULL or live per the contract.
    unsafe { EVP_MD_get0_name(md.cast::<crate::evp::digest::EvpMd>()) }
}

/// `static const void *get_cipher_by_name(OSSL_LIB_CTX *libctx, const char *name)` —
/// `crypto/evp/ctrl_params_translate.c:738`.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
unsafe extern "C" fn get_cipher_by_name(libctx: *mut c_void, name: *const c_char) -> *const c_void {
    // SAFETY: both are forwarded under this function's contract.
    unsafe { evp_get_cipherbyname_ex(libctx, name) }.cast::<c_void>()
}

/// `static const void *get_md_by_name(OSSL_LIB_CTX *libctx, const char *name)` —
/// `crypto/evp/ctrl_params_translate.c:743`.
///
/// # Safety
/// `libctx` NULL or live; `name` NULL or NUL-terminated.
unsafe extern "C" fn get_md_by_name(libctx: *mut c_void, name: *const c_char) -> *const c_void {
    // SAFETY: both are forwarded under this function's contract.
    unsafe { evp_get_digestbyname_ex(libctx, name) }.cast::<c_void>()
}

/// The shape of the authority's `(*get_name)(void *algo)` parameter of `fix_cipher_md`.
pub(crate) type XlatGetNameFn = unsafe extern "C" fn(*mut c_void) -> *const c_char;
/// The shape of its `(*get_algo_by_name)(OSSL_LIB_CTX *, const char *)` parameter.
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
pub(crate) unsafe extern "C" fn fix_cipher_md(
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
pub(crate) unsafe extern "C" fn fix_cipher(
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
pub(crate) unsafe extern "C" fn fix_md(
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
pub(crate) unsafe extern "C" fn fix_distid_len(
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
pub(crate) struct KdfTypeMap {
    /// `int kdf_type_num`.
    kdf_type_num: c_int,
    /// `const char *kdf_type_str` — NULL terminates the table.
    kdf_type_str: Option<&'static CStr>,
}

/// `EVP_PKEY_DH_KDF_NONE` — `include/openssl/dh.h:83`.
const EVP_PKEY_DH_KDF_NONE: c_int = 1;
/// `EVP_PKEY_DH_KDF_X9_42` — `include/openssl/dh.h:84`.
const EVP_PKEY_DH_KDF_X9_42: c_int = 2;
/// `EVP_PKEY_ECDH_KDF_NONE` — `include/openssl/ec.h:66`.
const EVP_PKEY_ECDH_KDF_NONE: c_int = 1;
/// `EVP_PKEY_ECDH_KDF_X9_63` — `include/openssl/ec.h:67`.
const EVP_PKEY_ECDH_KDF_X9_63: c_int = 2;

/// `fix_dh_kdf_type`'s table — `crypto/evp/ctrl_params_translate.c:927`.
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
pub(crate) unsafe extern "C" fn fix_kdf_type(
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
pub(crate) unsafe extern "C" fn fix_dh_kdf_type(
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
pub(crate) unsafe extern "C" fn fix_ec_kdf_type(
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
pub(crate) unsafe extern "C" fn fix_oid(
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

/// `fix_rsa_padding_mode`'s `padding name %s` site, which is the `%s` counterpart of
/// [`raise_action_state_tail_int`]: the same prefix and tail shape with a caller string where that
/// one has a decimal. It is a separate helper rather than a flag on that one because the two
/// argument types have nothing in common — one is a `c_int` to be printed and the other a
/// NUL-terminated string to be copied — and a shared helper that took both would have to spell out
/// which it got.
///
/// # Safety
/// The site is a compile-time constant whose pointers are static; `value` must be NULL or
/// NUL-terminated.
unsafe fn raise_action_state_tail_str(
    site: &err_sites::ErrSite,
    action: XlatAction,
    state: XlatState,
    tail: &[u8],
    value: *const c_char,
) {
    let mut m = action_state_prefix(action, state);
    m.push(b' ');
    m.extend_from_slice(tail);
    m.push(b' ');
    if !value.is_null() {
        // SAFETY: `value` is NUL-terminated per the contract.
        m.extend_from_slice(unsafe { CStr::from_ptr(value) }.to_bytes());
    }
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}
/// `default_fixup_args`'s `name=%s, value=%s` site.
///
/// # Safety
/// Both arguments must be NULL or NUL-terminated.
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
pub(crate) unsafe extern "C" fn default_fixup_args(
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

// ---------------------------------------------------------------------------------------------
// The names the tables speak — every `#define` the translations below name
//
// Four families: the `EVP_PKEY_CTRL_*` command numbers from `evp.h` and the four algorithm
// headers; the `OSSL_*_PARAM_*` key strings from the *generated* `include/openssl/core_names.h`
// (its source is `core_names.h.in`, so the line cited is the generated one the authority was built
// from); the NID aliases `evp.h` gives the `EVP_PKEY_*` type names; and the handful of algorithm
// constants the fixers compare against (`rsa.h`'s padding modes and salt lengths, `ec.h`'s two
// encoding values, `kdf.h`'s three HKDF modes).
//
// **Why every one is written out rather than inlined as a string literal.** A table entry whose
// key is one character off is a lookup that silently never matches, and the authority's own
// `ON`/`OEAP` typo in the padding map (`"oeap"` for `RSA_PKCS1_OAEP_PADDING`) is reproduced below
// precisely because it is reachable — a caller typing `rsa_padding_mode=oeap` is answered, and one
// typing `oaep` is not. A literal at the table would hide that; a name forces the reader to look.
//
// Where the crate already had one of these names it is **shared rather than duplicated**: the six
// Scrypt names and the password/salt names live in `pbe.rs`, `OSSL_KDF_PARAM_KEY` in `kdf.rs`,
// `OSSL_MAC_PARAM_SIZE` in `mac.rs`, and the two `OSSL_PKEY_PARAM_{PRIV,PUB}_KEY` names in
// `pkey.rs`. Each is re-exported into scope here.
// ---------------------------------------------------------------------------------------------

/// `EVP_PKEY_ALG_CTRL` — `include/openssl/evp.h:1828`. Every algorithm ctrl number is this plus an
/// offset, which is what keeps the five algorithm headers' ctrl spaces disjoint.
pub(crate) const EVP_PKEY_ALG_CTRL: c_int = 0x1000;

/// `EVP_PKEY_RSA` = `NID_rsaEncryption` — `include/openssl/evp.h:63`.
pub(crate) const EVP_PKEY_RSA: c_int = NID_rsaEncryption;
/// `EVP_PKEY_RSA_PSS` = `NID_rsassaPss` — `include/openssl/evp.h:65`.
pub(crate) const EVP_PKEY_RSA_PSS: c_int = NID_rsassaPss;
/// `EVP_PKEY_DSA` = `NID_dsa` — `include/openssl/evp.h:66`.
pub(crate) const EVP_PKEY_DSA: c_int = NID_dsa;
/// `EVP_PKEY_DH` = `NID_dhKeyAgreement` — `include/openssl/evp.h:71`.
pub(crate) const EVP_PKEY_DH: c_int = NID_dhKeyAgreement;
/// `EVP_PKEY_DHX` = `NID_dhpublicnumber` — `include/openssl/evp.h:72`.
pub(crate) const EVP_PKEY_DHX: c_int = NID_dhpublicnumber;
/// `EVP_PKEY_EC` = `NID_X9_62_id_ecPublicKey` — `include/openssl/evp.h:73`.
pub(crate) const EVP_PKEY_EC: c_int = NID_X9_62_id_ecPublicKey;
/// `EVP_PKEY_SM2` = `NID_sm2` — `include/openssl/evp.h:74`.
pub(crate) const EVP_PKEY_SM2: c_int = NID_sm2;
/// `EVP_PKEY_X25519` = `NID_X25519` — `include/openssl/evp.h:82`.
pub(crate) const EVP_PKEY_X25519: c_int = NID_X25519;
/// `EVP_PKEY_X448` = `NID_X448` — `include/openssl/evp.h:84`.
pub(crate) const EVP_PKEY_X448: c_int = NID_X448;

/// `EVP_PKEY_CTRL_MD` — `include/openssl/evp.h:1807`.
pub(crate) const EVP_PKEY_CTRL_MD: c_int = 1;
/// `EVP_PKEY_CTRL_SET_MAC_KEY` — `include/openssl/evp.h:1809`.
pub(crate) const EVP_PKEY_CTRL_SET_MAC_KEY: c_int = 6;
/// `EVP_PKEY_CTRL_CIPHER` — `include/openssl/evp.h:1821`.
pub(crate) const EVP_PKEY_CTRL_CIPHER: c_int = 12;
/// `EVP_PKEY_CTRL_GET_MD` — `include/openssl/evp.h:1822`.
pub(crate) const EVP_PKEY_CTRL_GET_MD: c_int = 13;
/// `EVP_PKEY_CTRL_SET_DIGEST_SIZE` — `include/openssl/evp.h:1823`.
pub(crate) const EVP_PKEY_CTRL_SET_DIGEST_SIZE: c_int = 14;
/// `EVP_PKEY_CTRL_GET1_ID` — `include/openssl/evp.h:1825`.
pub(crate) const EVP_PKEY_CTRL_GET1_ID: c_int = 16;
/// `EVP_PKEY_CTRL_GET1_ID_LEN` — `include/openssl/evp.h:1826`.
pub(crate) const EVP_PKEY_CTRL_GET1_ID_LEN: c_int = 17;

/// `EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN` — `include/openssl/dh.h:65`.
pub(crate) const EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN: c_int = EVP_PKEY_ALG_CTRL + 1;
/// `EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR` — `include/openssl/dh.h:66`.
pub(crate) const EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR: c_int = EVP_PKEY_ALG_CTRL + 2;
/// `EVP_PKEY_CTRL_DH_RFC5114` — `include/openssl/dh.h:67`.
pub(crate) const EVP_PKEY_CTRL_DH_RFC5114: c_int = EVP_PKEY_ALG_CTRL + 3;
/// `EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN` — `include/openssl/dh.h:68`.
pub(crate) const EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN: c_int = EVP_PKEY_ALG_CTRL + 4;
/// `EVP_PKEY_CTRL_DH_PARAMGEN_TYPE` — `include/openssl/dh.h:69`.
pub(crate) const EVP_PKEY_CTRL_DH_PARAMGEN_TYPE: c_int = EVP_PKEY_ALG_CTRL + 5;
/// `EVP_PKEY_CTRL_DH_KDF_TYPE` — `include/openssl/dh.h:70`.
pub(crate) const EVP_PKEY_CTRL_DH_KDF_TYPE: c_int = EVP_PKEY_ALG_CTRL + 6;
/// `EVP_PKEY_CTRL_DH_KDF_MD` — `include/openssl/dh.h:71`.
pub(crate) const EVP_PKEY_CTRL_DH_KDF_MD: c_int = EVP_PKEY_ALG_CTRL + 7;
/// `EVP_PKEY_CTRL_GET_DH_KDF_MD` — `include/openssl/dh.h:72`.
pub(crate) const EVP_PKEY_CTRL_GET_DH_KDF_MD: c_int = EVP_PKEY_ALG_CTRL + 8;
/// `EVP_PKEY_CTRL_DH_KDF_OUTLEN` — `include/openssl/dh.h:73`.
pub(crate) const EVP_PKEY_CTRL_DH_KDF_OUTLEN: c_int = EVP_PKEY_ALG_CTRL + 9;
/// `EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN` — `include/openssl/dh.h:74`.
pub(crate) const EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN: c_int = EVP_PKEY_ALG_CTRL + 10;
/// `EVP_PKEY_CTRL_DH_KDF_UKM` — `include/openssl/dh.h:75`.
pub(crate) const EVP_PKEY_CTRL_DH_KDF_UKM: c_int = EVP_PKEY_ALG_CTRL + 11;
/// `EVP_PKEY_CTRL_GET_DH_KDF_UKM` — `include/openssl/dh.h:76`.
pub(crate) const EVP_PKEY_CTRL_GET_DH_KDF_UKM: c_int = EVP_PKEY_ALG_CTRL + 12;
/// `EVP_PKEY_CTRL_DH_KDF_OID` — `include/openssl/dh.h:77`.
pub(crate) const EVP_PKEY_CTRL_DH_KDF_OID: c_int = EVP_PKEY_ALG_CTRL + 13;
/// `EVP_PKEY_CTRL_GET_DH_KDF_OID` — `include/openssl/dh.h:78`.
pub(crate) const EVP_PKEY_CTRL_GET_DH_KDF_OID: c_int = EVP_PKEY_ALG_CTRL + 14;
/// `EVP_PKEY_CTRL_DH_NID` — `include/openssl/dh.h:79`.
pub(crate) const EVP_PKEY_CTRL_DH_NID: c_int = EVP_PKEY_ALG_CTRL + 15;
/// `EVP_PKEY_CTRL_DH_PAD` — `include/openssl/dh.h:80`.
pub(crate) const EVP_PKEY_CTRL_DH_PAD: c_int = EVP_PKEY_ALG_CTRL + 16;

/// `EVP_PKEY_CTRL_DSA_PARAMGEN_BITS` — `include/openssl/dsa.h:55`.
pub(crate) const EVP_PKEY_CTRL_DSA_PARAMGEN_BITS: c_int = EVP_PKEY_ALG_CTRL + 1;
/// `EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS` — `include/openssl/dsa.h:56`.
pub(crate) const EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS: c_int = EVP_PKEY_ALG_CTRL + 2;
/// `EVP_PKEY_CTRL_DSA_PARAMGEN_MD` — `include/openssl/dsa.h:57`.
pub(crate) const EVP_PKEY_CTRL_DSA_PARAMGEN_MD: c_int = EVP_PKEY_ALG_CTRL + 3;

/// `EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID` — `include/openssl/ec.h:54`.
pub(crate) const EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID: c_int = EVP_PKEY_ALG_CTRL + 1;
/// `EVP_PKEY_CTRL_EC_PARAM_ENC` — `include/openssl/ec.h:55`.
pub(crate) const EVP_PKEY_CTRL_EC_PARAM_ENC: c_int = EVP_PKEY_ALG_CTRL + 2;
/// `EVP_PKEY_CTRL_EC_ECDH_COFACTOR` — `include/openssl/ec.h:56`.
pub(crate) const EVP_PKEY_CTRL_EC_ECDH_COFACTOR: c_int = EVP_PKEY_ALG_CTRL + 3;
/// `EVP_PKEY_CTRL_EC_KDF_TYPE` — `include/openssl/ec.h:57`.
pub(crate) const EVP_PKEY_CTRL_EC_KDF_TYPE: c_int = EVP_PKEY_ALG_CTRL + 4;
/// `EVP_PKEY_CTRL_EC_KDF_MD` — `include/openssl/ec.h:58`.
pub(crate) const EVP_PKEY_CTRL_EC_KDF_MD: c_int = EVP_PKEY_ALG_CTRL + 5;
/// `EVP_PKEY_CTRL_GET_EC_KDF_MD` — `include/openssl/ec.h:59`.
pub(crate) const EVP_PKEY_CTRL_GET_EC_KDF_MD: c_int = EVP_PKEY_ALG_CTRL + 6;
/// `EVP_PKEY_CTRL_EC_KDF_OUTLEN` — `include/openssl/ec.h:60`.
pub(crate) const EVP_PKEY_CTRL_EC_KDF_OUTLEN: c_int = EVP_PKEY_ALG_CTRL + 7;
/// `EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN` — `include/openssl/ec.h:61`.
pub(crate) const EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN: c_int = EVP_PKEY_ALG_CTRL + 8;
/// `EVP_PKEY_CTRL_EC_KDF_UKM` — `include/openssl/ec.h:62`.
pub(crate) const EVP_PKEY_CTRL_EC_KDF_UKM: c_int = EVP_PKEY_ALG_CTRL + 9;
/// `EVP_PKEY_CTRL_GET_EC_KDF_UKM` — `include/openssl/ec.h:63`.
pub(crate) const EVP_PKEY_CTRL_GET_EC_KDF_UKM: c_int = EVP_PKEY_ALG_CTRL + 10;

/// `EVP_PKEY_CTRL_RSA_PADDING` — `include/openssl/rsa.h:173`.
pub(crate) const EVP_PKEY_CTRL_RSA_PADDING: c_int = EVP_PKEY_ALG_CTRL + 1;
/// `EVP_PKEY_CTRL_RSA_PSS_SALTLEN` — `include/openssl/rsa.h:174`.
pub(crate) const EVP_PKEY_CTRL_RSA_PSS_SALTLEN: c_int = EVP_PKEY_ALG_CTRL + 2;
/// `EVP_PKEY_CTRL_RSA_KEYGEN_BITS` — `include/openssl/rsa.h:176`.
pub(crate) const EVP_PKEY_CTRL_RSA_KEYGEN_BITS: c_int = EVP_PKEY_ALG_CTRL + 3;
/// `EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP` — `include/openssl/rsa.h:177`.
pub(crate) const EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP: c_int = EVP_PKEY_ALG_CTRL + 4;
/// `EVP_PKEY_CTRL_RSA_MGF1_MD` — `include/openssl/rsa.h:178`.
pub(crate) const EVP_PKEY_CTRL_RSA_MGF1_MD: c_int = EVP_PKEY_ALG_CTRL + 5;
/// `EVP_PKEY_CTRL_GET_RSA_PADDING` — `include/openssl/rsa.h:180`.
pub(crate) const EVP_PKEY_CTRL_GET_RSA_PADDING: c_int = EVP_PKEY_ALG_CTRL + 6;
/// `EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN` — `include/openssl/rsa.h:181`.
pub(crate) const EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN: c_int = EVP_PKEY_ALG_CTRL + 7;
/// `EVP_PKEY_CTRL_GET_RSA_MGF1_MD` — `include/openssl/rsa.h:182`.
pub(crate) const EVP_PKEY_CTRL_GET_RSA_MGF1_MD: c_int = EVP_PKEY_ALG_CTRL + 8;
/// `EVP_PKEY_CTRL_RSA_OAEP_MD` — `include/openssl/rsa.h:184`.
pub(crate) const EVP_PKEY_CTRL_RSA_OAEP_MD: c_int = EVP_PKEY_ALG_CTRL + 9;
/// `EVP_PKEY_CTRL_RSA_OAEP_LABEL` — `include/openssl/rsa.h:185`.
pub(crate) const EVP_PKEY_CTRL_RSA_OAEP_LABEL: c_int = EVP_PKEY_ALG_CTRL + 10;
/// `EVP_PKEY_CTRL_GET_RSA_OAEP_MD` — `include/openssl/rsa.h:187`.
pub(crate) const EVP_PKEY_CTRL_GET_RSA_OAEP_MD: c_int = EVP_PKEY_ALG_CTRL + 11;
/// `EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL` — `include/openssl/rsa.h:188`.
pub(crate) const EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL: c_int = EVP_PKEY_ALG_CTRL + 12;
/// `EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES` — `include/openssl/rsa.h:190`.
pub(crate) const EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES: c_int = EVP_PKEY_ALG_CTRL + 13;
/// `EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION` — `include/openssl/rsa.h:192`.
pub(crate) const EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION: c_int = EVP_PKEY_ALG_CTRL + 14;

/// `EVP_PKEY_CTRL_TLS_MD` — `include/openssl/kdf.h:79`. Note that this one is the bare
/// `EVP_PKEY_ALG_CTRL`, because the TLS1-PRF ctrl space starts where the DH one ends.
pub(crate) const EVP_PKEY_CTRL_TLS_MD: c_int = EVP_PKEY_ALG_CTRL;
/// `EVP_PKEY_CTRL_TLS_SECRET` — `include/openssl/kdf.h:80`.
pub(crate) const EVP_PKEY_CTRL_TLS_SECRET: c_int = EVP_PKEY_ALG_CTRL + 1;
/// `EVP_PKEY_CTRL_TLS_SEED` — `include/openssl/kdf.h:81`.
pub(crate) const EVP_PKEY_CTRL_TLS_SEED: c_int = EVP_PKEY_ALG_CTRL + 2;
/// `EVP_PKEY_CTRL_HKDF_MD` — `include/openssl/kdf.h:82`.
pub(crate) const EVP_PKEY_CTRL_HKDF_MD: c_int = EVP_PKEY_ALG_CTRL + 3;
/// `EVP_PKEY_CTRL_HKDF_SALT` — `include/openssl/kdf.h:83`.
pub(crate) const EVP_PKEY_CTRL_HKDF_SALT: c_int = EVP_PKEY_ALG_CTRL + 4;
/// `EVP_PKEY_CTRL_HKDF_KEY` — `include/openssl/kdf.h:84`.
pub(crate) const EVP_PKEY_CTRL_HKDF_KEY: c_int = EVP_PKEY_ALG_CTRL + 5;
/// `EVP_PKEY_CTRL_HKDF_INFO` — `include/openssl/kdf.h:85`.
pub(crate) const EVP_PKEY_CTRL_HKDF_INFO: c_int = EVP_PKEY_ALG_CTRL + 6;
/// `EVP_PKEY_CTRL_HKDF_MODE` — `include/openssl/kdf.h:86`.
pub(crate) const EVP_PKEY_CTRL_HKDF_MODE: c_int = EVP_PKEY_ALG_CTRL + 7;
/// `EVP_PKEY_CTRL_PASS` — `include/openssl/kdf.h:87`.
pub(crate) const EVP_PKEY_CTRL_PASS: c_int = EVP_PKEY_ALG_CTRL + 8;
/// `EVP_PKEY_CTRL_SCRYPT_SALT` — `include/openssl/kdf.h:88`.
pub(crate) const EVP_PKEY_CTRL_SCRYPT_SALT: c_int = EVP_PKEY_ALG_CTRL + 9;
/// `EVP_PKEY_CTRL_SCRYPT_N` — `include/openssl/kdf.h:89`.
pub(crate) const EVP_PKEY_CTRL_SCRYPT_N: c_int = EVP_PKEY_ALG_CTRL + 10;
/// `EVP_PKEY_CTRL_SCRYPT_R` — `include/openssl/kdf.h:90`.
pub(crate) const EVP_PKEY_CTRL_SCRYPT_R: c_int = EVP_PKEY_ALG_CTRL + 11;
/// `EVP_PKEY_CTRL_SCRYPT_P` — `include/openssl/kdf.h:91`.
pub(crate) const EVP_PKEY_CTRL_SCRYPT_P: c_int = EVP_PKEY_ALG_CTRL + 12;
/// `EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES` — `include/openssl/kdf.h:92`.
pub(crate) const EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES: c_int = EVP_PKEY_ALG_CTRL + 13;

/// `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` — `include/openssl/kdf.h:66`.
pub(crate) const EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND: c_int = 0;
/// `EVP_KDF_HKDF_MODE_EXTRACT_ONLY` — `include/openssl/kdf.h:67`.
pub(crate) const EVP_KDF_HKDF_MODE_EXTRACT_ONLY: c_int = 1;
/// `EVP_KDF_HKDF_MODE_EXPAND_ONLY` — `include/openssl/kdf.h:68`.
pub(crate) const EVP_KDF_HKDF_MODE_EXPAND_ONLY: c_int = 2;

/// `RSA_PKCS1_PADDING` — `include/openssl/rsa.h:194`.
pub(crate) const RSA_PKCS1_PADDING: c_int = 1;
/// `RSA_NO_PADDING` — `include/openssl/rsa.h:195`.
pub(crate) const RSA_NO_PADDING: c_int = 3;
/// `RSA_PKCS1_OAEP_PADDING` — `include/openssl/rsa.h:196`.
pub(crate) const RSA_PKCS1_OAEP_PADDING: c_int = 4;
/// `RSA_X931_PADDING` — `include/openssl/rsa.h:197`.
pub(crate) const RSA_X931_PADDING: c_int = 5;
/// `RSA_PKCS1_PSS_PADDING` — `include/openssl/rsa.h:200`.
pub(crate) const RSA_PKCS1_PSS_PADDING: c_int = 6;
/// `RSA_PKCS1_WITH_TLS_PADDING` — `include/openssl/rsa.h:201`. The one padding mode with **no**
/// ctrl_str spelling, which is why `fix_rsa_padding_mode`'s map ends in a NULL string.
pub(crate) const RSA_PKCS1_WITH_TLS_PADDING: c_int = 7;
/// `RSA_PSS_SALTLEN_DIGEST` — `include/openssl/rsa.h:138`.
pub(crate) const RSA_PSS_SALTLEN_DIGEST: c_int = -1;
/// `RSA_PSS_SALTLEN_MAX` — `include/openssl/rsa.h:142`.
pub(crate) const RSA_PSS_SALTLEN_MAX: c_int = -3;
/// `RSA_PSS_SALTLEN_AUTO` — `include/openssl/rsa.h:140`. `SALTLEN_MAX_SIGN` is the same value under a
/// second name, so this is the whole of the distinct set the saltlen map speaks.
pub(crate) const RSA_PSS_SALTLEN_AUTO: c_int = -2;

/// `OPENSSL_EC_EXPLICIT_CURVE` — `include/openssl/ec.h:30`.
pub(crate) const OPENSSL_EC_EXPLICIT_CURVE: c_int = 0;
/// `OPENSSL_EC_NAMED_CURVE` — `include/openssl/ec.h:31`.
pub(crate) const OPENSSL_EC_NAMED_CURVE: c_int = 1;

/// `DH_PARAMGEN_TYPE_GENERATOR` — `include/openssl/dh.h:33`.
pub(crate) const DH_PARAMGEN_TYPE_GENERATOR: c_int = 0;
/// `DH_PARAMGEN_TYPE_FIPS_186_2` — `include/openssl/dh.h:34`.
pub(crate) const DH_PARAMGEN_TYPE_FIPS_186_2: c_int = 1;
/// `DH_PARAMGEN_TYPE_FIPS_186_4` — `include/openssl/dh.h:35`.
pub(crate) const DH_PARAMGEN_TYPE_FIPS_186_4: c_int = 2;
/// `DH_PARAMGEN_TYPE_GROUP` — `include/openssl/dh.h:36`.
pub(crate) const DH_PARAMGEN_TYPE_GROUP: c_int = 3;

/// `OSSL_ALG_PARAM_DIGEST` — `include/openssl/core_names.h:128`. Six other names are aliases of it,
/// and they are spelled as aliases here too so a reader can see that the same key string is meant.
pub(crate) const OSSL_ALG_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_ALG_PARAM_CIPHER` — `include/openssl/core_names.h:127`.
pub(crate) const OSSL_ALG_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();

/// `OSSL_PKEY_PARAM_DIST_ID` — `include/openssl/core_names.h:376`.
pub(crate) const OSSL_PKEY_PARAM_DIST_ID: *const c_char = c"distid".as_ptr();
/// `OSSL_PKEY_PARAM_FFC_TYPE` — `include/openssl/core_names.h:412`.
pub(crate) const OSSL_PKEY_PARAM_FFC_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_PKEY_PARAM_FFC_PBITS` — `include/openssl/core_names.h:407`.
pub(crate) const OSSL_PKEY_PARAM_FFC_PBITS: *const c_char = c"pbits".as_ptr();
/// `OSSL_PKEY_PARAM_FFC_QBITS` — `include/openssl/core_names.h:410`.
pub(crate) const OSSL_PKEY_PARAM_FFC_QBITS: *const c_char = c"qbits".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_FFC_P: *const c_char = c"p".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_FFC_Q: *const c_char = c"q".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_FFC_G: *const c_char = c"g".as_ptr();
/// `OSSL_PKEY_PARAM_GROUP_NAME` — `include/openssl/core_names.h:420`.
pub(crate) const OSSL_PKEY_PARAM_GROUP_NAME: *const c_char = c"group".as_ptr();
/// `OSSL_PKEY_PARAM_DH_GENERATOR` — `include/openssl/core_names.h:372`.
pub(crate) const OSSL_PKEY_PARAM_DH_GENERATOR: *const c_char = c"safeprime-generator".as_ptr();
/// `OSSL_PKEY_PARAM_EC_ENCODING` — `include/openssl/core_names.h:387`.
pub(crate) const OSSL_PKEY_PARAM_EC_ENCODING: *const c_char = c"encoding".as_ptr();
/// `OSSL_PKEY_EC_ENCODING_EXPLICIT` — `include/openssl/core_names.h:101`.
pub(crate) const OSSL_PKEY_EC_ENCODING_EXPLICIT: *const c_char = c"explicit".as_ptr();
/// `OSSL_PKEY_EC_ENCODING_GROUP` — `include/openssl/core_names.h:102`.
pub(crate) const OSSL_PKEY_EC_ENCODING_GROUP: *const c_char = c"named_curve".as_ptr();
/// `OSSL_PKEY_PARAM_EC_PUB_X` — `include/openssl/core_names.h:395`.
pub(crate) const OSSL_PKEY_PARAM_EC_PUB_X: *const c_char = c"qx".as_ptr();
/// `OSSL_PKEY_PARAM_EC_PUB_Y` — `include/openssl/core_names.h:396`.
pub(crate) const OSSL_PKEY_PARAM_EC_PUB_Y: *const c_char = c"qy".as_ptr();
/// `OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS` — `include/openssl/core_names.h:386`.
pub(crate) const OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS: *const c_char =
    c"decoded-from-explicit".as_ptr();
/// `OSSL_PKEY_PARAM_PAD_MODE` — `include/openssl/core_names.h:438`.
pub(crate) const OSSL_PKEY_PARAM_PAD_MODE: *const c_char = c"pad-mode".as_ptr();
/// `OSSL_PKEY_PARAM_MGF1_DIGEST` — `include/openssl/core_names.h:425`.
pub(crate) const OSSL_PKEY_PARAM_MGF1_DIGEST: *const c_char = c"mgf1-digest".as_ptr();
/// `OSSL_PKEY_PARAM_RSA_PSS_SALTLEN` — `include/openssl/core_names.h:484`.
pub(crate) const OSSL_PKEY_PARAM_RSA_PSS_SALTLEN: *const c_char = c"saltlen".as_ptr();
/// `OSSL_SIGNATURE_PARAM_PSS_SALTLEN` — `include/openssl/core_names.h:568`. The **same string** as
/// `OSSL_PKEY_PARAM_RSA_PSS_SALTLEN` under a different name, which is why the RSA-PSS keygen row and
/// the two RSA-PSS signing rows can share a ctrl number without sharing a key.
pub(crate) const OSSL_SIGNATURE_PARAM_PSS_SALTLEN: *const c_char = c"saltlen".as_ptr();
/// `OSSL_PKEY_PARAM_CIPHER` = `OSSL_ALG_PARAM_CIPHER` — `include/openssl/core_names.h:367`.
pub(crate) const OSSL_PKEY_PARAM_CIPHER: *const c_char = OSSL_ALG_PARAM_CIPHER;
/// `OSSL_PKEY_PARAM_BITS` — `include/openssl/core_names.h:366`.
pub(crate) const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_RSA_BITS` = `OSSL_PKEY_PARAM_BITS` — `include/openssl/core_names.h:442`.
pub(crate) const OSSL_PKEY_PARAM_RSA_BITS: *const c_char = OSSL_PKEY_PARAM_BITS;
/// `OSSL_PKEY_PARAM_RSA_E` — `include/openssl/core_names.h:457`.
pub(crate) const OSSL_PKEY_PARAM_RSA_E: *const c_char = c"e".as_ptr();
/// `OSSL_PKEY_PARAM_RSA_PRIMES` — `include/openssl/core_names.h:483`.
pub(crate) const OSSL_PKEY_PARAM_RSA_PRIMES: *const c_char = c"primes".as_ptr();
/// `OSSL_PKEY_PARAM_RSA_N` — `include/openssl/core_names.h:482`.
pub(crate) const OSSL_PKEY_PARAM_RSA_N: *const c_char = c"n".as_ptr();
/// `OSSL_PKEY_PARAM_RSA_D` — `include/openssl/core_names.h:453`.
pub(crate) const OSSL_PKEY_PARAM_RSA_D: *const c_char = c"d".as_ptr();
/// `OSSL_PKEY_PARAM_FFC_DIGEST` = `OSSL_PKEY_PARAM_DIGEST` = `OSSL_ALG_PARAM_DIGEST` —
/// `include/openssl/core_names.h:401`.
pub(crate) const OSSL_PKEY_PARAM_FFC_DIGEST: *const c_char = OSSL_ALG_PARAM_DIGEST;
/// `OSSL_PKEY_PARAM_DIGEST` = `OSSL_ALG_PARAM_DIGEST` — `include/openssl/core_names.h:374`.
pub(crate) const OSSL_PKEY_PARAM_DIGEST: *const c_char = OSSL_ALG_PARAM_DIGEST;
/// `OSSL_SIGNATURE_PARAM_DIGEST` = `OSSL_PKEY_PARAM_DIGEST` — `include/openssl/core_names.h:550`.
pub(crate) const OSSL_SIGNATURE_PARAM_DIGEST: *const c_char = OSSL_PKEY_PARAM_DIGEST;
/// `OSSL_KDF_PARAM_DIGEST` = `OSSL_ALG_PARAM_DIGEST` — `include/openssl/core_names.h:281`.
pub(crate) const OSSL_KDF_PARAM_DIGEST: *const c_char = OSSL_ALG_PARAM_DIGEST;
/// `OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST` = `OSSL_ALG_PARAM_DIGEST` — `include/openssl/core_names.h:142`.
pub(crate) const OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST: *const c_char = OSSL_ALG_PARAM_DIGEST;

/// `OSSL_EXCHANGE_PARAM_KDF_TYPE` — `include/openssl/core_names.h:268`.
pub(crate) const OSSL_EXCHANGE_PARAM_KDF_TYPE: *const c_char = c"kdf-type".as_ptr();
/// `OSSL_EXCHANGE_PARAM_KDF_DIGEST` — `include/openssl/core_names.h:265`.
pub(crate) const OSSL_EXCHANGE_PARAM_KDF_DIGEST: *const c_char = c"kdf-digest".as_ptr();
/// `OSSL_EXCHANGE_PARAM_KDF_OUTLEN` — `include/openssl/core_names.h:267`.
pub(crate) const OSSL_EXCHANGE_PARAM_KDF_OUTLEN: *const c_char = c"kdf-outlen".as_ptr();
/// `OSSL_EXCHANGE_PARAM_KDF_UKM` — `include/openssl/core_names.h:269`.
pub(crate) const OSSL_EXCHANGE_PARAM_KDF_UKM: *const c_char = c"kdf-ukm".as_ptr();
/// `OSSL_EXCHANGE_PARAM_PAD` — `include/openssl/core_names.h:270`.
pub(crate) const OSSL_EXCHANGE_PARAM_PAD: *const c_char = c"pad".as_ptr();
/// `OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE` — `include/openssl/core_names.h:260`.
pub(crate) const OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE: *const c_char =
    c"ecdh-cofactor-mode".as_ptr();

/// `OSSL_KDF_PARAM_CEK_ALG` — `include/openssl/core_names.h:277`.
pub(crate) const OSSL_KDF_PARAM_CEK_ALG: *const c_char = c"cekalg".as_ptr();
/// `OSSL_KDF_PARAM_INFO` — `include/openssl/core_names.h:289`.
pub(crate) const OSSL_KDF_PARAM_INFO: *const c_char = c"info".as_ptr();
/// `OSSL_KDF_PARAM_MODE` — `include/openssl/core_names.h:298`.
pub(crate) const OSSL_KDF_PARAM_MODE: *const c_char = c"mode".as_ptr();
/// `OSSL_KDF_PARAM_SECRET` — `include/openssl/core_names.h:309`.
pub(crate) const OSSL_KDF_PARAM_SECRET: *const c_char = c"secret".as_ptr();
/// `OSSL_KDF_PARAM_SEED` — `include/openssl/core_names.h:310`.
pub(crate) const OSSL_KDF_PARAM_SEED: *const c_char = c"seed".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL` — `include/openssl/core_names.h:144`.
pub(crate) const OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL: *const c_char = c"oaep-label".as_ptr();
/// `OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION` — `include/openssl/core_names.h:139`.
pub(crate) const OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION: *const c_char =
    c"implicit-rejection".as_ptr();

/// `OSSL_KEM_PARAM_OPERATION` — `include/openssl/core_names.h:326`.
pub(crate) const OSSL_KEM_PARAM_OPERATION: *const c_char = c"operation".as_ptr();

/// `OSSL_PKEY_PARAM_RSA_FACTOR1`..`FACTOR10` — `include/openssl/core_names.h:470-479`. Written out
/// one per line rather than formatted, because a `format!`-built key could not be a `const` and the
/// table needs one — the authority uses ten `#define`s and so does this.
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR1: *const c_char = c"rsa-factor1".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR2: *const c_char = c"rsa-factor2".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR3: *const c_char = c"rsa-factor3".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR4: *const c_char = c"rsa-factor4".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR5: *const c_char = c"rsa-factor5".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR6: *const c_char = c"rsa-factor6".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR7: *const c_char = c"rsa-factor7".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR8: *const c_char = c"rsa-factor8".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR9: *const c_char = c"rsa-factor9".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_FACTOR10: *const c_char = c"rsa-factor10".as_ptr();

/// `OSSL_PKEY_PARAM_RSA_EXPONENT1`..`EXPONENT10` — `include/openssl/core_names.h:459-468`.
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT1: *const c_char = c"rsa-exponent1".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT2: *const c_char = c"rsa-exponent2".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT3: *const c_char = c"rsa-exponent3".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT4: *const c_char = c"rsa-exponent4".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT5: *const c_char = c"rsa-exponent5".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT6: *const c_char = c"rsa-exponent6".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT7: *const c_char = c"rsa-exponent7".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT8: *const c_char = c"rsa-exponent8".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT9: *const c_char = c"rsa-exponent9".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_EXPONENT10: *const c_char = c"rsa-exponent10".as_ptr();

/// `OSSL_PKEY_PARAM_RSA_COEFFICIENT1`..`COEFFICIENT9` — `include/openssl/core_names.h:444-452`.
/// Nine and not ten: the first CRT coefficient is `iqmp` and the remaining ones are numbered from
/// two, which is why this family has one fewer member than the two above.
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT1: *const c_char = c"rsa-coefficient1".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT2: *const c_char = c"rsa-coefficient2".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT3: *const c_char = c"rsa-coefficient3".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT4: *const c_char = c"rsa-coefficient4".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT5: *const c_char = c"rsa-coefficient5".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT6: *const c_char = c"rsa-coefficient6".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT7: *const c_char = c"rsa-coefficient7".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT8: *const c_char = c"rsa-coefficient8".as_ptr();
pub(crate) const OSSL_PKEY_PARAM_RSA_COEFFICIENT9: *const c_char = c"rsa-coefficient9".as_ptr();

// ---------------------------------------------------------------------------------------------
// The remaining `fix_*` functions — slice (3) of `ctrl_params_translate.c`
//
// The same shape as the ones above: `default_check`, the caller's own work, then
// `default_fixup_args`. Three of them reach for data, and one of those three pieces of data —
// `crypto/ffc/ffc_dh.c`'s `dh_named_groups[]` — is a later stratum's and is **not** partially
// transcribed here; the arm that needs it says so and answers what the authority answers for a UID
// with no group. The other, `crypto/evp/dh_support.c`'s `dhtype2id[]`, is four integers and four
// printable names with no key material at all, so it is transcribed whole.
// ---------------------------------------------------------------------------------------------

/// libc's `atoi`, which the authority calls at three places: `fix_dh_nid5114`'s `dh_rfc5114` string
/// arm, `fix_dh_paramgen_type`'s, and `fix_rsa_pss_saltlen`'s fallback. All three read a value the
/// caller typed as a *string* and want the number the ctrl form would have carried.
///
/// glibc defines it as `(int)strtol(nptr, NULL, 10)`, and that is what this is. The identity is
/// worth stating because the obvious Rust substitute is a different function twice over:
/// `"123abc".parse::<c_int>()` is an `Err` where `atoi` answers 123, and `parse` refuses a value
/// that does not fit where `atoi` truncates it. Both are reachable — a caller may write
/// `rsa_pss_saltlen=digest7` or `rsa_pss_saltlen=9999999999` — so neither difference is academic.
///
/// # Safety
/// `s` must be NULL or NUL-terminated. NULL is answered with 0 where glibc would fault; the
/// authority's three sites all pass a string it has already tested for NULL, or the value half of
/// `EVP_PKEY_CTX_ctrl_str`, which `EVP_PKEY_CTX_ctrl_str` is handed by its caller.
unsafe fn atoi(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is NUL-terminated per the contract, and a NULL `end` is what `atoi` itself hands
    // `strtol`.
    unsafe { strtol(s, ptr::null_mut(), 10) as c_int }
}

/// `struct dh_name2id_st` — `crypto/evp/dh_support.c:18`.
///
/// The authority's `type` member is **not** reproduced: it is read only by
/// `ossl_dh_gen_type_name2id`, which the ctrl plane never calls — `fix_dh_paramgen_type` translates
/// ids to names and nothing here translates back — and a member no reader reads is weight this
/// project drops rather than carries. The `TYPE_ANY`/`TYPE_DH`/`TYPE_DHX` values it would hold are
/// consequently absent too.
struct DhGenTypeName2Id {
    /// `const char *name`.
    name: &'static CStr,
    /// `int id` — one of the four `DH_PARAMGEN_TYPE_*`.
    id: c_int,
}

/// `static const DH_GENTYPE_NAME2ID dhtype2id[]` — `crypto/evp/dh_support.c:31`.
///
/// Four entries in the authority's order, which is the order `ossl_dh_gen_type_id2name` scans and
/// therefore the order that would decide which of two equal ids answered. No two ids are equal
/// today; the order is kept because that is the fact a reader is checking.
static DHTYPE2ID: [DhGenTypeName2Id; 4] = [
    DhGenTypeName2Id {
        name: c"group",
        id: DH_PARAMGEN_TYPE_GROUP,
    },
    DhGenTypeName2Id {
        name: c"generator",
        id: DH_PARAMGEN_TYPE_GENERATOR,
    },
    DhGenTypeName2Id {
        name: c"fips186_4",
        id: DH_PARAMGEN_TYPE_FIPS_186_4,
    },
    DhGenTypeName2Id {
        name: c"fips186_2",
        id: DH_PARAMGEN_TYPE_FIPS_186_2,
    },
];

/// `const char *ossl_dh_gen_type_id2name(int id)` — `crypto/evp/dh_support.c:38`.
///
/// NULL for an id outside the four, which is what `fix_dh_paramgen_type` reports as
/// `EVP_R_INVALID_VALUE`. The authority's loop is linear over four entries; so is this.
fn ossl_dh_gen_type_id2name(id: c_int) -> *const c_char {
    for e in &DHTYPE2ID {
        if e.id == id {
            return e.name.as_ptr();
        }
    }
    ptr::null()
}

/// `static int fix_dh_nid(...)` — `crypto/evp/ctrl_params_translate.c:998`.
///
/// `EVP_PKEY_CTRL_DH_NID`, and set-only: the parameter it fills is `OSSL_PKEY_PARAM_GROUP_NAME`, so
/// the ctrl's UID becomes the group's **name** and `p1` is zeroed to let `default_fixup_args`
/// measure the string rather than be told a length. The "only settable" test is what turns a
/// hypothetical getter into a quiet 0; the table has no getter for this ctrl, and `default_check`
/// would refuse one anyway for the same reason.
///
/// **The lookup is absent, and this is the one remaining fixer whose absence is reachable.** The
/// authority's `ossl_ffc_named_group_get_name(ossl_ffc_uid_to_dh_named_group(ctx->p1))` is two
/// functions over `crypto/ffc/ffc_dh.c`'s `dh_named_groups[]`, a table whose entries carry each
/// group's *prime*, *subgroup order* and *generator* as BIGNUMs. Those are Phase 8's
/// (`docs/DECISIONS.md` D163), and transcribing only the table's `name` and `uid` columns would be
/// the partial copy that reads as complete and is not — a later slice adding `p` would find the
/// table already "here" and the two halves would be free to disagree. So the arm answers what the
/// authority answers for a UID with no group at all, `EVP_R_INVALID_VALUE`, for every UID.
///
/// # Safety
/// `translation` NULL or live; `ctx` live.
pub(crate) unsafe extern "C" fn fix_dh_nid(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    /* This is only settable. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).action_type } != XlatAction::Set {
        return 0;
    }

    if state == XlatState::PreCtrlToParams {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1013) };
        return 0;
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int fix_dh_nid5114(...)` — `crypto/evp/ctrl_params_translate.c:1023`.
///
/// The RFC 5114 sibling, and it differs from `fix_dh_nid` in two ways that are both about the two
/// doors it has: it answers the ctrl *and* the ctrl_str, and the ctrl_str value arrives as the UID
/// **in decimal** rather than as a NID, which is why the `atoi` is there. The `p2 == NULL` test in
/// the string arm is the caller-error guard, and it is **before** the lookup rather than after it,
/// so a NULL value answers 0 with no error raised.
///
/// The lookup itself is absent for the reason `fix_dh_nid` records: RFC 5114's three groups are
/// three more rows of the same `dh_named_groups[]` table, uid 1, 2 and 3, and their prime material
/// is what keeps the table out of this stratum.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NULL or NUL-terminated in the
/// `PRE_CTRL_STR_TO_PARAMS` arm.
pub(crate) unsafe extern "C" fn fix_dh_nid5114(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    /* This is only settable. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).action_type } != XlatAction::Set {
        return 0;
    }

    match state {
        XlatState::PreCtrlToParams => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1039) };
            return 0;
        }
        XlatState::PreCtrlStrToParams => {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).p2 }.is_null() {
                return 0;
            }
            /* `atoi(ctx->p2)` is the UID the absent lookup would be given. */
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1050) };
            return 0;
        }
        _ => {}
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int fix_dh_paramgen_type(...)` — `crypto/evp/ctrl_params_translate.c:1065`.
///
/// One arm, and it is the previous fixer's shape with the authority's own four-entry table behind
/// it: a string arm that turns the caller's decimal `"1"` into `"generator"` and lets
/// `default_fixup_args` carry the name. The ctrl arm needs no work, because the ctrl already carries
/// the numeric type and `OSSL_PKEY_PARAM_FFC_TYPE` is declared `UTF8_STRING` — so a numeric ctrl into
/// a string parameter is exactly the mismatch `default_fixup_args` cannot fix, and the authority
/// leaves it to `fix_dh_paramgen_type` only for the string door. Reproduced as written, including
/// `p1 = strlen(p2)` rather than 0: the string is a table entry, and the authority measures it.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NULL or NUL-terminated in
/// `PRE_CTRL_STR_TO_PARAMS`.
pub(crate) unsafe extern "C" fn fix_dh_paramgen_type(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    /* This is only settable. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).action_type } != XlatAction::Set {
        return 0;
    }

    if state == XlatState::PreCtrlStrToParams {
        // SAFETY: `ctx` is live and `p2` is the caller's NUL-terminated value.
        let name = unsafe { ossl_dh_gen_type_id2name(atoi((*ctx).p2.cast::<c_char>())) };
        if name.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1081) };
            return 0;
        }
        // SAFETY: `ctx` is live and `name` is a static NUL-terminated string.
        unsafe {
            (*ctx).p2 = name.cast_mut().cast::<c_void>();
            (*ctx).p1 = strlen(name) as c_int;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int fix_ec_param_enc(...)` — `crypto/evp/ctrl_params_translate.c:1091`.
///
/// Two conversions of one three-valued setting, and the two halves are *not* symmetric: the ctrl
/// door takes `OPENSSL_EC_EXPLICIT_CURVE`/`OPENSSL_EC_NAMED_CURVE` (0 and 1) and produces the
/// parameter's **string**, while the parameter door takes the string and produces the ctrl's
/// **number**. The default case in each half answers `-2` — the "command not supported" value
/// `EVP_PKEY_CTX_ctrl`'s callers are documented to expect — and both of them leave through the
/// `end:` label, which raises once for that value.
///
/// **This is the one fixer whose `end:` is a real label and matters.** The two `return ret` exits
/// that skip it are the `default_fixup_args` refusal and `default_check`'s, and neither may raise
/// `EVP_R_COMMAND_NOT_SUPPORTED`: the first has already reported a more specific failure, and the
/// second has reported why the table row itself is unusable. So the raise sits in two places rather
/// than one, and a Rust transcription that hoisted it to a single exit would raise where the
/// authority does not.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NULL or NUL-terminated in
/// `PRE_PARAMS_TO_CTRL`.
pub(crate) unsafe extern "C" fn fix_ec_param_enc(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    /* This is currently only settable. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).action_type } != XlatAction::Set {
        return 0;
    }

    if state == XlatState::PreCtrlToParams {
        // SAFETY: `ctx` is live.
        match unsafe { (*ctx).p1 } {
            OPENSSL_EC_EXPLICIT_CURVE => {
                // SAFETY: `ctx` is live; the string is a static with a `'static` lifetime.
                unsafe {
                    (*ctx).p2 = OSSL_PKEY_EC_ENCODING_EXPLICIT.cast_mut().cast::<c_void>();
                }
            }
            OPENSSL_EC_NAMED_CURVE => {
                // SAFETY: as above.
                unsafe { (*ctx).p2 = OSSL_PKEY_EC_ENCODING_GROUP.cast_mut().cast::<c_void>() };
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1134) };
                return -2;
            }
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p1 = 0 };
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if state == XlatState::PreParamsToCtrl {
        /* SAFETY: `ctx` is live and `p2` is the NUL-terminated name
         * `default_fixup_args` has just placed there. */
        let p2 = unsafe { (*ctx).p2 }.cast::<c_char>();
        // SAFETY: `p2` is NUL-terminated per the contract, and both statics are too.
        if unsafe { strcmp(p2, OSSL_PKEY_EC_ENCODING_EXPLICIT) } == 0 {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = OPENSSL_EC_EXPLICIT_CURVE };
        // SAFETY: as above.
        } else if unsafe { strcmp(p2, OSSL_PKEY_EC_ENCODING_GROUP) } == 0 {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = OPENSSL_EC_NAMED_CURVE };
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = -2 };
            ret = -2;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p2 = ptr::null_mut() };
    }

    if ret == -2 {
        /* SAFETY: a compile-time-constant site. */
        unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1134) };
    }
    ret
}

/// `static int fix_ec_paramgen_curve_nid(...)` — `crypto/evp/ctrl_params_translate.c:1139`.
///
/// A curve's **short name** is what both directions meet on, and the two doors are again
/// asymmetric: the ctrl carries a NID and the parameter a name. The `PRE_PARAMS_TO_CTRL` arm is the
/// interesting one — `default_fixup_args`'s `OSSL_PARAM_get_utf8_string` writes the *address of the
/// parameter's string* into the pointer it is given, so `p2` has to be the address of a `char *`
/// rather than the address of a buffer. Hence the named local, `sz`, and the very explicit authority
/// comment about the double indirection; a transcription that pointed `p2` at `name_buf` itself
/// would have the parameter's string written *over* the first eight bytes of the buffer.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NULL or NUL-terminated in
/// `PRE_CTRL_TO_PARAMS`.
pub(crate) unsafe extern "C" fn fix_ec_paramgen_curve_nid(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    /* The slot `default_fixup_args` writes the parameter's string pointer through. */
    let mut p2: *mut c_char = ptr::null_mut();

    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    /* This is currently only settable. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).action_type } != XlatAction::Set {
        return 0;
    }

    if state == XlatState::PreCtrlToParams {
        // SAFETY: `ctx` is live and `OBJ_nid2sn` answers a static string or NULL.
        unsafe {
            (*ctx).p2 = OBJ_nid2sn((*ctx).p1).cast_mut().cast::<c_void>();
            (*ctx).p1 = 0;
        }
    } else if state == XlatState::PreParamsToCtrl {
        // SAFETY: `ctx` is live and `p2` is this frame's own local, alive across the call below.
        unsafe {
            (*ctx).p2 = ptr::addr_of_mut!(p2).cast::<c_void>();
            (*ctx).sz = OSSL_MAX_NAME_SIZE;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if state == XlatState::PreParamsToCtrl {
        // SAFETY: `p2` was set by `default_fixup_args` and is NULL or NUL-terminated.
        unsafe {
            (*ctx).p1 = OBJ_sn2nid(p2);
            (*ctx).p2 = ptr::null_mut();
        }
    }

    ret
}

/// `static int fix_ecdh_cofactor(...)` — `crypto/evp/ctrl_params_translate.c:1182`.
///
/// The second of the two bidirectional-in-one-ctrl fixers, and it is the harder of the two because
/// **the action type is decided in four different states** and three of them are assertions: the
/// table row starts at `NONE` and the `PRE_CTRL_TO_PARAMS` arm requires it to still be `NONE`, the
/// `PRE_PARAMS_TO_CTRL` arm requires it to *not* be, and the two ctrl_str/`POST_PARAMS_TO_CTRL` arms
/// assign it outright. `ossl_assert` is live (D167), so a violated requirement is a quiet 0 rather
/// than a message — which is why the crate's `XlatAction` compares as a plain value here.
///
/// The two `-1`/`-2` sentinels are the ctrl's own protocol and are not this fixer's invention:
/// `p1 == -2` on the way in means "get", `p1 == -2` on the way *out* (the
/// `PRE_PARAMS_TO_CTRL` `GET` arm) means "this is a getter call", and a provider that answers a
/// cofactor of anything but 0 or 1 is reported as `-1` rather than as its own answer.
///
/// # Safety
/// `translation` NULL or live; `ctx` live.
pub(crate) unsafe extern "C" fn fix_ecdh_cofactor(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    if state == XlatState::PreCtrlToParams {
        /* The table row's initial action type must be zero; `EVP_PKEY_CTX_ctrl` takes it from the
         * translation item. */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).action_type } != XlatAction::None_ {
            return 0;
        }

        /* The action type depends on the value of `p1`. */
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).action_type = if (*ctx).p1 == -2 {
                XlatAction::Get
            } else {
                XlatAction::Set
            };
        }
    } else if state == XlatState::PreCtrlStrToParams {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).action_type = XlatAction::Set };
    } else if state == XlatState::PreParamsToCtrl {
        /* The initial value must *not* be zero here. */
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).action_type } == XlatAction::None_ {
            return 0;
        }
    } else if state == XlatState::PostParamsToCtrl {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).action_type } == XlatAction::None_ {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).action_type = XlatAction::Get };
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states. The authority declares `ret` as
    // 0 above its state switch and the switch never reads it, so binding it here is the same
    // value with one fewer dead store.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live. The action type is not written again below.
    let action_type = unsafe { (*ctx).action_type };

    if state == XlatState::PreCtrlToParams && action_type == XlatAction::Set {
        // SAFETY: `ctx` is live.
        let p1 = unsafe { (*ctx).p1 };
        if !(-1..=1).contains(&p1) {
            /* Uses the same return value `pkey_ec_ctrl` uses. */
            return -2;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if state == XlatState::PostCtrlToParams && action_type == XlatAction::Get {
        // SAFETY: `ctx` is live.
        let p1 = unsafe { (*ctx).p1 };
        if !(0..=1).contains(&p1) {
            /* The provider should return either 0 or 1; any other value is a provider error. */
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = -1 };
            ret = -1;
        }
    } else if state == XlatState::PreParamsToCtrl && action_type == XlatAction::Get {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p1 = -2 };
    } else if state == XlatState::PostParamsToCtrl && action_type == XlatAction::Get {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p1 = ret };
    }

    ret
}

/// The authority's `OSSL_ITEM` — `include/openssl/core.h:22` — as the three `str_value_map`s below
/// need it.
///
/// Two deviations, both forced. `id` is `unsigned int` in the authority and `c_int` here, because
/// both readers compare it against a signed `ctx->p1` through an `(int)` cast; the cast *is* this
/// declaration, and `RSA_PSS_SALTLEN_DIGEST`'s `-1` round-trips through it exactly. `ptr` is
/// `void *` there and `Option<&'static CStr>` here for the reason `KdfTypeMap`'s string is: a genuine
/// NULL member exists — `RSA_PKCS1_WITH_TLS_PADDING` has no name — and a bare `*const c_char` is not
/// `Sync`, so a `static` array spelled the authority's way would not compile.
struct StrValueMap {
    /// `unsigned int id`.
    id: c_int,
    /// `void *ptr` — NULL for the one mode with no string form.
    ptr: Option<&'static CStr>,
}

/// `fix_rsa_padding_mode`'s table — `crypto/evp/ctrl_params_translate.c:1252`.
///
/// **`"oeap"` is the authority's spelling**, and it is the second of the two
/// `RSA_PKCS1_OAEP_PADDING` rows: the first entry answers `"oaep"`, and this one exists so that a
/// caller who transposes the two vowels is answered as well. Correcting it to `"oaep"` would make
/// the table look tidier and answer one fewer string.
static RSA_PADDING_STR_VALUE_MAP: [StrValueMap; 7] = [
    StrValueMap {
        id: RSA_PKCS1_PADDING,
        ptr: Some(c"pkcs1"),
    },
    StrValueMap {
        id: RSA_NO_PADDING,
        ptr: Some(c"none"),
    },
    StrValueMap {
        id: RSA_PKCS1_OAEP_PADDING,
        ptr: Some(c"oaep"),
    },
    StrValueMap {
        id: RSA_PKCS1_OAEP_PADDING,
        ptr: Some(c"oeap"),
    },
    StrValueMap {
        id: RSA_X931_PADDING,
        ptr: Some(c"x931"),
    },
    StrValueMap {
        id: RSA_PKCS1_PSS_PADDING,
        ptr: Some(c"pss"),
    },
    /* Special case: passed directly as an integer. */
    StrValueMap {
        id: RSA_PKCS1_WITH_TLS_PADDING,
        ptr: None,
    },
];

/// `static int fix_rsa_padding_mode(...)` — `crypto/evp/ctrl_params_translate.c:1249`.
///
/// Four arms and a shared tail, and the reason it is this long is that the *same* setting has three
/// spellings: a number through the ctrl, a name through the ctrl_str, and either through an
/// `OSSL_PARAM`. The table standardises on names, so this function is what bridges the two.
///
/// Three details are load-bearing. `EVP_PKEY_CTRL_GET_RSA_PADDING` returns its answer through
/// `p2`-as-an-`int *` rather than as a return value, which is why the getter arm remembers `orig_p2`
/// exactly as `fix_cipher_md` does. The `SET` arm builds the `OSSL_PARAM` itself and **returns 1
/// without calling `default_fixup_args`**, because the parameter's declared type is `UTF8_STRING`
/// and the ctrl's value is an `int` — the one case where the core fixup cannot do the work.
/// `RSA_PKCS1_WITH_TLS_PADDING` has no name, so a caller who *gets* it as a string is told the
/// command is unsupported while a caller who gets it as an integer is answered.
///
/// **A defect is reproduced as a documented divergence.** The second loop — the one that turns a
/// name back into a number — calls `strcmp(ctx->p2, str_value_map[i].ptr)` for every entry,
/// including the last, whose `ptr` is NULL. A name that matches none of the six therefore reaches
/// `strcmp` with a NULL second argument, which is undefined; on the glibc build the authority is
/// pinned to it faults. The crate cannot reproduce a fault and does not want to, so `None` is
/// treated as "this entry does not match" and the loop's own not-found exit is taken instead: the
/// caller gets the `RSA_R_UNKNOWN_PADDING_TYPE` data error and `-2`, which is what the same caller
/// would get for any of the other five unmatched names.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's two-element array
/// in `PRE_CTRL_TO_PARAMS`, and `p2` NUL-terminated or NULL in the last arm.
pub(crate) unsafe extern "C" fn fix_rsa_padding_mode(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live. The action type is not written below.
    let action_type = unsafe { (*ctx).action_type };

    if state == XlatState::PreCtrlToParams && action_type == XlatAction::Get {
        /* `p2` holds the address of the caller's `int`; remember it and point `p2` at a buffer to be
         * filled with the name, `p1` at that buffer's size. */
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).orig_p2 = (*ctx).p2;
            (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
            (*ctx).p1 = OSSL_MAX_NAME_SIZE as c_int;
        }
    } else if state == XlatState::PreCtrlToParams && action_type == XlatAction::Set {
        /* The numeric mode goes straight through, so the parameter is built here and the core fixup
         * is skipped. */
        // SAFETY: `translation` is live, `ctx` is live, and `params` is the caller's array.
        unsafe {
            *(*ctx).params =
                OSSL_PARAM_construct_int((*translation).param_key, ptr::addr_of_mut!((*ctx).p1));
        }
        return 1;
    } else if state == XlatState::PostParamsToCtrl && action_type == XlatAction::Get {
        /* The caller may have asked for an integer, in which case it is answered directly; otherwise
         * the ctrl's number is translated into a name. */
        // SAFETY: `params` points at the caller's element.
        match unsafe { (*(*ctx).params).data_type } {
            OSSL_PARAM_INTEGER => {
                // SAFETY: `params` is the caller's element and `p1` is this context's own field.
                return unsafe { OSSL_PARAM_get_int((*ctx).params, ptr::addr_of_mut!((*ctx).p1)) };
            }
            OSSL_PARAM_UNSIGNED_INTEGER => {
                // SAFETY: as above, through the same `int`-sized slot.
                return unsafe {
                    OSSL_PARAM_get_uint((*ctx).params, ptr::addr_of_mut!((*ctx).p1).cast())
                };
            }
            _ => {}
        }

        let mut i = 0usize;
        while i < RSA_PADDING_STR_VALUE_MAP.len() {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).p1 } == RSA_PADDING_STR_VALUE_MAP[i].id {
                break;
            }
            i += 1;
        }
        if i == RSA_PADDING_STR_VALUE_MAP.len() {
            /* SAFETY: a compile-time-constant site; the `%d` is `ctx->p1`. */
            unsafe {
                raise_action_state_tail_int(
                    &err_sites::CTRL_PARAMS_TRANSLATE_1327,
                    action_type,
                    state,
                    b"padding number",
                    (*ctx).p1,
                )
            };
            return -2;
        }
        /* A NULL string is "no string for this number", which the caller asked for anyway. */
        let Some(s) = RSA_PADDING_STR_VALUE_MAP[i].ptr else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_1337) };
            return -2;
        };
        // SAFETY: `ctx` is live and `s` is a static NUL-terminated string.
        unsafe {
            (*ctx).p2 = s.as_ptr().cast_mut().cast::<c_void>();
            (*ctx).p1 = strlen(s.as_ptr()) as c_int;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if (action_type == XlatAction::Set && state == XlatState::PreParamsToCtrl)
        || (action_type == XlatAction::Get && state == XlatState::PostCtrlToParams)
    {
        let mut i = 0usize;
        while i < RSA_PADDING_STR_VALUE_MAP.len() {
            /* A NULL entry cannot be the name the caller passed, and the authority's own
             * `strcmp` against it is undefined; see this function's note. */
            if let Some(s) = RSA_PADDING_STR_VALUE_MAP[i].ptr {
                // SAFETY: `ctx` is live and both strings are NUL-terminated.
                if unsafe { strcmp((*ctx).p2.cast::<c_char>(), s.as_ptr()) } == 0 {
                    break;
                }
            }
            i += 1;
        }

        if i == RSA_PADDING_STR_VALUE_MAP.len() {
            /* SAFETY: a compile-time-constant site; the `%s` is `ctx->p2`. */
            unsafe {
                raise_action_state_tail_str(
                    &err_sites::CTRL_PARAMS_TRANSLATE_1357,
                    action_type,
                    state,
                    b"padding name",
                    (*ctx).p2.cast::<c_char>(),
                )
            };
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = -2 };
            ret = -2;
        } else if state == XlatState::PostCtrlToParams {
            /* `EVP_PKEY_CTRL_GET_RSA_PADDING`'s weirdness, explained further up. */
            // SAFETY: `orig_p2` is the caller's `int *`, remembered in the getter arm.
            unsafe { *(*ctx).orig_p2.cast::<c_int>() = RSA_PADDING_STR_VALUE_MAP[i].id };
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = RSA_PADDING_STR_VALUE_MAP[i].id };
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p2 = ptr::null_mut() };
    }

    ret
}

/// `fix_rsa_pss_saltlen`'s table — `crypto/evp/ctrl_params_translate.c:1376`.
///
/// Three entries and no NULL, which is the whole of the difference from the padding map: the three
/// keywords exist and a fourth — `RSA_PSS_SALTLEN_AUTO_DIGEST_MAX`, `-4` — deliberately has none, so
/// a `-4` reaching the second loop falls through to `atoi` and is answered as the number `-4`.
static RSA_PSS_SALTLEN_STR_VALUE_MAP: [StrValueMap; 3] = [
    StrValueMap {
        id: RSA_PSS_SALTLEN_DIGEST,
        ptr: Some(c"digest"),
    },
    StrValueMap {
        id: RSA_PSS_SALTLEN_MAX,
        ptr: Some(c"max"),
    },
    StrValueMap {
        id: RSA_PSS_SALTLEN_AUTO,
        ptr: Some(c"auto"),
    },
];

/// `static int fix_rsa_pss_saltlen(...)` — `crypto/evp/ctrl_params_translate.c:1374`.
///
/// `fix_rsa_padding_mode`'s shape with one difference that is entirely in the numbers: a salt length
/// may be **negative**, so the ctrl cannot return it as its own return value and the getter's `p2`
/// indirection is not a quirk here but a necessity. The other three-way distinction is that a salt
/// length is essentially numeric — any integer is legal — while only three of them have keywords, so
/// the number-to-name arm falls back to `%d` for the rest and the name-to-number arm falls back to
/// `atoi`.
///
/// Two spellings are copied rather than improved. `BIO_snprintf` is used for the numeric case where
/// `fix_kdf_type` would have used `strlen` of a table entry, and the keyword case goes through
/// `strncpy` plus a hand-written terminator — the authority's comment says the terminator "won't
/// truncate but it will quiet static analysers". Both write a NUL-terminated string into
/// `name_buf`; so does this, and `p1` is measured from the result either way.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NULL or NUL-terminated in the name-to-number
/// arm.
pub(crate) unsafe extern "C" fn fix_rsa_pss_saltlen(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live. The action type is not written below.
    let action_type = unsafe { (*ctx).action_type };

    if state == XlatState::PreCtrlToParams && action_type == XlatAction::Get {
        /* As in `fix_rsa_padding_mode`: `p2` is the address of the caller's `int`. */
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).orig_p2 = (*ctx).p2;
            (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
            (*ctx).p1 = OSSL_MAX_NAME_SIZE as c_int;
        }
    } else if (action_type == XlatAction::Set && state == XlatState::PreCtrlToParams)
        || (action_type == XlatAction::Get && state == XlatState::PostParamsToCtrl)
    {
        let mut i = 0usize;
        while i < RSA_PSS_SALTLEN_STR_VALUE_MAP.len() {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).p1 } == RSA_PSS_SALTLEN_STR_VALUE_MAP[i].id {
                break;
            }
            i += 1;
        }
        if i == RSA_PSS_SALTLEN_STR_VALUE_MAP.len() {
            /* `BIO_snprintf(ctx->name_buf, sizeof(ctx->name_buf), "%d", ctx->p1)` -- `push_int` is
             * this file's `%d`, already used for the error data text. `OSSL_MAX_NAME_SIZE` is
             * fifty and the longest `int` is eleven characters, so the authority's `snprintf`
             * truncation is unreachable and the bound is a formality here as it is there. */
            let mut m = Vec::new();
            // SAFETY: `ctx` is live.
            let p1 = unsafe { (*ctx).p1 };
            push_int(&mut m, p1);
            let n = m.len().min(OSSL_MAX_NAME_SIZE - 1);
            // SAFETY: `ctx` is live; `n < OSSL_MAX_NAME_SIZE`, so both the copy and the terminator
            // are inside `name_buf`.
            unsafe {
                let dst = ptr::addr_of_mut!((*ctx).name_buf).cast::<c_char>();
                ptr::copy_nonoverlapping(m.as_ptr().cast::<c_char>(), dst, n);
                *dst.add(n) = 0;
            }
        } else {
            /* `strncpy` plus the explicit terminator; all three strings are shorter than the
             * buffer. */
            if let Some(src) = RSA_PSS_SALTLEN_STR_VALUE_MAP[i].ptr {
                let src = src.to_bytes();
                let n = src.len().min(OSSL_MAX_NAME_SIZE - 1);
                // SAFETY: `ctx` is live; `n < OSSL_MAX_NAME_SIZE`, as above.
                unsafe {
                    let dst = ptr::addr_of_mut!((*ctx).name_buf).cast::<c_char>();
                    ptr::copy_nonoverlapping(src.as_ptr().cast::<c_char>(), dst, n);
                    *dst.add(n) = 0;
                }
            }
        }
        // SAFETY: `ctx` is live and `name_buf` is a NUL-terminated array inside it.
        unsafe {
            (*ctx).p2 = (*ctx).name_buf.as_mut_ptr().cast::<c_void>();
            (*ctx).p1 = strlen((*ctx).p2.cast::<c_char>()) as c_int;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if (action_type == XlatAction::Set && state == XlatState::PreParamsToCtrl)
        || (action_type == XlatAction::Get && state == XlatState::PostCtrlToParams)
    {
        let mut i = 0usize;
        while i < RSA_PSS_SALTLEN_STR_VALUE_MAP.len() {
            /* Every entry of this map has a string; a `None` would be a change to the authority's
             * table and is treated as a non-match rather than a fault. */
            let Some(s) = RSA_PSS_SALTLEN_STR_VALUE_MAP[i].ptr else {
                i += 1;
                continue;
            };
            // SAFETY: `ctx` is live and both strings are NUL-terminated.
            if unsafe { strcmp((*ctx).p2.cast::<c_char>(), s.as_ptr()) } == 0 {
                break;
            }
            i += 1;
        }

        /* SAFETY: `ctx` is live and `p2` is the NUL-terminated name the caller passed. */
        let val = unsafe {
            if i == RSA_PSS_SALTLEN_STR_VALUE_MAP.len() {
                atoi((*ctx).p2.cast::<c_char>())
            } else {
                RSA_PSS_SALTLEN_STR_VALUE_MAP[i].id
            }
        };
        if state == XlatState::PostCtrlToParams {
            /* `EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN`'s weirdness, explained further up. */
            // SAFETY: `orig_p2` is the caller's `int *`, remembered in the getter arm.
            unsafe { *(*ctx).orig_p2.cast::<c_int>() = val };
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = val };
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p2 = ptr::null_mut() };
    }

    ret
}

/// `fix_hkdf_mode`'s table — `crypto/evp/ctrl_params_translate.c:1456`.
static HKDF_MODE_STR_VALUE_MAP: [StrValueMap; 3] = [
    StrValueMap {
        id: EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
        ptr: Some(c"EXTRACT_AND_EXPAND"),
    },
    StrValueMap {
        id: EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
        ptr: Some(c"EXTRACT_ONLY"),
    },
    StrValueMap {
        id: EVP_KDF_HKDF_MODE_EXPAND_ONLY,
        ptr: Some(c"EXPAND_ONLY"),
    },
];

/// `static int fix_hkdf_mode(...)` — `crypto/evp/ctrl_params_translate.c:1454`.
///
/// The shortest of the three map fixers and the only one whose two loops **both** answer 0 — a mode
/// outside the three is refused rather than passed through as a number, which is the opposite of
/// `fix_rsa_pss_saltlen`'s `atoi` fallback and the same as `fix_kdf_type`'s `-1`.
///
/// **Its last line is a literal `1` and not `ret`.** That matters on the `GET` side:
/// `POST_CTRL_TO_PARAMS` assigns `ret = str_value_map[i].id` and the assignment is then discarded by
/// the `return 1`, so the ctrl's return value is "success" rather than the mode. The authority's own
/// comment on the ctrl-style GET protocol lives in `evp_pkey_ctx_ctrl_to_param`, which reads `p1`
/// rather than the return value on that path; the crate returns the literal for the same reason the
/// authority does, and it is *not* a transcription slip.
///
/// # Safety
/// `translation` NULL or live; `ctx` live, with `p2` NUL-terminated in the name-to-number arm.
pub(crate) unsafe extern "C" fn fix_hkdf_mode(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    let mut ret = unsafe { default_check(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    // SAFETY: `ctx` is live. The action type is not written below.
    let action_type = unsafe { (*ctx).action_type };

    if (action_type == XlatAction::Set && state == XlatState::PreCtrlToParams)
        || (action_type == XlatAction::Get && state == XlatState::PostParamsToCtrl)
    {
        let mut i = 0usize;
        while i < HKDF_MODE_STR_VALUE_MAP.len() {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).p1 } == HKDF_MODE_STR_VALUE_MAP[i].id {
                break;
            }
            i += 1;
        }
        if i == HKDF_MODE_STR_VALUE_MAP.len() {
            return 0;
        }
        /* Every entry of this map has a string; a `None` would be a change to the authority's table
         * and leaves `p2` NULL, which the core fixup then refuses. */
        let Some(s) = HKDF_MODE_STR_VALUE_MAP[i].ptr else {
            return 0;
        };
        // SAFETY: `ctx` is live and `s` is a static NUL-terminated string.
        unsafe {
            (*ctx).p2 = s.as_ptr().cast_mut().cast::<c_void>();
            (*ctx).p1 = strlen((*ctx).p2.cast::<c_char>()) as c_int;
        }
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    ret = unsafe { default_fixup_args(state, translation, ctx) };
    if ret <= 0 {
        return ret;
    }

    if (action_type == XlatAction::Set && state == XlatState::PreParamsToCtrl)
        || (action_type == XlatAction::Get && state == XlatState::PostCtrlToParams)
    {
        let mut i = 0usize;
        while i < HKDF_MODE_STR_VALUE_MAP.len() {
            /* As above: no entry is NULL. */
            let Some(s) = HKDF_MODE_STR_VALUE_MAP[i].ptr else {
                i += 1;
                continue;
            };
            // SAFETY: `ctx` is live and both strings are NUL-terminated.
            if unsafe { strcmp((*ctx).p2.cast::<c_char>(), s.as_ptr()) } == 0 {
                break;
            }
            i += 1;
        }
        if i == HKDF_MODE_STR_VALUE_MAP.len() {
            return 0;
        }
        if state == XlatState::PostCtrlToParams {
            /* Assigned and then discarded, exactly as in the authority: its `return 1` below
             * overrides whatever the map entry holds. */
            #[allow(unused_assignments)]
            {
                ret = HKDF_MODE_STR_VALUE_MAP[i].id;
            }
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = HKDF_MODE_STR_VALUE_MAP[i].id };
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).p2 = ptr::null_mut() };
    }

    /* The literal `1`, as in the authority. */
    1
}

// ---------------------------------------------------------------------------------------------
// The payload getters — slice (3) of `ctrl_params_translate.c`, and the one part of it this crate
// cannot finish
//
// **What these functions are for, and why nothing here runs.** They exist so that a *legacy*
// `EVP_PKEY` — a key built through a C API like `EVP_PKEY_assign_RSA`, carrying its key material in
// `pkey->pkey.ptr` rather than in a provider's keydata — can answer provider-style
// `EVP_PKEY_get_params` questions about that material. The whole of `EVP_PKEY_TRANSLATIONS` below is
// read by exactly one function, `evp_pkey_setget_params_to_ctrl`, which is called by exactly one,
// `evp_pkey_get_params_to_ctrl`, whose only caller in the authority is `EVP_PKEY_get_params`'s
// `#ifndef FIPS_MODULE` legacy arm — reached when `evp_pkey_is_legacy(pk)` holds, i.e. when
// `pk->type != EVP_PKEY_NONE && pk->keymgmt == NULL`.
//
// That state cannot be entered in this crate. `src/evp/pkey.rs`'s module note records why: the legacy
// block of `struct evp_pkey_st` is deliberately absent, so an `EVP_PKEY` here is always provider-side
// or blank, and the crate's own `EVP_PKEY_get_params` has no legacy arm to take. So the four
// functions on this axis — `evp_pkey_setget_params_to_ctrl`, `evp_pkey_get_params_to_ctrl`, and the
// lookups and tables above them — are written and have no caller until that arm lands. **One
// `#[allow(dead_code)]` covers the whole of it**, on `evp_pkey_get_params_to_ctrl`, which is the end
// of the chain: a reader who wonders why the thirteen getters below carry no allow of their own will
// find the answer there rather than a trail of them.
//
// **The dispatch is the part that cannot be written, and it is one line per function in the
// authority.** Every getter binds `EVP_PKEY *pkey = ctx->p2`, resets `ctx->p2`, and then switches on
// `EVP_PKEY_get_base_id(pkey)` to pick the key out of the legacy union with `EVP_PKEY_get0_DH`,
// `_get0_DSA`, `_get0_EC_KEY` or `_get0_RSA` before reading a member of it with `DH_get0_p`,
// `RSA_get0_n`, `EC_KEY_get0_group` and their siblings. **None of those ten functions exists in this
// crate**, and none can: they are the accessors of the legacy union, which is exactly the structure
// `src/evp/pkey.rs` does not have. There is no honest stand-in — a helper answering NULL would be a
// placeholder pretending to be an accessor — so each getter keeps everything that *is* expressible
// around the dispatch and the dispatch itself is the absence each site names.
//
// What that leaves is stated per function and is consistent: where the authority's own behaviour for
// "I looked and there is nothing there" is a value, that value is answered; where the authority would
// have *raised* because the key's type was unsupported, the crate does not raise, because it cannot
// read the type and inventing the error would put a message on the queue that a caller of a
// *supported* key would never see in the authority. Nothing here fabricates key material.
// ---------------------------------------------------------------------------------------------

/// `static int get_payload_group_name(...)` — `crypto/evp/ctrl_params_translate.c:1515`.
///
/// The named group of a DH or EC key, and the one getter whose miss is **not** an error: the
/// authority's closing comment says an unknown group is quietly ignored "to match the behaviour on
/// the provider side", and that is a `1` — the parameter was answered, with nothing. So the
/// dispatch's absence here leaves `ctx->p2` NULL and reaches the authority's own ignore path.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `p2` the `EVP_PKEY *` the table's caller passed.
pub(crate) unsafe extern "C" fn get_payload_group_name(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    /* The authority binds `EVP_PKEY *pkey = ctx->p2` and dispatches on
     * `EVP_PKEY_get_base_id(pkey)` here; see this section's note. */
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).p2 = ptr::null_mut() };

    /* Still NULL: the authority's "unknown group", which is ignored rather than reported. */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).p2 }.is_null() {
        return 1;
    }

    // SAFETY: `ctx` is live and `p2` is a NUL-terminated group name.
    unsafe { (*ctx).p1 = strlen((*ctx).p2.cast::<c_char>()) as c_int };
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int get_payload_private_key(...)` — `crypto/evp/ctrl_params_translate.c:1562`.
///
/// The key's private value as a BIGNUM, and the first of the two getters with a data-type guard that
/// runs **before** the dispatch and is therefore expressible: the answer is a BIGNUM, so anything but
/// `OSSL_PARAM_UNSIGNED_INTEGER` is a quiet 0 rather than an error. The dispatch after it is the
/// absence this section records, and with no dispatch there is no BIGNUM to hand
/// `default_fixup_args` — calling it with a NULL `p2` would have it answer from `p1` instead, which
/// is a wrong success rather than a refusal — so the answer is 0.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_payload_private_key(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).p2 = ptr::null_mut() };

    // SAFETY: `params` is the caller's element.
    if unsafe { (*(*ctx).params).data_type } != OSSL_PARAM_UNSIGNED_INTEGER {
        return 0;
    }

    /* The authority switches on `EVP_PKEY_get_base_id(pkey)` to pick the key out with
     * `EVP_PKEY_get0_DH`/`EVP_PKEY_get0_EC_KEY` and then reads `DH_get0_priv_key`/
     * `EC_KEY_get0_private_key`; see this section's note. No BIGNUM is fetched and `p2` stays NULL,
     * so there is nothing for `default_fixup_args` to write. */
    let _ = (state, translation);
    0
}

/// `static int get_payload_public_key(...)` — `crypto/evp/ctrl_params_translate.c:1595`.
///
/// The public key, and the one getter that answers **two different data types**: an octet string for
/// DH and EC (the encoded point or the padded public value) and an unsigned integer for DH and DSA.
/// It is the reason `OSSL_PKEY_PARAM_PUB_KEY`'s table row carries `param_data_type = 0` — the "let
/// the fixup decide" value this file's `default_fixup_args` documents. `buf` is allocated by the EC
/// and DH arms and freed after the fixup either way, on the success and the failure path alike.
///
/// With the dispatch absent there is no arm to enter and no buffer to free, so the answer is 0; the
/// authority's own `default:` arm would have raised `EVP_R_UNSUPPORTED_KEY_TYPE` here, and the crate
/// deliberately does not, for the reason this section's note gives.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_payload_public_key(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).p2 = ptr::null_mut() };

    /* The authority switches on `EVP_PKEY_get_base_id(pkey)` here and fills `buf`/`p2`/`sz` from
     * `ossl_dh_key2buf`, `DH_get0_pub_key`, `DSA_get0_pub_key` or `EC_POINT_point2buf`; see this
     * section's note. */
    let _ = (state, translation);
    0
}

/// `static int get_payload_public_key_ec(...)` — `crypto/evp/ctrl_params_translate.c:1658`.
///
/// `OSSL_PKEY_PARAM_EC_PUB_X` and `OSSL_PKEY_PARAM_EC_PUB_Y`: the affine coordinates, split out of
/// the point, and the reason the guard is on the **key** rather than on the data type — an `EC_KEY`
/// that is not there is `EVP_R_UNSUPPORTED_KEY_TYPE`, while a caller who asked for a BIGNUM when the
/// answer is a coordinate pair gets a quiet 0. The two columns are told apart by `strncmp` of the
/// parameter's own key name against `"qx"`/`"qy"` **for two characters**, which is the authority's
/// spelling and is enough because the two keys differ in their second byte.
///
/// The whole of it is inside `#ifndef OPENSSL_NO_EC` in the authority, with an `#else` that raises
/// and returns 0; this build has EC, so the `#ifndef` arm is the one transcribed — as an absence,
/// for the reason this section's note gives.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_payload_public_key_ec(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).p2 = ptr::null_mut() };

    /* The authority reads the key with `EVP_PKEY_get0_EC_KEY`, its group with `EC_KEY_get0_group`,
     * its point with `EC_KEY_get0_public_key`, and the two coordinates with
     * `EC_POINT_get_affine_coordinates`; see this section's note. */
    let _ = (state, translation);
    0
}

/// `static int get_payload_bn(...)` — `crypto/evp/ctrl_params_translate.c:1716`.
///
/// The tail every BIGNUM-shaped getter shares, and it is **fully transcribed** — it is the one place
/// in this group where nothing is absent. Two refusals in order: a NULL BIGNUM is a quiet 0, and a
/// caller who asked for anything but an unsigned integer is a quiet 0. Only then is `p2` set and the
/// core fixup trusted to turn a BIGNUM into the caller's parameter.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element; `bn` NULL or
/// a live `BIGNUM`.
pub(crate) unsafe extern "C" fn get_payload_bn(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    bn: *const BigNum,
) -> c_int {
    if bn.is_null() {
        return 0;
    }
    // SAFETY: `params` is the caller's element.
    if unsafe { (*(*ctx).params).data_type } != OSSL_PARAM_UNSIGNED_INTEGER {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).p2 = bn.cast_mut().cast::<c_void>() };

    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int get_dh_dsa_payload_p(...)` — `crypto/evp/ctrl_params_translate.c:1729`.
///
/// The FFC modulus, shared by DH and DSA. Note that the authority's `default:` arm raises and then
/// **falls through** to `get_payload_bn(state, translation, ctx, NULL)` — the two statements are not
/// alternatives, and since a NULL BIGNUM is a quiet 0 the raise is the only thing the default case
/// adds. The crate has neither the raise nor the dispatch, so the whole function is
/// `get_payload_bn(..., NULL)`, which is 0.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_dh_dsa_payload_p(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    /* The authority picks the modulus with `EVP_PKEY_get0_DH`/`DH_get0_p` or
     * `EVP_PKEY_get0_DSA`/`DSA_get0_p` after a `EVP_PKEY_get_base_id` switch; see this section's
     * note. */
    // SAFETY: `translation` and `ctx` are as the contract states; NULL is the contract's own
    // "no BIGNUM" and answers 0 without touching `ctx`.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_dh_dsa_payload_q(...)` — `crypto/evp/ctrl_params_translate.c:1754`.
///
/// The subgroup order. This one has **no `default:` arm at all** — a key that is neither DH nor DSA
/// leaves `bn` NULL and reaches the shared tail, which is 0 — so the crate's transcription is not
/// merely the same answer as the authority's, it is the same control flow with the two DH/DSA arms
/// removed.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_dh_dsa_payload_q(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_dh_dsa_payload_g(...)` — `crypto/evp/ctrl_params_translate.c:1776`.
///
/// The generator, and `get_dh_dsa_payload_q`'s sibling in every respect including the absence of a
/// `default:` arm.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_dh_dsa_payload_g(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_payload_int(...)` — `crypto/evp/ctrl_params_translate.c:1798`.
///
/// `get_payload_bn`'s signed sibling, and the differences are the whole of it: the guard is
/// `OSSL_PARAM_INTEGER`, the value travels in `p1` rather than `p2`, and `p2` is **cleared** rather
/// than set. Clearing matters: it tells `default_fixup_args`'s `POST` arm that this is a plain `int`
/// and not a BIGNUM, which is what selects `OSSL_PARAM_set_int` over `OSSL_PARAM_set_BN`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
#[allow(dead_code)] // read only by `get_ec_decoded_from_explicit_params`, whose EC arm is absent
pub(crate) unsafe extern "C" fn get_payload_int(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    val: c_int,
) -> c_int {
    // SAFETY: `params` is the caller's element.
    if unsafe { (*(*ctx).params).data_type } != OSSL_PARAM_INTEGER {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).p1 = val;
        (*ctx).p2 = ptr::null_mut();
    }

    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { default_fixup_args(state, translation, ctx) }
}

/// `static int get_ec_decoded_from_explicit_params(...)` —
/// `crypto/evp/ctrl_params_translate.c:1811`.
///
/// A three-valued answer — 1 for a key decoded from explicit parameters, 0 for one that was not, and
/// `EVP_R_INVALID_KEY` for a negative answer from the provider — so unlike the other integer getters
/// it cannot answer a default when it cannot tell: the authority's `val` starts at 0 and only the EC
/// arm ever writes it. Answering `get_payload_int(..., 0)` here would be a *plausible* answer that no
/// key in this crate was measured for, so the crate answers 0 without calling it.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_ec_decoded_from_explicit_params(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    /* The authority switches on `EVP_PKEY_base_id(pkey)` and reads the answer with
     * `EC_KEY_decoded_from_explicit_params`; see this section's note. */
    let _ = (state, translation, ctx);
    0
}

/// `static int get_rsa_payload_n(...)` — `crypto/evp/ctrl_params_translate.c:1836`.
///
/// The modulus, and the first of the seven getters that guard on the key's type being RSA **or**
/// RSA-PSS: the two share a key representation, so a PSS key's parameters are reachable through this
/// table. The guard and the `RSA_get0_n` behind it are one absence here, and it is a *harmless* one:
/// the guard's refusal and the shared tail's refusal are both 0, so the crate reaches the same answer
/// by the shorter route.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_n(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_rsa_payload_e(...)` — `crypto/evp/ctrl_params_translate.c:1850`.
///
/// The public exponent, `get_rsa_payload_n`'s twin down to the guard.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_rsa_payload_d(...)` — `crypto/evp/ctrl_params_translate.c:1864`.
///
/// The private exponent. Unlike the two above it, the crate's answer here is the *only* answer: the
/// authority's `EVP_PKEY_get0_RSA` would find a key for an RSA-typed `pkey`, so a transcription
/// without it is a gap and not an equivalence. It is a gap with no observable consequence, because
/// the caller that would reach it cannot exist; the section's note says so.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_d(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_rsa_payload_factor(...)` — `crypto/evp/ctrl_params_translate.c:1878`.
///
/// One prime, by index: 0 is `RSA_get0_p`, 1 is `RSA_get0_q`, and 2..12 are the multi-prime
/// `RSA_get0_multi_prime_factors` array under a bounds test against
/// `RSA_get_multi_prime_extra_count`. The two plain cases have **no** bounds test at all, which is
/// deliberate and asymmetric with the exponent and coefficient functions below.
///
/// The whole switch is the absence: it is five RSA accessors and a ten-element array, and with none
/// of them present there is no factor to return. `get_payload_bn` is handed NULL, which is the
/// authority's own answer for "this index has no factor".
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_factor(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    factornum: usize,
) -> c_int {
    /* The authority's `switch (factornum)` reads `RSA_get0_p`, `RSA_get0_q` and
     * `RSA_get0_multi_prime_factors` off `EVP_PKEY_get0_RSA(ctx->p2)`; see this section's note. */
    let _ = factornum;
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_rsa_payload_exponent(...)` — `crypto/evp/ctrl_params_translate.c:1906`.
///
/// One CRT exponent: 0 is `RSA_get0_dmp1`, 1 is `RSA_get0_dmq1`, and 2.. are the exponent half of
/// `RSA_get0_multi_prime_crt_params` — which is read **together with** the coefficient half into two
/// ten-element arrays that the function then ignores half of, because the API fills both and has no
/// one-output form.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_exponent(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    exponentnum: usize,
) -> c_int {
    let _ = exponentnum;
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

/// `static int get_rsa_payload_coefficient(...)` — `crypto/evp/ctrl_params_translate.c:1934`.
///
/// One CRT coefficient: 0 is `RSA_get0_iqmp` and 1.. are the coefficient half of
/// `RSA_get0_multi_prime_crt_params`. **The index offset differs from the other two families' and is
/// not a typo**: the multi-prime coefficient numbered `n` lives at `coefficientnum - 1` because the
/// first coefficient is `iqmp` and covers the first two primes, where the factors' and exponents'
/// arrays start at index 0 for the extra primes only.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_coefficient(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
    coefficientnum: usize,
) -> c_int {
    let _ = coefficientnum;
    // SAFETY: `translation` and `ctx` are as the contract states; NULL answers 0.
    unsafe { get_payload_bn(state, translation, ctx, ptr::null()) }
}

// ---------------------------------------------------------------------------------------------
// The thirty RSA payload instantiations — `IMPL_GET_RSA_PAYLOAD_{FACTOR,EXPONENT,COEFFICIENT}`
//
// C has no generic functions and the authority has no helper for this either, so it reaches for the
// preprocessor: three macros, thirty invocations, and one body apiece. Rust has no macro that can
// emit an *exported* item, and this project's rule is the stronger one anyway — every item is written
// out longhand so a reader can see it — so the three bodies are reproduced once, verbatim, in the
// comment below, and then each of the thirty instantiations is written out with `n` substituted.
//
//   #define IMPL_GET_RSA_PAYLOAD_FACTOR(n)                                 \
//       static int                                                         \
//       get_rsa_payload_f##n(enum state state,                             \
//           const struct translation_st *translation,                      \
//           struct translation_ctx_st *ctx)                                \
//       {                                                                  \
//           if (EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA              \
//               && EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA_PSS)      \
//               return 0;                                                  \
//           return get_rsa_payload_factor(state, translation, ctx, n - 1); \
//       }
//
//   #define IMPL_GET_RSA_PAYLOAD_EXPONENT(n)                          \
//       static int                                                    \
//       get_rsa_payload_e##n(enum state state,                        \
//           const struct translation_st *translation,                 \
//           struct translation_ctx_st *ctx)                           \
//       {                                                             \
//           if (EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA         \
//               && EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA_PSS) \
//               return 0;                                             \
//           return get_rsa_payload_exponent(state, translation, ctx,  \
//               n - 1);                                               \
//       }
//
//   #define IMPL_GET_RSA_PAYLOAD_COEFFICIENT(n)                         \
//       static int                                                      \
//       get_rsa_payload_c##n(enum state state,                          \
//           const struct translation_st *translation,                   \
//           struct translation_ctx_st *ctx)                             \
//       {                                                               \
//           if (EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA           \
//               && EVP_PKEY_get_base_id(ctx->p2) != EVP_PKEY_RSA_PSS)   \
//               return 0;                                               \
//           return get_rsa_payload_coefficient(state, translation, ctx, \
//               n - 1);                                                 \
//       }
//
// The guard in each body is the same absence the base functions carry — `EVP_PKEY_get_base_id` does
// not exist here — and it is *not* reproduced per function: it can only ever answer 0, which is what
// the base function answers anyway, so thirty copies of it would be thirty copies of a fact already
// stated. What is left of each body is the tail call, and that is the one line each instantiation
// below has, with the macro's `n - 1` already evaluated: `f1` passes 0, `f10` passes 9.
// ---------------------------------------------------------------------------------------------

/// `get_rsa_payload_f1` — `IMPL_GET_RSA_PAYLOAD_FACTOR(1)`, `ctrl_params_translate.c:1990`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f1(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 0) }
}

/// `get_rsa_payload_f2` — `IMPL_GET_RSA_PAYLOAD_FACTOR(2)`, `ctrl_params_translate.c:1991`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f2(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 1) }
}

/// `get_rsa_payload_f3` — `IMPL_GET_RSA_PAYLOAD_FACTOR(3)`, `ctrl_params_translate.c:1992`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f3(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 2) }
}

/// `get_rsa_payload_f4` — `IMPL_GET_RSA_PAYLOAD_FACTOR(4)`, `ctrl_params_translate.c:1993`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f4(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 3) }
}

/// `get_rsa_payload_f5` — `IMPL_GET_RSA_PAYLOAD_FACTOR(5)`, `ctrl_params_translate.c:1994`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f5(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 4) }
}

/// `get_rsa_payload_f6` — `IMPL_GET_RSA_PAYLOAD_FACTOR(6)`, `ctrl_params_translate.c:1995`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f6(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 5) }
}

/// `get_rsa_payload_f7` — `IMPL_GET_RSA_PAYLOAD_FACTOR(7)`, `ctrl_params_translate.c:1996`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f7(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 6) }
}

/// `get_rsa_payload_f8` — `IMPL_GET_RSA_PAYLOAD_FACTOR(8)`, `ctrl_params_translate.c:1997`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f8(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 7) }
}

/// `get_rsa_payload_f9` — `IMPL_GET_RSA_PAYLOAD_FACTOR(9)`, `ctrl_params_translate.c:1998`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f9(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 8) }
}

/// `get_rsa_payload_f10` — `IMPL_GET_RSA_PAYLOAD_FACTOR(10)`, `ctrl_params_translate.c:1999`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_f10(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_factor(state, translation, ctx, 9) }
}

/// `get_rsa_payload_e1` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(1)`, `ctrl_params_translate.c:2000`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e1(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 0) }
}

/// `get_rsa_payload_e2` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(2)`, `ctrl_params_translate.c:2001`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e2(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 1) }
}

/// `get_rsa_payload_e3` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(3)`, `ctrl_params_translate.c:2002`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e3(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 2) }
}

/// `get_rsa_payload_e4` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(4)`, `ctrl_params_translate.c:2003`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e4(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 3) }
}

/// `get_rsa_payload_e5` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(5)`, `ctrl_params_translate.c:2004`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e5(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 4) }
}

/// `get_rsa_payload_e6` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(6)`, `ctrl_params_translate.c:2005`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e6(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 5) }
}

/// `get_rsa_payload_e7` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(7)`, `ctrl_params_translate.c:2006`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e7(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 6) }
}

/// `get_rsa_payload_e8` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(8)`, `ctrl_params_translate.c:2007`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e8(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 7) }
}

/// `get_rsa_payload_e9` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(9)`, `ctrl_params_translate.c:2008`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e9(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 8) }
}

/// `get_rsa_payload_e10` — `IMPL_GET_RSA_PAYLOAD_EXPONENT(10)`, `ctrl_params_translate.c:2009`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_e10(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_exponent(state, translation, ctx, 9) }
}

/// `get_rsa_payload_c1` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(1)`, `ctrl_params_translate.c:2010`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c1(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 0) }
}

/// `get_rsa_payload_c2` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(2)`, `ctrl_params_translate.c:2011`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c2(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 1) }
}

/// `get_rsa_payload_c3` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(3)`, `ctrl_params_translate.c:2012`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c3(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 2) }
}

/// `get_rsa_payload_c4` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(4)`, `ctrl_params_translate.c:2013`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c4(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 3) }
}

/// `get_rsa_payload_c5` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(5)`, `ctrl_params_translate.c:2014`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c5(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 4) }
}

/// `get_rsa_payload_c6` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(6)`, `ctrl_params_translate.c:2015`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c6(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 5) }
}

/// `get_rsa_payload_c7` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(7)`, `ctrl_params_translate.c:2016`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c7(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 6) }
}

/// `get_rsa_payload_c8` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(8)`, `ctrl_params_translate.c:2017`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c8(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 7) }
}

/// `get_rsa_payload_c9` — `IMPL_GET_RSA_PAYLOAD_COEFFICIENT(9)`, `ctrl_params_translate.c:2018`.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with `params` pointing at the caller's element.
pub(crate) unsafe extern "C" fn get_rsa_payload_c9(
    state: XlatState,
    translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    // SAFETY: `translation` and `ctx` are as the contract states.
    unsafe { get_rsa_payload_coefficient(state, translation, ctx, 8) }
}

/// `static int fix_group_ecx(...)` — `crypto/evp/ctrl_params_translate.c:2027`.
///
/// The ECX rows' fixer, and the only one that **never calls `default_fixup_args`** — it is not a
/// translation at all. An ECX key has exactly one group, and the authority's contract for its
/// `OSSL_PKEY_PARAM_GROUP_NAME` is that the caller may only ever *assert* it: `PRE_PARAMS_TO_CTRL`
/// refuses unless the context is a generation one, and `POST_PARAMS_TO_CTRL` compares what the caller
/// asked for against `pctx->keytype` case-insensitively and answers 1 or `EVP_R_PASSED_INVALID_ARGUMENT`.
/// Which is why the four ECX rows carry `ctrl_num = -1` and no ctrl_str: there is no ctrl to call, and
/// the fixer short-circuits the loop by clearing the action type in `PRE_PARAMS_TO_CTRL` so that
/// `evp_pkey_ctx_setget_params_to_ctrl` skips its `EVP_PKEY_CTX_ctrl` call entirely.
///
/// # Safety
/// `translation` NULL or live; `ctx` live with a live `pctx` and `keytype`.
pub(crate) unsafe extern "C" fn fix_group_ecx(
    state: XlatState,
    _translation: *const XlatEntry,
    ctx: *mut XlatCtx,
) -> c_int {
    match state {
        XlatState::PreParamsToCtrl => {
            /* Not a generation operation: nothing to assert a group on. */
            // SAFETY: `ctx` is live and `pctx` is live per the contract.
            if !unsafe { (*(*ctx).pctx).is_gen_op() } {
                return 0;
            }
            /* `NONE` is what makes the caller's ctrl loop skip its `EVP_PKEY_CTX_ctrl` call. */
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).action_type = XlatAction::None_ };
            1
        }
        XlatState::PostParamsToCtrl => {
            let mut value: *const c_char = ptr::null();
            // SAFETY: `ctx` is live and `params` is the caller's element.
            let ok =
                unsafe { OSSL_PARAM_get_utf8_string_ptr((*ctx).params, ptr::addr_of_mut!(value)) };
            // SAFETY: `value` is NULL or points at the parameter's own NUL-terminated string, and
            // `pctx`'s `keytype` is this context's, which is NUL-terminated.
            let matches = ok != 0
                && !value.is_null()
                && unsafe { OPENSSL_strcasecmp((*(*ctx).pctx).keytype, value) } == 0;
            if !matches {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_2041) };
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).p1 = 0 };
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).p1 = 1 };
            1
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// The translation tables — slices (4) of `ctrl_params_translate.c`
//
// Two arrays of 127 entries between them, and every one of them is a *declaration* rather than a
// decision: the search rules live in `lookup_translation` below, and a row's meaning is entirely its
// ten fields. Both are laid out the way the authority's are, comments and all, so a reader can
// compare the two side by side; the authority's designated initialisers become named fields, which
// is the one transcription liberty taken and it removes the only way a row could be silently
// reordered.
//
// **`EVP_PKEY_CTX_TRANSLATIONS` is the whole of the observable surface; `EVP_PKEY_TRANSLATIONS` is
// not observable at all.** The first is read by the ctrl translator, which `EVP_PKEY_CTX_ctrl`
// reaches on every provider-side ctrl; the second is read only for *legacy* `EVP_PKEY`s, and this
// crate cannot hold one — see the payload-getter section above, which records the measurement at
// length.
//
// Three facts about the rows that a reader should check rather than assume, all of them measured
// against the authority rather than recalled:
//
//   * `action_type` is explicit on **all 127 rows**. There is no row that relies on the C enum's
//     zero default to mean `NONE`: the five rows that want `NONE` say so, and they name three
//     ctrls — `DH_KDF_TYPE`, `EC_ECDH_COFACTOR` and `EC_KDF_TYPE` — with the two EC ones appearing
//     twice each, because the SM2 block repeats the whole of the EC block and the repetition is
//     real: an SM2 context is a different key type and needs its own rows.
//   * `ctrl_num` is `-1` on exactly the four ECX rows of the ctx table, and `0` on every row of the
//     pkey table. Those are different absences: `-1` reaches `evp_pkey_ctx_setget_params_to_ctrl`'s
//     `EVP_PKEY_CTX_ctrl` call, which `fix_group_ecx` neutralises by clearing the action type, while
//     `0` means "there is no ctrl at all" and the pkey table has no ctrl call to make.
//   * exactly two rows have a `ctrl_hexstr` and no `ctrl_str` — `rsa_oaep_label` and
//     `rsa_pkcs1_implicit_rejection` — which is the authority's spelling of "this string is *always*
//     hex", and `default_fixup_args`'s `ishex` arm is what reads it.
// ---------------------------------------------------------------------------------------------

/// `static const struct translation_st evp_pkey_ctx_translations[]` —
/// `crypto/evp/ctrl_params_translate.c:2057`, 86 entries.
///
/// The authority's comment above the table says what the first three rows are for and why the
/// length getter has no `OSSL_PARAM` counterpart: the length of a DistID comes back with the DistID
/// itself, so `EVP_PKEY_CTRL_GET1_ID_LEN` exists only for callers written against the old ctrl API.
///
/// A `static` rather than a `const`, so that the address of each entry is stable and a
/// `*const XlatEntry` handed out by the lookup stays valid; and it can be one only because
/// [`XlatEntry`] is `Sync`, which its `unsafe impl` documents.
static EVP_PKEY_CTX_TRANSLATIONS: [XlatEntry; 86] = [
    /*
     * DistID: we pass it to the backend as an octet string,
     * but get it back as a pointer to an octet string.
     *
     * Note that the EVP_PKEY_CTRL_GET1_ID_LEN is purely for legacy purposes
     * that has no separate counterpart in OSSL_PARAM terms, since we get
     * the length of the DistID automatically when getting the DistID itself.
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_SET1_ID,
        ctrl_str: c"distid".as_ptr(),
        ctrl_hexstr: c"hexdistid".as_ptr(),
        param_key: OSSL_PKEY_PARAM_DIST_ID,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: EVP_PKEY_CTRL_GET1_ID,
        ctrl_str: c"distid".as_ptr(),
        ctrl_hexstr: c"hexdistid".as_ptr(),
        param_key: OSSL_PKEY_PARAM_DIST_ID,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: EVP_PKEY_CTRL_GET1_ID_LEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_DIST_ID,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: Some(fix_distid_len),
    },
    /*-
     * DH & DHX
     * ========
     */
    /*
     * EVP_PKEY_CTRL_DH_KDF_TYPE is used both for setting and getting.  The
     * fixup function has to handle this...
     */
    XlatEntry {
        action_type: XlatAction::None_,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_KDF_TYPE,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_TYPE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_kdf_type),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_KDF_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_DH_KDF_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_DH_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_KDF_OID,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_CEK_ALG,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_oid),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_DH_KDF_OID,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_CEK_ALG,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_oid),
    },
    /* DHX Keygen Parameters that are shared with DH */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,
        ctrl_str: c"dh_paramgen_type".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_TYPE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_paramgen_type),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN,
        ctrl_str: c"dh_paramgen_prime_len".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_PBITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_NID,
        ctrl_str: c"dh_param".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_RFC5114,
        ctrl_str: c"dh_rfc5114".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_nid5114),
    },
    /* DH Keygen Parameters that are shared with DHX */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,
        ctrl_str: c"dh_paramgen_type".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_TYPE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_paramgen_type),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN,
        ctrl_str: c"dh_paramgen_prime_len".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_PBITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_NID,
        ctrl_str: c"dh_param".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_nid),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_RFC5114,
        ctrl_str: c"dh_rfc5114".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_dh_nid5114),
    },
    /* DH specific Keygen Parameters */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR,
        ctrl_str: c"dh_paramgen_generator".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_DH_GENERATOR,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: None,
    },
    /* DHX specific Keygen Parameters */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DHX,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN,
        ctrl_str: c"dh_paramgen_subprime_len".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_QBITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DH,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_DH_PAD,
        ctrl_str: c"dh_pad".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_PAD,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    /*-
     * DSA
     * ===
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DSA_PARAMGEN_BITS,
        ctrl_str: c"dsa_paramgen_bits".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_PBITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS,
        ctrl_str: c"dsa_paramgen_q_bits".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_QBITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_DSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: EVP_PKEY_CTRL_DSA_PARAMGEN_MD,
        ctrl_str: c"dsa_paramgen_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    /*-
     * EC
     * ==
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_EC_PARAM_ENC,
        ctrl_str: c"ec_param_enc".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_EC_ENCODING,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_param_enc),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
        ctrl_str: c"ec_paramgen_curve".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_paramgen_curve_nid),
    },
    /*
     * EVP_PKEY_CTRL_EC_ECDH_COFACTOR and EVP_PKEY_CTRL_EC_KDF_TYPE are used
     * both for setting and getting.  The fixup function has to handle this...
     */
    XlatEntry {
        action_type: XlatAction::None_,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
        ctrl_str: c"ecdh_cofactor_mode".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: Some(fix_ecdh_cofactor),
    },
    XlatEntry {
        action_type: XlatAction::None_,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_TYPE,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_TYPE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_kdf_type),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_MD,
        ctrl_str: c"ecdh_kdf_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_EC,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: None,
    },
    /*-
     * SM2
     * ==
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_EC_PARAM_ENC,
        ctrl_str: c"ec_param_enc".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_EC_ENCODING,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_param_enc),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
        ctrl_str: c"ec_paramgen_curve".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_paramgen_curve_nid),
    },
    /*
     * EVP_PKEY_CTRL_EC_ECDH_COFACTOR and EVP_PKEY_CTRL_EC_KDF_TYPE are used
     * both for setting and getting.  The fixup function has to handle this...
     */
    XlatEntry {
        action_type: XlatAction::None_,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
        ctrl_str: c"ecdh_cofactor_mode".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: Some(fix_ecdh_cofactor),
    },
    XlatEntry {
        action_type: XlatAction::None_,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_TYPE,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_TYPE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_ec_kdf_type),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_MD,
        ctrl_str: c"ecdh_kdf_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_EC_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_SM2,
        keytype2: 0,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_GET_EC_KDF_UKM,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_EXCHANGE_PARAM_KDF_UKM,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: None,
    },
    /*-
     * RSA
     * ===
     */
    /*
     * RSA padding modes are numeric with ctrls, strings with ctrl_strs,
     * and can be both with OSSL_PARAM.  We standardise on strings here,
     * fix_rsa_padding_mode() does the work when the caller has a different
     * idea.
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_RSA_PADDING,
        ctrl_str: c"rsa_padding_mode".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_PAD_MODE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_rsa_padding_mode),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_GET_RSA_PADDING,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_PAD_MODE,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_rsa_padding_mode),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_RSA_MGF1_MD,
        ctrl_str: c"rsa_mgf1_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_MGF1_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_GET_RSA_MGF1_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_MGF1_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    /*
     * RSA-PSS saltlen is essentially numeric, but certain values can be
     * expressed as keywords (strings) with ctrl_str.  The corresponding
     * OSSL_PARAM allows both forms.
     * fix_rsa_pss_saltlen() takes care of the distinction.
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
        ctrl_str: c"rsa_pss_saltlen".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_rsa_pss_saltlen),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_rsa_pss_saltlen),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_RSA_OAEP_MD,
        ctrl_str: c"rsa_oaep_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_RSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_GET_RSA_OAEP_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    /*
     * The "rsa_oaep_label" ctrl_str expects the value to always be hex.
     * This is accommodated by default_fixup_args() above, which mimics that
     * expectation for any translation item where |ctrl_str| is NULL and
     * |ctrl_hexstr| is non-NULL.
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_RSA_OAEP_LABEL,
        ctrl_str: ptr::null(),
        ctrl_hexstr: c"rsa_oaep_label".as_ptr(),
        param_key: OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: EVP_PKEY_RSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
        param_data_type: OSSL_PARAM_OCTET_PTR,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION,
        ctrl_str: ptr::null(),
        ctrl_hexstr: c"rsa_pkcs1_implicit_rejection".as_ptr(),
        param_key: OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA_PSS,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_GEN,
        ctrl_num: EVP_PKEY_CTRL_MD,
        ctrl_str: c"rsa_pss_keygen_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_ALG_PARAM_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA_PSS,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_GEN,
        ctrl_num: EVP_PKEY_CTRL_RSA_MGF1_MD,
        ctrl_str: c"rsa_pss_keygen_mgf1_md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_MGF1_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA_PSS,
        keytype2: 0,
        optype: EVP_PKEY_OP_TYPE_GEN,
        ctrl_num: EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
        ctrl_str: c"rsa_pss_keygen_saltlen".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_RSA_KEYGEN_BITS,
        ctrl_str: c"rsa_keygen_bits".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_BITS,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,
        ctrl_str: c"rsa_keygen_pubexp".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_E,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_RSA,
        keytype2: EVP_PKEY_RSA_PSS,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES,
        ctrl_str: c"rsa_keygen_primes".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_PRIMES,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    /*-
     * SipHash
     * ======
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_SET_DIGEST_SIZE,
        ctrl_str: c"digestsize".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_MAC_PARAM_SIZE,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    /*-
     * TLS1-PRF
     * ========
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_TLS_MD,
        ctrl_str: c"md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_TLS_SECRET,
        ctrl_str: c"secret".as_ptr(),
        ctrl_hexstr: c"hexsecret".as_ptr(),
        param_key: OSSL_KDF_PARAM_SECRET,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_TLS_SEED,
        ctrl_str: c"seed".as_ptr(),
        ctrl_hexstr: c"hexseed".as_ptr(),
        param_key: OSSL_KDF_PARAM_SEED,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    /*-
     * HKDF
     * ====
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_HKDF_MD,
        ctrl_str: c"md".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_HKDF_SALT,
        ctrl_str: c"salt".as_ptr(),
        ctrl_hexstr: c"hexsalt".as_ptr(),
        param_key: OSSL_KDF_PARAM_SALT,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_HKDF_KEY,
        ctrl_str: c"key".as_ptr(),
        ctrl_hexstr: c"hexkey".as_ptr(),
        param_key: OSSL_KDF_PARAM_KEY,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_HKDF_INFO,
        ctrl_str: c"info".as_ptr(),
        ctrl_hexstr: c"hexinfo".as_ptr(),
        param_key: OSSL_KDF_PARAM_INFO,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_HKDF_MODE,
        ctrl_str: c"mode".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_MODE,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: Some(fix_hkdf_mode),
    },
    /*-
     * Scrypt
     * ======
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_PASS,
        ctrl_str: c"pass".as_ptr(),
        ctrl_hexstr: c"hexpass".as_ptr(),
        param_key: OSSL_KDF_PARAM_PASSWORD,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_SCRYPT_SALT,
        ctrl_str: c"salt".as_ptr(),
        ctrl_hexstr: c"hexsalt".as_ptr(),
        param_key: OSSL_KDF_PARAM_SALT,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_SCRYPT_N,
        ctrl_str: c"N".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_SCRYPT_N,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_SCRYPT_R,
        ctrl_str: c"r".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_SCRYPT_R,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_SCRYPT_P,
        ctrl_str: c"p".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_SCRYPT_P,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_DERIVE,
        ctrl_num: EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES,
        ctrl_str: c"maxmem_bytes".as_ptr(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_KDF_PARAM_SCRYPT_MAXMEM,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_KEYGEN | EVP_PKEY_OP_TYPE_CRYPT,
        ctrl_num: EVP_PKEY_CTRL_CIPHER,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_CIPHER,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_cipher),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: EVP_PKEY_CTRL_SET_MAC_KEY,
        ctrl_str: c"key".as_ptr(),
        ctrl_hexstr: c"hexkey".as_ptr(),
        param_key: OSSL_PKEY_PARAM_PRIV_KEY,
        param_data_type: OSSL_PARAM_OCTET_STRING,
        fixup_args: None,
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_SIGNATURE_PARAM_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: EVP_PKEY_OP_TYPE_SIG,
        ctrl_num: EVP_PKEY_CTRL_GET_MD,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_SIGNATURE_PARAM_DIGEST,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_md),
    },
    /*-
     * ECX
     * ===
     */
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_X25519,
        keytype2: EVP_PKEY_X25519,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: -1,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_group_ecx),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_X25519,
        keytype2: EVP_PKEY_X25519,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: -1,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_group_ecx),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_X448,
        keytype2: EVP_PKEY_X448,
        optype: EVP_PKEY_OP_KEYGEN,
        ctrl_num: -1,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_group_ecx),
    },
    XlatEntry {
        action_type: XlatAction::Set,
        keytype1: EVP_PKEY_X448,
        keytype2: EVP_PKEY_X448,
        optype: EVP_PKEY_OP_PARAMGEN,
        ctrl_num: -1,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(fix_group_ecx),
    },
];

/// `static const struct translation_st evp_pkey_translations[]` —
/// `crypto/evp/ctrl_params_translate.c:2432`, 41 entries.
///
/// The payload table, and the authority's own comment above it states the whole of its contract:
/// "The following contain no ctrls ... rely entirely on `fixup_args` to pass the actual data. The
/// `fixup_args` should expect to get the `EVP_PKEY` pointer through `ctx->p2`." That is why every
/// row's `ctrl_num` is 0 and its `optype` is `-1` — there is no ctrl to filter on and no operation
/// to match, because the caller is a key rather than a context.
static EVP_PKEY_TRANSLATIONS: [XlatEntry; 41] = [
    /*
     * The following contain no ctrls, they are exclusively here to extract
     * key payloads from legacy keys, using OSSL_PARAMs, and rely entirely
     * on |fixup_args| to pass the actual data.  The |fixup_args| should
     * expect to get the EVP_PKEY pointer through |ctx->p2|.
     */
    /* DH, DSA & EC */
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_GROUP_NAME,
        param_data_type: OSSL_PARAM_UTF8_STRING,
        fixup_args: Some(get_payload_group_name),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_PRIV_KEY,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_payload_private_key),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_PUB_KEY,
        /* no data type, let get_payload_public_key() handle that */
        param_data_type: 0,
        fixup_args: Some(get_payload_public_key),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_EC_PUB_X,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_payload_public_key_ec),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_EC_PUB_Y,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_payload_public_key_ec),
    },
    /* DH and DSA */
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_P,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_dh_dsa_payload_p),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_G,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_dh_dsa_payload_g),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_FFC_Q,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_dh_dsa_payload_q),
    },
    /* RSA */
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_N,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_n),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_E,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_D,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_d),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR1,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f1),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR2,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f2),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR3,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f3),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR4,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f4),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR5,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f5),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR6,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f6),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR7,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f7),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR8,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f8),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR9,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f9),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_FACTOR10,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_f10),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT1,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e1),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT2,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e2),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT3,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e3),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT4,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e4),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT5,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e5),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT6,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e6),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT7,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e7),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT8,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e8),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT9,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e9),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_EXPONENT10,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_e10),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c1),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c2),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c3),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c4),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c5),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c6),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c7),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c8),
    },
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_RSA_COEFFICIENT9,
        param_data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        fixup_args: Some(get_rsa_payload_c9),
    },
    /* EC */
    XlatEntry {
        action_type: XlatAction::Get,
        keytype1: -1,
        keytype2: -1,
        optype: -1,
        ctrl_num: 0,
        ctrl_str: ptr::null(),
        ctrl_hexstr: ptr::null(),
        param_key: OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
        param_data_type: OSSL_PARAM_INTEGER,
        fixup_args: Some(get_ec_decoded_from_explicit_params),
    },
];

// ---------------------------------------------------------------------------------------------
// The lookups and the seven entry points — slices (3) and (5) of `ctrl_params_translate.c`
// ---------------------------------------------------------------------------------------------

/// `int evp_pkey_ctx_set_params_strict(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)` —
/// `crypto/evp/pmeth_lib.c:858`.
///
/// The **provider-side** pre-check that turns "the provider never looked at this parameter" from a
/// silent success into `-2`: before the array is handed on, every key in it must appear in the
/// context's own settable list. A legacy context skips the check entirely and relies on the ctrl
/// translation answering `-2` for a command it does not know, which is the same answer by a longer
/// route — and the authority's comment says so, which is why the test is `is_provided` and not
/// "is there a method that could fail".
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a NULL-key-terminated array.
unsafe extern "C" fn evp_pkey_ctx_set_params_strict(
    ctx: *mut EvpPkeyCtx,
    params: *mut OsslParam,
) -> c_int {
    if ctx.is_null() || params.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).is_legacy() } {
        // SAFETY: `ctx` is live; the list is the provider's own static table or NULL.
        let settable = unsafe { EVP_PKEY_CTX_settable_params(ctx) };
        let mut p = params;
        // SAFETY: `params` is terminated, so walking it stays inside the array.
        while !unsafe { (*p).key }.is_null() {
            // SAFETY: `p` is a live element and `settable` is terminated.
            if unsafe { OSSL_PARAM_locate_const(settable, (*p).key) }.is_null() {
                return -2;
            }
            // SAFETY: `p` is inside the terminated array.
            p = unsafe { p.add(1) };
        }
    }

    // SAFETY: `ctx` and `params` are as the contract states.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params) }
}

/// `int evp_pkey_ctx_get_params_strict(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)` —
/// `crypto/evp/pmeth_lib.c:883`.
///
/// The read half, identical but for the list it consults — `gettable_ctx_params` where the setter
/// uses `settable_ctx_params`. That asymmetry is the provider contract's, not a mistake here: a
/// method may be able to read a parameter it cannot write.
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a NULL-key-terminated array.
unsafe extern "C" fn evp_pkey_ctx_get_params_strict(
    ctx: *mut EvpPkeyCtx,
    params: *mut OsslParam,
) -> c_int {
    if ctx.is_null() || params.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).is_legacy() } {
        // SAFETY: `ctx` is live; the list is the provider's own static table or NULL.
        let gettable = unsafe { EVP_PKEY_CTX_gettable_params(ctx) };
        let mut p = params;
        // SAFETY: `params` is terminated, so walking it stays inside the array.
        while !unsafe { (*p).key }.is_null() {
            // SAFETY: `p` is a live element and `gettable` is terminated.
            if unsafe { OSSL_PARAM_locate_const(gettable, (*p).key) }.is_null() {
                return -2;
            }
            // SAFETY: `p` is inside the terminated array.
            p = unsafe { p.add(1) };
        }
    }

    // SAFETY: `ctx` and `params` are as the contract states.
    unsafe { EVP_PKEY_CTX_get_params(ctx, params) }
}

/// `static const struct translation_st *lookup_translation(struct translation_st *tmpl, const struct
/// translation_st *translations, size_t translations_num)` — `crypto/evp/ctrl_params_translate.c:2573`.
///
/// The search, and the only decision-making in either table. Four criteria are applied in the
/// authority's order, and the order is observable: the first match wins, so a row that is *less*
/// specific above a more specific one would shadow it.
///
/// `tmpl` is an **in-out** parameter and that is the whole reason `evp_pkey_ctx_ctrl_str_to_param`
/// can tell whether the caller's name matched the row's `ctrl_str` or its `ctrl_hexstr`: the third
/// branch writes back which of the two it found, and the caller reads it as `ctx.ishex`. Writing the
/// template is therefore not an optimisation — it is the return channel.
///
/// The keytype test is `tmpl->keytype1 != item->keytype1 && tmpl->keytype2 != item->keytype2`, which
/// reads as a bug until one sees that every caller sets the template's two keytype fields to the
/// same value: the row matches either of its two types, which is how `(RSA, RSA_PSS)` covers both.
/// The sanity check above it is an `ossl_assert` over the *row* — a row with one keytype set and the
/// other not is skipped rather than matched — and it is live under `NDEBUG` (D167), so it is a plain
/// test here too.
///
/// # Safety
/// `tmpl` live; `translations` points at `translations_num` live entries.
unsafe extern "C" fn lookup_translation(
    tmpl: *mut XlatEntry,
    translations: *const XlatEntry,
    translations_num: usize,
) -> *const XlatEntry {
    let mut i = 0usize;
    while i < translations_num {
        // SAFETY: `i < translations_num`, so this entry is inside the caller's array.
        let item = unsafe { &*translations.add(i) };

        /* 1. Either both keytypes are -1, or neither of them are. */
        if !((item.keytype1 == -1) == (item.keytype2 == -1)) {
            i += 1;
            continue;
        }

        /* The base criteria: optype and keytypes, where relevant. */
        // SAFETY: `tmpl` is live.
        let tmpl_optype = unsafe { (*tmpl).optype };
        if item.optype != -1 && (tmpl_optype & item.optype) == 0 {
            i += 1;
            continue;
        }
        // SAFETY: `tmpl` is live.
        let (tmpl_k1, tmpl_k2) = unsafe { ((*tmpl).keytype1, (*tmpl).keytype2) };
        if item.keytype1 != -1 && tmpl_k1 != item.keytype1 && tmpl_k2 != item.keytype2 {
            i += 1;
            continue;
        }

        /* Now the criteria for the individual translation kinds. */
        // SAFETY: `tmpl` is live.
        let tmpl_ctrl_num = unsafe { (*tmpl).ctrl_num };
        if tmpl_ctrl_num != 0 {
            if tmpl_ctrl_num != item.ctrl_num {
                i += 1;
                continue;
            }
        } else {
            // SAFETY: `tmpl` is live.
            let tmpl_ctrl_str = unsafe { (*tmpl).ctrl_str };
            if !tmpl_ctrl_str.is_null() {
                let mut ctrl_str: *const c_char = ptr::null();
                let mut ctrl_hexstr: *const c_char = ptr::null();

                /* A ctrl_str search is only ever for *setting*. */
                if item.action_type != XlatAction::None_ && item.action_type != XlatAction::Set {
                    i += 1;
                    continue;
                }
                /* At least one of the two names must match. */
                // SAFETY: both strings are NULL or NUL-terminated, and the NULL test guards the
                // call.
                let plain = unsafe {
                    !item.ctrl_str.is_null()
                        && OPENSSL_strcasecmp(tmpl_ctrl_str, item.ctrl_str) == 0
                };
                // SAFETY: as above.
                let hex = !plain
                    && unsafe {
                        !item.ctrl_hexstr.is_null()
                            && OPENSSL_strcasecmp(tmpl_ctrl_str, item.ctrl_hexstr) == 0
                    };
                if plain {
                    ctrl_str = tmpl_ctrl_str;
                } else if hex {
                    ctrl_hexstr = tmpl_ctrl_str;
                } else {
                    i += 1;
                    continue;
                }

                /* Modify the template to signal which string matched. */
                // SAFETY: `tmpl` is live and belongs to the caller.
                unsafe {
                    (*tmpl).ctrl_str = ctrl_str;
                    (*tmpl).ctrl_hexstr = ctrl_hexstr;
                }
            } else {
                // SAFETY: `tmpl` is live.
                let tmpl_param_key = unsafe { (*tmpl).param_key };
                if !tmpl_param_key.is_null() {
                    /* `OSSL_PARAM` setters and getters are separated, so the action type has to be
                     * taken into account here in a way the ctrl side did not need. */
                    // SAFETY: `tmpl` is live.
                    let tmpl_action_type = unsafe { (*tmpl).action_type };
                    let action_mismatch = item.action_type != XlatAction::None_
                        && tmpl_action_type != item.action_type;
                    // SAFETY: both keys are NULL or NUL-terminated.
                    let key_mismatch = !item.param_key.is_null()
                        && unsafe { OPENSSL_strcasecmp(tmpl_param_key, item.param_key) } != 0;
                    if action_mismatch || key_mismatch {
                        i += 1;
                        continue;
                    }
                } else {
                    return ptr::null();
                }
            }
        }

        return item;
    }

    ptr::null()
}

/// `static const struct translation_st *lookup_evp_pkey_ctx_translation(struct translation_st
/// *tmpl)` — `crypto/evp/ctrl_params_translate.c:2662`.
///
/// # Safety
/// `tmpl` live.
unsafe extern "C" fn lookup_evp_pkey_ctx_translation(tmpl: *mut XlatEntry) -> *const XlatEntry {
    // SAFETY: `tmpl` is live and the table is a `static` of 86 live entries.
    unsafe { lookup_translation(tmpl, EVP_PKEY_CTX_TRANSLATIONS.as_ptr(), 86) }
}

/// `static const struct translation_st *lookup_evp_pkey_translation(struct translation_st *tmpl)` —
/// `crypto/evp/ctrl_params_translate.c:2669`.
///
/// # Safety
/// `tmpl` live.
unsafe extern "C" fn lookup_evp_pkey_translation(tmpl: *mut XlatEntry) -> *const XlatEntry {
    // SAFETY: `tmpl` is live and the table is a `static` of 41 live entries.
    unsafe { lookup_translation(tmpl, EVP_PKEY_TRANSLATIONS.as_ptr(), 41) }
}

/// `int evp_pkey_ctx_ctrl_to_param(EVP_PKEY_CTX *pctx, int keytype, int optype, int cmd, int p1,
/// void *p2)` — `crypto/evp/ctrl_params_translate.c:2676`.
///
/// The ctrl engine, and the shape every one of the seven entry points shares: build a template, find
/// a row, run the row's fixer **before** the real call to marshal the arguments, make the call, run
/// the fixer **after** it to marshal the results back, then clean up.
///
/// Four things about it are contracts rather than code. `keytype == -1` means "the context's own"
/// and is resolved from `legacy_keytype` — the field exists for exactly this. The two `ret > 0`
/// guards mean a fixer's refusal stops the call *and* the post-fixup, so a `-2` from a fixer reaches
/// the caller unchanged. The `ctx.p1 = ret` in the middle is how the ctrl's return value becomes
/// `p1` for the `POST` fixup, which is what lets a fixer adjust the length a getter reports. And
/// `cleanup_translation_ctx` is called **unconditionally**, on the failure paths too, because a fixer
/// that allocated before failing still owns that memory.
///
/// **One arm of the authority is absent here**: `pctx->pmeth != NULL && pctx->pmeth->pkey_id != ...`
/// answers `-1`. The crate's `EvpPkeyCtx` has no `pmeth` — D184's registry lives in a separate table
/// and `int_ctx_new` does not attach one — so the test is always false and the arm is omitted rather
/// than written as a dead branch.
///
/// # Safety
/// `pctx` live; `p2` NULL or valid for the state, action and ctrl the row describes.
pub(crate) unsafe extern "C" fn evp_pkey_ctx_ctrl_to_param(
    pctx: *mut EvpPkeyCtx,
    mut keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    let mut ctx = XlatCtx::ZEROED;
    let mut tmpl = XlatEntry::ZEROED;
    /* `OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END }`. */
    let mut params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    let mut fixup: FixupArgsFn = default_fixup_args;

    if keytype == -1 {
        // SAFETY: `pctx` is live per the contract.
        keytype = unsafe { (*pctx).legacy_keytype };
    }
    tmpl.ctrl_num = cmd;
    tmpl.keytype1 = keytype;
    tmpl.keytype2 = keytype;
    tmpl.optype = optype;
    // SAFETY: `tmpl` is live and the table is a static of 86 entries.
    let translation = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };

    if translation.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::CTRL_PARAMS_TRANSLATE_2717) };
        return -2;
    }

    /* The `pctx->pmeth` arm is absent; see this function's note. */

    // SAFETY: `translation` is live.
    if let Some(f) = unsafe { (*translation).fixup_args } {
        fixup = f;
    }
    // SAFETY: `ctx` is this frame's own live object; `params` is this frame's array.
    unsafe {
        ctx.action_type = (*translation).action_type;
        ctx.ctrl_cmd = cmd;
        ctx.p1 = p1;
        ctx.p2 = p2;
        ctx.pctx = pctx;
        ctx.params = params.as_mut_ptr();
    }

    // SAFETY: `translation` and `ctx` are live and the row describes these arguments.
    let mut ret = unsafe {
        fixup(
            XlatState::PreCtrlToParams,
            translation,
            ptr::addr_of_mut!(ctx),
        )
    };

    if ret > 0 {
        /* SAFETY: `ctx` is live and `params` is this frame's array, filled by the fixer. */
        ret = unsafe {
            match ctx.action_type {
                XlatAction::Get => evp_pkey_ctx_get_params_strict(pctx, ctx.params),
                XlatAction::Set => evp_pkey_ctx_set_params_strict(pctx, ctx.params),
                /* `fixup_args` is expected to make sure this is dead code. */
                XlatAction::None_ => ret,
            }
        };
    }

    if ret > 0 {
        /* SAFETY: `ctx` is live and `translation` is the row the lookup returned. */
        unsafe {
            ctx.p1 = ret;
            fixup(
                XlatState::PostCtrlToParams,
                translation,
                ptr::addr_of_mut!(ctx),
            );
            ret = ctx.p1;
        }
    }

    // SAFETY: `translation` and `ctx` are live; the cleanup releases whatever a fixer allocated.
    unsafe {
        cleanup_translation_ctx(
            XlatState::PostCtrlToParams,
            translation,
            ptr::addr_of_mut!(ctx),
        );
    }

    ret
}

/// `int evp_pkey_ctx_ctrl_str_to_param(EVP_PKEY_CTX *pctx, const char *name, const char *value)` —
/// `crypto/evp/ctrl_params_translate.c:2766`.
///
/// The string door, and the two things it does that the ctrl door does not are both about the name
/// being a *string*. It sets **both** `ctrl_str` and `ctrl_hexstr` in the template to the caller's
/// name, so the lookup may match either column; and it then sets `ctx.ishex` from which one *did*
/// match — `tmpl.ctrl_hexstr != NULL` after the lookup — which is how `default_fixup_args` knows to
/// build the `hex`-prefixed parameter key. A name that matches no row is not an error: the template
/// is left alone and the string is passed through as an `OSSL_PARAM` key, which is what makes
/// `EVP_PKEY_CTX_ctrl_str` usable with a provider parameter the table has never heard of.
///
/// `optype` is `-1` when the context has no operation yet, which is the one place this entry point
/// differs from `evp_pkey_ctx_ctrl_to_param`'s default: there, `-1` meant "the context's keytype".
///
/// # Safety
/// `pctx` live; `name` and `value` NUL-terminated.
pub(crate) unsafe extern "C" fn evp_pkey_ctx_ctrl_str_to_param(
    pctx: *mut EvpPkeyCtx,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let mut ctx = XlatCtx::ZEROED;
    let mut tmpl = XlatEntry::ZEROED;
    let mut params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `pctx` is live per the contract.
    let (keytype, operation) = unsafe { ((*pctx).legacy_keytype, (*pctx).operation) };
    let optype = if operation == 0 { -1 } else { operation };
    let mut fixup: FixupArgsFn = default_fixup_args;

    tmpl.action_type = XlatAction::Set;
    tmpl.keytype1 = keytype;
    tmpl.keytype2 = keytype;
    tmpl.optype = optype;
    tmpl.ctrl_str = name;
    tmpl.ctrl_hexstr = name;
    // SAFETY: `tmpl` is live and the table is a static of 86 entries.
    let translation = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };

    let mut ishex: c_int = 0;
    if !translation.is_null() {
        // SAFETY: `translation` is live.
        if let Some(f) = unsafe { (*translation).fixup_args } {
            fixup = f;
        }
        // SAFETY: `translation` is live.
        unsafe { ctx.action_type = (*translation).action_type };
        /* The lookup wrote `ctrl_hexstr` back; non-NULL means the hex column matched. */
        ishex = c_int::from(!tmpl.ctrl_hexstr.is_null());
    } else {
        /* String controls really only support setting. */
        ctx.action_type = XlatAction::Set;
    }
    // SAFETY: `ctx` and `params` are this frame's own; `value` is the caller's string.
    unsafe {
        ctx.ctrl_str = name;
        ctx.ishex = ishex;
        ctx.p1 = strlen(value) as c_int;
        ctx.p2 = value.cast_mut().cast::<c_void>();
        ctx.pctx = pctx;
        ctx.params = params.as_mut_ptr();
    }

    // SAFETY: `translation` and `ctx` are live; a NULL `translation` is legal in this state.
    let mut ret = unsafe {
        fixup(
            XlatState::PreCtrlStrToParams,
            translation,
            ptr::addr_of_mut!(ctx),
        )
    };

    if ret > 0 {
        // SAFETY: `ctx` is live and `params` is this frame's array, filled by the fixer.
        ret = unsafe {
            match ctx.action_type {
                /* Dead code, but present: the authority keeps the case for symmetry with the ctrl
                 * door, and there is nothing to do for it because a getter would have no value. */
                XlatAction::Get => ret,
                XlatAction::Set => evp_pkey_ctx_set_params_strict(pctx, ctx.params),
                XlatAction::None_ => ret,
            }
        };
    }

    if ret > 0 {
        // SAFETY: `translation` and `ctx` are live.
        ret = unsafe {
            fixup(
                XlatState::PostCtrlStrToParams,
                translation,
                ptr::addr_of_mut!(ctx),
            )
        };
    }

    // SAFETY: `translation` and `ctx` are live; the cleanup releases whatever a fixer allocated.
    unsafe {
        cleanup_translation_ctx(
            XlatState::CleanupCtrlStrToParams,
            translation,
            ptr::addr_of_mut!(ctx),
        );
    }

    ret
}

/// `static int evp_pkey_ctx_setget_params_to_ctrl(EVP_PKEY_CTX *pctx, enum action action_type,
/// OSSL_PARAM *params)` — `crypto/evp/ctrl_params_translate.c:2845`.
///
/// The reverse direction, and the whole of its shape comes from one fact: a **legacy** context has no
/// parameter plumbing at all, so a parameter must be turned into a ctrl and the ctrl called. Hence
/// the `ctx.ctrl_cmd = translation->ctrl_num` setup, the real `EVP_PKEY_CTX_ctrl` call in the middle,
/// and the `ctx.action_type != OSSL_ACTION_NONE` guard on it — a row whose fixer cleared the action
/// type, which is what `fix_group_ecx` does, is handled by the fixer alone.
///
/// The loop terminates on the first element that answers `<= 0`, and **only** on that: an element
/// that succeeds leaves the loop running, and the function's answer is the last element's. The
/// `ret >= 0` rather than `> 0` before the post-fixup is deliberate and the authority's comment says
/// why — `ecdh_cofactor` counts 0 as success — so a `0` still gets its `POST` fixup.
///
/// # Safety
/// `pctx` live; `params` NULL or a NULL-key-terminated array.
unsafe extern "C" fn evp_pkey_ctx_setget_params_to_ctrl(
    pctx: *mut EvpPkeyCtx,
    action_type: XlatAction,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `pctx` is live per the contract.
    let (keytype, operation) = unsafe { ((*pctx).legacy_keytype, (*pctx).operation) };
    let optype = if operation == 0 { -1 } else { operation };

    let mut p = params;
    while !p.is_null() {
        // SAFETY: `p` is inside the caller's terminated array.
        if unsafe { (*p).key }.is_null() {
            break;
        }

        let mut ctx = XlatCtx::ZEROED;
        let mut tmpl = XlatEntry::ZEROED;
        let mut fixup: FixupArgsFn = default_fixup_args;

        // SAFETY: `tmpl` is this frame's own live object.
        unsafe {
            ctx.action_type = action_type;
            tmpl.action_type = action_type;
            tmpl.keytype1 = keytype;
            tmpl.keytype2 = keytype;
            tmpl.optype = optype;
            tmpl.param_key = (*p).key;
        }
        // SAFETY: `tmpl` is live and the table is a static of 86 entries.
        let translation = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };

        if !translation.is_null() {
            // SAFETY: `translation` is live.
            if let Some(f) = unsafe { (*translation).fixup_args } {
                fixup = f;
            }
            // SAFETY: `translation` is live.
            unsafe { ctx.ctrl_cmd = (*translation).ctrl_num };
        }
        ctx.pctx = pctx;
        ctx.params = p;

        // SAFETY: `translation` and `ctx` are live; a NULL `translation` is legal here.
        let mut ret = unsafe {
            fixup(
                XlatState::PreParamsToCtrl,
                translation,
                ptr::addr_of_mut!(ctx),
            )
        };

        if ret > 0 && ctx.action_type != XlatAction::None_ {
            // SAFETY: `pctx` is live and `ctx`'s ctrl arguments came from the row and the fixer.
            ret = unsafe { EVP_PKEY_CTX_ctrl(pctx, keytype, optype, ctx.ctrl_cmd, ctx.p1, ctx.p2) };
        }

        if ret >= 0 {
            // SAFETY: `translation` and `ctx` are live.
            unsafe {
                ctx.p1 = ret;
                fixup(
                    XlatState::PostParamsToCtrl,
                    translation,
                    ptr::addr_of_mut!(ctx),
                );
                ret = ctx.p1;
            }
        }

        // SAFETY: `translation` and `ctx` are live; the cleanup releases whatever a fixer allocated.
        unsafe {
            cleanup_translation_ctx(
                XlatState::CleanupParamsToCtrl,
                translation,
                ptr::addr_of_mut!(ctx),
            );
        }

        if ret <= 0 {
            return 0;
        }

        /* SAFETY: `p` is inside the caller's terminated array. */
        p = unsafe { p.add(1) };
    }
    1
}

/// `int evp_pkey_ctx_set_params_to_ctrl(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params)` —
/// `crypto/evp/ctrl_params_translate.c:2914`.
///
/// # Safety
/// `ctx` live; `params` NULL or a NULL-key-terminated array.
pub(crate) unsafe extern "C" fn evp_pkey_ctx_set_params_to_ctrl(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if !unsafe { (*ctx).keymgmt }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` and `params` are as the contract states; the cast only discards `const`.
    unsafe { evp_pkey_ctx_setget_params_to_ctrl(ctx, XlatAction::Set, params.cast_mut()) }
}

/// `int evp_pkey_ctx_get_params_to_ctrl(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)` —
/// `crypto/evp/ctrl_params_translate.c:2921`.
///
/// # Safety
/// `ctx` live; `params` NULL or a NULL-key-terminated array.
pub(crate) unsafe extern "C" fn evp_pkey_ctx_get_params_to_ctrl(
    ctx: *mut EvpPkeyCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if !unsafe { (*ctx).keymgmt }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` and `params` are as the contract states.
    unsafe { evp_pkey_ctx_setget_params_to_ctrl(ctx, XlatAction::Get, params) }
}

/// `static int evp_pkey_setget_params_to_ctrl(const EVP_PKEY *pkey, enum action action_type,
/// OSSL_PARAM *params)` — `crypto/evp/ctrl_params_translate.c:2928`.
///
/// The key-side loop, and it is **not** the context-side loop with a different table: an `EVP_PKEY`
/// has no ctrl function at all, so the fixer does the whole of the work and there is no
/// `EVP_PKEY_CTX_ctrl` call, no `ctrl_cmd`, and no `cleanup` before the next element's `PRE`.
///
/// The three `ossl_assert`s are the contract, and they are live (D167): a caller whose parameter has
/// no row, or whose row is not a getter, or whose row has no fixer, gets `-2` rather than a quietly
/// unhandled parameter. The second one is why only `OSSL_ACTION_GET` may be asked for here, which is
/// the whole of what makes this table's rows all `GET`.
///
/// **It has no caller in this crate**, and the reason is measured rather than wished: its only caller
/// is `evp_pkey_get_params_to_ctrl` below, whose only caller in the authority is `EVP_PKEY_get_params`
/// on a legacy key — a state this crate cannot enter, as the payload-getter section above records.
///
/// # Safety
/// `pkey` live or NULL; `params` NULL or a NULL-key-terminated array.
unsafe extern "C" fn evp_pkey_setget_params_to_ctrl(
    pkey: *const EvpPkey,
    action_type: XlatAction,
    params: *mut OsslParam,
) -> c_int {
    let mut ret: c_int = 1;

    let mut p = params;
    while !p.is_null() {
        // SAFETY: `p` is inside the caller's terminated array.
        if unsafe { (*p).key }.is_null() {
            break;
        }

        let mut ctx = XlatCtx::ZEROED;
        let mut tmpl = XlatEntry::ZEROED;
        let mut fixup: FixupArgsFn = default_fixup_args;

        // SAFETY: `tmpl` is this frame's own live object; `p` is the caller's element.
        unsafe {
            tmpl.action_type = action_type;
            tmpl.param_key = (*p).key;
        }
        // SAFETY: `tmpl` is live and the table is a static of 41 entries.
        let translation = unsafe { lookup_evp_pkey_translation(ptr::addr_of_mut!(tmpl)) };

        if !translation.is_null() {
            // SAFETY: `translation` is live.
            if let Some(f) = unsafe { (*translation).fixup_args } {
                fixup = f;
            }
            // SAFETY: `translation` is live.
            unsafe { ctx.action_type = (*translation).action_type };
        }
        ctx.p2 = pkey.cast_mut().cast::<c_void>();
        ctx.params = p;

        /* The three live guards, in the authority's short-circuiting order: a NULL `translation`
         * must not reach the two dereferences. */
        // SAFETY: `translation` is live when it is not NULL, which is what the guard above each
        // dereference establishes.
        let bad = unsafe {
            translation.is_null()
                || (*translation).action_type != XlatAction::Get
                || (*translation).fixup_args.is_none()
        };
        if bad {
            return -2;
        }

        // SAFETY: `translation` and `ctx` are live and non-NULL on this path.
        ret = unsafe { fixup(XlatState::Pkey, translation, ptr::addr_of_mut!(ctx)) };

        // SAFETY: `translation` and `ctx` are live; the cleanup releases whatever a fixer allocated.
        unsafe {
            cleanup_translation_ctx(XlatState::Pkey, translation, ptr::addr_of_mut!(ctx));
        }

        /* SAFETY: `p` is inside the caller's terminated array. */
        p = unsafe { p.add(1) };
    }
    ret
}

/// `int evp_pkey_get_params_to_ctrl(const EVP_PKEY *pkey, OSSL_PARAM *params)` —
/// `crypto/evp/ctrl_params_translate.c:2972`.
///
/// **This is the root of the only dead chain in the file, and the single allow below is the whole of
/// its cost.** Its only caller is `EVP_PKEY_get_params` on a legacy key, a state this crate cannot
/// enter; keeping the allow *here* is what makes every other item on that axis — `EVP_PKEY_TRANSLATIONS`,
/// the thirteen payload getters, the twenty-nine RSA instantiations and the thirty
/// `OSSL_PKEY_PARAM_RSA_*` keys they name — reachable rather than dead, so the file carries one allow
/// for the chain instead of forty-five. A reader who wonders why those payload getters have no
/// `#[allow(dead_code)]` of their own has the answer in the one place it applies.
///
/// # Safety
/// `pkey` live or NULL; `params` NULL or a NULL-key-terminated array.
#[allow(dead_code)] // first live caller is `EVP_PKEY_get_params`'s legacy arm in `src/evp/pkey.rs`
pub(crate) unsafe extern "C" fn evp_pkey_get_params_to_ctrl(
    pkey: *const EvpPkey,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `pkey` and `params` are as the contract states.
    unsafe { evp_pkey_setget_params_to_ctrl(pkey, XlatAction::Get, params) }
}

// ---------------------------------------------------------------------------------------------
// The pmeth_lib.c entry points this file owns — slice (5)
//
// Twenty-nine exports, and they are the callers the slices above were waiting for: `EVP_PKEY_CTX_ctrl`
// is the only caller of `evp_pkey_ctx_ctrl_to_param`, `EVP_PKEY_CTX_ctrl_str` of
// `evp_pkey_ctx_ctrl_str_to_param`, `EVP_PKEY_CTX_set_params`/`get_params` of the two strict helpers,
// and the twenty-five remaining exports are thin wrappers over `EVP_PKEY_CTX_ctrl`,
// `EVP_PKEY_CTX_ctrl_str` or `EVP_PKEY_CTX_set_params` — which is why the `#[allow(dead_code)]`s
// that guarded those internals are gone as of this block.
//
// The one shape worth understanding before reading them: **the wrappers come in pairs, and the pair's
// difference is which side of the legacy split it falls back to.** A `set1_octet_string` style
// wrapper reads `ctx->op.kex.algctx == NULL` and, if it is, sends the value through the ctrl API
// where the translation tables above will turn it into an `OSSL_PARAM` — the "fallback" argument
// that every one of these functions carries. If it is not NULL the value goes straight to
// `EVP_PKEY_CTX_set_params`. The same value therefore has two roads to the same provider, and which
// one is taken is decided by a NULL test on one union member.
// ---------------------------------------------------------------------------------------------

/// `int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params)` —
/// `crypto/evp/pmeth_lib.c:677`.
///
/// The provider-side setter, and five blocks in an order that is **not** the getter's: the key
/// generation family is tried before the KEM family here and after it in `EVP_PKEY_CTX_get_params`.
/// Nothing observable depends on it — a context carries one operation bit at a time — and copying the
/// order rather than "fixing" it is the point, for the same reason `settable_params` here and
/// `gettable_params` above differ.
///
/// **A NULL context is answered `0` rather than faulted, and that is this crate's one divergence in
/// this block.** The authority's `switch (evp_pkey_ctx_state(ctx))` dereferences `ctx` — its
/// `evp_pkey_ctx_state` has no NULL test — so `EVP_PKEY_CTX_set_params(NULL, params)` faults there.
/// The crate's `gettable_params` and `settable_params`, which this file landed earlier, already answer
/// NULL for a NULL argument, so doing the same here keeps the family consistent instead of making one
/// of the five the odd one out; the value chosen is `0`, which is what the authority answers for the
/// state a NULL context would be in.
///
/// The legacy arm is the **whole** reason this function and `evp_pkey_ctx_set_params_to_ctrl` exist
/// as a pair: a legacy context has no provider method to hand the array to, so the array is walked
/// and each element is translated into a ctrl. It is reachable in this crate — a context whose
/// `keymgmt` is NULL but whose operation is set is `EVP_PKEY_STATE_LEGACY` by `evp_pkey_ctx_state`'s
/// definition — which is what makes the ctx table observable and the pkey table not.
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a NULL-key-terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_params(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live or NULL per the contract, and `evp_pkey_ctx_state` reads nothing from a
    // NULL pointer because the caller's test below comes first in the authority's switch.
    let state = if ctx.is_null() {
        EVP_PKEY_STATE_UNKNOWN
    } else {
        // SAFETY: `ctx` is live.
        unsafe { evp_pkey_ctx_state(ctx) }
    };

    if state == EVP_PKEY_STATE_LEGACY {
        // SAFETY: `ctx` is live and `params` is terminated.
        return unsafe { evp_pkey_ctx_set_params_to_ctrl(ctx, params) };
    }
    if state != EVP_PKEY_STATE_PROVIDER {
        return 0;
    }

    // SAFETY: `ctx` is live.
    let c = unsafe { &*ctx };

    if c.is_derive_op() && !c.op_kex_exchange.is_null() {
        // SAFETY: `op_kex_exchange` is live.
        let f = unsafe { (*c.op_kex_exchange).set_ctx_params };
        if let Some(f) = f {
            // SAFETY: `f` is the provider's own callback, `op_kex_algctx` is its context and
            // `params` is the caller's terminated array.
            return unsafe { f(c.op_kex_algctx, params) };
        }
    }
    if c.is_signature_op() && !c.op_sig_signature.is_null() {
        // SAFETY: `op_sig_signature` is live.
        let f = unsafe { (*c.op_sig_signature).set_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_sig_algctx, params) };
        }
    }
    if c.is_asym_cipher_op() && !c.op_ciph_cipher.is_null() {
        // SAFETY: `op_ciph_cipher` is live.
        let f = unsafe { (*c.op_ciph_cipher).set_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_ciph_algctx, params) };
        }
    }
    if c.is_gen_op() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        if unsafe { (*c.keymgmt).gen_set_params }.is_some() {
            // SAFETY: `keymgmt` is live and its genctx belongs to it.
            return unsafe { evp_keymgmt_gen_set_params(c.keymgmt, c.op_keymgmt_genctx, params) };
        }
    }
    if c.is_kem_op() && !c.op_encap_kem.is_null() {
        // SAFETY: `op_encap_kem` is live.
        let f = unsafe { (*c.op_encap_kem).set_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_encap_algctx, params) };
        }
    }
    0
}

/// `int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)` —
/// `crypto/evp/pmeth_lib.c:717`.
///
/// The read half. Its legacy arm is `evp_pkey_ctx_get_params_to_ctrl`, which is the *other* half of
/// the pair described above; the five provider blocks are the same five as the setter's with the
/// KEM and key-generation families swapped, and that swap is the authority's. A NULL context is
/// answered `0` for the reason `EVP_PKEY_CTX_set_params` records.
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a NULL-key-terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_params(
    ctx: *mut EvpPkeyCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live or NULL; see `EVP_PKEY_CTX_set_params`.
    let state = if ctx.is_null() {
        EVP_PKEY_STATE_UNKNOWN
    } else {
        // SAFETY: `ctx` is live.
        unsafe { evp_pkey_ctx_state(ctx) }
    };

    if state == EVP_PKEY_STATE_LEGACY {
        // SAFETY: `ctx` is live and `params` is terminated.
        return unsafe { evp_pkey_ctx_get_params_to_ctrl(ctx, params) };
    }
    if state != EVP_PKEY_STATE_PROVIDER {
        return 0;
    }

    // SAFETY: `ctx` is live.
    let c = unsafe { &*ctx };

    if c.is_derive_op() && !c.op_kex_exchange.is_null() {
        // SAFETY: `op_kex_exchange` is live.
        let f = unsafe { (*c.op_kex_exchange).get_ctx_params };
        if let Some(f) = f {
            // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
            return unsafe { f(c.op_kex_algctx, params) };
        }
    }
    if c.is_signature_op() && !c.op_sig_signature.is_null() {
        // SAFETY: `op_sig_signature` is live.
        let f = unsafe { (*c.op_sig_signature).get_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_sig_algctx, params) };
        }
    }
    if c.is_asym_cipher_op() && !c.op_ciph_cipher.is_null() {
        // SAFETY: `op_ciph_cipher` is live.
        let f = unsafe { (*c.op_ciph_cipher).get_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_ciph_algctx, params) };
        }
    }
    if c.is_kem_op() && !c.op_encap_kem.is_null() {
        // SAFETY: `op_encap_kem` is live.
        let f = unsafe { (*c.op_encap_kem).get_ctx_params };
        if let Some(f) = f {
            // SAFETY: as above.
            return unsafe { f(c.op_encap_algctx, params) };
        }
    }
    if c.is_gen_op() && !c.keymgmt.is_null() {
        // SAFETY: `keymgmt` is live.
        if unsafe { (*c.keymgmt).gen_get_params }.is_some() {
            // SAFETY: `keymgmt` is live and its genctx belongs to it.
            return unsafe { evp_keymgmt_gen_get_params(c.keymgmt, c.op_keymgmt_genctx, params) };
        }
    }
    0
}

/// `int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)` —
/// `crypto/evp/pmeth_lib.c:908`.
///
/// The one getter that answers an `EVP_MD` rather than a parameter value, and it does it in **two
/// different ways** depending on the context. A legacy signature context has a ctrl for it
/// (`EVP_PKEY_CTRL_GET_MD`, whose fixer writes the algorithm through the caller's pointer), so the
/// function asks the ctrl. A provider context has no such ctrl, so it asks for the digest's *name*
/// as a string parameter and looks the name up in the library context — an extra round trip that
/// exists because a provider returns its own method and only the library can turn its name back into
/// the `EVP_MD *` the caller's compiler sees.
///
/// `char name[80]` is the authority's and the buffer size is load-bearing twice: it is the
/// parameter's `data_size`, so a provider that writes more is refused rather than overrunning, and
/// the authority's comment calls eighty "big enough" rather than deriving it. `evp_get_digestbyname_ex`
/// is the *library context's* lookup, not the global one, which is what makes a signature context
/// fetched from a non-default context answer its own provider's digest.
///
/// # Safety
/// `ctx` NULL or live; `md` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_signature_md(
    ctx: *mut EvpPkeyCtx,
    md: *mut *const EvpMd,
) -> c_int {
    let mut name = [0 as c_char; 80];

    // SAFETY: `ctx` is live.
    if ctx.is_null() || !unsafe { (*ctx).is_signature_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_916) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).op_sig_algctx }.is_null() {
        // SAFETY: `ctx` is live and `md` is the caller's pointer-to-pointer.
        return unsafe {
            EVP_PKEY_CTX_ctrl(
                ctx,
                -1,
                EVP_PKEY_OP_TYPE_SIG,
                EVP_PKEY_CTRL_GET_MD,
                0,
                md.cast::<c_void>(),
            )
        };
    }

    let mut sig_md_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `name` is this frame's own array and the parameter points at it.
    unsafe {
        sig_md_params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_DIGEST,
            name.as_mut_ptr(),
            name.len(),
        );
    }

    // SAFETY: `ctx` is live and `sig_md_params` is this frame's terminated array.
    if unsafe { EVP_PKEY_CTX_get_params(ctx, sig_md_params.as_mut_ptr()) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live; `name` is a NUL-terminated array the provider wrote into.
    let tmp = unsafe { evp_get_digestbyname_ex((*ctx).libctx, name.as_ptr()) };
    if tmp.is_null() {
        return 0;
    }

    // SAFETY: `md` is the caller's writable pointer.
    unsafe { *md = tmp };
    1
}

/// `static int evp_pkey_ctx_set_md(EVP_PKEY_CTX *ctx, const EVP_MD *md, int fallback,
/// const char *param, int op, int ctrl)` — `crypto/evp/pmeth_lib.c:942`.
///
/// The shared body of the two `set_*_md` exports. Its guard is `(ctx->operation & op) == 0` — a
/// **bit test on the operation**, not an equality — so it refuses before the operation is set and
/// also for an operation of the wrong family, both with `EVP_R_COMMAND_NOT_SUPPORTED` and `-2`.
///
/// The `fallback` argument is the legacy road: when the operation's algorithm context is not there,
/// the `EVP_MD *` is handed to `EVP_PKEY_CTX_ctrl`, whose table row for that ctrl is the one that
/// calls `fix_md` — which is where a pointer becomes a name. When it *is* there, the name is taken
/// here and passed as a `UTF8_STRING` parameter, with `data_size` 0 meaning "NUL-terminated".
/// `md == NULL` becomes the empty string rather than NULL, which is the provider contract's way of
/// saying "no digest".
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or live; `param` NUL-terminated.
unsafe extern "C" fn evp_pkey_ctx_set_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
    fallback: c_int,
    param: *const c_char,
    op: c_int,
    ctrl: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_950) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } & op == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_950) };
        return -2;
    }

    if fallback != 0 {
        // SAFETY: `ctx` is live and `md` is the caller's pointer, which the row's fixer reads.
        return unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, op, ctrl, 0, md.cast_mut().cast::<c_void>()) };
    }

    // SAFETY: `md` is NULL or live.
    let name = if md.is_null() {
        c"".as_ptr()
    } else {
        // SAFETY: `md` is live.
        unsafe { EVP_MD_get0_name(md) }
    };

    let mut md_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `name` is NUL-terminated; the cast only discards `const`, which the parameter
    // contract's read-only use of `data` makes safe.
    unsafe {
        md_params[0] = OSSL_PARAM_construct_utf8_string(param, name.cast_mut(), 0);
    }

    // SAFETY: `ctx` is live and `md_params` is this frame's terminated array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, md_params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `crypto/evp/pmeth_lib.c:975`.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_signature_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_sig_algctx }.is_null())
    };
    // SAFETY: `ctx` and `md` are as the contract states.
    unsafe {
        evp_pkey_ctx_set_md(
            ctx,
            md,
            fallback,
            OSSL_SIGNATURE_PARAM_DIGEST,
            EVP_PKEY_OP_TYPE_SIG,
            EVP_PKEY_CTRL_MD,
        )
    }
}

/// `int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `crypto/evp/pmeth_lib.c:982`.
///
/// TLS1-PRF's digest, and the fallback test reads the **DERIVE** family's algorithm context. That is
/// the whole difference between this and `EVP_PKEY_CTX_set_signature_md` above: the same helper, the
/// same parameter key, and a different union member deciding which road the value takes.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_tls1_prf_md(
    ctx: *mut EvpPkeyCtx,
    md: *const EvpMd,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `md` are as the contract states.
    unsafe {
        evp_pkey_ctx_set_md(
            ctx,
            md,
            fallback,
            OSSL_KDF_PARAM_DIGEST,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_MD,
        )
    }
}

/// `static int evp_pkey_ctx_set1_octet_string(EVP_PKEY_CTX *ctx, int fallback, const char *param,
/// int op, int ctrl, const unsigned char *data, int datalen)` — `crypto/evp/pmeth_lib.c:989`.
///
/// The shared body of the nine `set1_*` exports, and unlike `set_md` it builds the parameter **after**
/// the fallback test rather than before: the `datalen < 0` guard sits below the ctrl road, so a
/// negative length on the legacy road is passed to the ctrl (where `fix_distid_len`-style rows read it
/// as a length) rather than refused here. The `OSSL_PARAM` is `OCTET_STRING` with the caller's length,
/// not `data_size` 0, because an octet string may contain NUL.
///
/// # Safety
/// `ctx` NULL or live; `param` NUL-terminated; `data` NULL or `datalen` readable bytes when
/// `datalen >= 0`.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn evp_pkey_ctx_set1_octet_string(
    ctx: *mut EvpPkeyCtx,
    fallback: c_int,
    param: *const c_char,
    op: c_int,
    ctrl: c_int,
    data: *const u8,
    datalen: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_997) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } & op == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_997) };
        return -2;
    }

    if fallback != 0 {
        // SAFETY: `ctx` is live and `data`/`datalen` are the caller's buffer and its length, which
        // the row's fixer reads as `p2`/`p1`.
        return unsafe {
            EVP_PKEY_CTX_ctrl(ctx, -1, op, ctrl, datalen, data.cast_mut().cast::<c_void>())
        };
    }

    if datalen < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1008) };
        return 0;
    }

    let mut octet_string_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `data` is NULL or `datalen` readable bytes, which is what the parameter records.
    unsafe {
        octet_string_params[0] = OSSL_PARAM_construct_octet_string(
            param,
            data.cast_mut().cast::<c_void>(),
            datalen as usize,
        );
    }

    // SAFETY: `ctx` is live and `octet_string_params` is this frame's terminated array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, octet_string_params.as_ptr()) }
}

/// `static int evp_pkey_ctx_add1_octet_string(EVP_PKEY_CTX *ctx, int fallback, const char *param,
/// int op, int ctrl, const unsigned char *data, int datalen)` — `crypto/evp/pmeth_lib.c:1024`.
///
/// The *append* form, used by exactly two exports (`add1_tls1_prf_seed` and `add1_hkdf_info`), and
/// it is the most intricate of these helpers because appending to a provider parameter means
/// read-modify-write. Four things about it are contracts:
///
///   * `datalen == 0` is **success without a call** — appending nothing is not an error and is
///     deliberately not even a round trip.
///   * a provider that does not carry the parameter at all (`gettable` does not list it) is sent the
///     value through `set1` instead, i.e. the fallback *within* the fallback. That is how an older
///     provider that refuses to be read still accepts an append.
///   * `return_size == OSSL_PARAM_UNMODIFIED` after a get is a provider error, checked because
///     `return_size` is `usize` and an unchecked one would size the allocation below.
///   * the new buffer is `return_size + datalen`, zeroed, and the caller's bytes are appended at
///     `info_len`. So the parameter that goes back carries **both** halves and the provider is
///     expected to replace rather than concatenate, which is why the get-then-set pair is not
///     `add1` on the provider side.
///
/// The `error:` label frees with `OPENSSL_clear_free`, on every path — an HMAC or HKDF key is a
/// secret, which is what the clearing is for.
///
/// # Safety
/// `ctx` NULL or live; `param` NUL-terminated; `data` NULL or `datalen` readable bytes when
/// `datalen >= 0`.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn evp_pkey_ctx_add1_octet_string(
    ctx: *mut EvpPkeyCtx,
    fallback: c_int,
    param: *const c_char,
    op: c_int,
    ctrl: c_int,
    data: *const u8,
    datalen: c_int,
) -> c_int {
    let mut ret: c_int = 0;

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1037) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } & op == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1037) };
        return -2;
    }

    if fallback != 0 {
        // SAFETY: `ctx` is live and `data`/`datalen` are the caller's buffer and its length.
        return unsafe {
            EVP_PKEY_CTX_ctrl(ctx, -1, op, ctrl, datalen, data.cast_mut().cast::<c_void>())
        };
    }

    if datalen < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1048) };
        return 0;
    }
    if datalen == 0 {
        return 1;
    }

    /* An older provider that cannot be read is sent the value through `set1` instead. */
    // SAFETY: `ctx` is live; the list is the provider's own static table or NULL.
    let gettables = unsafe { EVP_PKEY_CTX_gettable_params(ctx) };
    // SAFETY: `gettables` is NULL or terminated, and `param` is NUL-terminated.
    if gettables.is_null() || unsafe { OSSL_PARAM_locate_const(gettables, param) }.is_null() {
        // SAFETY: `ctx` and the caller's buffer are as this function's contract states.
        return unsafe {
            evp_pkey_ctx_set1_octet_string(ctx, fallback, param, op, ctrl, data, datalen)
        };
    }

    /* Ask for the current length only: a NULL `data` with `data_size` 0 does that. */
    let mut os_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: a NULL buffer with size 0 is the "how large is it" form of the constructor.
    unsafe {
        os_params[0] = OSSL_PARAM_construct_octet_string(param, ptr::null_mut(), 0);
    }

    // SAFETY: `ctx` is live and `os_params` is this frame's terminated array.
    if unsafe { EVP_PKEY_CTX_get_params(ctx, os_params.as_mut_ptr()) } == 0 {
        return 0;
    }

    /* This should not happen, but check to be sure. */
    if os_params[0].return_size == OSSL_PARAM_UNMODIFIED {
        return 0;
    }

    let info_alloc = os_params[0].return_size + datalen as usize;
    if info_alloc == 0 {
        return 0;
    }
    /* The allocation size is the sum of two non-negative values and the guard above keeps it
     * non-zero; `CRYPTO_zalloc` is this crate's own allocator and is not `unsafe`. */
    let info = CRYPTO_zalloc(info_alloc, FILE, LINE_ZALLOC_XLAT_BN_BUF).cast::<u8>();
    if info.is_null() {
        return 0;
    }
    let info_len = os_params[0].return_size;

    // SAFETY: `info` is `info_alloc` writable bytes, which the parameter records.
    unsafe {
        os_params[0] = OSSL_PARAM_construct_octet_string(param, info.cast(), info_alloc);
    }

    /* If there is data, go get it. */
    if info_len > 0 {
        // SAFETY: `ctx` is live and `os_params` is this frame's terminated array.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, os_params.as_mut_ptr()) } == 0 {
            // SAFETY: `info` is this call's own `info_alloc`-byte block.
            unsafe { CRYPTO_clear_free(info.cast(), info_alloc, FILE, LINE_FREE_XLAT_ADD1) };
            return ret;
        }
    }

    // SAFETY: `info` is `info_alloc` writable bytes, `info_len + datalen <= info_alloc`, and
    // `datalen` bytes are readable at `data`.
    unsafe {
        ptr::copy_nonoverlapping(data, info.add(info_len), datalen as usize);
    }

    // SAFETY: `ctx` is live and `os_params` is this frame's terminated array.
    ret = unsafe { EVP_PKEY_CTX_set_params(ctx, os_params.as_ptr()) };

    // SAFETY: `info` is this call's own `info_alloc`-byte block; the clearing is what the authority's
    // `OPENSSL_clear_free` is for.
    unsafe { CRYPTO_clear_free(info.cast(), info_alloc, FILE, LINE_FREE_XLAT_ADD1) };
    ret
}

/// `int EVP_PKEY_CTX_set1_tls1_prf_secret(EVP_PKEY_CTX *ctx, const unsigned char *sec, int seclen)`
/// — `crypto/evp/pmeth_lib.c:1096`.
///
/// # Safety
/// `ctx` NULL or live; `sec` NULL or `seclen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_tls1_prf_secret(
    ctx: *mut EvpPkeyCtx,
    sec: *const u8,
    seclen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `sec` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_SECRET,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_SECRET,
            sec,
            seclen,
        )
    }
}

/// `int EVP_PKEY_CTX_add1_tls1_prf_seed(EVP_PKEY_CTX *ctx, const unsigned char *seed, int seedlen)`
/// — `crypto/evp/pmeth_lib.c:1106`.
///
/// # Safety
/// `ctx` NULL or live; `seed` NULL or `seedlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_add1_tls1_prf_seed(
    ctx: *mut EvpPkeyCtx,
    seed: *const u8,
    seedlen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `seed` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_SEED,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_TLS_SEED,
            seed,
            seedlen,
        )
    }
}

/// `int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)` —
/// `crypto/evp/pmeth_lib.c:1116`.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut EvpPkeyCtx, md: *const EvpMd) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `md` are as the contract states.
    unsafe {
        evp_pkey_ctx_set_md(
            ctx,
            md,
            fallback,
            OSSL_KDF_PARAM_DIGEST,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_HKDF_MD,
        )
    }
}

/// `int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *ctx, const unsigned char *salt, int saltlen)` —
/// `crypto/evp/pmeth_lib.c:1123`.
///
/// # Safety
/// `ctx` NULL or live; `salt` NULL or `saltlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_salt(
    ctx: *mut EvpPkeyCtx,
    salt: *const u8,
    saltlen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `salt` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_SALT,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_HKDF_SALT,
            salt,
            saltlen,
        )
    }
}

/// `int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *ctx, const unsigned char *key, int keylen)` —
/// `crypto/evp/pmeth_lib.c:1133`.
///
/// # Safety
/// `ctx` NULL or live; `key` NULL or `keylen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_key(
    ctx: *mut EvpPkeyCtx,
    key: *const u8,
    keylen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `key` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_KEY,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_HKDF_KEY,
            key,
            keylen,
        )
    }
}

/// `int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *ctx, const unsigned char *info, int infolen)` —
/// `crypto/evp/pmeth_lib.c:1143`.
///
/// The **only** caller of `evp_pkey_ctx_add1_octet_string` in the authority's `pmeth_lib.c` that
/// really appends: the TLS1-PRF seed uses the `set1` body despite its `add1` name, and the authority
/// copies that discrepancy rather than hiding it. Reproduced here for the same reason.
///
/// # Safety
/// `ctx` NULL or live; `info` NULL or `infolen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_add1_hkdf_info(
    ctx: *mut EvpPkeyCtx,
    info: *const u8,
    infolen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `info` are as the contract states.
    unsafe {
        evp_pkey_ctx_add1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_INFO,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_HKDF_INFO,
            info,
            infolen,
        )
    }
}

/// `int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode)` — `crypto/evp/pmeth_lib.c:1153`.
///
/// The one wrapper here whose guard is the **family test** rather than an operation bit, so a
/// signature context is refused as well as an unset one. Its legacy road is `_ctrl` rather than
/// `_ctrl_uint64`, and it passes `mode` as `p1` with a NULL `p2` — which is exactly what
/// `fix_hkdf_mode`'s table row reads. A negative mode is refused *after* the fallback test, so the
/// legacy road sees it and the provider road does not.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_mode(ctx: *mut EvpPkeyCtx, mode: c_int) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1158) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).is_derive_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1158) };
        /* Uses the same return values as `EVP_PKEY_CTX_ctrl`. */
        return -2;
    }

    /* SAFETY: `ctx` is live; `mode` travels as the ctrl's `p1`. */
    if unsafe { (*ctx).op_kex_algctx }.is_null() {
        // SAFETY: `ctx` is live and `mode` is the caller's value.
        return unsafe {
            EVP_PKEY_CTX_ctrl(
                ctx,
                -1,
                EVP_PKEY_OP_DERIVE,
                EVP_PKEY_CTRL_HKDF_MODE,
                mode,
                ptr::null_mut(),
            )
        };
    }

    if mode < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1170) };
        return 0;
    }

    let mut mode = mode;
    let mut int_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `mode` is this frame's own live value and the parameter points at it.
    unsafe {
        int_params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, ptr::addr_of_mut!(mode));
    }

    // SAFETY: `ctx` is live and `int_params` is this frame's terminated array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, int_params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX *ctx, const char *pass, int passlen)` —
/// `crypto/evp/pmeth_lib.c:1180`.
///
/// The one `set1` wrapper whose value is a `char *` rather than `unsigned char *`, which is the
/// authority's spelling and not a difference in the bytes.
///
/// # Safety
/// `ctx` NULL or live; `pass` NULL or `passlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_pbe_pass(
    ctx: *mut EvpPkeyCtx,
    pass: *const c_char,
    passlen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `pass` are as the contract states; the cast only drops `signedness`, which
    // the parameter's `data` does not carry.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_PASSWORD,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_PASS,
            pass.cast::<u8>(),
            passlen,
        )
    }
}

/// `int EVP_PKEY_CTX_set1_scrypt_salt(EVP_PKEY_CTX *ctx, const unsigned char *salt, int saltlen)` —
/// `crypto/evp/pmeth_lib.c:1190`.
///
/// The **same parameter key** as `EVP_PKEY_CTX_set1_hkdf_salt` and a different ctrl, which is not
/// redundant: the ctrl numbers differ so that the legacy road can tell the two KDFs' salts apart,
/// while the parameter road cannot and does not need to.
///
/// # Safety
/// `ctx` NULL or live; `salt` NULL or `saltlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_scrypt_salt(
    ctx: *mut EvpPkeyCtx,
    salt: *const u8,
    saltlen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_kex_algctx }.is_null())
    };
    // SAFETY: `ctx` and `salt` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_KDF_PARAM_SALT,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_SCRYPT_SALT,
            salt,
            saltlen,
        )
    }
}

/// `static int evp_pkey_ctx_set_uint64(EVP_PKEY_CTX *ctx, const char *param, int op, int ctrl,
/// uint64_t val)` — `crypto/evp/pmeth_lib.c:1200`.
///
/// The shared body of the four Scrypt wrappers. Its legacy road is `_ctrl_uint64`, not `_ctrl`: the
/// value is a `uint64_t` and cannot travel in `p1`, so it goes as the address of the parameter in
/// `p2` and the ctrl's `p1` is 0 — which is why the table's `SCRYPT_*` rows are
/// `UNSIGNED_INTEGER` with no fixer and `default_fixup_args` treats a non-NULL `p2` as a BIGNUM. The
/// `val` declare mutable here exists for the same reason: the parameter needs its address.
///
/// # Safety
/// `ctx` NULL or live; `param` NUL-terminated.
unsafe extern "C" fn evp_pkey_ctx_set_uint64(
    ctx: *mut EvpPkeyCtx,
    param: *const c_char,
    op: c_int,
    ctrl: c_int,
    val: u64,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1206) };
        return -2;
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).is_derive_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1206) };
        return -2;
    }

    /* SAFETY: `ctx` is live. */
    if unsafe { (*ctx).op_kex_algctx }.is_null() {
        // SAFETY: `ctx` is live and `val` is the caller's value.
        return unsafe { EVP_PKEY_CTX_ctrl_uint64(ctx, -1, op, ctrl, val) };
    }

    let mut val = val;
    let mut uint64_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `val` is this frame's own live value and the parameter points at it.
    unsafe {
        uint64_params[0] = OSSL_PARAM_construct_uint64(param, ptr::addr_of_mut!(val));
    }

    // SAFETY: `ctx` is live and `uint64_params` is this frame's terminated array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, uint64_params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *ctx, uint64_t n)` —
/// `crypto/evp/pmeth_lib.c:1222`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_N(ctx: *mut EvpPkeyCtx, n: u64) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    unsafe {
        evp_pkey_ctx_set_uint64(
            ctx,
            OSSL_KDF_PARAM_SCRYPT_N,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_SCRYPT_N,
            n,
        )
    }
}

/// `int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *ctx, uint64_t r)` —
/// `crypto/evp/pmeth_lib.c:1229`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_r(ctx: *mut EvpPkeyCtx, r: u64) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    unsafe {
        evp_pkey_ctx_set_uint64(
            ctx,
            OSSL_KDF_PARAM_SCRYPT_R,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_SCRYPT_R,
            r,
        )
    }
}

/// `int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *ctx, uint64_t p)` —
/// `crypto/evp/pmeth_lib.c:1236`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_p(ctx: *mut EvpPkeyCtx, p: u64) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    unsafe {
        evp_pkey_ctx_set_uint64(
            ctx,
            OSSL_KDF_PARAM_SCRYPT_P,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_SCRYPT_P,
            p,
        )
    }
}

/// `int EVP_PKEY_CTX_set_scrypt_maxmem_bytes(EVP_PKEY_CTX *ctx, uint64_t maxmem_bytes)` —
/// `crypto/evp/pmeth_lib.c:1243`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_maxmem_bytes(
    ctx: *mut EvpPkeyCtx,
    maxmem_bytes: u64,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    unsafe {
        evp_pkey_ctx_set_uint64(
            ctx,
            OSSL_KDF_PARAM_SCRYPT_MAXMEM,
            EVP_PKEY_OP_DERIVE,
            EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES,
            maxmem_bytes,
        )
    }
}

/// `int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key, int keylen)` —
/// `crypto/evp/pmeth_lib.c:1252`.
///
/// The one `set1` wrapper whose fallback test reads the **key generation** union member and whose
/// operation is `KEYGEN`, because the value it sets is a MAC key for a key-generation operation.
///
/// # Safety
/// `ctx` NULL or live; `key` NULL or `keylen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_mac_key(
    ctx: *mut EvpPkeyCtx,
    key: *const u8,
    keylen: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    let fallback = if ctx.is_null() {
        0
    } else {
        // SAFETY: `ctx` is live.
        c_int::from(unsafe { (*ctx).op_keymgmt_genctx }.is_null())
    };
    // SAFETY: `ctx` and `key` are as the contract states.
    unsafe {
        evp_pkey_ctx_set1_octet_string(
            ctx,
            fallback,
            OSSL_PKEY_PARAM_PRIV_KEY,
            EVP_PKEY_OP_KEYGEN,
            EVP_PKEY_CTRL_SET_MAC_KEY,
            key,
            keylen,
        )
    }
}

/// `int EVP_PKEY_CTX_set_kem_op(EVP_PKEY_CTX *ctx, const char *op)` —
/// `crypto/evp/pmeth_lib.c:1262`.
///
/// The only one of these that has no ctrl road at all, and that is why its two tests come first and
/// its parameter is built last: there is no `EVP_PKEY_CTRL_KEM_OP`, so a KEM operation's name has
/// only the `OSSL_PARAM` road and there is nothing to fall back to. The two refusals are different
/// values — `EVP_R_INVALID_VALUE` with `0` for a NULL argument and `EVP_R_COMMAND_NOT_SUPPORTED` with
/// `-2` for a context that is not a KEM operation.
///
/// # Safety
/// `ctx` NULL or live; `op` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_kem_op(ctx: *mut EvpPkeyCtx, op: *const c_char) -> c_int {
    if ctx.is_null() || op.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1267) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).is_kem_op() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1271) };
        return -2;
    }

    let mut params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
    // SAFETY: `op` is NUL-terminated; the cast only discards `const`.
    unsafe {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION, op.cast_mut(), 0);
    }

    // SAFETY: `ctx` is live and `params` is this frame's terminated array.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len)` —
/// `crypto/evp/pmeth_lib.c:1280`.
///
/// The three DistID exports, and all three are one `EVP_PKEY_CTX_ctrl` call with `keytype` and
/// `optype` both `-1` — "any key, any operation", because a distinguishing identifier may be set
/// before the operation exists and is *cached* in that case (see this module's note on the three
/// cached-data functions). `get1_id` and `get1_id_len` differ only in the ctrl number, and the
/// difference is real: the buffer and the length have separate ctrls because the caller may ask for
/// either without the other.
///
/// # Safety
/// `ctx` NULL or live; `id` NULL or a live identifier of `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_id(
    ctx: *mut EvpPkeyCtx,
    id: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `ctx` is live or NULL and `id` is the caller's buffer.
    unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_SET1_ID, len, id.cast_mut()) }
}

/// `int EVP_PKEY_CTX_get1_id(EVP_PKEY_CTX *ctx, void *id)` — `crypto/evp/pmeth_lib.c:1286`.
///
/// # Safety
/// `ctx` NULL or live; `id` NULL or writable for the length `get1_id_len` reports.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get1_id(ctx: *mut EvpPkeyCtx, id: *mut c_void) -> c_int {
    // SAFETY: `ctx` is live or NULL.
    unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET1_ID, 0, id) }
}

/// `int EVP_PKEY_CTX_get1_id_len(EVP_PKEY_CTX *ctx, size_t *id_len)` —
/// `crypto/evp/pmeth_lib.c:1291`.
///
/// # Safety
/// `ctx` NULL or live; `id_len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get1_id_len(
    ctx: *mut EvpPkeyCtx,
    id_len: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live or NULL and `id_len` is the caller's writable `size_t`.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            -1,
            -1,
            EVP_PKEY_CTRL_GET1_ID_LEN,
            0,
            id_len.cast::<c_void>(),
        )
    }
}

/// `static int evp_pkey_ctx_ctrl_int(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1,
/// void *p2)` — `crypto/evp/pmeth_lib.c:1297`.
///
/// The operation gate in front of the ctrl engine, and the first of the two `pmeth`-dependent
/// functions in this block. Two different refusals live here and they are different values: an
/// operation that is unset or of the wrong family is `EVP_R_NO_OPERATION_SET`/`EVP_R_INVALID_OPERATION`
/// with `-1`, while a context with no method to call is `EVP_R_COMMAND_NOT_SUPPORTED` with `-2` — the
/// value a caller of `EVP_PKEY_CTX_ctrl` is documented to treat as unsupported.
///
/// **The `pmeth->digest_custom` escape is reproduced as its `NULL` case.** The authority relaxes both
/// operation tests when the context's method implements `digest_custom`, because such a method may be
/// called before the operation is initialized. The crate's `EvpPkeyCtx` has no `pmeth`, so the test
/// `ctx->pmeth == NULL || ctx->pmeth->digest_custom == NULL` is true unconditionally and the two
/// tests always run — which is the authority's behaviour for every context this crate can build.
/// The state switch's PROVIDER arm calls the ctrl engine; the LEGACY and UNKNOWN arms cannot reach a
/// method here and so always answer `-2`, which is what the authority answers for a context with no
/// `pmeth` or a `pmeth` with no `ctrl`.
///
/// # Safety
/// `ctx` live; `p2` NULL or valid for the ctrl the row describes.
unsafe extern "C" fn evp_pkey_ctx_ctrl_int(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live per the contract; the operation is read once and both tests below use
    // the same value the authority reads twice.
    let operation = unsafe { (*ctx).operation };
    if operation == EVP_PKEY_OP_UNDEFINED {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1309) };
        return -1;
    }

    if optype != -1 && operation & optype == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1314) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    let state = unsafe { evp_pkey_ctx_state(ctx) };
    if state == EVP_PKEY_STATE_PROVIDER {
        // SAFETY: `ctx` is live and `p2` is as the contract states.
        return unsafe { evp_pkey_ctx_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2) };
    }

    /* `ctx->pmeth == NULL || ctx->pmeth->ctrl == NULL`; see this function's note. */
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_LIB_1325) };
    -2
}

/// `int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2)` —
/// `crypto/evp/pmeth_lib.c:1340`.
///
/// The public ctrl door, and it is a **three-step** function rather than one. First the cached-data
/// call, which is what lets `EVP_PKEY_CTRL_SET1_ID` be set before the operation exists: it answers
/// `-2` for every *other* command and that is not an error, so the error mark is popped and the
/// command is dispatched normally. Second, if a value was cached and the operation is still unset,
/// the function returns that value — the caller's ctrl has been answered by being remembered. Third,
/// and only then, the real dispatch. The mark is what makes the first step's refusal invisible in the
/// error queue, which is the whole point of `ERR_set_mark`/`ERR_pop_to_mark` here.
///
/// The `ret < 1` test is not `ret == 0`: the cache answers 1, 0 and -2, and 0 (a failed allocation
/// inside the store) must be handed back rather than dispatched.
///
/// # Safety
/// `ctx` NULL or live; `p2` NULL or valid for the ctrl the row describes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1346) };
        return -2;
    }

    /* If unsupported, the mark is popped so the caller does not see it as an error. */
    ERR_set_mark();
    // SAFETY: `ctx` is live; `p2` travels as the cached value and is `p1` bytes long for the one
    // command that caches.
    let mut ret = unsafe {
        evp_pkey_ctx_store_cached_data(ctx, keytype, optype, cmd, ptr::null(), p2, p1 as usize)
    };
    if ret == -2 {
        ERR_pop_to_mark();
    } else {
        ERR_clear_last_mark();
        /* If there was an error, there was an error; if the operation is not initialized yet, the
         * saved values will be used when it is. */
        // SAFETY: `ctx` is live.
        if ret < 1 || unsafe { (*ctx).operation } == EVP_PKEY_OP_UNDEFINED {
            return ret;
        }
    }

    // SAFETY: `ctx` is live and `p2` is as the contract states.
    ret = unsafe { evp_pkey_ctx_ctrl_int(ctx, keytype, optype, cmd, p1, p2) };
    ret
}

/// `int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd,
/// uint64_t value)` — `crypto/evp/pmeth_lib.c:1368`.
///
/// A ctrl whose one value is a `uint64_t`: it travels as the address of a local, because no ctrl in
/// the authority has a 64-bit `p1`. Reproduced with the local, which is why the value's lifetime is
/// documented at the call.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl_uint64(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    value: u64,
) -> c_int {
    let mut value = value;
    // SAFETY: `ctx` is live or NULL; `value` is this frame's own live local, so the pointer stays
    // valid for the whole call.
    unsafe {
        EVP_PKEY_CTX_ctrl(
            ctx,
            keytype,
            optype,
            cmd,
            0,
            ptr::addr_of_mut!(value).cast::<c_void>(),
        )
    }
}

/// `static int evp_pkey_ctx_ctrl_str_int(EVP_PKEY_CTX *ctx, const char *name, const char *value)` —
/// `crypto/evp/pmeth_lib.c:1374`.
///
/// The string door's dispatch, and it carries the one special case of the whole file: the name
/// `"digest"` on a legacy context is routed to `EVP_PKEY_CTX_md` — which resolves the name to an
/// `EVP_MD *` and calls the ctrl — instead of to the method's `ctrl_str`, because no legacy method's
/// `ctrl_str` handles `"digest"` and every one of them has the `EVP_PKEY_CTRL_MD` ctrl. The two
/// operations in its optype span both the signature and the crypt families, so the same `"digest"`
/// works for an RSA signing context and an RSA ciphering one.
///
/// # Safety
/// `name` and `value` NUL-terminated; `ctx` NULL or live.
pub(crate) unsafe extern "C" fn evp_pkey_ctx_ctrl_str_int(
    ctx: *mut EvpPkeyCtx,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1380) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    let state = unsafe { evp_pkey_ctx_state(ctx) };
    if state == EVP_PKEY_STATE_PROVIDER {
        // SAFETY: `ctx` is live and both strings are the caller's.
        return unsafe { evp_pkey_ctx_ctrl_str_to_param(ctx, name, value) };
    }

    /* `ctx->pmeth == NULL || ctx->pmeth->ctrl_str == NULL`; see `evp_pkey_ctx_ctrl_int`'s note. */
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PMETH_LIB_1390) };
    -2
}

/// `int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *name, const char *value)` —
/// `crypto/evp/pmeth_lib.c:1405`.
///
/// `EVP_PKEY_CTX_ctrl`'s string-shaped twin, with the same three steps and the same mark dance. Two
/// things differ and both are visible. The cache call passes `name` — which is what `decode_cmd`
/// reads to recognise `"distid"` and `"hexdistid"` — and the cached value's length is
/// `strlen(value) + 1`, so the string's **NUL is stored with it**; that is deliberate, because the
/// replay path hands the stored bytes back as a `const void *` and the identifier's length is the
/// caller's, not the string's. And the dispatch passes `-1` for both `keytype` and `optype` to its
/// own helper, which takes neither.
///
/// # Safety
/// `ctx` NULL or live; `name` and `value` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl_str(
    ctx: *mut EvpPkeyCtx,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    /* If unsupported, the mark is popped so the caller does not see it as an error. */
    ERR_set_mark();
    // SAFETY: `ctx` is live or NULL; `name`/`value` are NUL-terminated and the cached length counts
    // the NUL.
    let mut ret = unsafe {
        evp_pkey_ctx_store_cached_data(
            ctx,
            -1,
            -1,
            -1,
            name,
            value.cast::<c_void>(),
            strlen(value) + 1,
        )
    };
    if ret == -2 {
        ERR_pop_to_mark();
    } else {
        ERR_clear_last_mark();
        /* SAFETY: `ctx` is live when the cache answered positively, which is the only way this arm
         * is reached with a non-NULL caller. */
        if ret < 1 || unsafe { (*ctx).operation } == EVP_PKEY_OP_UNDEFINED {
            return ret;
        }
    }

    // SAFETY: `ctx` and the two strings are as the contract states.
    ret = unsafe { evp_pkey_ctx_ctrl_str_int(ctx, name, value) };
    ret
}

/// `static int decode_cmd(int cmd, const char *name)` — `crypto/evp/pmeth_lib.c:1440`.
///
/// The one place a ctrl **string** becomes a ctrl **number**, and it knows exactly two names:
/// `"distid"` and `"hexdistid"`, both of which mean `EVP_PKEY_CTRL_SET1_ID`. `ossl_assert` is live
/// (D167), so a NULL `name` with `cmd == -1` — which is how `EVP_PKEY_CTX_ctrl` calls it — leaves the
/// cmd at `-1` rather than faulting, and `-1` then reaches the caller's switch as the default case.
/// Everything else is returned unchanged, so a caller that already has a number is not second-guessed.
///
/// # Safety
/// `name` NULL or NUL-terminated.
unsafe extern "C" fn decode_cmd(cmd: c_int, name: *const c_char) -> c_int {
    if cmd == -1 && !name.is_null() {
        /* SAFETY: `name` is NUL-terminated and both literals are static. */
        let is_distid = unsafe { strcmp(name, c"distid".as_ptr()) } == 0;
        // SAFETY: as above.
        let is_hexdistid = unsafe { strcmp(name, c"hexdistid".as_ptr()) } == 0;
        if is_distid || is_hexdistid {
            return EVP_PKEY_CTRL_SET1_ID;
        }
    }
    cmd
}

/// `static int evp_pkey_ctx_store_cached_data(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd,
/// const char *name, const void *data, size_t data_len)` — `crypto/evp/pmeth_lib.c:1446`.
///
/// The cached-data store, and the reason `EVP_PKEY_CTRL_SET1_ID` is special: a DistID may be set
/// before the operation exists, so it is *remembered* and replayed by the operation's init. Every
/// other command is refused here with `-2` — which its two callers treat as "not mine, carry on" — so
/// the function is really a filter with one arm.
///
/// **Two arms of the authority's version are unreachable in this crate and are written as their
/// `pmeth == NULL` result.** The `keytype != -1` test has a provider arm and a legacy arm; the
/// legacy arm's `EVP_PKEY_type(ctx->pmeth->pkey_id) != EVP_PKEY_type(keytype)` needs a `pmeth`, and
/// the test above it is `if (ctx->pmeth == NULL)`, which is always true here. So a caller that names
/// a key type on a legacy context gets `EVP_R_COMMAND_NOT_SUPPORTED` and `-2`, which is the
/// authority's own answer for a context with no method.
///
/// The store itself frees what it is about to replace **before** testing the new value for NULL, so a
/// failed allocation leaves a cleared cache rather than a stale one — which is why the crate's
/// `evp_pkey_ctx_free_cached_data` takes no `cmd`: `decode_cmd` cannot produce anything but
/// `SET1_ID` at this point, as the crate's version notes.
///
/// # Safety
/// `ctx` live; `name` NULL or NUL-terminated; `data` NULL or `data_len` readable bytes.
unsafe extern "C" fn evp_pkey_ctx_store_cached_data(
    ctx: *mut EvpPkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    name: *const c_char,
    data: *const c_void,
    data_len: usize,
) -> c_int {
    // SAFETY: `name` is NULL or NUL-terminated.
    let cmd = unsafe { decode_cmd(cmd, name) };

    if cmd != EVP_PKEY_CTRL_SET1_ID {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1460) };
        return -2;
    }

    if keytype != -1 {
        // SAFETY: `ctx` is live.
        let state = unsafe { evp_pkey_ctx_state(ctx) };
        if state == EVP_PKEY_STATE_PROVIDER {
            // SAFETY: `ctx` is live.
            let keymgmt = unsafe { (*ctx).keymgmt };
            if keymgmt.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PMETH_LIB_1468) };
                return -2;
            }
            // SAFETY: `keymgmt` is live and the name is a static from `pkey.rs`.
            if unsafe { EVP_KEYMGMT_is_a(keymgmt, evp_pkey_type2name(keytype)) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PMETH_LIB_1473) };
                return -1;
            }
        } else {
            /* `ctx->pmeth == NULL`; see this function's note. */
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PMETH_LIB_1480) };
            return -2;
        }
    }

    // SAFETY: `ctx` is live per the contract; the operation is read once, as `evp_pkey_ctx_ctrl_int`
    // does.
    let operation = unsafe { (*ctx).operation };
    if optype != -1 && operation & optype == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1491) };
        return -1;
    }

    /* One command, and the free is unconditional on both pointers. */
    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_cached_data(ctx) };

    if !name.is_null() {
        // SAFETY: `name` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(name, FILE, LINE_STRDUP_DIST_ID) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).cached_parameters.dist_id_name = dup };
        if dup.is_null() {
            return 0;
        }
    }

    if data_len > 0 {
        // SAFETY: `data` is NULL or `data_len` readable bytes, and the duplicate is released by the
        // next store or by the context's free.
        let mdup = unsafe { CRYPTO_memdup(data, data_len, FILE, LINE_MEMDUP_DIST_ID) }.cast();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).cached_parameters.dist_id = mdup };
        if mdup.is_null() {
            return 0;
        }
    }

    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).cached_parameters.dist_id_set = 1;
        (*ctx).cached_parameters.dist_id_len = data_len;
    }
    1
}

/// `int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str)` —
/// `crypto/evp/pmeth_lib.c:1588`.
///
/// **This one cannot be finished, and the reason is not a missing helper.** The authority's last line
/// is `ctx->pmeth->ctrl(ctx, cmd, (int)len, (void *)str)` — a *direct* call on the method's ctrl
/// callback, with **no NULL test on `ctx->pmeth`**. The crate's `EvpPkeyCtx` has no `pmeth` at all (it
/// is 7.4l's registry, and D184 records why the context does not attach one), so there is no callback
/// to call. Every context this crate can build is in the state the authority would throw the fault
/// on, so the honest answer is the one the authority reserves for "the ctrl was not reached": its
/// `-1`. The `strlen` and `INT_MAX` tests before it are transcribed whole, so the function's own
/// logic is present and only the callback is absent.
///
/// # Safety
/// `ctx` live; `str` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_str2ctrl(
    ctx: *mut EvpPkeyCtx,
    _cmd: c_int,
    str: *const c_char,
) -> c_int {
    // SAFETY: `str` is NUL-terminated per the contract.
    let len = unsafe { strlen(str) };
    if len > c_int::MAX as usize {
        return -1;
    }
    /* `ctx->pmeth->ctrl(...)` is absent; see this function's note. */
    let _ = ctx;
    -1
}

/// `int EVP_PKEY_CTX_hex2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *hex)` —
/// `crypto/evp/pmeth_lib.c:1598`.
///
/// `str2ctrl`'s hex sibling, and the same absence: the decode is transcribed and the callback call is
/// not. Its `rv` initialises to `-1` and is replaced only by the callback's answer, so `-1` is again
/// the value that means "the callback was not reached" — and it is answered both for a hex string
/// that decodes to more than `INT_MAX` bytes and for every string here.
///
/// # Safety
/// `ctx` live; `hex` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_hex2ctrl(
    ctx: *mut EvpPkeyCtx,
    _cmd: c_int,
    hex: *const c_char,
) -> c_int {
    let mut binlen: c_long = 0;
    // SAFETY: `hex` is NUL-terminated per the contract and `binlen` is this frame's own local.
    let bin = unsafe { OPENSSL_hexstr2buf(hex, ptr::addr_of_mut!(binlen)) };
    if bin.is_null() {
        return 0;
    }
    /* `ctx->pmeth->ctrl(...)` is absent; see `EVP_PKEY_CTX_str2ctrl`'s note. The buffer is this
     * call's own and must be released either way. */
    // SAFETY: `bin` is the block `OPENSSL_hexstr2buf` allocated with `CRYPTO_malloc`.
    unsafe { CRYPTO_free(bin.cast(), FILE, LINE_FREE_HEXCTRL) };
    let _ = ctx;
    -1
}

/// `int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md)` —
/// `crypto/evp/pmeth_lib.c:1614`.
///
/// The one helper that is *public* and a wrapper rather than an implementation: it turns a digest
/// name into an `EVP_MD *` and calls `EVP_PKEY_CTX_ctrl` with `keytype` `-1`. It is exported because
/// legacy method implementations call it, and it is the function `EVP_PKEY_CTX_ctrl_str`'s `"digest"`
/// special case routes to.
///
/// Both NULL tests raise the **same** reason, `EVP_R_INVALID_DIGEST`, which is the authority's: an
/// absent name and an unresolvable one are one failure to a caller. They are two statements here
/// rather than one `||` for the reason every other site in this block is — each raise needs its
/// `// SAFETY:` comment directly above it — and the two statements raise the same site.
///
/// The lookup is `EVP_get_digestbyname`, the **global** one, not the library-context form — so a
/// caller using it off a non-default `OSSL_LIB_CTX` gets the default context's digest. That is the
/// authority's code and it is reproduced; the same name could not be resolved by
/// `EVP_PKEY_CTX_get_signature_md`, which uses `_ex`.
///
/// # Safety
/// `ctx` NULL or live; `md` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_md(
    ctx: *mut EvpPkeyCtx,
    optype: c_int,
    cmd: c_int,
    md: *const c_char,
) -> c_int {
    if md.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1619) };
        return 0;
    }
    // SAFETY: `md` is NUL-terminated.
    let m = unsafe { EVP_get_digestbyname(md) };
    if m.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PMETH_LIB_1619) };
        return 0;
    }
    // SAFETY: `ctx` is live or NULL and `m` is a live digest method.
    unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, 0, m.cast_mut().cast::<c_void>()) }
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

    /// The C string a table cell points at, as bytes. Content rather than address, because two
    /// `c"literal"`s with the same bytes are not guaranteed to be one object.
    fn cell(p: *const c_char) -> Vec<u8> {
        assert!(
            !p.is_null(),
            "this cell is a string in every row that reads it"
        );
        // SAFETY: every string cell in the two tables is a `c"..."` literal, and NULL was refused.
        unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
    }

    /// The two tables' **shape**, which is what a transcription of 127 positional initialisers can
    /// get wrong without any single row looking wrong. Four facts, each one named in the section
    /// comment above the tables and each one checkable only by counting:
    ///
    ///   * the row counts the authority has;
    ///   * every pkey row's `ctrl_num` is 0 and every row carries a fixer, because that table has no
    ///     ctrl call to make and no `default_fixup_args` to fall back to;
    ///   * `ctrl_num == -1` is **exactly** the four ECX rows, all of them group-name rows;
    ///   * exactly two rows are hex-only, and they are the two the authority's comments name.
    #[test]
    fn the_tables_are_the_authority_rows_and_only_its_shapes() {
        assert_eq!(EVP_PKEY_CTX_TRANSLATIONS.len(), 86);
        assert_eq!(EVP_PKEY_TRANSLATIONS.len(), 41);

        assert!(
            EVP_PKEY_TRANSLATIONS.iter().all(|r| r.ctrl_num == 0),
            "the payload table has no ctrls"
        );
        assert!(
            EVP_PKEY_TRANSLATIONS.iter().all(|r| r.fixup_args.is_some()),
            "every payload row's work is its fixer's"
        );

        let minus_one: Vec<&XlatEntry> = EVP_PKEY_CTX_TRANSLATIONS
            .iter()
            .filter(|r| r.ctrl_num == -1)
            .collect();
        assert_eq!(minus_one.len(), 4, "four ECX rows");
        for r in &minus_one {
            assert_eq!(cell(r.param_key), b"group".to_vec());
            assert!(r.keytype1 == EVP_PKEY_X25519 || r.keytype1 == EVP_PKEY_X448);
        }

        let hex_only: Vec<&XlatEntry> = EVP_PKEY_CTX_TRANSLATIONS
            .iter()
            .filter(|r| r.ctrl_str.is_null() && !r.ctrl_hexstr.is_null())
            .collect();
        assert_eq!(hex_only.len(), 2);
        assert_eq!(cell(hex_only[0].ctrl_hexstr), b"rsa_oaep_label".to_vec());
        assert_eq!(
            cell(hex_only[1].ctrl_hexstr),
            b"rsa_pkcs1_implicit_rejection".to_vec()
        );

        /* Five rows leave the action type to their fixer, and they name the three ctrls whose
         * direction depends on `p1` or `p2`. It is five and not three because the SM2 block above
         * repeats the whole of the EC block, so the two EC ctrls appear twice. */
        let none: Vec<&XlatEntry> = EVP_PKEY_CTX_TRANSLATIONS
            .iter()
            .filter(|r| r.action_type == XlatAction::None_)
            .collect();
        assert_eq!(none.len(), 5);
        let mut ctrls: Vec<c_int> = none.iter().map(|r| r.ctrl_num).collect();
        ctrls.sort_unstable();
        let mut want = [
            EVP_PKEY_CTRL_DH_KDF_TYPE,
            EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
            EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
            EVP_PKEY_CTRL_EC_KDF_TYPE,
            EVP_PKEY_CTRL_EC_KDF_TYPE,
        ];
        want.sort_unstable();
        assert_eq!(ctrls, want.to_vec());
    }

    /// The lookup by ctrl number, which is the path every `EVP_PKEY_CTX_ctrl` on a provider context
    /// takes: the row the number names, and **NULL** rather than a near miss for a number no row
    /// carries.
    #[test]
    fn a_ctrl_number_finds_its_row_and_an_unknown_one_does_not() {
        let mut tmpl = XlatEntry::ZEROED;
        tmpl.action_type = XlatAction::Set;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_TYPE_SIG;
        tmpl.ctrl_num = EVP_PKEY_CTRL_SET1_ID;

        // SAFETY: `tmpl` is this frame's own live entry and the table is a static of 86 rows.
        let found = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };
        assert!(!found.is_null());
        // SAFETY: the lookup answers a row of the static table or NULL, and NULL was refused.
        let row = unsafe { &*found };
        assert_eq!(row.action_type, XlatAction::Set);
        assert_eq!(cell(row.param_key), b"distid".to_vec());
        assert_eq!(row.param_data_type, OSSL_PARAM_OCTET_STRING);

        /* An operation that does not intersect the row's leaves the same ctrl unmatched: the
         * `optype` test is `(tmpl.optype & item.optype) == 0`. */
        let mut tmpl = XlatEntry::ZEROED;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_DERIVE;
        tmpl.ctrl_num = EVP_PKEY_CTRL_SET1_ID;
        // SAFETY: as above.
        assert!(unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) }.is_null());

        let mut tmpl = XlatEntry::ZEROED;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_TYPE_SIG;
        tmpl.ctrl_num = 12345;
        // SAFETY: as above.
        assert!(unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) }.is_null());
    }

    /// The string door, and the **write-back that is its return channel**: `lookup_translation`
    /// rewrites the template's two ctrl-string fields to say which column matched, and
    /// `evp_pkey_ctx_ctrl_str_to_param` reads exactly that to set `ctx.ishex`. So `"distid"` must
    /// leave `ctrl_hexstr` NULL and `"hexdistid"` must leave `ctrl_str` NULL — a transcription that
    /// set both would make every `distid` value hex-decoded.
    #[test]
    fn the_distid_strings_match_their_own_columns_and_the_template_says_which() {
        let mut tmpl = XlatEntry::ZEROED;
        tmpl.action_type = XlatAction::Set;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_TYPE_SIG;
        tmpl.ctrl_str = c"distid".as_ptr();
        tmpl.ctrl_hexstr = c"distid".as_ptr();

        // SAFETY: `tmpl` is this frame's own live entry and the table is a static of 86 rows.
        let found = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };
        assert!(!found.is_null());
        assert!(!tmpl.ctrl_str.is_null(), "the plain column matched");
        assert!(tmpl.ctrl_hexstr.is_null(), "and the hex column did not");

        let mut tmpl = XlatEntry::ZEROED;
        tmpl.action_type = XlatAction::Set;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_TYPE_SIG;
        tmpl.ctrl_str = c"hexdistid".as_ptr();
        tmpl.ctrl_hexstr = c"hexdistid".as_ptr();

        // SAFETY: as above.
        let found = unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) };
        assert!(!found.is_null());
        assert!(tmpl.ctrl_str.is_null(), "the plain column did not match");
        assert!(!tmpl.ctrl_hexstr.is_null(), "the hex column did");

        /* A name no row carries is not an error: the caller passes it through as an `OSSL_PARAM`
         * key, which is what the `else { return NULL }` in the lookup is for. */
        let mut tmpl = XlatEntry::ZEROED;
        tmpl.action_type = XlatAction::Set;
        tmpl.keytype1 = -1;
        tmpl.keytype2 = -1;
        tmpl.optype = EVP_PKEY_OP_TYPE_SIG;
        tmpl.ctrl_str = c"no-such-ctrl".as_ptr();
        tmpl.ctrl_hexstr = c"no-such-ctrl".as_ptr();
        // SAFETY: as above.
        assert!(unsafe { lookup_evp_pkey_ctx_translation(ptr::addr_of_mut!(tmpl)) }.is_null());
    }
}
