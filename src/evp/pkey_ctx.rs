//! Phase 7.4 — the `EVP_PKEY_CTX` object.
//!
//! `crypto/evp/pmeth_lib.c`'s **object half**: the struct, its four constructors, its lifetime, the
//! operation-state test every operation init starts from, the cached-data trio, and the accessors.
//! What is *not* here is the `EVP_PKEY_METHOD` registry — `EVP_PKEY_meth_find`, `_new`, `_add0`,
//! `_remove`, the `get`/`set` accessors — which is 7.4l's because its lookup searches
//! `standard_methods[]`, a table whose contents are Phase 8's objects (`docs/DECISIONS.md` D163,
//! D165).
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

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::asymcipher::EvpAsymCipher;
use crate::evp::exchange::EvpKeyExch;
use crate::evp::kem::EvpKem;
use crate::evp::keymgmt::{
    evp_keymgmt_get_legacy_alg, EVP_KEYMGMT_fetch, EVP_KEYMGMT_free, EvpKeyMgmt,
};
use crate::evp::pkey::{evp_pkey_name2type, EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::evp::signature::EvpSignature;
use crate::provider::OsslProvider;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_undef, OBJ_nid2sn};

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
    pub(crate) pkey_gencb: Option<unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int>,
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
    fn is_derive_op(&self) -> bool {
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
    fn is_kem_op(&self) -> bool {
        (self.operation & EVP_PKEY_OP_TYPE_KEM) != 0
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

// SPDX-License-Identifier: Apache-2.0

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
