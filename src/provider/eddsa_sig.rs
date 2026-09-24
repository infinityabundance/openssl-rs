//! Phase 8 — `providers/implementations/signature/eddsa_sig.c`: the five `EdDSA`
//! `OSSL_OP_SIGNATURE` rows.
//!
//! The unit is the `EdDSA` face of the `ECX_KEY` objects `src/provider/ecx_kmgmt.rs` publishes
//! (D388): `PROV_EDDSA_CTX` holds a borrow of one `ECX_KEY`, the AlgorithmIdentifier the key's type
//! selects, and the RFC 8032 instance state — the five instances `Ed25519`, `Ed25519ph`,
//! `Ed25519ctx`, `Ed448` and `Ed448ph` differ only in `dom2`, the prehash flag and whether a context
//! string is required.
//!
//! ## The one prerequisite
//!
//! `eddsa_signverify_init` builds the AlgorithmIdentifier through `providers/common/der/der_ecx_key.c`'s
//! `ossl_DER_w_algorithmIdentifier_ED25519` and `_ED448`, now `src/provider/der_ecx_key.rs`. Every
//! other callee is landed: `ossl_ed25519_sign`/`_verify` (`src/ec/curve25519.rs`), `ossl_ed448_sign`/
//! `_verify` (`src/ec/curve448.rs`), `ossl_ecx_key_up_ref`/`_free` (`src/ec/ecx_key.rs`) and the
//! `EVP_MD`/`EVP_MD_CTX` layer. `providers/common/securitycheck.c` is **not** on the path: the unit
//! reaches no FIPS indicator at all on this profile, so it has no `securitycheck` caller.
//!
//! ## What is absent, and why
//!
//! `#ifdef S390X_EC_ASM` is not this profile's arm, so the four `s390x_ed*_digest*` helpers and the
//! two arms that select them are **not emitted** — including the two `PROV_R_FAILED_TO_SIGN` raises
//! that live inside those arms. The remaining `PROV_R_FAILED_TO_SIGN` raises, which follow the
//! `#endif`, are.
//!
//! ## The dispatch tables are not uniform
//!
//! `IMPL_EDDSA_DISPATCH` builds each table's common head, and each instance appends its own tail,
//! so the five tables are different sizes and two of them carry a **duplicate** `SIGN_INIT`
//! (`ed25519ph` and `ed448ph`) because their tail `#define` emits `SIGN_INIT`/`VERIFY_INIT` for the
//! `*_signverify_init` wrappers and then the variant `#define` emits them again for the
//! `*_signverify_message_init` wrappers. That is the authority's shape and it is transcribed
//! rather than tidied: a dispatch walk that took the first match and one that took the last are
//! both answered here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::curve25519::{ossl_ed25519_sign, ossl_ed25519_verify};
use crate::ec::curve448::{ossl_ed448_sign, ossl_ed448_verify};
use crate::ec::ecx_key::{
    ossl_ecx_key_free, ossl_ecx_key_up_ref, EcxKey, ECX_KEY_TYPE_ED25519, ECX_KEY_TYPE_ED448,
};
use crate::evp::digest::{
    EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_Q_digest,
};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_string, OSSL_PARAM_set_octet_string,
    OsslParam, END,
};
use crate::provider::cipher::{param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_ecx_key::{
    ossl_DER_w_algorithmIdentifier_ED25519, ossl_DER_w_algorithmIdentifier_ED448,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_strcasecmp;

/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `include/internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:449`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `ED25519_SIGSIZE` — `include/crypto/ecx.h:38`.
const ED25519_SIGSIZE: usize = 64;

/// `ED448_SIGSIZE` — `include/crypto/ecx.h:44`.
const ED448_SIGSIZE: usize = 114;

/// `EDDSA_MAX_CONTEXT_STRING_LEN` — `eddsa_sig.c.in:71`.
const EDDSA_MAX_CONTEXT_STRING_LEN: usize = 255;

/// `EDDSA_PREHASH_OUTPUT_LEN` — `eddsa_sig.c.in:72`.
const EDDSA_PREHASH_OUTPUT_LEN: usize = 64;

/// `SN_Ed25519` — the instance name the `EVP_PKEY_CTX` `instance` parameter selects.
const SN_ED25519: *const c_char = c"Ed25519".as_ptr();
/// `SN_Ed25519ph`.
const SN_ED25519PH: *const c_char = c"Ed25519ph".as_ptr();
/// `SN_Ed25519ctx`.
const SN_ED25519CTX: *const c_char = c"Ed25519ctx".as_ptr();
/// `SN_Ed448`.
const SN_ED448: *const c_char = c"Ed448".as_ptr();
/// `SN_Ed448ph`.
const SN_ED448PH: *const c_char = c"Ed448ph".as_ptr();
/// `SN_sha512` — the digest `Ed25519ph` prehashes with.
const SN_SHA512: *const c_char = c"SHA512".as_ptr();
/// `SN_shake256` — the digest `Ed448ph` prehashes with.
const SN_SHAKE256: *const c_char = c"SHAKE256".as_ptr();

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h:546`.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();
/// `OSSL_SIGNATURE_PARAM_INSTANCE` — `core_names.h:559`.
const OSSL_SIGNATURE_PARAM_INSTANCE: *const c_char = c"instance".as_ptr();
/// `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` — `core_names.h:548`.
const OSSL_SIGNATURE_PARAM_CONTEXT_STRING: *const c_char = c"context-string".as_ptr();

/// `ID_NOT_SET` — the `ID_EdDSA_INSTANCE` zero.
const ID_NOT_SET: c_int = 0;
/// `ID_Ed25519`.
const ID_ED25519: c_int = 1;
/// `ID_Ed25519ctx`.
const ID_ED25519CTX: c_int = 2;
/// `ID_Ed25519ph`.
const ID_ED25519PH: c_int = 3;
/// `ID_Ed448`.
const ID_ED448: c_int = 4;
/// `ID_Ed448ph`.
const ID_ED448PH: c_int = 5;

/// `instance_id_preset_flag`, the first `unsigned int : 1` at `eddsa_sig.c.in:171`.
const FLAG_INSTANCE_ID_PRESET: c_uint = 1;
/// `prehash_by_caller_flag`, the second.
const FLAG_PREHASH_BY_CALLER: c_uint = 2;
/// `dom2_flag`, the third.
const FLAG_DOM2: c_uint = 4;
/// `prehash_flag`, the fourth.
const FLAG_PREHASH: c_uint = 8;
/// `context_string_flag`, the fifth.
const FLAG_CONTEXT_STRING: c_uint = 16;

/// `PROV_EDDSA_CTX` — `eddsa_sig.c.in:161-185`. The five `unsigned int : 1` lanes are one packed
/// `c_uint`, as the authority packs them.
#[repr(C)]
struct ProvEddsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `ECX_KEY *key` — a borrow carrying a reference.
    key: *mut EcxKey,
    /// `unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE]`.
    aid_buf: [u8; OSSL_MAX_ALGORITHM_ID_SIZE],
    /// `size_t aid_len`.
    aid_len: usize,
    /// `int instance_id`.
    instance_id: c_int,
    /// The five one-bit lanes.
    flags: c_uint,
    /// `unsigned char context_string[EDDSA_MAX_CONTEXT_STRING_LEN]`.
    context_string: [u8; EDDSA_MAX_CONTEXT_STRING_LEN],
    /// `size_t context_string_len`.
    context_string_len: usize,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static void *eddsa_newctx(void *provctx, const char *propq_unused)` — `eddsa_sig.c.in:187-200`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn eddsa_newctx(provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<ProvEddsaCtx>(), FILE, 194).cast::<ProvEddsaCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is this call's own allocation.
    unsafe { (*ctx).libctx = prov_libctx_of(provctx) };

    ctx.cast()
}

/// `static int eddsa_setup_instance(...)` — `eddsa_sig.c.in:202-255`, without the
/// `#ifndef FIPS_MODULE` `ID_Ed25519ctx` arm (`:204-211`), which is not this profile's.
///
/// # Safety
/// `ctx` is live and holds a key of the instance's type when the instance matches.
unsafe fn eddsa_setup_instance(
    ctx: *mut ProvEddsaCtx,
    instance_id: c_int,
    instance_id_preset: c_uint,
    prehash_by_caller: c_uint,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        match instance_id {
            ID_ED25519 => {
                if (*ctx).key.is_null() || (*(*ctx).key).type_ != ECX_KEY_TYPE_ED25519 {
                    return 0;
                }
                (*ctx).flags &= !(FLAG_DOM2 | FLAG_PREHASH | FLAG_CONTEXT_STRING);
            }
            ID_ED25519CTX => {
                if (*ctx).key.is_null() || (*(*ctx).key).type_ != ECX_KEY_TYPE_ED25519 {
                    return 0;
                }
                (*ctx).flags = ((*ctx).flags & !(FLAG_PREHASH | FLAG_CONTEXT_STRING))
                    | FLAG_DOM2
                    | FLAG_CONTEXT_STRING;
            }
            ID_ED25519PH => {
                if (*ctx).key.is_null() || (*(*ctx).key).type_ != ECX_KEY_TYPE_ED25519 {
                    return 0;
                }
                (*ctx).flags = ((*ctx).flags & !(FLAG_PREHASH | FLAG_CONTEXT_STRING))
                    | FLAG_DOM2
                    | FLAG_PREHASH;
            }
            ID_ED448 => {
                if (*ctx).key.is_null() || (*(*ctx).key).type_ != ECX_KEY_TYPE_ED448 {
                    return 0;
                }
                (*ctx).flags &= !(FLAG_DOM2 | FLAG_PREHASH | FLAG_CONTEXT_STRING);
            }
            ID_ED448PH => {
                if (*ctx).key.is_null() || (*(*ctx).key).type_ != ECX_KEY_TYPE_ED448 {
                    return 0;
                }
                (*ctx).flags =
                    ((*ctx).flags & !(FLAG_PREHASH | FLAG_CONTEXT_STRING)) | FLAG_PREHASH;
            }
            _ => return 0,
        }
        (*ctx).instance_id = instance_id;
        if instance_id_preset != 0 {
            (*ctx).flags |= FLAG_INSTANCE_ID_PRESET;
        } else {
            (*ctx).flags &= !FLAG_INSTANCE_ID_PRESET;
        }
        if prehash_by_caller != 0 {
            (*ctx).flags |= FLAG_PREHASH_BY_CALLER;
        } else {
            (*ctx).flags &= !FLAG_PREHASH_BY_CALLER;
        }
    }
    1
}

/// `static int eddsa_signverify_init(void *vpeddsactx, void *vedkey)` — `eddsa_sig.c.in:257-320`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn eddsa_signverify_init(ctx: *mut ProvEddsaCtx, vedkey: *mut c_void) -> c_int {
    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context and `vedkey` is NULL or the caller's key.
    unsafe {
        if vedkey.is_null() {
            raise_site(&err_sites::PROV_EDDSA_SIG_249);
            return 0;
        }
        let edkey = vedkey.cast::<EcxKey>();
        if ossl_ecx_key_up_ref(edkey) == 0 {
            raise_site(&err_sites::PROV_EDDSA_SIG_254);
            return 0;
        }

        (*ctx).flags &= !(FLAG_INSTANCE_ID_PRESET | FLAG_DOM2 | FLAG_PREHASH | FLAG_CONTEXT_STRING);
        (*ctx).context_string_len = 0;
        (*ctx).key = edkey;

        /*
         * We do not care about DER writing errors: all it means is that there is no
         * AlgorithmIdentifier to be had, and the operation is still valid without one.
         */
        (*ctx).aid_len = 0;
        let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();
        let pkt = pkt.as_mut_ptr();
        let mut ret =
            WPACKET_init_der(pkt, (*ctx).aid_buf.as_mut_ptr(), OSSL_MAX_ALGORITHM_ID_SIZE);
        match (*edkey).type_ {
            ECX_KEY_TYPE_ED25519 => {
                if ret != 0 {
                    ret = ossl_DER_w_algorithmIdentifier_ED25519(pkt, -1, edkey);
                }
            }
            ECX_KEY_TYPE_ED448 => {
                if ret != 0 {
                    ret = ossl_DER_w_algorithmIdentifier_ED448(pkt, -1, edkey);
                }
            }
            _ => {
                raise_site(&err_sites::PROV_EDDSA_SIG_284);
                ossl_ecx_key_free(edkey);
                (*ctx).key = ptr::null_mut();
                WPACKET_cleanup(pkt);
                return 0;
            }
        }
        let mut aid: *mut u8 = ptr::null_mut();
        if ret != 0 && WPACKET_finish(pkt) != 0 {
            WPACKET_get_total_written(pkt, ptr::addr_of_mut!((*ctx).aid_len));
            aid = WPACKET_get_curr(pkt).cast::<u8>();
        }
        WPACKET_cleanup(pkt);
        if !aid.is_null() && (*ctx).aid_len != 0 {
            ptr::copy(aid, (*ctx).aid_buf.as_mut_ptr(), (*ctx).aid_len);
        }
    }
    1
}

/// One of the unit's seven instance init wrappers (`eddsa_sig.c.in:322-393`), all of which are
/// `eddsa_signverify_init && eddsa_setup_instance && eddsa_set_ctx_params`.
macro_rules! eddsa_instance_init {
    ($fn_name:ident, $id:expr, $preset:expr, $ph:expr) => {
        /// # Safety
        /// The signature init dispatch contract.
        unsafe extern "C" fn $fn_name(
            vctx: *mut c_void,
            vedkey: *mut c_void,
            params: *const OsslParam,
        ) -> c_int {
            let ctx = vctx.cast::<ProvEddsaCtx>();
            // SAFETY: the caller's contract.
            unsafe {
                if eddsa_signverify_init(ctx, vedkey) == 0
                    || eddsa_setup_instance(ctx, $id, $preset, $ph) == 0
                {
                    return 0;
                }
                eddsa_set_ctx_params(vctx, params)
            }
        }
    };
}

eddsa_instance_init!(ed25519_signverify_message_init, ID_ED25519, 1, 0);
eddsa_instance_init!(ed25519ph_signverify_message_init, ID_ED25519PH, 1, 0);
eddsa_instance_init!(ed25519ph_signverify_init, ID_ED25519PH, 1, 1);
eddsa_instance_init!(ed25519_signverify_init, ID_ED25519, 0, 1);
eddsa_instance_init!(ed25519ctx_signverify_message_init, ID_ED25519CTX, 1, 0);
eddsa_instance_init!(ed448_signverify_message_init, ID_ED448, 1, 0);
eddsa_instance_init!(ed448ph_signverify_message_init, ID_ED448PH, 1, 0);
eddsa_instance_init!(ed448ph_signverify_init, ID_ED448PH, 1, 1);
eddsa_instance_init!(ed448_signverify_init, ID_ED448, 0, 1);

/// `static int ed25519_sign(...)` — `eddsa_sig.c.in:399-470`, without the `S390X_EC_ASM` block
/// (`:416-432`).
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe fn ed25519_sign(
    ctx: *mut ProvEddsaCtx,
    sigret: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut md = [0u8; EVP_MAX_MD_SIZE];
    let mut mdlen: usize = 0;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if sigret.is_null() {
            *siglen = ED25519_SIGSIZE;
            return 1;
        }
        if sigsize < ED25519_SIGSIZE {
            raise_site(&err_sites::PROV_EDDSA_SIG_406);
            return 0;
        }
        let edkey = (*ctx).key;
        if edkey.is_null() || (*edkey).privkey.is_null() {
            raise_site(&err_sites::PROV_EDDSA_SIG_410);
            return 0;
        }

        let mut tbs = tbs;
        let mut tbslen = tbslen;
        if (*ctx).flags & FLAG_PREHASH != 0 {
            if (*ctx).flags & FLAG_PREHASH_BY_CALLER == 0 {
                if EVP_Q_digest(
                    (*ctx).libctx,
                    SN_SHA512,
                    ptr::null(),
                    tbs.cast(),
                    tbslen,
                    md.as_mut_ptr(),
                    &mut mdlen,
                ) == 0
                    || mdlen != EDDSA_PREHASH_OUTPUT_LEN
                {
                    raise_site(&err_sites::PROV_EDDSA_SIG_439);
                    return 0;
                }
                tbs = md.as_ptr();
                tbslen = mdlen;
            } else if tbslen != EDDSA_PREHASH_OUTPUT_LEN {
                raise_site(&err_sites::PROV_EDDSA_SIG_445);
                return 0;
            }
        } else if (*ctx).flags & FLAG_PREHASH_BY_CALLER != 0 {
            /* The caller is supposed to set up a ph instance! */
            raise_site(&err_sites::PROV_EDDSA_SIG_450);
            return 0;
        }

        if ossl_ed25519_sign(
            sigret,
            tbs,
            tbslen,
            (*edkey).pubkey.as_ptr(),
            (*edkey).privkey,
            c_u8((*ctx).flags & FLAG_DOM2 != 0),
            c_u8((*ctx).flags & FLAG_PREHASH != 0),
            c_u8((*ctx).flags & FLAG_CONTEXT_STRING != 0),
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            (*ctx).libctx,
            ptr::null(),
        ) == 0
        {
            raise_site(&err_sites::PROV_EDDSA_SIG_460);
            return 0;
        }
        *siglen = ED25519_SIGSIZE;
    }
    1
}

/// `static int ed448_shake256(...)` — `eddsa_sig.c.in:472-492`. `EVP_Q_digest` cannot answer an
/// XOF output of a chosen length, so the unit drives the `EVP_MD_CTX` itself.
///
/// # Safety
/// `in` readable for `inlen` bytes; `out` writable for `outlen` bytes.
unsafe fn ed448_shake256(
    libctx: *mut c_void,
    propq: *const c_char,
    input: *const u8,
    inlen: usize,
    out: *mut u8,
    outlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let hash_ctx = EVP_MD_CTX_new();
        let shake256 = EVP_MD_fetch(libctx, SN_SHAKE256, propq);
        if hash_ctx.is_null() || shake256.is_null() {
            EVP_MD_CTX_free(hash_ctx);
            EVP_MD_free(shake256);
            return 0;
        }

        let ret = c_int::from(
            EVP_DigestInit_ex(hash_ctx, shake256, ptr::null_mut()) != 0
                && EVP_DigestUpdate(hash_ctx, input.cast(), inlen) != 0
                && EVP_DigestFinalXOF(hash_ctx, out, outlen) != 0,
        );

        EVP_MD_CTX_free(hash_ctx);
        EVP_MD_free(shake256);
        ret
    }
}

/// `static int ed448_sign(...)` — `eddsa_sig.c.in:498-570`, without the `S390X_EC_ASM` block
/// (`:521-539`).
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe fn ed448_sign(
    ctx: *mut ProvEddsaCtx,
    sigret: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut md = [0u8; EDDSA_PREHASH_OUTPUT_LEN];
    let mdlen: usize = md.len();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if sigret.is_null() {
            *siglen = ED448_SIGSIZE;
            return 1;
        }
        if sigsize < ED448_SIGSIZE {
            raise_site(&err_sites::PROV_EDDSA_SIG_515);
            return 0;
        }
        let edkey = (*ctx).key;
        if edkey.is_null() || (*edkey).privkey.is_null() {
            raise_site(&err_sites::PROV_EDDSA_SIG_519);
            return 0;
        }

        let mut tbs = tbs;
        let mut tbslen = tbslen;
        if (*ctx).flags & FLAG_PREHASH != 0 {
            if (*ctx).flags & FLAG_PREHASH_BY_CALLER == 0 {
                if ed448_shake256(
                    (*ctx).libctx,
                    ptr::null(),
                    tbs,
                    tbslen,
                    md.as_mut_ptr(),
                    mdlen,
                ) == 0
                {
                    return 0;
                }
                tbs = md.as_ptr();
                tbslen = mdlen;
            } else if tbslen != EDDSA_PREHASH_OUTPUT_LEN {
                raise_site(&err_sites::PROV_EDDSA_SIG_548);
                return 0;
            }
        } else if (*ctx).flags & FLAG_PREHASH_BY_CALLER != 0 {
            /* The caller is supposed to set up a ph instance! */
            raise_site(&err_sites::PROV_EDDSA_SIG_553);
            return 0;
        }

        if ossl_ed448_sign(
            (*ctx).libctx,
            sigret,
            tbs,
            tbslen,
            (*edkey).pubkey.as_ptr(),
            (*edkey).privkey,
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            c_u8((*ctx).flags & FLAG_PREHASH != 0),
            (*edkey).propq,
        ) == 0
        {
            raise_site(&err_sites::PROV_EDDSA_SIG_563);
            return 0;
        }
        *siglen = ED448_SIGSIZE;
    }
    1
}

/// `static int ed25519_verify(...)` — `eddsa_sig.c.in:576-635`, without the `S390X_EC_ASM` block
/// (`:592-601`).
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe fn ed25519_verify(
    ctx: *mut ProvEddsaCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut md = [0u8; EVP_MAX_MD_SIZE];
    let mut mdlen: usize = 0;

    if is_running() == 0 || siglen != ED25519_SIGSIZE {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        let edkey = (*ctx).key;
        if edkey.is_null() {
            return 0;
        }

        let mut tbs = tbs;
        let mut tbslen = tbslen;
        if (*ctx).flags & FLAG_PREHASH != 0 {
            if (*ctx).flags & FLAG_PREHASH_BY_CALLER == 0 {
                if EVP_Q_digest(
                    (*ctx).libctx,
                    SN_SHA512,
                    ptr::null(),
                    tbs.cast(),
                    tbslen,
                    md.as_mut_ptr(),
                    &mut mdlen,
                ) == 0
                    || mdlen != EDDSA_PREHASH_OUTPUT_LEN
                {
                    raise_site(&err_sites::PROV_EDDSA_SIG_606);
                    return 0;
                }
                tbs = md.as_ptr();
                tbslen = mdlen;
            } else if tbslen != EDDSA_PREHASH_OUTPUT_LEN {
                raise_site(&err_sites::PROV_EDDSA_SIG_612);
                return 0;
            }
        } else if (*ctx).flags & FLAG_PREHASH_BY_CALLER != 0 {
            /* The caller is supposed to set up a ph instance! */
            raise_site(&err_sites::PROV_EDDSA_SIG_617);
            return 0;
        }

        ossl_ed25519_verify(
            tbs,
            tbslen,
            sig,
            (*edkey).pubkey.as_ptr(),
            c_u8((*ctx).flags & FLAG_DOM2 != 0),
            c_u8((*ctx).flags & FLAG_PREHASH != 0),
            c_u8((*ctx).flags & FLAG_CONTEXT_STRING != 0),
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            (*ctx).libctx,
            (*edkey).propq,
        )
    }
}

/// `static int ed448_verify(...)` — `eddsa_sig.c.in:641-686`, without the `S390X_EC_ASM` block
/// (`:652-662`).
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe fn ed448_verify(
    ctx: *mut ProvEddsaCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut md = [0u8; EDDSA_PREHASH_OUTPUT_LEN];
    let mdlen: usize = md.len();

    if is_running() == 0 || siglen != ED448_SIGSIZE {
        return 0;
    }

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        let edkey = (*ctx).key;
        if edkey.is_null() {
            return 0;
        }

        let mut tbs = tbs;
        let mut tbslen = tbslen;
        if (*ctx).flags & FLAG_PREHASH != 0 {
            if (*ctx).flags & FLAG_PREHASH_BY_CALLER == 0 {
                if ed448_shake256(
                    (*ctx).libctx,
                    ptr::null(),
                    tbs,
                    tbslen,
                    md.as_mut_ptr(),
                    mdlen,
                ) == 0
                {
                    return 0;
                }
                tbs = md.as_ptr();
                tbslen = mdlen;
            } else if tbslen != EDDSA_PREHASH_OUTPUT_LEN {
                raise_site(&err_sites::PROV_EDDSA_SIG_664);
                return 0;
            }
        } else if (*ctx).flags & FLAG_PREHASH_BY_CALLER != 0 {
            /* The caller is supposed to set up a ph instance! */
            raise_site(&err_sites::PROV_EDDSA_SIG_669);
            return 0;
        }

        ossl_ed448_verify(
            (*ctx).libctx,
            tbs,
            tbslen,
            sig,
            (*edkey).pubkey.as_ptr(),
            (*ctx).context_string.as_ptr(),
            (*ctx).context_string_len,
            c_u8((*ctx).flags & FLAG_PREHASH != 0),
            (*edkey).propq,
        )
    }
}

/// `static int ed25519_digest_signverify_init(...)` — `eddsa_sig.c.in:682-702`.
///
/// # Safety
/// The signature `digest_sign/verify_init` dispatch contract.
unsafe extern "C" fn ed25519_digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vedkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if !mdname.is_null() && (*mdname) != 0 {
            raise_site(&err_sites::PROV_EDDSA_SIG_688);
            return 0;
        }

        if vedkey.is_null() && !(*ctx).key.is_null() {
            return eddsa_set_ctx_params(vctx, params);
        }

        if eddsa_signverify_init(ctx, vedkey) == 0
            || eddsa_setup_instance(ctx, ID_ED25519, 0, 0) == 0
        {
            return 0;
        }
        eddsa_set_ctx_params(vctx, params)
    }
}

/// `static int ed448_digest_signverify_init(...)` — `eddsa_sig.c.in:716-736`.
///
/// # Safety
/// The signature `digest_sign/verify_init` dispatch contract.
unsafe extern "C" fn ed448_digest_signverify_init(
    vctx: *mut c_void,
    mdname: *const c_char,
    vedkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if !mdname.is_null() && (*mdname) != 0 {
            raise_site(&err_sites::PROV_EDDSA_SIG_722);
            return 0;
        }

        if vedkey.is_null() && !(*ctx).key.is_null() {
            return eddsa_set_ctx_params(vctx, params);
        }

        if eddsa_signverify_init(ctx, vedkey) == 0 || eddsa_setup_instance(ctx, ID_ED448, 0, 0) == 0
        {
            return 0;
        }
        eddsa_set_ctx_params(vctx, params)
    }
}

/// The four DIGEST_SIGN/VERIFY wrappers (`eddsa_sig.c.in:704-714`, `:738-748`), which are one call
/// each to the instance's own sign/verify.
macro_rules! eddsa_digest_wrapper {
    ($fn_name:ident, $inner:ident) => {
        /// # Safety
        /// The signature `digest_sign`/`digest_verify` dispatch contract.
        unsafe extern "C" fn $fn_name(
            vctx: *mut c_void,
            sigret: *mut u8,
            siglen: *mut usize,
            sigsize: usize,
            tbs: *const u8,
            tbslen: usize,
        ) -> c_int {
            // SAFETY: the caller's contract.
            unsafe {
                $inner(
                    vctx.cast::<ProvEddsaCtx>(),
                    sigret,
                    siglen,
                    sigsize,
                    tbs,
                    tbslen,
                )
            }
        }
    };
}

eddsa_digest_wrapper!(ed25519_digest_sign, ed25519_sign);
eddsa_digest_wrapper!(ed448_digest_sign, ed448_sign);

/// `static int ed25519_digest_verify(...)` — `eddsa_sig.c.in:706-712`.
///
/// # Safety
/// The signature `digest_verify` dispatch contract.
unsafe extern "C" fn ed25519_digest_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ed25519_verify(vctx.cast::<ProvEddsaCtx>(), sig, siglen, tbs, tbslen) }
}

/// `static int ed448_digest_verify(...)` — `eddsa_sig.c.in:740-746`.
///
/// # Safety
/// The signature `digest_verify` dispatch contract.
unsafe extern "C" fn ed448_digest_verify(
    vctx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ed448_verify(vctx.cast::<ProvEddsaCtx>(), sig, siglen, tbs, tbslen) }
}

/// `static void eddsa_freectx(void *vpeddsactx)` — `eddsa_sig.c.in:750-757`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn eddsa_freectx(vctx: *mut c_void) {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        ossl_ecx_key_free((*ctx).key);
        CRYPTO_free(ctx.cast(), FILE, 755);
    }
}

/// `static void *eddsa_dupctx(void *vpeddsactx)` — `eddsa_sig.c.in:759-781`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn eddsa_dupctx(vctx: *mut c_void) -> *mut c_void {
    let srcctx = vctx.cast::<ProvEddsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let dstctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvEddsaCtx>(), FILE, 764).cast::<ProvEddsaCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live per the contract, and the copy is of this call's allocation.
    unsafe {
        ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        (*dstctx).key = ptr::null_mut();

        if !(*srcctx).key.is_null() && ossl_ecx_key_up_ref((*srcctx).key) == 0 {
            raise_site(&err_sites::PROV_EDDSA_SIG_774);
            return eddsa_dupctx_err(dstctx);
        }
        (*dstctx).key = (*srcctx).key;
    }

    dstctx.cast()
}

/// The authority's `err:` arm (`eddsa_sig.c.in:779-781`).
///
/// # Safety
/// `dstctx` is this call's own allocation.
unsafe fn eddsa_dupctx_err(dstctx: *mut ProvEddsaCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { eddsa_freectx(dstctx.cast()) };
    ptr::null_mut()
}

/// `static const char **ed25519_sigalg_query_key_types(void)` — `eddsa_sig.c.in:783-788`.
unsafe extern "C" fn ed25519_sigalg_query_key_types() -> *mut *const c_char {
    /// `static const char *keytypes[] = { "ED25519", NULL }`.
    #[repr(C)]
    struct KeyTypeNames([*const c_char; 2]);
    // SAFETY: the array holds `'static` literals and a NULL terminator; nothing mutates it.
    unsafe impl Sync for KeyTypeNames {}
    static KEYTYPES: KeyTypeNames = KeyTypeNames([c"ED25519".as_ptr(), ptr::null()]);
    KEYTYPES.0.as_ptr().cast_mut()
}

/// `static const char **ed448_sigalg_query_key_types(void)` — `eddsa_sig.c.in:790-795`.
unsafe extern "C" fn ed448_sigalg_query_key_types() -> *mut *const c_char {
    /// `static const char *keytypes[] = { "ED448", NULL }`.
    #[repr(C)]
    struct KeyTypeNames([*const c_char; 2]);
    // SAFETY: the array holds `'static` literals and a NULL terminator; nothing mutates it.
    unsafe impl Sync for KeyTypeNames {}
    static KEYTYPES: KeyTypeNames = KeyTypeNames([c"ED448".as_ptr(), ptr::null()]);
    KEYTYPES.0.as_ptr().cast_mut()
}

/// `struct eddsa_get_ctx_params_st` — the `produce_param_decoder` expansion at
/// `eddsa_sig.c.in:797-800`, generated from the one name `algorithm-id` (field `id`).
#[derive(Clone, Copy)]
struct GetCtxParams {
    id: *const OsslParam,
}

/// `eddsa_get_ctx_params_decoder` — the decoder `produce_param_decoder` emits.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn eddsa_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams { id: ptr::null() };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            if s == b"algorithm-id" {
                if !r.id.is_null() {
                    raise_site(&err_sites::PROV_EDDSA_SIG_826);
                    return None;
                }
                r.id = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM eddsa_get_ctx_params_list[]` — `eddsa_sig.c.in:801-806`.
static EDDSA_GET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID), END];

/// `static int eddsa_get_ctx_params(void *vpeddsactx, OSSL_PARAM *params)` —
/// `eddsa_sig.c.in:808-822`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_get_ctx_params(vctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = eddsa_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.id.is_null()
            && OSSL_PARAM_set_octet_string(
                p.id.cast_mut(),
                if (*ctx).aid_len == 0 {
                    ptr::null()
                } else {
                    (*ctx).aid_buf.as_ptr().cast()
                },
                (*ctx).aid_len,
            ) == 0
        {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *eddsa_gettable_ctx_params(...)` — `eddsa_sig.c.in:824-829`.
///
/// # Safety
/// The signature `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    EDDSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct eddsa_set_ctx_params_st` — the `produce_param_decoder` expansion at
/// `eddsa_sig.c.in:831-835`, generated from the two names `instance` (field `inst`) and
/// `context-string` (field `ctx`).
#[derive(Clone, Copy)]
struct SetCtxParams {
    inst: *const OsslParam,
    ctx: *const OsslParam,
}

/// `eddsa_set_ctx_params_decoder` — the second generated decoder.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn eddsa_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        inst: ptr::null(),
        ctx: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"context-string" => {
                    if !r.ctx.is_null() {
                        raise_site(&err_sites::PROV_EDDSA_SIG_894);
                        return None;
                    }
                    r.ctx = p;
                }
                b"instance" => {
                    if !r.inst.is_null() {
                        raise_site(&err_sites::PROV_EDDSA_SIG_905);
                        return None;
                    }
                    r.inst = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static int eddsa_set_ctx_params_internal(...)` — `eddsa_sig.c.in:839-919`.
///
/// # Safety
/// `ctx` is live; the descriptors are NULL or live.
unsafe fn eddsa_set_ctx_params_internal(ctx: *mut ProvEddsaCtx, p: &SetCtxParams) -> c_int {
    // SAFETY: `ctx` is live and `p.inst` is NULL or a live descriptor.
    unsafe {
        if !p.inst.is_null() {
            let mut instance_name = [0 as c_char; OSSL_MAX_NAME_SIZE];
            let mut pinstance_name = instance_name.as_mut_ptr();

            if (*ctx).flags & FLAG_INSTANCE_ID_PRESET != 0 {
                /* When the instance is preset, the caller must not try to set it. */
                raise_site(&err_sites::PROV_EDDSA_SIG_926);
                return 0;
            }

            if OSSL_PARAM_get_utf8_string(p.inst, &mut pinstance_name, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }

            /*
             * When setting the new instance, the `prehash_by_caller` flag is left alone: the init
             * functions preset it and the sign functions check that the instance matches it.
             */
            let prehash_by_caller = (*ctx).flags & FLAG_PREHASH_BY_CALLER;
            if OPENSSL_strcasecmp(pinstance_name, SN_ED25519) == 0 {
                if eddsa_setup_instance(ctx, ID_ED25519, 0, prehash_by_caller) == 0 {
                    return 0;
                }
            } else if OPENSSL_strcasecmp(pinstance_name, SN_ED25519CTX) == 0 {
                if eddsa_setup_instance(ctx, ID_ED25519CTX, 0, prehash_by_caller) == 0 {
                    return 0;
                }
            } else if OPENSSL_strcasecmp(pinstance_name, SN_ED25519PH) == 0 {
                if eddsa_setup_instance(ctx, ID_ED25519PH, 0, prehash_by_caller) == 0 {
                    return 0;
                }
            } else if OPENSSL_strcasecmp(pinstance_name, SN_ED448) == 0 {
                if eddsa_setup_instance(ctx, ID_ED448, 0, prehash_by_caller) == 0 {
                    return 0;
                }
            } else if OPENSSL_strcasecmp(pinstance_name, SN_ED448PH) == 0 {
                if eddsa_setup_instance(ctx, ID_ED448PH, 0, prehash_by_caller) == 0 {
                    return 0;
                }
            } else {
                raise_site(&err_sites::PROV_EDDSA_SIG_961);
                return 0;
            }
        }

        if !p.ctx.is_null() {
            let mut vp_context_string: *mut c_void = (*ctx).context_string.as_mut_ptr().cast();
            if OSSL_PARAM_get_octet_string(
                p.ctx,
                &mut vp_context_string,
                EDDSA_MAX_CONTEXT_STRING_LEN,
                ptr::addr_of_mut!((*ctx).context_string_len),
            ) == 0
            {
                (*ctx).context_string_len = 0;
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM eddsa_set_ctx_params_list[]` — `eddsa_sig.c.in:837-846`.
static EDDSA_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE),
    param_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
    END,
];

/// `static const OSSL_PARAM *eddsa_settable_ctx_params(...)` — `eddsa_sig.c.in:868-874`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    EDDSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int eddsa_set_ctx_params(void *vpeddsactx, const OSSL_PARAM params[])` —
/// `eddsa_sig.c.in:876-884`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = eddsa_set_ctx_params_decoder(params) else {
            return 0;
        };
        eddsa_set_ctx_params_internal(ctx, &p)
    }
}

/// `struct eddsa_set_variant_ctx_params_st` — the third generated decoder's struct, the same
/// `SetCtxParams` (its one name, `context-string`, is a subset).
///
/// `eddsa_set_variant_ctx_params_decoder` — the third generated decoder.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn eddsa_set_variant_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        inst: ptr::null(),
        ctx: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            if s == b"context-string" {
                if !r.ctx.is_null() {
                    raise_site(&err_sites::PROV_EDDSA_SIG_1027);
                    return None;
                }
                r.ctx = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM eddsa_set_variant_ctx_params_list[]` — `eddsa_sig.c.in:888-898`.
static EDDSA_SET_VARIANT_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING), END];

/// `static const OSSL_PARAM *eddsa_settable_variant_ctx_params(...)` — `eddsa_sig.c.in:902-908`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_settable_variant_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    EDDSA_SET_VARIANT_CTX_PARAMS_LIST.as_ptr()
}

/// `static int eddsa_set_variant_ctx_params(...)` — `eddsa_sig.c.in:910-920`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn eddsa_set_variant_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvEddsaCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = eddsa_set_variant_ctx_params_decoder(params) else {
            return 0;
        };
        eddsa_set_ctx_params_internal(ctx, &p)
    }
}

/// The five dispatch tables (`eddsa_sig.c.in:1093-1168`'s `IMPL_EDDSA_DISPATCH` and the six
/// `*_DISPATCH_END` `#define`s). They are written out, one literal table each, because the
/// tails differ in which `set_ctx_params` they name and whether they carry the digest face.
///
/// `const OSSL_DISPATCH ossl_ed25519_signature_functions[]` — `eddsa_sig.c.in:1093-1109`.
pub(crate) static ED25519_SIGNATURE_FUNCTIONS: [OsslDispatch; 19] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: eddsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        function: ed25519_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ed25519_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        function: ed25519_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ed25519_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: eddsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: eddsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
        function: ed25519_sigalg_query_key_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed25519_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed25519_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: ed25519_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        function: ed25519_digest_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: ed25519_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        function: ed25519_digest_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: eddsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: eddsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: eddsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: eddsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_ed25519ph_signature_functions[]` — `eddsa_sig.c.in:1130-1136`. The
/// duplicate `SIGN_INIT`/`VERIFY_INIT` pair is the authority's: the `ed25519ph_DISPATCH_END` tail
/// emits them for the `_signverify_init` wrappers and then `eddsa_variant_DISPATCH_END` emits them
/// again for the `_signverify_message_init` ones.
pub(crate) static ED25519PH_SIGNATURE_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: eddsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        function: ed25519ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ed25519_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        function: ed25519ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ed25519_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: eddsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: eddsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
        function: ed25519_sigalg_query_key_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed25519ph_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed25519ph_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed25519ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed25519ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: eddsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: eddsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: eddsa_set_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: eddsa_settable_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_ed25519ctx_signature_functions[]` — `eddsa_sig.c.in:1138`.
pub(crate) static ED25519CTX_SIGNATURE_FUNCTIONS: [OsslDispatch; 15] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: eddsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        function: ed25519ctx_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ed25519_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        function: ed25519ctx_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ed25519_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: eddsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: eddsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
        function: ed25519_sigalg_query_key_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed25519ctx_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed25519ctx_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: eddsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: eddsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: eddsa_set_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: eddsa_settable_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_ed448_signature_functions[]` — `eddsa_sig.c.in:1140-1160`.
pub(crate) static ED448_SIGNATURE_FUNCTIONS: [OsslDispatch; 19] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: eddsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        function: ed448_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ed448_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        function: ed448_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ed448_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: eddsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: eddsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
        function: ed448_sigalg_query_key_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed448_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed448_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: ed448_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        function: ed448_digest_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: ed448_digest_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        function: ed448_digest_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: eddsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: eddsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: eddsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: eddsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_ed448ph_signature_functions[]` — `eddsa_sig.c.in:1162-1168`.
pub(crate) static ED448PH_SIGNATURE_FUNCTIONS: [OsslDispatch; 17] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: eddsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
        function: ed448ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: ed448_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
        function: ed448ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: ed448_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: eddsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: eddsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
        function: ed448_sigalg_query_key_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed448ph_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed448ph_signverify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: ed448ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: ed448ph_signverify_message_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: eddsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: eddsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: eddsa_set_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: eddsa_settable_variant_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// The unit's `__FILE__` — `.c.in`-generated, so the bare build-relative path (D235).
const FILE: *const c_char = c"providers/implementations/signature/eddsa_sig.c".as_ptr();

/// `(int)(bool)` for the `dom2`/`ph`/`cs` arguments the four EdDSA primitives take.
#[inline]
fn c_u8(b: bool) -> u8 {
    u8::from(b)
}
// `ID_NOT_SET` is the `ID_EdDSA_INSTANCE` zero the authority's enum defines; the unit never stores
// it once `eddsa_setup_instance` has run, but the constant is named so a reader can see the enum's
// full range.
const _: () = assert!(ID_NOT_SET == 0);
