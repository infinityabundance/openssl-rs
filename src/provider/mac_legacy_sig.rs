//! Phase 8.10 — `providers/implementations/signature/mac_legacy_sig.c`: the `HMAC`, `SIPHASH`,
//! `POLY1305` and `CMAC` `OSSL_OP_SIGNATURE` rows.
//!
//! Two hundred and sixty-four source lines, fourteen functions and four dispatch tables. The unit is
//! the legacy-MAC *signature* face of the same key objects `keymgmt/mac_legacy_kmgmt.c` publishes
//! (D389): `PROV_MAC_CTX` holds a [`MacKey`] borrow and an `EVP_MAC_CTX`, and the four rows differ
//! only in the MAC name their `newctx` fetches.
//!
//! ## What the unit is, and what it is not
//!
//! There is no signing arithmetic here at all. `mac_digest_sign_init` resolves the key's cipher name
//! (CMAC's case), sets `digest`/`cipher`/`engine`/`properties` on the MAC context through
//! [`ossl_prov_set_macctx`], and hands the private key to `EVP_MAC_init`; update and final are
//! forwarded to `EVP_MAC_update`/`EVP_MAC_final`. So the unit's whole closure is the MAC object
//! landed in D389 plus the `EVP_MAC_*` face, and it is the smallest member of the `OSSL_OP_SIGNATURE`
//! block — which is why it is the one the `DEFLT_SIGNATURES` table opens with.
//!
//! ## The `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` arm
//!
//! `mac_digest_sign_init`'s engine block (`:120-123`) is *compiled in* on this profile — D181
//! measured `OPENSSL_NO_ENGINE` as undefined — and it reads `ENGINE_get_id(key->cipher.engine)`.
//! `PROV_CIPHER.engine` can only ever be NULL in every state this crate can reach (D389's
//! measurement of the same field), so the block's guard is unreachable and the local `engine` is
//! NULL at the call below. It is **not emitted**, with that reason written at the site: the call is
//! absent because its guard is false in every reachable state, not because the unit was reduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get0_name;
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch,
    EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_settable_ctx_params, EVP_MAC_update, EvpMac,
    EvpMacCtx,
};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DUPCTX,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
};
use crate::params::OsslParam;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::mac_legacy_kmgmt::{ossl_mac_key_free, ossl_mac_key_up_ref, MacKey};
use crate::provider::util::ossl_prov_set_macctx;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};

/// The unit's own `__FILE__`. `mac_legacy_sig.c` is a plain `.c`, so it carries the source-tree
/// prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/signature/mac_legacy_sig.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_MAC_CTX` — `mac_legacy_sig.c:43-48`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvMacCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `MAC_KEY *key` — a borrow carrying a reference.
    key: *mut MacKey,
    /// `EVP_MAC_CTX *macctx`.
    macctx: *mut EvpMacCtx,
}

/// `static void *mac_newctx(void *provctx, const char *propq, const char *macname)` —
/// `mac_legacy_sig.c:50-83`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `macname` is NUL-terminated.
unsafe fn mac_newctx(
    provctx: *mut c_void,
    propq: *const c_char,
    macname: *const c_char,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let pmacctx = CRYPTO_zalloc(core::mem::size_of::<ProvMacCtx>(), FILE, 58).cast::<ProvMacCtx>();
    if pmacctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pmacctx` is this call's own allocation; `mac` is live or NULL.
    unsafe {
        (*pmacctx).libctx = prov_libctx_of(provctx);
        if !propq.is_null() {
            (*pmacctx).propq = CRYPTO_strdup(propq, FILE, 63);
            if (*pmacctx).propq.is_null() {
                return mac_newctx_err(pmacctx, ptr::null_mut());
            }
        }

        let mac = EVP_MAC_fetch((*pmacctx).libctx, macname, propq);
        if mac.is_null() {
            return mac_newctx_err(pmacctx, mac);
        }

        (*pmacctx).macctx = EVP_MAC_CTX_new(mac);
        if (*pmacctx).macctx.is_null() {
            return mac_newctx_err(pmacctx, mac);
        }

        EVP_MAC_free(mac);
    }

    pmacctx.cast()
}

/// The authority's `err:` arm (`mac_legacy_sig.c:78-82`), a labelled block reached from three
/// statements in [`mac_newctx`].
///
/// # Safety
/// `pmacctx` is this call's own allocation and `mac` is NULL or a live fetched MAC.
unsafe fn mac_newctx_err(pmacctx: *mut ProvMacCtx, mac: *mut EvpMac) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_free((*pmacctx).propq.cast(), FILE, 79);
        CRYPTO_free(pmacctx.cast(), FILE, 80);
        EVP_MAC_free(mac);
    }
    ptr::null_mut()
}

/// `MAC_NEWCTX` — the four one-line `newctx` slots (`mac_legacy_sig.c:85-94`).
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_hmac_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"HMAC".as_ptr()) }
}

/// `mac_siphash_newctx` — `mac_legacy_sig.c:92`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_siphash_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"SIPHASH".as_ptr()) }
}

/// `mac_poly1305_newctx` — `mac_legacy_sig.c:93`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_poly1305_newctx(
    provctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"POLY1305".as_ptr()) }
}

/// `mac_cmac_newctx` — `mac_legacy_sig.c:94`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_cmac_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"CMAC".as_ptr()) }
}

/// `static int mac_digest_sign_init(void *vpmacctx, const char *mdname, void *vkey,
/// const OSSL_PARAM params[])` — `mac_legacy_sig.c:96-137`.
///
/// The `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` engine block is named in this
/// module's header and is not emitted; `engine` is therefore NULL, which is the only value the
/// field can hold in this crate.
///
/// # Safety
/// The signature `digest_sign_init` dispatch contract.
unsafe extern "C" fn mac_digest_sign_init(
    vpmacctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();
    let key = vkey.cast::<MacKey>();
    let mut ciphername: *const c_char = ptr::null();
    let engine: *const c_char = ptr::null();

    if is_running() == 0 || pmacctx.is_null() {
        return 0;
    }

    // SAFETY: both objects are the caller's, per the dispatch contract.
    unsafe {
        if (*pmacctx).key.is_null() && key.is_null() {
            raise_site(&err_sites::PROV_MAC_LEGACY_SIG_107);
            return 0;
        }

        if !key.is_null() {
            if ossl_mac_key_up_ref(key) == 0 {
                return 0;
            }
            ossl_mac_key_free((*pmacctx).key);
            (*pmacctx).key = key;
        }

        if !(*(*pmacctx).key).cipher.cipher.is_null() {
            ciphername = EVP_CIPHER_get0_name((*(*pmacctx).key).cipher.cipher);
        }

        if ossl_prov_set_macctx(
            (*pmacctx).macctx,
            ciphername,
            mdname,
            engine,
            (*(*pmacctx).key).properties,
        ) == 0
        {
            return 0;
        }

        if EVP_MAC_init(
            (*pmacctx).macctx,
            (*(*pmacctx).key).priv_key,
            (*(*pmacctx).key).priv_key_len,
            params,
        ) == 0
        {
            return 0;
        }
    }

    1
}

/// `int mac_digest_sign_update(void *vpmacctx, const unsigned char *data, size_t datalen)` —
/// `mac_legacy_sig.c:139-148`.
///
/// # Safety
/// The signature `digest_sign_update` dispatch contract.
unsafe extern "C" fn mac_digest_sign_update(
    vpmacctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();

    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe {
        if pmacctx.is_null() || (*pmacctx).macctx.is_null() {
            return 0;
        }
        EVP_MAC_update((*pmacctx).macctx, data, datalen)
    }
}

/// `int mac_digest_sign_final(void *vpmacctx, unsigned char *mac, size_t *maclen,
/// size_t macsize)` — `mac_legacy_sig.c:150-159`.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
unsafe extern "C" fn mac_digest_sign_final(
    vpmacctx: *mut c_void,
    mac: *mut u8,
    maclen: *mut usize,
    macsize: usize,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe {
        if pmacctx.is_null() || (*pmacctx).macctx.is_null() {
            return 0;
        }
        EVP_MAC_final((*pmacctx).macctx, mac, maclen, macsize)
    }
}

/// `static void mac_freectx(void *vpmacctx)` — `mac_legacy_sig.c:161-169`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn mac_freectx(vpmacctx: *mut c_void) {
    let ctx = vpmacctx.cast::<ProvMacCtx>();

    // SAFETY: `ctx` is the caller's context, and every owned member is released here.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE, 165);
        EVP_MAC_CTX_free((*ctx).macctx);
        ossl_mac_key_free((*ctx).key);
        CRYPTO_free(ctx.cast(), FILE, 168);
    }
}

/// `static void *mac_dupctx(void *vpmacctx)` — `mac_legacy_sig.c:171-205`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn mac_dupctx(vpmacctx: *mut c_void) -> *mut c_void {
    let srcctx = vpmacctx.cast::<ProvMacCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let dstctx = CRYPTO_zalloc(core::mem::size_of::<ProvMacCtx>(), FILE, 179).cast::<ProvMacCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live per the contract; the copies are of this call's own
    // allocation.
    unsafe {
        *dstctx = *srcctx;
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).key = ptr::null_mut();
        (*dstctx).macctx = ptr::null_mut();

        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, 188);
            if (*dstctx).propq.is_null() {
                return mac_dupctx_err(dstctx);
            }
        }

        if !(*srcctx).key.is_null() && ossl_mac_key_up_ref((*srcctx).key) == 0 {
            return mac_dupctx_err(dstctx);
        }
        (*dstctx).key = (*srcctx).key;

        if !(*srcctx).macctx.is_null() {
            (*dstctx).macctx = EVP_MAC_CTX_dup((*srcctx).macctx);
            if (*dstctx).macctx.is_null() {
                return mac_dupctx_err(dstctx);
            }
        }
    }

    dstctx.cast()
}

/// The authority's `err:` arm (`mac_legacy_sig.c:202-204`), a labelled block reached from three
/// statements in [`mac_dupctx`].
///
/// # Safety
/// `dstctx` is this call's own allocation.
unsafe fn mac_dupctx_err(dstctx: *mut ProvMacCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_freectx(dstctx.cast()) };
    ptr::null_mut()
}

/// `static int mac_set_ctx_params(void *vpmacctx, const OSSL_PARAM params[])` —
/// `mac_legacy_sig.c:207-212`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn mac_set_ctx_params(vpmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vpmacctx.cast::<ProvMacCtx>();

    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe { EVP_MAC_CTX_set_params((*ctx).macctx, params) }
}

/// `static const OSSL_PARAM *mac_settable_ctx_params(void *ctx, void *provctx,
/// const char *macname)` — `mac_legacy_sig.c:214-229`.
///
/// # Safety
/// `provctx` is the caller's provider context; `macname` is NUL-terminated.
unsafe fn mac_settable_ctx_params(
    _ctx: *mut c_void,
    provctx: *mut c_void,
    macname: *const c_char,
) -> *const OsslParam {
    // SAFETY: both arguments are the caller's, per the dispatch contract.
    unsafe {
        let mac = EVP_MAC_fetch(prov_libctx_of(provctx), macname, ptr::null());
        if mac.is_null() {
            return ptr::null();
        }

        let params = EVP_MAC_settable_ctx_params(mac);
        EVP_MAC_free(mac);

        params
    }
}

/// `MAC_SETTABLE_CTX_PARAMS` — the four wrappers (`mac_legacy_sig.c:231-241`).
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_hmac_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"HMAC".as_ptr()) }
}

/// `mac_siphash_settable_ctx_params` — `mac_legacy_sig.c:239`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_siphash_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"SIPHASH".as_ptr()) }
}

/// `mac_poly1305_settable_ctx_params` — `mac_legacy_sig.c:240`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_poly1305_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"POLY1305".as_ptr()) }
}

/// `mac_cmac_settable_ctx_params` — `mac_legacy_sig.c:241`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_cmac_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"CMAC".as_ptr()) }
}

/// `const OSSL_DISPATCH ossl_mac_legacy_hmac_signature_functions[]` —
/// `mac_legacy_sig.c:243-261`. Eight slots, the authority's, in its order.
pub(crate) static MAC_LEGACY_HMAC_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_hmac_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_hmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_siphash_signature_functions[]` —
/// `mac_legacy_sig.c:262`. The same eight slots with `newctx` and `settable_ctx_params` replaced.
pub(crate) static MAC_LEGACY_SIPHASH_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_siphash_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_siphash_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_poly1305_signature_functions[]` —
/// `mac_legacy_sig.c:263`.
pub(crate) static MAC_LEGACY_POLY1305_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_poly1305_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_poly1305_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_cmac_signature_functions[]` — `mac_legacy_sig.c:264`.
pub(crate) static MAC_LEGACY_CMAC_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_cmac_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_cmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
