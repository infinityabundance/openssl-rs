//! Phase 8.10 — `providers/implementations/exchange/ecx_exch.c.in`: the `X25519` and `X448` key
//! exchange rows.
//!
//! Two hundred and forty-four lines, nine functions and two dispatch tables. The unit is small and
//! almost entirely context plumbing: the agreement itself is [`ossl_ecx_compute_key`], landed with
//! the ECX object in D372, and what this unit adds is the provider *context* — the key length the
//! two rows differ by, the reference the `init` and `set_peer` slots take, and the release the
//! `freectx`/`dupctx` slots owe.
//!
//! ## Why it lands with the `ecx_kmgmt.c` unit rather than after it
//!
//! D384 recorded the whole `OSSL_OP_KEYEXCH` group as gated by the keymgmt rows, and this is that
//! gate opening for the second time (after `dh_exch.c`): the two rows are fetched by the **keymgmt
//! rows' own names**, `X25519` and `X448`, and the key handed to `init` is the `ECX_KEY` those rows
//! build. Nothing in this unit reaches the curve arithmetic directly, so its own closure is
//! `ossl_ecx_key_up_ref`/`_free`/`ossl_ecx_compute_key` — all landed — plus the key lengths.
//!
//! ## The generated getter is the file's only `FIPS_MODULE` content, and it is absent
//!
//! `ecx_gettable_ctx_params` answers one empty `OSSL_PARAM_END` array and `ecx_get_ctx_params`
//! answers the literal 1 on this profile; the `ecx_get_ctx_params_list`/`_decoder` the generator
//! emits are inside `#ifdef FIPS_MODULE` and are not compiled. They are named here rather than
//! transcribed, and the two `OSSL_FUNC_KEYEXCH_GET[TABLE]_CTX_PARAMS` slots still exist because the
//! authority publishes them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::ecx_key::{
    ossl_ecx_compute_key, ossl_ecx_key_free, ossl_ecx_key_up_ref, EcxKey, X25519_KEYLEN,
    X448_KEYLEN,
};
use crate::evp::exchange::{
    OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX, OSSL_FUNC_KEYEXCH_FREECTX,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX, OSSL_FUNC_KEYEXCH_SET_PEER,
};
use crate::params::{OsslParam, END};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The generated unit's own `__FILE__`. `ecx_exch.c.in` is `.c.in`-generated, so it is the bare
/// build-relative path, exactly as `dh_exch.c.in`'s `FILE_DH_EXCH` is.
const FILE_ECX_EXCH: *const c_char = c"providers/implementations/exchange/ecx_exch.c".as_ptr();

/// `ossl_prov_is_running()` — a `FIPS_MODULE` self-test hook, the literal 1 on this build. Kept as
/// a function for the reason every other provider unit keeps it: so every authority guard is a
/// guard in the transcription.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_ECX_CTX` — `ecx_exch.c:42-46`. The key length selects the curve; both keys are borrows
/// carrying a reference. `Copy` is what lets `ecx_dupctx` transcribe the authority's `*dstctx =
/// *srcctx` as the struct copy it is.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvEcxCtx {
    /// `size_t keylen`.
    keylen: usize,
    /// `ECX_KEY *key`.
    key: *mut EcxKey,
    /// `ECX_KEY *peerkey`.
    peerkey: *mut EcxKey,
}

/// `static void *ecx_newctx(void *provctx, size_t keylen)` — `ecx_exch.c:48-62`.
///
/// # Safety
/// The keyexch `newctx` dispatch contract.
unsafe fn ecx_newctx(_provctx: *mut c_void, keylen: usize) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvEcxCtx>(), FILE_ECX_EXCH, 55).cast::<ProvEcxCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is this call's own allocation.
    unsafe { (*ctx).keylen = keylen };

    ctx.cast()
}

/// `static void *x25519_newctx(void *provctx)` — `ecx_exch.c:64-67`.
///
/// # Safety
/// The keyexch `newctx` dispatch contract.
unsafe extern "C" fn x25519_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { ecx_newctx(provctx, X25519_KEYLEN) }
}

/// `static void *x448_newctx(void *provctx)` — `ecx_exch.c:69-72`.
///
/// # Safety
/// The keyexch `newctx` dispatch contract.
unsafe extern "C" fn x448_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { ecx_newctx(provctx, X448_KEYLEN) }
}

/// `static int ecx_init(void *vecxctx, void *vkey, const char *algname)` — `ecx_exch.c:74-98`.
///
/// The `#ifdef FIPS_MODULE` `ossl_FIPS_IND_callback` tail is not this profile's and is not
/// transcribed, so the function returns 1 where the authority would consult the indicator.
///
/// # Safety
/// The keyexch `init` dispatch contract.
unsafe fn ecx_init(vecxctx: *mut c_void, vkey: *mut c_void, _algname: *const c_char) -> c_int {
    let ecxctx = vecxctx.cast::<ProvEcxCtx>();
    let key = vkey.cast::<EcxKey>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: both objects are the caller's, per the dispatch contract; `key` is read only behind
    // the NULL guard.
    unsafe {
        if ecxctx.is_null()
            || key.is_null()
            || (*key).keylen != (*ecxctx).keylen
            || ossl_ecx_key_up_ref(key) == 0
        {
            raise_site(&err_sites::PROV_ECX_EXCH_86);
            return 0;
        }

        ossl_ecx_key_free((*ecxctx).key);
        (*ecxctx).key = key;
    }
    1
}

/// `static int x25519_init(void *vecxctx, void *vkey, const OSSL_PARAM params[])` —
/// `ecx_exch.c:100-104`.
///
/// # Safety
/// The keyexch `init` dispatch contract.
unsafe extern "C" fn x25519_init(
    vecxctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecx_init(vecxctx, vkey, c"X25519".as_ptr()) }
}

/// `static int x448_init(void *vecxctx, void *vkey, const OSSL_PARAM params[])` —
/// `ecx_exch.c:106-110`.
///
/// # Safety
/// The keyexch `init` dispatch contract.
unsafe extern "C" fn x448_init(
    vecxctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecx_init(vecxctx, vkey, c"X448".as_ptr()) }
}

/// `static int ecx_set_peer(void *vecxctx, void *vkey)` — `ecx_exch.c:112-131`.
///
/// # Safety
/// The keyexch `set_peer` dispatch contract.
unsafe extern "C" fn ecx_set_peer(vecxctx: *mut c_void, vkey: *mut c_void) -> c_int {
    let ecxctx = vecxctx.cast::<ProvEcxCtx>();
    let key = vkey.cast::<EcxKey>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: both objects are the caller's, per the dispatch contract.
    unsafe {
        if ecxctx.is_null()
            || key.is_null()
            || (*key).keylen != (*ecxctx).keylen
            || ossl_ecx_key_up_ref(key) == 0
        {
            raise_site(&err_sites::PROV_ECX_EXCH_124);
            return 0;
        }
        ossl_ecx_key_free((*ecxctx).peerkey);
        (*ecxctx).peerkey = key;
    }
    1
}

/// `static int ecx_derive(void *vecxctx, unsigned char *secret, size_t *secretlen, size_t outlen)`
/// — `ecx_exch.c:133-142`.
///
/// # Safety
/// The keyexch `derive` dispatch contract.
unsafe extern "C" fn ecx_derive(
    vecxctx: *mut c_void,
    secret: *mut u8,
    secretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let ecxctx = vecxctx.cast::<ProvEcxCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: the caller's dispatch contract; `ecxctx`'s members are the caller's keys.
    unsafe {
        ossl_ecx_compute_key(
            (*ecxctx).peerkey,
            (*ecxctx).key,
            (*ecxctx).keylen,
            secret,
            secretlen,
            outlen,
        )
    }
}

/// `static void ecx_freectx(void *vecxctx)` — `ecx_exch.c:144-152`.
///
/// # Safety
/// The keyexch `freectx` dispatch contract.
unsafe extern "C" fn ecx_freectx(vecxctx: *mut c_void) {
    let ecxctx = vecxctx.cast::<ProvEcxCtx>();

    // SAFETY: `ecxctx` is the caller's context, and both keys are released here.
    unsafe {
        ossl_ecx_key_free((*ecxctx).key);
        ossl_ecx_key_free((*ecxctx).peerkey);
        CRYPTO_free(ecxctx.cast(), FILE_ECX_EXCH, 151);
    }
}

/// `static void *ecx_dupctx(void *vecxctx)` — `ecx_exch.c:154-181`.
///
/// # Safety
/// The keyexch `dupctx` dispatch contract.
unsafe extern "C" fn ecx_dupctx(vecxctx: *mut c_void) -> *mut c_void {
    let srcctx = vecxctx.cast::<ProvEcxCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let dstctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvEcxCtx>(), FILE_ECX_EXCH, 162).cast::<ProvEcxCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live or NULL per the contract; the copies are of this call's own
    // allocation.
    unsafe {
        *dstctx = *srcctx;
        if !(*dstctx).key.is_null() && ossl_ecx_key_up_ref((*dstctx).key) == 0 {
            raise_site(&err_sites::PROV_ECX_EXCH_168);
            CRYPTO_free(dstctx.cast(), FILE_ECX_EXCH, 169);
            return ptr::null_mut();
        }

        if !(*dstctx).peerkey.is_null() && ossl_ecx_key_up_ref((*dstctx).peerkey) == 0 {
            raise_site(&err_sites::PROV_ECX_EXCH_174);
            ossl_ecx_key_free((*dstctx).key);
            CRYPTO_free(dstctx.cast(), FILE_ECX_EXCH, 176);
            return ptr::null_mut();
        }
    }

    dstctx.cast()
}

/// The non-`FIPS_MODULE` arm's `static OSSL_PARAM params[] = { OSSL_PARAM_END };` — one entry,
/// returned from `ecx_gettable_ctx_params`.
static ECX_GETTABLE_PARAMS: [OsslParam; 1] = [END];

/// `static const OSSL_PARAM *ecx_gettable_ctx_params(void *vctx, void *provctx)` —
/// `ecx_exch.c:234-244`.
///
/// # Safety
/// The keyexch `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn ecx_gettable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECX_GETTABLE_PARAMS.as_ptr()
}

/// `static int ecx_get_ctx_params(void *vctx, OSSL_PARAM params[])` — `ecx_exch.c:246-259`. The
/// whole body is `#ifdef FIPS_MODULE`, so on this profile it returns 1 unconditionally.
///
/// # Safety
/// The keyexch `get_ctx_params` dispatch contract.
unsafe extern "C" fn ecx_get_ctx_params(_vctx: *mut c_void, _params: *mut OsslParam) -> c_int {
    1
}

/// `const OSSL_DISPATCH ossl_x25519_keyexch_functions[]` — `ecx_exch.c:261-272`. Eight slots, the
/// authority's, in its order.
pub(crate) static X25519_KEYEXCH_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: x25519_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: x25519_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: ecx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_PEER,
        function: ecx_set_peer as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: ecx_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: ecx_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: ecx_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: ecx_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_x448_keyexch_functions[]` — `ecx_exch.c:274-285`. The same eight slots
/// with `newctx` and `init` replaced.
pub(crate) static X448_KEYEXCH_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: x448_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: x448_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: ecx_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_PEER,
        function: ecx_set_peer as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: ecx_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: ecx_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: ecx_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: ecx_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
