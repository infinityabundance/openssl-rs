//! Phase 8 — `providers/implementations/keymgmt/slh_dsa_kmgmt.c`: the twelve SLH-DSA keymgmt rows.
//!
//! Five hundred and one source lines and one macro that expands twelve times, publishing the twelve
//! `SLH-DSA-*` rows of `deflt_keymgmt[]`. Every row's table is the same nineteen slots; only
//! `NEW` and `GEN` differ, because each carries its own algorithm name into
//! `ossl_slh_dsa_key_new`/`ossl_slh_dsa_generate_key`.
//!
//! ## The generated decoders are written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for each `produce_param_decoder` block, a nested
//! character-by-character `switch` over the parameter's key. Its whole observable content is the
//! **repeated-key refusal** — an `ERR_raise_data(..., PROV_R_REPEATED_PARAMETER, ...)` at the
//! parameter's own coordinate — plus the located pointer this unit's body reads. The two decoders
//! here are the repeated-key scan plus `OSSL_PARAM_locate_const` per key, the shape
//! `src/provider/ecx_kmgmt.rs` and `src/provider/exchange.rs` already use for theirs.
//!
//! ## `slh_dsa_gen_init` passes a NULL context into `slh_dsa_gen_set_params`'s failure path
//!
//! Unlike `dsa_gen_init`, the authority tests the allocation **before** calling the setter
//! (`slh_dsa_kmgmt.c.in:297-303`), so the NULL-into-setter path D388 recorded for DSA does not
//! arise here. It is written the authority's way.
//!
//! ## The `FIPS_MODULE` pairwise test is not compiled on this profile
//!
//! `slh_dsa_fips140_pairwise_test` (`:312-369`) is inside `#ifdef FIPS_MODULE`, so it is recorded
//! with its coordinate and not written: the crate's default provider is not a FIPS module, and
//! `slh_dsa_gen`'s call to it is inside the same guard.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The twelve tables share one body; each is a transcription of the same authority macro expansion.
#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey::{
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::param_build_set::ossl_param_build_set_octet_string;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string, OsslParam, END,
    OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::selftest::OsslCallback;
use crate::slh_dsa::hash_ctx::{ossl_slh_dsa_hash_ctx_free, ossl_slh_dsa_hash_ctx_new};
use crate::slh_dsa::key::{
    ossl_slh_dsa_generate_key, ossl_slh_dsa_key_dup, ossl_slh_dsa_key_equal, ossl_slh_dsa_key_free,
    ossl_slh_dsa_key_fromdata, ossl_slh_dsa_key_get_n, ossl_slh_dsa_key_get_priv,
    ossl_slh_dsa_key_get_priv_len, ossl_slh_dsa_key_get_pub, ossl_slh_dsa_key_get_pub_len,
    ossl_slh_dsa_key_get_security_category, ossl_slh_dsa_key_get_sig_len, ossl_slh_dsa_key_has,
    ossl_slh_dsa_key_new, ossl_slh_dsa_key_pairwise_check,
};
use crate::slh_dsa::{SlhDsaKey, SLH_DSA_MAX_N};

/// `OSSL_PKEY_PARAM_BITS` — `core_names.h` (spelled `OSSL_ALG_PARAM_BITS` there).
const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h`.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE` — `core_names.h`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — `core_names.h`, spelled `OSSL_ALG_PARAM_SECURITY_CATEGORY`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_MANDATORY_DIGEST` — `core_names.h`.
const OSSL_PKEY_PARAM_MANDATORY_DIGEST: *const c_char = c"mandatory-digest".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_SLH_DSA_SEED` — `core_names.h:497`.
const OSSL_PKEY_PARAM_SLH_DSA_SEED: *const c_char = c"seed".as_ptr();

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// The pair is **imported** from `src/evp/pkey.rs` rather than re-spelled. This unit used to
/// carry its own copies at `0x02`/`0x04`, one bit left of `core_dispatch.h:640-641`, so its
/// `has`/`export`/`dup` columns were called with the wrong selection bits (D402).
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
/// `SLH_DSA_POSSIBLE_SELECTIONS` — `slh_dsa_kmgmt.c:50`.
const SLH_DSA_POSSIBLE_SELECTIONS: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;

/// The unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/keymgmt/slh_dsa_kmgmt.c".as_ptr();
/// `slh_dsa_kmgmt.c:297`, the `OPENSSL_zalloc(sizeof(*gctx))` in `slh_dsa_gen_init`.
const LINE_ZALLOC_GCTX: c_int = 297;
/// `slh_dsa_kmgmt.c:111`, the `OPENSSL_strdup(p.propq->data)` in `slh_dsa_gen_set_params`.
const LINE_STRDUP_PROPQ: c_int = 111;
/// `slh_dsa_kmgmt.c:300`, the `OPENSSL_free(gctx)` in `slh_dsa_gen_init`'s failure path.
const LINE_FREE_GCTX: c_int = 300;
/// `slh_dsa_kmgmt.c:452`, the `OPENSSL_free(gctx->propq)` sites.
const LINE_FREE_PROPQ: c_int = 452;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `struct slh_dsa_gen_ctx` — `slh_dsa_kmgmt.c:52-58`.
///
/// `ctx` is the FIPS pairwise test's cached hash context; it is NULL on this profile because the
/// only writer is inside `#ifdef FIPS_MODULE`, so it is carried for the struct's shape rather than
/// read.
#[repr(C)]
struct SlhDsaGenCtx {
    ctx: *mut c_void,
    libctx: *mut c_void,
    propq: *mut c_char,
    entropy: [u8; SLH_DSA_MAX_N * 3],
    entropy_len: usize,
}

/// `static void *slh_dsa_new_key(void *provctx, const char *alg)` — `slh_dsa_kmgmt.c:60-66`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe fn slh_dsa_new_key(provctx: *mut c_void, alg: *const c_char) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's context and `alg` is NUL-terminated.
    unsafe { ossl_slh_dsa_key_new(prov_libctx_of(provctx), ptr::null(), alg).cast() }
}

/// `static void slh_dsa_free_key(void *keydata)` — `slh_dsa_kmgmt.c:68-71`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn slh_dsa_free_key(keydata: *mut c_void) {
    // SAFETY: `keydata` is NULL or the caller's key.
    unsafe { ossl_slh_dsa_key_free(keydata.cast::<SlhDsaKey>()) };
}

/// `static void *slh_dsa_dup_key(const void *keydata_from, int selection)` —
/// `slh_dsa_kmgmt.c:73-78`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn slh_dsa_dup_key(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract, forwarded.
        return unsafe { ossl_slh_dsa_key_dup(keydata_from.cast::<SlhDsaKey>(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `static int slh_dsa_has(const void *keydata, int selection)` — `slh_dsa_kmgmt.c:80-90`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn slh_dsa_has(keydata: *const c_void, selection: c_int) -> c_int {
    let key = keydata.cast::<SlhDsaKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* the selection is not missing */
    }
    // SAFETY: `key` is non-NULL past the guard.
    unsafe { ossl_slh_dsa_key_has(key, selection) }
}

/// `static int slh_dsa_match(const void *keydata1, const void *keydata2, int selection)` —
/// `slh_dsa_kmgmt.c:92-102`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn slh_dsa_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let key1 = keydata1.cast::<SlhDsaKey>();
    let key2 = keydata2.cast::<SlhDsaKey>();

    if is_running() == 0 || key1.is_null() || key2.is_null() {
        return 0;
    }
    // SAFETY: both keys are non-NULL past the guard.
    unsafe { ossl_slh_dsa_key_equal(key1, key2, selection) }
}

/// `static int slh_dsa_validate(const void *key_data, int selection, int check_type)` —
/// `slh_dsa_kmgmt.c:104-114`.
///
/// `check_type` is unused by the authority.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn slh_dsa_validate(
    key_data: *const c_void,
    selection: c_int,
    _check_type: c_int,
) -> c_int {
    // SAFETY: `key_data` is the caller's key.
    unsafe {
        if slh_dsa_has(key_data, selection) == 0 {
            return 0;
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            return ossl_slh_dsa_key_pairwise_check(key_data.cast::<SlhDsaKey>());
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The generated decoders — `paramnames.pm`'s repeated-key walk, written the crate's way.
// ---------------------------------------------------------------------------------------------

/// The repeated-key scan the three generated decoders share — the observable content of
/// `paramnames.pm`'s nested key walk.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn slh_dsa_repeated_param_site(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the array is key-terminated per the contract; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = core::ffi::CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if core::ffi::CStr::from_ptr(*name).to_bytes() == k {
                    let bit = 1u32 << i;
                    if seen & bit != 0 {
                        return Some(site);
                    }
                    seen |= bit;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
}

/// `static const OSSL_PARAM slh_dsa_import_list[]` — generated `slh_dsa_kmgmt.c:117-120`.
static SLH_DSA_IMPORT_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `struct slh_dsa_import_st` — generated `slh_dsa_kmgmt.c:125-128`.
struct SlhDsaImport {
    priv_: *const OsslParam,
    pub_: *const OsslParam,
}

/// The import decoder's repeated-key coordinates — generated `slh_dsa_kmgmt.c:151/162`.
const SLH_DSA_IMPORT_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_SLH_DSA_KMGMT_151, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_SLH_DSA_KMGMT_162, OSSL_PKEY_PARAM_PUB_KEY),
];

/// `slh_dsa_import_decoder` — generated `slh_dsa_kmgmt.c:132-174`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn slh_dsa_import_decoder(params: *const OsslParam, r: &mut SlhDsaImport) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = slh_dsa_repeated_param_site(params, &SLH_DSA_IMPORT_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.priv_ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        r.pub_ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    }
    1
}

/// `static int slh_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `slh_dsa_kmgmt.c:176-192`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn slh_dsa_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = keydata.cast::<SlhDsaKey>();
    let mut p = SlhDsaImport {
        priv_: ptr::null(),
        pub_: ptr::null(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if is_running() == 0 || key.is_null() || slh_dsa_import_decoder(params, &mut p) == 0 {
            return 0;
        }
        if (selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0 {
            return 0;
        }
        let include_priv = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
        ossl_slh_dsa_key_fromdata(key, p.pub_, p.priv_, include_priv)
    }
}

/// `static const OSSL_PARAM *slh_dsa_imexport_types(int selection)` —
/// `slh_dsa_kmgmt.c:194-200`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn slh_dsa_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0 {
        return ptr::null();
    }
    SLH_DSA_IMPORT_LIST.as_ptr()
}

/// `static const OSSL_PARAM slh_dsa_get_params_list[]` — generated `slh_dsa_kmgmt.c:204-212`.
static SLH_DSA_GET_PARAMS_LIST: [OsslParam; 8] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `struct slh_dsa_get_params_st` — generated `slh_dsa_kmgmt.c:217-225`.
struct SlhDsaGetParams {
    bits: *mut OsslParam,
    secbits: *mut OsslParam,
    maxsize: *mut OsslParam,
    seccat: *mut OsslParam,
    mandgst: *mut OsslParam,
    pub_: *mut OsslParam,
    priv_: *mut OsslParam,
}

/// The get-params decoder's repeated-key coordinates — generated `slh_dsa_kmgmt.c:244/263/274/291/302/350/361`.
const SLH_DSA_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_SLH_DSA_KMGMT_244, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_SLH_DSA_KMGMT_263,
        OSSL_PKEY_PARAM_MANDATORY_DIGEST,
    ),
    (&err_sites::PROV_SLH_DSA_KMGMT_274, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_SLH_DSA_KMGMT_291, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_SLH_DSA_KMGMT_302, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_SLH_DSA_KMGMT_350,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_SLH_DSA_KMGMT_361,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
];

/// `slh_dsa_get_params_decoder` — generated `slh_dsa_kmgmt.c:229-382`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn slh_dsa_get_params_decoder(params: *const OsslParam, r: &mut SlhDsaGetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = slh_dsa_repeated_param_site(params, &SLH_DSA_GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS).cast_mut();
        r.secbits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS).cast_mut();
        r.maxsize = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE).cast_mut();
        r.seccat = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY).cast_mut();
        r.mandgst = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST).cast_mut();
        r.pub_ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY).cast_mut();
        r.priv_ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY).cast_mut();
    }
    1
}

/// `static const OSSL_PARAM *slh_dsa_gettable_params(void *provctx)` —
/// `slh_dsa_kmgmt.c:383-386`.
///
/// `provctx` is unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn slh_dsa_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    SLH_DSA_GET_PARAMS_LIST.as_ptr()
}

/// `static int key_to_params(SLH_DSA_KEY *key, OSSL_PARAM_BLD *tmpl, int selection)` —
/// `slh_dsa_kmgmt.c:388-411`.
///
/// # Safety
/// `key` is NULL or live; `tmpl` is the caller's builder.
unsafe fn key_to_params(key: *mut SlhDsaKey, tmpl: *mut OSSL_PARAM_BLD, selection: c_int) -> c_int {
    // SAFETY: `key` is NULL or live per the contract.
    unsafe {
        /* Error if there is no key or public key. */
        if key.is_null() || ossl_slh_dsa_key_get_pub(key).is_null() {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && !ossl_slh_dsa_key_get_priv(key).is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                ptr::null_mut(),
                OSSL_PKEY_PARAM_PRIV_KEY,
                ossl_slh_dsa_key_get_priv(key),
                ossl_slh_dsa_key_get_priv_len(key),
            ) != 1
        {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 {
            return 1;
        }

        ossl_param_build_set_octet_string(
            tmpl,
            ptr::null_mut(),
            OSSL_PKEY_PARAM_PUB_KEY,
            ossl_slh_dsa_key_get_pub(key),
            ossl_slh_dsa_key_get_pub_len(key),
        )
    }
}

/// `static int slh_dsa_get_params(void *keydata, OSSL_PARAM params[])` —
/// `slh_dsa_kmgmt.c:413-457`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn slh_dsa_get_params(keydata: *mut c_void, params: *mut OsslParam) -> c_int {
    let key = keydata.cast::<SlhDsaKey>();
    let mut p = SlhDsaGetParams {
        bits: ptr::null_mut(),
        secbits: ptr::null_mut(),
        maxsize: ptr::null_mut(),
        seccat: ptr::null_mut(),
        mandgst: ptr::null_mut(),
        pub_: ptr::null_mut(),
        priv_: ptr::null_mut(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if key.is_null() || slh_dsa_get_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.bits.is_null()
            && OSSL_PARAM_set_size_t(p.bits, 8 * ossl_slh_dsa_key_get_pub_len(key)) == 0
        {
            return 0;
        }
        if !p.secbits.is_null()
            && OSSL_PARAM_set_size_t(p.secbits, 8 * ossl_slh_dsa_key_get_n(key)) == 0
        {
            return 0;
        }
        if !p.maxsize.is_null()
            && OSSL_PARAM_set_size_t(p.maxsize, ossl_slh_dsa_key_get_sig_len(key)) == 0
        {
            return 0;
        }
        if !p.seccat.is_null()
            && OSSL_PARAM_set_int(p.seccat, ossl_slh_dsa_key_get_security_category(key)) == 0
        {
            return 0;
        }

        let priv_ = ossl_slh_dsa_key_get_priv(key);
        if !priv_.is_null() && !p.priv_.is_null() {
            /* Note: `ossl_slh_dsa_key_get_priv_len()` includes the public key. */
            if OSSL_PARAM_set_octet_string(
                p.priv_,
                priv_.cast(),
                ossl_slh_dsa_key_get_priv_len(key),
            ) == 0
            {
                return 0;
            }
        }
        let pub_ = ossl_slh_dsa_key_get_pub(key);
        if !pub_.is_null()
            && !p.pub_.is_null()
            && OSSL_PARAM_set_octet_string(p.pub_, pub_.cast(), ossl_slh_dsa_key_get_pub_len(key))
                == 0
        {
            return 0;
        }
        /*
         * This allows apps to use an empty digest, so that the old API for digest signing can be
         * used.
         */
        if !p.mandgst.is_null() && OSSL_PARAM_set_utf8_string(p.mandgst, c"".as_ptr()) == 0 {
            return 0;
        }
    }
    1
}

/// `static int slh_dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,`
/// `void *cbarg)` — `slh_dsa_kmgmt.c:459-495`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn slh_dsa_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = keydata.cast::<SlhDsaKey>();
    let mut ret: c_int = 0;

    if is_running() == 0 || key.is_null() {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `key` is live; `tmpl` is this call's own builder.
    unsafe {
        if key_to_params(key, tmpl, selection) == 0 {
            /* The authority's `err:` label. */
            OSSL_PARAM_BLD_free(tmpl);
            return ret;
        }

        let params = OSSL_PARAM_BLD_to_param(tmpl);
        if params.is_null() {
            OSSL_PARAM_BLD_free(tmpl);
            return ret;
        }

        ret = match param_cb {
            Some(cb) => cb(params, cbarg),
            None => 0,
        };
        /*
         * `OSSL_PARAM_free()` only wipes the secure-heap data block, so wipe the key material
         * copies held in the params first.
         */
        let mut p = params;
        while !(*p).key.is_null() {
            OPENSSL_cleanse((*p).data, (*p).data_size);
            p = p.add(1);
        }
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(tmpl);
    }
    ret
}

/// `static void *slh_dsa_load(const void *reference, size_t reference_sz)` —
/// `slh_dsa_kmgmt.c:497-509`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn slh_dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut SlhDsaKey>() {
        // SAFETY: `reference` is readable for the object's size per the contract.
        return unsafe {
            /* The contents of the reference is the address to our object. */
            let key = *(reference as *const *mut SlhDsaKey);
            /* We grabbed, so we detach it. */
            *(reference as *mut *mut SlhDsaKey) = ptr::null_mut();
            key.cast()
        };
    }
    ptr::null_mut()
}

/// `static void *slh_dsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `slh_dsa_kmgmt.c:511-528`.
///
/// `selection` is unused by the authority.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn slh_dsa_gen_init(
    provctx: *mut c_void,
    _selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `provctx` is the caller's context.
    let libctx = unsafe { prov_libctx_of(provctx) };

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_zalloc` answers a zeroed block or NULL.
    let gctx = CRYPTO_zalloc(core::mem::size_of::<SlhDsaGenCtx>(), FILE, LINE_ZALLOC_GCTX)
        .cast::<SlhDsaGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is a fresh zeroed block this call owns.
        unsafe {
            (*gctx).libctx = libctx;
            if slh_dsa_gen_set_params(gctx.cast(), params) == 0 {
                CRYPTO_free(gctx.cast(), FILE, LINE_FREE_GCTX);
                return ptr::null_mut();
            }
        }
    }
    gctx.cast()
}

/// `static void *slh_dsa_gen(void *genctx, const char *alg)` — `slh_dsa_kmgmt.c:595-616`.
///
/// The FIPS pairwise test's call is inside `#ifdef FIPS_MODULE` and is not compiled here.
///
/// # Safety
/// `genctx` is the caller's generator context; `alg` is NUL-terminated.
unsafe fn slh_dsa_gen(genctx: *mut c_void, alg: *const c_char) -> *mut c_void {
    let gctx = genctx.cast::<SlhDsaGenCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `gctx` is the caller's context.
    let key = unsafe { ossl_slh_dsa_key_new((*gctx).libctx, (*gctx).propq, alg) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `key` is live.
    let ctx = unsafe { ossl_slh_dsa_hash_ctx_new(key) };
    if ctx.is_null() {
        // SAFETY: `key` is this call's own.
        unsafe { ossl_slh_dsa_key_free(key) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live; `key` is this call's own and `gctx` the caller's.
    let ok = unsafe {
        ossl_slh_dsa_generate_key(
            ctx,
            key,
            (*gctx).libctx,
            (*gctx).entropy.as_ptr(),
            (*gctx).entropy_len,
        )
    };
    // SAFETY: `ctx` is this call's own.
    unsafe { ossl_slh_dsa_hash_ctx_free(ctx) };
    if ok == 0 {
        // SAFETY: `key` is this call's own.
        unsafe { ossl_slh_dsa_key_free(key) };
        return ptr::null_mut();
    }
    key.cast()
}

/// `static const OSSL_PARAM slh_dsa_gen_set_params_list[]` — generated
/// `slh_dsa_kmgmt.c:627-631`.
static SLH_DSA_GEN_SET_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    param_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED),
    END,
];

/// `struct slh_dsa_gen_set_params_st` — generated `slh_dsa_kmgmt.c:635-638`.
struct SlhDsaGenSetParams {
    propq: *mut OsslParam,
    seed: *mut OsslParam,
}

/// The gen-set-params decoder's repeated-key coordinates — generated
/// `slh_dsa_kmgmt.c:657/668`.
const SLH_DSA_GEN_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (
        &err_sites::PROV_SLH_DSA_KMGMT_657,
        OSSL_PKEY_PARAM_PROPERTIES,
    ),
    (
        &err_sites::PROV_SLH_DSA_KMGMT_668,
        OSSL_PKEY_PARAM_SLH_DSA_SEED,
    ),
];

/// `slh_dsa_gen_set_params_decoder` — generated `slh_dsa_kmgmt.c:642-678`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn slh_dsa_gen_set_params_decoder(
    params: *const OsslParam,
    r: &mut SlhDsaGenSetParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) =
            slh_dsa_repeated_param_site(params, &SLH_DSA_GEN_SET_PARAMS_DECODER_KEYS)
        {
            raise_site(site);
            return 0;
        }
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES).cast_mut();
        r.seed = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SLH_DSA_SEED).cast_mut();
    }
    1
}

/// `static int slh_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `slh_dsa_kmgmt.c:681-708`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn slh_dsa_gen_set_params(
    genctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let gctx = genctx.cast::<SlhDsaGenCtx>();
    let mut p = SlhDsaGenSetParams {
        propq: ptr::null_mut(),
        seed: ptr::null_mut(),
    };

    // SAFETY: `gctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if gctx.is_null() || slh_dsa_gen_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.seed.is_null() {
            let mut vp: *mut c_void = (*gctx).entropy.as_mut_ptr().cast();
            let len = (*gctx).entropy.len();
            if OSSL_PARAM_get_octet_string(p.seed, &mut vp, len, &mut (*gctx).entropy_len) == 0 {
                (*gctx).entropy_len = 0;
                return 0;
            }
        }

        if !p.propq.is_null() {
            if (*p.propq).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).propq.cast(), FILE, LINE_FREE_PROPQ);
            (*gctx).propq =
                CRYPTO_strdup((*p.propq).data.cast::<c_char>(), FILE, LINE_STRDUP_PROPQ);
            if (*gctx).propq.is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *slh_dsa_gen_settable_params(void *genctx, void *provctx)` —
/// `slh_dsa_kmgmt.c:710-714`.
///
/// Both arguments are unused by the authority.
///
/// # Safety
/// Takes no live pointers it reads.
unsafe extern "C" fn slh_dsa_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    SLH_DSA_GEN_SET_PARAMS_LIST.as_ptr()
}

/// `static void slh_dsa_gen_cleanup(void *genctx)` — `slh_dsa_kmgmt.c:716-726`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn slh_dsa_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<SlhDsaGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's live context.
    unsafe {
        OPENSSL_cleanse((*gctx).entropy.as_mut_ptr().cast(), (*gctx).entropy.len());
        CRYPTO_free((*gctx).propq.cast(), FILE, LINE_FREE_PROPQ);
        CRYPTO_free(gctx.cast(), FILE, LINE_ZALLOC_GCTX);
    }
}

/// `MAKE_KEYMGMT_FUNCTIONS(alg, fn)` — `slh_dsa_kmgmt.c:455-488`, once per parameter set.
///
/// Each expansion differs in the algorithm name and in the two per-algorithm callbacks
/// (`slh_dsa_<fn>_new_key` and `slh_dsa_<fn>_gen`); every other slot is one of the shared
/// functions above.
///
/// **The name is passed as a NUL-terminated C string, not as a Rust `&str`.** `$alg.as_ptr()`
/// points into a `str` literal, which carries no terminator, and `ossl_slh_dsa_params_get`
/// compares with a `strcmp`-style `cstr_eq` — so the pointer would read past the literal, never
/// match, and make `ossl_slh_dsa_key_new` refuse every generation. `concat!($alg, "\0")` is what
/// supplies the terminator, and it is the same byte string the authority's
/// `MAKE_KEYMGMT_FUNCTIONS("SLH-DSA-...", fn)` macro passes. This was found by `RT-KEYMGMT`'s
/// probe: the candidate's generation answered `0` where the authority's answered `1`, and every
/// row's `fetch`, `keygen_init` and `set_seed` had already agreed.
macro_rules! make_keymgmt_functions {
    ($table:ident, $alg:literal, $fn_new:ident, $fn_gen:ident) => {
        /// `static void *slh_dsa_<fn>_new_key(void *provctx)` — one macro expansion's new.
        ///
        /// # Safety
        /// The keymgmt `new` dispatch contract.
        unsafe extern "C" fn $fn_new(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: the caller's contract, forwarded with this expansion's algorithm name,
            // which `concat!` has already given its terminator.
            unsafe { slh_dsa_new_key(provctx, concat!($alg, "\0").as_ptr().cast::<c_char>()) }
        }

        /// `static void *slh_dsa_<fn>_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
        /// one macro expansion's gen.
        ///
        /// # Safety
        /// The keymgmt `gen` dispatch contract.
        unsafe extern "C" fn $fn_gen(
            genctx: *mut c_void,
            _osslcb: Option<OsslCallback>,
            _cbarg: *mut c_void,
        ) -> *mut c_void {
            // SAFETY: the caller's contract, forwarded with this expansion's algorithm name,
            // which `concat!` has already given its terminator.
            unsafe { slh_dsa_gen(genctx, concat!($alg, "\0").as_ptr().cast::<c_char>()) }
        }

        /// `const OSSL_DISPATCH ossl_slh_dsa_<fn>_keymgmt_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 19] = [
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_NEW,
                function: $fn_new as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_FREE,
                function: slh_dsa_free_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_DUP,
                function: slh_dsa_dup_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_HAS,
                function: slh_dsa_has as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_MATCH,
                function: slh_dsa_match as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT,
                function: slh_dsa_import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
                function: slh_dsa_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT,
                function: slh_dsa_export as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
                function: slh_dsa_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_LOAD,
                function: slh_dsa_load as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
                function: slh_dsa_get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
                function: slh_dsa_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
                function: slh_dsa_validate as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
                function: slh_dsa_gen_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN,
                function: $fn_gen as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
                function: slh_dsa_gen_cleanup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
                function: slh_dsa_gen_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                function: slh_dsa_gen_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

make_keymgmt_functions!(
    SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-128s",
    slh_dsa_sha2_128s_new_key,
    slh_dsa_sha2_128s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-128f",
    slh_dsa_sha2_128f_new_key,
    slh_dsa_sha2_128f_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-192s",
    slh_dsa_sha2_192s_new_key,
    slh_dsa_sha2_192s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-192f",
    slh_dsa_sha2_192f_new_key,
    slh_dsa_sha2_192f_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-256s",
    slh_dsa_sha2_256s_new_key,
    slh_dsa_sha2_256s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHA2-256f",
    slh_dsa_sha2_256f_new_key,
    slh_dsa_sha2_256f_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-128s",
    slh_dsa_shake_128s_new_key,
    slh_dsa_shake_128s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-128f",
    slh_dsa_shake_128f_new_key,
    slh_dsa_shake_128f_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-192s",
    slh_dsa_shake_192s_new_key,
    slh_dsa_shake_192s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-192f",
    slh_dsa_shake_192f_new_key,
    slh_dsa_shake_192f_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-256s",
    slh_dsa_shake_256s_new_key,
    slh_dsa_shake_256s_gen
);
make_keymgmt_functions!(
    SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    "SLH-DSA-SHAKE-256f",
    slh_dsa_shake_256f_new_key,
    slh_dsa_shake_256f_gen
);
