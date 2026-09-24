//! Phase 8.10 — `providers/implementations/keymgmt/mac_legacy_kmgmt.c`: the four legacy MAC key
//! types.
//!
//! Five hundred and sixty-nine lines, thirty functions and two dispatch tables. The unit publishes
//! four rows: `HMAC`, `SIPHASH` and `POLY1305` share `ossl_mac_legacy_keymgmt_functions` and `CMAC`
//! is `ossl_cmac_legacy_keymgmt_functions` — the many-to-one association the census's partition
//! equality describes rather than refuses (D386). The object is `MAC_KEY`
//! (`prov/macsignature.h:19`): a library context, a reference count, a secure private key, a
//! `PROV_CIPHER` and a property query. There is no public key and no real key generation — the
//! authority's own comment calls `mac_gen` "horrible but required for backwards compatibility",
//! copying the key the caller set in the generator context.
//!
//! ## The one `#if !defined(OPENSSL_NO_ENGINE)` arm, reduced the way D181 reduces that family
//!
//! `key_to_params`'s engine block (`:253-259`) is **compiled in** on this profile — D181 measured
//! `OPENSSL_NO_ENGINE` as undefined — and reads `ENGINE_get_id(key->cipher.engine)`. `ENGINE` is
//! Phase 13's and this crate has no engine type or registry, so `PROV_CIPHER.engine`
//! (`src/provider/util.rs`) can **only** ever be NULL and the block's guard is unreachable in the
//! only state the crate can reach. It is therefore not emitted, with its reason written at the
//! site, which is the same shape `ossl_prov_cipher_reset`'s `ENGINE_finish` note and D181's two
//! `ameth_lib.c` arms take: the call is absent **because its guard is false in every reachable
//! state**, not because the unit was dropped.
//!
//! ## What this unit depends on, and one allow it discharges
//!
//! `ossl_prov_cipher_load_from_params` (`src/provider/util.rs`) — landed with `#![allow(dead_code)]`
//! and a note naming the provider rows that would call it — gets its first caller here, and the
//! allow is removed with it. `ossl_prov_cipher_reset`/`_copy` were already live callers.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{fence, AtomicI32, Ordering};

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::{EVP_CIPHER_get0_name, EVP_CIPHER_is_a};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT,
    OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS,
};
use crate::param_build_set::{ossl_param_build_set_octet_string, ossl_param_build_set_utf8_string};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_locate_const, OsslParam, END, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::util::{
    ossl_prov_cipher_copy, ossl_prov_cipher_load_from_params, ossl_prov_cipher_reset, ProvCipher,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memcmp, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// The constants — `core_names.h` and `core_dispatch.h`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_PKEY_PARAM_PRIV_KEY` — `core_names.h:439`.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h:440`, the value of `OSSL_ALG_PARAM_PROPERTIES`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_CIPHER` — `core_names.h:367`, the value of `OSSL_ALG_PARAM_CIPHER`.
const OSSL_PKEY_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();
/// `OSSL_PKEY_PARAM_ENGINE` — `core_names.h:399`, the value of `OSSL_ALG_PARAM_ENGINE`.
const OSSL_PKEY_PARAM_ENGINE: *const c_char = c"engine".as_ptr();

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640-652`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x03;

/// The unit's own `__FILE__`. `mac_legacy_kmgmt.c` is a plain `.c`, so it carries the source-tree
/// prefix, as the crate's own `../../src/openssl-3.6.4/` spelling does.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/keymgmt/mac_legacy_kmgmt.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `MAC_KEY` — `prov/macsignature.h:19-27`. A legacy MAC key is a secure private key plus, for
/// `CMAC`, the cipher it names.
#[repr(C)]
pub struct MacKey {
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `CRYPTO_REF_COUNT refcnt` — `_Atomic int` on this profile.
    pub refcnt: AtomicI32,
    /// `unsigned char *priv_key` — a secure allocation.
    pub priv_key: *mut u8,
    /// `size_t priv_key_len`.
    pub priv_key_len: usize,
    /// `PROV_CIPHER cipher`.
    pub cipher: ProvCipher,
    /// `char *properties` — owned.
    pub properties: *mut c_char,
    /// `int cmac`.
    pub cmac: c_int,
}

/// `MAC_KEY *ossl_mac_key_new(OSSL_LIB_CTX *libctx, int cmac)` — `mac_legacy_kmgmt.c:64-83`.
///
/// `prov/macsignature.h` declares it and `signature/mac_legacy.c` links to it across translation
/// units, so it is a `#[no_mangle]` export here as `ossl_kdf_data_new` is.
///
/// # Safety
/// `libctx` is NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn ossl_mac_key_new(libctx: *mut c_void, cmac: c_int) -> *mut MacKey {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    let mackey = CRYPTO_zalloc(core::mem::size_of::<MacKey>(), FILE, 71).cast::<MacKey>();
    if mackey.is_null() {
        return ptr::null_mut();
    }

    // `CRYPTO_NEW_REF(&mackey->refcnt, 1)` — the header's fallback arm on this profile stores 1 and
    // answers 1, so its failure branch (and its `OPENSSL_free`) is unreachable rather than omitted.
    // SAFETY: `refcnt` is a field of this call's own allocation.
    unsafe { (*mackey).refcnt.store(1, Ordering::Relaxed) };
    // SAFETY: as above.
    unsafe {
        (*mackey).libctx = libctx;
        (*mackey).cmac = cmac;
    }

    mackey
}

/// `void ossl_mac_key_free(MAC_KEY *mackey)` — `mac_legacy_kmgmt.c:85-101`.
///
/// # Safety
/// `mackey` is NULL or a live handle; it must not be used again unless a reference remains.
#[no_mangle]
pub unsafe extern "C" fn ossl_mac_key_free(mackey: *mut MacKey) {
    if mackey.is_null() {
        return;
    }

    // SAFETY: `mackey` is live per the contract.
    let ref_ = unsafe { (*mackey).refcnt.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if ref_ == 0 {
        fence(Ordering::Acquire);
    }
    if ref_ > 0 {
        return;
    }

    // SAFETY: this is the last reference.
    unsafe {
        CRYPTO_secure_clear_free((*mackey).priv_key.cast(), (*mackey).priv_key_len, FILE, 96);
        CRYPTO_free((*mackey).properties.cast(), FILE, 97);
        ossl_prov_cipher_reset(&raw mut (*mackey).cipher);
        // `CRYPTO_FREE_REF(&mackey->refcnt)` is empty on this profile's arm of the header.
        CRYPTO_free(mackey.cast(), FILE, 100);
    }
}

/// `int ossl_mac_key_up_ref(MAC_KEY *mackey)` — `mac_legacy_kmgmt.c:103-119`.
///
/// # Safety
/// `mackey` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_mac_key_up_ref(mackey: *mut MacKey) -> c_int {
    if is_running() == 0 {
        return 0;
    }

    // `CRYPTO_UP_REF` is a relaxed fetch-add.
    // SAFETY: `mackey` is live per the contract.
    unsafe { (*mackey).refcnt.fetch_add(1, Ordering::Relaxed) };
    1
}

/// `static void *mac_new(void *provctx)` — `mac_legacy_kmgmt.c:121-124`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn mac_new(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    unsafe { ossl_mac_key_new(prov_libctx_of(provctx), 0).cast() }
}

/// `static void *mac_new_cmac(void *provctx)` — `mac_legacy_kmgmt.c:126-129`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn mac_new_cmac(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    unsafe { ossl_mac_key_new(prov_libctx_of(provctx), 1).cast() }
}

/// `static void mac_free(void *mackey)` — `mac_legacy_kmgmt.c:131-134`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn mac_free(mackey: *mut c_void) {
    // SAFETY: the caller hands back what `mac_new`/`mac_new_cmac` answered.
    unsafe { ossl_mac_key_free(mackey.cast()) };
}

/// `static int mac_has(const void *keydata, int selection)` — `mac_legacy_kmgmt.c:136-153`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn mac_has(keydata: *const c_void, selection: c_int) -> c_int {
    let key = keydata.cast::<MacKey>();
    let mut ok: c_int = 0;

    if is_running() != 0 && !key.is_null() {
        /*
         * MAC keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         * Similarly for public keys.
         */
        ok = 1;

        // SAFETY: `key` is non-NULL past the guard.
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            // SAFETY: as above; the field is read, not written.
            ok = c_int::from(!unsafe { (*key).priv_key }.is_null());
        }
    }
    ok
}

/// `static int mac_match(const void *keydata1, const void *keydata2, int selection)` —
/// `mac_legacy_kmgmt.c:155-178`.
///
/// The first clause compares the two private keys' *presence* and lengths, and the tail asks
/// whether the first key's cipher is one of the second's names — the asymmetry is the authority's.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn mac_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let key1 = keydata1.cast::<MacKey>();
    let key2 = keydata2.cast::<MacKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the two objects are the caller's, per the dispatch contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            if ((*key1).priv_key.is_null() && !(*key2).priv_key.is_null())
                || (!(*key1).priv_key.is_null() && (*key2).priv_key.is_null())
                || (*key1).priv_key_len != (*key2).priv_key_len
                || ((*key1).cipher.cipher.is_null() && !(*key2).cipher.cipher.is_null())
                || (!(*key1).cipher.cipher.is_null() && (*key2).cipher.cipher.is_null())
            {
                ok = 0;
            } else {
                ok &= c_int::from(
                    (*key1).priv_key.is_null() /* implies key2->privkey == NULL */
                        || CRYPTO_memcmp(
                            (*key1).priv_key.cast(),
                            (*key2).priv_key.cast(),
                            (*key1).priv_key_len,
                        ) == 0,
                );
            }
            if !(*key1).cipher.cipher.is_null() {
                ok &= EVP_CIPHER_is_a(
                    (*key1).cipher.cipher,
                    EVP_CIPHER_get0_name((*key2).cipher.cipher),
                );
            }
        }
    }
    ok
}

/// `static int mac_key_fromdata(MAC_KEY *key, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:180-220`.
///
/// # Safety
/// `key` is live; `params` is NULL or key-terminated.
unsafe fn mac_key_fromdata(key: *mut MacKey, params: *const OsslParam) -> c_int {
    // SAFETY: `key` is live and `params` is the caller's array.
    unsafe {
        let mut p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_187);
                return 0;
            }
            CRYPTO_secure_clear_free((*key).priv_key.cast(), (*key).priv_key_len, FILE, 190);
            /* allocate at least one byte to distinguish empty key from no key set */
            (*key).priv_key = CRYPTO_secure_malloc(
                if (*p).data_size > 0 {
                    (*p).data_size
                } else {
                    1
                },
                FILE,
                192,
            )
            .cast::<u8>();
            if (*key).priv_key.is_null() {
                return 0;
            }
            ptr::copy_nonoverlapping((*p).data.cast::<u8>(), (*key).priv_key, (*p).data_size);
            (*key).priv_key_len = (*p).data_size;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_202);
                return 0;
            }
            CRYPTO_free((*key).properties.cast(), FILE, 205);
            (*key).properties = CRYPTO_strdup((*p).data.cast(), FILE, 206);
            if (*key).properties.is_null() {
                return 0;
            }
        }

        if (*key).cmac != 0
            && ossl_prov_cipher_load_from_params(&raw mut (*key).cipher, params, (*key).libctx) == 0
        {
            raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_212);
            return 0;
        }

        if !(*key).priv_key.is_null() {
            return 1;
        }
    }
    0
}

/// `static int mac_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:222-233`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn mac_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = keydata.cast::<MacKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0 {
        return 0;
    }

    // SAFETY: `key` is non-NULL past the guard and `params` is the caller's array.
    unsafe { mac_key_fromdata(key, params) }
}

/// `static int key_to_params(MAC_KEY *key, OSSL_PARAM_BLD *tmpl, OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:235-262`.
///
/// # Safety
/// `key` is NULL or live; `tmpl` is NULL or a live builder; `params` is NULL or descriptors.
unsafe fn key_to_params(
    key: *mut MacKey,
    tmpl: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
) -> c_int {
    if key.is_null() {
        return 0;
    }

    // SAFETY: `key` is live and `tmpl`/`params` are per the contract.
    unsafe {
        if !(*key).priv_key.is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                params,
                OSSL_PKEY_PARAM_PRIV_KEY,
                (*key).priv_key,
                (*key).priv_key_len,
            ) == 0
        {
            return 0;
        }

        if !(*key).cipher.cipher.is_null()
            && ossl_param_build_set_utf8_string(
                tmpl,
                params,
                OSSL_PKEY_PARAM_CIPHER,
                EVP_CIPHER_get0_name((*key).cipher.cipher),
            ) == 0
        {
            return 0;
        }

        // `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` follows in the authority and
        // reads `ENGINE_get_id(key->cipher.engine)`. `OPENSSL_NO_ENGINE` is undefined (D181), so
        // the arm is compiled in -- but `PROV_CIPHER.engine` is only ever NULL in this crate
        // (nothing can set it; there is no `ENGINE` type or registry, Phase 13's), so the guard is
        // false in every state the crate can reach and the call is absent with this reason rather
        // than transcribed against a NULL `ENGINE_get_id`. `OSSL_PKEY_PARAM_ENGINE` is still
        // reported by `cmac_gettable_params`/`cmac_imexport_types`, as the authority reports it.
    }
    1
}

/// `static int mac_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `mac_legacy_kmgmt.c:264-295`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn mac_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = keydata.cast::<MacKey>();
    let mut ret: c_int = 0;

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0 {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `key` is non-NULL past the guard; `tmpl` is this call's own builder.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && key_to_params(key, tmpl, ptr::null_mut()) == 0
        {
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
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(tmpl);
    }
    ret
}

/// `static const OSSL_PARAM mac_key_types[]` — `mac_legacy_kmgmt.c:297-301`.
static MAC_KEY_TYPES: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `static const OSSL_PARAM *mac_imexport_types(int selection)` — `mac_legacy_kmgmt.c:302-307`.
unsafe extern "C" fn mac_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        return MAC_KEY_TYPES.as_ptr();
    }
    ptr::null()
}

/// `static const OSSL_PARAM cmac_key_types[]` — `mac_legacy_kmgmt.c:309-315`.
static CMAC_KEY_TYPES: [OsslParam; 5] = [
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_CIPHER),
    param_utf8_string(OSSL_PKEY_PARAM_ENGINE),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `static const OSSL_PARAM *cmac_imexport_types(int selection)` — `mac_legacy_kmgmt.c:316-321`.
unsafe extern "C" fn cmac_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        return CMAC_KEY_TYPES.as_ptr();
    }
    ptr::null()
}

/// `static int mac_get_params(void *key, OSSL_PARAM params[])` — `mac_legacy_kmgmt.c:323-326`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn mac_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { key_to_params(key.cast(), ptr::null_mut(), params) }
}

/// `static const OSSL_PARAM gettable_params[]` of `mac_gettable_params` —
/// `mac_legacy_kmgmt.c:330-333`.
static MAC_GETTABLE_PARAMS: [OsslParam; 2] = [param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY), END];

/// `static const OSSL_PARAM *mac_gettable_params(void *provctx)` — `mac_legacy_kmgmt.c:328-335`.
unsafe extern "C" fn mac_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    MAC_GETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM gettable_params[]` of `cmac_gettable_params` —
/// `mac_legacy_kmgmt.c:339-343`.
static CMAC_GETTABLE_PARAMS: [OsslParam; 4] = [
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_CIPHER),
    param_utf8_string(OSSL_PKEY_PARAM_ENGINE),
    END,
];

/// `static const OSSL_PARAM *cmac_gettable_params(void *provctx)` — `mac_legacy_kmgmt.c:337-346`.
unsafe extern "C" fn cmac_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    CMAC_GETTABLE_PARAMS.as_ptr()
}

/// `static int mac_set_params(void *keydata, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:348-361`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn mac_set_params(keydata: *mut c_void, params: *const OsslParam) -> c_int {
    let key = keydata.cast::<MacKey>();

    if key.is_null() {
        return 0;
    }

    // SAFETY: `key` is live and `params` is the caller's array.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) };
    if !p.is_null() {
        // SAFETY: `key` is live and `params` is the caller's array.
        return unsafe { mac_key_fromdata(key, params) };
    }

    1
}

/// `static const OSSL_PARAM settable_params[]` of `mac_settable_params` —
/// `mac_legacy_kmgmt.c:365-368`.
static MAC_SETTABLE_PARAMS: [OsslParam; 2] = [param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY), END];

/// `static const OSSL_PARAM *mac_settable_params(void *provctx)` — `mac_legacy_kmgmt.c:363-370`.
unsafe extern "C" fn mac_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    MAC_SETTABLE_PARAMS.as_ptr()
}

/// `struct mac_gen_ctx` — `mac_legacy_kmgmt.c:56-62`.
#[repr(C)]
struct MacGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `int selection`.
    selection: c_int,
    /// `unsigned char *priv_key` — a secure allocation.
    priv_key: *mut u8,
    /// `size_t priv_key_len`.
    priv_key_len: usize,
    /// `PROV_CIPHER cipher`.
    cipher: ProvCipher,
}

/// `static void *mac_gen_init_common(void *provctx, int selection)` —
/// `mac_legacy_kmgmt.c:372-385`.
///
/// # Safety
/// `provctx` is the caller's provider context.
unsafe fn mac_gen_init_common(provctx: *mut c_void, selection: c_int) -> *mut MacGenCtx {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let gctx = CRYPTO_zalloc(core::mem::size_of::<MacGenCtx>(), FILE, 380).cast::<MacGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation; `provctx` is the caller's.
        unsafe {
            (*gctx).libctx = prov_libctx_of(provctx);
            (*gctx).selection = selection;
        }
    }
    gctx
}

/// `static void *mac_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:387-397`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn mac_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract; `gctx` is NULL or a live context.
    let gctx = unsafe { mac_gen_init_common(provctx, selection) };

    // SAFETY: `gctx` is NULL or live, and `params` is the caller's array.
    if !gctx.is_null() && unsafe { mac_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is this call's own allocation, not yet published.
        unsafe { mac_gen_cleanup(gctx.cast()) };
        return ptr::null_mut();
    }
    gctx.cast()
}

/// `static void *cmac_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:399-409`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn cmac_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract; `gctx` is NULL or a live context.
    let gctx = unsafe { mac_gen_init_common(provctx, selection) };

    // SAFETY: `gctx` is NULL or live, and `params` is the caller's array.
    if !gctx.is_null() && unsafe { cmac_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is this call's own allocation, not yet published.
        unsafe { mac_gen_cleanup(gctx.cast()) };
        return ptr::null_mut();
    }
    gctx.cast()
}

/// `static int mac_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:411-433`.
///
/// # Safety
/// `genctx` is NULL or a live `MacGenCtx`; `params` is NULL or key-terminated.
unsafe fn mac_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<MacGenCtx>();

    if gctx.is_null() {
        return 0;
    }

    // SAFETY: `gctx` is live and `params` is the caller's array.
    unsafe {
        let p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_422);
                return 0;
            }
            (*gctx).priv_key = CRYPTO_secure_malloc((*p).data_size, FILE, 425).cast::<u8>();
            if (*gctx).priv_key.is_null() {
                return 0;
            }
            ptr::copy_nonoverlapping((*p).data.cast::<u8>(), (*gctx).priv_key, (*p).data_size);
            (*gctx).priv_key_len = (*p).data_size;
        }
    }
    1
}

/// `static int cmac_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `mac_legacy_kmgmt.c:435-449`.
///
/// # Safety
/// `genctx` is a live `MacGenCtx`; `params` is NULL or key-terminated.
unsafe fn cmac_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<MacGenCtx>();

    // SAFETY: the caller's contract.
    if unsafe { mac_gen_set_params(genctx, params) } == 0 {
        return 0;
    }

    // SAFETY: `gctx` is live and `params` is the caller's array.
    if unsafe { ossl_prov_cipher_load_from_params(&raw mut (*gctx).cipher, params, (*gctx).libctx) }
        == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_444) };
        return 0;
    }
    1
}

/// `static OSSL_PARAM settable[]` of `mac_gen_settable_params` — `mac_legacy_kmgmt.c:454-457`.
static MAC_GEN_SETTABLE_PARAMS: [OsslParam; 2] =
    [param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY), END];

/// `static const OSSL_PARAM *mac_gen_settable_params(void *genctx, void *provctx)` —
/// `mac_legacy_kmgmt.c:451-459`.
unsafe extern "C" fn mac_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    MAC_GEN_SETTABLE_PARAMS.as_ptr()
}

/// `static OSSL_PARAM settable[]` of `cmac_gen_settable_params` — `mac_legacy_kmgmt.c:464-467`.
static CMAC_GEN_SETTABLE_PARAMS: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_CIPHER),
    END,
];

/// `static const OSSL_PARAM *cmac_gen_settable_params(void *genctx, void *provctx)` —
/// `mac_legacy_kmgmt.c:461-470`.
unsafe extern "C" fn cmac_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    CMAC_GEN_SETTABLE_PARAMS.as_ptr()
}

/// `static void *mac_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)` —
/// `mac_legacy_kmgmt.c:472-513`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn mac_gen(
    genctx: *mut c_void,
    _cb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<MacGenCtx>();

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is non-NULL past the guard; every object below is this call's.
    unsafe {
        let key = ossl_mac_key_new((*gctx).libctx, 0);
        if key.is_null() {
            raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_481);
            return ptr::null_mut();
        }

        /* If we're doing parameter generation then we just return a blank key */
        if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
            return key.cast();
        }

        if (*gctx).priv_key.is_null() {
            raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_490);
            ossl_mac_key_free(key);
            return ptr::null_mut();
        }

        /*
         * This is horrible but required for backwards compatibility. We don't
         * actually do real key generation at all. We simply copy the key that was
         * previously set in the gctx. Hopefully at some point in the future all
         * of this can be removed and we will only support the EVP_KDF APIs.
         */
        if ossl_prov_cipher_copy(&raw mut (*key).cipher, &raw const (*gctx).cipher) == 0 {
            ossl_mac_key_free(key);
            raise_site(&err_sites::PROV_MAC_LEGACY_KMGMT_503);
            return ptr::null_mut();
        }
        ossl_prov_cipher_reset(&raw mut (*gctx).cipher);
        (*key).priv_key = (*gctx).priv_key;
        (*key).priv_key_len = (*gctx).priv_key_len;
        (*gctx).priv_key_len = 0;
        (*gctx).priv_key = ptr::null_mut();

        key.cast()
    }
}

/// `static void mac_gen_cleanup(void *genctx)` — `mac_legacy_kmgmt.c:515-525`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn mac_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<MacGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's context, allocated by `mac_gen_init_common`.
    unsafe {
        CRYPTO_secure_clear_free((*gctx).priv_key.cast(), (*gctx).priv_key_len, FILE, 522);
        ossl_prov_cipher_reset(&raw mut (*gctx).cipher);
        CRYPTO_free(gctx.cast(), FILE, 524);
    }
}

/// `const OSSL_DISPATCH ossl_mac_legacy_keymgmt_functions[]` — `mac_legacy_kmgmt.c:527-547`.
/// Seventeen slots, the authority's, in its order. The three rows `HMAC`, `SIPHASH` and `POLY1305`
/// share it.
pub(crate) static MAC_LEGACY_KEYMGMT_FUNCTIONS: [OsslDispatch; 18] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: mac_new as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: mac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: mac_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: mac_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: mac_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: mac_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: mac_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: mac_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: mac_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: mac_imexport_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: mac_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: mac_imexport_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: mac_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: mac_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: mac_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: mac_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: mac_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_cmac_legacy_keymgmt_functions[]` — `mac_legacy_kmgmt.c:549-569`. The
/// same seventeen slots with **five** replaced: `new`, `gettable_params`, `import_types`,
/// `export_types`, `gen_init`, `gen_set_params` and `gen_settable_params` (six, counting the two
/// `imexport_types` slots) — `gen` is the shared `mac_gen`, which builds a *non*-CMAC key.
pub(crate) static CMAC_LEGACY_KEYMGMT_FUNCTIONS: [OsslDispatch; 18] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: mac_new_cmac as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: mac_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: mac_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: cmac_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: mac_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: mac_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: mac_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: mac_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: mac_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: cmac_imexport_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: mac_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: cmac_imexport_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: cmac_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: cmac_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: cmac_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: mac_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: mac_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
