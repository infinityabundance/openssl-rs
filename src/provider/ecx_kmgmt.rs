//! Phase 8.10 — `providers/implementations/keymgmt/ecx_kmgmt.c.in`: the four ECX key types.
//!
//! One thousand three hundred and thirty-eight source lines, thirty-odd functions and **four**
//! dispatch tables (`X25519`, `X448`, `ED25519`, `ED448`), each the authority's twenty-slot
//! `MAKE_KEYMGMT_FUNCTIONS` expansion with its own `new_key`, `get_params`, `set_params`,
//! `gettable_params`, `settable_params`, `gen_init`, `gen` and `validate` slots. It is the largest
//! reachable keymgmt unit and the gate D387 left first in line: landing the four rows makes
//! [`crate::provider::ecx_exch`]'s two `OSSL_OP_KEYEXCH` rows and [`crate::provider::ecx_kem`]'s two
//! `OSSL_OP_KEM` rows drivable, which is why the three land together.
//!
//! ## What is transcribed, and what this profile does not compile
//!
//! The S390X arms (the four `s390x_*_keygen*` functions and their guarded branches in
//! `x25519_gen`/`x448_gen`/`ed25519_gen`/`ed448_gen`) are behind `#ifdef S390X_EC_ASM` and are not
//! compiled, so they are named here rather than transcribed; their eight `ERR_R_EC_LIB` raise sites
//! are still recorded by `gen_err_raise_sites.py`, exactly as the FIPS-only sites are. The
//! `FIPS_MODULE` arms — `ecd_fips140_pairwise_test`, `ecd_key_pub_check`, the FIPS half of
//! `ecd_key_pairwise_check`, the `approved` indicator in `ecx_get_params`, the `ossl_FIPS_IND_*`
//! calls in `ecx_gen_init`, and the pairwise-test tails of `ed25519_gen`/`ed448_gen` — are not this
//! profile's either, and each is named at the site it would be.
//!
//! ## The four generated decoders are written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for each `produce_param_decoder` block, a nested
//! `switch` that walks the parameter keys a character at a time and stores the located descriptor
//! in a struct field, raising `PROV_R_REPEATED_PARAMETER` on a second occurrence. The crate writes
//! the observable content of that block instead: one repeated-key scan (the shared helper below)
//! plus one `OSSL_PARAM_locate_const` per field, which is what `src/provider/mac.rs` and
//! `src/provider/exchange.rs` do for theirs. `ecx_imexport_types_decoder`, `ecx_get_params_decoder`,
//! `ed_get_params_decoder`, `ecx_set_params_decoder` and `ecx_gen_set_params_decoder` are the five
//! here.
//!
//! ## `ossl_ecx_dhkem_derive_private` lives in the KEM unit
//!
//! Both this unit (`ecx_gen`'s `#ifndef FIPS_MODULE` DHKEM-IKM arm) and `kem/ecx_kem.c` call it, and
//! the authority **defines** it in the KEM unit (`ecx_kem.c.in:342`), declared in `prov/ecx.h`. It is
//! therefore [`crate::provider::ecx_kem::ossl_ecx_dhkem_derive_private`], and this module depends on
//! the KEM unit for it — which is why the three land in one pass rather than in three.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::curve25519::{ossl_ed25519_public_from_private, ossl_x25519_public_from_private};
use crate::ec::curve448::{ossl_ed448_public_from_private, ossl_x448_public_from_private};
use crate::ec::ecx_backend::{ossl_ecx_key_dup, ossl_ecx_key_fromdata};
use crate::ec::ecx_key::{
    ossl_ecx_key_allocate_privkey, ossl_ecx_key_free, ossl_ecx_key_new, EcxKey, ED25519_KEYLEN,
    ED448_KEYLEN, MAX_KEYLEN, X25519_KEYLEN, X448_KEYLEN,
};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::param_build_set::ossl_param_build_set_octet_string;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string, OsslParam, END,
    OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memcmp, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// The constants — `include/crypto/ecx.h`, `core_names.h` and `core_dispatch.h`.
// ---------------------------------------------------------------------------------------------

/// `X25519_BITS` — `include/crypto/ecx.h:33`.
const X25519_BITS: c_int = 253;
/// `X25519_SECURITY_BITS`.
const X25519_SECURITY_BITS: c_int = 128;
/// `X448_BITS`.
const X448_BITS: c_int = 448;
/// `X448_SECURITY_BITS`.
const X448_SECURITY_BITS: c_int = 224;
/// `ED25519_BITS`.
const ED25519_BITS: c_int = 256;
/// `ED25519_SECURITY_BITS`.
const ED25519_SECURITY_BITS: c_int = 128;
/// `ED25519_SIGSIZE` — the `max-size` the `ED25519` row reports.
const ED25519_SIGSIZE: c_int = 64;
/// `ED448_BITS`.
const ED448_BITS: c_int = 456;
/// `ED448_SECURITY_BITS`.
const ED448_SECURITY_BITS: c_int = 224;
/// `ED448_SIGSIZE`.
const ED448_SIGSIZE: c_int = 114;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640-652`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` — `core_dispatch.h`.
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
/// `ECX_POSSIBLE_SELECTIONS` — `ecx_kmgmt.c:82`.
const ECX_POSSIBLE_SELECTIONS: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;

/// `OSSL_PKEY_PARAM_PUB_KEY` — `core_names.h:441`.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `core_names.h:439`.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_BITS` — `core_names.h:366`.
const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h:495`.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE` — `core_names.h:424`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — `core_names.h:496`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
/// `OSSL_PKEY_PARAM_MANDATORY_DIGEST` — `core_names.h:422`.
const OSSL_PKEY_PARAM_MANDATORY_DIGEST: *const c_char = c"mandatory-digest".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h:440`, the value of `OSSL_ALG_PARAM_PROPERTIES`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_KDF_PARAM_PROPERTIES` — `core_names.h:303`. The same string, a different name.
const OSSL_KDF_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_PKEY_PARAM_GROUP_NAME` — `core_names.h:420`.
const OSSL_PKEY_PARAM_GROUP_NAME: *const c_char = c"group".as_ptr();
/// `OSSL_PKEY_PARAM_DHKEM_IKM` — `core_names.h:371`.
const OSSL_PKEY_PARAM_DHKEM_IKM: *const c_char = c"dhkem-ikm".as_ptr();

/// The generated unit's own `__FILE__`. `ecx_kmgmt.c.in` is `.c.in`-generated, so it is the bare
/// build-relative path.
const FILE_ECX_KMGMT: *const c_char = c"providers/implementations/keymgmt/ecx_kmgmt.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `struct ecx_gen_ctx` — `ecx_kmgmt.c:84-91`.
#[repr(C)]
struct EcxGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `ECX_KEY_TYPE type`.
    type_: c_int,
    /// `int selection`.
    selection: c_int,
    /// `unsigned char *dhkem_ikm` — owned.
    dhkem_ikm: *mut u8,
    /// `size_t dhkem_ikmlen`.
    dhkem_ikmlen: usize,
}

/// `static ossl_inline int ecx_key_type_is_ed(ECX_KEY_TYPE type)` — `ecx_kmgmt.c:104-107`.
fn ecx_key_type_is_ed(type_: c_int) -> c_int {
    c_int::from(
        type_ == crate::ec::ecx_key::ECX_KEY_TYPE_ED25519
            || type_ == crate::ec::ecx_key::ECX_KEY_TYPE_ED448,
    )
}

/// `static void *x25519_new_key(void *provctx)` — `ecx_kmgmt.c:109-115`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn x25519_new_key(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe {
        ossl_ecx_key_new(
            prov_libctx_of(provctx),
            crate::ec::ecx_key::ECX_KEY_TYPE_X25519,
            0,
            ptr::null(),
        )
        .cast()
    }
}

/// `static void *x448_new_key(void *provctx)` — `ecx_kmgmt.c:117-123`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn x448_new_key(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe {
        ossl_ecx_key_new(
            prov_libctx_of(provctx),
            crate::ec::ecx_key::ECX_KEY_TYPE_X448,
            0,
            ptr::null(),
        )
        .cast()
    }
}

/// `static void *ed25519_new_key(void *provctx)` — `ecx_kmgmt.c:125-131`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn ed25519_new_key(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe {
        ossl_ecx_key_new(
            prov_libctx_of(provctx),
            crate::ec::ecx_key::ECX_KEY_TYPE_ED25519,
            0,
            ptr::null(),
        )
        .cast()
    }
}

/// `static void *ed448_new_key(void *provctx)` — `ecx_kmgmt.c:133-139`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn ed448_new_key(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe {
        ossl_ecx_key_new(
            prov_libctx_of(provctx),
            crate::ec::ecx_key::ECX_KEY_TYPE_ED448,
            0,
            ptr::null(),
        )
        .cast()
    }
}

/// `static int ecx_has(const void *keydata, int selection)` — `ecx_kmgmt.c:141-160`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn ecx_has(keydata: *const c_void, selection: c_int) -> c_int {
    let key = keydata.cast::<EcxKey>();
    let mut ok: c_int = 0;

    if is_running() != 0 && !key.is_null() {
        /*
         * ECX keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        // SAFETY: `key` is non-NULL past the guard.
        unsafe {
            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                ok &= c_int::from((*key).haspubkey != 0);
            }
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                ok &= c_int::from(!(*key).privkey.is_null());
            }
        }
    }
    ok
}

/// `static int ecx_match(const void *keydata1, const void *keydata2, int selection)` —
/// `ecx_kmgmt.c:162-208`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn ecx_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let key1 = keydata1.cast::<EcxKey>();
    let key2 = keydata2.cast::<EcxKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the two objects are the caller's, per the dispatch contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= c_int::from((*key1).type_ == (*key2).type_);
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked = 0;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                let pa = if (*key1).haspubkey != 0 {
                    (*key1).pubkey.as_ptr()
                } else {
                    ptr::null()
                };
                let pb = if (*key2).haspubkey != 0 {
                    (*key2).pubkey.as_ptr()
                } else {
                    ptr::null()
                };
                let pal = (*key1).keylen;
                let pbl = (*key2).keylen;

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(
                        (*key1).type_ == (*key2).type_
                            && pal == pbl
                            && CRYPTO_memcmp(pa.cast(), pb.cast(), pal) == 0,
                    );
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                let pa = (*key1).privkey;
                let pb = (*key2).privkey;
                let pal = (*key1).keylen;
                let pbl = (*key2).keylen;

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(
                        (*key1).type_ == (*key2).type_
                            && pal == pbl
                            && CRYPTO_memcmp(pa.cast(), pb.cast(), pal) == 0,
                    );
                    key_checked = 1;
                }
            }
            ok &= key_checked;
        }
    }
    ok
}

/// The repeated-key scan the five generated decoders share — the observable content of
/// `paramnames.pm`'s nested key walk.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecx_repeated_param_site(
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
            let k = CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if CStr::from_ptr(*name).to_bytes() == k {
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

/// `static const OSSL_PARAM ecx_imexport_types_list[]` — generated `ecx_kmgmt.c:213-217`.
static ECX_IMEXPORT_TYPES_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `struct ecx_imexport_types_st` — generated `ecx_kmgmt.c:221-224`.
struct EcxImexportTypes {
    pub_key: *const OsslParam,
    priv_key: *const OsslParam,
}

/// The import/export decoder's repeated-key coordinates, from the generated file's two arms.
const ECX_IMEXPORT_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_ECX_KMGMT_247, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ECX_KMGMT_258, OSSL_PKEY_PARAM_PUB_KEY),
];

/// `ecx_imexport_types_decoder` — generated `ecx_kmgmt.c:228-267`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecx_imexport_types_decoder(params: *const OsslParam, r: &mut EcxImexportTypes) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecx_repeated_param_site(params, &ECX_IMEXPORT_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        r.priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    }
    1
}

/// `static int ecx_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:272-291`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn ecx_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = keydata.cast::<EcxKey>();
    let mut p = EcxImexportTypes {
        pub_key: ptr::null(),
        priv_key: ptr::null(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if is_running() == 0 || key.is_null() || ecx_imexport_types_decoder(params, &mut p) == 0 {
            return 0;
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
            return 0;
        }

        let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
        ossl_ecx_key_fromdata(key, p.pub_key, p.priv_key, include_private)
    }
}

/// `static int key_to_params(ECX_KEY *key, OSSL_PARAM_BLD *tmpl, OSSL_PARAM *pub,
/// OSSL_PARAM *priv, int include_private)` — `ecx_kmgmt.c:293-312`.
///
/// # Safety
/// `key` is NULL or live; `tmpl` is NULL or a live builder; `pub`/`priv` are NULL or descriptors.
unsafe fn key_to_params(
    key: *mut EcxKey,
    tmpl: *mut OSSL_PARAM_BLD,
    pub_key: *mut OsslParam,
    priv_key: *mut OsslParam,
    include_private: c_int,
) -> c_int {
    if key.is_null() {
        return 0;
    }

    // SAFETY: `key` is live and `tmpl`/`pub_key`/`priv_key` are per the contract.
    unsafe {
        if ossl_param_build_set_octet_string(
            tmpl,
            pub_key,
            OSSL_PKEY_PARAM_PUB_KEY,
            (*key).pubkey.as_ptr(),
            (*key).keylen,
        ) == 0
        {
            return 0;
        }

        if include_private != 0
            && !(*key).privkey.is_null()
            && ossl_param_build_set_octet_string(
                tmpl,
                priv_key,
                OSSL_PKEY_PARAM_PRIV_KEY,
                (*key).privkey,
                (*key).keylen,
            ) == 0
        {
            return 0;
        }
    }
    1
}

/// `static int ecx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `ecx_kmgmt.c:314-348`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn ecx_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = keydata.cast::<EcxKey>();
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

    // SAFETY: `key` is non-NULL past the guard; `tmpl` is this call's own builder.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            if key_to_params(key, tmpl, ptr::null_mut(), ptr::null_mut(), include_private) == 0 {
                OSSL_PARAM_BLD_free(tmpl);
                return ret;
            }
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

/// `static const OSSL_PARAM *ecx_imexport_types(int selection)` — `ecx_kmgmt.c:350-355`.
unsafe extern "C" fn ecx_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        return ECX_IMEXPORT_TYPES_LIST.as_ptr();
    }
    ptr::null()
}

/// `struct ecx_ed_common_get_params_st` — `ecx_kmgmt.c:357-367`. The `ind` member exists only
/// under `FIPS_MODULE` and is absent here; `digest` only for the Ed rows.
struct EcxEdCommonGetParams {
    bits: *const OsslParam,
    secbits: *const OsslParam,
    size: *const OsslParam,
    seccat: *const OsslParam,
    pub_key: *const OsslParam,
    priv_key: *const OsslParam,
    encpub: *const OsslParam,
    digest: *const OsslParam,
}

/// `static const OSSL_PARAM ecx_get_params_list[]` — generated `ecx_kmgmt.c:374-386`, without the
/// `FIPS_MODULE`-guarded indicator.
static ECX_GET_PARAMS_LIST: [OsslParam; 8] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    END,
];

/// The X-rows' `get_params` decoder coordinates, from the generated file's non-FIPS arms.
const ECX_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_ECX_KMGMT_420, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_ECX_KMGMT_431,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    ),
    (&err_sites::PROV_ECX_KMGMT_455, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_ECX_KMGMT_470, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ECX_KMGMT_481, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ECX_KMGMT_529,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_ECX_KMGMT_540,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
];

/// `ecx_get_params_decoder` — generated `ecx_kmgmt.c:405-557`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecx_get_params_decoder(params: *const OsslParam, r: &mut EcxEdCommonGetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecx_repeated_param_site(params, &ECX_GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
        r.encpub = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        r.size = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE);
        r.priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        r.pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        r.secbits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        r.seccat = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
    }
    1
}

/// `static const OSSL_PARAM ed_get_params_list[]` — generated `ecx_kmgmt.c:567-576`.
static ED_GET_PARAMS_LIST: [OsslParam; 8] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST),
    END,
];

/// The Ed-rows' `get_params` decoder coordinates, from the generated file's arms.
const ED_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_ECX_KMGMT_607, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_ECX_KMGMT_626,
        OSSL_PKEY_PARAM_MANDATORY_DIGEST,
    ),
    (&err_sites::PROV_ECX_KMGMT_637, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_ECX_KMGMT_654, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_ECX_KMGMT_665, OSSL_PKEY_PARAM_PUB_KEY),
    (
        &err_sites::PROV_ECX_KMGMT_713,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_ECX_KMGMT_724,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
];

/// `ed_get_params_decoder` — generated `ecx_kmgmt.c:592-741`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ed_get_params_decoder(params: *const OsslParam, r: &mut EcxEdCommonGetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(repeat) = ecx_repeated_param_site(params, &ED_GET_PARAMS_DECODER_KEYS) {
            raise_site(repeat);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
        r.digest = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        r.size = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE);
        r.priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        r.pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        r.secbits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        r.seccat = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
    }
    1
}

/// `static int ecx_ed_common_get_params(void *key, const struct ecx_ed_common_get_params_st *p,
/// int bits, int secbits, int size)` — `ecx_kmgmt.c:747-762`.
///
/// # Safety
/// `key` is live; `p` holds this call's own decoder result.
unsafe fn ecx_ed_common_get_params(
    key: *mut c_void,
    p: &EcxEdCommonGetParams,
    bits: c_int,
    secbits: c_int,
    size: c_int,
) -> c_int {
    let ecx = key.cast::<EcxKey>();

    // SAFETY: `ecx` is live and `p`'s descriptors are the caller's, per the dispatch contract.
    unsafe {
        if !p.bits.is_null() && OSSL_PARAM_set_int(p.bits.cast_mut(), bits) == 0 {
            return 0;
        }
        if !p.secbits.is_null() && OSSL_PARAM_set_int(p.secbits.cast_mut(), secbits) == 0 {
            return 0;
        }
        if !p.size.is_null() && OSSL_PARAM_set_int(p.size.cast_mut(), size) == 0 {
            return 0;
        }
        if !p.seccat.is_null() && OSSL_PARAM_set_int(p.seccat.cast_mut(), 0) == 0 {
            return 0;
        }
        key_to_params(
            ecx,
            ptr::null_mut(),
            p.pub_key.cast_mut(),
            p.priv_key.cast_mut(),
            1,
        )
    }
}

/// `static int ecx_get_params(void *key, OSSL_PARAM params[], int bits, int secbits, int size)` —
/// `ecx_kmgmt.c:765-788`.
///
/// # Safety
/// `key` is NULL or live; `params` is NULL or key-terminated.
unsafe fn ecx_get_params(
    key: *mut c_void,
    params: *mut OsslParam,
    bits: c_int,
    secbits: c_int,
    size: c_int,
) -> c_int {
    let ecx = key.cast::<EcxKey>();
    let mut p = EcxEdCommonGetParams {
        bits: ptr::null(),
        secbits: ptr::null(),
        size: ptr::null(),
        seccat: ptr::null(),
        pub_key: ptr::null(),
        priv_key: ptr::null(),
        encpub: ptr::null(),
        digest: ptr::null(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if key.is_null() || ecx_get_params_decoder(params.cast_const(), &mut p) == 0 {
            return 0;
        }

        if !p.encpub.is_null()
            && OSSL_PARAM_set_octet_string(
                p.encpub.cast_mut(),
                (*ecx).pubkey.as_ptr().cast(),
                (*ecx).keylen,
            ) == 0
        {
            return 0;
        }
        // `#ifdef FIPS_MODULE { approved = 0; if (p.ind != NULL && !set_int(p.ind, 0)) ... }` is
        // not this profile's arm.

        ecx_ed_common_get_params(key, &p, bits, secbits, size)
    }
}

/// `static int ed_get_params(void *key, OSSL_PARAM params[], int bits, int secbits, int size)` —
/// `ecx_kmgmt.c:791-801`.
///
/// # Safety
/// `key` is NULL or live; `params` is NULL or key-terminated.
unsafe fn ed_get_params(
    key: *mut c_void,
    params: *mut OsslParam,
    bits: c_int,
    secbits: c_int,
    size: c_int,
) -> c_int {
    let mut p = EcxEdCommonGetParams {
        bits: ptr::null(),
        secbits: ptr::null(),
        size: ptr::null(),
        seccat: ptr::null(),
        pub_key: ptr::null(),
        priv_key: ptr::null(),
        encpub: ptr::null(),
        digest: ptr::null(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if key.is_null() || ed_get_params_decoder(params.cast_const(), &mut p) == 0 {
            return 0;
        }
        if !p.digest.is_null() && OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), c"".as_ptr()) == 0
        {
            return 0;
        }
        ecx_ed_common_get_params(key, &p, bits, secbits, size)
    }
}

/// `static int x25519_get_params(void *key, OSSL_PARAM params[])` — `ecx_kmgmt.c:803-807`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn x25519_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_get_params(
            key,
            params,
            X25519_BITS,
            X25519_SECURITY_BITS,
            X25519_KEYLEN as c_int,
        )
    }
}

/// `static int x448_get_params(void *key, OSSL_PARAM params[])` — `ecx_kmgmt.c:809-813`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn x448_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_get_params(
            key,
            params,
            X448_BITS,
            X448_SECURITY_BITS,
            X448_KEYLEN as c_int,
        )
    }
}

/// `static int ed25519_get_params(void *key, OSSL_PARAM params[])` — `ecx_kmgmt.c:815-819`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn ed25519_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ed_get_params(
            key,
            params,
            ED25519_BITS,
            ED25519_SECURITY_BITS,
            ED25519_SIGSIZE,
        )
    }
}

/// `static int ed448_get_params(void *key, OSSL_PARAM params[])` — `ecx_kmgmt.c:820-824`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn ed448_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ed_get_params(key, params, ED448_BITS, ED448_SECURITY_BITS, ED448_SIGSIZE) }
}

/// `static const OSSL_PARAM *x25519_gettable_params(void *provctx)` — `ecx_kmgmt.c:826-829`.
unsafe extern "C" fn x25519_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ECX_GET_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM *x448_gettable_params(void *provctx)` — `ecx_kmgmt.c:831-834`.
unsafe extern "C" fn x448_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ECX_GET_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM *ed25519_gettable_params(void *provctx)` — `ecx_kmgmt.c:836-839`.
unsafe extern "C" fn ed25519_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ED_GET_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM *ed448_gettable_params(void *provctx)` — `ecx_kmgmt.c:841-844`.
unsafe extern "C" fn ed448_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    ED_GET_PARAMS_LIST.as_ptr()
}

/// `static int set_property_query(ECX_KEY *ecxkey, const char *propq)` — `ecx_kmgmt.c:846-856`.
///
/// # Safety
/// `ecxkey` is live; `propq` is NULL or NUL-terminated.
unsafe fn set_property_query(ecxkey: *mut EcxKey, propq: *const c_char) -> c_int {
    // SAFETY: `ecxkey` is live and its own `propq` is released and replaced here.
    unsafe {
        CRYPTO_free((*ecxkey).propq.cast(), FILE_ECX_KMGMT, 848);
        (*ecxkey).propq = ptr::null_mut();
        if !propq.is_null() {
            (*ecxkey).propq = CRYPTO_strdup(propq, FILE_ECX_KMGMT, 851);
            if (*ecxkey).propq.is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM ecx_set_params_list[]` — generated `ecx_kmgmt.c:861-865`.
static ECX_SET_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `struct ecx_set_params_st` — generated `ecx_kmgmt.c:869-872`.
struct EcxSetParams {
    propq: *const OsslParam,
    pub_key: *const OsslParam,
}

/// The set-decoder's repeated-key coordinates, from the generated file's two arms.
const ECX_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (
        &err_sites::PROV_ECX_KMGMT_891,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    ),
    (&err_sites::PROV_ECX_KMGMT_902, OSSL_PKEY_PARAM_PROPERTIES),
];

/// `ecx_set_params_decoder` — generated `ecx_kmgmt.c:876-910`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecx_set_params_decoder(params: *const OsslParam, r: &mut EcxSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecx_repeated_param_site(params, &ECX_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    }
    1
}

/// `static int ecx_set_params(void *key, const OSSL_PARAM params[])` — `ecx_kmgmt.c:915-942`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn ecx_set_params(key: *mut c_void, params: *const OsslParam) -> c_int {
    let ecxkey = key.cast::<EcxKey>();
    let mut p = EcxSetParams {
        propq: ptr::null(),
        pub_key: ptr::null(),
    };

    // SAFETY: `key`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if key.is_null() || ecx_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.pub_key.is_null() {
            let mut buf: *mut c_void = (*ecxkey).pubkey.as_mut_ptr().cast();

            if (*p.pub_key).data_size != (*ecxkey).keylen
                || OSSL_PARAM_get_octet_string(p.pub_key, &mut buf, MAX_KEYLEN, ptr::null_mut())
                    == 0
            {
                return 0;
            }
            CRYPTO_clear_free(
                (*ecxkey).privkey.cast(),
                (*ecxkey).keylen,
                FILE_ECX_KMGMT,
                930,
            );
            (*ecxkey).privkey = ptr::null_mut();
            (*ecxkey).haspubkey = 1;
        }

        if !p.propq.is_null()
            && ((*p.propq).data_type != OSSL_PARAM_UTF8_STRING
                || set_property_query(ecxkey, (*p.propq).data.cast()) == 0)
        {
            return 0;
        }
    }
    1
}

/// `static int x25519_set_params(void *key, const OSSL_PARAM params[])` — `ecx_kmgmt.c:944-947`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn x25519_set_params(key: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecx_set_params(key, params) }
}

/// `static int x448_set_params(void *key, const OSSL_PARAM params[])` — `ecx_kmgmt.c:949-952`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn x448_set_params(key: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecx_set_params(key, params) }
}

/// `static int ed25519_set_params(void *key, const OSSL_PARAM params[])` — `ecx_kmgmt.c:954-957`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract; neither argument is read.
unsafe extern "C" fn ed25519_set_params(_key: *mut c_void, _params: *const OsslParam) -> c_int {
    1
}

/// `static int ed448_set_params(void *key, const OSSL_PARAM params[])` — `ecx_kmgmt.c:959-962`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract; neither argument is read.
unsafe extern "C" fn ed448_set_params(_key: *mut c_void, _params: *const OsslParam) -> c_int {
    1
}

/// `static const OSSL_PARAM ed_settable_params[]` — `ecx_kmgmt.c:964-966`.
static ED_SETTABLE_PARAMS: [OsslParam; 1] = [END];

/// `static const OSSL_PARAM *x25519_settable_params(void *provctx)` — `ecx_kmgmt.c:968-971`.
unsafe extern "C" fn x25519_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    ECX_SET_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM *x448_settable_params(void *provctx)` — `ecx_kmgmt.c:973-976`.
unsafe extern "C" fn x448_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    ECX_SET_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM *ed25519_settable_params(void *provctx)` — `ecx_kmgmt.c:978-981`.
unsafe extern "C" fn ed25519_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    ED_SETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *ed448_settable_params(void *provctx)` — `ecx_kmgmt.c:983-986`.
unsafe extern "C" fn ed448_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    ED_SETTABLE_PARAMS.as_ptr()
}

/// `static void *ecx_gen_init(void *provctx, int selection, const OSSL_PARAM params[],
/// ECX_KEY_TYPE type, const char *algdesc)` — `ecx_kmgmt.c:988-1018`.
///
/// The `#ifdef FIPS_MODULE` `ossl_FIPS_IND_callback` arm is not this profile's; on this profile the
/// `algdesc` argument has no reader and is therefore not carried.
///
/// # Safety
/// `provctx` is the caller's provider context; `params` is NULL or key-terminated.
unsafe fn ecx_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
    type_: c_int,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let gctx =
        CRYPTO_zalloc(core::mem::size_of::<EcxGenCtx>(), FILE_ECX_KMGMT, 998).cast::<EcxGenCtx>();
    if gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is this call's own allocation; `provctx` is the caller's.
    unsafe {
        (*gctx).libctx = prov_libctx_of(provctx);
        (*gctx).type_ = type_;
        (*gctx).selection = selection;
    }
    // SAFETY: `gctx` is non-NULL; `params` is the caller's array.
    if unsafe { ecx_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is this call's own allocation, not yet published.
        unsafe { ecx_gen_cleanup(gctx.cast()) };
        return ptr::null_mut();
    }
    gctx.cast()
}

/// `static void *x25519_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:1020-1024`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn x25519_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_gen_init(
            provctx,
            selection,
            params,
            crate::ec::ecx_key::ECX_KEY_TYPE_X25519,
        )
    }
}

/// `static void *x448_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:1026-1030`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn x448_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_gen_init(
            provctx,
            selection,
            params,
            crate::ec::ecx_key::ECX_KEY_TYPE_X448,
        )
    }
}

/// `static void *ed25519_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:1032-1036`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn ed25519_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_gen_init(
            provctx,
            selection,
            params,
            crate::ec::ecx_key::ECX_KEY_TYPE_ED25519,
        )
    }
}

/// `static void *ed448_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:1038-1042`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn ed448_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_gen_init(
            provctx,
            selection,
            params,
            crate::ec::ecx_key::ECX_KEY_TYPE_ED448,
        )
    }
}

/// `static const OSSL_PARAM ecx_gen_set_params_list[]` — generated `ecx_kmgmt.c:1047-1052`.
static ECX_GEN_SET_PARAMS_LIST: [OsslParam; 4] = [
    param_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME),
    param_utf8_string(OSSL_KDF_PARAM_PROPERTIES),
    param_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM),
    END,
];

/// `struct ecx_gen_set_params_st` — generated `ecx_kmgmt.c:1056-1060`.
struct EcxGenSetParams {
    group: *const OsslParam,
    ikm: *const OsslParam,
    kdfpropq: *const OsslParam,
}

/// The gen set-decoder's repeated-key coordinates, from the generated file's three arms.
const ECX_GEN_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 3] = [
    (&err_sites::PROV_ECX_KMGMT_1079, OSSL_PKEY_PARAM_DHKEM_IKM),
    (&err_sites::PROV_ECX_KMGMT_1090, OSSL_PKEY_PARAM_GROUP_NAME),
    (&err_sites::PROV_ECX_KMGMT_1101, OSSL_KDF_PARAM_PROPERTIES),
];

/// `ecx_gen_set_params_decoder` — generated `ecx_kmgmt.c:1064-1109`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecx_gen_set_params_decoder(params: *const OsslParam, r: &mut EcxGenSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecx_repeated_param_site(params, &ECX_GEN_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.ikm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DHKEM_IKM);
        r.group = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        r.kdfpropq = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    }
    1
}

/// `static int ecx_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `ecx_kmgmt.c:1114-1169`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn ecx_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<EcxGenCtx>();
    let mut p = EcxGenSetParams {
        group: ptr::null(),
        ikm: ptr::null(),
        kdfpropq: ptr::null(),
    };

    // SAFETY: `gctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if gctx.is_null() || ecx_gen_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.group.is_null() {
            /*
             * We optionally allow setting a group name - but each algorithm only
             * support one such name, so all we do is verify that it is the one we
             * expected.
             */
            let groupname: *const c_char = match (*gctx).type_ {
                crate::ec::ecx_key::ECX_KEY_TYPE_X25519 => c"x25519".as_ptr(),
                crate::ec::ecx_key::ECX_KEY_TYPE_X448 => c"x448".as_ptr(),
                /* We only support this for key exchange at the moment */
                _ => ptr::null(),
            };
            if (*p.group).data_type != OSSL_PARAM_UTF8_STRING
                || groupname.is_null()
                || OPENSSL_strcasecmp((*p.group).data.cast(), groupname) != 0
            {
                raise_site(&err_sites::PROV_ECX_KMGMT_1144);
                return 0;
            }
        }

        if !p.kdfpropq.is_null() {
            if (*p.kdfpropq).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).propq.cast(), FILE_ECX_KMGMT, 1152);
            (*gctx).propq = CRYPTO_strdup((*p.kdfpropq).data.cast(), FILE_ECX_KMGMT, 1153);
            if (*gctx).propq.is_null() {
                return 0;
            }
        }

        if !p.ikm.is_null() && (*p.ikm).data_size != 0 && !(*p.ikm).data.is_null() {
            CRYPTO_free((*gctx).dhkem_ikm.cast(), FILE_ECX_KMGMT, 1160);
            (*gctx).dhkem_ikm = ptr::null_mut();
            let slot: *mut *mut u8 = &raw mut (*gctx).dhkem_ikm;
            if OSSL_PARAM_get_octet_string(
                p.ikm,
                slot.cast::<*mut c_void>(),
                0,
                &mut (*gctx).dhkem_ikmlen,
            ) == 0
            {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *ecx_gen_settable_params(void *genctx, void *provctx)` —
/// `ecx_kmgmt.c:1171-1175`.
unsafe extern "C" fn ecx_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECX_GEN_SET_PARAMS_LIST.as_ptr()
}

/// `static void *ecx_gen(struct ecx_gen_ctx *gctx)` — `ecx_kmgmt.c:1245-1309`.
///
/// # Safety
/// `gctx` is NULL or a live context from `ecx_gen_init`.
// The authority's `switch` has an `if (...) goto err;` inside two of its four cases; collapsing the
// `if` into a match guard would be the same control flow written less like the C, so the nesting
// stays.
#[allow(clippy::collapsible_match)]
unsafe fn ecx_gen(gctx: *mut EcxGenCtx) -> *mut c_void {
    if gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is non-NULL past the guard; every field read is its own.
    unsafe {
        let key = ossl_ecx_key_new((*gctx).libctx, (*gctx).type_, 0, (*gctx).propq);
        if key.is_null() {
            raise_site(&err_sites::PROV_ECX_KMGMT_1255);
            return ptr::null_mut();
        }

        /* If we're doing parameter generation then we just return a blank key */
        if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
            return key.cast();
        }

        let privkey = ossl_ecx_key_allocate_privkey(key);
        if privkey.is_null() {
            raise_site(&err_sites::PROV_ECX_KMGMT_1264);
            return ecx_gen_err(key);
        }
        // The `#ifndef FIPS_MODULE` guard compiles this arm.
        if !(*gctx).dhkem_ikm.is_null() && (*gctx).dhkem_ikmlen != 0 {
            if ecx_key_type_is_ed((*gctx).type_) != 0
                || crate::provider::ecx_kem::ossl_ecx_dhkem_derive_private(
                    key,
                    privkey,
                    (*gctx).dhkem_ikm,
                    (*gctx).dhkem_ikmlen,
                ) == 0
            {
                return ecx_gen_err(key);
            }
        } else if RAND_priv_bytes_ex((*gctx).libctx, privkey, (*key).keylen, 0) <= 0 {
            return ecx_gen_err(key);
        }

        match (*gctx).type_ {
            crate::ec::ecx_key::ECX_KEY_TYPE_X25519 => {
                *privkey &= 248;
                *privkey.add(X25519_KEYLEN - 1) &= 127;
                *privkey.add(X25519_KEYLEN - 1) |= 64;
                ossl_x25519_public_from_private((*key).pubkey.as_mut_ptr(), privkey);
            }
            crate::ec::ecx_key::ECX_KEY_TYPE_X448 => {
                *privkey &= 252;
                *privkey.add(X448_KEYLEN - 1) |= 128;
                ossl_x448_public_from_private((*key).pubkey.as_mut_ptr(), privkey);
            }
            crate::ec::ecx_key::ECX_KEY_TYPE_ED25519 => {
                if ossl_ed25519_public_from_private(
                    (*gctx).libctx,
                    (*key).pubkey.as_mut_ptr(),
                    privkey,
                    (*gctx).propq,
                ) == 0
                {
                    return ecx_gen_err(key);
                }
            }
            crate::ec::ecx_key::ECX_KEY_TYPE_ED448 => {
                if ossl_ed448_public_from_private(
                    (*gctx).libctx,
                    (*key).pubkey.as_mut_ptr(),
                    privkey,
                    (*gctx).propq,
                ) == 0
                {
                    return ecx_gen_err(key);
                }
            }
            _ => {}
        }
        (*key).haspubkey = 1;
        key.cast()
    }
}

/// The `err:` label of [`ecx_gen`] — `ecx_kmgmt.c:1306-1308`.
///
/// # Safety
/// `key` is a live object this call owns.
unsafe fn ecx_gen_err(key: *mut EcxKey) -> *mut c_void {
    // SAFETY: `key` is this call's own object.
    unsafe { ossl_ecx_key_free(key) };
    ptr::null_mut()
}

/// `static void *x25519_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ecx_kmgmt.c:1311-1323`. The `#ifdef S390X_EC_ASM` fast path is not this profile's.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn x25519_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcxGenCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: the caller's contract.
    unsafe { ecx_gen(gctx) }
}

/// `static void *x448_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ecx_kmgmt.c:1325-1337`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn x448_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcxGenCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: the caller's contract.
    unsafe { ecx_gen(gctx) }
}

/// `static void *ed25519_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ecx_kmgmt.c:1339-1370`. The S390X fast path and the FIPS pairwise tail are both absent.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn ed25519_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcxGenCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: the caller's contract.
    unsafe { ecx_gen(gctx) }
}

/// `static void *ed448_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ecx_kmgmt.c:1372-1402`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn ed448_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcxGenCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: the caller's contract.
    unsafe { ecx_gen(gctx) }
}

/// `static void ecx_gen_cleanup(void *genctx)` — `ecx_kmgmt.c:1404-1414`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn ecx_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<EcxGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's context, allocated by `ecx_gen_init`.
    unsafe {
        CRYPTO_clear_free(
            (*gctx).dhkem_ikm.cast(),
            (*gctx).dhkem_ikmlen,
            FILE_ECX_KMGMT,
            1411,
        );
        CRYPTO_free((*gctx).propq.cast(), FILE_ECX_KMGMT, 1412);
        CRYPTO_free(gctx.cast(), FILE_ECX_KMGMT, 1413);
    }
}

/// `void *ecx_load(const void *reference, size_t reference_sz)` — `ecx_kmgmt.c:1416-1428`. The
/// authority's definition is **not** `static`, so it is a `#[no_mangle]` export here.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
#[no_mangle]
pub unsafe extern "C" fn ecx_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut EcxKey>() {
        // The contents of the reference is the address to our object.
        // SAFETY: `reference` is readable for `reference_sz` bytes and the authority detaches the
        // object it names.
        unsafe {
            let slot = reference.cast::<*mut EcxKey>().cast_mut();
            let key = *slot;
            *slot = ptr::null_mut();
            return key.cast();
        }
    }
    ptr::null_mut()
}

/// `static void *ecx_dup(const void *keydata_from, int selection)` — `ecx_kmgmt.c:1430-1435`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn ecx_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract.
        return unsafe { ossl_ecx_key_dup(keydata_from.cast(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `static int ecx_key_pairwise_check(const ECX_KEY *ecx, int type)` — `ecx_kmgmt.c:1437-1452`.
///
/// # Safety
/// `ecx` is live.
unsafe fn ecx_key_pairwise_check(ecx: *const EcxKey, type_: c_int) -> c_int {
    let mut pub_: [u8; 64] = [0; 64];

    // SAFETY: `ecx` is live per the contract; `pub_` is this call's own buffer.
    unsafe {
        match type_ {
            crate::ec::ecx_key::ECX_KEY_TYPE_X25519 => {
                ossl_x25519_public_from_private(pub_.as_mut_ptr(), (*ecx).privkey);
            }
            crate::ec::ecx_key::ECX_KEY_TYPE_X448 => {
                ossl_x448_public_from_private(pub_.as_mut_ptr(), (*ecx).privkey);
            }
            _ => return 0,
        }
        c_int::from(
            CRYPTO_memcmp(
                (*ecx).pubkey.as_ptr().cast(),
                pub_.as_ptr().cast(),
                (*ecx).keylen,
            ) == 0,
        )
    }
}

/// `static int ecd_key_pairwise_check(const ECX_KEY *ecx, int type)` — `ecx_kmgmt.c:1479-1499`,
/// the **non-`FIPS_MODULE`** arm.
///
/// # Safety
/// `ecx` is live.
unsafe fn ecd_key_pairwise_check(ecx: *const EcxKey, type_: c_int) -> c_int {
    let mut pub_: [u8; 64] = [0; 64];

    // SAFETY: `ecx` is live per the contract; `pub_` is this call's own buffer.
    unsafe {
        match type_ {
            crate::ec::ecx_key::ECX_KEY_TYPE_ED25519 => {
                if ossl_ed25519_public_from_private(
                    (*ecx).libctx,
                    pub_.as_mut_ptr(),
                    (*ecx).privkey,
                    (*ecx).propq,
                ) == 0
                {
                    return 0;
                }
            }
            crate::ec::ecx_key::ECX_KEY_TYPE_ED448 => {
                if ossl_ed448_public_from_private(
                    (*ecx).libctx,
                    pub_.as_mut_ptr(),
                    (*ecx).privkey,
                    (*ecx).propq,
                ) == 0
                {
                    return 0;
                }
            }
            _ => return 0,
        }
        c_int::from(
            CRYPTO_memcmp(
                (*ecx).pubkey.as_ptr().cast(),
                pub_.as_ptr().cast(),
                (*ecx).keylen,
            ) == 0,
        )
    }
}

/// `static int ecx_validate(const void *keydata, int selection, int type, size_t keylen)` —
/// `ecx_kmgmt.c:1501-1537`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe fn ecx_validate(
    keydata: *const c_void,
    selection: c_int,
    type_: c_int,
    keylen: usize,
) -> c_int {
    let ecx = keydata.cast::<EcxKey>();
    // SAFETY: `ecx` is the caller's object.
    let mut ok: c_int = c_int::from(keylen == unsafe { (*ecx).keylen });

    if is_running() == 0 {
        return 0;
    }
    if (selection & ECX_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }
    if ok == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ECX_KMGMT_1514) };
        return 0;
    }

    // SAFETY: `ecx` is the caller's object.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= c_int::from((*ecx).haspubkey != 0);
            // `#ifdef FIPS_MODULE ok = ok && ecd_key_pub_check(ecx, type);` is absent.
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= c_int::from(!(*ecx).privkey.is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != OSSL_KEYMGMT_SELECT_KEYPAIR {
            return ok;
        }
        if ecx_key_type_is_ed(type_) != 0 {
            ok &= ecd_key_pairwise_check(ecx, type_);
        } else {
            ok &= ecx_key_pairwise_check(ecx, type_);
        }
    }
    ok
}

/// `static int x25519_validate(const void *keydata, int selection, int checktype)` —
/// `ecx_kmgmt.c:1539-1542`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn x25519_validate(
    keydata: *const c_void,
    selection: c_int,
    _checktype: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_validate(
            keydata,
            selection,
            crate::ec::ecx_key::ECX_KEY_TYPE_X25519,
            X25519_KEYLEN,
        )
    }
}

/// `static int x448_validate(const void *keydata, int selection, int checktype)` —
/// `ecx_kmgmt.c:1544-1547`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn x448_validate(
    keydata: *const c_void,
    selection: c_int,
    _checktype: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_validate(
            keydata,
            selection,
            crate::ec::ecx_key::ECX_KEY_TYPE_X448,
            X448_KEYLEN,
        )
    }
}

/// `static int ed25519_validate(const void *keydata, int selection, int checktype)` —
/// `ecx_kmgmt.c:1549-1552`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn ed25519_validate(
    keydata: *const c_void,
    selection: c_int,
    _checktype: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_validate(
            keydata,
            selection,
            crate::ec::ecx_key::ECX_KEY_TYPE_ED25519,
            ED25519_KEYLEN,
        )
    }
}

/// `static int ed448_validate(const void *keydata, int selection, int checktype)` —
/// `ecx_kmgmt.c:1554-1557`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn ed448_validate(
    keydata: *const c_void,
    selection: c_int,
    _checktype: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecx_validate(
            keydata,
            selection,
            crate::ec::ecx_key::ECX_KEY_TYPE_ED448,
            ED448_KEYLEN,
        )
    }
}

/// `static void ecx_free_key(void *keydata)` — `ecx_kmgmt.c:1559-1562`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn ecx_free_key(keydata: *mut c_void) {
    // SAFETY: the caller hands back what a `*_new_key` answered.
    unsafe { ossl_ecx_key_free(keydata.cast()) };
}

/// `MAKE_KEYMGMT_FUNCTIONS(alg)` — `ecx_kmgmt.c:1564-1588`. The authority's macro expands to one
/// twenty-slot table per algorithm; Rust cannot splice a macro into an array literal's slot list,
/// so each of the four is written out. Every slot is the authority's, in its order.
macro_rules! ecx_keymgmt_functions {
    (
        $new_key:expr, $get_params:expr, $gettable:expr, $set_params:expr, $settable:expr,
        $validate:expr, $gen_init:expr, $gen:expr,
    ) => {
        [
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_NEW,
                function: $new_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_FREE,
                function: ecx_free_key as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
                function: $get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
                function: $gettable as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
                function: $set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
                function: $settable as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_HAS,
                function: ecx_has as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_MATCH,
                function: ecx_match as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
                function: $validate as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT,
                function: ecx_import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
                function: ecx_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT,
                function: ecx_export as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
                function: ecx_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
                function: $gen_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
                function: ecx_gen_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                function: ecx_gen_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN,
                function: $gen as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
                function: ecx_gen_cleanup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_LOAD,
                function: ecx_load as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_DUP,
                function: ecx_dup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ]
    };
}

/// `const OSSL_DISPATCH ossl_x25519_keymgmt_functions[]` — `ecx_kmgmt.c:1590`.
pub(crate) static X25519_KEYMGMT_FUNCTIONS: [OsslDispatch; 21] = ecx_keymgmt_functions!(
    x25519_new_key,
    x25519_get_params,
    x25519_gettable_params,
    x25519_set_params,
    x25519_settable_params,
    x25519_validate,
    x25519_gen_init,
    x25519_gen,
);

/// `const OSSL_DISPATCH ossl_x448_keymgmt_functions[]` — `ecx_kmgmt.c:1591`.
pub(crate) static X448_KEYMGMT_FUNCTIONS: [OsslDispatch; 21] = ecx_keymgmt_functions!(
    x448_new_key,
    x448_get_params,
    x448_gettable_params,
    x448_set_params,
    x448_settable_params,
    x448_validate,
    x448_gen_init,
    x448_gen,
);

/// `const OSSL_DISPATCH ossl_ed25519_keymgmt_functions[]` — `ecx_kmgmt.c:1592`.
pub(crate) static ED25519_KEYMGMT_FUNCTIONS: [OsslDispatch; 21] = ecx_keymgmt_functions!(
    ed25519_new_key,
    ed25519_get_params,
    ed25519_gettable_params,
    ed25519_set_params,
    ed25519_settable_params,
    ed25519_validate,
    ed25519_gen_init,
    ed25519_gen,
);

/// `const OSSL_DISPATCH ossl_ed448_keymgmt_functions[]` — `ecx_kmgmt.c:1593`.
pub(crate) static ED448_KEYMGMT_FUNCTIONS: [OsslDispatch; 21] = ecx_keymgmt_functions!(
    ed448_new_key,
    ed448_get_params,
    ed448_gettable_params,
    ed448_set_params,
    ed448_settable_params,
    ed448_validate,
    ed448_gen_init,
    ed448_gen,
);
