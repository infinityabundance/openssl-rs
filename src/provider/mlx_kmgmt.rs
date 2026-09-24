//! Phase 8 — `providers/implementations/keymgmt/mlx_kmgmt.c.in`: the four ML-KEM/EC-ECX hybrid
//! `OSSL_OP_KEYMGMT` rows.
//!
//! Eight hundred and forty-four template lines and **one** body with four macro expansions. The
//! hybrid holds *two* `EVP_PKEY`s — an ML-KEM half and an EC or ECX half — and every column is a
//! thin pass-through to the corresponding `EVP_PKEY_*` call on one or both of them. **There is no
//! `crypto/mlx/`**: the hybrid logic *is* this unit and its KEM sibling `mlx_kem.c`.
//!
//! ## The key-material layout is the authority's offset arithmetic, not a struct
//!
//! The exported public block is `ML-KEM-pub || x-pub` or `x-pub || ML-KEM-pub` depending on
//! `xinfo->ml_kem_slot`, and the private block the same way; `export_sub`/`load_keys` place each
//! half's bytes at its slot's offset. Those offsets are computed here exactly as the authority
//! computes them (`slot * pubkey_bytes`, `(1 - ml_kem_slot) * pubkey_bytes`, ...).
//!
//! ## The decoders are written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for each `produce_param_decoder` block, a
//! character-by-character `switch` trie over the parameter's key. Its whole observable content is
//! the **repeated-key refusal** at the parameter's own coordinate plus the located pointer this
//! unit's body reads. The four decoders here are the repeated-key scan plus `OSSL_PARAM_locate_const`
//! per key. **The coordinates are not guessed from the tuple's order**: they were read back from the
//! generated `build/openssl-3.6.4-production/.../mlx_kmgmt.c`, which is why the import decoder's
//! `priv`/`pub` pair (both `p`, `r` before `u`), the get-params decoder's `b`·`e`·`m`·`p` then the
//! `s` subtree, the set-params decoder's `e`·`p`, and the gen-set-params decoder's lone `p` are
//! paired with the lines that file actually raises at.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS,
};
use crate::evp::pkey::{
    openssl_rs_evp_pkey_q_keygen, EVP_PKEY_dup, EVP_PKEY_eq, EVP_PKEY_free, EvpPkey,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, OSSL_PKEY_PARAM_GROUP_NAME,
};
use crate::evp::pmeth_gn::{EVP_PKEY_export, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init};
use crate::ml_kem::key::ossl_ml_kem_get_vinfo;
use crate::ml_kem::{MlKemVinfo, EVP_PKEY_ML_KEM_1024, EVP_PKEY_ML_KEM_768};
use crate::param_build_set::ossl_param_build_set_octet_string;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_size_t, OsslParam, END,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
    OPENSSL_cleanse,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_zalloc};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649-650`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// `src/evp/pkey.rs` keeps its own copy private, so the union is spelled here from the two
/// **imported** bits rather than from a second copy of either (D402).
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `OSSL_PKEY_PARAM_BITS` — `core_names.h` (spelled `OSSL_ALG_PARAM_BITS` there).
const OSSL_PKEY_PARAM_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h`.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE` — `core_names.h`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — `core_names.h`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
/// `OSSL_PKEY_PARAM_PRIV_KEY` — `core_names.h`.
const OSSL_PKEY_PARAM_PRIV_KEY: *const c_char = c"priv".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — `core_names.h`.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();
/// `OSSL_PKEY_PARAM_PROPERTIES` — `core_names.h`.
const OSSL_PKEY_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `minimal_selection` — `mlx_kmgmt.c:47-48`.
const MINIMAL_SELECTION: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

/// `MLX_HAVE_NOKEYS` — `prov/mlx_kem.h:39`.
const MLX_HAVE_NOKEYS: c_uint = 0;
/// `MLX_HAVE_PUBKEY` — `prov/mlx_kem.h:40`.
const MLX_HAVE_PUBKEY: c_uint = 1;
/// `MLX_HAVE_PRVKEY` — `prov/mlx_kem.h:41`.
const MLX_HAVE_PRVKEY: c_uint = 2;

/// `mlx_kem_have_pubkey(key)` — `prov/mlx_kem.h:44`, `(key)->state > 0`.
#[inline]
pub(crate) unsafe fn mlx_kem_have_pubkey(key: *const MlxKey) -> bool {
    // SAFETY: `key` is live per the caller's contract.
    unsafe { (*key).state > MLX_HAVE_NOKEYS }
}

/// `mlx_kem_have_prvkey(key)` — `prov/mlx_kem.h:45`, `(key)->state > 1`.
#[inline]
pub(crate) unsafe fn mlx_kem_have_prvkey(key: *const MlxKey) -> bool {
    // SAFETY: `key` is live per the caller's contract.
    unsafe { (*key).state > MLX_HAVE_PUBKEY }
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `ECDH_VINFO` — `prov/mlx_kem.h:19-27`, field for field.
#[repr(C)]
pub(crate) struct EcdhVinfo {
    /// `const char *algorithm_name`.
    pub(crate) algorithm_name: *const c_char,
    /// `const char *group_name` — NULL for the ECX halves.
    pub(crate) group_name: *const c_char,
    /// `size_t pubkey_bytes`.
    pub(crate) pubkey_bytes: usize,
    /// `size_t prvkey_bytes`.
    pub(crate) prvkey_bytes: usize,
    /// `size_t shsec_bytes`.
    pub(crate) shsec_bytes: usize,
    /// `int ml_kem_slot`.
    pub(crate) ml_kem_slot: c_int,
    /// `int ml_kem_variant`.
    pub(crate) ml_kem_variant: c_int,
}

// SAFETY: every pointer is to a `'static` literal, so the table is immutable and safe to share,
// exactly like the C's `static const ECDH_VINFO hybrid_vtable[]`.
unsafe impl Sync for EcdhVinfo {}

/// `static const ECDH_VINFO hybrid_vtable[]` — `mlx_kmgmt.c:51-58`, in the authority's own order.
/// The `#if !defined(OPENSSL_NO_ECX)` rows are compiled: `OPENSSL_NO_ECX` is not in the admitted
/// profile.
static HYBRID_VTABLE: [EcdhVinfo; 4] = [
    EcdhVinfo {
        algorithm_name: c"EC".as_ptr(),
        group_name: c"P-256".as_ptr(),
        pubkey_bytes: 65,
        prvkey_bytes: 32,
        shsec_bytes: 32,
        ml_kem_slot: 1,
        ml_kem_variant: EVP_PKEY_ML_KEM_768,
    },
    EcdhVinfo {
        algorithm_name: c"EC".as_ptr(),
        group_name: c"P-384".as_ptr(),
        pubkey_bytes: 97,
        prvkey_bytes: 48,
        shsec_bytes: 48,
        ml_kem_slot: 1,
        ml_kem_variant: EVP_PKEY_ML_KEM_1024,
    },
    EcdhVinfo {
        algorithm_name: c"X25519".as_ptr(),
        group_name: ptr::null(),
        pubkey_bytes: 32,
        prvkey_bytes: 32,
        shsec_bytes: 32,
        ml_kem_slot: 0,
        ml_kem_variant: EVP_PKEY_ML_KEM_768,
    },
    EcdhVinfo {
        algorithm_name: c"X448".as_ptr(),
        group_name: ptr::null(),
        pubkey_bytes: 56,
        prvkey_bytes: 56,
        shsec_bytes: 56,
        ml_kem_slot: 0,
        ml_kem_variant: EVP_PKEY_ML_KEM_1024,
    },
];

/// `MLX_KEY` — `prov/mlx_kem.h:29-37`, field for field.
#[repr(C)]
pub(crate) struct MlxKey {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — owned.
    pub(crate) propq: *mut c_char,
    /// `const ML_KEM_VINFO *minfo`.
    pub(crate) minfo: *const MlKemVinfo,
    /// `const ECDH_VINFO *xinfo`.
    pub(crate) xinfo: *const EcdhVinfo,
    /// `EVP_PKEY *mkey`.
    pub(crate) mkey: *mut EvpPkey,
    /// `EVP_PKEY *xkey`.
    pub(crate) xkey: *mut EvpPkey,
    /// `unsigned int state`.
    pub(crate) state: c_uint,
}

/// `PROV_ML_KEM_GEN_CTX` — `mlx_kmgmt.c:60-65`.
#[repr(C)]
struct ProvMlxKemGenCtx {
    /// `OSSL_LIB_CTX *libctx` — borrowed.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `int selection`.
    selection: c_int,
    /// `unsigned int evp_type` — the hybrid-vtable index.
    evp_type: c_uint,
}

/// The generated unit's own `__FILE__`. `.c.in`-generated, so the bare build-relative path.
const FILE: *const c_char = c"providers/implementations/keymgmt/mlx_kmgmt.c".as_ptr();

/// `mlx_kmgmt.c:86`, `mlx_kem_key_new`'s `OPENSSL_malloc`.
const LINE_KEY_NEW: c_int = 86;
/// `mlx_kmgmt.c:99`, `mlx_kem_key_new`'s `err:` `OPENSSL_free(propq)`.
const LINE_KEY_NEW_PROPQ: c_int = 99;
/// `mlx_kmgmt.c:334`, `mlx_kem_export`'s `OPENSSL_malloc(publen)`.
const LINE_EXPORT_PUB: c_int = 334;
/// `mlx_kmgmt.c:346`, `mlx_kem_export`'s `OPENSSL_secure_zalloc(prvlen)`.
const LINE_EXPORT_PRV: c_int = 346;
/// `mlx_kmgmt.c:872`, `mlx_kem_set_params`'s `OPENSSL_free(key->propq)`.
const LINE_SET_FREE_PROPQ: c_int = 872;
/// `mlx_kmgmt.c:950`/`951`, `mlx_kem_gen_set_params`'s free-then-`OPENSSL_strdup`.
const LINE_GEN_SET_PROPQ: c_int = 950;
/// `mlx_kmgmt.c:968`, `mlx_kem_gen_init`'s `OPENSSL_zalloc(sizeof(*gctx))`.
const LINE_GEN_ZALLOC: c_int = 968;
/// `mlx_kmgmt.c:1027`/`1028`, `mlx_kem_gen_cleanup`'s two frees.
const LINE_GEN_CLEANUP_PROPQ: c_int = 1027;
/// `mlx_kmgmt.c:1028`.
const LINE_GEN_CLEANUP_CTX: c_int = 1028;
/// `mlx_kmgmt.c:1037`, `mlx_kem_dup`'s `OPENSSL_memdup`.
const LINE_DUP_MEMDUP: c_int = 1037;
/// `mlx_kmgmt.c:1044`/`1054`, `mlx_kem_dup`'s `OPENSSL_free(ret)`.
const LINE_DUP_FREE: c_int = 1044;
/// `mlx_kmgmt.c:71`, `mlx_kem_key_free`'s `OPENSSL_free(key->propq)`.
const LINE_KEY_FREE_PROPQ: c_int = 71;
/// `mlx_kmgmt.c:74`, `mlx_kem_key_free`'s `OPENSSL_free(key)`.
const LINE_KEY_FREE: c_int = 74;

/// Raise a fixed message through a site, the `ERR_raise_data` form.
///
/// # Safety
/// Nothing: the message is a NUL-terminated literal built here.
unsafe fn raise_fixed(site: &err_sites::ErrSite, msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
}

/// `static void mlx_kem_key_free(void *vkey)` — `mlx_kmgmt.c:67-77`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn mlx_kem_key_free(vkey: *mut c_void) {
    let key = vkey.cast::<MlxKey>();

    if key.is_null() {
        return;
    }
    // SAFETY: `key` is live per the contract; both frees accept NULL.
    unsafe {
        CRYPTO_free((*key).propq.cast(), FILE, LINE_KEY_FREE_PROPQ);
        EVP_PKEY_free((*key).mkey);
        EVP_PKEY_free((*key).xkey);
        CRYPTO_free(vkey, FILE, LINE_KEY_FREE);
    }
}

/// `static void *mlx_kem_key_new(unsigned int v, OSSL_LIB_CTX *libctx, char *propq)` —
/// `mlx_kmgmt.c:80-103`. Takes ownership of `propq`.
///
/// # Safety
/// `libctx` is NULL or live; `propq` is NULL or a heap string this call may take.
unsafe fn mlx_kem_key_new(v: c_uint, libctx: *mut c_void, propq: *mut c_char) -> *mut MlxKey {
    // SAFETY: the malloc answers NULL on failure, which is checked.
    unsafe {
        if is_running() == 0 || v as usize >= HYBRID_VTABLE.len() {
            CRYPTO_free(propq.cast(), FILE, LINE_KEY_NEW_PROPQ);
            return ptr::null_mut();
        }
        let key =
            CRYPTO_malloc(core::mem::size_of::<MlxKey>(), FILE, LINE_KEY_NEW).cast::<MlxKey>();
        if key.is_null() {
            CRYPTO_free(propq.cast(), FILE, LINE_KEY_NEW_PROPQ);
            return ptr::null_mut();
        }

        let ml_kem_variant = HYBRID_VTABLE[v as usize].ml_kem_variant;
        (*key).libctx = libctx;
        (*key).minfo = ossl_ml_kem_get_vinfo(ml_kem_variant);
        (*key).xinfo = &HYBRID_VTABLE[v as usize];
        (*key).xkey = ptr::null_mut();
        (*key).mkey = ptr::null_mut();
        (*key).state = MLX_HAVE_NOKEYS;
        (*key).propq = propq;
        key
    }
}

/// `static int mlx_kem_has(const void *vkey, int selection)` — `mlx_kmgmt.c:105-121`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn mlx_kem_has(vkey: *const c_void, selection: c_int) -> c_int {
    let key = vkey.cast::<MlxKey>();

    // A NULL key MUST fail to have anything
    if is_running() == 0 || key.is_null() {
        return 0;
    }

    // SAFETY: `key` is non-NULL past the guard.
    unsafe {
        match selection & OSSL_KEYMGMT_SELECT_KEYPAIR {
            0 => 1,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY => c_int::from(mlx_kem_have_pubkey(key)),
            _ => c_int::from(mlx_kem_have_prvkey(key)),
        }
    }
}

/// `static int mlx_kem_match(const void *vkey1, const void *vkey2, int selection)` —
/// `mlx_kmgmt.c:123-149`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn mlx_kem_match(
    vkey1: *const c_void,
    vkey2: *const c_void,
    selection: c_int,
) -> c_int {
    let key1 = vkey1.cast::<MlxKey>();
    let key2 = vkey2.cast::<MlxKey>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: both keys are the caller's.
    unsafe {
        let have_pub1 = mlx_kem_have_pubkey(key1);
        let have_pub2 = mlx_kem_have_pubkey(key2);

        // Compare domain parameters
        if (*key1).xinfo != (*key2).xinfo {
            return 0;
        }

        if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
            return 1;
        }

        if have_pub1 ^ have_pub2 {
            return 0;
        }

        // As in other providers, equal when both have no key material.
        if !have_pub1 {
            return 1;
        }

        c_int::from(
            EVP_PKEY_eq((*key1).mkey, (*key2).mkey) != 0
                && EVP_PKEY_eq((*key1).xkey, (*key2).xkey) != 0,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The four generated decoders' lists, in the order `paramnames.pm` emits them.
// ---------------------------------------------------------------------------------------------

/// `static const OSSL_PARAM ml_kem_import_export_list[]` — generated `mlx_kmgmt.c:152-156`.
static ML_KEM_IMPORT_EXPORT_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PUB_KEY),
    END,
];

/// `static const OSSL_PARAM mlx_get_params_list[]` — generated `mlx_kmgmt.c:542-550`.
static MLX_GET_PARAMS_LIST: [OsslParam; 7] = [
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    param_octet_string(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `static const OSSL_PARAM mlx_set_params_list[]` — generated `mlx_kmgmt.c:802-806`.
static MLX_SET_PARAMS_LIST: [OsslParam; 3] = [
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES),
    END,
];

/// `static const OSSL_PARAM mlx_gen_set_params_list[]` — generated `mlx_kmgmt.c:903-906`.
static MLX_GEN_SET_PARAMS_LIST: [OsslParam; 2] =
    [param_utf8_string(OSSL_PKEY_PARAM_PROPERTIES), END];

/// `struct ml_kem_import_export_st` — generated `mlx_kmgmt.c:160-163`.
pub(crate) struct MlKemImportExport {
    /// `OSSL_PARAM *privkey`.
    privkey: *const OsslParam,
    /// `OSSL_PARAM *pubkey`.
    pubkey: *const OsslParam,
}

/// `struct mlx_get_params_st` — generated `mlx_kmgmt.c:554-561`.
struct MlxGetParams {
    /// `OSSL_PARAM *bits`.
    bits: *mut OsslParam,
    /// `OSSL_PARAM *maxsize`.
    maxsize: *mut OsslParam,
    /// `OSSL_PARAM *priv`.
    privkey: *mut OsslParam,
    /// `OSSL_PARAM *pub`.
    pubkey: *mut OsslParam,
    /// `OSSL_PARAM *secbits`.
    secbits: *mut OsslParam,
    /// `OSSL_PARAM *seccat`.
    seccat: *mut OsslParam,
}

/// `struct mlx_set_params_st` — generated `mlx_kmgmt.c:810-813`.
struct MlxSetParams {
    /// `OSSL_PARAM *propq`.
    propq: *mut OsslParam,
    /// `OSSL_PARAM *pub`.
    pubparam: *mut OsslParam,
}

/// `struct mlx_gen_set_params_st` — generated `mlx_kmgmt.c:910-912`.
struct MlxGenSetParams {
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
}

/// The repeated-key scan a generated decoder is — the same walk `src/provider/ml_kem_kmgmt.rs`
/// carries.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn repeated_param_site(
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

/// The `ml_kem_import_export` decoder's two coordinates, read back from the generated unit:
/// both keys start `p`, `r` (`priv`) before `u` (`pub`).
const IMPORT_EXPORT_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_MLX_KMGMT_186, OSSL_PKEY_PARAM_PRIV_KEY),
    (&err_sites::PROV_MLX_KMGMT_197, OSSL_PKEY_PARAM_PUB_KEY),
];

/// The `mlx_get_params` decoder's six coordinates, in the trie's own leaf order:
/// `b` (`bits`), `e` (`encoded-pub-key`), `m` (`max-size`), `p` (`priv`), then the `s` subtree's
/// `security-bits`·`security-category`.
const GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 6] = [
    (&err_sites::PROV_MLX_KMGMT_580, OSSL_PKEY_PARAM_BITS),
    (
        &err_sites::PROV_MLX_KMGMT_591,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    ),
    (&err_sites::PROV_MLX_KMGMT_602, OSSL_PKEY_PARAM_MAX_SIZE),
    (&err_sites::PROV_MLX_KMGMT_613, OSSL_PKEY_PARAM_PRIV_KEY),
    (
        &err_sites::PROV_MLX_KMGMT_660,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    ),
    (
        &err_sites::PROV_MLX_KMGMT_671,
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
    ),
];

/// The `mlx_set_params` decoder's two coordinates: `e` (`encoded-pub-key`), then `p`
/// (`properties`).
const SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (
        &err_sites::PROV_MLX_KMGMT_832,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    ),
    (&err_sites::PROV_MLX_KMGMT_843, OSSL_PKEY_PARAM_PROPERTIES),
];

/// The `mlx_gen_set_params` decoder's one coordinate.
const GEN_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] =
    [(&err_sites::PROV_MLX_KMGMT_927, OSSL_PKEY_PARAM_PROPERTIES)];

/// `ml_kem_import_export_decoder` — generated `mlx_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
pub(crate) unsafe fn ml_kem_import_export_decoder(
    params: *const OsslParam,
    r: &mut MlKemImportExport,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &IMPORT_EXPORT_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        r.pubkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    }
    1
}

/// `mlx_get_params_decoder` — generated `mlx_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn get_params_decoder(params: *const OsslParam, r: &mut MlxGetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS) as *mut OsslParam;
        r.secbits =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS) as *mut OsslParam;
        r.maxsize = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE) as *mut OsslParam;
        r.seccat =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY) as *mut OsslParam;
        r.pubkey =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) as *mut OsslParam;
        r.privkey = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) as *mut OsslParam;
    }
    1
}

/// `mlx_set_params_decoder` — generated `mlx_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn set_params_decoder(params: *const OsslParam, r: &mut MlxSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.pubparam =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) as *mut OsslParam;
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES) as *mut OsslParam;
    }
    1
}

/// `mlx_gen_set_params_decoder` — generated `mlx_kmgmt.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn gen_set_params_decoder(params: *const OsslParam, r: &mut MlxGenSetParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = repeated_param_site(params, &GEN_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.propq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    }
    1
}

// ---------------------------------------------------------------------------------------------
// `export`
// ---------------------------------------------------------------------------------------------

/// `EXPORT_CB_ARG` — `mlx_kmgmt.c:158-168`.
#[repr(C)]
struct ExportCbArg {
    /// `const char *algorithm_name`.
    algorithm_name: *const c_char,
    /// `uint8_t *pubenc`.
    pubenc: *mut u8,
    /// `uint8_t *prvenc`.
    prvenc: *mut u8,
    /// `int pubcount`.
    pubcount: c_int,
    /// `int prvcount`.
    prvcount: c_int,
    /// `size_t puboff`.
    puboff: usize,
    /// `size_t prvoff`.
    prvoff: usize,
    /// `size_t publen`.
    publen: usize,
    /// `size_t prvlen`.
    prvlen: usize,
}

/// The authority's `"Unexpected %s <kind> key length %lu != %lu"` message, built here.
///
/// # Safety
/// `alg` is a NUL-terminated C string.
unsafe fn raise_length_mismatch(
    site: &err_sites::ErrSite,
    alg: *const c_char,
    kind: &str,
    got: usize,
    expected: usize,
) {
    // SAFETY: `alg` is NUL-terminated per the contract.
    let a = unsafe { CStr::from_ptr(alg) }.to_string_lossy();
    // SAFETY: forwarded under this function's contract.
    unsafe {
        raise_fixed(
            site,
            &format!("Unexpected {a} {kind} key length {got} != {expected}"),
        );
    }
}

/// `static int export_sub_cb(const OSSL_PARAM *params, void *varg)` — `mlx_kmgmt.c:171-214`.
///
/// # Safety
/// `params` is key-terminated and `varg` names a live `ExportCbArg`.
unsafe extern "C" fn export_sub_cb(params: *const OsslParam, varg: *mut c_void) -> c_int {
    let sub_arg = varg.cast::<ExportCbArg>();
    let mut p = MlKemImportExport {
        privkey: ptr::null(),
        pubkey: ptr::null(),
    };
    let mut len = 0usize;

    // SAFETY: the arguments are per the contract.
    unsafe {
        if ml_kem_import_export_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !(*sub_arg).pubenc.is_null() && !p.pubkey.is_null() {
            let mut pubp: *mut c_void = (*sub_arg).pubenc.add((*sub_arg).puboff).cast();

            if OSSL_PARAM_get_octet_string(p.pubkey, &mut pubp, (*sub_arg).publen, &mut len) != 1 {
                return 0;
            }
            if len != (*sub_arg).publen {
                raise_length_mismatch(
                    &err_sites::PROV_MLX_KMGMT_244,
                    (*sub_arg).algorithm_name,
                    "public",
                    len,
                    (*sub_arg).publen,
                );
                return 0;
            }
            (*sub_arg).pubcount += 1;
        }
        if !(*sub_arg).prvenc.is_null() && !p.privkey.is_null() {
            let mut prvp: *mut c_void = (*sub_arg).prvenc.add((*sub_arg).prvoff).cast();

            if OSSL_PARAM_get_octet_string(p.privkey, &mut prvp, (*sub_arg).prvlen, &mut len) != 1 {
                return 0;
            }
            if len != (*sub_arg).prvlen {
                // The authority's own message prints `sub_arg->publen` here, not `prvlen`
                // (`mlx_kmgmt.c:261`); it is reproduced rather than corrected.
                raise_length_mismatch(
                    &err_sites::PROV_MLX_KMGMT_258,
                    (*sub_arg).algorithm_name,
                    "private",
                    len,
                    (*sub_arg).publen,
                );
                return 0;
            }
            (*sub_arg).prvcount += 1;
        }
    }
    1
}

/// `static int export_sub(EXPORT_CB_ARG *sub_arg, int selection, MLX_KEY *key)` —
/// `mlx_kmgmt.c:216-252`.
///
/// # Safety
/// `sub_arg` is writable and `key` is live.
unsafe fn export_sub(sub_arg: *mut ExportCbArg, selection: c_int, key: *mut MlxKey) -> c_int {
    // SAFETY: the pointers are the caller's.
    unsafe {
        (*sub_arg).pubcount = 0;
        (*sub_arg).prvcount = 0;

        for slot in 0..2 {
            let ml_kem_slot = (*(*key).xinfo).ml_kem_slot;
            let pkey: *const EvpPkey;

            // Export the parts of each component into its storage slot.
            if slot == ml_kem_slot {
                pkey = (*key).mkey;
                (*sub_arg).algorithm_name = (*(*key).minfo).algorithm_name;
                (*sub_arg).puboff = slot as usize * (*(*key).xinfo).pubkey_bytes;
                (*sub_arg).prvoff = slot as usize * (*(*key).xinfo).prvkey_bytes;
                (*sub_arg).publen = (*(*key).minfo).pubkey_bytes;
                (*sub_arg).prvlen = (*(*key).minfo).prvkey_bytes;
            } else {
                pkey = (*key).xkey;
                (*sub_arg).algorithm_name = (*(*key).xinfo).algorithm_name;
                (*sub_arg).puboff = (1 - ml_kem_slot) as usize * (*(*key).minfo).pubkey_bytes;
                (*sub_arg).prvoff = (1 - ml_kem_slot) as usize * (*(*key).minfo).prvkey_bytes;
                (*sub_arg).publen = (*(*key).xinfo).pubkey_bytes;
                (*sub_arg).prvlen = (*(*key).xinfo).prvkey_bytes;
            }
            if EVP_PKEY_export(pkey, selection, Some(export_sub_cb), sub_arg.cast()) == 0 {
                return 0;
            }
        }
    }
    1
}

/// `static int mlx_kem_export(void *vkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `mlx_kmgmt.c:254-334`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn mlx_kem_export(
    vkey: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let key = vkey.cast::<MlxKey>();
    let mut tmpl: *mut OSSL_PARAM_BLD = ptr::null_mut();
    let mut ret: c_int = 0;
    let mut sub_arg = ExportCbArg {
        algorithm_name: ptr::null(),
        pubenc: ptr::null_mut(),
        prvenc: ptr::null_mut(),
        pubcount: 0,
        prvcount: 0,
        puboff: 0,
        prvoff: 0,
        publen: 0,
        prvlen: 0,
    };

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
        return 0;
    }

    // SAFETY: `key` is live per the contract.
    unsafe {
        // Fail when no key material has yet been provided
        if !mlx_kem_have_pubkey(key) {
            raise_site(&err_sites::PROV_MLX_KMGMT_326);
            return 0;
        }
        let publen = (*(*key).minfo).pubkey_bytes + (*(*key).xinfo).pubkey_bytes;
        let prvlen = (*(*key).minfo).prvkey_bytes + (*(*key).xinfo).prvkey_bytes;

        // The authority's `err:` label, as one labelled block.
        'err: {
            if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
                sub_arg.pubenc = CRYPTO_malloc(publen, FILE, LINE_EXPORT_PUB).cast::<u8>();
                if sub_arg.pubenc.is_null() {
                    break 'err;
                }
            }

            if mlx_kem_have_prvkey(key) && selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
                // Allocated on the secure heap if configured; `ossl_param_build_set_octet_string`
                // detects it and uses the secure heap too.
                sub_arg.prvenc = CRYPTO_secure_zalloc(prvlen, FILE, LINE_EXPORT_PRV).cast::<u8>();
                if sub_arg.prvenc.is_null() {
                    break 'err;
                }
            }

            tmpl = OSSL_PARAM_BLD_new();
            if tmpl.is_null() {
                break 'err;
            }

            // Extract sub-component key material.
            if export_sub(&mut sub_arg as *mut ExportCbArg, selection, key) == 0 {
                break 'err;
            }

            if !sub_arg.pubenc.is_null()
                && sub_arg.pubcount == 2
                && ossl_param_build_set_octet_string(
                    tmpl,
                    ptr::null_mut(),
                    OSSL_PKEY_PARAM_PUB_KEY,
                    sub_arg.pubenc,
                    publen,
                ) == 0
            {
                break 'err;
            }

            if !sub_arg.prvenc.is_null()
                && sub_arg.prvcount == 2
                && ossl_param_build_set_octet_string(
                    tmpl,
                    ptr::null_mut(),
                    OSSL_PKEY_PARAM_PRIV_KEY,
                    sub_arg.prvenc,
                    prvlen,
                ) == 0
            {
                break 'err;
            }

            let params = OSSL_PARAM_BLD_to_param(tmpl);
            if params.is_null() {
                break 'err;
            }

            ret = match param_cb {
                Some(cb) => cb(params, cbarg),
                None => 0,
            };
            // `OSSL_PARAM_free()` only wipes the secure-heap data block, so wipe the key material
            // copies held in the params first.
            let mut p = params;
            while !(*p).key.is_null() {
                OPENSSL_cleanse((*p).data, (*p).data_size);
                p = p.add(1);
            }
            OSSL_PARAM_free(params);
        }

        // The `err:` tail — `mlx_kmgmt.c:329-333`. `ret` is 0 unless the callback ran.
        OSSL_PARAM_BLD_free(tmpl);
        CRYPTO_secure_clear_free(sub_arg.prvenc.cast(), prvlen, FILE, LINE_EXPORT_PRV);
        CRYPTO_clear_free(sub_arg.pubenc.cast(), publen, FILE, LINE_EXPORT_PUB);
        ret
    }
}

/// `static const OSSL_PARAM *mlx_kem_imexport_types(int selection)` — `mlx_kmgmt.c:336-341`.
///
/// # Safety
/// The keymgmt `import_types`/`export_types` dispatch contract.
unsafe extern "C" fn mlx_kem_imexport_types(selection: c_int) -> *const OsslParam {
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR != 0 {
        return ML_KEM_IMPORT_EXPORT_LIST.as_ptr();
    }
    ptr::null()
}

/// `static int load_slot(OSSL_LIB_CTX *libctx, const char *propq, const char *pname,`
/// `int selection, MLX_KEY *key, int slot, const uint8_t *in, int mbytes, int xbytes)` —
/// `mlx_kmgmt.c:343-385`.
///
/// # Safety
/// `key` is live and `in` is readable for the lengths the two halves imply.
unsafe fn load_slot(
    key: *mut MlxKey,
    pname: *const c_char,
    selection: c_int,
    slot: c_int,
    in_: *const u8,
    mbytes: c_int,
    xbytes: c_int,
) -> c_int {
    let mut parr: [OsslParam; 3] = [END, END, END];
    let alg: *const c_char;
    let mut group: *const c_char = ptr::null();
    let ppkey: *mut *mut EvpPkey;
    let off: usize;
    let len: usize;
    let mut ret = 0;

    // SAFETY: the pointers and lengths are per the contract.
    unsafe {
        let ml_kem_slot = (*(*key).xinfo).ml_kem_slot;

        if slot == ml_kem_slot {
            alg = (*(*key).minfo).algorithm_name;
            ppkey = ptr::addr_of_mut!((*key).mkey);
            off = slot as usize * xbytes as usize;
            len = mbytes as usize;
        } else {
            alg = (*(*key).xinfo).algorithm_name;
            group = (*(*key).xinfo).group_name;
            ppkey = ptr::addr_of_mut!((*key).xkey);
            off = (1 - ml_kem_slot) as usize * mbytes as usize;
            len = xbytes as usize;
        }

        let val: *mut c_void = in_.add(off).cast_mut().cast();

        let ctx = EVP_PKEY_CTX_new_from_name((*key).libctx, alg, (*key).propq);
        parr[0] = OSSL_PARAM_construct_octet_string(pname, val, len);
        if !group.is_null() {
            parr[1] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group.cast_mut(), 0);
        }
        if !ctx.is_null()
            && EVP_PKEY_fromdata_init(ctx) > 0
            && EVP_PKEY_fromdata(ctx, ppkey, selection, parr.as_mut_ptr()) > 0
        {
            ret = 1;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    ret
}

/// `static int load_keys(MLX_KEY *key, const uint8_t *pubenc, size_t publen,`
/// `const uint8_t *prvenc, size_t prvlen)` — `mlx_kmgmt.c:387-420`.
///
/// # Safety
/// `key` is live and the two buffers are readable for their stated lengths.
unsafe fn load_keys(
    key: *mut MlxKey,
    pubenc: *const u8,
    publen: usize,
    prvenc: *const u8,
    prvlen: usize,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        let mut ok = true;
        for slot in 0..2 {
            if prvlen != 0 {
                // Ignore public keys when private provided.
                ok = load_slot(
                    key,
                    OSSL_PKEY_PARAM_PRIV_KEY,
                    MINIMAL_SELECTION,
                    slot,
                    prvenc,
                    (*(*key).minfo).prvkey_bytes as c_int,
                    (*(*key).xinfo).prvkey_bytes as c_int,
                ) != 0;
            } else if publen != 0 {
                // Absent private key data, import public keys.
                ok = load_slot(
                    key,
                    OSSL_PKEY_PARAM_PUB_KEY,
                    MINIMAL_SELECTION,
                    slot,
                    pubenc,
                    (*(*key).minfo).pubkey_bytes as c_int,
                    (*(*key).xinfo).pubkey_bytes as c_int,
                ) != 0;
            }
            if !ok {
                break;
            }
        }
        if !ok {
            EVP_PKEY_free((*key).mkey);
            EVP_PKEY_free((*key).xkey);
            (*key).xkey = ptr::null_mut();
            (*key).mkey = ptr::null_mut();
            (*key).state = MLX_HAVE_NOKEYS;
            return 0;
        }
        (*key).state = if prvlen != 0 {
            MLX_HAVE_PRVKEY
        } else {
            MLX_HAVE_PUBKEY
        };
    }
    1
}

/// `static int mlx_kem_key_fromdata(MLX_KEY *key, const OSSL_PARAM params[],`
/// `int include_private)` — `mlx_kmgmt.c:422-469`.
///
/// # Safety
/// `key` is live and has no key material yet.
unsafe fn mlx_kem_key_fromdata(
    key: *mut MlxKey,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    let mut p = MlKemImportExport {
        privkey: ptr::null(),
        pubkey: ptr::null(),
    };
    let mut pubenc: *const c_void = ptr::null();
    let mut prvenc: *const c_void = ptr::null();
    let mut publen = 0usize;
    let mut prvlen = 0usize;

    // SAFETY: the arguments are per the contract.
    unsafe {
        // Invalid attempt to mutate a key, what is the right error to report?
        if key.is_null() || mlx_kem_have_pubkey(key) {
            return 0;
        }
        let pubkey_bytes = (*(*key).minfo).pubkey_bytes + (*(*key).xinfo).pubkey_bytes;
        let prvkey_bytes = (*(*key).minfo).prvkey_bytes + (*(*key).xinfo).prvkey_bytes;

        if ml_kem_import_export_decoder(params, &mut p) == 0 {
            return 0;
        }

        // What does the caller want to set?
        if !p.pubkey.is_null()
            && OSSL_PARAM_get_octet_string_ptr(p.pubkey, &mut pubenc, &mut publen) != 1
        {
            return 0;
        }
        if include_private != 0
            && !p.privkey.is_null()
            && OSSL_PARAM_get_octet_string_ptr(p.privkey, &mut prvenc, &mut prvlen) != 1
        {
            return 0;
        }

        // The caller MUST specify at least one of the public or private keys.
        if publen == 0 && prvlen == 0 {
            raise_site(&err_sites::PROV_MLX_KMGMT_503);
            return 0;
        }

        // When a pubkey is provided, its length MUST be correct, if a private key is also
        // provided, the public key will be otherwise ignored.
        if publen != 0 && publen != pubkey_bytes {
            raise_site(&err_sites::PROV_MLX_KMGMT_513);
            return 0;
        }
        if prvlen != 0 && prvlen != prvkey_bytes {
            raise_site(&err_sites::PROV_MLX_KMGMT_517);
            return 0;
        }

        load_keys(key, pubenc.cast(), publen, prvenc.cast(), prvlen)
    }
}

/// `static int mlx_kem_import(void *vkey, int selection, const OSSL_PARAM params[])` —
/// `mlx_kmgmt.c:471-484`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn mlx_kem_import(
    vkey: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlxKey>();

    if is_running() == 0 || key.is_null() {
        return 0;
    }
    if selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
        return 0;
    }

    let include_private = c_int::from(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0);
    // SAFETY: `key` is live per the contract.
    unsafe { mlx_kem_key_fromdata(key, params, include_private) }
}

/// `static const OSSL_PARAM *mlx_kem_gettable_params(void *provctx)` — `mlx_kmgmt.c:497-500`.
///
/// # Safety
/// The keymgmt `gettable_params` dispatch contract.
unsafe extern "C" fn mlx_kem_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    MLX_GET_PARAMS_LIST.as_ptr()
}

/// `static int mlx_kem_get_params(void *vkey, OSSL_PARAM params[])` — `mlx_kmgmt.c:505-601`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn mlx_kem_get_params(vkey: *mut c_void, params: *mut OsslParam) -> c_int {
    let key = vkey.cast::<MlxKey>();
    let mut pubp: *mut OsslParam;
    let mut prv: *mut OsslParam = ptr::null_mut();
    let mut sub_arg = ExportCbArg {
        algorithm_name: ptr::null(),
        pubenc: ptr::null_mut(),
        prvenc: ptr::null_mut(),
        pubcount: 0,
        prvcount: 0,
        puboff: 0,
        prvoff: 0,
        publen: 0,
        prvlen: 0,
    };
    let mut p = MlxGetParams {
        bits: ptr::null_mut(),
        maxsize: ptr::null_mut(),
        privkey: ptr::null_mut(),
        pubkey: ptr::null_mut(),
        secbits: ptr::null_mut(),
        seccat: ptr::null_mut(),
    };

    // SAFETY: `key` and `params` are the caller's.
    unsafe {
        if key.is_null() || get_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        // The reported values are those of the ML-KEM key.
        if !p.bits.is_null() && OSSL_PARAM_set_int(p.bits, (*(*key).minfo).bits) == 0 {
            return 0;
        }
        if !p.secbits.is_null() && OSSL_PARAM_set_int(p.secbits, (*(*key).minfo).secbits) == 0 {
            return 0;
        }
        if !p.seccat.is_null()
            && OSSL_PARAM_set_int(p.seccat, (*(*key).minfo).security_category) == 0
        {
            return 0;
        }

        // The ciphertext sizes are additive.
        if !p.maxsize.is_null()
            && OSSL_PARAM_set_size_t(
                p.maxsize,
                (*(*key).minfo).ctext_bytes + (*(*key).xinfo).pubkey_bytes,
            ) == 0
        {
            return 0;
        }

        if !mlx_kem_have_pubkey(key) {
            return 1;
        }

        pubp = p.pubkey;
        if !pubp.is_null() {
            let publen = (*(*key).minfo).pubkey_bytes + (*(*key).xinfo).pubkey_bytes;

            if (*pubp).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            (*pubp).return_size = publen;
            if (*pubp).data.is_null() {
                pubp = ptr::null_mut();
            } else if (*pubp).data_size < publen {
                raise_fixed(
                    &err_sites::PROV_MLX_KMGMT_745,
                    &format!(
                        "public key output buffer too short: {} < {}",
                        (*pubp).data_size,
                        publen
                    ),
                );
                return 0;
            } else {
                sub_arg.pubenc = (*pubp).data.cast::<u8>();
            }
        }
        if mlx_kem_have_prvkey(key) {
            prv = p.privkey;
            if !prv.is_null() {
                let prvlen = (*(*key).minfo).prvkey_bytes + (*(*key).xinfo).prvkey_bytes;

                if (*prv).data_type != OSSL_PARAM_OCTET_STRING {
                    return 0;
                }
                (*prv).return_size = prvlen;
                if (*prv).data.is_null() {
                    prv = ptr::null_mut();
                } else if (*prv).data_size < prvlen {
                    raise_fixed(
                        &err_sites::PROV_MLX_KMGMT_764,
                        &format!(
                            "private key output buffer too short: {} < {}",
                            (*prv).data_size,
                            prvlen
                        ),
                    );
                    return 0;
                } else {
                    sub_arg.prvenc = (*prv).data.cast::<u8>();
                }
            }
        }
        if pubp.is_null() && prv.is_null() {
            return 1;
        }

        let mut selection = if prv.is_null() {
            0
        } else {
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY
        };
        selection |= if pubp.is_null() {
            0
        } else {
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY
        };
        if !(*(*key).xinfo).group_name.is_null() {
            selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
        }

        // Extract sub-component key material.
        if export_sub(&mut sub_arg as *mut ExportCbArg, selection, key) == 0
            || (!pubp.is_null() && sub_arg.pubcount != 2)
            || (!prv.is_null() && sub_arg.prvcount != 2)
        {
            // Erase any partial key material on failure.
            if !sub_arg.pubenc.is_null() {
                OPENSSL_cleanse(
                    sub_arg.pubenc.cast(),
                    (*(*key).minfo).pubkey_bytes + (*(*key).xinfo).pubkey_bytes,
                );
            }
            if !sub_arg.prvenc.is_null() {
                OPENSSL_cleanse(
                    sub_arg.prvenc.cast(),
                    (*(*key).minfo).prvkey_bytes + (*(*key).xinfo).prvkey_bytes,
                );
            }
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *mlx_kem_settable_params(void *provctx)` — `mlx_kmgmt.c:610-613`.
///
/// # Safety
/// The keymgmt `settable_params` dispatch contract.
unsafe extern "C" fn mlx_kem_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    MLX_SET_PARAMS_LIST.as_ptr()
}

/// `static int mlx_kem_set_params(void *vkey, const OSSL_PARAM params[])` —
/// `mlx_kmgmt.c:615-652`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn mlx_kem_set_params(vkey: *mut c_void, params: *const OsslParam) -> c_int {
    let key = vkey.cast::<MlxKey>();
    let mut p = MlxSetParams {
        propq: ptr::null_mut(),
        pubparam: ptr::null_mut(),
    };
    let mut pubenc: *const c_void = ptr::null();
    let mut publen = 0usize;

    // SAFETY: `key` and `params` are the caller's.
    unsafe {
        if key.is_null() || set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.propq.is_null() {
            CRYPTO_free((*key).propq.cast(), FILE, LINE_SET_FREE_PROPQ);
            (*key).propq = ptr::null_mut();
            if OSSL_PARAM_get_utf8_string(p.propq, &mut (*key).propq, 0) == 0 {
                return 0;
            }
        }

        if p.pubparam.is_null() {
            return 1;
        }

        // Key mutation is reportedly generally not allowed.
        if mlx_kem_have_pubkey(key) {
            raise_fixed(&err_sites::PROV_MLX_KMGMT_883, "keys cannot be mutated");
            return 0;
        }
        // An unlikely failure mode is the parameter having some unexpected type.
        if OSSL_PARAM_get_octet_string_ptr(p.pubparam, &mut pubenc, &mut publen) == 0 {
            return 0;
        }

        if publen != (*(*key).minfo).pubkey_bytes + (*(*key).xinfo).pubkey_bytes {
            raise_site(&err_sites::PROV_MLX_KMGMT_893);
            return 0;
        }

        load_keys(key, pubenc.cast(), publen, ptr::null(), 0)
    }
}

/// `static int mlx_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])` —
/// `mlx_kmgmt.c:660-676`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn mlx_kem_gen_set_params(vgctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = vgctx.cast::<ProvMlxKemGenCtx>();
    let mut p = MlxGenSetParams { propq: ptr::null() };

    // SAFETY: `gctx` and `params` are the caller's.
    unsafe {
        if gctx.is_null() || gen_set_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.propq.is_null() {
            if (*p.propq).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_SET_PROPQ);
            (*gctx).propq = CRYPTO_strdup((*p.propq).data.cast(), FILE, LINE_GEN_SET_PROPQ);
            if (*gctx).propq.is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static void *mlx_kem_gen_init(int evp_type, OSSL_LIB_CTX *libctx, int selection,`
/// `const OSSL_PARAM params[])` — `mlx_kmgmt.c:678-700`.
///
/// # Safety
/// `libctx` is NULL or live and `params` NULL or key-terminated.
unsafe fn mlx_kem_gen_init(
    evp_type: c_uint,
    libctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    if is_running() == 0 || selection & MINIMAL_SELECTION == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `CRYPTO_zalloc` answers NULL on failure, which is checked.
    let gctx = CRYPTO_zalloc(
        core::mem::size_of::<ProvMlxKemGenCtx>(),
        FILE,
        LINE_GEN_ZALLOC,
    )
    .cast::<ProvMlxKemGenCtx>();
    if gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is a fresh allocation; every field is written below.
    unsafe {
        (*gctx).evp_type = evp_type;
        (*gctx).libctx = libctx;
        (*gctx).selection = selection;
        if mlx_kem_gen_set_params(gctx.cast(), params) != 0 {
            return gctx.cast();
        }
        mlx_kem_gen_cleanup(gctx.cast());
    }
    ptr::null_mut()
}

/// `static const OSSL_PARAM *mlx_kem_gen_settable_params(void *vgctx, void *provctx)` —
/// `mlx_kmgmt.c:702-706`.
///
/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn mlx_kem_gen_settable_params(
    _vgctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    MLX_GEN_SET_PARAMS_LIST.as_ptr()
}

/// `static void *mlx_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `mlx_kmgmt.c:708-740`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn mlx_kem_gen(
    vgctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = vgctx.cast::<ProvMlxKemGenCtx>();

    if gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is live per the contract.
    unsafe {
        if (*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR == OSSL_KEYMGMT_SELECT_PUBLIC_KEY {
            return ptr::null_mut();
        }

        // Lose ownership of propq.
        let propq = (*gctx).propq;
        (*gctx).propq = ptr::null_mut();
        let key = mlx_kem_key_new((*gctx).evp_type, (*gctx).libctx, propq);
        if key.is_null() {
            return ptr::null_mut();
        }

        if (*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR == 0 {
            return key.cast();
        }

        // For now, using the same "propq" for all components.
        (*key).mkey = q_keygen(
            (*key).libctx,
            (*key).propq,
            (*(*key).minfo).algorithm_name,
            ptr::null(),
        );
        (*key).xkey = q_keygen(
            (*key).libctx,
            (*key).propq,
            (*(*key).xinfo).algorithm_name,
            (*(*key).xinfo).group_name,
        );
        if !(*key).mkey.is_null() && !(*key).xkey.is_null() {
            (*key).state = MLX_HAVE_PRVKEY;
            return key.cast();
        }

        mlx_kem_key_free(key.cast());
    }
    ptr::null_mut()
}

/// `EVP_PKEY_Q_keygen(libctx, propq, type, ...)` — `crypto/evp/evp_lib.c:1219`.
///
/// The export is C-variadic, so the walk lives in `src/evp/pkey_q_keygen_variadic.c` and reports
/// `kind` — 0 for no argument, 2 for one group name. Its whole decision is which name reads what:
/// `"EC"` (case-insensitively) reads one `char *`, anything else reads nothing. That test is
/// reproduced here so the two halves of the call agree, and `group` is passed as the name argument
/// (NULL for the ECX halves, which the `kind == 0` path never reads).
///
/// # Safety
/// `libctx` NULL or live; `propq`/`alg`/`group` NULL or NUL-terminated.
unsafe fn q_keygen(
    libctx: *mut c_void,
    propq: *const c_char,
    alg: *const c_char,
    group: *const c_char,
) -> *mut EvpPkey {
    // SAFETY: the strings are NUL-terminated per the contract.
    let kind = if unsafe { OPENSSL_strcasecmp(alg, c"EC".as_ptr()) } == 0 {
        2
    } else {
        0
    };
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { openssl_rs_evp_pkey_q_keygen(libctx, propq, alg, kind, 0, group) }
}

/// `static void mlx_kem_gen_cleanup(void *vgctx)` — `mlx_kmgmt.c:742-750`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn mlx_kem_gen_cleanup(vgctx: *mut c_void) {
    let gctx = vgctx.cast::<ProvMlxKemGenCtx>();

    if gctx.is_null() {
        return;
    }
    // SAFETY: `gctx` is live per the contract; both frees accept NULL.
    unsafe {
        CRYPTO_free((*gctx).propq.cast(), FILE, LINE_GEN_CLEANUP_PROPQ);
        CRYPTO_free(vgctx, FILE, LINE_GEN_CLEANUP_CTX);
    }
}

/// `static void *mlx_kem_dup(const void *vkey, int selection)` — `mlx_kmgmt.c:752-797`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn mlx_kem_dup(vkey: *const c_void, selection: c_int) -> *mut c_void {
    let key = vkey.cast::<MlxKey>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `key` is the caller's.
    unsafe {
        let ret = CRYPTO_memdup(vkey, core::mem::size_of::<MlxKey>(), FILE, LINE_DUP_MEMDUP)
            .cast::<MlxKey>();
        if ret.is_null() {
            return ptr::null_mut();
        }

        (*ret).mkey = ptr::null_mut();
        (*ret).xkey = ptr::null_mut();

        if !(*key).propq.is_null() {
            (*ret).propq = CRYPTO_strdup((*key).propq, FILE, LINE_DUP_MEMDUP);
            if (*ret).propq.is_null() {
                CRYPTO_free(ret.cast(), FILE, LINE_DUP_FREE);
                return ptr::null_mut();
            }
        }

        // Absent key material, nothing left to do.
        if (*key).mkey.is_null() {
            if (*key).xkey.is_null() {
                return ret.cast();
            }
            // Fail if the source key is in an inconsistent state.
            CRYPTO_free((*ret).propq.cast(), FILE, LINE_DUP_FREE);
            CRYPTO_free(ret.cast(), FILE, LINE_DUP_FREE);
            return ptr::null_mut();
        }

        match selection & OSSL_KEYMGMT_SELECT_KEYPAIR {
            0 => {
                (*ret).state = MLX_HAVE_NOKEYS;
                return ret.cast();
            }
            OSSL_KEYMGMT_SELECT_KEYPAIR => {
                (*ret).mkey = EVP_PKEY_dup((*key).mkey);
                (*ret).xkey = EVP_PKEY_dup((*key).xkey);
                if !(*ret).xkey.is_null() && !(*ret).mkey.is_null() {
                    return ret.cast();
                }
            }
            _ => {
                raise_fixed(
                    &err_sites::PROV_MLX_KMGMT_1069,
                    "duplication of partial key material not supported",
                );
            }
        }

        mlx_kem_key_free(ret.cast());
    }
    ptr::null_mut()
}

/// One `DECLARE_DISPATCH(name, variant)` expansion — `mlx_kmgmt.c:799-837`.
///
/// The two differing columns are `NEW` and `GEN_INIT`; every other slot is the shared body. Eighteen
/// slots, and **no `LOAD` and no `VALIDATE`** — the authority's macro does not name them.
macro_rules! declare_dispatch {
    ($fn_new:ident, $fn_gen_init:ident, $table:ident, $variant:expr) => {
        /// `static void *mlx_<name>_kem_new(void *provctx)` — one expansion's `NEW`.
        ///
        /// # Safety
        /// The keymgmt `new` dispatch contract.
        unsafe extern "C" fn $fn_new(provctx: *mut c_void) -> *mut c_void {
            let libctx = if provctx.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `provctx` is non-NULL past the guard.
                unsafe { prov_libctx_of(provctx) }
            };
            // SAFETY: forwarded with this expansion's own variant and no propq.
            unsafe { mlx_kem_key_new($variant, libctx, ptr::null_mut()).cast() }
        }

        /// `static void *mlx_<name>_kem_gen_init(void *provctx, int selection,`
        /// `const OSSL_PARAM params[])` — one expansion's `GEN_INIT`.
        ///
        /// # Safety
        /// The keymgmt `gen_init` dispatch contract.
        unsafe extern "C" fn $fn_gen_init(
            provctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            let libctx = if provctx.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `provctx` is non-NULL past the guard.
                unsafe { prov_libctx_of(provctx) }
            };
            // SAFETY: forwarded with this expansion's own variant.
            unsafe { mlx_kem_gen_init($variant, libctx, selection, params) }
        }

        /// `const OSSL_DISPATCH ossl_mlx_<name>_kem_kmgmt_functions[]` — one expansion's table.
        pub(crate) static $table: [OsslDispatch; 19] = [
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_NEW,
                function: $fn_new as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_FREE,
                function: mlx_kem_key_free as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
                function: mlx_kem_get_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
                function: mlx_kem_gettable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
                function: mlx_kem_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
                function: mlx_kem_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_HAS,
                function: mlx_kem_has as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_MATCH,
                function: mlx_kem_match as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
                function: $fn_gen_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
                function: mlx_kem_gen_set_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                function: mlx_kem_gen_settable_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN,
                function: mlx_kem_gen as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
                function: mlx_kem_gen_cleanup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_DUP,
                function: mlx_kem_dup as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT,
                function: mlx_kem_import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
                function: mlx_kem_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT,
                function: mlx_kem_export as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
                function: mlx_kem_imexport_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

// See `HYBRID_VTABLE` above.
declare_dispatch!(
    mlx_p256_kem_new,
    mlx_p256_kem_gen_init,
    MLX_P256_KEM_KMGMT_FUNCTIONS,
    0
);
declare_dispatch!(
    mlx_p384_kem_new,
    mlx_p384_kem_gen_init,
    MLX_P384_KEM_KMGMT_FUNCTIONS,
    1
);
declare_dispatch!(
    mlx_x25519_kem_new,
    mlx_x25519_kem_gen_init,
    MLX_X25519_KEM_KMGMT_FUNCTIONS,
    2
);
declare_dispatch!(
    mlx_x448_kem_new,
    mlx_x448_kem_gen_init,
    MLX_X448_KEM_KMGMT_FUNCTIONS,
    3
);
