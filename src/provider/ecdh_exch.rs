//! Phase 8.10 — `providers/implementations/exchange/ecdh_exch.c.in`: the `ECDH` key exchange row.
//!
//! Six hundred and sixty source lines, twelve functions and one dispatch table. It is the last
//! `OSSL_OP_KEYEXCH` row and it lands with the `EC` keymgmt row that gates it (unit
//! `keymgmt/ec_kmgmt.c`), exactly as `dh_exch.c.in` landed with `dh_kmgmt.c` (D387) and
//! `ecx_exch.c.in` with `ecx_kmgmt.c.in` (D388).
//!
//! ## The object, and the cofactor rule inside it
//!
//! `PROV_ECDH_CTX` holds the private key, the peer, and — when the caller asked for a KDF — an
//! `EVP_MD`, a UKM and an output length. `ecdh_plain_derive` is where the unit's real content is:
//! the context's `cofactor_mode` **overrides** the key's own `EC_FLAG_COFACTOR_ECDH` bit only when
//! the two disagree *and* the group has a cofactor other than 1, and the override is a **duplicate**
//! of the key rather than a mutation of the caller's. The `FIPS_MODULE` `OSS_FIPS_IND_*` arms and
//! the SP800-56A cofactor refusal are not this profile's and are named at each site.
//!
//! ## The two generated decoders
//!
//! `produce_param_decoder` emits a repeated-key scan plus one located field per parameter; the crate
//! writes that observable content directly, as `src/provider/exchange.rs` does for `dh_exch.c`'s two
//! and `src/provider/ecx_kem.rs` for its one. Each decoder's `PROV_R_REPEATED_PARAMETER` sites are
//! the generated file's own coordinates.
//!
//! ## What is withheld, and why
//!
//! **Nothing.** The unit's whole non-`FIPS_MODULE` closure is landed: `ECDH_compute_key`
//! (`src/ec/kmeth.rs`), `ossl_ecdh_kdf_X9_63` (`src/ec/kdf.rs`), the `EC_KEY_*` accessors and
//! `EC_GROUP_*` readers, and `EVP_MD_*`. D387 measured this as reached by the `EC` keymgmt row and
//! nothing else, and that is what this pass supplies.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::bn::bignum::BN_is_one;
use crate::bn::ctx::BN_CTX_free;
use crate::bn::ctx::BN_CTX_new_ex;
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::kdf::ossl_ecdh_kdf_X9_63;
use crate::ec::key::{
    ossl_ec_key_get_libctx, EC_KEY_clear_flags, EC_KEY_dup, EC_KEY_free, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_KEY_get_flags, EC_KEY_set_flags, EC_KEY_up_ref,
    EC_FLAG_COFACTOR_ECDH,
};
use crate::ec::kmeth::ECDH_compute_key;
use crate::ec::lib::{EC_GROUP_cmp, EC_GROUP_get0_cofactor, EC_GROUP_get_degree};
use crate::ec::EcKey;
use crate::evp::digest::EvpMd;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_up_ref, EVP_MD_xof};
use crate::evp::exchange::{
    OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DERIVE_SKEY, OSSL_FUNC_KEYEXCH_DUPCTX,
    OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_SET_PEER,
};
use crate::evp::pkey_ctx::{
    OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, OSSL_EXCHANGE_PARAM_KDF_DIGEST,
    OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_EXCHANGE_PARAM_KDF_UKM,
};
use crate::evp::skeymgmt::{
    SkeymgmtImportFn, OSSL_SKEYMGMT_SELECT_SECRET_KEY, OSSL_SKEY_PARAM_RAW_BYTES,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_int,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{
    param_int, param_octet_ptr, param_octet_string, param_size_t, param_utf8_string,
};
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::bio::sys::strcmp;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

/// `OSSL_KDF_NAME_X963KDF` — `core_names.h`, the name the X9.63 KDF is fetched by.
const OSSL_KDF_NAME_X963KDF: *const c_char = c"X963KDF".as_ptr();
/// `OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS` — `core_names.h:266`.
const OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS: *const c_char = c"kdf-digest-props".as_ptr();

/// `PROV_ECDH_KDF_NONE` — `ecdh_exch.c.in:50`.
const PROV_ECDH_KDF_NONE: c_int = 0;
/// `PROV_ECDH_KDF_X9_63` — `ecdh_exch.c.in:51`.
const PROV_ECDH_KDF_X9_63: c_int = 1;

/// `PROV_ECDH_NAME_SIZE` — the authority's `char name[80]` in `ecdh_set_ctx_params`.
const PROV_ECDH_NAME_SIZE: usize = 80;

/// The generated unit's own `__FILE__`.
const FILE_ECDH_EXCH: *const c_char = c"providers/implementations/exchange/ecdh_exch.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_ECDH_CTX` — `ecdh_exch.c.in:60-88`, without the `FIPS_MODULE`-only indicator field.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvEcdhCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `EC_KEY *k`.
    k: *mut EcKey,
    /// `EC_KEY *peerk`.
    peerk: *mut EcKey,
    /// `int cofactor_mode` — `-1` means "use the key's own bit".
    cofactor_mode: c_int,
    /// `enum kdf_type kdf_type`.
    kdf_type: c_int,
    /// `EVP_MD *kdf_md`.
    kdf_md: *mut EvpMd,
    /// `unsigned char *kdf_ukm` — owned.
    kdf_ukm: *mut u8,
    /// `size_t kdf_ukmlen`.
    kdf_ukmlen: usize,
    /// `size_t kdf_outlen`.
    kdf_outlen: usize,
}

/// `static void *ecdh_newctx(void *provctx)` — `ecdh_exch.c.in:90-107`.
///
/// # Safety
/// The keyexch `newctx` dispatch contract.
unsafe extern "C" fn ecdh_newctx(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let pectx = CRYPTO_zalloc(core::mem::size_of::<ProvEcdhCtx>(), FILE_ECDH_EXCH, 97)
        .cast::<ProvEcdhCtx>();
    if pectx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `pectx` is this call's own allocation; `provctx` is the caller's.
    unsafe {
        (*pectx).libctx = prov_libctx_of(provctx);
        (*pectx).cofactor_mode = -1;
        (*pectx).kdf_type = PROV_ECDH_KDF_NONE;
    }

    pectx.cast()
}

/// `static int ecdh_init(void *vpecdhctx, void *vecdh, const OSSL_PARAM params[])` —
/// `ecdh_exch.c.in:109-134`.
///
/// # Safety
/// The keyexch `init` dispatch contract.
unsafe extern "C" fn ecdh_init(
    vpecdhctx: *mut c_void,
    vecdh: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();

    if is_running() == 0 || pecdhctx.is_null() || vecdh.is_null() {
        return 0;
    }
    // SAFETY: `vecdh` is non-NULL past the guard.
    unsafe {
        if EC_KEY_get0_group(vecdh.cast()).is_null() || EC_KEY_up_ref(vecdh.cast()) == 0 {
            return 0;
        }
        EC_KEY_free((*pecdhctx).k);
        (*pecdhctx).k = vecdh.cast();
        (*pecdhctx).cofactor_mode = -1;
        (*pecdhctx).kdf_type = PROV_ECDH_KDF_NONE;

        // `OSSL_FIPS_IND_SET_APPROVED(pecdhctx)` is not this profile's arm.

        if ecdh_set_ctx_params(pecdhctx.cast(), params) == 0 {
            return 0;
        }
        // `#ifdef FIPS_MODULE ossl_fips_ind_ec_key_check(...)` is not this profile's arm.
    }
    1
}

/// `static int ecdh_match_params(const EC_KEY *priv, const EC_KEY *peer)` —
/// `ecdh_exch.c.in:136-155`.
///
/// # Safety
/// Both keys are live.
unsafe fn ecdh_match_params(priv_: *const EcKey, peer: *const EcKey) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe {
        let group_priv = EC_KEY_get0_group(priv_);
        let group_peer = EC_KEY_get0_group(peer);

        let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(priv_));
        if ctx.is_null() {
            raise_site(&err_sites::PROV_ECDH_EXCH_143);
            return 0;
        }
        let ret = c_int::from(
            !group_priv.is_null()
                && !group_peer.is_null()
                && EC_GROUP_cmp(group_priv, group_peer, ctx) == 0,
        );
        if ret == 0 {
            raise_site(&err_sites::PROV_ECDH_EXCH_150);
        }
        BN_CTX_free(ctx);
        ret
    }
}

/// `static int ecdh_set_peer(void *vpecdhctx, void *vecdh)` — `ecdh_exch.c.in:157-179`.
///
/// # Safety
/// The keyexch `set_peer` dispatch contract.
unsafe extern "C" fn ecdh_set_peer(vpecdhctx: *mut c_void, vecdh: *mut c_void) -> c_int {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();

    if is_running() == 0 || pecdhctx.is_null() || vecdh.is_null() {
        return 0;
    }
    // SAFETY: `pecdhctx` and `vecdh` are the caller's, per the dispatch contract.
    unsafe {
        if ecdh_match_params((*pecdhctx).k, vecdh.cast()) == 0 {
            return 0;
        }
        // `#ifdef FIPS_MODULE ossl_fips_ind_ec_key_check(...)` is not this profile's arm.
        if EC_KEY_up_ref(vecdh.cast()) == 0 {
            return 0;
        }

        EC_KEY_free((*pecdhctx).peerk);
        (*pecdhctx).peerk = vecdh.cast();
    }
    1
}

/// `static void ecdh_freectx(void *vpecdhctx)` — `ecdh_exch.c.in:181-192`.
///
/// # Safety
/// The keyexch `freectx` dispatch contract.
unsafe extern "C" fn ecdh_freectx(vpecdhctx: *mut c_void) {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();

    // SAFETY: `pecdhctx` is the caller's context.
    unsafe {
        EC_KEY_free((*pecdhctx).k);
        EC_KEY_free((*pecdhctx).peerk);

        EVP_MD_free((*pecdhctx).kdf_md);
        CRYPTO_clear_free(
            (*pecdhctx).kdf_ukm.cast(),
            (*pecdhctx).kdf_ukmlen,
            FILE_ECDH_EXCH,
            189,
        );

        CRYPTO_free(pecdhctx.cast(), FILE_ECDH_EXCH, 191);
    }
}

/// `static void *ecdh_dupctx(void *vpecdhctx)` — `ecdh_exch.c.in:194-245`.
///
/// # Safety
/// The keyexch `dupctx` dispatch contract.
unsafe extern "C" fn ecdh_dupctx(vpecdhctx: *mut c_void) -> *mut c_void {
    let srcctx = vpecdhctx.cast::<ProvEcdhCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let dstctx = CRYPTO_zalloc(core::mem::size_of::<ProvEcdhCtx>(), FILE_ECDH_EXCH, 202)
        .cast::<ProvEcdhCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live or NULL per the contract.
    unsafe {
        *dstctx = *srcctx;

        /* clear all pointers */
        (*dstctx).k = ptr::null_mut();
        (*dstctx).peerk = ptr::null_mut();
        (*dstctx).kdf_md = ptr::null_mut();
        (*dstctx).kdf_ukm = ptr::null_mut();

        /* up-ref all ref-counted objects referenced in dstctx */
        if !(*srcctx).k.is_null() {
            if EC_KEY_up_ref((*srcctx).k) == 0 {
                ecdh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
            (*dstctx).k = (*srcctx).k;
        }

        if !(*srcctx).peerk.is_null() {
            if EC_KEY_up_ref((*srcctx).peerk) == 0 {
                ecdh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
            (*dstctx).peerk = (*srcctx).peerk;
        }

        if !(*srcctx).kdf_md.is_null() {
            if EVP_MD_up_ref((*srcctx).kdf_md) == 0 {
                ecdh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
            (*dstctx).kdf_md = (*srcctx).kdf_md;
        }

        /* Duplicate UKM data if present */
        if !(*srcctx).kdf_ukm.is_null() && (*srcctx).kdf_ukmlen > 0 {
            (*dstctx).kdf_ukm = CRYPTO_memdup(
                (*srcctx).kdf_ukm.cast(),
                (*srcctx).kdf_ukmlen,
                FILE_ECDH_EXCH,
                234,
            )
            .cast::<u8>();
            if (*dstctx).kdf_ukm.is_null() {
                ecdh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }
    }
    dstctx.cast()
}

/// `static const OSSL_PARAM ecdh_set_ctx_params_list[]` — generated `ecdh_exch.c`, without the
/// three `FIPS_MODULE`-guarded entries.
static ECDH_SET_CTX_PARAMS_LIST: [OsslParam; 7] = [
    param_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS),
    param_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    param_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM),
    END,
];

/// `struct ecdh_set_ctx_params_st` — the generated decoder's result, without its FIPS members.
struct EcdhSetCtxParams {
    mode: *const OsslParam,
    kdf: *const OsslParam,
    digest: *const OsslParam,
    propq: *const OsslParam,
    len: *const OsslParam,
    ukm: *const OsslParam,
}

/// The set-decoder's repeated-key coordinates, from the generated file's non-FIPS arms.
const ECDH_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 6] = [
    (
        &err_sites::PROV_ECDH_EXCH_374,
        OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    ),
    (&err_sites::PROV_ECDH_EXCH_386, OSSL_EXCHANGE_PARAM_KDF_TYPE),
    (
        &err_sites::PROV_ECDH_EXCH_451,
        OSSL_EXCHANGE_PARAM_KDF_DIGEST,
    ),
    (
        &err_sites::PROV_ECDH_EXCH_460,
        OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
    ),
    (
        &err_sites::PROV_ECDH_EXCH_476,
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
    ),
    (&err_sites::PROV_ECDH_EXCH_487, OSSL_EXCHANGE_PARAM_KDF_UKM),
];

/// The repeated-key scan the generated decoders are — shared with `src/provider/ecx_kem.rs`'s and
/// `src/provider/exchange.rs`'s copies, and written here rather than exported across modules for the
/// reason those two give.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecdh_repeated_param_site(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the array is key-terminated per the contract.
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

/// `ecdh_set_ctx_params_decoder` — the generated decoder.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecdh_set_ctx_params_decoder(params: *const OsslParam, r: &mut EcdhSetCtxParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecdh_repeated_param_site(params, &ECDH_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.mode = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
        r.kdf = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
        r.digest = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        r.propq = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
        r.len = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        r.ukm = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    }
    1
}

/// `static int ecdh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[])` —
/// `ecdh_exch.c.in:261-356`.
///
/// # Safety
/// The keyexch `set_ctx_params` dispatch contract.
unsafe extern "C" fn ecdh_set_ctx_params(
    vpecdhctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let mut name = [0 as c_char; PROV_ECDH_NAME_SIZE];
    let pectx = vpecdhctx.cast::<ProvEcdhCtx>();
    let mut p = EcdhSetCtxParams {
        mode: ptr::null(),
        kdf: ptr::null(),
        digest: ptr::null(),
        propq: ptr::null(),
        len: ptr::null(),
        ukm: ptr::null(),
    };

    // SAFETY: `pectx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if pectx.is_null() || ecdh_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        // `OSSL_FIPS_IND_SET_CTX_FROM_PARAM(pectx, SETTABLE0/1/2, p.ind_k/ind_d/ind_cofac)` is the
        // literal 1 without `FIPS_MODULE`.

        if !p.mode.is_null() {
            let mut mode: c_int = 0;

            if OSSL_PARAM_get_int(p.mode, &mut mode) == 0 {
                return 0;
            }
            if !(-1..=1).contains(&mode) {
                return 0;
            }
            (*pectx).cofactor_mode = mode;
        }

        if !p.kdf.is_null() {
            let mut str_: *mut c_char = name.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.kdf, &mut str_, PROV_ECDH_NAME_SIZE) == 0 {
                return 0;
            }

            if name[0] == 0 {
                (*pectx).kdf_type = PROV_ECDH_KDF_NONE;
            } else if strcmp(name.as_ptr(), OSSL_KDF_NAME_X963KDF) == 0 {
                (*pectx).kdf_type = PROV_ECDH_KDF_X9_63;
            } else {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let mut mdprops = [0 as c_char; PROV_ECDH_NAME_SIZE];

            let mut str_: *mut c_char = name.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.digest, &mut str_, PROV_ECDH_NAME_SIZE) == 0 {
                return 0;
            }

            let mut str_: *mut c_char = mdprops.as_mut_ptr();
            if !p.propq.is_null()
                && OSSL_PARAM_get_utf8_string(p.propq, &mut str_, PROV_ECDH_NAME_SIZE) == 0
            {
                return 0;
            }

            EVP_MD_free((*pectx).kdf_md);
            (*pectx).kdf_md = EVP_MD_fetch((*pectx).libctx, name.as_ptr(), mdprops.as_ptr());
            if (*pectx).kdf_md.is_null() {
                return 0;
            }
            /* XOF digests are not allowed */
            if EVP_MD_xof((*pectx).kdf_md) != 0 {
                raise_site(&err_sites::PROV_ECDH_EXCH_591);
                return 0;
            }
            // `#ifdef FIPS_MODULE ossl_fips_ind_digest_exch_check(...)` is not this profile's arm.
        }

        if !p.len.is_null() {
            let mut outlen: usize = 0;

            if OSSL_PARAM_get_size_t(p.len, &mut outlen) == 0 {
                return 0;
            }
            (*pectx).kdf_outlen = outlen;
        }

        if !p.ukm.is_null() {
            let mut tmp_ukm: *mut c_void = ptr::null_mut();
            let mut tmp_ukmlen: usize = 0;

            if OSSL_PARAM_get_octet_string(p.ukm, &mut tmp_ukm, 0, &mut tmp_ukmlen) == 0 {
                return 0;
            }
            CRYPTO_free((*pectx).kdf_ukm.cast(), FILE_ECDH_EXCH, 350);
            (*pectx).kdf_ukm = tmp_ukm.cast::<u8>();
            (*pectx).kdf_ukmlen = tmp_ukmlen;
        }
    }
    1
}

/// `static const OSSL_PARAM *ecdh_settable_ctx_params(void *vpecdhctx, void *provctx)` —
/// `ecdh_exch.c.in:358-362`.
///
/// # Safety
/// The keyexch `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ecdh_settable_ctx_params(
    _vpecdhctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECDH_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static const OSSL_PARAM ecdh_get_ctx_params_list[]` — generated `ecdh_exch.c`, without the
/// `FIPS_MODULE`-guarded indicator.
static ECDH_GET_CTX_PARAMS_LIST: [OsslParam; 6] = [
    param_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    param_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    param_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM),
    END,
];

/// `struct ecdh_get_ctx_params_st` — the generated decoder's result, without its FIPS member.
struct EcdhGetCtxParams {
    mode: *const OsslParam,
    kdf: *const OsslParam,
    digest: *const OsslParam,
    len: *const OsslParam,
    ukm: *const OsslParam,
}

/// The get-decoder's repeated-key coordinates, from the generated file's non-FIPS arms.
const ECDH_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (
        &err_sites::PROV_ECDH_EXCH_678,
        OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    ),
    (&err_sites::PROV_ECDH_EXCH_690, OSSL_EXCHANGE_PARAM_KDF_TYPE),
    (
        &err_sites::PROV_ECDH_EXCH_718,
        OSSL_EXCHANGE_PARAM_KDF_DIGEST,
    ),
    (
        &err_sites::PROV_ECDH_EXCH_729,
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
    ),
    (&err_sites::PROV_ECDH_EXCH_740, OSSL_EXCHANGE_PARAM_KDF_UKM),
];

/// `ecdh_get_ctx_params_decoder` — the generated decoder.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecdh_get_ctx_params_decoder(params: *const OsslParam, r: &mut EcdhGetCtxParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecdh_repeated_param_site(params, &ECDH_GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.mode = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
        r.kdf = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
        r.digest = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        r.len = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        r.ukm = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    }
    1
}

/// `static int ecdh_get_ctx_params(void *vpecdhctx, OSSL_PARAM params[])` —
/// `ecdh_exch.c.in:375-427`.
///
/// # Safety
/// The keyexch `get_ctx_params` dispatch contract.
unsafe extern "C" fn ecdh_get_ctx_params(vpecdhctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let pectx = vpecdhctx.cast::<ProvEcdhCtx>();
    let mut p = EcdhGetCtxParams {
        mode: ptr::null(),
        kdf: ptr::null(),
        digest: ptr::null(),
        len: ptr::null(),
        ukm: ptr::null(),
    };

    // SAFETY: `pectx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if pectx.is_null() || ecdh_get_ctx_params_decoder(params.cast_const(), &mut p) == 0 {
            return 0;
        }

        if !p.mode.is_null() {
            let mut mode = (*pectx).cofactor_mode;

            if mode == -1 {
                /* check what is the default for pecdhctx->k */
                mode = c_int::from((EC_KEY_get_flags((*pectx).k) & EC_FLAG_COFACTOR_ECDH) != 0);
            }

            if OSSL_PARAM_set_int(p.mode.cast_mut(), mode) == 0 {
                return 0;
            }
        }

        if !p.kdf.is_null() {
            let kdf_type: *const c_char = match (*pectx).kdf_type {
                PROV_ECDH_KDF_NONE => c"".as_ptr(),
                PROV_ECDH_KDF_X9_63 => OSSL_KDF_NAME_X963KDF,
                _ => return 0,
            };

            if OSSL_PARAM_set_utf8_string(p.kdf.cast_mut(), kdf_type) == 0 {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let name = if (*pectx).kdf_md.is_null() {
                c"".as_ptr()
            } else {
                EVP_MD_get0_name((*pectx).kdf_md)
            };
            if OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), name) == 0 {
                return 0;
            }
        }

        if !p.len.is_null() && OSSL_PARAM_set_size_t(p.len.cast_mut(), (*pectx).kdf_outlen) == 0 {
            return 0;
        }

        if !p.ukm.is_null()
            && OSSL_PARAM_set_octet_ptr(
                p.ukm.cast_mut(),
                (*pectx).kdf_ukm.cast(),
                (*pectx).kdf_ukmlen,
            ) == 0
        {
            return 0;
        }

        // `OSSL_FIPS_IND_GET_CTX_FROM_PARAM(pectx, p.ind)` is the literal 1 here.
    }
    1
}

/// `static const OSSL_PARAM *ecdh_gettable_ctx_params(void *vpecdhctx, void *provctx)` —
/// `ecdh_exch.c.in:429-433`.
///
/// # Safety
/// The keyexch `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn ecdh_gettable_ctx_params(
    _vpecdhctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECDH_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static ossl_inline size_t ecdh_size(const EC_KEY *k)` — `ecdh_exch.c.in:435-449`.
///
/// # Safety
/// `k` is NULL or live.
unsafe fn ecdh_size(k: *const EcKey) -> usize {
    if k.is_null() {
        return 0;
    }
    // SAFETY: `k` is non-NULL past the guard.
    let group = unsafe { EC_KEY_get0_group(k) };
    if group.is_null() {
        return 0;
    }

    // SAFETY: `group` is live.
    let degree = unsafe { EC_GROUP_get_degree(group) };

    // `(degree + 7) / 8` in the authority; `div_ceil` is the same expression for the unsigned
    // type, as `src/evp/pkey_ctx.rs` writes `BN_num_bytes` against an unsigned width.
    (degree as usize).div_ceil(8)
}

/// `static ossl_inline int ecdh_plain_derive(void *vpecdhctx, unsigned char *secret,
/// size_t *psecretlen, size_t outlen)` — `ecdh_exch.c.in:451-553`.
///
/// # Safety
/// `vpecdhctx` is live with a `k` and a `peerk`; `psecretlen` is writable; `secret` is NULL or
/// writable for the returned length.
#[allow(unused_assignments)] // the authority initialises `privk` to NULL and assigns it before its only read
unsafe fn ecdh_plain_derive(
    vpecdhctx: *mut c_void,
    secret: *mut u8,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();
    let mut ret: c_int = 0;
    let mut privk: *mut EcKey = ptr::null_mut();

    // SAFETY: `pecdhctx` is the caller's context.
    unsafe {
        if (*pecdhctx).k.is_null() || (*pecdhctx).peerk.is_null() {
            raise_site(&err_sites::PROV_ECDH_EXCH_861);
            return 0;
        }

        let ecdhsize = ecdh_size((*pecdhctx).k);
        if secret.is_null() {
            *psecretlen = ecdhsize;
            return 1;
        }

        let group = EC_KEY_get0_group((*pecdhctx).k);
        if group.is_null() {
            return 0;
        }
        let cofactor = EC_GROUP_get0_cofactor(group);
        if cofactor.is_null() {
            return 0;
        }

        let has_cofactor = BN_is_one(cofactor) == 0;

        /*
         * NB: unlike PKCS#3 DH, if outlen is less than maximum size this is not
         * an error, the result is truncated.
         */
        let size = if outlen < ecdhsize { outlen } else { ecdhsize };

        /*
         * The ctx->cofactor_mode flag has precedence over the cofactor_mode flag set on ctx->k,
         * but only while the group's cofactor is not 1; the override is a duplicate of the key.
         */
        let key_cofactor_mode =
            c_int::from((EC_KEY_get_flags((*pecdhctx).k) & EC_FLAG_COFACTOR_ECDH) != 0);
        if (*pecdhctx).cofactor_mode != -1
            && (*pecdhctx).cofactor_mode != key_cofactor_mode
            && has_cofactor
        {
            privk = EC_KEY_dup((*pecdhctx).k);
            if privk.is_null() {
                return 0;
            }

            if (*pecdhctx).cofactor_mode == 1 {
                EC_KEY_set_flags(privk, EC_FLAG_COFACTOR_ECDH);
            } else {
                EC_KEY_clear_flags(privk, EC_FLAG_COFACTOR_ECDH);
            }
        } else {
            privk = (*pecdhctx).k;
        }

        // `#ifdef FIPS_MODULE`'s SP800-56A cofactor refusal is not this profile's arm.

        let ppubkey = EC_KEY_get0_public_key((*pecdhctx).peerk);

        let retlen = ECDH_compute_key(secret.cast(), size, ppubkey, privk, None);

        if retlen > 0 {
            *psecretlen = retlen as usize;
            ret = 1;
        }

        if privk != (*pecdhctx).k {
            EC_KEY_free(privk);
        }
    }
    ret
}

/// `static ossl_inline int ecdh_X9_63_kdf_derive(void *vpecdhctx, unsigned char *secret,
/// size_t *psecretlen, size_t outlen)` — `ecdh_exch.c.in:555-593`.
///
/// # Safety
/// As [`ecdh_plain_derive`].
#[allow(non_snake_case, unused_assignments)] // the authority's own internal name; `stmp` is assigned before its only read
unsafe fn ecdh_X9_63_kdf_derive(
    vpecdhctx: *mut c_void,
    secret: *mut u8,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();
    let mut stmp: *mut u8 = ptr::null_mut();
    let mut stmplen: usize = 0;
    let mut ret: c_int = 0;

    // SAFETY: `pecdhctx` is the caller's context.
    unsafe {
        if secret.is_null() {
            *psecretlen = (*pecdhctx).kdf_outlen;
            return 1;
        }

        if (*pecdhctx).kdf_outlen > outlen {
            raise_site(&err_sites::PROV_ECDH_EXCH_926);
            return 0;
        }
        if ecdh_plain_derive(vpecdhctx, ptr::null_mut(), &mut stmplen, 0) == 0 {
            return 0;
        }
        stmp = CRYPTO_secure_malloc(stmplen, FILE_ECDH_EXCH, 574).cast::<u8>();
        if stmp.is_null() {
            return 0;
        }
        if ecdh_plain_derive(vpecdhctx, stmp, &mut stmplen, stmplen) == 0 {
            CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_ECDH_EXCH, 591);
            return ret;
        }

        /* Do KDF stuff */
        if ossl_ecdh_kdf_X9_63(
            secret,
            (*pecdhctx).kdf_outlen,
            stmp,
            stmplen,
            (*pecdhctx).kdf_ukm,
            (*pecdhctx).kdf_ukmlen,
            (*pecdhctx).kdf_md,
            (*pecdhctx).libctx,
            ptr::null(),
        ) == 0
        {
            CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_ECDH_EXCH, 591);
            return ret;
        }
        *psecretlen = (*pecdhctx).kdf_outlen;
        ret = 1;

        CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_ECDH_EXCH, 591);
    }
    ret
}

/// `static int ecdh_derive(void *vpecdhctx, unsigned char *secret, size_t *psecretlen,
/// size_t outlen)` — `ecdh_exch.c.in:595-609`.
///
/// # Safety
/// The keyexch `derive` dispatch contract.
unsafe extern "C" fn ecdh_derive(
    vpecdhctx: *mut c_void,
    secret: *mut u8,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let pecdhctx = vpecdhctx.cast::<ProvEcdhCtx>();

    // SAFETY: `pecdhctx` is the caller's context.
    unsafe {
        match (*pecdhctx).kdf_type {
            PROV_ECDH_KDF_NONE => ecdh_plain_derive(vpecdhctx, secret, psecretlen, outlen),
            PROV_ECDH_KDF_X9_63 => ecdh_X9_63_kdf_derive(vpecdhctx, secret, psecretlen, outlen),
            _ => 0,
        }
    }
}

/// `static void *ecdh_derive_skey(void *vpecdhctx, const char *key_type, void *provctx,
/// OSSL_FUNC_skeymgmt_import_fn *import, size_t outlen, const OSSL_PARAM params_in[])` —
/// `ecdh_exch.c.in:611-643`.
///
/// # Safety
/// The keyexch `derive_skey` dispatch contract.
unsafe extern "C" fn ecdh_derive_skey(
    vpecdhctx: *mut c_void,
    _key_type: *const c_char,
    provctx: *mut c_void,
    import: Option<SkeymgmtImportFn>,
    outlen: usize,
    _params_in: *const OsslParam,
) -> *mut c_void {
    let mut secret: *mut u8 = ptr::null_mut();
    let mut secretlen: usize = 0;

    if import.is_none() || outlen == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `vpecdhctx` is the caller's context; `secret` is NULL so this is the size probe.
    unsafe {
        if ecdh_derive(vpecdhctx, secret, &mut secretlen, outlen) == 0 {
            return ptr::null_mut();
        }

        secret = CRYPTO_malloc(secretlen, FILE_ECDH_EXCH, 626).cast::<u8>();
        if secret.is_null() {
            return ptr::null_mut();
        }

        if ecdh_derive(vpecdhctx, secret, &mut secretlen, outlen) == 0 || secretlen != outlen {
            CRYPTO_clear_free(secret.cast(), secretlen, FILE_ECDH_EXCH, 631);
            return ptr::null_mut();
        }

        let mut params: [OsslParam; 2] = [END, END];
        params[0] =
            OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, secret.cast(), outlen);
        let _ = OSSL_PARAM_construct_end();

        /* This is mandatory, no need to check for its presence */
        let ret = match import {
            Some(f) => f(provctx, OSSL_SKEYMGMT_SELECT_SECRET_KEY, params.as_ptr()),
            None => ptr::null_mut(),
        };
        CRYPTO_clear_free(secret.cast(), secretlen, FILE_ECDH_EXCH, 640);

        ret
    }
}

/// `const OSSL_DISPATCH ossl_ecdh_keyexch_functions[]` — `ecdh_exch.c.in:645-660`. Eleven slots,
/// the authority's, in its order.
pub(crate) static ECDH_KEYEXCH_FUNCTIONS: [OsslDispatch; 12] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: ecdh_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: ecdh_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: ecdh_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE_SKEY,
        function: ecdh_derive_skey as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_PEER,
        function: ecdh_set_peer as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: ecdh_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: ecdh_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        function: ecdh_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        function: ecdh_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: ecdh_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: ecdh_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
