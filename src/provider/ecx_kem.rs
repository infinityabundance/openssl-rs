//! Phase 8.10 — `providers/implementations/kem/ecx_kem.c.in`: the ECX DHKEM rows and
//! `ossl_ecx_dhkem_derive_private`.
//!
//! Seven hundred and nine source lines, sixteen functions and **one** dispatch table — two rows
//! (`X25519` and `X448`) sharing `ossl_ecx_asym_kem_functions`, exactly as the authority's
//! `deflt_asym_kem[]` publishes them. The unit is RFC 9180 section 4.1's `DHKEM` over the ECX
//! keys: `Encap`, `Decap`, the two authenticated variants, and the `DeriveKeyPair` primitive.
//!
//! ## `ossl_ecx_dhkem_derive_private` is **defined here**, and the keymgmt unit calls it
//!
//! `prov/ecx.h` declares it, and the authority's only definition is in this unit
//! (`ecx_kem.c.in:342-428`), which is why it is a `#[no_mangle]` export of this module and why
//! `src/provider/ecx_kmgmt.rs`'s `ecx_gen` reaches it here. Its callers are two units in two
//! different subsystems — the KEM itself (`derivekey`) and the ECX key type's generator — so the
//! three units of this pass land together rather than in three: the keymgmt unit cannot compile
//! without this symbol, and the KEM unit cannot compile without the ECX keymgmt rows it fetches
//! its keys through.
//!
//! ## The dependencies, and the two that were not landed
//!
//! `get_kem_info` calls `ossl_HPKE_KEM_INFO_find_curve` (`crypto/hpke/hpke_util.c:156`), which
//! `crypto/hpke/hpke.c` never calls and the Phase 7.6 pass therefore omitted; this pass lands it
//! beside its `find_id` sibling with the reason it was missing recorded there. The rest of the
//! closure is landed: `ossl_hpke_labeled_extract`/`_expand` and `ossl_kdf_ctx_create`
//! (`src/hpke/mod.rs`, made `pub(crate)` for this caller), `ossl_eckem_modename2id`
//! (`src/provider/kem_util.rs`, landed with this unit), `ossl_ecx_public_from_private`
//! (`src/ec/ecx_backend.rs`), `ossl_ecx_compute_key` (`src/ec/ecx_key.rs`) and `RAND_priv_bytes_ex`
//! (`src/rand/rand_lib.rs`).
//!
//! ## What the crate writes instead of the generator
//!
//! The generated `ecxkem_set_ctx_params_decoder` is one repeated-key scan plus two
//! `OSSL_PARAM_locate_const` calls, the idiom `src/provider/ecx_kmgmt.rs` and
//! `src/provider/exchange.rs` already use.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::ecx_backend::{ossl_ecx_key_fromdata, ossl_ecx_public_from_private};
use crate::ec::ecx_key::{
    ossl_ecx_compute_key, ossl_ecx_key_allocate_privkey, ossl_ecx_key_free, ossl_ecx_key_new,
    ossl_ecx_key_up_ref, EcxKey, X448_KEYLEN,
};
use crate::evp::kdf::{EVP_KDF_CTX_free, EvpKdfCtx};
use crate::evp::kem::{
    OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT, OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_ENCAPSULATE,
    OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_SET_CTX_PARAMS,
};
use crate::evp::pkey_ctx::{EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE};
use crate::hpke::{
    hpke_labeled_expand, hpke_labeled_extract, kdf_ctx_create, ossl_HPKE_KEM_INFO_find_curve,
    HpkeKemInfo,
};
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const,
    OsslParam, END, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::kem_util::{ossl_eckem_modename2id, KEM_MODE_DHKEM, KEM_MODE_UNDEFINED};
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{cleanse, CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

/// `MAX_ECX_KEYLEN` — `ecx_kem.c:43`, the value of `X448_KEYLEN`.
const MAX_ECX_KEYLEN: usize = X448_KEYLEN;

// `KEMID_X25519_HKDF_SHA256` (0x20) and `KEMID_X448_HKDF_SHA512` (0x21) — `ecx_kem.c:46-47`. They
// are the two rows of the HPKE KEM table this unit resolves through `get_kem_info`, and their
// values are read from `info->kem_id` rather than named here, so only the identifiers are recorded.

/// `static const char LABEL_KEM[]` — `ecx_kem.c:50`, `"KEM"` spelled in hex in the authority for
/// EBCDIC compatibility.
const LABEL_KEM: &[u8] = b"KEM";

/// `OSSL_DHKEM_LABEL_EAE_PRK` — `prov/ecx.h:17`, `"eae_prk"`.
const OSSL_DHKEM_LABEL_EAE_PRK: &[u8] = b"eae_prk";
/// `OSSL_DHKEM_LABEL_SHARED_SECRET` — `prov/ecx.h:19`, `"shared_secret"`.
const OSSL_DHKEM_LABEL_SHARED_SECRET: &[u8] = b"shared_secret";
/// `OSSL_DHKEM_LABEL_DKP_PRK` — `prov/ecx.h:21`, `"dkp_prk"`.
const OSSL_DHKEM_LABEL_DKP_PRK: &[u8] = b"dkp_prk";
/// `OSSL_DHKEM_LABEL_SK` — `prov/ecx.h:25`, `"sk"`.
const OSSL_DHKEM_LABEL_SK: &[u8] = b"sk";

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:404`. The `prk` scratch is `EVP_MAX_MD_SIZE` bytes.
const EVP_MAX_MD_SIZE: usize = 64;

/// `OSSL_HPKE_MAX_PRIVATE` — `include/internal/hpke_util.h:17`.
const OSSL_HPKE_MAX_PRIVATE: usize = 66;

/// `OSSL_KEM_PARAM_OPERATION` — `core_names.h:326`.
const OSSL_KEM_PARAM_OPERATION: *const c_char = c"operation".as_ptr();
/// `OSSL_KEM_PARAM_IKME` — `core_names.h:325`.
const OSSL_KEM_PARAM_IKME: *const c_char = c"ikme".as_ptr();
/// `OSSL_PKEY_PARAM_PUB_KEY` — `core_names.h:441`.
const OSSL_PKEY_PARAM_PUB_KEY: *const c_char = c"pub".as_ptr();

/// The generated unit's own `__FILE__`. `ecx_kem.c.in` is `.c.in`-generated, so it is the bare
/// build-relative path.
const FILE_ECX_KEM: *const c_char = c"providers/implementations/kem/ecx_kem.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_ECX_CTX` — `ecx_kem.c:52-63`.
#[repr(C)]
struct ProvEcxCtx {
    /// `ECX_KEY *recipient_key`.
    recipient_key: *mut EcxKey,
    /// `ECX_KEY *sender_authkey`.
    sender_authkey: *mut EcxKey,
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `unsigned int mode`.
    mode: c_uint,
    /// `unsigned int op`.
    op: c_uint,
    /// `unsigned char *ikm` — owned.
    ikm: *mut u8,
    /// `size_t ikmlen`.
    ikmlen: usize,
    /// `const char *kdfname` — a `'static` literal.
    kdfname: *const c_char,
    /// `const OSSL_HPKE_KEM_INFO *info` — a `'static` table entry.
    info: *const HpkeKemInfo,
}

/// `static const OSSL_HPKE_KEM_INFO *get_kem_info(ECX_KEY *ecx)` — `ecx_kem.c:80-89`.
///
/// The two names are `SN_X25519`/`SN_X448` — `"X25519"`/`"X448"` — which are the KEM table's
/// `keytype` column for the two `KEMID_X25519_HKDF_SHA256`/`KEMID_X448_HKDF_SHA512` rows.
///
/// # Safety
/// `ecx` is live.
unsafe fn get_kem_info(ecx: *mut EcxKey) -> *const HpkeKemInfo {
    // SAFETY: `ecx` is live per the contract.
    let name = unsafe {
        if (*ecx).type_ == crate::ec::ecx_key::ECX_KEY_TYPE_X25519 {
            c"X25519".as_ptr()
        } else {
            c"X448".as_ptr()
        }
    };
    // SAFETY: `name` is NUL-terminated and the table's own contract holds.
    unsafe { ossl_HPKE_KEM_INFO_find_curve(name) }
}

/// `static int recipient_key_set(PROV_ECX_CTX *ctx, ECX_KEY *ecx)` — `ecx_kem.c:95-109`.
///
/// `-2` is a KEM whose suite cannot be resolved, and it is a distinct answer from the `0` a failed
/// reference gives — `ecxkem_init` returns it unaltered.
///
/// # Safety
/// `ctx` is live; `ecx` is NULL or live.
unsafe fn recipient_key_set(ctx: *mut ProvEcxCtx, ecx: *mut EcxKey) -> c_int {
    // SAFETY: `ctx` is live and its own keys are released and replaced here.
    unsafe {
        ossl_ecx_key_free((*ctx).recipient_key);
        (*ctx).recipient_key = ptr::null_mut();
        if !ecx.is_null() {
            (*ctx).info = get_kem_info(ecx);
            if (*ctx).info.is_null() {
                return -2;
            }
            (*ctx).kdfname = c"HKDF".as_ptr();
            if ossl_ecx_key_up_ref(ecx) == 0 {
                return 0;
            }
            (*ctx).recipient_key = ecx;
        }
    }
    1
}

/// `static int sender_authkey_set(PROV_ECX_CTX *ctx, ECX_KEY *ecx)` — `ecx_kem.c:115-126`.
///
/// # Safety
/// `ctx` is live; `ecx` is NULL or live.
unsafe fn sender_authkey_set(ctx: *mut ProvEcxCtx, ecx: *mut EcxKey) -> c_int {
    // SAFETY: `ctx` is live and its own key is released and replaced here.
    unsafe {
        ossl_ecx_key_free((*ctx).sender_authkey);
        (*ctx).sender_authkey = ptr::null_mut();

        if !ecx.is_null() {
            if ossl_ecx_key_up_ref(ecx) == 0 {
                return 0;
            }
            (*ctx).sender_authkey = ecx;
        }
    }
    1
}

/// `static ECX_KEY *ecxkey_pubfromdata(PROV_ECX_CTX *ctx, const unsigned char *pubbuf,
/// size_t pubbuflen)` — `ecx_kem.c:133-150`.
///
/// # Safety
/// `ctx` is live with a `recipient_key`; `pubbuf` is readable for `pubbuflen` bytes.
unsafe fn ecxkey_pubfromdata(
    ctx: *mut ProvEcxCtx,
    pubbuf: *const u8,
    pubbuflen: usize,
) -> *mut EcxKey {
    // SAFETY: `ctx` is live and its recipient key names the type.
    let pub_ = unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            pubbuf.cast_mut().cast::<c_void>(),
            pubbuflen,
        )
    };

    // SAFETY: `ctx`/`pub_` are per the contract.
    unsafe {
        let ecx = ossl_ecx_key_new(
            (*ctx).libctx,
            (*(*ctx).recipient_key).type_,
            1,
            (*ctx).propq,
        );
        if ecx.is_null() {
            return ptr::null_mut();
        }
        if ossl_ecx_key_fromdata(ecx, &pub_, ptr::null(), 0) <= 0 {
            ossl_ecx_key_free(ecx);
            return ptr::null_mut();
        }
        ecx
    }
}

/// `static unsigned char *ecx_pubkey(ECX_KEY *ecx)` — `ecx_kem.c:152-159`.
///
/// # Safety
/// `ecx` is NULL or live.
unsafe fn ecx_pubkey(ecx: *mut EcxKey) -> *mut u8 {
    if ecx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ECX_KEM_155) };
        return ptr::null_mut();
    }
    // SAFETY: `ecx` is non-NULL past the guard.
    if unsafe { (*ecx).haspubkey } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ECX_KEM_155) };
        return ptr::null_mut();
    }
    // SAFETY: `ecx` is non-NULL and has a public key.
    unsafe { (*ecx).pubkey.as_mut_ptr() }
}

/// `static void *ecxkem_newctx(void *provctx)` — `ecx_kem.c:161-171`.
///
/// # Safety
/// The KEM `newctx` dispatch contract.
unsafe extern "C" fn ecxkem_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvEcxCtx>(), FILE_ECX_KEM, 163).cast::<ProvEcxCtx>();

    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is this call's own allocation; `provctx` is the caller's.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        (*ctx).mode = KEM_MODE_DHKEM as c_uint;
    }

    ctx.cast()
}

/// `static void ecxkem_freectx(void *vectx)` — `ecx_kem.c:173-181`.
///
/// # Safety
/// The KEM `freectx` dispatch contract.
unsafe extern "C" fn ecxkem_freectx(vectx: *mut c_void) {
    let ctx = vectx.cast::<ProvEcxCtx>();

    // SAFETY: `ctx` is the caller's context; `recipient_key_set`/`sender_authkey_set` accept a
    // NULL key and release the held ones, and `ctx` is released last.
    unsafe {
        CRYPTO_clear_free((*ctx).ikm.cast(), (*ctx).ikmlen, FILE_ECX_KEM, 177);
        recipient_key_set(ctx, ptr::null_mut());
        sender_authkey_set(ctx, ptr::null_mut());
        CRYPTO_free(ctx.cast(), FILE_ECX_KEM, 180);
    }
}

/// `static int ecx_match_params(const ECX_KEY *key1, const ECX_KEY *key2)` — `ecx_kem.c:183-186`.
///
/// # Safety
/// Both keys are live.
unsafe fn ecx_match_params(key1: *const EcxKey, key2: *const EcxKey) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe { c_int::from((*key1).type_ == (*key2).type_ && (*key1).keylen == (*key2).keylen) }
}

/// `static int ecx_key_check(const ECX_KEY *ecx, int requires_privatekey)` — `ecx_kem.c:188-193`.
///
/// # Safety
/// `ecx` is live.
unsafe fn ecx_key_check(ecx: *const EcxKey, requires_privatekey: c_int) -> c_int {
    // SAFETY: `ecx` is live per the contract.
    if unsafe { (*ecx).privkey }.is_null() {
        return c_int::from(requires_privatekey == 0);
    }
    1
}

/// `static int ecxkem_init(void *vecxctx, int operation, void *vecx, void *vauth,
/// const OSSL_PARAM params[])` — `ecx_kem.c:195-221`.
///
/// # Safety
/// The KEM init dispatch contract; `params` is NULL or key-terminated.
unsafe fn ecxkem_init(
    vecxctx: *mut c_void,
    operation: c_int,
    vecx: *mut c_void,
    vauth: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vecxctx.cast::<ProvEcxCtx>();
    let ecx = vecx.cast::<EcxKey>();
    let auth = vauth.cast::<EcxKey>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the caller's contract; `ecx` may be NULL and `ecx_key_check` reads it only then.
    unsafe {
        if ecx_key_check(ecx, c_int::from(operation == EVP_PKEY_OP_DECAPSULATE)) == 0 {
            return 0;
        }
        let rv = recipient_key_set(ctx, ecx);
        if rv <= 0 {
            return rv;
        }

        if !auth.is_null()
            && (ecx_match_params(auth, (*ctx).recipient_key) == 0
                || ecx_key_check(auth, c_int::from(operation == EVP_PKEY_OP_ENCAPSULATE)) == 0
                || sender_authkey_set(ctx, auth) == 0)
        {
            return 0;
        }

        (*ctx).op = operation as c_uint;
        ecxkem_set_ctx_params(vecxctx, params)
    }
}

/// `static int ecxkem_encapsulate_init(void *vecxctx, void *vecx, const OSSL_PARAM params[])` —
/// `ecx_kem.c:223-227`.
///
/// # Safety
/// The KEM `encapsulate_init` dispatch contract.
unsafe extern "C" fn ecxkem_encapsulate_init(
    vecxctx: *mut c_void,
    vecx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecxkem_init(
            vecxctx,
            EVP_PKEY_OP_ENCAPSULATE,
            vecx,
            ptr::null_mut(),
            params,
        )
    }
}

/// `static int ecxkem_decapsulate_init(void *vecxctx, void *vecx, const OSSL_PARAM params[])` —
/// `ecx_kem.c:229-233`.
///
/// # Safety
/// The KEM `decapsulate_init` dispatch contract.
unsafe extern "C" fn ecxkem_decapsulate_init(
    vecxctx: *mut c_void,
    vecx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ecxkem_init(
            vecxctx,
            EVP_PKEY_OP_DECAPSULATE,
            vecx,
            ptr::null_mut(),
            params,
        )
    }
}

/// `static int ecxkem_auth_encapsulate_init(void *vctx, void *vecx, void *vauthpriv,
/// const OSSL_PARAM params[])` — `ecx_kem.c:235-239`.
///
/// # Safety
/// The KEM `auth_encapsulate_init` dispatch contract.
unsafe extern "C" fn ecxkem_auth_encapsulate_init(
    vctx: *mut c_void,
    vecx: *mut c_void,
    vauthpriv: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecxkem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vecx, vauthpriv, params) }
}

/// `static int ecxkem_auth_decapsulate_init(void *vctx, void *vecx, void *vauthpub,
/// const OSSL_PARAM params[])` — `ecx_kem.c:241-245`.
///
/// # Safety
/// The KEM `auth_decapsulate_init` dispatch contract.
unsafe extern "C" fn ecxkem_auth_decapsulate_init(
    vctx: *mut c_void,
    vecx: *mut c_void,
    vauthpub: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ecxkem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vecx, vauthpub, params) }
}

/// `static const OSSL_PARAM ecxkem_set_ctx_params_list[]` — generated `ecx_kem.c:250-254`.
static ECXKEM_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_KEM_PARAM_OPERATION),
    param_octet_string(OSSL_KEM_PARAM_IKME),
    END,
];

/// The set-decoder's repeated-key coordinates, from the generated file's two arms.
const ECXKEM_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_ECX_KEM_280, OSSL_KEM_PARAM_IKME),
    (&err_sites::PROV_ECX_KEM_291, OSSL_KEM_PARAM_OPERATION),
];

/// The repeated-key scan the generated decoder is.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ecxkem_repeated_param_site(
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

/// `struct ecxkem_set_ctx_params_st` — generated `ecx_kem.c:258-261`.
struct EcxkemSetCtxParams {
    ikme: *const OsslParam,
    op: *const OsslParam,
}

/// `ecxkem_set_ctx_params_decoder` — generated `ecx_kem.c:265-299`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ecxkem_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut EcxkemSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ecxkem_repeated_param_site(params, &ECXKEM_SET_CTX_PARAMS_DECODER_KEYS)
        {
            raise_site(site);
            return 0;
        }
        r.ikme = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
        r.op = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    }
    1
}

/// `static int ecxkem_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ecx_kem.c:304-335`.
///
/// # Safety
/// The KEM `set_ctx_params` dispatch contract.
unsafe extern "C" fn ecxkem_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcxCtx>();
    let mut p = EcxkemSetCtxParams {
        ikme: ptr::null(),
        op: ptr::null(),
    };

    // SAFETY: `ctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if ctx.is_null() || ecxkem_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if !p.ikme.is_null() {
            let mut tmp: *mut c_void = ptr::null_mut();
            let mut tmplen: usize = 0;

            if !(*p.ikme).data.is_null()
                && (*p.ikme).data_size != 0
                && OSSL_PARAM_get_octet_string(p.ikme, &mut tmp, 0, &mut tmplen) == 0
            {
                return 0;
            }
            CRYPTO_clear_free((*ctx).ikm.cast(), (*ctx).ikmlen, FILE_ECX_KEM, 321);
            (*ctx).ikm = tmp.cast::<u8>();
            (*ctx).ikmlen = tmplen;
        }

        if !p.op.is_null() {
            if (*p.op).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            let mode = ossl_eckem_modename2id((*p.op).data.cast());
            if mode == KEM_MODE_UNDEFINED {
                return 0;
            }
            (*ctx).mode = mode as c_uint;
        }
    }
    1
}

/// `static const OSSL_PARAM *ecxkem_settable_ctx_params(void *vctx, void *provctx)` —
/// `ecx_kem.c:337-341`.
///
/// # Safety
/// The KEM `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ecxkem_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECXKEM_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int dhkem_extract_and_expand(EVP_KDF_CTX *kctx, unsigned char *okm, size_t okmlen,
/// uint16_t kemid, const unsigned char *dhkm, size_t dhkmlen, const unsigned char *kemctx,
/// size_t kemctxlen)` — `ecx_kem.c:346-373`.
///
/// # Safety
/// `kctx` is live; `okm` is writable for `okmlen`; `dhkm`/`kemctx` are readable for their lengths.
#[allow(clippy::too_many_arguments)]
unsafe fn dhkem_extract_and_expand(
    kctx: *mut EvpKdfCtx,
    okm: *mut u8,
    okmlen: usize,
    kemid: u16,
    dhkm: *const u8,
    dhkmlen: usize,
    kemctx: *const u8,
    kemctxlen: usize,
) -> c_int {
    let mut suiteid: [u8; 2] = [0; 2];
    let mut prk: [u8; EVP_MAX_MD_SIZE] = [0; EVP_MAX_MD_SIZE];
    let prklen = okmlen; /* Nh */

    if prklen > prk.len() {
        return 0;
    }

    suiteid[0] = ((kemid >> 8) & 0xff) as u8;
    suiteid[1] = (kemid & 0xff) as u8;

    // SAFETY: every pointer is per the contract; `prk` is this call's own buffer.
    let ret = unsafe {
        hpke_labeled_extract(
            kctx,
            prk.as_mut_ptr(),
            prklen,
            ptr::null(),
            0,
            LABEL_KEM,
            suiteid.as_ptr(),
            suiteid.len(),
            OSSL_DHKEM_LABEL_EAE_PRK,
            dhkm,
            dhkmlen,
        ) != 0
            && hpke_labeled_expand(
                kctx,
                okm,
                okmlen,
                prk.as_ptr(),
                prklen,
                LABEL_KEM,
                suiteid.as_ptr(),
                suiteid.len(),
                OSSL_DHKEM_LABEL_SHARED_SECRET,
                kemctx,
                kemctxlen,
            ) != 0
    };
    // SAFETY: `prk` is this call's own buffer.
    unsafe { cleanse(prk.as_mut_ptr(), prklen) };
    c_int::from(ret)
}

/// `int ossl_ecx_dhkem_derive_private(ECX_KEY *ecx, unsigned char *privout,
/// const unsigned char *ikm, size_t ikmlen)` — `ecx_kem.c:390-428`. The authority's definition is
/// not `static`, so it is a `#[no_mangle]` export here; `provider/ecx_kmgmt.c`'s `ecx_gen` is its
/// other caller.
///
/// # Safety
/// `ecx` is live; `privout` is writable for `ecx->keylen`; `ikm` is readable for `ikmlen`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_dhkem_derive_private(
    ecx: *mut EcxKey,
    privout: *mut u8,
    ikm: *const u8,
    ikmlen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut prk: [u8; EVP_MAX_MD_SIZE] = [0; EVP_MAX_MD_SIZE];
    let mut suiteid: [u8; 2] = [0; 2];
    // SAFETY: `ecx` is live per the contract.
    let info = unsafe { get_kem_info(ecx) };

    // SAFETY: `ecx` is live and `info` is a `'static` table entry.
    unsafe {
        /* ikmlen should have a length of at least Nsk */
        if ikmlen < (*info).nsk {
            let mut msg = [0 as c_char; 64];
            // SAFETY: `msg` is a 64-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"ikm length is :%zu, should be at least %zu".as_ptr(),
                ikmlen,
                (*info).nsk,
            );
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            raise_site_data(&err_sites::PROV_ECX_KEM_401, msg.as_ptr());
            return ret;
        }

        let kdfctx = kdf_ctx_create(
            c"HKDF".as_ptr(),
            (*info).mdname.as_ptr(),
            (*ecx).libctx,
            (*ecx).propq,
        );
        if kdfctx.is_null() {
            return 0;
        }

        suiteid[0] = ((*info).kem_id / 256) as u8;
        suiteid[1] = ((*info).kem_id % 256) as u8;

        if hpke_labeled_extract(
            kdfctx,
            prk.as_mut_ptr(),
            (*info).nsecret,
            ptr::null(),
            0,
            LABEL_KEM,
            suiteid.as_ptr(),
            suiteid.len(),
            OSSL_DHKEM_LABEL_DKP_PRK,
            ikm,
            ikmlen,
        ) == 0
        {
            cleanse(prk.as_mut_ptr(), prk.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }

        if hpke_labeled_expand(
            kdfctx,
            privout,
            (*info).nsk,
            prk.as_ptr(),
            (*info).nsecret,
            LABEL_KEM,
            suiteid.as_ptr(),
            suiteid.len(),
            OSSL_DHKEM_LABEL_SK,
            ptr::null(),
            0,
        ) == 0
        {
            cleanse(prk.as_mut_ptr(), prk.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }
        ret = 1;
        cleanse(prk.as_mut_ptr(), prk.len());
        EVP_KDF_CTX_free(kdfctx);
    }
    ret
}

/// `static ECX_KEY *derivekey(PROV_ECX_CTX *ctx, const unsigned char *ikm, size_t ikmlen)` —
/// `ecx_kem.c:438-479`.
///
/// The `err:` label is shared by four failures and does two things the early returns cannot be
/// simplified away from: it releases the key, and it cleanses `tmpbuf` when the random seed was
/// taken there rather than from the caller's `ikm`.
///
/// # Safety
/// `ctx` is live with an `info`; `ikm` is NULL or readable for `ikmlen` bytes.
unsafe fn derivekey(ctx: *mut ProvEcxCtx, ikm: *const u8, ikmlen: usize) -> *mut EcxKey {
    let mut ok = false;
    // SAFETY: `ctx` is live per the contract.
    let info = unsafe { (*ctx).info };
    let mut seed: *const u8 = ikm;
    let mut seedlen = ikmlen;
    let mut tmpbuf: [u8; OSSL_HPKE_MAX_PRIVATE] = [0; OSSL_HPKE_MAX_PRIVATE];
    let key;

    // SAFETY: `ctx` is live and its `info` is a `'static` table entry.
    unsafe {
        key = ossl_ecx_key_new(
            (*ctx).libctx,
            (*(*ctx).recipient_key).type_,
            0,
            (*ctx).propq,
        );
        if key.is_null() {
            return ptr::null_mut();
        }

        'derive: {
            let privkey = ossl_ecx_key_allocate_privkey(key);
            if privkey.is_null() {
                break 'derive;
            }

            /* Generate a random seed if there is no input ikm */
            if seed.is_null() || seedlen == 0 {
                if (*info).nsk > tmpbuf.len() {
                    break 'derive;
                }
                if RAND_priv_bytes_ex((*ctx).libctx, tmpbuf.as_mut_ptr(), (*info).nsk, 0) <= 0 {
                    break 'derive;
                }
                seed = tmpbuf.as_ptr();
                seedlen = (*info).nsk;
            }
            if ossl_ecx_dhkem_derive_private(key, privkey, seed, seedlen) == 0 {
                break 'derive;
            }
            if ossl_ecx_public_from_private(key) == 0 {
                break 'derive;
            }
            (*key).haspubkey = 1;
            ok = true;
        }

        if !seed.is_null() && seed != ikm {
            cleanse(seed.cast_mut(), seedlen);
        }
        if !ok {
            ossl_ecx_key_free(key);
            return ptr::null_mut();
        }
        key
    }
}

/// `static int generate_ecxdhkm(const ECX_KEY *sender, const ECX_KEY *peer, unsigned char *out,
/// size_t maxout, unsigned int secretsz)` — `ecx_kem.c:490-499`.
///
/// # Safety
/// The two keys are live; `out` is writable for `maxout` bytes.
unsafe fn generate_ecxdhkm(
    sender: *const EcxKey,
    peer: *const EcxKey,
    out: *mut u8,
    maxout: usize,
    _secretsz: c_uint,
) -> c_int {
    let mut len: usize = 0;

    /* NOTE: ossl_ecx_compute_key checks for shared secret being all zeros */
    // SAFETY: the caller's contract.
    unsafe {
        ossl_ecx_compute_key(
            peer.cast_mut(),
            sender.cast_mut(),
            (*sender).keylen,
            out,
            &mut len,
            maxout,
        )
    }
}

/// `static int derive_secret(PROV_ECX_CTX *ctx, unsigned char *secret, const ECX_KEY *privkey1,
/// const ECX_KEY *peerkey1, const ECX_KEY *privkey2, const ECX_KEY *peerkey2,
/// const unsigned char *sender_pub, const unsigned char *recipient_pub)` —
/// `ecx_kem.c:523-578`.
///
/// # Safety
/// `ctx` is live with an `info`; the key and buffer arguments are per the KEM caller's contract.
#[allow(clippy::too_many_arguments)]
unsafe fn derive_secret(
    ctx: *mut ProvEcxCtx,
    secret: *mut u8,
    privkey1: *const EcxKey,
    peerkey1: *const EcxKey,
    privkey2: *const EcxKey,
    peerkey2: *const EcxKey,
    sender_pub: *const u8,
    recipient_pub: *const u8,
) -> c_int {
    let mut ret: c_int = 0;
    let mut sender_authpub: *mut u8 = ptr::null_mut();
    let mut dhkm: [u8; MAX_ECX_KEYLEN * 2] = [0; MAX_ECX_KEYLEN * 2];
    let mut kemctx: [u8; MAX_ECX_KEYLEN * 3] = [0; MAX_ECX_KEYLEN * 3];
    let mut dhkmlen: usize = 0;

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let info = (*ctx).info;
        let auth = !(*ctx).sender_authkey.is_null();
        let encodedkeylen = (*info).npk;

        if generate_ecxdhkm(
            privkey1,
            peerkey1,
            dhkm.as_mut_ptr(),
            dhkm.len(),
            encodedkeylen as c_uint,
        ) == 0
        {
            cleanse(dhkm.as_mut_ptr(), dhkmlen);
            EVP_KDF_CTX_free(ptr::null_mut());
            return ret;
        }
        dhkmlen = encodedkeylen;

        /* Concat the optional second ECXDH (used for Auth) */
        if auth {
            if generate_ecxdhkm(
                privkey2,
                peerkey2,
                dhkm.as_mut_ptr().add(dhkmlen),
                dhkm.len() - dhkmlen,
                encodedkeylen as c_uint,
            ) == 0
            {
                cleanse(dhkm.as_mut_ptr(), dhkmlen);
                EVP_KDF_CTX_free(ptr::null_mut());
                return ret;
            }
            /* Get the public key of the auth sender in encoded form */
            sender_authpub = ecx_pubkey((*ctx).sender_authkey);
            if sender_authpub.is_null() {
                cleanse(dhkm.as_mut_ptr(), dhkmlen);
                EVP_KDF_CTX_free(ptr::null_mut());
                return ret;
            }
            dhkmlen += encodedkeylen;
        }
        let kemctxlen = encodedkeylen + dhkmlen;
        if kemctxlen > kemctx.len() {
            cleanse(dhkm.as_mut_ptr(), dhkmlen);
            EVP_KDF_CTX_free(ptr::null_mut());
            return ret;
        }

        /* kemctx is the concat of both sides encoded public key */
        ptr::copy_nonoverlapping(sender_pub, kemctx.as_mut_ptr(), encodedkeylen);
        ptr::copy_nonoverlapping(
            recipient_pub,
            kemctx.as_mut_ptr().add(encodedkeylen),
            encodedkeylen,
        );
        if auth {
            ptr::copy_nonoverlapping(
                sender_authpub,
                kemctx.as_mut_ptr().add(2 * encodedkeylen),
                encodedkeylen,
            );
        }
        let kdfctx = kdf_ctx_create(
            (*ctx).kdfname,
            (*info).mdname.as_ptr(),
            (*ctx).libctx,
            (*ctx).propq,
        );
        if kdfctx.is_null() {
            cleanse(dhkm.as_mut_ptr(), dhkmlen);
            return ret;
        }
        if dhkem_extract_and_expand(
            kdfctx,
            secret,
            (*info).nsecret,
            (*info).kem_id,
            dhkm.as_ptr(),
            dhkmlen,
            kemctx.as_ptr(),
            kemctxlen,
        ) == 0
        {
            cleanse(dhkm.as_mut_ptr(), dhkmlen);
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }
        ret = 1;
        cleanse(dhkm.as_mut_ptr(), dhkmlen);
        EVP_KDF_CTX_free(kdfctx);
    }
    ret
}

/// `static int dhkem_encap(PROV_ECX_CTX *ctx, unsigned char *enc, size_t *enclen,
/// unsigned char *secret, size_t *secretlen)` — `ecx_kem.c:598-648`.
///
/// # Safety
/// `ctx` is live with an `info`; `enclen`/`secretlen` are NULL or writable.
unsafe fn dhkem_encap(
    ctx: *mut ProvEcxCtx,
    enc: *mut u8,
    enclen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `ctx` is live per the contract.
    let info = unsafe { (*ctx).info };

    // SAFETY: the caller's contract.
    unsafe {
        if enc.is_null() {
            if enclen.is_null() && secretlen.is_null() {
                return 0;
            }
            if !enclen.is_null() {
                *enclen = (*info).nenc;
            }
            if !secretlen.is_null() {
                *secretlen = (*info).nsecret;
            }
            return 1;
        }

        if *secretlen < (*info).nsecret {
            raise_site_data(
                &err_sites::PROV_ECX_KEM_618,
                c"*secretlen too small".as_ptr(),
            );
            return 0;
        }
        if *enclen < (*info).nenc {
            raise_site_data(&err_sites::PROV_ECX_KEM_622, c"*enclen too small".as_ptr());
            return 0;
        }

        /* Create an ephemeral key */
        let sender_ephemkey = derivekey(ctx, (*ctx).ikm, (*ctx).ikmlen);

        let sender_ephempub = ecx_pubkey(sender_ephemkey);
        let recipient_pub = ecx_pubkey((*ctx).recipient_key);
        if sender_ephempub.is_null() || recipient_pub.is_null() {
            ossl_ecx_key_free(sender_ephemkey);
            return ret;
        }

        if derive_secret(
            ctx,
            secret,
            sender_ephemkey,
            (*ctx).recipient_key,
            (*ctx).sender_authkey,
            (*ctx).recipient_key,
            sender_ephempub,
            recipient_pub,
        ) == 0
        {
            ossl_ecx_key_free(sender_ephemkey);
            return ret;
        }

        /* Return the public part of the ephemeral key */
        ptr::copy_nonoverlapping(sender_ephempub, enc, (*info).nenc);
        *enclen = (*info).nenc;
        *secretlen = (*info).nsecret;
        ret = 1;
        ossl_ecx_key_free(sender_ephemkey);
    }
    ret
}

/// `static int dhkem_decap(PROV_ECX_CTX *ctx, unsigned char *secret, size_t *secretlen,
/// const unsigned char *enc, size_t enclen)` — `ecx_kem.c:666-709`.
///
/// # Safety
/// `ctx` is live with an `info`; `secretlen` is writable when `secret` is not NULL; `enc` is
/// readable for `enclen` bytes.
unsafe fn dhkem_decap(
    ctx: *mut ProvEcxCtx,
    secret: *mut u8,
    secretlen: *mut usize,
    enc: *const u8,
    enclen: usize,
) -> c_int {
    let mut ret: c_int = 0;

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let recipient_privkey = (*ctx).recipient_key;
        let info = (*ctx).info;

        if secret.is_null() {
            *secretlen = (*info).nsecret;
            return 1;
        }
        if *secretlen < (*info).nsecret {
            raise_site_data(
                &err_sites::PROV_ECX_KEM_681,
                c"*secretlen too small".as_ptr(),
            );
            return 0;
        }
        if enclen != (*info).nenc {
            raise_site_data(
                &err_sites::PROV_ECX_KEM_685,
                c"Invalid enc public key".as_ptr(),
            );
            return 0;
        }

        /* Get the public part of the ephemeral key created by encap */
        let sender_ephempubkey = ecxkey_pubfromdata(ctx, enc, enclen);
        if sender_ephempubkey.is_null() {
            return ret;
        }

        let recipient_pub = ecx_pubkey(recipient_privkey);
        if recipient_pub.is_null() {
            ossl_ecx_key_free(sender_ephempubkey);
            return ret;
        }

        if derive_secret(
            ctx,
            secret,
            (*ctx).recipient_key,
            sender_ephempubkey,
            (*ctx).recipient_key,
            (*ctx).sender_authkey,
            enc,
            recipient_pub,
        ) == 0
        {
            ossl_ecx_key_free(sender_ephempubkey);
            return ret;
        }

        *secretlen = (*info).nsecret;
        ret = 1;
        ossl_ecx_key_free(sender_ephempubkey);
    }
    ret
}

/// `static int ecxkem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
/// unsigned char *secret, size_t *secretlen)` — `ecx_kem.c:711-723`.
///
/// # Safety
/// The KEM `encapsulate` dispatch contract.
unsafe extern "C" fn ecxkem_encapsulate(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcxCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        match (*ctx).mode as c_int {
            KEM_MODE_DHKEM => dhkem_encap(ctx, out, outlen, secret, secretlen),
            _ => {
                raise_site(&err_sites::PROV_ECX_KEM_720);
                -2
            }
        }
    }
}

/// `static int ecxkem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
/// const unsigned char *in, size_t inlen)` — `ecx_kem.c:725-737`.
///
/// # Safety
/// The KEM `decapsulate` dispatch contract.
unsafe extern "C" fn ecxkem_decapsulate(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcxCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        match (*ctx).mode as c_int {
            KEM_MODE_DHKEM => dhkem_decap(ctx, out, outlen, in_, inlen),
            _ => {
                raise_site(&err_sites::PROV_ECX_KEM_734);
                -2
            }
        }
    }
}

/// `const OSSL_DISPATCH ossl_ecx_asym_kem_functions[]` — `ecx_kem.c:739-757`. Ten slots, the
/// authority's, in its order. The two `X25519`/`X448` rows the census records share this one
/// table, exactly as the authority's `deflt_asym_kem[]` publishes them.
pub(crate) static ECX_ASYM_KEM_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_NEWCTX,
        function: ecxkem_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        function: ecxkem_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE,
        function: ecxkem_encapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE_INIT,
        function: ecxkem_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE,
        function: ecxkem_decapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_FREECTX,
        function: ecxkem_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SET_CTX_PARAMS,
        function: ecxkem_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        function: ecxkem_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
        function: ecxkem_auth_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
        function: ecxkem_auth_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
