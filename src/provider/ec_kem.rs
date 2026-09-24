//! Phase 8.10 — `providers/implementations/kem/ec_kem.c.in`: the `EC` DHKEM row's whole unit.
//!
//! Eight hundred and twenty-two source lines (the `produce_param_decoder` expansion makes the
//! compiled translation unit some four dozen lines longer), one dispatch table and twenty-seven
//! functions: the three NIST-curve rows of RFC 9180 §4.1's `DHKEM` — `Encap`, `Decap`, the two
//! authenticated variants and the `DeriveKeyPair` primitive — over `EC` keys. The unit's one row
//! (`EC` under `OSSL_OP_KEM`) shares `ossl_ec_asym_kem_functions` with its siblings in the
//! authority's `deflt_asym_kem[]`; `src/provider/kem.rs` registers it against
//! [`EC_ASYM_KEM_FUNCTIONS`], which is the only table this module publishes.
//!
//! ## `ossl_ec_dhkem_derive_private` is defined here, and `ec_kmgmt.c` calls it
//!
//! `prov/ecx.h` declares it, and the authority's only definition is in this unit (`:387-452`).
//! `crypto/ec/ec_key.c`'s `ossl_ec_generate_key_dhkem` — which `ec_kmgmt.c`'s `ec_gen` reaches
//! whenever the caller sets `OSSL_PKEY_PARAM_DHKEM_IKM` — is a one-line call to it, so it is a
//! `#[no_mangle]` export of this module (its authority definition is not `static`) and
//! `src/ec/key.rs:737` reaches it here. Its other caller is this unit's own `derivekey`.
//!
//! ## The dependencies, and what the crate writes instead of the generator
//!
//! `eckem_set_ctx_params` resolves its operation name through `ossl_eckem_modename2id`
//! (`src/provider/kem_util.rs`), and its key material flows through the crate's EC key surface
//! (`src/ec/key.rs`, `src/ec/lib.rs`, `src/ec/oct.rs`, `src/ec/kmeth.rs`, including
//! `ossl_ec_key_public_check`, which supplies `check_publickey`). The DHKEM primitives are
//! `src/hpke/mod.rs`'s `ossl_hpke_labeled_extract`/`_expand`, `ossl_kdf_ctx_create` and
//! `ossl_HPKE_KEM_INFO_find_curve`.
//!
//! The generated `eckem_set_ctx_params_decoder` is one repeated-key scan plus two
//! `OSSL_PARAM_locate_const` calls, the idiom `src/provider/ecx_kem.rs` and
//! `src/provider/ml_kem_kem.rs` already use. `ec_kem.c.in` carries no profile `#ifdef` arms: the
//! only conditional directives in the generated file are the three `#ifndef` generate-once guards
//! around the decoder's own definitions.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::arith::{BN_cmp, BN_div};
use crate::bn::bignum::{BN_bin2bn, BN_free, BN_is_zero, BN_new, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::curve::EC_curve_nid2nist;
use crate::ec::key::{
    ossl_ec_generate_key_dhkem, ossl_ec_key_get0_propq, ossl_ec_key_get_libctx,
    ossl_ec_key_public_check, EC_KEY_free, EC_KEY_get0_group, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key, EC_KEY_new_ex, EC_KEY_oct2key, EC_KEY_set_group, EC_KEY_up_ref,
};
use crate::ec::kmeth::ECDH_compute_key;
use crate::ec::lib::{
    EC_GROUP_cmp, EC_GROUP_get0_order, EC_GROUP_get_curve_name, EC_GROUP_get_degree,
};
use crate::ec::oct::EC_POINT_point2oct;
use crate::ec::{EcKey, POINT_CONVERSION_UNCOMPRESSED};
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
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OsslParam, END, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::kem_util::{ossl_eckem_modename2id, KEM_MODE_DHKEM, KEM_MODE_UNDEFINED};
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::{cleanse, CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

/// `LABEL_KEM` — `ec_kem.c.in:70`, `"KEM"`.
const LABEL_KEM: &[u8] = b"KEM";
/// `OSSL_DHKEM_LABEL_EAE_PRK` — `prov/ecx.h:17`, `"eae_prk"`.
const OSSL_DHKEM_LABEL_EAE_PRK: &[u8] = b"eae_prk";
/// `OSSL_DHKEM_LABEL_SHARED_SECRET` — `prov/ecx.h:19`, `"shared_secret"`.
const OSSL_DHKEM_LABEL_SHARED_SECRET: &[u8] = b"shared_secret";
/// `OSSL_DHKEM_LABEL_DKP_PRK` — `prov/ecx.h:21`, `"dkp_prk"`.
const OSSL_DHKEM_LABEL_DKP_PRK: &[u8] = b"dkp_prk";
/// `OSSL_DHKEM_LABEL_CANDIDATE` — `prov/ecx.h:23`, `"candidate"`.
const OSSL_DHKEM_LABEL_CANDIDATE: &[u8] = b"candidate";

/// `OSSL_HPKE_MAX_SECRET` — `include/internal/hpke_util.h:15`.
const OSSL_HPKE_MAX_SECRET: usize = 64;
/// `OSSL_HPKE_MAX_PUBLIC` — `include/internal/hpke_util.h:16`.
const OSSL_HPKE_MAX_PUBLIC: usize = 133;
/// `OSSL_HPKE_MAX_PRIVATE` — `include/internal/hpke_util.h:17`.
const OSSL_HPKE_MAX_PRIVATE: usize = 66;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:404`. The `prk` scratch is `EVP_MAX_MD_SIZE` bytes.
const EVP_MAX_MD_SIZE: usize = 64;

/// `OSSL_KEM_PARAM_OPERATION` — `core_names.h:326`.
const OSSL_KEM_PARAM_OPERATION: *const c_char = c"operation".as_ptr();
/// `OSSL_KEM_PARAM_IKME` — `core_names.h:325`.
const OSSL_KEM_PARAM_IKME: *const c_char = c"ikme".as_ptr();

/// The generated unit's own `__FILE__`. `ec_kem.c.in` is `.c.in`-generated, so it is the bare
/// build-relative path.
const FILE_EC_KEM: *const c_char = c"providers/implementations/kem/ec_kem.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_EC_CTX` — `ec_kem.c.in:45-56`.
#[repr(C)]
struct ProvEcCtx {
    /// `EC_KEY *recipient_key`.
    recipient_key: *mut EcKey,
    /// `EC_KEY *sender_authkey`.
    sender_authkey: *mut EcKey,
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

/// `static int eckey_check(const EC_KEY *ec, int requires_privatekey)` — `ec_kem.c.in:72-103`.
///
/// A key must have a public component, and a private component must be non-zero modulo the group
/// order. The `rem`/`bnctx` allocations are released on both exits the authority reaches once they
/// exist; the two NULL guards return before either is allocated.
///
/// # Safety
/// `ec` is live.
unsafe fn eckey_check(ec: *const EcKey, requires_privatekey: c_int) -> c_int {
    // SAFETY: `ec` is live per the contract.
    unsafe {
        let priv_ = EC_KEY_get0_private_key(ec);
        let pub_ = EC_KEY_get0_public_key(ec);

        /* Keys always require a public component */
        if pub_.is_null() {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::PROV_EC_KEM_80);
            return 0;
        }
        if priv_.is_null() {
            return c_int::from(requires_privatekey == 0);
        }
        /* If there is a private key, check that is non zero (mod order) */
        let group = EC_KEY_get0_group(ec);
        let order = EC_GROUP_get0_order(group);

        let bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
        let rem = BN_new();

        let mut rv: c_int = 0;
        if !order.is_null() && !rem.is_null() && !bnctx.is_null() {
            // `BN_mod(rem, priv, order, bnctx)` is the authority's macro over
            // `BN_div(NULL, rem, priv, order, bnctx)`.
            rv = c_int::from(
                BN_div(ptr::null_mut(), rem, priv_, order, bnctx) != 0 && BN_is_zero(rem) == 0,
            );
        }
        BN_free(rem);
        BN_CTX_free(bnctx);
        rv
    }
}

/// `static const char *ec_curvename_get0(const EC_KEY *ec)` — `ec_kem.c.in:106-111`.
///
/// # Safety
/// `ec` is live.
unsafe fn ec_curvename_get0(ec: *const EcKey) -> *const c_char {
    // SAFETY: `ec` is live per the contract.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: `group` is the key's own group, live whenever the key is.
    unsafe { EC_curve_nid2nist(EC_GROUP_get_curve_name(group)) }
}

/// `static int recipient_key_set(PROV_EC_CTX *ctx, EC_KEY *ec)` — `ec_kem.c.in:119-138`.
///
/// `-2` is a KEM whose curve the HPKE table does not name, a distinct answer from the `0` a failed
/// reference gives — `eckem_init` returns it unaltered.
///
/// # Safety
/// `ctx` is live; `ec` is NULL or live.
unsafe fn recipient_key_set(ctx: *mut ProvEcCtx, ec: *mut EcKey) -> c_int {
    // SAFETY: `ctx` is live and its own key is released and replaced here.
    unsafe {
        EC_KEY_free((*ctx).recipient_key);
        (*ctx).recipient_key = ptr::null_mut();

        if !ec.is_null() {
            let curve = ec_curvename_get0(ec);
            if curve.is_null() {
                return -2;
            }
            (*ctx).info = ossl_HPKE_KEM_INFO_find_curve(curve);
            if (*ctx).info.is_null() {
                return -2;
            }
            if EC_KEY_up_ref(ec) == 0 {
                return 0;
            }
            (*ctx).recipient_key = ec;
            (*ctx).kdfname = c"HKDF".as_ptr();
        }
    }
    1
}

/// `static int sender_authkey_set(PROV_EC_CTX *ctx, EC_KEY *ec)` — `ec_kem.c.in:144-155`.
///
/// # Safety
/// `ctx` is live; `ec` is NULL or live.
unsafe fn sender_authkey_set(ctx: *mut ProvEcCtx, ec: *mut EcKey) -> c_int {
    // SAFETY: `ctx` is live and its own key is released and replaced here.
    unsafe {
        EC_KEY_free((*ctx).sender_authkey);
        (*ctx).sender_authkey = ptr::null_mut();

        if !ec.is_null() {
            if EC_KEY_up_ref(ec) == 0 {
                return 0;
            }
            (*ctx).sender_authkey = ec;
        }
    }
    1
}

/// `static EC_KEY *eckey_frompub(EC_KEY *in, const unsigned char *pubbuf, size_t pubbuflen)` —
/// `ec_kem.c.in:164-180`.
///
/// # Safety
/// `in` is live with a group; `pubbuf` is readable for `pubbuflen` bytes.
unsafe fn eckey_frompub(in_: *mut EcKey, pubbuf: *const u8, pubbuflen: usize) -> *mut EcKey {
    // SAFETY: `in_` is live per the contract and the new key borrows its libctx/propq.
    unsafe {
        let key = EC_KEY_new_ex(ossl_ec_key_get_libctx(in_), ossl_ec_key_get0_propq(in_));
        if key.is_null() {
            return ptr::null_mut();
        }
        if EC_KEY_set_group(key, EC_KEY_get0_group(in_)) == 0
            || EC_KEY_oct2key(key, pubbuf, pubbuflen, ptr::null_mut()) == 0
        {
            EC_KEY_free(key);
            return ptr::null_mut();
        }
        key
    }
}

/// `static int ecpubkey_todata(const EC_KEY *ec, unsigned char *out, size_t *outlen,
/// size_t maxoutlen)` — `ec_kem.c.in:186-197`.
///
/// # Safety
/// `ec` is live with a public point; `out` is writable for `maxoutlen` bytes; `outlen` is writable.
unsafe fn ecpubkey_todata(
    ec: *const EcKey,
    out: *mut u8,
    outlen: *mut usize,
    maxoutlen: usize,
) -> c_int {
    // SAFETY: `ec` is live per the contract.
    unsafe {
        let group = EC_KEY_get0_group(ec);
        let pub_ = EC_KEY_get0_public_key(ec);
        *outlen = EC_POINT_point2oct(
            group,
            pub_,
            POINT_CONVERSION_UNCOMPRESSED,
            out,
            maxoutlen,
            ptr::null_mut(),
        );
        c_int::from(*outlen != 0)
    }
}

/// `static void *eckem_newctx(void *provctx)` — `ec_kem.c.in:199-209`.
///
/// # Safety
/// The KEM `newctx` dispatch contract.
unsafe extern "C" fn eckem_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvEcCtx>(), FILE_EC_KEM, 199).cast::<ProvEcCtx>();

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

/// `static void eckem_freectx(void *vectx)` — `ec_kem.c.in:211-219`.
///
/// # Safety
/// The KEM `freectx` dispatch contract.
unsafe extern "C" fn eckem_freectx(vectx: *mut c_void) {
    let ctx = vectx.cast::<ProvEcCtx>();

    // SAFETY: `ctx` is the caller's context; `recipient_key_set`/`sender_authkey_set` accept a
    // NULL key and release the held ones, and `ctx` is released last.
    unsafe {
        CRYPTO_clear_free((*ctx).ikm.cast(), (*ctx).ikmlen, FILE_EC_KEM, 213);
        recipient_key_set(ctx, ptr::null_mut());
        sender_authkey_set(ctx, ptr::null_mut());
        CRYPTO_free(ctx.cast(), FILE_EC_KEM, 216);
    }
}

/// `static int ossl_ec_match_params(const EC_KEY *key1, const EC_KEY *key2)` —
/// `ec_kem.c.in:221-239`. Static in the authority despite the `ossl_` prefix.
///
/// # Safety
/// Both keys are live.
unsafe fn ossl_ec_match_params(key1: *const EcKey, key2: *const EcKey) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe {
        let group1 = EC_KEY_get0_group(key1);
        let group2 = EC_KEY_get0_group(key2);

        let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key1));
        if ctx.is_null() {
            return 0;
        }

        let ret = c_int::from(
            !group1.is_null() && !group2.is_null() && EC_GROUP_cmp(group1, group2, ctx) == 0,
        );
        if ret == 0 {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::PROV_EC_KEM_234);
        }
        BN_CTX_free(ctx);
        ret
    }
}

/// `static int eckem_init(void *vctx, int operation, void *vec, void *vauth,
/// const OSSL_PARAM params[])` — `ec_kem.c.in:241-267`.
///
/// # Safety
/// The KEM init dispatch contract; `params` is NULL or key-terminated.
unsafe fn eckem_init(
    vctx: *mut c_void,
    operation: c_int,
    vec: *mut c_void,
    vauth: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvEcCtx>();
    let ec = vec.cast::<EcKey>();
    let auth = vauth.cast::<EcKey>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the caller's contract; `ec` may be NULL and `eckey_check` reads it only then.
    unsafe {
        if eckey_check(ec, c_int::from(operation == EVP_PKEY_OP_DECAPSULATE)) == 0 {
            return 0;
        }
        let rv = recipient_key_set(ctx, ec);
        if rv <= 0 {
            return rv;
        }

        if !auth.is_null()
            && (ossl_ec_match_params(ec, auth) == 0
                || eckey_check(auth, c_int::from(operation == EVP_PKEY_OP_ENCAPSULATE)) == 0
                || sender_authkey_set(ctx, auth) == 0)
        {
            return 0;
        }

        (*ctx).op = operation as c_uint;
        eckem_set_ctx_params(vctx, params)
    }
}

/// `static int eckem_encapsulate_init(void *vctx, void *vec, const OSSL_PARAM params[])` —
/// `ec_kem.c.in:269-273`.
///
/// # Safety
/// The KEM `encapsulate_init` dispatch contract.
unsafe extern "C" fn eckem_encapsulate_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { eckem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vec, ptr::null_mut(), params) }
}

/// `static int eckem_decapsulate_init(void *vctx, void *vec, const OSSL_PARAM params[])` —
/// `ec_kem.c.in:275-279`.
///
/// # Safety
/// The KEM `decapsulate_init` dispatch contract.
unsafe extern "C" fn eckem_decapsulate_init(
    vctx: *mut c_void,
    vec: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { eckem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vec, ptr::null_mut(), params) }
}

/// `static int eckem_auth_encapsulate_init(void *vctx, void *vecx, void *vauthpriv,
/// const OSSL_PARAM params[])` — `ec_kem.c.in:281-285`.
///
/// # Safety
/// The KEM `auth_encapsulate_init` dispatch contract.
unsafe extern "C" fn eckem_auth_encapsulate_init(
    vctx: *mut c_void,
    vecx: *mut c_void,
    vauthpriv: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { eckem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vecx, vauthpriv, params) }
}

/// `static int eckem_auth_decapsulate_init(void *vctx, void *vecx, void *vauthpub,
/// const OSSL_PARAM params[])` — `ec_kem.c.in:287-291`.
///
/// # Safety
/// The KEM `auth_decapsulate_init` dispatch contract.
unsafe extern "C" fn eckem_auth_decapsulate_init(
    vctx: *mut c_void,
    vecx: *mut c_void,
    vauthpub: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { eckem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vecx, vauthpub, params) }
}

/// `static const OSSL_PARAM eckem_set_ctx_params_list[]` — generated `ec_kem.c:294-298`.
static ECKEM_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_KEM_PARAM_OPERATION),
    param_octet_string(OSSL_KEM_PARAM_IKME),
    END,
];

/// The set-decoder's repeated-key coordinates, from the generated file's two arms.
const ECKEM_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 2] = [
    (&err_sites::PROV_EC_KEM_324, OSSL_KEM_PARAM_IKME),
    (&err_sites::PROV_EC_KEM_335, OSSL_KEM_PARAM_OPERATION),
];

/// The repeated-key scan the generated decoder is.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn eckem_repeated_param_site(
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

/// `struct eckem_set_ctx_params_st` — generated `ec_kem.c:302-305`.
struct EckemSetCtxParams {
    ikme: *const OsslParam,
    op: *const OsslParam,
}

/// `eckem_set_ctx_params_decoder` — generated `ec_kem.c:309-343`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn eckem_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut EckemSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = eckem_repeated_param_site(params, &ECKEM_SET_CTX_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.ikme = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
        r.op = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    }
    1
}

/// `static int eckem_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ec_kem.c.in:300-332`.
///
/// # Safety
/// The KEM `set_ctx_params` dispatch contract.
unsafe extern "C" fn eckem_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvEcCtx>();
    let mut p = EckemSetCtxParams {
        ikme: ptr::null(),
        op: ptr::null(),
    };

    // SAFETY: `ctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if ctx.is_null() || eckem_set_ctx_params_decoder(params, &mut p) == 0 {
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
            CRYPTO_clear_free((*ctx).ikm.cast(), (*ctx).ikmlen, FILE_EC_KEM, 365);
            /* Set the ephemeral seed */
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

/// `static const OSSL_PARAM *eckem_settable_ctx_params(void *vctx, void *provctx)` —
/// `ec_kem.c.in:334-338`.
///
/// # Safety
/// The KEM `settable_ctx_params` dispatch contract.
unsafe extern "C" fn eckem_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ECKEM_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int dhkem_extract_and_expand(EVP_KDF_CTX *kctx, unsigned char *okm, size_t okmlen,
/// uint16_t kemid, const unsigned char *dhkm, size_t dhkmlen, const unsigned char *kemctx,
/// size_t kemctxlen)` — `ec_kem.c.in:343-370`.
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

/// `int ossl_ec_dhkem_derive_private(EC_KEY *ec, BIGNUM *priv, const unsigned char *ikm,
/// size_t ikmlen)` — `ec_kem.c.in:387-452`.
///
/// The `-2` return is the authority's "unsupported curve" answer, distinct from the `0` a failed
/// KDF context or a failed expansion gives, and `ossl_ec_generate_key_dhkem` propagates it as a
/// plain failure (`<= 0`).
///
/// # Safety
/// `ec` is live; `priv` is a live `BIGNUM` the caller owns; `ikm` is NULL or readable for `ikmlen`.
#[allow(unused_assignments)] // the authority initialises `kdfctx` to NULL and assigns it before its only read
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_dhkem_derive_private(
    ec: *mut EcKey,
    priv_: *mut BigNum,
    ikm: *const u8,
    ikmlen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut suiteid: [u8; 2] = [0; 2];
    let mut prk: [u8; OSSL_HPKE_MAX_SECRET] = [0; OSSL_HPKE_MAX_SECRET];
    let mut privbuf: [u8; OSSL_HPKE_MAX_PRIVATE] = [0; OSSL_HPKE_MAX_PRIVATE];
    let mut counter: u8 = 0;
    let mut kdfctx: *mut EvpKdfCtx = core::ptr::null_mut();

    // SAFETY: `ec` is live per the contract.
    let curve = unsafe { ec_curvename_get0(ec) };
    if curve.is_null() {
        return -2;
    }

    // SAFETY: `curve` is NUL-terminated and the table's own contract holds.
    let info = unsafe { ossl_HPKE_KEM_INFO_find_curve(curve) };
    if info.is_null() {
        return -2;
    }

    // SAFETY: `ec` is live and `info` is a `'static` table entry.
    unsafe {
        kdfctx = kdf_ctx_create(
            c"HKDF".as_ptr(),
            (*info).mdname.as_ptr(),
            ossl_ec_key_get_libctx(ec),
            ossl_ec_key_get0_propq(ec),
        );
        if kdfctx.is_null() {
            return 0;
        }

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
            raise_site_data(&err_sites::PROV_EC_KEM_463, msg.as_ptr());
            cleanse(prk.as_mut_ptr(), prk.len());
            cleanse(privbuf.as_mut_ptr(), privbuf.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }

        suiteid[0] = ((*info).kem_id / 256) as u8;
        suiteid[1] = ((*info).kem_id % 256) as u8;

        if hpke_labeled_extract(
            kdfctx,
            prk.as_mut_ptr(),
            (*info).nsecret,
            core::ptr::null(),
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
            cleanse(privbuf.as_mut_ptr(), privbuf.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }

        // SAFETY: `ec` is live, so its group is.
        let order = EC_GROUP_get0_order(EC_KEY_get0_group(ec));
        loop {
            if hpke_labeled_expand(
                kdfctx,
                privbuf.as_mut_ptr(),
                (*info).nsk,
                prk.as_ptr(),
                (*info).nsecret,
                LABEL_KEM,
                suiteid.as_ptr(),
                suiteid.len(),
                OSSL_DHKEM_LABEL_CANDIDATE,
                &counter,
                1,
            ) == 0
            {
                break;
            }
            privbuf[0] &= (*info).bitmask;
            if BN_bin2bn(privbuf.as_ptr(), (*info).nsk as c_int, priv_).is_null() {
                break;
            }
            if counter == 0xFF {
                raise_site(&err_sites::PROV_EC_KEM_489);
                cleanse(prk.as_mut_ptr(), prk.len());
                cleanse(privbuf.as_mut_ptr(), privbuf.len());
                EVP_KDF_CTX_free(kdfctx);
                return ret;
            }
            counter = counter.wrapping_add(1);
            if !(BN_is_zero(priv_) != 0 || BN_cmp(priv_, order) >= 0) {
                ret = 1;
                break;
            }
        }
        cleanse(prk.as_mut_ptr(), prk.len());
        cleanse(privbuf.as_mut_ptr(), privbuf.len());
        EVP_KDF_CTX_free(kdfctx);
    }
    ret
}

/// `static EC_KEY *derivekey(PROV_EC_CTX *ctx, const unsigned char *ikm, size_t ikmlen)` —
/// `ec_kem.c.in:462-495`.
///
/// The `err:` label is shared by the four failures: it cleanses `tmpbuf` when the random seed was
/// taken there rather than from the caller's `ikm`, and releases the key when the keygen failed.
///
/// # Safety
/// `ctx` is live with a `recipient_key` and an `info`; `ikm` is NULL or readable for `ikmlen`.
unsafe fn derivekey(ctx: *mut ProvEcCtx, ikm: *const u8, ikmlen: usize) -> *mut EcKey {
    let mut ret: c_int = 0;
    let mut seed: *const u8 = ikm;
    let mut seedlen = ikmlen;
    let mut tmpbuf: [u8; OSSL_HPKE_MAX_PRIVATE] = [0; OSSL_HPKE_MAX_PRIVATE];
    let key: *mut EcKey;

    // SAFETY: `ctx` is live and its `info` is a `'static` table entry.
    unsafe {
        'derive: {
            key = EC_KEY_new_ex((*ctx).libctx, (*ctx).propq);
            if key.is_null() {
                break 'derive;
            }
            if EC_KEY_set_group(key, EC_KEY_get0_group((*ctx).recipient_key)) == 0 {
                break 'derive;
            }

            /* Generate a random seed if there is no input ikm */
            if seed.is_null() || seedlen == 0 {
                seedlen = (*(*ctx).info).nsk;
                if seedlen > tmpbuf.len() {
                    break 'derive;
                }
                if RAND_priv_bytes_ex((*ctx).libctx, tmpbuf.as_mut_ptr(), seedlen, 0) <= 0 {
                    break 'derive;
                }
                seed = tmpbuf.as_ptr();
            }
            ret = ossl_ec_generate_key_dhkem(key, seed, seedlen);
        }

        if seed != ikm {
            cleanse(seed.cast_mut(), seedlen);
        }
        if ret <= 0 {
            EC_KEY_free(key);
            return ptr::null_mut();
        }
        key
    }
}

/// `static int check_publickey(const EC_KEY *pub)` — `ec_kem.c.in:504-515`.
///
/// # Safety
/// `pub_` is live with a group and a public point.
unsafe fn check_publickey(pub_: *const EcKey) -> c_int {
    // SAFETY: `pub_` is live per the contract.
    unsafe {
        let bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(pub_));
        if bnctx.is_null() {
            return 0;
        }
        let ret = ossl_ec_key_public_check(pub_, bnctx);
        BN_CTX_free(bnctx);
        ret
    }
}

/// `static int generate_ecdhkm(const EC_KEY *sender, const EC_KEY *peer, unsigned char *out,
/// size_t maxout, unsigned int secretsz)` — `ec_kem.c.in:526-543`.
///
/// # Safety
/// Both keys are live; `out` is writable for `maxout` bytes.
unsafe fn generate_ecdhkm(
    sender: *const EcKey,
    peer: *const EcKey,
    out: *mut u8,
    maxout: usize,
    secretsz: c_uint,
) -> c_int {
    // SAFETY: both keys are live per the contract.
    unsafe {
        let group = EC_KEY_get0_group(sender);
        // `(EC_GROUP_get_degree(group) + 7) / 8` in the authority.
        let secretlen = (EC_GROUP_get_degree(group) as usize).div_ceil(8);

        if secretlen != secretsz as usize || secretlen > maxout {
            raise_site_data(&err_sites::PROV_EC_KEM_582, c"secretsz invalid".as_ptr());
            return 0;
        }

        if check_publickey(peer) == 0 {
            return 0;
        }
        c_int::from(
            ECDH_compute_key(
                out.cast(),
                secretlen,
                EC_KEY_get0_public_key(peer),
                sender,
                None,
            ) > 0,
        )
    }
}

/// `static int derive_secret(PROV_EC_CTX *ctx, unsigned char *secret, const EC_KEY *privkey1,
/// const EC_KEY *peerkey1, const EC_KEY *privkey2, const EC_KEY *peerkey2,
/// const unsigned char *sender_pub, const unsigned char *recipient_pub)` —
/// `ec_kem.c.in:567-630`.
///
/// # Safety
/// `ctx` is live with an `info`; the key and buffer arguments are per the KEM caller's contract.
#[allow(clippy::too_many_arguments)]
unsafe fn derive_secret(
    ctx: *mut ProvEcCtx,
    secret: *mut u8,
    privkey1: *const EcKey,
    peerkey1: *const EcKey,
    privkey2: *const EcKey,
    peerkey2: *const EcKey,
    sender_pub: *const u8,
    recipient_pub: *const u8,
) -> c_int {
    let mut ret: c_int = 0;
    let mut sender_authpub: [u8; OSSL_HPKE_MAX_PUBLIC] = [0; OSSL_HPKE_MAX_PUBLIC];
    let mut dhkm: [u8; OSSL_HPKE_MAX_PRIVATE * 2] = [0; OSSL_HPKE_MAX_PRIVATE * 2];
    let mut kemctx: [u8; OSSL_HPKE_MAX_PUBLIC * 3] = [0; OSSL_HPKE_MAX_PUBLIC * 3];
    let mut sender_authpublen: usize = 0;
    let mut kemctxlen: usize;
    let mut dhkmlen: usize = 0;
    let mut kdfctx: *mut EvpKdfCtx = ptr::null_mut();

    // SAFETY: `ctx` is live and its `info` is a `'static` table entry.
    unsafe {
        let info = (*ctx).info;
        let encodedpublen = (*info).npk;
        let encodedprivlen = (*info).nsk;
        let auth = !(*ctx).sender_authkey.is_null();

        'derive: {
            if generate_ecdhkm(
                privkey1,
                peerkey1,
                dhkm.as_mut_ptr(),
                dhkm.len(),
                encodedprivlen as c_uint,
            ) == 0
            {
                break 'derive;
            }
            dhkmlen = encodedprivlen;
            kemctxlen = 2 * encodedpublen;

            /* Concat the optional second ECDH (used for Auth) */
            if auth {
                /* Get the public key of the auth sender in encoded form */
                if ecpubkey_todata(
                    (*ctx).sender_authkey,
                    sender_authpub.as_mut_ptr(),
                    &mut sender_authpublen,
                    sender_authpub.len(),
                ) == 0
                {
                    break 'derive;
                }
                if sender_authpublen != encodedpublen {
                    raise_site_data(
                        &err_sites::PROV_EC_KEM_646,
                        c"Invalid sender auth public key".as_ptr(),
                    );
                    break 'derive;
                }
                if generate_ecdhkm(
                    privkey2,
                    peerkey2,
                    dhkm.as_mut_ptr().add(dhkmlen),
                    dhkm.len() - dhkmlen,
                    encodedprivlen as c_uint,
                ) == 0
                {
                    break 'derive;
                }
                dhkmlen += encodedprivlen;
                kemctxlen += encodedpublen;
            }
            if kemctxlen > kemctx.len() {
                break 'derive;
            }

            /* kemctx is the concat of both sides encoded public key */
            ptr::copy_nonoverlapping(sender_pub, kemctx.as_mut_ptr(), (*info).npk);
            ptr::copy_nonoverlapping(
                recipient_pub,
                kemctx.as_mut_ptr().add((*info).npk),
                (*info).npk,
            );
            if auth {
                ptr::copy_nonoverlapping(
                    sender_authpub.as_ptr(),
                    kemctx.as_mut_ptr().add(2 * encodedpublen),
                    encodedpublen,
                );
            }
            kdfctx = kdf_ctx_create(
                (*ctx).kdfname,
                (*info).mdname.as_ptr(),
                (*ctx).libctx,
                (*ctx).propq,
            );
            if kdfctx.is_null() {
                break 'derive;
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
                break 'derive;
            }
            ret = 1;
        }

        cleanse(dhkm.as_mut_ptr(), dhkmlen);
        EVP_KDF_CTX_free(kdfctx);
    }
    ret
}

/// `static int dhkem_encap(PROV_EC_CTX *ctx, unsigned char *enc, size_t *enclen,
/// unsigned char *secret, size_t *secretlen)` — `ec_kem.c.in:650-710`.
///
/// # Safety
/// `ctx` is live with an `info`; `enclen`/`secretlen` are NULL or writable.
unsafe fn dhkem_encap(
    ctx: *mut ProvEcCtx,
    enc: *mut u8,
    enclen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut sender_pub: [u8; OSSL_HPKE_MAX_PUBLIC] = [0; OSSL_HPKE_MAX_PUBLIC];
    let mut recipient_pub: [u8; OSSL_HPKE_MAX_PUBLIC] = [0; OSSL_HPKE_MAX_PUBLIC];
    let mut sender_publen: usize = 0;
    let mut recipient_publen: usize = 0;

    // SAFETY: `ctx` is live and its `info` is a `'static` table entry.
    unsafe {
        let info = (*ctx).info;

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
                &err_sites::PROV_EC_KEM_720,
                c"*secretlen too small".as_ptr(),
            );
            return 0;
        }
        if *enclen < (*info).nenc {
            raise_site_data(&err_sites::PROV_EC_KEM_724, c"*enclen too small".as_ptr());
            return 0;
        }

        /* Create an ephemeral key */
        let sender_ephemkey = derivekey(ctx, (*ctx).ikm, (*ctx).ikmlen);
        if sender_ephemkey.is_null() {
            EC_KEY_free(sender_ephemkey);
            return ret;
        }
        if ecpubkey_todata(
            sender_ephemkey,
            sender_pub.as_mut_ptr(),
            &mut sender_publen,
            sender_pub.len(),
        ) == 0
            || ecpubkey_todata(
                (*ctx).recipient_key,
                recipient_pub.as_mut_ptr(),
                &mut recipient_publen,
                recipient_pub.len(),
            ) == 0
        {
            EC_KEY_free(sender_ephemkey);
            return ret;
        }
        if sender_publen != (*info).npk || recipient_publen != sender_publen {
            raise_site_data(&err_sites::PROV_EC_KEM_740, c"Invalid public key".as_ptr());
            EC_KEY_free(sender_ephemkey);
            return ret;
        }

        if derive_secret(
            ctx,
            secret,
            sender_ephemkey,
            (*ctx).recipient_key,
            (*ctx).sender_authkey,
            (*ctx).recipient_key,
            sender_pub.as_ptr(),
            recipient_pub.as_ptr(),
        ) == 0
        {
            EC_KEY_free(sender_ephemkey);
            return ret;
        }

        /* Return the senders ephemeral public key in encoded form */
        ptr::copy_nonoverlapping(sender_pub.as_ptr(), enc, sender_publen);
        *enclen = sender_publen;
        *secretlen = (*info).nsecret;
        ret = 1;
        EC_KEY_free(sender_ephemkey);
    }
    ret
}

/// `static int dhkem_decap(PROV_EC_CTX *ctx, unsigned char *secret, size_t *secretlen,
/// const unsigned char *enc, size_t enclen)` — `ec_kem.c.in:728-774`.
///
/// # Safety
/// `ctx` is live with an `info`; `secretlen` is writable when `secret` is not NULL; `enc` is
/// readable for `enclen` bytes.
unsafe fn dhkem_decap(
    ctx: *mut ProvEcCtx,
    secret: *mut u8,
    secretlen: *mut usize,
    enc: *const u8,
    enclen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut recipient_pub: [u8; OSSL_HPKE_MAX_PUBLIC] = [0; OSSL_HPKE_MAX_PUBLIC];
    let mut recipient_publen: usize = 0;

    // SAFETY: `ctx` is live and its `info` is a `'static` table entry.
    unsafe {
        let info = (*ctx).info;
        let encodedpublen = (*info).npk;

        if secret.is_null() {
            *secretlen = (*info).nsecret;
            return 1;
        }

        if *secretlen < (*info).nsecret {
            raise_site_data(
                &err_sites::PROV_EC_KEM_793,
                c"*secretlen too small".as_ptr(),
            );
            return 0;
        }
        if enclen != encodedpublen {
            raise_site_data(
                &err_sites::PROV_EC_KEM_797,
                c"Invalid enc public key".as_ptr(),
            );
            return 0;
        }

        let sender_ephempubkey = eckey_frompub((*ctx).recipient_key, enc, enclen);
        if sender_ephempubkey.is_null() {
            EC_KEY_free(sender_ephempubkey);
            return ret;
        }
        if ecpubkey_todata(
            (*ctx).recipient_key,
            recipient_pub.as_mut_ptr(),
            &mut recipient_publen,
            recipient_pub.len(),
        ) == 0
        {
            EC_KEY_free(sender_ephempubkey);
            return ret;
        }
        if recipient_publen != encodedpublen {
            raise_site_data(
                &err_sites::PROV_EC_KEM_808,
                c"Invalid recipient public key".as_ptr(),
            );
            EC_KEY_free(sender_ephempubkey);
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
            recipient_pub.as_ptr(),
        ) == 0
        {
            EC_KEY_free(sender_ephempubkey);
            return ret;
        }
        *secretlen = (*info).nsecret;
        ret = 1;
        EC_KEY_free(sender_ephempubkey);
    }
    ret
}

/// `static int eckem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
/// unsigned char *secret, size_t *secretlen)` — `ec_kem.c.in:776-788`.
///
/// # Safety
/// The KEM `encapsulate` dispatch contract.
unsafe extern "C" fn eckem_encapsulate(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        match (*ctx).mode as c_int {
            KEM_MODE_DHKEM => dhkem_encap(ctx, out, outlen, secret, secretlen),
            _ => {
                raise_site(&err_sites::PROV_EC_KEM_833);
                -2
            }
        }
    }
}

/// `static int eckem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
/// const unsigned char *in, size_t inlen)` — `ec_kem.c.in:790-802`.
///
/// # Safety
/// The KEM `decapsulate` dispatch contract.
unsafe extern "C" fn eckem_decapsulate(
    vctx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvEcCtx>();

    // SAFETY: `ctx` is the caller's context.
    unsafe {
        match (*ctx).mode as c_int {
            KEM_MODE_DHKEM => dhkem_decap(ctx, out, outlen, in_, inlen),
            _ => {
                raise_site(&err_sites::PROV_EC_KEM_847);
                -2
            }
        }
    }
}

/// `const OSSL_DISPATCH ossl_ec_asym_kem_functions[]` — `ec_kem.c.in:804-822`. Ten slots, the
/// authority's, in its order, shared by the `P-256`/`P-384`/`P-521` rows that `deflt_asym_kem[]`
/// publishes. `src/provider/kem.rs` registers the `EC` row against this table.
pub(crate) static EC_ASYM_KEM_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_NEWCTX,
        function: eckem_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        function: eckem_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE,
        function: eckem_encapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE_INIT,
        function: eckem_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE,
        function: eckem_decapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_FREECTX,
        function: eckem_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SET_CTX_PARAMS,
        function: eckem_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        function: eckem_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
        function: eckem_auth_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
        function: eckem_auth_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::key::{
        ossl_ec_generate_key_dhkem, EC_KEY_free, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
        EC_KEY_new_ex, EC_KEY_set_group,
    };
    use crate::ec::lib::{EC_POINT_cmp, EC_POINT_free, EC_POINT_mul, EC_POINT_new};
    use crate::runtime::obj::NID_X9_62_prime256v1;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// `ossl_ec_dhkem_derive_private` must reproduce RFC 9180 §7.1.3's `DeriveKeyPair` for
    /// DHKEM(P-256, HKDF-SHA256) exactly: the fixed seed `00..1f` derives the private scalar
    /// `c4a9b2ed...`, and its public point encodes as `04cfb264...`.
    ///
    /// Both values are the authority's: `RT-KEYMGMT`'s `eckem.pub_sha256` is the SHA-256 of that
    /// encoding, and an independent RFC 9180 transcription derives the same pair. This is a *value*
    /// test, and it is the one that would have caught the `hpke_labeled_expand` defect: when the
    /// KDF was handed an over-long `info` (the allocation bound `2 + okmlen + prklen + ...` rather
    /// than the bytes written), the derived scalar became `c7508c97...` and the public point
    /// `0456e803...`, both wrong, while the keypair stayed internally consistent.
    #[test]
    fn the_dhkem_derive_private_matches_rfc9180_p256() {
        // The probe's `dhkem-ikm`, bytes 0x00..0x1f.
        let ikm: [u8; 32] = core::array::from_fn(|i| i as u8);

        // SAFETY: every object is created here and freed here; each call's contract is that its
        // arguments are live, which the assertions between them establish before use.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            let key = EC_KEY_new_ex(core::ptr::null_mut(), core::ptr::null());
            assert_eq!(EC_KEY_set_group(key, group), 1);
            assert_eq!(ossl_ec_generate_key_dhkem(key, ikm.as_ptr(), ikm.len()), 1);

            let priv_ = EC_KEY_get0_private_key(key);
            let mut sc = [0u8; 32];
            let n = crate::bn::bignum::BN_bn2bin(priv_, sc.as_mut_ptr()) as usize;
            assert_eq!(n, 32, "the derived scalar is not 32 bytes");
            assert_eq!(
                hex(&sc),
                "c4a9b2ed5595907ca64a481ea78cf93a047ef7153f7d70121b2552b9b6f07cee",
                "the derived private scalar is not RFC 9180's"
            );

            let mut pub_raw = [0u8; 128];
            let publen = EC_POINT_point2oct(
                group,
                EC_KEY_get0_public_key(key),
                POINT_CONVERSION_UNCOMPRESSED,
                pub_raw.as_mut_ptr(),
                pub_raw.len(),
                core::ptr::null_mut(),
            );
            assert_eq!(
                hex(&pub_raw[..publen]),
                "04cfb264d85c7eb276cf60773c461d722e25b64bf345d077c1a8b10c05b8decb45b7ad849cce5e9660102f3f368afd22fe797caf6c3a9cbcbe7657b27bbcddfdb1",
                "the derived public point is not RFC 9180's"
            );

            EC_KEY_free(key);
        }
    }

    /// `ossl_ec_generate_key_dhkem` must leave a key whose public point is *its own* private
    /// scalar times the generator.
    ///
    /// This is the invariant the DHKEM round trip stands on: `dhkem_encap` sends the ephemeral
    /// key's public point and computes `DH(ephemeral_priv, recipient_pub)`, while `dhkem_decap`
    /// reconstructs the point from those bytes and computes `DH(recipient_priv, ephemeral_pub)`.
    /// The two agree only if each stored public point is its private scalar's image. A keygen that
    /// merely derives a *different* scalar would still round-trip; one that stores a mismatched
    /// public point cannot.
    #[test]
    fn the_dhkem_keygen_stores_a_public_key_that_matches_its_private() {
        let ikm = [0x5au8; 32];

        // SAFETY: every object is created here and freed here; each call's contract is that its
        // arguments are live, which the assertions between them establish before use.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            let key = EC_KEY_new_ex(core::ptr::null_mut(), core::ptr::null());
            assert!(!key.is_null());
            assert_eq!(EC_KEY_set_group(key, group), 1);

            assert_eq!(ossl_ec_generate_key_dhkem(key, ikm.as_ptr(), ikm.len()), 1);

            let ctx = BN_CTX_new();
            assert!(!ctx.is_null());
            let expect = EC_POINT_new(group);
            assert!(!expect.is_null());
            assert_eq!(
                EC_POINT_mul(
                    group,
                    expect,
                    EC_KEY_get0_private_key(key),
                    core::ptr::null(),
                    core::ptr::null(),
                    ctx,
                ),
                1
            );
            assert_eq!(
                EC_POINT_cmp(group, expect, EC_KEY_get0_public_key(key), ctx),
                0,
                "the stored public point is not priv*G"
            );

            EC_POINT_free(expect);
            BN_CTX_free(ctx);
            EC_KEY_free(key);
        }
    }

    /// `dhkem_encap` and `dhkem_decap` must derive the same secret for a shared recipient key.
    ///
    /// This is the unit's own round trip, driven directly rather than through `EVP_PKEY`, so a
    /// failure here is the unit's and a pass with the probe failing would be the EVP layer's.
    #[test]
    fn the_dhkem_round_trip_agrees_in_crate() {
        let ikm = [0x5au8; 32];

        // SAFETY: every object is created here and freed here; the KEM calls take pointers to
        // locals of the sizes their contracts require.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            let rkey = EC_KEY_new_ex(core::ptr::null_mut(), core::ptr::null());
            assert_eq!(EC_KEY_set_group(rkey, group), 1);
            assert_eq!(ossl_ec_generate_key_dhkem(rkey, ikm.as_ptr(), ikm.len()), 1);

            let mut ectx = ProvEcCtx {
                recipient_key: core::ptr::null_mut(),
                sender_authkey: core::ptr::null_mut(),
                libctx: core::ptr::null_mut(),
                propq: core::ptr::null_mut(),
                mode: 1,
                op: 0,
                ikm: core::ptr::null_mut(),
                ikmlen: 0,
                kdfname: c"HKDF".as_ptr(),
                info: core::ptr::null(),
            };
            assert_eq!(recipient_key_set(&mut ectx, rkey), 1);

            let mut enc = [0u8; 128];
            let mut enclen = enc.len();
            let mut secret = [0u8; 64];
            let mut secretlen = secret.len();
            assert_eq!(
                dhkem_encap(
                    &mut ectx,
                    enc.as_mut_ptr(),
                    &mut enclen,
                    secret.as_mut_ptr(),
                    &mut secretlen,
                ),
                1
            );

            let mut dctx = ProvEcCtx {
                recipient_key: core::ptr::null_mut(),
                sender_authkey: core::ptr::null_mut(),
                libctx: core::ptr::null_mut(),
                propq: core::ptr::null_mut(),
                mode: 1,
                op: 0,
                ikm: core::ptr::null_mut(),
                ikmlen: 0,
                kdfname: c"HKDF".as_ptr(),
                info: core::ptr::null(),
            };
            assert_eq!(recipient_key_set(&mut dctx, rkey), 1);

            // The peer point `dhkem_decap` rebuilds must be the same point `dhkem_encap` sent:
            // encode it back and require the bytes to be identical.
            let parsed = eckey_frompub(rkey, enc.as_ptr(), enclen);
            assert!(!parsed.is_null(), "the enc point did not parse");
            let mut back = [0u8; 128];
            let mut backlen = 0usize;
            assert_eq!(
                ecpubkey_todata(parsed, back.as_mut_ptr(), &mut backlen, back.len()),
                1
            );
            assert_eq!(
                &back[..backlen],
                &enc[..enclen],
                "the decap peer point differs"
            );
            EC_KEY_free(parsed);

            let mut secret2 = [0u8; 64];
            let mut secretlen2 = secret2.len();
            assert_eq!(
                dhkem_decap(
                    &mut dctx,
                    secret2.as_mut_ptr(),
                    &mut secretlen2,
                    enc.as_ptr(),
                    enclen,
                ),
                1
            );
            assert_eq!(secretlen, secretlen2);
            assert_eq!(&secret[..secretlen], &secret2[..secretlen2]);

            EC_KEY_free(rkey);
        }
    }
}
