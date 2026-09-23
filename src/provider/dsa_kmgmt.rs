//! Phase 8 — `providers/implementations/keymgmt/dsa_kmgmt.c`: the `DSA` keymgmt row.
//!
//! Seven hundred and fifty source lines, twenty-one statics and one dispatch table, publishing the
//! one row `DSA` (`PROV_NAMES_DSA`). The unit is the **last** of the keymgmt rows to land: D387
//! measured the keymgmt group as the gate for 119 of the 122 remaining provider rows, and this is
//! the last one whose only hold was another unit.
//!
//! **What gated it.** `dsa_validate` (`:373-408`) calls the four `ossl_dsa_check_*` validators
//! outside any `#ifdef FIPS_MODULE` guard, and none of them existed in the crate: `crypto/dsa/dsa_check.c`
//! is what D391 lands as `src/dsa/check.rs`, in the same pass as this module. The three helpers
//! `dsa_validate_domparams`/`dsa_validate_public`/`dsa_validate_private` are this unit's own thin
//! wrappers over them, each threading the local `int status` the authority's `*ret` out-parameter
//! fills.
//!
//! ## The `OSSL_FIPS_IND_*` macros are no-ops on this profile and are named, not stubbed
//!
//! `providers/fips/include/fips/fipsindicator.h:152-165` defines the whole family empty for a
//! non-`FIPS_MODULE` build: `OSSL_FIPS_IND_INIT(ctx)` and `OSSL_FIPS_IND_SETTABLE_CTX_PARAM(name)`
//! expand to nothing, `OSSL_FIPS_IND_SET_CTX_PARAM`/`GET_CTX_PARAM` to the literal `1`, and
//! `OSSL_FIPS_IND_GETTABLE_CTX_PARAM()` to nothing. So `struct dsa_gen_ctx` has no indicator
//! member here, `dsa_gen_set_params`'s `if (!OSSL_FIPS_IND_SET_CTX_PARAM(...)) return 0;` is
//! unreachable, `dsa_gen_get_params`'s is a no-op, and the two indicator tables reduce to a single
//! `OSSL_PARAM_END`. `dsa_gen`'s `#ifdef FIPS_MODULE` "DSA signing is not approved in FIPS 140-3"
//! arm is not compiled at all. Each site names the macro it is the empty expansion of.
//!
//! ## `dsa_gen_init` calls `dsa_gen_set_params` even when the allocation failed
//!
//! The authority's `if (!dsa_gen_set_params(gctx, params)) { dsa_gen_cleanup(gctx); gctx = NULL; }`
//! runs **outside** the `OPENSSL_zalloc` success test, so a failed allocation still passes a NULL
//! `gctx` into both calls. `dsa_gen_set_params`'s first line answers 0 for a NULL context and
//! `dsa_gen_cleanup`'s first line returns for one, so the two compose to "stay NULL" — and a
//! transcription that hoisted the parameter call inside the non-NULL arm would be the same
//! observable answer by a different route. It is written the authority's way.
//!
//! ## `dsa_imexport_types` indexes by the sum of two selection weights
//!
//! `dsa_types[0]` is NULL ("none of them"), `[1]` the parameter types, `[2]` the key types and
//! `[3]` their union, and the index is `ALL_PARAMETERS ? 1 : 0` plus `KEYPAIR ? 2 : 0`. The newtype
//! is only there because a `static` of raw pointers needs a `Sync` impl, exactly as `ec_kmgmt.rs`'s
//! `EcTypes` is.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set, BnGencb};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dsa::backend::{ossl_dsa_dup, ossl_dsa_key_fromdata};
use crate::dsa::check::{
    ossl_dsa_check_pairwise, ossl_dsa_check_params, ossl_dsa_check_priv_key, ossl_dsa_check_pub_key,
};
use crate::dsa::gen::ossl_dsa_generate_ffc_parameters;
use crate::dsa::key::DSA_generate_key;
use crate::dsa::object::{
    ossl_dsa_ffc_params_fromdata, ossl_dsa_get0_params, ossl_dsa_new, DSA_bits, DSA_free,
    DSA_get0_g, DSA_get0_key, DSA_get0_p, DSA_get0_priv_key, DSA_get0_pub_key, DSA_security_bits,
};
use crate::dsa::sign::DSA_size;
use crate::dsa::{
    Dsa, DSA_PARAMGEN_TYPE_FIPS_186_2, DSA_PARAMGEN_TYPE_FIPS_186_4, DSA_PARAMGEN_TYPE_FIPS_DEFAULT,
};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey::{OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY};
use crate::evp::pkey_ctx::{
    OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_PCOUNTER,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED,
    OSSL_PKEY_PARAM_FFC_TYPE,
};
use crate::ffc::params::{
    ossl_ffc_params_cmp, ossl_ffc_params_copy, ossl_ffc_params_enable_flags,
    ossl_ffc_params_set_gindex, ossl_ffc_params_set_h, ossl_ffc_params_set_pcounter,
    ossl_ffc_params_set_seed, ossl_ffc_params_todata, ossl_ffc_set_digest,
};
use crate::ffc::{FfcParams, FFC_PARAM_FLAG_VALIDATE_LEGACY};
use crate::param_build_set::ossl_param_build_set_bn;
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_int, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_string, OsslParam, END,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_size_t, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// The constants — `core_names.h` and `core_dispatch.h`.
// ---------------------------------------------------------------------------------------------

/// `DSA_DEFAULT_MD` — `dsa_kmgmt.c:51`.
const DSA_DEFAULT_MD: *const c_char = c"SHA256".as_ptr();

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640-652`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — the union of the two parameter bits.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x03;
/// `DSA_POSSIBLE_SELECTIONS` — `dsa_kmgmt.c:52-53`.
const DSA_POSSIBLE_SELECTIONS: c_int =
    OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

/// `OSSL_PKEY_PARAM_BITS` — `core_names.h:405`.
const P_BITS: *const c_char = c"bits".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h:406`.
const P_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE` — `core_names.h:407`.
const P_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY` — `core_names.h:409`.
const P_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_DEFAULT_DIGEST` — `core_names.h:379`.
const P_DEFAULT_DIGEST: *const c_char = c"default-digest".as_ptr();

/// `OSSL_GEN_PARAM_POTENTIAL` — `core_names.h`, the generated one.
const OSSL_GEN_PARAM_POTENTIAL: *const c_char = c"potential".as_ptr();
/// `OSSL_GEN_PARAM_ITERATION` — the same header.
const OSSL_GEN_PARAM_ITERATION: *const c_char = c"iteration".as_ptr();

/// The unit's own `__FILE__`. `dsa_kmgmt.c` is a plain `.c`, so it carries the source-tree prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/keymgmt/dsa_kmgmt.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `ossl_assert` — `include/internal/assert.h`, the NDEBUG form.
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `ossl_param_is_empty` — `include/internal/common.h`. The same three-line reader the other
/// provider units carry.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn param_is_empty(params: *const OsslParam) -> bool {
    if params.is_null() {
        return true;
    }
    // SAFETY: the first entry of a key-terminated array is readable.
    unsafe { (*params).key.is_null() }
}

/// `OSSL_PARAM_BN(key, NULL, 0)` — `include/openssl/params.h`.
const fn param_bn(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: crate::params::OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: crate::params::OSSL_PARAM_UNMODIFIED,
    }
}

// ---------------------------------------------------------------------------------------------
// `struct dsa_gen_ctx` and the generation type name table.
// ---------------------------------------------------------------------------------------------

/// `struct dsa_gen_ctx` — `dsa_kmgmt.c:55-76`, without the `OSSL_FIPS_IND_DECLARE` member (the
/// macro is empty on this profile).
#[repr(C)]
struct DsaGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `FFC_PARAMS *ffc_params` — borrowed from a template, or NULL.
    ffc_params: *mut FfcParams,
    /// `int selection`.
    selection: c_int,
    /// `size_t pbits`.
    pbits: usize,
    /// `size_t qbits`.
    qbits: usize,
    /// `unsigned char *seed` — owned.
    seed: *mut u8,
    /// `size_t seedlen`.
    seedlen: usize,
    /// `int gindex` — `-1` means "unset".
    gindex: c_int,
    /// `int gen_type` — a `DSA_PARAMGEN_TYPE_*`.
    gen_type: c_int,
    /// `int pcounter` — `-1` means "unset".
    pcounter: c_int,
    /// `int hindex`.
    hindex: c_int,
    /// `char *mdname` — owned.
    mdname: *mut c_char,
    /// `char *mdprops` — owned.
    mdprops: *mut c_char,
    /// `OSSL_CALLBACK *cb` — the generator's progress callback, borrowed.
    cb: Option<OsslCallback>,
    /// `void *cbarg`.
    cbarg: *mut c_void,
}

/// `DSA_GENTYPE_NAME2ID` — `dsa_kmgmt.c:78-81`.
///
/// The names are `'static` C literals, so the struct is safe to share; the marker exists only
/// because `static DSATYPE2ID` holds raw pointers.
#[repr(C)]
struct DsaGentypeName2id {
    /// `const char *name`.
    name: *const c_char,
    /// `int id`.
    id: c_int,
}
// SAFETY: `name` is always the address of a `'static` C string literal and nothing writes either
// field after the static is built.
unsafe impl Sync for DsaGentypeName2id {}

/// `static const DSA_GENTYPE_NAME2ID dsatype2id[]` — `dsa_kmgmt.c:83-91`. This profile's
/// `"default"` row is `DSA_PARAMGEN_TYPE_FIPS_DEFAULT`; the `FIPS_MODULE` arm's is
/// `DSA_PARAMGEN_TYPE_FIPS_186_4` and is not compiled here.
static DSATYPE2ID: [DsaGentypeName2id; 3] = [
    DsaGentypeName2id {
        name: c"default".as_ptr(),
        id: DSA_PARAMGEN_TYPE_FIPS_DEFAULT,
    },
    DsaGentypeName2id {
        name: c"fips186_4".as_ptr(),
        id: DSA_PARAMGEN_TYPE_FIPS_186_4,
    },
    DsaGentypeName2id {
        name: c"fips186_2".as_ptr(),
        id: DSA_PARAMGEN_TYPE_FIPS_186_2,
    },
];

/// `static int dsa_gen_type_name2id(const char *name)` — `dsa_kmgmt.c:93-103`.
///
/// # Safety
/// `name` is a NUL-terminated string.
unsafe fn dsa_gen_type_name2id(name: *const c_char) -> c_int {
    let mut i: usize = 0;

    while i < DSATYPE2ID.len() {
        // SAFETY: `name` is NUL-terminated per the contract and each table entry's `name` is a
        // literal.
        if unsafe { OPENSSL_strcasecmp(DSATYPE2ID[i].name, name) } == 0 {
            return DSATYPE2ID[i].id;
        }
        i += 1;
    }
    -1
}

// ---------------------------------------------------------------------------------------------
// The object path.
// ---------------------------------------------------------------------------------------------

/// `static void *dsa_newdata(void *provctx)` — `dsa_kmgmt.c:122-127`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn dsa_newdata(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context; `ossl_dsa_new` accepts a NULL libctx.
    unsafe { ossl_dsa_new(prov_libctx_of(provctx)) }.cast()
}

/// `static void dsa_freedata(void *keydata)` — `dsa_kmgmt.c:129-132`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn dsa_freedata(keydata: *mut c_void) {
    // SAFETY: the caller's contract; `DSA_free` accepts NULL.
    unsafe { DSA_free(keydata.cast::<Dsa>()) };
}

/// `static int dsa_has(const void *keydata, int selection)` — `dsa_kmgmt.c:134-150`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn dsa_has(keydata: *const c_void, selection: c_int) -> c_int {
    let dsa = keydata.cast::<Dsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dsa.is_null() {
        return 0;
    }
    if (selection & DSA_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* the selection is not missing */
    }

    // SAFETY: `dsa` is non-NULL past the guard.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= c_int::from(!DSA_get0_pub_key(dsa).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= c_int::from(!DSA_get0_priv_key(dsa).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= c_int::from(!DSA_get0_p(dsa).is_null() && !DSA_get0_g(dsa).is_null());
        }
    }
    ok
}

/// `static int dsa_match(const void *keydata1, const void *keydata2, int selection)` —
/// `dsa_kmgmt.c:152-190`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn dsa_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let dsa1 = keydata1.cast::<Dsa>();
    let dsa2 = keydata2.cast::<Dsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: both are the caller's objects; the accessors answer their own `BIGNUM`s.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked: c_int = 0;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                let pa = DSA_get0_pub_key(dsa1);
                let pb = DSA_get0_pub_key(dsa2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                let pa = DSA_get0_priv_key(dsa1);
                let pb = DSA_get0_priv_key(dsa2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            ok &= key_checked;
        }
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            /* The authority casts both away from `const` because `ossl_dsa_get0_params` takes a
             * mutable `DSA *`; the function only takes the member's address. */
            let dsaparams1 = ossl_dsa_get0_params(dsa1.cast_mut());
            let dsaparams2 = ossl_dsa_get0_params(dsa2.cast_mut());

            ok &= ossl_ffc_params_cmp(dsaparams1, dsaparams2, 1);
        }
    }
    ok
}

/// `static int dsa_key_todata(DSA *dsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[],`
/// `int include_private)` — `dsa_kmgmt.c:105-120`.
///
/// # Safety
/// `dsa` is NULL or live; `bld` and `params` are as `ossl_param_build_set_bn` requires.
unsafe fn dsa_key_todata(
    dsa: *mut Dsa,
    bld: *mut crate::params::build::OSSL_PARAM_BLD,
    params: *mut OsslParam,
    include_private: c_int,
) -> c_int {
    let mut priv_: *const BigNum = ptr::null();
    let mut pub_: *const BigNum = ptr::null();

    if dsa.is_null() {
        return 0;
    }

    // SAFETY: `dsa` is non-NULL; the two out-parameters are this frame's.
    unsafe {
        DSA_get0_key(dsa, &mut pub_, &mut priv_);
        if include_private != 0
            && !priv_.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv_) == 0
        {
            return 0;
        }
        if !pub_.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub_) == 0
        {
            return 0;
        }
    }
    1
}

/// `static int dsa_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `dsa_kmgmt.c:192-211`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn dsa_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let dsa = keydata.cast::<Dsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dsa.is_null() {
        return 0;
    }

    if (selection & DSA_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    // SAFETY: `dsa` is non-NULL past the guard; `params` is the caller's array.
    unsafe {
        /* a key without parameters is meaningless */
        ok &= ossl_dsa_ffc_params_fromdata(dsa, params);

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= ossl_dsa_key_fromdata(dsa, params, include_private);
        }
    }
    ok
}

/// `static int dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `dsa_kmgmt.c:213-245`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn dsa_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let dsa = keydata.cast::<Dsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dsa.is_null() {
        return 0;
    }

    if (selection & DSA_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `dsa` is live; `tmpl` is this call's own builder; the values are its own pointers.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 {
            ok &= ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), tmpl, ptr::null_mut());
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= dsa_key_todata(dsa, tmpl, ptr::null_mut(), include_private);
        }

        let params = if ok == 0 {
            ptr::null_mut()
        } else {
            OSSL_PARAM_BLD_to_param(tmpl)
        };
        if ok == 0 || params.is_null() {
            ok = 0;
            /* The authority's `err:` label. */
            OSSL_PARAM_BLD_free(tmpl);
            return ok;
        }

        ok = match param_cb {
            Some(cb) => cb(params, cbarg),
            None => 0,
        };
        OSSL_PARAM_free(params);
        /* The authority's `err:` label. */
        OSSL_PARAM_BLD_free(tmpl);
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// The imexport descriptors.
// ---------------------------------------------------------------------------------------------

/// `DSA_IMEXPORTABLE_PARAMETERS` — `dsa_kmgmt.c:248-256`, written out because a `macro_rules!`
/// expanding to a comma-separated list cannot be spliced into an array literal.
macro_rules! dsa_imexportable_parameters {
    () => {
        [
            param_bn(OSSL_PKEY_PARAM_FFC_P),
            param_bn(OSSL_PKEY_PARAM_FFC_Q),
            param_bn(OSSL_PKEY_PARAM_FFC_G),
            param_bn(OSSL_PKEY_PARAM_FFC_COFACTOR),
            param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
            param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
            param_int(OSSL_PKEY_PARAM_FFC_H),
            param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
            END,
        ]
    };
}

/// `static const OSSL_PARAM dsa_all_types[]` — `dsa_kmgmt.c:260-265`.
static DSA_ALL_TYPES: [OsslParam; 11] = [
    param_bn(OSSL_PKEY_PARAM_FFC_P),
    param_bn(OSSL_PKEY_PARAM_FFC_Q),
    param_bn(OSSL_PKEY_PARAM_FFC_G),
    param_bn(OSSL_PKEY_PARAM_FFC_COFACTOR),
    param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
    param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
    param_int(OSSL_PKEY_PARAM_FFC_H),
    param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `static const OSSL_PARAM dsa_parameter_types[]` — `dsa_kmgmt.c:266-269`.
static DSA_PARAMETER_TYPES: [OsslParam; 9] = dsa_imexportable_parameters!();

/// `static const OSSL_PARAM dsa_key_types[]` — `dsa_kmgmt.c:270-274`.
static DSA_KEY_TYPES: [OsslParam; 3] = [
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `static const OSSL_PARAM *dsa_types[]` — `dsa_kmgmt.c:275-280`, **the sixteen-entry index's
/// four-pointer sibling**: index 0 is "none of them"; the index is the sum of the two selection
/// bits' weights.
///
/// The newtype is only here because a `static` of raw pointers needs a `Sync` impl; the four
/// entries are `'static` table addresses and nothing writes it.
struct DsaTypes([*const OsslParam; 4]);
// SAFETY: the array holds `'static` addresses of `'static` const tables and has no interior
// mutability.
unsafe impl Sync for DsaTypes {}

/// `dsa_types[]`'s storage.
static DSA_TYPES: DsaTypes = DsaTypes([
    ptr::null(),
    DSA_PARAMETER_TYPES.as_ptr(),
    DSA_KEY_TYPES.as_ptr(),
    DSA_ALL_TYPES.as_ptr(),
]);

/// `static const OSSL_PARAM *dsa_imexport_types(int selection)` — `dsa_kmgmt.c:282-291`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn dsa_imexport_types(selection: c_int) -> *const OsslParam {
    let mut type_select: usize = 0;

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 {
        type_select += 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        type_select += 2;
    }
    DSA_TYPES.0[type_select]
}

/// `static const OSSL_PARAM *dsa_import_types(int selection)` — `dsa_kmgmt.c:293-296`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn dsa_import_types(selection: c_int) -> *const OsslParam {
    // SAFETY: a forwarding call with no pointer argument of its own.
    unsafe { dsa_imexport_types(selection) }
}

/// `static const OSSL_PARAM *dsa_export_types(int selection)` — `dsa_kmgmt.c:298-301`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn dsa_export_types(selection: c_int) -> *const OsslParam {
    // SAFETY: a forwarding call with no pointer argument of its own.
    unsafe { dsa_imexport_types(selection) }
}

// ---------------------------------------------------------------------------------------------
// `dsa_get_params` and its descriptor array.
// ---------------------------------------------------------------------------------------------

/// `static ossl_inline int dsa_get_params(void *key, OSSL_PARAM params[])` — `dsa_kmgmt.c:303-328`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn dsa_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    let dsa = key.cast::<Dsa>();

    // SAFETY: `dsa` is the caller's object and `params` is the caller's array.
    unsafe {
        let mut p = OSSL_PARAM_locate(params, P_BITS);
        if !p.is_null() && OSSL_PARAM_set_int(p, DSA_bits(dsa)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_BITS);
        if !p.is_null() && OSSL_PARAM_set_int(p, DSA_security_bits(dsa)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_MAX_SIZE);
        if !p.is_null() && OSSL_PARAM_set_int(p, DSA_size(dsa)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_DEFAULT_DIGEST);
        if !p.is_null() && OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_CATEGORY);
        if !p.is_null() && OSSL_PARAM_set_int(p, 0) == 0 {
            return 0;
        }
        c_int::from(
            ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), ptr::null_mut(), params) != 0
                && dsa_key_todata(dsa, ptr::null_mut(), params, 1) != 0,
        )
    }
}

/// `static const OSSL_PARAM dsa_params[]` — `dsa_kmgmt.c:330-340`.
static DSA_PARAMS: [OsslParam; 16] = [
    param_int(P_BITS),
    param_int(P_SECURITY_BITS),
    param_int(P_MAX_SIZE),
    param_int(P_SECURITY_CATEGORY),
    param_utf8_string(P_DEFAULT_DIGEST),
    param_bn(OSSL_PKEY_PARAM_FFC_P),
    param_bn(OSSL_PKEY_PARAM_FFC_Q),
    param_bn(OSSL_PKEY_PARAM_FFC_G),
    param_bn(OSSL_PKEY_PARAM_FFC_COFACTOR),
    param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
    param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
    param_int(OSSL_PKEY_PARAM_FFC_H),
    param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `static const OSSL_PARAM *dsa_gettable_params(void *provctx)` — `dsa_kmgmt.c:342-345`.
///
/// # Safety
/// The keymgmt `gettable_params` dispatch contract.
unsafe extern "C" fn dsa_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    DSA_PARAMS.as_ptr()
}

// ---------------------------------------------------------------------------------------------
// `dsa_validate` — the thin wrappers over `crypto/dsa/dsa_check.c`.
// ---------------------------------------------------------------------------------------------

/// `static int dsa_validate_domparams(const DSA *dsa, int checktype)` — `dsa_kmgmt.c:347-352`.
///
/// # Safety
/// `dsa` is live.
unsafe fn dsa_validate_domparams(dsa: *const Dsa, checktype: c_int) -> c_int {
    let mut status: c_int = 0;

    // SAFETY: `dsa` is live and `status` is this frame's.
    unsafe { ossl_dsa_check_params(dsa, checktype, &mut status) }
}

/// `static int dsa_validate_public(const DSA *dsa)` — `dsa_kmgmt.c:354-365`.
///
/// # Safety
/// `dsa` is live.
unsafe fn dsa_validate_public(dsa: *const Dsa) -> c_int {
    let mut status: c_int = 0;
    let mut pub_key: *const BigNum = ptr::null();

    // SAFETY: `dsa` is live and `pub_key` is this frame's.
    unsafe {
        DSA_get0_key(dsa, &mut pub_key, ptr::null_mut());
        if pub_key.is_null() {
            return 0;
        }
        ossl_dsa_check_pub_key(dsa, pub_key, &mut status)
    }
}

/// `static int dsa_validate_private(const DSA *dsa)` — `dsa_kmgmt.c:367-378`.
///
/// # Safety
/// `dsa` is live.
unsafe fn dsa_validate_private(dsa: *const Dsa) -> c_int {
    let mut status: c_int = 0;
    let mut priv_key: *const BigNum = ptr::null();

    // SAFETY: `dsa` is live and `priv_key` is this frame's.
    unsafe {
        DSA_get0_key(dsa, ptr::null_mut(), &mut priv_key);
        if priv_key.is_null() {
            return 0;
        }
        ossl_dsa_check_priv_key(dsa, priv_key, &mut status)
    }
}

/// `static int dsa_validate(const void *keydata, int selection, int checktype)` —
/// `dsa_kmgmt.c:380-408`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn dsa_validate(
    keydata: *const c_void,
    selection: c_int,
    checktype: c_int,
) -> c_int {
    let dsa = keydata.cast::<Dsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    if (selection & DSA_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }

    // SAFETY: `dsa` is the caller's object.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= dsa_validate_domparams(dsa, checktype);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= dsa_validate_public(dsa);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= dsa_validate_private(dsa);
        }

        /* If the whole key is selected, we do a pairwise validation */
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            ok &= ossl_dsa_check_pairwise(dsa);
        }
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// The generation path.
// ---------------------------------------------------------------------------------------------

/// `static void *dsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `dsa_kmgmt.c:410-438`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn dsa_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    let libctx = unsafe { prov_libctx_of(provctx) };

    if is_running() == 0 || (selection & DSA_POSSIBLE_SELECTIONS) == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let mut gctx = CRYPTO_zalloc(core::mem::size_of::<DsaGenCtx>(), FILE, 416).cast::<DsaGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation.
        unsafe {
            (*gctx).selection = selection;
            (*gctx).libctx = libctx;
            (*gctx).pbits = 2048;
            (*gctx).qbits = 224;
            (*gctx).gen_type = DSA_PARAMGEN_TYPE_FIPS_DEFAULT;
            (*gctx).gindex = -1;
            (*gctx).pcounter = -1;
            (*gctx).hindex = 0;
            /* `OSSL_FIPS_IND_INIT(gctx)` is empty on this profile. */
        }
    }
    // SAFETY: `gctx` is NULL or this call's own context; `params` is the caller's array. The
    // authority calls this outside the allocation test, which is what makes a failed allocation
    // compose with the cleanup below rather than skip it.
    if unsafe { dsa_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is NULL or this call's own allocation, not yet published.
        unsafe { dsa_gen_cleanup(gctx.cast()) };
        gctx = ptr::null_mut();
    }
    gctx.cast()
}

/// `static int dsa_gen_set_template(void *genctx, void *templ)` — `dsa_kmgmt.c:440-449`.
///
/// # Safety
/// The keymgmt `gen_set_template` dispatch contract.
unsafe extern "C" fn dsa_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int {
    let gctx = genctx.cast::<DsaGenCtx>();
    let dsa = templ.cast::<Dsa>();

    if is_running() == 0 || gctx.is_null() || dsa.is_null() {
        return 0;
    }
    // SAFETY: both are non-NULL past the guard.
    unsafe { (*gctx).ffc_params = ossl_dsa_get0_params(dsa) };
    1
}

/// `static int dsa_set_gen_seed(struct dsa_gen_ctx *gctx, unsigned char *seed,`
/// `size_t seedlen)` — `dsa_kmgmt.c:451-464`.
///
/// # Safety
/// `gctx` is live; `seed` is NULL or readable for `seedlen` bytes.
unsafe fn dsa_set_gen_seed(gctx: *mut DsaGenCtx, seed: *mut u8, seedlen: usize) -> c_int {
    // SAFETY: `gctx` is live per the contract.
    unsafe {
        CRYPTO_clear_free((*gctx).seed.cast(), (*gctx).seedlen, FILE, 454);
        (*gctx).seed = ptr::null_mut();
        (*gctx).seedlen = 0;
        if !seed.is_null() && seedlen > 0 {
            (*gctx).seed = CRYPTO_memdup(seed.cast(), seedlen, FILE, 458).cast::<u8>();
            if (*gctx).seed.is_null() {
                return 0;
            }
            (*gctx).seedlen = seedlen;
        }
    }
    1
}

/// `static int dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `dsa_kmgmt.c:466-532`.
///
/// `OSSL_FIPS_IND_SET_CTX_PARAM(gctx, OSSL_FIPS_IND_SETTABLE0, params,
/// OSSL_PKEY_PARAM_FIPS_SIGN_CHECK)` is the literal `1` on this profile, so the authority's
/// `if (!...) return 0;` is not reachable and is not written.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn dsa_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<DsaGenCtx>();

    if gctx.is_null() {
        return 0;
    }
    // SAFETY: `params` is NULL or key-terminated per the contract.
    if unsafe { param_is_empty(params) } {
        return 1;
    }

    // SAFETY: `gctx` is non-NULL past the guard; `params` is the caller's array.
    unsafe {
        let mut p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                raise_site(&err_sites::PROV_DSA_KMGMT_486);
                return 0;
            }
            let gen_type = dsa_gen_type_name2id((*p).data.cast::<c_char>());
            if gen_type == -1 {
                raise_site(&err_sites::PROV_DSA_KMGMT_486);
                return 0;
            }

            /*
             * Only assign context gen_type if it was set by dsa_gen_type_name2id
             * must be in range:
             * DSA_PARAMGEN_TYPE_FIPS_186_4 <= gen_type <= DSA_PARAMGEN_TYPE_FIPS_DEFAULT
             */
            (*gctx).gen_type = gen_type;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
        if !p.is_null() && OSSL_PARAM_get_int(p, &raw mut (*gctx).gindex) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
        if !p.is_null() && OSSL_PARAM_get_int(p, &raw mut (*gctx).pcounter) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
        if !p.is_null() && OSSL_PARAM_get_int(p, &raw mut (*gctx).hindex) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
        if !p.is_null()
            && ((*p).data_type != OSSL_PARAM_OCTET_STRING
                || dsa_set_gen_seed(gctx, (*p).data.cast::<u8>(), (*p).data_size) == 0)
        {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, &raw mut (*gctx).pbits) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, &raw mut (*gctx).qbits) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).mdname.cast(), FILE, 513);
            (*gctx).mdname = CRYPTO_strdup((*p).data.cast::<c_char>(), FILE, 514);
            if (*gctx).mdname.is_null() {
                return 0;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).mdprops.cast(), FILE, 523);
            (*gctx).mdprops = CRYPTO_strdup((*p).data.cast::<c_char>(), FILE, 524);
            if (*gctx).mdprops.is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *dsa_gen_settable_params(void *genctx, void *provctx)`'s
/// function-local array — `dsa_kmgmt.c:534-546`. `OSSL_FIPS_IND_SETTABLE_CTX_PARAM` is empty on
/// this profile, so the array is the nine entries the authority writes plus the terminator.
static DSA_GEN_SETTABLE: [OsslParam; 10] = [
    param_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE),
    param_size_t(OSSL_PKEY_PARAM_FFC_PBITS),
    param_size_t(OSSL_PKEY_PARAM_FFC_QBITS),
    param_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST),
    param_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS),
    param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
    param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
    param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
    param_int(OSSL_PKEY_PARAM_FFC_H),
    END,
];

/// `static const OSSL_PARAM *dsa_gen_settable_params(void *genctx, void *provctx)` —
/// `dsa_kmgmt.c:534-547`.
///
/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn dsa_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DSA_GEN_SETTABLE.as_ptr()
}

/// `dsa_gen_gettable_params`'s function-local array — `dsa_kmgmt.c:567-573`. Its only content is
/// `OSSL_FIPS_IND_GETTABLE_CTX_PARAM()`, which is empty on this profile, so the table is the
/// terminator alone.
static DSA_GEN_GETTABLE: [OsslParam; 1] = [END];

/// `static const OSSL_PARAM *dsa_gen_gettable_params(void *ctx, void *provctx)` —
/// `dsa_kmgmt.c:566-574`.
///
/// # Safety
/// The keymgmt `gen_gettable_params` dispatch contract.
unsafe extern "C" fn dsa_gen_gettable_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DSA_GEN_GETTABLE.as_ptr()
}

/// `static int dsa_gen_get_params(void *genctx, OSSL_PARAM *params)` — `dsa_kmgmt.c:557-565`.
///
/// # Safety
/// The keymgmt `gen_get_params` dispatch contract.
unsafe extern "C" fn dsa_gen_get_params(genctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let gctx = genctx.cast::<DsaGenCtx>();

    if gctx.is_null() {
        return 0;
    }
    // SAFETY: `params` is NULL or key-terminated per the contract.
    if unsafe { param_is_empty(params) } {
        return 1;
    }
    /* `OSSL_FIPS_IND_GET_CTX_PARAM(gctx, params)` is the literal 1 on this profile. */
    1
}

/// `static int dsa_gencb(int p, int n, BN_GENCB *cb)` — `dsa_kmgmt.c:576-585`.
///
/// # Safety
/// The `BN_GENCB` callback contract: `cb` carries the generator context this unit set with
/// `BN_GENCB_set`.
unsafe extern "C" fn dsa_gencb(p: c_int, n: c_int, cb: *mut BnGencb) -> c_int {
    // SAFETY: `cb` is live per the contract.
    let gctx = unsafe { BN_GENCB_get_arg(cb) }.cast::<DsaGenCtx>();

    let mut p = p;
    let mut n = n;
    let mut params: [OsslParam; 3] = [END, END, END];

    // SAFETY: `params` is this frame's array and the two pointers are its own locals.
    unsafe {
        params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &raw mut p);
        params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &raw mut n);
    }
    // SAFETY: the callback is read off this frame's live context and is the caller's, set in
    // `dsa_gen`.
    let cb = unsafe { (*gctx).cb };
    match cb {
        // SAFETY: the callback and its argument are the caller's, set in `dsa_gen`.
        Some(callback) => unsafe { callback(params.as_ptr(), (*gctx).cbarg) },
        None => 0,
    }
}

/// `static void *dsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` — `dsa_kmgmt.c:587-697`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
// The authority nests the parameter-generation block inside the domain-parameters selection test;
// collapsing the two `if`s would be the same control flow written less like the C.
#[allow(clippy::collapsible_if)]
unsafe extern "C" fn dsa_gen(
    genctx: *mut c_void,
    osslcb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<DsaGenCtx>();

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is live.
    let mut dsa = unsafe { ossl_dsa_new((*gctx).libctx) };
    let mut gencb: *mut BnGencb = ptr::null_mut();
    let mut ret: c_int = 0;

    if dsa.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is live per the contract.
    unsafe {
        if (*gctx).gen_type == DSA_PARAMGEN_TYPE_FIPS_DEFAULT {
            (*gctx).gen_type = if (*gctx).pbits >= 2048 {
                DSA_PARAMGEN_TYPE_FIPS_186_4
            } else {
                DSA_PARAMGEN_TYPE_FIPS_186_2
            };
        }
    }

    /*
     * Do a bounds check on context gen_type. Must be in range:
     * DSA_PARAMGEN_TYPE_FIPS_186_4 <= gen_type <= DSA_PARAMGEN_TYPE_FIPS_DEFAULT
     * Noted here as this needs to be adjusted if a new type is
     * added.
     */
    // SAFETY: `gctx` is live.
    let in_range = unsafe {
        ossl_assert(
            (*gctx).gen_type >= DSA_PARAMGEN_TYPE_FIPS_186_4
                && (*gctx).gen_type <= DSA_PARAMGEN_TYPE_FIPS_DEFAULT,
        )
    };
    if in_range == 0 {
        let mut msg = [0 as c_char; 64];
        // SAFETY: `msg` is a 64-byte buffer and the format is the authority's.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"gen_type set to unsupported value %d".as_ptr(),
                (*gctx).gen_type,
            );
        }
        // SAFETY: a compile-time-constant site; the message is NUL-terminated.
        unsafe { raise_site_data(&err_sites::PROV_DSA_KMGMT_633, msg.as_ptr()) };
        /* The authority's `end:` label. */
        // SAFETY: both are this call's own, NULL or live.
        unsafe {
            DSA_free(dsa);
            BN_GENCB_free(gencb);
        }
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is this call's context; `osslcb`/`cbarg` are the caller's.
    unsafe {
        (*gctx).cb = osslcb;
        (*gctx).cbarg = cbarg;
    }
    // SAFETY: a fresh callback this call owns; `BN_GENCB_set` below fills it in.
    gencb = unsafe { BN_GENCB_new() };
    if !gencb.is_null() {
        // SAFETY: `gencb` is this call's own and `gctx` outlives the generation below.
        unsafe { BN_GENCB_set(gencb, Some(dsa_gencb), genctx) };
    }

    'end: {
        // SAFETY: `dsa` is this call's own object; `gctx` is the caller's context and every
        // pointer read below belongs to one of the two.
        let ffc = unsafe { ossl_dsa_get0_params(dsa) };

        // SAFETY: `ffc` is `dsa`'s own embedded parameter block, `gctx` is the caller's context
        // and `gencb` is this call's own callback.
        unsafe {
            /* Copy the template value if one was passed */
            if !(*gctx).ffc_params.is_null() && ossl_ffc_params_copy(ffc, (*gctx).ffc_params) == 0 {
                break 'end;
            }

            if !(*gctx).seed.is_null()
                && ossl_ffc_params_set_seed(ffc, (*gctx).seed, (*gctx).seedlen) == 0
            {
                break 'end;
            }
            if (*gctx).gindex != -1 {
                ossl_ffc_params_set_gindex(ffc, (*gctx).gindex);
                if (*gctx).pcounter != -1 {
                    ossl_ffc_params_set_pcounter(ffc, (*gctx).pcounter);
                }
            } else if (*gctx).hindex != 0 {
                ossl_ffc_params_set_h(ffc, (*gctx).hindex);
            }
            if !(*gctx).mdname.is_null() {
                ossl_ffc_set_digest(ffc, (*gctx).mdname, (*gctx).mdprops);
            }

            if ((*gctx).selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
                if ossl_dsa_generate_ffc_parameters(
                    dsa,
                    (*gctx).gen_type,
                    (*gctx).pbits as c_int,
                    (*gctx).qbits as c_int,
                    gencb,
                ) <= 0
                {
                    break 'end;
                }
            }
            ossl_ffc_params_enable_flags(
                ffc,
                FFC_PARAM_FLAG_VALIDATE_LEGACY,
                c_int::from((*gctx).gen_type == DSA_PARAMGEN_TYPE_FIPS_186_2),
            );
            if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
                if (*ffc).p.is_null() || (*ffc).q.is_null() || (*ffc).g.is_null() {
                    break 'end;
                }
                if DSA_generate_key(dsa) <= 0 {
                    break 'end;
                }
            }
            ret = 1;
        }
    }
    /* The authority's `end:` label. */
    if ret <= 0 {
        // SAFETY: `dsa` is this call's own object.
        unsafe { DSA_free(dsa) };
        dsa = ptr::null_mut();
    }
    // SAFETY: `gencb` is this call's own callback, NULL or live.
    unsafe { BN_GENCB_free(gencb) };
    dsa.cast()
}

/// `static void dsa_gen_cleanup(void *genctx)` — `dsa_kmgmt.c:699-709`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn dsa_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<DsaGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is this call's own context and every member is its own allocation.
    unsafe {
        CRYPTO_free((*gctx).mdname.cast(), FILE, 706);
        CRYPTO_free((*gctx).mdprops.cast(), FILE, 707);
        CRYPTO_clear_free((*gctx).seed.cast(), (*gctx).seedlen, FILE, 708);
        CRYPTO_free(gctx.cast(), FILE, 709);
    }
}

/// `static void *dsa_load(const void *reference, size_t reference_sz)` — `dsa_kmgmt.c:711-723`.
///
/// **The reference is detached, not copied**, and unlike `rsa_kmgmt.c`'s `common_load` there is no
/// sub-type to check.
///
/// # Safety
/// `reference` is readable for `reference_sz` bytes and, when the size matches, holds a live
/// `*mut Dsa` slot this call may clear.
unsafe extern "C" fn dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut Dsa>() {
        // SAFETY: `reference` is readable for the object's size per the contract.
        let dsa = unsafe {
            /* The contents of the reference is the address to our object */
            let dsa = *(reference as *const *mut Dsa);
            /* We grabbed, so we detach it */
            *(reference as *mut *mut Dsa) = ptr::null_mut();
            dsa
        };
        return dsa.cast();
    }
    ptr::null_mut()
}

/// `static void *dsa_dup(const void *keydata_from, int selection)` — `dsa_kmgmt.c:725-730`.
///
/// The keypair bit is **not** required here, unlike `rsa_dup`: the authority's DSA row duplicates
/// whatever selection it is given.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn dsa_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract, forwarded.
        return unsafe { ossl_dsa_dup(keydata_from.cast::<Dsa>(), selection) }.cast();
    }
    ptr::null_mut()
}

// ---------------------------------------------------------------------------------------------
// The dispatch table.
// ---------------------------------------------------------------------------------------------

/// `const OSSL_DISPATCH ossl_dsa_keymgmt_functions[]` — `dsa_kmgmt.c:732-758`. It is the only
/// landed keymgmt table with the `GEN_SET_TEMPLATE`/`GEN_GET_PARAMS`/`GEN_GETTABLE_PARAMS` trio,
/// which the DSA row needs because a DSA parameter set can be generated from another key's.
pub(crate) static DSA_KEYMGMT_FUNCTIONS: [OsslDispatch; 22] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: dsa_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: dsa_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        function: dsa_gen_set_template as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: dsa_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: dsa_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
        function: dsa_gen_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
        function: dsa_gen_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: dsa_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: dsa_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: dsa_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: dsa_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: dsa_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: dsa_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: dsa_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: dsa_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: dsa_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: dsa_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: dsa_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: dsa_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: dsa_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: dsa_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
