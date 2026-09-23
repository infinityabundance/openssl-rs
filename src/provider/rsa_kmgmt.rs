//! Phase 8 — `providers/implementations/keymgmt/rsa_kmgmt.c`: the `RSA` and `RSA-PSS` keymgmt rows.
//!
//! Seven hundred and forty-two source lines, twenty-four statics and two dispatch tables. The
//! unit publishes two rows — `RSA` (`PROV_NAMES_RSA`) and `RSA-PSS` (`PROV_NAMES_RSA_PSS`) — and
//! the difference between them is where `RSA_FLAG_TYPE_RSA` and `RSA_FLAG_TYPE_RSASSAPSS` are
//! stamped into the object's `flags`: `rsa_newdata`/`rsapss_newdata` on the object path,
//! `gen_init`'s `rsa_type` argument and `rsa_gen`'s re-stamp on the generation path, and
//! `common_load`'s `expected_rsa_type` on the load path. Everything else is shared.
//!
//! **This unit is what `crypto/rsa/rsa_chk.c`'s `ossl_rsa_validate_public`/`_private`/`_pairwise`
//! waited on.** `rsa_validate` (`:390-410`) calls all three **outside any `#ifdef FIPS_MODULE`
//! guard**, so D327's withholding of `crypto/rsa/rsa_sp800_56b_check.c` -- which nothing on the
//! generate path reached -- was the only hold on the two rows. D391 landed that unit whole (in
//! `src/rsa/check.rs`, moving the three helpers D326 had left in `src/rsa/sp800.rs`) and the three
//! delegating validators beside `rsa_validate_keypair_multiprime` in `src/rsa/mod.rs`, in the same
//! pass as this module, so the rows and what gates them arrive together.
//!
//! ## What is not transcribed, and why
//!
//! * **The `FIPS_MODULE && !OPENSSL_NO_ACVP_TESTS` arms.** `struct rsa_gen_ctx`'s
//!   `acvp_test_params` member, the three `ossl_rsa_acvp_test_*` calls and `rsa_cleanup`'s free are
//!   all inside that double guard, which this profile does not define. They are named at each site
//!   rather than stubbed, as `src/rsa/sp800.rs`'s `RSA_ACVP_TEST` note does for the object's own
//!   member.
//! * **`FIPS_MODULE`'s `RSA_KEY_MP_TYPES`.** The module arm declares five multi-prime descriptors
//!   (`FACTOR1`, `FACTOR2`, `EXPONENT1`, `EXPONENT2`, `COEFFICIENT1`) because "in fips mode there
//!   are no multi-primes"; the `#else` arm below -- ten factors, ten exponents, nine coefficients --
//!   is this build's, and the module arm is not compiled.
//! * **`ossl_rsa_pss_params_30_set_defaults`/`_is_default`** are `crypto/rsa/rsa_backend.c`'s and
//!   the `pss_defaults_set` flag this unit threads through `pss_params_fromdata` is what tracks
//!   whether they ran; the unit never calls either directly.
//!
//! ## `rsa_gen_settable_params` returns a `static` that is written once
//!
//! The authority's two settable arrays are `static OSSL_PARAM settable[]` inside the function --
//! function-local statics, so the address a caller gets is stable across calls and the second call
//! sees the first call's writes. The crate publishes them as module `static`s for the same reason
//! `ec_kmgmt.rs` does: a `static` in a function would be the same object.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_clear_free, BN_free, BN_new, BN_set_word, BigNum};
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set, BnGencb};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey_ctx::{
    OSSL_PKEY_PARAM_RSA_BITS, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT3, OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT5, OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT7, OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT9, OSSL_PKEY_PARAM_RSA_D, OSSL_PKEY_PARAM_RSA_DIGEST,
    OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT10, OSSL_PKEY_PARAM_RSA_EXPONENT2, OSSL_PKEY_PARAM_RSA_EXPONENT3,
    OSSL_PKEY_PARAM_RSA_EXPONENT4, OSSL_PKEY_PARAM_RSA_EXPONENT5, OSSL_PKEY_PARAM_RSA_EXPONENT6,
    OSSL_PKEY_PARAM_RSA_EXPONENT7, OSSL_PKEY_PARAM_RSA_EXPONENT8, OSSL_PKEY_PARAM_RSA_EXPONENT9,
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR10, OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_FACTOR3, OSSL_PKEY_PARAM_RSA_FACTOR4, OSSL_PKEY_PARAM_RSA_FACTOR5,
    OSSL_PKEY_PARAM_RSA_FACTOR6, OSSL_PKEY_PARAM_RSA_FACTOR7, OSSL_PKEY_PARAM_RSA_FACTOR8,
    OSSL_PKEY_PARAM_RSA_FACTOR9, OSSL_PKEY_PARAM_RSA_MASKGENFUNC, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
    OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
};
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_BN, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::cipher::{param_int, param_size_t, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::rsa::backend::{
    ossl_rsa_dup, ossl_rsa_fromdata, ossl_rsa_pss_params_30_fromdata,
    ossl_rsa_pss_params_30_todata, ossl_rsa_todata,
};
use crate::rsa::gen::{RSA_generate_multi_prime_key, RSA_DEFAULT_PRIME_NUM, RSA_MIN_MODULUS_BITS};
use crate::rsa::object::{
    ossl_rsa_get0_libctx, ossl_rsa_get0_pss_params_30, ossl_rsa_new_with_ctx, RSA_bits,
    RSA_clear_flags, RSA_free, RSA_get0_d, RSA_get0_e, RSA_get0_n, RSA_security_bits,
    RSA_set_flags, RSA_size, RSA_test_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA,
    RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::{
    ossl_rsa_pss_params_30_copy, ossl_rsa_pss_params_30_hashalg,
    ossl_rsa_pss_params_30_is_unrestricted,
};
use crate::rsa::schemes::ossl_rsa_oaeppss_nid2name;
use crate::rsa::{
    ossl_rsa_validate_pairwise, ossl_rsa_validate_private, ossl_rsa_validate_public, Rsa,
    RsaPssParams30,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// The constants — `core_names.h`, `core_dispatch.h` and `rsa.h`.
// ---------------------------------------------------------------------------------------------

/// `RSA_DEFAULT_MD` — `rsa_kmgmt.c:54`.
const RSA_DEFAULT_MD: *const c_char = c"SHA256".as_ptr();

/// `RSA_F4` — `include/openssl/rsa.h:43`, the exponent `gen_init` starts its generator with.
const RSA_F4: u64 = 0x1_0001;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640-652`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x03;
/// `RSA_POSSIBLE_SELECTIONS` — `rsa_kmgmt.c:55-56`.
const RSA_POSSIBLE_SELECTIONS: c_int =
    OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

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
/// `OSSL_PKEY_PARAM_MANDATORY_DIGEST` — `core_names.h:381`.
const P_MANDATORY_DIGEST: *const c_char = c"mandatory-digest".as_ptr();

/// `OSSL_GEN_PARAM_POTENTIAL` — `core_names.h`, the generated one.
const OSSL_GEN_PARAM_POTENTIAL: *const c_char = c"potential".as_ptr();
/// `OSSL_GEN_PARAM_ITERATION` — the same header.
const OSSL_GEN_PARAM_ITERATION: *const c_char = c"iteration".as_ptr();

/// The unit's own `__FILE__`. `rsa_kmgmt.c` is a plain `.c`, so it carries the source-tree prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/keymgmt/rsa_kmgmt.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
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
// The two `PROV_NAMES_*_keymgmt_functions` rows' shared context.
// ---------------------------------------------------------------------------------------------

/// `struct rsa_gen_ctx` — `rsa_kmgmt.c:425-445`, without the `FIPS_MODULE && !OPENSSL_NO_ACVP_TESTS`
/// `acvp_test_params` member.
#[repr(C)]
struct RsaGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `const char *propq` — borrowed, never set by this unit.
    propq: *const c_char,
    /// `int rsa_type` — `RSA_FLAG_TYPE_RSA` or `RSA_FLAG_TYPE_RSASSAPSS`.
    rsa_type: c_int,
    /// `size_t nbits`.
    nbits: usize,
    /// `BIGNUM *pub_exp` — owned.
    pub_exp: *mut BigNum,
    /// `size_t primes`.
    primes: usize,
    /// `RSA_PSS_PARAMS_30 pss_params`.
    pss_params: RsaPssParams30,
    /// `int pss_defaults_set`.
    pss_defaults_set: c_int,
    /// `OSSL_CALLBACK *cb` — the generator's progress callback, borrowed.
    cb: Option<OsslCallback>,
    /// `void *cbarg`.
    cbarg: *mut c_void,
}

/// `static int pss_params_fromdata(RSA_PSS_PARAMS_30 *pss_params, int *defaults_set,`
/// `const OSSL_PARAM params[], int rsa_type, OSSL_LIB_CTX *libctx)` — `rsa_kmgmt.c:60-74`.
///
/// # Safety
/// `pss_params` and `defaults_set` are live; `params` is NULL or key-terminated.
unsafe fn pss_params_fromdata(
    pss_params: *mut RsaPssParams30,
    defaults_set: *mut c_int,
    params: *const OsslParam,
    rsa_type: c_int,
    libctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if ossl_rsa_pss_params_30_fromdata(pss_params, defaults_set, params, libctx) == 0 {
            return 0;
        }

        /* If not a PSS type RSA, sending us PSS parameters is wrong */
        if rsa_type != RSA_FLAG_TYPE_RSASSAPSS
            && ossl_rsa_pss_params_30_is_unrestricted(pss_params) == 0
        {
            return 0;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The object path — `rsa_newdata`, `rsapss_newdata`, `rsa_freedata`, `rsa_has`, `rsa_match`.
// ---------------------------------------------------------------------------------------------

/// `static void *rsa_newdata(void *provctx)` — `rsa_kmgmt.c:76-90`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn rsa_newdata(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    let libctx = unsafe { prov_libctx_of(provctx) };

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `libctx` is NULL or live.
    let rsa = unsafe { ossl_rsa_new_with_ctx(libctx) };
    if !rsa.is_null() {
        // SAFETY: `rsa` is this call's own object.
        unsafe {
            RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
            RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
        }
    }
    rsa.cast()
}

/// `static void *rsapss_newdata(void *provctx)` — `rsa_kmgmt.c:92-106`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn rsapss_newdata(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    let libctx = unsafe { prov_libctx_of(provctx) };

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `libctx` is NULL or live.
    let rsa = unsafe { ossl_rsa_new_with_ctx(libctx) };
    if !rsa.is_null() {
        // SAFETY: `rsa` is this call's own object.
        unsafe {
            RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
            RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
        }
    }
    rsa.cast()
}

/// `static void rsa_freedata(void *keydata)` — `rsa_kmgmt.c:108-111`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn rsa_freedata(keydata: *mut c_void) {
    // SAFETY: the caller's contract; `RSA_free` accepts NULL.
    unsafe { RSA_free(keydata.cast::<Rsa>()) };
}

/// `static int rsa_has(const void *keydata, int selection)` — `rsa_kmgmt.c:113-128`.
///
/// The `RSA_POSSIBLE_SELECTIONS` test answers **1** rather than 0: a selection this key cannot
/// describe is not a selection it is missing.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn rsa_has(keydata: *const c_void, selection: c_int) -> c_int {
    let rsa = keydata.cast::<Rsa>();
    let mut ok: c_int = 1;

    if rsa.is_null() || is_running() == 0 {
        return 0;
    }
    if (selection & RSA_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* the selection is not missing */
    }

    // SAFETY: `rsa` is non-NULL past the guard.
    unsafe {
        /* OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty */
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            ok &= c_int::from(!RSA_get0_n(rsa).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= c_int::from(!RSA_get0_e(rsa).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= c_int::from(!RSA_get0_d(rsa).is_null());
        }
    }
    ok
}

/// `static int rsa_match(const void *keydata1, const void *keydata2, int selection)` —
/// `rsa_kmgmt.c:130-166`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn rsa_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let rsa1 = keydata1.cast::<Rsa>();
    let rsa2 = keydata2.cast::<Rsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: both pointers are the caller's; every `BN_cmp` below takes the two objects' own
    // `BIGNUM`s, which the accessors answer.
    unsafe {
        /* There is always an |e| */
        ok &= c_int::from(BN_cmp(RSA_get0_e(rsa1), RSA_get0_e(rsa2)) == 0);
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked: c_int = 0;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                let pa = RSA_get0_n(rsa1);
                let pb = RSA_get0_n(rsa2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                let pa = RSA_get0_d(rsa1);
                let pb = RSA_get0_d(rsa2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            ok &= key_checked;
        }
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// Import and export.
// ---------------------------------------------------------------------------------------------

/// `static int rsa_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `rsa_kmgmt.c:168-188`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn rsa_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let rsa = keydata.cast::<Rsa>();
    let rsa_type: c_int;
    let mut ok: c_int = 1;
    let mut pss_defaults_set: c_int = 0;

    if is_running() == 0 || rsa.is_null() {
        return 0;
    }

    if (selection & RSA_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    // SAFETY: `rsa` is non-NULL past the guard.
    unsafe {
        rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);

        if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
            ok &= pss_params_fromdata(
                ossl_rsa_get0_pss_params_30(rsa),
                &mut pss_defaults_set,
                params,
                rsa_type,
                ossl_rsa_get0_libctx(rsa),
            );
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= ossl_rsa_fromdata(rsa, params, include_private);
        }
    }
    ok
}

/// `static int rsa_export(void *keydata, int selection, OSSL_CALLBACK *param_callback,`
/// `void *cbarg)` — `rsa_kmgmt.c:190-224`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn rsa_export(
    keydata: *mut c_void,
    selection: c_int,
    param_callback: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let rsa = keydata.cast::<Rsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 || rsa.is_null() {
        return 0;
    }

    if (selection & RSA_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    // SAFETY: `rsa` is non-NULL past the guard.
    let pss_params = unsafe { ossl_rsa_get0_pss_params_30(rsa) };

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `rsa` is live; `tmpl` is this call's own builder; the values are its own pointers.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
            ok &= c_int::from(
                ossl_rsa_pss_params_30_is_unrestricted(pss_params) != 0
                    || ossl_rsa_pss_params_30_todata(pss_params, tmpl, ptr::null_mut()) != 0,
            );
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= ossl_rsa_todata(rsa, tmpl, ptr::null_mut(), include_private);
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

        ok = match param_callback {
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
// The imexport descriptors — `rsa_kmgmt.c`'s three macros, written out.
// ---------------------------------------------------------------------------------------------

/// `RSA_KEY_MP_TYPES()` — `rsa_kmgmt.c:236-264`'s `#else` arm: ten factors, ten exponents and nine
/// coefficients. The `FIPS_MODULE` arm's five descriptors are not this profile's.
///
/// **The macro is not written, and its absence is deliberate.** `RSA_KEY_TYPES()` splices it into
/// two array literals, and a `macro_rules!` that expands to a comma-separated list is not a single
/// expression, so the splice cannot be written in Rust at all. The block is written out in each of
/// the two arrays that use it — `rsa_key_types` below and `rsa_params` further down — which is the
/// same trade `ec_kmgmt.rs` makes for its shared domain-parameter block.
///
/// `static const OSSL_PARAM rsa_key_types[]` — `rsa_kmgmt.c:277-280`: `n`, `e`, `d` then that
/// block. The same array describes import and export, because "this provider can export everything
/// in an RSA key".
static RSA_KEY_TYPES: [OsslParam; 33] = [
    param_bn(OSSL_PKEY_PARAM_RSA_N),
    param_bn(OSSL_PKEY_PARAM_RSA_E),
    param_bn(OSSL_PKEY_PARAM_RSA_D),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR1),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR2),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR3),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR4),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR5),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR6),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR7),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR8),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR9),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR10),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT3),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT4),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT5),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT6),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT7),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT8),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT9),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT10),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT2),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT3),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT4),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT5),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT6),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT7),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT8),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT9),
    END,
];

/// `static const OSSL_PARAM *rsa_imexport_types(int selection)` — `rsa_kmgmt.c:288-293`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn rsa_imexport_types(selection: c_int) -> *const OsslParam {
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        return RSA_KEY_TYPES.as_ptr();
    }
    ptr::null()
}

/// `static const OSSL_PARAM *rsa_import_types(int selection)` — `rsa_kmgmt.c:295-298`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn rsa_import_types(selection: c_int) -> *const OsslParam {
    // SAFETY: a forwarding call with no pointer argument of its own.
    unsafe { rsa_imexport_types(selection) }
}

/// `static const OSSL_PARAM *rsa_export_types(int selection)` — `rsa_kmgmt.c:300-303`.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn rsa_export_types(selection: c_int) -> *const OsslParam {
    // SAFETY: a forwarding call with no pointer argument of its own.
    unsafe { rsa_imexport_types(selection) }
}

// ---------------------------------------------------------------------------------------------
// `rsa_get_params` and its two descriptor arrays.
// ---------------------------------------------------------------------------------------------

/// `static int rsa_get_params(void *key, OSSL_PARAM params[])` — `rsa_kmgmt.c:305-364`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
// The authority nests the `OSSL_PARAM_set_utf8_string` call inside the `p != NULL` arm's second
// test; collapsing the two `if`s would be the same control flow written less like the C.
#[allow(clippy::collapsible_if)]
unsafe extern "C" fn rsa_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    let rsa = key.cast::<Rsa>();

    // SAFETY: `rsa` is the caller's object.
    let pss_params = unsafe { ossl_rsa_get0_pss_params_30(rsa) };
    // SAFETY: as above.
    let rsa_type = unsafe { RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) };
    // SAFETY: as above.
    let empty = unsafe { RSA_get0_n(rsa) }.is_null();

    // SAFETY: `params` is the caller's array; every `OSSL_PARAM_locate` returns an element of it.
    unsafe {
        let mut p = OSSL_PARAM_locate(params, P_BITS);
        if !p.is_null() && (empty || OSSL_PARAM_set_int(p, RSA_bits(rsa)) == 0) {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_BITS);
        if !p.is_null() && (empty || OSSL_PARAM_set_int(p, RSA_security_bits(rsa)) == 0) {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_MAX_SIZE);
        if !p.is_null() && (empty || OSSL_PARAM_set_int(p, RSA_size(rsa)) == 0) {
            return 0;
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_CATEGORY);
        if !p.is_null() && OSSL_PARAM_set_int(p, 0) == 0 {
            return 0;
        }

        /*
         * For restricted RSA-PSS keys, we ignore the default digest request.
         * With RSA-OAEP keys, this may need to be amended.
         */
        p = OSSL_PARAM_locate(params, P_DEFAULT_DIGEST);
        if !p.is_null()
            && (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
                || ossl_rsa_pss_params_30_is_unrestricted(pss_params) != 0)
        {
            if OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD) == 0 {
                return 0;
            }
        }

        /*
         * For non-RSA-PSS keys, we ignore the mandatory digest request.
         * With RSA-OAEP keys, this may need to be amended.
         */
        p = OSSL_PARAM_locate(params, P_MANDATORY_DIGEST);
        if !p.is_null()
            && rsa_type == RSA_FLAG_TYPE_RSASSAPSS
            && ossl_rsa_pss_params_30_is_unrestricted(pss_params) == 0
        {
            let mdname = ossl_rsa_oaeppss_nid2name(ossl_rsa_pss_params_30_hashalg(pss_params));

            if mdname.is_null() || OSSL_PARAM_set_utf8_string(p, mdname) == 0 {
                return 0;
            }
        }

        c_int::from(
            (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
                || ossl_rsa_pss_params_30_todata(pss_params, ptr::null_mut(), params) != 0)
                && ossl_rsa_todata(rsa, ptr::null_mut(), params, 1) != 0,
        )
    }
}

/// `static const OSSL_PARAM rsa_params[]` — `rsa_kmgmt.c:366-374`: the five fixed descriptors then
/// the same `n`, `e`, `d` and `RSA_KEY_MP_TYPES` block as `rsa_key_types`.
static RSA_PARAMS: [OsslParam; 38] = [
    param_int(P_BITS),
    param_int(P_SECURITY_BITS),
    param_int(P_MAX_SIZE),
    param_int(P_SECURITY_CATEGORY),
    param_utf8_string(P_DEFAULT_DIGEST),
    param_bn(OSSL_PKEY_PARAM_RSA_N),
    param_bn(OSSL_PKEY_PARAM_RSA_E),
    param_bn(OSSL_PKEY_PARAM_RSA_D),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR1),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR2),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR3),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR4),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR5),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR6),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR7),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR8),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR9),
    param_bn(OSSL_PKEY_PARAM_RSA_FACTOR10),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT3),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT4),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT5),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT6),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT7),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT8),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT9),
    param_bn(OSSL_PKEY_PARAM_RSA_EXPONENT10),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT2),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT3),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT4),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT5),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT6),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT7),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT8),
    param_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT9),
    END,
];

/// `static const OSSL_PARAM *rsa_gettable_params(void *provctx)` — `rsa_kmgmt.c:376-379`.
///
/// # Safety
/// The keymgmt `gettable_params` dispatch contract.
unsafe extern "C" fn rsa_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    RSA_PARAMS.as_ptr()
}

// ---------------------------------------------------------------------------------------------
// `rsa_validate` — the three `rsa_chk.c` validators this unit is the reachability for.
// ---------------------------------------------------------------------------------------------

/// `static int rsa_validate(const void *keydata, int selection, int checktype)` —
/// `rsa_kmgmt.c:381-410`.
///
/// A whole-key selection runs the **pairwise** check alone; otherwise the private and public halves
/// run independently, in that order. `checktype` is unused, exactly as it is in the authority.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn rsa_validate(
    keydata: *const c_void,
    selection: c_int,
    _checktype: c_int,
) -> c_int {
    let rsa = keydata.cast::<Rsa>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    if (selection & RSA_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }

    // SAFETY: `rsa` is the caller's object.
    unsafe {
        /* If the whole key is selected, we do a pairwise validation */
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            ok &= ossl_rsa_validate_pairwise(rsa);
        } else {
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                ok &= ossl_rsa_validate_private(rsa);
            }
            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                ok &= ossl_rsa_validate_public(rsa);
            }
        }
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// The generation path — `rsa_gencb`, `gen_init`, `rsa_gen_set_params`, the settable arrays,
// `rsa_gen`, `rsa_gen_cleanup`.
// ---------------------------------------------------------------------------------------------

/// `static int rsa_gencb(int p, int n, BN_GENCB *cb)` — `rsa_kmgmt.c:447-456`.
///
/// # Safety
/// The `BN_GENCB` callback contract: `cb` carries the generator context this unit set with
/// `BN_GENCB_set`.
unsafe extern "C" fn rsa_gencb(p: c_int, n: c_int, cb: *mut BnGencb) -> c_int {
    // SAFETY: `cb` is live per the contract; `BN_GENCB_get_arg` answers the `genctx` set below.
    let gctx = unsafe { BN_GENCB_get_arg(cb) }.cast::<RsaGenCtx>();

    // The authority takes the *address of its own parameters*, so the two `OSSL_PARAM`s point at
    // this frame's copies. They are `mut` only because `OSSL_PARAM_construct_int` writes through
    // the pointer it is given.
    let mut p = p;
    let mut n = n;
    let mut params: [OsslParam; 3] = [END, END, END];

    // SAFETY: `params` is this frame's array and the two pointers are its own locals.
    unsafe {
        params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &raw mut p);
        params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &raw mut n);
    }
    // SAFETY: the callback is read off this frame's live context and is the caller's, set in
    // `rsa_gen`.
    let cb = unsafe { (*gctx).cb };
    match cb {
        // SAFETY: the callback and its argument are the caller's, set in `rsa_gen`.
        Some(callback) => unsafe { callback(params.as_ptr(), (*gctx).cbarg) },
        None => 0,
    }
}

/// `static void *gen_init(void *provctx, int selection, int rsa_type, const OSSL_PARAM params[])`
/// — `rsa_kmgmt.c:458-491`. `OPENSSL_zalloc` is `CRYPTO_zalloc` here, as everywhere in this crate.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe fn gen_init(
    provctx: *mut c_void,
    selection: c_int,
    rsa_type: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    let libctx = unsafe { prov_libctx_of(provctx) };

    if is_running() == 0 {
        return ptr::null_mut();
    }

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let gctx = CRYPTO_zalloc(core::mem::size_of::<RsaGenCtx>(), FILE, 459).cast::<RsaGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation; `libctx` is the caller's.
        unsafe {
            (*gctx).libctx = libctx;
            (*gctx).pub_exp = BN_new();
        }
        // SAFETY: `gctx` is non-NULL past the guard and `pub_exp` is this call's own.
        let ok = unsafe { !(*gctx).pub_exp.is_null() && BN_set_word((*gctx).pub_exp, RSA_F4) != 0 };
        if !ok {
            // SAFETY: `gctx` and its `pub_exp` are this call's own, not yet published.
            unsafe { gen_init_cleanup(gctx) };
            return ptr::null_mut();
        }
        // SAFETY: `gctx` is this call's own allocation.
        unsafe {
            (*gctx).nbits = 2048;
            (*gctx).primes = RSA_DEFAULT_PRIME_NUM as usize;
            (*gctx).rsa_type = rsa_type;
        }
    } else {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is non-NULL and this call's own; `params` is the caller's.
    if unsafe { rsa_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is this call's own allocation, not yet published.
        unsafe { gen_init_cleanup(gctx) };
        return ptr::null_mut();
    }
    gctx.cast()
}

/// The authority's `err:` label of `gen_init` — `BN_free(gctx->pub_exp); OPENSSL_free(gctx);`.
///
/// # Safety
/// `gctx` is this call's own allocation and has not been published.
unsafe fn gen_init_cleanup(gctx: *mut RsaGenCtx) {
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation.
        unsafe {
            BN_free((*gctx).pub_exp);
            CRYPTO_free(gctx.cast(), FILE, 490);
        }
    }
}

/// `static void *rsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `rsa_kmgmt.c:493-498`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn rsa_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract, forwarded.
    unsafe { gen_init(provctx, selection, RSA_FLAG_TYPE_RSA, params) }
}

/// `static void *rsapss_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `rsa_kmgmt.c:500-505`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn rsapss_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract, forwarded.
    unsafe { gen_init(provctx, selection, RSA_FLAG_TYPE_RSASSAPSS, params) }
}

/// `static int rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `rsa_kmgmt.c:512-536`.
///
/// # Safety
/// The keymgmt `gen_set_params` dispatch contract.
unsafe extern "C" fn rsa_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<RsaGenCtx>();

    // SAFETY: `params` is NULL or key-terminated per the contract.
    if unsafe { param_is_empty(params) } {
        return 1;
    }

    // SAFETY: `gctx` is the caller's generator context; `params` is the caller's array.
    unsafe {
        let mut p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
        if !p.is_null() {
            if OSSL_PARAM_get_size_t(p, &raw mut (*gctx).nbits) == 0 {
                return 0;
            }
            if ((*gctx).nbits as c_int) < RSA_MIN_MODULUS_BITS {
                raise_site(&err_sites::PROV_RSA_KMGMT_513);
                return 0;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, &raw mut (*gctx).primes) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        if !p.is_null() && OSSL_PARAM_get_BN(p, &raw mut (*gctx).pub_exp) == 0 {
            return 0;
        }
        /* Only attempt to get PSS parameters when generating an RSA-PSS key */
        if (*gctx).rsa_type == RSA_FLAG_TYPE_RSASSAPSS
            && pss_params_fromdata(
                &raw mut (*gctx).pss_params,
                &raw mut (*gctx).pss_defaults_set,
                params,
                (*gctx).rsa_type,
                (*gctx).libctx,
            ) == 0
        {
            return 0;
        }
        /* `#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)`'s
         * `ossl_rsa_acvp_test_gen_params_new` call is not this profile's. */
    }
    1
}

/// `rsa_gen_basic` — `rsa_kmgmt.c:538-541`.
macro_rules! rsa_gen_basic {
    () => {
        [
            param_size_t(OSSL_PKEY_PARAM_RSA_BITS),
            param_size_t(OSSL_PKEY_PARAM_RSA_PRIMES),
            param_bn(OSSL_PKEY_PARAM_RSA_E),
            END,
        ]
    };
}

/// `rsa_gen_settable_params`'s function-local `static OSSL_PARAM settable[]` —
/// `rsa_kmgmt.c:554-566`.
static RSA_GEN_SETTABLE: [OsslParam; 4] = rsa_gen_basic!();

/// `rsapss_gen_settable_params`'s function-local `static OSSL_PARAM settable[]` —
/// `rsa_kmgmt.c:568-581`.
macro_rules! rsapss_gen_settable {
    () => {
        [
            param_size_t(OSSL_PKEY_PARAM_RSA_BITS),
            param_size_t(OSSL_PKEY_PARAM_RSA_PRIMES),
            param_bn(OSSL_PKEY_PARAM_RSA_E),
            param_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST),
            param_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS),
            param_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC),
            param_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST),
            param_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN),
            END,
        ]
    };
}

/// `static const OSSL_PARAM *rsa_gen_settable_params(void *genctx, void *provctx)` —
/// `rsa_kmgmt.c:554-566`.
///
/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn rsa_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSA_GEN_SETTABLE.as_ptr()
}

/// `static const OSSL_PARAM *rsapss_gen_settable_params(void *genctx, void *provctx)` —
/// `rsa_kmgmt.c:568-581`.
///
/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn rsapss_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSA_PSS_GEN_SETTABLE.as_ptr()
}

/// `rsapss_gen_settable_params`'s function-local `static OSSL_PARAM settable[]`.
static RSA_PSS_GEN_SETTABLE: [OsslParam; 9] = rsapss_gen_settable!();

/// `static void *rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `rsa_kmgmt.c:584-637`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn rsa_gen(
    genctx: *mut c_void,
    osslcb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<RsaGenCtx>();
    let mut ret: *mut Rsa = ptr::null_mut();

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is non-NULL past the guard and is the caller's context.
    match unsafe { (*gctx).rsa_type } {
        RSA_FLAG_TYPE_RSA => {
            /* For plain RSA keys, PSS parameters must not be set */
            // SAFETY: `gctx` is live and `pss_params` is its own embedded member.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(&raw const (*gctx).pss_params) } == 0
            {
                /* The authority's `err:` label, reached with `gencb` and `rsa_tmp` both NULL. */
                return ptr::null_mut();
            }
        }
        /*
         * For plain RSA-PSS keys, PSS parameters may be set but don't have
         * to, so not check.
         */
        RSA_FLAG_TYPE_RSASSAPSS => {}
        /* Unsupported RSA key sub-type... */
        _ => return ptr::null_mut(),
    }

    // SAFETY: `gctx` is live.
    let mut rsa_tmp = unsafe { ossl_rsa_new_with_ctx((*gctx).libctx) };
    if rsa_tmp.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is this call's context; `osslcb`/`cbarg` are the caller's.
    unsafe {
        (*gctx).cb = osslcb;
        (*gctx).cbarg = cbarg;
    }
    // SAFETY: a fresh callback this call owns; `BN_GENCB_set` below fills it in.
    let gencb = unsafe { BN_GENCB_new() };
    if !gencb.is_null() {
        // SAFETY: `gencb` is this call's own and `gctx` outlives the generation below.
        unsafe { BN_GENCB_set(gencb, Some(rsa_gencb), genctx) };
    }

    'err: {
        /* `#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)`'s
         * `ossl_rsa_acvp_test_set_params` call is not this profile's. */

        // SAFETY: `gctx` is live; `rsa_tmp` is this call's own object; `gencb` is this call's own.
        let generated = unsafe {
            RSA_generate_multi_prime_key(
                rsa_tmp,
                (*gctx).nbits as c_int,
                (*gctx).primes as c_int,
                (*gctx).pub_exp,
                gencb,
            )
        };
        if generated == 0 {
            break 'err;
        }

        // SAFETY: `rsa_tmp` is live and `gctx` is the caller's context.
        let copied = unsafe {
            ossl_rsa_pss_params_30_copy(
                ossl_rsa_get0_pss_params_30(rsa_tmp),
                &raw const (*gctx).pss_params,
            )
        };
        if copied == 0 {
            break 'err;
        }

        // SAFETY: `rsa_tmp` is this call's own object and `gctx` is the caller's context.
        unsafe {
            RSA_clear_flags(rsa_tmp, RSA_FLAG_TYPE_MASK);
            RSA_set_flags(rsa_tmp, (*gctx).rsa_type);
        }

        ret = rsa_tmp;
        rsa_tmp = ptr::null_mut();
    }
    /* The authority's `err:` label. */
    // SAFETY: `gencb` is this call's own and `rsa_tmp` is NULL or this call's own.
    unsafe {
        BN_GENCB_free(gencb);
        RSA_free(rsa_tmp);
    }
    ret.cast()
}

/// `static void rsa_gen_cleanup(void *genctx)` — `rsa_kmgmt.c:639-653`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn rsa_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<RsaGenCtx>();

    if gctx.is_null() {
        return;
    }
    /* `#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)`'s
     * `ossl_rsa_acvp_test_gen_params_free` call is not this profile's. */
    // SAFETY: `gctx` is this call's own context.
    unsafe {
        BN_clear_free((*gctx).pub_exp);
        CRYPTO_free(gctx.cast(), FILE, 652);
    }
}

// ---------------------------------------------------------------------------------------------
// The load and duplicate paths.
// ---------------------------------------------------------------------------------------------

/// `static void *common_load(const void *reference, size_t reference_sz, int expected_rsa_type)`
/// — `rsa_kmgmt.c:655-673`.
///
/// **The reference is detached, not copied**: the contents are the address of the object and the
/// function sets that slot to NULL before answering it, so the caller takes ownership. A wrong
/// sub-type is refused *without* detaching.
///
/// # Safety
/// `reference` is readable for `reference_sz` bytes and, when the size matches, holds a live
/// `*mut Rsa` slot this call may clear.
unsafe fn common_load(
    reference: *const c_void,
    reference_sz: usize,
    expected_rsa_type: c_int,
) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut Rsa>() {
        // SAFETY: `reference` is readable for the object's size per the contract.
        let rsa = unsafe {
            /* The contents of the reference is the address to our object */
            let rsa = *(reference as *const *mut Rsa);

            if RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) != expected_rsa_type {
                return ptr::null_mut();
            }

            /* We grabbed, so we detach it */
            *(reference as *mut *mut Rsa) = ptr::null_mut();
            rsa
        };
        return rsa.cast();
    }
    ptr::null_mut()
}

/// `static void *rsa_load(const void *reference, size_t reference_sz)` — `rsa_kmgmt.c:675-678`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn rsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    // SAFETY: the caller's contract, forwarded.
    unsafe { common_load(reference, reference_sz, RSA_FLAG_TYPE_RSA) }
}

/// `static void *rsapss_load(const void *reference, size_t reference_sz)` — `rsa_kmgmt.c:680-683`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn rsapss_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    // SAFETY: the caller's contract, forwarded.
    unsafe { common_load(reference, reference_sz, RSA_FLAG_TYPE_RSASSAPSS) }
}

/// `static void *rsa_dup(const void *keydata_from, int selection)` — `rsa_kmgmt.c:685-692`.
///
/// The keypair bit is required: "do not allow creating empty keys by duplication".
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn rsa_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        // SAFETY: the caller's contract, forwarded.
        return unsafe { ossl_rsa_dup(keydata_from.cast::<Rsa>(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `static const char *rsa_query_operation_name(int operation_id)` — `rsa_kmgmt.c:695-698`.
///
/// "For any RSA key, we use the `RSA` algorithms regardless of sub-type" — so the `RSA-PSS` row
/// answers `RSA` too, and the signature and cipher rows it resolves are the plain ones.
///
/// # Safety
/// Takes no pointers.
unsafe extern "C" fn rsa_query_operation_name(_operation_id: c_int) -> *const c_char {
    c"RSA".as_ptr()
}

// ---------------------------------------------------------------------------------------------
// The two dispatch tables.
// ---------------------------------------------------------------------------------------------

/// `const OSSL_DISPATCH ossl_rsa_keymgmt_functions[]` — `rsa_kmgmt.c:700-722`.
pub(crate) static RSA_KEYMGMT_FUNCTIONS: [OsslDispatch; 19] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: rsa_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: rsa_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: rsa_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: rsa_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: rsa_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: rsa_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: rsa_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: rsa_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: rsa_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: rsa_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: rsa_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: rsa_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: rsa_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: rsa_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: rsa_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: rsa_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: rsa_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: rsa_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_rsapss_keymgmt_functions[]` — `rsa_kmgmt.c:724-749`. The same
/// eighteen callbacks as [`RSA_KEYMGMT_FUNCTIONS`] with four substitutions -- `rsapss_newdata`,
/// `rsapss_gen_init`, `rsapss_gen_settable_params`, `rsapss_load` -- and one addition,
/// `rsa_query_operation_name`, which only the PSS row's table carries.
pub(crate) static RSA_PSS_KEYMGMT_FUNCTIONS: [OsslDispatch; 20] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: rsapss_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: rsapss_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: rsa_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: rsapss_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: rsa_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: rsa_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: rsapss_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: rsa_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: rsa_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: rsa_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: rsa_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: rsa_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: rsa_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: rsa_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: rsa_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: rsa_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: rsa_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        function: rsa_query_operation_name as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: rsa_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
