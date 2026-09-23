//! Phase 8.10 — `providers/implementations/keymgmt/ec_kmgmt.c`: the `EC` and `SM2` key types.
//!
//! One thousand four hundred and ninety-two lines, thirty-odd functions and **two** dispatch tables.
//! The unit is the largest provider key management unit after the ECX one, and it is reachable
//! because the object layer it stands on is landed: `EC_GROUP_new_by_curve_name`
//! (`src/ec/curve.rs`), `EC_POINT_new`/`EC_POINT_mul` (`src/ec/lib.rs`), the wNAF/ladder
//! (`src/ec/mult.rs`), `EC_POINT_point2oct`/`_point2buf` (`src/ec/oct.rs`) and the whole
//! `crypto/ec/ec_backend.c` bridge (`ossl_ec_group_fromdata`, `ossl_ec_key_fromdata`,
//! `ossl_ec_key_otherparams_fromdata`, `ossl_ec_group_todata`, `ossl_ec_key_dup`) — D387 re-measured
//! the D334 record as stale and this pass is its consequence.
//!
//! ## The two prerequisite functions this pass landed with it
//!
//! Of `ec_kmgmt.c`'s non-`FIPS_MODULE` callees exactly two were missing:
//!
//! * **`ossl_ec_generate_key_dhkem`** (`crypto/ec/ec_key.c:357`, reached by `ec_gen` whenever the
//!   caller sets `OSSL_PKEY_PARAM_DHKEM_IKM`) and its own callee
//!   `ossl_ec_dhkem_derive_private` (`kem/ec_kem.c.in:387`). Both landed in this pass — the second
//!   in [`crate::provider::ec_kem`], where its authority unit defines it — and the
//!   `forensics/prerequisites.json` divergence row that recorded the withholding was removed rather
//!   than left to fail-closed as `stale`.
//! * **`ossl_sm2_key_private_check`** (`crypto/sm2/sm2_key.c:22`), the `SM2` row's private-key
//!   validate, landed as [`crate::ec::sm2_key::ossl_sm2_key_private_check`].
//!
//! ## What is transcribed, and what this profile does not compile
//!
//! `OPENSSL_NO_EC2M` and `OPENSSL_NO_SM2` are both undefined on this profile, so the EC2M
//! parameter arm of `ec_get_ecm_params` and every `#ifndef FIPS_MODULE`/`#ifndef OPENSSL_NO_SM2`
//! block are compiled and are transcribed — including the `SM2` dispatch table. The `FIPS_MODULE`
//! arms — `OSSL_FIPS_IND_DECLARE`/`_INIT`/`_SET_CTX_PARAM`/`_GET_CTX_PARAM`/`_SETTABLE_CTX_PARAM`/
//! `_GETTABLE_CTX_PARAM` and the `ossl_fips_ind_ec_key_check` call in `ec_gen` — are not this
//! profile's, and each is named at the site it would be. `ec_gen_gettable_params` therefore answers
//! the empty table and `ec_gen_get_params` the literal 1, exactly as the macros reduce to.
//!
//! ## `EC_IMEXPORTABLE_*` and `ec_types[]`
//!
//! `ec_kmgmt_imexport.inc` is included by this unit and declares fifteen `OSSL_PARAM` arrays and the
//! sixteen-entry `ec_types[]` index over them. The arrays are written out here — the four
//! `EC_IMEXPORTABLE_*` groups are `macro_rules!`-shaped the way `dh_kmgmt.c`'s are, because Rust
//! cannot splice a comma-separated macro into an array literal's slot list without expanding to a
//! single expression, and the C's own `#include`d tables are the thing being transcribed rather
//! than a scheme of ours.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_new, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::asn1::ECDSA_size;
use crate::ec::backend::{
    ossl_ec_check_group_type_id2name, ossl_ec_encoding_name2id, ossl_ec_group_fromdata,
    ossl_ec_group_todata, ossl_ec_key_dup, ossl_ec_key_fromdata, ossl_ec_key_otherparams_fromdata,
    ossl_ec_pt_format_id2name, ossl_ec_pt_format_name2id, ossl_ec_set_check_group_type_from_name,
    ossl_ec_set_ecdh_cofactor_mode,
};
use crate::ec::check::{EC_GROUP_check, EC_GROUP_check_named_curve};
use crate::ec::key::{
    ossl_ec_generate_key_dhkem, ossl_ec_key_get0_propq, ossl_ec_key_get_libctx,
    ossl_ec_key_pairwise_check, ossl_ec_key_private_check, ossl_ec_key_public_check,
    ossl_ec_key_public_check_quick, EC_KEY_decoded_from_explicit_params, EC_KEY_free,
    EC_KEY_generate_key, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
    EC_KEY_get_conv_form, EC_KEY_get_enc_flags, EC_KEY_get_flags, EC_KEY_new_by_curve_name_ex,
    EC_KEY_new_ex, EC_KEY_oct2key, EC_KEY_set_group, EC_FLAG_CHECK_NAMED_GROUP,
    EC_FLAG_CHECK_NAMED_GROUP_MASK, EC_FLAG_CHECK_NAMED_GROUP_NIST, EC_FLAG_COFACTOR_ECDH,
    EC_PKEY_NO_PUBKEY,
};
use crate::ec::lib::{
    ossl_ec_group_set_params, EC_GROUP_cmp, EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_basis_type,
    EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_get_pentanomial_basis, EC_GROUP_get_trinomial_basis, EC_GROUP_new_from_params,
    EC_GROUP_order_bits, EC_GROUP_set_asn1_flag, EC_GROUP_set_point_conversion_form, EC_POINT_cmp,
    EC_POINT_get_affine_coordinates,
};
use crate::ec::oct::{EC_POINT_point2buf, EC_POINT_point2oct};
use crate::ec::sm2_key::ossl_sm2_key_private_check;
use crate::ec::{EcGroup, EcKey};
use crate::evp::exchange::OSSL_OP_KEYEXCH;
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::signature::OSSL_OP_SIGNATURE;
use crate::param_build_set::{
    ossl_param_build_set_bn, ossl_param_build_set_bn_pad, ossl_param_build_set_int,
    ossl_param_build_set_octet_string, ossl_param_build_set_utf8_string,
};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
    OSSL_PARAM_BLD,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_string, OsslParam, END, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::obj::{
    NID_X9_62_characteristic_two_field, NID_X9_62_ppBasis, NID_X9_62_tpBasis, NID_sm2,
};
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// The constants — `ec_kmgmt.c`, `ec.h` and `core_names.h`.
// ---------------------------------------------------------------------------------------------

/// `EC_DEFAULT_MD` — `ec_kmgmt.c:77`.
const EC_DEFAULT_MD: *const c_char = c"SHA256".as_ptr();
/// `SM2_DEFAULT_MD` — `ec_kmgmt.c:80`.
const SM2_DEFAULT_MD: *const c_char = c"SM3".as_ptr();

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
/// `OSSL_KEYMGMT_SELECT_KEYPAIR`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
/// `EC_POSSIBLE_SELECTIONS` — `ec_kmgmt.c:78-79`.
const EC_POSSIBLE_SELECTIONS: c_int =
    OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
/// `OSSL_KEYMGMT_VALIDATE_QUICK_CHECK` — `core_dispatch.h`.
const OSSL_KEYMGMT_VALIDATE_QUICK_CHECK: c_int = 1;

/// `POINT_CONVERSION_UNCOMPRESSED` — `include/openssl/ec.h`, re-exported by `crate::ec`.
const POINT_CONVERSION_UNCOMPRESSED: c_int = crate::ec::POINT_CONVERSION_UNCOMPRESSED;

/// `SN_X9_62_tpBasis` — `obj_mac.h`, `"tpBasis"`.
#[allow(non_upper_case_globals)] // the authority's macro name, kept verbatim
const SN_X9_62_tpBasis: *const c_char = c"tpBasis".as_ptr();
/// `SN_X9_62_ppBasis` — `obj_mac.h`, `"ppBasis"`.
#[allow(non_upper_case_globals)] // the authority's macro name, kept verbatim
const SN_X9_62_ppBasis: *const c_char = c"ppBasis".as_ptr();

// The `OSSL_PKEY_PARAM_*` keys this unit reads. They are restated here for the reason every numeric
// or string constant in this crate is: the crate does not re-export the header's macro set.
const P_GROUP_NAME: *const c_char = c"group".as_ptr();
const P_EC_ENCODING: *const c_char = c"encoding".as_ptr();
const P_EC_POINT_CONVERSION_FORMAT: *const c_char = c"point-format".as_ptr();
const P_EC_FIELD_TYPE: *const c_char = c"field-type".as_ptr();
const P_EC_P: *const c_char = c"p".as_ptr();
const P_EC_A: *const c_char = c"a".as_ptr();
const P_EC_B: *const c_char = c"b".as_ptr();
const P_EC_GENERATOR: *const c_char = c"generator".as_ptr();
const P_EC_ORDER: *const c_char = c"order".as_ptr();
const P_EC_COFACTOR: *const c_char = c"cofactor".as_ptr();
const P_EC_SEED: *const c_char = c"seed".as_ptr();
const P_EC_DECODED_FROM_EXPLICIT_PARAMS: *const c_char = c"decoded-from-explicit".as_ptr();
const P_PUB_KEY: *const c_char = c"pub".as_ptr();
const P_PRIV_KEY: *const c_char = c"priv".as_ptr();
const P_EC_PUB_X: *const c_char = c"qx".as_ptr();
const P_EC_PUB_Y: *const c_char = c"qy".as_ptr();
const P_USE_COFACTOR_ECDH: *const c_char = c"use-cofactor-flag".as_ptr();
const P_EC_INCLUDE_PUBLIC: *const c_char = c"include-public".as_ptr();
const P_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();
const P_DEFAULT_DIGEST: *const c_char = c"default-digest".as_ptr();
const P_BITS: *const c_char = c"bits".as_ptr();
const P_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
const P_MAX_SIZE: *const c_char = c"max-size".as_ptr();
const P_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
const P_EC_GROUP_CHECK_TYPE: *const c_char = c"group-check".as_ptr();
const P_EC_CHAR2_M: *const c_char = c"m".as_ptr();
const P_EC_CHAR2_TYPE: *const c_char = c"basis-type".as_ptr();
const P_EC_CHAR2_TP_BASIS: *const c_char = c"tp".as_ptr();
const P_EC_CHAR2_PP_K1: *const c_char = c"k1".as_ptr();
const P_EC_CHAR2_PP_K2: *const c_char = c"k2".as_ptr();
const P_EC_CHAR2_PP_K3: *const c_char = c"k3".as_ptr();
const P_DHKEM_IKM: *const c_char = c"dhkem-ikm".as_ptr();

/// The unit's own `__FILE__`. `ec_kmgmt.c` is a plain `.c`, so it carries the source-tree prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/keymgmt/ec_kmgmt.c".as_ptr();

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

/// `static const char *ec_query_operation_name(int operation_id)` — `ec_kmgmt.c:82-91`.
unsafe extern "C" fn ec_query_operation_name(operation_id: c_int) -> *const c_char {
    match operation_id {
        x if x == OSSL_OP_KEYEXCH => c"ECDH".as_ptr(),
        x if x == OSSL_OP_SIGNATURE => c"ECDSA".as_ptr(),
        _ => ptr::null(),
    }
}

/// `static const char *sm2_query_operation_name(int operation_id)` — `ec_kmgmt.c:95-102`.
unsafe extern "C" fn sm2_query_operation_name(operation_id: c_int) -> *const c_char {
    match operation_id {
        x if x == OSSL_OP_SIGNATURE => c"SM2".as_ptr(),
        _ => ptr::null(),
    }
}

/// `static ossl_inline int key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
/// OSSL_PARAM params[], int include_private, unsigned char **pub_key)` — `ec_kmgmt.c:113-238`.
///
/// Callers must export the domain parameters too; this function exports only the bare keypair.
///
/// # Safety
/// `eckey` is NULL or live; `tmpl`/`params` are per the contract; `pub_key` is writable.
unsafe fn key_to_params(
    eckey: *const EcKey,
    tmpl: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    include_private: c_int,
    pub_key: *mut *mut c_uchar,
) -> c_int {
    let mut x: *mut BigNum = ptr::null_mut();
    let mut y: *mut BigNum = ptr::null_mut();
    let mut ret: c_int = 0;
    let mut bnctx: *mut BnCtx = ptr::null_mut();

    if eckey.is_null() {
        return 0;
    }
    // SAFETY: `eckey` is non-NULL past the guard.
    let ecg = unsafe { EC_KEY_get0_group(eckey) };
    if ecg.is_null() {
        return 0;
    }

    // SAFETY: `eckey` is live.
    let priv_key = unsafe { EC_KEY_get0_private_key(eckey) };
    // SAFETY: as above.
    let pub_point = unsafe { EC_KEY_get0_public_key(eckey) };

    // SAFETY: every pointer below is per the contract.
    unsafe {
        if !pub_point.is_null() {
            let mut p: *mut OsslParam = ptr::null_mut();
            let mut px: *mut OsslParam = ptr::null_mut();
            let mut py: *mut OsslParam = ptr::null_mut();
            /*
             * EC_POINT_point2buf() can generate random numbers in some
             * implementations so we need to ensure we use the correct libctx.
             */
            bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(eckey));
            if bnctx.is_null() {
                BN_CTX_free(bnctx);
                return ret;
            }

            /* If we are doing a get then check first before decoding the point */
            if tmpl.is_null() {
                p = OSSL_PARAM_locate(params, P_PUB_KEY);
                px = OSSL_PARAM_locate(params, P_EC_PUB_X);
                py = OSSL_PARAM_locate(params, P_EC_PUB_Y);
            }

            if !p.is_null() || !tmpl.is_null() {
                /* convert pub_point to a octet string according to the SECG standard */
                let format = EC_KEY_get_conv_form(eckey);

                let pub_key_len = EC_POINT_point2buf(ecg, pub_point, format, pub_key, bnctx);
                if pub_key_len == 0
                    || ossl_param_build_set_octet_string(tmpl, p, P_PUB_KEY, *pub_key, pub_key_len)
                        == 0
                {
                    BN_CTX_free(bnctx);
                    return ret;
                }
            }
            if !px.is_null() || !py.is_null() {
                if !px.is_null() {
                    x = BN_CTX_get(bnctx);
                    if x.is_null() {
                        BN_CTX_free(bnctx);
                        return ret;
                    }
                }
                if !py.is_null() {
                    y = BN_CTX_get(bnctx);
                    if y.is_null() {
                        BN_CTX_free(bnctx);
                        return ret;
                    }
                }

                if EC_POINT_get_affine_coordinates(ecg, pub_point, x, y, bnctx) == 0 {
                    BN_CTX_free(bnctx);
                    return ret;
                }
                if !px.is_null() && ossl_param_build_set_bn(tmpl, px, P_EC_PUB_X, x) == 0 {
                    BN_CTX_free(bnctx);
                    return ret;
                }
                if !py.is_null() && ossl_param_build_set_bn(tmpl, py, P_EC_PUB_Y, y) == 0 {
                    BN_CTX_free(bnctx);
                    return ret;
                }
            }
        }

        if !priv_key.is_null() && include_private != 0 {
            /*
             * Key import/export should never leak the bit length of the secret
             * scalar in the key. ... For padding on export we use the bit length
             * of the order converted to bytes (rounding up).
             */
            let ecbits = EC_GROUP_order_bits(ecg);
            if ecbits <= 0 {
                BN_CTX_free(bnctx);
                return ret;
            }
            let sz = ((ecbits + 7) / 8) as usize;

            if ossl_param_build_set_bn_pad(tmpl, params, P_PRIV_KEY, priv_key, sz) == 0 {
                BN_CTX_free(bnctx);
                return ret;
            }
        }
        ret = 1;
        BN_CTX_free(bnctx);
    }
    ret
}

/// `static ossl_inline int otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
/// OSSL_PARAM params[])` — `ec_kmgmt.c:240-275`.
///
/// # Safety
/// `ec` is NULL or live; `tmpl`/`params` are per the contract.
unsafe fn otherparams_to_params(
    ec: *const EcKey,
    tmpl: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
) -> c_int {
    if ec.is_null() {
        return 0;
    }

    // SAFETY: `ec` is non-NULL past the guard.
    unsafe {
        let format = EC_KEY_get_conv_form(ec);
        let name = ossl_ec_pt_format_id2name(format);
        if !name.is_null()
            && ossl_param_build_set_utf8_string(tmpl, params, P_EC_POINT_CONVERSION_FORMAT, name)
                == 0
        {
            return 0;
        }

        let group_check = EC_KEY_get_flags(ec) & EC_FLAG_CHECK_NAMED_GROUP_MASK;
        let name = ossl_ec_check_group_type_id2name(group_check);
        if !name.is_null()
            && ossl_param_build_set_utf8_string(tmpl, params, P_EC_GROUP_CHECK_TYPE, name) == 0
        {
            return 0;
        }

        if (EC_KEY_get_enc_flags(ec) & (EC_PKEY_NO_PUBKEY as c_uint)) != 0
            && ossl_param_build_set_int(tmpl, params, P_EC_INCLUDE_PUBLIC, 0) == 0
        {
            return 0;
        }

        let ecdh_cofactor_mode = c_int::from((EC_KEY_get_flags(ec) & EC_FLAG_COFACTOR_ECDH) != 0);
        ossl_param_build_set_int(tmpl, params, P_USE_COFACTOR_ECDH, ecdh_cofactor_mode)
    }
}

/// `static void *ec_newdata(void *provctx)` — `ec_kmgmt.c:277-282`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn ec_newdata(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe { EC_KEY_new_ex(prov_libctx_of(provctx), ptr::null()).cast() }
}

/// `static void *sm2_newdata(void *provctx)` — `ec_kmgmt.c:286-291`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn sm2_newdata(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `provctx` is the caller's provider context.
    unsafe { EC_KEY_new_by_curve_name_ex(prov_libctx_of(provctx), ptr::null(), NID_sm2).cast() }
}

/// `static void ec_freedata(void *keydata)` — `ec_kmgmt.c:295-298`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn ec_freedata(keydata: *mut c_void) {
    // SAFETY: the caller hands back what `ec_newdata`/`sm2_newdata` answered.
    unsafe { EC_KEY_free(keydata.cast()) };
}

/// `static int ec_has(const void *keydata, int selection)` — `ec_kmgmt.c:300-322`.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn ec_has(keydata: *const c_void, selection: c_int) -> c_int {
    let ec = keydata.cast::<EcKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 || ec.is_null() {
        return 0;
    }
    if (selection & EC_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* the selection is not missing */
    }

    // SAFETY: `ec` is non-NULL past the guard.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= c_int::from(!EC_KEY_get0_public_key(ec).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= c_int::from(!EC_KEY_get0_private_key(ec).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= c_int::from(!EC_KEY_get0_group(ec).is_null());
        }
    }
    ok
}

/// `static int ec_match(const void *keydata1, const void *keydata2, int selection)` —
/// `ec_kmgmt.c:324-369`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn ec_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let ec1 = keydata1.cast::<EcKey>();
    let ec2 = keydata2.cast::<EcKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the two objects are the caller's, per the dispatch contract.
    unsafe {
        let group_a = EC_KEY_get0_group(ec1);
        let group_b = EC_KEY_get0_group(ec2);

        let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec1));
        if ctx.is_null() {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= c_int::from(
                !group_a.is_null()
                    && !group_b.is_null()
                    && EC_GROUP_cmp(group_a, group_b, ctx) == 0,
            );
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked = 0;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                let pa = EC_KEY_get0_public_key(ec1);
                let pb = EC_KEY_get0_public_key(ec2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(EC_POINT_cmp(group_b, pa, pb, ctx) == 0);
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                let pa = EC_KEY_get0_private_key(ec1);
                let pb = EC_KEY_get0_private_key(ec2);

                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            ok &= key_checked;
        }
        BN_CTX_free(ctx);
    }
    ok
}

/// `static int common_check_sm2(const EC_KEY *ec, int sm2_wanted)` — `ec_kmgmt.c:371-383`.
///
/// # Safety
/// `ec` is live.
unsafe fn common_check_sm2(ec: *const EcKey, sm2_wanted: c_int) -> c_int {
    // SAFETY: `ec` is live per the contract.
    unsafe {
        let ecg = EC_KEY_get0_group(ec);
        if ecg.is_null() {
            return 0;
        }
        let on_sm2 = c_int::from(EC_GROUP_get_curve_name(ecg) == NID_sm2);
        if sm2_wanted ^ on_sm2 != 0 {
            return 0;
        }
    }
    1
}

/// `static int common_import(void *keydata, int selection, const OSSL_PARAM params[],
/// int sm2_wanted)` — `ec_kmgmt.c:385-424`.
///
/// # Safety
/// `keydata` is NULL or live; `params` is NULL or key-terminated.
unsafe fn common_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
    sm2_wanted: c_int,
) -> c_int {
    let ec = keydata.cast::<EcKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 || ec.is_null() {
        return 0;
    }

    /*
     * Domain parameters must always be requested; private key must be requested alongside public
     * key; other parameters are always optional.
     */
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0 {
        return 0;
    }

    // SAFETY: `ec` is live and `params` is the caller's array.
    unsafe {
        ok &= ossl_ec_group_fromdata(ec, params);

        if common_check_sm2(ec, sm2_wanted) == 0 {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= ossl_ec_key_fromdata(ec, params, include_private);
        }
        if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
            ok &= ossl_ec_key_otherparams_fromdata(ec, params);
        }
    }
    ok
}

/// `static int ec_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `ec_kmgmt.c:426-429`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn ec_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { common_import(keydata, selection, params, 0) }
}

/// `static int sm2_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `ec_kmgmt.c:433-436`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn sm2_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { common_import(keydata, selection, params, 1) }
}

/// `static int ec_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `ec_kmgmt.c:440-508`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn ec_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let ec = keydata.cast::<EcKey>();
    let mut pub_key: *mut c_uchar = ptr::null_mut();
    let mut genbuf: *mut c_uchar = ptr::null_mut();
    let mut bnctx: *mut BnCtx = ptr::null_mut();
    let mut ok: c_int = 1;

    if is_running() == 0 || ec.is_null() {
        return 0;
    }

    /* Domain parameters must always be requested; a private key needs its public key. */
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0 {
        return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
    {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `ec` is non-NULL past the guard; `tmpl` is this call's own builder.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
            if bnctx.is_null() {
                ok = 0;
                OSSL_PARAM_BLD_free(tmpl);
                return ok;
            }
            BN_CTX_start(bnctx);
            ok &= ossl_ec_group_todata(
                EC_KEY_get0_group(ec),
                tmpl,
                ptr::null_mut(),
                ossl_ec_key_get_libctx(ec),
                ossl_ec_key_get0_propq(ec),
                bnctx,
                &mut genbuf,
            );
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

            ok &= key_to_params(ec, tmpl, ptr::null_mut(), include_private, &mut pub_key);
        }
        if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
            ok &= otherparams_to_params(ec, tmpl, ptr::null_mut());
        }

        let params = if ok == 0 {
            ptr::null_mut()
        } else {
            OSSL_PARAM_BLD_to_param(tmpl)
        };
        if ok == 0 || params.is_null() {
            ok = 0;
            OSSL_PARAM_BLD_free(tmpl);
            CRYPTO_free(pub_key.cast(), FILE, 503);
            CRYPTO_free(genbuf.cast(), FILE, 504);
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            return ok;
        }

        ok = match param_cb {
            Some(cb) => cb(params, cbarg),
            None => 0,
        };
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(tmpl);
        CRYPTO_free(pub_key.cast(), FILE, 503);
        CRYPTO_free(genbuf.cast(), FILE, 504);
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// `ec_kmgmt_imexport.inc`: the fifteen parameter tables and the sixteen-entry index.
// ---------------------------------------------------------------------------------------------

/// `EC_IMEXPORTABLE_PRIVATE_KEY` — `ec_kmgmt.c:528-529`.
const fn ec_imexportable_private_key() -> OsslParam {
    param_bn(P_PRIV_KEY)
}

/// `EC_IMEXPORTABLE_PUBLIC_KEY` — `ec_kmgmt.c:526-527`.
const fn ec_imexportable_public_key() -> OsslParam {
    param_octet_string(P_PUB_KEY)
}

/// `EC_IMEXPORTABLE_OTHER_PARAMETERS` — `ec_kmgmt.c:530-532`: two entries, `use-cofactor-flag` and
/// `include-public`, both `int`.
const fn ec_other_parameters() -> [OsslParam; 2] {
    [
        param_int(P_USE_COFACTOR_ECDH),
        param_int(P_EC_INCLUDE_PUBLIC),
    ]
}

/// `EC_IMEXPORTABLE_DOM_PARAMETERS` — `ec_kmgmt.c:512-524`: the twelve domain-parameter
/// descriptors. A `macro_rules!` cannot be spliced into an array literal's element list — a
/// fragment that expands to a comma-separated list is not a single expression — so this macro
/// expands the *whole* table and the callers' surrounding entries arrive as `pre`/`post`
/// repetitions, exactly as `dh_kmgmt.rs` (D387) writes its `DH_*_TYPES` tables out.
macro_rules! ec_types_with_dom {
    ([$($pre:expr),*] [$($post:expr),*]) => {
        [
            $($pre,)*
            param_utf8_string(P_GROUP_NAME),
            param_utf8_string(P_EC_ENCODING),
            param_utf8_string(P_EC_POINT_CONVERSION_FORMAT),
            param_utf8_string(P_EC_FIELD_TYPE),
            param_bn(P_EC_P),
            param_bn(P_EC_A),
            param_bn(P_EC_B),
            param_octet_string(P_EC_GENERATOR),
            param_bn(P_EC_ORDER),
            param_bn(P_EC_COFACTOR),
            param_octet_string(P_EC_SEED),
            param_int(P_EC_DECODED_FROM_EXPLICIT_PARAMS),
            $($post,)*
            END,
        ]
    };
}

/// `ec_private_key_types[]` — `ec_kmgmt_imexport.inc:14-17`.
static EC_PRIVATE_KEY_TYPES: [OsslParam; 2] = [ec_imexportable_private_key(), END];

/// `ec_public_key_types[]` — `:18-21`.
static EC_PUBLIC_KEY_TYPES: [OsslParam; 2] = [ec_imexportable_public_key(), END];

/// `ec_key_types[]` — `:22-26`.
static EC_KEY_TYPES: [OsslParam; 3] = [
    ec_imexportable_private_key(),
    ec_imexportable_public_key(),
    END,
];

/// `ec_dom_parameters_types[]` — `:27-30`.
static EC_DOM_PARAMETERS_TYPES: [OsslParam; 13] = ec_types_with_dom!([] []);

/// `ec_5_types[]` — `:31-35` (private key + domain parameters).
static EC_5_TYPES: [OsslParam; 14] = ec_types_with_dom!([ec_imexportable_private_key()] []);

/// `ec_6_types[]` — `:36-40` (public key + domain parameters).
static EC_6_TYPES: [OsslParam; 14] = ec_types_with_dom!([ec_imexportable_public_key()] []);

/// `ec_key_domp_types[]` — `:41-46`.
static EC_KEY_DOMP_TYPES: [OsslParam; 15] = ec_types_with_dom!(
    [ec_imexportable_private_key(), ec_imexportable_public_key()]
    []
);

/// `ec_other_parameters_types[]` — `:47-50`.
static EC_OTHER_PARAMETERS_TYPES: [OsslParam; 3] =
    [ec_other_parameters()[0], ec_other_parameters()[1], END];

/// `ec_9_types[]` — `:51-55` (private key + other parameters).
static EC_9_TYPES: [OsslParam; 4] = [
    ec_imexportable_private_key(),
    ec_other_parameters()[0],
    ec_other_parameters()[1],
    END,
];

/// `ec_10_types[]` — `:56-60` (public key + other parameters).
static EC_10_TYPES: [OsslParam; 4] = [
    ec_imexportable_public_key(),
    ec_other_parameters()[0],
    ec_other_parameters()[1],
    END,
];

/// `ec_11_types[]` — `:61-66`.
static EC_11_TYPES: [OsslParam; 5] = [
    ec_imexportable_private_key(),
    ec_imexportable_public_key(),
    ec_other_parameters()[0],
    ec_other_parameters()[1],
    END,
];

/// `ec_all_parameters_types[]` — `:67-71` (domain + other).
static EC_ALL_PARAMETERS_TYPES: [OsslParam; 15] = ec_types_with_dom!(
    []
    [ec_other_parameters()[0], ec_other_parameters()[1]]
);

/// `ec_13_types[]` — `:72-77`.
static EC_13_TYPES: [OsslParam; 16] = ec_types_with_dom!(
    [ec_imexportable_private_key()]
    [ec_other_parameters()[0], ec_other_parameters()[1]]
);

/// `ec_14_types[]` — `:78-83`.
static EC_14_TYPES: [OsslParam; 16] = ec_types_with_dom!(
    [ec_imexportable_public_key()]
    [ec_other_parameters()[0], ec_other_parameters()[1]]
);

/// `ec_all_types[]` — `:84-90`.
static EC_ALL_TYPES: [OsslParam; 17] = ec_types_with_dom!(
    [ec_imexportable_private_key(), ec_imexportable_public_key()]
    [ec_other_parameters()[0], ec_other_parameters()[1]]
);

/// `static const OSSL_PARAM *ec_types[]` — `ec_kmgmt_imexport.inc:92-109`. Index 0 is "none of
/// them"; the index is the sum of the four selection bits' weights.
///
/// The newtype is only here because a `static` of raw pointers needs a `Sync` impl; the sixteen
/// entries are `'static` table addresses and nothing writes it.
struct EcTypes([*const OsslParam; 16]);
// SAFETY: the array holds `'static` addresses of `'static` const tables and has no interior
// mutability; the same reasoning `OsslParam` and `OsslDispatch` carry.
unsafe impl Sync for EcTypes {}

static EC_TYPES: EcTypes = EcTypes([
    ptr::null(),
    EC_PRIVATE_KEY_TYPES.as_ptr(),
    EC_PUBLIC_KEY_TYPES.as_ptr(),
    EC_KEY_TYPES.as_ptr(),
    EC_DOM_PARAMETERS_TYPES.as_ptr(),
    EC_5_TYPES.as_ptr(),
    EC_6_TYPES.as_ptr(),
    EC_KEY_DOMP_TYPES.as_ptr(),
    EC_OTHER_PARAMETERS_TYPES.as_ptr(),
    EC_9_TYPES.as_ptr(),
    EC_10_TYPES.as_ptr(),
    EC_11_TYPES.as_ptr(),
    EC_ALL_PARAMETERS_TYPES.as_ptr(),
    EC_13_TYPES.as_ptr(),
    EC_14_TYPES.as_ptr(),
    EC_ALL_TYPES.as_ptr(),
]);

/// `static ossl_inline const OSSL_PARAM *ec_imexport_types(int selection)` —
/// `ec_kmgmt.c:543-556`.
unsafe extern "C" fn ec_imexport_types(selection: c_int) -> *const OsslParam {
    let mut type_select = 0usize;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        type_select += 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        type_select += 2;
    }
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        type_select += 4;
    }
    if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
        type_select += 8;
    }
    EC_TYPES.0[type_select]
}

/// `static const OSSL_PARAM *ec_import_types(int selection)` — `ec_kmgmt.c:558-561`.
unsafe extern "C" fn ec_import_types(selection: c_int) -> *const OsslParam {
    // SAFETY: the shared helper reads only its argument.
    unsafe { ec_imexport_types(selection) }
}

/// `static const OSSL_PARAM *ec_export_types(int selection)` — `ec_kmgmt.c:563-566`.
unsafe extern "C" fn ec_export_types(selection: c_int) -> *const OsslParam {
    // SAFETY: as above.
    unsafe { ec_imexport_types(selection) }
}

/// `static int ec_get_ecm_params(const EC_GROUP *group, OSSL_PARAM params[])` —
/// `ec_kmgmt.c:568-617`.
///
/// `OPENSSL_NO_EC2M` is undefined on this profile, so the binary-field arm is compiled; it answers
/// 1 immediately for every curve this crate holds, because they are all prime-field.
///
/// # Safety
/// `group` is live; `params` is NULL or key-terminated.
#[allow(unused_assignments)] // the authority initialises `basis_name` to NULL and assigns it before its only read
unsafe fn ec_get_ecm_params(group: *const EcGroup, params: *mut OsslParam) -> c_int {
    let mut ret: c_int = 0;
    let mut k1: c_uint = 0;
    let mut k2: c_uint = 0;
    let mut k3: c_uint = 0;
    let mut basis_name: *const c_char = ptr::null();

    // SAFETY: `group` is live per the contract.
    let fid = unsafe { EC_GROUP_get_field_type(group) };
    if fid != NID_X9_62_characteristic_two_field {
        return 1;
    }

    // SAFETY: `group` is live.
    let basis_nid = unsafe { EC_GROUP_get_basis_type(group) };
    if basis_nid == NID_X9_62_tpBasis {
        basis_name = SN_X9_62_tpBasis;
    } else if basis_nid == NID_X9_62_ppBasis {
        basis_name = SN_X9_62_ppBasis;
    } else {
        return ret;
    }

    // SAFETY: `group` is live and the descriptors are the caller's.
    unsafe {
        let m = EC_GROUP_get_degree(group);
        if ossl_param_build_set_int(ptr::null_mut(), params, P_EC_CHAR2_M, m) == 0
            || ossl_param_build_set_utf8_string(
                ptr::null_mut(),
                params,
                P_EC_CHAR2_TYPE,
                basis_name,
            ) == 0
        {
            return ret;
        }

        if basis_nid == NID_X9_62_tpBasis {
            if EC_GROUP_get_trinomial_basis(group, &mut k1) == 0
                || ossl_param_build_set_int(
                    ptr::null_mut(),
                    params,
                    P_EC_CHAR2_TP_BASIS,
                    k1 as c_int,
                ) == 0
            {
                return ret;
            }
        } else if EC_GROUP_get_pentanomial_basis(group, &mut k1, &mut k2, &mut k3) == 0
            || ossl_param_build_set_int(ptr::null_mut(), params, P_EC_CHAR2_PP_K1, k1 as c_int) == 0
            || ossl_param_build_set_int(ptr::null_mut(), params, P_EC_CHAR2_PP_K2, k2 as c_int) == 0
            || ossl_param_build_set_int(ptr::null_mut(), params, P_EC_CHAR2_PP_K3, k3 as c_int) == 0
        {
            return ret;
        }
    }
    ret = 1;
    ret
}

/// `static int common_get_params(void *key, OSSL_PARAM params[], int sm2)` — `ec_kmgmt.c:619-750`.
///
/// # Safety
/// `key` is live; `params` is NULL or key-terminated.
unsafe fn common_get_params(key: *mut c_void, params: *mut OsslParam, sm2: c_int) -> c_int {
    let mut ret: c_int = 0;
    let eck = key.cast::<EcKey>();
    let mut pub_key: *mut c_uchar = ptr::null_mut();
    let mut genbuf: *mut c_uchar = ptr::null_mut();

    // SAFETY: `eck` is live per the contract.
    let ecg = unsafe { EC_KEY_get0_group(eck) };
    if ecg.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_EC_KMGMT_632) };
        return 0;
    }

    // SAFETY: `eck` is live.
    let (libctx, propq) = unsafe { (ossl_ec_key_get_libctx(eck), ossl_ec_key_get0_propq(eck)) };

    // SAFETY: the descriptors are the caller's; the BN_CTX is this call's own.
    unsafe {
        let bnctx = BN_CTX_new_ex(libctx);
        if bnctx.is_null() {
            return 0;
        }
        BN_CTX_start(bnctx);

        let mut p = OSSL_PARAM_locate(params, P_MAX_SIZE);
        if !p.is_null() && OSSL_PARAM_set_int(p, ECDSA_size(eck)) == 0 {
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            return ret;
        }
        p = OSSL_PARAM_locate(params, P_BITS);
        if !p.is_null() && OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg)) == 0 {
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            return ret;
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_BITS);
        if !p.is_null() {
            let ecbits = EC_GROUP_order_bits(ecg);

            /*
             * The estimates are NIST SP 800-57 Part 1 Rev 4 Table 2's, applied to
             * every curve rather than to the NIST-approved ones alone.
             */
            let sec_bits = if ecbits >= 512 {
                256
            } else if ecbits >= 384 {
                192
            } else if ecbits >= 256 {
                128
            } else if ecbits >= 224 {
                112
            } else if ecbits >= 160 {
                80
            } else {
                ecbits / 2
            };

            if OSSL_PARAM_set_int(p, sec_bits) == 0 {
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
        }
        p = OSSL_PARAM_locate(params, P_SECURITY_CATEGORY);
        if !p.is_null() && OSSL_PARAM_set_int(p, 0) == 0 {
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            return ret;
        }

        p = OSSL_PARAM_locate(params, P_EC_DECODED_FROM_EXPLICIT_PARAMS);
        if !p.is_null() {
            let explicitparams = EC_KEY_decoded_from_explicit_params(eck);

            if explicitparams < 0 || OSSL_PARAM_set_int(p, explicitparams) == 0 {
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
        }

        if sm2 == 0 {
            p = OSSL_PARAM_locate(params, P_DEFAULT_DIGEST);
            if !p.is_null() && OSSL_PARAM_set_utf8_string(p, EC_DEFAULT_MD) == 0 {
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
        } else {
            p = OSSL_PARAM_locate(params, P_DEFAULT_DIGEST);
            if !p.is_null() && OSSL_PARAM_set_utf8_string(p, SM2_DEFAULT_MD) == 0 {
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
        }

        /* SM2 doesn't support this PARAM */
        if sm2 == 0 {
            p = OSSL_PARAM_locate(params, P_USE_COFACTOR_ECDH);
            if !p.is_null() {
                let ecdh_cofactor_mode =
                    c_int::from((EC_KEY_get_flags(eck) & EC_FLAG_COFACTOR_ECDH) != 0);

                if OSSL_PARAM_set_int(p, ecdh_cofactor_mode) == 0 {
                    BN_CTX_end(bnctx);
                    BN_CTX_free(bnctx);
                    return ret;
                }
            }
        }
        p = OSSL_PARAM_locate(params, P_ENCODED_PUBLIC_KEY);
        if !p.is_null() {
            let ecp = EC_KEY_get0_public_key(key.cast::<EcKey>());

            if ecp.is_null() {
                raise_site(&err_sites::PROV_EC_KMGMT_729);
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
            (*p).return_size = EC_POINT_point2oct(
                ecg,
                ecp,
                POINT_CONVERSION_UNCOMPRESSED,
                (*p).data.cast(),
                (*p).data_size,
                bnctx,
            );
            if (*p).return_size == 0 {
                BN_CTX_end(bnctx);
                BN_CTX_free(bnctx);
                return ret;
            }
        }

        ret = c_int::from(
            ec_get_ecm_params(ecg, params) != 0
                && ossl_ec_group_todata(
                    ecg,
                    ptr::null_mut(),
                    params,
                    libctx,
                    propq,
                    bnctx,
                    &mut genbuf,
                ) != 0
                && key_to_params(eck, ptr::null_mut(), params, 1, &mut pub_key) != 0
                && otherparams_to_params(eck, ptr::null_mut(), params) != 0,
        );

        CRYPTO_free(genbuf.cast(), FILE, 745);
        CRYPTO_free(pub_key.cast(), FILE, 746);
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }
    ret
}

/// `static int ec_get_params(void *key, OSSL_PARAM params[])` — `ec_kmgmt.c:752-755`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn ec_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { common_get_params(key, params, 0) }
}

/// `static int sm2_get_params(void *key, OSSL_PARAM params[])` — `ec_kmgmt.c:840-843`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn sm2_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { common_get_params(key, params, 1) }
}

/// `static const OSSL_PARAM ec_known_gettable_params[]` — `ec_kmgmt.c:769-785`. `OPENSSL_NO_EC2M`
/// is undefined, so the six `EC2M_GETTABLE_DOM_PARAMS` entries are present.
static EC_KNOWN_GETTABLE_PARAMS: [OsslParam; 32] = ec_types_with_dom!(
    [
        param_int(P_BITS),
        param_int(P_SECURITY_BITS),
        param_int(P_MAX_SIZE),
        param_int(P_SECURITY_CATEGORY),
        param_utf8_string(P_DEFAULT_DIGEST),
        param_octet_string(P_ENCODED_PUBLIC_KEY),
        param_int(P_EC_DECODED_FROM_EXPLICIT_PARAMS)
    ]
    [
        param_int(P_EC_CHAR2_M),
        param_utf8_string(P_EC_CHAR2_TYPE),
        param_int(P_EC_CHAR2_TP_BASIS),
        param_int(P_EC_CHAR2_PP_K1),
        param_int(P_EC_CHAR2_PP_K2),
        param_int(P_EC_CHAR2_PP_K3),
        ec_imexportable_public_key(),
        param_bn(P_EC_PUB_X),
        param_bn(P_EC_PUB_Y),
        ec_imexportable_private_key(),
        ec_other_parameters()[0],
        ec_other_parameters()[1]
    ]
);

/// `static const OSSL_PARAM *ec_gettable_params(void *provctx)` — `ec_kmgmt.c:787-790`.
unsafe extern "C" fn ec_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    EC_KNOWN_GETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM sm2_known_gettable_params[]` — `ec_kmgmt.c:845-858`.
static SM2_KNOWN_GETTABLE_PARAMS: [OsslParam; 23] = ec_types_with_dom!(
    [
        param_int(P_BITS),
        param_int(P_SECURITY_BITS),
        param_int(P_MAX_SIZE),
        param_utf8_string(P_DEFAULT_DIGEST),
        param_octet_string(P_ENCODED_PUBLIC_KEY),
        param_int(P_EC_DECODED_FROM_EXPLICIT_PARAMS)
    ]
    [
        ec_imexportable_public_key(),
        param_bn(P_EC_PUB_X),
        param_bn(P_EC_PUB_Y),
        ec_imexportable_private_key()
    ]
);

/// `static const OSSL_PARAM *sm2_gettable_params(void *provctx)` — `ec_kmgmt.c:860-863`.
unsafe extern "C" fn sm2_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    SM2_KNOWN_GETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM ec_known_settable_params[]` — `ec_kmgmt.c:792-801`.
static EC_KNOWN_SETTABLE_PARAMS: [OsslParam; 8] = [
    param_int(P_USE_COFACTOR_ECDH),
    param_octet_string(P_ENCODED_PUBLIC_KEY),
    param_utf8_string(P_EC_ENCODING),
    param_utf8_string(P_EC_POINT_CONVERSION_FORMAT),
    param_octet_string(P_EC_SEED),
    param_int(P_EC_INCLUDE_PUBLIC),
    param_utf8_string(P_EC_GROUP_CHECK_TYPE),
    END,
];

/// `static const OSSL_PARAM *ec_settable_params(void *provctx)` — `ec_kmgmt.c:803-806`.
unsafe extern "C" fn ec_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    EC_KNOWN_SETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM sm2_known_settable_params[]` — `ec_kmgmt.c:865-868`.
static SM2_KNOWN_SETTABLE_PARAMS: [OsslParam; 2] = [param_octet_string(P_ENCODED_PUBLIC_KEY), END];

/// `static const OSSL_PARAM *sm2_settable_params(void *provctx)` — `ec_kmgmt.c:870-873`.
unsafe extern "C" fn sm2_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    SM2_KNOWN_SETTABLE_PARAMS.as_ptr()
}

/// `static int ec_set_params(void *key, const OSSL_PARAM params[])` — `ec_kmgmt.c:808-836`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn ec_set_params(key: *mut c_void, params: *const OsslParam) -> c_int {
    let eck = key.cast::<EcKey>();

    if key.is_null() {
        return 0;
    }
    // SAFETY: `params` is NULL or key-terminated per the contract.
    if unsafe { param_is_empty(params) } {
        return 1;
    }

    // SAFETY: `key` is live and the descriptors are the caller's.
    unsafe {
        if ossl_ec_group_set_params(EC_KEY_get0_group(eck).cast_mut(), params) == 0 {
            return 0;
        }

        let p = OSSL_PARAM_locate_const(params, P_ENCODED_PUBLIC_KEY);
        if !p.is_null() {
            let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(eck));
            let mut ret = 1;

            if ctx.is_null()
                || (*p).data_type != OSSL_PARAM_OCTET_STRING
                || EC_KEY_oct2key(eck, (*p).data.cast(), (*p).data_size, ctx) == 0
            {
                ret = 0;
            }
            BN_CTX_free(ctx);
            if ret == 0 {
                return 0;
            }
        }

        ossl_ec_key_otherparams_fromdata(eck, params)
    }
}

/// `static int sm2_validate(const void *keydata, int selection, int checktype)` —
/// `ec_kmgmt.c:875-909`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn sm2_validate(
    keydata: *const c_void,
    selection: c_int,
    checktype: c_int,
) -> c_int {
    let eck = keydata.cast::<EcKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }
    if (selection & EC_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }

    // SAFETY: `eck` is the caller's object.
    unsafe {
        let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(eck));
        if ctx.is_null() {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= EC_GROUP_check(EC_KEY_get0_group(eck), ctx);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                ok &= ossl_ec_key_public_check_quick(eck, ctx);
            } else {
                ok &= ossl_ec_key_public_check(eck, ctx);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= ossl_sm2_key_private_check(eck);
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            ok &= ossl_ec_key_pairwise_check(eck, ctx);
        }

        BN_CTX_free(ctx);
    }
    ok
}

/// `static int ec_validate(const void *keydata, int selection, int checktype)` —
/// `ec_kmgmt.c:913-953`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn ec_validate(
    keydata: *const c_void,
    selection: c_int,
    checktype: c_int,
) -> c_int {
    let eck = keydata.cast::<EcKey>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }
    if (selection & EC_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }

    // SAFETY: `eck` is the caller's object.
    unsafe {
        let ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(eck));
        if ctx.is_null() {
            return 0;
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            let flags = EC_KEY_get_flags(eck);

            if (flags & EC_FLAG_CHECK_NAMED_GROUP) != 0 {
                ok &= c_int::from(
                    EC_GROUP_check_named_curve(
                        EC_KEY_get0_group(eck),
                        c_int::from((flags & EC_FLAG_CHECK_NAMED_GROUP_NIST) != 0),
                        ctx,
                    ) > 0,
                );
            } else {
                ok &= EC_GROUP_check(EC_KEY_get0_group(eck), ctx);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                ok &= ossl_ec_key_public_check_quick(eck, ctx);
            } else {
                ok &= ossl_ec_key_public_check(eck, ctx);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= ossl_ec_key_private_check(eck);
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            ok &= ossl_ec_key_pairwise_check(eck, ctx);
        }

        BN_CTX_free(ctx);
    }
    ok
}

/// `struct ec_gen_ctx` — `ec_kmgmt.c:955-971`, without the `FIPS_MODULE`-only indicator.
#[repr(C)]
struct EcGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *group_name` — owned.
    group_name: *mut c_char,
    /// `char *encoding` — owned.
    encoding: *mut c_char,
    /// `char *pt_format` — owned.
    pt_format: *mut c_char,
    /// `char *group_check` — owned.
    group_check: *mut c_char,
    /// `char *field_type` — owned.
    field_type: *mut c_char,
    /// `BIGNUM *p, *a, *b, *order, *cofactor`.
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    order: *mut BigNum,
    cofactor: *mut BigNum,
    /// `unsigned char *gen, *seed` — owned.
    gen: *mut u8,
    seed: *mut u8,
    /// `size_t gen_len, seed_len`.
    gen_len: usize,
    seed_len: usize,
    /// `int selection`.
    selection: c_int,
    /// `int ecdh_mode`.
    ecdh_mode: c_int,
    /// `EC_GROUP *gen_group` — owned.
    gen_group: *mut EcGroup,
    /// `unsigned char *dhkem_ikm` — owned.
    dhkem_ikm: *mut u8,
    /// `size_t dhkem_ikmlen`.
    dhkem_ikmlen: usize,
}

/// `static void *ec_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ec_kmgmt.c:973-993`. The `OSSL_FIPS_IND_INIT(gctx)` line is not this profile's.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn ec_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    if is_running() == 0 || (selection & EC_POSSIBLE_SELECTIONS) == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation; `provctx` is the caller's.
        unsafe {
            (*gctx).libctx = prov_libctx_of(provctx);
            (*gctx).selection = selection;
            (*gctx).ecdh_mode = 0;
        }
        // SAFETY: `gctx` is non-NULL; `params` is the caller's array.
        if unsafe { ec_gen_set_params(gctx.cast(), params) } == 0 {
            // SAFETY: `gctx` is this call's own allocation, not yet published.
            unsafe { ec_gen_cleanup(gctx.cast()) };
            return ptr::null_mut();
        }
    }
    gctx.cast()
}

/// `static void *sm2_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `ec_kmgmt.c:997-1010`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn sm2_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    let gctx = unsafe { ec_gen_init(provctx, selection, params) };

    if !gctx.is_null() {
        // SAFETY: `gctx` is the `EcGenCtx` `ec_gen_init` just returned and has not been published.
        let gctx = gctx.cast::<EcGenCtx>();
        // SAFETY: `gctx` is this call's own context.
        unsafe {
            if !(*gctx).group_name.is_null() {
                return gctx.cast();
            }
            (*gctx).group_name = CRYPTO_strdup(c"sm2".as_ptr(), FILE, 1005);
            if !(*gctx).group_name.is_null() {
                return gctx.cast();
            }
        }
        // SAFETY: `gctx` is this call's own context, not yet published.
        unsafe { ec_gen_cleanup(gctx.cast()) };
    }
    ptr::null_mut()
}

/// `static int ec_gen_set_group(void *genctx, const EC_GROUP *src)` — `ec_kmgmt.c:1014-1027`.
///
/// # Safety
/// `genctx` is a live `EcGenCtx`; `src` is live.
unsafe fn ec_gen_set_group(genctx: *mut c_void, src: *const EcGroup) -> c_int {
    let gctx = genctx.cast::<EcGenCtx>();

    // SAFETY: `src` is live and the copy is this call's own.
    let group = unsafe { EC_GROUP_dup(src) };
    if group.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_EC_KMGMT_1021) };
        return 0;
    }
    // SAFETY: `gctx` is live; its own group is released and replaced.
    unsafe {
        EC_GROUP_free((*gctx).gen_group);
        (*gctx).gen_group = group;
    }
    1
}

/// `static int ec_gen_set_template(void *genctx, void *templ)` — `ec_kmgmt.c:1029-1040`.
///
/// # Safety
/// The keymgmt `gen_set_template` dispatch contract.
unsafe extern "C" fn ec_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int {
    let gctx = genctx.cast::<EcGenCtx>();
    let ec = templ.cast::<EcKey>();

    if is_running() == 0 || gctx.is_null() || ec.is_null() {
        return 0;
    }
    // SAFETY: both objects are non-NULL past the guard.
    let ec_group = unsafe { EC_KEY_get0_group(ec) };
    if ec_group.is_null() {
        return 0;
    }
    // SAFETY: `gctx` is live and `ec_group` is the template's.
    unsafe { ec_gen_set_group(gctx.cast(), ec_group) }
}

/// `static int ec_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `ec_kmgmt.c:1079-1113`.
///
/// The `OSSL_FIPS_IND_SET_CTX_PARAM` line is not this profile's. The C's four `COPY_*` macros are
/// written out at each site, because a Rust macro that could `goto err` from inside an expression
/// is a control-flow scheme of ours rather than the authority's.
///
/// # Safety
/// `genctx` is a live `EcGenCtx`; `params` is NULL or key-terminated.
unsafe fn ec_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<EcGenCtx>();

    // SAFETY: `gctx` is live and `params` is the caller's array; every field written is its own.
    unsafe {
        let mut p = OSSL_PARAM_locate_const(params, P_USE_COFACTOR_ECDH);
        if !p.is_null() && OSSL_PARAM_get_int(p, &mut (*gctx).ecdh_mode) == 0 {
            return 0;
        }

        // COPY_UTF8_PARAM, five times.
        for (key, field) in [
            (P_GROUP_NAME, &raw mut (*gctx).group_name),
            (P_EC_FIELD_TYPE, &raw mut (*gctx).field_type),
            (P_EC_ENCODING, &raw mut (*gctx).encoding),
            (P_EC_POINT_CONVERSION_FORMAT, &raw mut (*gctx).pt_format),
            (P_EC_GROUP_CHECK_TYPE, &raw mut (*gctx).group_check),
        ] {
            p = OSSL_PARAM_locate_const(params, key);
            if !p.is_null() {
                if (*p).data_type != OSSL_PARAM_UTF8_STRING {
                    return 0;
                }
                CRYPTO_free((*field).cast(), FILE, 1090);
                *field = CRYPTO_strdup((*p).data.cast(), FILE, 1090);
                if (*field).is_null() {
                    return 0;
                }
            }
        }

        // COPY_BN_PARAM, five times.
        for (key, field) in [
            (P_EC_P, &raw mut (*gctx).p),
            (P_EC_A, &raw mut (*gctx).a),
            (P_EC_B, &raw mut (*gctx).b),
            (P_EC_ORDER, &raw mut (*gctx).order),
            (P_EC_COFACTOR, &raw mut (*gctx).cofactor),
        ] {
            p = OSSL_PARAM_locate_const(params, key);
            if !p.is_null() {
                if (*field).is_null() {
                    *field = BN_new();
                }
                if (*field).is_null() || OSSL_PARAM_get_BN(p, field) == 0 {
                    return 0;
                }
            }
        }

        // COPY_OCTET_PARAM, three times.
        for (key, field, len) in [
            (P_EC_SEED, &raw mut (*gctx).seed, &raw mut (*gctx).seed_len),
            (
                P_EC_GENERATOR,
                &raw mut (*gctx).gen,
                &raw mut (*gctx).gen_len,
            ),
            (
                P_DHKEM_IKM,
                &raw mut (*gctx).dhkem_ikm,
                &raw mut (*gctx).dhkem_ikmlen,
            ),
        ] {
            p = OSSL_PARAM_locate_const(params, key);
            if !p.is_null() {
                if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                    return 0;
                }
                CRYPTO_free((*field).cast(), FILE, 1063);
                *len = (*p).data_size;
                *field = CRYPTO_memdup((*p).data, (*p).data_size, FILE, 1065).cast::<u8>();
                if (*field).is_null() {
                    return 0;
                }
            }
        }
    }
    1
}

/// `static int ec_gen_set_group_from_params(struct ec_gen_ctx *gctx)` — `ec_kmgmt.c:1115-1190`.
///
/// # Safety
/// `gctx` is a live `EcGenCtx`.
#[allow(unused_assignments)] // the authority initialises `params` and `group` and assigns both before their only reads
unsafe fn ec_gen_set_group_from_params(gctx: *mut EcGenCtx) -> c_int {
    let mut ret: c_int = 0;
    let mut params: *mut OsslParam = ptr::null_mut();
    let mut group: *mut EcGroup = ptr::null_mut();

    let bld = OSSL_PARAM_BLD_new();
    if bld.is_null() {
        return 0;
    }

    // SAFETY: `gctx` is live; `bld` is this call's own builder; the values are its own pointers.
    unsafe {
        if !(*gctx).encoding.is_null()
            && OSSL_PARAM_BLD_push_utf8_string(bld, P_EC_ENCODING, (*gctx).encoding, 0) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        if !(*gctx).pt_format.is_null()
            && OSSL_PARAM_BLD_push_utf8_string(
                bld,
                P_EC_POINT_CONVERSION_FORMAT,
                (*gctx).pt_format,
                0,
            ) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        if !(*gctx).group_name.is_null() {
            if OSSL_PARAM_BLD_push_utf8_string(bld, P_GROUP_NAME, (*gctx).group_name, 0) == 0 {
                OSSL_PARAM_BLD_free(bld);
                return ret;
            }
            /* Ignore any other parameters if there is a group name */
            params = OSSL_PARAM_BLD_to_param(bld);
            if params.is_null() {
                OSSL_PARAM_BLD_free(bld);
                return ret;
            }
            group = EC_GROUP_new_from_params(params, (*gctx).libctx, ptr::null());
            if group.is_null() {
                OSSL_PARAM_free(params);
                OSSL_PARAM_BLD_free(bld);
                return ret;
            }

            EC_GROUP_free((*gctx).gen_group);
            (*gctx).gen_group = group;
            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
            return 1;
        } else if !(*gctx).field_type.is_null() {
            if OSSL_PARAM_BLD_push_utf8_string(bld, P_EC_FIELD_TYPE, (*gctx).field_type, 0) == 0 {
                OSSL_PARAM_BLD_free(bld);
                return ret;
            }
        } else {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }
        if (*gctx).p.is_null()
            || (*gctx).a.is_null()
            || (*gctx).b.is_null()
            || (*gctx).order.is_null()
            || OSSL_PARAM_BLD_push_BN(bld, P_EC_P, (*gctx).p) == 0
            || OSSL_PARAM_BLD_push_BN(bld, P_EC_A, (*gctx).a) == 0
            || OSSL_PARAM_BLD_push_BN(bld, P_EC_B, (*gctx).b) == 0
            || OSSL_PARAM_BLD_push_BN(bld, P_EC_ORDER, (*gctx).order) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        if !(*gctx).cofactor.is_null()
            && OSSL_PARAM_BLD_push_BN(bld, P_EC_COFACTOR, (*gctx).cofactor) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        if !(*gctx).seed.is_null()
            && OSSL_PARAM_BLD_push_octet_string(
                bld,
                P_EC_SEED,
                (*gctx).seed.cast(),
                (*gctx).seed_len,
            ) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        if (*gctx).gen.is_null()
            || OSSL_PARAM_BLD_push_octet_string(
                bld,
                P_EC_GENERATOR,
                (*gctx).gen.cast(),
                (*gctx).gen_len,
            ) == 0
        {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        params = OSSL_PARAM_BLD_to_param(bld);
        if params.is_null() {
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }
        group = EC_GROUP_new_from_params(params, (*gctx).libctx, ptr::null());
        if group.is_null() {
            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
            return ret;
        }

        EC_GROUP_free((*gctx).gen_group);
        (*gctx).gen_group = group;

        ret = 1;
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
    }
    ret
}

/// `static OSSL_PARAM settable[]` of `ec_gen_settable_params` — `ec_kmgmt.c:1195-1211`, without the
/// `FIPS_MODULE`-only key-check entry.
static EC_GEN_SETTABLE_PARAMS: [OsslParam; 14] = [
    param_utf8_string(P_GROUP_NAME),
    param_int(P_USE_COFACTOR_ECDH),
    param_utf8_string(P_EC_ENCODING),
    param_utf8_string(P_EC_POINT_CONVERSION_FORMAT),
    param_utf8_string(P_EC_FIELD_TYPE),
    param_bn(P_EC_P),
    param_bn(P_EC_A),
    param_bn(P_EC_B),
    param_octet_string(P_EC_GENERATOR),
    param_bn(P_EC_ORDER),
    param_bn(P_EC_COFACTOR),
    param_octet_string(P_EC_SEED),
    param_octet_string(P_DHKEM_IKM),
    END,
];

/// `static const OSSL_PARAM *ec_gen_settable_params(void *genctx, void *provctx)` —
/// `ec_kmgmt.c:1192-1213`.
unsafe extern "C" fn ec_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    EC_GEN_SETTABLE_PARAMS.as_ptr()
}

/// `static OSSL_PARAM known_ec_gen_gettable_ctx_params[]` — `ec_kmgmt.c:1218-1221`, which is the
/// empty table without `FIPS_MODULE`'s indicator.
static EC_GEN_GETTABLE_PARAMS: [OsslParam; 1] = [END];

/// `static const OSSL_PARAM *ec_gen_gettable_params(void *genctx, void *provctx)` —
/// `ec_kmgmt.c:1215-1223`.
unsafe extern "C" fn ec_gen_gettable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    EC_GEN_GETTABLE_PARAMS.as_ptr()
}

/// `static int ec_gen_get_params(void *genctx, OSSL_PARAM *params)` — `ec_kmgmt.c:1225-1236`. The
/// `OSSL_FIPS_IND_GET_CTX_PARAM` call is not this profile's, so the function answers 1.
///
/// # Safety
/// The keymgmt `gen_get_params` dispatch contract.
unsafe extern "C" fn ec_gen_get_params(genctx: *mut c_void, _params: *mut OsslParam) -> c_int {
    if genctx.is_null() {
        return 0;
    }
    1
}

/// `static int ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)` — `ec_kmgmt.c:1238-1245`.
///
/// # Safety
/// `ec` is live; `group` is NULL or live.
unsafe fn ec_gen_assign_group(ec: *mut EcKey, group: *mut EcGroup) -> c_int {
    if group.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_EC_KMGMT_1241) };
        return 0;
    }
    // SAFETY: `ec` is live and `group` is the generator's own.
    unsafe { c_int::from(EC_KEY_set_group(ec, group) > 0) }
}

/// `static void *ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` — `ec_kmgmt.c:1250-1312`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
#[allow(unused_assignments)] // the authority initialises `ret` to 0 and assigns it before its only read
unsafe extern "C" fn ec_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcGenCtx>();
    let mut ret: c_int = 0;

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `gctx` is non-NULL past the guard.
    let ec = unsafe { EC_KEY_new_ex((*gctx).libctx, ptr::null()) };
    if ec.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` and `ec` are live; the group is the generator's own.
    unsafe {
        if (*gctx).gen_group.is_null() {
            if ec_gen_set_group_from_params(gctx) == 0 {
                EC_KEY_free(ec);
                return ptr::null_mut();
            }
        } else {
            if !(*gctx).encoding.is_null() {
                let flags = ossl_ec_encoding_name2id((*gctx).encoding.cast_const());

                if flags < 0 {
                    EC_KEY_free(ec);
                    return ptr::null_mut();
                }
                EC_GROUP_set_asn1_flag((*gctx).gen_group, flags);
            }
            if !(*gctx).pt_format.is_null() {
                let format = ossl_ec_pt_format_name2id((*gctx).pt_format.cast_const());

                if format < 0 {
                    EC_KEY_free(ec);
                    return ptr::null_mut();
                }
                EC_GROUP_set_point_conversion_form((*gctx).gen_group, format);
            }
        }
        // `#ifdef FIPS_MODULE ossl_fips_ind_ec_key_check(...)` is not this profile's arm.

        /* We must always assign a group, no matter what */
        ret = ec_gen_assign_group(ec, (*gctx).gen_group);

        /* Whether you want it or not, you get a keypair, not just one half */
        if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            // The `#ifndef FIPS_MODULE` DHKEM-IKM arm compiles.
            if !(*gctx).dhkem_ikm.is_null() && (*gctx).dhkem_ikmlen != 0 {
                ret = c_int::from(
                    ret != 0
                        && ossl_ec_generate_key_dhkem(ec, (*gctx).dhkem_ikm, (*gctx).dhkem_ikmlen)
                            != 0,
                );
            } else {
                ret = c_int::from(ret != 0 && EC_KEY_generate_key(ec) != 0);
            }
        }

        if (*gctx).ecdh_mode != -1 {
            ret =
                c_int::from(ret != 0 && ossl_ec_set_ecdh_cofactor_mode(ec, (*gctx).ecdh_mode) != 0);
        }

        if !(*gctx).group_check.is_null() {
            ret = c_int::from(
                ret != 0
                    && ossl_ec_set_check_group_type_from_name(ec, (*gctx).group_check.cast_const())
                        != 0,
            );
        }

        if ret != 0 {
            return ec.cast();
        }
        /* Something went wrong, throw the key away */
        EC_KEY_free(ec);
    }
    ptr::null_mut()
}

/// `static void *sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` —
/// `ec_kmgmt.c:1319-1362`.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
#[allow(unused_assignments)] // the authority initialises `ret` to 1 and assigns it before its only read
unsafe extern "C" fn sm2_gen(
    genctx: *mut c_void,
    _osslcb: Option<OsslCallback>,
    _cbarg: *mut c_void,
) -> *mut c_void {
    let gctx = genctx.cast::<EcGenCtx>();
    let mut ret: c_int = 1;

    if gctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `gctx` is non-NULL past the guard.
    let ec = unsafe { EC_KEY_new_ex((*gctx).libctx, ptr::null()) };
    if ec.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` and `ec` are live; the group is the generator's own.
    unsafe {
        if (*gctx).gen_group.is_null() {
            if ec_gen_set_group_from_params(gctx) == 0 {
                EC_KEY_free(ec);
                return ptr::null_mut();
            }
        } else {
            if !(*gctx).encoding.is_null() {
                let flags = ossl_ec_encoding_name2id((*gctx).encoding.cast_const());

                if flags < 0 {
                    EC_KEY_free(ec);
                    return ptr::null_mut();
                }
                EC_GROUP_set_asn1_flag((*gctx).gen_group, flags);
            }
            if !(*gctx).pt_format.is_null() {
                let format = ossl_ec_pt_format_name2id((*gctx).pt_format.cast_const());

                if format < 0 {
                    EC_KEY_free(ec);
                    return ptr::null_mut();
                }
                EC_GROUP_set_point_conversion_form((*gctx).gen_group, format);
            }
        }

        /* We must always assign a group, no matter what */
        ret = ec_gen_assign_group(ec, (*gctx).gen_group);

        /* Whether you want it or not, you get a keypair, not just one half */
        if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            ret = c_int::from(ret != 0 && EC_KEY_generate_key(ec) != 0);
        }

        if ret != 0 {
            return ec.cast();
        }
        EC_KEY_free(ec);
    }
    ptr::null_mut()
}

/// `static void ec_gen_cleanup(void *genctx)` — `ec_kmgmt.c:1366-1387`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn ec_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<EcGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's context, allocated by `ec_gen_init`.
    unsafe {
        CRYPTO_clear_free((*gctx).dhkem_ikm.cast(), (*gctx).dhkem_ikmlen, FILE, 1373);
        EC_GROUP_free((*gctx).gen_group);
        crate::bn::bignum::BN_free((*gctx).p);
        crate::bn::bignum::BN_free((*gctx).a);
        crate::bn::bignum::BN_free((*gctx).b);
        crate::bn::bignum::BN_free((*gctx).order);
        crate::bn::bignum::BN_free((*gctx).cofactor);
        CRYPTO_free((*gctx).group_name.cast(), FILE, 1380);
        CRYPTO_free((*gctx).field_type.cast(), FILE, 1381);
        CRYPTO_free((*gctx).pt_format.cast(), FILE, 1382);
        CRYPTO_free((*gctx).encoding.cast(), FILE, 1383);
        CRYPTO_free((*gctx).seed.cast(), FILE, 1384);
        CRYPTO_free((*gctx).gen.cast(), FILE, 1385);
        CRYPTO_free(gctx.cast(), FILE, 1386);
    }
}

/// `static void *common_load(const void *reference, size_t reference_sz, int sm2_wanted)` —
/// `ec_kmgmt.c:1389-1406`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe fn common_load(
    reference: *const c_void,
    reference_sz: usize,
    sm2_wanted: c_int,
) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut EcKey>() {
        // The contents of the reference is the address to our object.
        // SAFETY: `reference` is readable for `reference_sz` bytes and the authority detaches the
        // object it names.
        unsafe {
            let slot = reference.cast::<*mut EcKey>().cast_mut();
            let ec = *slot;

            if common_check_sm2(ec, sm2_wanted) == 0 {
                return ptr::null_mut();
            }

            /* We grabbed, so we detach it */
            *slot = ptr::null_mut();
            return ec.cast();
        }
    }
    ptr::null_mut()
}

/// `static void *ec_load(const void *reference, size_t reference_sz)` — `ec_kmgmt.c:1408-1411`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn ec_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { common_load(reference, reference_sz, 0) }
}

/// `static void *sm2_load(const void *reference, size_t reference_sz)` — `ec_kmgmt.c:1415-1418`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn sm2_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { common_load(reference, reference_sz, 1) }
}

/// `static void *ec_dup(const void *keydata_from, int selection)` — `ec_kmgmt.c:1422-1427`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn ec_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract.
        return unsafe { ossl_ec_key_dup(keydata_from.cast(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `const OSSL_DISPATCH ossl_ec_keymgmt_functions[]` — `ec_kmgmt.c:1429-1459`. Twenty-four slots,
/// the authority's, in its order.
pub(crate) static EC_KEYMGMT_FUNCTIONS: [OsslDispatch; 25] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: ec_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: ec_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        function: ec_gen_set_template as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: ec_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: ec_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
        function: ec_gen_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
        function: ec_gen_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: ec_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: ec_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: ec_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: ec_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: ec_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: ec_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: ec_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: ec_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: ec_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: ec_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: ec_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: ec_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: ec_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: ec_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: ec_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        function: ec_query_operation_name as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: ec_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_sm2_keymgmt_functions[]` — `ec_kmgmt.c:1463-1490`. Twenty-two slots:
/// the `SM2` row has no `GEN_GET_PARAMS`/`GEN_GETTABLE_PARAMS` pair.
pub(crate) static SM2_KEYMGMT_FUNCTIONS: [OsslDispatch; 23] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: sm2_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: sm2_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        function: ec_gen_set_template as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: ec_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: ec_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: sm2_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: ec_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: sm2_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: ec_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: sm2_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: sm2_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: ec_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: sm2_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: ec_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: ec_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: sm2_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: sm2_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: ec_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: ec_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: ec_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        function: sm2_query_operation_name as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: ec_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
