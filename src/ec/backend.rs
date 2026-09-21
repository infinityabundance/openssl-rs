//! `crypto/ec/ec_backend.c` — the provider group/key backend the `EC_GROUP` object reaches,
//! Phase 8.7.
//!
//! Eight hundred and thirty-four lines: **seventeen internals** and seven file-static helpers.
//! The unit is the EC counterpart of `ffc_backend.c`, and its four jobs are distinct:
//!
//! * the **name/id maps** the provider spells as strings — the encoding (`explicit`/`named_curve`),
//!   the point conversion format and the group-check type — with their two-way lookups;
//! * `ossl_ec_group_todata` and its static `ec_group_explicit_todata`, which are what
//!   [`crate::ec::lib::EC_GROUP_to_params`] serialises a group with, and which are the reason
//!   `EC_GROUP_to_params` and `EC_GROUP_new_from_params` waited for this unit;
//! * the key-pair `fromdata` half — `ossl_ec_key_fromdata`, `ossl_ec_group_fromdata`,
//!   `ossl_ec_key_otherparams_fromdata` and their statics — which is the provider's import path
//!   into an `EC_KEY`;
//! * `ossl_ec_key_dup`, the group and key copier [`crate::ec::key::EC_KEY_dup`] calls, which is
//!   the one name of this unit another *landed* module reads.
//!
//! ## The ASN.1/X.509 tail landed with D351, and the divergence row shrank to one name
//!
//! `ossl_ec_key_param_from_x509_algor` and `ossl_ec_key_from_pkcs8` are the unit's
//! `#ifndef FIPS_MODULE` tail. Their bodies reach `X509_ALGOR_get0`, `d2i_ECParameters`,
//! `d2i_ECPrivateKey` and `PKCS8_pkey_get0` — `crypto/ec/ec_asn1.c`'s template machinery and
//! `crypto/x509`'s algorithm object, which were 8.8's and slice E's when D340 withheld them.
//! **Both are in the crate now** (D345's `ec_asn1.c` family, D348's `x_algor.c`, D349's
//! `p8_pkey.c`), so D351 transcribes the pair and the `forensics/prerequisites.json` divergence
//! row that covered these names shrinks to `ossl_x509_algor_is_sm2` — which stays withheld, and
//! for the reason D340 gave: its body reaches `d2i_ECPKParameters` and its only caller is the
//! provider half, which is not in this crate.
//!
//! The unit's one refusal coordinate `CRYPTO_R_TOO_SMALL_BUFFER` belongs to
//! [`crate::param_build_set`], not here; every raise below is an `EC_R_*`/`ERR_R_*` site from
//! `crypto/ec/ec_backend.c` itself.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::p8_pkey::{PKCS8_pkey_get0, Pkcs8PrivKeyInfo};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::bn::bignum::{
    bn_get_top, bn_wexpand, BN_clear_free, BN_copy, BN_is_one, BN_is_zero, BN_new, BN_secure_new,
    BN_set_flags, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BnCtx};
use crate::ec::asn1::{d2i_ECParameters, d2i_ECPrivateKey};
use crate::ec::curve::EC_GROUP_new_by_curve_name_ex;
use crate::ec::key::EC_KEY_new_ex;
use crate::ec::key::{
    ossl_ec_key_get0_propq, ossl_ec_key_get_libctx, EC_KEY_clear_flags, EC_KEY_free,
    EC_KEY_get0_group, EC_KEY_get_enc_flags, EC_KEY_set_conv_form, EC_KEY_set_enc_flags,
    EC_KEY_set_flags, EC_KEY_set_group, EC_KEY_set_private_key, EC_KEY_set_public_key,
    EC_FLAG_CHECK_NAMED_GROUP, EC_FLAG_CHECK_NAMED_GROUP_MASK, EC_FLAG_CHECK_NAMED_GROUP_NIST,
    EC_FLAG_COFACTOR_ECDH, EC_PKEY_NO_PUBKEY,
};
use crate::ec::kmeth::{ossl_ec_key_new_method_int, EC_KEY_OpenSSL, EC_KEY_get_method};
use crate::ec::lib::EC_GROUP_set_asn1_flag;
use crate::ec::lib::{
    ossl_ec_group_new_ex, EC_GROUP_copy, EC_GROUP_free, EC_GROUP_get0_cofactor,
    EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed, EC_GROUP_get_asn1_flag,
    EC_GROUP_get_curve, EC_GROUP_get_curve_name, EC_GROUP_get_field_type,
    EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len, EC_GROUP_new_from_params,
    EC_POINT_copy, EC_POINT_free, EC_POINT_new,
};
use crate::ec::oct::EC_POINT_oct2point;
use crate::ec::support::OSSL_EC_curve_nid2name;
use crate::ec::{EcGroup, EcKey, EcPoint};
use crate::evp::pkey_ctx::{OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE};
use crate::param_build_set::{
    ossl_param_build_set_bn, ossl_param_build_set_int, ossl_param_build_set_octet_string,
    ossl_param_build_set_utf8_string,
};
use crate::params::build::OSSL_PARAM_BLD;
use crate::params::{
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_ptr,
    OSSL_PARAM_locate_const, OsslParam, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{CRYPTO_dup_ex_data, CRYPTO_EX_INDEX_EC_KEY};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    Asn1Object, NID_X9_62_characteristic_two_field, NID_X9_62_prime_field, NID_undef, OBJ_obj2nid,
};
use crate::runtime::str::OPENSSL_strcasecmp;

/// The translation-unit coordinate the `OPENSSL_free` sites in this unit are attributed to.
const FILE: *const c_char = c"crypto/ec/ec_backend.c".as_ptr();

// SAFETY: the array is a compile-time constant whose two `ptr` fields are `'static` string
// literals, and it is never written; a shared reference to it is therefore safe to share between
// threads.
unsafe impl Sync for OsslItem {}

/// `OSSL_ITEM` — `include/openssl/core.h`'s `struct ossl_item_st { int id; const char *ptr; }`.
///
/// The three name/id maps below are arrays of these, and the two-way lookups walk them in
/// declaration order, which is why the *first* match wins and the order is load-bearing.
#[repr(C)]
struct OsslItem {
    id: c_int,
    ptr: *const c_char,
}

/// `static const OSSL_ITEM encoding_nameid_map[]` — `crypto/ec/ec_backend.c:32-35`.
static ENCODING_NAMEID_MAP: [OsslItem; 2] = [
    OsslItem {
        id: OPENSSL_EC_EXPLICIT_CURVE,
        ptr: c"explicit".as_ptr(),
    },
    OsslItem {
        id: OPENSSL_EC_NAMED_CURVE,
        ptr: c"named_curve".as_ptr(),
    },
];

/// `static const OSSL_ITEM check_group_type_nameid_map[]` — `crypto/ec/ec_backend.c:37-41`.
static CHECK_GROUP_TYPE_NAMEID_MAP: [OsslItem; 3] = [
    OsslItem {
        id: 0,
        ptr: c"default".as_ptr(),
    },
    OsslItem {
        id: EC_FLAG_CHECK_NAMED_GROUP,
        ptr: c"named".as_ptr(),
    },
    OsslItem {
        id: EC_FLAG_CHECK_NAMED_GROUP_NIST,
        ptr: c"named-nist".as_ptr(),
    },
];

/// `static const OSSL_ITEM format_nameid_map[]` — `crypto/ec/ec_backend.c:43-47`.
static FORMAT_NAMEID_MAP: [OsslItem; 3] = [
    OsslItem {
        id: crate::ec::POINT_CONVERSION_UNCOMPRESSED,
        ptr: c"uncompressed".as_ptr(),
    },
    OsslItem {
        id: crate::ec::POINT_CONVERSION_COMPRESSED,
        ptr: c"compressed".as_ptr(),
    },
    OsslItem {
        id: crate::ec::POINT_CONVERSION_HYBRID,
        ptr: c"hybrid".as_ptr(),
    },
];

// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-652`, the bit set
// `ossl_ec_key_dup` copies per member.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `int ossl_ec_encoding_name2id(const char *name)` — `crypto/ec/ec_backend.c:49-62`.
///
/// A NULL name answers `OPENSSL_EC_NAMED_CURVE` (1), not an error: the provider's default when
/// nothing was asked for. No match answers **-1**.
///
/// # Safety
///
/// `name` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_encoding_name2id(name: *const c_char) -> c_int {
    if name.is_null() {
        return OPENSSL_EC_NAMED_CURVE;
    }
    for row in ENCODING_NAMEID_MAP.iter() {
        // SAFETY: `name` is NUL-terminated and each `ptr` is a `'static` literal.
        if unsafe { OPENSSL_strcasecmp(name, row.ptr) } == 0 {
            return row.id;
        }
    }
    -1
}

/// `static char *ec_param_encoding_id2name(int id)` — `crypto/ec/ec_backend.c:64-73`.
fn ec_param_encoding_id2name(id: c_int) -> *const c_char {
    for row in ENCODING_NAMEID_MAP.iter() {
        if id == row.id {
            return row.ptr;
        }
    }
    ptr::null()
}

/// `char *ossl_ec_check_group_type_id2name(int id)` — `crypto/ec/ec_backend.c:75-84`.
#[no_mangle]
pub extern "C" fn ossl_ec_check_group_type_id2name(id: c_int) -> *const c_char {
    for row in CHECK_GROUP_TYPE_NAMEID_MAP.iter() {
        if id == row.id {
            return row.ptr;
        }
    }
    ptr::null()
}

/// `static int ec_check_group_type_name2id(const char *name)` — `crypto/ec/ec_backend.c:86-99`.
///
/// # Safety
///
/// `name` is NULL or NUL-terminated.
unsafe fn ec_check_group_type_name2id(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }
    for row in CHECK_GROUP_TYPE_NAMEID_MAP.iter() {
        // SAFETY: `name` is NUL-terminated and each `ptr` is a `'static` literal.
        if unsafe { OPENSSL_strcasecmp(name, row.ptr) } == 0 {
            return row.id;
        }
    }
    -1
}

/// `int ossl_ec_set_check_group_type_from_name(EC_KEY *ec, const char *name)` —
/// `crypto/ec/ec_backend.c:101-110`.
///
/// A name that matches no row answers 0 **without touching the key's flags**; a match clears the
/// whole two-bit mask before setting the new mode, so `named` followed by `named-nist` is
/// `named-nist` and not both.
///
/// # Safety
///
/// `ec` is live; `name` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_set_check_group_type_from_name(
    ec: *mut EcKey,
    name: *const c_char,
) -> c_int {
    // SAFETY: `name` is NULL or NUL-terminated.
    let flags = unsafe { ec_check_group_type_name2id(name) };
    if flags == -1 {
        return 0;
    }
    // SAFETY: `ec` is live per the contract.
    unsafe {
        EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK);
        EC_KEY_set_flags(ec, flags);
    }
    1
}

/// `static int ec_set_check_group_type_from_param(EC_KEY *ec, const OSSL_PARAM *p)` —
/// `crypto/ec/ec_backend.c:112-129`.
///
/// A `UTF8_STRING` is read in place; a `UTF8_PTR` through `OSSL_PARAM_get_utf8_ptr`; any other
/// type leaves `status` 0 and the call answers 0.
///
/// # Safety
///
/// `ec` is live; `p` is a live `OSSL_PARAM`.
unsafe fn ec_set_check_group_type_from_param(ec: *mut EcKey, p: *const OsslParam) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut name: *const c_char = ptr::null();
        let mut status = false;

        if (*p).data_type == OSSL_PARAM_UTF8_STRING {
            name = (*p).data.cast();
            status = !name.is_null();
        } else if (*p).data_type == OSSL_PARAM_UTF8_PTR {
            status = OSSL_PARAM_get_utf8_ptr(p, &mut name) != 0;
        }
        if status {
            return ossl_ec_set_check_group_type_from_name(ec, name);
        }
        0
    }
}

/// `int ossl_ec_pt_format_name2id(const char *name)` — `crypto/ec/ec_backend.c:131-144`.
///
/// A NULL name answers `POINT_CONVERSION_UNCOMPRESSED` (4); no match answers -1.
///
/// # Safety
///
/// `name` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_pt_format_name2id(name: *const c_char) -> c_int {
    if name.is_null() {
        return crate::ec::POINT_CONVERSION_UNCOMPRESSED;
    }
    for row in FORMAT_NAMEID_MAP.iter() {
        // SAFETY: `name` is NUL-terminated and each `ptr` is a `'static` literal.
        if unsafe { OPENSSL_strcasecmp(name, row.ptr) } == 0 {
            return row.id;
        }
    }
    -1
}

/// `char *ossl_ec_pt_format_id2name(int id)` — `crypto/ec/ec_backend.c:146-155`.
#[no_mangle]
pub extern "C" fn ossl_ec_pt_format_id2name(id: c_int) -> *const c_char {
    for row in FORMAT_NAMEID_MAP.iter() {
        if id == row.id {
            return row.ptr;
        }
    }
    ptr::null()
}

/// `static int ec_group_explicit_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
/// OSSL_PARAM params[], BN_CTX *bnctx, unsigned char **genbuf)` — `crypto/ec/ec_backend.c:157-286`.
///
/// Writes the explicit parameters a caller asked for — `p`, `a`, `b`, the order, the field type,
/// the generator octets, the optional cofactor and seed — into the builder when one is supplied or
/// into a located descriptor otherwise. The `tmpl != NULL || param != NULL` guards are what make a
/// parameter **optional**: a field the caller did not ask for is not computed, so this function
/// does not require a complete group.
///
/// `OPENSSL_NO_EC2M` is not defined on this profile, so the characteristic-two arm takes the
/// short-name path rather than raising `EC_R_GF2M_NOT_SUPPORTED`.
///
/// # Safety
///
/// `group` is live; `tmpl` is NULL or a live builder; `params` is NULL or a key-terminated
/// descriptor array; `bnctx` is a live `BN_CTX`; `genbuf` is a writable pointer slot.
unsafe fn ec_group_explicit_todata(
    group: *const EcGroup,
    tmpl: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    bnctx: *mut BnCtx,
    genbuf: *mut *mut core::ffi::c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = false;
        const P_P: *const c_char = c"p".as_ptr();
        const P_A: *const c_char = c"a".as_ptr();
        const P_B: *const c_char = c"b".as_ptr();
        const P_ORDER: *const c_char = c"order".as_ptr();
        const P_FIELD_TYPE: *const c_char = c"field-type".as_ptr();
        const P_GENERATOR: *const c_char = c"generator".as_ptr();
        const P_COFACTOR: *const c_char = c"cofactor".as_ptr();
        const P_SEED: *const c_char = c"seed".as_ptr();

        let fid = EC_GROUP_get_field_type(group);

        let field_type: *const c_char = if fid == NID_X9_62_prime_field {
            c"prime-field".as_ptr()
        } else if fid == NID_X9_62_characteristic_two_field {
            c"characteristic-two-field".as_ptr()
        } else {
            // SAFETY: a compile-time-constant site (`ec_backend.c:180`, EC_R_INVALID_FIELD).
            raise_site(&err_sites::EC_BACKEND_180);
            return 0;
        };

        'build: {
            let param_p = OSSL_PARAM_locate_const(params, P_P);
            let param_a = OSSL_PARAM_locate_const(params, P_A);
            let param_b = OSSL_PARAM_locate_const(params, P_B);
            if !tmpl.is_null() || !param_p.is_null() || !param_a.is_null() || !param_b.is_null() {
                let p = BN_CTX_get(bnctx);
                let a = BN_CTX_get(bnctx);
                let b = BN_CTX_get(bnctx);

                if b.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:193`, ERR_R_BN_LIB).
                    raise_site(&err_sites::EC_BACKEND_193);
                    break 'build;
                }

                if EC_GROUP_get_curve(group, p, a, b, bnctx) == 0 {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:198`, EC_R_INVALID_CURVE).
                    raise_site(&err_sites::EC_BACKEND_198);
                    break 'build;
                }
                if ossl_param_build_set_bn(tmpl, params, P_P, p) == 0
                    || ossl_param_build_set_bn(tmpl, params, P_A, a) == 0
                    || ossl_param_build_set_bn(tmpl, params, P_B, b) == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:204`, ERR_R_CRYPTO_LIB).
                    raise_site(&err_sites::EC_BACKEND_204);
                    break 'build;
                }
            }

            let param = OSSL_PARAM_locate_const(params, P_ORDER);
            if !tmpl.is_null() || !param.is_null() {
                let order = EC_GROUP_get0_order(group);

                if order.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:214`,
                    // EC_R_INVALID_GROUP_ORDER).
                    raise_site(&err_sites::EC_BACKEND_214);
                    break 'build;
                }
                if ossl_param_build_set_bn(tmpl, params, P_ORDER, order) == 0 {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:219`, ERR_R_CRYPTO_LIB).
                    raise_site(&err_sites::EC_BACKEND_219);
                    break 'build;
                }
            }

            let param = OSSL_PARAM_locate_const(params, P_FIELD_TYPE);
            if (!tmpl.is_null() || !param.is_null())
                && ossl_param_build_set_utf8_string(tmpl, params, P_FIELD_TYPE, field_type) == 0
            {
                // SAFETY: a compile-time-constant site (`ec_backend.c:229`, ERR_R_CRYPTO_LIB).
                raise_site(&err_sites::EC_BACKEND_229);
                break 'build;
            }

            let param = OSSL_PARAM_locate_const(params, P_GENERATOR);
            if !tmpl.is_null() || !param.is_null() {
                let genpt = EC_GROUP_get0_generator(group);
                let genform = EC_GROUP_get_point_conversion_form(group);

                if genpt.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:241`,
                    // EC_R_INVALID_GENERATOR).
                    raise_site(&err_sites::EC_BACKEND_241);
                    break 'build;
                }
                let genbuf_len =
                    crate::ec::oct::EC_POINT_point2buf(group, genpt, genform, genbuf, bnctx);
                if genbuf_len == 0 {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:246`,
                    // EC_R_INVALID_GENERATOR).
                    raise_site(&err_sites::EC_BACKEND_246);
                    break 'build;
                }
                if ossl_param_build_set_octet_string(tmpl, params, P_GENERATOR, *genbuf, genbuf_len)
                    == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:252`, ERR_R_CRYPTO_LIB).
                    raise_site(&err_sites::EC_BACKEND_252);
                    break 'build;
                }
            }

            let param = OSSL_PARAM_locate_const(params, P_COFACTOR);
            if !tmpl.is_null() || !param.is_null() {
                let cofactor = EC_GROUP_get0_cofactor(group);

                if !cofactor.is_null()
                    && ossl_param_build_set_bn(tmpl, params, P_COFACTOR, cofactor) == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:264`, ERR_R_CRYPTO_LIB).
                    raise_site(&err_sites::EC_BACKEND_264);
                    break 'build;
                }
            }

            let param = OSSL_PARAM_locate_const(params, P_SEED);
            if !tmpl.is_null() || !param.is_null() {
                let seed = EC_GROUP_get0_seed(group);
                let seed_len = EC_GROUP_get_seed_len(group);

                if !seed.is_null()
                    && seed_len > 0
                    && ossl_param_build_set_octet_string(tmpl, params, P_SEED, seed, seed_len) == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:279`, ERR_R_CRYPTO_LIB).
                    raise_site(&err_sites::EC_BACKEND_279);
                    break 'build;
                }
            }
            ret = true;
        }
        ret as c_int
    }
}

/// `int ossl_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl, OSSL_PARAM params[],
/// OSSL_LIB_CTX *libctx, const char *propq, BN_CTX *bnctx, unsigned char **genbuf)` —
/// `crypto/ec/ec_backend.c:288-352`.
///
/// The provider's group serialiser. It always writes the point conversion format and the encoding
/// name; it writes the decoded-from-explicit flag; and it writes the explicit parameters whenever
/// there is no builder **or** the group names no curve — which is the authority's own reading of
/// "a specific parameter was asked for, or the curve is not named".
///
/// # Safety
///
/// As [`ec_group_explicit_todata`]; `libctx` is NULL or a live library context and `propq` is NULL
/// or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_todata(
    group: *const EcGroup,
    tmpl: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    libctx: *mut c_void,
    propq: *const c_char,
    bnctx: *mut BnCtx,
    genbuf: *mut *mut core::ffi::c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let _ = (libctx, propq);
        const P_POINT_CONVERSION_FORMAT: *const c_char = c"point-format".as_ptr();
        const P_ENCODING: *const c_char = c"encoding".as_ptr();
        const P_DECODED: *const c_char = c"decoded-from-explicit".as_ptr();
        const P_GROUP_NAME: *const c_char = c"group".as_ptr();

        if group.is_null() {
            // SAFETY: a compile-time-constant site (`ec_backend.c:298`, EC_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_BACKEND_298);
            return 0;
        }

        let genform = EC_GROUP_get_point_conversion_form(group);
        let pt_form_name = ossl_ec_pt_format_id2name(genform);
        if pt_form_name.is_null()
            || ossl_param_build_set_utf8_string(
                tmpl,
                params,
                P_POINT_CONVERSION_FORMAT,
                pt_form_name,
            ) == 0
        {
            // SAFETY: a compile-time-constant site (`ec_backend.c:308`, EC_R_INVALID_FORM).
            raise_site(&err_sites::EC_BACKEND_308);
            return 0;
        }
        let encoding_flag = EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE;
        let encoding_name = ec_param_encoding_id2name(encoding_flag);
        if encoding_name.is_null()
            || ossl_param_build_set_utf8_string(tmpl, params, P_ENCODING, encoding_name) == 0
        {
            // SAFETY: a compile-time-constant site (`ec_backend.c:317`, EC_R_INVALID_ENCODING).
            raise_site(&err_sites::EC_BACKEND_317);
            return 0;
        }

        if ossl_param_build_set_int(
            tmpl,
            params,
            P_DECODED,
            (*group).decoded_from_explicit_params,
        ) == 0
        {
            return 0;
        }

        let curve_nid = EC_GROUP_get_curve_name(group);

        // Get the explicit parameters in these two cases:
        // - We do not have a template, i.e. specific parameters are requested
        // - The curve is not a named curve
        let mut ret = false;
        'build: {
            if (tmpl.is_null() || curve_nid == NID_undef)
                && ec_group_explicit_todata(group, tmpl, params, bnctx, genbuf) == 0
            {
                break 'build;
            }

            if curve_nid != NID_undef {
                // Named curve.
                let curve_name = OSSL_EC_curve_nid2name(curve_nid);

                if curve_name.is_null()
                    || ossl_param_build_set_utf8_string(tmpl, params, P_GROUP_NAME, curve_name) == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_backend.c:345`, EC_R_INVALID_CURVE).
                    raise_site(&err_sites::EC_BACKEND_345);
                    break 'build;
                }
            }
            ret = true;
        }
        ret as c_int
    }
}

/// `int ossl_ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode)` — `crypto/ec/ec_backend.c:359-386`.
///
/// A cofactor of one makes the mode a no-op that still answers 1 — there is nothing to multiply.
/// Any other mode than 0 or 1 answers 0.
///
/// # Safety
///
/// `ec` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_set_ecdh_cofactor_mode(ec: *mut EcKey, mode: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ecg = EC_KEY_get0_group(ec);
        if !(0..=1).contains(&mode) {
            return 0;
        }
        let cofactor = EC_GROUP_get0_cofactor(ecg);
        if cofactor.is_null() {
            return 0;
        }
        // ECDH cofactor mode has no effect if cofactor is 1.
        if BN_is_one(cofactor) != 0 {
            return 1;
        }

        if mode == 1 {
            EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
        } else if mode == 0 {
            EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);
        }
        1
    }
}

/// `int ossl_ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)` —
/// `crypto/ec/ec_backend.c:396-495`.
///
/// Imports a bare key pair. The private half is deliberately over-allocated: `bn_get_top(order) + 2`
/// words and `BN_FLG_CONSTTIME`, so that neither the scalar's bit length nor a reallocation during
/// the import is observable. A caller **must** have set the group first; without one the call
/// answers 0 immediately.
///
/// # Safety
///
/// `ec` is live and has a group; `params` is NULL or a key-terminated descriptor array.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_fromdata(
    ec: *mut EcKey,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        const P_PUB_KEY: *const c_char = c"pub".as_ptr();
        const P_PRIV_KEY: *const c_char = c"priv".as_ptr();

        let mut ok = false;
        let mut priv_key: *mut BigNum = ptr::null_mut();
        let mut pub_key: *mut core::ffi::c_uchar = ptr::null_mut();
        let mut pub_key_len: usize = 0;
        let mut pub_point: *mut EcPoint = ptr::null_mut();

        let ecg = EC_KEY_get0_group(ec);
        if ecg.is_null() {
            return 0;
        }

        let param_pub_key = OSSL_PARAM_locate_const(params, P_PUB_KEY);
        let param_priv_key = if include_private != 0 {
            OSSL_PARAM_locate_const(params, P_PRIV_KEY)
        } else {
            ptr::null()
        };

        let ctx: *mut BnCtx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
        if ctx.is_null() {
            return ok as c_int;
        }

        'build: {
            if !param_pub_key.is_null() {
                let got = OSSL_PARAM_get_octet_string(
                    param_pub_key,
                    (&raw mut pub_key).cast::<*mut c_void>(),
                    0,
                    &mut pub_key_len,
                ) != 0;
                pub_point = EC_POINT_new(ecg);
                if !got
                    || pub_point.is_null()
                    || EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx) == 0
                {
                    break 'build;
                }
            }

            if !param_priv_key.is_null() && include_private != 0 {
                let order = EC_GROUP_get0_order(ecg);
                if order.is_null() || BN_is_zero(order) != 0 {
                    break 'build;
                }

                let fixed_words = bn_get_top(order) + 2;

                priv_key = BN_secure_new();
                if priv_key.is_null() {
                    break 'build;
                }
                if bn_wexpand(priv_key, fixed_words).is_null() {
                    break 'build;
                }
                BN_set_flags(priv_key, BN_FLG_CONSTTIME);

                if OSSL_PARAM_get_BN(param_priv_key, &mut priv_key) == 0 {
                    break 'build;
                }
            }

            if !priv_key.is_null() && EC_KEY_set_private_key(ec, priv_key) == 0 {
                break 'build;
            }

            if !pub_point.is_null() && EC_KEY_set_public_key(ec, pub_point) == 0 {
                break 'build;
            }

            ok = true;
        }

        BN_CTX_free(ctx);
        BN_clear_free(priv_key);
        CRYPTO_free(pub_key.cast(), FILE, 492);
        EC_POINT_free(pub_point);
        ok as c_int
    }
}

/// `int ossl_ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[])` —
/// `crypto/ec/ec_backend.c:497-514`.
///
/// The group is built by [`EC_GROUP_new_from_params`] and released **whether or not**
/// `EC_KEY_set_group` took it, because `EC_KEY_set_group` copies the pointer's referent into its
/// own group.
///
/// # Safety
///
/// `ec` is NULL or live; `params` is NULL or a key-terminated descriptor array.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_fromdata(ec: *mut EcKey, params: *const OsslParam) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok = false;

        if ec.is_null() {
            return 0;
        }

        let group: *mut EcGroup = EC_GROUP_new_from_params(
            params,
            ossl_ec_key_get_libctx(ec),
            ossl_ec_key_get0_propq(ec),
        );

        if EC_KEY_set_group(ec, group) == 0 {
            EC_GROUP_free(group);
            return ok as c_int;
        }
        ok = true;
        EC_GROUP_free(group);
        ok as c_int
    }
}

/// `static int ec_key_point_format_fromdata(EC_KEY *ec, const OSSL_PARAM params[])` —
/// `crypto/ec/ec_backend.c:516-530`.
///
/// # Safety
///
/// `ec` is live; `params` is NULL or a key-terminated descriptor array.
unsafe fn ec_key_point_format_fromdata(ec: *mut EcKey, params: *const OsslParam) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        const P_POINT_CONVERSION_FORMAT: *const c_char = c"point-format".as_ptr();
        let mut format: c_int = -1;

        let p = OSSL_PARAM_locate_const(params, P_POINT_CONVERSION_FORMAT);
        if !p.is_null() {
            if ossl_ec_pt_format_param2id(p, &mut format) == 0 {
                // SAFETY: a compile-time-constant site (`ec_backend.c:524`, EC_R_INVALID_FORM).
                raise_site(&err_sites::EC_BACKEND_524);
                return 0;
            }
            EC_KEY_set_conv_form(ec, format);
        }
        1
    }
}

/// `static int ec_key_group_check_fromdata(EC_KEY *ec, const OSSL_PARAM params[])` —
/// `crypto/ec/ec_backend.c:532-540`.
///
/// # Safety
///
/// `ec` is live; `params` is NULL or a key-terminated descriptor array.
unsafe fn ec_key_group_check_fromdata(ec: *mut EcKey, params: *const OsslParam) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        const P_GROUP_CHECK_TYPE: *const c_char = c"group-check".as_ptr();
        let p = OSSL_PARAM_locate_const(params, P_GROUP_CHECK_TYPE);
        if !p.is_null() {
            return ec_set_check_group_type_from_param(ec, p);
        }
        1
    }
}

/// `static int ec_set_include_public(EC_KEY *ec, int include)` —
/// `crypto/ec/ec_backend.c:542-552`.
///
/// The flag is **inverted**: `include == 0` *sets* `EC_PKEY_NO_PUBKEY`.
///
/// # Safety
///
/// `ec` is live.
unsafe fn ec_set_include_public(ec: *mut EcKey, include: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut flags = EC_KEY_get_enc_flags(ec);

        if include == 0 {
            flags |= EC_PKEY_NO_PUBKEY as c_uint;
        } else {
            flags &= !(EC_PKEY_NO_PUBKEY as c_uint);
        }
        EC_KEY_set_enc_flags(ec, flags);
        1
    }
}

/// `int ossl_ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[])` —
/// `crypto/ec/ec_backend.c:554-583`.
///
/// The three set-only parameters a key carries outside its domain parameters: the cofactor mode,
/// the include-public flag and the point conversion format, plus the group-check type through
/// [`ec_key_group_check_fromdata`]. All four are optional.
///
/// # Safety
///
/// `ec` is NULL or live; `params` is NULL or a key-terminated descriptor array.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_otherparams_fromdata(
    ec: *mut EcKey,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        const P_USE_COFACTOR_ECDH: *const c_char = c"use-cofactor-flag".as_ptr();
        const P_EC_INCLUDE_PUBLIC: *const c_char = c"include-public".as_ptr();

        if ec.is_null() {
            return 0;
        }

        let p = OSSL_PARAM_locate_const(params, P_USE_COFACTOR_ECDH);
        if !p.is_null() {
            let mut mode: c_int = 0;

            if OSSL_PARAM_get_int(p, &mut mode) == 0
                || ossl_ec_set_ecdh_cofactor_mode(ec, mode) == 0
            {
                return 0;
            }
        }

        let p = OSSL_PARAM_locate_const(params, P_EC_INCLUDE_PUBLIC);
        if !p.is_null() {
            let mut include: c_int = 1;

            if OSSL_PARAM_get_int(p, &mut include) == 0 || ec_set_include_public(ec, include) == 0 {
                return 0;
            }
        }
        if ec_key_point_format_fromdata(ec, params) == 0 {
            return 0;
        }
        if ec_key_group_check_fromdata(ec, params) == 0 {
            return 0;
        }
        1
    }
}

/// `int ossl_ec_key_is_foreign(const EC_KEY *ec)` — `crypto/ec/ec_backend.c:585-592`.
///
/// `#ifndef FIPS_MODULE` is compiled here: an engine-held key or a key whose method is not the
/// default answers 1. Since this crate can build no engine, the engine test is false on every
/// object it makes and the method test is the reachable one.
///
/// # Safety
///
/// `ec` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_is_foreign(ec: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !(*ec).engine.is_null() || EC_KEY_get_method(ec) != EC_KEY_OpenSSL() {
            return 1;
        }
        0
    }
}

/// `EC_KEY *ossl_ec_key_dup(const EC_KEY *src, int selection)` —
/// `crypto/ec/ec_backend.c:594-675`.
///
/// The copier [`crate::ec::key::EC_KEY_dup`] calls with `OSSL_KEYMGMT_SELECT_ALL`. It copies each
/// half only when the caller's `selection` asks for it, refuses a key whose halves are present
/// without a group ("no parameter-less keys allowed"), and runs the group method's `keycopy` and
/// then the key method's `copy` — each guarded, so a table with a NULL column is a table the copy
/// simply does not run.
///
/// # Safety
///
/// `src` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_dup(src: *const EcKey, selection: c_int) -> *mut EcKey {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if src.is_null() {
            // SAFETY: a compile-time-constant site (`ec_backend.c:599`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_BACKEND_599);
            return ptr::null_mut();
        }

        let ret = ossl_ec_key_new_method_int((*src).libctx, (*src).propq, (*src).engine);
        if ret.is_null() {
            return ptr::null_mut();
        }

        'build: {
            // Copy the parameters.
            if !(*src).group.is_null() && (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
                (*ret).group =
                    ossl_ec_group_new_ex((*src).libctx, (*src).propq, (*(*src).group).meth);
                if (*ret).group.is_null() || EC_GROUP_copy((*ret).group, (*src).group) == 0 {
                    break 'build;
                }

                if !(*src).meth.is_null() {
                    (*ret).meth = (*src).meth;
                }
            }

            // Copy the public key.
            if !(*src).pub_key.is_null() && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                if (*ret).group.is_null() {
                    // no parameter-less keys allowed
                    break 'build;
                }
                (*ret).pub_key = EC_POINT_new((*ret).group);
                if (*ret).pub_key.is_null() || EC_POINT_copy((*ret).pub_key, (*src).pub_key) == 0 {
                    break 'build;
                }
            }

            // Copy the private key.
            if !(*src).priv_key.is_null() && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                if (*ret).group.is_null() {
                    // no parameter-less keys allowed
                    break 'build;
                }
                (*ret).priv_key = BN_new();
                if (*ret).priv_key.is_null() || BN_copy((*ret).priv_key, (*src).priv_key).is_null()
                {
                    break 'build;
                }
                if let Some(keycopy) = (*(*(*ret).group).meth).keycopy {
                    if keycopy(ret, src) == 0 {
                        break 'build;
                    }
                }
            }

            // Copy the rest.
            if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
                (*ret).enc_flag = (*src).enc_flag;
                (*ret).conv_form = (*src).conv_form;
            }

            (*ret).version = (*src).version;
            (*ret).flags = (*src).flags;

            if CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY, &mut (*ret).ex_data, &(*src).ex_data) == 0
            {
                break 'build;
            }

            if !(*ret).meth.is_null() {
                if let Some(copy) = (*(*ret).meth).copy {
                    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != OSSL_KEYMGMT_SELECT_KEYPAIR {
                        break 'build;
                    }
                    if copy(ret, src) == 0 {
                        break 'build;
                    }
                }
            }

            return ret;
        }

        EC_KEY_free(ret);
        ptr::null_mut()
    }
}

/// `int ossl_ec_encoding_param2id(const OSSL_PARAM *p, int *id)` —
/// `crypto/ec/ec_backend.c:677-701`.
///
/// # Safety
///
/// `p` is a live `OSSL_PARAM`; `id` is a writable `int` slot.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_encoding_param2id(p: *const OsslParam, id: *mut c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut name: *const c_char = ptr::null();
        let mut status = false;

        if (*p).data_type == OSSL_PARAM_UTF8_STRING {
            // The OSSL_PARAM functions have no support for this.
            name = (*p).data.cast();
            status = !name.is_null();
        } else if (*p).data_type == OSSL_PARAM_UTF8_PTR {
            status = OSSL_PARAM_get_utf8_ptr(p, &mut name) != 0;
        }
        if status {
            let i = ossl_ec_encoding_name2id(name);

            if i >= 0 {
                *id = i;
                return 1;
            }
        }
        0
    }
}

/// `int ossl_ec_pt_format_param2id(const OSSL_PARAM *p, int *id)` —
/// `crypto/ec/ec_backend.c:703-727`.
///
/// # Safety
///
/// `p` is a live `OSSL_PARAM`; `id` is a writable `int` slot.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_pt_format_param2id(p: *const OsslParam, id: *mut c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut name: *const c_char = ptr::null();
        let mut status = false;

        if (*p).data_type == OSSL_PARAM_UTF8_STRING {
            // The OSSL_PARAM functions have no support for this.
            name = (*p).data.cast();
            status = !name.is_null();
        } else if (*p).data_type == OSSL_PARAM_UTF8_PTR {
            status = OSSL_PARAM_get_utf8_ptr(p, &mut name) != 0;
        }
        if status {
            let i = ossl_ec_pt_format_name2id(name);

            if i >= 0 {
                *id = i;
                return 1;
            }
        }
        0
    }
}

// `V_ASN1_UNDEF`/`V_ASN1_SEQUENCE`/`V_ASN1_OBJECT` are read through `crate::asn1::layout`.

/// `EC_KEY *ossl_ec_key_param_from_x509_algor(const X509_ALGOR *palg, OSSL_LIB_CTX *libctx, const
/// char *propq)` — `ec_backend.c:759-807`. Internal, inside `#ifndef FIPS_MODULE`.
///
/// The `ECParameters` decoder's front door, and the **three-way dispatch on the parameter's type**
/// is the whole function's shape:
///
/// * `V_ASN1_SEQUENCE` — explicit parameters: the parameter is an `ASN1_STRING` holding DER, and
///   `d2i_ECParameters` decodes it **into the key it is handed** (`&eckey`), which is why the
///   failure test is against the returned pointer rather than against `eckey`.
/// * `V_ASN1_OBJECT` — a named curve: the identifier is the parameter, the group is looked up by
///   NID, and — the half a reader gets wrong — the group is marked `OPENSSL_EC_NAMED_CURVE`
///   **before** it is installed, because the flag is the group's and not the key's.
/// * anything else — the same `EC_R_DECODE_ERROR` a failed `d2i_ECParameters` answers.
///
/// The key is allocated **before** the dispatch, so every one of the three arms falls into the
/// same `ecerr:` label, which releases the key and the group. In the named-curve arm the group is
/// released on the success path too — *after* `EC_KEY_set_group` has copied what it needs — so
/// `group` is NULL there by the time `ecerr:` could run.
///
/// `#[allow(dead_code)]`'s reason: **its callers are [`ossl_ec_key_from_pkcs8`] below and 8.8's
/// `ec_ameth.c` `priv_decode`**, and the PKCS#8 path is unreached until that callback lands.
///
/// # Safety
/// `palg` is a live `X509_ALGOR`; `libctx` is NULL or live; `propq` is NULL or NUL-terminated. On
/// success the answer is a new `EC_KEY` the caller owns.
#[allow(dead_code)] // read by ossl_ec_key_from_pkcs8 and 8.8's ec_ameth.c `priv_decode`
pub(crate) unsafe fn ossl_ec_key_param_from_x509_algor(
    palg: *const X509Algor,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcKey {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ptype: c_int = 0;
        let mut pval: *const c_void = ptr::null();
        let mut group: *mut EcGroup = ptr::null_mut();

        X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, palg);
        let mut eckey = EC_KEY_new_ex(libctx, propq);
        if eckey.is_null() {
            raise_site(&err_sites::EC_BACKEND_769);
            return ecerr(eckey, group);
        }

        if ptype == crate::asn1::layout::V_ASN1_SEQUENCE {
            let pstr = pval.cast::<Asn1String>();
            let mut pm = (*pstr).data.cast_const();
            let pmlen = (*pstr).length;

            // `&eckey` is the authority's `&eckey`: the decoder writes the slot back when it
            // succeeds, and leaves it alone when it fails, which is why the release below still
            // sees the key it allocated.
            if d2i_ECParameters(&mut eckey, &mut pm, pmlen as core::ffi::c_long).is_null() {
                raise_site(&err_sites::EC_BACKEND_779);
                return ecerr(eckey, group);
            }
        } else if ptype == crate::asn1::layout::V_ASN1_OBJECT {
            let poid = pval.cast::<Asn1Object>();

            /*
             * type == V_ASN1_OBJECT => the parameters are given by an asn1 OID
             */
            group = EC_GROUP_new_by_curve_name_ex(libctx, propq, OBJ_obj2nid(poid));
            if group.is_null() {
                return ecerr(eckey, group);
            }
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
            if EC_KEY_set_group(eckey, group) == 0 {
                return ecerr(eckey, group);
            }
            EC_GROUP_free(group);
        } else {
            raise_site(&err_sites::EC_BACKEND_797);
            return ecerr(eckey, group);
        }

        eckey
    }
}

/// The authority's `ecerr:` label of [`ossl_ec_key_param_from_x509_algor`].
///
/// # Safety
/// `eckey` and `group` are each NULL or this call's own.
unsafe fn ecerr(eckey: *mut EcKey, group: *mut EcGroup) -> *mut EcKey {
    // SAFETY: each pointer is NULL or this call's own, per the contract.
    unsafe {
        EC_KEY_free(eckey);
        EC_GROUP_free(group);
    }
    ptr::null_mut()
}

/// `EC_KEY *ossl_ec_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const
/// char *propq)` — `ec_backend.c:809-833`. Internal, inside `#ifndef FIPS_MODULE`.
///
/// The PKCS#8 decoder's EC half, and its shape is the **two-step** one the DH and DSA twins also
/// have, with one difference worth naming: the parameters and the private scalar are read by two
/// different entry points whose ownership rules differ. `ossl_ec_key_param_from_x509_algor`
/// returns a fresh key that already carries the group, and `d2i_ECPrivateKey` then decodes **into**
/// that key — which is why a failure there releases the whole object rather than a partial one and
/// why the group the first call installed is not re-created.
///
/// `libctx` and `propq` are forwarded rather than unused: the parameter lookup needs them to
/// resolve a named curve through the provider's group constructors.
///
/// `#[allow(dead_code)]`'s reason: **8.8's `ec_ameth.c` `priv_decode` callback is its reader**.
///
/// # Safety
/// `p8inf` is a live `PKCS8_PRIV_KEY_INFO`; on success the answer is a new `EC_KEY` the caller
/// owns.
#[allow(dead_code)] // read by 8.8's ec_ameth.c `priv_decode`
pub(crate) unsafe fn ossl_ec_key_from_pkcs8(
    p8inf: *const Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcKey {
    // SAFETY: the caller's contract.
    unsafe {
        let mut p: *const c_uchar = ptr::null();
        let mut pklen: c_int = 0;
        let mut palg: *const X509Algor = ptr::null();

        if PKCS8_pkey_get0(ptr::null_mut(), &mut p, &mut pklen, &mut palg, p8inf) == 0 {
            return ptr::null_mut();
        }
        let mut eckey = ossl_ec_key_param_from_x509_algor(palg, libctx, propq);
        if eckey.is_null() {
            return ecerr(eckey, ptr::null_mut());
        }

        /* We have parameters now set private key */
        if d2i_ECPrivateKey(&mut eckey, &mut p, pklen as core::ffi::c_long).is_null() {
            raise_site(&err_sites::EC_BACKEND_825);
            return ecerr(eckey, ptr::null_mut());
        }

        eckey
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_new};
    use crate::ec::key::EC_KEY_get0_group;
    use crate::ec::lib::{EC_GROUP_get_asn1_flag, EC_GROUP_get_curve_name};
    use crate::runtime::obj::{NID_X9_62_prime256v1, NID_undef};

    /// **The `V_ASN1_OBJECT` arm is the one that can be driven without DER**: an algorithm
    /// identifier whose parameter *is* a curve OID resolves through
    /// `EC_GROUP_new_by_curve_name_ex`, and — the half a reader gets wrong — the group is marked
    /// `OPENSSL_EC_NAMED_CURVE` before it is installed.
    #[test]
    fn a_named_curve_identifier_produces_a_key_with_that_group() {
        // SAFETY: `X509_ALGOR_new` answers a fresh object or NULL; `OBJ_nid2obj` an object or
        // NULL. Both are asserted.
        unsafe {
            let alg = X509_ALGOR_new();
            assert!(!alg.is_null());
            let obj = crate::runtime::obj::OBJ_nid2obj(NID_X9_62_prime256v1);
            assert!(!obj.is_null());
            assert_eq!(
                crate::asn1::x_algor::X509_ALGOR_set0(
                    alg,
                    obj,
                    crate::asn1::layout::V_ASN1_OBJECT,
                    obj.cast()
                ),
                1
            );

            let key = ossl_ec_key_param_from_x509_algor(alg, ptr::null_mut(), ptr::null());
            assert!(!key.is_null());
            let group = EC_KEY_get0_group(key);
            assert!(!group.is_null());
            assert_eq!(EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);
            assert_eq!(
                EC_GROUP_get_asn1_flag(group),
                crate::evp::pkey_ctx::OPENSSL_EC_NAMED_CURVE
            );
            EC_KEY_free(key);
            X509_ALGOR_free(alg);
        }
    }

    /// **The `else` arm is a refusal with an error raised**, and the object it allocated first is
    /// released by the shared `ecerr:` label. A `V_ASN1_NULL` parameter is the cheapest way to
    /// reach it, and it is what an identifier with no parameters at all looks like.
    #[test]
    fn an_identifier_that_is_neither_a_sequence_nor_an_object_is_refused() {
        // SAFETY: both calls answer a fresh object or NULL, which is asserted.
        unsafe {
            let alg = X509_ALGOR_new();
            assert!(!alg.is_null());
            let obj = crate::runtime::obj::OBJ_nid2obj(NID_X9_62_prime256v1);
            assert!(!obj.is_null());
            assert_eq!(
                crate::asn1::x_algor::X509_ALGOR_set0(
                    alg,
                    obj,
                    crate::asn1::layout::V_ASN1_NULL,
                    ptr::null_mut()
                ),
                1
            );

            let key = ossl_ec_key_param_from_x509_algor(alg, ptr::null_mut(), ptr::null());
            assert!(key.is_null());
            X509_ALGOR_free(alg);
        }
    }

    /// A named curve that does not exist is the same refusal reached one step later, from inside
    /// the `V_ASN1_OBJECT` arm: `EC_GROUP_new_by_curve_name_ex` answers NULL and the label
    /// releases the key. `NID_undef` is the OID this crate answers for an unresolvable
    /// identifier.
    #[test]
    fn a_curve_oid_that_resolves_to_no_group_is_refused() {
        // SAFETY: as above.
        unsafe {
            let alg = X509_ALGOR_new();
            let obj = crate::runtime::obj::OBJ_nid2obj(NID_undef);
            assert!(!alg.is_null() && !obj.is_null());
            assert_eq!(
                crate::asn1::x_algor::X509_ALGOR_set0(
                    alg,
                    obj,
                    crate::asn1::layout::V_ASN1_OBJECT,
                    ptr::null_mut()
                ),
                1
            );

            let key = ossl_ec_key_param_from_x509_algor(alg, ptr::null_mut(), ptr::null());
            assert!(key.is_null());
            X509_ALGOR_free(alg);
        }
    }

    // **`ossl_ec_key_from_pkcs8` has no arm here, and the reason is the container.** Its first act
    // is `PKCS8_pkey_get0`, so a test needs a live `PKCS8_PRIV_KEY_INFO` carrying an
    // `ECPrivateKey` — which means the `ECParameters`/`ECPrivateKey` DER encoders and a key to
    // encode. `RT-EC` already drives `d2i_ECPrivateKey` and `i2d_ECPrivateKey` over a generated
    // key, and D351's entry records that the PKCS#8 wrapper's own evidence is that arm plus this
    // module's two above; a hand-built container here would be a test of the test.
}
