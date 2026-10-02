//! `crypto/x509/v3_conf.c` — the extension-configuration surface. Phase 11.5, **landed whole but
//! for the two `X509_REQ` entry points**.
//!
//! `crypto/x509/v3_conf.c` is 599 lines. Phase 10.14.4 landed the **config-value layer** — the part
//! the extension tables call — and withheld the **extension-building chain** by name, because
//! every function in that chain funnels through `X509V3_EXT_get_nid` (`v3_lib.rs`, then withheld
//! behind the incomplete `standard_exts[]`, D456). That dispatch landed in `v3_lib.rs` (10.15), so
//! this slice lands the chain:
//!
//! * the helpers `v3_check_critical` (`:203-213`), `v3_check_generic` (`:216-232`),
//!   `v3_generic_extension` (`:235-278`), `generic_asn1` (`:280-292`), `delete_ext` (`:294-302`),
//!   `do_ext_nconf` (`:79-135`) and `X509V3_EXT_nconf_int` (`:34-56`), all `static`;
//! * the five construction entry points [`X509V3_EXT_nconf`] (`:58-62`),
//!   [`X509V3_EXT_nconf_nid`] (`:64-75`), [`X509V3_EXT_conf`] (`:495-508`),
//!   [`X509V3_EXT_conf_nid`] (`:510-523`) and [`X509V3_EXT_add_nconf_sk`] (`:309-350`);
//! * the six add-to-carrier wrappers [`X509V3_EXT_add_nconf`] (`:356-363`),
//!   [`X509V3_EXT_CRL_add_nconf`] (`:369-376`), [`X509V3_EXT_REQ_add_nconf`] (`:382-392`),
//!   [`X509V3_EXT_add_conf`] (`:552-565`), [`X509V3_EXT_CRL_add_conf`] (`:569-582`) and
//!   [`X509V3_EXT_REQ_add_conf`] (`:586-599`).
//!
//! ## What lands
//!
//! * the value/section accessors the tables read: [`X509V3_get_string`] (`:396-405`),
//!   [`X509V3_get_section`] (`:407-416`), [`X509V3_string_free`] (`:418-424`) and
//!   [`X509V3_section_free`] (`:426-432`);
//! * the two configuration-method tables and their callbacks — [`nconf_get_string`]/
//!   [`nconf_get_section`] over `NCONF_*` and [`conf_lhash_get_string`]/
//!   [`conf_lhash_get_section`] over the legacy `CONF_*` lhash API;
//! * the context setters [`X509V3_set_nconf`] (`:451-459`), [`X509V3_set_ctx`] (`:461-476`),
//!   [`X509V3_set_issuer_pkey`] (`:479-491`) and [`X509V3_set_conf_lhash`] (`:542-550`).
//!
//! ## `X509V3_EXT_i2d` and the encoder it wraps
//!
//! `X509V3_EXT_i2d` (`:191-200`) and the static `do_ext_i2d` (`:137-187`) it wraps are the encoder
//! `X509V3_add1_i2d` (`v3_lib.c:271`) and this unit's own `do_ext_nconf` call.
//! `X509V3_EXT_i2d` raises `X509V3_R_UNKNOWN_EXTENSION` (`:196`), and `do_ext_i2d` raises
//! `ERR_R_ASN1_LIB` at `:150`/`:158`/`:167` and `ERR_R_X509V3_LIB` at `:176`.
//!
//! ## The request wrappers, and why 11.4b lands them
//!
//! `X509V3_EXT_REQ_add_nconf` (`:382-392`) and `X509V3_EXT_REQ_add_conf` (`:586-599`) were withheld
//! through 11.5 because the first calls `X509_REQ_add_extensions` (`crypto/x509/x509_req.c`), which
//! that unit withheld while the `X509_EXTENSIONS` item was absent from `src/x509/x_exten.rs`, and
//! the second funnels through the first. 11.4b landed that item and the request functions over it,
//! so both wrappers land with them.
//!
//! ## The `X509V3_CTX` structure
//!
//! `struct v3_ext_ctx` (`include/openssl/x509v3.h.in:95-108`) is `x509v3.h`'s, Phase 11's by
//! header. It is defined here because this unit is its only authority manipulator and the
//! generals-name and generator units read it through the accessors above; the field order and
//! offsets are asserted. The `X509V3_CONF_METHOD` table (`x509v3.h.in:80-85`) is defined the same
//! way.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_conf.c` is **not** an entry in `gen_err_raise_sites.py` (the generator's covered
//! set is the closed-stratum file list), so its coordinates are **declared locally** with the
//! `err_sites::ErrSite` shape, as `src/store/store_register.rs` does. The value-layer sites are the
//! `X509V3_R_OPERATION_NOT_DEFINED` refusals of `X509V3_get_string`/`_get_section` and the
//! `ERR_R_PASSED_NULL_PARAMETER`/`ERR_R_PASSED_INVALID_ARGUMENT` refusals of the four setters. The
//! chain adds: `X509V3_EXT_nconf_int`'s two `X509V3_R_ERROR_IN_EXTENSION` refusals (`:48`, `:52`);
//! `do_ext_nconf`'s `X509V3_R_UNKNOWN_EXTENSION_NAME` (`:88`), `X509V3_R_UNKNOWN_EXTENSION`
//! (`:92`), `X509V3_R_INVALID_EXTENSION_STRING` (`:102`), `X509V3_R_NO_CONFIG_DATABASE` (`:118`)
//! and `X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED` (`:124`); and `v3_generic_extension`'s
//! `X509V3_R_EXTENSION_NAME_ERROR` (`:246`), `X509V3_R_EXTENSION_VALUE_ERROR` (`:257`) and
//! `ERR_R_ASN1_LIB` (`:263`). `do_ext_i2d`/`X509V3_EXT_i2d`'s five sites are declared above.
//!
//! ## One safety guard, recorded
//!
//! The authority's `X509V3_string_free`/`_section_free` dereference `ctx->db_meth` unconditionally.
//! Every real caller reaches them only after a successful accessor call, so `db_meth` is set; this
//! transcription adds a NULL check on `db_meth` so a misuse cannot be undefined behaviour in Rust.
//! No court drives the fault, so no observation differs.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::asn1::a_type::{i2d_ASN1_TYPE, ASN1_TYPE_free};
use crate::asn1::asn1_gen::ASN1_generate_v3;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::evp::pkey::EvpPkey;
use crate::runtime::bio::sys::{strcmp, strncmp};
use crate::runtime::conf::lib::{
    CONF_get_section, CONF_get_string, CONF_set_nconf, NCONF_free, NCONF_get_section,
    NCONF_get_string, NCONF_new,
};
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::ctype::ossl_isspace;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::lhash::OpenSslLhash;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_undef, OBJ_nid2sn, OBJ_sn2nid, OBJ_txt2obj};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::runtime::str::OPENSSL_hexstr2buf;
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_get_nid};
use crate::x509::v3_utl::{X509V3_conf_free, X509V3_parse_list};
use crate::x509::x509_req::{X509Req, X509_REQ_add_extensions};
use crate::x509::x509_v3::{
    X509_EXTENSION_create_by_NID, X509_EXTENSION_create_by_OBJ, X509_EXTENSION_get_object,
    X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext_by_OBJ,
};
use crate::x509::x_crl::X509Crl;
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};
use crate::x509::x_x509::X509;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `X509V3_R_OPERATION_NOT_DEFINED` — `include/openssl/x509v3err.h:76`.
const X509V3_R_OPERATION_NOT_DEFINED: c_int = 148;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h.in:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509V3_LIB` — `include/openssl/err.h`, `ERR_LIB_X509V3 | ERR_RFLAG_COMMON`.
const ERR_R_X509V3_LIB: c_int = 524322;
/// `X509V3_R_UNKNOWN_EXTENSION` — `include/openssl/x509v3err.h:87`.
const X509V3_R_UNKNOWN_EXTENSION: c_int = 129;
/// `X509V3_R_ERROR_IN_EXTENSION` — `include/openssl/x509v3err.h:34`.
const X509V3_R_ERROR_IN_EXTENSION: c_int = 128;
/// `X509V3_R_EXTENSION_NAME_ERROR` — `include/openssl/x509v3err.h:37`.
const X509V3_R_EXTENSION_NAME_ERROR: c_int = 115;
/// `X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED` — `include/openssl/x509v3err.h:39`.
const X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED: c_int = 103;
/// `X509V3_R_EXTENSION_VALUE_ERROR` — `include/openssl/x509v3err.h:40`.
const X509V3_R_EXTENSION_VALUE_ERROR: c_int = 116;
/// `X509V3_R_INVALID_EXTENSION_STRING` — `include/openssl/x509v3err.h:48`.
const X509V3_R_INVALID_EXTENSION_STRING: c_int = 105;
/// `X509V3_R_NO_CONFIG_DATABASE` — `include/openssl/x509v3err.h:69`.
const X509V3_R_NO_CONFIG_DATABASE: c_int = 136;
/// `X509V3_R_UNKNOWN_EXTENSION_NAME` — `include/openssl/x509v3err.h:88`.
const X509V3_R_UNKNOWN_EXTENSION_NAME: c_int = 130;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc`/`OPENSSL_free` expansions —
/// `crypto/x509/v3_conf.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_conf.c";
/// `do_ext_i2d`'s `OPENSSL_malloc(ext_len)` — `crypto/x509/v3_conf.c:161`.
const LINE_MALLOC_DER: c_int = 161;
/// `do_ext_i2d`'s `err:` `OPENSSL_free(ext_der)` — `crypto/x509/v3_conf.c:184`.
const LINE_FREE_DER: c_int = 184;

/// One `v3_conf.c` raise coordinate: the authority file's own line and function.
///
/// The stem is `V3_CONF`; the coordinates are declared here rather than generated because
/// `v3_conf.c` is not in `gen_err_raise_sites.py`'s covered set (see the module doc).
const fn v3_conf_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_conf.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `X509V3_get_string`'s refusal at `v3_conf.c:399`.
const V3_CONF_399: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(399, c"X509V3_get_string", X509V3_R_OPERATION_NOT_DEFINED);
/// `X509V3_get_section`'s refusal at `v3_conf.c:410`.
const V3_CONF_410: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(410, c"X509V3_get_section", X509V3_R_OPERATION_NOT_DEFINED);
/// `X509V3_set_nconf`'s NULL-context refusal at `v3_conf.c:454`.
const V3_CONF_454: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(454, c"X509V3_set_nconf", ERR_R_PASSED_NULL_PARAMETER);
/// `X509V3_set_ctx`'s NULL-context refusal at `v3_conf.c:465`.
const V3_CONF_465: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(465, c"X509V3_set_ctx", ERR_R_PASSED_NULL_PARAMETER);
/// `X509V3_set_issuer_pkey`'s NULL-context refusal at `v3_conf.c:482`.
const V3_CONF_482: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(482, c"X509V3_set_issuer_pkey", ERR_R_PASSED_NULL_PARAMETER);
/// `X509V3_set_issuer_pkey`'s no-subject refusal at `v3_conf.c:486`.
const V3_CONF_486: crate::runtime::err::err_sites::ErrSite = v3_conf_site(
    486,
    c"X509V3_set_issuer_pkey",
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `X509V3_set_conf_lhash`'s NULL-context refusal at `v3_conf.c:545`.
const V3_CONF_545: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(545, c"X509V3_set_conf_lhash", ERR_R_PASSED_NULL_PARAMETER);
/// `do_ext_i2d`'s ASN1-item encode failure at `v3_conf.c:150` (`ERR_R_ASN1_LIB`).
const V3_CONF_150: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(150, c"do_ext_i2d", ERR_R_ASN1_LIB);
/// `do_ext_i2d`'s old-style encode failure at `v3_conf.c:158` (`ERR_R_ASN1_LIB`).
const V3_CONF_158: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(158, c"do_ext_i2d", ERR_R_ASN1_LIB);
/// `do_ext_i2d`'s failed `ASN1_OCTET_STRING_new` at `v3_conf.c:167` (`ERR_R_ASN1_LIB`).
const V3_CONF_167: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(167, c"do_ext_i2d", ERR_R_ASN1_LIB);
/// `do_ext_i2d`'s failed `X509_EXTENSION_create_by_NID` at `v3_conf.c:176` (`ERR_R_X509V3_LIB`).
const V3_CONF_176: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(176, c"do_ext_i2d", ERR_R_X509V3_LIB);
/// `X509V3_EXT_i2d`'s unknown-extension refusal at `v3_conf.c:196`.
const V3_CONF_196: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(196, c"X509V3_EXT_i2d", X509V3_R_UNKNOWN_EXTENSION);
/// `X509V3_EXT_nconf_int`'s sectioned failure at `v3_conf.c:48`.
const V3_CONF_48: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(48, c"X509V3_EXT_nconf_int", X509V3_R_ERROR_IN_EXTENSION);
/// `X509V3_EXT_nconf_int`'s sectionless failure at `v3_conf.c:52`.
const V3_CONF_52: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(52, c"X509V3_EXT_nconf_int", X509V3_R_ERROR_IN_EXTENSION);
/// `do_ext_nconf`'s undefined-NID refusal at `v3_conf.c:88`.
const V3_CONF_88: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(88, c"do_ext_nconf", X509V3_R_UNKNOWN_EXTENSION_NAME);
/// `do_ext_nconf`'s unknown-NID refusal at `v3_conf.c:92`.
const V3_CONF_92: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(92, c"do_ext_nconf", X509V3_R_UNKNOWN_EXTENSION);
/// `do_ext_nconf`'s empty-value-list refusal at `v3_conf.c:102`.
const V3_CONF_102: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(102, c"do_ext_nconf", X509V3_R_INVALID_EXTENSION_STRING);
/// `do_ext_nconf`'s missing-config-database refusal at `v3_conf.c:118`.
const V3_CONF_118: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(118, c"do_ext_nconf", X509V3_R_NO_CONFIG_DATABASE);
/// `do_ext_nconf`'s unsupported-setting refusal at `v3_conf.c:124`.
const V3_CONF_124: crate::runtime::err::err_sites::ErrSite = v3_conf_site(
    124,
    c"do_ext_nconf",
    X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED,
);
/// `v3_generic_extension`'s bad-object-name refusal at `v3_conf.c:246`.
const V3_CONF_246: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(246, c"v3_generic_extension", X509V3_R_EXTENSION_NAME_ERROR);
/// `v3_generic_extension`'s undecodable-value refusal at `v3_conf.c:257`.
const V3_CONF_257: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(257, c"v3_generic_extension", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v3_generic_extension`'s failed `ASN1_OCTET_STRING_new` at `v3_conf.c:263` (`ERR_R_ASN1_LIB`).
const V3_CONF_263: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(263, c"v3_generic_extension", ERR_R_ASN1_LIB);

/// `X509V3_CTX_TEST` — `include/openssl/x509v3.h.in:96`.
pub const X509V3_CTX_TEST: c_int = 0x1;
/// `X509V3_CTX_REPLACE` — `include/openssl/x509v3.h.in:100`.
pub const X509V3_CTX_REPLACE: c_int = 0x2;

/// `X509V3_CONF_METHOD.get_string`.
pub type X509V3GetString =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_char>;
/// `X509V3_CONF_METHOD.get_section`.
pub type X509V3GetSection =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut OpenSslStack>;
/// `X509V3_CONF_METHOD.free_string`.
pub type X509V3FreeString = Option<unsafe extern "C" fn(*mut c_void, *mut c_char)>;
/// `X509V3_CONF_METHOD.free_section`.
pub type X509V3FreeSection = Option<unsafe extern "C" fn(*mut c_void, *mut OpenSslStack)>;

/// `struct X509V3_CONF_METHOD_st` — `include/openssl/x509v3.h.in:79-85`.
#[repr(C)]
pub struct X509V3ConfMethod {
    /// `char *(*get_string)(void *db, const char *section, const char *value)`.
    pub get_string: X509V3GetString,
    /// `STACK_OF(CONF_VALUE) *(*get_section)(void *db, const char *section)`.
    pub get_section: X509V3GetSection,
    /// `void (*free_string)(void *db, char *string)`.
    pub free_string: X509V3FreeString,
    /// `void (*free_section)(void *db, STACK_OF(CONF_VALUE) *section)`.
    pub free_section: X509V3FreeSection,
}

/// `struct v3_ext_ctx` — `X509V3_CTX`, from `include/openssl/x509v3.h.in:95-108`.
///
/// The header's field order: the flag word, the four certificate/request/CRL pointers, the
/// configuration method and its database, and the issuer key last.
#[repr(C)]
pub struct X509V3Ctx {
    /// `int flags` — `X509V3_CTX_TEST` / `X509V3_CTX_REPLACE`.
    pub flags: c_int,
    /// `X509 *issuer_cert`.
    pub issuer_cert: *mut X509,
    /// `X509 *subject_cert`.
    pub subject_cert: *mut X509,
    /// `X509_REQ *subject_req` — the request type is 10.14.11's, so this is an opaque slot.
    pub subject_req: *mut c_void,
    /// `X509_CRL *crl`.
    pub crl: *mut X509Crl,
    /// `X509V3_CONF_METHOD *db_meth`.
    pub db_meth: *mut X509V3ConfMethod,
    /// `void *db`.
    pub db: *mut c_void,
    /// `EVP_PKEY *issuer_pkey`.
    pub issuer_pkey: *mut EvpPkey,
}

const _: () = {
    assert!(core::mem::size_of::<X509V3Ctx>() == 64);
    assert!(core::mem::offset_of!(X509V3Ctx, flags) == 0);
    assert!(core::mem::offset_of!(X509V3Ctx, issuer_cert) == 8);
    assert!(core::mem::offset_of!(X509V3Ctx, subject_cert) == 16);
    assert!(core::mem::offset_of!(X509V3Ctx, subject_req) == 24);
    assert!(core::mem::offset_of!(X509V3Ctx, crl) == 32);
    assert!(core::mem::offset_of!(X509V3Ctx, db_meth) == 40);
    assert!(core::mem::offset_of!(X509V3Ctx, db) == 48);
    assert!(core::mem::offset_of!(X509V3Ctx, issuer_pkey) == 56);
};

/// `static char *nconf_get_string(void *db, const char *section, const char *value)` —
/// `v3_conf.c:434-437`.
///
/// # Safety
///
/// `db` is NULL or a live `CONF`; `section`/`value` are NULL or NUL-terminated.
unsafe extern "C" fn nconf_get_string(
    db: *mut c_void,
    section: *const c_char,
    value: *const c_char,
) -> *mut c_char {
    // SAFETY: the caller's contract makes `db` NULL or a live `CONF`.
    unsafe { NCONF_get_string(db.cast::<Conf>(), section, value) }
}

/// `static STACK_OF(CONF_VALUE) *nconf_get_section(void *db, const char *section)` —
/// `v3_conf.c:439-442`.
///
/// # Safety
///
/// `db` is NULL or a live `CONF`; `section` is NULL or NUL-terminated.
unsafe extern "C" fn nconf_get_section(
    db: *mut c_void,
    section: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract makes `db` NULL or a live `CONF`.
    unsafe { NCONF_get_section(db.cast::<Conf>(), section) }
}

/// `static X509V3_CONF_METHOD nconf_method` — `v3_conf.c:444-449`.
static NCONF_METHOD: X509V3ConfMethod = X509V3ConfMethod {
    get_string: Some(nconf_get_string),
    get_section: Some(nconf_get_section),
    free_string: None,
    free_section: None,
};

/// `static char *conf_lhash_get_string(void *db, const char *section, const char *value)` —
/// `v3_conf.c:525-528`.
///
/// # Safety
///
/// `db` is NULL or a live `LHASH_OF(CONF_VALUE)`; `section`/`value` are NULL or NUL-terminated.
unsafe extern "C" fn conf_lhash_get_string(
    db: *mut c_void,
    section: *const c_char,
    value: *const c_char,
) -> *mut c_char {
    // SAFETY: the caller's contract makes `db` NULL or a live lhash.
    unsafe { CONF_get_string(db.cast::<OpenSslLhash>(), section, value) }
}

/// `static STACK_OF(CONF_VALUE) *conf_lhash_get_section(void *db, const char *section)` —
/// `v3_conf.c:530-533`.
///
/// # Safety
///
/// `db` is NULL or a live `LHASH_OF(CONF_VALUE)`; `section` is NULL or NUL-terminated.
unsafe extern "C" fn conf_lhash_get_section(
    db: *mut c_void,
    section: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract makes `db` NULL or a live lhash.
    unsafe { CONF_get_section(db.cast::<OpenSslLhash>(), section) }
}

/// `static X509V3_CONF_METHOD conf_lhash_method` — `v3_conf.c:535-540`.
static CONF_LHASH_METHOD: X509V3ConfMethod = X509V3ConfMethod {
    get_string: Some(conf_lhash_get_string),
    get_section: Some(conf_lhash_get_section),
    free_string: None,
    free_section: None,
};

/// `char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section)` —
/// `crypto/x509/v3_conf.c:396-405`.
///
/// # Safety
///
/// `ctx` must be live; `name`/`section` are NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_string(
    ctx: *mut X509V3Ctx,
    name: *const c_char,
    section: *const c_char,
) -> *mut c_char {
    // SAFETY: `ctx` is live per the contract.
    let (db, db_meth) = unsafe { ((*ctx).db, (*ctx).db_meth) };
    if db.is_null() || db_meth.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_399) };
        return ptr::null_mut();
    }
    // SAFETY: `db_meth` is live; `get_string` was checked non-null by the authority's own `if`.
    match unsafe { (*db_meth).get_string } {
        // SAFETY: `db` and the strings are per the caller's contract.
        Some(f) => unsafe { f(db, name, section) },
        None => ptr::null_mut(),
    }
}

/// `STACK_OF(CONF_VALUE) *X509V3_get_section(X509V3_CTX *ctx, const char *section)` —
/// `crypto/x509/v3_conf.c:407-416`.
///
/// # Safety
///
/// `ctx` must be live; `section` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_section(
    ctx: *mut X509V3Ctx,
    section: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    let (db, db_meth) = unsafe { ((*ctx).db, (*ctx).db_meth) };
    if db.is_null() || db_meth.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_410) };
        return ptr::null_mut();
    }
    // SAFETY: `db_meth` is live; `get_section` is checked by the authority's own `if`.
    match unsafe { (*db_meth).get_section } {
        // SAFETY: `db` and `section` are per the caller's contract.
        Some(f) => unsafe { f(db, section) },
        None => ptr::null_mut(),
    }
}

/// `void X509V3_string_free(X509V3_CTX *ctx, char *str)` — `crypto/x509/v3_conf.c:418-424`.
///
/// # Safety
///
/// `ctx` must be live; `str` is NULL or a string this context produced.
#[no_mangle]
pub unsafe extern "C" fn X509V3_string_free(ctx: *mut X509V3Ctx, str_: *mut c_char) {
    if str_.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    let (db, db_meth) = unsafe { ((*ctx).db, (*ctx).db_meth) };
    if db_meth.is_null() {
        return;
    }
    // SAFETY: `db_meth` is live; the callback is optional.
    if let Some(f) = unsafe { (*db_meth).free_string } {
        // SAFETY: `db` and `str_` are per the caller's contract.
        unsafe { f(db, str_) };
    }
}

/// `void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)` —
/// `crypto/x509/v3_conf.c:426-432`.
///
/// # Safety
///
/// `ctx` must be live; `section` is NULL or a stack this context produced.
#[no_mangle]
pub unsafe extern "C" fn X509V3_section_free(ctx: *mut X509V3Ctx, section: *mut OpenSslStack) {
    if section.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    let (db, db_meth) = unsafe { ((*ctx).db, (*ctx).db_meth) };
    if db_meth.is_null() {
        return;
    }
    // SAFETY: `db_meth` is live; the callback is optional.
    if let Some(f) = unsafe { (*db_meth).free_section } {
        // SAFETY: `db` and `section` are per the caller's contract.
        unsafe { f(db, section) };
    }
}

/// `void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf)` — `crypto/x509/v3_conf.c:451-459`.
///
/// # Safety
///
/// `ctx` is NULL or live; `conf` is NULL or a live `CONF`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_nconf(ctx: *mut X509V3Ctx, conf: *mut Conf) {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_454) };
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).db_meth = core::ptr::addr_of!(NCONF_METHOD).cast_mut();
        (*ctx).db = conf.cast::<c_void>();
    }
}

/// `void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subj, X509_REQ *req, X509_CRL *crl,
/// int flags)` — `crypto/x509/v3_conf.c:461-476`.
///
/// # Safety
///
/// `ctx` is NULL or live; the certificate/request/CRL pointers are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_ctx(
    ctx: *mut X509V3Ctx,
    issuer: *mut X509,
    subj: *mut X509,
    req: *mut c_void,
    crl: *mut X509Crl,
    flags: c_int,
) {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_465) };
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).flags = flags;
        (*ctx).issuer_cert = issuer;
        (*ctx).subject_cert = subj;
        (*ctx).subject_req = req;
        (*ctx).crl = crl;
        (*ctx).db_meth = ptr::null_mut();
        (*ctx).db = ptr::null_mut();
        (*ctx).issuer_pkey = ptr::null_mut();
    }
}

/// `int X509V3_set_issuer_pkey(X509V3_CTX *ctx, EVP_PKEY *pkey)` —
/// `crypto/x509/v3_conf.c:479-491`.
///
/// # Safety
///
/// `ctx` is NULL or live; `pkey` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_issuer_pkey(ctx: *mut X509V3Ctx, pkey: *mut EvpPkey) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_482) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).subject_cert }.is_null() && !pkey.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_486) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).issuer_pkey = pkey };
    1
}

/// `void X509V3_set_conf_lhash(X509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash)` —
/// `crypto/x509/v3_conf.c:542-550`.
///
/// # Safety
///
/// `ctx` is NULL or live; `lhash` is NULL or a live `LHASH_OF(CONF_VALUE)`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_conf_lhash(ctx: *mut X509V3Ctx, lhash: *mut OpenSslLhash) {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&V3_CONF_545) };
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).db_meth = core::ptr::addr_of!(CONF_LHASH_METHOD).cast_mut();
        (*ctx).db = lhash.cast::<c_void>();
    }
}

/// `static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method, int ext_nid, int crit,
/// void *ext_struc)` — `crypto/x509/v3_conf.c:137-187`.
///
/// DER-encodes `ext_struc` (through the method's `it` when set, else its old-style `i2d`), wraps
/// the octets in an `ASN1_OCTET_STRING` and builds the extension with `X509_EXTENSION_create_by_NID`.
///
/// # Safety
///
/// `method` must be a live `X509V3_EXT_METHOD`; `ext_struc` is the internal structure that method's
/// `it`/`i2d` encodes.
unsafe fn do_ext_i2d(
    method: *const X509V3ExtMethod,
    ext_nid: c_int,
    crit: c_int,
    ext_struc: *mut c_void,
) -> *mut X509Extension {
    let mut ext_der: *mut c_uchar = ptr::null_mut();
    let mut ext_oct: *mut Asn1String = ptr::null_mut();

    /* Convert internal representation to DER. */
    // SAFETY: `method` is live.
    let it = unsafe { (*method).it };
    // SAFETY: `method` is live.
    let i2d = unsafe { (*method).i2d };
    let ext_len = if let Some(it) = it {
        // SAFETY: `ext_struc` is the value `it()` describes; `&mut ext_der` is a writable slot that
        // starts NULL, so the encoder allocates.
        let len = unsafe { ASN1_item_i2d(ext_struc, &mut ext_der, it()) };
        if len < 0 {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_CONF_150) };
            // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
            return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
        }
        len
    } else {
        // SAFETY: `i2d` is the method's old-style encoder; a NULL destination sizes the output.
        let len = if let Some(f) = i2d {
            // SAFETY: `f` is the live old-style encoder; a NULL destination sizes the output.
            unsafe { f(ext_struc, ptr::null_mut()) }
        } else {
            0
        };
        if len <= 0 {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_CONF_158) };
            // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
            return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
        }
        // SAFETY: the allocator answers NULL or `len` bytes.
        let buf = CRYPTO_malloc(len as usize, FILE.as_ptr(), LINE_MALLOC_DER).cast::<c_uchar>();
        if buf.is_null() {
            // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
            return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
        }
        ext_der = buf;
        let mut p = ext_der;
        if let Some(f) = i2d {
            // SAFETY: `f` is the live old-style encoder; `p` points into `ext_der`'s `len` bytes.
            unsafe { f(ext_struc, &mut p) };
        }
        len
    };

    // SAFETY: the item allocator answers NULL or a live `ASN1_OCTET_STRING`.
    ext_oct = ASN1_OCTET_STRING_new();
    if ext_oct.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_167) };
        // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
        return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
    }
    // SAFETY: `ext_oct` is live and owns `ext_der` from here on (`ext_der` is nulled).
    unsafe {
        (*ext_oct).data = ext_der;
        ext_der = ptr::null_mut();
        (*ext_oct).length = ext_len;
    }

    // SAFETY: `ext_oct` is live; the creator duplicates its octets.
    let ext = unsafe { X509_EXTENSION_create_by_NID(ptr::null_mut(), ext_nid, crit, ext_oct) };
    if ext.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_176) };
        // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
        return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
    }
    // SAFETY: `ext_oct` is this call's own string.
    unsafe { ASN1_OCTET_STRING_free(ext_oct) };
    ext
}

/// The authority's `err:` tail of [`do_ext_i2d`].
///
/// # Safety
///
/// `ext_der` is NULL or this call's own allocation; `ext_oct` is NULL or this call's own string.
unsafe fn do_ext_i2d_err(ext_der: *mut c_uchar, ext_oct: *mut Asn1String) -> *mut X509Extension {
    // SAFETY: each is NULL or this call's own value (`CRYPTO_free` and `ASN1_OCTET_STRING_free`
    // both tolerate NULL).
    unsafe {
        CRYPTO_free(ext_der.cast(), FILE.as_ptr(), LINE_FREE_DER);
        ASN1_OCTET_STRING_free(ext_oct);
    }
    ptr::null_mut()
}

/// `X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc)` —
/// `crypto/x509/v3_conf.c:191-200`.
///
/// Looks the `ext_nid` method up through the [`crate::x509::v3_lib`] dispatch and encodes through
/// [`do_ext_i2d`]; an unknown NID raises `X509V3_R_UNKNOWN_EXTENSION` and answers NULL.
///
/// # Safety
///
/// `ext_struc` is NULL or the internal structure the `ext_nid` method's `it`/`i2d` encodes.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_i2d(
    ext_nid: c_int,
    crit: c_int,
    ext_struc: *mut c_void,
) -> *mut X509Extension {
    // SAFETY: `ext_nid` is an integer NID.
    let method = unsafe { X509V3_EXT_get_nid(ext_nid) };
    if method.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_196) };
        return ptr::null_mut();
    }
    // SAFETY: `method` is live; `ext_struc` is the value its `it`/`i2d` encodes.
    unsafe { do_ext_i2d(method, ext_nid, crit, ext_struc) }
}

// ---------------------------------------------------------------------------
// The extension-building chain
// ---------------------------------------------------------------------------

/// Appends `s`'s bytes to `buf`, rendering NULL as the literal `(null)` — the authority's
/// `BIO_vsnprintf` `%s` of a NULL argument, which is what `ERR_raise_data`'s formatted message
/// carries.
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, s: *const c_char) {
    if s.is_null() {
        buf.extend_from_slice(b"(null)");
        return;
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    buf.extend_from_slice(unsafe { CStr::from_ptr(s) }.to_bytes());
}

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(nval, X509V3_conf_free)` installs —
/// `crypto/x509/v3_conf.c:105`/`:110`.
///
/// # Safety
///
/// `p` must be NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `static int v3_check_critical(const char **value)` — `crypto/x509/v3_conf.c:203-213`.
///
/// `CHECK_AND_SKIP_PREFIX(p, "critical,")` (`include/internal/common.h:60`), then any following
/// whitespace, advances the caller's pointer past the prefix; the return is whether it matched.
///
/// # Safety
///
/// `value` must be writable and hold a NUL-terminated string.
unsafe fn v3_check_critical(value: *mut *const c_char) -> c_int {
    // SAFETY: `value` is writable per the contract.
    let mut p = unsafe { *value };
    // SAFETY: `p` is NUL-terminated; the literal is static and nine bytes.
    if unsafe { strncmp(p, c"critical,".as_ptr(), c"critical,".count_bytes()) } != 0 {
        return 0;
    }
    // SAFETY: the prefix matched, so `p` has nine non-terminator bytes.
    p = unsafe { p.add(c"critical,".count_bytes()) };
    // SAFETY: `p` walks the NUL-terminated string.
    while unsafe { ossl_isspace(*p as c_int) } {
        // SAFETY: `p` is before the terminator.
        p = unsafe { p.add(1) };
    }
    // SAFETY: `value` is writable per the contract.
    unsafe { *value = p };
    1
}

/// `static int v3_check_generic(const char **value)` — `crypto/x509/v3_conf.c:216-232`.
///
/// Returns 1 for a `DER:` prefix and 2 for `ASN1:`, advancing the caller's pointer past the prefix
/// and any whitespace; 0 means neither.
///
/// # Safety
///
/// `value` must be writable and hold a NUL-terminated string.
unsafe fn v3_check_generic(value: *mut *const c_char) -> c_int {
    // SAFETY: `value` is writable per the contract.
    let mut p = unsafe { *value };
    let gen_type;
    // SAFETY: `p` is NUL-terminated; the literal is static.
    if unsafe { strncmp(p, c"DER:".as_ptr(), c"DER:".count_bytes()) } == 0 {
        gen_type = 1;
        // SAFETY: the prefix matched, so `p` has four non-terminator bytes.
        p = unsafe { p.add(c"DER:".count_bytes()) };
    // SAFETY: as above.
    } else if unsafe { strncmp(p, c"ASN1:".as_ptr(), c"ASN1:".count_bytes()) } == 0 {
        gen_type = 2;
        // SAFETY: the prefix matched, so `p` has five non-terminator bytes.
        p = unsafe { p.add(c"ASN1:".count_bytes()) };
    } else {
        return 0;
    }
    // SAFETY: `p` walks the NUL-terminated string.
    while unsafe { ossl_isspace(*p as c_int) } {
        // SAFETY: `p` is before the terminator.
        p = unsafe { p.add(1) };
    }
    // SAFETY: `value` is writable per the contract.
    unsafe { *value = p };
    gen_type
}

/// `static unsigned char *generic_asn1(const char *value, X509V3_CTX *ctx, long *ext_len)` —
/// `crypto/x509/v3_conf.c:280-292`.
///
/// # Safety
///
/// `value` must be NUL-terminated; `ctx` NULL or live; `ext_len` writable.
unsafe fn generic_asn1(
    value: *const c_char,
    ctx: *mut X509V3Ctx,
    ext_len: *mut c_long,
) -> *mut c_uchar {
    // SAFETY: `value` is NUL-terminated; `ctx` is NULL or live.
    let typ = unsafe { ASN1_generate_v3(value, ctx) };
    if typ.is_null() {
        return ptr::null_mut();
    }
    let mut ext_der: *mut c_uchar = ptr::null_mut();
    // SAFETY: `typ` is live; `&mut ext_der` is a writable slot that starts NULL, so the encoder
    // allocates.
    let len = unsafe { i2d_ASN1_TYPE(typ, &raw mut ext_der) };
    // SAFETY: `typ` is this call's own.
    unsafe { ASN1_TYPE_free(typ) };
    // SAFETY: `ext_len` is writable per the contract.
    unsafe { *ext_len = len as c_long };
    ext_der
}

/// `static X509_EXTENSION *v3_generic_extension(const char *ext, const char *value, int crit,
/// int gen_type, X509V3_CTX *ctx)` — `crypto/x509/v3_conf.c:235-278`.
///
/// Builds an arbitrary extension from a textual object name and either a hex (`DER:`) or
/// `ASN1_generate_v3` (`ASN1:`) value.
///
/// # Safety
///
/// `ext`/`value` must be NUL-terminated; `ctx` NULL or live.
unsafe fn v3_generic_extension(
    ext: *const c_char,
    value: *const c_char,
    crit: c_int,
    gen_type: c_int,
    ctx: *mut X509V3Ctx,
) -> *mut X509Extension {
    let mut ext_der: *mut c_uchar = ptr::null_mut();
    let mut ext_len: c_long = 0;
    let mut oct: *mut Asn1String = ptr::null_mut();

    // SAFETY: `ext` is NUL-terminated per the contract.
    let obj = unsafe { OBJ_txt2obj(ext, 0) };
    if obj.is_null() {
        // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR, "name=%s", ext)`.
        let mut msg = b"name=".to_vec();
        // SAFETY: `ext` is NUL-terminated.
        unsafe { push_cstr(&mut msg, ext) };
        msg.push(0);
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(&V3_CONF_246, msg.as_ptr().cast()) };
        // SAFETY: `obj` is NULL; `oct` is NULL; `ext_der` is NULL.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // SAFETY: `ext_der` is NULL; the site is constant.
        unsafe { CRYPTO_free(ext_der.cast::<c_void>(), FILE.as_ptr(), 276) };
        return ptr::null_mut();
    }

    if gen_type == 1 {
        // SAFETY: `value` is NUL-terminated; `&mut ext_len` is writable.
        ext_der = unsafe { OPENSSL_hexstr2buf(value, &raw mut ext_len) };
    } else if gen_type == 2 {
        // SAFETY: `value` is NUL-terminated; `ctx` NULL or live; `&mut ext_len` writable.
        ext_der = unsafe { generic_asn1(value, ctx, &raw mut ext_len) };
    }

    if ext_der.is_null() {
        // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, "value=%s", value)`.
        let mut msg = b"value=".to_vec();
        // SAFETY: `value` is NUL-terminated.
        unsafe { push_cstr(&mut msg, value) };
        msg.push(0);
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(&V3_CONF_257, msg.as_ptr().cast()) };
        // SAFETY: `obj` is this call's own; `oct` is NULL; `ext_der` is NULL.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // SAFETY: `ext_der` is NULL; the site is constant.
        unsafe { CRYPTO_free(ext_der.cast::<c_void>(), FILE.as_ptr(), 276) };
        return ptr::null_mut();
    }

    // SAFETY: the item allocator answers NULL or a live `ASN1_OCTET_STRING`.
    oct = ASN1_OCTET_STRING_new();
    if oct.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_263) };
        // SAFETY: `obj` is this call's own; `oct` is NULL; `ext_der` is this call's own.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // SAFETY: `ext_der` is this call's own; the site is constant.
        unsafe { CRYPTO_free(ext_der.cast::<c_void>(), FILE.as_ptr(), 276) };
        return ptr::null_mut();
    }
    // SAFETY: `oct` is live and takes ownership of `ext_der` (`ext_der` is nulled).
    unsafe {
        (*oct).data = ext_der;
        (*oct).length = ext_len as c_int;
        ext_der = ptr::null_mut();
    }

    // SAFETY: `oct` is live; the creator duplicates its octets; `obj` is live.
    let extension = unsafe { X509_EXTENSION_create_by_OBJ(ptr::null_mut(), obj, crit, oct) };

    // SAFETY: `obj`/`oct` are this call's own; `ext_der` is NULL; the site is constant.
    unsafe {
        ASN1_OBJECT_free(obj);
        ASN1_OCTET_STRING_free(oct);
        CRYPTO_free(ext_der.cast::<c_void>(), FILE.as_ptr(), 276);
    }
    extension
}

/// `static X509_EXTENSION *do_ext_nconf(CONF *conf, X509V3_CTX *ctx, int ext_nid, int crit,
/// const char *value)` — `crypto/x509/v3_conf.c:79-135`.
///
/// The v2i/s2i/r2i dispatch, then `do_ext_i2d`. The `@section` value form reads the list from the
/// config database instead of parsing it inline.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `value` NUL-terminated.
unsafe fn do_ext_nconf(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    ext_nid: c_int,
    crit: c_int,
    value: *const c_char,
) -> *mut X509Extension {
    let ext_struc: *mut c_void;

    if ext_nid == NID_undef {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_88) };
        return ptr::null_mut();
    }
    // SAFETY: `ext_nid` is an integer NID.
    let method = unsafe { X509V3_EXT_get_nid(ext_nid) };
    if method.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_92) };
        return ptr::null_mut();
    }
    // SAFETY: `method` is live.
    let (v2i, s2i, r2i, it, ext_free) = unsafe {
        (
            (*method).v2i,
            (*method).s2i,
            (*method).r2i,
            (*method).it,
            (*method).ext_free,
        )
    };
    if let Some(cb) = v2i {
        // SAFETY: `value` is NUL-terminated per the contract.
        let at_section = unsafe { *value } == b'@' as c_char;
        let nval = if at_section {
            // SAFETY: `conf` is NULL or live; `value + 1` is the NUL-terminated section name.
            unsafe { NCONF_get_section(conf, value.add(1)) }
        } else {
            // SAFETY: `value` is NUL-terminated.
            unsafe { X509V3_parse_list(value) }
        };
        // SAFETY: `nval` is NULL or a live stack (a NULL answer is -1).
        let num = unsafe { OPENSSL_sk_num(nval) };
        if nval.is_null() || num <= 0 {
            // `ERR_raise_data(..., X509V3_R_INVALID_EXTENSION_STRING, "name=%s,section=%s", ...)`.
            let mut msg = b"name=".to_vec();
            // SAFETY: `OBJ_nid2sn` answers NULL or a NUL-terminated string.
            unsafe { push_cstr(&mut msg, OBJ_nid2sn(ext_nid)) };
            msg.extend_from_slice(b",section=");
            // SAFETY: `value` is NUL-terminated.
            unsafe { push_cstr(&mut msg, value) };
            msg.push(0);
            // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
            unsafe { raise_site_data(&V3_CONF_102, msg.as_ptr().cast()) };
            if !at_section {
                // SAFETY: `nval` is this call's own parsed list.
                unsafe { OPENSSL_sk_pop_free(nval, Some(conf_value_free_thunk)) };
            }
            return ptr::null_mut();
        }
        // SAFETY: `cb` is the live callback; `method`/`ctx` are its contract; `nval` is live.
        ext_struc = unsafe { cb(method, ctx.cast::<c_void>(), nval) };
        if !at_section {
            // SAFETY: `nval` is this call's own parsed list.
            unsafe { OPENSSL_sk_pop_free(nval, Some(conf_value_free_thunk)) };
        }
        if ext_struc.is_null() {
            return ptr::null_mut();
        }
    } else if let Some(cb) = s2i {
        // SAFETY: `cb` is the live callback; `method`/`ctx` are its contract.
        ext_struc = unsafe { cb(method, ctx.cast::<c_void>(), value) };
        if ext_struc.is_null() {
            return ptr::null_mut();
        }
    } else if let Some(cb) = r2i {
        // SAFETY: `ctx` is live; the `db`/`db_meth` pair is what the r2i callback reads.
        let (db, db_meth) = unsafe { ((*ctx).db, (*ctx).db_meth) };
        if db.is_null() || db_meth.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_CONF_118) };
            return ptr::null_mut();
        }
        // SAFETY: `cb` is the live callback; `method`/`ctx` are its contract.
        ext_struc = unsafe { cb(method, ctx.cast::<c_void>(), value) };
        if ext_struc.is_null() {
            return ptr::null_mut();
        }
    } else {
        // `ERR_raise_data(..., X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED, "name=%s", ...)`.
        let mut msg = b"name=".to_vec();
        // SAFETY: `OBJ_nid2sn` answers NULL or a NUL-terminated string.
        unsafe { push_cstr(&mut msg, OBJ_nid2sn(ext_nid)) };
        msg.push(0);
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(&V3_CONF_124, msg.as_ptr().cast()) };
        return ptr::null_mut();
    }

    // SAFETY: `method` is live; `ext_struc` is the value its `it`/`i2d` encodes.
    let ext = unsafe { do_ext_i2d(method, ext_nid, crit, ext_struc) };
    if let Some(it) = it {
        // SAFETY: `ext_struc` is the item value; `it()` answers the item it describes.
        unsafe { ASN1_item_free(ext_struc, it()) };
    } else if let Some(f) = ext_free {
        // SAFETY: `ext_struc` is the old-style value `f` releases.
        unsafe { f(ext_struc) };
    }
    ext
}

/// `static void delete_ext(STACK_OF(X509_EXTENSION) *sk, X509_EXTENSION *dext)` —
/// `crypto/x509/v3_conf.c:294-302`.
///
/// Removes every extension in `sk` with the same object as `dext`.
///
/// # Safety
///
/// `sk`/`dext` must be live.
unsafe fn delete_ext(sk: *mut OpenSslStack, dext: *mut X509Extension) {
    // SAFETY: `dext` is live.
    let obj = unsafe { X509_EXTENSION_get_object(dext) };
    loop {
        // SAFETY: `sk` is live; `obj` is live.
        let idx = unsafe { X509v3_get_ext_by_OBJ(sk, obj, -1) };
        if idx < 0 {
            return;
        }
        // SAFETY: the returned extension is owned by `sk` and is being removed.
        unsafe { X509_EXTENSION_free(X509v3_delete_ext(sk, idx)) };
    }
}

/// `static X509_EXTENSION *X509V3_EXT_nconf_int(CONF *conf, X509V3_CTX *ctx,
/// const char *section, const char *name, const char *value)` —
/// `crypto/x509/v3_conf.c:34-56`.
///
/// Strips the `critical,` and `DER:`/`ASN1:` prefixes, dispatches a generic extension if either of
/// the latter is present, else builds through [`do_ext_nconf`]; a failure raises
/// `X509V3_R_ERROR_IN_EXTENSION`, with the section in the message when it was named.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `section`/`name`/`value` NULL or NUL-terminated.
unsafe fn X509V3_EXT_nconf_int(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    name: *const c_char,
    value: *const c_char,
) -> *mut X509Extension {
    let mut p = value;
    // SAFETY: `&mut p` is this frame's own slot; `p` is NUL-terminated.
    let crit = unsafe { v3_check_critical(&raw mut p) };
    // SAFETY: as above.
    let ext_type = unsafe { v3_check_generic(&raw mut p) };
    if ext_type != 0 {
        // SAFETY: `name`/`p` are NULL or NUL-terminated; `ctx` NULL or live.
        return unsafe { v3_generic_extension(name, p, crit, ext_type, ctx) };
    }
    // SAFETY: `OBJ_sn2nid` takes the NUL-terminated name and answers an integer NID.
    let nid = unsafe { OBJ_sn2nid(name) };
    // SAFETY: `conf` NULL or live; `ctx` NULL or live; `p` NUL-terminated.
    let ret = unsafe { do_ext_nconf(conf, ctx, nid, crit, p) };
    if ret.is_null() {
        let mut msg: Vec<u8> = Vec::new();
        if !section.is_null() {
            msg.extend_from_slice(b"section=");
            // SAFETY: `section` is NUL-terminated.
            unsafe { push_cstr(&mut msg, section) };
            msg.extend_from_slice(b", ");
        }
        msg.extend_from_slice(b"name=");
        // SAFETY: `name` is NUL-terminated.
        unsafe { push_cstr(&mut msg, name) };
        msg.extend_from_slice(b", value=");
        // SAFETY: `p` is NUL-terminated.
        unsafe { push_cstr(&mut msg, p) };
        msg.push(0);
        let site = if section.is_null() {
            &V3_CONF_52
        } else {
            &V3_CONF_48
        };
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(site, msg.as_ptr().cast()) };
    }
    ret
}

/// `X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, const char *name,
/// const char *value)` — `crypto/x509/v3_conf.c:58-62`.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `name`/`value` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_nconf(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    name: *const c_char,
    value: *const c_char,
) -> *mut X509Extension {
    // SAFETY: the caller's contract is `X509V3_EXT_nconf_int`'s; `section` is NULL.
    unsafe { X509V3_EXT_nconf_int(conf, ctx, ptr::null(), name, value) }
}

/// `X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid,
/// const char *value)` — `crypto/x509/v3_conf.c:64-75`.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `value` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_nconf_nid(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    ext_nid: c_int,
    value: *const c_char,
) -> *mut X509Extension {
    let mut p = value;
    // SAFETY: `&mut p` is this frame's own slot; `p` is NUL-terminated.
    let crit = unsafe { v3_check_critical(&raw mut p) };
    // SAFETY: as above.
    let ext_type = unsafe { v3_check_generic(&raw mut p) };
    if ext_type != 0 {
        // SAFETY: `OBJ_nid2sn` answers NULL or a NUL-terminated string; `p` is NUL-terminated;
        // `ctx` NULL or live.
        return unsafe { v3_generic_extension(OBJ_nid2sn(ext_nid), p, crit, ext_type, ctx) };
    }
    // SAFETY: `conf` NULL or live; `ctx` NULL or live; `p` NUL-terminated.
    unsafe { do_ext_nconf(conf, ctx, ext_nid, crit, p) }
}

/// `int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, const char *section,
/// STACK_OF(X509_EXTENSION) **sk)` — `crypto/x509/v3_conf.c:309-350`.
///
/// Walks the `section`'s `CONF_VALUE` entries, building each through [`X509V3_EXT_nconf_int`].
/// `subjectKeyIdentifier` is reordered before `authorityKeyIdentifier` when both are present so
/// the SKID is handled first, and `X509V3_CTX_REPLACE` deletes any same-object extension before
/// adding. On failure new elements may remain in `*sk`, exactly as the authority notes.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `section` NUL-terminated; `sk` NULL or a writable slot
/// holding NULL or a live extension stack (`ctx` must be live whenever `sk` is non-NULL).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_nconf_sk(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    sk: *mut *mut OpenSslStack,
) -> c_int {
    // SAFETY: `conf` is NULL or live; `section` NULL or NUL-terminated.
    let nval = unsafe { NCONF_get_section(conf, section) };
    if nval.is_null() {
        return 0;
    }
    // SAFETY: `nval` is live.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut akid: c_int = -1;
    let mut skid: c_int = -1;
    for i in 0..num {
        // SAFETY: `nval` is live and `i` is within its count.
        let val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `val` is a live `CONF_VALUE`.
        let name = unsafe { (*val).name };
        if name.is_null() {
            continue;
        }
        // SAFETY: `name` is NUL-terminated and the literal is static.
        if unsafe { strcmp(name, c"authorityKeyIdentifier".as_ptr()) } == 0 {
            akid = i;
        // SAFETY: as above.
        } else if unsafe { strcmp(name, c"subjectKeyIdentifier".as_ptr()) } == 0 {
            skid = i;
        }
    }
    for i in 0..num {
        // SAFETY: `nval` is live and `i` is within its count.
        let mut val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        if skid > akid && akid >= 0 {
            if i == akid {
                // SAFETY: `nval` is live and `skid`/`akid` are valid indices.
                val = unsafe { OPENSSL_sk_value(nval, skid) }.cast::<ConfValue>();
            } else if i == skid {
                // SAFETY: as above.
                val = unsafe { OPENSSL_sk_value(nval, akid) }.cast::<ConfValue>();
            }
        }
        // SAFETY: `val` is a live `CONF_VALUE`; `conf`/`ctx` are the caller's; the three strings
        // are NUL-terminated members of `val`.
        let ext =
            unsafe { X509V3_EXT_nconf_int(conf, ctx, (*val).section, (*val).name, (*val).value) };
        if ext.is_null() {
            return 0;
        }
        if !sk.is_null() {
            // SAFETY: `sk` is a writable slot; `ctx` is live when `sk` is non-NULL (its flags are
            // read), which is the authority's own precondition.
            if unsafe { (*ctx).flags } == X509V3_CTX_REPLACE {
                // SAFETY: `*sk` is NULL or a live extension stack; `ext` is live.
                unsafe { delete_ext(*sk, ext) };
            }
            // SAFETY: `sk` holds NULL or a live stack; `ext` is live.
            if unsafe { X509v3_add_ext(sk, ext, -1) }.is_null() {
                // SAFETY: `ext` is this call's own.
                unsafe { X509_EXTENSION_free(ext) };
                return 0;
            }
        }
        // SAFETY: `ext` is this call's own.
        unsafe { X509_EXTENSION_free(ext) };
    }
    1
}

/// `int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section, X509 *cert)` —
/// `crypto/x509/v3_conf.c:356-363`.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `section` NUL-terminated; `cert` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_nconf(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    cert: *mut X509,
) -> c_int {
    let sk = if cert.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `cert` is live per the guard.
        unsafe { core::ptr::addr_of_mut!((*cert).cert_info.extensions) }
    };
    // SAFETY: `sk` is NULL or a writable slot into a live `X509`.
    unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, sk) }
}

/// `int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
/// X509_CRL *crl)` — `crypto/x509/v3_conf.c:369-376`.
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `section` NUL-terminated; `crl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_CRL_add_nconf(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    crl: *mut X509Crl,
) -> c_int {
    let sk = if crl.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `crl` is live per the guard.
        unsafe { core::ptr::addr_of_mut!((*crl).crl.extensions) }
    };
    // SAFETY: `sk` is NULL or a writable slot into a live `X509_CRL`.
    unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, sk) }
}

/// The `void (*)(void *)` thunk `sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free)` installs —
/// `crypto/x509/v3_conf.c:391`.
///
/// # Safety
///
/// `p` must be NULL or a live `X509_EXTENSION` (the stack contract).
unsafe extern "C" fn x509_extension_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `X509_EXTENSION` pointers per the contract.
    unsafe { X509_EXTENSION_free(p.cast::<X509Extension>()) };
}

/// `int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
/// X509_REQ *req)` — `crypto/x509/v3_conf.c:382-392`.
///
/// The section's extensions are built into a fresh stack; when that succeeds and `req` is non-NULL
/// and non-empty the stack is added to the request through `X509_REQ_add_extensions`, and the
/// stack is released either way (`:389-391`).
///
/// # Safety
///
/// `conf` NULL or live; `ctx` NULL or live; `section` NUL-terminated; `req` NULL or live.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509V3_EXT_REQ_add_nconf(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    req: *mut X509Req,
) -> c_int {
    let mut exts: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `&mut exts` is a writable slot; the remaining arguments are the caller's contract.
    let mut ret = unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, &raw mut exts) };
    if ret != 0 && !req.is_null() && !exts.is_null() {
        // SAFETY: `req` is live and `exts` is this call's own live stack.
        ret = unsafe { X509_REQ_add_extensions(req, exts) };
    }
    // SAFETY: `exts` is NULL or this call's own stack of extensions.
    unsafe { OPENSSL_sk_pop_free(exts, Some(x509_extension_free_thunk)) };
    ret
}

/// `X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
/// const char *name, const char *value)` — `crypto/x509/v3_conf.c:495-508`.
///
/// The legacy lhash entry point: builds a temporary `NCONF` wrapped around the lhash, dispatches,
/// then frees it.
///
/// # Safety
///
/// `conf` NULL or a live lhash; `ctx` NULL or live; `name`/`value` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_conf(
    conf: *mut OpenSslLhash,
    ctx: *mut X509V3Ctx,
    name: *const c_char,
    value: *const c_char,
) -> *mut X509Extension {
    // SAFETY: `NCONF_new` accepts a NULL method.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctmp` is live; `conf` NULL or a live lhash.
    unsafe { CONF_set_nconf(ctmp, conf) };
    // SAFETY: `ctmp` is live; `ctx` NULL or live; `name`/`value` NULL or NUL-terminated.
    let ret = unsafe { X509V3_EXT_nconf(ctmp, ctx, name, value) };
    // SAFETY: `ctmp` is live.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: `ctmp` is this call's own.
    unsafe { NCONF_free(ctmp) };
    ret
}

/// `X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
/// int ext_nid, const char *value)` — `crypto/x509/v3_conf.c:510-523`.
///
/// # Safety
///
/// `conf` NULL or a live lhash; `ctx` NULL or live; `value` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_conf_nid(
    conf: *mut OpenSslLhash,
    ctx: *mut X509V3Ctx,
    ext_nid: c_int,
    value: *const c_char,
) -> *mut X509Extension {
    // SAFETY: `NCONF_new` accepts a NULL method.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctmp` is live; `conf` NULL or a live lhash.
    unsafe { CONF_set_nconf(ctmp, conf) };
    // SAFETY: `ctmp` is live; `ctx` NULL or live; `value` NULL or NUL-terminated.
    let ret = unsafe { X509V3_EXT_nconf_nid(ctmp, ctx, ext_nid, value) };
    // SAFETY: `ctmp` is live.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: `ctmp` is this call's own.
    unsafe { NCONF_free(ctmp) };
    ret
}

/// `int X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, const char *section,
/// X509 *cert)` — `crypto/x509/v3_conf.c:552-565`.
///
/// # Safety
///
/// `conf` NULL or a live lhash; `ctx` NULL or live; `section` NUL-terminated; `cert` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_conf(
    conf: *mut OpenSslLhash,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `NCONF_new` accepts a NULL method.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return 0;
    }
    // SAFETY: `ctmp` is live; `conf` NULL or a live lhash.
    unsafe { CONF_set_nconf(ctmp, conf) };
    // SAFETY: `ctmp` is live; `ctx` NULL or live; `section` NUL-terminated; `cert` NULL or live.
    let ret = unsafe { X509V3_EXT_add_nconf(ctmp, ctx, section, cert) };
    // SAFETY: `ctmp` is live.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: `ctmp` is this call's own.
    unsafe { NCONF_free(ctmp) };
    ret
}

/// `int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
/// const char *section, X509_CRL *crl)` — `crypto/x509/v3_conf.c:569-582`.
///
/// # Safety
///
/// `conf` NULL or a live lhash; `ctx` NULL or live; `section` NUL-terminated; `crl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_CRL_add_conf(
    conf: *mut OpenSslLhash,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    crl: *mut X509Crl,
) -> c_int {
    // SAFETY: `NCONF_new` accepts a NULL method.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return 0;
    }
    // SAFETY: `ctmp` is live; `conf` NULL or a live lhash.
    unsafe { CONF_set_nconf(ctmp, conf) };
    // SAFETY: `ctmp` is live; `ctx` NULL or live; `section` NUL-terminated; `crl` NULL or live.
    let ret = unsafe { X509V3_EXT_CRL_add_nconf(ctmp, ctx, section, crl) };
    // SAFETY: `ctmp` is live.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: `ctmp` is this call's own.
    unsafe { NCONF_free(ctmp) };
    ret
}

/// `int X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
/// const char *section, X509_REQ *req)` — `crypto/x509/v3_conf.c:586-599`.
///
/// # Safety
///
/// `conf` NULL or a live lhash; `ctx` NULL or live; `section` NUL-terminated; `req` NULL or live.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509V3_EXT_REQ_add_conf(
    conf: *mut OpenSslLhash,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    req: *mut X509Req,
) -> c_int {
    // SAFETY: `NCONF_new` accepts a NULL method.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return 0;
    }
    // SAFETY: `ctmp` is live; `conf` NULL or a live lhash.
    unsafe { CONF_set_nconf(ctmp, conf) };
    // SAFETY: `ctmp` is live; `ctx` NULL or live; `section` NUL-terminated; `req` NULL or live.
    let ret = unsafe { X509V3_EXT_REQ_add_nconf(ctmp, ctx, section, req) };
    // SAFETY: `ctmp` is live.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: `ctmp` is this call's own.
    unsafe { NCONF_free(ctmp) };
    ret
}
