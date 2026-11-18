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
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::obj::{NID_undef, OBJ_nid2sn, OBJ_sn2nid, OBJ_txt2obj};
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::runtime::str::OPENSSL_hexstr2buf;
use crate::x509::v3_lib::{RegistryReadGuard, X509V3ExtMethod, X509V3_EXT_get_nid};
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
/// `v3_generic_extension`'s `err:`/tail `OPENSSL_free(ext_der)` — `crypto/x509/v3_conf.c:276`.
const LINE_FREE_GENERIC_DER: c_int = 276;

// ---------------------------------------------------------------------------------------------
// Ownership of the DER blocks the extension builders allocate
// ---------------------------------------------------------------------------------------------

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
/// `X509V3_get_section`'s NULL-context refusal, a deliberate safety deviation.
///
/// The authority dereferences `ctx->db` here unconditionally, so a NULL `ctx` is
/// undefined behaviour in `v3_conf.c`; it is not reproduced. The line is the
/// same 410 so a reader lands on the authority's function, and the reason says
/// what actually happened.
const V3_CONF_410_NULL: crate::runtime::err::err_sites::ErrSite =
    v3_conf_site(410, c"X509V3_get_section", ERR_R_PASSED_NULL_PARAMETER);
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
/// `ctx` is NULL or live; `section` is NULL or NUL-terminated. A NULL `ctx` is refused — an
/// error is raised and NULL is returned — instead of being dereferenced. That refusal is a
/// deliberate deviation from `v3_conf.c`, which reads `ctx->db` unconditionally.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_section(
    ctx: *mut X509V3Ctx,
    section: *const c_char,
) -> *mut OpenSslStack {
    if ctx.is_null() {
        // Deliberate deviation from `v3_conf.c`, which dereferences `ctx` here:
        // refuse instead of reproducing undefined behaviour.
        // SAFETY: the site is a compile-time constant and raising needs no
        // live object beyond the thread's error queue.
        unsafe { raise_site(&V3_CONF_410_NULL) };
        return ptr::null_mut();
    }
    // SAFETY: the guard above returned for a NULL `ctx`, so `ctx` is live here.
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
/// `ctx` is NULL or live; `section` is NULL or a stack this context produced. `ctx` is read
/// only when `section` is non-NULL, so a NULL `section` may be paired with a NULL `ctx` (which
/// is what `v3_san::do_dirname` does after a refused section read).
#[no_mangle]
pub unsafe extern "C" fn X509V3_section_free(ctx: *mut X509V3Ctx, section: *mut OpenSslStack) {
    if section.is_null() {
        return;
    }
    // SAFETY: the guard above returned for a NULL `section`, so this read only happens when
    // `section` is a live stack the context produced and `ctx` is live per the contract.
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
    // The DER block, owned: `Drop` is the authority's own `CRYPTO_free(ext_der)` at its `err:`
    // site (`:184`).
    // SAFETY: the seed value is NULL, the empty block `adopt_plain_nullable` documents.
    let mut ext_der = unsafe {
        OwnedBuf::adopt_plain_nullable(ptr::null_mut(), SeamFile::new(FILE), LINE_FREE_DER)
    };
    let mut ext_oct: *mut Asn1String = ptr::null_mut();

    /* Convert internal representation to DER. */
    // SAFETY: `method` is live.
    let it = unsafe { (*method).it };
    // SAFETY: `method` is live.
    let i2d = unsafe { (*method).i2d };
    let ext_len = if let Some(it) = it {
        let mut raw: *mut c_uchar = ptr::null_mut();
        // SAFETY: `ext_struc` is the value `it()` describes; `&raw mut raw` is a writable slot that
        // starts NULL, so the encoder allocates.
        let len = unsafe { ASN1_item_i2d(ext_struc, &raw mut raw, it()) };
        // SAFETY: `raw` is this call's own block or NULL, from the crate's `CRYPTO_*` seam.
        ext_der = unsafe {
            OwnedBuf::adopt_plain_nullable(
                raw.cast::<c_uchar>(),
                SeamFile::new(FILE),
                LINE_FREE_DER,
            )
        };
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
        let buf = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(len as usize, FILE.as_ptr(), LINE_MALLOC_DER)
        }
        .cast::<c_uchar>();
        if buf.is_null() {
            // SAFETY: `ext_der`/`ext_oct` are NULL or this call's own values.
            return unsafe { do_ext_i2d_err(ext_der, ext_oct) };
        }
        // SAFETY: `buf` is a fresh block of `len` bytes this call owns from the crate's
        // `CRYPTO_*` seam.
        ext_der = unsafe {
            OwnedBuf::adopt_plain_nullable(
                buf.cast::<c_uchar>(),
                SeamFile::new(FILE),
                LINE_FREE_DER,
            )
        };
        let mut p = buf;
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
    // SAFETY: `ext_oct` is live and takes the DER block (`ext_der` is emptied).
    unsafe {
        (*ext_oct).data = ext_der.into_raw();
        // The owner is empty again so its `Drop` still emits the authority's own no-op
        // `CRYPTO_free(NULL, FILE, LINE_FREE_DER)` on the remaining paths.
        ext_der =
            OwnedBuf::adopt_plain_nullable(ptr::null_mut(), SeamFile::new(FILE), LINE_FREE_DER);
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
    // SAFETY: `ext_oct` is this call's own string (it owns the DER block now).
    unsafe { ASN1_OCTET_STRING_free(ext_oct) };
    ext
}

/// The authority's `err:` tail of [`do_ext_i2d`].
///
/// # Safety
///
/// `ext_oct` is NULL or this call's own string.
unsafe fn do_ext_i2d_err(ext_der: OwnedBuf, ext_oct: *mut Asn1String) -> *mut X509Extension {
    // `ext_der`'s `Drop` is the authority's `CRYPTO_free(ext_der)` at `:184`.
    drop(ext_der);
    // SAFETY: `ext_oct` is NULL or this call's own string (`ASN1_OCTET_STRING_free` tolerates
    // NULL).
    unsafe { ASN1_OCTET_STRING_free(ext_oct) };
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
/// `ext_struc` is NULL or the internal structure the `ext_nid` method's `it`/`i2d` encodes. The row
/// `X509V3_EXT_get_nid` resolves is protected for the whole call by the registry read hold, so a
/// DYNAMIC row cannot be released between the lookup and `do_ext_i2d`'s read of it (B51).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_i2d(
    ext_nid: c_int,
    crit: c_int,
    ext_struc: *mut c_void,
) -> *mut X509Extension {
    // Hold the registry read lock across the row resolution and the encoder's use of it:
    // `do_ext_i2d` reads and calls the row's `it`/`i2d` after `X509V3_EXT_get_nid` returns, and a
    // concurrent `X509V3_EXT_cleanup` would otherwise be free to release a DYNAMIC row first
    // (B51). The nested read inside the lookup is a reader/reader acquisition. A failure to take
    // the hold raises the same unknown-extension site the lookup's own failure raises.
    let Some(_registry) = RegistryReadGuard::acquire() else {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_196) };
        return ptr::null_mut();
    };
    // SAFETY: `ext_nid` is an integer NID; the read hold protects the row.
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
    // The DER block, owned: `Drop` is the authority's own `CRYPTO_free(ext_der)` at its `err:`
    // site (`:276`).
    // SAFETY: the seed value is NULL, the empty block `adopt_plain_nullable` documents.
    let mut ext_der = unsafe {
        OwnedBuf::adopt_plain_nullable(ptr::null_mut(), SeamFile::new(FILE), LINE_FREE_GENERIC_DER)
    };
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
        // SAFETY: `obj` is NULL; `oct` is NULL.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // `ext_der` is empty; its `Drop` is the authority's own `CRYPTO_free(ext_der)` at `:276`.
        drop(ext_der);
        return ptr::null_mut();
    }

    if gen_type == 1 {
        // SAFETY: `value` is NUL-terminated; `&raw mut ext_len` is writable; the seam takes the
        // file/line for its record only.
        ext_der = unsafe {
            OwnedBuf::adopt_plain_nullable(
                OPENSSL_hexstr2buf(value, &raw mut ext_len).cast::<c_uchar>(),
                SeamFile::new(FILE),
                LINE_FREE_GENERIC_DER,
            )
        };
    } else if gen_type == 2 {
        // SAFETY: `value` is NUL-terminated; `ctx` NULL or live; `&raw mut ext_len` writable; the
        // helper allocated its block through the same seam.
        ext_der = unsafe {
            OwnedBuf::adopt_plain_nullable(
                generic_asn1(value, ctx, &raw mut ext_len).cast::<c_uchar>(),
                SeamFile::new(FILE),
                LINE_FREE_GENERIC_DER,
            )
        };
    }

    if ext_der.as_ptr().is_null() {
        // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, "value=%s", value)`.
        let mut msg = b"value=".to_vec();
        // SAFETY: `value` is NUL-terminated.
        unsafe { push_cstr(&mut msg, value) };
        msg.push(0);
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(&V3_CONF_257, msg.as_ptr().cast()) };
        // SAFETY: `obj` is this call's own; `oct` is NULL.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // `ext_der` is empty; its `Drop` is the authority's own `CRYPTO_free(ext_der)` at `:276`.
        drop(ext_der);
        return ptr::null_mut();
    }

    // SAFETY: the item allocator answers NULL or a live `ASN1_OCTET_STRING`.
    oct = ASN1_OCTET_STRING_new();
    if oct.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_263) };
        // SAFETY: `obj` is this call's own; `oct` is NULL.
        unsafe { ASN1_OBJECT_free(obj) };
        // SAFETY: `oct` is NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        // `ext_der`'s `Drop` is the authority's own `CRYPTO_free(ext_der)` at `:276`.
        drop(ext_der);
        return ptr::null_mut();
    }
    // SAFETY: `oct` is live and takes the DER block (`ext_der` is emptied).
    unsafe {
        (*oct).data = ext_der.into_raw();
        // The owner is empty again so its `Drop` still emits the authority's own no-op
        // `CRYPTO_free(NULL, FILE, LINE_FREE_GENERIC_DER)` at the tail.
        ext_der = OwnedBuf::adopt_plain_nullable(
            ptr::null_mut(),
            SeamFile::new(FILE),
            LINE_FREE_GENERIC_DER,
        );
        (*oct).length = ext_len as c_int;
    }

    // SAFETY: `oct` is live; the creator duplicates its octets; `obj` is live.
    let extension = unsafe { X509_EXTENSION_create_by_OBJ(ptr::null_mut(), obj, crit, oct) };

    // SAFETY: `obj`/`oct` are this call's own (`oct` owns the DER block now).
    unsafe {
        ASN1_OBJECT_free(obj);
        ASN1_OCTET_STRING_free(oct);
    }
    // The authority's trailing `CRYPTO_free(ext_der)` at `:276`: `ext_der` is empty here, so the
    // owner's `Drop` is its own no-op `free(NULL)`.
    drop(ext_der);
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
/// `conf` NULL or live; `ctx` NULL or live; `value` NUL-terminated. A NULL `ctx` is not
/// dereferenced: the `r2i` arm refuses it before reading the row, and a `v2i`/`s2i` callback
/// reaches the context only through `X509V3_get_section`, which refuses it; both raise and
/// return NULL. The method row the dispatcher resolves is protected for the whole call by the
/// registry read hold, so a DYNAMIC row stays live through the `v2i`/`s2i`/`r2i` callback and
/// through `do_ext_i2d`'s use of it (B51).
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
    // Hold the registry read lock across the row resolution **and** every use of that row below:
    // the `v2i`/`s2i`/`r2i` dispatch (the callbacks receive `method`), the `it`/`i2d` read and call
    // inside `do_ext_i2d`, and the release. A DYNAMIC row (an `X509V3_EXT_add_alias` copy) is
    // released by `X509V3_EXT_cleanup`; its write hold cannot be taken while this guard is alive,
    // so the row stays live for the whole call. This mirrors the B49 hold in
    // `X509V3_EXT_print`: the callbacks below never take the registry's write hold, so the nested
    // read inside `X509V3_EXT_get_nid` is a reader/reader acquisition, not a self-deadlock. A
    // failure to take the hold raises the same unknown-extension site the lookup's own failure
    // raises.
    let Some(_registry) = RegistryReadGuard::acquire() else {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_CONF_92) };
        return ptr::null_mut();
    };
    // SAFETY: `ext_nid` is an integer NID; the read hold protects the row.
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
        if ctx.is_null() {
            // Deliberate deviation: `v3_conf.c` reads `ctx->db` here, so a NULL
            // `ctx` is undefined behaviour in the authority. The public entries
            // document `ctx` as NULL-or-live, so this input is reachable and is
            // refused rather than dereferenced.
            // nothing to release; the refusal is the whole effect.
            // SAFETY: the site is a compile-time constant; no pointer is read.
            unsafe { raise_site(&V3_CONF_410_NULL) };
            return ptr::null_mut();
        }
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
/// A NULL `ctx` is refused by the `r2i` arm or by the first section read with an error, not
/// dereferenced. A NULL `value` is refused with an error before the prefix scan, instead of
/// being dereferenced as the authority does (divergence `D-V3-CONF-NULL-VALUE-1`).
unsafe fn X509V3_EXT_nconf_int(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    section: *const c_char,
    name: *const c_char,
    value: *const c_char,
) -> *mut X509Extension {
    if value.is_null() {
        let mut msg: Vec<u8> = Vec::new();
        if !section.is_null() {
            msg.extend_from_slice(b"section=");
            // SAFETY: `section` is NUL-terminated.
            unsafe { push_cstr(&mut msg, section) };
            msg.extend_from_slice(b", ");
        }
        msg.extend_from_slice(b"name=");
        // SAFETY: `name` is NULL or NUL-terminated; `push_cstr` writes `(null)` for NULL.
        unsafe { push_cstr(&mut msg, name) };
        msg.extend_from_slice(b", value=(null)");
        msg.push(0);
        let site = if section.is_null() {
            &V3_CONF_52
        } else {
            &V3_CONF_48
        };
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(site, msg.as_ptr().cast()) };
        return ptr::null_mut();
    }
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
/// `conf` NULL or live; `ctx` NULL or live; `name`/`value` NULL or NUL-terminated. A NULL
/// `ctx` is refused by the `r2i` arm or by the first section read with an error, not
/// dereferenced. A NULL `value` is refused with an error before the prefix scan, instead of
/// being dereferenced as the authority does (divergence `D-V3-CONF-NULL-VALUE-1`).
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
/// `conf` NULL or live; `ctx` NULL or live; `value` NULL or NUL-terminated. A NULL `ctx` is
/// refused by the `r2i` arm or by the first section read with an error, not dereferenced. A NULL
/// `value` is refused with an error before the prefix scan, instead of being dereferenced as the
/// authority does (divergence `D-V3-CONF-NULL-VALUE-1`).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_nconf_nid(
    conf: *mut Conf,
    ctx: *mut X509V3Ctx,
    ext_nid: c_int,
    value: *const c_char,
) -> *mut X509Extension {
    if value.is_null() {
        let mut msg = b"value=(null)".to_vec();
        msg.push(0);
        // SAFETY: the site is a declared constant; `msg` is NUL-terminated.
        unsafe { raise_site_data(&V3_CONF_52, msg.as_ptr().cast()) };
        return ptr::null_mut();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::{ERR_clear_error, ERR_get_error};
    use crate::runtime::obj::{
        NID_basic_att_constraints, NID_basic_constraints, NID_ext_key_usage, NID_group_ac,
        NID_indirect_issuer, NID_info_access, NID_inhibit_any_policy, NID_issuerSignTool,
        NID_netscape_comment, NID_no_assertion, NID_no_rev_avail, NID_policy_constraints,
        NID_policy_mappings, NID_sbgp_autonomousSysNum, NID_single_use, NID_soa_identifier,
        NID_subjectSignTool, NID_subject_alt_name, NID_sxnet, NID_tlsfeature, OBJ_obj2nid,
    };
    use crate::x509::v3_lib::{
        X509V3ExtMethod, X509V3_EXT_add, X509V3_EXT_cleanup, X509V3_EXT_d2i,
    };
    use crate::x509::x509_v3::X509_EXTENSION_get_data;

    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

    use crate::asn1::items::ASN1_OCTET_STRING_it;
    use crate::asn1::layout::Asn1Item;
    use crate::runtime::obj::OBJ_create;
    use crate::x509::v3_bcons::{
        BASIC_CONSTRAINTS_free, BASIC_CONSTRAINTS_it, BASIC_CONSTRAINTS_new,
    };

    /// Set by [`hold_probe_v2i`] to whether the callback ran under the registry read hold.
    static HOLD_SEEN_IN_V2I: AtomicBool = AtomicBool::new(false);
    /// Set by [`hold_probe_s2i`] to whether the callback ran under the registry read hold.
    static HOLD_SEEN_IN_S2I: AtomicBool = AtomicBool::new(false);
    /// Set by [`hold_probe_it`] to whether the row's `it` accessor ran under the hold.
    static HOLD_SEEN_IN_IT: AtomicBool = AtomicBool::new(false);
    /// Set by [`reentrant_write_v2i`] to whether it observed the registry read hold.
    static WRITER_HOLD_SEEN: AtomicBool = AtomicBool::new(false);
    /// Set by [`reentrant_write_v2i`] to the value the re-entrant `X509V3_EXT_add` returned.
    static WRITER_RESULT: AtomicI32 = AtomicI32::new(-1);
    /// The row [`reentrant_write_v2i`] tries to add, installed by the test that uses it.
    static REENTRANT_TARGET: AtomicPtr<X509V3ExtMethod> = AtomicPtr::new(ptr::null_mut());

    /// The B53 canary: a `v2i` callback that, while `do_ext_nconf` holds the registry
    /// **read** hold on this same thread, requests the registry **write** hold through
    /// [`X509V3_EXT_add`]. With the per-thread reader accounting `write_lock` refuses (0);
    /// without it the calling thread waits for its own read and the dispatch never returns.
    unsafe extern "C" fn reentrant_write_v2i(
        _method: *const X509V3ExtMethod,
        _ctx: *mut c_void,
        _values: *mut OpenSslStack,
    ) -> *mut c_void {
        WRITER_HOLD_SEEN.store(
            crate::x509::v3_lib::registry_read_held_on_this_thread(),
            Ordering::SeqCst,
        );
        let target = REENTRANT_TARGET.load(Ordering::SeqCst);
        // SAFETY: `target` is the leaked `'static` row the test installed before spawning the
        // dispatch; the write request must be refused while this thread holds the read.
        let result = unsafe { X509V3_EXT_add(target) };
        WRITER_RESULT.store(result, Ordering::SeqCst);
        BASIC_CONSTRAINTS_new().cast::<c_void>()
    }

    /// A `v2i` row wrapping [`reentrant_write_v2i`]; it still carries the encoder probe so the
    /// dispatch builds a real extension through `do_ext_i2d`.
    fn reentrant_write_row(nid: c_int) -> X509V3ExtMethod {
        X509V3ExtMethod {
            v2i: Some(reentrant_write_v2i),
            ..hold_probe_row(nid)
        }
    }

    /// A `v2i` probe: it records the hold **on entry**, before anything else can take a read hold of
    /// its own, then builds a `BASIC_CONSTRAINTS` for the row's declared item.
    unsafe extern "C" fn hold_probe_v2i(
        _method: *const X509V3ExtMethod,
        _ctx: *mut c_void,
        _values: *mut OpenSslStack,
    ) -> *mut c_void {
        HOLD_SEEN_IN_V2I.store(
            crate::x509::v3_lib::registry_read_held_on_this_thread(),
            Ordering::SeqCst,
        );
        BASIC_CONSTRAINTS_new().cast::<c_void>()
    }

    /// An `s2i` probe with the same recording rule as [`hold_probe_v2i`]. It is the B52 control's
    /// slot: `do_ext_nconf`'s `s2i` arm is a distinct branch from the `v2i` arm B51 tested.
    unsafe extern "C" fn hold_probe_s2i(
        _method: *const X509V3ExtMethod,
        _ctx: *mut c_void,
        _value: *const c_char,
    ) -> *mut c_void {
        HOLD_SEEN_IN_S2I.store(
            crate::x509::v3_lib::registry_read_held_on_this_thread(),
            Ordering::SeqCst,
        );
        BASIC_CONSTRAINTS_new().cast::<c_void>()
    }

    /// The row's `it` accessor. `do_ext_i2d` and `X509V3_EXT_d2i` call it *after* the lookup has
    /// returned, so it records the hold at the last point a dispatcher still uses the row.
    unsafe extern "C" fn hold_probe_it() -> *const Asn1Item {
        HOLD_SEEN_IN_IT.store(
            crate::x509::v3_lib::registry_read_held_on_this_thread(),
            Ordering::SeqCst,
        );
        BASIC_CONSTRAINTS_it()
    }

    /// A caller-owned row pairing the two probes with the `BASIC_CONSTRAINTS` item.
    fn hold_probe_row(nid: c_int) -> X509V3ExtMethod {
        X509V3ExtMethod {
            ext_nid: nid,
            ext_flags: 0,
            it: Some(hold_probe_it),
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: Some(hold_probe_v2i),
            i2r: None,
            r2i: None,
            usr_data: ptr::null_mut(),
        }
    }

    /// The `s2i` counterpart of [`hold_probe_row`]: same item and `it`, but the construction slot
    /// is the `s2i` arm, so the dispatch reaches `:1095` rather than the `v2i` arm.
    fn s2i_hold_probe_row(nid: c_int) -> X509V3ExtMethod {
        X509V3ExtMethod {
            s2i: Some(hold_probe_s2i),
            v2i: None,
            ..hold_probe_row(nid)
        }
    }

    /// Register a fresh object and answer its NID. A fresh NID has no `STANDARD_EXTS` row, so the
    /// probe row registered for it is reached only through the dynamic `EXT_LIST` fallback.
    fn fresh_nid(oid: &CStr, sn: &CStr, ln: &CStr) -> c_int {
        // SAFETY: all three strings are NUL-terminated and `OBJ_create` copies them.
        let nid = unsafe { OBJ_create(oid.as_ptr(), sn.as_ptr(), ln.as_ptr()) };
        assert_ne!(nid, 0, "the object must be registered under a fresh NID");
        nid
    }

    /// Build an extension of `nid` whose value is `der`.
    fn extension_with_der(nid: c_int, der: &[u8]) -> *mut X509Extension {
        let value = ASN1_OCTET_STRING_new();
        assert!(!value.is_null(), "the extension value must be allocatable");
        // SAFETY: `value` is live and uniquely owned; `der` is `der.len()` readable bytes.
        let set = unsafe {
            crate::asn1::string::ASN1_OCTET_STRING_set(value, der.as_ptr(), der.len() as c_int)
        };
        assert_eq!(set, 1);
        // SAFETY: `value` is live; the constructor copies its contents.
        let ext = unsafe { X509_EXTENSION_create_by_NID(ptr::null_mut(), nid, 0, value) };
        // SAFETY: the extension copied the octets; release this test's reference.
        unsafe { ASN1_OCTET_STRING_free(value) };
        assert!(!ext.is_null(), "the extension must be created");
        ext
    }

    /// Registers a probe row under a fresh NID and answers `(nid, row)`.
    ///
    /// The registry **borrows** the caller's row: it stores the pointer and, on
    /// `X509V3_EXT_cleanup`, frees only a `X509V3_EXT_DYNAMIC` copy. The row must therefore outlive
    /// the registry entry. Leaking it gives it the `'static` lifetime that borrow requires; this is
    /// sound here because the tests run in a dedicated test process, every call registers its own
    /// fresh row under a fresh NID, cleanup must not free a non-`DYNAMIC` row, and the leak is
    /// bounded by that process's lifetime. Keeping the row as a stack local instead leaves the
    /// registry pointing into a dead helper frame.
    fn register_hold_probe(
        oid: &CStr,
        sn: &CStr,
        ln: &CStr,
    ) -> (c_int, &'static mut X509V3ExtMethod) {
        let nid = fresh_nid(oid, sn, ln);
        let row = Box::leak(Box::new(hold_probe_row(nid)));
        // SAFETY: `row` is a leaked `'static` row that outlives the registry entry; the call takes
        // the write hold and stores the pointer without taking ownership.
        let added = unsafe { X509V3_EXT_add(row as *mut X509V3ExtMethod) };
        assert_eq!(added, 1, "the probe row must register");
        (nid, row)
    }

    /// Registers the `s2i` probe row under a fresh NID, with the same borrowed-row lifetime rule
    /// as [`register_hold_probe`].
    fn register_s2i_hold_probe(
        oid: &CStr,
        sn: &CStr,
        ln: &CStr,
    ) -> (c_int, &'static mut X509V3ExtMethod) {
        let nid = fresh_nid(oid, sn, ln);
        let row = Box::leak(Box::new(s2i_hold_probe_row(nid)));
        // SAFETY: `row` is a leaked `'static` row that outlives the registry entry; the call takes
        // the write hold and stores the pointer without taking ownership.
        let added = unsafe { X509V3_EXT_add(row as *mut X509V3ExtMethod) };
        assert_eq!(added, 1, "the s2i probe row must register");
        (nid, row)
    }

    /// The B51 liveness canary: `do_ext_nconf` must hold the registry read lock from the row
    /// lookup, across the `v2i` callback that receives `method`, and on through the encoder that
    /// reads the row's `it`. Removing the guard makes both probes observe no hold and this test
    /// fails deterministically (no second thread is involved; the probe is thread-local).
    #[test]
    fn the_v2i_dispatch_holds_the_registry_read_lock_across_the_callback() {
        let _serial = crate::test_support::lock_global_state();
        HOLD_SEEN_IN_V2I.store(false, Ordering::SeqCst);
        HOLD_SEEN_IN_IT.store(false, Ordering::SeqCst);
        // Neutral control: outside any dispatch this thread must not already hold the registry
        // read lock, otherwise a probe observing `false` below would prove nothing.
        assert!(
            !crate::x509::v3_lib::registry_read_held_on_this_thread(),
            "the neutral control must observe no registry read hold outside a dispatch"
        );
        let (nid, _row) =
            register_hold_probe(c"1.3.6.1.4.1.57264.51.1", c"b51-hold-v2i", c"B51 hold v2i");
        // SAFETY: the value is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, c"CA:TRUE".as_ptr())
        };
        // SAFETY: no pointer arguments; cleanup retires this test's registry entry. The row is
        // caller-owned, so cleanup does not release it.
        unsafe { X509V3_EXT_cleanup() };
        assert!(!ext.is_null(), "the probe row must build an extension");
        assert!(
            HOLD_SEEN_IN_V2I.load(Ordering::SeqCst),
            "the v2i callback ran without the registry read hold: do_ext_nconf released the row"
        );
        assert!(
            HOLD_SEEN_IN_IT.load(Ordering::SeqCst),
            "the encoder used the row after the registry read hold was released"
        );
        // SAFETY: `ext` is this frame's own.
        unsafe { X509_EXTENSION_free(ext) };
    }

    /// The B52 liveness canary on the **`s2i` arm**. B51's hold was proven on the `v2i` arm only;
    /// this drives the distinct `s2i` branch at `src/x509/v3_conf.rs:1095` through the same
    /// `do_ext_nconf` guard, with a registered row so the callback is reached through the registry
    /// and never called directly. Removing the guard makes both probes observe no hold and this
    /// test fails deterministically (the probe is thread-local; no second thread is involved).
    #[test]
    fn the_s2i_dispatch_holds_the_registry_read_lock_across_the_callback() {
        let _serial = crate::test_support::lock_global_state();
        HOLD_SEEN_IN_S2I.store(false, Ordering::SeqCst);
        HOLD_SEEN_IN_IT.store(false, Ordering::SeqCst);
        // Neutral control: outside any dispatch this thread must not already hold the registry
        // read lock, otherwise a probe observing `false` below would prove nothing.
        assert!(
            !crate::x509::v3_lib::registry_read_held_on_this_thread(),
            "the neutral control must observe no registry read hold outside a dispatch"
        );
        let (nid, _row) =
            register_s2i_hold_probe(c"1.3.6.1.4.1.57264.52.1", c"b52-hold-s2i", c"B52 hold s2i");
        // SAFETY: the value is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, c"ignored".as_ptr())
        };
        // SAFETY: no pointer arguments; cleanup retires this test's registry entry. The row is
        // caller-owned, so cleanup does not release it.
        unsafe { X509V3_EXT_cleanup() };
        assert!(!ext.is_null(), "the probe row must build an extension");
        assert!(
            HOLD_SEEN_IN_S2I.load(Ordering::SeqCst),
            "the s2i callback ran without the registry read hold: do_ext_nconf released the row"
        );
        assert!(
            HOLD_SEEN_IN_IT.load(Ordering::SeqCst),
            "the encoder used the row after the registry read hold was released"
        );
        // SAFETY: `ext` is this frame's own.
        unsafe { X509_EXTENSION_free(ext) };
    }

    /// The `X509V3_EXT_i2d` caller has the same window as `do_ext_nconf`: it resolves the row and
    /// then `do_ext_i2d` reads `it`/`i2d` from it. Removing that guard makes the accessor probe
    /// observe no hold.
    #[test]
    fn the_i2d_entry_point_holds_the_registry_read_lock_across_the_encoder() {
        let _serial = crate::test_support::lock_global_state();
        HOLD_SEEN_IN_IT.store(false, Ordering::SeqCst);
        let (nid, _row) =
            register_hold_probe(c"1.3.6.1.4.1.57264.51.2", c"b51-hold-i2d", c"B51 hold i2d");
        let value = BASIC_CONSTRAINTS_new();
        assert!(!value.is_null(), "the value must be allocatable");
        // SAFETY: `value` is the internal structure the row's `it` encodes; the row is live.
        let ext = unsafe { X509V3_EXT_i2d(nid, 0, value.cast::<c_void>()) };
        // SAFETY: no pointer arguments; cleanup retires this test's registry entry.
        unsafe { X509V3_EXT_cleanup() };
        assert!(!ext.is_null(), "the probe row must encode");
        assert!(
            HOLD_SEEN_IN_IT.load(Ordering::SeqCst),
            "the encoder read the row after X509V3_EXT_i2d released the read hold"
        );
        // SAFETY: both values are this frame's own.
        unsafe {
            BASIC_CONSTRAINTS_free(value);
            X509_EXTENSION_free(ext);
        }
    }

    /// `X509V3_EXT_d2i` resolves the row through `X509V3_EXT_get` and then reads its `it`/`d2i`
    /// slot; it is the decoder's instance of the same window. Removing that guard makes the
    /// accessor probe observe no hold.
    #[test]
    fn the_d2i_entry_point_holds_the_registry_read_lock_across_the_decoder() {
        let _serial = crate::test_support::lock_global_state();
        HOLD_SEEN_IN_IT.store(false, Ordering::SeqCst);
        let (nid, _row) =
            register_hold_probe(c"1.3.6.1.4.1.57264.51.3", c"b51-hold-d2i", c"B51 hold d2i");
        // `BASIC_CONSTRAINTS ::= SEQUENCE { ca BOOLEAN DEFAULT FALSE }`, ca = TRUE.
        let ext = extension_with_der(nid, &[0x30, 0x03, 0x01, 0x01, 0xFF]);
        // SAFETY: `ext` is a live extension this frame owns.
        let decoded = unsafe { X509V3_EXT_d2i(ext) };
        // SAFETY: no pointer arguments; cleanup retires this test's registry entry.
        unsafe { X509V3_EXT_cleanup() };
        assert!(!decoded.is_null(), "the probe row must decode");
        assert!(
            HOLD_SEEN_IN_IT.load(Ordering::SeqCst),
            "the decoder read the row after X509V3_EXT_d2i released the read hold"
        );
        // SAFETY: both values are this frame's own.
        unsafe {
            BASIC_CONSTRAINTS_free(decoded.cast());
            X509_EXTENSION_free(ext);
        }
    }

    /// B53: a registry **writer** requested from inside a dispatcher callback that runs under the
    /// registry **read** hold must be refused, not waited on. The dispatch runs on a spawned thread
    /// so the harness can bound the wait; a self-deadlock reports "timed out — deadlock" and aborts
    /// rather than leaving the process alive with a thread wedged on its own read (which would hang
    /// every later registry user in the same test process).
    #[test]
    fn a_registry_writer_requested_under_a_read_hold_is_refused_not_deadlocked() {
        let _serial = crate::test_support::lock_global_state();
        WRITER_RESULT.store(-1, Ordering::SeqCst);
        WRITER_HOLD_SEEN.store(false, Ordering::SeqCst);

        // The row the callback tries to add. With the refusal it is never published, so it must
        // remain caller-owned; if the write were admitted it would change the row count below.
        let target_nid = fresh_nid(
            c"1.3.6.1.4.1.57264.53.2",
            c"b53-write-target",
            c"B53 write target",
        );
        let target: &'static mut X509V3ExtMethod = Box::leak(Box::new(hold_probe_row(target_nid)));
        REENTRANT_TARGET.store(target as *mut X509V3ExtMethod, Ordering::SeqCst);

        let nid = fresh_nid(
            c"1.3.6.1.4.1.57264.53.1",
            c"b53-reentrant-write",
            c"B53 reentrant write",
        );
        let row = Box::leak(Box::new(reentrant_write_row(nid)));
        // SAFETY: `row` is a leaked `'static` row and no registry read is held on this thread here.
        assert_eq!(unsafe { X509V3_EXT_add(row as *mut X509V3ExtMethod) }, 1);

        let before = crate::x509::v3_lib::registry_row_count();
        assert!(
            before >= 1,
            "the dispatcher row must be registered before the dispatch"
        );

        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let worker = std::thread::spawn(move || {
            // SAFETY: the value is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
            let ext = unsafe {
                X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, c"ignored".as_ptr())
            };
            let built = !ext.is_null();
            if built {
                // SAFETY: `ext` is this thread's own extension.
                unsafe { X509_EXTENSION_free(ext) };
            }
            // A closed receiver is fine: the main thread may already have timed out.
            let _ = tx.send(built);
        });

        // Bounded wait: a self-deadlock must surface as this explicit failure, not as a hung
        // harness. `assert!` is the failing outcome here; the worker (still holding the read and
        // blocked requesting the write) is left detached, so the process terminates once the
        // harness writes its summary instead of waiting on the wedged thread.
        let (completed, failure) = match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(built) => (
                built,
                "the re-entrant v2i callback must still build the extension",
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (
                false,
                "timed out — deadlock: write_lock waited on the caller's own read hold",
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                (false, "the dispatch thread exited without reporting")
            }
        };
        assert!(completed, "{failure}");
        assert!(
            worker.join().is_ok(),
            "the dispatch thread must finish without panicking"
        );

        assert!(
            WRITER_HOLD_SEEN.load(Ordering::SeqCst),
            "the callback ran without the registry read hold: do_ext_nconf released the row"
        );
        assert_eq!(
            WRITER_RESULT.load(Ordering::SeqCst),
            0,
            "X509V3_EXT_add must report the refusal (0) instead of waiting"
        );
        assert_eq!(
            crate::x509::v3_lib::registry_row_count(),
            before,
            "a refused writer must leave the registry unchanged"
        );

        // SAFETY: no pointer arguments; cleanup retires the dispatcher row. The target row was
        // never added, so it stays caller-owned and the leaks are bounded by the test process.
        unsafe { X509V3_EXT_cleanup() };
        assert_eq!(
            crate::x509::v3_lib::registry_row_count(),
            0,
            "cleanup must empty the registry after the refusal"
        );
    }

    /// One `(nid, config value)` pair per `v2i` decoder B51 discharges. Each value is accepted by
    /// the standard row's only construction slot, so a non-NULL extension proves the callback ran.
    const V2I_ACCEPT: [(c_int, &core::ffi::CStr); 10] = [
        (NID_sbgp_autonomousSysNum, c"AS:1"),
        (NID_basic_att_constraints, c"authority:TRUE,pathlen:1"),
        (NID_basic_constraints, c"CA:TRUE,pathlen:1"),
        (NID_ext_key_usage, c"serverAuth"),
        (NID_info_access, c"OCSP;URI:http://example.com"),
        (NID_issuerSignTool, c"signTool:tool"),
        (NID_policy_constraints, c"requireExplicitPolicy:1"),
        (NID_policy_mappings, c"1.2.3.4:1.2.3.5"),
        (NID_sxnet, c"1:user"),
        (NID_tlsfeature, c"status_request"),
    ];

    /// The same rows with a value each decoder must refuse. Every arm drives a distinct
    /// partial-decode release path in its callback.
    const V2I_REJECT: [(c_int, &core::ffi::CStr); 10] = [
        (NID_sbgp_autonomousSysNum, c"XX:1"),
        (NID_basic_att_constraints, c"authority:bogus"),
        (NID_basic_constraints, c"CA:bogus"),
        (NID_ext_key_usage, c"notanoid"),
        (NID_info_access, c"OCSP"),
        (NID_issuerSignTool, c"bogusTool:tool"),
        (NID_policy_constraints, c"requireExplicitPolicy:bogus"),
        (NID_policy_mappings, c"1.2.3.4"),
        (NID_sxnet, c"notanint:user"),
        (NID_tlsfeature, c"notafeature"),
    ];

    /// Every discharged decoder builds its object end-to-end through the real `v2i` dispatcher.
    /// `X509V3_EXT_nconf_nid` resolves the standard row and, because these rows carry only `v2i`
    /// among the construction slots, a non-NULL, correctly tagged extension can be produced only
    /// by the callback under test.
    #[test]
    fn v2i_callbacks_build_end_to_end() {
        ERR_clear_error();
        for &(nid, value) in V2I_ACCEPT.iter() {
            // SAFETY: `value` is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
            let ext = unsafe {
                X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr())
            };
            assert!(!ext.is_null(), "nid {nid} must build an extension");
            // SAFETY: `ext` is live and this frame owns it.
            unsafe {
                let obj = X509_EXTENSION_get_object(ext);
                assert_eq!(OBJ_obj2nid(obj), nid, "nid {nid} must tag the extension");
                let data = X509_EXTENSION_get_data(ext);
                assert!(!data.is_null(), "nid {nid} must carry encoded data");
                assert!((*data).length > 0, "nid {nid} must carry non-empty DER");
                X509_EXTENSION_free(ext);
            }
        }
    }

    /// The same rows refuse a bad value through the callback, releasing the partial object and
    /// answering NULL before `do_ext_i2d`'s encoder runs.
    #[test]
    fn v2i_callbacks_reject_bad_values() {
        ERR_clear_error();
        for &(nid, value) in V2I_REJECT.iter() {
            // SAFETY: `value` is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
            let ext = unsafe {
                X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr())
            };
            assert!(ext.is_null(), "nid {nid} must refuse the bad value");
            ERR_clear_error();
        }
    }

    /// The dispatcher's pre-slot guard: a value `X509V3_parse_list` cannot turn into even one
    /// `CONF_VALUE` is refused before any `v2i` callback. Removing the
    /// `nval.is_null() || num <= 0` refusal (`src/x509/v3_conf.rs:1041`) lets the callback build an
    /// empty object and this assertion fails.
    #[test]
    fn an_empty_value_is_refused_before_the_v2i_slot() {
        ERR_clear_error();
        // SAFETY: the value is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                NID_basic_constraints,
                c" ".as_ptr(),
            )
        };
        assert!(ext.is_null(), "an empty value must not reach the v2i slot");
        assert_ne!(ERR_get_error(), 0, "the refusal must raise");
    }

    /// One `(nid, config value)` pair per `s2i` callback B52 discharges. Each row carries no
    /// `v2i`, so `do_ext_nconf` reaches the `s2i` arm and a non-NULL, correctly tagged extension
    /// can be produced only by the callback under test. The five `ASN1_NULL` rows ignore the
    /// value; `ia5_s2i`, `s2i_asn1_int` and `utf8_s2i` parse it.
    const S2I_ACCEPT: [(c_int, &core::ffi::CStr); 9] = [
        (NID_group_ac, c"ignored"),
        (NID_netscape_comment, c"example.test"),
        (NID_indirect_issuer, c"ignored"),
        (NID_inhibit_any_policy, c"1"),
        (NID_no_assertion, c"ignored"),
        (NID_no_rev_avail, c"ignored"),
        (NID_single_use, c"ignored"),
        (NID_soa_identifier, c"ignored"),
        (NID_subjectSignTool, c"signing-tool"),
    ];

    /// Every discharged `s2i` decoder builds its object end-to-end through the real dispatcher.
    /// `X509V3_EXT_nconf_nid` resolves each standard row and calls its `s2i` slot; the row has no
    /// `v2i`, so nothing else can construct the value.
    #[test]
    fn s2i_callbacks_build_end_to_end() {
        ERR_clear_error();
        for &(nid, value) in S2I_ACCEPT.iter() {
            // SAFETY: `value` is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
            let ext = unsafe {
                X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr())
            };
            assert!(
                !ext.is_null(),
                "nid {nid} must build an extension through its s2i callback"
            );
            // SAFETY: `ext` is live and this frame owns it.
            unsafe {
                let obj = X509_EXTENSION_get_object(ext);
                assert_eq!(OBJ_obj2nid(obj), nid, "nid {nid} must tag the extension");
                let data = X509_EXTENSION_get_data(ext);
                assert!(!data.is_null(), "nid {nid} must carry encoded data");
                assert!((*data).length > 0, "nid {nid} must carry non-empty DER");
                X509_EXTENSION_free(ext);
            }
        }
    }

    /// `s2i_asn1_int`'s failure path, reached through the real dispatcher: the parse consumes no
    /// complete number, the callback frees its partial `BIGNUM`/`ASN1_INTEGER`, and `do_ext_nconf`
    /// answers NULL before the encoder. Removing that failure handling would return a partially
    /// built integer instead of NULL.
    #[test]
    fn s2i_asn1_int_callback_rejects_a_bad_value() {
        ERR_clear_error();
        // SAFETY: the value is NUL-terminated; NULL `conf`/`ctx` are what the contract allows.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                NID_inhibit_any_policy,
                c"12x".as_ptr(),
            )
        };
        assert!(
            ext.is_null(),
            "a bad integer must be refused by the s2i callback"
        );
        assert_ne!(ERR_get_error(), 0, "the refusal must raise");
        ERR_clear_error();
    }

    // ---------------------------------------------------------------------------------------
    // B54: the config-decode dispatch (`v2i`/`s2i`) supplies a live `CONF_VALUE` stack or a
    // NUL-terminated value, and the row's own item is what encodes the returned object.
    // ---------------------------------------------------------------------------------------

    /// Whether the last `v2i` probe found its own declared item on the row it was called on.
    static CONF_ITEM_MATCHED: AtomicBool = AtomicBool::new(false);
    /// Whether the last `v2i` probe found the live `CONF_VALUE` the dispatcher parsed.
    static CONF_INPUT_OK: AtomicBool = AtomicBool::new(false);
    /// The `s2i` twins.
    static S2I_ITEM_MATCHED: AtomicBool = AtomicBool::new(false);
    static S2I_STR_OK: AtomicBool = AtomicBool::new(false);

    /// B54-C3: a `v2i` probe that (a) verifies the row it is installed in declares the item it
    /// produces, (b) verifies the dispatcher supplied a live `name:value` entry, and (c) refuses
    /// when (a) fails. The check happens before any input is used, so a mispaired row is caught
    /// by the type check and never reaches the encoder.
    unsafe extern "C" fn b54_conf_v2i(
        method: *const X509V3ExtMethod,
        _ctx: *mut c_void,
        values: *mut OpenSslStack,
    ) -> *mut c_void {
        // SAFETY: `method` is the live row the dispatcher resolved; `it` is its accessor.
        let declared = unsafe { (*method).it }.and_then(|it| {
            // SAFETY: `it` is the row's item accessor.
            let p = unsafe { it() };
            if p.is_null() {
                None
            } else {
                Some(p)
            }
        });
        // SAFETY: the item accessor answers a static item the crate owns.
        let expected = ASN1_OCTET_STRING_it();
        let matched = matches!(declared, Some(p) if p == expected);
        CONF_ITEM_MATCHED.store(matched, Ordering::SeqCst);

        // SAFETY: `values` is the dispatcher's live non-empty stack; `i = 0` is in bounds.
        let num = unsafe { OPENSSL_sk_num(values) };
        if num > 0 {
            // SAFETY: `values` is live and `0` is in bounds; the element is a `CONF_VALUE`.
            let cnf = unsafe { OPENSSL_sk_value(values, 0) }.cast::<ConfValue>();
            // SAFETY: `cnf` is live; both fields are NULL or NUL-terminated.
            let (name, value) = unsafe { ((*cnf).name, (*cnf).value) };
            // SAFETY: the two pointers are NULL or NUL-terminated per the stack contract.
            let ok = unsafe {
                !name.is_null()
                    && !value.is_null()
                    && core::ffi::CStr::from_ptr(name) == c"b54"
                    && core::ffi::CStr::from_ptr(value) == c"probe"
            };
            CONF_INPUT_OK.store(ok, Ordering::SeqCst);
        }

        if !matched {
            // The row declares a different item: refuse before building anything, so the
            // mispairing is reported as a failed extension rather than encoded as the wrong type.
            return ptr::null_mut();
        }
        // SAFETY: the item allocator answers NULL or a fresh octet string owned by the dispatcher.
        crate::asn1::string::ASN1_OCTET_STRING_new().cast::<c_void>()
    }

    /// B54-C4: the `s2i` twin of [`b54_conf_v2i`].
    unsafe extern "C" fn b54_conf_s2i(
        method: *const X509V3ExtMethod,
        _ctx: *mut c_void,
        value: *const c_char,
    ) -> *mut c_void {
        // SAFETY: `method` is the live row the dispatcher resolved; `it` is its accessor.
        let declared = unsafe { (*method).it }.and_then(|it| {
            // SAFETY: `it` is the row's item accessor.
            let p = unsafe { it() };
            if p.is_null() {
                None
            } else {
                Some(p)
            }
        });
        // SAFETY: the item accessor answers a static item the crate owns.
        let expected = ASN1_OCTET_STRING_it();
        let matched = matches!(declared, Some(p) if p == expected);
        S2I_ITEM_MATCHED.store(matched, Ordering::SeqCst);
        // SAFETY: `value` is the caller's NUL-terminated configuration string.
        let ok = unsafe { !value.is_null() && core::ffi::CStr::from_ptr(value) == c"probe" };
        S2I_STR_OK.store(ok, Ordering::SeqCst);

        if !matched {
            return ptr::null_mut();
        }
        // SAFETY: the item allocator answers NULL or a fresh octet string owned by the dispatcher.
        crate::asn1::string::ASN1_OCTET_STRING_new().cast::<c_void>()
    }

    /// One leaked caller-owned row for the B54 config probes.
    fn b54_conf_row(
        nid: c_int,
        item: unsafe extern "C" fn() -> *const Asn1Item,
        v2i: bool,
    ) -> *mut X509V3ExtMethod {
        Box::leak(Box::new(X509V3ExtMethod {
            ext_nid: nid,
            ext_flags: 0,
            it: Some(item),
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: if v2i { None } else { Some(b54_conf_s2i) },
            i2v: None,
            v2i: if v2i { Some(b54_conf_v2i) } else { None },
            i2r: None,
            r2i: None,
            usr_data: ptr::null_mut(),
        }))
    }

    /// The config path: the dispatcher hands the callback a live `CONF_VALUE` (or the raw string)
    /// and encodes the returned object with the row's own `it`; a row whose `it` is not the item
    /// the callback produces is refused by the callback's own check.
    #[test]
    fn config_slots_receive_conf_values_and_check_the_rows_item() {
        // The three probe rows below are process-global registry entries: hold the same global
        // state lock every other registry-touching unit takes, so a concurrent registry-count
        // control (B53) cannot observe them and no concurrent cleanup can retire them.
        let _serial = crate::test_support::lock_global_state();
        use crate::asn1::items::ASN1_INTEGER_it;
        use crate::runtime::obj::OBJ_create;

        let v2i_nid = {
            // SAFETY: all three strings are NUL-terminated and `OBJ_create` copies them.
            let nid = unsafe {
                OBJ_create(
                    c"1.3.6.1.4.1.57264.54.7".as_ptr(),
                    c"b54-v2i".as_ptr(),
                    c"B54 v2i probe".as_ptr(),
                )
            };
            assert_ne!(nid, 0);
            nid
        };
        let bad_nid = {
            // SAFETY: as above.
            let nid = unsafe {
                OBJ_create(
                    c"1.3.6.1.4.1.57264.54.8".as_ptr(),
                    c"b54-bad-v2i".as_ptr(),
                    c"B54 v2i mispaired".as_ptr(),
                )
            };
            assert_ne!(nid, 0);
            nid
        };
        let s2i_nid = {
            // SAFETY: as above.
            let nid = unsafe {
                OBJ_create(
                    c"1.3.6.1.4.1.57264.54.9".as_ptr(),
                    c"b54-s2i".as_ptr(),
                    c"B54 s2i probe".as_ptr(),
                )
            };
            assert_ne!(nid, 0);
            nid
        };

        // SAFETY: the three rows are leaked so they outlive the registry borrows; `_add` takes
        // the write hold.
        for row in [
            b54_conf_row(v2i_nid, ASN1_OCTET_STRING_it, true),
            b54_conf_row(bad_nid, ASN1_INTEGER_it, true),
            b54_conf_row(s2i_nid, ASN1_OCTET_STRING_it, false),
        ] {
            assert_eq!(
                unsafe {
                    // SAFETY: `row` is a live leaked row.
                    X509V3_EXT_add(row)
                },
                1,
                "the probe row must register"
            );
        }

        ERR_clear_error();
        // SAFETY: NULL `conf`/`ctx` are what the entry contract allows; `b54:probe` is
        // NUL-terminated.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                v2i_nid,
                c"b54:probe".as_ptr(),
            )
        };
        assert!(!ext.is_null(), "the correctly paired v2i must build");
        assert!(
            CONF_ITEM_MATCHED.load(Ordering::SeqCst),
            "the v2i row must declare the item the callback produces"
        );
        assert!(
            CONF_INPUT_OK.load(Ordering::SeqCst),
            "the v2i callback must receive the dispatcher's live CONF_VALUE"
        );
        // SAFETY: `ext` is this frame's own.
        unsafe { crate::x509::x_exten::X509_EXTENSION_free(ext) };

        // The mispaired row: a different item, so the callback's own check fires and the
        // extension is refused. No object is ever encoded or freed as the wrong type.
        CONF_ITEM_MATCHED.store(true, Ordering::SeqCst);
        // SAFETY: as above.
        let bad = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                bad_nid,
                c"b54:probe".as_ptr(),
            )
        };
        assert!(bad.is_null(), "the mispaired v2i must be refused");
        assert!(
            !CONF_ITEM_MATCHED.load(Ordering::SeqCst),
            "the probe must observe the mispaired row's declared item"
        );
        ERR_clear_error();

        // The `s2i` arm receives the raw NUL-terminated value, not a parsed stack.
        // SAFETY: NULL `conf`/`ctx` are allowed; `probe` is NUL-terminated.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), s2i_nid, c"probe".as_ptr())
        };
        assert!(!ext.is_null(), "the correctly paired s2i must build");
        assert!(
            S2I_ITEM_MATCHED.load(Ordering::SeqCst),
            "the s2i row must declare the item the callback produces"
        );
        assert!(
            S2I_STR_OK.load(Ordering::SeqCst),
            "the s2i callback must receive the caller's NUL-terminated value"
        );
        // SAFETY: `ext` is this frame's own.
        unsafe { crate::x509::x_exten::X509_EXTENSION_free(ext) };
    }

    /// B54-F1: the section path used to dereference a NULL `ctx`.
    ///
    /// `X509V3_EXT_nconf*` document `ctx` as NULL-or-live, and a `dirName:` value
    /// reaches `X509V3_get_section`, which the authority lets dereference NULL.
    /// The input below is reachable through the public entry and must be refused
    /// with an error rather than faulting.
    #[test]
    fn a_null_config_context_is_refused_on_the_section_path() {
        ERR_clear_error();
        // SAFETY: every pointer argument is NULL or a NUL-terminated literal, which
        // is exactly the input under test.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                NID_subject_alt_name,
                c"dirName:section".as_ptr(),
            )
        };
        assert!(
            ext.is_null(),
            "a NULL ctx must not produce an extension on the section path"
        );
        let err = ERR_get_error();
        assert_ne!(err, 0, "the refusal must be reported on the error stack");
    }

    /// B54-F2: a NULL `value` used to be handed to the prefix scan.
    ///
    /// `X509V3_EXT_nconf*` document `value` as NULL-or-NUL-terminated, but the
    /// authority passes it straight to `v3_check_critical`, which scans it with
    /// `strncmp`. The input below is reachable through the documented contract
    /// and must be refused with an error rather than dereferenced.
    #[test]
    fn a_null_extension_value_is_refused_before_the_prefix_scan() {
        ERR_clear_error();
        // SAFETY: every pointer argument is NULL or a NUL-terminated literal, which
        // is exactly the input under test.
        let ext = unsafe {
            X509V3_EXT_nconf(
                ptr::null_mut(),
                ptr::null_mut(),
                c"basicConstraints".as_ptr(),
                ptr::null(),
            )
        };
        assert!(ext.is_null(), "a NULL value must not produce an extension");
        let err = ERR_get_error();
        assert_ne!(err, 0, "the refusal must be reported on the error stack");

        ERR_clear_error();
        // SAFETY: every pointer argument is NULL or a constant NID, which is
        // exactly the input under test.
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                NID_basic_constraints,
                ptr::null(),
            )
        };
        assert!(
            ext.is_null(),
            "a NULL value must not produce an extension on the NID path"
        );
        let err = ERR_get_error();
        assert_ne!(err, 0, "the refusal must be reported on the error stack");
    }
}

#[cfg(test)]
mod b55_tests {
    #![allow(clippy::expect_used)]
    use super::*;

    use crate::asn1::layout::Asn1Item;
    use crate::runtime::err::{ERR_clear_error, ERR_get_error};
    use crate::runtime::obj::{
        NID_certificate_policies, NID_crl_distribution_points,
        NID_id_aa_issuing_distribution_point, NID_info_access, NID_issuer_alt_name,
        NID_issuing_distribution_point, NID_name_constraints, NID_proxyCertInfo,
        NID_subject_alt_name,
    };
    use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push};
    use crate::x509::v3_cpols::{ossl_v3_cpols, CERTIFICATEPOLICIES_it};
    use crate::x509::v3_crld::{
        ossl_v3_aa_issuing_dist_point, ossl_v3_crld, ossl_v3_freshest_crl, ossl_v3_idp,
        CRL_DIST_POINTS_it, ISSUING_DIST_POINT_it, OSSL_AA_DIST_POINT_it,
    };
    use crate::x509::v3_genn::GENERAL_NAMES_it;
    use crate::x509::v3_info::{ossl_v3_info, ossl_v3_sinfo, AUTHORITY_INFO_ACCESS_it};
    use crate::x509::v3_ncons::{
        ossl_v3_delegated_name_constraints, ossl_v3_holder_name_constraints,
        ossl_v3_name_constraints, NAME_CONSTRAINTS_it,
    };
    use crate::x509::v3_pci::ossl_v3_pci;
    use crate::x509::v3_pcia::PROXY_CERT_INFO_EXTENSION_it;
    use crate::x509::v3_san::{
        ossl_v3_alt, v2i_GENERAL_NAME, v2i_GENERAL_NAMES, v2i_GENERAL_NAME_ex,
    };

    /// The item a row declares: the dispatcher decodes, encodes and frees the callback's answer
    /// with this accessor, so the answer's dynamic type is fixed by the method-table entry.
    fn declared_item(row: &X509V3ExtMethod) -> *const Asn1Item {
        // SAFETY: every row asserted here declares an item accessor, and the accessor is a static
        // `extern "C" fn() -> *const Asn1Item` with no preconditions.
        unsafe { row.it.expect("the row declares an item")() }
    }

    /// B55 type fact, re-checked at this HEAD: the 13 method-table entries that carry the
    /// adjudicated callbacks still declare the item those callbacks produce. The B54-F1 repair
    /// touched only `v3_conf.rs`, and this is the property that makes each row's dynamic type
    /// independent of the input bytes.
    #[test]
    fn b55_rows_still_declare_the_item_their_callbacks_produce() {
        let cases: [(&X509V3ExtMethod, *const Asn1Item); 13] = [
            (&ossl_v3_crld, CRL_DIST_POINTS_it()),
            (&ossl_v3_freshest_crl, CRL_DIST_POINTS_it()),
            (&ossl_v3_idp, ISSUING_DIST_POINT_it()),
            (&ossl_v3_aa_issuing_dist_point, OSSL_AA_DIST_POINT_it()),
            (&ossl_v3_name_constraints, NAME_CONSTRAINTS_it()),
            (&ossl_v3_holder_name_constraints, NAME_CONSTRAINTS_it()),
            (&ossl_v3_delegated_name_constraints, NAME_CONSTRAINTS_it()),
            (&ossl_v3_alt[0], GENERAL_NAMES_it()),
            (&ossl_v3_alt[1], GENERAL_NAMES_it()),
            (&ossl_v3_info, AUTHORITY_INFO_ACCESS_it()),
            (&ossl_v3_sinfo, AUTHORITY_INFO_ACCESS_it()),
            (&ossl_v3_cpols, CERTIFICATEPOLICIES_it()),
            (&ossl_v3_pci, PROXY_CERT_INFO_EXTENSION_it()),
        ];
        for (row, want) in cases {
            assert_eq!(
                declared_item(row),
                want,
                "row NID {} must keep its declared item",
                row.ext_nid
            );
        }
    }

    /// B55 null-context negative control: every adjudicated row whose value can reach a
    /// config-section read is driven through the public entry with a NULL `ctx`. Each call must
    /// answer NULL with the error stack populated and the process must survive. Removing the
    /// `X509V3_get_section` NULL guard makes the first case abort (SIGABRT), which is the
    /// mutation evidence recorded with this receipt.
    #[test]
    fn b55_null_config_context_is_refused_on_every_section_path() {
        let _guard = crate::test_support::lock_global_state();

        // `<nid>, <value>, <row>`: each value is shaped so that, with a live context, the row
        // would read the named section. Here the context is NULL and the read must be refused.
        // `v2i_idp` and `v2i_aaidp` are both listed at B57: the B55-F1 template-walk defect
        // that aborted their refusal cleanup (and a successful aaidp encode) is repaired, so
        // the refusal path now runs to a NULL answer on the error stack.
        let rows: [(c_int, &CStr, &str); 9] = [
            (
                NID_crl_distribution_points,
                c"b55_crl_section",
                "v2i_crld (value-less entry names a section)",
            ),
            (
                NID_issuing_distribution_point,
                c"fullname:b55_idp_section",
                "v2i_idp -> set_dist_point_name -> gnames_from_sectname",
            ),
            (
                NID_id_aa_issuing_distribution_point,
                c"b55_aaidp_section",
                "v2i_aaidp (value-less entry names a section; refused branch frees NULL)",
            ),
            (
                NID_name_constraints,
                c"permitted;dirName:b55_nc_section",
                "v2i_NAME_CONSTRAINTS -> v2i_GENERAL_NAME_ex -> do_dirname",
            ),
            (
                NID_issuer_alt_name,
                c"dirName:b55_issuer_section",
                "v2i_issuer_alt -> v2i_GENERAL_NAME -> do_dirname",
            ),
            (
                NID_subject_alt_name,
                c"dirName:b55_subject_section",
                "v2i_subject_alt -> v2i_GENERAL_NAME -> do_dirname",
            ),
            (
                NID_info_access,
                c"OCSP;dirName:b55_info_section",
                "v2i_AUTHORITY_INFO_ACCESS -> v2i_GENERAL_NAME_ex -> do_dirname",
            ),
            (
                NID_certificate_policies,
                c"@b55_policy_section",
                "r2i_certpol (the r2i arm refuses a NULL ctx)",
            ),
            (
                NID_proxyCertInfo,
                c"@b55_proxy_section",
                "r2i_pci (the r2i arm refuses a NULL ctx)",
            ),
        ];

        for (nid, value, what) in rows {
            ERR_clear_error();
            // SAFETY: every pointer is NULL or a NUL-terminated literal, exactly the input
            // under test.
            let ext = unsafe {
                X509V3_EXT_nconf_nid(ptr::null_mut(), ptr::null_mut(), nid, value.as_ptr())
            };
            assert!(
                ext.is_null(),
                "{what}: a NULL ctx must not produce an extension"
            );
            let err = ERR_get_error();
            assert_ne!(err, 0, "{what}: the refusal must be on the error stack");
            ERR_clear_error();
        }

        // The three helpers are public entry points in their own right; drive each with a live
        // `CONF_VALUE` whose name is `dirName` and whose value names a section.
        let mut cnf = ConfValue {
            section: ptr::null_mut(),
            name: c"dirName".as_ptr().cast_mut(),
            value: c"b55_helper_section".as_ptr().cast_mut(),
        };

        ERR_clear_error();
        // SAFETY: `cnf` is a live local `CONF_VALUE`; the context and method are NULL, which the
        // helper's contract admits.
        let ex = unsafe {
            v2i_GENERAL_NAME_ex(
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                &raw mut cnf,
                0,
            )
        };
        assert!(
            ex.is_null(),
            "v2i_GENERAL_NAME_ex: a NULL ctx must be refused"
        );
        assert_ne!(
            ERR_get_error(),
            0,
            "v2i_GENERAL_NAME_ex: the refusal must be on the error stack"
        );

        ERR_clear_error();
        // SAFETY: `cnf` is a live local `CONF_VALUE`; the context and method are NULL.
        let one = unsafe { v2i_GENERAL_NAME(ptr::null(), ptr::null_mut(), &raw mut cnf) };
        assert!(
            one.is_null(),
            "v2i_GENERAL_NAME: a NULL ctx must be refused"
        );
        assert_ne!(
            ERR_get_error(),
            0,
            "v2i_GENERAL_NAME: the refusal must be on the error stack"
        );

        let nval = OPENSSL_sk_new_null();
        assert!(!nval.is_null(), "the test must own a stack");
        // SAFETY: `nval` is live and `cnf` is a live local entry whose address outlives the call.
        unsafe { OPENSSL_sk_push(nval, (&raw mut cnf).cast::<c_void>()) };
        ERR_clear_error();
        // SAFETY: `nval` is a live stack of live `CONF_VALUE` pointers; the context and method
        // are NULL, which the contract admits.
        let many = unsafe { v2i_GENERAL_NAMES(ptr::null(), ptr::null_mut(), nval) };
        assert!(
            many.is_null(),
            "v2i_GENERAL_NAMES: a NULL ctx must be refused"
        );
        assert_ne!(
            ERR_get_error(),
            0,
            "v2i_GENERAL_NAMES: the refusal must be on the error stack"
        );
        // SAFETY: `nval` is this test's own stack and holds no owned elements.
        unsafe { OPENSSL_sk_free(nval) };
        ERR_clear_error();
    }
}
