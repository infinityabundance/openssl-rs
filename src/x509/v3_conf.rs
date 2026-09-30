//! `crypto/x509/v3_conf.c` — the extension-configuration surface. Phase 10.14.4, **partial at
//! function granularity**.
//!
//! `crypto/x509/v3_conf.c` is 599 lines. This slice lands its **config-value layer** — the part
//! the extension tables call — and withholds the **extension-building chain** by name, because
//! every function in that chain funnels through `X509V3_EXT_get_nid` (`v3_lib.rs`, withheld behind
//! the incomplete `standard_exts[]`, D456).
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
//! ## The endgame addition: `X509V3_EXT_i2d`
//!
//! `X509V3_EXT_i2d` (`:191-200`) and the static `do_ext_i2d` (`:137-187`) it wraps land here now
//! that `X509V3_EXT_get_nid` (`v3_lib.rs`, this slice) exists: they are the encoder
//! `X509V3_add1_i2d` (`v3_lib.c:271`) calls. `X509V3_EXT_i2d` raises
//! `X509V3_R_UNKNOWN_EXTENSION` (`:196`), and `do_ext_i2d` raises `ERR_R_ASN1_LIB` at
//! `:150`/`:158`/`:167` and `ERR_R_X509V3_LIB` at `:176`; all are declared locally below.
//!
//! ## What is still withheld, and the one blocker
//!
//! The rest of the extension-building chain is withheld by name: `do_ext_nconf` (`:79`),
//! `X509V3_EXT_nconf_int` (`:34`), `X509V3_EXT_nconf` (`:58`), `X509V3_EXT_nconf_nid` (`:64`),
//! `X509V3_EXT_add_nconf_sk` (`:309`), `X509V3_EXT_add_nconf` (`:356`), `X509V3_EXT_CRL_add_nconf`
//! (`:369`), `X509V3_EXT_conf` (`:495`), `X509V3_EXT_conf_nid` (`:510`), `X509V3_EXT_add_conf`
//! (`:552`), `X509V3_EXT_CRL_add_conf` (`:569`) and `X509V3_EXT_REQ_add_conf` (`:586`).
//! `X509V3_EXT_REQ_add_nconf` (`:382`) additionally needs `X509_REQ_add_extensions` (`x509_req.c`,
//! 10.14.11).
//!
//! Five more are withheld under D453's second reason — closure complete, but every caller is itself
//! withheld, so the function would be dead code: `v3_check_critical` (`:203`), `v3_check_generic`
//! (`:216`), `v3_generic_extension` (`:235`), `generic_asn1` (`:280`) and `delete_ext` (`:294`).
//! Their own closures are landed (or, for `v3_generic_extension`/`generic_asn1`, land with
//! `ASN1_generate_v3`); only their callers block them. (`do_ext_i2d` left this list with this
//! slice, because `X509V3_EXT_i2d` is now its reachable caller.)
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
//! `err_sites::ErrSite` shape, as `src/store/store_register.rs` does. The reachable sites are the
//! `X509V3_R_OPERATION_NOT_DEFINED` refusals of `X509V3_get_string`/`_get_section` and the
//! `ERR_R_PASSED_NULL_PARAMETER`/`ERR_R_PASSED_INVALID_ARGUMENT` refusals of the four setters.
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

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::evp::pkey::EvpPkey;
use crate::runtime::conf::lib::{
    CONF_get_section, CONF_get_string, NCONF_get_section, NCONF_get_string,
};
use crate::runtime::conf::types::Conf;
use crate::runtime::err::raise_site;
use crate::runtime::lhash::OpenSslLhash;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_get_nid};
use crate::x509::x509_v3::X509_EXTENSION_create_by_NID;
use crate::x509::x_crl::X509Crl;
use crate::x509::x_exten::X509Extension;
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
