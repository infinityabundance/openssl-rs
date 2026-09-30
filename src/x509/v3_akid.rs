//! `crypto/x509/v3_akid.c` — the authority-key-identifier table and its `i2v`/`v2i` callbacks.
//! Phase 10.15, the endgame slice.
//!
//! `crypto/x509/v3_akid.c` is 237 lines. Its unit is small and lands whole:
//!
//! * [`ossl_v3_akey_id`] (`:27-36`), the `NID_authority_key_identifier` row whose `it` is
//!   `ASN1_ITEM_ref(AUTHORITY_KEYID)` and whose `i2v`/`v2i` are the two callbacks below. The row is
//!   one of the 73 entries `standard_exts[]` names.
//! * `i2v_AUTHORITY_KEYID` (`:38-85`) — the printer. Its callees are all landed:
//!   `i2s_ASN1_OCTET_STRING` (`v3_skid.rs`), `X509V3_add_value`/`X509V3_conf_free` (`v3_utl.rs`)
//!   and `i2v_GENERAL_NAMES` (`v3_san.rs`).
//! * `v2i_AUTHORITY_KEYID` (`:96-237`) — the builder. Its callees are landed too:
//!   `AUTHORITY_KEYID_new`/`_free` (`v3_akeya.rs`), `X509V3_EXT_d2i` (`v3_lib.rs`),
//!   `X509_get_ext_by_NID`/`X509_get_ext`, `X509_check_private_key`, `X509_NAME_dup`,
//!   `ASN1_INTEGER_dup`, `X509_get_issuer_name`/`X509_get0_serialNumber`, `X509_PUBKEY_set`/`_free`,
//!   `ERR_set_mark`/`ERR_pop_to_mark`, and the stack/`GENERAL_NAME` layer.
//!
//! ## The one pulled-forward dependency
//!
//! `v2i_AUTHORITY_KEYID`'s self-signed fallback calls `ossl_x509_pubkey_hash`
//! (`crypto/x509/v3_skid.c:54-88`). That internal **belongs to `crypto/x509/v3_skid.c`**, and it is
//! landed there (`src/x509/v3_skid.rs`), not here: D472 first transcribed it inside this module to
//! avoid publishing a 72-entry partial `standard_exts[]`, and D472's follow-up moved it to its own
//! unit once the array existed, so this module now reaches it by Rust path. It is not exported
//! (`nm -D` shows no `ossl_x509_pubkey_hash`), so no `#[no_mangle]` is involved.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_akid.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! coordinates are declared locally in the `err_sites::ErrSite` shape (as `v3_san.rs`/`v3_conf.rs`
//! do). The reason values are read from `include/openssl/x509v3err.h` and `include/openssl/err.h`.
//! Every one is reachable through the two landed callbacks.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void, CStr};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_dup;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_free, ASN1_STRING_length};
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::{raise_site, raise_site_data, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{NID_authority_key_identifier, NID_subject_key_identifier};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_akeya::{
    AUTHORITY_KEYID_free, AUTHORITY_KEYID_it, AUTHORITY_KEYID_new, AuthorityKeyid,
};
use crate::x509::v3_conf::{X509V3Ctx, X509V3_CTX_TEST};
use crate::x509::v3_genn::{GENERAL_NAME_free, GENERAL_NAME_new, GeneralName, GEN_DIRNAME};
use crate::x509::v3_lib::{
    X509V3ExtI2v, X509V3ExtMethod, X509V3ExtV2i, X509V3_EXT_d2i, X509V3_EXT_MULTILINE,
};
use crate::x509::v3_san::i2v_GENERAL_NAMES;
use crate::x509::v3_skid::{i2s_ASN1_OCTET_STRING, ossl_x509_pubkey_hash};
use crate::x509::v3_utl::{X509V3_add_value, X509V3_conf_free};
use crate::x509::x509_cmp::{X509_check_private_key, X509_get0_serialNumber, X509_get_issuer_name};
use crate::x509::x509_ext::{X509_get_ext, X509_get_ext_by_NID};
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_free, X509_PUBKEY_set};

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansions — `crypto/x509/v3_akid.c`.
const FILE: &CStr = c"crypto/x509/v3_akid.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509_LIB` — `include/openssl/err.h`, `ERR_LIB_X509 | ERR_RFLAG_COMMON`.
const ERR_R_X509_LIB: c_int = 524299;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in`, `258 | ERR_RFLAG_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `X509V3_R_UNKNOWN_OPTION` — `include/openssl/x509v3err.h:89`.
const X509V3_R_UNKNOWN_OPTION: c_int = 120;
/// `X509V3_R_BAD_VALUE` — `include/openssl/x509v3err.h:25`.
const X509V3_R_BAD_VALUE: c_int = 171;
/// `X509V3_R_UNKNOWN_VALUE` — `include/openssl/x509v3err.h:90`.
const X509V3_R_UNKNOWN_VALUE: c_int = 172;
/// `X509V3_R_NO_ISSUER_CERTIFICATE` — `include/openssl/x509v3err.h:70`.
const X509V3_R_NO_ISSUER_CERTIFICATE: c_int = 121;
/// `X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS` — `include/openssl/x509v3err.h:84`.
const X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS: c_int = 122;
/// `X509V3_R_UNABLE_TO_GET_ISSUER_KEYID` — `include/openssl/x509v3err.h:85`.
const X509V3_R_UNABLE_TO_GET_ISSUER_KEYID: c_int = 123;

/// One `v3_akid.c` raise coordinate, declared locally (see the module doc).
const fn v3_akid_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_akid.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `i2v_AUTHORITY_KEYID`'s failed `i2s_ASN1_OCTET_STRING` at `v3_akid.c:49` (`ERR_R_ASN1_LIB`).
const V3_AKID_49: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(49, c"i2v_AUTHORITY_KEYID", ERR_R_ASN1_LIB);
/// `i2v_AUTHORITY_KEYID`'s failed `X509V3_add_value` at `v3_akid.c:55` (`ERR_R_X509_LIB`).
const V3_AKID_55: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(55, c"i2v_AUTHORITY_KEYID", ERR_R_X509_LIB);
/// `i2v_AUTHORITY_KEYID`'s failed `i2v_GENERAL_NAMES` at `v3_akid.c:63` (`ERR_R_X509_LIB`).
const V3_AKID_63: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(63, c"i2v_AUTHORITY_KEYID", ERR_R_X509_LIB);
/// `i2v_AUTHORITY_KEYID`'s failed `i2s_ASN1_OCTET_STRING` at `v3_akid.c:71` (`ERR_R_ASN1_LIB`).
const V3_AKID_71: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(71, c"i2v_AUTHORITY_KEYID", ERR_R_ASN1_LIB);
/// `v2i_AUTHORITY_KEYID`'s unknown option at `v3_akid.c:123` (`X509V3_R_UNKNOWN_OPTION`, with data).
const V3_AKID_123: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(123, c"v2i_AUTHORITY_KEYID", X509V3_R_UNKNOWN_OPTION);
/// `v2i_AUTHORITY_KEYID`'s bad value at `v3_akid.c:138` (`X509V3_R_BAD_VALUE`, with data).
const V3_AKID_138: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(138, c"v2i_AUTHORITY_KEYID", X509V3_R_BAD_VALUE);
/// `v2i_AUTHORITY_KEYID`'s unknown value at `v3_akid.c:142` (`X509V3_R_UNKNOWN_VALUE`, with data).
const V3_AKID_142: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(142, c"v2i_AUTHORITY_KEYID", X509V3_R_UNKNOWN_VALUE);
/// `v2i_AUTHORITY_KEYID`'s NULL context at `v3_akid.c:152` (`ERR_R_PASSED_NULL_PARAMETER`).
const V3_AKID_152: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(152, c"v2i_AUTHORITY_KEYID", ERR_R_PASSED_NULL_PARAMETER);
/// `v2i_AUTHORITY_KEYID`'s missing issuer certificate at `v3_akid.c:156`.
const V3_AKID_156: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(156, c"v2i_AUTHORITY_KEYID", X509V3_R_NO_ISSUER_CERTIFICATE);
/// `v2i_AUTHORITY_KEYID`'s missing issuer key id at `v3_akid.c:193`.
const V3_AKID_193: crate::runtime::err::err_sites::ErrSite = v3_akid_site(
    193,
    c"v2i_AUTHORITY_KEYID",
    X509V3_R_UNABLE_TO_GET_ISSUER_KEYID,
);
/// `v2i_AUTHORITY_KEYID`'s missing issuer details at `v3_akid.c:202`.
const V3_AKID_202: crate::runtime::err::err_sites::ErrSite = v3_akid_site(
    202,
    c"v2i_AUTHORITY_KEYID",
    X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS,
);
/// `v2i_AUTHORITY_KEYID`'s failed `sk_GENERAL_NAME_new_null`/`GENERAL_NAME_new` at `v3_akid.c:210`.
const V3_AKID_210: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(210, c"v2i_AUTHORITY_KEYID", ERR_R_ASN1_LIB);
/// `v2i_AUTHORITY_KEYID`'s failed `sk_GENERAL_NAME_push` at `v3_akid.c:214` (`ERR_R_CRYPTO_LIB`).
const V3_AKID_214: crate::runtime::err::err_sites::ErrSite =
    v3_akid_site(214, c"v2i_AUTHORITY_KEYID", ERR_R_CRYPTO_LIB);

/// Append the bytes of a NUL-terminated C string to a buffer (an `ERR_raise_data` operand).
///
/// # Safety
///
/// `s` must be NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, s: *const c_char) {
    // SAFETY: `s` is NUL-terminated per the contract.
    buf.extend_from_slice(unsafe { CStr::from_ptr(s) }.to_bytes());
}

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(extlist, X509V3_conf_free)` installs.
///
/// # Safety
///
/// `p` must be NULL or a live `CONF_VALUE`.
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the stack contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `(X509V3_EXT_I2V)i2v_AUTHORITY_KEYID` — the cast the row's initialiser writes.
const fn as_i2v(
    f: unsafe extern "C" fn(
        *mut X509V3ExtMethod,
        *mut AuthorityKeyid,
        *mut OpenSslStack,
    ) -> *mut OpenSslStack,
) -> X509V3ExtI2v {
    // SAFETY: both function types take three pointer arguments and answer a pointer; the authority
    // writes exactly this cast in the row.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                *mut X509V3ExtMethod,
                *mut AuthorityKeyid,
                *mut OpenSslStack,
            ) -> *mut OpenSslStack,
            unsafe extern "C" fn(
                *const X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut OpenSslStack,
        >(f)
    })
}

/// `(X509V3_EXT_V2I)v2i_AUTHORITY_KEYID` — the cast the row's initialiser writes.
const fn as_v2i(
    f: unsafe extern "C" fn(
        *mut X509V3ExtMethod,
        *mut X509V3Ctx,
        *mut OpenSslStack,
    ) -> *mut AuthorityKeyid,
) -> X509V3ExtV2i {
    // SAFETY: both function types take three pointer arguments and answer a pointer; the authority
    // writes exactly this cast in the row.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                *mut X509V3ExtMethod,
                *mut X509V3Ctx,
                *mut OpenSslStack,
            ) -> *mut AuthorityKeyid,
            unsafe extern "C" fn(
                *const X509V3ExtMethod,
                *mut c_void,
                *mut OpenSslStack,
            ) -> *mut c_void,
        >(f)
    })
}

/// `const X509V3_EXT_METHOD ossl_v3_akey_id` — `crypto/x509/v3_akid.c:27-36`.
///
/// `NID_authority_key_identifier`, `X509V3_EXT_MULTILINE`, `it = AUTHORITY_KEYID_it`, and the
/// `i2v`/`v2i` pair; every other slot is the authority's zero.
pub static ossl_v3_akey_id: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_authority_key_identifier,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(AUTHORITY_KEYID_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: as_i2v(i2v_AUTHORITY_KEYID),
    v2i: as_v2i(v2i_AUTHORITY_KEYID),
    i2r: None,
    r2i: None,
    usr_data: core::ptr::null_mut(),
};

/// `static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,
/// AUTHORITY_KEYID *akeyid, STACK_OF(CONF_VALUE) *extlist)` — `crypto/x509/v3_akid.c:38-85`.
///
/// # Safety
///
/// `method` may be NULL; `akeyid` must be a live `AUTHORITY_KEYID`; `extlist` is NULL or a stack of
/// this call's own `CONF_VALUE`s.
unsafe extern "C" fn i2v_AUTHORITY_KEYID(
    _method: *mut X509V3ExtMethod,
    akeyid: *mut AuthorityKeyid,
    extlist: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let origextlist = extlist;
    let mut extlist = extlist;

    // The authority's `err:` tail: free the stack only when this call built it.
    macro_rules! err {
        () => {{
            if origextlist.is_null() {
                // SAFETY: `extlist` is this call's own stack; the thunk frees the values.
                unsafe { OPENSSL_sk_pop_free(extlist, Some(conf_value_free_thunk)) };
            }
            return core::ptr::null_mut();
        }};
    }

    // SAFETY: `akeyid` is live per the contract.
    if unsafe { !(*akeyid).keyid.is_null() } {
        // SAFETY: the keyid is a live `ASN1_OCTET_STRING`.
        let tmp = unsafe { i2s_ASN1_OCTET_STRING(core::ptr::null_mut(), (*akeyid).keyid) };
        if tmp.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_49) };
            return core::ptr::null_mut();
        }
        // `(akeyid->issuer || akeyid->serial) ? "keyid" : NULL`.
        // SAFETY: `akeyid` is live.
        let name = unsafe {
            if !(*akeyid).issuer.is_null() || !(*akeyid).serial.is_null() {
                c"keyid".as_ptr()
            } else {
                core::ptr::null()
            }
        };
        // SAFETY: `tmp` is NUL-terminated; `extlist` is this call's own sink.
        if unsafe { X509V3_add_value(name, tmp, &mut extlist) } == 0 {
            // SAFETY: `tmp` is this call's own allocation; the authority frees it at `:54`.
            unsafe { CRYPTO_free(tmp.cast(), FILE.as_ptr(), 54) };
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_55) };
            err!();
        }
        // SAFETY: `tmp` is this call's own allocation; the authority frees it at `:58`.
        unsafe { CRYPTO_free(tmp.cast(), FILE.as_ptr(), 58) };
    }
    // SAFETY: `akeyid` is live.
    if unsafe { !(*akeyid).issuer.is_null() } {
        // SAFETY: the issuer stack is a live `GENERAL_NAMES`; `extlist` is this call's own sink.
        let tmpextlist =
            unsafe { i2v_GENERAL_NAMES(core::ptr::null_mut(), (*akeyid).issuer, extlist) };
        if tmpextlist.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_63) };
            err!();
        }
        extlist = tmpextlist;
    }
    // SAFETY: `akeyid` is live.
    if unsafe { !(*akeyid).serial.is_null() } {
        // SAFETY: the serial is a live `ASN1_OCTET_STRING`.
        let tmp = unsafe { i2s_ASN1_OCTET_STRING(core::ptr::null_mut(), (*akeyid).serial) };
        if tmp.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_71) };
            err!();
        }
        // SAFETY: `tmp` is NUL-terminated; `extlist` is this call's own sink.
        if unsafe { X509V3_add_value(c"serial".as_ptr(), tmp, &mut extlist) } == 0 {
            // SAFETY: `tmp` is this call's own allocation; the authority frees it at `:75`.
            unsafe { CRYPTO_free(tmp.cast(), FILE.as_ptr(), 75) };
            err!();
        }
        // SAFETY: `tmp` is this call's own allocation; the authority frees it at `:78`.
        unsafe { CRYPTO_free(tmp.cast(), FILE.as_ptr(), 78) };
    }
    extlist
}

/// The authority's `err:` tail of [`v2i_AUTHORITY_KEYID`]: release whatever each local owns.
///
/// # Safety
///
/// Each argument is NULL or a value that call built and still owns.
unsafe fn akid_v2i_err(
    akeyid: *mut AuthorityKeyid,
    gens: *mut OpenSslStack,
    gen: *mut GeneralName,
    isname: *mut X509Name,
    serial: *mut Asn1String,
    ikeyid: *mut Asn1String,
) -> *mut AuthorityKeyid {
    // SAFETY: each is NULL or the value this call built/owns.
    unsafe {
        // `sk_GENERAL_NAME_free` frees only the stack, not its elements.
        OPENSSL_sk_free(gens);
        GENERAL_NAME_free(gen);
        X509_NAME_free(isname);
        ASN1_INTEGER_free(serial);
        ASN1_OCTET_STRING_free(ikeyid);
        AUTHORITY_KEYID_free(akeyid);
    }
    core::ptr::null_mut()
}

/// `static AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_akid.c:96-237`.
///
/// # Safety
///
/// `method` may be NULL; `ctx` is NULL or a live `X509V3_CTX`; `values` must be a live stack of
/// `CONF_VALUE` pointers.
unsafe extern "C" fn v2i_AUTHORITY_KEYID(
    _method: *mut X509V3ExtMethod,
    ctx: *mut X509V3Ctx,
    values: *mut OpenSslStack,
) -> *mut AuthorityKeyid {
    let mut keyid: c_char = 0;
    let mut issuer: c_char = 0;
    // SAFETY: `values` is live per the contract.
    let n = unsafe { OPENSSL_sk_num(values) };
    let mut ikeyid: *mut Asn1String = core::ptr::null_mut();
    let mut isname: *mut X509Name = core::ptr::null_mut();
    let mut gens: *mut OpenSslStack = core::ptr::null_mut();
    let mut gen: *mut GeneralName = core::ptr::null_mut();
    let mut serial: *mut Asn1String = core::ptr::null_mut();
    let akeyid = AUTHORITY_KEYID_new();
    if akeyid.is_null() {
        return core::ptr::null_mut();
    }

    // The authority's `err:` tail; every error below reaches it.
    macro_rules! err {
        () => {{
            // SAFETY: every argument is NULL or a value this call built and still owns.
            unsafe { return akid_v2i_err(akeyid, gens, gen, isname, serial, ikeyid) };
        }};
    }

    if n == 1 {
        // SAFETY: `values` is live and holds one element; the element is a live `CONF_VALUE`.
        let cnf = unsafe { OPENSSL_sk_value(values, 0) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live and `name` is NUL-terminated.
        if unsafe { strcmp((*cnf).name, c"none".as_ptr()) } == 0 {
            return akeyid;
        }
    }

    let mut i = 0;
    while i < n {
        // SAFETY: `values` is live and `i` is in bounds; the element is a live `CONF_VALUE`.
        let cnf = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live.
        let (cname, cvalue) = unsafe { ((*cnf).name, (*cnf).value) };
        // SAFETY: `cvalue` is NULL or NUL-terminated and `cname` is NUL-terminated.
        if unsafe { !cvalue.is_null() && strcmp(cvalue, c"always".as_ptr()) != 0 } {
            // `ERR_raise_data(..., X509V3_R_UNKNOWN_OPTION, "name=%s option=%s", ...)`.
            let mut msg = b"name=".to_vec();
            // SAFETY: `cname`/`cvalue` are NUL-terminated.
            unsafe {
                push_cstr(&mut msg, cname);
            }
            msg.extend_from_slice(b" option=");
            // SAFETY: `cvalue` is NUL-terminated.
            unsafe {
                push_cstr(&mut msg, cvalue);
            }
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
            unsafe { raise_site_data(&V3_AKID_123, msg.as_ptr().cast()) };
            err!();
        }
        // SAFETY: `cname` is NUL-terminated.
        let is_keyid = unsafe { strcmp(cname, c"keyid".as_ptr()) } == 0;
        // SAFETY: `cname` is NUL-terminated.
        let is_issuer = unsafe { strcmp(cname, c"issuer".as_ptr()) } == 0;
        // SAFETY: `cname` is NUL-terminated.
        let is_none = unsafe { strcmp(cname, c"none".as_ptr()) } == 0;
        if is_keyid && keyid == 0 {
            keyid = 1;
            if !cvalue.is_null() {
                keyid = 2;
            }
        } else if is_issuer && issuer == 0 {
            issuer = 1;
            if !cvalue.is_null() {
                issuer = 2;
            }
        } else if is_none || is_keyid || is_issuer {
            // `ERR_raise_data(..., X509V3_R_BAD_VALUE, "name=%s", cnf->name)`.
            let mut msg = b"name=".to_vec();
            // SAFETY: `cname` is NUL-terminated.
            unsafe { push_cstr(&mut msg, cname) };
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
            unsafe { raise_site_data(&V3_AKID_138, msg.as_ptr().cast()) };
            err!();
        } else {
            // `ERR_raise_data(..., X509V3_R_UNKNOWN_VALUE, "name=%s", cnf->name)`.
            let mut msg = b"name=".to_vec();
            // SAFETY: `cname` is NUL-terminated.
            unsafe { push_cstr(&mut msg, cname) };
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
            unsafe { raise_site_data(&V3_AKID_142, msg.as_ptr().cast()) };
            err!();
        }
        i += 1;
    }

    // SAFETY: `ctx` is NULL or live per the contract.
    if !ctx.is_null() && unsafe { (*ctx).flags } & X509V3_CTX_TEST != 0 {
        return akeyid;
    }
    if ctx.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_AKID_152) };
        err!();
    }
    // SAFETY: `ctx` is live here.
    let issuer_cert = unsafe { (*ctx).issuer_cert };
    if issuer_cert.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_AKID_156) };
        err!();
    }
    // SAFETY: `ctx` is live.
    let same_issuer = unsafe { (*ctx).subject_cert == (*ctx).issuer_cert };
    ERR_set_mark();
    // SAFETY: `ctx` is live.
    let issuer_pkey = unsafe { (*ctx).issuer_pkey };
    let ss = if issuer_pkey.is_null() {
        c_int::from(same_issuer)
    } else {
        // SAFETY: `ctx` is live; when `issuer_pkey` is non-NULL its subject is set
        // (`X509V3_set_issuer_pkey` requires a subject) and the key is live.
        unsafe { X509_check_private_key((*ctx).subject_cert, issuer_pkey) }
    };
    ERR_pop_to_mark();

    // unless forced with "always", AKID is suppressed for self-signed certs.
    if keyid == 2 || (keyid == 1 && ss == 0) {
        // SAFETY: `issuer_cert` is live.
        let idx = unsafe { X509_get_ext_by_NID(issuer_cert, NID_subject_key_identifier, -1) };
        if idx >= 0 {
            // SAFETY: `issuer_cert` is live and `idx` is a valid extension index.
            let ext = unsafe { X509_get_ext(issuer_cert, idx) };
            if !ext.is_null() && !(same_issuer && ss == 0) {
                // SAFETY: `ext` is live and its NID is `NID_subject_key_identifier`, whose table sets
                // `it = ASN1_OCTET_STRING_it`, so the decode answers an `ASN1_OCTET_STRING`.
                ikeyid = unsafe { X509V3_EXT_d2i(ext) }.cast::<Asn1String>();
                if ikeyid.is_null() {
                    err!();
                }
                // SAFETY: `ikeyid` is live.
                if unsafe { ASN1_STRING_length(ikeyid) } == 0 {
                    // SAFETY: `ikeyid` is this call's own decoded value.
                    unsafe { ASN1_OCTET_STRING_free(ikeyid) };
                    ikeyid = core::ptr::null_mut();
                }
            }
        }
        // SAFETY: `ctx` is live.
        if ikeyid.is_null() && same_issuer && !issuer_pkey.is_null() {
            let mut pubkey: *mut X509Pubkey = core::ptr::null_mut();
            // SAFETY: `&mut pubkey` is writable and `issuer_pkey` is live; the setter answers 1 and
            // fills `pubkey`.
            if unsafe { X509_PUBKEY_set(&mut pubkey, issuer_pkey) } != 0 {
                // SAFETY: `pubkey` is live here.
                ikeyid = unsafe { ossl_x509_pubkey_hash(pubkey) };
            }
            // SAFETY: `pubkey` is NULL or this call's own wrapper.
            unsafe { X509_PUBKEY_free(pubkey) };
        }
        if keyid == 2 && ikeyid.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_193) };
            err!();
        }
    }

    if issuer == 2 || (issuer == 1 && ss == 0 && ikeyid.is_null()) {
        // SAFETY: `issuer_cert` is live; the dup answers NULL or a live `X509_NAME`.
        isname = unsafe { X509_NAME_dup(X509_get_issuer_name(issuer_cert)) };
        // SAFETY: `issuer_cert` is live; the dup answers NULL or a live `ASN1_INTEGER`.
        serial = unsafe { ASN1_INTEGER_dup(X509_get0_serialNumber(issuer_cert)) };
        if isname.is_null() || serial.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_202) };
            err!();
        }
    }

    if !isname.is_null() {
        gens = OPENSSL_sk_new_null();
        gen = GENERAL_NAME_new();
        if gens.is_null() || gen.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_210) };
            err!();
        }
        // SAFETY: `gens` is live and `gen` is this call's own value.
        if unsafe { OPENSSL_sk_push(gens, gen.cast::<c_void>()) } == 0 {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_AKID_214) };
            err!();
        }
        // SAFETY: `gen` is live; the `dirn` arm is the selected one.
        unsafe {
            (*gen).type_ = GEN_DIRNAME;
            (*gen).d.directoryName = isname;
        }
    }

    // SAFETY: `akeyid` is live; ownership of each local passes to it.
    unsafe {
        (*akeyid).issuer = gens;
        (*akeyid).serial = serial;
        (*akeyid).keyid = ikeyid;
    }
    akeyid
}
