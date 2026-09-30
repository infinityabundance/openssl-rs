//! Phase 10.14.3 — `crypto/x509/v3_utl.c`: the X.509v3 extension string/value utilities.
//!
//! `crypto/x509/v3_utl.c` is 1,449 lines and defines 51 hand-written functions. **This module lands
//! all 51** — the D451/D459 rule applied at function granularity.
//!
//! Phase 10.14.3 landed 32: the value/string utilities and the IP-address conversions. **This slice
//! (Phase 11.5) lands the remaining 19** the withheld half waited on, now that 10.14.5's
//! `X509_get_ext_d2i`/`X509V3_get_d2i` and the `GENERAL_NAME`/`ACCESS_DESCRIPTION` decoders exist:
//!
//! * the two email/OCSP accessors [`X509_get1_email`] (`:449-458`) and [`X509_get1_ocsp`]
//!   (`:460-480`) and the three helpers they share: `sk_strcmp` (`:444-447`), `get_email`
//!   (`:496-523`) and `append_ia5` (`:530-566`);
//! * the whole hostname/email/IP matching surface — the `equal_fn` cluster `skip_prefix`
//!   (`:578-606`), `equal_nocase` (`:609-636`), `equal_case` (`:639-647`), `equal_email`
//!   (`:653-677`), `wildcard_match` (`:683-728`), `valid_star` (`:735-796`), `equal_wildcard`
//!   (`:799-817`), `do_check_string` (`:825-867`) and `do_x509_check` (`:869-1000`) — and the four
//!   public entry points built on it: [`X509_check_host`] (`:1002-1019`), [`X509_check_email`]
//!   (`:1021-1038`), [`X509_check_ip`] (`:1040-1046`) and [`X509_check_ip_asc`] (`:1048-1059`).
//!
//! ## `X509_REQ_get1_email`, and why 11.4b lands it
//!
//! `X509_REQ_get1_email` (`:482-494`) was withheld through Phase 10.14.3 and 11.5 because it calls
//! `X509_REQ_get_extensions` (`crypto/x509/x509_req.c`), which that unit withheld while the
//! `X509_EXTENSIONS` item was absent from `src/x509/x_exten.rs`. 11.4b landed that item and the
//! request functions over it, so the request"s `subjectAltName` is now decodable and this last name
//! lands with them. Its other two callees, `X509_REQ_get_subject_name` and `X509V3_get_d2i`, were
//! already landed.
//!
//! `OSSL_GENERAL_NAMES_print` (`:1421-1432`) landed in the 10.14.3 slice once `GENERAL_NAME_print`
//! (`v3_san.rs`) existed, so its closure is satisfied and the export is drivable from the admitted
//! DSO (`OPENSSL_3.4.0`).
//!
//! ## What it unblocks
//!
//! The landed value/string helpers are what the forty-odd `v3_*` table units and `v3_prn.c` name:
//! `X509V3_add_value` and its `_uchar`/`_int`/`_bool` siblings, the `i2s_`/`s2i_ASN1_INTEGER`
//! pair (`v3_int.c`, `v3_sxnet.c`, `v3_usernotice.c`, `v3_cpols.c`, `v3_asid.c`), `X509V3_parse_list`
//! (`v3_conf.c`, `v3_cpols.c`, `v3_pci.c`), `X509V3_conf_free` (`v3_prn.c`, `v3_conf.c`,
//! `v3_info.c`, `v3_akid.c`, `v3_cpols.c`, `v3_pci.c`), `ossl_v3_name_cmp` (`v3_addr.c`,
//! `v3_asid.c`), `ossl_a2i_ipadd`/`ossl_ipaddr_to_asc` (`v3_addr.c`, `v3_ncons.c`, `x509_vpm.c`)
//! and `X509V3_NAME_from_section` (`v3_conf.c`). It closes no Phase-10 export or provider row on
//! its own — the expected shape for a dependency sub-subphase.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_utl.c` has been in `gen_err_raise_sites.py`'s covered set since Phase 5
//! (because `i2s_ASN1_INTEGER` is observable through `ASN1_item_print`), so its fifteen
//! coordinates are already the generated `V3_UTL_*` constants. The landed functions reach all
//! fifteen: `x509v3_add_len_value`'s `ERR_R_CRYPTO_LIB` (`:60`), the two `i2s_` arms (`:174`,
//! `:176`, `:189`, `:191`), `s2i_ASN1_INTEGER`'s four (`:204`, `:209`, `:233`, `:243`),
//! `X509V3_get_value_bool`'s (`:291`) and `X509V3_parse_list`'s five (`:340`, `:349`, `:364`,
//! `:379`, `:388`). `X509V3_get_value_bool`/`_int`'s `X509V3_conf_add_error_name_value`
//! expansion is `ERR_add_error_data(4, …)` (`x509_local.h:12`), modelled through
//! `openssl_rs_err_add_data` with the authority's NULL-becomes-`<NULL>` rule.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_strex::ASN1_STRING_to_UTF8;
use crate::asn1::layout::{
    Asn1String, V_ASN1_IA5STRING, V_ASN1_NEG, V_ASN1_OCTET_STRING, V_ASN1_UTF8STRING,
};
use crate::asn1::prim::{ASN1_ENUMERATED_to_BN, ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::bn::bignum::{
    BN_bn2dec, BN_bn2hex, BN_dec2bn, BN_free, BN_hex2bn, BN_is_zero, BN_new, BN_num_bits, BigNum,
};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::sys::{memchr, memcmp, memcpy, memset, strchr, strcmp, strlen, strncmp};
use crate::runtime::bio::Bio;
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::ctype::{ossl_isdigit, ossl_isspace};
use crate::runtime::err::{err_sites, openssl_rs_err_add_data, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_strndup};
use crate::runtime::obj::{
    NID_ad_OCSP, NID_commonName, NID_id_on_SmtpUTF8Mailbox, NID_info_access,
    NID_pkcs9_emailAddress, NID_subject_alt_name, NID_undef, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::{
    OPENSSL_buf2hexstr, OPENSSL_hexchar2int, OPENSSL_strlcat, OPENSSL_strlcpy, OPENSSL_strncasecmp,
};
use crate::x509::v3_genn::{
    GENERAL_NAMES_free, GENERAL_NAME_free, GeneralName, GEN_DNS, GEN_EMAIL, GEN_IPADD,
    GEN_OTHERNAME, GEN_URI,
};
use crate::x509::v3_info::{AUTHORITY_INFO_ACCESS_free, AccessDescription};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_get_d2i};
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::x509_cmp::X509_get_subject_name;
use crate::x509::x509_ext::X509_get_ext_d2i;
use crate::x509::x509_req::{X509Req, X509_REQ_get_extensions, X509_REQ_get_subject_name};
use crate::x509::x509name::{
    X509_NAME_ENTRY_get_data, X509_NAME_add_entry_by_txt, X509_NAME_get_entry,
    X509_NAME_get_index_by_NID,
};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::X509;

/// `OPENSSL_FILE` for this unit's allocation expansions — `crypto/x509/v3_utl.c`.
const FILE: &CStr = c"crypto/x509/v3_utl.c";

/// The state machine's two states — `crypto/x509/v3_utl.c:308-309`.
const HDR_NAME: c_int = 1;
/// See [`HDR_NAME`].
const HDR_VALUE: c_int = 2;

// ---------------------------------------------------------------------------
// The CONF_VALUE value stack
// ---------------------------------------------------------------------------

/// `static int x509v3_add_len_value(const char *name, const char *value, size_t vallen,
/// STACK_OF(CONF_VALUE) **extlist)` — `crypto/x509/v3_utl.c:40-78`.
///
/// **`static` in the authority, and private here**: it is a C symbol neither the authority's DSO
/// nor this crate's version script admits, so it is an `unsafe fn` rather than a `#[no_mangle]`
/// export.
///
/// The embedded-NUL refusal (`memchr(value, 0, vallen) != NULL`) is the authority's, and it is
/// why a value with a NUL in its first `vallen` bytes is rejected rather than stored truncated.
/// The stack is built here only when the caller's slot was NULL, and the error tail frees it
/// again only in that case; a caller-supplied stack survives.
///
/// # Safety
///
/// `name`/`value` must be NULL or point at readable buffers; when `value` is non-NULL it must be
/// readable for `vallen` bytes; `extlist` must be writable.
unsafe fn x509v3_add_len_value(
    name: *const c_char,
    value: *const c_char,
    vallen: usize,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    let mut vtmp: *mut ConfValue = ptr::null_mut();
    let mut tname: *mut c_char = ptr::null_mut();
    let mut tvalue: *mut c_char = ptr::null_mut();
    // SAFETY: `extlist` is writable per the contract.
    let sk_allocated = unsafe { (*extlist).is_null() };

    if !name.is_null() {
        // SAFETY: `name` is NUL-terminated per the contract; the allocation site is constant.
        tname = unsafe { CRYPTO_strdup(name, FILE.as_ptr(), 47) };
        if tname.is_null() {
            // SAFETY: the error tail's contract is this function's.
            return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
        }
    }
    if !value.is_null() {
        // SAFETY: `value` is readable for `vallen` bytes per the contract.
        if !unsafe { memchr(value.cast::<c_void>(), 0, vallen) }.is_null() {
            // SAFETY: as above.
            return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
        }
        // SAFETY: `value` is readable for `vallen` bytes per the contract.
        tvalue = unsafe { CRYPTO_strndup(value, vallen, FILE.as_ptr(), 53) };
        if tvalue.is_null() {
            // SAFETY: as above.
            return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
        }
    }
    vtmp = CRYPTO_malloc(core::mem::size_of::<ConfValue>(), FILE.as_ptr(), 57).cast::<ConfValue>();
    if vtmp.is_null() {
        // SAFETY: as above.
        return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
    }
    if sk_allocated {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        // SAFETY: `extlist` is writable per the contract.
        unsafe { *extlist = fresh };
        if fresh.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::V3_UTL_60) };
            // SAFETY: as above.
            return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
        }
    }
    // SAFETY: `vtmp` is this call's own, freshly allocated `CONF_VALUE`.
    unsafe {
        (*vtmp).section = ptr::null_mut();
        (*vtmp).name = tname;
        (*vtmp).value = tvalue;
    }
    // SAFETY: `*extlist` is live (freshly built or the caller's) and `vtmp` is this call's own.
    if unsafe { OPENSSL_sk_push(*extlist, vtmp.cast::<c_void>()) } == 0 {
        // SAFETY: as above.
        return unsafe { add_len_value_err(extlist, sk_allocated, vtmp, tname, tvalue) };
    }
    1
}

/// `crypto/x509/v3_utl.c:69-77`'s `err:` label of [`x509v3_add_len_value`].
///
/// Frees the caller-visible stack only when this call built it, and the three allocations this
/// call owns. A failed push has not taken ownership of `vtmp`/`tname`/`tvalue`.
///
/// # Safety
///
/// `extlist` must be writable; each pointer must be NULL or this call's own.
unsafe fn add_len_value_err(
    extlist: *mut *mut OpenSslStack,
    sk_allocated: bool,
    vtmp: *mut ConfValue,
    tname: *mut c_char,
    tvalue: *mut c_char,
) -> c_int {
    if sk_allocated {
        // SAFETY: `*extlist` is this call's own stack or NULL.
        unsafe { OPENSSL_sk_free(*extlist) };
        // SAFETY: `extlist` is writable per the contract.
        unsafe { *extlist = ptr::null_mut() };
    }
    // SAFETY: each is NULL or this call's own allocation.
    unsafe {
        CRYPTO_free(vtmp.cast::<c_void>(), FILE.as_ptr(), 74);
        CRYPTO_free(tname.cast::<c_void>(), FILE.as_ptr(), 75);
        CRYPTO_free(tvalue.cast::<c_void>(), FILE.as_ptr(), 76);
    }
    0
}

/// `int X509V3_add_value(const char *name, const char *value, STACK_OF(CONF_VALUE) **extlist)` —
/// `crypto/x509/v3_utl.c:80-86`.
///
/// # Safety
///
/// `name`/`value` must be NULL or NUL-terminated; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add_value(
    name: *const c_char,
    value: *const c_char,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    let vallen = if value.is_null() {
        0
    } else {
        // SAFETY: `value` is NULL or NUL-terminated per the contract.
        unsafe { strlen(value) }
    };
    // SAFETY: the caller's contract is `x509v3_add_len_value`'s.
    unsafe { x509v3_add_len_value(name, value, vallen, extlist) }
}

/// `int X509V3_add_value_uchar(const char *name, const unsigned char *value,
/// STACK_OF(CONF_VALUE) **extlist)` — `crypto/x509/v3_utl.c:88-94`.
///
/// # Safety
///
/// `name` NULL or NUL-terminated; `value` NULL or NUL-terminated; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add_value_uchar(
    name: *const c_char,
    value: *const c_uchar,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    let vallen = if value.is_null() {
        0
    } else {
        // SAFETY: `value` is NULL or NUL-terminated per the contract.
        unsafe { strlen(value.cast::<c_char>()) }
    };
    // SAFETY: the caller's contract is `x509v3_add_len_value`'s.
    unsafe { x509v3_add_len_value(name, value.cast::<c_char>(), vallen, extlist) }
}

/// `int x509v3_add_len_value_uchar(const char *name, const unsigned char *value, size_t vallen,
/// STACK_OF(CONF_VALUE) **extlist)` — `crypto/x509/v3_utl.c:96-100`.
///
/// # Safety
///
/// `name` NULL or NUL-terminated; `value` NULL or readable for `vallen`; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn x509v3_add_len_value_uchar(
    name: *const c_char,
    value: *const c_uchar,
    vallen: usize,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    // SAFETY: the caller's contract is `x509v3_add_len_value`'s.
    unsafe { x509v3_add_len_value(name, value.cast::<c_char>(), vallen, extlist) }
}

/// `void X509V3_conf_free(CONF_VALUE *conf)` — `crypto/x509/v3_utl.c:104-112`.
///
/// # Safety
///
/// `conf` must be NULL or a live, uniquely-owned `CONF_VALUE`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_conf_free(conf: *mut ConfValue) {
    if conf.is_null() {
        return;
    }
    // SAFETY: `conf` is live per the contract; each field is NULL or this structure's own.
    unsafe {
        CRYPTO_free((*conf).name.cast::<c_void>(), FILE.as_ptr(), 108);
        CRYPTO_free((*conf).value.cast::<c_void>(), FILE.as_ptr(), 109);
        CRYPTO_free((*conf).section.cast::<c_void>(), FILE.as_ptr(), 110);
        CRYPTO_free(conf.cast::<c_void>(), FILE.as_ptr(), 111);
    }
}

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(values, X509V3_conf_free)` installs —
/// `crypto/x509/v3_utl.c:400`.
///
/// # Safety
///
/// `p` must be NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `int X509V3_add_value_bool(const char *name, int asn1_bool, STACK_OF(CONF_VALUE) **extlist)` —
/// `crypto/x509/v3_utl.c:114-120`.
///
/// # Safety
///
/// `name` NULL or NUL-terminated; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add_value_bool(
    name: *const c_char,
    asn1_bool: c_int,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    if asn1_bool != 0 {
        // SAFETY: the caller's contract is `X509V3_add_value`'s.
        unsafe { X509V3_add_value(name, c"TRUE".as_ptr(), extlist) }
    } else {
        // SAFETY: as above.
        unsafe { X509V3_add_value(name, c"FALSE".as_ptr(), extlist) }
    }
}

/// `int X509V3_add_value_bool_nf(const char *name, int asn1_bool, STACK_OF(CONF_VALUE) **extlist)`
/// — `crypto/x509/v3_utl.c:122-128`.
///
/// The `f` is "false is nothing": a false value adds no entry at all and answers success.
///
/// # Safety
///
/// `name` NULL or NUL-terminated; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add_value_bool_nf(
    name: *const c_char,
    asn1_bool: c_int,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    if asn1_bool != 0 {
        // SAFETY: the caller's contract is `X509V3_add_value`'s.
        unsafe { X509V3_add_value(name, c"TRUE".as_ptr(), extlist) }
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// The ASN1_INTEGER / ASN1_ENUMERATED string pair
// ---------------------------------------------------------------------------

/// `static char *bignum_to_string(const BIGNUM *bn)` — `crypto/x509/v3_utl.c:130-164`.
///
/// Under 128 bits the value is decimal; at 128 bits or more it is hex, and the `0x` prefix goes
/// **after** a leading `-`. The switch is a readability choice the authority makes, not a
/// correctness one, and it is observable because the two spellings differ.
///
/// # Safety
///
/// `bn` must be a live bignum.
unsafe fn bignum_to_string(bn: *const BigNum) -> *mut c_char {
    // SAFETY: `bn` is live per the contract.
    if unsafe { BN_num_bits(bn) } < 128 {
        // SAFETY: `bn` is live per the contract.
        return unsafe { BN_bn2dec(bn) };
    }
    // SAFETY: `bn` is live per the contract.
    let tmp = unsafe { BN_bn2hex(bn) };
    if tmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `tmp` is a NUL-terminated allocation.
    let len = unsafe { strlen(tmp) } + 3;
    let ret = CRYPTO_malloc(len, FILE.as_ptr(), 148).cast::<c_char>();
    if ret.is_null() {
        // SAFETY: `tmp` is this call's own.
        unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 150) };
        return ptr::null_mut();
    }
    // SAFETY: `tmp` is NUL-terminated; `ret` is `len` writable bytes.
    unsafe {
        if *tmp == b'-' as c_char {
            OPENSSL_strlcpy(ret, c"-0x".as_ptr(), len);
            OPENSSL_strlcat(ret, tmp.add(1), len);
        } else {
            OPENSSL_strlcpy(ret, c"0x".as_ptr(), len);
            OPENSSL_strlcat(ret, tmp, len);
        }
        CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 162);
    }
    ret
}

/// `char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *method, const ASN1_ENUMERATED *a)` —
/// `crypto/x509/v3_utl.c:166-179`.
///
/// `method` is read by no line of the body; the parameter is the authority's and is kept for the
/// signature's sake.
///
/// # Safety
///
/// `a` must be NULL or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_ENUMERATED(
    method: *mut X509V3ExtMethod,
    a: *const Asn1String,
) -> *mut c_char {
    let _ = method;
    let mut strtmp: *mut c_char = ptr::null_mut();
    if a.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `a` is live per the contract.
    let bntmp = unsafe { ASN1_ENUMERATED_to_BN(a, ptr::null_mut()) };
    if bntmp.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_174) };
    } else {
        // SAFETY: `bntmp` is live and this call's own.
        strtmp = unsafe { bignum_to_string(bntmp) };
        if strtmp.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::V3_UTL_176) };
        }
    }
    // SAFETY: `bntmp` is NULL or this call's own.
    unsafe { BN_free(bntmp) };
    strtmp
}

/// `char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *method, const ASN1_INTEGER *a)` —
/// `crypto/x509/v3_utl.c:181-194`.
///
/// # Safety
///
/// `a` must be NULL or a live integer.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_INTEGER(
    method: *mut X509V3ExtMethod,
    a: *const Asn1String,
) -> *mut c_char {
    let _ = method;
    let mut strtmp: *mut c_char = ptr::null_mut();
    if a.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `a` is live per the contract.
    let bntmp = unsafe { ASN1_INTEGER_to_BN(a, ptr::null_mut()) };
    if bntmp.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_189) };
    } else {
        // SAFETY: `bntmp` is live and this call's own.
        strtmp = unsafe { bignum_to_string(bntmp) };
        if strtmp.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::V3_UTL_191) };
        }
    }
    // SAFETY: `bntmp` is NULL or this call's own.
    unsafe { BN_free(bntmp) };
    strtmp
}

/// `ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method, const char *value)` —
/// `crypto/x509/v3_utl.c:196-249`.
///
/// The optional `-` sign and the optional `0x`/`0X` prefix are stripped in order, so `-0x10` and
/// `0x-10` differ: the first is a negative sixteen and the second fails the `BN_hex2bn`
/// consumption test. A negative that parses to zero loses its sign (`isneg && BN_is_zero`).
///
/// # Safety
///
/// `value` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn s2i_ASN1_INTEGER(
    method: *mut X509V3ExtMethod,
    value: *const c_char,
) -> *mut Asn1String {
    let _ = method;
    if value.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_204) };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let mut bn = unsafe { BN_new() };
    if bn.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_209) };
        return ptr::null_mut();
    }
    let mut p = value;
    let mut isneg = false;
    // SAFETY: `value` is NUL-terminated per the contract, so `*p` reads in bounds.
    let first = unsafe { *p };
    if first == b'-' as c_char {
        // SAFETY: `p` points at a non-terminator byte, so `p + 1` is in bounds.
        p = unsafe { p.add(1) };
        isneg = true;
    }
    let mut ishex = false;
    // SAFETY: `p` points into the NUL-terminated string.
    let b0 = unsafe { *p };
    if b0 == b'0' as c_char {
        // SAFETY: `b0` is a non-terminator, so `p + 1` is within the buffer.
        let b1 = unsafe { *p.add(1) };
        if b1 == b'x' as c_char || b1 == b'X' as c_char {
            // SAFETY: `b0` and `b1` are non-terminators, so `p + 2` is in bounds.
            p = unsafe { p.add(2) };
            ishex = true;
        }
    }
    let ret = if ishex {
        // SAFETY: `bn` is a writable slot; `p` is NUL-terminated.
        unsafe { BN_hex2bn(&mut bn, p) }
    } else {
        // SAFETY: `bn` is a writable slot; `p` is NUL-terminated.
        unsafe { BN_dec2bn(&mut bn, p) }
    };
    // SAFETY: `ret` is the number of characters consumed; the authority reads `value[ret]` and so
    // does this, which is the whole point of the consumption test.
    if ret == 0 || unsafe { *p.add(ret as usize) } != 0 {
        // SAFETY: `bn` is this call's own.
        unsafe { BN_free(bn) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_233) };
        return ptr::null_mut();
    }
    // SAFETY: `bn` is live.
    if isneg && unsafe { BN_is_zero(bn) } != 0 {
        isneg = false;
    }
    // SAFETY: `bn` is live and this call's own; the result, if any, is a fresh integer.
    let aint = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    // SAFETY: `bn` is this call's own.
    unsafe { BN_free(bn) };
    if aint.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::V3_UTL_243) };
        return ptr::null_mut();
    }
    if isneg {
        // SAFETY: `aint` is this call's own, freshly built integer.
        unsafe { (*aint).type_ |= V_ASN1_NEG };
    }
    aint
}

/// `int X509V3_add_value_int(const char *name, const ASN1_INTEGER *aint,
/// STACK_OF(CONF_VALUE) **extlist)` — `crypto/x509/v3_utl.c:251-264`.
///
/// # Safety
///
/// `name` NULL or NUL-terminated; `aint` NULL or live; `extlist` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add_value_int(
    name: *const c_char,
    aint: *const Asn1String,
    extlist: *mut *mut OpenSslStack,
) -> c_int {
    if aint.is_null() {
        return 1;
    }
    // SAFETY: `aint` is live per the contract.
    let strtmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), aint) };
    if strtmp.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract is `X509V3_add_value`'s.
    let ret = unsafe { X509V3_add_value(name, strtmp, extlist) };
    // SAFETY: `strtmp` is this call's own.
    unsafe { CRYPTO_free(strtmp.cast::<c_void>(), FILE.as_ptr(), 262) };
    ret
}

/// `void X509V3_conf_add_error_name_value(CONF_VALUE *val)` — the `x509_local.h:12` macro's
/// expansion, `ERR_add_error_data(4, "name=", (val)->name, ", value=", (val)->value)`.
///
/// The authority's `ERR_add_error_vdata` renders a NULL argument as the literal `<NULL>`
/// (`crypto/err/err.c:855-856`), which is reproduced here rather than skipped.
///
/// # Safety
///
/// `val` must be a live `CONF_VALUE`.
pub(crate) unsafe fn conf_add_error_name_value(val: *const ConfValue) {
    let mut buf: Vec<u8> = b"name=".to_vec();
    // SAFETY: `val` is live per the contract.
    unsafe { push_cstr_or_null(&mut buf, (*val).name) };
    buf.extend_from_slice(b", value=");
    // SAFETY: as above.
    unsafe { push_cstr_or_null(&mut buf, (*val).value) };
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated.
    unsafe { openssl_rs_err_add_data(buf.as_ptr().cast::<c_char>()) };
}

/// Appends `p`'s bytes, or the literal `<NULL>` when `p` is NULL — `crypto/err/err.c:855-856`.
///
/// # Safety
///
/// `p` must be NULL or NUL-terminated.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { CStr::from_ptr(p) }.to_bytes());
    }
}

/// `int X509V3_get_value_bool(const CONF_VALUE *value, int *asn1_bool)` —
/// `crypto/x509/v3_utl.c:266-294`.
///
/// Six truthy spellings (up to `yes`) and six falsy ones (down to `no`); a leading or trailing
/// space is *not* accepted, which is observable. The boolean written is `0xff`, not `1`.
///
/// # Safety
///
/// `value` must be live; `asn1_bool` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_value_bool(
    value: *const ConfValue,
    asn1_bool: *mut c_int,
) -> c_int {
    // SAFETY: `value` is live per the contract.
    let btmp = unsafe { (*value).value };
    if !btmp.is_null() {
        // SAFETY: `btmp` is NUL-terminated and each literal is static.
        let truthy = unsafe {
            strcmp(btmp, c"TRUE".as_ptr()) == 0
                || strcmp(btmp, c"true".as_ptr()) == 0
                || strcmp(btmp, c"Y".as_ptr()) == 0
                || strcmp(btmp, c"y".as_ptr()) == 0
                || strcmp(btmp, c"YES".as_ptr()) == 0
                || strcmp(btmp, c"yes".as_ptr()) == 0
        };
        if truthy {
            // SAFETY: `asn1_bool` is writable per the contract.
            unsafe { *asn1_bool = 0xff };
            return 1;
        }
        // SAFETY: `btmp` is NUL-terminated and each literal is static.
        let falsy = unsafe {
            strcmp(btmp, c"FALSE".as_ptr()) == 0
                || strcmp(btmp, c"false".as_ptr()) == 0
                || strcmp(btmp, c"N".as_ptr()) == 0
                || strcmp(btmp, c"n".as_ptr()) == 0
                || strcmp(btmp, c"NO".as_ptr()) == 0
                || strcmp(btmp, c"no".as_ptr()) == 0
        };
        if falsy {
            // SAFETY: `asn1_bool` is writable per the contract.
            unsafe { *asn1_bool = 0 };
            return 1;
        }
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_site(&err_sites::V3_UTL_291) };
    // SAFETY: `value` is live per the contract.
    unsafe { conf_add_error_name_value(value) };
    0
}

/// `int X509V3_get_value_int(const CONF_VALUE *value, ASN1_INTEGER **aint)` —
/// `crypto/x509/v3_utl.c:296-306`.
///
/// # Safety
///
/// `value` must be live; `aint` writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_value_int(
    value: *const ConfValue,
    aint: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `value` is live per the contract; `s2i_ASN1_INTEGER` accepts a NULL-or-string.
    let itmp = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), (*value).value) };
    if itmp.is_null() {
        // SAFETY: `value` is live per the contract.
        unsafe { conf_add_error_name_value(value) };
        return 0;
    }
    // SAFETY: `aint` is writable per the contract.
    unsafe { *aint = itmp };
    1
}

// ---------------------------------------------------------------------------
// The `name:value,…` list parser and the name comparator
// ---------------------------------------------------------------------------

/// `STACK_OF(CONF_VALUE) *X509V3_parse_list(const char *line)` — `crypto/x509/v3_utl.c:315-402`.
///
/// The line is copied first and modified in place. A bare `name` (no `:`) becomes a one-element
/// entry with a NULL value; a `name:` becomes an entry with a NULL value and no error; a
/// `:value` or a `name:` whose value strips to empty is `X509V3_R_INVALID_NULL_VALUE`, and a
/// `name` that strips to empty is `X509V3_R_INVALID_EMPTY_NAME`. Whitespace is stripped from
/// both halves.
///
/// # Safety
///
/// `line` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509V3_parse_list(line: *const c_char) -> *mut OpenSslStack {
    // SAFETY: `line` is NUL-terminated per the contract.
    let linebuf = unsafe { CRYPTO_strdup(line, FILE.as_ptr(), 324) };
    if linebuf.is_null() {
        return ptr::null_mut();
    }
    let mut values: *mut OpenSslStack = ptr::null_mut();
    let mut state = HDR_NAME;
    let mut ntmp: *mut c_char = ptr::null_mut();
    let mut p = linebuf;
    let mut q = linebuf;
    loop {
        // SAFETY: `p` walks a NUL-terminated buffer and stops at the terminator below.
        let c = unsafe { *p };
        if c == 0 || c == b'\r' as c_char || c == b'\n' as c_char {
            break;
        }
        if state == HDR_NAME {
            if c == b':' as c_char {
                state = HDR_VALUE;
                // SAFETY: `p` points into the writable copy.
                unsafe { *p = 0 };
                // SAFETY: `q` is a NUL-terminated offset into the copy.
                ntmp = unsafe { strip_spaces(q) };
                if ntmp.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::V3_UTL_340) };
                    // SAFETY: the error tail's contract is this function's.
                    return unsafe { parse_list_err(linebuf, values) };
                }
                // SAFETY: `p` points at the ':' replaced by NUL.
                q = unsafe { p.add(1) };
            } else if c == b',' as c_char {
                // SAFETY: `p` points into the writable copy.
                unsafe { *p = 0 };
                // SAFETY: `q` is a NUL-terminated offset into the copy.
                ntmp = unsafe { strip_spaces(q) };
                // SAFETY: `p` points at the ',' replaced by NUL.
                q = unsafe { p.add(1) };
                if ntmp.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::V3_UTL_349) };
                    // SAFETY: the error tail's contract is this function's.
                    return unsafe { parse_list_err(linebuf, values) };
                }
                // SAFETY: the caller's contract is `X509V3_add_value`'s.
                if unsafe { X509V3_add_value(ntmp, ptr::null(), &mut values) } == 0 {
                    // SAFETY: the error tail's contract is this function's.
                    return unsafe { parse_list_err(linebuf, values) };
                }
            }
        } else if c == b',' as c_char {
            state = HDR_NAME;
            // SAFETY: `p` points into the writable copy.
            unsafe { *p = 0 };
            // SAFETY: `q` is a NUL-terminated offset into the copy.
            let vtmp = unsafe { strip_spaces(q) };
            if vtmp.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::V3_UTL_364) };
                // SAFETY: the error tail's contract is this function's.
                return unsafe { parse_list_err(linebuf, values) };
            }
            // SAFETY: the caller's contract is `X509V3_add_value`'s.
            if unsafe { X509V3_add_value(ntmp, vtmp, &mut values) } == 0 {
                // SAFETY: the error tail's contract is this function's.
                return unsafe { parse_list_err(linebuf, values) };
            }
            ntmp = ptr::null_mut();
            // SAFETY: `p` points at the ',' replaced by NUL.
            q = unsafe { p.add(1) };
        }
        // SAFETY: `p` walks a NUL-terminated buffer.
        p = unsafe { p.add(1) };
    }

    if state == HDR_VALUE {
        // SAFETY: `q` is a NUL-terminated offset into the copy.
        let vtmp = unsafe { strip_spaces(q) };
        if vtmp.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::V3_UTL_379) };
            // SAFETY: the error tail's contract is this function's.
            return unsafe { parse_list_err(linebuf, values) };
        }
        // SAFETY: the caller's contract is `X509V3_add_value`'s.
        if unsafe { X509V3_add_value(ntmp, vtmp, &mut values) } == 0 {
            // SAFETY: the error tail's contract is this function's.
            return unsafe { parse_list_err(linebuf, values) };
        }
    } else {
        // SAFETY: `q` is a NUL-terminated offset into the copy.
        ntmp = unsafe { strip_spaces(q) };
        if ntmp.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::V3_UTL_388) };
            // SAFETY: the error tail's contract is this function's.
            return unsafe { parse_list_err(linebuf, values) };
        }
        // SAFETY: the caller's contract is `X509V3_add_value`'s.
        if unsafe { X509V3_add_value(ntmp, ptr::null(), &mut values) } == 0 {
            // SAFETY: the error tail's contract is this function's.
            return unsafe { parse_list_err(linebuf, values) };
        }
    }
    // SAFETY: `linebuf` is this call's own copy.
    unsafe { CRYPTO_free(linebuf.cast::<c_void>(), FILE.as_ptr(), 395) };
    values
}

/// `crypto/x509/v3_utl.c:398-401`'s `err:` label of [`X509V3_parse_list`].
///
/// # Safety
///
/// `linebuf` must be this call's own copy; `values` NULL or a live stack this call built.
unsafe fn parse_list_err(linebuf: *mut c_char, values: *mut OpenSslStack) -> *mut OpenSslStack {
    // SAFETY: `linebuf` is this call's own.
    unsafe { CRYPTO_free(linebuf.cast::<c_void>(), FILE.as_ptr(), 399) };
    // SAFETY: `values` is NULL or this call's own stack of `CONF_VALUE` pointers.
    unsafe { OPENSSL_sk_pop_free(values, Some(conf_value_free_thunk)) };
    ptr::null_mut()
}

/// `static char *strip_spaces(char *name)` — `crypto/x509/v3_utl.c:405-423`.
///
/// Strips leading and trailing whitespace in place (`ossl_isspace` is the ctype table's space
/// predicate). A string that is empty after stripping answers NULL, so the caller can tell "no
/// name" from "the empty name".
///
/// # Safety
///
/// `name` must be a NUL-terminated, writable buffer.
unsafe fn strip_spaces(name: *mut c_char) -> *mut c_char {
    let mut p = name;
    // SAFETY: `p` walks a NUL-terminated buffer.
    while unsafe { *p } != 0 && unsafe { ossl_isspace(*p as c_int) } {
        // SAFETY: `p` is before the terminator.
        p = unsafe { p.add(1) };
    }
    // SAFETY: `p` is at or before the terminator.
    if unsafe { *p } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `*p` is non-zero, so `strlen(p) >= 1` and `q` is in bounds.
    let mut q = unsafe { p.add(strlen(p) - 1) };
    // SAFETY: `q >= p` and in bounds; `ossl_isspace` reads its own tables.
    while q != p && unsafe { ossl_isspace(*q as c_int) } {
        // SAFETY: `q > p >= name`, so `q` is in bounds.
        q = unsafe { q.sub(1) };
    }
    if p != q {
        // SAFETY: `q` is before the terminator, so `q + 1` is writable.
        unsafe { *q.add(1) = 0 };
    }
    // SAFETY: `p` is at or before the terminator.
    if unsafe { *p } == 0 {
        return ptr::null_mut();
    }
    p
}

/// `int ossl_v3_name_cmp(const char *name, const char *cmp)` — `crypto/x509/v3_utl.c:429-442`.
///
/// "Equal" means `cmp` is a prefix of `name` ending at a `.` or the terminator; this is the
/// V2I name comparison the `v3_*` tables use.
///
/// # Safety
///
/// `name`/`cmp` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_v3_name_cmp(name: *const c_char, cmp: *const c_char) -> c_int {
    // SAFETY: `cmp` is NUL-terminated per the contract.
    let len = unsafe { strlen(cmp) };
    // SAFETY: both are NUL-terminated and `len` bytes of `cmp` are readable.
    let ret = unsafe { strncmp(name, cmp, len) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: `name` is NUL-terminated, so `name[len]` is within the buffer once `len` bytes
    // matched (the first mismatch would have returned above).
    let c = unsafe { *name.add(len) };
    if c == 0 || c == b'.' as c_char {
        return 0;
    }
    1
}

/// `int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE) *dn_sk,
/// unsigned long chtype)` — `crypto/x509/v3_utl.c:1372-1419`.
///
/// The leading `X.`/`X:`/`X,` group is skipped so one section can spell a name's multiple
/// instances; a leading `+` marks a multi-valued addition. The `chtype` (an `unsigned long` in
/// the signature) is passed to `X509_NAME_add_entry_by_txt`'s `int` parameter, as in the
/// authority.
///
/// # Safety
///
/// `nm` NULL or live; `dn_sk` NULL or a live `CONF_VALUE` stack.
#[no_mangle]
pub unsafe extern "C" fn X509V3_NAME_from_section(
    nm: *mut X509Name,
    dn_sk: *mut OpenSslStack,
    chtype: c_ulong,
) -> c_int {
    if nm.is_null() {
        return 0;
    }
    // SAFETY: `dn_sk` is NULL or a live stack per the contract.
    let n = unsafe { OPENSSL_sk_num(dn_sk) };
    let mut i = 0;
    while i < n {
        // SAFETY: `0 <= i < n` and every element is a `CONF_VALUE`.
        let v = unsafe { OPENSSL_sk_value(dn_sk, i) }.cast::<ConfValue>();
        // SAFETY: `v` is a live `CONF_VALUE`; its `name` is NUL-terminated.
        let mut type_ = unsafe { (*v).name };
        let mut p = type_;
        // SAFETY: `p` walks the NUL-terminated name.
        while unsafe { *p } != 0 {
            // SAFETY: `p` is at or before the terminator.
            let spec =
                unsafe { *p == b':' as c_char || *p == b',' as c_char || *p == b'.' as c_char };
            if spec {
                // SAFETY: `p` is at a separator, so `p + 1` is within the buffer.
                p = unsafe { p.add(1) };
                // SAFETY: `p` is at or before the terminator.
                if unsafe { *p } != 0 {
                    type_ = p;
                }
                break;
            }
            // SAFETY: `p` walks the NUL-terminated name.
            p = unsafe { p.add(1) };
        }
        let mval;
        // SAFETY: `type_` is NUL-terminated, so `*type_` reads in bounds.
        if unsafe { *type_ } == b'+' as c_char {
            mval = -1;
            // SAFETY: `type_` points at the '+' and the buffer is NUL-terminated.
            type_ = unsafe { type_.add(1) };
        } else {
            mval = 0;
        }
        // SAFETY: `v` is live; `type_` NUL-terminated; `chtype` is the caller's type word.
        if unsafe {
            X509_NAME_add_entry_by_txt(
                nm,
                type_,
                chtype as c_int,
                (*v).value.cast::<c_uchar>(),
                -1,
                -1,
                mval,
            )
        } == 0
        {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------
// The IP-address conversions and the address printer
// ---------------------------------------------------------------------------

/// `struct IPV6_STAT` — `crypto/x509/v3_utl.c:1236-1245`.
#[repr(C)]
struct Ipv6Stat {
    /// `unsigned char tmp[16]` — the temporary IPv6 store.
    tmp: [c_uchar; 16],
    /// `int total` — bytes written into `tmp`.
    total: c_int,
    /// `int zero_pos` — the `::` position, or `-1`.
    zero_pos: c_int,
    /// `int zero_cnt` — the number of zero-length elements.
    zero_cnt: c_int,
}

/// `static int ipv6_from_asc(unsigned char *v6, const char *in)` — `crypto/x509/v3_utl.c:1247-1309`.
///
/// The colon-separated walk is `CONF_parse_list`; the sanity table that turns a `::` count into a
/// validity answer is the authority's, including the zero-count-dependent positions.
///
/// # Safety
///
/// `v6` must be 16 writable bytes; `in` must be NUL-terminated.
unsafe fn ipv6_from_asc(v6: *mut c_uchar, in_: *const c_char) -> c_int {
    let mut s = Ipv6Stat {
        tmp: [0; 16],
        total: 0,
        zero_pos: -1,
        zero_cnt: 0,
    };
    // SAFETY: `in_` is NUL-terminated; `ipv6_cb` accepts this `IPV6_STAT`.
    let ok = unsafe {
        CONF_parse_list(
            in_,
            b':' as c_int,
            0,
            Some(ipv6_cb),
            (&mut s as *mut Ipv6Stat).cast::<c_void>(),
        )
    };
    if ok == 0 {
        return 0;
    }
    if s.zero_pos == -1 {
        if s.total != 16 {
            return 0;
        }
    } else {
        if s.total == 16 {
            return 0;
        }
        if s.zero_cnt > 3 {
            return 0;
        } else if s.zero_cnt == 3 {
            if s.total > 0 {
                return 0;
            }
        } else if s.zero_cnt == 2 {
            if s.zero_pos != 0 && s.zero_pos != s.total {
                return 0;
            }
        } else if s.zero_pos == 0 || s.zero_pos == s.total {
            return 0;
        }
    }

    if s.zero_pos >= 0 {
        let zero_pos = s.zero_pos as usize;
        // SAFETY: `zero_pos <= 16` and `zero_pos` bytes are readable from `s.tmp`.
        unsafe {
            memcpy(
                v6.cast::<c_void>(),
                s.tmp.as_ptr().cast::<c_void>(),
                zero_pos,
            );
            memset(
                v6.add(zero_pos).cast::<c_void>(),
                0,
                (16 - s.total) as usize,
            );
        }
        if s.total != s.zero_pos {
            let n = (s.total - s.zero_pos) as usize;
            // SAFETY: the source range `s.tmp[zero_pos .. total]` is in bounds and the destination
            // `v6[zero_pos + 16 - total .. zero_pos + 16 - total + n]` is within the 16 bytes.
            unsafe {
                memcpy(
                    v6.add((s.zero_pos + 16 - s.total) as usize)
                        .cast::<c_void>(),
                    s.tmp.as_ptr().add(zero_pos).cast::<c_void>(),
                    n,
                );
            }
        }
    } else {
        // SAFETY: `s.tmp` is 16 bytes and `v6` is 16 writable bytes.
        unsafe { memcpy(v6.cast::<c_void>(), s.tmp.as_ptr().cast::<c_void>(), 16) };
    }
    1
}

/// `static int ipv6_cb(const char *elem, int len, void *usr)` — `crypto/x509/v3_utl.c:1311-1345`.
///
/// One `CONF_parse_list` element: length zero is a `::` component, longer than four is the
/// trailing dotted-quad form, and anything else is up to two hex bytes.
///
/// # Safety
///
/// `usr` must be a live `IPV6_STAT`; `elem` readable for `len` bytes plus the terminator.
unsafe extern "C" fn ipv6_cb(elem: *const c_char, len: c_int, usr: *mut c_void) -> c_int {
    let s = usr.cast::<Ipv6Stat>();
    // SAFETY: `s` is a live `IPV6_STAT` per the contract.
    if unsafe { (*s).total } == 16 {
        return 0;
    }
    if len == 0 {
        // SAFETY: `s` is a live `IPV6_STAT` per the contract.
        let zero_pos = unsafe { (*s).zero_pos };
        if zero_pos == -1 {
            // SAFETY: `s` is live per the contract.
            let total = unsafe { (*s).total };
            // SAFETY: as above.
            unsafe { (*s).zero_pos = total };
        } else {
            // SAFETY: `s` is live per the contract.
            if zero_pos != unsafe { (*s).total } {
                return 0;
            }
        }
        // SAFETY: `s` is live per the contract.
        unsafe { (*s).zero_cnt += 1 };
    } else if len > 4 {
        // SAFETY: `s` is live per the contract.
        if unsafe { (*s).total } > 12 {
            return 0;
        }
        // SAFETY: `elem` has at least `len + 1` readable bytes.
        if unsafe { *elem.add(len as usize) } != 0 {
            return 0;
        }
        // SAFETY: `total <= 12`, so `total + 4 <= 16` and the slice is inside `tmp`.
        let ok = unsafe { ipv4_from_asc((*s).tmp.as_mut_ptr().add((*s).total as usize), elem) };
        if ok == 0 {
            return 0;
        }
        // SAFETY: `s` is live per the contract.
        unsafe { (*s).total += 4 };
    } else {
        // SAFETY: `total <= 16`, so `total + 2 <= 18`; `ipv6_hex` writes at most two bytes, and
        // the authority's own `total > 12` guard above is what keeps the dotted-quad form safe.
        let ok = unsafe { ipv6_hex((*s).tmp.as_mut_ptr().add((*s).total as usize), elem, len) };
        if ok == 0 {
            return 0;
        }
        // SAFETY: `s` is live per the contract.
        unsafe { (*s).total += 2 };
    }
    1
}

/// `static int ipv6_hex(unsigned char *out, const char *in, int inlen)` —
/// `crypto/x509/v3_utl.c:1351-1370`.
///
/// At most four hex digits, accumulated big-endian into two output bytes.
///
/// # Safety
///
/// `out` must be 2 writable bytes; `in` readable for `inlen`.
unsafe fn ipv6_hex(out: *mut c_uchar, in_: *const c_char, inlen: c_int) -> c_int {
    if inlen > 4 {
        return 0;
    }
    let mut num: c_uint = 0;
    let mut n = inlen;
    let mut p = in_;
    while n > 0 {
        n -= 1;
        // SAFETY: `p` has `n` unconsumed bytes when the loop is entered.
        let c = unsafe { *p };
        // SAFETY: `p` is within the readable range.
        p = unsafe { p.add(1) };
        num <<= 4;
        // SAFETY: `c` is a byte value; `OPENSSL_hexchar2int` reads its own tables.
        let x = OPENSSL_hexchar2int(c as c_uchar);
        if x < 0 {
            return 0;
        }
        num |= (x as u8) as c_uint;
    }
    // SAFETY: `out` is 2 writable bytes per the contract.
    unsafe {
        *out = (num >> 8) as c_uchar;
        *out.add(1) = (num & 0xff) as c_uchar;
    }
    1
}

/// `static int ipv4_from_asc(unsigned char *v4, const char *in)` —
/// `crypto/x509/v3_utl.c:1225-1234`.
///
/// Four components separated by dots and no trailing input.
///
/// # Safety
///
/// `v4` must be 4 writable bytes; `in` must be NUL-terminated.
unsafe fn ipv4_from_asc(v4: *mut c_uchar, in_: *const c_char) -> c_int {
    let mut p = in_;
    // SAFETY: `in_` is NUL-terminated per the contract; each helper advances `p` within it.
    let ok = unsafe { get_ipv4_component(v4, &mut p) } != 0
        && unsafe { get_ipv4_dot(&mut p) } != 0
        && unsafe { get_ipv4_component(v4.add(1), &mut p) } != 0
        && unsafe { get_ipv4_dot(&mut p) } != 0
        && unsafe { get_ipv4_component(v4.add(2), &mut p) } != 0
        && unsafe { get_ipv4_dot(&mut p) } != 0
        && unsafe { get_ipv4_component(v4.add(3), &mut p) } != 0;
    // SAFETY: `p` is within the NUL-terminated input.
    if !ok || unsafe { *p } != 0 {
        return 0;
    }
    1
}

/// `static int get_ipv4_component(uint8_t *out_byte, const char **str)` —
/// `crypto/x509/v3_utl.c:1184-1210`.
///
/// Consumes one dotted component into `out_byte` and advances `*str`. A component over 255, an
/// empty one, a leading zero on a multi-digit one (a parser that accepted `010` as octal would
/// misread it), and a non-digit all answer zero.
///
/// # Safety
///
/// `str_` must point at a `*const c_char` within a NUL-terminated string; `out_byte` writable.
unsafe fn get_ipv4_component(out_byte: *mut c_uchar, str_: *mut *const c_char) -> c_int {
    let mut out: u32 = 0;
    loop {
        // SAFETY: `*str_` walks a NUL-terminated string.
        let ch = unsafe { **str_ };
        if !ossl_isdigit(ch as c_int) {
            return 0;
        }
        out = out * 10 + (ch as c_int - b'0' as c_int) as u32;
        if out > 255 {
            return 0;
        }
        // SAFETY: `*str_` was a digit, so it is before the terminator.
        unsafe { *str_ = (*str_).add(1) };
        // SAFETY: `*str_` is at or before the terminator.
        let next = unsafe { **str_ };
        if next == b'.' as c_char || next == 0 {
            // SAFETY: `out_byte` is writable per the contract.
            unsafe { *out_byte = out as c_uchar };
            return 1;
        }
        if out == 0 {
            return 0;
        }
    }
}

/// `static int get_ipv4_dot(const char **str)` — `crypto/x509/v3_utl.c:1216-1223`.
///
/// # Safety
///
/// `str_` must point at a `*const c_char` within a NUL-terminated string.
unsafe fn get_ipv4_dot(str_: *mut *const c_char) -> c_int {
    // SAFETY: `*str_` is at or before a terminator.
    if unsafe { **str_ } != b'.' as c_char {
        return 0;
    }
    // SAFETY: `*str_` was a '.', so it is before the terminator.
    unsafe { *str_ = (*str_).add(1) };
    1
}

/// `int ossl_a2i_ipadd(unsigned char *ipout, const char *ipasc)` —
/// `crypto/x509/v3_utl.c:1163-1176`.
///
/// A `:` anywhere selects the IPv6 form; otherwise it is IPv4. Answers the byte count written,
/// or 0 for an invalid string.
///
/// # Safety
///
/// `ipout` must be 16 writable bytes; `ipasc` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_a2i_ipadd(ipout: *mut c_uchar, ipasc: *const c_char) -> c_int {
    // SAFETY: `ipasc` is NUL-terminated per the contract.
    if !unsafe { strchr(ipasc, b':' as c_int) }.is_null() {
        // SAFETY: `ipout` is 16 writable bytes; `ipasc` is NUL-terminated.
        if unsafe { ipv6_from_asc(ipout, ipasc) } == 0 {
            return 0;
        }
        16
    } else {
        // SAFETY: `ipout` is 16 writable bytes (4 used); `ipasc` is NUL-terminated.
        if unsafe { ipv4_from_asc(ipout, ipasc) } == 0 {
            return 0;
        }
        4
    }
}

/// `ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc)` —
/// `crypto/x509/v3_utl.c:1096-1117`.
///
/// # Safety
///
/// `ipasc` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn a2i_IPADDRESS(ipasc: *const c_char) -> *mut Asn1String {
    let mut ipout = [0 as c_uchar; 16];
    // SAFETY: `ipout` is 16 writable bytes; `ipasc` is NUL-terminated.
    let iplen = unsafe { ossl_a2i_ipadd(ipout.as_mut_ptr(), ipasc) };
    if iplen == 0 {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let ret = ASN1_OCTET_STRING_new();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is live and this call's own; `ipout` is readable for `iplen`.
    if unsafe { ASN1_OCTET_STRING_set(ret, ipout.as_ptr(), iplen) } == 0 {
        // SAFETY: `ret` is this call's own.
        unsafe { ASN1_OCTET_STRING_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc)` —
/// `crypto/x509/v3_utl.c:1119-1161`.
///
/// The `address/netmask` form: both halves must parse and be the same length. A missing `/`
/// denies outright; a `NULL` allocation is the caller's, so the two failure paths are distinct.
///
/// # Safety
///
/// `ipasc` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn a2i_IPADDRESS_NC(ipasc: *const c_char) -> *mut Asn1String {
    let mut ipout = [0 as c_uchar; 32];
    let mut iptmp: *mut c_char;
    // SAFETY: `ipasc` is NUL-terminated per the contract.
    let slash = unsafe { strchr(ipasc, b'/' as c_int) };
    if slash.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ipasc` is NUL-terminated per the contract.
    iptmp = unsafe { CRYPTO_strdup(ipasc, FILE.as_ptr(), 1130) };
    if iptmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `slash` is within `ipasc`'s buffer.
    let mut p = unsafe { iptmp.add(slash.offset_from(ipasc) as usize) };
    // SAFETY: `p` points at the '/' within the copy.
    unsafe { *p = 0 };
    // SAFETY: `p` pointed at the '/' and `ipasc` is NUL-terminated, so `p + 1` is in bounds.
    p = unsafe { p.add(1) };

    // SAFETY: `ipout` is 32 writable bytes; `iptmp` is the first half, NUL-terminated.
    let iplen1 = unsafe { ossl_a2i_ipadd(ipout.as_mut_ptr(), iptmp) };
    if iplen1 == 0 {
        // SAFETY: the error tail's contract is this function's; `iptmp` is this call's own copy.
        return unsafe { ipaddress_nc_err(iptmp, ptr::null_mut()) };
    }
    // SAFETY: `p` is the second half, NUL-terminated; `ipout` has 32 bytes.
    let iplen2 = unsafe { ossl_a2i_ipadd(ipout.as_mut_ptr().add(iplen1 as usize), p) };
    // SAFETY: `iptmp` is this call's own.
    unsafe { CRYPTO_free(iptmp.cast::<c_void>(), FILE.as_ptr(), 1143) };
    iptmp = ptr::null_mut();

    if iplen2 == 0 || iplen1 != iplen2 {
        // SAFETY: the error tail's contract is this function's.
        return unsafe { ipaddress_nc_err(iptmp, ptr::null_mut()) };
    }
    // SAFETY: no preconditions.
    let ret = ASN1_OCTET_STRING_new();
    if ret.is_null() {
        // SAFETY: the error tail's contract is this function's.
        return unsafe { ipaddress_nc_err(iptmp, ret) };
    }
    // SAFETY: `ret` is live and this call's own; `ipout` is readable for `iplen1 + iplen2`.
    if unsafe { ASN1_OCTET_STRING_set(ret, ipout.as_ptr(), iplen1 + iplen2) } == 0 {
        // SAFETY: the error tail's contract is this function's.
        return unsafe { ipaddress_nc_err(iptmp, ret) };
    }
    ret
}

/// `crypto/x509/v3_utl.c:1157-1160`'s `err:` label of [`a2i_IPADDRESS_NC`].
///
/// # Safety
///
/// `iptmp` must be this call's own or NULL; `ret` NULL or this call's own.
unsafe fn ipaddress_nc_err(iptmp: *mut c_char, ret: *mut Asn1String) -> *mut Asn1String {
    // SAFETY: `iptmp` is NULL or this call's own; the site is constant.
    unsafe { CRYPTO_free(iptmp.cast::<c_void>(), FILE.as_ptr(), 1158) };
    // SAFETY: `ret` is NULL or this call's own.
    unsafe { ASN1_OCTET_STRING_free(ret) };
    ptr::null_mut()
}

/// `char *ossl_ipaddr_to_asc(unsigned char *p, int len)` — `crypto/x509/v3_utl.c:1061-1089`.
///
/// Four bytes are dotted decimal, sixteen are colon-separated upper-case hex, and anything else
/// is the `<invalid length=%d>` literal; the result is a fresh `OPENSSL_strdup`.
///
/// # Safety
///
/// `p` must be 4 or 16 readable bytes when `len` is 4 or 16.
#[no_mangle]
pub unsafe extern "C" fn ossl_ipaddr_to_asc(p: *mut c_uchar, len: c_int) -> *mut c_char {
    let mut buf = [0 as c_char; 40];
    match len {
        4 => {
            // SAFETY: `p` is 4 readable bytes; `buf` is 40 writable.
            unsafe {
                BIO_snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    c"%d.%d.%d.%d".as_ptr(),
                    c_int::from(*p),
                    c_int::from(*p.add(1)),
                    c_int::from(*p.add(2)),
                    c_int::from(*p.add(3)),
                );
            }
        }
        16 => {
            let mut out = buf.as_mut_ptr();
            let mut remain = buf.len();
            let mut bytes: c_int = 0;
            let mut i = 8;
            let mut q = p;
            while i > 0 {
                i -= 1;
                if bytes < 0 {
                    break;
                }
                let template = if i > 0 {
                    c"%X:".as_ptr()
                } else {
                    c"%X".as_ptr()
                };
                // SAFETY: `q` is within the 16 readable bytes.
                let val = (c_uint::from(unsafe { *q }) << 8) | c_uint::from(unsafe { *q.add(1) });
                // SAFETY: `out` points into `buf` and `remain` is the bytes left.
                bytes = unsafe { BIO_snprintf(out, remain, template, val) };
                // SAFETY: `q` advanced by one address pair.
                q = unsafe { q.add(2) };
                remain = (remain as c_int - bytes) as usize;
                // SAFETY: `out` advances by the bytes written, within `buf`.
                out = unsafe { out.add(bytes as usize) };
            }
        }
        _ => {
            // SAFETY: `buf` is 40 writable bytes.
            unsafe {
                BIO_snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    c"<invalid length=%d>".as_ptr(),
                    len,
                );
            }
        }
    }
    // SAFETY: `buf` is NUL-terminated by `BIO_snprintf`.
    unsafe { CRYPTO_strdup(buf.as_ptr(), FILE.as_ptr(), 1088) }
}

/// `void X509_email_free(STACK_OF(OPENSSL_STRING) *sk)` — `crypto/x509/v3_utl.c:568-571`.
///
/// # Safety
///
/// `sk` must be NULL or a live stack of `OPENSSL_STRING` elements.
#[no_mangle]
pub unsafe extern "C" fn X509_email_free(sk: *mut OpenSslStack) {
    // SAFETY: `sk` is NULL or a live stack whose elements are this call's own strings.
    unsafe { OPENSSL_sk_pop_free(sk, Some(str_free)) };
}

/// The `void (*)(void *)` thunk `sk_OPENSSL_STRING_pop_free(sk, str_free)` installs —
/// `crypto/x509/v3_utl.c:570`.
///
/// # Safety
///
/// `s` must be NULL or an `OPENSSL_STRING` element of the stack.
unsafe extern "C" fn str_free(s: *mut c_void) {
    // SAFETY: `s` is NULL or a stack element this call owns.
    unsafe { CRYPTO_free(s, FILE.as_ptr(), 527) };
}

/// `int OSSL_GENERAL_NAMES_print(BIO *out, GENERAL_NAMES *gens, int indent)` —
/// `crypto/x509/v3_utl.c:1421-1432`.
///
/// One general name per line, each indented by `indent + 2`; the newline is written *before* every
/// name but the first. The authority answers 1 unconditionally (the per-name printer's result is
/// discarded).
///
/// # Safety
///
/// `out` must be a live BIO; `gens` must be a live `GENERAL_NAMES`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_GENERAL_NAMES_print(
    out: *mut Bio,
    gens: *mut OpenSslStack,
    indent: c_int,
) -> c_int {
    // SAFETY: `gens` is a live `GENERAL_NAMES` per the contract.
    let num = unsafe { OPENSSL_sk_num(gens) };
    for i in 0..num {
        if i > 0 {
            // SAFETY: `out` is a live BIO and the literal is static NUL-terminated.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: `out` is a live BIO and the format is a static literal.
        unsafe { BIO_printf(out, c"%*s".as_ptr(), indent + 2, c"".as_ptr()) };
        // SAFETY: `gens` is live and `i` is within its count.
        let gen = unsafe { OPENSSL_sk_value(gens, i) };
        // SAFETY: `out` is live and `gen` is a live `GENERAL_NAME`.
        unsafe { GENERAL_NAME_print(out, gen.cast()) };
    }
    1
}

/// `int ossl_bio_print_hex(BIO *out, unsigned char *buf, int len)` —
/// `crypto/x509/v3_utl.c:1434-1449`.
///
/// An empty buffer prints nothing and answers success; otherwise the buffer is hex-encoded and
/// written, and the write's positivity is the answer.
///
/// # Safety
///
/// `out` must be a live BIO; `buf` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_bio_print_hex(out: *mut Bio, buf: *mut c_uchar, len: c_int) -> c_int {
    if len == 0 {
        return 1;
    }
    // SAFETY: `buf` is readable for `len` bytes per the contract.
    let hexbuf = unsafe { OPENSSL_buf2hexstr(buf, len as c_long) };
    if hexbuf.is_null() {
        return 0;
    }
    // SAFETY: `out` is a live BIO and `hexbuf` is NUL-terminated.
    let result = unsafe { BIO_puts(out, hexbuf) } > 0;
    // SAFETY: `hexbuf` is this call's own allocation.
    unsafe { CRYPTO_free(hexbuf.cast::<c_void>(), FILE.as_ptr(), 1447) };
    c_int::from(result)
}

// ---------------------------------------------------------------------------
// The email/OCSP accessors
// ---------------------------------------------------------------------------

/// `static int sk_strcmp(const char *const *a, const char *const *b)` —
/// `crypto/x509/v3_utl.c:444-447`.
///
/// The dedup comparator `sk_OPENSSL_STRING_new(sk_strcmp)` installs, so the email stack
/// [`append_ia5`] builds is ordered by `strcmp` and `OPENSSL_sk_find` then binary-searches it.
///
/// # Safety
///
/// `a`/`b` must be stack element slots, each holding a live `OPENSSL_STRING`.
unsafe extern "C" fn sk_strcmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack layer passes element slots for a comparator installed on this stack.
    let (x, y) = unsafe { (*a.cast::<*const c_char>(), *b.cast::<*const c_char>()) };
    // SAFETY: both are non-null, NUL-terminated strings the caller pushed.
    unsafe { strcmp(x, y) }
}

/// `static int append_ia5(STACK_OF(OPENSSL_STRING) **sk, const ASN1_IA5STRING *email)` —
/// `crypto/x509/v3_utl.c:530-566`.
///
/// Sanity-checks the string (type, empty, embedded NUL), then appends a duplicate-free copy. The
/// three "not a usable IA5 address" cases answer success without appending; on an allocation or
/// push failure the caller-visible stack is freed and set back to NULL, so a partial result never
/// escapes. `X509_email_free` is the caller's sharing free, reused here as the authority does.
///
/// # Safety
///
/// `sk` must be writable and hold NULL or a live string stack; `email` must be live.
unsafe fn append_ia5(sk: *mut *mut OpenSslStack, email: *const Asn1String) -> c_int {
    // SAFETY: `email` is live per the contract.
    let (type_, data, length) = unsafe { ((*email).type_, (*email).data, (*email).length) };
    if type_ != V_ASN1_IA5STRING {
        return 1;
    }
    if data.is_null() || length == 0 {
        return 1;
    }
    // SAFETY: `data` is `length` readable bytes per the contract.
    if !unsafe { memchr(data.cast::<c_void>(), 0, length as usize) }.is_null() {
        return 1;
    }
    // SAFETY: `sk` is writable per the contract.
    if unsafe { *sk }.is_null() {
        // SAFETY: no preconditions; the comparator is this module's own.
        let fresh = OPENSSL_sk_new(Some(sk_strcmp));
        // SAFETY: `sk` is writable per the contract.
        unsafe { *sk = fresh };
    }
    // SAFETY: `sk` is writable per the contract.
    if unsafe { *sk }.is_null() {
        return 0;
    }
    // SAFETY: `data` is `length` readable bytes per the contract.
    let emtmp =
        unsafe { CRYPTO_strndup(data.cast::<c_char>(), length as usize, FILE.as_ptr(), 547) };
    if emtmp.is_null() {
        // SAFETY: `*sk` is the live stack this call built or the caller's own.
        unsafe { X509_email_free(*sk) };
        // SAFETY: `sk` is writable per the contract.
        unsafe { *sk = ptr::null_mut() };
        return 0;
    }
    // SAFETY: `*sk` is live; `emtmp` is this call's own NUL-terminated string.
    if unsafe { OPENSSL_sk_find(*sk, emtmp.cast::<c_void>()) } != -1 {
        // SAFETY: `emtmp` is this call's own.
        unsafe { CRYPTO_free(emtmp.cast::<c_void>(), FILE.as_ptr(), 556) };
        return 1;
    }
    // SAFETY: `*sk` is live; `emtmp` is this call's own string.
    if unsafe { OPENSSL_sk_push(*sk, emtmp.cast::<c_void>()) } == 0 {
        // SAFETY: `emtmp` is this call's own (the failed push did not take it).
        unsafe { CRYPTO_free(emtmp.cast::<c_void>(), FILE.as_ptr(), 560) };
        // SAFETY: `*sk` is the live stack this call built or the caller's own.
        unsafe { X509_email_free(*sk) };
        // SAFETY: `sk` is writable per the contract.
        unsafe { *sk = ptr::null_mut() };
        return 0;
    }
    1
}

/// The `void (*)(void *)` thunk `sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free)` installs —
/// `crypto/x509/v3_utl.c:456`.
///
/// # Safety
///
/// `p` must be NULL or a live `GENERAL_NAME` (the stack contract).
unsafe extern "C" fn general_name_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `GENERAL_NAME` pointers per the contract.
    unsafe { GENERAL_NAME_free(p.cast::<GeneralName>()) };
}

/// `static STACK_OF(OPENSSL_STRING) *get_email(const X509_NAME *name, GENERAL_NAMES *gens)` —
/// `crypto/x509/v3_utl.c:496-523`.
///
/// First the subject DN's `emailAddress` attributes, then every `GEN_EMAIL` general name. A failed
/// append answers NULL; the partial stack is left for the caller's `X509_email_free` to drain, as
/// in the authority.
///
/// # Safety
///
/// `name` must be NULL or a live `X509_NAME`; `gens` NULL or a live `GENERAL_NAMES`.
unsafe fn get_email(name: *const X509Name, gens: *mut OpenSslStack) -> *mut OpenSslStack {
    let mut ret: *mut OpenSslStack = ptr::null_mut();
    let mut i: c_int = -1;
    loop {
        // SAFETY: `name` is NULL or live; the NID is a constant.
        i = unsafe { X509_NAME_get_index_by_NID(name, NID_pkcs9_emailAddress, i) };
        if i < 0 {
            break;
        }
        // SAFETY: `i` is a valid entry index returned above.
        let ne = unsafe { X509_NAME_get_entry(name, i) };
        // SAFETY: `ne` is a live entry.
        let email = unsafe { X509_NAME_ENTRY_get_data(ne) };
        // SAFETY: `&mut ret` is writable; `email` is live.
        if unsafe { append_ia5(&raw mut ret, email) } == 0 {
            return ptr::null_mut();
        }
    }
    // SAFETY: `gens` is NULL or a live `GENERAL_NAMES` per the contract (a NULL answer is -1).
    let num = unsafe { OPENSSL_sk_num(gens) };
    for j in 0..num {
        // SAFETY: `gens` is live and `j` is within its count.
        let gen = unsafe { OPENSSL_sk_value(gens, j) }.cast::<GeneralName>();
        // SAFETY: `gen` is a live `GENERAL_NAME`.
        if unsafe { (*gen).type_ } != GEN_EMAIL {
            continue;
        }
        // SAFETY: `gen` is live and the `rfc822Name` arm is live under the `GEN_EMAIL` selector.
        let ia5 = unsafe { (*gen).d.ia5 };
        // SAFETY: `&mut ret` is writable; `ia5` is live.
        if unsafe { append_ia5(&raw mut ret, ia5) } == 0 {
            return ptr::null_mut();
        }
    }
    ret
}

/// `STACK_OF(OPENSSL_STRING) *X509_get1_email(X509 *x)` — `crypto/x509/v3_utl.c:449-458`.
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_get1_email(x: *mut X509) -> *mut OpenSslStack {
    // SAFETY: `x` is live per the contract; `crit`/`idx` are NULL, which the decoder accepts.
    let gens =
        unsafe { X509_get_ext_d2i(x, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }
            .cast::<OpenSslStack>();
    // SAFETY: `x` is live; `gens` is NULL or a live `GENERAL_NAMES`.
    let ret = unsafe { get_email(X509_get_subject_name(x), gens) };
    // SAFETY: `gens` is NULL or this call's own stack of `GENERAL_NAME` pointers.
    unsafe { OPENSSL_sk_pop_free(gens, Some(general_name_free_thunk)) };
    ret
}

/// `STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x)` — `crypto/x509/v3_utl.c:460-480`.
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_get1_ocsp(x: *mut X509) -> *mut OpenSslStack {
    let mut ret: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `x` is live per the contract; `crit`/`idx` are NULL, which the decoder accepts.
    let info = unsafe { X509_get_ext_d2i(x, NID_info_access, ptr::null_mut(), ptr::null_mut()) }
        .cast::<OpenSslStack>();
    if info.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `info` is live.
    let num = unsafe { OPENSSL_sk_num(info) };
    for i in 0..num {
        // SAFETY: `info` is live and `i` is within its count.
        let ad = unsafe { OPENSSL_sk_value(info, i) }.cast::<AccessDescription>();
        // SAFETY: `ad` is a live `ACCESS_DESCRIPTION`; its `method` is a live object.
        if unsafe { OBJ_obj2nid((*ad).method) } == NID_ad_OCSP {
            // SAFETY: `ad` is live; `location` is a live `GENERAL_NAME`.
            let loc = unsafe { (*ad).location };
            // SAFETY: `loc` is live.
            if unsafe { (*loc).type_ } == GEN_URI {
                // SAFETY: `loc` is live and the `uniformResourceIdentifier` arm is live under the
                // `GEN_URI` selector.
                let ia5 = unsafe { (*loc).d.ia5 };
                // SAFETY: `&mut ret` is writable; `ia5` is live.
                if unsafe { append_ia5(&raw mut ret, ia5) } == 0 {
                    break;
                }
            }
        }
    }
    // SAFETY: `info` is this call's own authority-info stack.
    unsafe { AUTHORITY_INFO_ACCESS_free(info) };
    ret
}

/// The `void (*)(void *)` thunk `sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free)` installs —
/// `crypto/x509/v3_utl.c:492`.
///
/// # Safety
///
/// `p` must be NULL or a live `X509_EXTENSION` (the stack contract).
unsafe extern "C" fn x509_extension_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `X509_EXTENSION` pointers per the contract.
    unsafe { X509_EXTENSION_free(p.cast::<X509Extension>()) };
}

/// `STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x)` — `crypto/x509/v3_utl.c:482-494`.
///
/// The request's `subjectAltName` extension is decoded (`:487-488`), the subject DN and the
/// `GEN_EMAIL` general names are collected through [`get_email`] (`:490`), and both intermediate
/// stacks are released (`:491-492`).
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get1_email(x: *mut X509Req) -> *mut OpenSslStack {
    // SAFETY: `x` is live per the contract; the callee answers a new stack or NULL.
    let exts = unsafe { X509_REQ_get_extensions(x) };
    // SAFETY: `exts` is NULL or a live extension stack; `crit`/`idx` are NULL, which the decoder
    // accepts.
    let gens =
        unsafe { X509V3_get_d2i(exts, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }
            .cast::<OpenSslStack>();
    // SAFETY: `x` is live; `gens` is NULL or a live `GENERAL_NAMES`.
    let ret = unsafe { get_email(X509_REQ_get_subject_name(x), gens) };
    // SAFETY: `gens` is NULL or this call's own stack of `GENERAL_NAME` pointers.
    unsafe { OPENSSL_sk_pop_free(gens, Some(general_name_free_thunk)) };
    // SAFETY: `exts` is NULL or this call's own stack of extensions.
    unsafe { OPENSSL_sk_pop_free(exts, Some(x509_extension_free_thunk)) };
    ret
}

// ---------------------------------------------------------------------------
// The hostname / email / IP matching surface
// ---------------------------------------------------------------------------

/// `#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 0x1` — `include/openssl/x509v3.h.in:790`.
const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT: c_uint = 0x1;
/// `#define X509_CHECK_FLAG_NO_WILDCARDS 0x2` — `include/openssl/x509v3.h.in:792`.
const X509_CHECK_FLAG_NO_WILDCARDS: c_uint = 0x2;
/// `#define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4` — `include/openssl/x509v3.h.in:794`.
const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS: c_uint = 0x4;
/// `#define X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8` — `include/openssl/x509v3.h.in:796`.
const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS: c_uint = 0x8;
/// `#define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10` — `include/openssl/x509v3.h.in:798`.
const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS: c_uint = 0x10;
/// `#define X509_CHECK_FLAG_NEVER_CHECK_SUBJECT 0x20` — `include/openssl/x509v3.h.in:800`.
const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: c_uint = 0x20;
/// `#define _X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000` — `include/openssl/x509v3.h.in:806`.
const _X509_CHECK_FLAG_DOT_SUBDOMAINS: c_uint = 0x8000;

/// `#define LABEL_START (1 << 0)` — `crypto/x509/v3_utl.c:730`.
const LABEL_START: c_int = 1 << 0;
/// `#define LABEL_END (1 << 1)` — `crypto/x509/v3_utl.c:731`. The authority defines it and no line
/// reads it; kept for fidelity.
#[allow(dead_code)]
const LABEL_END: c_int = 1 << 1;
/// `#define LABEL_HYPHEN (1 << 2)` — `crypto/x509/v3_utl.c:732`.
const LABEL_HYPHEN: c_int = 1 << 2;
/// `#define LABEL_IDNA (1 << 3)` — `crypto/x509/v3_utl.c:733`.
const LABEL_IDNA: c_int = 1 << 3;

/// `typedef int (*equal_fn)(const unsigned char *pattern, size_t pattern_len,
/// const unsigned char *subject, size_t subject_len, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:573-575`.
type EqualFn = unsafe extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, c_uint) -> c_int;

/// `HAS_CASE_PREFIX(s, p)` — `include/internal/common.h:63`, i.e.
/// `OPENSSL_strncasecmp(s, p, sizeof(p) - 1) == 0`.
///
/// # Safety
///
/// `s` must be readable for `p`'s byte length (the callers guarantee at least that many bytes).
unsafe fn has_case_prefix(s: *const c_uchar, p: &CStr) -> bool {
    // SAFETY: `s` is readable for `p`'s length per the contract.
    (unsafe { OPENSSL_strncasecmp(s.cast::<c_char>(), p.as_ptr(), p.count_bytes()) }) == 0
}

/// `static void skip_prefix(const unsigned char **p, size_t *plen, size_t subject_len,
/// unsigned int flags)` — `crypto/x509/v3_utl.c:578-606`.
///
/// Advances the pattern past any leading labels the dot-subdomain flag permits, but only if the
/// whole prefix can be dropped (the remaining length equals the subject's).
///
/// # Safety
///
/// `p`/`plen` are writable slots naming the pattern; `*p` is `*plen` readable bytes.
unsafe fn skip_prefix(p: *mut *const c_uchar, plen: *mut usize, subject_len: usize, flags: c_uint) {
    // SAFETY: `p`/`plen` are the caller's own slots.
    let mut pattern = unsafe { *p };
    // SAFETY: as above.
    let mut pattern_len = unsafe { *plen };
    if flags & _X509_CHECK_FLAG_DOT_SUBDOMAINS == 0 {
        return;
    }
    while pattern_len > subject_len {
        // SAFETY: `pattern` has `pattern_len` readable bytes, so `*pattern` is in bounds.
        if unsafe { *pattern } == 0 {
            break;
        }
        if flags & X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS != 0
            // SAFETY: `pattern` is before the terminator.
            && unsafe { *pattern } == b'.'
        {
            break;
        }
        // SAFETY: `pattern` is before the terminator.
        pattern = unsafe { pattern.add(1) };
        pattern_len -= 1;
    }
    if pattern_len == subject_len {
        // SAFETY: `p`/`plen` are the caller's own slots.
        unsafe {
            *p = pattern;
            *plen = pattern_len;
        }
    }
}

/// `static int equal_nocase(const unsigned char *pattern, size_t pattern_len,
/// const unsigned char *subject, size_t subject_len, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:609-636`.
///
/// ASCII-case-insensitive compare after the optional dot-subdomain prefix skip; a NUL in the
/// pattern is refused even if it would match.
///
/// # Safety
///
/// `pattern` is `pattern_len` and `subject` is `subject_len` readable bytes.
unsafe extern "C" fn equal_nocase(
    pattern: *const c_uchar,
    pattern_len: usize,
    subject: *const c_uchar,
    subject_len: usize,
    flags: c_uint,
) -> c_int {
    let mut p = pattern;
    let mut plen = pattern_len;
    // SAFETY: `&mut p`/`&mut plen` are this frame's own slots; the byte ranges are the caller's.
    unsafe { skip_prefix(&raw mut p, &raw mut plen, subject_len, flags) };
    if plen != subject_len {
        return 0;
    }
    let mut s = subject;
    let mut n = plen;
    while n != 0 {
        // SAFETY: `p`/`s` each have `n` readable bytes remaining.
        let (mut l, mut r) = unsafe { (*p, *s) };
        if l == 0 {
            return 0;
        }
        if l != r {
            if l.is_ascii_uppercase() {
                l = (l - b'A') + b'a';
            }
            if r.is_ascii_uppercase() {
                r = (r - b'A') + b'a';
            }
            if l != r {
                return 0;
            }
        }
        // SAFETY: `p`/`s` advance within the `n`-byte range.
        unsafe {
            p = p.add(1);
            s = s.add(1);
        }
        n -= 1;
    }
    1
}

/// `static int equal_case(const unsigned char *pattern, size_t pattern_len,
/// const unsigned char *subject, size_t subject_len, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:639-647`.
///
/// # Safety
///
/// `pattern` is `pattern_len` and `subject` is `subject_len` readable bytes.
unsafe extern "C" fn equal_case(
    pattern: *const c_uchar,
    pattern_len: usize,
    subject: *const c_uchar,
    subject_len: usize,
    flags: c_uint,
) -> c_int {
    let mut p = pattern;
    let mut plen = pattern_len;
    // SAFETY: `&mut p`/`&mut plen` are this frame's own slots; the byte ranges are the caller's.
    unsafe { skip_prefix(&raw mut p, &raw mut plen, subject_len, flags) };
    if plen != subject_len {
        return 0;
    }
    // SAFETY: `p`/`subject` are each `plen` readable bytes.
    c_int::from(unsafe { memcmp(p.cast::<c_void>(), subject.cast::<c_void>(), plen) } == 0)
}

/// `static int equal_email(const unsigned char *a, size_t a_len, const unsigned char *b,
/// size_t b_len, unsigned int unused_flags)` — `crypto/x509/v3_utl.c:653-677`.
///
/// RFC 5280 §7.5: only the domain is compared case-insensitively, so the search for the last `@`
/// runs backwards to leave any quoted local-part alone.
///
/// # Safety
///
/// `a` is `a_len` and `b` is `b_len` readable bytes.
unsafe extern "C" fn equal_email(
    a: *const c_uchar,
    a_len: usize,
    b: *const c_uchar,
    b_len: usize,
    _unused_flags: c_uint,
) -> c_int {
    let mut i = a_len;
    if a_len != b_len {
        return 0;
    }
    while i > 0 {
        i -= 1;
        // SAFETY: `i < a_len == b_len`, so both reads are in bounds.
        if unsafe { *a.add(i) } == b'@' || unsafe { *b.add(i) } == b'@' {
            // SAFETY: `a+i`/`b+i` are each `a_len - i` readable bytes.
            if unsafe { equal_nocase(a.add(i), a_len - i, b.add(i), a_len - i, 0) } == 0 {
                return 0;
            }
            break;
        }
    }
    if i == 0 {
        i = a_len;
    }
    // SAFETY: `a`/`b` are each at least `i <= a_len == b_len` readable bytes.
    unsafe { equal_case(a, i, b, i, 0) }
}

/// `static int wildcard_match(const unsigned char *prefix, size_t prefix_len,
/// const unsigned char *suffix, size_t suffix_len, const unsigned char *subject,
/// size_t subject_len, unsigned int flags)` — `crypto/x509/v3_utl.c:683-728`.
///
/// Matches the wildcard's fixed prefix and suffix against the subject and then validates the
/// in-between label characters.
///
/// # Safety
///
/// `prefix`/`suffix`/`subject` are readable for their stated lengths; `suffix_len >= 1` (both
/// callers derive the suffix from a `valid_star` result, which leaves at least one byte after the
/// star).
unsafe extern "C" fn wildcard_match(
    prefix: *const c_uchar,
    prefix_len: usize,
    suffix: *const c_uchar,
    suffix_len: usize,
    subject: *const c_uchar,
    subject_len: usize,
    flags: c_uint,
) -> c_int {
    let mut allow_multi = false;
    let mut allow_idna = false;
    if subject_len < prefix_len + suffix_len {
        return 0;
    }
    // SAFETY: `prefix` is `prefix_len` and `subject` is `subject_len >= prefix_len` bytes.
    if unsafe { equal_nocase(prefix, prefix_len, subject, prefix_len, flags) } == 0 {
        return 0;
    }
    // SAFETY: `prefix_len <= subject_len`.
    let wildcard_start = unsafe { subject.add(prefix_len) };
    // SAFETY: `suffix_len <= subject_len`.
    let wildcard_end = unsafe { subject.add(subject_len - suffix_len) };
    // SAFETY: `wildcard_end` is `suffix_len` readable bytes.
    if unsafe { equal_nocase(wildcard_end, suffix_len, suffix, suffix_len, flags) } == 0 {
        return 0;
    }
    // SAFETY: `suffix` has `suffix_len >= 1` readable bytes per the contract.
    if prefix_len == 0 && unsafe { *suffix } == b'.' {
        if wildcard_start == wildcard_end {
            return 0;
        }
        allow_idna = true;
        if flags & X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS != 0 {
            allow_multi = true;
        }
    }
    // SAFETY: `subject` has `subject_len >= 4` bytes when the guard is true.
    if !allow_idna && subject_len >= 4 && unsafe { has_case_prefix(subject, c"xn--") } {
        return 0;
    }
    // SAFETY: `wildcard_start`/`wildcard_end` delimit the star's matched bytes.
    if wildcard_end == unsafe { wildcard_start.add(1) } && unsafe { *wildcard_start } == b'*' {
        return 1;
    }
    let mut q = wildcard_start;
    while q != wildcard_end {
        // SAFETY: `q` is within the wildcard byte range.
        let c = unsafe { *q };
        let ok = c.is_ascii_alphanumeric() || c == b'-' || (allow_multi && c == b'.');
        if !ok {
            return 0;
        }
        // SAFETY: `q` advances toward `wildcard_end`.
        q = unsafe { q.add(1) };
    }
    1
}

/// `static const unsigned char *valid_star(const unsigned char *p, size_t len,
/// unsigned int flags)` — `crypto/x509/v3_utl.c:735-796`.
///
/// Locates the one legal wildcard, or NULL. `LABEL_*` is the little state machine the authority
/// runs; the final label may not end in a hyphen or dot and at least two dots must follow the
/// star.
///
/// # Safety
///
/// `p` must be `len` readable bytes.
unsafe fn valid_star(p: *const c_uchar, len: usize, flags: c_uint) -> *const c_uchar {
    let mut star: *const c_uchar = ptr::null();
    let mut state = LABEL_START;
    let mut dots: c_int = 0;
    let mut i = 0;
    while i < len {
        // SAFETY: `i < len`, so `p[i]` is readable.
        let c = unsafe { *p.add(i) };
        if c == b'*' {
            let atstart = (state & LABEL_START) != 0;
            // SAFETY: `i < len`, so `i == len - 1` or `i + 1 < len` is readable.
            let atend = i == len - 1 || unsafe { *p.add(i + 1) } == b'.';
            if !star.is_null() || (state & LABEL_IDNA) != 0 || dots != 0 {
                return ptr::null();
            }
            if flags & X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS != 0 && !(atstart && atend) {
                return ptr::null();
            }
            if !atstart && !atend {
                return ptr::null();
            }
            // SAFETY: `i < len`; the returned pointer points into the caller's buffer.
            star = unsafe { p.add(i) };
            state &= !LABEL_START;
        } else if c.is_ascii_alphanumeric() {
            if (state & LABEL_START) != 0
                && len - i >= 4
                // SAFETY: `len - i >= 4` bytes are readable from `p + i`.
                && unsafe { has_case_prefix(p.add(i), c"xn--") }
            {
                state |= LABEL_IDNA;
            }
            state &= !(LABEL_HYPHEN | LABEL_START);
        } else if c == b'.' {
            if (state & (LABEL_HYPHEN | LABEL_START)) != 0 {
                return ptr::null();
            }
            state = LABEL_START;
            dots += 1;
        } else if c == b'-' {
            if (state & LABEL_START) != 0 {
                return ptr::null();
            }
            state |= LABEL_HYPHEN;
        } else {
            return ptr::null();
        }
        i += 1;
    }
    if (state & (LABEL_START | LABEL_HYPHEN)) != 0 || dots < 2 {
        return ptr::null();
    }
    star
}

/// `static int equal_wildcard(const unsigned char *pattern, size_t pattern_len,
/// const unsigned char *subject, size_t subject_len, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:799-817`.
///
/// # Safety
///
/// `pattern` is `pattern_len` and `subject` is `subject_len` readable bytes.
unsafe extern "C" fn equal_wildcard(
    pattern: *const c_uchar,
    pattern_len: usize,
    subject: *const c_uchar,
    subject_len: usize,
    flags: c_uint,
) -> c_int {
    let mut star: *const c_uchar = ptr::null();
    // SAFETY: `subject` is `subject_len` readable bytes.
    if !(subject_len > 1 && unsafe { *subject } == b'.') {
        // SAFETY: `pattern` is `pattern_len` readable bytes.
        star = unsafe { valid_star(pattern, pattern_len, flags) };
    }
    if star.is_null() {
        // SAFETY: readable ranges per the contract.
        return unsafe { equal_nocase(pattern, pattern_len, subject, subject_len, flags) };
    }
    // SAFETY: `star` is within `pattern[..pattern_len]`, so both derived lengths are exact.
    unsafe {
        wildcard_match(
            pattern,
            star.offset_from(pattern).cast_unsigned(),
            star.add(1),
            pattern
                .add(pattern_len)
                .offset_from(star.add(1))
                .cast_unsigned(),
            subject,
            subject_len,
            flags,
        )
    }
}

/// `static int do_check_string(const ASN1_STRING *a, int cmp_type, equal_fn equal,
/// unsigned int flags, const char *b, size_t blen, char **peername)` —
/// `crypto/x509/v3_utl.c:825-867`.
///
/// Compares one candidate string by the chosen `equal` function. `cmp_type > 0` requires an exact
/// type match; `cmp_type <= 0` converts the string to UTF-8 first. A positive match optionally
/// records the peer name (a fresh `OPENSSL_strndup`); an allocation failure answers -1.
///
/// # Safety
///
/// `a` is `NULL` or live but the callers pass live; `b` is `blen` readable bytes; `peername` is
/// NULL or writable.
unsafe fn do_check_string(
    a: *const Asn1String,
    cmp_type: c_int,
    equal: EqualFn,
    flags: c_uint,
    b: *const c_char,
    blen: usize,
    peername: *mut *mut c_char,
) -> c_int {
    let mut rv = 0;
    // SAFETY: `a` is live per the contract.
    let (data, length, type_) = unsafe { ((*a).data, (*a).length, (*a).type_) };
    if data.is_null() || length == 0 {
        return 0;
    }
    if cmp_type > 0 {
        if cmp_type != type_ {
            return 0;
        }
        if cmp_type == V_ASN1_IA5STRING {
            // SAFETY: `data` is `length` and `b` is `blen` readable bytes.
            rv = unsafe { equal(data, length as usize, b.cast::<c_uchar>(), blen, flags) };
        } else if length as usize == blen
            // SAFETY: `data` and `b` are each `blen` readable bytes.
            && unsafe { memcmp(data.cast::<c_void>(), b.cast::<c_void>(), blen) } == 0
        {
            rv = 1;
        }
        if rv > 0 && !peername.is_null() {
            // SAFETY: `data` is `length` readable bytes.
            let dup = unsafe {
                CRYPTO_strndup(data.cast::<c_char>(), length as usize, FILE.as_ptr(), 841)
            };
            // SAFETY: `peername` is writable per the contract.
            unsafe { *peername = dup };
            if dup.is_null() {
                return -1;
            }
        }
    } else {
        let mut astr: *mut c_uchar = ptr::null_mut();
        // SAFETY: `a` is live; `astr` is a writable slot.
        let astrlen = unsafe { ASN1_STRING_to_UTF8(&raw mut astr, a) };
        if astrlen < 0 {
            return -1;
        }
        // SAFETY: `astr` is `astrlen` and `b` is `blen` readable bytes.
        rv = unsafe { equal(astr, astrlen as usize, b.cast::<c_uchar>(), blen, flags) };
        if rv > 0 && !peername.is_null() {
            // SAFETY: `astr` is `astrlen` readable bytes.
            let dup = unsafe {
                CRYPTO_strndup(astr.cast::<c_char>(), astrlen as usize, FILE.as_ptr(), 858)
            };
            // SAFETY: `peername` is writable per the contract.
            unsafe { *peername = dup };
            if dup.is_null() {
                // SAFETY: `astr` is this call's own.
                unsafe { CRYPTO_free(astr.cast::<c_void>(), FILE.as_ptr(), 860) };
                return -1;
            }
        }
        // SAFETY: `astr` is this call's own.
        unsafe { CRYPTO_free(astr.cast::<c_void>(), FILE.as_ptr(), 864) };
    }
    rv
}

/// `static int do_x509_check(X509 *x, const char *chk, size_t chklen, unsigned int flags,
/// int check_type, char **peername)` — `crypto/x509/v3_utl.c:869-1000`.
///
/// The shared engine behind the four public checks: scans the subjectAltName general names for
/// the requested type (an `otherName` `SmtpUTF8Mailbox` counts as an email under RFC 8398), then
/// falls back to the subject CN/emailAddress attributes unless a flag says otherwise. The
/// internal dot-subdomain flag is cleared on entry and re-derived for the DNS case only.
///
/// # Safety
///
/// `x` is live; `chk` is `chklen` readable bytes; `peername` is NULL or writable.
unsafe fn do_x509_check(
    x: *mut X509,
    chk: *const c_char,
    mut chklen: usize,
    mut flags: c_uint,
    check_type: c_int,
    peername: *mut *mut c_char,
) -> c_int {
    let mut cnid = NID_undef;
    let mut alt_type;
    let mut san_present = 0;
    let mut rv = 0;
    let equal: EqualFn;

    flags &= !_X509_CHECK_FLAG_DOT_SUBDOMAINS;
    if check_type == GEN_EMAIL {
        cnid = NID_pkcs9_emailAddress;
        alt_type = V_ASN1_IA5STRING;
        equal = equal_email;
    } else if check_type == GEN_DNS {
        cnid = NID_commonName;
        // SAFETY: `chk` is `chklen` readable bytes.
        if chklen > 1 && unsafe { *chk } == b'.' as c_char {
            flags |= _X509_CHECK_FLAG_DOT_SUBDOMAINS;
        }
        alt_type = V_ASN1_IA5STRING;
        if flags & X509_CHECK_FLAG_NO_WILDCARDS != 0 {
            equal = equal_nocase;
        } else {
            equal = equal_wildcard;
        }
    } else {
        alt_type = V_ASN1_OCTET_STRING;
        equal = equal_case;
    }

    if chklen == 0 {
        // SAFETY: `chk` is NULL or NUL-terminated per the contract.
        chklen = unsafe { strlen(chk) };
    }

    // SAFETY: `x` is live per the contract; `crit`/`idx` are NULL, which the decoder accepts.
    let gens =
        unsafe { X509_get_ext_d2i(x, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }
            .cast::<OpenSslStack>();
    if !gens.is_null() {
        // SAFETY: `gens` is live.
        let num = unsafe { OPENSSL_sk_num(gens) };
        for i in 0..num {
            // SAFETY: `gens` is live and `i` is within its count.
            let gen = unsafe { OPENSSL_sk_value(gens, i) }.cast::<GeneralName>();
            // SAFETY: `gen` is a live `GENERAL_NAME`.
            let cstr: *mut Asn1String;
            // SAFETY: `gen` is live; the selector chooses which union arm is live.
            match unsafe { (*gen).type_ } {
                GEN_OTHERNAME => {
                    // SAFETY: the `otherName` arm is live under the `GEN_OTHERNAME` selector.
                    let other = unsafe { (*gen).d.otherName };
                    // SAFETY: `other` is live.
                    let type_id = unsafe { (*other).type_id };
                    // SAFETY: `type_id` is a live object.
                    if unsafe { OBJ_obj2nid(type_id) } != NID_id_on_SmtpUTF8Mailbox {
                        continue;
                    }
                    // SAFETY: `other->value` is a live `ASN1_TYPE`.
                    let val = unsafe { (*other).value };
                    // SAFETY: `val` is live.
                    if check_type != GEN_EMAIL || unsafe { (*val).type_ } != V_ASN1_UTF8STRING {
                        continue;
                    }
                    alt_type = 0;
                    // SAFETY: `val` is live and the `utf8string` arm is live under the
                    // `V_ASN1_UTF8STRING` selector.
                    cstr = unsafe { (*val).value.ptr }.cast::<Asn1String>();
                }
                GEN_EMAIL => {
                    if check_type != GEN_EMAIL {
                        continue;
                    }
                    // SAFETY: the `rfc822Name` arm is live under the `GEN_EMAIL` selector.
                    cstr = unsafe { (*gen).d.ia5 };
                }
                GEN_DNS => {
                    if check_type != GEN_DNS {
                        continue;
                    }
                    // SAFETY: the `dNSName` arm is live under the `GEN_DNS` selector.
                    cstr = unsafe { (*gen).d.ia5 };
                }
                GEN_IPADD => {
                    if check_type != GEN_IPADD {
                        continue;
                    }
                    // SAFETY: the `iPAddress` arm is live under the `GEN_IPADD` selector.
                    cstr = unsafe { (*gen).d.iPAddress };
                }
                _ => continue,
            }
            san_present = 1;
            // SAFETY: `cstr` is a live `ASN1_STRING`; `chk` is `chklen` bytes.
            rv = unsafe { do_check_string(cstr, alt_type, equal, flags, chk, chklen, peername) };
            if rv != 0 {
                break;
            }
        }
        // SAFETY: `gens` is this call's own general-names stack.
        unsafe { GENERAL_NAMES_free(gens) };
        if rv != 0 {
            return rv;
        }
        if san_present != 0 && flags & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT == 0 {
            return 0;
        }
    }

    if cnid == NID_undef || flags & X509_CHECK_FLAG_NEVER_CHECK_SUBJECT != 0 {
        return 0;
    }

    let mut i: c_int = -1;
    // SAFETY: `x` is live.
    let name = unsafe { X509_get_subject_name(x) };
    loop {
        // SAFETY: `name` is live; the NID is a constant.
        i = unsafe { X509_NAME_get_index_by_NID(name, cnid, i) };
        if i < 0 {
            return 0;
        }
        // SAFETY: `i` is a valid entry index returned above.
        let ne = unsafe { X509_NAME_get_entry(name, i) };
        // SAFETY: `ne` is a live entry.
        let str_ = unsafe { X509_NAME_ENTRY_get_data(ne) };
        // SAFETY: `str_` is a live `ASN1_STRING`; `chk` is `chklen` bytes.
        rv = unsafe { do_check_string(str_, -1, equal, flags, chk, chklen, peername) };
        if rv != 0 {
            return rv;
        }
    }
}

/// `int X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags,
/// char **peername)` — `crypto/x509/v3_utl.c:1002-1019`.
///
/// # Safety
///
/// `x` is live; `chk` is `chklen` readable bytes; `peername` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_check_host(
    x: *mut X509,
    chk: *const c_char,
    mut chklen: usize,
    flags: c_uint,
    peername: *mut *mut c_char,
) -> c_int {
    if chk.is_null() {
        return -2;
    }
    // Embedded NULs are disallowed except as the last character of a length-2-or-more string.
    if chklen == 0 {
        // SAFETY: `chk` is NUL-terminated per the contract.
        chklen = unsafe { strlen(chk) };
    } else {
        let probe = if chklen > 1 { chklen - 1 } else { chklen };
        // SAFETY: `chk` is `chklen` readable bytes, so `probe <= chklen` are readable.
        if !unsafe { memchr(chk.cast::<c_void>(), 0, probe) }.is_null() {
            return -2;
        }
    }
    // SAFETY: `chk` is `chklen` readable bytes.
    if chklen > 1 && unsafe { *chk.add(chklen - 1) } == 0 {
        chklen -= 1;
    }
    // SAFETY: `x` is live; `chk` is `chklen` bytes.
    unsafe { do_x509_check(x, chk, chklen, flags, GEN_DNS, peername) }
}

/// `int X509_check_email(X509 *x, const char *chk, size_t chklen, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:1021-1038`.
///
/// # Safety
///
/// `x` is live; `chk` is `chklen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_check_email(
    x: *mut X509,
    chk: *const c_char,
    mut chklen: usize,
    flags: c_uint,
) -> c_int {
    if chk.is_null() {
        return -2;
    }
    if chklen == 0 {
        // SAFETY: `chk` is NUL-terminated per the contract.
        chklen = unsafe { strlen(chk) };
    } else {
        let probe = if chklen > 1 { chklen - 1 } else { chklen };
        // SAFETY: `chk` is `chklen` readable bytes, so `probe <= chklen` are readable.
        if !unsafe { memchr(chk.cast::<c_void>(), 0, probe) }.is_null() {
            return -2;
        }
    }
    // SAFETY: `chk` is `chklen` readable bytes.
    if chklen > 1 && unsafe { *chk.add(chklen - 1) } == 0 {
        chklen -= 1;
    }
    // SAFETY: `x` is live; `chk` is `chklen` bytes.
    unsafe { do_x509_check(x, chk, chklen, flags, GEN_EMAIL, ptr::null_mut()) }
}

/// `int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
/// unsigned int flags)` — `crypto/x509/v3_utl.c:1040-1046`.
///
/// # Safety
///
/// `x` is live; `chk` is `chklen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_check_ip(
    x: *mut X509,
    chk: *const c_uchar,
    chklen: usize,
    flags: c_uint,
) -> c_int {
    if chk.is_null() {
        return -2;
    }
    // SAFETY: `x` is live; `chk` is `chklen` bytes and is read as bytes.
    unsafe {
        do_x509_check(
            x,
            chk.cast::<c_char>(),
            chklen,
            flags,
            GEN_IPADD,
            ptr::null_mut(),
        )
    }
}

/// `int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags)` —
/// `crypto/x509/v3_utl.c:1048-1059`.
///
/// # Safety
///
/// `x` is live; `ipasc` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_check_ip_asc(
    x: *mut X509,
    ipasc: *const c_char,
    flags: c_uint,
) -> c_int {
    let mut ipout = [0 as c_uchar; 16];
    if ipasc.is_null() {
        return -2;
    }
    // SAFETY: `ipout` is 16 writable bytes; `ipasc` is NUL-terminated.
    let iplen = unsafe { ossl_a2i_ipadd(ipout.as_mut_ptr(), ipasc) };
    if iplen == 0 {
        return -2;
    }
    // SAFETY: `x` is live; `ipout` is `iplen <= 16` readable bytes.
    unsafe {
        do_x509_check(
            x,
            ipout.as_ptr().cast::<c_char>(),
            iplen as usize,
            flags,
            GEN_IPADD,
            ptr::null_mut(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `X509V3_parse_list` over the four shapes the state machine distinguishes and read
    /// the resulting `CONF_VALUE` pairs back out.
    #[test]
    fn parse_list_handles_the_four_entry_shapes() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every input is a static NUL-terminated literal; the returned stack is walked
        // with the stack layer's own accessors and then freed with its owning pop-free.
        unsafe {
            let sk = X509V3_parse_list(c"a:b, c : d ,e".as_ptr());
            assert!(!sk.is_null(), "a well-formed list parses");
            let n = OPENSSL_sk_num(sk);
            assert_eq!(n, 3, "three entries");
            let first = OPENSSL_sk_value(sk, 0).cast::<ConfValue>();
            assert_eq!(CStr::from_ptr((*first).name), c"a");
            assert_eq!(CStr::from_ptr((*first).value), c"b");
            let third = OPENSSL_sk_value(sk, 2).cast::<ConfValue>();
            assert_eq!(CStr::from_ptr((*third).name), c"e");
            assert!((*third).value.is_null(), "a bare name has a NULL value");
            OPENSSL_sk_pop_free(sk, Some(conf_value_free_thunk));
        }

        // SAFETY: a static NUL-terminated literal.
        unsafe {
            let bad = X509V3_parse_list(c":empty-name".as_ptr());
            assert!(bad.is_null(), "an empty name is refused");
            // SAFETY: no live error is required to pop; the queue is drained to leave it clean.
            crate::runtime::err::ERR_clear_error();
        }
    }

    /// `s2i_ASN1_INTEGER` strips the sign and the radix prefix in the authority's order, and a
    /// consumption failure is refused with its coordinate.
    #[test]
    fn integer_string_round_trips_and_refuses_trailing_input() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: static NUL-terminated literals; the returned integer is this call's own.
        unsafe {
            let a = s2i_ASN1_INTEGER(ptr::null_mut(), c"-0x10".as_ptr());
            assert!(!a.is_null());
            assert!((*a).type_ & V_ASN1_NEG != 0, "the sign survives");
            let shown = i2s_ASN1_INTEGER(ptr::null_mut(), a);
            assert_eq!(CStr::from_ptr(shown), c"-16", "hex is read, sign preserved");
            CRYPTO_free(shown.cast::<c_void>(), FILE.as_ptr(), 0);
            ASN1_OCTET_STRING_free(a);

            let bad = s2i_ASN1_INTEGER(ptr::null_mut(), c"12x".as_ptr());
            assert!(bad.is_null(), "leftover input is refused");
            // SAFETY: the queue is drained to leave it clean.
            crate::runtime::err::ERR_clear_error();
        }
    }

    /// `ossl_ipaddr_to_asc`'s three arms, including the invalid-length literal.
    #[test]
    fn ipaddr_to_asc_spells_v4_v6_and_invalid() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: static buffers of the advertised lengths; the results are this call's own
        // strings, freed here.
        unsafe {
            let mut v4 = [192u8, 0, 2, 1];
            let s = ossl_ipaddr_to_asc(v4.as_mut_ptr(), 4);
            assert_eq!(CStr::from_ptr(s), c"192.0.2.1");
            CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), 0);

            let mut v6 = [0u8; 16];
            v6[15] = 1;
            let s6 = ossl_ipaddr_to_asc(v6.as_mut_ptr(), 16);
            assert_eq!(CStr::from_ptr(s6), c"0:0:0:0:0:0:0:1");
            CRYPTO_free(s6.cast::<c_void>(), FILE.as_ptr(), 0);

            let sbad = ossl_ipaddr_to_asc(v4.as_mut_ptr(), 5);
            assert_eq!(CStr::from_ptr(sbad), c"<invalid length=5>");
            CRYPTO_free(sbad.cast::<c_void>(), FILE.as_ptr(), 0);
        }
    }
}
