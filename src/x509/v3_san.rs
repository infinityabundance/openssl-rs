//! `crypto/x509/v3_san.c` — the general-name printers and the `v2i` cluster. Phase 10.14.6,
//! **partial at function granularity**.
//!
//! `crypto/x509/v3_san.c` is 689 lines. The previous slice landed the **printers**
//! (`GENERAL_NAME_print` `:207-299`, `i2v_GENERAL_NAME` `:79-205`, `i2v_GENERAL_NAMES` `:51-77`).
//! This slice lands the `v2i` half that `ASN1_generate_v3` was the one blocker of: `do_othername`
//! (`:631-662`) and `do_dirname` (`:664-689`), the exported builders `a2i_GENERAL_NAME`
//! (`:503-590`), `v2i_GENERAL_NAME_ex` (`:592-629`), `v2i_GENERAL_NAME` (`:497-501`) and
//! `v2i_GENERAL_NAMES` (`:470-495`), plus the `GENERAL_NAME_free` thunk the stack pop uses.
//!
//! ## What is still withheld, and each name's blocker
//!
//! Four names stay withheld **by name**: `v2i_subject_alt` (`:377-413`) and `copy_email`
//! (`:419-468`) need `X509_REQ_get_subject_name` (`x509_req.c`, 10.14.11) and the now-landed
//! `v2i_GENERAL_NAME`; `v2i_issuer_alt` (`:301-332`) and `copy_issuer` (`:336-375`) need the
//! withheld dispatch `X509V3_EXT_d2i` (`v3_lib.rs`). `ossl_v3_alt` (`:29-49`) is the unit's one
//! table; two of its three rows name `v2i_subject_alt`/`v2i_issuer_alt`, so the table is withheld
//! with them rather than published with holes -- a `prerequisites.json` divergence row.
//!
//! ## Why the `v2i` cluster alone is worth landing
//!
//! `v2i_GENERAL_NAME`/`v2i_GENERAL_NAME_ex`/`v2i_GENERAL_NAMES` are the blockers D465 measured
//! for `v3_crld.c` and `v3_info.c`, so landing them turns those two table units closure-ready.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_san.c` is not in `gen_err_raise_sites.py`'s covered set, so its coordinates are
//! declared locally (see `v3_conf.rs`'s note). Every landed `ERR_raise*` is now reachable through
//! the `v2i` builders, so most of the declared constants are live.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
// The crate's NID constants keep the authority's own macro spelling (`NID_XmppAddr`, ...), so a
// pattern match on them trips the upper-case lint; the same allow is used by `src/x509/x509type.rs`.
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_ulong, c_void, CStr};

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::asn1::a_type::ASN1_TYPE_free;
use crate::asn1::asn1_gen::ASN1_generate_v3;
use crate::asn1::layout::{Asn1String, MBSTRING_ASC, V_ASN1_IA5STRING, V_ASN1_UTF8STRING};
use crate::asn1::string::{ASN1_IA5STRING_free, ASN1_IA5STRING_new, ASN1_STRING_set};
use crate::asn1::text::{i2a_ASN1_OBJECT, i2t_ASN1_OBJECT};
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::sys::{strchr, strlen};
use crate::runtime::bio::Bio;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strndup};
use crate::runtime::obj::{
    NID_NAIRealm, NID_SRVName, NID_XmppAddr, NID_id_on_SmtpUTF8Mailbox, NID_ms_upn, OBJ_obj2nid,
    OBJ_obj2txt, OBJ_txt2obj,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strlcpy;
use crate::x509::v3_conf::{X509V3Ctx, X509V3_get_section, X509V3_section_free};
use crate::x509::v3_genn::{
    GENERAL_NAME_free, GENERAL_NAME_new, GeneralName, OTHERNAME_free, OTHERNAME_new, GEN_DIRNAME,
    GEN_DNS, GEN_EDIPARTY, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME, GEN_RID, GEN_URI, GEN_X400,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{
    a2i_IPADDRESS, a2i_IPADDRESS_NC, ossl_ipaddr_to_asc, ossl_v3_name_cmp,
    x509v3_add_len_value_uchar, X509V3_NAME_from_section, X509V3_add_value,
};
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};

/// The authority file path this module's raises name.
const FILE: &CStr = c"crypto/x509/v3_san.c";

/// One `v3_san.c` raise coordinate, declared locally (see the module doc). The reason values are
/// read from `include/openssl/x509v3err.h` and the two `ERR_R_*` codes; the reachable ones are
/// pinned by the `RT-STORE` refusal arms.
const fn v3_san_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_san.c",
        line,
        func,
        lib: 34,
        reason,
        dynamic_reason: false,
    }
}

/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `X509V3_R_MISSING_VALUE` — `include/openssl/x509v3err.h:66`.
const X509V3_R_MISSING_VALUE: c_int = 124;
/// `X509V3_R_BAD_OBJECT` — `include/openssl/x509v3err.h:23`.
const X509V3_R_BAD_OBJECT: c_int = 119;
/// `X509V3_R_BAD_IP_ADDRESS` — `include/openssl/x509v3err.h:22`.
const X509V3_R_BAD_IP_ADDRESS: c_int = 118;
/// `X509V3_R_DIRNAME_ERROR` — `include/openssl/x509v3err.h:28`.
const X509V3_R_DIRNAME_ERROR: c_int = 149;
/// `X509V3_R_OTHERNAME_ERROR` — `include/openssl/x509v3err.h:77`.
const X509V3_R_OTHERNAME_ERROR: c_int = 147;
/// `X509V3_R_UNSUPPORTED_TYPE` — `include/openssl/x509v3err.h:92`.
const X509V3_R_UNSUPPORTED_TYPE: c_int = 167;
/// `X509V3_R_UNSUPPORTED_OPTION` — `include/openssl/x509v3err.h:91`.
const X509V3_R_UNSUPPORTED_OPTION: c_int = 117;
/// `X509V3_R_SECTION_NOT_FOUND` — `include/openssl/x509v3err.h:83`.
const X509V3_R_SECTION_NOT_FOUND: c_int = 150;
/// `X509V3_R_NO_SUBJECT_DETAILS` — `include/openssl/x509v3err.h:75`.
const X509V3_R_NO_SUBJECT_DETAILS: c_int = 125;
/// `X509V3_R_NO_ISSUER_DETAILS` — `include/openssl/x509v3err.h:71`.
const X509V3_R_NO_ISSUER_DETAILS: c_int = 127;
/// `X509V3_R_ISSUER_DECODE_ERROR` — `include/openssl/x509v3err.h:65`.
const X509V3_R_ISSUER_DECODE_ERROR: c_int = 126;

#[allow(dead_code)]
const V3_SAN_310: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(310, c"v2i_issuer_alt", ERR_R_CRYPTO_LIB);
#[allow(dead_code)]
const V3_SAN_388: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(388, c"v2i_subject_alt", ERR_R_CRYPTO_LIB);
#[allow(dead_code)]
const V3_SAN_481: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(481, c"v2i_GENERAL_NAMES", ERR_R_CRYPTO_LIB);
#[allow(dead_code)]
const V3_SAN_431: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(431, c"copy_email", X509V3_R_NO_SUBJECT_DETAILS);
#[allow(dead_code)]
const V3_SAN_449: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(449, c"copy_email", ERR_R_ASN1_LIB);
#[allow(dead_code)]
const V3_SAN_456: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(456, c"copy_email", ERR_R_CRYPTO_LIB);
#[allow(dead_code)]
const V3_SAN_346: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(346, c"copy_issuer", X509V3_R_NO_ISSUER_DETAILS);
#[allow(dead_code)]
const V3_SAN_354: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(354, c"copy_issuer", X509V3_R_ISSUER_DECODE_ERROR);
#[allow(dead_code)]
const V3_SAN_360: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(360, c"copy_issuer", ERR_R_CRYPTO_LIB);
const V3_SAN_512: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(512, c"a2i_GENERAL_NAME", X509V3_R_MISSING_VALUE);
#[allow(dead_code)]
const V3_SAN_521: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(521, c"a2i_GENERAL_NAME", ERR_R_ASN1_LIB);
const V3_SAN_536: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(536, c"a2i_GENERAL_NAME", X509V3_R_BAD_OBJECT);
const V3_SAN_549: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(549, c"a2i_GENERAL_NAME", X509V3_R_BAD_IP_ADDRESS);
const V3_SAN_557: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(557, c"a2i_GENERAL_NAME", X509V3_R_DIRNAME_ERROR);
const V3_SAN_564: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(564, c"a2i_GENERAL_NAME", X509V3_R_OTHERNAME_ERROR);
const V3_SAN_569: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(569, c"a2i_GENERAL_NAME", X509V3_R_UNSUPPORTED_TYPE);
#[allow(dead_code)]
const V3_SAN_577: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(577, c"a2i_GENERAL_NAME", ERR_R_ASN1_LIB);
const V3_SAN_604: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(604, c"v2i_GENERAL_NAME_ex", X509V3_R_MISSING_VALUE);
const V3_SAN_623: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(623, c"v2i_GENERAL_NAME_ex", X509V3_R_UNSUPPORTED_OPTION);
const V3_SAN_674: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(674, c"do_dirname", X509V3_R_SECTION_NOT_FOUND);

/// Read a general name's `type` selector.
///
/// # Safety
///
/// `gen` must be a live `GENERAL_NAME`.
unsafe fn gen_type(gen: *mut GeneralName) -> c_int {
    // SAFETY: `gen` is live per the contract.
    unsafe { (*gen).type_ }
}

/// Read the `otherName` arm.
///
/// # Safety
/// `gen` must be live and its `type` must be `GEN_OTHERNAME`.
unsafe fn gen_othername(gen: *mut GeneralName) -> *mut crate::x509::v3_genn::Othername {
    // SAFETY: the caller's contract selects the live `otherName` union member.
    unsafe { (*gen).d.otherName }
}

/// Read the `ia5` arm (RFC822/DNS/URI).
///
/// # Safety
/// `gen` must be live and its `type` must select one of the three IA5 general names.
unsafe fn gen_ia5(gen: *mut GeneralName) -> *mut Asn1String {
    // SAFETY: the caller's contract selects the live `ia5` union member.
    unsafe { (*gen).d.ia5 }
}

/// Read the `directoryName` arm.
///
/// # Safety
/// `gen` must be live and its `type` must be `GEN_DIRNAME`.
unsafe fn gen_dirname(gen: *mut GeneralName) -> *mut crate::x509::x_name::X509Name {
    // SAFETY: the caller's contract selects the live `directoryName` union member.
    unsafe { (*gen).d.directoryName }
}

/// Read the `iPAddress` arm.
///
/// # Safety
/// `gen` must be live and its `type` must be `GEN_IPADD`.
unsafe fn gen_ip(gen: *mut GeneralName) -> *mut Asn1String {
    // SAFETY: the caller's contract selects the live `iPAddress` union member.
    unsafe { (*gen).d.iPAddress }
}

/// Read the `registeredID` arm.
///
/// # Safety
/// `gen` must be live and its `type` must be `GEN_RID`.
unsafe fn gen_rid(gen: *mut GeneralName) -> *mut crate::runtime::obj::Asn1Object {
    // SAFETY: the caller's contract selects the live `registeredID` union member.
    unsafe { (*gen).d.registeredID }
}

/// Read the `ASN1_TYPE` arm of an `OTHERNAME`'s optional value.
///
/// # Safety
/// `on` must be a live `OTHERNAME`.
unsafe fn othername_value(
    on: *mut crate::x509::v3_genn::Othername,
) -> *mut crate::asn1::layout::Asn1Type {
    // SAFETY: `on` is live per the contract.
    unsafe { (*on).value }
}

/// Read an `ASN1_TYPE`'s `type` tag.
///
/// # Safety
/// `v` must be a live `ASN1_TYPE`.
unsafe fn asn1_type_tag(v: *mut crate::asn1::layout::Asn1Type) -> c_int {
    // SAFETY: `v` is live per the contract.
    unsafe { (*v).type_ }
}

/// Read the `utf8string`/`ia5string` arm of an `ASN1_TYPE` (the same union slot).
///
/// # Safety
/// `v` must be live and its tag must select a string-valued union member.
unsafe fn asn1_type_string(v: *mut crate::asn1::layout::Asn1Type) -> *mut Asn1String {
    // SAFETY: the caller's contract selects the live string union member.
    unsafe { (*v).value.ptr.cast::<Asn1String>() }
}

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(ret, X509V3_conf_free)` installs.
///
/// # Safety
///
/// `p` must be NULL or a live `CONF_VALUE`.
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the stack contract.
    unsafe { crate::x509::v3_utl::X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method, GENERAL_NAMES *gens,
/// STACK_OF(CONF_VALUE) *ret)` — `crypto/x509/v3_san.c:51-77`.
///
/// # Safety
///
/// `method` may be NULL; `gens` must be a live `GENERAL_NAMES`; `ret` is NULL or a stack of this
/// call's own `CONF_VALUE`s.
#[no_mangle]
pub unsafe extern "C" fn i2v_GENERAL_NAMES(
    method: *mut X509V3ExtMethod,
    gens: *mut OpenSslStack,
    ret: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let origret = ret;
    let mut ret = ret;
    // SAFETY: `gens` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(gens) };
    for i in 0..num {
        // SAFETY: `gens` is live and `i` is within its count.
        let gen = unsafe { OPENSSL_sk_value(gens, i) }.cast::<GeneralName>();
        // SAFETY: `method` is NULL-or-live, `gen` is a live element, and `ret` is this call's own.
        let tmpret = unsafe { i2v_GENERAL_NAME(method, gen, ret) };
        if tmpret.is_null() {
            /* Only free the stack if it was empty when this function was entered. */
            if origret.is_null() {
                // SAFETY: `ret` is this call's own stack; the thunk frees `CONF_VALUE`s.
                unsafe { OPENSSL_sk_pop_free(ret, Some(conf_value_free_thunk)) };
            }
            return core::ptr::null_mut();
        }
        ret = tmpret;
    }
    if ret.is_null() {
        OPENSSL_sk_new_null()
    } else {
        ret
    }
}

/// `STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method, GENERAL_NAME *gen,
/// STACK_OF(CONF_VALUE) *ret)` — `crypto/x509/v3_san.c:79-205`.
///
/// # Safety
///
/// `method` may be NULL; `gen` must be a live `GENERAL_NAME`; `ret` is NULL or a stack of this
/// call's own `CONF_VALUE`s.
#[no_mangle]
pub unsafe extern "C" fn i2v_GENERAL_NAME(
    _method: *mut X509V3ExtMethod,
    gen: *mut GeneralName,
    ret: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut othername = [0 as c_char; 300];
    let mut oline = [0 as c_char; 256];
    let mut ret = ret;

    // SAFETY: `gen` is live per the contract.
    let type_ = unsafe { gen_type(gen) };
    match type_ {
        GEN_OTHERNAME => {
            // SAFETY: the `otherName` arm is selected by `type_`.
            let on = unsafe { gen_othername(gen) };
            // SAFETY: `on` is live; its `type_id` is live.
            let nid = unsafe { OBJ_obj2nid((*on).type_id) };
            // SAFETY: `on` is live.
            let v = unsafe { othername_value(on) };
            // SAFETY: `v` is live; its tag is the same for every arm below.
            let vtag = unsafe { asn1_type_tag(v) };
            let mut add = |name: &'static CStr, s: *mut Asn1String| -> c_int {
                // SAFETY: `s` is live and its content is readable for `length` bytes; `ret` is this
                // call's own sink.
                unsafe {
                    x509v3_add_len_value_uchar(
                        name.as_ptr(),
                        (*s).data,
                        (*s).length as usize,
                        &mut ret,
                    )
                }
            };
            match nid {
                NID_id_on_SmtpUTF8Mailbox => {
                    if vtag != V_ASN1_UTF8STRING {
                        return core::ptr::null_mut();
                    }
                    // SAFETY: the guard above selects `v`'s utf8 arm.
                    if add(c"othername: SmtpUTF8Mailbox", unsafe {
                        asn1_type_string(v)
                    }) == 0
                    {
                        return core::ptr::null_mut();
                    }
                }
                NID_XmppAddr => {
                    if vtag != V_ASN1_UTF8STRING {
                        return core::ptr::null_mut();
                    }
                    // SAFETY: the guard above selects `v`'s utf8 arm.
                    if add(c"othername: XmppAddr", unsafe { asn1_type_string(v) }) == 0 {
                        return core::ptr::null_mut();
                    }
                }
                NID_SRVName => {
                    if vtag != V_ASN1_IA5STRING {
                        return core::ptr::null_mut();
                    }
                    // SAFETY: the guard above selects `v`'s ia5 arm (the same union slot).
                    if add(c"othername: SRVName", unsafe { asn1_type_string(v) }) == 0 {
                        return core::ptr::null_mut();
                    }
                }
                NID_ms_upn => {
                    if vtag != V_ASN1_UTF8STRING {
                        return core::ptr::null_mut();
                    }
                    // SAFETY: the guard above selects `v`'s utf8 arm.
                    if add(c"othername: UPN", unsafe { asn1_type_string(v) }) == 0 {
                        return core::ptr::null_mut();
                    }
                }
                NID_NAIRealm => {
                    if vtag != V_ASN1_UTF8STRING {
                        return core::ptr::null_mut();
                    }
                    // SAFETY: the guard above selects `v`'s utf8 arm.
                    if add(c"othername: NAIRealm", unsafe { asn1_type_string(v) }) == 0 {
                        return core::ptr::null_mut();
                    }
                }
                _ => {
                    // SAFETY: `on` is live; `oline` is 256 writable bytes.
                    let n = unsafe {
                        OBJ_obj2txt(oline.as_mut_ptr(), oline.len() as c_int, (*on).type_id, 0)
                    };
                    if n > 0 {
                        // SAFETY: `oline` is NUL-terminated; `othername` is 300 writable bytes.
                        unsafe {
                            BIO_snprintf(
                                othername.as_mut_ptr(),
                                othername.len(),
                                c"othername: %s".as_ptr(),
                                oline.as_ptr(),
                            )
                        };
                    } else {
                        // SAFETY: `othername` is 300 writable bytes and the literal is static.
                        unsafe {
                            OPENSSL_strlcpy(
                                othername.as_mut_ptr(),
                                c"othername".as_ptr(),
                                othername.len(),
                            )
                        };
                    }
                    // SAFETY: `v` is live.
                    let vtype = unsafe { asn1_type_tag(v) };
                    if vtype == V_ASN1_IA5STRING {
                        // SAFETY: the tag selects `v`'s ia5 arm.
                        let s = unsafe { asn1_type_string(v) };
                        // SAFETY: `s` is live; `othername` is NUL-terminated; `ret` is this call's.
                        if unsafe {
                            x509v3_add_len_value_uchar(
                                othername.as_ptr(),
                                (*s).data,
                                (*s).length as usize,
                                &mut ret,
                            )
                        } != 0
                        {
                            return ret;
                        }
                    }
                    if vtype == V_ASN1_UTF8STRING {
                        // SAFETY: the tag selects `v`'s utf8 arm.
                        let s = unsafe { asn1_type_string(v) };
                        // SAFETY: `s` is live; `othername` is NUL-terminated; `ret` is this call's.
                        if unsafe {
                            x509v3_add_len_value_uchar(
                                othername.as_ptr(),
                                (*s).data,
                                (*s).length as usize,
                                &mut ret,
                            )
                        } != 0
                        {
                            return ret;
                        }
                    }
                    // SAFETY: `othername` is NUL-terminated; `ret` is this call's own sink.
                    if unsafe {
                        X509V3_add_value(othername.as_ptr(), c"<unsupported>".as_ptr(), &mut ret)
                    } == 0
                    {
                        return core::ptr::null_mut();
                    }
                }
            }
        }
        GEN_X400 => {
            // SAFETY: the literals are static; `ret` is this call's own sink.
            if unsafe {
                X509V3_add_value(c"X400Name".as_ptr(), c"<unsupported>".as_ptr(), &mut ret)
            } == 0
            {
                return core::ptr::null_mut();
            }
        }
        GEN_EDIPARTY => {
            // SAFETY: the literals are static; `ret` is this call's own sink.
            if unsafe {
                X509V3_add_value(
                    c"EdiPartyName".as_ptr(),
                    c"<unsupported>".as_ptr(),
                    &mut ret,
                )
            } == 0
            {
                return core::ptr::null_mut();
            }
        }
        GEN_EMAIL => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `s` is live; `ret` is this call's own sink.
            if unsafe {
                x509v3_add_len_value_uchar(
                    c"email".as_ptr(),
                    (*s).data,
                    (*s).length as usize,
                    &mut ret,
                )
            } == 0
            {
                return core::ptr::null_mut();
            }
        }
        GEN_DNS => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `s` is live; `ret` is this call's own sink.
            if unsafe {
                x509v3_add_len_value_uchar(
                    c"DNS".as_ptr(),
                    (*s).data,
                    (*s).length as usize,
                    &mut ret,
                )
            } == 0
            {
                return core::ptr::null_mut();
            }
        }
        GEN_URI => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `s` is live; `ret` is this call's own sink.
            if unsafe {
                x509v3_add_len_value_uchar(
                    c"URI".as_ptr(),
                    (*s).data,
                    (*s).length as usize,
                    &mut ret,
                )
            } == 0
            {
                return core::ptr::null_mut();
            }
        }
        GEN_DIRNAME => {
            // SAFETY: the tag selects the `directoryName` arm.
            let dn = unsafe { gen_dirname(gen) };
            let mut ok = false;
            // SAFETY: `dn` is live and `oline` is 256 writable bytes.
            if !unsafe { X509_NAME_oneline(dn, oline.as_mut_ptr(), oline.len() as c_int) }.is_null()
            {
                // SAFETY: `oline` is NUL-terminated; `ret` is this call's own sink.
                ok =
                    unsafe { X509V3_add_value(c"DirName".as_ptr(), oline.as_ptr(), &mut ret) } != 0;
            }
            if !ok {
                return core::ptr::null_mut();
            }
        }
        GEN_IPADD => {
            // SAFETY: the tag selects the `iPAddress` arm.
            let ip = unsafe { gen_ip(gen) };
            // SAFETY: `ip` is live and its content is readable for `length` bytes.
            let tmp = unsafe { ossl_ipaddr_to_asc((*ip).data, (*ip).length) };
            if tmp.is_null() {
                ret = core::ptr::null_mut();
            } else {
                // SAFETY: `tmp` is NUL-terminated; `ret` is this call's own sink.
                let added = unsafe { X509V3_add_value(c"IP Address".as_ptr(), tmp, &mut ret) };
                // SAFETY: `tmp` is this call's own allocation (the authority frees it regardless).
                unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 195) };
                if added == 0 {
                    ret = core::ptr::null_mut();
                }
            }
        }
        GEN_RID => {
            // SAFETY: the tag selects the `registeredID` arm.
            let rid = unsafe { gen_rid(gen) };
            // SAFETY: `oline` is 256 writable bytes and `rid` is live.
            unsafe { i2t_ASN1_OBJECT(oline.as_mut_ptr(), 256, rid) };
            // SAFETY: `oline` is NUL-terminated; `ret` is this call's own sink.
            if unsafe { X509V3_add_value(c"Registered ID".as_ptr(), oline.as_ptr(), &mut ret) } == 0
            {
                return core::ptr::null_mut();
            }
        }
        _ => {}
    }
    ret
}

/// `int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen)` — `crypto/x509/v3_san.c:207-299`.
///
/// # Safety
///
/// `out` must be a live BIO; `gen` must be a live `GENERAL_NAME`.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_print(out: *mut Bio, gen: *mut GeneralName) -> c_int {
    // The `%.*s` printer every othername arm shares; the format's precision bounds the read of `s`
    // even when its content is not NUL-terminated.
    let print_othername = |fmt: &'static CStr, s: *mut Asn1String| {
        // SAFETY: `out` is a live BIO and `fmt` is a static literal; `s` is live and its content is
        // bounded by `%.*s`'s precision.
        unsafe { BIO_printf(out, fmt.as_ptr(), (*s).length, (*s).data.cast::<c_char>()) }
    };

    // SAFETY: `gen` is live per the contract.
    let type_ = unsafe { gen_type(gen) };
    match type_ {
        GEN_OTHERNAME => {
            // SAFETY: the `otherName` arm is selected by `type_`.
            let on = unsafe { gen_othername(gen) };
            // SAFETY: `on` is live; its `type_id` is live.
            let nid = unsafe { OBJ_obj2nid((*on).type_id) };
            // SAFETY: `on` is live.
            let v = unsafe { othername_value(on) };
            // SAFETY: `v` is live.
            let vtype = unsafe { asn1_type_tag(v) };
            if (nid == NID_SRVName && vtype != V_ASN1_IA5STRING)
                || (nid != NID_SRVName && vtype != V_ASN1_UTF8STRING)
            {
                // SAFETY: `out` is a live BIO and the literal is static.
                unsafe { BIO_printf(out, c"othername:<unsupported>".as_ptr()) };
            } else {
                match nid {
                    NID_id_on_SmtpUTF8Mailbox => {
                        // SAFETY: the guard above selects `v`'s utf8 arm.
                        print_othername(c"othername:SmtpUTF8Mailbox:%.*s", unsafe {
                            asn1_type_string(v)
                        });
                    }
                    NID_XmppAddr => {
                        // SAFETY: the guard above selects `v`'s utf8 arm.
                        print_othername(c"othername:XmppAddr:%.*s", unsafe { asn1_type_string(v) });
                    }
                    NID_SRVName => {
                        // SAFETY: the guard above selects `v`'s ia5 arm.
                        print_othername(c"othername:SRVName:%.*s", unsafe { asn1_type_string(v) });
                    }
                    NID_ms_upn => {
                        // SAFETY: the guard above selects `v`'s utf8 arm.
                        print_othername(c"othername:UPN:%.*s", unsafe { asn1_type_string(v) });
                    }
                    NID_NAIRealm => {
                        // SAFETY: the guard above selects `v`'s utf8 arm.
                        print_othername(c"othername:NAIRealm:%.*s", unsafe { asn1_type_string(v) });
                    }
                    _ => {
                        // SAFETY: `out` is a live BIO and the literal is static.
                        unsafe { BIO_printf(out, c"othername:<unsupported>".as_ptr()) };
                    }
                }
            }
        }
        GEN_X400 => {
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"X400Name:<unsupported>".as_ptr()) };
        }
        GEN_EDIPARTY => {
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"EdiPartyName:<unsupported>".as_ptr()) };
        }
        GEN_EMAIL => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"email:".as_ptr()) };
            // SAFETY: `out` is live and `s` is a live string.
            unsafe { ASN1_STRING_print(out, s) };
        }
        GEN_DNS => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"DNS:".as_ptr()) };
            // SAFETY: `out` is live and `s` is a live string.
            unsafe { ASN1_STRING_print(out, s) };
        }
        GEN_URI => {
            // SAFETY: the tag selects the ia5 arm.
            let s = unsafe { gen_ia5(gen) };
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"URI:".as_ptr()) };
            // SAFETY: `out` is live and `s` is a live string.
            unsafe { ASN1_STRING_print(out, s) };
        }
        GEN_DIRNAME => {
            // SAFETY: the tag selects the `directoryName` arm.
            let dn = unsafe { gen_dirname(gen) };
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"DirName:".as_ptr()) };
            // SAFETY: `dn` is live and `out` is live.
            unsafe { X509_NAME_print_ex(out, dn, 0, XN_FLAG_ONELINE) };
        }
        GEN_IPADD => {
            // SAFETY: the tag selects the `iPAddress` arm.
            let ip = unsafe { gen_ip(gen) };
            // SAFETY: `ip` is live and its content is readable for `length` bytes.
            let tmp = unsafe { ossl_ipaddr_to_asc((*ip).data, (*ip).length) };
            if tmp.is_null() {
                return 0;
            }
            // SAFETY: `tmp` is NUL-terminated; `out` is live.
            unsafe { BIO_printf(out, c"IP Address:%s".as_ptr(), tmp) };
            // SAFETY: `tmp` is this call's own allocation.
            unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 290) };
        }
        GEN_RID => {
            // SAFETY: the tag selects the `registeredID` arm.
            let rid = unsafe { gen_rid(gen) };
            // SAFETY: `out` is a live BIO and the literal is static.
            unsafe { BIO_printf(out, c"Registered ID:".as_ptr()) };
            // SAFETY: `out` is live and `rid` is a live object.
            unsafe { i2a_ASN1_OBJECT(out, rid) };
        }
        _ => {}
    }
    1
}

/// Append the bytes of a NUL-terminated C string to a buffer (a `%s` operand).
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

/// The `void (*)(void *)` thunk `sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free)` installs.
///
/// # Safety
///
/// `p` must be NULL or a live `GENERAL_NAME`.
unsafe extern "C" fn general_name_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `GENERAL_NAME` pointers per the stack contract.
    unsafe { GENERAL_NAME_free(p.cast::<GeneralName>()) };
}

/// `static int do_othername(GENERAL_NAME *gen, const char *value, X509V3_CTX *ctx)` —
/// `crypto/x509/v3_san.c:631-662`.
///
/// Splits `value` at its `;` into an OID and an `ASN1_generate_v3` operand, and installs both on
/// the name's `otherName` arm. The one call is what made this whole cluster wait on Phase 5's
/// deferred pair (D465).
///
/// # Safety
///
/// `gen` must be live; `value` must be NUL-terminated; `ctx` is NULL or a live `X509V3_CTX`.
unsafe fn do_othername(gen: *mut GeneralName, value: *const c_char, ctx: *mut X509V3Ctx) -> c_int {
    // SAFETY: `value` is NUL-terminated per the contract.
    let p = unsafe { strchr(value, b';' as c_int) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: the item allocator answers NULL or a live value.
    let on = OTHERNAME_new();
    if on.is_null() {
        return 0;
    }
    // SAFETY: `gen` is live; ownership of `on` passes to the union.
    unsafe { (*gen).d.otherName = on };
    // SAFETY: `on` is live; the fresh item's optional value is released before it is
    // overwritten, as the authority does.
    unsafe { ASN1_TYPE_free((*on).value) };
    // SAFETY: `p + 1` is the operand after the `;`; `ctx` is NULL or live.
    let v = unsafe { ASN1_generate_v3(p.add(1), ctx) };
    // SAFETY: `on` is live; the assignment happens before the failure test so the
    // release path below cannot double-free the old value.
    unsafe { (*on).value = v };
    if v.is_null() {
        // SAFETY: `gen`/`on` are live per this function's contract.
        unsafe { othername_err(gen, on) };
        return 0;
    }
    let objlen = (p as usize).wrapping_sub(value as usize);
    // SAFETY: `value` is NUL-terminated and `objlen <= strlen(value)`.
    let objtmp = unsafe { CRYPTO_strndup(value, objlen, FILE.as_ptr(), 649) };
    if objtmp.is_null() {
        // SAFETY: `gen`/`on` are live per this function's contract.
        unsafe { othername_err(gen, on) };
        return 0;
    }
    // SAFETY: `objtmp` is NUL-terminated.
    let type_id = unsafe { OBJ_txt2obj(objtmp, 0) };
    // SAFETY: `objtmp` is this call's own allocation.
    unsafe { CRYPTO_free(objtmp.cast::<c_void>(), FILE.as_ptr(), 653) };
    // SAFETY: `on` is live.
    unsafe { (*on).type_id = type_id };
    if type_id.is_null() {
        // SAFETY: `gen`/`on` are live per this function's contract.
        unsafe { othername_err(gen, on) };
        return 0;
    }
    1
}

/// The authority's `err:` tail of [`do_othername`]: free the `OTHERNAME` and clear the slot.
///
/// # Safety
///
/// `gen` must be live and `on` must be the `OTHERNAME` installed on its `otherName` arm.
unsafe fn othername_err(gen: *mut GeneralName, on: *mut crate::x509::v3_genn::Othername) {
    // SAFETY: `on` is live and this call owns it.
    unsafe { OTHERNAME_free(on) };
    // SAFETY: `gen` is live.
    unsafe { (*gen).d.otherName = core::ptr::null_mut() };
}

/// `static int do_dirname(GENERAL_NAME *gen, const char *value, X509V3_CTX *ctx)` —
/// `crypto/x509/v3_san.c:664-689`.
///
/// Builds an `X509_NAME` from the config section `value` names.
///
/// # Safety
///
/// `gen` must be live; `value` must be NUL-terminated; `ctx` must be a live `X509V3_CTX`.
unsafe fn do_dirname(gen: *mut GeneralName, value: *const c_char, ctx: *mut X509V3Ctx) -> c_int {
    let mut ret = 0;
    let mut sk: *mut OpenSslStack = core::ptr::null_mut();
    // SAFETY: the item allocator answers NULL or a live value.
    let nm = X509_NAME_new();
    if !nm.is_null() {
        // SAFETY: `ctx` is live and `value` is NUL-terminated per the contract.
        sk = unsafe { X509V3_get_section(ctx, value) };
        if sk.is_null() {
            // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND, "section=%s", value)`.
            let mut msg = b"section=".to_vec();
            // SAFETY: `value` is the caller's NUL-terminated operand.
            unsafe { push_cstr(&mut msg, value) };
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
            unsafe { raise_site_data(&V3_SAN_674, msg.as_ptr().cast()) };
        } else {
            // SAFETY: `nm` is live and `sk` is a live section; `MBSTRING_ASC` is the
            // authority's `chtype` for a directoryName.
            ret = unsafe { X509V3_NAME_from_section(nm, sk, MBSTRING_ASC as c_ulong) };
            if ret != 0 {
                // SAFETY: `gen` is live; ownership of `nm` passes to the union.
                unsafe { (*gen).d.directoryName = nm };
            }
        }
    }
    if ret == 0 {
        // SAFETY: `nm` is NULL or this call's own value.
        unsafe { X509_NAME_free(nm) };
    }
    // SAFETY: `ctx` is live and `sk` is NULL or this call's own section.
    unsafe { X509V3_section_free(ctx, sk) };
    ret
}

/// `GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out, const X509V3_EXT_METHOD *method,
/// X509V3_CTX *ctx, int gen_type, const char *value, int is_nc)` — `crypto/x509/v3_san.c:503-590`.
///
/// The one builder every `v2i` callback funnels through. `out` reuses a name, so a failed build
/// does not free it; `is_nc` selects the two-address form for `GEN_IPADD`.
///
/// # Safety
///
/// `out` is NULL or a live `GENERAL_NAME`; `value` must be NUL-terminated; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn a2i_GENERAL_NAME(
    out: *mut GeneralName,
    _method: *const X509V3ExtMethod,
    ctx: *mut X509V3Ctx,
    gen_type: c_int,
    value: *const c_char,
    is_nc: c_int,
) -> *mut GeneralName {
    let mut is_string = false;
    if value.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_SAN_512) };
        return core::ptr::null_mut();
    }
    let gen = if !out.is_null() {
        out
    } else {
        // SAFETY: the item allocator answers NULL or a live value.
        let g = GENERAL_NAME_new();
        if g.is_null() {
            // SAFETY: the site is a declared constant.
            unsafe { raise_site(&V3_SAN_521) };
            return core::ptr::null_mut();
        }
        g
    };

    // A `'build` block reproduces the authority's `err:` tail, which frees only a
    // freshly allocated `gen` (`if (!out)`).
    let ok = 'build: {
        match gen_type {
            GEN_URI | GEN_EMAIL | GEN_DNS => is_string = true,
            GEN_RID => {
                // SAFETY: `value` is NUL-terminated.
                let obj = unsafe { OBJ_txt2obj(value, 0) };
                if obj.is_null() {
                    // SAFETY: `value` is NUL-terminated per this function's contract.
                    unsafe { err_value(&V3_SAN_536, value) };
                    break 'build false;
                }
                // SAFETY: `gen` is live; the `rid` arm is the selected one.
                unsafe { (*gen).d.registeredID = obj };
            }
            GEN_IPADD => {
                // SAFETY: `value` is NUL-terminated; the two builders answer NULL or a
                // live `ASN1_OCTET_STRING`.
                let ip = if is_nc != 0 {
                    // SAFETY: `value` is NUL-terminated per this function's contract.
                    unsafe { a2i_IPADDRESS_NC(value) }
                } else {
                    // SAFETY: `value` is NUL-terminated per this function's contract.
                    unsafe { a2i_IPADDRESS(value) }
                };
                // SAFETY: `gen` is live; the `ip` arm is the selected one.
                unsafe { (*gen).d.iPAddress = ip };
                if ip.is_null() {
                    // SAFETY: `value` is NUL-terminated per this function's contract.
                    unsafe { err_value(&V3_SAN_549, value) };
                    break 'build false;
                }
            }
            GEN_DIRNAME => {
                // SAFETY: `gen` is live; `value`/`ctx` are per the contract.
                if unsafe { do_dirname(gen, value, ctx) } == 0 {
                    // SAFETY: the site is a declared constant.
                    unsafe { raise_site(&V3_SAN_557) };
                    break 'build false;
                }
            }
            GEN_OTHERNAME => {
                // SAFETY: `gen` is live; `value`/`ctx` are per the contract.
                if unsafe { do_othername(gen, value, ctx) } == 0 {
                    // SAFETY: the site is a declared constant.
                    unsafe { raise_site(&V3_SAN_564) };
                    break 'build false;
                }
            }
            _ => {
                // SAFETY: the site is a declared constant.
                unsafe { raise_site(&V3_SAN_569) };
                break 'build false;
            }
        }

        if is_string {
            // SAFETY: no preconditions.
            let ia5 = ASN1_IA5STRING_new();
            // SAFETY: `gen` is live; the `ia5` arm is the selected one. `value` is
            // NUL-terminated, so `strlen` measures it.
            let set_ok = unsafe {
                (*gen).d.ia5 = ia5;
                !ia5.is_null() && ASN1_STRING_set(ia5, value.cast(), strlen(value) as c_int) != 0
            };
            if !set_ok {
                // SAFETY: `gen`'s `ia5` arm is this call's own or NULL.
                unsafe {
                    ASN1_IA5STRING_free((*gen).d.ia5);
                    (*gen).d.ia5 = core::ptr::null_mut();
                    raise_site(&V3_SAN_577);
                }
                break 'build false;
            }
        }

        // SAFETY: `gen` is live and uniquely owned here.
        unsafe { (*gen).type_ = gen_type };
        true
    };

    if ok {
        gen
    } else {
        if out.is_null() {
            // SAFETY: `gen` is this call's own value.
            unsafe { GENERAL_NAME_free(gen) };
        }
        core::ptr::null_mut()
    }
}

/// Raise a `"value=%s"`-shaped `X509V3` reason through the declared site.
///
/// # Safety
///
/// `value` must be NUL-terminated.
unsafe fn err_value(site: &crate::runtime::err::err_sites::ErrSite, value: *const c_char) {
    let mut msg = b"value=".to_vec();
    // SAFETY: `value` is NUL-terminated per the contract.
    unsafe { push_cstr(&mut msg, value) };
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated.
    unsafe { raise_site_data(site, msg.as_ptr().cast()) };
}

/// `GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out, const X509V3_EXT_METHOD *method,
/// X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc)` — `crypto/x509/v3_san.c:592-629`.
///
/// Maps a config entry's name to a `GEN_*` type and defers to [`a2i_GENERAL_NAME`].
///
/// # Safety
///
/// `out` is NULL or a live `GENERAL_NAME`; `cnf` must be a live `CONF_VALUE`; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn v2i_GENERAL_NAME_ex(
    out: *mut GeneralName,
    method: *const X509V3ExtMethod,
    ctx: *mut X509V3Ctx,
    cnf: *mut ConfValue,
    is_nc: c_int,
) -> *mut GeneralName {
    // SAFETY: `cnf` is live per the contract.
    let (name, value) = unsafe { ((*cnf).name, (*cnf).value) };
    if value.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_SAN_604) };
        return core::ptr::null_mut();
    }
    // Each `ossl_v3_name_cmp(name, "...")` is a case-insensitive prefix compare by
    // length; `name` is NUL-terminated.
    // SAFETY: `name` is NUL-terminated per the contract.
    let type_ = unsafe {
        if ossl_v3_name_cmp(name, c"email".as_ptr()) == 0 {
            GEN_EMAIL
        } else if ossl_v3_name_cmp(name, c"URI".as_ptr()) == 0 {
            GEN_URI
        } else if ossl_v3_name_cmp(name, c"DNS".as_ptr()) == 0 {
            GEN_DNS
        } else if ossl_v3_name_cmp(name, c"RID".as_ptr()) == 0 {
            GEN_RID
        } else if ossl_v3_name_cmp(name, c"IP".as_ptr()) == 0 {
            GEN_IPADD
        } else if ossl_v3_name_cmp(name, c"dirName".as_ptr()) == 0 {
            GEN_DIRNAME
        } else if ossl_v3_name_cmp(name, c"otherName".as_ptr()) == 0 {
            GEN_OTHERNAME
        } else {
            -1
        }
    };
    if type_ == -1 {
        // `ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNSUPPORTED_OPTION, "name=%s", name)`.
        let mut msg = b"name=".to_vec();
        // SAFETY: `name` is NUL-terminated per the contract.
        unsafe { push_cstr(&mut msg, name) };
        msg.push(0);
        // SAFETY: `msg` is NUL-terminated; the site is a declared constant.
        unsafe { raise_site_data(&V3_SAN_623, msg.as_ptr().cast()) };
        return core::ptr::null_mut();
    }
    // SAFETY: `out`/`ctx` are per the contract; `value` is NUL-terminated.
    unsafe { a2i_GENERAL_NAME(out, method, ctx, type_, value, is_nc) }
}

/// `GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// CONF_VALUE *cnf)` — `crypto/x509/v3_san.c:497-501`.
///
/// # Safety
///
/// `cnf` must be a live `CONF_VALUE`; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn v2i_GENERAL_NAME(
    method: *const X509V3ExtMethod,
    ctx: *mut X509V3Ctx,
    cnf: *mut ConfValue,
) -> *mut GeneralName {
    // SAFETY: the contract of `v2i_GENERAL_NAME_ex` is satisfied by this function's.
    unsafe { v2i_GENERAL_NAME_ex(core::ptr::null_mut(), method, ctx, cnf, 0) }
}

/// `GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_san.c:470-495`.
///
/// # Safety
///
/// `ctx` is NULL or live; `nval` must be a live stack of `CONF_VALUE` pointers.
#[no_mangle]
pub unsafe extern "C" fn v2i_GENERAL_NAMES(
    method: *const X509V3ExtMethod,
    ctx: *mut X509V3Ctx,
    nval: *mut OpenSslStack,
) -> *mut OpenSslStack {
    // SAFETY: `nval` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let gens = OPENSSL_sk_new_reserve(None, num);
    if gens.is_null() {
        // SAFETY: the site is a declared constant.
        unsafe { raise_site(&V3_SAN_481) };
        return core::ptr::null_mut();
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is a live `CONF_VALUE`; `ctx` is NULL or live.
        let gen = unsafe { v2i_GENERAL_NAME(method, ctx, cnf) };
        if gen.is_null() {
            // SAFETY: `gens` is this call's own stack; each element is freed by the thunk.
            unsafe { OPENSSL_sk_pop_free(gens, Some(general_name_free_thunk)) };
            return core::ptr::null_mut();
        }
        // SAFETY: `gens` is live and `gen` is this call's own value.
        unsafe { OPENSSL_sk_push(gens, gen.cast::<c_void>()) };
        i += 1;
    }
    gens
}
