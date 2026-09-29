//! `crypto/x509/v3_san.c` — the general-name printers. Phase 10.14.6, **partial at function
//! granularity**.
//!
//! `crypto/x509/v3_san.c` is 689 lines. This slice lands the half the extension tables call: the
//! **printers** `GENERAL_NAME_print` (`:207-299`), `i2v_GENERAL_NAME` (`:79-205`) and
//! `i2v_GENERAL_NAMES` (`:51-77`), the widest blocker D464 measured
//! (`GENERAL_NAME_print`/`i2v_GENERAL_NAME`/`i2v_GENERAL_NAMES`).
//!
//! ## What is withheld, and the one blocker
//!
//! The **`v2i` cluster is withheld by name behind `ASN1_generate_v3`** (`crypto/asn1/asn1_gen.c`,
//! not landed in this slice): `a2i_GENERAL_NAME` (`:503-590`) calls `do_othername` (`:631-662`),
//! which builds its `[0] EXPLICIT ANY` value with `ASN1_generate_v3`; `v2i_GENERAL_NAME_ex`
//! (`:592-629`), `v2i_GENERAL_NAME` (`:497-501`) and `v2i_GENERAL_NAMES` (`:470-495`) all funnel
//! through `a2i_GENERAL_NAME`, and `do_dirname` (`:664-689`) additionally needs
//! `X509V3_get_section`/`_section_free` (landed this slice in `v3_conf.rs`). Because every arrow
//! in that cluster is one of these names, the whole cluster is one withhold:
//! `a2i_GENERAL_NAME`, `v2i_GENERAL_NAME`, `v2i_GENERAL_NAME_ex`, `v2i_GENERAL_NAMES`,
//! `do_othername`, `do_dirname`.
//!
//! `v2i_subject_alt` (`:377-413`) and `copy_email` (`:419-468`) are withheld behind the same
//! `ASN1_generate_v3` (through `v2i_GENERAL_NAME`) plus `X509_REQ_get_subject_name`
//! (`x509_req.c`, 10.14.11); `v2i_issuer_alt` (`:301-332`) and `copy_issuer` (`:336-375`) behind
//! `X509V3_EXT_d2i` (`v3_lib.rs`, the withheld dispatch). `ossl_v3_alt` (`:29-49`) is the unit's
//! one table; two of its three rows name the withheld `v2i_subject_alt`/`v2i_issuer_alt`, so the
//! table is withheld with them rather than published with holes.
//!
//! ## Why the printers alone are worth landing
//!
//! `GENERAL_NAME_print` is the blocker D464 named for `v3_ncons.c`, `v3_aaa.c`, `v3_ac_tgt.c`,
//! `v3_admis.c`, `v3_iobo.c`, `v3_rolespec.c` and `v3_info.c`; `i2v_GENERAL_NAME`/`i2v_GENERAL_NAMES`
//! are the blockers of `v3_akid.c` and `v3_info.c`. Landing them (and un-withholding
//! `OSSL_GENERAL_NAMES_print` in `v3_utl.rs`) turns several table units closure-ready even before
//! the `v2i` cluster lands.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_san.c` is not in `gen_err_raise_sites.py`'s covered set, so its coordinates are
//! declared locally (see `v3_conf.rs`'s note). The **landed** printers raise nothing; every site is
//! in the withheld cluster and is declared unused until it lands.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
// The crate's NID constants keep the authority's own macro spelling (`NID_XmppAddr`, ...), so a
// pattern match on them trips the upper-case lint; the same allow is used by `src/x509/x509type.rs`.
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void, CStr};

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::asn1::layout::{Asn1String, V_ASN1_IA5STRING, V_ASN1_UTF8STRING};
use crate::asn1::text::{i2a_ASN1_OBJECT, i2t_ASN1_OBJECT};
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::Bio;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    NID_NAIRealm, NID_SRVName, NID_XmppAddr, NID_id_on_SmtpUTF8Mailbox, NID_ms_upn, OBJ_obj2nid,
    OBJ_obj2txt,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strlcpy;
use crate::x509::v3_genn::{
    GeneralName, GEN_DIRNAME, GEN_DNS, GEN_EDIPARTY, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME, GEN_RID,
    GEN_URI, GEN_X400,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{ossl_ipaddr_to_asc, x509v3_add_len_value_uchar, X509V3_add_value};
use crate::x509::x509_obj::X509_NAME_oneline;

/// The authority file path this module's raises name.
const FILE: &CStr = c"crypto/x509/v3_san.c";

/// One `v3_san.c` raise coordinate, declared locally (see the module doc). Every site is in the
/// withheld `v2i` cluster, so no constant here is reachable yet.
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

#[allow(dead_code)]
const V3_SAN_310: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(310, c"v2i_issuer_alt", 524303);
#[allow(dead_code)]
const V3_SAN_388: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(388, c"v2i_subject_alt", 524303);
#[allow(dead_code)]
const V3_SAN_481: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(481, c"v2i_GENERAL_NAMES", 524303);
#[allow(dead_code)]
const V3_SAN_431: crate::runtime::err::err_sites::ErrSite = v3_san_site(431, c"copy_email", 125);
#[allow(dead_code)]
const V3_SAN_449: crate::runtime::err::err_sites::ErrSite = v3_san_site(449, c"copy_email", 524557);
#[allow(dead_code)]
const V3_SAN_456: crate::runtime::err::err_sites::ErrSite = v3_san_site(456, c"copy_email", 524303);
#[allow(dead_code)]
const V3_SAN_346: crate::runtime::err::err_sites::ErrSite = v3_san_site(346, c"copy_issuer", 108);
#[allow(dead_code)]
const V3_SAN_354: crate::runtime::err::err_sites::ErrSite = v3_san_site(354, c"copy_issuer", 126);
#[allow(dead_code)]
const V3_SAN_360: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(360, c"copy_issuer", 524303);
#[allow(dead_code)]
const V3_SAN_512: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(512, c"a2i_GENERAL_NAME", 109);
#[allow(dead_code)]
const V3_SAN_521: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(521, c"a2i_GENERAL_NAME", 524557);
#[allow(dead_code)]
const V3_SAN_536: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(536, c"a2i_GENERAL_NAME", 119);
#[allow(dead_code)]
const V3_SAN_549: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(549, c"a2i_GENERAL_NAME", 103);
#[allow(dead_code)]
const V3_SAN_557: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(557, c"a2i_GENERAL_NAME", 109);
#[allow(dead_code)]
const V3_SAN_564: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(564, c"a2i_GENERAL_NAME", 112);
#[allow(dead_code)]
const V3_SAN_569: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(569, c"a2i_GENERAL_NAME", 117);
#[allow(dead_code)]
const V3_SAN_577: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(577, c"a2i_GENERAL_NAME", 524557);
#[allow(dead_code)]
const V3_SAN_604: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(604, c"v2i_GENERAL_NAME_ex", 109);
#[allow(dead_code)]
const V3_SAN_623: crate::runtime::err::err_sites::ErrSite =
    v3_san_site(623, c"v2i_GENERAL_NAME_ex", 110);
#[allow(dead_code)]
const V3_SAN_674: crate::runtime::err::err_sites::ErrSite = v3_san_site(674, c"do_dirname", 111);

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
