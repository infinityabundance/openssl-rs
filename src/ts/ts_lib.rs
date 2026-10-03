//! `crypto/ts/ts_lib.c` — the timestamping print helpers. Phase 12.5.
//!
//! Five exports, each composing an authority printer: the ASN.1 integer as `BN_bn2hex`, an OID
//! through `OBJ_obj2txt`, the extension stack through `X509V3_EXT_print`, the hash algorithm
//! through `OBJ_nid2ln`, and a `MessageImprint` through `BIO_dump_indent`. `ts_req_print` and
//! `ts_rsp_print` are these plus literals, which is why the court compares their text byte for
//! byte.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::c_int;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::asn1::x_algor::X509Algor;
use crate::bn::bignum::{BN_bn2hex, BN_free, BigNum};
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{Asn1Object, OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_prn::X509V3_EXT_print;
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
    X509v3_get_ext, X509v3_get_ext_count,
};

use super::ts_asn1::TsMsgImprint;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_lib.c";

/// `int TS_ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num)` — `ts_lib.c:19-36`.
///
/// # Safety
/// `bio` is live; `num` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ASN1_INTEGER_print_bio(
    bio: *mut Bio,
    num: *const crate::asn1::layout::Asn1String,
) -> c_int {
    let mut result = 0;

    // SAFETY: the caller's contract.
    let num_bn: *mut BigNum = unsafe { ASN1_INTEGER_to_BN(num, core::ptr::null_mut()) };
    if num_bn.is_null() {
        return -1;
    }
    // SAFETY: `num_bn` is live.
    let hex = unsafe { BN_bn2hex(num_bn) };
    if !hex.is_null() {
        // SAFETY: `hex` is a NUL-terminated string.
        let hex_len = unsafe { core::ffi::CStr::from_ptr(hex) }.to_bytes().len() as c_int;
        // SAFETY: `bio` is live and `hex` holds `hex_len` bytes.
        result = (unsafe { BIO_write(bio, c"0x".as_ptr().cast(), 2) } > 0) as c_int;
        // SAFETY: as above.
        result &= (unsafe { BIO_write(bio, hex.cast(), hex_len) } > 0) as c_int;
        // SAFETY: `hex` is a `BN_bn2hex` allocation; this is `OPENSSL_free(hex)` at `:31`.
        unsafe { CRYPTO_free(hex.cast(), FILE.as_ptr(), 31) };
    }
    // SAFETY: `num_bn` is live.
    unsafe { BN_free(num_bn) };

    result
}

/// `int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj)` — `ts_lib.c:38-46`.
///
/// # Safety
/// `bio` is live; `obj` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_OBJ_print_bio(bio: *mut Bio, obj: *const Asn1Object) -> c_int {
    let mut obj_txt = [0 as core::ffi::c_char; 128];

    // SAFETY: `obj_txt` is 128 writable bytes and `obj` is live.
    unsafe { OBJ_obj2txt(obj_txt.as_mut_ptr(), obj_txt.len() as c_int, obj, 0) };
    // SAFETY: the caller's contract.
    unsafe { BIO_printf(bio, c"%s\n".as_ptr(), obj_txt.as_ptr()) };

    1
}

/// `int TS_ext_print_bio(BIO *bio, const STACK_OF(X509_EXTENSION) *extensions)` —
/// `ts_lib.c:48-71`.
///
/// # Safety
/// `bio` is live; `extensions` is NULL or a live stack of `X509_EXTENSION`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ext_print_bio(
    bio: *mut Bio,
    extensions: *const OpenSslStack,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { BIO_printf(bio, c"Extensions:\n".as_ptr()) };
    // SAFETY: as above.
    let n = unsafe { X509v3_get_ext_count(extensions) };
    for i in 0..n {
        // SAFETY: `extensions` is live.
        let ex = unsafe { X509v3_get_ext(extensions, i) };
        // SAFETY: `ex` is live.
        let obj = unsafe { X509_EXTENSION_get_object(ex) };
        // SAFETY: `bio` and `obj` are live.
        if unsafe { i2a_ASN1_OBJECT(bio, obj) } < 0 {
            return 0;
        }
        // SAFETY: `ex` is live.
        let critical = unsafe { X509_EXTENSION_get_critical(ex) };
        // SAFETY: `bio` is live.
        unsafe {
            BIO_printf(
                bio,
                c":%s\n".as_ptr(),
                if critical != 0 {
                    c" critical".as_ptr()
                } else {
                    c"".as_ptr()
                },
            )
        };
        // SAFETY: `bio` and `ex` are live.
        if unsafe { X509V3_EXT_print(bio, ex, 0, 4) } == 0 {
            // SAFETY: `bio` is live.
            unsafe { BIO_printf(bio, c"%4s".as_ptr(), c"".as_ptr()) };
            // SAFETY: `bio` is live and `ex`'s data is live.
            unsafe { ASN1_STRING_print(bio, X509_EXTENSION_get_data(ex)) };
        }
        // SAFETY: `bio` is live.
        unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };
    }

    1
}

/// `int TS_X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg)` — `ts_lib.c:73-78`.
///
/// # Safety
/// `bio` is live; `alg` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_X509_ALGOR_print_bio(
    bio: *mut Bio,
    alg: *const X509Algor,
) -> c_int {
    // SAFETY: `alg` is live.
    let i = unsafe { OBJ_obj2nid((*alg).algorithm) };
    // SAFETY: `bio` is live and the answered name is NUL-terminated or NULL.
    unsafe {
        BIO_printf(
            bio,
            c"Hash Algorithm: %s\n".as_ptr(),
            if i == NID_undef {
                c"UNKNOWN".as_ptr()
            } else {
                OBJ_nid2ln(i)
            },
        )
    }
}

/// `int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *a)` — `ts_lib.c:80-92`.
///
/// # Safety
/// `bio` is live; `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_print_bio(
    bio: *mut Bio,
    a: *mut TsMsgImprint,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { TS_X509_ALGOR_print_bio(bio, (*a).hash_algo) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Message data:\n".as_ptr()) };
    // SAFETY: `a` is live.
    let msg = unsafe { (*a).hashed_msg };
    // SAFETY: `msg` is live.
    unsafe {
        BIO_dump_indent(
            bio,
            ASN1_STRING_get0_data(msg).cast(),
            ASN1_STRING_length(msg),
            4,
        )
    };

    1
}

// `NID_undef` is the object database's answer for an unknown OID.
use crate::runtime::obj::NID_undef;
