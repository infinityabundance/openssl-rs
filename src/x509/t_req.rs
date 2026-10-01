//! `crypto/x509/t_req.c` -- the `X509_REQ` printer. Phase 11.4.
//!
//! The unit is 216 lines and defines **three exports and no internals**: [`X509_REQ_print_fp`]
//! (`:21-34`, inside `#ifndef OPENSSL_NO_STDIO`), the printer it wraps, [`X509_REQ_print_ex`]
//! (`:37-211`), and the default spelling [`X509_REQ_print`] (`:213-216`). All three land here --
//! every callee is already the crate's, so there is nothing withheld.
//!
//! The printer walks the request in the authority's order: header, version, subject, the
//! `SubjectPublicKeyInfo` (algorithm OID then the public key at indent 16), the attributes with
//! each value checked against the five printable string types, the requested extensions when the
//! request carries them, and finally the signature through [`X509_signature_print`]. The two
//! `get_next`-loop arms -- the `j` space-padding counter and the `enter` flag that decides whether
//! the per-value read runs at all -- are transcribed exactly, including the second iteration's
//! `25 - 0` padding the C's reused loop counter produces.
//!
//! ## The raises
//!
//! Three, and the unit is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so each is
//! declared here in the crate's `ErrSite` idiom:
//!
//! * `X509_REQ_print_fp`'s BIO-creation failure at `:27` (`ERR_R_BUF_LIB`).
//! * `X509_REQ_print_ex`'s zero-`X509_ATTRIBUTE_count` refusal at `:132`
//!   (`X509_R_INVALID_ATTRIBUTES`).
//! * `X509_REQ_print_ex`'s `err:`-label failure at `:209` (`ERR_R_BUF_LIB`).
//!
//! ## The court
//!
//! `RT-X509-REQ` (`courts/phase11/rt_x509_req_probe.c`) drives all three over the fixed request
//! DER, prints each writer's exact bytes to a memory BIO or a controlled `tmpfile()` and compares
//! them to the authority's. No address is printed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::asn1::layout::{
    Asn1String, Asn1Type, V_ASN1_IA5STRING, V_ASN1_NUMERICSTRING, V_ASN1_PRINTABLESTRING,
    V_ASN1_T61STRING, V_ASN1_UTF8STRING,
};
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::asn1::x_algor::X509Algor;
use crate::evp::pkey::EVP_PKEY_print_public;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_print_errors};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::t_x509::X509_signature_print;
use crate::x509::v3_prn::X509V3_EXT_print;
use crate::x509::x509_att::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type,
};
use crate::x509::x509_req::{
    X509Req, X509_REQ_extension_nid, X509_REQ_get0_pubkey, X509_REQ_get0_signature,
    X509_REQ_get_X509_PUBKEY, X509_REQ_get_attr, X509_REQ_get_attr_count, X509_REQ_get_extensions,
    X509_REQ_get_subject_name, X509_REQ_get_version,
};
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};
use crate::x509::x_pubkey::X509_PUBKEY_get0_param;

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BUF_LIB` -- `include/openssl/err.h.in:323`, `ERR_LIB_BUF | ERR_RFLAG_COMMON`.
const ERR_R_BUF_LIB: c_int = 524295;
/// `X509_R_INVALID_ATTRIBUTES` -- `include/openssl/x509err.h`, `138`.
const X509_R_INVALID_ATTRIBUTES: c_int = 138;

/// `X509_FLAG_COMPAT` -- `include/openssl/x509.h.in:137`, `0`.
const X509_FLAG_COMPAT: c_ulong = 0;
/// `X509_FLAG_NO_HEADER` -- `include/openssl/x509.h.in:138`, `1L`.
const X509_FLAG_NO_HEADER: c_ulong = 1;
/// `X509_FLAG_NO_VERSION` -- `include/openssl/x509.h.in:139`.
const X509_FLAG_NO_VERSION: c_ulong = 1 << 1;
/// `X509_FLAG_NO_SUBJECT` -- `include/openssl/x509.h.in:144`.
const X509_FLAG_NO_SUBJECT: c_ulong = 1 << 6;
/// `X509_FLAG_NO_PUBKEY` -- `include/openssl/x509.h.in:145`.
const X509_FLAG_NO_PUBKEY: c_ulong = 1 << 7;
/// `X509_FLAG_NO_EXTENSIONS` -- `include/openssl/x509.h.in:146`.
const X509_FLAG_NO_EXTENSIONS: c_ulong = 1 << 8;
/// `X509_FLAG_NO_SIGDUMP` -- `include/openssl/x509.h.in:147`.
const X509_FLAG_NO_SIGDUMP: c_ulong = 1 << 9;
/// `X509_FLAG_NO_ATTRIBUTES` -- `include/openssl/x509.h.in:149`.
const X509_FLAG_NO_ATTRIBUTES: c_ulong = 1 << 11;

/// `XN_FLAG_SEP_MASK` -- `include/openssl/x509.h.in:157`, the separator group selector.
const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
/// `XN_FLAG_COMPAT` -- `include/openssl/x509.h.in:159`; selects the old `X509_NAME_print`.
const XN_FLAG_COMPAT: c_ulong = 0;
/// `XN_FLAG_SEP_MULTILINE` -- `include/openssl/x509.h.in:163`; one field per line.
const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;

/// `X509_REQ_VERSION_1` -- `include/openssl/x509.h.in:695`, `0`.
const X509_REQ_VERSION_1: c_long = 0;

/// One `t_req.c` raise coordinate, declared locally because the unit is not in
/// `gen_err_raise_sites.py`'s covered set (see the module doc).
const fn t_req_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/t_req.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_REQ_print_fp`'s BIO-creation failure at `crypto/x509/t_req.c:27`, `ERR_R_BUF_LIB`.
const X509_REQ_PRINT_FP_27: ErrSite = t_req_site(27, c"X509_REQ_print_fp", ERR_R_BUF_LIB);
/// `X509_REQ_print_ex`'s zero-attribute-count refusal at `crypto/x509/t_req.c:132`.
const X509_REQ_132: ErrSite = t_req_site(132, c"X509_REQ_print_ex", X509_R_INVALID_ATTRIBUTES);
/// `X509_REQ_print_ex`'s `err:`-label failure at `crypto/x509/t_req.c:209`, `ERR_R_BUF_LIB`.
const X509_REQ_209: ErrSite = t_req_site(209, c"X509_REQ_print_ex", ERR_R_BUF_LIB);

/// The `void (*)(void *)` destructor shape `OPENSSL_sk_pop_free` takes, adapting
/// [`X509_EXTENSION_free`] for [`X509_REQ_print_ex`]'s extension stack.
///
/// # Safety
///
/// `p` must be NULL or a live `X509_EXTENSION`.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_EXTENSION_free(p.cast::<X509Extension>()) };
}

/// `int X509_REQ_print_fp(FILE *fp, X509_REQ *x)` -- `crypto/x509/t_req.c:21-34`.
///
/// The whole body sits inside `#ifndef OPENSSL_NO_STDIO`, which holds on this profile: wrap `fp`
/// in a no-close `BIO_s_file` BIO and print through [`X509_REQ_print`]. A BIO that cannot be made
/// raises `ERR_R_BUF_LIB` at `:27` and answers 0.
///
/// # Safety
///
/// `fp` is a live writable stream; `x` is a live `X509_REQ`.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_print_fp(fp: *mut c_void, x: *mut X509Req) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&X509_REQ_PRINT_FP_27);
            return 0;
        }
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp);
        let ret = X509_REQ_print(b, x);
        BIO_free(b);
        ret
    }
}

/// `int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflags, unsigned long cflag)` --
/// `crypto/x509/t_req.c:37-211`.
///
/// The request printer. A multiline separator sets the field separator to newline and the name
/// indent to 12; `XN_FLAG_COMPAT` makes `X509_NAME_print_ex`'s zero answer a failure. Each
/// unflagged section prints in the authority's order, and every failure arm raises
/// `ERR_R_BUF_LIB` at the `err:` label (`:209`) and answers 0; success answers 1. A request
/// attribute whose `X509_ATTRIBUTE_count` is 0 raises `X509_R_INVALID_ATTRIBUTES` at `:132` and
/// answers 0 immediately.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live `X509_REQ`.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_print_ex(
    bp: *mut Bio,
    x: *mut X509Req,
    nmflags: c_ulong,
    cflag: c_ulong,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let mut mlch: c_int = c_int::from(b' ');
        let mut nmindent: c_int = 0;
        let mut printok: c_int = 0;

        if (nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE {
            mlch = c_int::from(b'\n');
            nmindent = 12;
        }
        if nmflags == XN_FLAG_COMPAT {
            printok = 1;
        }

        if cflag & X509_FLAG_NO_HEADER == 0 {
            if BIO_write(bp, c"Certificate Request:\n".as_ptr().cast(), 21) <= 0 {
                return req_err();
            }
            if BIO_write(bp, c"    Data:\n".as_ptr().cast(), 10) <= 0 {
                return req_err();
            }
        }
        if cflag & X509_FLAG_NO_VERSION == 0 {
            let l = X509_REQ_get_version(x);
            if l == X509_REQ_VERSION_1 {
                if BIO_printf(
                    bp,
                    c"%8sVersion: %ld (0x%lx)\n".as_ptr(),
                    c"".as_ptr(),
                    l + 1,
                    l as c_ulong,
                ) <= 0
                {
                    return req_err();
                }
            } else if BIO_printf(bp, c"%8sVersion: Unknown (%ld)\n".as_ptr(), c"".as_ptr(), l) <= 0
            {
                return req_err();
            }
        }
        if cflag & X509_FLAG_NO_SUBJECT == 0 {
            if BIO_printf(bp, c"        Subject:%c".as_ptr(), mlch) <= 0 {
                return req_err();
            }
            if X509_NAME_print_ex(bp, X509_REQ_get_subject_name(x), nmindent, nmflags) < printok {
                return req_err();
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return req_err();
            }
        }
        if cflag & X509_FLAG_NO_PUBKEY == 0 {
            let mut koid: *mut Asn1Object = ptr::null_mut();
            if BIO_write(
                bp,
                c"        Subject Public Key Info:\n".as_ptr().cast(),
                33,
            ) <= 0
            {
                return req_err();
            }
            if BIO_printf(bp, c"%12sPublic Key Algorithm: ".as_ptr(), c"".as_ptr()) <= 0 {
                return req_err();
            }
            let xpkey = X509_REQ_get_X509_PUBKEY(x);
            X509_PUBKEY_get0_param(
                &raw mut koid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                xpkey,
            );
            if i2a_ASN1_OBJECT(bp, koid) <= 0 {
                return req_err();
            }
            if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                return req_err();
            }

            let pkey = X509_REQ_get0_pubkey(x);
            if pkey.is_null() {
                if BIO_printf(
                    bp,
                    c"%12sUnable to load Public Key\n".as_ptr(),
                    c"".as_ptr(),
                ) <= 0
                {
                    return req_err();
                }
                ERR_print_errors(bp);
            } else if EVP_PKEY_print_public(bp, pkey, 16, ptr::null_mut()) <= 0 {
                return req_err();
            }
        }

        if cflag & X509_FLAG_NO_ATTRIBUTES == 0 {
            // may not be
            if BIO_printf(bp, c"%8sAttributes:\n".as_ptr(), c"".as_ptr()) <= 0 {
                return req_err();
            }

            if X509_REQ_get_attr_count(x) == 0 {
                if BIO_printf(bp, c"%12s(none)\n".as_ptr(), c"".as_ptr()) <= 0 {
                    return req_err();
                }
            } else {
                let count_attrs = X509_REQ_get_attr_count(x);
                let mut i: c_int = 0;
                while i < count_attrs {
                    let mut type_: c_int = 0;
                    let mut count: c_int = 1;
                    let mut ii: c_int = 0;
                    let mut bs: *const Asn1String = ptr::null();

                    let a = X509_REQ_get_attr(x, i);
                    let aobj = X509_ATTRIBUTE_get0_object(a);
                    if X509_REQ_extension_nid(OBJ_obj2nid(aobj)) != 0 {
                        i += 1;
                        continue;
                    }
                    if BIO_printf(bp, c"%12s".as_ptr(), c"".as_ptr()) <= 0 {
                        return req_err();
                    }
                    // The C's `get_next` label block runs only when the object printed; the reused
                    // loop counter `j` then falls to 0, so the second value pads with `25 - 0`.
                    let mut entered = false;
                    let mut j = i2a_ASN1_OBJECT(bp, aobj);
                    if j > 0 {
                        entered = true;
                        ii = 0;
                        count = X509_ATTRIBUTE_count(a);
                        if count == 0 {
                            raise_site(&X509_REQ_132);
                            return 0;
                        }
                    }
                    loop {
                        if entered {
                            let at: *mut Asn1Type = X509_ATTRIBUTE_get0_type(a, ii);
                            type_ = (*at).type_;
                            bs = (*at).value.ptr.cast::<Asn1String>();
                        }
                        j = 25 - j;
                        while j > 0 {
                            if BIO_write(bp, c" ".as_ptr().cast(), 1) != 1 {
                                return req_err();
                            }
                            j -= 1;
                        }
                        if BIO_puts(bp, c":".as_ptr()) <= 0 {
                            return req_err();
                        }
                        match type_ {
                            V_ASN1_PRINTABLESTRING
                            | V_ASN1_T61STRING
                            | V_ASN1_NUMERICSTRING
                            | V_ASN1_UTF8STRING
                            | V_ASN1_IA5STRING => {
                                if BIO_write(bp, (*bs).data.cast(), (*bs).length) != (*bs).length {
                                    return req_err();
                                }
                                if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                                    return req_err();
                                }
                            }
                            _ => {
                                if BIO_puts(bp, c"unable to print attribute\n".as_ptr()) <= 0 {
                                    return req_err();
                                }
                            }
                        }
                        if entered {
                            ii += 1;
                            if ii < count {
                                continue;
                            }
                        }
                        break;
                    }
                    i += 1;
                }
            }
        }
        if cflag & X509_FLAG_NO_EXTENSIONS == 0 {
            let exts = X509_REQ_get_extensions(x);
            if !exts.is_null() {
                if BIO_printf(bp, c"%12sRequested Extensions:\n".as_ptr(), c"".as_ptr()) <= 0 {
                    return req_err();
                }
                let n = OPENSSL_sk_num(exts);
                let mut i: c_int = 0;
                while i < n {
                    let ex = OPENSSL_sk_value(exts, i).cast::<X509Extension>();
                    if BIO_printf(bp, c"%16s".as_ptr(), c"".as_ptr()) <= 0 {
                        return req_err();
                    }
                    let obj = X509_EXTENSION_get_object(ex);
                    if i2a_ASN1_OBJECT(bp, obj) <= 0 {
                        return req_err();
                    }
                    let critical = X509_EXTENSION_get_critical(ex);
                    let critical_str = if critical != 0 {
                        c"critical".as_ptr()
                    } else {
                        c"".as_ptr()
                    };
                    if BIO_printf(bp, c": %s\n".as_ptr(), critical_str) <= 0 {
                        return req_err();
                    }
                    if X509V3_EXT_print(bp, ex, cflag, 20) == 0
                        && (BIO_printf(bp, c"%20s".as_ptr(), c"".as_ptr()) <= 0
                            || ASN1_STRING_print(bp, X509_EXTENSION_get_data(ex)) <= 0)
                    {
                        return req_err();
                    }
                    if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                        return req_err();
                    }
                    i += 1;
                }
                OPENSSL_sk_pop_free(exts, Some(x509_extension_free_void));
            }
        }

        if cflag & X509_FLAG_NO_SIGDUMP == 0 {
            let mut sig_alg: *const X509Algor = ptr::null();
            let mut sig: *const Asn1String = ptr::null();
            X509_REQ_get0_signature(x, &raw mut sig, &raw mut sig_alg);
            if X509_signature_print(bp, sig_alg, sig) == 0 {
                return req_err();
            }
        }

        1
    }
}

/// The `err:` label of [`X509_REQ_print_ex`] (`crypto/x509/t_req.c:208-210`).
fn req_err() -> c_int {
    // SAFETY: a compiled-in site coordinate.
    unsafe { raise_site(&X509_REQ_209) };
    0
}

/// `int X509_REQ_print(BIO *bp, X509_REQ *x)` -- `crypto/x509/t_req.c:213-216`.
///
/// [`X509_REQ_print_ex`] with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live `X509_REQ`.
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_print(bp: *mut Bio, x: *mut X509Req) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe { X509_REQ_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT) }
}
