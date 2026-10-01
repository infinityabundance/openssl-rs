//! `crypto/x509/t_acert.c` -- the attribute-certificate printer. Phase 11.3, landed with 11.7.
//!
//! `crypto/x509/t_acert.c` is 289 lines and publishes exactly two functions:
//! `X509_ACERT_print_ex` (`:83-284`) and its `X509_ACERT_print` wrapper (`:286-289`), plus the
//! file-local `print_attribute` helper (`:17-81`). **Both exports land here.**
//!
//! ## What withheld them, and what un-blocked them
//!
//! `X509_ACERT_print_ex` prints every section of the certificate and finally, when
//! `X509_FLAG_NO_SIGDUMP` is clear, reaches
//!
//! ```text
//! X509_ACERT_get0_signature(x, &sig, &sig_alg);
//! if (X509_signature_print(bp, sig_alg, sig) <= 0)      /* t_acert.c:275 */
//!     return 0;
//! ```
//!
//! `X509_signature_print` is `crypto/x509/t_x509.c`'s (`:292-316`), and it was the **one**
//! unlanded name in the pair's closure: 11.4 landed it in `src/x509/t_x509.rs`, so the printers
//! land now rather than being stubbed. Every other callee is already the crate's -- the
//! `X509_ACERT_get_*` accessors (`src/x509/x509_acert.rs`), `OSSL_ISSUER_SERIAL_get0_*`,
//! `GENERAL_NAME_print` (`src/x509/v3_san.rs`), `X509_NAME_print_ex` (`src/asn1/a_strex.rs`),
//! `X509_signature_dump` (`src/x509/t_x509.rs`), `X509V3_EXT_print` (`src/x509/v3_prn.rs`),
//! `i2a_ASN1_OBJECT`/`i2a_ASN1_INTEGER`/`ASN1_parse_dump`/`ASN1_STRING_print` (`src/asn1/`) and
//! `ASN1_GENERALIZEDTIME_print` (`src/asn1/time.rs`). `X509_ACERT_print` is `X509_ACERT_print_ex`
//! under `XN_FLAG_COMPAT`/`X509_FLAG_COMPAT` (`= 0`), so its `cflag` carries no
//! `X509_FLAG_NO_SIGDUMP` bit and it *always* takes that arm.
//!
//! ## The raises
//!
//! Two, and the unit is **not** in `gen_err_raise_sites.py`'s covered set, so each is declared
//! here in the crate's `ErrSite` idiom: `print_attribute`'s
//! `ERR_raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES)` for a zero-count attribute
//! (`t_acert.c:32`), and `X509_ACERT_print_ex`'s `ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB)` from its
//! `err:` label (`t_acert.c:282`). The signature-dump arm answers 0 *without* raising, which is
//! the authority's own asymmetry and is reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, CStr};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::asn1::der::ASN1_parse_dump;
use crate::asn1::layout::{
    Asn1String, Asn1Type, V_ASN1_IA5STRING, V_ASN1_NUMERICSTRING, V_ASN1_PRINTABLESTRING,
    V_ASN1_SEQUENCE, V_ASN1_T61STRING, V_ASN1_UTF8STRING,
};
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::asn1::x_algor::X509Algor;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::t_x509::{X509_signature_dump, X509_signature_print};
use crate::x509::v3_genn::GeneralName;
use crate::x509::v3_prn::X509V3_EXT_print;
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::x509_acert::{
    OSSL_ISSUER_SERIAL_get0_issuer, OSSL_ISSUER_SERIAL_get0_issuerUID,
    OSSL_ISSUER_SERIAL_get0_serial, X509Acert, X509_ACERT_get0_extensions,
    X509_ACERT_get0_holder_baseCertId, X509_ACERT_get0_holder_entityName,
    X509_ACERT_get0_issuerName, X509_ACERT_get0_notAfter, X509_ACERT_get0_notBefore,
    X509_ACERT_get0_serialNumber, X509_ACERT_get0_signature, X509_ACERT_get_attr,
    X509_ACERT_get_attr_count, X509_ACERT_get_version,
};
use crate::x509::x509_att::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type,
};
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
};
use crate::x509::x_attrib::X509Attribute;
use crate::x509::x_exten::X509Extension;
use crate::x509::x_name::X509Name;

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BUF_LIB` -- `include/openssl/err.h.in:323`, `ERR_LIB_BUF | ERR_RFLAG_COMMON`.
const ERR_R_BUF_LIB: c_int = 524295;
/// `X509_R_INVALID_ATTRIBUTES` -- `include/openssl/x509err.h`, `138`.
const X509_R_INVALID_ATTRIBUTES: c_int = 138;

/// `X509_ACERT_VERSION_2` -- `include/openssl/x509_acert.h.in:58`, `1`.
const X509_ACERT_VERSION_2: c_long = 1;

/// `X509_FLAG_NO_HEADER` -- `include/openssl/x509.h.in:138`, `1L`.
const X509_FLAG_NO_HEADER: c_ulong = 1;
/// `X509_FLAG_NO_VERSION` -- `include/openssl/x509.h.in:139`.
const X509_FLAG_NO_VERSION: c_ulong = 1 << 1;
/// `X509_FLAG_NO_SERIAL` -- `include/openssl/x509.h.in:140`.
const X509_FLAG_NO_SERIAL: c_ulong = 1 << 2;
/// `X509_FLAG_NO_ISSUER` -- `include/openssl/x509.h.in:142`.
const X509_FLAG_NO_ISSUER: c_ulong = 1 << 4;
/// `X509_FLAG_NO_VALIDITY` -- `include/openssl/x509.h.in:143`.
const X509_FLAG_NO_VALIDITY: c_ulong = 1 << 5;
/// `X509_FLAG_NO_SUBJECT` -- `include/openssl/x509.h.in:144`; the holder section.
const X509_FLAG_NO_SUBJECT: c_ulong = 1 << 6;
/// `X509_FLAG_NO_EXTENSIONS` -- `include/openssl/x509.h.in:146`.
const X509_FLAG_NO_EXTENSIONS: c_ulong = 1 << 8;
/// `X509_FLAG_NO_SIGDUMP` -- `include/openssl/x509.h.in:147`.
const X509_FLAG_NO_SIGDUMP: c_ulong = 1 << 9;
/// `X509_FLAG_NO_ATTRIBUTES` -- `include/openssl/x509.h.in:149`.
const X509_FLAG_NO_ATTRIBUTES: c_ulong = 1 << 11;

/// `XN_FLAG_SEP_MASK` -- `include/openssl/x509.h.in:157`, the separator group selector.
const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
/// `XN_FLAG_COMPAT` -- `include/openssl/x509.h.in:159`.
const XN_FLAG_COMPAT: c_ulong = 0;
/// `X509_FLAG_COMPAT` -- `include/openssl/x509.h.in:137`, `0`.
const X509_FLAG_COMPAT: c_ulong = 0;
/// `XN_FLAG_SEP_MULTILINE` -- `include/openssl/x509.h.in:163`; one field per line.
const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;

/// One `t_acert.c` raise coordinate, declared locally because the unit is not in
/// `gen_err_raise_sites.py`'s covered set (see the module doc).
const fn t_acert_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/t_acert.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `print_attribute`'s zero-attribute-count refusal at `crypto/x509/t_acert.c:32`.
const X509_ACERT_32: ErrSite = t_acert_site(32, c"print_attribute", X509_R_INVALID_ATTRIBUTES);
/// `X509_ACERT_print_ex`'s `err:`-label failure at `crypto/x509/t_acert.c:282`.
const X509_ACERT_282: ErrSite = t_acert_site(282, c"X509_ACERT_print_ex", ERR_R_BUF_LIB);

/// `static int print_attribute(BIO *bp, X509_ATTRIBUTE *a)` -- `crypto/x509/t_acert.c:17-81`.
///
/// One attribute: twelve spaces, the object's `i2a` text, padding to column 25 and a colon, then
/// each value. A string-typed value is written raw and newline-terminated; a `SEQUENCE` is
/// newline-terminated and then dumped with `ASN1_parse_dump` at indent `i` (the *value index*,
/// which the authority passes -- not a fixed indent); anything else prints an `unable to print`
/// line. A zero value count raises `X509_R_INVALID_ATTRIBUTES` and fails.
///
/// # Safety
/// `bp` is a live BIO; `a` is a live `X509_ATTRIBUTE`.
unsafe fn print_attribute(bp: *mut Bio, a: *mut X509Attribute) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `bp` and `a` are live per the contract.
    unsafe {
        let aobj = X509_ATTRIBUTE_get0_object(a);
        if BIO_printf(bp, c"%12s".as_ptr(), c"".as_ptr()) <= 0 {
            return ret;
        }
        let j = i2a_ASN1_OBJECT(bp, aobj);
        if j <= 0 {
            return ret;
        }
        let count = X509_ATTRIBUTE_count(a);
        if count == 0 {
            raise_site(&X509_ACERT_32);
            return ret;
        }
        if j < 25 && BIO_printf(bp, c"%*s".as_ptr(), 25 - j, c" ".as_ptr()) <= 0 {
            return ret;
        }
        if BIO_puts(bp, c":".as_ptr()) <= 0 {
            return ret;
        }

        let mut i: c_int = 0;
        while i < count {
            let at: *mut Asn1Type = X509_ATTRIBUTE_get0_type(a, i);
            let type_ = (*at).type_;
            match type_ {
                V_ASN1_PRINTABLESTRING
                | V_ASN1_T61STRING
                | V_ASN1_NUMERICSTRING
                | V_ASN1_UTF8STRING
                | V_ASN1_IA5STRING => {
                    let bs = (*at).value.ptr.cast::<Asn1String>();
                    if BIO_write(bp, (*bs).data.cast(), (*bs).length) != (*bs).length {
                        return ret;
                    }
                    if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                        return ret;
                    }
                }
                V_ASN1_SEQUENCE => {
                    if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                        return ret;
                    }
                    let seq = (*at).value.ptr.cast::<Asn1String>();
                    if ASN1_parse_dump(bp, (*seq).data, (*seq).length as c_long, i, 1) <= 0 {
                        return ret;
                    }
                }
                _ => {
                    if BIO_printf(
                        bp,
                        c"unable to print attribute of type 0x%X\n".as_ptr(),
                        type_,
                    ) < 0
                    {
                        return ret;
                    }
                }
            }
            i += 1;
        }
        ret = 1;
    }
    ret
}

/// `int X509_ACERT_print_ex(BIO *bp, X509_ACERT *x, unsigned long nmflags, unsigned long cflag)`
/// -- `crypto/x509/t_acert.c:83-284`.
///
/// Every section of the attribute certificate in the authority's order, each gated by its
/// `X509_FLAG_NO_*` bit. The holder section prints its entity names, then the base-certificate
/// identifier's issuer/serial/UID when that is present. Failures raise `ERR_R_BUF_LIB` at the
/// `err:` label (`:282`) and answer 0; the signature-dump arm answers 0 without raising.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_print_ex(
    bp: *mut Bio,
    x: *mut X509Acert,
    nmflags: c_ulong,
    cflag: c_ulong,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let mut mlch: c_int = c_int::from(b' ');
        if (nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE {
            mlch = c_int::from(b'\n');
        }

        if cflag & X509_FLAG_NO_HEADER == 0 {
            if BIO_printf(bp, c"Attribute Certificate:\n".as_ptr()) <= 0 {
                return acert_err();
            }
            if BIO_printf(bp, c"%4sData:\n".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
        }

        if cflag & X509_FLAG_NO_VERSION == 0 {
            let l = X509_ACERT_get_version(x);
            if l == X509_ACERT_VERSION_2 {
                if BIO_printf(
                    bp,
                    c"%8sVersion: %ld (0x%lx)\n".as_ptr(),
                    c"".as_ptr(),
                    l + 1,
                    l as c_ulong,
                ) <= 0
                {
                    return acert_err();
                }
            } else if BIO_printf(bp, c"%8sVersion: Unknown (%ld)\n".as_ptr(), c"".as_ptr(), l) <= 0
            {
                return acert_err();
            }
        }

        if cflag & X509_FLAG_NO_SERIAL == 0 {
            let serial = X509_ACERT_get0_serialNumber(x);
            if BIO_printf(bp, c"%8sSerial Number: ".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
            if i2a_ASN1_INTEGER(bp, serial) <= 0 {
                return acert_err();
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return acert_err();
            }
        }

        if cflag & X509_FLAG_NO_SUBJECT == 0 {
            if BIO_printf(bp, c"%8sHolder:\n".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }

            let holder_entities: *const OpenSslStack = X509_ACERT_get0_holder_entityName(x);
            if !holder_entities.is_null() {
                let n = OPENSSL_sk_num(holder_entities);
                let mut i: c_int = 0;
                while i < n {
                    let entity = OPENSSL_sk_value(holder_entities, i).cast::<GeneralName>();
                    if BIO_printf(bp, c"%12sName:%c".as_ptr(), c"".as_ptr(), mlch) <= 0 {
                        return acert_err();
                    }
                    if GENERAL_NAME_print(bp, entity) <= 0 {
                        return acert_err();
                    }
                    if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                        return acert_err();
                    }
                    i += 1;
                }
            }

            let holder_bcid = X509_ACERT_get0_holder_baseCertId(x);
            let holder_issuer: *const X509Name = if holder_bcid.is_null() {
                ptr::null()
            } else {
                OSSL_ISSUER_SERIAL_get0_issuer(holder_bcid)
            };

            if !holder_issuer.is_null() {
                if BIO_printf(bp, c"%12sIssuer:%c".as_ptr(), c"".as_ptr(), mlch) <= 0 {
                    return acert_err();
                }
                if X509_NAME_print_ex(bp, holder_issuer, 0, nmflags) <= 0 {
                    return acert_err();
                }
                if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                    return acert_err();
                }
                if BIO_printf(bp, c"%12sSerial: ".as_ptr(), c"".as_ptr()) <= 0 {
                    return acert_err();
                }
                let holder_serial = OSSL_ISSUER_SERIAL_get0_serial(holder_bcid);
                if i2a_ASN1_INTEGER(bp, holder_serial) <= 0 {
                    return acert_err();
                }
                let iuid = OSSL_ISSUER_SERIAL_get0_issuerUID(holder_bcid);
                if !iuid.is_null() {
                    if BIO_printf(bp, c"%12sIssuer UID: ".as_ptr(), c"".as_ptr()) <= 0 {
                        return acert_err();
                    }
                    if X509_signature_dump(bp, iuid, 24) <= 0 {
                        return acert_err();
                    }
                }
                if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                    return acert_err();
                }
            }
        }

        if cflag & X509_FLAG_NO_ISSUER == 0 {
            if BIO_printf(bp, c"%8sIssuer:%c".as_ptr(), c"".as_ptr(), mlch) <= 0 {
                return acert_err();
            }
            let issuer = X509_ACERT_get0_issuerName(x);
            if !issuer.is_null() {
                if X509_NAME_print_ex(bp, issuer, 0, nmflags) < 0 {
                    return acert_err();
                }
            } else if BIO_printf(bp, c"Unsupported Issuer Type".as_ptr()) <= 0 {
                return acert_err();
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return acert_err();
            }
        }

        if cflag & X509_FLAG_NO_VALIDITY == 0 {
            if BIO_printf(bp, c"%8sValidity\n".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
            if BIO_printf(bp, c"%12sNot Before: ".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
            if ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notBefore(x)) == 0 {
                return acert_err();
            }
            if BIO_printf(bp, c"\n%12sNot After : ".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
            if ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notAfter(x)) == 0 {
                return acert_err();
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return acert_err();
            }
        }

        if cflag & X509_FLAG_NO_ATTRIBUTES == 0 {
            if BIO_printf(bp, c"%8sAttributes:\n".as_ptr(), c"".as_ptr()) <= 0 {
                return acert_err();
            }
            if X509_ACERT_get_attr_count(x) == 0 {
                if BIO_printf(bp, c"%12s(none)\n".as_ptr(), c"".as_ptr()) <= 0 {
                    return acert_err();
                }
            } else {
                let n = X509_ACERT_get_attr_count(x);
                let mut i: c_int = 0;
                while i < n {
                    if print_attribute(bp, X509_ACERT_get_attr(x, i)) == 0 {
                        return acert_err();
                    }
                    i += 1;
                }
            }
        }

        if cflag & X509_FLAG_NO_EXTENSIONS == 0 {
            let exts: *const OpenSslStack = X509_ACERT_get0_extensions(x);
            if !exts.is_null() {
                if BIO_printf(bp, c"%8sExtensions:\n".as_ptr(), c"".as_ptr()) <= 0 {
                    return acert_err();
                }
                let n = OPENSSL_sk_num(exts);
                let mut i: c_int = 0;
                while i < n {
                    let ex = OPENSSL_sk_value(exts, i).cast::<X509Extension>();
                    if BIO_printf(bp, c"%12s".as_ptr(), c"".as_ptr()) <= 0 {
                        return acert_err();
                    }
                    let obj: *mut Asn1Object = X509_EXTENSION_get_object(ex);
                    if i2a_ASN1_OBJECT(bp, obj) <= 0 {
                        return acert_err();
                    }
                    let critical = X509_EXTENSION_get_critical(ex);
                    let critical_str = if critical != 0 {
                        c"critical".as_ptr()
                    } else {
                        c"".as_ptr()
                    };
                    if BIO_printf(bp, c": %s\n".as_ptr(), critical_str) <= 0 {
                        return acert_err();
                    }
                    if X509V3_EXT_print(bp, ex, cflag, 20) <= 0 {
                        if BIO_printf(bp, c"%16s".as_ptr(), c"".as_ptr()) <= 0 {
                            return acert_err();
                        }
                        if ASN1_STRING_print(bp, X509_EXTENSION_get_data(ex)) <= 0 {
                            return acert_err();
                        }
                    }
                    if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                        return acert_err();
                    }
                    i += 1;
                }
            }
        }

        if cflag & X509_FLAG_NO_SIGDUMP == 0 {
            let mut sig_alg: *const X509Algor = ptr::null();
            let mut sig: *const Asn1String = ptr::null();
            X509_ACERT_get0_signature(x, &raw mut sig, &raw mut sig_alg);
            if X509_signature_print(bp, sig_alg, sig) <= 0 {
                return 0;
            }
        }

        1
    }
}

/// The `err:` label of [`X509_ACERT_print_ex`] (`crypto/x509/t_acert.c:281-283`).
fn acert_err() -> c_int {
    // SAFETY: a compiled-in site coordinate.
    unsafe { raise_site(&X509_ACERT_282) };
    0
}

/// `int X509_ACERT_print(BIO *bp, X509_ACERT *x)` -- `crypto/x509/t_acert.c:286-289`.
///
/// [`X509_ACERT_print_ex`] with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_print(bp: *mut Bio, x: *mut X509Acert) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { X509_ACERT_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT) }
}
