//! `crypto/x509/t_crl.c` -- the `X509_CRL` printer. Phase 11.4.
//!
//! The unit is 99 lines and defines **three exports and no internals**: [`X509_CRL_print_fp`]
//! (`:19-32`, inside `#ifndef OPENSSL_NO_STDIO`), the printer it wraps, [`X509_CRL_print_ex`]
//! (`:40-99`), and the default spelling [`X509_CRL_print`] (`:35-38`). All three land here --
//! every callee is already the crate's, so there is nothing withheld.
//!
//! Unlike the certificate and request printers, `X509_CRL_print_ex` checks almost nothing: it
//! writes the header, version, TBS signature, issuer, last and next update, the CRL extensions,
//! the revoked-entry list (each entry's serial, revocation date and extensions) and the outer
//! signature, and answers 1 unconditionally. A multiline `nmflag` sets the issuer indent to 8.
//!
//! ## The raise
//!
//! One: `X509_CRL_print_fp`'s BIO-creation failure at `:25` (`ERR_LIB_X509`/`ERR_R_BUF_LIB`).
//! The unit is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the coordinate is
//! declared here in the crate's `ErrSite` idiom.
//!
//! ## The court
//!
//! `RT-X509-REQ` (`courts/phase11/rt_x509_req_probe.c`) drives all three over the fixed CRL DER,
//! prints each writer's exact bytes to a memory BIO or a controlled `tmpfile()` and compares them
//! to the authority's. No address is printed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::asn1::layout::Asn1String;
use crate::asn1::text::i2a_ASN1_INTEGER;
use crate::asn1::time::ASN1_TIME_print;
use crate::asn1::x_algor::X509Algor;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::t_x509::X509_signature_print;
use crate::x509::v3_prn::X509V3_extensions_print;
use crate::x509::x509cset::{
    X509_CRL_get0_extensions, X509_CRL_get0_lastUpdate, X509_CRL_get0_nextUpdate,
    X509_CRL_get0_signature, X509_CRL_get_REVOKED, X509_CRL_get_issuer, X509_CRL_get_version,
    X509_REVOKED_get0_extensions, X509_REVOKED_get0_revocationDate, X509_REVOKED_get0_serialNumber,
};
use crate::x509::x_crl::{X509Crl, X509Revoked};

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BUF_LIB` -- `include/openssl/err.h.in:323`, `ERR_LIB_BUF | ERR_RFLAG_COMMON`.
const ERR_R_BUF_LIB: c_int = 524295;

/// `XN_FLAG_SEP_MASK` -- `include/openssl/x509.h.in:157`, the separator group selector.
const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
/// `XN_FLAG_COMPAT` -- `include/openssl/x509.h.in:159`; selects the old `X509_NAME_print`.
const XN_FLAG_COMPAT: c_ulong = 0;
/// `XN_FLAG_SEP_MULTILINE` -- `include/openssl/x509.h.in:163`; one field per line.
const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;

/// `X509_CRL_VERSION_1` -- `include/openssl/x509.h.in:735`, `0`.
const X509_CRL_VERSION_1: c_long = 0;
/// `X509_CRL_VERSION_2` -- `include/openssl/x509.h.in:736`, `1`.
const X509_CRL_VERSION_2: c_long = 1;

/// `X509_CRL_print_fp`'s BIO-creation failure at `crypto/x509/t_crl.c:25`, `ERR_R_BUF_LIB`.
const X509_CRL_PRINT_FP_25: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/t_crl.c",
    line: 25,
    func: c"X509_CRL_print_fp",
    lib: ERR_LIB_X509,
    reason: ERR_R_BUF_LIB,
    dynamic_reason: false,
};

/// `int X509_CRL_print_fp(FILE *fp, X509_CRL *x)` -- `crypto/x509/t_crl.c:19-32`.
///
/// The whole body sits inside `#ifndef OPENSSL_NO_STDIO`, which holds on this profile: wrap `fp`
/// in a no-close `BIO_s_file` BIO and print through [`X509_CRL_print`]. A BIO that cannot be made
/// raises `ERR_R_BUF_LIB` at `:25` and answers 0.
///
/// # Safety
///
/// `fp` is a live writable stream; `x` is a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_print_fp(fp: *mut c_void, x: *mut X509Crl) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&X509_CRL_PRINT_FP_25);
            return 0;
        }
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp);
        let ret = X509_CRL_print(b, x);
        BIO_free(b);
        ret
    }
}

/// `int X509_CRL_print(BIO *out, X509_CRL *x)` -- `crypto/x509/t_crl.c:35-38`.
///
/// [`X509_CRL_print_ex`] with `XN_FLAG_COMPAT`.
///
/// # Safety
///
/// `out` is a live BIO; `x` is a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_print(out: *mut Bio, x: *mut X509Crl) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe { X509_CRL_print_ex(out, x, XN_FLAG_COMPAT) }
}

/// `int X509_CRL_print_ex(BIO *out, X509_CRL *x, unsigned long nmflag)` --
/// `crypto/x509/t_crl.c:40-99`.
///
/// The CRL printer. A multiline separator sets the issuer indent to 8. The authority checks no
/// return value and answers 1 on every path.
///
/// # Safety
///
/// `out` is a live BIO; `x` is a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_print_ex(
    out: *mut Bio,
    x: *mut X509Crl,
    nmflag: c_ulong,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let mut mlch: c_int = c_int::from(b' ');
        let mut nmindent: c_int = 0;

        if (nmflag & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE {
            mlch = c_int::from(b'\n');
            nmindent = 8;
        }

        BIO_printf(out, c"Certificate Revocation List (CRL):\n".as_ptr());
        let l = X509_CRL_get_version(x);
        if (X509_CRL_VERSION_1..=X509_CRL_VERSION_2).contains(&l) {
            BIO_printf(
                out,
                c"%4sVersion %ld (0x%lx)\n".as_ptr(),
                c"".as_ptr(),
                l + 1,
                l as c_ulong,
            );
        } else {
            BIO_printf(out, c"%4sVersion unknown (%ld)\n".as_ptr(), c"".as_ptr(), l);
        }
        let mut sig_alg: *const X509Algor = ptr::null();
        let mut sig: *const Asn1String = ptr::null();
        X509_CRL_get0_signature(x, &raw mut sig, &raw mut sig_alg);
        X509_signature_print(out, sig_alg, ptr::null());
        BIO_printf(out, c"%4sIssuer:%c".as_ptr(), c"".as_ptr(), mlch);
        X509_NAME_print_ex(out, X509_CRL_get_issuer(x), nmindent, nmflag);
        BIO_puts(out, c"\n".as_ptr());
        BIO_printf(out, c"%4sLast Update: ".as_ptr(), c"".as_ptr());
        ASN1_TIME_print(out, X509_CRL_get0_lastUpdate(x));
        BIO_printf(out, c"\n%4sNext Update: ".as_ptr(), c"".as_ptr());
        if !X509_CRL_get0_nextUpdate(x).is_null() {
            ASN1_TIME_print(out, X509_CRL_get0_nextUpdate(x));
        } else {
            BIO_printf(out, c"NONE".as_ptr());
        }
        BIO_printf(out, c"\n".as_ptr());

        X509V3_extensions_print(
            out,
            c"CRL extensions".as_ptr(),
            X509_CRL_get0_extensions(x),
            0,
            4,
        );

        let rev = X509_CRL_get_REVOKED(x);

        if OPENSSL_sk_num(rev) > 0 {
            BIO_printf(out, c"Revoked Certificates:\n".as_ptr());
        } else {
            BIO_printf(out, c"No Revoked Certificates.\n".as_ptr());
        }

        let n = OPENSSL_sk_num(rev);
        let mut i: c_int = 0;
        while i < n {
            let r = OPENSSL_sk_value(rev, i).cast::<X509Revoked>();
            BIO_printf(out, c"    Serial Number: ".as_ptr());
            i2a_ASN1_INTEGER(out, X509_REVOKED_get0_serialNumber(r));
            BIO_printf(out, c"\n        Revocation Date: ".as_ptr());
            ASN1_TIME_print(out, X509_REVOKED_get0_revocationDate(r));
            BIO_printf(out, c"\n".as_ptr());
            X509V3_extensions_print(
                out,
                c"CRL entry extensions".as_ptr(),
                X509_REVOKED_get0_extensions(r),
                0,
                8,
            );
            i += 1;
        }
        X509_signature_print(out, sig_alg, sig);

        1
    }
}
