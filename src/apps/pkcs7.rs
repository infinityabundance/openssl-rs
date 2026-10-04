//! Phase 17.1f — `apps/pkcs7.c`: the `openssl pkcs7` command.
//!
//! The whole command body (`apps/pkcs7.c:64-231`): parse the generated
//! `PKCS7_OPTIONS` table, read a `PKCS7` object in PEM or DER
//! ([`PEM_read_bio_PKCS7`]/[`d2i_PKCS7_bio`]), then re-emit it or print its
//! fields (`-print`), the certificates/CRLs it carries (`-print_certs`, with
//! `-quiet` and `-text` variants) or nothing (`-noout`). Every libcrypto function
//! the body reaches is landed: `PKCS7_new_ex`, `PKCS7_print_ctx`, `PKCS7_free`,
//! `PEM_read_bio_PKCS7`, `PEM_write_bio_PKCS7`, `d2i_PKCS7_bio`, `i2d_PKCS7_bio`,
//! `OBJ_obj2nid`, `X509_print`, `X509_CRL_print_ex` and `PEM_write_bio_X509`.
//!
//! ## What the court drives
//!
//! `pkcs7 -in <p7.pem>`, `pkcs7 -print_certs -in <p7.pem>` (and `-quiet`, with
//! `dump_cert_text`'s `subject=`/`issuer=` lines) and `pkcs7 -print -in <p7.pem>`
//! over a fixed PKCS7 blob built from the fixed certificate fixture. The
//! re-encode is a pure function of the fixture, so both sides emit identical
//! bytes.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-engine` is not landed** (`apps/pkcs7.c:116-118`).
//! * **`opt_format(s, OPT_FMT_PEMDER, ...)` is reduced to PEM/DER** (see
//!   [`crate::apps::crl2pkcs7`]'s header for the same shape).
//! * **`bio_open_default` is reduced to its observable**: a `-in`/`-out` that
//!   cannot be opened reaches [`not_landed`] rather than fabricating the
//!   `apps/lib` failure text. The court's fixtures open.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arms reach the unlanded `opt_provider`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong};

use crate::apps::keyio::{bio_open_default, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKCS7_OPTIONS;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::pem::pem_all::{PEM_read_bio_PKCS7, PEM_write_bio_PKCS7};
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::pkcs7::pk7_asn1::{PKCS7_free, PKCS7_new_ex, PKCS7_print_ctx};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio};
use crate::runtime::obj::{NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, OBJ_obj2nid};
use crate::x509::t_crl::X509_CRL_print_ex;
use crate::x509::t_x509::X509_print;
use crate::x509::x509_cmp::{X509_get_issuer_name, X509_get_subject_name};
use crate::x509::x_all::{d2i_PKCS7_bio, i2d_PKCS7_bio};
use crate::x509::x_crl::X509Crl;
use crate::x509::x_x509::X509;

/// `GET_NAMEOPT` — the `print_name` flags `dump_cert_text` uses
/// (`apps/lib/apps.c:199-203`), as [`crate::apps::nseq`] transcribes them.
const GET_NAMEOPT: c_ulong = (2 << 16) | 2 | 0x10 | 0x100 | 0x200;

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms of
/// `apps/lib/opt.c:277-365`.
fn opt_format_pemder(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'P') | Some(b'p') if b.len() == 1 || s == "PEM" || s == "pem" => {
            *result = FORMAT_PEM;
            true
        }
        Some(b'D') | Some(b'd') => {
            *result = FORMAT_ASN1;
            true
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

/// `void dump_cert_text(BIO *out, X509 *x)` — `apps/lib/apps.c:199-203`, via
/// `print_name` with the fixed `get_nameopt` flags.
fn dump_cert_text(out: *mut Bio, x: *const X509) {
    // SAFETY: `x` is a live certificate.
    let subject = unsafe { X509_get_subject_name(x) };
    // SAFETY: `x` is a live certificate.
    let issuer = unsafe { X509_get_issuer_name(x) };
    for (title, nm) in [(c"subject=", subject), (c"issuer=", issuer)] {
        // SAFETY: `out` is live and `title` is a static literal.
        unsafe { BIO_puts(out, title.as_ptr()) };
        // SAFETY: `out` is live and `nm` is a live name or NULL.
        unsafe { X509_NAME_print_ex(out, nm, 0, GET_NAMEOPT) };
        // SAFETY: `out` is live and the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
}

/// `int pkcs7_main(int argc, char **argv)` — `apps/pkcs7.c:64-231`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, PKCS7_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_PEM;
    let mut outformat = FORMAT_PEM;
    let mut print_certs = false;
    let mut text = false;
    let mut noout = false;
    let mut p7_print = false;
    let mut quiet = false;

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ret = 0; goto end;` —
            // `apps/pkcs7.c:83-86`.
            OptMatch::Help => return not_landed("pkcs7 -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/pkcs7.c:78-82`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat)) ...` —
            // `apps/pkcs7.c:87-90`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUTFORM: ... &outformat` — `apps/pkcs7.c:91-94`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg();` — `apps/pkcs7.c:95-97`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg();` — `apps/pkcs7.c:98-100`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_NOOUT: noout = 1;` — `apps/pkcs7.c:101-103`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TEXT: text = 1;` — `apps/pkcs7.c:104-106`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_PRINT: p7_print = 1;` — `apps/pkcs7.c:107-109`.
            OptMatch::Flag("print") => p7_print = true,
            // `case OPT_PRINT_CERTS: print_certs = 1;` — `apps/pkcs7.c:110-112`.
            OptMatch::Flag("print_certs") => print_certs = true,
            // `case OPT_QUIET: quiet = 1;` — `apps/pkcs7.c:113-115`.
            OptMatch::Flag("quiet") => quiet = true,
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0);` — `apps/pkcs7.c:116-118`.
            OptMatch::Value("engine", _) => return not_landed("pkcs7 -engine"),
            // `case OPT_PROV_CASES: ...` — `apps/pkcs7.c:119-122`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkcs7 -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/pkcs7.c:126-128`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `in = bio_open_default(infile, 'r', informat);` — `apps/pkcs7.c:130-132`.
    let inb = bio_open_default(infile.as_deref(), false);
    if inb.is_null() {
        return not_landed("pkcs7 -in (unopenable)");
    }

    // `p7 = PKCS7_new_ex(libctx, app_get0_propq());` — `apps/pkcs7.c:134-139`.
    // SAFETY: the context is NULL and the property query is the unconfigured default.
    let mut p7 = unsafe { PKCS7_new_ex(core::ptr::null_mut(), core::ptr::null()) };
    if p7.is_null() {
        eprintln!("unable to allocate PKCS7 object");
        // SAFETY: `inb` is live and not freed again.
        unsafe { BIO_free(inb) };
        return 1;
    }

    // `p7i = informat == FORMAT_ASN1 ? d2i_PKCS7_bio(in, &p7)
    // : PEM_read_bio_PKCS7(in, &p7, NULL, NULL);` — `apps/pkcs7.c:141-144`.
    // SAFETY: `inb` is live; `p7` is a live out-slot; cb/arg are the no-password arms.
    let p7i = unsafe {
        if informat == FORMAT_ASN1 {
            d2i_PKCS7_bio(inb, core::ptr::addr_of_mut!(p7))
        } else {
            PEM_read_bio_PKCS7(
                inb,
                core::ptr::addr_of_mut!(p7),
                None,
                core::ptr::null_mut(),
            )
        }
    };
    if p7i.is_null() {
        eprintln!("unable to load PKCS7 object");
        // SAFETY: all three are live and not freed again.
        unsafe {
            PKCS7_free(p7);
            BIO_free(inb);
        }
        return 1;
    }
    p7 = p7i;

    // `out = bio_open_default(outfile, 'w', outformat);` — `apps/pkcs7.c:151-153`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: all three are live and not freed again.
        unsafe {
            PKCS7_free(p7);
            BIO_free(inb);
        }
        return 1;
    }

    // `if (p7_print) PKCS7_print_ctx(out, p7, 0, NULL);` — `apps/pkcs7.c:155-156`.
    if p7_print {
        // SAFETY: `out`/`p7` are live; the print context is NULL.
        unsafe { PKCS7_print_ctx(out, p7, 0, core::ptr::null()) };
    }

    // `if (print_certs) { ... }` — `apps/pkcs7.c:158-211`.
    if print_certs {
        // SAFETY: `p7` is live.
        let mut certs: *mut crate::runtime::stack::OpenSslStack = core::ptr::null_mut();
        // SAFETY: `p7` is live.
        let mut crls: *mut crate::runtime::stack::OpenSslStack = core::ptr::null_mut();
        // SAFETY: `p7` is live and its `type_` is a live object.
        let i = unsafe { OBJ_obj2nid((*p7).type_) };
        if i == NID_pkcs7_signed {
            // SAFETY: `p7` is a signed-data object on this arm.
            if !unsafe { (*p7).d.sign }.is_null() {
                // SAFETY: the signed-data field is live.
                certs = unsafe { (*(*p7).d.sign).cert };
                // SAFETY: as above.
                crls = unsafe { (*(*p7).d.sign).crl };
            }
        } else if i == NID_pkcs7_signedAndEnveloped {
            // SAFETY: `p7` is a signed-and-enveloped object on this arm.
            if !unsafe { (*p7).d.signed_and_enveloped }.is_null() {
                // SAFETY: the field is live.
                certs = unsafe { (*(*p7).d.signed_and_enveloped).cert };
                // SAFETY: as above.
                crls = unsafe { (*(*p7).d.signed_and_enveloped).crl };
            }
        }

        if !certs.is_null() {
            // `for (i = 0; i < sk_X509_num(certs); i++) { ... }` — `apps/pkcs7.c:183-193`.
            // SAFETY: `certs` is a live stack of `X509`.
            let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(certs) };
            for idx in 0..n {
                // SAFETY: `certs` is live and `idx` is in range.
                let x =
                    unsafe { crate::runtime::stack::OPENSSL_sk_value(certs, idx) }.cast::<X509>();
                if text {
                    // SAFETY: `out`/`x` are live.
                    unsafe { X509_print(out, x) };
                } else if !quiet {
                    dump_cert_text(out, x);
                }
                if !noout {
                    // SAFETY: `out`/`x` are live.
                    unsafe { PEM_write_bio_X509(out, x) };
                }
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
        }
        if !crls.is_null() {
            // `for (i = 0; i < sk_X509_CRL_num(crls); i++) { ... }` — `apps/pkcs7.c:195-207`.
            // SAFETY: `crls` is a live stack of `X509_CRL`.
            let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(crls) };
            for idx in 0..n {
                // SAFETY: `crls` is live and `idx` is in range.
                let crl =
                    unsafe { crate::runtime::stack::OPENSSL_sk_value(crls, idx) }.cast::<X509Crl>();
                // SAFETY: `out`/`crl` are live.
                unsafe { X509_CRL_print_ex(out, crl, GET_NAMEOPT) };
                if !noout {
                    // SAFETY: `out`/`crl` are live.
                    unsafe { crate::pem::pem_all::PEM_write_bio_X509_CRL(out, crl) };
                }
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
        }

        // SAFETY: all three are live and not freed again.
        unsafe {
            PKCS7_free(p7);
            BIO_free(inb);
            BIO_free_all(out);
        }
        return 0;
    }

    // `if (!noout) { ... }` — `apps/pkcs7.c:213-224`.
    if !noout {
        let i = if outformat == FORMAT_ASN1 {
            // SAFETY: `out`/`p7` are live.
            unsafe { i2d_PKCS7_bio(out, p7) }
        } else {
            // SAFETY: `out`/`p7` are live.
            unsafe { PEM_write_bio_PKCS7(out, p7) }
        };
        if i == 0 {
            eprintln!("unable to write pkcs7 object");
            // SAFETY: all three are live and not freed again.
            unsafe {
                PKCS7_free(p7);
                BIO_free(inb);
                BIO_free_all(out);
            }
            return 1;
        }
    }

    // SAFETY: all three are live and not freed again.
    unsafe {
        PKCS7_free(p7);
        BIO_free(inb);
        BIO_free_all(out);
    }
    0
}
