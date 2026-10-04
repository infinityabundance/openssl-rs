//! Phase 17.1 — `apps/crl2pkcs7.c`: the `openssl crl2pkcs7` command.
//!
//! The whole command body (`apps/crl2pkcs7.c:54-188`): parse the generated
//! `CRL2PKCS7_OPTIONS` table, optionally load a CRL (`apps/crl2pkcs7.c:114-128`),
//! build a `PKCS7` signed-data object whose content is an empty `NID_pkcs7_data`
//! and whose `crl`/`cert` stacks hold the loaded CRL and the certificates read by
//! `add_certs_from_file` (`apps/crl2pkcs7.c:200-241`), then write it in PEM or
//! DER. Every libcrypto function the body reaches is landed: `PKCS7_new`,
//! `PKCS7_SIGNED_new`, `OBJ_nid2obj`, `ASN1_INTEGER_set`, `PKCS7_free`,
//! `PEM_X509_INFO_read_bio`, `X509_INFO_free`, `i2d_PKCS7_bio`,
//! `PEM_write_bio_PKCS7`, `PEM_read_bio_X509_CRL`, `d2i_X509_CRL_bio` and the
//! `OPENSSL_sk_*` stack accessors.
//!
//! ## What the court drives
//!
//! `crl2pkcs7 -nocrl -certfile <certs.pem>` (PEM) over the fixed certificate
//! fixture. The re-encoded PKCS7 is a pure function of the fixture certificate and
//! the fixed `signedData` skeleton, so both sides emit identical bytes. The
//! `-outform DER` arm was verified byte-identical too but is not in the probe: the
//! transcript harness decodes each side's output as UTF-8 text, so a binary arm
//! cannot be diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **`opt_format` is reduced to its observable.** The authority parses
//!   `-inform`/`-outform` through `opt_format` (`apps/lib/opt.c:277-365`) with
//!   `OPT_FMT_PEMDER`; this module transcribes the PEM/DER arms and their
//!   `Bad format` messages rather than the whole `OPT_FMT_*` table.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::configutl`]'s header for the same shape). A `-in`/`-out` that
//!   cannot be opened is an `apps/lib` failure arm and reaches [`not_landed`].
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/crl2pkcs7.c:103-106`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CRL2PKCS7_OPTIONS;
use crate::asn1::prim::ASN1_INTEGER_set;
use crate::asn1::x_info::{X509Info, X509_INFO_free};
use crate::pem::pem_all::{PEM_read_bio_X509_CRL, PEM_write_bio_PKCS7};
use crate::pem::pem_info::PEM_X509_INFO_read_bio;
use crate::pkcs7::pk7_asn1::{PKCS7_SIGNED_new, PKCS7_free, PKCS7_new};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio, BIO_NOCLOSE};
use crate::runtime::obj::{NID_pkcs7_data, NID_pkcs7_signed, OBJ_nid2obj};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_shift, OpenSslStack,
};
use crate::x509::x_all::{d2i_X509_CRL_bio, i2d_PKCS7_bio};
use crate::x509::x_crl::{X509Crl, X509_CRL_free};

/// `FORMAT_ASN1` — `apps/include/fmt.h:27`.
const FORMAT_ASN1: c_int = 4;
/// `FORMAT_PEM` — `apps/include/fmt.h:29`.
const FORMAT_PEM: c_int = 5 | 0x8000;

/// `bio_open_default(filename, mode, format)` — `apps/lib/apps.c:3264-3267`, the
/// stdio/file split (see the header).
fn bio_open(filename: Option<&str>, writing: bool) -> *mut Bio {
    match filename {
        None | Some("-") => {
            // SAFETY: `stdout`/`stdin` are the C library's live standard stream pointers.
            let fp = unsafe {
                if writing {
                    stdout
                } else {
                    stdin
                }
            };
            // SAFETY: `fp` is one of the C library's live standard streams.
            unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) }
        }
        Some(path) => {
            let cs = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return core::ptr::null_mut(),
            };
            let mode = if writing { c"w" } else { c"r" };
            // SAFETY: `cs` is NUL-terminated and outlives the call.
            unsafe { BIO_new_file(cs.as_ptr(), mode.as_ptr()) }
        }
    }
}

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`, `D` and `default` arms of
/// `apps/lib/opt.c:277-365`, with `OPT_FMT_PEMDER` (`OPT_FMT_PEM | OPT_FMT_DER`).
/// Returns the authority's 0/1 and prints its refusal text to stderr.
fn opt_format_pemder(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'P') | Some(b'p') => {
            if b.len() == 1 || s == "PEM" || s == "pem" {
                *result = FORMAT_PEM;
                true
            } else {
                // `P` with any other body falls to the `Bad format` arm unless it
                // names PVK/P12/PKCS12, none of which `OPT_FMT_PEMDER` admits.
                eprintln!("{prog}: Bad format \"{s}\"");
                false
            }
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

/// `static int add_certs_from_file(STACK_OF(X509) *stack, char *certfile)` —
/// `apps/crl2pkcs7.c:200-241`. Returns the number of certificates added, or -1.
fn add_certs_from_file(stack: *mut OpenSslStack, certfile: &str) -> c_int {
    let cs = match std::ffi::CString::new(certfile) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    // `in = BIO_new_file(certfile, "r");` — `apps/crl2pkcs7.c:208`.
    // SAFETY: `cs` is NUL-terminated and outlives the call.
    let inb = unsafe { BIO_new_file(cs.as_ptr(), c"r".as_ptr()) };
    if inb.is_null() {
        // `BIO_printf(bio_err, "error opening the file, %s\n", certfile);` —
        // `apps/crl2pkcs7.c:210-211`.
        eprintln!("error opening the file, {certfile}");
        return -1;
    }

    // `sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);` —
    // `apps/crl2pkcs7.c:215`.
    // SAFETY: `inb` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let sk =
        unsafe { PEM_X509_INFO_read_bio(inb, core::ptr::null_mut(), None, core::ptr::null_mut()) };
    let mut ret = -1;
    if sk.is_null() {
        // `BIO_printf(bio_err, "error reading the file, %s\n", certfile);` —
        // `apps/crl2pkcs7.c:217-218`.
        eprintln!("error reading the file, {certfile}");
    } else {
        let mut count = 0;
        // `while (sk_X509_INFO_num(sk)) { xi = sk_X509_INFO_shift(sk); ... }` —
        // `apps/crl2pkcs7.c:222-233`.
        // SAFETY: `sk` is a live stack of `X509_INFO`.
        while unsafe { OPENSSL_sk_num(sk) } != 0 {
            // SAFETY: `sk` is live and non-empty.
            let xi = unsafe { OPENSSL_sk_shift(sk) }.cast::<X509Info>();
            // SAFETY: `xi` is a live `X509_INFO` just shifted off the stack.
            let x509 = unsafe { (*xi).x509 };
            if !x509.is_null() {
                // SAFETY: `stack` is a live stack of `X509`; `xi` is live.
                if unsafe { OPENSSL_sk_push(stack, x509.cast::<c_void>()) } == 0 {
                    // SAFETY: `xi` is live and uniquely owned here.
                    unsafe { X509_INFO_free(xi) };
                    // SAFETY: `inb`/`sk` are live and not freed again below.
                    unsafe { BIO_free(inb) };
                    // SAFETY: `inb`/`sk` are live and not freed again below.
                    unsafe { crate::runtime::stack::OPENSSL_sk_free(sk) };
                    return -1;
                }
                // `xi->x509 = NULL;` — `apps/crl2pkcs7.c:229`.
                // SAFETY: `xi` is live and uniquely owned here.
                unsafe { (*xi).x509 = core::ptr::null_mut() };
                count += 1;
            }
            // `X509_INFO_free(xi);` — `apps/crl2pkcs7.c:232`.
            // SAFETY: `xi` is live and uniquely owned here.
            unsafe { X509_INFO_free(xi) };
        }
        ret = count;
        // SAFETY: `sk` is empty and live.
        unsafe { crate::runtime::stack::OPENSSL_sk_free(sk) };
    }

    // `end: BIO_free(in); ...` — `apps/crl2pkcs7.c:236-239`.
    // SAFETY: `inb` is live and not freed again.
    unsafe { BIO_free(inb) };
    ret
}

/// `int crl2pkcs7_main(int argc, char **argv)` — `apps/crl2pkcs7.c:54-188`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, crl2pkcs7_options);` — `apps/crl2pkcs7.c:67`.
    let mut opts = Opts::init(argv, CRL2PKCS7_OPTIONS);
    let mut ret = 1i32;
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_PEM;
    let mut outformat = FORMAT_PEM;
    let mut nocrl = false;
    // `STACK_OF(OPENSSL_STRING) *certflst = NULL;` — `apps/crl2pkcs7.c:59`; the
    // `-certfile` values, kept as a Rust `Vec` because the body only iterates them.
    let mut certflst: Vec<String> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/crl2pkcs7.c:68`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(crl2pkcs7_options); ret = 0; goto end;` —
            // `apps/crl2pkcs7.c:75-78`.
            OptMatch::Help => return not_landed("crl2pkcs7 -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/crl2pkcs7.c:72-74`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &informat)) goto opthelp;` — `apps/crl2pkcs7.c:79-82`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    return 1;
                }
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &outformat)) goto opthelp;` — `apps/crl2pkcs7.c:83-86`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/crl2pkcs7.c:87-89`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/crl2pkcs7.c:90-92`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_NOCRL: nocrl = 1; break;` — `apps/crl2pkcs7.c:93-95`.
            OptMatch::Flag("nocrl") => nocrl = true,
            // `case OPT_CERTFILE: ... sk_OPENSSL_STRING_push(certflst, opt_arg());`
            // — `apps/crl2pkcs7.c:96-102`.
            OptMatch::Value("certfile", v) => certflst.push(v),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/crl2pkcs7.c:103-106`. `opt_provider` is unlanded.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("crl2pkcs7 -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/crl2pkcs7.c:111-112`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    let mut crl: *mut X509Crl = core::ptr::null_mut();
    let mut inb: *mut Bio = core::ptr::null_mut();
    if !nocrl {
        // `in = bio_open_default(infile, 'r', informat); if (in == NULL) goto
        // end;` — `apps/crl2pkcs7.c:115-117`.
        inb = bio_open(infile.as_deref(), false);
        if inb.is_null() {
            return not_landed("crl2pkcs7 -in (unopenable)");
        }

        // `if (informat == FORMAT_ASN1) crl = d2i_X509_CRL_bio(in, NULL); else if
        // (informat == FORMAT_PEM) crl = PEM_read_bio_X509_CRL(in, NULL, NULL,
        // NULL);` — `apps/crl2pkcs7.c:119-122`.
        crl = if informat == FORMAT_ASN1 {
            // SAFETY: `inb` is live; the out-slot is NULL.
            unsafe { d2i_X509_CRL_bio(inb, core::ptr::null_mut()) }
        } else {
            // SAFETY: `inb` is live; the out-slot is NULL and cb/arg are NULL.
            unsafe {
                PEM_read_bio_X509_CRL(inb, core::ptr::null_mut(), None, core::ptr::null_mut())
            }
        };
        if crl.is_null() {
            // `BIO_printf(bio_err, "unable to load CRL\n");
            // ERR_print_errors(bio_err);` — `apps/crl2pkcs7.c:123-127`. Not driven:
            // the error queue renders pointer-bearing lines.
            eprintln!("unable to load CRL");
            // SAFETY: `inb` is live and not freed again.
            unsafe { BIO_free(inb) };
            return ret;
        }
    }

    // `if ((p7 = PKCS7_new()) == NULL) goto end;` — `apps/crl2pkcs7.c:130-131`.
    let p7 = PKCS7_new();
    if p7.is_null() {
        // SAFETY: `inb`/`crl` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { X509_CRL_free(crl) };
        return ret;
    }
    // `if ((p7s = PKCS7_SIGNED_new()) == NULL) goto end;` — `apps/crl2pkcs7.c:132-133`.
    let p7s = PKCS7_SIGNED_new();
    if p7s.is_null() {
        // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
        unsafe { PKCS7_free(p7) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { X509_CRL_free(crl) };
        return ret;
    }
    // `p7->type = OBJ_nid2obj(NID_pkcs7_signed);` — `apps/crl2pkcs7.c:134`.
    // SAFETY: `p7` is live and uniquely owned.
    unsafe { (*p7).type_ = OBJ_nid2obj(NID_pkcs7_signed) };
    // `p7->d.sign = p7s;` — `apps/crl2pkcs7.c:135`.
    // SAFETY: `p7` is live; the `sign` union arm is the selected one.
    unsafe { (*p7).d.sign = p7s };
    // `p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);` — `apps/crl2pkcs7.c:136`.
    // SAFETY: `p7s` is live and its `contents` item was built by the template.
    unsafe { (*(*p7s).contents).type_ = OBJ_nid2obj(NID_pkcs7_data) };

    // `if (!ASN1_INTEGER_set(p7s->version, 1)) goto end;` — `apps/crl2pkcs7.c:138-139`.
    // SAFETY: `p7s` is live and its `version` slot is live.
    if unsafe { ASN1_INTEGER_set((*p7s).version, 1) } == 0 {
        // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
        unsafe { PKCS7_free(p7) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { X509_CRL_free(crl) };
        return ret;
    }

    if !crl.is_null() {
        // `if ((crl_stack = sk_X509_CRL_new_null()) == NULL) goto end;` —
        // `apps/crl2pkcs7.c:142-143`.
        // SAFETY: the stack is type-erased; no element free function is attached.
        let crl_stack = OPENSSL_sk_new_null();
        if crl_stack.is_null() {
            // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
            unsafe { PKCS7_free(p7) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { BIO_free(inb) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { X509_CRL_free(crl) };
            return ret;
        }
        // `p7s->crl = crl_stack;` — `apps/crl2pkcs7.c:144`.
        // SAFETY: `p7s` is live.
        unsafe { (*p7s).crl = crl_stack };
        // `if (!sk_X509_CRL_push(crl_stack, crl)) goto end;` —
        // `apps/crl2pkcs7.c:146-147`.
        // SAFETY: `crl_stack` is live and `crl` is live.
        if unsafe { OPENSSL_sk_push(crl_stack, crl.cast::<c_void>()) } == 0 {
            // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
            unsafe { PKCS7_free(p7) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { BIO_free(inb) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { X509_CRL_free(crl) };
            return ret;
        }
        // `crl = NULL; /* now part of p7 for OPENSSL_freeing */` —
        // `apps/crl2pkcs7.c:148`.
        crl = core::ptr::null_mut();
    }

    if !certflst.is_empty() {
        // `if ((cert_stack = sk_X509_new_null()) == NULL) goto end;` —
        // `apps/crl2pkcs7.c:152-153`.
        // SAFETY: the stack is type-erased; no element free function is attached.
        let cert_stack = OPENSSL_sk_new_null();
        if cert_stack.is_null() {
            // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
            unsafe { PKCS7_free(p7) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { BIO_free(inb) };
            // SAFETY: `inb`/`crl` are live.
            unsafe { X509_CRL_free(crl) };
            return ret;
        }
        // `p7s->cert = cert_stack;` — `apps/crl2pkcs7.c:154`.
        // SAFETY: `p7s` is live.
        unsafe { (*p7s).cert = cert_stack };

        // `for (i = 0; i < sk_OPENSSL_STRING_num(certflst); i++) { certfile =
        // sk_OPENSSL_STRING_value(certflst, i); if (add_certs_from_file(cert_stack,
        // certfile) < 0) { ... goto end; } }` — `apps/crl2pkcs7.c:156-163`.
        for certfile in &certflst {
            if add_certs_from_file(cert_stack, certfile) < 0 {
                // `BIO_printf(bio_err, "error loading certificates\n");
                // ERR_print_errors(bio_err);` — `apps/crl2pkcs7.c:159-161`. Not
                // driven: the error queue renders pointer-bearing lines.
                eprintln!("error loading certificates");
                // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
                unsafe { PKCS7_free(p7) };
                // SAFETY: `inb`/`crl` are live.
                unsafe { BIO_free(inb) };
                // SAFETY: `inb`/`crl` are live.
                unsafe { X509_CRL_free(crl) };
                return ret;
            }
        }
    }

    // `out = bio_open_default(outfile, 'w', outformat); if (out == NULL) goto
    // end;` — `apps/crl2pkcs7.c:166-168`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `p7` is live and uniquely owned; `inb`/`crl` are live.
        unsafe { PKCS7_free(p7) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`crl` are live.
        unsafe { X509_CRL_free(crl) };
        return not_landed("crl2pkcs7 -out (unopenable)");
    }

    // `if (outformat == FORMAT_ASN1) i = i2d_PKCS7_bio(out, p7); else if
    // (outformat == FORMAT_PEM) i = PEM_write_bio_PKCS7(out, p7);` —
    // `apps/crl2pkcs7.c:170-173`.
    let i = if outformat == FORMAT_ASN1 {
        // SAFETY: `out` and `p7` are live.
        unsafe { i2d_PKCS7_bio(out, p7) }
    } else {
        // SAFETY: `out` and `p7` are live.
        unsafe { PEM_write_bio_PKCS7(out, p7) }
    };
    if i == 0 {
        // `BIO_printf(bio_err, "unable to write pkcs7 object\n");
        // ERR_print_errors(bio_err);` — `apps/crl2pkcs7.c:174-177`. Not driven.
        eprintln!("unable to write pkcs7 object");
        // SAFETY: `p7` is live and uniquely owned; `inb`/`out` are live.
        unsafe { PKCS7_free(p7) };
        // SAFETY: `inb` is live.
        unsafe { BIO_free(inb) };
        // SAFETY: `out` is live and not freed again.
        unsafe { BIO_free_all(out) };
        // SAFETY: `crl` is NULL or live.
        unsafe { X509_CRL_free(crl) };
        return ret;
    }
    // `ret = 0;` — `apps/crl2pkcs7.c:179`.
    ret = 0;

    // `end: sk_OPENSSL_STRING_free(certflst); BIO_free(in); BIO_free_all(out);
    // PKCS7_free(p7); X509_CRL_free(crl);` — `apps/crl2pkcs7.c:180-185`.
    // SAFETY: `inb` is NULL or live and not freed again.
    unsafe { BIO_free(inb) };
    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free_all(out) };
    // SAFETY: `p7` is live and not freed again.
    unsafe { PKCS7_free(p7) };
    // SAFETY: `crl` is NULL or live and not freed again.
    unsafe { X509_CRL_free(crl) };
    ret
}
