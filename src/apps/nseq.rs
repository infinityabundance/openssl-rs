//! Phase 17.1 — `apps/nseq.c`: the `openssl nseq` command.
//!
//! The whole command body (`apps/nseq.c:40-131`): parse the generated
//! `NSEQ_OPTIONS` table, then either read a list of certificates from a PEM and
//! write a `NETSCAPE_CERT_SEQUENCE` (`-toseq`, `apps/nseq.c:88-109`) or read a
//! sequence and dump each certificate's subject/issuer text followed by its PEM
//! (`apps/nseq.c:111-124`). `dump_cert_text` (`apps/lib/apps.c:199-203`) calls
//! `print_name` (`apps/lib/apps.c:1375-1401`) with `get_nameopt`'s flag value.
//!
//! ## What the court drives
//!
//! A fixed single-certificate PEM fixture for `-toseq` (the re-encoded sequence
//! is build-independent) and a fixed sequence fixture for the read arm. Every
//! libcrypto function the body reaches is landed: `PEM_read_bio_X509`,
//! `PEM_write_bio_X509`, `PEM_read_bio_NETSCAPE_CERT_SEQUENCE`,
//! `PEM_write_bio_NETSCAPE_CERT_SEQUENCE`, the `OPENSSL_sk_*` stack accessors and
//! `X509_NAME_print_ex`.
//!
//! ## Recorded divergences (module header)
//!
//! * **`dump_cert_text`/`print_name` are reduced to their observable.** The
//!   authority's `print_name` has three shapes selected by the name flags
//!   (`XN_FLAG_COMPAT`, `XN_FLAG_SEP_MULTILINE`, otherwise); `get_nameopt`
//!   (`apps/lib/apps.c:185-190`) always returns the non-multiline,
//!   non-`COMPAT` flags, so this module transcribes that one shape with the flag
//!   value `XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN | ASN1_STRFLGS_ESC_CTRL |
//!   ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_DUMP_UNKNOWN | ASN1_STRFLGS_DUMP_DER`.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::pkeyparam`]'s header for the same shape).
//! * **The decode-failure arms are not driven.** `nseq -in <non-sequence>`
//!   prints `Error reading sequence file ...` and then `ERR_print_errors`, whose
//!   lines begin with a per-run pointer (`apps/nseq.c:113-115`); the authority's
//!   own output is not deterministic, so the court cannot diff it. The message is
//!   transcribed; the error queue is the `ERR` surface's.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/nseq.c:70-73`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_ulong, c_void};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::NSEQ_OPTIONS;
use crate::asn1::nsseq::{NETSCAPE_CERT_SEQUENCE_free, NETSCAPE_CERT_SEQUENCE_new};
use crate::pem::pem_all::{
    PEM_read_bio_NETSCAPE_CERT_SEQUENCE, PEM_write_bio_NETSCAPE_CERT_SEQUENCE,
};
use crate::pem::pem_x509::{PEM_read_bio_X509, PEM_write_bio_X509};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio, BIO_NOCLOSE};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::x509_cmp::{X509_get_issuer_name, X509_get_subject_name};
use crate::x509::x_x509::X509;

/// `get_nameopt()` — `apps/lib/apps.c:185-190`, with
/// `nmflag_set == 0`, the value the command's fixed path uses.
const GET_NAMEOPT: c_ulong = (2 << 16) | 2 | 0x10 | 0x100 | 0x200;

/// `bio_open_default(filename, mode, format)` — `apps/lib/apps.c:3264-3267`, the
/// stdio/file split.
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

/// `void dump_cert_text(BIO *out, X509 *x)` — `apps/lib/apps.c:199-203`, via
/// `print_name` (`apps/lib/apps.c:1375-1401`) with the fixed `get_nameopt` flags.
fn dump_cert_text(out: *mut Bio, x: *const X509) {
    // SAFETY: `x` is a live certificate.
    let subject = unsafe { X509_get_subject_name(x) };
    // SAFETY: `x` is a live certificate.
    let issuer = unsafe { X509_get_issuer_name(x) };
    for (title, nm) in [(c"subject=", subject), (c"issuer=", issuer)] {
        // `BIO_puts(out, title);` — `apps/lib/apps.c:1385-1386`.
        // SAFETY: `out` is live and `title` is a static literal.
        unsafe { BIO_puts(out, title.as_ptr()) };
        // `X509_NAME_print_ex(out, nm, indent, lflags);` — the non-multiline,
        // non-`COMPAT` arm (`apps/lib/apps.c:1396-1397`); `indent` is 0.
        // SAFETY: `out` is live and `nm` is a live name or NULL.
        unsafe { crate::asn1::a_strex::X509_NAME_print_ex(out, nm, 0, GET_NAMEOPT) };
        // `BIO_puts(out, "\n");` — `apps/lib/apps.c:1398`.
        // SAFETY: `out` is live and the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
}

/// `int nseq_main(int argc, char **argv)` — `apps/nseq.c:40-131`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, nseq_options);` — `apps/nseq.c:49`.
    let mut opts = Opts::init(argv, NSEQ_OPTIONS);
    let mut ret = 1i32;
    let mut toseq = false;
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/nseq.c:50`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: ret = 0; opt_help(nseq_options); goto end;` —
            // `apps/nseq.c:57-60`.
            OptMatch::Help => return not_landed("nseq -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog);` — `apps/nseq.c:52-56`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_TOSEQ: toseq = 1; break;` — `apps/nseq.c:61-63`.
            OptMatch::Flag("toseq") => toseq = true,
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/nseq.c:64-66`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/nseq.c:67-69`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/nseq.c:70-73`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("nseq -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/nseq.c:78-79`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `in = bio_open_default(infile, 'r', FORMAT_PEM); if (in == NULL) goto end;`
    // — `apps/nseq.c:81-83`.
    let inbio = bio_open(infile.as_deref(), false);
    if inbio.is_null() {
        return not_landed("nseq -in (unopenable)");
    }
    // `out = bio_open_default(outfile, 'w', FORMAT_PEM); if (out == NULL) goto
    // end;` — `apps/nseq.c:84-86`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `inbio` is live.
        unsafe { BIO_free(inbio) };
        return not_landed("nseq -out (unopenable)");
    }

    let seq: *mut crate::asn1::nsseq::NetScapeCertSequence;
    if toseq {
        // `seq = NETSCAPE_CERT_SEQUENCE_new(); if (seq == NULL) goto end;` —
        // `apps/nseq.c:89-91`.
        seq = NETSCAPE_CERT_SEQUENCE_new();
        if seq.is_null() {
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free(inbio) };
            return ret;
        }
        // `seq->certs = sk_X509_new_null(); if (seq->certs == NULL) goto end;` —
        // `apps/nseq.c:92-94`.
        // SAFETY: `seq` is live and uniquely owned here.
        unsafe { (*seq).certs = OPENSSL_sk_new_null() };
        // SAFETY: `seq` is live.
        if unsafe { (*seq).certs }.is_null() {
            // SAFETY: `seq` is live and uniquely owned; `inbio`/`out` are live.
            unsafe { NETSCAPE_CERT_SEQUENCE_free(seq) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free(inbio) };
            return ret;
        }
        // `while ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL))) { if
        // (!sk_X509_push(seq->certs, x509)) goto end; }` — `apps/nseq.c:95-98`.
        loop {
            // SAFETY: `inbio` is live; the out-slot is NULL and cb/arg are the
            // no-password arms.
            let x509 = unsafe {
                PEM_read_bio_X509(inbio, core::ptr::null_mut(), None, core::ptr::null_mut())
            };
            if x509.is_null() {
                break;
            }
            // SAFETY: `seq` is live and its `certs` stack is live.
            if unsafe { OPENSSL_sk_push((*seq).certs, x509.cast::<c_void>()) } == 0 {
                // SAFETY: `seq` is live and uniquely owned; `inbio`/`out` are live.
                unsafe { NETSCAPE_CERT_SEQUENCE_free(seq) };
                // SAFETY: `inbio`/`out` are live BIOs not freed again.
                unsafe { BIO_free_all(out) };
                // SAFETY: `inbio`/`out` are live BIOs not freed again.
                unsafe { BIO_free(inbio) };
                return ret;
            }
        }
        // `if (!sk_X509_num(seq->certs)) { BIO_printf(bio_err, "%s: Error
        // reading certs file %s\n", prog, infile); ERR_print_errors(bio_err); goto
        // end; }` — `apps/nseq.c:100-105`. Not driven: the error queue renders
        // pointer-bearing lines.
        // SAFETY: `seq` is live and `certs` is live.
        if unsafe { OPENSSL_sk_num((*seq).certs) } == 0 {
            eprintln!(
                "{}: Error reading certs file {}",
                opts.prog(),
                infile.as_deref().unwrap_or("")
            );
            // SAFETY: `seq` is live and uniquely owned; `inbio`/`out` are live.
            unsafe { NETSCAPE_CERT_SEQUENCE_free(seq) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free(inbio) };
            return ret;
        }
        // `PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out, seq); ret = 0; goto end;` —
        // `apps/nseq.c:106-108`.
        // SAFETY: `out` and `seq` are live.
        unsafe { PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out, seq) };
        ret = 0;
    } else {
        // `seq = PEM_read_bio_NETSCAPE_CERT_SEQUENCE(in, NULL, NULL, NULL); if
        // (seq == NULL) { BIO_printf(... "Error reading sequence file %s" ...);
        // ERR_print_errors(bio_err); goto end; }` — `apps/nseq.c:111-117`.
        // SAFETY: `inbio` is live; the out-slot is NULL and cb/arg are the
        // no-password arms.
        seq = unsafe {
            PEM_read_bio_NETSCAPE_CERT_SEQUENCE(
                inbio,
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        };
        if seq.is_null() {
            // Not driven: `ERR_print_errors` renders pointer-bearing lines.
            eprintln!(
                "{}: Error reading sequence file {}",
                opts.prog(),
                infile.as_deref().unwrap_or("")
            );
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `inbio`/`out` are live BIOs not freed again.
            unsafe { BIO_free(inbio) };
            return ret;
        }
        // `for (i = 0; i < sk_X509_num(seq->certs); i++) { x509 =
        // sk_X509_value(seq->certs, i); dump_cert_text(out, x509);
        // PEM_write_bio_X509(out, x509); }` — `apps/nseq.c:119-123`.
        // SAFETY: `seq` is live.
        let certs = unsafe { (*seq).certs };
        // SAFETY: `certs` is a live stack of certificates.
        let n = unsafe { OPENSSL_sk_num(certs) };
        for i in 0..n {
            // SAFETY: `certs` is live and `i` is in bounds.
            let x509 = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
            dump_cert_text(out, x509);
            // SAFETY: `out` is live and `x509` is live.
            unsafe { PEM_write_bio_X509(out, x509) };
        }
        // `ret = 0;` — `apps/nseq.c:124`.
        ret = 0;
    }

    // `end: BIO_free(in); BIO_free_all(out); NETSCAPE_CERT_SEQUENCE_free(seq);`
    // — `apps/nseq.c:125-128`.
    // SAFETY: each pointer is NULL or live and not freed again.
    unsafe { BIO_free(inbio) };
    // SAFETY: each pointer is NULL or live and not freed again.
    unsafe { BIO_free_all(out) };
    // SAFETY: each pointer is NULL or live and not freed again.
    unsafe { NETSCAPE_CERT_SEQUENCE_free(seq) };
    ret
}
