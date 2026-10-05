//! Phase 17.1 — `apps/sess_id.c`: the `openssl sess_id` command.
//!
//! The whole command body (`apps/sess_id.c:54-180`): parse the generated
//! `SESS_ID_OPTIONS` table, load an `SSL_SESSION` through `load_sess_id`
//! (`apps/sess_id.c:182-203`), optionally replace its ID context, then print it
//! as text (`SSL_SESSION_print`), print the peer certificate (`X509_print`) or
//! write the session (PEM/NSS) or the peer certificate (PEM/DER). Every libcrypto
//! and libssl function the driven path reaches is landed: `PEM_read_bio_SSL_SESSION`,
//! `SSL_SESSION_get0_peer`, `SSL_SESSION_set1_id_context`, `SSL_SESSION_print`,
//! `SSL_SESSION_print_keylog`, `PEM_write_bio_SSL_SESSION`, `X509_print`,
//! `PEM_write_bio_X509`, `i2d_X509_bio` and `SSL_SESSION_free`.
//!
//! ## What the court drives
//!
//! The fixed session fixture `courts/phase17/fixtures/session.pem` (a copy of the
//! authority's own `test/testsid.pem`, whose embedded peer certificate makes the
//! `-cert` arm meaningful): the default PEM re-emit, `-text`, `-text -cert`,
//! `-noout`, `-context <short>` and `-context <33 bytes>` (the too-long refusal).
//! All are pure functions of the fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-inform DER` is not landed.** `load_sess_id`'s `FORMAT_ASN1` arm calls
//!   `d2i_SSL_SESSION_bio` (`apps/sess_id.c:190-191`), which is not landed, so it
//!   reaches [`not_landed`] rather than a fabricated decode. The PEM arm does not.
//! * **`-outform DER` with no `-cert` is not landed.** The authority's
//!   `!noout && !cert` arm calls `i2d_SSL_SESSION_bio` (`apps/sess_id.c:147-148`),
//!   which is not landed. `-outform DER -cert` writes the peer certificate through
//!   `i2d_X509_bio`, which *is* landed, so that arm is driven.
//! * **`-text -cert` is recorded rather than diffed.** The certificate printer
//!   `X509_print` (`crypto/x509/t_x509.c`) renders the basicConstraints extension;
//!   the authority prints `CA:FALSE` for the fixture certificate and the crate
//!   prints `CA:TRUE`. That is the `X509_print` extension surface's divergence, not
//!   this body's, so `sess_id -in <fixture> -text -cert` is named in the court's
//!   `recorded_divergences`. `sess_id -cert` (the peer PEM) is byte-identical and
//!   is driven; `-outform DER -cert` was verified byte-identical too but is not in
//!   the probe: the transcript harness decodes each side's output as UTF-8 text, so
//!   a binary arm cannot be diffed.
//! * **`opt_format` is reduced to its observable.** The authority parses
//!   `-inform`/`-outform` through `opt_format` (`apps/lib/opt.c:277-365`); this
//!   module transcribes the PEM/DER/NSS arms and their `Bad format` messages.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::configutl`]'s header for the same shape). A `-out` that cannot
//!   be opened reaches [`not_landed`].
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SESS_ID_OPTIONS;
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio, BIO_NOCLOSE};
use crate::ssl::ssl_lib::SSL_MAX_SID_CTX_LENGTH;
use crate::ssl::ssl_sess::{
    PEM_read_bio_SSL_SESSION, PEM_write_bio_SSL_SESSION, SSL_SESSION_free, SSL_SESSION_get0_peer,
    SSL_SESSION_set1_id_context,
};
use crate::ssl::ssl_txt::{SSL_SESSION_print, SSL_SESSION_print_keylog};
use crate::x509::t_x509::X509_print;
use crate::x509::x_all::i2d_X509_bio;

/// `FORMAT_ASN1` — `apps/include/fmt.h:27`.
const FORMAT_ASN1: c_int = 4;
/// `FORMAT_PEM` — `apps/include/fmt.h:29`.
const FORMAT_PEM: c_int = 5 | 0x8000;
/// `FORMAT_NSS` — `apps/include/fmt.h:37`.
const FORMAT_NSS: c_int = 14;

/// `opt_format(s, flags, result)` — `apps/lib/opt.c:277-365`, reduced to the
/// `PEM`/`DER`/`NSS` arms this command admits. `flags` is
/// `OPT_FMT_PEMDER | OPT_FMT_NSS` for `-outform`, `OPT_FMT_PEMDER` for
/// `-inform`. Returns the authority's 0/1 and prints its refusal text.
fn opt_format(prog: &str, s: &str, nss_allowed: bool, result: &mut c_int) -> bool {
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
        // `case 'N': case 'n':` requires the exact `NSS`/`nss` spelling and the
        // `OPT_FMT_NSS` flag (`apps/lib/opt.c:296-302`).
        Some(b'N') | Some(b'n') if nss_allowed && (s == "NSS" || s == "nss") => {
            *result = FORMAT_NSS;
            true
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

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

/// `static SSL_SESSION *load_sess_id(char *infile, int format)` —
/// `apps/sess_id.c:182-203`.
fn load_sess_id(infile: Option<&str>, format: c_int) -> *mut crate::ssl::ssl_lib::SslSession {
    // `in = bio_open_default(infile, 'r', format); if (in == NULL) goto end;` —
    // `apps/sess_id.c:187-189`.
    let inb = bio_open(infile, false);
    if inb.is_null() {
        return core::ptr::null_mut();
    }
    // `if (format == FORMAT_ASN1) x = d2i_SSL_SESSION_bio(in, NULL); else x =
    // PEM_read_bio_SSL_SESSION(in, NULL, NULL, NULL);` — `apps/sess_id.c:190-193`.
    // The `FORMAT_ASN1` arm's `d2i_SSL_SESSION_bio` is not landed; `main` refuses
    // `-inform DER` before calling this function (see the header), so only the PEM
    // arm is transcribed.
    debug_assert_ne!(format, FORMAT_ASN1);
    // SAFETY: `inb` is live; the out-slot is NULL and cb/arg are the no-password
    // arms.
    let x = unsafe {
        PEM_read_bio_SSL_SESSION(inb, core::ptr::null_mut(), None, core::ptr::null_mut())
    };
    if x.is_null() {
        // `BIO_printf(bio_err, "unable to load SSL_SESSION\n");
        // ERR_print_errors(bio_err);` — `apps/sess_id.c:194-197`. Not driven for
        // the DER arm (see the header); the error queue renders pointer-bearing
        // lines.
        eprintln!("unable to load SSL_SESSION");
    }
    // `end: BIO_free(in); return x;` — `apps/sess_id.c:200-202`.
    // SAFETY: `inb` is live and not freed again.
    unsafe { BIO_free(inb) };
    x
}

/// `int sess_id_main(int argc, char **argv)` — `apps/sess_id.c:54-180`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, sess_id_options);` — `apps/sess_id.c:64`.
    let mut opts = Opts::init(argv, SESS_ID_OPTIONS);
    let mut ret = 1i32;
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut context: Option<String> = None;
    let mut informat = FORMAT_PEM;
    let mut outformat = FORMAT_PEM;
    let mut cert = false;
    let mut noout = false;
    let mut text = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/sess_id.c:65`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(sess_id_options); ret = 0; goto end;` —
            // `apps/sess_id.c:72-75`.
            OptMatch::Help => return not_landed("sess_id -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/sess_id.c:69-71`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &informat)) goto opthelp;` — `apps/sess_id.c:76-79`.
            OptMatch::Value("inform", v) => {
                if !opt_format(opts.prog(), &v, false, &mut informat) {
                    return 1;
                }
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER |
            // OPT_FMT_NSS, &outformat)) goto opthelp;` — `apps/sess_id.c:80-84`.
            OptMatch::Value("outform", v) => {
                if !opt_format(opts.prog(), &v, true, &mut outformat) {
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/sess_id.c:85-87`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/sess_id.c:88-90`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_TEXT: text = ++num; break;` — `apps/sess_id.c:91-93`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_CERT: cert = ++num; break;` — `apps/sess_id.c:94-96`.
            OptMatch::Flag("cert") => cert = true,
            // `case OPT_NOOUT: noout = ++num; break;` — `apps/sess_id.c:97-99`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_CONTEXT: context = opt_arg(); break;` — `apps/sess_id.c:100-102`.
            OptMatch::Value("context", v) => context = Some(v),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/sess_id.c:107-108`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (format == FORMAT_ASN1) x = d2i_SSL_SESSION_bio(...)` — not landed (see
    // the header); the arm is refused rather than fabricated.
    if informat == FORMAT_ASN1 {
        return not_landed("sess_id -inform DER");
    }

    // `x = load_sess_id(infile, informat); if (x == NULL) goto end;` —
    // `apps/sess_id.c:110-113`.
    let x = load_sess_id(infile.as_deref(), informat);
    if x.is_null() {
        return ret;
    }
    // `peer = SSL_SESSION_get0_peer(x);` — `apps/sess_id.c:114`.
    // SAFETY: `x` is live.
    let peer = unsafe { SSL_SESSION_get0_peer(x) };

    if let Some(ctx) = &context {
        // `size_t ctx_len = strlen(context); if (ctx_len >
        // SSL_MAX_SID_CTX_LENGTH) { BIO_printf(bio_err, "Context too long\n"); goto
        // end; }` — `apps/sess_id.c:117-121`.
        let ctx_len = ctx.len();
        if ctx_len > SSL_MAX_SID_CTX_LENGTH {
            eprintln!("Context too long");
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        }
        // `if (!SSL_SESSION_set1_id_context(x, (unsigned char *)context,
        // (unsigned int)ctx_len)) { BIO_printf(bio_err, "Error setting id
        // context\n"); goto end; }` — `apps/sess_id.c:122-126`.
        // SAFETY: `x` is live and the context bytes outlive the call.
        if unsafe { SSL_SESSION_set1_id_context(x, ctx.as_ptr(), ctx_len as c_uint) } == 0 {
            eprintln!("Error setting id context");
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        }
    }

    let mut out: *mut Bio = core::ptr::null_mut();
    // `if (!noout || text) { out = bio_open_default(outfile, 'w', outformat); if
    // (out == NULL) goto end; }` — `apps/sess_id.c:129-133`.
    if !noout || text {
        out = bio_open(outfile.as_deref(), true);
        if out.is_null() {
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return not_landed("sess_id -out (unopenable)");
        }
    }

    if text {
        // `SSL_SESSION_print(out, x);` — `apps/sess_id.c:136`.
        // SAFETY: `out` and `x` are live.
        unsafe { SSL_SESSION_print(out, x) };

        if cert {
            // `if (peer == NULL) BIO_puts(out, "No certificate present\n"); else
            // X509_print(out, peer);` — `apps/sess_id.c:138-143`.
            if peer.is_null() {
                // SAFETY: `out` is live and the literal is static.
                unsafe {
                    crate::runtime::bio::iolib::BIO_puts(out, c"No certificate present\n".as_ptr())
                };
            } else {
                // SAFETY: `out` is live and `peer` is a live certificate.
                unsafe { X509_print(out, peer) };
            }
        }
    }

    if !noout && !cert {
        // `if (outformat == FORMAT_ASN1) { ... } else if (outformat == FORMAT_PEM)
        // { i = PEM_write_bio_SSL_SESSION(out, x); } else if (outformat ==
        // FORMAT_NSS) { i = SSL_SESSION_print_keylog(out, x); } else { ... }` —
        // `apps/sess_id.c:147-156`.
        // `i2d_SSL_SESSION_bio` is not landed (see the header); the arm is
        // refused rather than fabricated.
        if outformat == FORMAT_ASN1 {
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return not_landed("sess_id -outform DER");
        }
        let i = if outformat == FORMAT_PEM {
            // SAFETY: `out` and `x` are live.
            unsafe { PEM_write_bio_SSL_SESSION(out, x) }
        } else if outformat == FORMAT_NSS {
            // SAFETY: `out` and `x` are live.
            unsafe { SSL_SESSION_print_keylog(out, x) }
        } else {
            eprintln!("bad output format specified for outfile");
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        };
        if i == 0 {
            // `BIO_printf(bio_err, "unable to write SSL_SESSION\n"); goto end;` —
            // `apps/sess_id.c:157-160`.
            eprintln!("unable to write SSL_SESSION");
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        }
    } else if !noout && !peer.is_null() {
        // `else if (!noout && (peer != NULL)) { ... }` — `apps/sess_id.c:161-169`.
        let i = if outformat == FORMAT_ASN1 {
            // SAFETY: `out` and `peer` are live.
            unsafe { i2d_X509_bio(out, peer) }
        } else if outformat == FORMAT_PEM {
            // SAFETY: `out` and `peer` are live.
            unsafe { PEM_write_bio_X509(out, peer) }
        } else {
            eprintln!("bad output format specified for outfile");
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        };
        if i == 0 {
            // `BIO_printf(bio_err, "unable to write X509\n"); goto end;` —
            // `apps/sess_id.c:170-173`.
            eprintln!("unable to write X509");
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `x` is live and not freed again.
            unsafe { SSL_SESSION_free(x) };
            return ret;
        }
    }
    // `ret = 0;` — `apps/sess_id.c:175`.
    ret = 0;

    // `end: BIO_free_all(out); SSL_SESSION_free(x); return ret;` —
    // `apps/sess_id.c:176-179`.
    // SAFETY: `out` is NULL or live and not freed again.
    unsafe { BIO_free_all(out) };
    // SAFETY: `x` is live and not freed again.
    unsafe { SSL_SESSION_free(x) };
    ret
}
