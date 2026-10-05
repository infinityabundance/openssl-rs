//! Phase 17.1 — `apps/pkeyparam.c`: the `openssl pkeyparam` command.
//!
//! The whole command body (`apps/pkeyparam.c:50-156`): parse the generated
//! `PKEYPARAM_OPTIONS` table, read a parameters PEM with
//! `PEM_read_bio_Parameters_ex`, optionally `-check` it with
//! `EVP_PKEY_param_check`, and write it back with `PEM_write_bio_Parameters`
//! (unless `-noout`) and/or `EVP_PKEY_print_params` (`-text`). Every libcrypto
//! function it reaches is landed.
//!
//! ## What the court drives
//!
//! A fixed parameters fixture (a `DH PARAMETERS` PEM): the default
//! re-encode, `-noout`, `-text` and `-check` arms. The output is deterministic;
//! the fixture's values are fixed, so the re-encoded base64 cannot drift.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-engine` is not landed.** `setup_engine`/`release_engine`
//!   (`apps/lib/apps.c`) are `apps/lib` helpers this stratum does not own, so
//!   `-engine` reaches [`not_landed`] rather than silently ignoring a device
//!   request.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * **`bio_open_default` is reduced to its observable.** The authority opens
//!   `in`/`out` through `apps/lib/apps.c`'s `bio_open_default`; this stratum has
//!   no `apps/lib` helper, so the file/stdio distinction is made directly. The
//!   byte stream is identical; the authority's "Can't open ..." failure text is
//!   the `apps/lib` arm's and is not reproduced (an unopenable `-in`/`-out`
//!   reaches [`not_landed`]).
//! * **`app_get0_libctx`/`app_get0_propq` are NULL.** `pkeyparam` exposes no
//!   `-libctx`/`-propquery` option, so the authority's two `app_get0_*` helpers
//!   answer NULL and the candidate passes NULL literally.
//! * **The failure arms are not driven.** A read that fails (`Error reading
//!   parameters`, `apps/pkeyparam.c:107`) or a `-check` that rejects the
//!   parameters (`Parameters are invalid`, `apps/pkeyparam.c:135`) then calls
//!   `ERR_print_errors`, whose lines begin with a per-run pointer; the
//!   authority's own output is not deterministic, so the court cannot diff it.
//!   The messages are transcribed; the error queue is the `ERR` surface's.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/pkeyparam.c:90-93`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKEYPARAM_OPTIONS;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_print_params};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::pmeth_check::EVP_PKEY_param_check;
use crate::pem::pem_pkey::{PEM_read_bio_Parameters_ex, PEM_write_bio_Parameters};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{Bio, BIO_NOCLOSE};

/// `bio_open_default(filename, mode, format)` — `apps/lib/apps.c:3264-3267`, the
/// stdio/file split. A NULL or `-` filename is the standard stream; anything
/// else is `BIO_new_file`.
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

/// `int pkeyparam_main(int argc, char **argv)` — `apps/pkeyparam.c:50-156`.
#[allow(clippy::never_loop)] // every arm breaks or returns; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, pkeyparam_options);` — `apps/pkeyparam.c:60`.
    let mut opts = Opts::init(argv, PKEYPARAM_OPTIONS);
    let mut ret = 1i32;
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let (mut text, mut noout, mut check) = (false, false, false);

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/pkeyparam.c:61`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(pkeyparam_options); ret = 0; goto end;` —
            // `apps/pkeyparam.c:68-71`.
            OptMatch::Help => return not_landed("pkeyparam -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/pkeyparam.c:63-66`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/pkeyparam.c:72-74`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/pkeyparam.c:75-77`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_TEXT: text = 1; break;` — `apps/pkeyparam.c:81-83`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/pkeyparam.c:84-86`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_CHECK: check = 1; break;` — `apps/pkeyparam.c:87-89`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0);` —
            // `apps/pkeyparam.c:78-80`. `setup_engine` is unlanded; see the header.
            OptMatch::Value("engine", _) => return not_landed("pkeyparam -engine"),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/pkeyparam.c:90-93`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkeyparam -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/pkeyparam.c:98-99`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `in = bio_open_default(infile, 'r', FORMAT_PEM); if (in == NULL) goto end;`
    // — `apps/pkeyparam.c:101-103`.
    let inbio = bio_open(infile.as_deref(), false);
    if inbio.is_null() {
        return not_landed("pkeyparam -in (unopenable)");
    }
    // `pkey = PEM_read_bio_Parameters_ex(in, NULL, app_get0_libctx(),
    // app_get0_propq());` — `apps/pkeyparam.c:104-105`. The two `app_get0_*`
    // helpers are NULL here (see the header).
    // SAFETY: `inbio` is live; the out-slot is NULL and both context/property
    // pointers are the no-context default.
    let pkey = unsafe {
        PEM_read_bio_Parameters_ex(
            inbio,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    if pkey.is_null() {
        // `BIO_printf(bio_err, "Error reading parameters\n");
        // ERR_print_errors(bio_err);` — `apps/pkeyparam.c:106-109`. Not driven:
        // `ERR_print_errors` renders pointer-bearing lines.
        eprintln!("Error reading parameters");
        // SAFETY: `inbio` is live.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return ret;
    }

    // `out = bio_open_default(outfile, 'w', FORMAT_PEM); if (out == NULL) goto end;`
    // — `apps/pkeyparam.c:111-113`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `pkey` is live and not freed again.
        unsafe { EVP_PKEY_free(pkey) };
        // SAFETY: `inbio` is a live BIO not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return not_landed("pkeyparam -out (unopenable)");
    }

    if check {
        // `if (e == NULL) ctx = EVP_PKEY_CTX_new_from_pkey(app_get0_libctx(),
        // pkey, app_get0_propq()); else ctx = EVP_PKEY_CTX_new(pkey, e);` —
        // `apps/pkeyparam.c:116-120`. `e` is NULL (no `-engine`).
        // SAFETY: `pkey` is live; both context/property pointers are NULL.
        let ctx =
            unsafe { EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null()) };
        if ctx.is_null() {
            // `ERR_print_errors(bio_err); goto end;` — `apps/pkeyparam.c:121-124`.
            // SAFETY: `pkey` is live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: `out` is a live BIO not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            // SAFETY: `inbio` is a live BIO not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return ret;
        }
        // `r = EVP_PKEY_param_check(ctx);` — `apps/pkeyparam.c:126`.
        // SAFETY: `ctx` is live.
        let r = unsafe { EVP_PKEY_param_check(ctx) };
        if r == 1 {
            // `BIO_printf(out, "Parameters are valid\n");` — `apps/pkeyparam.c:129`.
            let msg = b"Parameters are valid\n";
            // SAFETY: `out` is live and `msg` is a 21-byte slice.
            unsafe { crate::runtime::bio::BIO_write(out, msg.as_ptr().cast(), msg.len() as c_int) };
        } else {
            // `BIO_printf(bio_err, "Parameters are invalid\n");
            // ERR_print_errors(bio_err); goto end;` — `apps/pkeyparam.c:135-137`.
            // Not driven: `ERR_print_errors` renders pointer-bearing lines.
            eprintln!("Parameters are invalid");
            // SAFETY: `ctx` is live and not freed again.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            // SAFETY: `pkey` is live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: `out` is a live BIO not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            // SAFETY: `inbio` is a live BIO not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return ret;
        }
        // SAFETY: `ctx` is live and not used again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
    }

    // `if (!noout) PEM_write_bio_Parameters(out, pkey);` — `apps/pkeyparam.c:141-142`.
    if !noout {
        // SAFETY: `out` and `pkey` are live.
        unsafe { PEM_write_bio_Parameters(out, pkey) };
    }

    // `if (text) EVP_PKEY_print_params(out, pkey, 0, NULL);` — `apps/pkeyparam.c:144-145`.
    if text {
        // SAFETY: `out`/`pkey` are live; indent 0 and a NULL print context.
        unsafe { EVP_PKEY_print_params(out, pkey, 0, core::ptr::null_mut()) };
    }

    // `ret = EXIT_SUCCESS;` — `apps/pkeyparam.c:147`.
    ret = 0;

    // `end: EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); release_engine(e);
    // BIO_free_all(out); BIO_free(in);` — `apps/pkeyparam.c:149-154`.
    // SAFETY: `pkey` is live and not freed again.
    unsafe { EVP_PKEY_free(pkey) };
    // SAFETY: `out` is a live BIO not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    // SAFETY: `inbio` is a live BIO not freed again.
    unsafe { crate::runtime::bio::BIO_free(inbio) };
    ret
}
