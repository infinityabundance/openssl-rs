//! Phase 17.1e — `apps/storeutl.c`: the `openssl storeutl` command.
//!
//! The command body (`apps/storeutl.c:82-516`): parse the generated
//! `STOREUTL_OPTIONS` table, open the URI through `OSSL_STORE_open`, restrict
//! the expected object type (`-certs`/`-keys`/`-crls`), then loop over
//! `OSSL_STORE_load`, printing each item's type and (unless `-noout`) its
//! PEM/text form, ending with the `Total found: N` count. The parse, the
//! open/load loop and the `-noout` status arm are transcribed.
//!
//! ## What the court drives
//!
//! `storeutl -noout -keys <rsa-key.pem>` and `storeutl -noout -certs
//! <certs.pem>` over the fixed fixtures: the status line and the `Total found`
//! count are a pure function of the file.
//!
//! ## Recorded divergences (module header)
//!
//! * **The search-criterion arms are not landed.** `-subject`/`-issuer`/
//!   `-serial`/`-fingerprint`/`-alias` call `parse_name`/`s2i_ASN1_INTEGER`/
//!   `OPENSSL_hexstr2buf` and build an `OSSL_STORE_SEARCH` (`apps/storeutl.c:161-314`);
//!   none is driven.
//! * **`-r` (recursive) is not landed** (`apps/storeutl.c:126-128, 456-462`).
//! * **The pointer-bearing error tails are not diffed.** On a failed open the
//!   authority's `ERR_print_errors` emits a per-run pointer; the missing-file arm
//!   is therefore recorded rather than driven.
//! * **`app_passwd` is reduced to its no-argument observable**; no `-passin` is
//!   driven.
//! * **`-engine`, the unknown-digest name and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::STOREUTL_OPTIONS;
use crate::evp::pkey::{EVP_PKEY_print_params, EVP_PKEY_print_private, EVP_PKEY_print_public};
use crate::pem::pem_all::{PEM_write_bio_PUBKEY, PEM_write_bio_X509_CRL};
use crate::pem::pem_pkey::{PEM_write_bio_Parameters, PEM_write_bio_PrivateKey};
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::sys::{stderr, stdout};
use crate::runtime::bio::{Bio, BIO_NOCLOSE};
use crate::runtime::err::{ERR_clear_error, ERR_print_errors};
use crate::store::store_lib::{
    OSSL_STORE_INFO_free, OSSL_STORE_INFO_get0_CERT, OSSL_STORE_INFO_get0_CRL,
    OSSL_STORE_INFO_get0_NAME, OSSL_STORE_INFO_get0_NAME_description, OSSL_STORE_INFO_get0_PARAMS,
    OSSL_STORE_INFO_get0_PKEY, OSSL_STORE_INFO_get0_PUBKEY, OSSL_STORE_INFO_get_type,
    OSSL_STORE_close, OSSL_STORE_eof, OSSL_STORE_error, OSSL_STORE_expect, OSSL_STORE_load,
    OSSL_STORE_open,
};
use crate::store::store_strings::OSSL_STORE_INFO_type_string;
use crate::store::{
    OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME, OSSL_STORE_INFO_PARAMS,
    OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY,
};
use crate::x509::t_crl::X509_CRL_print;
use crate::x509::t_x509::X509_print;
use crate::x509::x_crl::X509Crl;
use crate::x509::x_x509::X509;

/// `bio_err` — the stderr BIO.
fn bio_err() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard error `FILE *`.
    unsafe { BIO_new_fp(stderr.cast(), BIO_NOCLOSE) }
}

/// `bio_out` — the stdout BIO.
fn bio_out() -> *mut Bio {
    // SAFETY: `stdout` is the C library's live standard output `FILE *`.
    unsafe { BIO_new_fp(stdout.cast(), BIO_NOCLOSE) }
}

/// `BIO_puts(out, s)` with a Rust string.
fn puts(bio: *mut Bio, s: &str) {
    let Ok(cs) = std::ffi::CString::new(s) else {
        return;
    };
    // SAFETY: `bio` is live; `cs` is NUL-terminated.
    unsafe { BIO_puts(bio, cs.as_ptr()) };
}

/// `static int process(...)` — `apps/storeutl.c:362-516`, the non-recursive,
/// no-criterion arm the court drives.
fn process(
    uri: &str,
    expected: c_int,
    text: bool,
    noout: bool,
    outfile: Option<&str>,
    prog: &str,
) -> i32 {
    let c_uri = match std::ffi::CString::new(uri) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Couldn't open file or uri {uri}");
            return 1;
        }
    };
    // `store_ctx = OSSL_STORE_open_ex(uri, libctx, propq, uimeth, uidata, NULL,
    // NULL, NULL);` — `apps/storeutl.c:370-372`, reduced to `OSSL_STORE_open`
    // (the NULL libctx/propq arm).
    // SAFETY: `c_uri` is NUL-terminated; the remaining arguments are NULL.
    let store_ctx = unsafe {
        OSSL_STORE_open(
            c_uri.as_ptr(),
            core::ptr::null(),
            core::ptr::null_mut(),
            None,
            core::ptr::null_mut(),
        )
    };
    if store_ctx.is_null() {
        eprintln!("Couldn't open file or uri {uri}");
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { crate::runtime::bio::BIO_free(err) };
        return 1;
    }

    // `if (expected != 0) { if (!OSSL_STORE_expect(store_ctx, expected)) { ... } }`
    // — `apps/storeutl.c:378-383`.
    if expected != 0 {
        // SAFETY: `store_ctx` is live.
        if unsafe { OSSL_STORE_expect(store_ctx, expected) } == 0 {
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { crate::runtime::bio::BIO_free(err) };
            // SAFETY: `store_ctx` is live and not freed again.
            unsafe { OSSL_STORE_close(store_ctx) };
            return 1;
        }
    }

    let _ = prog;
    let stdout_bio = bio_out();
    let mut out: *mut Bio = core::ptr::null_mut();
    let mut ret = 0i32;
    let mut items = 0i32;

    // `for (;;) { OSSL_STORE_INFO *info = OSSL_STORE_load(store_ctx); ... }` —
    // `apps/storeutl.c:402-506`.
    loop {
        // SAFETY: `store_ctx` is live.
        let info = unsafe { OSSL_STORE_load(store_ctx) };
        if info.is_null() {
            // SAFETY: `store_ctx` is live.
            if unsafe { OSSL_STORE_error(store_ctx) } != 0 {
                let err = bio_err();
                // SAFETY: `err` is a live stderr BIO.
                unsafe { ERR_print_errors(err) };
                // SAFETY: `err` is NOCLOSE.
                unsafe { crate::runtime::bio::BIO_free(err) };
                // SAFETY: `store_ctx` is live.
                if unsafe { OSSL_STORE_eof(store_ctx) } != 0 {
                    break;
                }
                ret += 1;
                continue;
            }
            // SAFETY: `store_ctx` is live.
            if unsafe { OSSL_STORE_eof(store_ctx) } != 0 {
                break;
            }
            eprintln!("ERROR: OSSL_STORE_load() returned NULL without eof or error indications");
            eprintln!("       This is an error in the loader");
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { crate::runtime::bio::BIO_free(err) };
            ret += 1;
            break;
        }

        // SAFETY: `info` is live.
        let typ = unsafe { OSSL_STORE_INFO_get_type(info) };
        // SAFETY: `typ` came from a live info just read.
        let infostr = OSSL_STORE_INFO_type_string(typ);
        let infostr = if infostr.is_null() {
            String::new()
        } else {
            // SAFETY: `infostr` is a NUL-terminated static.
            unsafe { std::ffi::CStr::from_ptr(infostr) }
                .to_string_lossy()
                .into_owned()
        };

        // `if (type == OSSL_STORE_INFO_NAME) { ... indent_printf(..., "%d: %s:
        // %s\n", items, infostr, name); ... } else { indent_printf(..., "%d:
        // %s\n", items, infostr); }` — `apps/storeutl.c:431-440`.
        if typ == OSSL_STORE_INFO_NAME {
            // SAFETY: `info` is live.
            let name = unsafe { OSSL_STORE_INFO_get0_NAME(info) };
            let name = cstr(name);
            puts(stdout_bio, &format!("{items}: {infostr}: {name}\n"));
            // SAFETY: `info` is live.
            let desc = unsafe { OSSL_STORE_INFO_get0_NAME_description(info) };
            if !desc.is_null() {
                puts(stdout_bio, &format!("{}\n", cstr(desc)));
            }
        } else {
            puts(stdout_bio, &format!("{items}: {infostr}\n"));
        }

        // `if (out == NULL) { if ((out = bio_open_default(outfile, 'w',
        // FORMAT_TEXT)) == NULL) { ret++; goto end2; } }` —
        // `apps/storeutl.c:442-447`.
        if out.is_null() {
            out = crate::apps::keyio::bio_open_default(outfile, true);
            if out.is_null() {
                ret += 1;
                // SAFETY: `info`/`store_ctx` are live and not freed again.
                unsafe { OSSL_STORE_INFO_free(info) };
                // SAFETY: as above.
                unsafe { OSSL_STORE_close(store_ctx) };
                // SAFETY: `stdout_bio` is NOCLOSE.
                unsafe { crate::runtime::bio::BIO_free(stdout_bio) };
                return ret;
            }
        }

        // `switch (type) { case OSSL_STORE_INFO_PARAMS: ... }` —
        // `apps/storeutl.c:454-503`.
        match typ {
            t if t == OSSL_STORE_INFO_NAME => {}
            t if t == OSSL_STORE_INFO_PARAMS => {
                // SAFETY: `info` is live and of the PARAMS type.
                let pkey = unsafe { OSSL_STORE_INFO_get0_PARAMS(info) };
                if text {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { EVP_PKEY_print_params(out, pkey, 0, core::ptr::null_mut()) };
                }
                if !noout {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { PEM_write_bio_Parameters(out, pkey) };
                }
            }
            t if t == OSSL_STORE_INFO_PUBKEY => {
                // SAFETY: `info` is live and of the PUBKEY type.
                let pkey = unsafe { OSSL_STORE_INFO_get0_PUBKEY(info) };
                if text {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { EVP_PKEY_print_public(out, pkey, 0, core::ptr::null_mut()) };
                }
                if !noout {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { PEM_write_bio_PUBKEY(out, pkey) };
                }
            }
            t if t == OSSL_STORE_INFO_PKEY => {
                // SAFETY: `info` is live and of the PKEY type.
                let pkey = unsafe { OSSL_STORE_INFO_get0_PKEY(info) };
                if text {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { EVP_PKEY_print_private(out, pkey, 0, core::ptr::null_mut()) };
                }
                if !noout {
                    // SAFETY: `out`/`pkey` are live; cipher/kstr/cb/arg are the
                    // no-cipher arms.
                    unsafe {
                        PEM_write_bio_PrivateKey(
                            out,
                            pkey,
                            core::ptr::null_mut(),
                            core::ptr::null(),
                            0,
                            None,
                            core::ptr::null_mut(),
                        )
                    };
                }
            }
            t if t == OSSL_STORE_INFO_CERT => {
                // SAFETY: `info` is live and of the CERT type.
                let cert = unsafe { OSSL_STORE_INFO_get0_CERT(info) }.cast::<X509>();
                if text {
                    // SAFETY: `out`/`cert` are live.
                    unsafe { X509_print(out, cert) };
                }
                if !noout {
                    // SAFETY: `out`/`cert` are live.
                    unsafe { PEM_write_bio_X509(out, cert) };
                }
            }
            t if t == OSSL_STORE_INFO_CRL => {
                // SAFETY: `info` is live and of the CRL type.
                let crl = unsafe { OSSL_STORE_INFO_get0_CRL(info) }.cast::<X509Crl>();
                if text {
                    // SAFETY: `out`/`crl` are live.
                    unsafe { X509_CRL_print(out, crl) };
                }
                if !noout {
                    // SAFETY: `out`/`crl` are live.
                    unsafe { PEM_write_bio_X509_CRL(out, crl) };
                }
            }
            _ => {
                eprintln!("!!! Unknown code");
                ret += 1;
            }
        }
        items += 1;
        // SAFETY: `info` is live and not freed again.
        unsafe { OSSL_STORE_INFO_free(info) };
    }

    // `indent_printf(indent, out, "Total found: %d\n", items);` —
    // `apps/storeutl.c:507`.
    if out.is_null() {
        out = crate::apps::keyio::bio_open_default(outfile, true);
    }
    puts(out, &format!("Total found: {items}\n"));

    // `end2: if (!OSSL_STORE_close(store_ctx)) { ... }` —
    // `apps/storeutl.c:509-513`.
    // SAFETY: `store_ctx` is live and not freed again.
    if unsafe { OSSL_STORE_close(store_ctx) } == 0 {
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { crate::runtime::bio::BIO_free(err) };
        ret += 1;
    }
    // SAFETY: `stdout_bio` is NOCLOSE.
    unsafe { crate::runtime::bio::BIO_free(stdout_bio) };
    if out != stdout_bio && !out.is_null() {
        // SAFETY: `out` is the file BIO opened above.
        unsafe { crate::runtime::bio::BIO_free(out) };
    }
    // The queue is cleared unconditionally at the end of `process`.
    ERR_clear_error();
    ret
}

/// A `const char *` as an owned string.
fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: `p` is a NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }
}

/// `int storeutl_main(int argc, char *argv[])` — `apps/storeutl.c:82-339`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("digest"); prog = opt_init(argc, argv,
    // storeutl_options);` — `apps/storeutl.c:101-102`.
    let mut opts = Opts::init(argv, STOREUTL_OPTIONS);
    let mut outfile: Option<String> = None;
    let mut _passinarg: Option<String> = None;
    let mut noout = false;
    let mut text = false;
    let mut expected = 0i32;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/storeutl.c:103`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(storeutl_options); ret = 0; goto end;` —
            // `apps/storeutl.c:110-113`.
            OptMatch::Help => return not_landed("storeutl -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/storeutl.c:105-109`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/storeutl.c:114-116`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` —
            // `apps/storeutl.c:117-119`.
            OptMatch::Value("passin", v) => _passinarg = Some(v),
            // `case OPT_NOOUT: noout = 1; break;` — `apps/storeutl.c:120-122`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/storeutl.c:123-125`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_RECURSIVE: recursive = 1; break;` —
            // `apps/storeutl.c:126-128`.
            OptMatch::Flag("r") => return not_landed("storeutl -r"),
            // `case OPT_SEARCHFOR_CERTS/KEYS/CRLS: ... expected = ...` —
            // `apps/storeutl.c:129-160`.
            OptMatch::Flag("certs") => {
                if expected != 0 {
                    eprintln!("{}: only one search type can be given.", opts.prog());
                    return 1;
                }
                expected = OSSL_STORE_INFO_CERT;
            }
            OptMatch::Flag("keys") => {
                if expected != 0 {
                    eprintln!("{}: only one search type can be given.", opts.prog());
                    return 1;
                }
                expected = OSSL_STORE_INFO_PKEY;
            }
            OptMatch::Flag("crls") => {
                if expected != 0 {
                    eprintln!("{}: only one search type can be given.", opts.prog());
                    return 1;
                }
                expected = OSSL_STORE_INFO_CRL;
            }
            // `case OPT_CRITERION_SUBJECT/ISSUER/SERIAL/FINGERPRINT/ALIAS: ...` —
            // `apps/storeutl.c:161-255`.
            OptMatch::Value("subject", _)
            | OptMatch::Value("issuer", _)
            | OptMatch::Value("serial", _)
            | OptMatch::Value("fingerprint", _)
            | OptMatch::Value("alias", _) => return not_landed("storeutl search criterion"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/storeutl.c:256-258`.
            OptMatch::Value("engine", _) => return not_landed("storeutl -engine"),
            // `case OPT_MD: digestname = opt_unknown(); break;` —
            // `apps/storeutl.c:259-261`.
            OptMatch::Value("", _) => return not_landed("storeutl digest"),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/storeutl.c:262-265`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("storeutl -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg("URI")) goto opthelp; argv = opt_rest();` —
    // `apps/storeutl.c:269-272`.
    if !opts.check_rest_arg(Some("URI")) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    let uri = opts.rest()[0].clone();

    // `if (!app_passwd(passinarg, NULL, &passin, NULL)) { ... }` with both NULL
    // succeeds and leaves `passin` NULL (`apps/lib/apps.c:231-274`).

    // `ret = process(argv[0], get_ui_method(), &pw_cb_data, expected, criterion,
    // search, text, noout, recursive, 0, outfile, prog, libctx);` —
    // `apps/storeutl.c:323-325`.
    process(&uri, expected, text, noout, outfile.as_deref(), opts.prog())
}
