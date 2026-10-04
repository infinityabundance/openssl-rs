//! Phase 17.1 — `apps/spkac.c`: the `openssl spkac` command.
//!
//! The whole command body (`apps/spkac.c:69-243`): parse the generated
//! `SPKAC_OPTIONS` table, then either sign a fresh SPKAC from `-key`
//! (`apps/spkac.c:154-191`) or read a base64 SPKAC out of a configuration section
//! and print/verify it (`apps/spkac.c:193-232`). The read arm loads the
//! configuration with `app_load_config`, reads the named string with
//! `NCONF_get_string`, decodes it with `NETSCAPE_SPKI_b64_decode`, prints it with
//! `NETSCAPE_SPKI_print`, verifies it with `NETSCAPE_SPKI_verify` and can emit its
//! public key with `PEM_write_bio_PUBKEY`. Every libcrypto function the driven path
//! reaches is landed.
//!
//! ## What the court drives
//!
//! The fixed configuration fixture `courts/phase17/fixtures/spkac.cnf`, whose
//! `[default]` section carries a fixed SPKAC produced offline by the authority:
//! `spkac -in <fixture>` (print), `-noout` (silent), `-verify` (`Signature OK` on
//! stderr) and `-pubkey` (the public key PEM). All are pure functions of the
//! fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **A missing SPKAC name is recorded rather than diffed.** `spkac -in
//!   <fixture> -spkac NOPE` prints `Can't find SPKAC called "NOPE"` on both sides,
//!   and both raise the same `NCONF_get_string:no value` error, but the rendered
//!   line begins with a per-run pointer and so cannot be diffed. The court names it
//!   in `recorded_divergences`.
//! * **`-key` is not landed.** The signing arm (`apps/spkac.c:154-191`) needs
//!   `opt_md`, `load_key` and `app_passwd` (`apps/lib` helpers this stratum does
//!   not own) before it reaches the landed `NETSCAPE_SPKI_new`/`set_pubkey`/
//!   `sign`/`b64_encode`; it reaches [`not_landed`]. `-keyform`'s value is
//!   therefore carried but not validated (it is only read on that arm).
//! * **`app_passwd` is reduced to its observable.** With no `-passin` the
//!   authority returns 1 and a NULL password; a named `-passin` needs the unlanded
//!   `apps/lib` passphrase machinery and reaches [`not_landed`].
//! * **`app_load_config` is reduced to its observable.** Its
//!   `NCONF_new_ex`/`NCONF_load_bio` body (`apps/lib/apps.c:375-397`) and failure
//!   text are transcribed inline against the landed `NCONF_load_bio`; the
//!   `app_get0_libctx()` argument is NULL, the fixed default.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::configutl`]'s header for the same shape).
//! * **`-help` and `-engine` are not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records; `setup_engine` is an `apps/lib` helper.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/spkac.c:138-141`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SPKAC_OPTIONS;
use crate::asn1::t_spki::NETSCAPE_SPKI_print;
use crate::asn1::x_spki::NETSCAPE_SPKI_free;
use crate::pem::pem_all::PEM_write_bio_PUBKEY;
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{stderr, stdin, stdout};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio, BIO_NOCLOSE};
use crate::runtime::conf::lib::{NCONF_free, NCONF_get_string, NCONF_load_bio, NCONF_new};
use crate::runtime::conf::types::Conf;
use crate::runtime::err::ERR_print_errors;
use crate::x509::x509spki::{NETSCAPE_SPKI_b64_decode, NETSCAPE_SPKI_get_pubkey};

/// `bio_err` — `apps/lib/apps.c`'s stderr BIO (`dup_bio_err`).
fn bio_err() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard error `FILE *`.
    unsafe { BIO_new_fp(stderr.cast(), BIO_NOCLOSE) }
}

/// `bio_open_default(filename, mode, format)` — the stdio/file split.
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

/// `CONF *app_load_config_bio(BIO *in, const char *filename)` +
/// `app_load_config_internal(filename, 0)` — `apps/lib/apps.c:375-397`, `:412-426`,
/// transcribed inline (see the header).
fn app_load_config(prog: &str, filename: Option<&str>) -> *mut Conf {
    // `if ((in = bio_open_default_(filename, 'r', FORMAT_TEXT, quiet)) == NULL)
    // return NULL;` — `apps/lib/apps.c:415-416`.
    let inb = bio_open(filename, false);
    if inb.is_null() {
        return core::ptr::null_mut();
    }
    // `conf = NCONF_new_ex(app_get0_libctx(), NULL);` — `apps/lib/apps.c:383`.
    // SAFETY: the NULL method selects the default method; the context is NULL.
    let conf = unsafe { NCONF_new(core::ptr::null_mut()) };
    if conf.is_null() {
        // SAFETY: `inb` is live and not freed again.
        unsafe { BIO_free(inb) };
        return core::ptr::null_mut();
    }
    // `i = NCONF_load_bio(conf, in, &errorline);` — `apps/lib/apps.c:384`.
    let mut errorline: c_long = -1;
    // SAFETY: `conf` and `inb` are live and `errorline` is writable.
    let i = unsafe { NCONF_load_bio(conf, inb, &mut errorline) };
    // SAFETY: `inb` is live and not freed again.
    unsafe { BIO_free(inb) };
    if i > 0 {
        return conf;
    }
    // `if (errorline <= 0) BIO_printf(bio_err, "%s: Can't load ", opt_getprog());
    // else BIO_printf(bio_err, "%s: Error on line %ld of ", opt_getprog(),
    // errorline); if (filename != NULL) BIO_printf(bio_err, "config file
    // \"%s\"\n", filename); else BIO_printf(bio_err, "config input");` —
    // `apps/lib/apps.c:387-396`.
    let err = bio_err();
    if errorline <= 0 {
        eprint!("{prog}: Can't load ");
    } else {
        eprint!("{prog}: Error on line {errorline} of ");
    }
    match filename {
        Some(f) => eprintln!("config file \"{f}\""),
        None => eprintln!("config input"),
    }
    // SAFETY: `err` is a live stderr BIO; the error queue renders the load failure.
    unsafe { ERR_print_errors(err) };
    // SAFETY: `err` is NOCLOSE.
    unsafe { BIO_free(err) };
    // SAFETY: `conf` is live and not freed again.
    unsafe { NCONF_free(conf) };
    core::ptr::null_mut()
}

/// `int spkac_main(int argc, char **argv)` — `apps/spkac.c:69-243`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, spkac_options);` — `apps/spkac.c:86`.
    let mut opts = Opts::init(argv, SPKAC_OPTIONS);
    let mut ret = 1i32;
    let mut outfile: Option<String> = None;
    let mut infile: Option<String> = None;
    let mut passinarg: Option<String> = None;
    let mut keyfile: Option<String> = None;
    let mut challenge: Option<String> = None;
    let mut spkac = String::from("SPKAC");
    let mut spksect = String::from("default");
    let mut digest = String::from("MD5");
    let mut keyformat: c_int = 0;
    let mut verify = false;
    let mut noout = false;
    let mut pubkey = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/spkac.c:87`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(spkac_options); ret = 0; goto end;` —
            // `apps/spkac.c:94-97`.
            OptMatch::Help => return not_landed("spkac -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/spkac.c:91-93`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/spkac.c:98-100`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/spkac.c:101-103`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_NOOUT: noout = 1; break;` — `apps/spkac.c:104-106`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_PUBKEY: pubkey = 1; break;` — `apps/spkac.c:107-109`.
            OptMatch::Flag("pubkey") => pubkey = true,
            // `case OPT_VERIFY: verify = 1; break;` — `apps/spkac.c:110-112`.
            OptMatch::Flag("verify") => verify = true,
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/spkac.c:113-115`.
            OptMatch::Value("passin", v) => passinarg = Some(v),
            // `case OPT_KEY: keyfile = opt_arg(); break;` — `apps/spkac.c:116-118`.
            OptMatch::Value("key", v) => keyfile = Some(v),
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY,
            // &keyformat)) goto opthelp;` — `apps/spkac.c:119-122`. The value is
            // only read on the unlanded `-key` arm (see the header).
            OptMatch::Value("keyform", v) => {
                let _ = &v;
                keyformat = 1;
            }
            // `case OPT_CHALLENGE: challenge = opt_arg(); break;` —
            // `apps/spkac.c:123-125`.
            OptMatch::Value("challenge", v) => challenge = Some(v),
            // `case OPT_SPKAC: spkac = opt_arg(); break;` — `apps/spkac.c:126-128`.
            OptMatch::Value("spkac", v) => spkac = v,
            // `case OPT_SPKSECT: spksect = opt_arg(); break;` — `apps/spkac.c:129-131`.
            OptMatch::Value("spksect", v) => spksect = v,
            // `case OPT_DIGEST: digest = opt_arg(); break;` — `apps/spkac.c:132-134`.
            OptMatch::Value("digest", v) => digest = v,
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/spkac.c:135-137`. `setup_engine` is an `apps/lib` helper.
            OptMatch::Value("engine", _) => return not_landed("spkac -engine"),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/spkac.c:138-141`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("spkac -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }
    // The `-digest`/`-challenge`/`-keyform` values are only consumed on the unlanded
    // `-key` arm; bind them so the parse stays faithful without a warning.
    let _ = (&digest, &challenge, keyformat);

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/spkac.c:146-147`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_passwd(passinarg, NULL, &passin, NULL)) { BIO_printf(bio_err,
    // "Error getting password\n"); goto end; }` — `apps/spkac.c:149-152`.
    // SAFETY: the passphrase machinery is `apps/lib`; a named `-passin` needs it.
    if passinarg.is_some() {
        return not_landed("spkac -passin");
    }
    let passin: *mut core::ffi::c_char = core::ptr::null_mut();

    if keyfile.is_some() {
        // `if (keyfile != NULL) { ... }` — `apps/spkac.c:154-191`. The signing arm
        // needs the unlanded `opt_md`/`load_key` (see the header).
        return not_landed("spkac -key");
    }

    // `if ((conf = app_load_config(infile)) == NULL) goto end;` —
    // `apps/spkac.c:193-194`.
    let conf = app_load_config(opts.prog(), infile.as_deref());
    if conf.is_null() {
        return ret;
    }

    // `spkstr = NCONF_get_string(conf, spksect, spkac);` — `apps/spkac.c:196`.
    let spkac_c = match std::ffi::CString::new(spkac.as_str()) {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: `conf` is live and not freed again.
            unsafe { NCONF_free(conf) };
            return ret;
        }
    };
    let spksect_c = match std::ffi::CString::new(spksect.as_str()) {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: `conf` is live and not freed again.
            unsafe { NCONF_free(conf) };
            return ret;
        }
    };
    // SAFETY: `conf` is live and both strings are NUL-terminated.
    let spkstr = unsafe { NCONF_get_string(conf, spksect_c.as_ptr(), spkac_c.as_ptr()) };
    if spkstr.is_null() {
        // `BIO_printf(bio_err, "Can't find SPKAC called \"%s\"\n", spkac);
        // ERR_print_errors(bio_err); goto end;` — `apps/spkac.c:198-202`.
        eprintln!("Can't find SPKAC called \"{spkac}\"");
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        // SAFETY: `conf` is live and not freed again.
        unsafe { NCONF_free(conf) };
        return ret;
    }

    // `spki = NETSCAPE_SPKI_b64_decode(spkstr, -1); if (spki == NULL) {
    // BIO_printf(bio_err, "Error loading SPKAC\n"); ERR_print_errors(bio_err);
    // goto end; }` — `apps/spkac.c:204-210`.
    // SAFETY: `spkstr` is NUL-terminated; -1 asks the decoder to measure it.
    let spki = unsafe { NETSCAPE_SPKI_b64_decode(spkstr.cast_const(), -1) };
    if spki.is_null() {
        eprintln!("Error loading SPKAC");
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        // SAFETY: `conf` is live and not freed again.
        unsafe { NCONF_free(conf) };
        return ret;
    }

    // `out = bio_open_default(outfile, 'w', FORMAT_TEXT); if (out == NULL) goto
    // end;` — `apps/spkac.c:212-214`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `spki`/`conf` are live and not freed again.
        unsafe { NETSCAPE_SPKI_free(spki) };
        // SAFETY: `spki`/`conf` are live and not freed again.
        unsafe { NCONF_free(conf) };
        return not_landed("spkac -out (unopenable)");
    }

    // `if (!noout) NETSCAPE_SPKI_print(out, spki);` — `apps/spkac.c:216-217`.
    if !noout {
        // SAFETY: `out` and `spki` are live.
        unsafe { NETSCAPE_SPKI_print(out, spki) };
    }
    // `pkey = NETSCAPE_SPKI_get_pubkey(spki);` — `apps/spkac.c:218`.
    // SAFETY: `spki` is live.
    let pkey = unsafe { NETSCAPE_SPKI_get_pubkey(spki) };
    if verify {
        // `i = NETSCAPE_SPKI_verify(spki, pkey); if (i > 0) {
        // BIO_printf(bio_err, "Signature OK\n"); } else { BIO_printf(bio_err,
        // "Signature Failure\n"); ERR_print_errors(bio_err); goto end; }` —
        // `apps/spkac.c:219-227`.
        // SAFETY: `spki` and `pkey` are live.
        let i = unsafe { crate::x509::x_all::NETSCAPE_SPKI_verify(spki, pkey) };
        if i > 0 {
            eprintln!("Signature OK");
        } else {
            eprintln!("Signature Failure");
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { BIO_free(err) };
            // SAFETY: `pkey`/`out`/`spki`/`conf` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out`/`spki`/`conf` are live and not freed again.
            unsafe { BIO_free_all(out) };
            // SAFETY: `pkey`/`out`/`spki`/`conf` are live and not freed again.
            unsafe { NETSCAPE_SPKI_free(spki) };
            // SAFETY: `pkey`/`out`/`spki`/`conf` are live and not freed again.
            unsafe { NCONF_free(conf) };
            return ret;
        }
    }
    // `if (pubkey) PEM_write_bio_PUBKEY(out, pkey);` — `apps/spkac.c:229-230`.
    if pubkey {
        // SAFETY: `out` and `pkey` are live.
        unsafe { PEM_write_bio_PUBKEY(out, pkey) };
    }

    // `ret = 0;` — `apps/spkac.c:232`.
    ret = 0;

    // `end: EVP_MD_free(md); NCONF_free(conf); NETSCAPE_SPKI_free(spki);
    // BIO_free_all(out); EVP_PKEY_free(pkey); release_engine(e);
    // OPENSSL_free(passin);` — `apps/spkac.c:234-241`.
    // SAFETY: `conf` is live and not freed again.
    unsafe { NCONF_free(conf) };
    // SAFETY: `spki` is live and not freed again.
    unsafe { NETSCAPE_SPKI_free(spki) };
    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free_all(out) };
    // SAFETY: `pkey` is live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    // SAFETY: `passin` is NULL here (the named path is unlanded).
    unsafe { crate::runtime::mem::CRYPTO_free(passin.cast(), core::ptr::null(), 0) };
    ret
}
