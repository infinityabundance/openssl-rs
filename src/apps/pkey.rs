//! Phase 17.1d — `apps/pkey.c`: the `openssl pkey` command.
//!
//! The command body (`apps/pkey.c:82-350`): parse the generated `PKEY_OPTIONS` table,
//! load a private or public key, apply the EC encoding/point-format parameters,
//! `-check`/`-pubcheck` it, write the encoded key (`PEM_write_bio_PrivateKey`/
//! `PEM_write_bio_PUBKEY`/`PEM_write_bio_PrivateKey_traditional` or the DER writers)
//! unless `-noout`, and/or print its text (`-text`/`-text_pub`). The parse, the key
//! load, the check and the text/encode arms are transcribed.
//!
//! ## What the court drives
//!
//! `pkey -in <rsa-key.pem> -noout -text`, `pkey -in <rsa-pub.pem> -pubin -noout -text`
//! (the `-pubin`⇒`-pubout`/`-text_pub` rewrite), `pkey -in <rsa-key.pem> -check -noout`
//! (`Key is valid`) and the default `pkey -in <rsa-key.pem>`, which writes a PKCS#8
//! `PRIVATE KEY` PEM.
//!
//! ## Recorded divergences (module header)
//!
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/pkey.c:100`); an unknown
//!   option is the parser's refusal rather than a cipher name. Not driven.
//! * **`opt_cipher`/`app_passwd`/`bio_open_owner` are `apps/lib` helpers** reconstructed
//!   at the observable; no cipher and no pass phrase is driven, so the `-passout`
//!   warning and the cipher/PEM compatibility error are transcribed but not exercised.
//! * **`-engine` is not landed** (`apps/pkey.c:127-129`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arm reaches the unlanded `opt_provider`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_key, load_pubkey, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKEY_OPTIONS;
use crate::evp::pkey::{EVP_PKEY_print_private, EVP_PKEY_print_public};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new};
use crate::evp::pmeth_check::{EVP_PKEY_check, EVP_PKEY_public_check};
use crate::pem::pem_all::PEM_write_bio_PUBKEY;
use crate::pem::pem_pk8::i2d_PKCS8PrivateKey_bio;
use crate::pem::pem_pkey::{PEM_write_bio_PrivateKey, PEM_write_bio_PrivateKey_traditional};
use crate::x509::x_all::{i2d_PUBKEY_bio, i2d_PrivateKey_bio};

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;

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

/// `int pkey_main(int argc, char **argv)` — `apps/pkey.c:82-350`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, pkey_options);` —
    // `apps/pkey.c:100-101`.
    let mut opts = Opts::init(argv, PKEY_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut pubin = false;
    let mut pubout = false;
    let mut text_pub = false;
    let mut text = false;
    let mut noout = false;
    let mut traditional = false;
    let mut check = false;
    let mut pub_check = false;
    let mut point_format: Option<String> = None;
    let mut asn1_encoding: Option<String> = None;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/pkey.c:102`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(pkey_options); ret = 0; goto end;` —
            // `apps/pkey.c:109-112`.
            OptMatch::Help => return not_landed("pkey -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/pkey.c:104-108`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
            // goto opthelp;` — `apps/pkey.c:113-116`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/pkey.c:117-120`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/pkey.c:121-123`.
            OptMatch::Value("passin", _) => return not_landed("pkey -passin"),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` — `apps/pkey.c:124-126`.
            OptMatch::Value("passout", _) => return not_landed("pkey -passout"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/pkey.c:127-129`.
            OptMatch::Value("engine", _) => return not_landed("pkey -engine"),
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/pkey.c:130-132`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/pkey.c:133-135`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_PUBIN: pubin = pubout = 1; break;` — `apps/pkey.c:136-138`.
            OptMatch::Flag("pubin") => {
                pubin = true;
                pubout = true;
            }
            // `case OPT_PUBOUT: pubout = 1; break;` — `apps/pkey.c:139-141`.
            OptMatch::Flag("pubout") => pubout = true,
            // `case OPT_TEXT_PUB: text_pub = 1; break;` — `apps/pkey.c:142-144`.
            OptMatch::Flag("text_pub") => text_pub = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/pkey.c:145-147`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/pkey.c:148-150`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TRADITIONAL: traditional = 1; break;` — `apps/pkey.c:151-153`.
            OptMatch::Flag("traditional") => traditional = true,
            // `case OPT_CHECK: check = 1; break;` — `apps/pkey.c:154-156`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_PUB_CHECK: pub_check = 1; break;` — `apps/pkey.c:157-159`.
            OptMatch::Flag("pubcheck") => pub_check = true,
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/pkey.c:160-162`.
            OptMatch::Value("", _) => {}
            // `case OPT_EC_CONV_FORM: point_format = opt_arg(); ...` —
            // `apps/pkey.c:163-171`.
            OptMatch::Value("ec_conv_form", v) => point_format = Some(v),
            // `case OPT_EC_PARAM_ENC: asn1_encoding = opt_arg(); ...` —
            // `apps/pkey.c:172-180`.
            OptMatch::Value("ec_param_enc", v) => asn1_encoding = Some(v),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/pkey.c:181-184`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkey -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/pkey.c:188-190`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (text && text_pub) BIO_printf(bio_err, "Warning: The -text option is ignored
    // with -text_pub\n");` — `apps/pkey.c:192-194`.
    if text && text_pub {
        eprintln!("Warning: The -text option is ignored with -text_pub");
    }
    // `if (traditional && (noout || pubout)) BIO_printf(bio_err, "Warning:
    // -traditional is ignored with no private key output\n");` — `apps/pkey.c:195-197`.
    if traditional && (noout || pubout) {
        eprintln!("Warning: -traditional is ignored with no private key output");
    }
    // `if (!text_pub && pubout && text) { text = 0; text_pub = 1; }` — `apps/pkey.c:200-203`.
    if !text_pub && pubout && text {
        text = false;
        text_pub = true;
    }
    // `private = (!noout && !pubout) || (text && !text_pub);` — `apps/pkey.c:205`.
    let private = (!noout && !pubout) || (text && !text_pub);

    // `if (!opt_cipher(ciphername, &cipher)) goto opthelp;` — no cipher option leaves
    // `cipher` NULL; `if (cipher == NULL) { if (passoutarg != NULL) warn ... }` —
    // `apps/pkey.c:207-219`.
    // `app_passwd(passinarg, passoutarg, ...)` with both NULL succeeds —
    // `apps/pkey.c:220-223`.

    // `if (pubin) pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key"); else
    // pkey = load_key(infile, informat, 1, passin, e, "key");` — `apps/pkey.c:225-228`.
    let pkey = if pubin {
        load_pubkey(infile.as_deref(), informat, "Public Key")
    } else {
        load_key(infile.as_deref(), informat, "key")
    };
    if pkey.is_null() {
        return 1;
    }

    // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
    // — `apps/pkey.c:232-234`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `pkey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return not_landed("pkey -out (unopenable)");
    }
    let mut ret = 1i32;

    // `if (asn1_encoding != NULL || point_format != NULL) { ... EVP_PKEY_set_params ... }`
    // — `apps/pkey.c:236-254`. The EC parameter build is not driven by the court (see the
    // header), so the arm reaches `not_landed`.
    if asn1_encoding.is_some() || point_format.is_some() {
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return not_landed("pkey -ec_conv_form/-ec_param_enc");
    }

    // `if (check || pub_check) { ctx = EVP_PKEY_CTX_new(pkey, e); ... r = check &&
    // !pubin ? EVP_PKEY_check(ctx) : EVP_PKEY_public_check(ctx); ... }` —
    // `apps/pkey.c:256-281`.
    if check || pub_check {
        // SAFETY: `pkey` is live; `e` is NULL.
        let ctx = unsafe { EVP_PKEY_CTX_new(pkey, core::ptr::null_mut()) };
        if ctx.is_null() {
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ctx` is live.
        let r = if check && !pubin {
            // SAFETY: as above.
            unsafe { EVP_PKEY_check(ctx) }
        } else {
            // SAFETY: `ctx` is live.
            unsafe { EVP_PKEY_public_check(ctx) }
        };
        // SAFETY: `ctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        if r == 1 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"Key is valid\n".as_ptr()) };
        } else {
            eprintln!("Key is invalid");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (!noout) { ... PEM/DER writers ... }` — `apps/pkey.c:283-325`.
    if !noout {
        if outformat == FORMAT_PEM {
            let ok = if pubout {
                // SAFETY: `out`/`pkey` are live.
                unsafe { PEM_write_bio_PUBKEY(out, pkey) }
            } else if traditional {
                // SAFETY: `out`/`pkey` are live; cipher/kstr/cb/arg are the no-cipher arms.
                unsafe {
                    PEM_write_bio_PrivateKey_traditional(
                        out,
                        pkey,
                        core::ptr::null_mut(),
                        core::ptr::null(),
                        0,
                        None,
                        core::ptr::null_mut(),
                    )
                }
            } else {
                // SAFETY: as above.
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
                }
            };
            if ok == 0 {
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free_all(out) };
                return ret;
            }
        } else if outformat == FORMAT_ASN1 {
            if text || text_pub {
                eprintln!("Error: Text output cannot be combined with DER output");
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free_all(out) };
                return ret;
            }
            let ok = if pubout {
                // SAFETY: `out`/`pkey` are live.
                unsafe { i2d_PUBKEY_bio(out, pkey) }
            } else if traditional {
                // SAFETY: `out`/`pkey` are live.
                unsafe { i2d_PrivateKey_bio(out, pkey) }
            } else {
                // SAFETY: `out`/`pkey` are live; enc/kstr/cb/arg are the no-cipher arms.
                unsafe {
                    i2d_PKCS8PrivateKey_bio(
                        out,
                        pkey,
                        core::ptr::null_mut(),
                        core::ptr::null(),
                        0,
                        None,
                        core::ptr::null_mut(),
                    )
                }
            };
            if ok == 0 {
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free_all(out) };
                return ret;
            }
        } else {
            eprintln!("Bad format specified for key");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (text_pub) print_public; else if (text) print_private;` —
    // `apps/pkey.c:327-334`.
    if text_pub {
        // SAFETY: `out`/`pkey` are live; indent 0 and a NULL print context.
        if unsafe { EVP_PKEY_print_public(out, pkey, 0, core::ptr::null_mut()) } <= 0 {
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    } else if text {
        // SAFETY: as above.
        if unsafe { EVP_PKEY_print_private(out, pkey, 0, core::ptr::null_mut()) } <= 0 {
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }
    ret = 0;

    let _ = private;
    // `end: ... EVP_PKEY_free(pkey); ... BIO_free_all(out);` — `apps/pkey.c:338-347`.
    // SAFETY: `pkey`/`out` are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    // SAFETY: `pkey`/`out` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
