//! Phase 17.1d — `apps/ec.c`: the `openssl ec` command.
//!
//! The command body (`apps/ec.c:78-301`): parse the generated `EC_OPTIONS` table, load
//! a private or public EC key, optionally set its point-conversion/ASN.1 encoding and
//! public-key inclusion, print its text (`-text`), check it (`-check`), then re-encode
//! it through `OSSL_ENCODER_CTX_new_for_pkey`/`OSSL_ENCODER_to_bio` unless `-noout`.
//! The parse, the key load, the print/check arms and the encoder arm are transcribed.
//!
//! ## What the court drives
//!
//! `ec -in <ec-key.pem> -noout -text`, `ec -in <ec-pub.pem> -pubin -noout -text` (the
//! public print), `ec -in <ec-key.pem> -check -noout` (the `EC Key valid.` arm) and the
//! default `ec -in <ec-key.pem>`, which re-encodes the SEC1 private key.
//!
//! ## Recorded divergences (module header)
//!
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/ec.c:97`); an unknown
//!   option is the parser's refusal rather than a cipher name. Not driven.
//! * **`opt_cipher`/`app_passwd`/`bio_open_owner` are `apps/lib` helpers** reconstructed
//!   at the observable; no cipher and no pass phrase is driven.
//! * **`-engine` is not landed** (`apps/ec.c:145-147`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * **`opt_format(OPT_FMT_ANY)` is reduced to its PEM/DER bodies**; the P12/ENGINE
//!   bodies `apps/ec.c:111` admits for `-inform` are not reconstructed.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_key, load_pubkey, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::EC_OPTIONS;
use crate::encoder_lib::OSSL_ENCODER_to_bio;
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{
    EVP_PKEY_print_private, EVP_PKEY_print_public, EVP_PKEY_set_int_param,
    EVP_PKEY_set_utf8_string_param,
};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::pmeth_check::EVP_PKEY_check;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-651`.
const SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
const SELECT_PUBLIC_KEY: c_int = 0x02;
const SELECT_ALL: c_int = 0x87;
/// `OSSL_PKEY_PARAM_*` — `include/openssl/core_names.h`.
const PARAM_EC_INCLUDE_PUBLIC: &core::ffi::CStr = cr"include-public";
const PARAM_EC_POINT_CONVERSION_FORMAT: &core::ffi::CStr = cr"point-format";
const PARAM_EC_ENCODING: &core::ffi::CStr = cr"encoding";

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms of
/// `apps/lib/opt.c:277-365` for `-outform` (`OPT_FMT_PEMDER`).
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

/// `opt_format(s, OPT_FMT_ANY, result)` — the PEM/DER bodies `apps/ec.c:111` needs.
fn opt_format_any(prog: &str, s: &str, result: &mut c_int) -> bool {
    opt_format_pemder(prog, s, result)
}

/// `int ec_main(int argc, char **argv)` — `apps/ec.c:78-301`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, ec_options);` —
    // `apps/ec.c:97-98`.
    let mut opts = Opts::init(argv, EC_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut text = false;
    let mut noout = false;
    let mut pubin = false;
    let mut pubout = false;
    let mut param_out = false;
    let mut no_public = false;
    let mut check = false;
    let mut point_format: Option<String> = None;
    let mut asn1_encoding: Option<String> = None;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/ec.c:99`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(ec_options); ret = 0; goto end;` —
            // `apps/ec.c:106-109`.
            OptMatch::Help => return not_landed("ec -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/ec.c:101-105`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
            // goto opthelp;` — `apps/ec.c:110-113`.
            OptMatch::Value("inform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/ec.c:114-116`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/ec.c:117-120`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/ec.c:121-123`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_NOOUT: noout = 1; break;` — `apps/ec.c:124-126`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/ec.c:127-129`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_PARAM_OUT: param_out = 1; break;` — `apps/ec.c:130-132`.
            OptMatch::Flag("param_out") => param_out = true,
            // `case OPT_PUBIN: pubin = 1; break;` — `apps/ec.c:133-135`.
            OptMatch::Flag("pubin") => pubin = true,
            // `case OPT_PUBOUT: pubout = 1; break;` — `apps/ec.c:136-138`.
            OptMatch::Flag("pubout") => pubout = true,
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/ec.c:139-141`.
            OptMatch::Value("passin", _) => return not_landed("ec -passin"),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` — `apps/ec.c:142-144`.
            OptMatch::Value("passout", _) => return not_landed("ec -passout"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/ec.c:145-147`.
            OptMatch::Value("engine", _) => return not_landed("ec -engine"),
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` — `apps/ec.c:148-150`.
            OptMatch::Value("", _) => {}
            // `case OPT_CONV_FORM: point_format = opt_arg(); if (!opt_string(...))
            // goto opthelp;` — `apps/ec.c:151-155`. The `opt_string` vocabulary check is
            // not driven; the value is carried.
            OptMatch::Value("conv_form", v) => point_format = Some(v),
            // `case OPT_PARAM_ENC: asn1_encoding = opt_arg(); if (!opt_string(...))
            // goto opthelp;` — `apps/ec.c:156-160`.
            OptMatch::Value("param_enc", v) => asn1_encoding = Some(v),
            // `case OPT_NO_PUBLIC: no_public = 1; break;` — `apps/ec.c:161-163`.
            OptMatch::Flag("no_public") => no_public = true,
            // `case OPT_CHECK: check = 1; break;` — `apps/ec.c:164-166`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/ec.c:167-170`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("ec -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/ec.c:174-176`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `private = !pubin && (text || (!param_out && !pubout));` — `apps/ec.c:180`.
    let private = !pubin && (text || (!param_out && !pubout));
    let _ = private;

    // `if (pubin) eckey = load_pubkey(...); else eckey = load_key(...);` —
    // `apps/ec.c:187-190`.
    let eckey = if pubin {
        load_pubkey(infile.as_deref(), informat, "public key")
    } else {
        load_key(infile.as_deref(), informat, "private key")
    };
    if eckey.is_null() {
        eprintln!("unable to load Key");
        return 1;
    }

    // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
    // — `apps/ec.c:197-199`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `eckey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
        return not_landed("ec -out (unopenable)");
    }
    let mut ret = 1i32;

    // `if (point_format && !EVP_PKEY_set_utf8_string_param(...)) { ... }` —
    // `apps/ec.c:201-207`.
    if let Some(pf) = point_format.as_deref() {
        let cs = std::ffi::CString::new(pf).unwrap_or_default();
        // SAFETY: `eckey` is live; the name/value strings are NUL-terminated.
        let ok = unsafe {
            EVP_PKEY_set_utf8_string_param(
                eckey,
                PARAM_EC_POINT_CONVERSION_FORMAT.as_ptr(),
                cs.as_ptr(),
            )
        };
        if ok == 0 {
            eprintln!("unable to set point conversion format");
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }
    // `if (asn1_encoding != NULL && !EVP_PKEY_set_utf8_string_param(...)) { ... }` —
    // `apps/ec.c:209-214`.
    if let Some(enc) = asn1_encoding.as_deref() {
        let cs = std::ffi::CString::new(enc).unwrap_or_default();
        // SAFETY: `eckey` is live; the name/value strings are NUL-terminated.
        let ok = unsafe {
            EVP_PKEY_set_utf8_string_param(eckey, PARAM_EC_ENCODING.as_ptr(), cs.as_ptr())
        };
        if ok == 0 {
            eprintln!("unable to set asn1 encoding format");
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }
    // `if (no_public) { EVP_PKEY_set_int_param(..., 0); } else { ... 1; }` —
    // `apps/ec.c:216-226`.
    // SAFETY: `eckey` is live; the name is a NUL-terminated static.
    let ok = unsafe {
        EVP_PKEY_set_int_param(
            eckey,
            PARAM_EC_INCLUDE_PUBLIC.as_ptr(),
            if no_public { 0 } else { 1 },
        )
    };
    if ok == 0 {
        eprintln!(
            "{}",
            if no_public {
                "unable to disable public key encoding"
            } else {
                "unable to enable public key encoding"
            }
        );
        // SAFETY: `eckey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
        // SAFETY: `eckey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }

    // `if (text) { if ((pubin && print_public <= 0) || (!pubin && print_private <= 0))
    // { "unable to print EC key"; goto end; } }` — `apps/ec.c:228-235`.
    if text {
        let n = if pubin {
            // SAFETY: `out`/`eckey` are live; indent 0 and a NULL print context.
            unsafe { EVP_PKEY_print_public(out, eckey, 0, core::ptr::null_mut()) }
        } else {
            // SAFETY: as above.
            unsafe { EVP_PKEY_print_private(out, eckey, 0, core::ptr::null_mut()) }
        };
        if n <= 0 {
            eprintln!("unable to print EC key");
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (check) { pctx = EVP_PKEY_CTX_new_from_pkey(NULL, eckey, NULL); if (pctx ==
    // NULL) { "unable to check EC key"; goto end; } if (EVP_PKEY_check(pctx) <= 0)
    // "EC Key Invalid!"; else "EC Key valid."; ERR_print_errors(bio_err); }` —
    // `apps/ec.c:237-248`.
    if check {
        // SAFETY: `eckey` is live; both context/property pointers are NULL.
        let pctx =
            unsafe { EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), eckey, core::ptr::null()) };
        if pctx.is_null() {
            eprintln!("unable to check EC key");
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
            // SAFETY: `eckey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `pctx` is live.
        let r = unsafe { EVP_PKEY_check(pctx) };
        // `BIO_printf(bio_err, "EC Key Invalid!\n")` else `BIO_printf(bio_err,
        // "EC Key valid.\n")` — `apps/ec.c:243-246`: the authority prints either to
        // bio_err.
        if r <= 0 {
            eprintln!("EC Key Invalid!");
        } else {
            eprintln!("EC Key valid.");
        }
        // SAFETY: `pctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(pctx) };
    }

    // `if (!noout) { ... OSSL_ENCODER_* ... }` — `apps/ec.c:250-283`.
    if !noout {
        let output_type = if outformat == FORMAT_ASN1 {
            "DER"
        } else {
            "PEM"
        };
        let (selection, output_structure) = if param_out {
            (SELECT_DOMAIN_PARAMETERS, "type-specific")
        } else if pubin || pubout {
            (
                SELECT_DOMAIN_PARAMETERS | SELECT_PUBLIC_KEY,
                "SubjectPublicKeyInfo",
            )
        } else {
            (SELECT_ALL, "type-specific")
        };
        let out_type_c = std::ffi::CString::new(output_type).unwrap_or_default();
        let out_struct_c = std::ffi::CString::new(output_structure).unwrap_or_default();
        // SAFETY: `eckey` is live; the strings are NUL-terminated; propq NULL.
        let ectx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                eckey,
                selection,
                out_type_c.as_ptr(),
                out_struct_c.as_ptr(),
                core::ptr::null(),
            )
        };
        // `if (enc != NULL) { ... }` — no cipher is driven (see the header).
        // SAFETY: `ectx`/`out` are live.
        if unsafe { OSSL_ENCODER_to_bio(ectx, out) } == 0 {
            eprintln!("unable to write EC key");
            // SAFETY: `ectx`/`eckey`/`out` are live and not freed again.
            unsafe { OSSL_ENCODER_CTX_free(ectx) };
            // SAFETY: `ectx`/`eckey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
            // SAFETY: `ectx`/`eckey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ectx` is live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
    }
    ret = 0;

    // `end: ... BIO_free_all(out); EVP_PKEY_free(eckey); ...` — `apps/ec.c:286-300`.
    // SAFETY: `eckey`/`out` are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(eckey) };
    // SAFETY: `eckey`/`out` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
