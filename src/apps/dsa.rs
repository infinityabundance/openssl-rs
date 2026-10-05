//! Phase 17.1d — `apps/dsa.c`: the `openssl dsa` command.
//!
//! The command body (`apps/dsa.c:89-319`): parse the generated `DSA_OPTIONS` table,
//! print `read DSA key` to stderr, load a private or public DSA key, optionally print
//! its text or `-modulus` (the `pub` parameter), then re-encode it through
//! `OSSL_ENCODER_CTX_new_for_pkey`/`OSSL_ENCODER_to_bio` unless `-noout`. The parse,
//! the key load, the two print arms and the encoder arm are transcribed.
//!
//! ## What the court drives
//!
//! `dsa -in <dsa-key.pem> -noout -text` (the private text print, with its `read DSA
//! key` stderr line), `dsa -in <dsa-pub.pem> -pubin -noout -text` (the public arm) and
//! the default `dsa -in <dsa-key.pem>`, which re-encodes through the encoder and prints
//! `writing DSA key`.
//!
//! ## Recorded divergences (module header)
//!
//! * **The `-modulus` arm is not driven.** `BN_print`'s rendering diverges
//!   (`src/bn/bignum.rs`, the `prime` court's recorded divergence): the authority strips
//!   leading nibbles and writes uppercase, the crate pads to whole bytes and writes
//!   lowercase, so `Public Key=<hex>` cannot be diffed. The body is transcribed.
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/dsa.c:107`); an unknown
//!   option is the parser's refusal rather than a cipher name. Not driven.
//! * **`opt_cipher`/`app_passwd`/`bio_open_owner` are `apps/lib` helpers** reconstructed
//!   at the observable; no cipher and no pass phrase is driven.
//! * **`-engine` is not landed** (`apps/dsa.c:135-137`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_key, load_pubkey, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::DSA_OPTIONS;
use crate::bn::bignum::{BN_free, BN_print, BigNum};
use crate::encoder_lib::{OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{
    EVP_PKEY_get_bn_param, EVP_PKEY_is_a, EVP_PKEY_print_private, EVP_PKEY_print_public,
};

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `FORMAT_MSBLOB` — the `M`/`m` arm of `opt_format`.
const FORMAT_MSBLOB: c_int = 8;
/// `FORMAT_PVK` — the `PVK` arm of `opt_format`.
const FORMAT_PVK: c_int = 6;
/// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-651`.
const SELECT_PUBLIC_KEY: c_int = 0x02;
const SELECT_ALL: c_int = 0x87;

/// `opt_format(s, OPT_FMT_ANY, result)` — the PEM/DER/MSBLOB/PVK bodies
/// `apps/dsa.c:121-130` and `apps/lib/opt.c:277-365` need.
fn opt_format_any(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'P') | Some(b'p') => {
            if b.len() == 1 || s == "PEM" || s == "pem" {
                *result = FORMAT_PEM;
                true
            } else if s == "PVK" || s == "pvk" {
                *result = FORMAT_PVK;
                true
            } else {
                eprintln!("{prog}: Bad format \"{s}\"");
                false
            }
        }
        Some(b'D') | Some(b'd') => {
            *result = FORMAT_ASN1;
            true
        }
        Some(b'M') | Some(b'm') => {
            *result = FORMAT_MSBLOB;
            true
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

/// `int dsa_main(int argc, char **argv)` — `apps/dsa.c:89-319`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, dsa_options);` —
    // `apps/dsa.c:107-108`.
    let mut opts = Opts::init(argv, DSA_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut text = false;
    let mut noout = false;
    let mut modulus = false;
    let mut pubin = false;
    let mut pubout = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/dsa.c:109`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(dsa_options); ret = 0; goto end;` —
            // `apps/dsa.c:117-120`.
            OptMatch::Help => return not_landed("dsa -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: ret = 0; BIO_printf(bio_err, "%s:
            // Use -help for summary.\n", prog); goto end;` — `apps/dsa.c:111-116`. Note
            // the authority sets `ret = 0` here, unlike its sibling commands.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 0;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
            // goto opthelp;` — `apps/dsa.c:121-124`.
            OptMatch::Value("inform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 0;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/dsa.c:125-127`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
            // goto opthelp;` — `apps/dsa.c:128-131`.
            OptMatch::Value("outform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 0;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/dsa.c:132-134`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/dsa.c:135-137`.
            OptMatch::Value("engine", _) => return not_landed("dsa -engine"),
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/dsa.c:138-140`.
            OptMatch::Value("passin", _) => return not_landed("dsa -passin"),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` — `apps/dsa.c:141-143`.
            OptMatch::Value("passout", _) => return not_landed("dsa -passout"),
            // `case OPT_PVK_STRONG: case OPT_PVK_WEAK: case OPT_PVK_NONE: pvk_encr =
            // (o - OPT_PVK_NONE); break;` — `apps/dsa.c:144-150`.
            OptMatch::Flag("pvk-strong")
            | OptMatch::Flag("pvk-weak")
            | OptMatch::Flag("pvk-none") => {}
            // `case OPT_NOOUT: noout = 1; break;` — `apps/dsa.c:151-153`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/dsa.c:154-156`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_MODULUS: modulus = 1; break;` — `apps/dsa.c:157-159`.
            OptMatch::Flag("modulus") => modulus = true,
            // `case OPT_PUBIN: pubin = 1; break;` — `apps/dsa.c:160-162`.
            OptMatch::Flag("pubin") => pubin = true,
            // `case OPT_PUBOUT: pubout = 1; break;` — `apps/dsa.c:163-165`.
            OptMatch::Flag("pubout") => pubout = true,
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` — `apps/dsa.c:166-168`.
            OptMatch::Value("", _) => {}
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/dsa.c:169-172`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("dsa -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 0;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/dsa.c:176-178`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 0;
    }

    // `private = !pubin && (!pubout || text);` — `apps/dsa.c:182`.
    let private = !pubin && (!pubout || text);
    let _ = private;

    // `BIO_printf(bio_err, "read DSA key\n");` — `apps/dsa.c:189`.
    eprintln!("read DSA key");
    // `if (pubin) pkey = load_pubkey(infile, informat, 1, passin, e, "public key"); else
    // pkey = load_key(infile, informat, 1, passin, e, "private key");` —
    // `apps/dsa.c:190-193`.
    let pkey = if pubin {
        load_pubkey(infile.as_deref(), informat, "public key")
    } else {
        load_key(infile.as_deref(), informat, "private key")
    };
    if pkey.is_null() {
        eprintln!("unable to load Key");
        return 1;
    }
    // `if (!EVP_PKEY_is_a(pkey, "DSA")) { ... "Not a DSA key" ... }` —
    // `apps/dsa.c:200-203`.
    // SAFETY: `pkey` is live; the name is a static literal.
    if unsafe { EVP_PKEY_is_a(pkey, c"DSA".as_ptr()) } == 0 {
        eprintln!("Not a DSA key");
        // SAFETY: `pkey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return 1;
    }

    // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
    // — `apps/dsa.c:205-207`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `pkey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return not_landed("dsa -out (unopenable)");
    }
    let mut ret = 1i32;

    // `if (text) { ... }` — `apps/dsa.c:209-217`.
    if text {
        let ok = if pubin {
            // SAFETY: `out`/`pkey` are live; indent 0 and a NULL print context.
            unsafe { EVP_PKEY_print_public(out, pkey, 0, core::ptr::null_mut()) }
        } else {
            // SAFETY: as above.
            unsafe { EVP_PKEY_print_private(out, pkey, 0, core::ptr::null_mut()) }
        };
        if ok <= 0 {
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (modulus) { EVP_PKEY_get_bn_param(pkey, "pub", &pub_key); BIO_printf(out,
    // "Public Key="); BN_print(out, pub_key); BIO_printf(out, "\n"); BN_free(pub_key);
    // }` — `apps/dsa.c:219-230`. Not driven (`BN_print` rendering diverges).
    if modulus {
        let mut pub_key: *mut BigNum = core::ptr::null_mut();
        // SAFETY: `pkey` is live; `pub_key` is this frame's out-slot; the name is static.
        unsafe { EVP_PKEY_get_bn_param(pkey, c"pub".as_ptr(), &mut pub_key) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"Public Key=".as_ptr()) };
        // SAFETY: `out`/`pub_key` are live (pub_key may be NULL).
        unsafe { BN_print(out, pub_key) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"\n".as_ptr()) };
        // SAFETY: `pub_key` is NULL or live and not freed again.
        unsafe { BN_free(pub_key) };
    }

    if noout {
        ret = 0;
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }
    // `BIO_printf(bio_err, "writing DSA key\n");` — `apps/dsa.c:236`.
    eprintln!("writing DSA key");

    // `if (outformat == FORMAT_ASN1) output_type = "DER"; else if (FORMAT_PEM) "PEM";
    // else if (FORMAT_MSBLOB) "MSBLOB"; else if (FORMAT_PVK) { if (pubin) {...}; "PVK";
    // } else { "bad output format specified for outfile"; }` — `apps/dsa.c:237-252`.
    let output_type = match outformat {
        FORMAT_ASN1 => "DER",
        FORMAT_PEM => "PEM",
        FORMAT_MSBLOB => "MSBLOB",
        FORMAT_PVK => {
            if pubin {
                eprintln!("PVK form impossible with public key input");
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
                // SAFETY: `pkey`/`out` are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free_all(out) };
                return ret;
            }
            "PVK"
        }
        _ => {
            eprintln!("bad output format specified for outfile");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    };

    // `if (outformat == FORMAT_ASN1 || outformat == FORMAT_PEM) { if (pubout || pubin)
    // output_structure = "SubjectPublicKeyInfo"; else output_structure =
    // "type-specific"; }` — `apps/dsa.c:254-259`.
    let output_structure: Option<&str> = if outformat == FORMAT_ASN1 || outformat == FORMAT_PEM {
        if pubout || pubin {
            Some("SubjectPublicKeyInfo")
        } else {
            Some("type-specific")
        }
    } else {
        None
    };
    // `selection` — `apps/dsa.c:261-268`.
    let selection = if pubout || pubin {
        SELECT_PUBLIC_KEY
    } else {
        SELECT_ALL
    };

    let out_type_c = std::ffi::CString::new(output_type).unwrap_or_default();
    let out_struct_c = output_structure.map(|s| std::ffi::CString::new(s).unwrap_or_default());
    // SAFETY: `pkey` is live; the strings are NUL-terminated; propq NULL.
    let ectx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            pkey,
            selection,
            out_type_c.as_ptr(),
            out_struct_c
                .as_ref()
                .map_or(core::ptr::null(), |c| c.as_ptr()),
            core::ptr::null(),
        )
    };
    // `if (OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0) { "%s format not supported";
    // goto end; }` — `apps/dsa.c:273-276`.
    // SAFETY: `ectx` is live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ectx) } == 0 {
        eprintln!("{output_type} format not supported");
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }
    // `if (!OSSL_ENCODER_to_bio(ectx, out)) { "unable to write key"; goto end; }` —
    // `apps/dsa.c:303-306`.
    // SAFETY: `ectx`/`out` are live.
    if unsafe { OSSL_ENCODER_to_bio(ectx, out) } == 0 {
        eprintln!("unable to write key");
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }
    ret = 0;

    // `end: ... OSSL_ENCODER_CTX_free(ectx); BIO_free_all(out); EVP_PKEY_free(pkey);
    // ...` — `apps/dsa.c:308-318`.
    // SAFETY: all three are live and not freed again.
    unsafe { OSSL_ENCODER_CTX_free(ectx) };
    // SAFETY: all three are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    // SAFETY: all three are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
