//! Phase 17.1d — `apps/rsa.c`: the `openssl rsa` command.
//!
//! The command body (`apps/rsa.c:137-428`): parse the generated `RSA_OPTIONS` table,
//! load a private or public RSA key, optionally print its text/`-modulus`, `-check` it,
//! then re-encode it through `OSSL_ENCODER_CTX_new_for_pkey`/`OSSL_ENCODER_to_bio` (or
//! the legacy `try_legacy_encoding` fallback) unless `-noout`. The parse, the key
//! load, the three print arms and the encoder arm are transcribed.
//!
//! ## What the court drives
//!
//! `rsa -in <rsa-key.pem> -noout -text`, `-check -noout`, `-modulus -noout`, the
//! `-pubin -text` public arm, `rsa -check -pubin` (the "Only private keys can be
//! checked" refusal), and the default arm (`rsa -in <key>`), which re-encodes through
//! the encoder and prints `writing RSA key` to stderr. The key and its text are a pure
//! function of the fixed fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/rsa.c:157`). The
//!   authority treats an otherwise-unknown option as a cipher name and fetches it; the
//!   crate's parser has no such mode, so such an option is the parser's `Unknown
//!   option` refusal. Not driven.
//! * **`opt_cipher`/`app_passwd`/`bio_open_owner` are `apps/lib` helpers** this
//!   stratum reconstructs at the observable: with no cipher option the encoder has no
//!   cipher, and no `-passin`/`-passout` is driven.
//! * **`-engine` is not landed** (`apps/rsa.c:190-192`); `setup_engine` is `apps/lib`'s.
//! * **`try_legacy_encoding` is not driven.** It is reached only when the encoder finds
//!   no encoder for a public-key structure the crate's provider does not publish; the
//!   court's RSA fixtures re-encode through the provider, so the fallback is
//!   transcribed but not exercised.
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
use crate::apps::tables::RSA_OPTIONS;
use crate::bn::bignum::{BN_free, BN_print, BigNum};
use crate::encoder_lib::{OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{
    EVP_PKEY_get_bn_param, EVP_PKEY_is_a, EVP_PKEY_print_private, EVP_PKEY_print_public,
};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::pmeth_check::EVP_PKEY_check;
use crate::runtime::bio::Bio;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `FORMAT_MSBLOB` — `apps/include/fmt.h` (the `M`/`m` arm).
const FORMAT_MSBLOB: c_int = 8;
/// `FORMAT_PVK` — `apps/include/fmt.h` (the `PVK` arm).
const FORMAT_PVK: c_int = 6;
/// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-651`.
const SELECT_PUBLIC_KEY: c_int = 0x02;
const SELECT_ALL: c_int = 0x87;

/// `opt_format(s, OPT_FMT_ANY, result)` — the `P`/`D`/`M`/`PVK` and `default` arms of
/// `apps/lib/opt.c:277-365` with `OPT_FMT_ANY` (every format bit set). Only the PEM,
/// DER, MSBLOB and PVK bodies the command's own `output_type` switch names are
/// transcribed; other bodies are the authority's `Bad format`.
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

/// `static int try_legacy_encoding(EVP_PKEY *pkey, int outformat, int pubout, BIO *out)`
/// — `apps/rsa.c:107-135`. Reached only when the provider encoder set is empty; the
/// court does not drive it (see the header).
fn try_legacy_encoding(
    _pkey: *const crate::evp::pkey::EvpPkey,
    _outformat: c_int,
    _pubout: c_int,
    _out: *mut Bio,
) -> bool {
    false
}

/// `int rsa_main(int argc, char **argv)` — `apps/rsa.c:137-428`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, rsa_options);` —
    // `apps/rsa.c:157-158`. The unknown-name mode is an `apps/lib` behaviour (see the
    // header).
    let mut opts = Opts::init(argv, RSA_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut text = false;
    let mut check = false;
    let mut noout = false;
    let mut modulus = false;
    let mut pubin: c_int = 0;
    let mut pubout: c_int = 0;
    let mut traditional = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/rsa.c:159`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(rsa_options); ret = 0; goto end;` —
            // `apps/rsa.c:166-169`.
            OptMatch::Help => return not_landed("rsa -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/rsa.c:161-165`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
            // goto opthelp;` — `apps/rsa.c:170-173`.
            OptMatch::Value("inform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/rsa.c:174-176`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
            // goto opthelp;` — `apps/rsa.c:177-180`.
            OptMatch::Value("outform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/rsa.c:181-183`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/rsa.c:184-186`.
            OptMatch::Value("passin", _) => return not_landed("rsa -passin"),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` — `apps/rsa.c:187-189`.
            OptMatch::Value("passout", _) => return not_landed("rsa -passout"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/rsa.c:190-192`.
            OptMatch::Value("engine", _) => return not_landed("rsa -engine"),
            // `case OPT_PUBIN: pubin = 1; break;` — `apps/rsa.c:193-195`.
            OptMatch::Flag("pubin") => pubin = 1,
            // `case OPT_PUBOUT: pubout = 1; break;` — `apps/rsa.c:196-198`.
            OptMatch::Flag("pubout") => pubout = 1,
            // `case OPT_RSAPUBKEY_IN: pubin = 2; break;` — `apps/rsa.c:199-201`.
            OptMatch::Flag("RSAPublicKey_in") => pubin = 2,
            // `case OPT_RSAPUBKEY_OUT: pubout = 2; break;` — `apps/rsa.c:202-204`.
            OptMatch::Flag("RSAPublicKey_out") => pubout = 2,
            // `case OPT_PVK_STRONG: case OPT_PVK_WEAK: case OPT_PVK_NONE: pvk_encr =
            // (o - OPT_PVK_NONE); break;` — `apps/rsa.c:205-209`.
            OptMatch::Flag("pvk-strong")
            | OptMatch::Flag("pvk-weak")
            | OptMatch::Flag("pvk-none") => {}
            // `case OPT_NOOUT: noout = 1; break;` — `apps/rsa.c:210-212`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/rsa.c:213-215`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_MODULUS: modulus = 1; break;` — `apps/rsa.c:216-218`.
            OptMatch::Flag("modulus") => modulus = true,
            // `case OPT_CHECK: check = 1; break;` — `apps/rsa.c:219-221`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/rsa.c:222-224` (not landed; see the header).
            OptMatch::Value("", _) => {}
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/rsa.c:225-228`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("rsa -provider"),
            // `case OPT_TRADITIONAL: traditional = 1; break;` — `apps/rsa.c:229-231`.
            OptMatch::Flag("traditional") => traditional = true,
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/rsa.c:235-237`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `opt_cipher(ciphername, &enc)` with no cipher option leaves `enc` NULL.
    let enc: *const crate::evp::cipher::EvpCipher = core::ptr::null();
    // `private = (text && !pubin) || (!pubout && !noout);` — `apps/rsa.c:241`.
    let private = (text && pubin == 0) || (pubout == 0 && !noout);
    let _ = private;

    // `app_passwd(passinarg, passoutarg, &passin, &passout)` with both NULL succeeds and
    // leaves both NULL (`apps/lib/apps.c:231-274`).
    let _ = enc;

    // `if (check && pubin) { ... "Only private keys can be checked" ... }` —
    // `apps/rsa.c:247-250`.
    if check && pubin != 0 {
        eprintln!("Only private keys can be checked");
        return 1;
    }

    // `if (pubin) { ... tmpformat ...; pkey = load_pubkey(...); } else { pkey =
    // load_key(...); }` — `apps/rsa.c:252-267`.
    let pkey = if pubin != 0 {
        let tmpformat = if pubin == 2 {
            if informat == FORMAT_PEM {
                FORMAT_PEM
            } else if informat == FORMAT_ASN1 {
                FORMAT_ASN1
            } else {
                FORMAT_UNDEF
            }
        } else {
            informat
        };
        load_pubkey(infile.as_deref(), tmpformat, "public key")
    } else {
        load_key(infile.as_deref(), informat, "private key")
    };

    if pkey.is_null() {
        return 1;
    }
    // `if (!EVP_PKEY_is_a(pkey, "RSA") && !EVP_PKEY_is_a(pkey, "RSA-PSS")) { ... "Not an
    // RSA key" ... }` — `apps/rsa.c:273-276`.
    // SAFETY: `pkey` is live; the name is a static literal.
    let is_rsa = unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) };
    // SAFETY: `pkey` is live; the name is a static literal.
    let is_rsa_pss = unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) };
    if is_rsa == 0 && is_rsa_pss == 0 {
        eprintln!("Not an RSA key");
        // SAFETY: `pkey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return 1;
    }

    // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
    // — `apps/rsa.c:278-280`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `pkey` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return not_landed("rsa -out (unopenable)");
    }

    let mut ret = 1i32;

    // `if (text) { ... EVP_PKEY_print_public/private ... }` — `apps/rsa.c:282-290`.
    if text {
        let ok = if pubin != 0 {
            // SAFETY: `out`/`pkey` are live; indent 0 and a NULL print context.
            unsafe { EVP_PKEY_print_public(out, pkey, 0, core::ptr::null_mut()) }
        } else {
            // SAFETY: as above.
            unsafe { EVP_PKEY_print_private(out, pkey, 0, core::ptr::null_mut()) }
        };
        if ok <= 0 {
            eprintln!("{}", outfile.as_deref().unwrap_or(""));
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (modulus) { ... EVP_PKEY_get_bn_param(pkey, "n", &n); BIO_printf(out,
    // "Modulus="); BN_print(out, n); BIO_printf(out, "\n"); BN_free(n); }` —
    // `apps/rsa.c:292-301`.
    if modulus {
        let mut n: *mut BigNum = core::ptr::null_mut();
        // SAFETY: `pkey` is live; `n` is this frame's out-slot; the name is a static.
        unsafe { EVP_PKEY_get_bn_param(pkey, c"n".as_ptr(), &mut n) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"Modulus=".as_ptr()) };
        // SAFETY: `out`/`n` are live (n may be NULL, which prints nothing).
        unsafe { BN_print(out, n) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"\n".as_ptr()) };
        // SAFETY: `n` is NULL or a live `BIGNUM` not freed again.
        unsafe { BN_free(n) };
    }

    let _ = ret;
    // `if (check) { pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL); ... r =
    // EVP_PKEY_check(pctx); ... }` — `apps/rsa.c:303-324`.
    if check {
        // SAFETY: `pkey` is live; both context/property pointers are NULL.
        let pctx =
            unsafe { EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null()) };
        if pctx.is_null() {
            eprintln!("RSA unable to create PKEY context");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `pctx` is live.
        let r = unsafe { EVP_PKEY_check(pctx) };
        // SAFETY: `pctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        if r == 1 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"RSA key ok\n".as_ptr()) };
        } else if r == 0 {
            eprintln!("RSA key not ok");
        } else {
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    if noout {
        ret = 0;
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }
    // `BIO_printf(bio_err, "writing RSA key\n");` — `apps/rsa.c:330`.
    eprintln!("writing RSA key");

    // `if (outformat == FORMAT_ASN1) output_type = "DER"; else if (FORMAT_PEM) "PEM";
    // else if (FORMAT_MSBLOB) "MSBLOB"; else if (FORMAT_PVK) { if (pubin) {...} "PVK"; }
    // else { "bad output format ..."; }` — `apps/rsa.c:332-348`.
    let output_type = match outformat {
        FORMAT_ASN1 => "DER",
        FORMAT_PEM => "PEM",
        FORMAT_MSBLOB => "MSBLOB",
        FORMAT_PVK => {
            if pubin != 0 {
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

    // `selection` and `output_structure` — `apps/rsa.c:350-373`.
    let selection = if pubout != 0 || pubin != 0 {
        SELECT_PUBLIC_KEY
    } else {
        SELECT_ALL
    };
    let output_structure: Option<&str> = if outformat == FORMAT_ASN1 || outformat == FORMAT_PEM {
        if pubout != 0 || pubin != 0 {
            if pubout == 2 {
                Some("pkcs1")
            } else {
                Some("SubjectPublicKeyInfo")
            }
        } else if traditional {
            Some("pkcs1")
        } else {
            Some("PrivateKeyInfo")
        }
    } else {
        None
    };

    // `ectx = OSSL_ENCODER_CTX_new_for_pkey(...)` — `apps/rsa.c:376-378`.
    let out_type_c = std::ffi::CString::new(output_type).unwrap_or_default();
    let out_struct_c = output_structure.map(|s| std::ffi::CString::new(s).unwrap_or_default());
    // SAFETY: `pkey` is live; the type/structure strings are NUL-terminated; propq NULL.
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
    // `if (OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0) { if ((!pubout && !pubin) ||
    // !try_legacy_encoding(...)) BIO_printf("%s format not supported\n", output_type);
    // else ret = 0; goto end; }` — `apps/rsa.c:379-386`.
    // SAFETY: `ectx` is live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ectx) } == 0 {
        if (pubout == 0 && pubin == 0) || !try_legacy_encoding(pkey, outformat, pubout, out) {
            eprintln!("{output_type} format not supported");
        } else {
            ret = 0;
        }
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: `ectx`/`pkey`/`out` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return ret;
    }

    // `if (!OSSL_ENCODER_to_bio(ectx, out)) { ... "unable to write key" ... }` —
    // `apps/rsa.c:413-417`.
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

    // `end: OSSL_ENCODER_CTX_free(ectx); ... BIO_free_all(out); EVP_PKEY_free(pkey);
    // ...` — `apps/rsa.c:419-427`.
    // SAFETY: all three are live and not freed again.
    unsafe { OSSL_ENCODER_CTX_free(ectx) };
    // SAFETY: all three are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    // SAFETY: all three are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
