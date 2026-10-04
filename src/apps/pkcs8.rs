//! Phase 17.1d — `apps/pkcs8.c`: the `openssl pkcs8` command.
//!
//! The command body (`apps/pkcs8.c:90-406`): parse the generated `PKCS8_OPTIONS` table,
//! then either convert a traditional/plain key into a PKCS#8 private-key-info
//! (`-topk8`, through `EVP_PKEY2PKCS8`) or read a PKCS#8 key back (`EVP_PKCS82PKEY`),
//! writing it as PEM/DER. The `-nocrypt` arms are transcribed whole; the encrypted
//! arms reach the PBE construction and the passphrase prompter.
//!
//! ## What the court drives
//!
//! `pkcs8 -topk8 -nocrypt -in <rsa-key.pem>`, `pkcs8 -topk8 -nocrypt -in
//! <rsa-key-trad.pem>` (a `PKCS#1 RSA PRIVATE KEY` re-wrapped as `PRIVATE KEY`), and
//! `pkcs8 -in <rsa-key.pem> -nocrypt` (the read-back arm). `-nocrypt` avoids the
//! random salt and the passphrase prompt, so the output is a pure function of the
//! fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **The encrypted arms are not driven.** Without `-nocrypt` the body builds a PBE
//!   with `PKCS5_pbe2_set_iv`/`PKCS5_pbe_set`, which draws a random salt and prompts for
//!   a password (`EVP_read_pw_string`), so the bytes are not deterministic and the
//!   `-passout` prompt is not reconstructed; those arms reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`app_RAND_load` with no `-rand`** is the authority's no-op success
//!   (`apps/lib/app_rand.c:66-79`).
//! * **`opt_cipher`/`app_passwd`/`bio_open_owner` are `apps/lib` helpers** reconstructed
//!   at the observable; the default `EVP_aes_256_cbc` cipher the authority assigns when
//!   none is named is unused by every driven `-nocrypt` arm.
//! * **`-engine` is not landed** (`apps/pkcs8.c:189-191`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_key, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKCS8_OPTIONS;
use crate::asn1::p8_pkey::{PKCS8_PRIV_KEY_INFO_free, Pkcs8PrivKeyInfo};
use crate::evp::evp_pkey::{EVP_PKCS82PKEY, EVP_PKEY2PKCS8};
use crate::pem::pem_pk8::{PEM_read_bio_PKCS8_PRIV_KEY_INFO, PEM_write_bio_PKCS8_PRIV_KEY_INFO};
use crate::pem::pem_pkey::{PEM_write_bio_PrivateKey, PEM_write_bio_PrivateKey_traditional};
use crate::x509::x_all::{
    d2i_PKCS8_PRIV_KEY_INFO_bio, i2d_PKCS8_PRIV_KEY_INFO_bio, i2d_PrivateKey_bio,
};

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

/// `int pkcs8_main(int argc, char **argv)` — `apps/pkcs8.c:90-406`.
#[allow(clippy::never_loop)] // every arms returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, pkcs8_options);` — `apps/pkcs8.c:113`.
    let mut opts = Opts::init(argv, PKCS8_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut topk8 = false;
    let mut nocrypt = false;
    let mut traditional = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/pkcs8.c:114`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(pkcs8_options); ret = 0; goto end;` —
            // `apps/pkcs8.c:121-124`.
            OptMatch::Help => return not_landed("pkcs8 -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/pkcs8.c:116-120`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
            // goto opthelp;` — `apps/pkcs8.c:125-128`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/pkcs8.c:129-131`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/pkcs8.c:132-135`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/pkcs8.c:136-138`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_TOPK8: topk8 = 1; break;` — `apps/pkcs8.c:139-141`.
            OptMatch::Flag("topk8") => topk8 = true,
            // `case OPT_NOITER: iter = 1; break;` — `apps/pkcs8.c:142-144`.
            OptMatch::Flag("noiter") => {}
            // `case OPT_NOCRYPT: nocrypt = 1; break;` — `apps/pkcs8.c:145-147`.
            OptMatch::Flag("nocrypt") => nocrypt = true,
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/pkcs8.c:148-151`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("pkcs8 -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/pkcs8.c:152-155`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkcs8 -provider"),
            // `case OPT_TRADITIONAL: traditional = 1; break;` — `apps/pkcs8.c:156-158`.
            OptMatch::Flag("traditional") => traditional = true,
            // `case OPT_V2: ciphername = opt_arg(); break;` — `apps/pkcs8.c:159-161`.
            OptMatch::Value("v2", _) => return not_landed("pkcs8 -v2"),
            // `case OPT_V1: pbe_nid = OBJ_txt2nid(opt_arg()); ...` — `apps/pkcs8.c:162-169`.
            OptMatch::Value("v1", _) => return not_landed("pkcs8 -v1"),
            // `case OPT_V2PRF: pbe_nid = OBJ_txt2nid(opt_arg()); ...` —
            // `apps/pkcs8.c:170-179`.
            OptMatch::Value("v2prf", _) => return not_landed("pkcs8 -v2prf"),
            // `case OPT_ITER: iter = opt_int_arg(); break;` — `apps/pkcs8.c:180-182`.
            OptMatch::Value("iter", _) => {}
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/pkcs8.c:183-185`.
            OptMatch::Value("passin", _) => return not_landed("pkcs8 -passin"),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` — `apps/pkcs8.c:186-188`.
            OptMatch::Value("passout", _) => return not_landed("pkcs8 -passout"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/pkcs8.c:189-191`.
            OptMatch::Value("engine", _) => return not_landed("pkcs8 -engine"),
            // `case OPT_SCRYPT*: ...` — `apps/pkcs8.c:193-211`.
            OptMatch::Flag("scrypt") => return not_landed("pkcs8 -scrypt"),
            OptMatch::Value("scrypt_N", _)
            | OptMatch::Value("scrypt_r", _)
            | OptMatch::Value("scrypt_p", _) => return not_landed("pkcs8 -scrypt_*"),
            // `case OPT_SALTLEN: if (!opt_int(opt_arg(), &saltlen)) goto opthelp;` —
            // `apps/pkcs8.c:212-216`.
            OptMatch::Value("saltlen", _) => {}
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/pkcs8.c:220-222`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `private = 1; if (!app_RAND_load()) goto end;` — `apps/pkcs8.c:224-226`. With no
    // `-rand` the authority's loader is a no-op success.

    // `in = bio_open_default(infile, 'r', informat == FORMAT_UNDEF ? FORMAT_PEM :
    // informat);` — `apps/pkcs8.c:241-244`.
    let inbio = bio_open_default(infile.as_deref(), false);
    if inbio.is_null() {
        return not_landed("pkcs8 -in (unopenable)");
    }

    // `if (topk8) { pkey = load_key(...); p8inf = EVP_PKEY2PKCS8(pkey); ... }` —
    // `apps/pkcs8.c:246-321`.
    if topk8 {
        let pkey = load_key(infile.as_deref(), informat, "key");
        if pkey.is_null() {
            // SAFETY: `inbio` is live.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return 1;
        }
        // SAFETY: `pkey` is live.
        let p8inf = unsafe { EVP_PKEY2PKCS8(pkey) };
        if p8inf.is_null() {
            eprintln!("Error converting key");
            // SAFETY: `pkey`/`inbio` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: `pkey`/`inbio` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return 1;
        }
        // `out = bio_open_owner(outfile, outformat, private);` — `apps/pkcs8.c:255-256`.
        let out = bio_open_default(outfile.as_deref(), true);
        if out.is_null() {
            // SAFETY: all three are live and not freed again.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return not_landed("pkcs8 -out (unopenable)");
        }
        if nocrypt {
            // `if (outformat == FORMAT_PEM) PEM_write_bio_PKCS8_PRIV_KEY_INFO; else if
            // (FORMAT_ASN1) i2d_PKCS8_PRIV_KEY_INFO_bio; else "Bad format ...";` —
            // `apps/pkcs8.c:257-266`.
            if outformat == FORMAT_PEM {
                // SAFETY: `out`/`p8inf` are live.
                unsafe { PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf) };
            } else if outformat == FORMAT_ASN1 {
                // SAFETY: `out`/`p8inf` are live.
                unsafe { i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf) };
            } else {
                eprintln!("Bad format specified for key");
                // SAFETY: all four are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free_all(out) };
                // SAFETY: all four are live and not freed again.
                unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
                // SAFETY: all four are live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
                // SAFETY: all four are live and not freed again.
                unsafe { crate::runtime::bio::BIO_free(inbio) };
                return 1;
            }
        } else {
            // The PBE encryption arm draws a random salt and prompts for a password.
            eprintln!("Error setting PBE algorithm");
            // SAFETY: all four are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            // SAFETY: all four are live and not freed again.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
            // SAFETY: all four are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            // SAFETY: all four are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return 1;
        }
        // SAFETY: all four are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: all four are live and not freed again.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        // SAFETY: all four are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: all four are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return 0;
    }

    // The read-back arms — `apps/pkcs8.c:323-362`.
    let p8inf: *mut Pkcs8PrivKeyInfo;
    if nocrypt {
        if informat == FORMAT_PEM || informat == FORMAT_UNDEF {
            // SAFETY: `inbio` is live; the out-slot is NULL and cb/arg are the
            // no-password arms.
            p8inf = unsafe {
                PEM_read_bio_PKCS8_PRIV_KEY_INFO(
                    inbio,
                    core::ptr::null_mut(),
                    None,
                    core::ptr::null_mut(),
                )
            };
        } else if informat == FORMAT_ASN1 {
            // SAFETY: `inbio` is live; the out-slot is NULL.
            p8inf = unsafe { d2i_PKCS8_PRIV_KEY_INFO_bio(inbio, core::ptr::null_mut()) };
        } else {
            eprintln!("Bad format specified for key");
            // SAFETY: `inbio` is live.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return 1;
        }
    } else {
        // The encrypted read arm decrypts with a pass phrase prompt; not driven.
        // SAFETY: `inbio` is live.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return not_landed("pkcs8 (encrypted read)");
    }

    if p8inf.is_null() {
        eprintln!("Error decrypting key");
        // SAFETY: `inbio` is live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return 1;
    }

    // `pkey = EVP_PKCS82PKEY(p8inf);` — `apps/pkcs8.c:370-374`.
    // SAFETY: `p8inf` is live.
    let pkey = unsafe { EVP_PKCS82PKEY(p8inf) };
    if pkey.is_null() {
        eprintln!("Error converting key");
        // SAFETY: `p8inf`/`inbio` are live and not freed again.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        // SAFETY: `p8inf`/`inbio` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return 1;
    }

    // `out = bio_open_owner(outfile, outformat, private);` — `apps/pkcs8.c:377-379`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: all three are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: all three are live and not freed again.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        // SAFETY: all three are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return not_landed("pkcs8 -out (unopenable)");
    }
    // `if (outformat == FORMAT_PEM) { if (traditional) private_key_traditional; else
    // private_key; } else if (FORMAT_ASN1) i2d_PrivateKey_bio; else "Bad format ...";`
    // — `apps/pkcs8.c:380-391`.
    if outformat == FORMAT_PEM {
        if traditional {
            // SAFETY: `out`/`pkey` are live; the cipher/kstr/cb/arg are the no-cipher
            // arms.
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
            };
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
            };
        }
    } else if outformat == FORMAT_ASN1 {
        // SAFETY: `out`/`pkey` are live.
        unsafe { i2d_PrivateKey_bio(out, pkey) };
    } else {
        eprintln!("Bad format specified for key");
        // SAFETY: all four are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: all four are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        // SAFETY: all four are live and not freed again.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
        // SAFETY: all four are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return 1;
    }

    // `end: X509_SIG_free(p8); PKCS8_PRIV_KEY_INFO_free(p8inf); EVP_PKEY_free(pkey);
    // ... BIO_free_all(out); BIO_free(in);` — `apps/pkcs8.c:394-403`.
    // SAFETY: all four are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    // SAFETY: all four are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    // SAFETY: all four are live and not freed again.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    // SAFETY: all four are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free(inbio) };
    0
}
