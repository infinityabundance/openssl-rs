//! Phase 17.1d — `apps/rsautl.c`: the `openssl rsautl` command.
//!
//! The command body (`apps/rsautl.c:88-309`): parse the generated `RSAUTL_OPTIONS`
//! table, load a key, read the input, run one `EVP_PKEY_*` operation (verify-recover,
//! sign, encrypt or decrypt) under the selected RSA padding, and write the result
//! (raw, `-hexdump` or `-asn1parse`). The parse and the two pre-key-load arms — the
//! private-key requirement and the password read — are transcribed; the operation
//! reaches `EVP_PKEY_*` and the `apps/lib` `app_malloc`/`bio_open_default` helpers.
//!
//! ## What the court drives
//!
//! The refusal arms, which finish before any key is loaded:
//! `rsautl -sign -pubin` and `rsautl -decrypt -certin` print
//! `A private key is needed for this operation` after the dispatcher's deprecation
//! warning, and `rsautl -bogus` is the parser's `Unknown option` refusal. Each has
//! fixed text and an empty error queue.
//!
//! ## Recorded divergences (module header)
//!
//! * **The RSA operation arm is not driven.** After a key loads, the body reads the
//!   input, runs `EVP_PKEY_verify_recover`/`EVP_PKEY_sign`/`EVP_PKEY_encrypt`/
//!   `EVP_PKEY_decrypt` and writes raw bytes; the PKCS#1 v1.5 and OAEP paddings draw
//!   randomness, and the raw-byte output is not a text transcript. The
//!   `app_malloc`/`bio_open_default` helpers are `apps/lib`'s. Those arms reach
//!   [`not_landed`](crate::apps::openssl::not_landed); the parse and the requirement
//!   checks are transcribed.
//! * **`-engine` is not landed** (`apps/rsautl.c:126-128`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`); `app_RAND_load` with no `-rand` is the
//!   authority's no-op success (`apps/lib/app_rand.c:66-79`).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::RSAUTL_OPTIONS;

/// `RSA_SIGN`/`RSA_VERIFY`/`RSA_ENCRYPT`/`RSA_DECRYPT` — `apps/rsautl.c:19-22`.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}
/// `KEY_PRIVKEY`/`KEY_PUBKEY`/`KEY_CERT` — `apps/rsautl.c:24-26`.
#[derive(Clone, Copy, PartialEq)]
enum KeyType {
    PrivKey,
    PubKey,
    Cert,
}

/// `int rsautl_main(int argc, char **argv)` — `apps/rsautl.c:88-309`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, rsautl_options);` — `apps/rsautl.c:104`.
    let mut opts = Opts::init(argv, RSAUTL_OPTIONS);
    let mut mode = Mode::Verify;
    let mut key_type = KeyType::PrivKey;
    let mut need_priv = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/rsautl.c:105`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(rsautl_options); ret = 0; goto end;` —
            // `apps/rsautl.c:112-115`.
            OptMatch::Help => return not_landed("rsautl -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/rsautl.c:107-111`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat))
            // goto opthelp;` — `apps/rsautl.c:116-119`.
            OptMatch::Value("keyform", _) => {}
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/rsautl.c:120-122`.
            OptMatch::Value("in", _) => {}
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/rsautl.c:123-125`.
            OptMatch::Value("out", _) => {}
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/rsautl.c:126-128`.
            OptMatch::Value("engine", _) => return not_landed("rsautl -engine"),
            // `case OPT_ASN1PARSE: asn1parse = 1; break;` — `apps/rsautl.c:129-131`.
            OptMatch::Flag("asn1parse") => {}
            // `case OPT_HEXDUMP: hexdump = 1; break;` — `apps/rsautl.c:132-134`.
            OptMatch::Flag("hexdump") => {}
            // `case OPT_RSA_RAW: pad = RSA_NO_PADDING; break;` — `apps/rsautl.c:135-137`.
            OptMatch::Flag("raw") => {}
            // `case OPT_OAEP: pad = RSA_PKCS1_OAEP_PADDING; break;` —
            // `apps/rsautl.c:138-140`.
            OptMatch::Flag("oaep") => {}
            // `case OPT_PKCS: pad = RSA_PKCS1_PADDING; break;` — `apps/rsautl.c:141-143`.
            OptMatch::Flag("pkcs") => {}
            // `case OPT_X931: pad = RSA_X931_PADDING; break;` — `apps/rsautl.c:144-146`.
            OptMatch::Flag("x931") => {}
            // `case OPT_SIGN: rsa_mode = RSA_SIGN; need_priv = 1; break;` —
            // `apps/rsautl.c:147-150`.
            OptMatch::Flag("sign") => {
                mode = Mode::Sign;
                need_priv = true;
            }
            // `case OPT_VERIFY: rsa_mode = RSA_VERIFY; break;` — `apps/rsautl.c:151-153`.
            OptMatch::Flag("verify") => mode = Mode::Verify,
            // `case OPT_REV: rev = 1; break;` — `apps/rsautl.c:154-156`.
            OptMatch::Flag("rev") => {}
            // `case OPT_ENCRYPT: rsa_mode = RSA_ENCRYPT; break;` — `apps/rsautl.c:157-159`.
            OptMatch::Flag("encrypt") => mode = Mode::Encrypt,
            // `case OPT_DECRYPT: rsa_mode = RSA_DECRYPT; need_priv = 1; break;` —
            // `apps/rsautl.c:160-163`.
            OptMatch::Flag("decrypt") => {
                mode = Mode::Decrypt;
                need_priv = true;
            }
            // `case OPT_PUBIN: key_type = KEY_PUBKEY; break;` — `apps/rsautl.c:164-166`.
            OptMatch::Flag("pubin") => key_type = KeyType::PubKey,
            // `case OPT_CERTIN: key_type = KEY_CERT; break;` — `apps/rsautl.c:167-169`.
            OptMatch::Flag("certin") => key_type = KeyType::Cert,
            // `case OPT_INKEY: keyfile = opt_arg(); break;` — `apps/rsautl.c:170-172`.
            OptMatch::Value("inkey", _) => {}
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/rsautl.c:173-175`.
            OptMatch::Value("passin", _) => return not_landed("rsautl -passin"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/rsautl.c:176-179`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("rsautl -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/rsautl.c:180-183`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("rsautl -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/rsautl.c:187-189`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_RAND_load()) goto end;` — `apps/rsautl.c:191-192`. With no `-rand` the
    // authority's loader is the no-op success (`apps/lib/app_rand.c:66-79`).

    // `if (need_priv && (key_type != KEY_PRIVKEY)) { BIO_printf(bio_err, "A private key
    // is needed for this operation\n"); goto end; }` — `apps/rsautl.c:194-197`.
    if need_priv && key_type != KeyType::PrivKey {
        eprintln!("A private key is needed for this operation");
        return 1;
    }

    // `app_passwd(passinarg, NULL, &passin, NULL)` with `passinarg` NULL succeeds and
    // leaves `passin` NULL — `apps/rsautl.c:199-202`.

    // The key load and the RSA operation are not driven (see the header).
    let _ = mode;
    not_landed("rsautl key load and RSA operation (not driven)")
}
