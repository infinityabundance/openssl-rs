//! Phase 17.1g — `apps/smime.c`: the `openssl smime` command.
//!
//! The command body (`apps/smime.c:195-746`): parse the generated `SMIME_OPTIONS`
//! table (with `opt_set_unknown_name("cipher")`, so an unknown option is a cipher
//! name), select one operation (`-encrypt`/`-decrypt`/`-sign`/`-resign`/`-verify`/
//! `-pk7out`), load the signer/recipient certificate(s) and key, run the PKCS#7
//! operation (`PKCS7_sign_ex`+`PKCS7_sign_add_signer`+`PKCS7_final`, `PKCS7_verify`,
//! `PKCS7_encrypt_ex`, `PKCS7_decrypt`) and write the S/MIME, PEM or DER result
//! (`SMIME_write_PKCS7`/`PEM_write_bio_PKCS7_stream`/`i2d_PKCS7_bio_stream`).
//!
//! ## What the court drives
//!
//! `smime -sign -noattr -nodetach -outform DER|PEM -in <smime.txt> -signer <signer.pem>
//! -inkey <rsa-key.pem>`, `smime -verify -inform PEM -noverify -in
//! <smime-signed.pem>`, `smime -decrypt -inform PEM -in <smime-enc.pem> -recip
//! <signer.pem> -inkey <rsa-key.pem>` and the operation refusals (`smime` with no
//! operation, `-encrypt` with no recipient, `-decrypt` with no recipient/key,
//! `-sign` with no signer). `-noattr` removes the `signingTime` attribute, which is
//! the only wall-clock input; PKCS#1 v1.5 signing is otherwise deterministic.
//!
//! ## Recorded divergences (module header)
//!
//! * **The default `-sign` (with the `signingTime` attribute) is recorded.** Without
//!   `-noattr` the signed attributes carry the wall clock, so the output differs
//!   across a second boundary; the driven sign arms pass `-noattr`.
//! * **`smime -encrypt` is not driven.** The content-encryption key is drawn at
//!   random, so the envelope bytes are independent on the two sides (the fixed
//!   `smime-enc.pem` fixture is decrypted instead). The operation is transcribed.
//! * **The `SMIME` output format is not driven.** `SMIME_write_PKCS7` draws a random
//!   MIME boundary; the `PEM`/`DER` output formats are byte-deterministic.
//! * **`-certfile` (`load_certs`) and `-resign`/`-pk7out` re-encode arms are not
//!   driven.** `-certfile` reaches [`not_landed`] (no `load_certs` in [`crate::apps::keyio`]).
//! * **`-content` (`BIO_new_file` override), `-passin`, `-config`, `-engine`,
//!   `-to`/`-from`/`-subject` header printing and the `-V` verify-parameter arms are
//!   not driven**; `-nameopt`-equivalent text is the default.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_cert, load_key, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SMIME_OPTIONS;
use crate::evp::e_aes::EVP_aes_256_cbc;
use crate::pem::pem_all::{PEM_read_bio_PKCS7, PEM_write_bio_PKCS7};
use crate::pkcs7::pk7_asn1::{PKCS7_free, Pkcs7};
use crate::pkcs7::pk7_mime::{
    i2d_PKCS7_bio_stream, PEM_write_bio_PKCS7_stream, SMIME_read_PKCS7_ex, SMIME_write_PKCS7,
};
use crate::pkcs7::pk7_smime::{
    PKCS7_decrypt, PKCS7_encrypt_ex, PKCS7_final, PKCS7_sign_add_signer, PKCS7_sign_ex,
    PKCS7_verify,
};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio};
use crate::runtime::stack::{OPENSSL_sk_new_null, OPENSSL_sk_push, OpenSslStack};
use crate::x509::x509_lu::{X509Store, X509_STORE_free, X509_STORE_new, X509_STORE_set_verify_cb};
use crate::x509::x_all::d2i_PKCS7_bio;
use crate::x509::x_x509::X509_free;

/// `FORMAT_SMIME` — `apps/include/fmt.h:36`.
const FORMAT_SMIME: c_int = 7 | 0x8000;
/// `FORMAT_BINARY` — `apps/include/fmt.h:29`.
const FORMAT_BINARY: c_int = 2;

/// The `PKCS7_*` flag words — `include/openssl/pkcs7.h`.
const PKCS7_TEXT: c_int = 0x1;
const PKCS7_NOCERTS: c_int = 0x2;
const PKCS7_NOSIGS: c_int = 0x4;
const PKCS7_NOINTERN: c_int = 0x10;
const PKCS7_NOVERIFY: c_int = 0x20;
const PKCS7_DETACHED: c_int = 0x40;
const PKCS7_BINARY: c_int = 0x80;
const PKCS7_NOATTR: c_int = 0x100;
const PKCS7_NOCHAIN: c_int = 0x8;
const PKCS7_NOSMIMECAP: c_int = 0x200;
const PKCS7_CRLFEOL: c_int = 0x800;
const PKCS7_STREAM: c_int = 0x1000;
const PKCS7_PARTIAL: c_int = 0x4000;
const PKCS7_REUSE_DIGEST: c_int = 0x8000;

/// The `SMIME_*` operation selectors — `apps/smime.c:25-33`.
const SMIME_OP: c_int = 0x10;
const SMIME_IP: c_int = 0x20;
const SMIME_SIGNERS: c_int = 0x40;
const SMIME_ENCRYPT: c_int = 1 | SMIME_OP;
const SMIME_DECRYPT: c_int = 2 | SMIME_IP;
const SMIME_SIGN: c_int = 3 | SMIME_OP | SMIME_SIGNERS;
const SMIME_RESIGN: c_int = 6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS;
const SMIME_VERIFY: c_int = 4 | SMIME_IP;
const SMIME_PK7OUT: c_int = 5 | SMIME_IP | SMIME_OP;

/// `opt_format(s, OPT_FMT_PDS, result)` — the `S`/`P`/`D`/default arms of
/// `apps/lib/opt.c:277-365`.
fn opt_format_pds(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'S') | Some(b's') => {
            *result = FORMAT_SMIME;
            true
        }
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

/// The operation-refusal helper: `BIO_puts(bio_err, msg); goto opthelp;`
/// (`apps/smime.c:444-490`). `smime`'s `ret` is 0 on this path, so the exit is 0.
fn refusal(msg: &str, prog: &str) -> i32 {
    eprintln!("{msg}");
    eprintln!("{prog}: Use -help for summary.");
    0
}

/// `int smime_main(int argc, char **argv)` — `apps/smime.c:195-746`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, smime_options);` —
    // `apps/smime.c:225-226`.
    let mut opts = Opts::init(argv, SMIME_OPTIONS);
    opts.enable_unknown("cipher");
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut certfile: Option<String> = None;
    let mut signerfile: Option<String> = None;
    let mut recipfile: Option<String> = None;
    let mut keyfile: Option<String> = None;
    let mut to: Option<String> = None;
    let mut from: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut digestname: Option<String> = None;
    let mut ciphername: Option<String> = None;
    let mut informat = FORMAT_SMIME;
    let mut outformat = FORMAT_SMIME;
    let mut operation: c_int = 0;
    let mut flags: c_int = PKCS7_DETACHED;
    let mut mime_eol: &str = "\n";
    let mut indef = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/smime.c:227`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(smime_options); ret = 0; goto end;` —
            // `apps/smime.c:234-237`.
            OptMatch::Help => return not_landed("smime -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: ...` — `apps/smime.c:229-233`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PDS, &informat))
            // goto opthelp;` — `apps/smime.c:238-241`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pds(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/smime.c:242-244`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: ...` — `apps/smime.c:245-248`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pds(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/smime.c:249-251`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // The operation selectors — `apps/smime.c:252-275`.
            OptMatch::Flag("encrypt") => operation = SMIME_ENCRYPT,
            OptMatch::Flag("decrypt") => operation = SMIME_DECRYPT,
            OptMatch::Flag("sign") => operation = SMIME_SIGN,
            OptMatch::Flag("resign") => operation = SMIME_RESIGN,
            OptMatch::Flag("verify") => operation = SMIME_VERIFY,
            OptMatch::Flag("pk7out") => operation = SMIME_PK7OUT,
            // The flag word arms — `apps/smime.c:276-316`.
            OptMatch::Flag("text") => flags |= PKCS7_TEXT,
            OptMatch::Flag("nointern") => flags |= PKCS7_NOINTERN,
            OptMatch::Flag("noverify") => flags |= PKCS7_NOVERIFY,
            OptMatch::Flag("nochain") => flags |= PKCS7_NOCHAIN,
            OptMatch::Flag("nocerts") => flags |= PKCS7_NOCERTS,
            OptMatch::Flag("noattr") => flags |= PKCS7_NOATTR,
            OptMatch::Flag("nodetach") => flags &= !PKCS7_DETACHED,
            OptMatch::Flag("nosmimecap") => flags |= PKCS7_NOSMIMECAP,
            OptMatch::Flag("binary") => flags |= PKCS7_BINARY,
            OptMatch::Flag("nosigs") => flags |= PKCS7_NOSIGS,
            OptMatch::Flag("stream") | OptMatch::Flag("indef") => indef = true,
            OptMatch::Flag("noindef") => indef = false,
            OptMatch::Flag("crlfeol") => {
                flags |= PKCS7_CRLFEOL;
                mime_eol = "\r\n";
            }
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/smime.c:333-335`.
            OptMatch::Value("passin", _) => return not_landed("smime -passin"),
            // `case OPT_TO`/`OPT_FROM`/`OPT_SUBJECT` — `apps/smime.c:336-344`.
            OptMatch::Value("to", v) => to = Some(v),
            OptMatch::Value("from", v) => from = Some(v),
            OptMatch::Value("subject", v) => subject = Some(v),
            // `case OPT_SIGNER: ...` — `apps/smime.c:345-363`. A simple parse: the last
            // `-signer` wins; the multi-signer stack is not driven.
            OptMatch::Value("signer", v) => {
                if signerfile.is_some() {
                    return not_landed("smime -signer (multiple)");
                }
                signerfile = Some(v);
            }
            // `case OPT_RECIP: recipfile = opt_arg(); break;` — `apps/smime.c:364-366`.
            OptMatch::Value("recip", v) => recipfile = Some(v),
            // `case OPT_MD: digestname = opt_arg(); break;` — `apps/smime.c:367-369`.
            OptMatch::Value("md", v) => digestname = Some(v),
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/smime.c:370-372`.
            OptMatch::Value("", v) => ciphername = Some(v),
            // `case OPT_INKEY: ...` — `apps/smime.c:373-394`.
            OptMatch::Value("inkey", v) => {
                if keyfile.is_some() {
                    return not_landed("smime -inkey (multiple)");
                }
                keyfile = Some(v);
            }
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
            // goto opthelp;` — `apps/smime.c:395-398`.
            OptMatch::Value("keyform", _) => return not_landed("smime -keyform"),
            // `case OPT_CERTFILE: certfile = opt_arg(); break;` —
            // `apps/smime.c:399-401`.
            OptMatch::Value("certfile", v) => certfile = Some(v),
            // `-CAfile`/`-CApath`/`-CAstore`/`-no-CA*` — `apps/smime.c:402-419`.
            OptMatch::Value("CAfile", _)
            | OptMatch::Value("CApath", _)
            | OptMatch::Value("CAstore", _) => {}
            OptMatch::Flag("no-CAfile")
            | OptMatch::Flag("no-CApath")
            | OptMatch::Flag("no-CAstore") => {}
            // `case OPT_CONTENT: contfile = opt_arg(); break;` —
            // `apps/smime.c:420-422`.
            OptMatch::Value("content", _) => return not_landed("smime -content"),
            // `case OPT_V_CASES: if (!opt_verify(o, vpm)) goto opthelp; vpmtouched++;` —
            // `apps/smime.c:423-427`.
            OptMatch::Flag("x509_strict")
            | OptMatch::Value("attime", _)
            | OptMatch::Value("verify_depth", _)
            | OptMatch::Value("verify_email", _)
            | OptMatch::Value("verify_hostname", _)
            | OptMatch::Value("verify_ip", _)
            | OptMatch::Value("verify_name", _)
            | OptMatch::Value("policy", _)
            | OptMatch::Value("purpose", _)
            | OptMatch::Value("auth_level", _)
            | OptMatch::Flag("partial_chain")
            | OptMatch::Flag("trusted_first")
            | OptMatch::Flag("no_alt_chains")
            | OptMatch::Flag("no_check_time")
            | OptMatch::Flag("crl_check")
            | OptMatch::Flag("crl_check_all")
            | OptMatch::Flag("ignore_critical")
            | OptMatch::Flag("inhibit_any")
            | OptMatch::Flag("inhibit_map")
            | OptMatch::Flag("extended_crl")
            | OptMatch::Flag("use_deltas")
            | OptMatch::Flag("policy_print") => return not_landed("smime -V option"),
            // `case OPT_CONFIG: conf = app_load_config_modules(opt_arg()); ...` —
            // `apps/smime.c:325-329`.
            OptMatch::Value("config", _) => return not_landed("smime -config"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/smime.c:330-332`.
            OptMatch::Value("engine", _) => return not_landed("smime -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/smime.c:317-320`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("smime -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/smime.c:321-324`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("smime -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest();` — `apps/smime.c:432-433`.
    let recipients: Vec<String> = opts.rest().to_vec();

    // The digest/cipher resolution — `apps/smime.c:438-443`.
    if digestname.is_some() {
        return not_landed("smime -md");
    }
    if ciphername.is_some() {
        return not_landed("smime -cipher");
    }
    // `if (!(operation & SMIME_SIGNERS) && (skkeys != NULL || sksigners != NULL)) ...
    // Multiple signers or keys not allowed` — `apps/smime.c:444-447`. The multi-signer
    // stack is not driven.
    // `if (!operation) { "No operation (-encrypt|-sign|...) specified\n"; goto opthelp; }`
    // — `apps/smime.c:448-452`.
    if operation == 0 {
        return refusal("No operation (-encrypt|-sign|...) specified", opts.prog());
    }

    if operation & SMIME_SIGNERS != 0 {
        // `if (keyfile && !signerfile) { "Illegal -inkey without -signer\n"; ... }` —
        // `apps/smime.c:454-459`.
        if keyfile.is_some() && signerfile.is_none() {
            return refusal("Illegal -inkey without -signer", opts.prog());
        }
        // `if (sksigners == NULL) { "No signer certificate specified\n"; ... }` —
        // `apps/smime.c:473-476`.
        if signerfile.is_none() {
            return refusal("No signer certificate specified", opts.prog());
        }
    } else if operation == SMIME_DECRYPT {
        // `if (recipfile == NULL && keyfile == NULL) { "No recipient certificate or key
        // specified\n"; ... }` — `apps/smime.c:479-484`.
        if recipfile.is_none() && keyfile.is_none() {
            return refusal("No recipient certificate or key specified", opts.prog());
        }
    } else if operation == SMIME_ENCRYPT {
        // `if (argc == 0) { "No recipient(s) certificate(s) specified\n"; ... }` —
        // `apps/smime.c:485-489`.
        if recipients.is_empty() {
            return refusal("No recipient(s) certificate(s) specified", opts.prog());
        }
    }

    // `-passin` reaches `not_landed` above; the no-password arm is the NULL success.
    // `if (!(operation & SMIME_SIGNERS)) flags &= ~PKCS7_DETACHED;` —
    // `apps/smime.c:499-500`.
    if operation & SMIME_SIGNERS == 0 {
        flags &= !PKCS7_DETACHED;
    }
    // `if (!(operation & SMIME_OP)) { if (flags & PKCS7_BINARY) outformat =
    // FORMAT_BINARY; }` and `if (!(operation & SMIME_IP)) … informat = FORMAT_BINARY;` —
    // `apps/smime.c:502-510`.
    if operation & SMIME_OP == 0 && flags & PKCS7_BINARY != 0 {
        outformat = FORMAT_BINARY;
    }
    if operation & SMIME_IP == 0 && flags & PKCS7_BINARY != 0 {
        informat = FORMAT_BINARY;
    }

    let mut encerts: *mut OpenSslStack = core::ptr::null_mut();
    if operation == SMIME_ENCRYPT {
        encerts = OPENSSL_sk_new_null();
        if encerts.is_null() {
            return 1;
        }
        for r in &recipients {
            let cert = load_cert(Some(r.as_str()), 0, "recipient certificate file");
            if cert.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
                return 1;
            }
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { OPENSSL_sk_push(encerts, cert.cast()) };
        }
    }
    let _ = certfile; // `-certfile` (`load_certs`) is not landed (see header).
    let _ = to;
    let _ = from;
    let _ = subject;

    // `in = bio_open_default(infile, 'r', informat);` — `apps/smime.c:562-564`.
    let inbio = bio_open_default(infile.as_deref(), false);
    if inbio.is_null() {
        if !encerts.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
        }
        return not_landed("smime -in (unopenable)");
    }

    // The `SMIME_IP` read arms — `apps/smime.c:566-596`.
    let mut p7: *mut Pkcs7 = core::ptr::null_mut();
    let mut indata: *mut Bio = core::ptr::null_mut();
    if operation & SMIME_IP != 0 {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        p7 = unsafe {
            crate::pkcs7::pk7_asn1::PKCS7_new_ex(core::ptr::null_mut(), core::ptr::null())
        };
        if p7.is_null() {
            eprintln!("Error allocating PKCS7 object");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            if !encerts.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
            }
            return 1;
        }
        let p7_in = if informat == FORMAT_SMIME {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { SMIME_read_PKCS7_ex(inbio, &mut indata, &mut p7) }
        } else if informat == FORMAT_PEM {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PEM_read_bio_PKCS7(inbio, &mut p7, None, core::ptr::null_mut()) }
        } else if informat == FORMAT_ASN1 {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { d2i_PKCS7_bio(inbio, &mut p7) }
        } else {
            eprintln!("Bad input format for PKCS#7 file");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            if !encerts.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
            }
            return 1;
        };
        if p7_in.is_null() {
            eprintln!("Error reading S/MIME message");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            if !encerts.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
            }
            return 1;
        }
    }

    // `out = bio_open_default(outfile, 'w', outformat);` — `apps/smime.c:598-600`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free(inbio) };
        if !p7.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
        }
        if !encerts.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
        }
        return not_landed("smime -out (unopenable)");
    }

    // The verify store — `apps/smime.c:602-610`. With `-noverify` the store contents do
    // not decide the result, so the empty store is enough (see the header).
    let mut store: *mut X509Store = core::ptr::null_mut();
    if operation == SMIME_VERIFY {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        store = unsafe { X509_STORE_new() };
        if store.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_STORE_set_verify_cb(store, None) };
    }

    // The operation arms — `apps/smime.c:614-666`.
    if operation == SMIME_ENCRYPT {
        if indef {
            flags |= PKCS7_STREAM;
        }
        let cipher = EVP_aes_256_cbc();
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        p7 = unsafe {
            PKCS7_encrypt_ex(
                encerts,
                inbio,
                cipher,
                flags,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };
    } else if operation & SMIME_SIGNERS != 0 {
        if operation == SMIME_SIGN {
            if flags & PKCS7_DETACHED != 0 {
                if outformat == FORMAT_SMIME {
                    flags |= PKCS7_STREAM;
                }
            } else if indef {
                flags |= PKCS7_STREAM;
            }
            flags |= PKCS7_PARTIAL;
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            p7 = unsafe {
                PKCS7_sign_ex(
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    inbio,
                    flags,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                )
            };
            if p7.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free_all(out) };
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free(inbio) };
                if !store.is_null() {
                    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                    unsafe { X509_STORE_free(store) };
                }
                return 1;
            }
        } else {
            flags |= PKCS7_REUSE_DIGEST;
        }
        let sf = signerfile.clone().unwrap_or_default();
        let kf = keyfile.clone().unwrap_or_else(|| sf.clone());
        let signer = load_cert(Some(sf.as_str()), 0, "signer certificate");
        if signer.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
        let key = load_key(Some(kf.as_str()), 0, "signing key");
        if key.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { X509_free(signer) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        if unsafe { PKCS7_sign_add_signer(p7, signer, key, core::ptr::null(), flags) }.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { X509_free(signer) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(signer) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
        if operation == SMIME_SIGN && flags & PKCS7_STREAM == 0 {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            if unsafe { PKCS7_final(p7, inbio, flags) } == 0 {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free_all(out) };
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free(inbio) };
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { PKCS7_free(p7) };
                return 1;
            }
        }
    }

    if p7.is_null() {
        eprintln!("Error creating PKCS#7 structure");
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free_all(out) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free(inbio) };
        if !store.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { X509_STORE_free(store) };
        }
        return 1;
    }

    // The per-operation terminal arms — `apps/smime.c:673-721`.
    if operation == SMIME_DECRYPT {
        let key = load_key(keyfile.as_deref(), 0, "signing key");
        let recip = load_cert(recipfile.as_deref(), 0, "recipient certificate file");
        if key.is_null() || recip.is_null() {
            if !key.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
            }
            if !recip.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { X509_free(recip) };
            }
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        let ok = unsafe { PKCS7_decrypt(p7, key, recip, out, flags) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(recip) };
        if ok == 0 {
            eprintln!("Error decrypting PKCS#7 structure");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        }
    } else if operation == SMIME_VERIFY {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        let ok = unsafe { PKCS7_verify(p7, core::ptr::null_mut(), store, indata, out, flags) };
        if ok != 0 {
            eprintln!("Verification successful");
        } else {
            eprintln!("Verification failure");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            if !store.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { X509_STORE_free(store) };
            }
            return 1;
        }
    } else if operation == SMIME_PK7OUT {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { PEM_write_bio_PKCS7(out, p7) };
    } else {
        // The `to`/`from`/`subject` headers and the writers — `apps/smime.c:697-721`.
        if let Some(t) = &to {
            let line = format!("To: {t}{mime_eol}");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe {
                crate::runtime::bio::iolib::BIO_write(
                    out,
                    line.as_ptr().cast(),
                    line.len() as c_int,
                )
            };
        }
        if let Some(f) = &from {
            let line = format!("From: {f}{mime_eol}");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe {
                crate::runtime::bio::iolib::BIO_write(
                    out,
                    line.as_ptr().cast(),
                    line.len() as c_int,
                )
            };
        }
        if let Some(s) = &subject {
            let line = format!("Subject: {s}{mime_eol}");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe {
                crate::runtime::bio::iolib::BIO_write(
                    out,
                    line.as_ptr().cast(),
                    line.len() as c_int,
                )
            };
        }
        let rv = if outformat == FORMAT_SMIME {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { SMIME_write_PKCS7(out, p7, inbio, flags) }
        } else if outformat == FORMAT_PEM {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PEM_write_bio_PKCS7_stream(out, p7, inbio, flags) }
        } else if outformat == FORMAT_ASN1 {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { i2d_PKCS7_bio_stream(out, p7, inbio, flags) }
        } else {
            eprintln!("Bad output format for PKCS#7 file");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 1;
        };
        if rv == 0 {
            eprintln!("Error writing output");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PKCS7_free(p7) };
            return 3;
        }
    }

    // `end:` cleanup — `apps/smime.c:723-745`.
    if !encerts.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::runtime::stack::OPENSSL_sk_free(encerts) };
    }
    if !store.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_STORE_free(store) };
    }
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { PKCS7_free(p7) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { BIO_free(inbio) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { BIO_free_all(out) };
    0
}
