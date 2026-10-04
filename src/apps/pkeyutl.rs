//! Phase 17.1e — `apps/pkeyutl.c`: the `openssl pkeyutl` command.
//!
//! The command body (`apps/pkeyutl.c:150-637`): parse the generated
//! `PKEYUTL_OPTIONS` table, load the input key ([`get_pkey`]), build and
//! initialise the operation context ([`init_ctx`]), apply the `-pkeyopt`
//! controls, read the input, then run the operation ([`do_keyop`]) and write the
//! result. The parse, the key load, the non-raw `sign`/`verify`/`verifyrecover`/
//! `encrypt`/`decrypt`/`derive` dispatch and the output arms are transcribed. The
//! raw (`-rawin`/`-digest`), KEM (`-encap`/`-decap`), KDF (`-kdf`) and peer-key
//! arms reach [`not_landed`].
//!
//! ## What the court drives
//!
//! `pkeyutl -sign -inkey <rsa-key.pem> -in <small.bin>`,
//! `pkeyutl -verify -pubin -inkey <rsa-pub.pem> -in <small.bin> -sigfile
//! <small.sig>`, and `-encrypt`/`-decrypt` with `-pkeyopt rsa_padding_mode:none`
//! over the fixed 256-byte input/ciphertext. RSA PKCS#1 v1.5 signing is
//! deterministic, and the no-padding arm is a raw modular exponentiation, so
//! both are byte-identical.
//!
//! ## Recorded divergences (module header)
//!
//! * **The KEM/KDF/raw arms are not landed.** `-encap`/`-decap` (EVP_PKEY
//!   encapsulate/decapsulate), `-kdf`, and `-rawin`/`-digest` (the `EVP_MD_CTX`
//!   stream path of `do_raw_keyop`, `apps/pkeyutl.c:858-945`) are other surfaces;
//!   the corresponding argv are not driven.
//! * **`#include <sys/stat.h>`'s `stat(infile, &st)` is reduced to a length
//!   read.** The authority records `st.st_size` for the one-shot raw path
//!   (`apps/pkeyutl.c:471-476`); this module reads the input through `bio_to_mem`
//!   and does not need the size for the non-raw path.
//! * **`app_passwd` is reduced to its no-argument observable**; no `-passin` is
//!   driven.
//! * **`-engine`/`-engine_impl` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{
    bio_open_default, load_cert, load_key, load_pubkey, FORMAT_ASN1, FORMAT_PEM,
};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKEYUTL_OPTIONS;
use crate::asn1::der::ASN1_parse_dump;
use crate::evp::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_is_a};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_ctrl_str, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::signature::{
    EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify, EVP_PKEY_verify_init,
    EVP_PKEY_verify_recover, EVP_PKEY_verify_recover_init,
};
use crate::runtime::bio::dump::BIO_dump;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio};
use crate::x509::x_x509::X509;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:27`.
const FORMAT_UNDEF: c_int = 0;
/// `KEY_NONE` — `apps/pkeyutl.c:18`.
const KEY_NONE: c_int = 0;
/// `KEY_PRIVKEY` — `apps/pkeyutl.c:19`.
const KEY_PRIVKEY: c_int = 1;
/// `KEY_PUBKEY` — `apps/pkeyutl.c:20`.
const KEY_PUBKEY: c_int = 2;
/// `KEY_CERT` — `apps/pkeyutl.c:21`.
const KEY_CERT: c_int = 3;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h`.
const EVP_MAX_MD_SIZE: usize = 64;

/// The operation selector (`EVP_PKEY_OP_*`), reduced to the arms this module
/// drives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Sign,
    Verify,
    VerifyRecover,
    Encrypt,
    Decrypt,
    Derive,
}

/// `opt_format(s, OPT_FMT_ANY, result)` — the `P`/`D`/`M`/`PVK` and `default`
/// arms of `apps/lib/opt.c:277-365`, reduced to the PEM/DER bodies this command
/// reads.
fn opt_format_any(prog: &str, s: &str, result: &mut c_int) -> bool {
    match s.as_bytes().first().copied() {
        Some(b'P') | Some(b'p') if s.len() == 1 || s == "PEM" || s == "pem" => {
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

/// `bio_to_mem(&buf, &len, maxlen, bio)` — `apps/lib/apps.c`, reading the whole
/// BIO into a buffer. Returns `None` on error or an over-long stream.
fn bio_to_mem(bio: *mut Bio, maxlen: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // SAFETY: `bio` is live; `chunk` is writable for its length.
        let n =
            unsafe { crate::runtime::bio::iolib::BIO_read(bio, chunk.as_mut_ptr().cast(), 4096) };
        if n < 0 {
            return None;
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
        if maxlen > 0 && out.len() > maxlen {
            return None;
        }
    }
    Some(out)
}

/// `static EVP_PKEY *get_pkey(...)` — `apps/pkeyutl.c:639-679`.
fn get_pkey(
    keyfile: Option<&str>,
    keyform: c_int,
    key_type: c_int,
    op: Op,
) -> *mut crate::evp::pkey::EvpPkey {
    if (op == Op::Sign || op == Op::Decrypt || op == Op::Derive) && key_type != KEY_PRIVKEY {
        eprintln!("A private key is needed for this operation");
        return core::ptr::null_mut();
    }
    match key_type {
        // `load_key(keyfile, keyform, 0, passin, e, "private key")`.
        KEY_PRIVKEY => load_key(keyfile, keyform, "private key"),
        // `load_pubkey(keyfile, keyform, 0, NULL, e, "public key")`.
        KEY_PUBKEY => load_pubkey(keyfile, keyform, "public key"),
        // `x = load_cert(keyfile, keyform, "Certificate"); pkey =
        // X509_get_pubkey(x); X509_free(x);`
        KEY_CERT => {
            let x: *mut X509 = load_cert(keyfile, keyform, "Certificate");
            if x.is_null() {
                return core::ptr::null_mut();
            }
            // SAFETY: `x` is live.
            let pkey = unsafe { crate::x509::x509_cmp::X509_get_pubkey(x) };
            // SAFETY: `x` is live and not freed again.
            unsafe { crate::x509::x_x509::X509_free(x) };
            pkey
        }
        _ => core::ptr::null_mut(),
    }
}

/// `static EVP_PKEY_CTX *init_ctx(...)` — `apps/pkeyutl.c:681-787`, the non-raw
/// arm (the `rawin`/KEM arms are not landed).
fn init_ctx(pkey: *mut crate::evp::pkey::EvpPkey, op: Op) -> *mut crate::evp::pkey_ctx::EvpPkeyCtx {
    if pkey.is_null() {
        return core::ptr::null_mut();
    }
    // `ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq);` —
    // `apps/pkeyutl.c:718-720`.
    // SAFETY: `pkey` is live; NULL libctx/propq.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null()) };
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    // `switch (pkey_op) { case EVP_PKEY_OP_SIGN: rv = EVP_PKEY_sign_init(ctx);
    // ... }` — `apps/pkeyutl.c:741-778`.
    // SAFETY: `ctx` is live.
    let rv = unsafe {
        match op {
            Op::Sign => EVP_PKEY_sign_init(ctx),
            Op::Verify => EVP_PKEY_verify_init(ctx),
            Op::VerifyRecover => EVP_PKEY_verify_recover_init(ctx),
            Op::Encrypt => EVP_PKEY_encrypt_init(ctx),
            Op::Decrypt => EVP_PKEY_decrypt_init(ctx),
            Op::Derive => EVP_PKEY_derive_init(ctx),
        }
    };
    if rv <= 0 {
        // SAFETY: `ctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        return core::ptr::null_mut();
    }
    ctx
}

/// `static int do_keyop(...)` — `apps/pkeyutl.c:817-854`, the non-KEM arms.
fn do_keyop(
    ctx: *mut crate::evp::pkey_ctx::EvpPkeyCtx,
    op: Op,
    out: *mut u8,
    poutlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `ctx` is live; the buffers are the caller's.
    unsafe {
        match op {
            Op::VerifyRecover => EVP_PKEY_verify_recover(ctx, out, poutlen, input, inlen),
            Op::Sign => EVP_PKEY_sign(ctx, out, poutlen, input, inlen),
            Op::Encrypt => EVP_PKEY_encrypt(ctx, out, poutlen, input, inlen),
            Op::Decrypt => EVP_PKEY_decrypt(ctx, out, poutlen, input, inlen),
            Op::Derive => EVP_PKEY_derive(ctx, out, poutlen),
            Op::Verify => 0,
        }
    }
}

/// `int pkeyutl_main(int argc, char **argv)` — `apps/pkeyutl.c:150-637`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, pkeyutl_options);` — `apps/pkeyutl.c:179`.
    let mut opts = Opts::init(argv, PKEYUTL_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut sigfile: Option<String> = None;
    let mut inkey: Option<String> = None;
    let mut peerkey: Option<String> = None;
    let mut _passinarg: Option<String> = None;
    let mut keyform = FORMAT_UNDEF;
    let mut peerform = FORMAT_UNDEF;
    let mut key_type = KEY_PRIVKEY;
    let mut op = Op::Sign;
    let mut asn1parse = false;
    let mut hexdump = false;
    let mut rev = false;
    let mut rawin = false;
    let mut digestname: Option<String> = None;
    let mut kdfalg: Option<String> = None;
    let mut pkeyopts: Vec<String> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/pkeyutl.c:180`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(pkeyutl_options); ret = 0; goto end;` —
            // `apps/pkeyutl.c:187-190`.
            OptMatch::Help => return not_landed("pkeyutl -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/pkeyutl.c:182-186`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/pkeyutl.c:191-193`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/pkeyutl.c:194-196`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_SECOUT: secoutfile = opt_arg(); break;` —
            // `apps/pkeyutl.c:197-199`. KEM-only.
            OptMatch::Value("secret", _) => return not_landed("pkeyutl -secret"),
            // `case OPT_SIGFILE: sigfile = opt_arg(); break;` —
            // `apps/pkeyutl.c:200-202`.
            OptMatch::Value("sigfile", v) => sigfile = Some(v),
            // `case OPT_ENGINE_IMPL: engine_impl = 1; break;` —
            // `apps/pkeyutl.c:203-205`.
            OptMatch::Flag("engine_impl") => return not_landed("pkeyutl -engine_impl"),
            // `case OPT_INKEY: inkey = opt_arg(); break;` — `apps/pkeyutl.c:206-208`.
            OptMatch::Value("inkey", v) => inkey = Some(v),
            // `case OPT_PEERKEY: peerkey = opt_arg(); break;` —
            // `apps/pkeyutl.c:209-211`.
            OptMatch::Value("peerkey", v) => peerkey = Some(v),
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` —
            // `apps/pkeyutl.c:212-214`.
            OptMatch::Value("passin", v) => _passinarg = Some(v),
            // `case OPT_PEERFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY,
            // &peerform)) goto opthelp;` — `apps/pkeyutl.c:215-218`.
            OptMatch::Value("peerform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut peerform) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY,
            // &keyform)) goto opthelp;` — `apps/pkeyutl.c:219-222`.
            OptMatch::Value("keyform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut keyform) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/pkeyutl.c:223-226`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("pkeyutl -rand")
            }
            // `case OPT_CONFIG: conf = app_load_config_modules(opt_arg());` —
            // `apps/pkeyutl.c:227-231`.
            OptMatch::Value("config", _) => return not_landed("pkeyutl -config"),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/pkeyutl.c:232-235`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkeyutl -provider"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/pkeyutl.c:236-238`.
            OptMatch::Value("engine", _) => return not_landed("pkeyutl -engine"),
            // `case OPT_PUBIN: key_type = KEY_PUBKEY; break;` —
            // `apps/pkeyutl.c:239-241`.
            OptMatch::Flag("pubin") => key_type = KEY_PUBKEY,
            // `case OPT_CERTIN: key_type = KEY_CERT; break;` —
            // `apps/pkeyutl.c:242-244`.
            OptMatch::Flag("certin") => key_type = KEY_CERT,
            // `case OPT_ASN1PARSE: asn1parse = 1; break;` —
            // `apps/pkeyutl.c:245-247`.
            OptMatch::Flag("asn1parse") => asn1parse = true,
            // `case OPT_HEXDUMP: hexdump = 1; break;` — `apps/pkeyutl.c:248-250`.
            OptMatch::Flag("hexdump") => hexdump = true,
            // `case OPT_SIGN: pkey_op = EVP_PKEY_OP_SIGN; break;` —
            // `apps/pkeyutl.c:251-253`.
            OptMatch::Flag("sign") => op = Op::Sign,
            // `case OPT_VERIFY: pkey_op = EVP_PKEY_OP_VERIFY; break;` —
            // `apps/pkeyutl.c:254-256`.
            OptMatch::Flag("verify") => op = Op::Verify,
            // `case OPT_VERIFYRECOVER: pkey_op = EVP_PKEY_OP_VERIFYRECOVER; break;`
            // — `apps/pkeyutl.c:257-259`.
            OptMatch::Flag("verifyrecover") => op = Op::VerifyRecover,
            // `case OPT_ENCRYPT: pkey_op = EVP_PKEY_OP_ENCRYPT; break;` —
            // `apps/pkeyutl.c:260-262`.
            OptMatch::Flag("encrypt") => op = Op::Encrypt,
            // `case OPT_DECRYPT: pkey_op = EVP_PKEY_OP_DECRYPT; break;` —
            // `apps/pkeyutl.c:263-265`.
            OptMatch::Flag("decrypt") => op = Op::Decrypt,
            // `case OPT_DERIVE: pkey_op = EVP_PKEY_OP_DERIVE; break;` —
            // `apps/pkeyutl.c:266-268`.
            OptMatch::Flag("derive") => op = Op::Derive,
            // `case OPT_DECAP: pkey_op = EVP_PKEY_OP_DECAPSULATE; break;` —
            // `apps/pkeyutl.c:269-271`.
            OptMatch::Flag("decap") => return not_landed("pkeyutl -decap"),
            // `case OPT_ENCAP: key_type = KEY_PUBKEY; pkey_op =
            // EVP_PKEY_OP_ENCAPSULATE; break;` — `apps/pkeyutl.c:272-275`.
            OptMatch::Flag("encap") => return not_landed("pkeyutl -encap"),
            // `case OPT_KEMOP: kemop = opt_arg(); break;` — `apps/pkeyutl.c:276-278`.
            OptMatch::Value("kemop", _) => return not_landed("pkeyutl -kemop"),
            // `case OPT_KDF: pkey_op = EVP_PKEY_OP_DERIVE; key_type = KEY_NONE;
            // kdfalg = opt_arg();` — `apps/pkeyutl.c:279-283`.
            OptMatch::Value("kdf", v) => {
                op = Op::Derive;
                key_type = KEY_NONE;
                kdfalg = Some(v);
            }
            // `case OPT_KDFLEN: kdflen = atoi(opt_arg()); break;` —
            // `apps/pkeyutl.c:284-286`.
            OptMatch::Value("kdflen", _) => {}
            // `case OPT_REV: rev = 1; break;` — `apps/pkeyutl.c:287-289`.
            OptMatch::Flag("rev") => rev = true,
            // `case OPT_PKEYOPT: ... sk_OPENSSL_STRING_push(pkeyopts, opt_arg());`
            // — `apps/pkeyutl.c:290-295`.
            OptMatch::Value("pkeyopt", v) => pkeyopts.push(v),
            // `case OPT_PKEYOPT_PASSIN: ... push ...` — `apps/pkeyutl.c:296-301`.
            OptMatch::Value("pkeyopt_passin", _) => return not_landed("pkeyutl -pkeyopt_passin"),
            // `case OPT_RAWIN: rawin = 1; break;` — `apps/pkeyutl.c:302-304`.
            OptMatch::Flag("rawin") => rawin = true,
            // `case OPT_DIGEST: digestname = opt_arg(); break;` —
            // `apps/pkeyutl.c:305-307`.
            OptMatch::Value("digest", v) => digestname = Some(v),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/pkeyutl.c:311-313`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (!app_RAND_load()) goto end;` — `apps/pkeyutl.c:315-316`. Skipped (see
    // the header); unobservable for the deterministic arms.

    // `if (digestname != NULL) rawin = 1;` — `apps/pkeyutl.c:318-319`.
    if digestname.is_some() {
        rawin = true;
    }
    // The KDF/peer/raw arms reach surfaces this module does not land.
    if kdfalg.is_some() {
        return not_landed("pkeyutl -kdf");
    }
    if rawin {
        return not_landed("pkeyutl -rawin/-digest");
    }
    if peerkey.is_some() {
        return not_landed("pkeyutl -peerkey");
    }

    // `else if (inkey == NULL) { BIO_printf(bio_err, "%s: no private key given
    // (-inkey parameter).\n", prog); goto opthelp; }` — `apps/pkeyutl.c:327-330`.
    if inkey.is_none() {
        eprintln!("{}: no private key given (-inkey parameter).", opts.prog());
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `pkey = get_pkey(kdfalg, inkey, keyform, key_type, passinarg, pkey_op,
    // e); if (key_type != KEY_NONE && pkey == NULL) { ... "Error loading key"
    // ... }` — `apps/pkeyutl.c:341-345`.
    let pkey = get_pkey(inkey.as_deref(), keyform, key_type, op);
    if key_type != KEY_NONE && pkey.is_null() {
        eprintln!("{}: Error loading key", opts.prog());
        return 1;
    }

    // `if (pkey_op == EVP_PKEY_OP_VERIFYRECOVER && !EVP_PKEY_is_a(pkey, "RSA"))
    // { ... "-verifyrecover can be used only with RSA" ... }` —
    // `apps/pkeyutl.c:347-350`.
    if op == Op::VerifyRecover {
        // SAFETY: `pkey` is live; the name is a static literal.
        if unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } == 0 {
            eprintln!("{}: -verifyrecover can be used only with RSA", opts.prog());
            // SAFETY: `pkey` is live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            return 1;
        }
    }

    // `if (pkey_op == EVP_PKEY_OP_SIGN || pkey_op == EVP_PKEY_OP_VERIFY) { if
    // (only_nomd(pkey)) { ... } } else if (digestname != NULL || rawin) { ... }`
    // — `apps/pkeyutl.c:352-368`. `only_nomd` is the Ed25519-style one-shot
    // surface; not driven.
    if op != Op::Sign && op != Op::Verify && (digestname.is_some() || rawin) {
        eprintln!(
            "{}: -digest and -rawin can only be used with -sign or -verify",
            opts.prog()
        );
        // SAFETY: `pkey` is live and not freed again.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    // `if (rawin && rev) { ... }` — `apps/pkeyutl.c:370-373`.
    if rawin && rev {
        eprintln!("{}: -rev cannot be used with raw input", opts.prog());
        // SAFETY: `pkey` is live and not freed again.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    // `ctx = init_ctx(...); if (ctx == NULL) { ... "Error initializing context"
    // ... }` — `apps/pkeyutl.c:381-386`.
    let ctx = init_ctx(pkey, op);
    if ctx.is_null() {
        eprintln!("{}: Error initializing context", opts.prog());
        // SAFETY: `pkey` is live and not freed again.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    // `if (pkeyopts != NULL) { ... pkey_ctrl_string(ctx, opt) ... }` —
    // `apps/pkeyutl.c:391-404`.
    for opt in &pkeyopts {
        let (name, value) = match opt.split_once(':') {
            Some((n, v)) => (n, v),
            None => (opt.as_str(), ""),
        };
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        let Ok(cvalue) = std::ffi::CString::new(value) else {
            continue;
        };
        // SAFETY: `ctx` is live; the strings are NUL-terminated.
        if unsafe { EVP_PKEY_CTX_ctrl_str(ctx, cname.as_ptr(), cvalue.as_ptr()) } <= 0 {
            eprintln!("{}: Can't set parameter \"{opt}\":", opts.prog());
            // SAFETY: `ctx`/`pkey` are live and not freed again.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_free(pkey) };
            return 1;
        }
    }

    // `if (sigfile != NULL && (pkey_op != EVP_PKEY_OP_VERIFY)) { ... }` —
    // `apps/pkeyutl.c:457-461`.
    if sigfile.is_some() && op != Op::Verify {
        eprintln!("{}: Signature file specified for non verify", opts.prog());
        // SAFETY: `ctx`/`pkey` are live and not freed again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }
    // `if (sigfile == NULL && (pkey_op == EVP_PKEY_OP_VERIFY)) { ... "No
    // signature file specified for verify" ... }` — `apps/pkeyutl.c:463-467`.
    if sigfile.is_none() && op == Op::Verify {
        eprintln!("{}: No signature file specified for verify", opts.prog());
        // SAFETY: `ctx`/`pkey` are live and not freed again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    // `if (pkey_op != EVP_PKEY_OP_DERIVE && pkey_op != EVP_PKEY_OP_ENCAPSULATE)
    // { in = bio_open_default(infile, 'r', FORMAT_BINARY); ... }` —
    // `apps/pkeyutl.c:469-479`.
    let inbio = if op != Op::Derive {
        let b = bio_open_default(infile.as_deref(), false);
        if b.is_null() {
            // SAFETY: `ctx`/`pkey` are live and not freed again.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_free(pkey) };
            return 1;
        }
        b
    } else {
        core::ptr::null_mut()
    };

    // `out = bio_open_default(outfile, 'w', FORMAT_BINARY); if (out == NULL) goto
    // end;` — `apps/pkeyutl.c:490-494`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: all are live and not freed again.
        unsafe { BIO_free(inbio) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    // `if (sigfile != NULL) { BIO *sigbio = BIO_new_file(sigfile, "rb"); ...
    // bio_to_mem(&sig, &siglen, maxsiglen, sigbio) ... }` —
    // `apps/pkeyutl.c:509-523`.
    let sig = if let Some(sf) = &sigfile {
        let sigbio = bio_open_default(Some(sf), false);
        if sigbio.is_null() {
            eprintln!("Can't open signature file {sf}");
            // SAFETY: all are live and not freed again.
            unsafe { BIO_free(inbio) };
            // SAFETY: as above.
            unsafe { BIO_free_all(out) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_free(pkey) };
            return 1;
        }
        let r = bio_to_mem(sigbio, 16 * 1024 * 1024);
        // SAFETY: `sigbio` is live and not freed again.
        unsafe { BIO_free(sigbio) };
        match r {
            Some(v) => v,
            None => {
                eprintln!("Error reading signature data");
                // SAFETY: all are live and not freed again.
                unsafe { BIO_free(inbio) };
                // SAFETY: as above.
                unsafe { BIO_free_all(out) };
                // SAFETY: as above.
                unsafe { EVP_PKEY_CTX_free(ctx) };
                // SAFETY: as above.
                unsafe { EVP_PKEY_free(pkey) };
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    // `if (in != NULL && !rawin) { if (!bio_to_mem(&buf_in, &buf_inlen, 0, in))
    // { ... } if (rev) { ... } }` — `apps/pkeyutl.c:525-543`.
    let mut buf_in = if !inbio.is_null() {
        match bio_to_mem(inbio, 0) {
            Some(v) => v,
            None => {
                eprintln!("Error reading input Data");
                // SAFETY: all are live and not freed again.
                unsafe { BIO_free(inbio) };
                // SAFETY: as above.
                unsafe { BIO_free_all(out) };
                // SAFETY: as above.
                unsafe { EVP_PKEY_CTX_free(ctx) };
                // SAFETY: as above.
                unsafe { EVP_PKEY_free(pkey) };
                return 1;
            }
        }
    } else {
        Vec::new()
    };
    if rev {
        buf_in.reverse();
    }

    // `if (!rawin && (pkey_op == EVP_PKEY_OP_SIGN || pkey_op ==
    // EVP_PKEY_OP_VERIFY)) { if (buf_inlen > EVP_MAX_MD_SIZE) { ... } }` —
    // `apps/pkeyutl.c:545-555`.
    if (op == Op::Sign || op == Op::Verify) && buf_in.len() > EVP_MAX_MD_SIZE {
        eprintln!(
            "Error: The non-raw input data length {} is too long - max supported hashed size is {}",
            buf_in.len(),
            EVP_MAX_MD_SIZE
        );
        // SAFETY: all are live and not freed again.
        unsafe { BIO_free(inbio) };
        // SAFETY: as above.
        unsafe { BIO_free_all(out) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }

    let mut ret = 1i32;

    // `if (pkey_op == EVP_PKEY_OP_VERIFY) { ... rv = EVP_PKEY_verify(...); if
    // (rv == 1) { "Signature Verified Successfully"; ret = 0; } else {
    // "Signature Verification Failure"; } goto end; }` — `apps/pkeyutl.c:557-571`.
    if op == Op::Verify {
        // SAFETY: `ctx` is live; the buffers are the caller's.
        let rv =
            unsafe { EVP_PKEY_verify(ctx, sig.as_ptr(), sig.len(), buf_in.as_ptr(), buf_in.len()) };
        if rv == 1 {
            bio_puts(out, "Signature Verified Successfully\n");
            ret = 0;
        } else {
            bio_puts(out, "Signature Verification Failure\n");
        }
        // SAFETY: all are live and not freed again.
        unsafe { BIO_free(inbio) };
        // SAFETY: as above.
        unsafe { BIO_free_all(out) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return ret;
    }

    // `rv = do_keyop(ctx, pkey_op, NULL, &buf_outlen, buf_in, buf_inlen, NULL,
    // &secretlen); if (rv > 0 && ...) { buf_out = app_malloc(...); rv =
    // do_keyop(ctx, pkey_op, buf_out, &buf_outlen, ...); }` —
    // `apps/pkeyutl.c:577-595`.
    let mut buf_outlen: usize = 0;
    // SAFETY: `ctx` is live; the size-query arm passes a NULL out pointer.
    let rv = do_keyop(
        ctx,
        op,
        core::ptr::null_mut(),
        &mut buf_outlen,
        buf_in.as_ptr(),
        buf_in.len(),
    );
    let buf_out = if rv > 0 && buf_outlen > 0 {
        let mut v = vec![0u8; buf_outlen];
        // SAFETY: `ctx` is live; `v` is writable for `buf_outlen` bytes.
        let rv2 = do_keyop(
            ctx,
            op,
            v.as_mut_ptr(),
            &mut buf_outlen,
            buf_in.as_ptr(),
            buf_in.len(),
        );
        if rv2 <= 0 {
            // SAFETY: all are live and not freed again.
            unsafe { BIO_free(inbio) };
            // SAFETY: as above.
            unsafe { BIO_free_all(out) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_free(ctx) };
            // SAFETY: as above.
            unsafe { EVP_PKEY_free(pkey) };
            eprintln!("Public Key operation error");
            return 1;
        }
        v.truncate(buf_outlen);
        v
    } else if rv > 0 {
        Vec::new()
    } else {
        // `if (rv <= 0) { if (pkey_op != EVP_PKEY_OP_DERIVE) "Public Key
        // operation error"; else "Key derivation failed"; goto end; }` —
        // `apps/pkeyutl.c:596-603`.
        let msg = if op != Op::Derive {
            "Public Key operation error"
        } else {
            "Key derivation failed"
        };
        eprintln!("{msg}");
        // SAFETY: all are live and not freed again.
        unsafe { BIO_free(inbio) };
        // SAFETY: as above.
        unsafe { BIO_free_all(out) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pkey) };
        return ret;
    };
    ret = 0;

    // `if (asn1parse) { ASN1_parse_dump(out, buf_out, (long)buf_outlen, 1, -1) }
    // else if (hexdump) { BIO_dump(out, buf_out, (int)buf_outlen); } else {
    // BIO_write(out, buf_out, (int)buf_outlen); }` — `apps/pkeyutl.c:606-613`.
    if asn1parse {
        // SAFETY: `out` is live; `buf_out` is readable.
        unsafe { ASN1_parse_dump(out, buf_out.as_ptr(), buf_outlen as i64, 1, -1) };
    } else if hexdump {
        // SAFETY: `out` is live; `buf_out` is readable.
        unsafe { BIO_dump(out, buf_out.as_ptr().cast(), buf_outlen as c_int) };
    } else {
        // SAFETY: `out` is live; `buf_out` is readable.
        unsafe { BIO_write(out, buf_out.as_ptr().cast(), buf_outlen as c_int) };
    }

    // `end: ... BIO_free(in); BIO_free_all(out); ... EVP_PKEY_CTX_free(ctx);
    // EVP_PKEY_free(pkey); ...` — `apps/pkeyutl.c:618-636`.
    // SAFETY: all are live and not freed again.
    unsafe { BIO_free(inbio) };
    // SAFETY: as above.
    unsafe { BIO_free_all(out) };
    // SAFETY: as above.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { EVP_PKEY_free(pkey) };
    ret
}

/// `BIO_write(bio, s, strlen(s))` — the small string writer this module uses.
fn bio_puts(bio: *mut Bio, s: &str) {
    // SAFETY: `bio` is live; the bytes are this frame's.
    unsafe { BIO_write(bio, s.as_ptr().cast(), s.len() as c_int) };
}
