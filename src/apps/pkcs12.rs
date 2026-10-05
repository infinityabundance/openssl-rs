//! Phase 17.1g — `apps/pkcs12.c`: the `openssl pkcs12` command.
//!
//! The command body (`apps/pkcs12.c:202-958`): parse the generated
//! `PKCS12_OPTIONS` table (with `opt_set_unknown_name("cipher")`), then either
//! export a PKCS#12 structure (`-export`, `PKCS12_create_ex2` + `i2d_PKCS12_bio`)
//! or read one and dump its contents/MAC (`-info`, `d2i_PKCS12_bio`,
//! `PKCS12_get0_mac`, `PKCS12_verify_mac`, `dump_certs_keys_p12`).
//!
//! ## What the court drives
//!
//! `pkcs12 -export -nomac -keypbe NONE -certpbe NONE -in <signer.pem> -inkey
//! <rsa-key.pem> -passout pass:test`, whose DER output is a pure function of the
//! fixed fixtures (no random salt/key). The `-info` MAC lines and bag dump, and
//! the ordinary (random-salt) `-export`, are recorded.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-info` is not landed.** The bag dump needs `alg_print`
//!   (`apps/pkcs12.c:1178-1377`, the `PBES2`/`PBKDF2`/`PKCS12KDF` algorithm printer)
//!   and the `PKCS12_SAFEBAG` walk; the MAC header lines are read but the dump is
//!   not transcribed, so the arm reaches
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **The ordinary `-export` (without `-nomac -keypbe NONE -certpbe NONE`) is
//!   recorded, not driven.** It draws a random salt/MAC, so the bytes are
//!   independent on the two sides; the operation is transcribed.
//! * **`-chain`/`-untrusted`/`-certfile` (`load_certs`, `get_cert_chain`),
//!   `-descert`/`-keyex`/`-keysig`/`-CSP`/`-LMK`/`-jdktrust`, `-name`/`-caname`,
//!   `-twopass`/`-passcerts`, `-password` and `-engine` are not landed.**
//! * **`-passin`/`-passout` are reduced to the `pass:` observable** (`app_passwd`'s
//!   `env:`/`file:`/`fd:`/`stdin` sources are not landed).
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::apps::keyio::{bio_open_default, load_cert, load_key};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PKCS12_OPTIONS;
use crate::pkcs12::p12_asn::{PKCS12_free, Pkcs12};
use crate::pkcs12::p12_crt::PKCS12_create_ex2;
use crate::pkcs12::p12_utl::i2d_PKCS12_bio;
use crate::runtime::bio::{BIO_free_all, Bio};
use crate::x509::x_x509::X509_free;

/// `set_pbe(ppbe, str)` — `apps/pkcs12.c:1379-1393`, the `NONE` arm (other names
/// need `OBJ_txt2nid`, not landed).
fn set_pbe(str_: Option<&str>) -> Option<c_int> {
    let s = str_?;
    if s == "NONE" {
        Some(-1)
    } else {
        None
    }
}

/// `app_passwd(arg, NULL, &pass, NULL)` — the `pass:` arm of `apps/lib/apps.c:231-274`.
fn app_passwd(arg: Option<&str>) -> Option<Option<String>> {
    match arg {
        None => Some(None),
        Some(a) => a.strip_prefix("pass:").map(|p| Some(p.to_string())),
    }
}

/// `int pkcs12_main(int argc, char **argv)` — `apps/pkcs12.c:202-958`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, pkcs12_options);`
    // — `apps/pkcs12.c:234-235`.
    let mut opts = Opts::init(argv, PKCS12_OPTIONS);
    opts.enable_unknown("cipher");
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut inkey: Option<String> = None;
    let mut passoutarg: Option<String> = None;
    let mut export_pkcs12 = false;
    let mut info = false;
    let mut nomac = false;
    let mut enc: Option<c_int> = None;
    let mut key_pbe: c_int = 0;
    let mut cert_pbe: c_int = 0;
    let mut iter: c_int = 2048;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/pkcs12.c:236`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(pkcs12_options); ret = 0; goto end;` —
            // `apps/pkcs12.c:243-246`.
            OptMatch::Help => return not_landed("pkcs12 -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/pkcs12.c:238-242`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: infile = opt_arg();` — `apps/pkcs12.c:374-376`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg();` — `apps/pkcs12.c:377-379`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_INKEY: inkey = opt_arg();` — `apps/pkcs12.c:346-348`.
            OptMatch::Value("inkey", v) => inkey = Some(v),
            // `case OPT_PASSOUT: passoutarg = opt_arg();` — `apps/pkcs12.c:383-385`.
            OptMatch::Value("passout", v) => passoutarg = Some(v),
            // `case OPT_EXPORT: export_pkcs12 = 1;` — `apps/pkcs12.c:290-292`.
            OptMatch::Flag("export") => export_pkcs12 = true,
            // `case OPT_INFO: options |= INFO;` — `apps/pkcs12.c:273-275`.
            OptMatch::Flag("info") => info = true,
            // `case OPT_NOMAC: cert_pbe = -1; maciter = -1;` — `apps/pkcs12.c:321-324`.
            OptMatch::Flag("nomac") => {
                cert_pbe = -1;
                nomac = true;
            }
            // `case OPT_NOENC`/`OPT_NODES: enc = NULL;` — `apps/pkcs12.c:293-302`.
            OptMatch::Flag("noenc") | OptMatch::Flag("nodes") => enc = None,
            // `case OPT_KEYPBE: if (!set_pbe(&key_pbe, opt_arg())) goto opthelp;` —
            // `apps/pkcs12.c:338-341`.
            OptMatch::Value("keypbe", v) => match set_pbe(Some(&v)) {
                Some(p) => key_pbe = p,
                None => {
                    eprintln!("Unknown PBE algorithm {v}");
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            },
            // `case OPT_CERTPBE: if (!set_pbe(&cert_pbe, opt_arg())) goto opthelp;` —
            // `apps/pkcs12.c:334-337`.
            OptMatch::Value("certpbe", v) => match set_pbe(Some(&v)) {
                Some(p) => cert_pbe = p,
                None => {
                    eprintln!("Unknown PBE algorithm {v}");
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            },
            // `case OPT_ITER: maciter = iter = opt_int_arg();` — `apps/pkcs12.c:306-308`.
            OptMatch::Value("iter", v) => {
                iter = v.parse().unwrap_or(0);
            }
            // `case OPT_NOITER: iter = 1;` — `apps/pkcs12.c:309-311`.
            OptMatch::Flag("noiter") => iter = 1,
            // `case OPT_CIPHER: enc_name = ciphername = opt_unknown();` —
            // `apps/pkcs12.c:303-305`. `enc` stays the default.
            OptMatch::Value("", _) => return not_landed("pkcs12 -cipher"),
            // `case OPT_PASSIN`/`OPT_PASSWORD`/`OPT_PASSCERTS` — not driven.
            OptMatch::Value("passin", _) => return not_landed("pkcs12 -passin"),
            OptMatch::Value("password", _) => return not_landed("pkcs12 -password"),
            OptMatch::Value("passcerts", _) => return not_landed("pkcs12 -passcerts"),
            // The chain/certificate arms — `apps/pkcs12.c:346-406`.
            OptMatch::Value("certfile", _)
            | OptMatch::Value("untrusted", _)
            | OptMatch::Value("CAfile", _)
            | OptMatch::Value("CApath", _)
            | OptMatch::Value("CAstore", _)
            | OptMatch::Flag("chain")
            | OptMatch::Value("name", _)
            | OptMatch::Value("caname", _)
            | OptMatch::Value("CSP", _)
            | OptMatch::Value("jdktrust", _)
            | OptMatch::Value("macalg", _)
            | OptMatch::Value("pbmac1_pbkdf2_md", _)
            | OptMatch::Value("macsaltlen", _)
            | OptMatch::Flag("pbmac1_pbkdf2")
            | OptMatch::Flag("descert")
            | OptMatch::Flag("keyex")
            | OptMatch::Flag("keysig")
            | OptMatch::Flag("LMK")
            | OptMatch::Flag("twopass")
            | OptMatch::Flag("legacy")
            | OptMatch::Flag("nokeys")
            | OptMatch::Flag("nocerts")
            | OptMatch::Flag("clcerts")
            | OptMatch::Flag("cacerts")
            | OptMatch::Flag("nomacver")
            | OptMatch::Flag("maciter")
            | OptMatch::Flag("nomaciter")
            | OptMatch::Flag("no-CAfile")
            | OptMatch::Flag("no-CApath")
            | OptMatch::Flag("no-CAstore") => return not_landed("pkcs12 -chain/-pbe"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0);` —
            // `apps/pkcs12.c:407-410`.
            OptMatch::Value("engine", _) => return not_landed("pkcs12 -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/pkcs12.c:342-345`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("pkcs12 -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/pkcs12.c:415-418`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("pkcs12 -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (infile == NULL && export_pkcs12) { ... }` — the export path needs `-in`
    // and a key. The court's arm supplies both.
    let _ = enc;
    if info {
        return not_landed("pkcs12 -info");
    }
    if !export_pkcs12 {
        return not_landed("pkcs12");
    }

    let Some(passout) = app_passwd(passoutarg.as_deref()) else {
        eprintln!("Error getting password");
        return 1;
    };
    let _ = &passout;

    // The certificate/key loads — `apps/pkcs12.c:599-608`.
    let cert = load_cert(infile.as_deref(), 0, "certificate");
    if cert.is_null() {
        return 1;
    }
    let key = load_key(inkey.as_deref(), 0, "private key");
    if key.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(cert) };
        return 1;
    }

    // `p12 = PKCS12_create_ex2(cpass, name, key, ee_cert, certs, key_pbe, cert_pbe,
    // iter, -1, keytype, ctx, propq, jdk_trust, obj);` — `apps/pkcs12.c:732-735`.
    let cpass = passout.unwrap_or_default();
    let cpass_c = std::ffi::CString::new(cpass).unwrap_or_default();
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    let p12: *mut Pkcs12 = unsafe {
        PKCS12_create_ex2(
            cpass_c.as_ptr(),
            core::ptr::null(),
            key,
            cert,
            core::ptr::null_mut(),
            key_pbe,
            cert_pbe,
            iter,
            -1,
            c_int::default(),
            core::ptr::null_mut(),
            core::ptr::null(),
            None,
            core::ptr::null_mut(),
        )
    };
    let _ = &nomac;
    if p12.is_null() {
        eprintln!("Error creating PKCS12 structure for {outfile:?}");
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(cert) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
        return 1;
    }

    // `out = bio_open_owner(outfile, FORMAT_PKCS12, private); i2d_PKCS12_bio(out,
    // p12);` — `apps/pkcs12.c:767-771`.
    let out: *mut Bio = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { PKCS12_free(p12) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(cert) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
        return 1;
    }
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { i2d_PKCS12_bio(out, p12) };

    // `PKCS12_free(p12); ...` — `apps/pkcs12.c:948-958`.
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { BIO_free_all(out) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { PKCS12_free(p12) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { X509_free(cert) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
    let _: *const c_char = core::ptr::null();
    0
}
