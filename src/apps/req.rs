//! Phase 17.1g — `apps/req.c`: the `openssl req` command.
//!
//! The command body (`apps/req.c:283-1110`): parse the generated `REQ_OPTIONS` table
//! (with `opt_set_unknown_name("digest")`, so an unknown option is a digest name),
//! load a request (`load_csr_autofmt` at `apps/lib/apps.c`), optionally verify its
//! self-signature (`do_X509_REQ_verify`), print the selected fields (`-text` via
//! `X509_REQ_print_ex`, `-subject`, `-pubkey`) and, unless `-noout`, re-encode the
//! request (`PEM_write_bio_X509_REQ`/`i2d_X509_REQ_bio`).
//!
//! ## What the court drives
//!
//! `req -in <req.pem> -noout -text`, `-noout -verify` (the `Certificate request
//! self-signature verify OK` line), `-noout -subject` and the default
//! `req -in <req.pem> -noout` re-encode. Each output is a pure function of the fixed
//! CSR fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **The request/certificate generation arms are not landed.** `-new`, `-newkey`,
//!   `-key`/`-keyform`, `-x509`/`-x509v1`, `-CA`/`-CAkey`, `-subj`, `-addext`,
//!   `-extensions`/`-reqexts`, `-precert`, `-set_serial`, `-not_before`/`-not_after`/
//!   `-days`, `-copy_extensions`, `-passin`/`-passout`, `-cipher`/`-noenc`/`-nodes`
//!   and `-keyout` build or write a request/certificate and reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`-config`/`-section` (`app_load_config_verbose`/`app_load_modules`) and the
//!   `oid_file`/`default_md`/extension-section reads are not landed.** The court arm
//!   runs with `OPENSSL_CONF=/dev/null`, so no configuration contributes; the
//!   default `req` section values (`default_md`, `input_password`, …) are therefore
//!   the empty config's NULLs, which is what the driven arm exercises.
//! * **`-nameopt`/`-reqopt` (`set_nameopt`/`set_req_ex`) are not landed.** The default
//!   `get_nameopt()` flags and a zero `reqflag` are used.
//! * **`-modulus` (`BN_print`), `-verbose`/`-quiet` and `-utf8`/`-multivalue-rdn`/
//!   `-batch` are not driven** (the generation arms they modify are not landed).
//! * **`-engine`/`-keygen_engine` are not landed** (`apps/req.c:340-351`).
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_ulong};

use crate::apps::keyio::{bio_open_default, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::REQ_OPTIONS;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::pem::pem_all::PEM_write_bio_PUBKEY;
use crate::pem::pem_all::{
    PEM_read_bio_X509_REQ, PEM_write_bio_X509_REQ, PEM_write_bio_X509_REQ_NEW,
};
use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::{BIO_free, Bio};
use crate::x509::t_req::X509_REQ_print_ex;
use crate::x509::x509_req::{X509Req, X509_REQ_get0_pubkey, X509_REQ_get_subject_name};
use crate::x509::x_all::{d2i_X509_REQ_bio, i2d_X509_REQ_bio, X509_REQ_verify};
use crate::x509::x_name::X509Name;
use crate::x509::x_req::X509_REQ_free;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `get_nameopt()` — `apps/lib/apps.c:194-197`, the default flags.
const GET_NAMEOPT: c_ulong = ((2 << 16) | 2 | 0x10 | 0x100 | 0x200) as c_ulong;
/// `UNSET_DAYS` — `apps/req.c`.
const UNSET_DAYS: c_int = -1;

/// `void print_name(BIO *out, const char *title, const X509_NAME *nm)` —
/// `apps/lib/apps.c:1375-1401`, the default-flags arm.
fn print_name(out: *mut Bio, title: &core::ffi::CStr, nm: *const X509Name) {
    if out.is_null() {
        return;
    }
    // SAFETY: `out` is live; `title` is a static literal.
    unsafe { BIO_puts(out, title.as_ptr()) };
    // SAFETY: `out` is live; `nm` is live or NULL.
    unsafe { X509_NAME_print_ex(out, nm, 0, GET_NAMEOPT) };
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
}

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms.
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

/// `X509_REQ *load_csr_autofmt(...)` — `apps/lib/apps.c`, the PEM/DER decoder arms.
fn load_csr(uri: Option<&str>, format: c_int) -> *mut X509Req {
    let Some(path) = uri else {
        eprintln!("Could not open file or uri for loading of X509 request from <stdin>");
        return core::ptr::null_mut();
    };
    let Ok(cs) = std::ffi::CString::new(path) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `cs` is NUL-terminated and outlives the call.
    let bio = unsafe { BIO_new_file(cs.as_ptr(), c"r".as_ptr()) };
    if bio.is_null() {
        eprintln!("Could not open file or uri for loading of X509 request from {path}");
        return core::ptr::null_mut();
    }
    // SAFETY: `bio` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let req = unsafe {
        if format == FORMAT_ASN1 {
            d2i_X509_REQ_bio(bio, core::ptr::null_mut())
        } else {
            PEM_read_bio_X509_REQ(bio, core::ptr::null_mut(), None, core::ptr::null_mut())
        }
    };
    if req.is_null() {
        eprintln!("Could not read X509 request from {path}");
    }
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    req
}

/// `int req_main(int argc, char **argv)` — `apps/req.c:283-1110`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("digest"); prog = opt_init(argc, argv, req_options);` —
    // `apps/req.c:319-320`.
    let mut opts = Opts::init(argv, REQ_OPTIONS);
    opts.enable_unknown("digest");
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut verify = false;
    let mut text = false;
    let mut subject = false;
    let mut pubkey = false;
    let mut noout = false;
    let mut newhdr = false;
    let mut modulus = false;
    let mut gen_x509 = false;
    let mut newreq = false;
    let mut digest: Option<String> = None;
    let mut days = UNSET_DAYS;
    let mut not_before = false;
    let mut not_after = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/req.c:321`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(req_options); ret = 0; goto end;` —
            // `apps/req.c:328-331`.
            OptMatch::Help => return not_landed("req -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/req.c:323-327`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
            // goto opthelp;` — `apps/req.c:332-335`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/req.c:336-339`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/req.c:371-373`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/req.c:374-376`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_VERIFY: verify = 1; break;` — `apps/req.c:426-428`.
            OptMatch::Flag("verify") => verify = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/req.c:455-457`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_SUBJECT: subject = 1; break;` — `apps/req.c:497-499`.
            OptMatch::Flag("subject") => subject = true,
            // `case OPT_PUBKEY: pubkey = 1; break;` — `apps/req.c:355-357`.
            OptMatch::Flag("pubkey") => pubkey = true,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/req.c:433-435`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_NEWHDR: newhdr = 1; break;` — `apps/req.c:420-422`.
            OptMatch::Flag("newhdr") => newhdr = true,
            // `case OPT_MODULUS: modulus = 1; break;` — `apps/req.c:423-425`.
            OptMatch::Flag("modulus") => modulus = true,
            // `case OPT_NEW: newreq = 1; break;` — `apps/req.c:358-360`.
            OptMatch::Flag("new") => newreq = true,
            // `case OPT_X509: gen_x509 = 1; break;` — `apps/req.c:461-463`.
            OptMatch::Flag("x509") => gen_x509 = true,
            // `case OPT_X509V1: break;` — `apps/req.c:458-460`.
            OptMatch::Flag("x509v1") => {}
            // `case OPT_DAYS: days = opt_int_arg(); break;` — `apps/req.c:477-484`.
            OptMatch::Value("days", v) => days = v.parse().unwrap_or(0),
            // `case OPT_NOT_BEFORE: not_before = opt_arg(); break;` — `apps/req.c:471-473`.
            OptMatch::Value("not_before", _) => not_before = true,
            // `case OPT_NOT_AFTER: not_after = opt_arg(); break;` — `apps/req.c:474-476`.
            OptMatch::Value("not_after", _) => not_after = true,
            // `case OPT_MD: digest = opt_unknown(); break;` — `apps/req.c:540-542`.
            OptMatch::Value("", v) => digest = Some(v),
            // The generation/mutation arms — `apps/req.c:352-540`.
            OptMatch::Value("key", _)
            | OptMatch::Value("keyform", _)
            | OptMatch::Value("newkey", _)
            | OptMatch::Value("pkeyopt", _)
            | OptMatch::Value("sigopt", _)
            | OptMatch::Value("vfyopt", _)
            | OptMatch::Value("passin", _)
            | OptMatch::Value("passout", _)
            | OptMatch::Value("cipher", _)
            | OptMatch::Value("keyout", _)
            | OptMatch::Flag("noenc")
            | OptMatch::Flag("nodes")
            | OptMatch::Value("subj", _)
            | OptMatch::Value("config", _)
            | OptMatch::Value("section", _)
            | OptMatch::Flag("multivalue-rdn")
            | OptMatch::Value("extensions", _)
            | OptMatch::Value("reqexts", _)
            | OptMatch::Value("addext", _)
            | OptMatch::Value("copy_extensions", _)
            | OptMatch::Value("set_serial", _)
            | OptMatch::Value("CA", _)
            | OptMatch::Value("CAkey", _)
            | OptMatch::Flag("precert")
            | OptMatch::Flag("batch")
            | OptMatch::Flag("verbose")
            | OptMatch::Flag("quiet")
            | OptMatch::Flag("utf8")
            | OptMatch::Value("nameopt", _)
            | OptMatch::Value("reqopt", _) => return not_landed("req -new/-config/-key"),
            // `case OPT_ENGINE`/`OPT_KEYGEN_ENGINE` — `apps/req.c:340-351`.
            OptMatch::Value("engine", _) | OptMatch::Value("keygen_engine", _) => {
                return not_landed("req -engine")
            }
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/req.c:386-389`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("req -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/req.c:390-393`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("req -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/req.c:547-548`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!gen_x509) { if (days != UNSET_DAYS) "Warning: Ignoring -days without
    // -x509…"; … }` — `apps/req.c:553-562`.
    if !gen_x509 {
        if days != UNSET_DAYS {
            eprintln!("Warning: Ignoring -days without -x509; not generating a certificate");
        }
        if not_before {
            eprintln!("Warning: Ignoring -not_before without -x509; not generating a certificate");
        }
        if not_after {
            eprintln!("Warning: Ignoring -not_after without -x509; not generating a certificate");
        }
    }
    // `if (infile == NULL) { if (gen_x509) newreq = 1; else if (!newreq && isatty(...)) … }`
    // — `apps/req.c:563-569`. The court always passes `-in`.
    if infile.is_none() && gen_x509 {
        newreq = true;
    }
    // `if (!app_passwd(...)) { Error getting passwords }` — `apps/req.c:571-574`; the
    // no-`-passin`/`-passout` arm is the NULL success.
    // `app_load_config_verbose(template, verbose)` and the config-derived
    // `default_md`/extension section reads — `apps/req.c:576-643`: with
    // `OPENSSL_CONF=/dev/null` they contribute nothing (see the header).
    if let Some(d) = &digest {
        // `opt_check_md(digest)` — `apps/req.c:607-609`.
        return not_landed(if d.is_empty() { "req -md" } else { d });
    }
    if newreq || gen_x509 {
        return not_landed("req -new/-x509");
    }

    // `req = load_csr_autofmt(infile, informat, vfyopts, "X509 request"); if (req ==
    // NULL) goto end;` — `apps/req.c:783-786`.
    let req = load_csr(infile.as_deref(), informat);
    if req.is_null() {
        return 1;
    }

    // `if (verify) { tpubkey = X509_REQ_get0_pubkey(req); i = do_X509_REQ_verify(req,
    // tpubkey, vfyopts); if (i < 0) goto end; if (i == 0) { "...verify failure" }
    // else BIO_printf(bio_out, "Certificate request self-signature verify OK\n"); }`
    // — `apps/req.c:970-989`.
    // `if (verify) { ... }` — `apps/req.c:970-989`.
    if verify {
        // SAFETY: `req` is live.
        let tpubkey = unsafe { X509_REQ_get0_pubkey(req) };
        if !tpubkey.is_null() {
            // SAFETY: `req`/`tpubkey` are live.
            let i = unsafe { X509_REQ_verify(req, tpubkey) };
            if i < 0 {
                // SAFETY: `req` is live and not freed again.
                unsafe { X509_REQ_free(req) };
                return 1;
            }
            if i == 0 {
                eprintln!("Certificate request self-signature verify failure");
                // SAFETY: `req` is live and not freed again.
                unsafe { X509_REQ_free(req) };
                return 1;
            }
            let bio_out = bio_open_default(None, true);
            let line = b"Certificate request self-signature verify OK\n";
            // SAFETY: `bio_out` is live; `line` is this frame's bytes.
            unsafe {
                crate::runtime::bio::iolib::BIO_write(
                    bio_out,
                    line.as_ptr().cast(),
                    line.len() as c_int,
                )
            };
            // SAFETY: `bio_out` is this frame's own BIO.
            unsafe { crate::runtime::bio::BIO_free(bio_out) };
        }
    }

    // `if (noout && !text && !modulus && !subject && !pubkey) { ret = 0; goto end; }`
    // — `apps/req.c:991-994`.
    if noout && !text && !modulus && !subject && !pubkey {
        // SAFETY: `req` is live and not freed again.
        unsafe { X509_REQ_free(req) };
        return 0;
    }

    // `out = bio_open_default(outfile, 'w', outformat); if (out == NULL) goto end;` —
    // `apps/req.c:996-1000`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `req` is live and not freed again.
        unsafe { X509_REQ_free(req) };
        return not_landed("req -out (unopenable)");
    }

    // `if (pubkey) { tpubkey = X509_REQ_get0_pubkey(req); PEM_write_bio_PUBKEY(out,
    // tpubkey); }` — `apps/req.c:1002-1010`.
    if pubkey {
        // SAFETY: `req` is live.
        let tpubkey = unsafe { X509_REQ_get0_pubkey(req) };
        if tpubkey.is_null() {
            eprintln!("Error getting public key");
            // SAFETY: `out`/`req` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            // SAFETY: `out`/`req` are live and not freed again.
            unsafe { X509_REQ_free(req) };
            return 1;
        }
        // SAFETY: `out`/`tpubkey` are live.
        unsafe { PEM_write_bio_PUBKEY(out, tpubkey) };
    }

    // `if (text) ret = X509_REQ_print_ex(out, req, get_nameopt(), reqflag);` —
    // `apps/req.c:1012-1025`.
    if text {
        // SAFETY: `out`/`req` are live; the default flags and a zero reqflag.
        let i = unsafe { X509_REQ_print_ex(out, req, GET_NAMEOPT, 0) };
        if i == 0 {
            eprintln!("Error printing certificate request");
            // SAFETY: `out`/`req` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            // SAFETY: `out`/`req` are live and not freed again.
            unsafe { X509_REQ_free(req) };
            return 1;
        }
    }

    // `if (subject) print_name(out, "subject=", X509_REQ_get_subject_name(req));` —
    // `apps/req.c:1027-1029`.
    if subject {
        // SAFETY: `req` is live.
        let nm = unsafe { X509_REQ_get_subject_name(req) };
        print_name(out, c"subject=", nm);
    }

    // `if (modulus) { ... }` — `apps/req.c:1031-1054`.
    if modulus {
        // SAFETY: `out`/`req` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`req` are live and not freed again.
        unsafe { X509_REQ_free(req) };
        return not_landed("req -modulus");
    }

    // `if (!noout && !gen_x509) { i = ... i2d_X509_REQ_bio/PEM_write_bio_X509_REQ[_NEW]
    // ... }` — `apps/req.c:1056-1067`.
    let ret = if !noout {
        let i = if outformat == FORMAT_ASN1 {
            // SAFETY: `out`/`req` are live.
            unsafe { i2d_X509_REQ_bio(out, req) }
        } else if newhdr {
            // SAFETY: `out`/`req` are live.
            unsafe { PEM_write_bio_X509_REQ_NEW(out, req) }
        } else {
            // SAFETY: `out`/`req` are live.
            unsafe { PEM_write_bio_X509_REQ(out, req) }
        };
        if i == 0 {
            eprintln!("Unable to write certificate request");
            1
        } else {
            0
        }
    } else {
        0
    };

    // `end: ... BIO_free_all(out); ... X509_REQ_free(req); ...` — `apps/req.c:1079-1109`.
    // SAFETY: `out`/`req` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    // SAFETY: `out`/`req` are live and not freed again.
    unsafe { X509_REQ_free(req) };
    ret
}
