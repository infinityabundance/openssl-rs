//! Phase 17.1g — `apps/x509.c`: the `openssl x509` command.
//!
//! The command body (`apps/x509.c:321-1234`): parse the generated `X509_OPTIONS` table
//! (with `opt_set_unknown_name("digest")`, so an unknown option is a digest name),
//! load a certificate (or, with `-req`, a CSR), then walk the `++num`-ordered print
//! requests (`-subject`, `-issuer`, `-serial`, `-dates`, `-fingerprint`, `-pubkey`,
//! `-subject_hash`, …), print the whole text form (`X509_print_ex`) and, unless
//! `-noout`/`-nocert`, re-encode the certificate as PEM or DER.
//!
//! ## What the court drives
//!
//! `x509 -in <ca.pem|leaf.pem> -noout -text` / `-subject` / `-issuer` / `-dates` /
//! `-fingerprint` / `-serial` / `-pubkey` / `-subject_hash`, plus the default
//! `x509 -in ca.pem` re-encode. Each output is a pure function of the fixed
//! certificate fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **The certificate-generation arms are not landed.** `-new`, `-x509toreq`, `-req`,
//!   `-CA`/`-CAkey`/`-set_serial`/`-days`/`-not_before`/`-not_after`,
//!   `-force_pubkey`/`-key`/`-signkey`, `-extfile`/`-extensions`/`-clrext` and the
//!   trust/alias writers (`-addtrust`/`-addreject`/`-setalias`/`-trustout`/`-clrtrust`/
//!   `-clrreject`) build or mutate a certificate and reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`-checkend`/`-checkhost`/`-checkemail`/`-checkip`/`-purpose`/`-modulus`/
//!   `-ocspid`/`-ext`/`-next_serial`/`-email`/`-ocsp_uri`/`-alias` are not driven.**
//!   The `-checkend` arm reads the wall clock; the others reach the `X509V3`/purpose/
//!   `BN_print`/email surfaces this stratum does not own. Each reaches `not_landed`.
//! * **`-nameopt` (`set_nameopt`) and `-certopt` (`set_cert_ex`) are not landed.** The
//!   default `get_nameopt()` flags and a zero `certflag` are used, which is what the
//!   driven arms exercise.
//! * **`-dateopt` (`set_dateopt`) is not landed.** The default `ASN1_DTFLGS_RFC822` is
//!   used for `-dates`.
//! * **`-md`/unknown-digest checking (`opt_check_md`) and `-badsig` are not landed.**
//! * **`-engine` is not landed** (`apps/x509.c:544-546`).
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_ulong};

use crate::apps::keyio::{bio_open_default, load_cert, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::X509_OPTIONS;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::asn1::text::i2a_ASN1_INTEGER;
use crate::asn1::time::ASN1_TIME_print_ex;
use crate::evp::legacy_sha::EVP_sha1;
use crate::pem::pem_all::PEM_write_bio_PUBKEY;
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::x509::t_x509::X509_print_ex;
use crate::x509::x509_cmp::{
    X509_get0_pubkey, X509_get0_serialNumber, X509_get_issuer_name, X509_get_subject_name,
    X509_issuer_name_hash, X509_subject_name_hash,
};
use crate::x509::x509_set::{X509_get0_notAfter, X509_get0_notBefore};
use crate::x509::x_all::{i2d_X509_bio, X509_digest};
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::X509_free;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `ASN1_DTFLGS_RFC822` — `include/openssl/asn1.h`.
const ASN1_DTFLGS_RFC822: c_long = 0x100;
/// `get_nameopt()` — `apps/lib/apps.c:194-197`, the default flags.
const GET_NAMEOPT: c_ulong = ((2 << 16) | 2 | 0x10 | 0x100 | 0x200) as c_ulong;

/// `void print_name(BIO *out, const char *title, const X509_NAME *nm)` —
/// `apps/lib/apps.c:1375-1401`, the default-flags arm (see the header).
fn print_name(out: *mut Bio, title: &core::ffi::CStr, nm: *const X509Name) {
    if out.is_null() {
        return;
    }
    if !title.to_bytes().is_empty() {
        // SAFETY: `out` is live; `title` is a static literal.
        unsafe { BIO_puts(out, title.as_ptr()) };
    }
    // SAFETY: `out` is live; `nm` is live or NULL.
    unsafe { X509_NAME_print_ex(out, nm, 0, GET_NAMEOPT) };
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
}

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

/// The certificate-printing arm an option registered, in `++num` order
/// (`apps/x509.c:1037-1153`).
enum Print {
    Issuer,
    Subject,
    Serial,
    NextSerial,
    Email,
    OcspUri,
    Alias,
    SubjectHash,
    IssuerHash,
    Purpose,
    Modulus,
    Pubkey,
    Text,
    StartDate,
    EndDate,
    Fingerprint,
    OcspId,
    Ext,
}

/// `int x509_main(int argc, char **argv)` — `apps/x509.c:321-1234`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("digest"); prog = opt_init(argc, argv, x509_options);` —
    // `apps/x509.c:374-375`.
    let mut opts = Opts::init(argv, X509_OPTIONS);
    opts.enable_unknown("digest");
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut noout = false;
    let mut nocert = false;
    let mut reqfile = false;
    let mut digest: Option<String> = None;
    let mut prints: Vec<Print> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/x509.c:376`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(x509_options); ret = 0; goto end;` —
            // `apps/x509.c:383-386`.
            OptMatch::Help => return not_landed("x509 -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto err;` — `apps/x509.c:378-382`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
            // goto opthelp;` — `apps/x509.c:387-390`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/x509.c:391-393`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat)) ...`
            // — `apps/x509.c:394-397`. `OPT_FMT_ANY` accepts the PEMDER pairs.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/x509.c:410-412`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_REQ: reqfile = 1; break;` — `apps/x509.c:413-415`.
            OptMatch::Flag("req") => reqfile = true,
            // `case OPT_TEXT: text = ++num; break;` — `apps/x509.c:571-573`.
            OptMatch::Flag("text") => prints.push(Print::Text),
            // `case OPT_NOOUT: noout = ++num; break;` — `apps/x509.c:598-600`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_NOCERT: nocert = 1; break;` — `apps/x509.c:605-607`.
            OptMatch::Flag("nocert") => nocert = true,
            // `case OPT_SUBJECT: subject = ++num; break;` — `apps/x509.c:574-576`.
            OptMatch::Flag("subject") => prints.push(Print::Subject),
            // `case OPT_ISSUER: issuer = ++num; break;` — `apps/x509.c:577-579`.
            OptMatch::Flag("issuer") => prints.push(Print::Issuer),
            // `case OPT_SERIAL: serial = ++num; break;` — `apps/x509.c:553-555`.
            OptMatch::Flag("serial") => prints.push(Print::Serial),
            // `case OPT_NEXT_SERIAL: next_serial = ++num; break;` — `apps/x509.c:556-558`.
            OptMatch::Flag("next_serial") => prints.push(Print::NextSerial),
            // `case OPT_FINGERPRINT: fingerprint = ++num; break;` — `apps/x509.c:580-582`.
            OptMatch::Flag("fingerprint") => prints.push(Print::Fingerprint),
            // `case OPT_DATES: startdate = ++num; enddate = ++num; break;` —
            // `apps/x509.c:644-647`.
            OptMatch::Flag("dates") => {
                prints.push(Print::StartDate);
                prints.push(Print::EndDate);
            }
            // `case OPT_STARTDATE: startdate = ++num; break;` — `apps/x509.c:592-594`.
            OptMatch::Flag("startdate") => prints.push(Print::StartDate),
            // `case OPT_ENDDATE: enddate = ++num; break;` — `apps/x509.c:595-597`.
            OptMatch::Flag("enddate") => prints.push(Print::EndDate),
            // `case OPT_HASH: case OPT_SUBJECT_HASH: subject_hash = ++num; break;` —
            // `apps/x509.c:583-585` (the table maps both `hash` and `subject_hash` to
            // `OPT_HASH`).
            OptMatch::Flag("hash") | OptMatch::Flag("subject_hash") => {
                prints.push(Print::SubjectHash)
            }
            // `case OPT_ISSUER_HASH: issuer_hash = ++num; break;` — `apps/x509.c:586-588`.
            OptMatch::Flag("issuer_hash") => prints.push(Print::IssuerHash),
            // `case OPT_PUBKEY: print_pubkey = ++num; break;` — `apps/x509.c:565-567`.
            OptMatch::Flag("pubkey") => prints.push(Print::Pubkey),
            // `case OPT_EMAIL: email = ++num; break;` — `apps/x509.c:547-549`.
            OptMatch::Flag("email") => prints.push(Print::Email),
            // `case OPT_OCSP_URI: ocsp_uri = ++num; break;` — `apps/x509.c:550-552`.
            OptMatch::Flag("ocsp_uri") => prints.push(Print::OcspUri),
            // `case OPT_ALIAS: aliasout = ++num; break;` — `apps/x509.c:617-619`.
            OptMatch::Flag("alias") => prints.push(Print::Alias),
            // `case OPT_PURPOSE: pprint = ++num; break;` — `apps/x509.c:589-591`.
            OptMatch::Flag("purpose") => prints.push(Print::Purpose),
            // `case OPT_MODULUS: modulus = ++num; break;` — `apps/x509.c:559-561`.
            OptMatch::Flag("modulus") => prints.push(Print::Modulus),
            // `case OPT_OCSPID: ocspid = ++num; break;` — `apps/x509.c:626-628`.
            OptMatch::Flag("ocspid") => prints.push(Print::OcspId),
            // `case OPT_EXT: ext = ++num; ext_names = opt_arg(); break;` —
            // `apps/x509.c:601-604`.
            OptMatch::Value("ext", _) => prints.push(Print::Ext),
            // `case OPT_MD: digest = opt_unknown(); break;` — `apps/x509.c:674-676`, the
            // empty-name unknown-option slot `opt_set_unknown_name("digest")` selects.
            OptMatch::Value("", v) => digest = Some(v),
            // The generation/mutation arms — `apps/x509.c:496-546`, `:648-673`. Each
            // reaches the boundary rather than fabricating a certificate.
            OptMatch::Flag("new")
            | OptMatch::Flag("x509toreq")
            | OptMatch::Value("set_serial", _)
            | OptMatch::Flag("force_pubkey")
            | OptMatch::Value("subj", _)
            | OptMatch::Value("key", _)
            | OptMatch::Value("signkey", _)
            | OptMatch::Value("CA", _)
            | OptMatch::Value("CAkey", _)
            | OptMatch::Value("CAserial", _)
            | OptMatch::Flag("CAcreateserial")
            | OptMatch::Flag("trustout")
            | OptMatch::Value("setalias", _)
            | OptMatch::Flag("clrtrust")
            | OptMatch::Value("addtrust", _)
            | OptMatch::Flag("clrreject")
            | OptMatch::Value("addreject", _)
            | OptMatch::Flag("clrext")
            | OptMatch::Value("extfile", _)
            | OptMatch::Value("extensions", _)
            | OptMatch::Value("not_before", _)
            | OptMatch::Value("not_after", _)
            | OptMatch::Value("days", _)
            | OptMatch::Flag("preserve_dates")
            | OptMatch::Flag("badsig")
            | OptMatch::Value("checkend", _)
            | OptMatch::Value("checkhost", _)
            | OptMatch::Value("checkemail", _)
            | OptMatch::Value("checkip", _)
            | OptMatch::Flag("multi") => return not_landed("x509 -new/-CA/checking"),
            // `case OPT_DATEOPT: if (!set_dateopt(&dateopt, opt_arg())) ...` —
            // `apps/x509.c:417-423`.
            OptMatch::Value("dateopt", _) => return not_landed("x509 -dateopt"),
            // `case OPT_COPY_EXTENSIONS: ...` — `apps/x509.c:424-430`.
            OptMatch::Value("copy_extensions", _) => return not_landed("x509 -copy_extensions"),
            // `case OPT_SIGOPT: ...` — `apps/x509.c:432-437`.
            OptMatch::Value("sigopt", _) => return not_landed("x509 -sigopt"),
            // `case OPT_VFYOPT: ...` — `apps/x509.c:438-443`.
            OptMatch::Value("vfyopt", _) => return not_landed("x509 -vfyopt"),
            // `case OPT_PASSIN: passinarg = opt_arg(); break;` — `apps/x509.c:458-460`.
            OptMatch::Value("passin", _) => return not_landed("x509 -passin"),
            // `case OPT_CERTOPT: if (!set_cert_ex(&certflag, opt_arg())) goto opthelp;` —
            // `apps/x509.c:536-539`.
            OptMatch::Value("certopt", _) => return not_landed("x509 -certopt"),
            // `case OPT_NAMEOPT: if (!set_nameopt(opt_arg())) goto opthelp;` —
            // `apps/x509.c:540-543`.
            OptMatch::Value("nameopt", _) => return not_landed("x509 -nameopt"),
            // `case OPT_KEYFORM`/`OPT_CAFORM`/`OPT_CAKEYFORM` — format strings for the
            // generation arms, not driven.
            OptMatch::Value("keyform", _)
            | OptMatch::Value("CAform", _)
            | OptMatch::Value("CAkeyform", _) => return not_landed("x509 -keyform"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/x509.c:544-546`.
            OptMatch::Value("engine", _) => return not_landed("x509 -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/x509.c:464-467`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("x509 -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/x509.c:468-471`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("x509 -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/x509.c:680-681`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (!opt_check_md(digest)) goto opthelp;` — `apps/x509.c:686-687`.
    if let Some(d) = &digest {
        return not_landed(if d.is_empty() { "x509 -md" } else { d });
    }

    // `if (reqfile) { ... }` — the CSR arms are not driven.
    if reqfile {
        return not_landed("x509 -req");
    }

    // `x = load_cert_pass(infile, informat, 1, passin, "certificate"); if (x == NULL)
    // goto err;` — `apps/x509.c:867-871`.
    let x = load_cert(infile.as_deref(), informat, "certificate");
    if x.is_null() {
        return 1;
    }

    // `out = bio_open_default(outfile, 'w', outformat); if (out == NULL) goto err;` —
    // `apps/x509.c:874-876`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `x` is live and not freed again.
        unsafe { X509_free(x) };
        return not_landed("x509 -out (unopenable)");
    }

    // `pkey = X509_get0_pubkey(x);` — `apps/x509.c:971`.
    // SAFETY: `x` is live.
    let pkey = unsafe { X509_get0_pubkey(x) };

    // The `num`-ordered print loop — `apps/x509.c:1037-1153`.
    for p in &prints {
        match p {
            Print::Issuer => {
                // SAFETY: `x` is live.
                let nm = unsafe { X509_get_issuer_name(x) };
                print_name(out, c"issuer=", nm);
            }
            Print::Subject => {
                // SAFETY: `x` is live.
                let nm = unsafe { X509_get_subject_name(x) };
                print_name(out, c"subject=", nm);
            }
            Print::Serial => {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_printf(out, c"serial=".as_ptr()) };
                // SAFETY: `out`/`x` are live.
                unsafe { i2a_ASN1_INTEGER(out, X509_get0_serialNumber(x)) };
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::StartDate => {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"notBefore=".as_ptr()) };
                // SAFETY: `out`/`x` are live; the RFC822 default flag is passed.
                unsafe {
                    ASN1_TIME_print_ex(out, X509_get0_notBefore(x), ASN1_DTFLGS_RFC822 as c_ulong)
                };
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::EndDate => {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"notAfter=".as_ptr()) };
                // SAFETY: `out`/`x` are live; the RFC822 default flag is passed.
                unsafe {
                    ASN1_TIME_print_ex(out, X509_get0_notAfter(x), ASN1_DTFLGS_RFC822 as c_ulong)
                };
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::SubjectHash => {
                // SAFETY: `x` is live.
                let h = unsafe { X509_subject_name_hash(x) };
                // SAFETY: `out` is live; the format/`h` are this frame's.
                unsafe { BIO_printf(out, c"%08lx\n".as_ptr(), h) };
            }
            Print::IssuerHash => {
                // SAFETY: `x` is live.
                let h = unsafe { X509_issuer_name_hash(x) };
                // SAFETY: `out` is live; the format/`h` are this frame's.
                unsafe { BIO_printf(out, c"%08lx\n".as_ptr(), h) };
            }
            Print::Pubkey => {
                // `PEM_write_bio_PUBKEY(out, pkey);` — `apps/x509.c:1110-1112`.
                if !pkey.is_null() {
                    // SAFETY: `out`/`pkey` are live.
                    unsafe { PEM_write_bio_PUBKEY(out, pkey) };
                }
            }
            Print::Fingerprint => {
                // `if (fdigname == NULL) fdigname = "SHA1";` — `apps/x509.c:1129-1130`.
                let digest = EVP_sha1();
                let mut md = [0u8; 64];
                let mut n: c_uint = 0;
                // SAFETY: `x` is live; `digest` is a static method; `md`/`n` are this
                // frame's out-parameters.
                let digres =
                    unsafe { X509_digest(x, digest, md.as_mut_ptr().cast::<c_uchar>(), &mut n) };
                if digres == 0 {
                    eprintln!("Out of memory");
                    // SAFETY: `out`/`x` are live and not freed again.
                    unsafe { crate::runtime::bio::BIO_free_all(out) };
                    // SAFETY: `out`/`x` are live and not freed again.
                    unsafe { X509_free(x) };
                    return 1;
                }
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_printf(out, c"SHA1 Fingerprint=".as_ptr()) };
                let mut s = String::new();
                for (j, b) in md[..n as usize].iter().enumerate() {
                    if j + 1 == n as usize {
                        s.push_str(&format!("{b:02X}\n"));
                    } else {
                        s.push_str(&format!("{b:02X}:"));
                    }
                }
                // SAFETY: `out` is live; `s` is this frame's bytes.
                unsafe {
                    crate::runtime::bio::iolib::BIO_write(out, s.as_ptr().cast(), s.len() as c_int)
                };
            }
            Print::Text => {
                // `X509_print_ex(out, x, get_nameopt(), certflag);` —
                // `apps/x509.c:1112-1113`.
                // SAFETY: `out`/`x` are live; the flag word is the default, `certflag` 0.
                unsafe { X509_print_ex(out, x, GET_NAMEOPT, 0) };
            }
            Print::NextSerial
            | Print::Email
            | Print::OcspUri
            | Print::Alias
            | Print::Purpose
            | Print::Modulus
            | Print::OcspId
            | Print::Ext => return not_landed("x509 print arm"),
        }
    }

    if noout || nocert {
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { X509_free(x) };
        return 0;
    }

    // `if (outformat == FORMAT_ASN1) i = i2d_X509_bio(out, x); else if (FORMAT_PEM) i =
    // PEM_write_bio_X509(out, x); else "Bad output format ...";` — `apps/x509.c:1183-1193`.
    let i = if outformat == FORMAT_ASN1 {
        // SAFETY: `out`/`x` are live.
        unsafe { i2d_X509_bio(out, x) }
    } else if outformat == FORMAT_PEM {
        // SAFETY: `out`/`x` are live.
        unsafe { PEM_write_bio_X509(out, x) }
    } else {
        eprintln!("Bad output format specified for outfile");
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { X509_free(x) };
        return 1;
    };
    if i == 0 {
        eprintln!("Unable to write certificate");
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { X509_free(x) };
        return 1;
    }

    // `end: ... BIO_free_all(out); X509_free(x); ...` — `apps/x509.c:1209-1233`.
    // SAFETY: `out`/`x` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    // SAFETY: `out`/`x` are live and not freed again.
    unsafe { X509_free(x) };
    0
}
