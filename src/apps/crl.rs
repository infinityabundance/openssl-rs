//! Phase 17.1d — `apps/crl.c`: the `openssl crl` command.
//!
//! The command body (`apps/crl.c:100-418`): parse the generated `CRL_OPTIONS` table,
//! load a CRL with `load_crl`, optionally verify it (`-verify`/`-CAfile`), print the
//! selected fields (`-issuer`, `-lastupdate`, `-nextupdate`, `-crlnumber`, `-hash`,
//! `-hash_old`, `-fingerprint`), print the whole text form (`-text` via
//! `X509_CRL_print_ex`) and re-encode it (`PEM_write_bio_X509_CRL`/`i2d_X509_CRL_bio`)
//! unless `-noout`. The parse, the load, every print arm and the writer are transcribed.
//!
//! ## What the court drives
//!
//! `crl -in <crl.pem> -noout`, `-text -noout`, `-issuer -noout`, `-lastupdate -noout`,
//! `-nextupdate -noout`, `-crlnumber -noout`, `-hash -noout`, `-fingerprint -noout` and
//! the default `crl -in <crl.pem>`, which re-encodes the CRL. Each output is a pure
//! function of the fixed CRL fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **The verify/delta/badsig arms are not landed.** `-verify` and the `-CA*` options
//!   reach `setup_verify` and `X509_CRL_verify` (`apps/crl.c:245-281`), `-gendelta`
//!   reaches `X509_CRL_diff` (`apps/crl.c:283-307`) and `-badsig` calls the `apps/lib`
//!   `corrupt_signature` helper (`apps/crl.c:309-314`); each reaches
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`opt_set_unknown_name("digest")` is not landed** (`apps/crl.c:124`); an unknown
//!   option is the parser's refusal rather than a digest name. Not driven.
//! * **`opt_md`/`app_get0_libctx`/`app_get0_propq`** are `apps/lib` helpers; no `-md` is
//!   driven, so `digest` stays `EVP_sha1()`.
//! * **`-nameopt` is not landed** (`set_nameopt`); `print_name` uses the default
//!   `get_nameopt()` flags as [`crate::apps::nseq`] does.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arm reaches the unlanded `opt_provider`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_uint};

use crate::apps::keyio::{bio_open_default, load_crl, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CRL_OPTIONS;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_INTEGER_free;
use crate::asn1::text::i2a_ASN1_INTEGER;
use crate::asn1::time::ASN1_TIME_print_ex;
use crate::evp::digest::EVP_MD_free;
use crate::evp::legacy_sha::EVP_sha1;
use crate::pem::pem_all::PEM_write_bio_X509_CRL;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_crl_number;
use crate::x509::t_crl::X509_CRL_print_ex;
use crate::x509::x509_cmp::{X509_NAME_hash_ex, X509_NAME_hash_old};
use crate::x509::x509cset::{
    X509_CRL_get0_lastUpdate, X509_CRL_get0_nextUpdate, X509_CRL_get_issuer,
};
use crate::x509::x_all::{i2d_X509_CRL_bio, X509_CRL_digest};
use crate::x509::x_crl::X509_CRL_free;
use crate::x509::x_name::X509Name;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `ASN1_DTFLGS_RFC822` — `include/openssl/asn1.h`.
const ASN1_DTFLGS_RFC822: c_long = 0x100;
/// `get_nameopt()` — `apps/lib/apps.c:194-197`, the default flags.
const GET_NAMEOPT: c_long = (2 << 16) | 2 | 0x10 | 0x100 | 0x200;

/// `void print_name(BIO *out, const char *title, const X509_NAME *nm)` —
/// `apps/lib/apps.c:1375-1401`, the non-multiline, non-`COMPAT` arm.
fn print_name(out: *mut Bio, title: &core::ffi::CStr, nm: *const X509Name) {
    // `BIO_puts(out, title);` — `apps/lib/apps.c:1385`.
    // SAFETY: `out` is live; `title` is a static literal.
    unsafe { BIO_puts(out, title.as_ptr()) };
    // `X509_NAME_print_ex(out, nm, indent, lflags);` with `indent == 0` (the default
    // flags are not `XN_FLAG_SEP_MULTILINE`).
    // SAFETY: `out` is live; `nm` is live or NULL.
    unsafe {
        crate::asn1::a_strex::X509_NAME_print_ex(out, nm, 0, GET_NAMEOPT as core::ffi::c_ulong)
    };
    // `BIO_puts(out, "\n");` — `apps/lib/apps.c:1399`.
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

/// The print request a `-issuer`/`-crlnumber`/… option registered, in match order
/// (`apps/crl.c:316-385`).
enum Print {
    Issuer,
    CrlNumber,
    Hash,
    HashOld,
    LastUpdate,
    NextUpdate,
    Fingerprint,
}

/// `int crl_main(int argc, char **argv)` — `apps/crl.c:100-418`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("digest"); prog = opt_init(argc, argv, crl_options);` —
    // `apps/crl.c:124-125`.
    let mut opts = Opts::init(argv, CRL_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_UNDEF;
    let mut outformat = FORMAT_PEM;
    let mut text = false;
    let mut noout = false;
    let mut do_ver = false;
    let mut prints: Vec<Print> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/crl.c:126`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(crl_options); ret = 0; goto end;` —
            // `apps/crl.c:133-136`.
            OptMatch::Help => return not_landed("crl -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/crl.c:128-132`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
            // goto opthelp;` — `apps/crl.c:137-140`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/crl.c:141-143`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/crl.c:144-147`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/crl.c:148-150`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat))
            // goto opthelp;` — `apps/crl.c:151-154`.
            OptMatch::Value("keyform", _) => {}
            // `case OPT_KEY: keyfile = opt_arg(); break;` — `apps/crl.c:155-157`.
            OptMatch::Value("key", _) => {}
            // `case OPT_GENDELTA: crldiff = opt_arg(); break;` — `apps/crl.c:158-160`.
            OptMatch::Value("gendelta", _) => return not_landed("crl -gendelta"),
            // `case OPT_CAPATH: CApath = opt_arg(); do_ver = 1; break;` —
            // `apps/crl.c:161-164`.
            OptMatch::Value("CApath", _) => do_ver = true,
            // `case OPT_CAFILE: CAfile = opt_arg(); do_ver = 1; break;` —
            // `apps/crl.c:165-168`.
            OptMatch::Value("CAfile", _) => do_ver = true,
            // `case OPT_CASTORE: CAstore = opt_arg(); do_ver = 1; break;` —
            // `apps/crl.c:169-172`.
            OptMatch::Value("CAstore", _) => do_ver = true,
            // `case OPT_NOCAPATH: noCApath = 1; break;` — `apps/crl.c:173-175`.
            OptMatch::Flag("no-CApath") => {}
            // `case OPT_NOCAFILE: noCAfile = 1; break;` — `apps/crl.c:176-178`.
            OptMatch::Flag("no-CAfile") => {}
            // `case OPT_NOCASTORE: noCAstore = 1; break;` — `apps/crl.c:179-181`.
            OptMatch::Flag("no-CAstore") => {}
            // `case OPT_HASH_OLD: hash_old = ++num; break;` — `apps/crl.c:182-186`.
            OptMatch::Flag("hash_old") => prints.push(Print::HashOld),
            // `case OPT_VERIFY: do_ver = 1; break;` — `apps/crl.c:187-189`.
            OptMatch::Flag("verify") => do_ver = true,
            // `case OPT_DATEOPT: if (!set_dateopt(&dateopt, opt_arg())) goto opthelp;`
            // — `apps/crl.c:190-193`.
            OptMatch::Value("dateopt", _) => {}
            // `case OPT_TEXT: text = 1; break;` — `apps/crl.c:194-196`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_HASH: hash = ++num; break;` — `apps/crl.c:197-199`.
            OptMatch::Flag("hash") => prints.push(Print::Hash),
            // `case OPT_ISSUER: issuer = ++num; break;` — `apps/crl.c:200-202`.
            OptMatch::Flag("issuer") => prints.push(Print::Issuer),
            // `case OPT_LASTUPDATE: lastupdate = ++num; break;` — `apps/crl.c:203-205`.
            OptMatch::Flag("lastupdate") => prints.push(Print::LastUpdate),
            // `case OPT_NEXTUPDATE: nextupdate = ++num; break;` — `apps/crl.c:206-208`.
            OptMatch::Flag("nextupdate") => prints.push(Print::NextUpdate),
            // `case OPT_NOOUT: noout = 1; break;` — `apps/crl.c:209-211`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_FINGERPRINT: fingerprint = ++num; break;` —
            // `apps/crl.c:212-214`.
            OptMatch::Flag("fingerprint") => prints.push(Print::Fingerprint),
            // `case OPT_CRLNUMBER: crlnumber = ++num; break;` — `apps/crl.c:215-217`.
            OptMatch::Flag("crlnumber") => prints.push(Print::CrlNumber),
            // `case OPT_BADSIG: badsig = 1; break;` — `apps/crl.c:218-220`.
            OptMatch::Flag("badsig") => return not_landed("crl -badsig"),
            // `case OPT_NAMEOPT: if (!set_nameopt(opt_arg())) goto opthelp;` —
            // `apps/crl.c:221-224`.
            OptMatch::Value("nameopt", _) => return not_landed("crl -nameopt"),
            // `case OPT_MD: digestname = opt_unknown(); break;` — `apps/crl.c:225-227`.
            OptMatch::Value("", _) => {}
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/crl.c:228-231`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("crl -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/crl.c:235-237`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (do_ver) { ... setup_verify ... X509_CRL_verify ... }` — `apps/crl.c:245-281`.
    if do_ver {
        return not_landed("crl -verify");
    }

    // `x = load_crl(infile, informat, 1, "CRL"); if (x == NULL) goto end;` —
    // `apps/crl.c:241-243`.
    let x = load_crl(infile.as_deref(), informat, "CRL");
    if x.is_null() {
        return 1;
    }

    // `out = bio_open_default(outfile, 'w', outformat);` — `apps/crl.c:387-389`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `x` is live and not freed again.
        unsafe { X509_CRL_free(x) };
        return not_landed("crl -out (unopenable)");
    }
    let mut ret = 1i32;

    // The `num`-ordered print loop — `apps/crl.c:316-385`.
    for p in &prints {
        match p {
            Print::Issuer => {
                // SAFETY: `x` is live.
                let issuer = unsafe { X509_CRL_get_issuer(x) };
                print_name(out, c"issuer=", issuer);
            }
            Print::CrlNumber => {
                // SAFETY: `x` is live; crit/idx are NULL out-slots.
                let crlnum = unsafe {
                    crate::x509::x509_ext::X509_CRL_get_ext_d2i(
                        x,
                        NID_crl_number,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
                .cast::<Asn1String>();
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"crlNumber=".as_ptr()) };
                if !crlnum.is_null() {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"0x".as_ptr()) };
                    // SAFETY: `out`/`crlnum` are live.
                    unsafe { i2a_ASN1_INTEGER(out, crlnum) };
                    // SAFETY: `crlnum` is live and not freed again.
                    unsafe { ASN1_INTEGER_free(crlnum) };
                } else {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"<NONE>".as_ptr()) };
                }
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::Hash => {
                let mut ok = 0i32;
                // SAFETY: `x` is live; libctx/propq NULL.
                let hash_value = unsafe {
                    X509_NAME_hash_ex(
                        X509_CRL_get_issuer(x),
                        core::ptr::null_mut(),
                        core::ptr::null(),
                        &mut ok,
                    )
                };
                if prints.len() > 1 {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"issuer name hash=".as_ptr()) };
                }
                if ok != 0 {
                    let line = format!("{hash_value:08x}\n");
                    // SAFETY: `out` is live; `line` is this frame's bytes.
                    unsafe {
                        crate::runtime::bio::iolib::BIO_write(
                            out,
                            line.as_ptr().cast(),
                            line.len() as c_int,
                        )
                    };
                } else {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"<ERROR>".as_ptr()) };
                    ret = 1;
                    break;
                }
            }
            Print::HashOld => {
                if prints.len() > 1 {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"issuer name old hash=".as_ptr()) };
                }
                // SAFETY: `x` is live.
                let h = unsafe { X509_NAME_hash_old(X509_CRL_get_issuer(x)) };
                let line = format!("{h:08x}\n");
                // SAFETY: `out` is live; `line` is this frame's bytes.
                unsafe {
                    crate::runtime::bio::iolib::BIO_write(
                        out,
                        line.as_ptr().cast(),
                        line.len() as c_int,
                    )
                };
            }
            Print::LastUpdate => {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"lastUpdate=".as_ptr()) };
                // SAFETY: `out`/`x` are live; the dateopt flag is the RFC822 default.
                unsafe {
                    ASN1_TIME_print_ex(
                        out,
                        X509_CRL_get0_lastUpdate(x),
                        ASN1_DTFLGS_RFC822 as core::ffi::c_ulong,
                    )
                };
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::NextUpdate => {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"nextUpdate=".as_ptr()) };
                // SAFETY: `x` is live.
                let next = unsafe { X509_CRL_get0_nextUpdate(x) };
                if !next.is_null() {
                    // SAFETY: `out`/`next` are live.
                    unsafe {
                        ASN1_TIME_print_ex(out, next, ASN1_DTFLGS_RFC822 as core::ffi::c_ulong)
                    };
                } else {
                    // SAFETY: `out` is live; the literal is static.
                    unsafe { BIO_puts(out, c"NONE".as_ptr()) };
                }
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            Print::Fingerprint => {
                let digest = EVP_sha1();
                let mut md = [0u8; 64];
                let mut n: c_uint = 0;
                // SAFETY: `x` is live; `digest` is a static method; `md`/`n` are this
                // frame's out-parameters.
                if unsafe {
                    X509_CRL_digest(x, digest, md.as_mut_ptr().cast::<c_uchar>(), &mut n) == 0
                } {
                    eprintln!("out of memory");
                    // SAFETY: `out`/`x` are live and not freed again.
                    unsafe { crate::runtime::bio::BIO_free_all(out) };
                    // SAFETY: `out`/`x` are live and not freed again.
                    unsafe { X509_CRL_free(x) };
                    return 1;
                }
                // `BIO_printf(bio_out, "%s Fingerprint=", EVP_MD_get0_name(digest));` —
                // `apps/crl.c:379-380`.
                // SAFETY: `digest` is a static method.
                let name = unsafe { crate::evp::digest::EVP_MD_get0_name(digest) };
                // SAFETY: `out` is live; `name` is a static NUL-terminated string.
                unsafe { BIO_puts(out, name) };
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c" Fingerprint=".as_ptr()) };
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
                // SAFETY: `digest` is a static method; the free is a no-op for it.
                unsafe { EVP_MD_free(digest.cast_mut()) };
            }
        }
    }

    // `if (text) X509_CRL_print_ex(out, x, get_nameopt());` — `apps/crl.c:391-392`.
    if text {
        // SAFETY: `out`/`x` are live; the flag word is the default name-print flags.
        unsafe { X509_CRL_print_ex(out, x, GET_NAMEOPT as core::ffi::c_ulong) };
    }

    if noout {
        ret = 0;
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { X509_CRL_free(x) };
        return ret;
    }

    // `if (outformat == FORMAT_ASN1) i = i2d_X509_CRL_bio(out, x); else i =
    // PEM_write_bio_X509_CRL(out, x); if (!i) { "unable to write CRL"; goto end; }` —
    // `apps/crl.c:399-406`.
    let i = if outformat == FORMAT_ASN1 {
        // SAFETY: `out`/`x` are live.
        unsafe { i2d_X509_CRL_bio(out, x) }
    } else {
        // SAFETY: `out`/`x` are live.
        unsafe { PEM_write_bio_X509_CRL(out, x) }
    };
    if i == 0 {
        eprintln!("unable to write CRL");
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        // SAFETY: `out`/`x` are live and not freed again.
        unsafe { X509_CRL_free(x) };
        return ret;
    }
    ret = 0;

    // `end: ... BIO_free_all(out); EVP_MD_free(digest); X509_CRL_free(x); ...` —
    // `apps/crl.c:409-417`.
    // SAFETY: `out`/`x` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    // SAFETY: `out`/`x` are live and not freed again.
    unsafe { X509_CRL_free(x) };
    ret
}
