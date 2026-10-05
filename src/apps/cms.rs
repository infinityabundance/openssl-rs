//! Phase 17.1g — `apps/cms.c`: the `openssl cms` command.
//!
//! The command body (`apps/cms.c:371-1518`): parse the generated `CMS_OPTIONS`
//! table (with `opt_set_unknown_name("cipher")`), select one operation
//! (`-sign`/`-verify`/`-encrypt`/`-decrypt`/…), load the signer/recipient
//! certificate(s) and key, run the CMS operation (`CMS_sign_ex`+`CMS_add1_signer`+
//! `CMS_final`, `CMS_verify`) and write the S/MIME, PEM or DER result
//! (`SMIME_write_CMS`/`PEM_write_bio_CMS_stream`/`i2d_CMS_bio_stream`).
//!
//! ## What the court drives
//!
//! `cms -sign -noattr -nodetach -outform PEM|DER -in <smime.txt> -signer <signer.pem>
//! -inkey <rsa-key.pem>`, `cms -verify -inform PEM -noverify -in <cms-signed.pem>`
//! and the operation refusals. `-noattr` removes the `signingTime` attribute; the
//! signed bytes are otherwise a pure function of the fixed fixtures (PKCS#1 v1.5).
//!
//! ## Recorded divergences (module header)
//!
//! * **The default `-sign` (with the `signingTime` attribute) is recorded.** Without
//!   `-noattr`/`-no_signing_time` the signed attributes carry the wall clock, so the
//!   output differs across a second boundary; the driven sign arms pass `-noattr`.
//! * **Every operation other than `-sign`/`-verify` is not driven.** `-encrypt`/
//!   `-EncryptedData_encrypt` draw a random content key, `-decrypt`/`-resign`/
//!   `-sign_receipt`/`-verify_receipt`/`-digest`/`-digest_create`/`-digest_verify`/
//!   `-compress`/`-uncompress`/`-data_create`/`-data_out`/`-cmsout` and the `-keyopt`/
//!   `-secretkey`/`-pwri_password`/`-recip_kdf`/`-wrap` key-management arms reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`-certfile` (`load_certs`) is not landed.** The signer's own certificate is
//!   included by `CMS_sign_ex`; no extra chain is added.
//! * **`-nameopt`/`-print` (`CMS_ContentInfo_print_ctx`) and the S/MIME output format
//!   are not driven** (the MIME boundary is random).
//! * **`-passin`/`-config`/`-engine`/`-receipt_request_*`/`-certsout`/`-rctform`/
//!   `-content` and the `-V` verify-parameter arms are not driven.**
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::apps::keyio::{bio_open_default, load_cert, load_key, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CMS_OPTIONS;
use crate::cms::cms_asn1::CmsContentInfo;
use crate::cms::cms_io::{
    d2i_CMS_bio, i2d_CMS_bio_stream, PEM_read_bio_CMS, PEM_write_bio_CMS_stream, SMIME_read_CMS_ex,
    SMIME_write_CMS,
};
use crate::cms::cms_lib::{CMS_ContentInfo_free, CMS_ContentInfo_new_ex};
use crate::cms::cms_sd::CMS_add1_signer;
use crate::cms::cms_smime::{CMS_final, CMS_sign_ex, CMS_verify};
use crate::runtime::bio::{BIO_free, BIO_free_all, Bio};
use crate::x509::x509_lu::{X509Store, X509_STORE_free, X509_STORE_new};
use crate::x509::x_x509::X509_free;

/// `FORMAT_SMIME` — `apps/include/fmt.h:36`.
const FORMAT_SMIME: c_int = 7 | 0x8000;

/// The `CMS_*` flag words — `include/openssl/cms.h`.
const CMS_TEXT: c_uint = 0x1;
const CMS_NOCERTS: c_uint = 0x2;
const CMS_NO_CONTENT_VERIFY: c_uint = 0x4;
const CMS_NO_ATTR_VERIFY: c_uint = 0x8;
const CMS_NOINTERN: c_uint = 0x10;
const CMS_NOVERIFY: c_uint = 0x20;
const CMS_DETACHED: c_uint = 0x40;
const CMS_BINARY: c_uint = 0x80;
const CMS_NOATTR: c_uint = 0x100;
const CMS_NOSMIMECAP: c_uint = 0x200;
const CMS_CRLFEOL: c_uint = 0x800;
const CMS_STREAM: c_uint = 0x1000;
const CMS_PARTIAL: c_uint = 0x4000;
const CMS_REUSE_DIGEST: c_uint = 0x8000;
const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
const CMS_ASCIICRLF: c_uint = 0x80000;
const CMS_CADES: c_uint = 0x100000;
const CMS_NO_SIGNING_TIME: c_uint = 0x200000;

/// The `SMIME_*` operation selectors — `apps/cms.c:32-50` (the `cms` spellings).
const SMIME_OP: c_int = 0x100;
const SMIME_IP: c_int = 0x200;
const SMIME_SIGNERS: c_int = 0x400;
const SMIME_ENCRYPT: c_int = 1 | SMIME_OP;
const SMIME_DECRYPT: c_int = 2 | SMIME_IP;
const SMIME_SIGN: c_int = 3 | SMIME_OP | SMIME_SIGNERS;
const SMIME_VERIFY: c_int = 4 | SMIME_IP;
const SMIME_RESIGN: c_int = 5 | SMIME_IP | SMIME_OP | SMIME_SIGNERS;
const SMIME_SIGN_RECEIPT: c_int = 6 | SMIME_IP | SMIME_OP;
const SMIME_VERIFY_RECEIPT: c_int = 7 | SMIME_IP;
const SMIME_DIGEST_CREATE: c_int = 8 | SMIME_OP;
const SMIME_DIGEST_VERIFY: c_int = 9 | SMIME_IP;
const SMIME_COMPRESS: c_int = 10 | SMIME_OP;
const SMIME_UNCOMPRESS: c_int = 11 | SMIME_IP;
const SMIME_ENCRYPTED_ENCRYPT: c_int = 12 | SMIME_OP;
const SMIME_ENCRYPTED_DECRYPT: c_int = 13 | SMIME_IP;
const SMIME_DATA_CREATE: c_int = 14 | SMIME_OP;
const SMIME_DATA_OUT: c_int = 15 | SMIME_IP;
const SMIME_CMSOUT: c_int = 16 | SMIME_IP | SMIME_OP;

/// `opt_format(s, OPT_FMT_PDS, result)` — `apps/lib/opt.c:277-365`.
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

/// The operation-refusal helper: `BIO_puts(bio_err, msg); goto opthelp;` — for
/// `cms` the `ret` is 1 on this path, so the exit is 1 (`apps/cms.c:404`).
fn refusal(msg: &str, prog: &str) -> i32 {
    eprintln!("{msg}");
    eprintln!("{prog}: Use -help for summary.");
    1
}

/// `CMS_ContentInfo *load_content_info(informat, in, flags, indata, name)` —
/// `apps/cms.c:324-356`.
fn load_content_info(
    informat: c_int,
    inbio: *mut Bio,
    flags: c_int,
    indata: *mut *mut Bio,
    name: &str,
) -> *mut CmsContentInfo {
    let mut cms: *mut CmsContentInfo =
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { CMS_ContentInfo_new_ex(core::ptr::null_mut(), core::ptr::null()) };
    if cms.is_null() {
        eprintln!("Error allocating CMS_contentinfo");
        return core::ptr::null_mut();
    }
    let ci = if informat == FORMAT_SMIME {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { SMIME_read_CMS_ex(inbio, flags, indata, &mut cms) }
    } else if informat == FORMAT_PEM {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { PEM_read_bio_CMS(inbio, &mut cms, None, core::ptr::null_mut()) }
    } else if informat == FORMAT_ASN1 {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { d2i_CMS_bio(inbio, &mut cms) }
    } else {
        eprintln!("Bad input format for {name}");
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { CMS_ContentInfo_free(cms) };
        return core::ptr::null_mut();
    };
    if ci.is_null() {
        eprintln!("Error reading {name} Content Info");
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { CMS_ContentInfo_free(cms) };
        return core::ptr::null_mut();
    }
    cms
}

/// `int cms_main(int argc, char **argv)` — `apps/cms.c:371-1518`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, cms_options);` —
    // `apps/cms.c:419-420`.
    let mut opts = Opts::init(argv, CMS_OPTIONS);
    opts.enable_unknown("cipher");
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut signerfile: Option<String> = None;
    let mut keyfile: Option<String> = None;
    let mut recipfile: Option<String> = None;
    let mut informat = FORMAT_SMIME;
    let mut outformat = FORMAT_SMIME;
    let mut operation: c_int = 0;
    let mut flags: c_uint = CMS_DETACHED;
    let mut mime_eol: &str = "\n";
    let mut indef = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/cms.c:421`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(cms_options); ret = 0; goto end;` —
            // `apps/cms.c:428-431`.
            OptMatch::Help => return not_landed("cms -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: ...` — `apps/cms.c:423-427`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM`/`OPT_OUTFORM` — `apps/cms.c:432-439`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pds(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            OptMatch::Value("outform", v) => {
                if !opt_format_pds(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg();` — `apps/cms.c:440-442`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // The operation selectors — `apps/cms.c:444-499`.
            OptMatch::Flag("encrypt") => operation = SMIME_ENCRYPT,
            OptMatch::Flag("decrypt") => operation = SMIME_DECRYPT,
            OptMatch::Flag("sign") => operation = SMIME_SIGN,
            OptMatch::Flag("verify") => operation = SMIME_VERIFY,
            OptMatch::Flag("resign") => operation = SMIME_RESIGN,
            OptMatch::Value("verify_receipt", _) => operation = SMIME_VERIFY_RECEIPT,
            OptMatch::Flag("sign_receipt") => operation = SMIME_SIGN_RECEIPT,
            OptMatch::Flag("digest_create") => operation = SMIME_DIGEST_CREATE,
            OptMatch::Flag("digest_verify") => operation = SMIME_DIGEST_VERIFY,
            OptMatch::Flag("compress") => operation = SMIME_COMPRESS,
            OptMatch::Flag("uncompress") => operation = SMIME_UNCOMPRESS,
            OptMatch::Flag("EncryptedData_encrypt") => operation = SMIME_ENCRYPTED_ENCRYPT,
            OptMatch::Flag("EncryptedData_decrypt") => operation = SMIME_ENCRYPTED_DECRYPT,
            OptMatch::Flag("data_create") => operation = SMIME_DATA_CREATE,
            OptMatch::Flag("data_out") => operation = SMIME_DATA_OUT,
            OptMatch::Flag("cmsout") => operation = SMIME_CMSOUT,
            // The flag word arms — `apps/cms.c:503-556`.
            OptMatch::Flag("text") => flags |= CMS_TEXT,
            OptMatch::Flag("nointern") => flags |= CMS_NOINTERN,
            OptMatch::Flag("noverify") => flags |= CMS_NOVERIFY,
            OptMatch::Flag("nocerts") => flags |= CMS_NOCERTS,
            OptMatch::Flag("noattr") => flags |= CMS_NOATTR,
            OptMatch::Flag("nodetach") => flags &= !CMS_DETACHED,
            OptMatch::Flag("nosmimecap") => flags |= CMS_NOSMIMECAP,
            OptMatch::Flag("no_signing_time") => flags |= CMS_NO_SIGNING_TIME,
            OptMatch::Flag("binary") => flags |= CMS_BINARY,
            OptMatch::Flag("cades") => flags |= CMS_CADES,
            OptMatch::Flag("keyid") => flags |= 0x10000,
            OptMatch::Flag("nosigs") => flags |= CMS_NO_CONTENT_VERIFY | CMS_NO_ATTR_VERIFY,
            OptMatch::Flag("no_content_verify") => flags |= CMS_NO_CONTENT_VERIFY,
            OptMatch::Flag("no_attr_verify") => flags |= CMS_NO_ATTR_VERIFY,
            OptMatch::Flag("indef") => indef = true,
            OptMatch::Flag("noindef") => indef = false,
            OptMatch::Flag("crlfeol") => {
                flags |= CMS_CRLFEOL;
                mime_eol = "\r\n";
            }
            OptMatch::Flag("asciicrlf") => flags |= CMS_ASCIICRLF,
            OptMatch::Flag("debug_decrypt") => flags |= CMS_DEBUG_DECRYPT,
            OptMatch::Flag("noout") => {}
            OptMatch::Flag("print") => return not_landed("cms -print"),
            // `-md`/unknown-cipher — `apps/cms.c:682-684`, `:785-787`.
            OptMatch::Value("md", _) => return not_landed("cms -md"),
            OptMatch::Value("", _) => return not_landed("cms -cipher"),
            // The key/recipient/certificate loaders — `apps/cms.c:575-745`.
            OptMatch::Value("signer", v) => signerfile = Some(v),
            OptMatch::Value("inkey", v) => keyfile = Some(v),
            OptMatch::Value("recip", v) => recipfile = Some(v),
            OptMatch::Value("keyform", _) => {}
            OptMatch::Value("certfile", _) => return not_landed("cms -certfile"),
            OptMatch::Value("originator", _) => return not_landed("cms -originator"),
            // `-CA*`/`-no-CA*` — `apps/cms.c:578-595`.
            OptMatch::Value("CAfile", _)
            | OptMatch::Value("CApath", _)
            | OptMatch::Value("CAstore", _) => {}
            OptMatch::Flag("no-CAfile")
            | OptMatch::Flag("no-CApath")
            | OptMatch::Flag("no-CAstore") => {}
            // `case OPT_IN: infile = opt_arg();` — `apps/cms.c:596-598`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_CONTENT: contfile = opt_arg();` — `apps/cms.c:599-601`.
            OptMatch::Value("content", _) => return not_landed("cms -content"),
            // `case OPT_TO`/`OPT_FROM`/`OPT_SUBJECT` — `apps/cms.c:670-678`.
            OptMatch::Value("to", _)
            | OptMatch::Value("from", _)
            | OptMatch::Value("subject", _) => {}
            // `case OPT_PASSIN: passinarg = opt_arg();` — `apps/cms.c:667-669`.
            OptMatch::Value("passin", _) => return not_landed("cms -passin"),
            // `case OPT_ENGINE` — `apps/cms.c:664-666`.
            OptMatch::Value("engine", _) => return not_landed("cms -engine"),
            // `case OPT_CONFIG` — `apps/cms.c:837-841`.
            OptMatch::Value("config", _) => return not_landed("cms -config"),
            // `case OPT_NAMEOPT` — `apps/cms.c:617-622`.
            OptMatch::Value("nameopt", _) => return not_landed("cms -nameopt"),
            // The key-management arms — `apps/cms.c:623-851`.
            OptMatch::Value("secretkey", _)
            | OptMatch::Value("secretkeyid", _)
            | OptMatch::Value("pwri_password", _)
            | OptMatch::Value("econtent_type", _)
            | OptMatch::Value("certsout", _)
            | OptMatch::Value("rctform", _)
            | OptMatch::Value("recip_kdf", _)
            | OptMatch::Value("recip_ukm", _)
            | OptMatch::Value("kekcipher", _)
            | OptMatch::Value("wrap", _)
            | OptMatch::Value("digest", _)
            | OptMatch::Value("keyopt", _)
            | OptMatch::Flag("aes128-wrap")
            | OptMatch::Flag("aes192-wrap")
            | OptMatch::Flag("aes256-wrap")
            | OptMatch::Flag("des3-wrap")
            | OptMatch::Flag("rr_print")
            | OptMatch::Flag("receipt_request_all")
            | OptMatch::Flag("receipt_request_first")
            | OptMatch::Value("receipt_request_from", _)
            | OptMatch::Value("receipt_request_to", _)
            | OptMatch::Flag("verify_retcode") => return not_landed("cms -keyopt/secretkey"),
            // `case OPT_R_CASES` — `apps/cms.c:829-832`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("cms -rand")
            }
            // `case OPT_PROV_CASES` — `apps/cms.c:833-836`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("cms -provider"),
            // `case OPT_V_CASES` — `apps/cms.c:824-828`.
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
            | OptMatch::Flag("policy_print") => return not_landed("cms -V option"),
            // `case OPT_PRECERT`-like and the remaining option names.
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argv = opt_rest();` — `apps/cms.c:870`.
    let rest: Vec<String> = opts.rest().to_vec();
    let _ = indef;

    // The operation-refusal checks — `apps/cms.c:872-941`.
    if (flags & CMS_CADES) != 0 && (flags & CMS_NOATTR) != 0 {
        return refusal(
            "Incompatible options: CAdES requires signed attributes",
            opts.prog(),
        );
    }
    if operation & SMIME_SIGNERS != 0 {
        if keyfile.is_some() && signerfile.is_none() {
            return refusal("Illegal -inkey without -signer", opts.prog());
        }
        if signerfile.is_none() {
            return refusal("No signer certificate specified", opts.prog());
        }
    } else if operation == SMIME_DECRYPT {
        if recipfile.is_none() && keyfile.is_none() {
            return refusal("No recipient certificate or key specified", opts.prog());
        }
    } else if operation == SMIME_ENCRYPT {
        if rest.is_empty() {
            return refusal("No recipient(s) certificate(s) specified", opts.prog());
        }
    } else if operation == 0 {
        return refusal(
            "No operation option (-encrypt|-decrypt|-sign|-verify|...) specified.",
            opts.prog(),
        );
    }

    // `if ((operation & SMIME_SIGNERS) == 0) { ...; flags &= ~CMS_DETACHED; }` —
    // `apps/cms.c:950-956`.
    if operation & SMIME_SIGNERS == 0 {
        flags &= !CMS_DETACHED;
    }
    if operation != SMIME_ENCRYPT && !rest.is_empty() {
        eprintln!(
            "Warning: recipient certificate file parameters ignored for operation other than -encrypt"
        );
    }

    // `if (operation == SMIME_ENCRYPT) { ... }` — `apps/cms.c:978-995`; each
    // recipient beyond the fixed fixture would be a random envelope, not driven.

    // `in = bio_open_default(infile, 'r', ...);` — `apps/cms.c:1055-1059`.
    let inbio = bio_open_default(infile.as_deref(), false);
    if inbio.is_null() {
        return not_landed("cms -in (unopenable)");
    }

    let mut cms: *mut CmsContentInfo = core::ptr::null_mut();
    let mut indata: *mut Bio = core::ptr::null_mut();
    if operation & SMIME_IP != 0 {
        // `cms = load_content_info(informat, in, flags, &indata, "SMIME");` —
        // `apps/cms.c:1061-1064`.
        cms = load_content_info(informat, inbio, flags as c_int, &mut indata, "SMIME");
        if cms.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            return 1;
        }
    }

    // `out = bio_open_default(outfile, 'w', ...);` — `apps/cms.c:1098-1101`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free(inbio) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { CMS_ContentInfo_free(cms) };
        return not_landed("cms -out (unopenable)");
    }

    // `if ((operation == SMIME_VERIFY) || ...) { store = setup_verify(...); ... }` —
    // `apps/cms.c:1103-1111`. With `-noverify` the empty store is enough (see header).
    let mut store: *mut X509Store = core::ptr::null_mut();
    if operation == SMIME_VERIFY || operation == SMIME_VERIFY_RECEIPT {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        store = unsafe { X509_STORE_new() };
        if store.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { CMS_ContentInfo_free(cms) };
            return 1;
        }
    }

    // The `-sign` arm — `apps/cms.c:1248-1336`.
    if operation & SMIME_SIGNERS != 0 {
        if operation == SMIME_SIGN {
            if (flags & CMS_DETACHED) != 0 && outformat == FORMAT_SMIME {
                flags |= CMS_STREAM;
            }
            flags |= CMS_PARTIAL;
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            cms = unsafe {
                CMS_sign_ex(
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    inbio,
                    flags,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                )
            };
            if cms.is_null() {
                eprintln!("CMS SignedData Creation Error");
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
            flags |= CMS_REUSE_DIGEST;
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
            unsafe { CMS_ContentInfo_free(cms) };
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
            unsafe { CMS_ContentInfo_free(cms) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        if unsafe { CMS_add1_signer(cms, signer, key, core::ptr::null(), flags) }.is_null() {
            eprintln!("Error adding SignerInfo with key from {kf}");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { X509_free(signer) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { CMS_ContentInfo_free(cms) };
            return 1;
        }
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_free(signer) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
        if operation == SMIME_SIGN && flags & CMS_STREAM == 0 {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            if unsafe { CMS_final(cms, inbio, core::ptr::null_mut(), flags) } == 0 {
                eprintln!("Error finalizing CMS structure");
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free_all(out) };
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { BIO_free(inbio) };
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { CMS_ContentInfo_free(cms) };
                return 1;
            }
        }
    } else if operation != SMIME_VERIFY {
        // Every other operation is recorded rather than fabricated.
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free_all(out) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { BIO_free(inbio) };
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { CMS_ContentInfo_free(cms) };
        if !store.is_null() {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { X509_STORE_free(store) };
        }
        return not_landed("cms operation");
    }

    if cms.is_null() {
        eprintln!("Error creating CMS structure");
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

    // The `-verify` arm — `apps/cms.c:1392-1413`.
    if operation == SMIME_VERIFY {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        let ok = unsafe { CMS_verify(cms, core::ptr::null_mut(), store, indata, out, flags) };
        if ok > 0 {
            eprintln!("CMS Verification successful");
        } else {
            eprintln!("CMS Verification failure");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { CMS_ContentInfo_free(cms) };
            if !store.is_null() {
                // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
                unsafe { X509_STORE_free(store) };
            }
            return 1;
        }
    } else {
        // The sign output — `apps/cms.c:1424-1464`.
        let ret = if outformat == FORMAT_SMIME {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { SMIME_write_CMS(out, cms, inbio, flags as c_int) }
        } else if outformat == FORMAT_PEM {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { PEM_write_bio_CMS_stream(out, cms, inbio, flags as c_int) }
        } else if outformat == FORMAT_ASN1 {
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { i2d_CMS_bio_stream(out, cms, inbio, flags as c_int) }
        } else {
            eprintln!("Bad output format for CMS file");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { CMS_ContentInfo_free(cms) };
            return 1;
        };
        if ret <= 0 {
            eprintln!("Error writing CMS output");
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free_all(out) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { BIO_free(inbio) };
            // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
            unsafe { CMS_ContentInfo_free(cms) };
            return 6;
        }
    }

    // `end: ... CMS_ContentInfo_free(cms); RV... ` — `apps/cms.c:1467-1517`.
    if !store.is_null() {
        // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
        unsafe { X509_STORE_free(store) };
    }
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { CMS_ContentInfo_free(cms) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { BIO_free(inbio) };
    // SAFETY: FFI call; the arguments are this frame's live pointers, and the callee's own `# Safety` section states the contract.
    unsafe { BIO_free_all(out) };
    let _ = (recipfile, mime_eol);
    0
}
