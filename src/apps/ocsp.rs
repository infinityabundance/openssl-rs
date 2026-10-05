//! Phase 17.1f — `apps/ocsp.c`: the `openssl ocsp` command.
//!
//! The command's option parse (`apps/ocsp.c:304-578`), its no-work refusal
//! (`apps/ocsp.c:595-598`) and the request-building half of the body
//! (`apps/ocsp.c:600-764`) are transcribed: `-issuer`/`-cert` build an
//! `OCSP_REQUEST` through `OCSP_cert_to_id`/`OCSP_request_add0_id`, `-req_text`
//! prints it through `OCSP_REQUEST_print`, and `-reqout`/`-out` serialize it.
//! The responder and verification half — a live server (`-port`/`-url`), a
//! response to read (`-respin`) or an index file (`-index`/`-CA`) — is not
//! landed.
//!
//! ## What the court drives
//!
//! `ocsp` (the no-work refusal), `ocsp -bogus` (the parser's refusal) and
//! `ocsp -issuer <ca.pem> -cert <leaf.pem> -no_nonce -reqout /dev/stdout`, which
//! emits the request's DER to stdout. The fixed CA/leaf and `-no_nonce` make the
//! request a pure function of the fixtures; a request built without `-no_nonce`
//! draws a random nonce and is recorded, not diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **The responder/verification arms are not landed.** `-index`/`-CA`
//!   (`load_index`, `apps/lib`), `-port`/`-url`/`-host` (a live server or
//!   `OSSL_HTTP`), `-respin`/`-rsigner`/`-rkey`/`-CAfile` verification, `-signer`/
//!   `-signkey` request signing and `-serial` (`s2i_ASN1_INTEGER`) reach
//!   [`not_landed`]. They need a responder or a network, so they cannot be
//!   diffed deterministically.
//! * **`-serial` is not landed** (`OCSP_cert_id_new` + `s2i_ASN1_INTEGER`).
//! * **A request without `-no_nonce` draws a random nonce** through
//!   `OCSP_request_add1_nonce(req, NULL, -1)`; it is recorded rather than diffed.
//! * **`d2i_OCSP_REQUEST_bio`/`i2d_OCSP_REQUEST_bio` are reconstructed** from the
//!   landed `ASN1_item_i2d_bio`/`ASN1_item_d2i_bio` over `OCSP_REQUEST_it()`, the
//!   same `_bio` wrapper the authority's generated `IMPLEMENT_ASN1_*` macros use.
//! * **`app_passwd`, `setup_verify` and `opt_verify` are reduced or absent**; no
//!   `-passin`/verification arm is driven.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use std::ffi::CString;

use crate::apps::keyio::{bio_open_default, load_cert};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::OCSP_OPTIONS;
use crate::asn1::a_i2d_fp::ASN1_item_i2d_bio;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha1;
use crate::ocsp::ocsp_asn::{OCSP_REQUEST_free, OCSP_REQUEST_it, OCSP_REQUEST_new, OcspRequest};
use crate::ocsp::ocsp_cl::OCSP_request_add0_id;
use crate::ocsp::ocsp_ext::OCSP_request_add1_nonce;
use crate::ocsp::ocsp_lib::OCSP_cert_to_id;
use crate::ocsp::ocsp_prn::OCSP_REQUEST_print;
use crate::runtime::bio::{BIO_free, BIO_free_all};
use crate::x509::x_x509::X509;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;

/// `int opt_md(const char *name, EVP_MD **mdp)` — `apps/lib/opt.c:491-501`.
fn opt_md(prog: &str, name: &str) -> Option<*mut EvpMd> {
    let cs = CString::new(name).ok()?;
    // SAFETY: `cs` is NUL-terminated; the context/query are the defaults.
    let fetched = unsafe { EVP_MD_fetch(core::ptr::null_mut(), cs.as_ptr(), core::ptr::null()) };
    if !fetched.is_null() {
        return Some(fetched);
    }
    // SAFETY: `cs` is NUL-terminated.
    let legacy = unsafe { EVP_get_digestbyname(cs.as_ptr()) };
    if legacy.is_null() {
        eprintln!("{prog}: Unknown option or message digest: {name}");
        None
    } else {
        Some(legacy.cast_mut())
    }
}

/// `static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, const EVP_MD
/// *cert_id_md, X509 *issuer, STACK_OF(OCSP_CERTID) *ids)` — `apps/ocsp.c`.
fn add_ocsp_cert(
    req: &mut *mut OcspRequest,
    cert: *mut X509,
    cert_id_md: *const EvpMd,
    issuer: *mut X509,
) -> bool {
    if issuer.is_null() {
        eprintln!("No issuer certificate specified");
        return false;
    }
    if (*req).is_null() {
        *req = OCSP_REQUEST_new();
    }
    if (*req).is_null() {
        eprintln!("Error Creating OCSP request");
        return false;
    }
    // SAFETY: `cert`/`issuer`/`cert_id_md` are live (or NULL for the method).
    let id = unsafe { OCSP_cert_to_id(cert_id_md, cert, issuer) };
    // SAFETY: `*req` is live; `id` is live or NULL.
    if id.is_null() || unsafe { OCSP_request_add0_id(*req, id) }.is_null() {
        eprintln!("Error Creating OCSP request");
        return false;
    }
    true
}

/// `int ocsp_main(int argc, char **argv)` — `apps/ocsp.c:254-924`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, OCSP_OPTIONS);
    // `opt_set_unknown_name("digest");` — `apps/ocsp.c:304`.
    opts.enable_unknown("digest");

    let mut req: *mut OcspRequest = core::ptr::null_mut();
    let mut issuer: *mut X509 = core::ptr::null_mut();
    let mut cert_id_md: *mut EvpMd = core::ptr::null_mut();
    let mut outfile: Option<String> = None;
    let mut reqout: Option<String> = None;
    let mut add_nonce: c_int = 1;
    let mut req_text = false;
    let mut trailing_md = false;

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: ret = 0; opt_help(...); goto end;` —
            // `apps/ocsp.c:313-316`.
            OptMatch::Help => return not_landed("ocsp -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/ocsp.c:308-312`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            OptMatch::Flag("ignore_err") => {}
            OptMatch::Value("CAfile", _) | OptMatch::Value("CApath", _) => {}
            OptMatch::Value("CAstore", _) => {}
            OptMatch::Flag("no-CAfile")
            | OptMatch::Flag("no-CApath")
            | OptMatch::Flag("no-CAstore") => {}
            // `case OPT_OUTFILE: outfile = opt_arg();` — `apps/ocsp.c:317-319`.
            OptMatch::Value("out", v) => outfile = Some(v),
            OptMatch::Value("timeout", _) => {}
            // `case OPT_URL: ... OSSL_HTTP_parse_url ...` — `apps/ocsp.c:325-339`.
            OptMatch::Value("url", _) => return not_landed("ocsp -url"),
            OptMatch::Value("host", _) => return not_landed("ocsp -host"),
            OptMatch::Value("port", _) => return not_landed("ocsp -port"),
            OptMatch::Value("path", _) => {}
            OptMatch::Value("proxy", _) | OptMatch::Value("no_proxy", _) => {
                return not_landed("ocsp -proxy")
            }
            OptMatch::Flag("noverify") => {}
            // `case OPT_NONCE: add_nonce = 2;` — `apps/ocsp.c:363-365`.
            OptMatch::Flag("nonce") => add_nonce = 2,
            // `case OPT_NO_NONCE: add_nonce = 0;` — `apps/ocsp.c:366-368`.
            OptMatch::Flag("no_nonce") => add_nonce = 0,
            OptMatch::Flag("resp_no_certs")
            | OptMatch::Flag("resp_key_id")
            | OptMatch::Flag("no_certs")
            | OptMatch::Flag("no_signature_verify")
            | OptMatch::Flag("no_cert_verify")
            | OptMatch::Flag("no_chain")
            | OptMatch::Flag("no_cert_checks")
            | OptMatch::Flag("no_explicit")
            | OptMatch::Flag("trust_other")
            | OptMatch::Flag("no_intern") => {}
            OptMatch::Flag("badsig") => return not_landed("ocsp -badsig"),
            // `case OPT_TEXT: req_text = resp_text = 1;` — `apps/ocsp.c:402-404`.
            OptMatch::Flag("text") => req_text = true,
            // `case OPT_REQ_TEXT: req_text = 1;` — `apps/ocsp.c:405-407`.
            OptMatch::Flag("req_text") => req_text = true,
            OptMatch::Flag("resp_text") => {}
            // `case OPT_REQIN: reqin = opt_arg();` — `apps/ocsp.c:411-413`.
            OptMatch::Value("reqin", _) => return not_landed("ocsp -reqin"),
            // `case OPT_RESPIN: respin = opt_arg();` — `apps/ocsp.c:414-416`.
            OptMatch::Value("respin", _) => return not_landed("ocsp -respin"),
            // `case OPT_SIGNER: signfile = opt_arg();` — `apps/ocsp.c:417-419`.
            OptMatch::Value("signer", _) => return not_landed("ocsp -signer"),
            OptMatch::Value("VAfile", _) | OptMatch::Value("verify_other", _) => {}
            OptMatch::Value("sign_other", _) => {}
            // `case OPT_ISSUER: issuer = load_cert(...); sk_X509_push(issuers, issuer);` —
            // `apps/ocsp.c:468-478`.
            OptMatch::Value("issuer", v) => {
                let x = load_cert(Some(v.as_str()), FORMAT_UNDEF, "issuer certificate");
                if x.is_null() {
                    return 1;
                }
                issuer = x;
            }
            // `case OPT_CERT: reset_unknown(); X509_free(cert); cert = load_cert(...);
            // ... add_ocsp_cert(...); ...` — `apps/ocsp.c:479-492`.
            OptMatch::Value("cert", v) => {
                opts.reset_unknown();
                if cert_id_md.is_null() {
                    cert_id_md = EVP_sha1() as *mut EvpMd;
                }
                let c = load_cert(Some(v.as_str()), FORMAT_UNDEF, "certificate");
                if c.is_null() {
                    return 1;
                }
                if !add_ocsp_cert(&mut req, c, cert_id_md, issuer) {
                    return 1;
                }
                trailing_md = false;
            }
            // `case OPT_SERIAL: reset_unknown(); ... add_ocsp_serial(...);` —
            // `apps/ocsp.c:493-502`.
            OptMatch::Value("serial", _) => return not_landed("ocsp -serial"),
            OptMatch::Value("index", _) => return not_landed("ocsp -index"),
            OptMatch::Value("CA", _) => return not_landed("ocsp -CA"),
            OptMatch::Value("nmin", _)
            | OptMatch::Value("request", _)
            | OptMatch::Value("ndays", _) => {}
            OptMatch::Value("rsigner", _)
            | OptMatch::Value("rkey", _)
            | OptMatch::Value("rother", _) => return not_landed("ocsp responder"),
            OptMatch::Value("passin", _) => return not_landed("ocsp -passin"),
            OptMatch::Value("rmd", _) => return not_landed("ocsp -rmd"),
            OptMatch::Value("rsigopt", _) => return not_landed("ocsp -rsigopt"),
            OptMatch::Value("header", _) => return not_landed("ocsp -header"),
            OptMatch::Value("rcid", _) => return not_landed("ocsp -rcid"),
            // `case OPT_MD: ... opt_md(opt_unknown(), &cert_id_md); trailing_md = 1;` —
            // `apps/ocsp.c:557-567`.
            OptMatch::Value("", v) => {
                if trailing_md {
                    eprintln!("{}: Digest must be before -cert or -serial", opts.prog());
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                match opt_md(opts.prog(), &v) {
                    Some(m) => {
                        // SAFETY: `cert_id_md` is a live or NULL slot; `EVP_MD_free`
                        // accepts NULL.
                        unsafe { EVP_MD_free(cert_id_md) };
                        cert_id_md = m;
                    }
                    None => {
                        eprintln!("{}: Use -help for summary.", opts.prog());
                        return 1;
                    }
                }
                trailing_md = true;
            }
            // `case OPT_MULTI: ...` — `apps/ocsp.c:568-572`.
            OptMatch::Value("multi", _) => {}
            OptMatch::Value("validity_period", _) | OptMatch::Value("status_age", _) => {}
            OptMatch::Value("signkey", _) => return not_landed("ocsp -signkey"),
            // `case OPT_REQOUT: reqout = opt_arg();` — `apps/ocsp.c:462-464`.
            OptMatch::Value("reqout", v) => reqout = Some(v),
            OptMatch::Value("respout", _) => return not_landed("ocsp -respout"),
            OptMatch::Value("policy", _)
            | OptMatch::Value("purpose", _)
            | OptMatch::Value("verify_name", _) => {}
            OptMatch::Value("verify_depth", _) | OptMatch::Value("auth_level", _) => {}
            OptMatch::Value("attime", _) => {}
            OptMatch::Value("verify_hostname", _)
            | OptMatch::Value("verify_email", _)
            | OptMatch::Value("verify_ip", _) => {}
            OptMatch::Flag("ignore_critical")
            | OptMatch::Flag("issuer_checks")
            | OptMatch::Flag("crl_check")
            | OptMatch::Flag("crl_check_all")
            | OptMatch::Flag("policy_check")
            | OptMatch::Flag("explicit_policy")
            | OptMatch::Flag("inhibit_any")
            | OptMatch::Flag("inhibit_map")
            | OptMatch::Flag("x509_strict")
            | OptMatch::Flag("extended_crl")
            | OptMatch::Flag("use_deltas")
            | OptMatch::Flag("policy_print")
            | OptMatch::Flag("check_ss_sig")
            | OptMatch::Flag("trusted_first")
            | OptMatch::Flag("suiteB_128_only")
            | OptMatch::Flag("suiteB_128")
            | OptMatch::Flag("suiteB_192")
            | OptMatch::Flag("partial_chain")
            | OptMatch::Flag("no_alt_chains")
            | OptMatch::Flag("no_check_time")
            | OptMatch::Flag("allow_proxy_certs") => {}
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("ocsp -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/ocsp.c:580-582`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (trailing_md) { ... goto opthelp; }` — `apps/ocsp.c:584-588`.
    if trailing_md {
        eprintln!("{}: Digest must be before -cert or -serial", opts.prog());
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (req == NULL && reqin == NULL && respin == NULL && !(port && ridx)) goto opthelp;`
    // — `apps/ocsp.c:595-598`. The responder arms are not landed, so their
    // operands are always NULL here.
    if req.is_null() {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (req != NULL && add_nonce) { OCSP_request_add1_nonce(req, NULL, -1); }` —
    // `apps/ocsp.c:721-724`. A non-`-no_nonce` request is random and recorded.
    if add_nonce != 0 {
        // SAFETY: `req` is live; the nonce is the RAND-driven default length.
        unsafe { OCSP_request_add1_nonce(req, core::ptr::null_mut(), -1) };
    }

    // `out = bio_open_default(outfile, 'w', FORMAT_TEXT);` — `apps/ocsp.c:751-753`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `req` is live and not freed again.
        unsafe { OCSP_REQUEST_free(req) };
        return 1;
    }
    // `if (req_text && req != NULL) OCSP_REQUEST_print(out, req, 0);` —
    // `apps/ocsp.c:755-756`.
    if req_text {
        // SAFETY: `out`/`req` are live.
        unsafe { OCSP_REQUEST_print(out, req, 0) };
    }
    // `if (reqout != NULL) { derbio = bio_open_default(reqout, 'w', FORMAT_ASN1);
    // i2d_OCSP_REQUEST_bio(derbio, req); BIO_free(derbio); }` — `apps/ocsp.c:758-764`.
    if let Some(rq) = &reqout {
        let derbio = bio_open_default(Some(rq.as_str()), true);
        if derbio.is_null() {
            // SAFETY: the live pointers are not freed again.
            unsafe {
                BIO_free_all(out);
                OCSP_REQUEST_free(req);
            }
            return 1;
        }
        // SAFETY: `derbio`/`req` are live; the item is the crate's own.
        unsafe { ASN1_item_i2d_bio(OCSP_REQUEST_it(), derbio, req.cast::<c_void>()) };
        // SAFETY: `derbio` is live and not freed again.
        unsafe { BIO_free(derbio) };
    }

    // No responder, no response, no index: `ret = 0; goto end;` — `apps/ocsp.c:795-798`.
    // SAFETY: the live pointers are not freed again.
    unsafe {
        BIO_free_all(out);
        OCSP_REQUEST_free(req);
    }
    0
}
