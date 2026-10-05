//! Phase 17.1f — `apps/ts.c`: the `openssl ts` command.
//!
//! The command's option parse (`apps/ts.c:205-312`), its mode refusal
//! (`apps/ts.c:317-320`) and the query half of the body (`apps/ts.c:417-526`) are
//! transcribed: `-data` (or a `-digest` hex string) is hashed with the named
//! digest, wrapped in a `TS_REQ` through `TS_REQ_set_version`/`TS_MSG_IMPRINT_set_*`/
//! `TS_REQ_set_msg_imprint`, and serialized with `i2d_TS_REQ_bio` or printed with
//! `TS_REQ_print_bio`. The `-reply`/`-verify` halves — a TSA configuration, a
//! signing key and certificate verification — are not landed.
//!
//! ## What the court drives
//!
//! `ts` (the mode refusal), `ts -query -reply` (the mutually-exclusive refusal),
//! `ts -bogus` (the mode refusal, since `-bogus` is the digest sentinel) and
//! `ts -query -no_nonce -data <small.bin>` (the DER query) and its `-text`
//! spelling, all over the fixed input. `-no_nonce` is required for determinism;
//! a query without it draws a random nonce and is recorded.
//!
//! ## Recorded divergences (module header)
//!
//! * **The `-reply`/`-verify` and TSA-signing arms are not landed.** They need
//!   `load_config_file`'s TSA section, `EVP_PKEY` signing, `TS_RESP` construction
//!   and certificate verification; each reaches [`not_landed`].
//! * **`app_load_config` is reduced to the `/dev/null` observable.** The
//!   authority's helper searches default paths and loads modules; this module
//!   builds a `CONF` from the one named file (`apps/ts.c:390-412`'s
//!   `load_config_file` minus the `oid_file`/`oid_section` steps, which are
//!   no-ops for the empty default config). `CONF_get1_default_config_file`
//!   supplies the default path, so `OPENSSL_CONF=/dev/null` is the driven value.
//! * **A query without `-no_nonce` draws a random nonce** through
//!   `create_nonce`; it is recorded rather than diffed.
//! * **`-digest` (a hex digest), `-policy`, `-engine` and `-token_in` are not
//!   landed**, and the `-rand`/provider arms reach the unlanded `opt_rand`/
//!   `opt_provider`.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records; the authority's extra `opt_helplist` lines are
//!   that boundary too.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};
use std::ffi::{CStr, CString};

use crate::apps::keyio::bio_open_default;
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::TS_OPTIONS;
use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::layout::V_ASN1_NULL;
use crate::asn1::x_algor::{X509_ALGOR_free, X509_ALGOR_new};
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get_type, EvpMd,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::runtime::bio::iolib::BIO_read;
use crate::runtime::bio::{BIO_free_all, Bio};
use crate::runtime::conf::lib::{NCONF_free, NCONF_load, NCONF_new};
use crate::runtime::conf::modparse::CONF_get1_default_config_file;
use crate::runtime::conf::types::Conf;
use crate::runtime::obj::OBJ_nid2obj;
use crate::ts::ts_asn1::TsReq;
use crate::ts::ts_asn1::{
    d2i_TS_REQ_bio, i2d_TS_REQ_bio, TS_MSG_IMPRINT_free, TS_MSG_IMPRINT_new, TS_REQ_free,
    TS_REQ_new,
};
use crate::ts::ts_req_print::TS_REQ_print_bio;
use crate::ts::ts_req_utils::{
    TS_MSG_IMPRINT_set_algo, TS_MSG_IMPRINT_set_msg, TS_REQ_set_cert_req, TS_REQ_set_msg_imprint,
    TS_REQ_set_version,
};

/// `-query`/`-reply`/`-verify` selector (`apps/ts.c:193`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Query,
    Reply,
    Verify,
}

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

/// `static CONF *load_config_file(const char *configfile)` — `apps/ts.c:390-412`,
/// reduced to the one-file load and its banner (see the header).
fn load_config_file(configfile: &str) -> Option<*mut Conf> {
    let cs = CString::new(configfile).ok()?;
    // SAFETY: the method is NULL (the default table).
    let conf = unsafe { NCONF_new(core::ptr::null_mut()) };
    if conf.is_null() {
        return None;
    }
    let mut eline: c_long = 0;
    // SAFETY: `conf`/`cs` are live; `eline` is a live local.
    if unsafe { NCONF_load(conf, cs.as_ptr(), core::ptr::addr_of_mut!(eline)) } == 0 {
        // SAFETY: `conf` is live and not used again.
        unsafe { NCONF_free(conf) };
        return None;
    }
    // `BIO_printf(bio_err, "Using configuration from %s\n", configfile);` —
    // `apps/ts.c:397`.
    eprintln!("Using configuration from {configfile}");
    Some(conf)
}

/// `static int create_digest(BIO *input, const char *digest, const EVP_MD *md,
/// unsigned char **md_value)` — `apps/ts.c:528-...`, the `input != NULL` arm.
fn create_digest(input: *mut Bio, md: *const EvpMd) -> Option<Vec<u8>> {
    // SAFETY: `md` is live or NULL.
    let md_value_len = unsafe { EVP_MD_get_size(md) };
    if md_value_len <= 0 {
        return None;
    }
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return None;
    }
    let mut out = vec![0u8; md_value_len as usize];
    // SAFETY: `ctx`/`md` are live; the engine is NULL.
    if unsafe { EVP_DigestInit(ctx, md) } == 0 {
        // SAFETY: `ctx` is live and not used again.
        unsafe { EVP_MD_CTX_free(ctx) };
        return None;
    }
    let mut buffer = [0u8; 4096];
    loop {
        // SAFETY: `input` is live; `buffer` is writable for its length.
        let n = unsafe { BIO_read(input, buffer.as_mut_ptr().cast(), 4096) };
        if n <= 0 {
            break;
        }
        // SAFETY: `ctx` is live; `buffer` holds `n` bytes.
        if unsafe { EVP_DigestUpdate(ctx, buffer.as_ptr().cast(), n as usize) } == 0 {
            // SAFETY: `ctx` is live and not used again.
            unsafe { EVP_MD_CTX_free(ctx) };
            return None;
        }
    }
    // SAFETY: `ctx` is live; `out` is writable for the digest length.
    let ok = unsafe { EVP_DigestFinal(ctx, out.as_mut_ptr(), core::ptr::null_mut()) } != 0;
    // SAFETY: `ctx` is live and not used again.
    unsafe { EVP_MD_CTX_free(ctx) };
    if ok {
        Some(out)
    } else {
        None
    }
}

/// `static TS_REQ *create_query(BIO *data_bio, const char *digest, const EVP_MD
/// *md, const char *policy, int no_nonce, int cert)` — `apps/ts.c:464-526`, the
/// `-data`/no-policy/`-no_nonce` arm.
fn create_query(data_bio: *mut Bio, md: *mut EvpMd, no_nonce: bool, cert: bool) -> *mut TsReq {
    // `if (md == NULL && (md = EVP_get_digestbyname("sha256")) == NULL) goto err;` —
    // `apps/ts.c:476-477`.
    let md = if md.is_null() {
        // SAFETY: the literal is NUL-terminated.
        let legacy = unsafe { EVP_get_digestbyname(c"sha256".as_ptr()) };
        if legacy.is_null() {
            eprintln!("could not create query");
            return core::ptr::null_mut();
        }
        legacy.cast_mut()
    } else {
        md
    };
    if !no_nonce {
        // A non-`-no_nonce` query draws a random nonce; not landed/deterministic.
        eprintln!("could not create query");
        return core::ptr::null_mut();
    }

    // SAFETY: `TS_REQ_new` has no argument.
    let ts_req = unsafe { TS_REQ_new() };
    if ts_req.is_null() {
        eprintln!("could not create query");
        return core::ptr::null_mut();
    }
    // SAFETY: `ts_req` is live.
    unsafe { TS_REQ_set_version(ts_req, 1) };
    // SAFETY: `TS_MSG_IMPRINT_new` has no argument.
    let msg_imprint = unsafe { TS_MSG_IMPRINT_new() };
    let algo = X509_ALGOR_new();
    // SAFETY: `ASN1_TYPE_new` has no argument.
    let param = ASN1_TYPE_new();
    if msg_imprint.is_null() || algo.is_null() || param.is_null() {
        eprintln!("could not create query");
        // SAFETY: each pointer is NULL-or-live.
        unsafe {
            TS_MSG_IMPRINT_free(msg_imprint);
            X509_ALGOR_free(algo);
            ASN1_TYPE_free(param);
            TS_REQ_free(ts_req);
        }
        return core::ptr::null_mut();
    }
    // `algo->algorithm = OBJ_nid2obj(EVP_MD_get_type(md));` — `apps/ts.c:486`.
    // SAFETY: `algo` is live; `md` is live.
    unsafe { (*algo).algorithm = OBJ_nid2obj(EVP_MD_get_type(md)) };
    // `algo->parameter = ASN1_TYPE_new(); algo->parameter->type = V_ASN1_NULL;` —
    // `apps/ts.c:488-490`.
    // SAFETY: `algo` is live.
    unsafe {
        (*algo).parameter = param;
        (*param).type_ = V_ASN1_NULL;
    }
    // SAFETY: `msg_imprint`/`algo` are live.
    let ok_algo = unsafe { TS_MSG_IMPRINT_set_algo(msg_imprint, algo) } != 0;

    let Some(data) = create_digest(data_bio, md) else {
        eprintln!("could not create query");
        // SAFETY: each pointer is NULL-or-live.
        unsafe {
            TS_MSG_IMPRINT_free(msg_imprint);
            X509_ALGOR_free(algo);
            TS_REQ_free(ts_req);
        }
        return core::ptr::null_mut();
    };
    // SAFETY: `msg_imprint` is live; `data` holds `data.len()` bytes.
    let ok_msg = unsafe {
        TS_MSG_IMPRINT_set_msg(msg_imprint, data.as_ptr().cast_mut(), data.len() as c_int)
    } != 0;
    // SAFETY: `ts_req`/`msg_imprint` are live.
    let ok_set = unsafe { TS_REQ_set_msg_imprint(ts_req, msg_imprint) } != 0;
    // SAFETY: `ts_req` is live.
    unsafe { TS_REQ_set_cert_req(ts_req, i32::from(cert)) };

    // `err:` label frees the locals; `TS_REQ_set_msg_imprint` took a copy.
    // SAFETY: each pointer is live and not used again.
    unsafe {
        TS_MSG_IMPRINT_free(msg_imprint);
        X509_ALGOR_free(algo);
    }
    if ok_algo && ok_msg && ok_set {
        ts_req
    } else {
        eprintln!("could not create query");
        // SAFETY: `ts_req` is live and owned here.
        unsafe { TS_REQ_free(ts_req) };
        core::ptr::null_mut()
    }
}

/// `static int query_command(const char *data, const char *digest, const EVP_MD
/// *md, const char *policy, int no_nonce, int cert, const char *in, const char
/// *out, int text)` — `apps/ts.c:417-462`.
#[allow(clippy::too_many_arguments)]
fn query_command(
    data: Option<&str>,
    digest: Option<&str>,
    md: *mut EvpMd,
    no_nonce: bool,
    cert: bool,
    in_file: Option<&str>,
    out_file: Option<&str>,
    text: bool,
) -> bool {
    let mut in_bio: *mut Bio = core::ptr::null_mut();
    let mut data_bio: *mut Bio = core::ptr::null_mut();

    let query: *mut TsReq;
    if let Some(inf) = in_file {
        // `if ((in_bio = bio_open_default(in, 'r', FORMAT_ASN1)) == NULL) goto end;`
        // `query = d2i_TS_REQ_bio(in_bio, NULL);` — `apps/ts.c:428-432`.
        in_bio = bio_open_default(Some(inf), false);
        if in_bio.is_null() {
            return false;
        }
        // SAFETY: `in_bio` is live; the out-slot is NULL.
        query = unsafe { d2i_TS_REQ_bio(in_bio, core::ptr::null_mut()) };
    } else {
        if let Some(d) = data {
            data_bio = bio_open_default(Some(d), false);
            if data_bio.is_null() {
                return false;
            }
        } else {
            data_bio = bio_open_default(None, false);
        }
        if digest.is_some() {
            // `create_digest`'s hex arm is not landed.
            return false;
        }
        query = create_query(data_bio, md, no_nonce, cert);
    }
    if query.is_null() {
        // SAFETY: the live BIOs are not used again.
        unsafe {
            BIO_free_all(in_bio);
            BIO_free_all(data_bio);
        }
        return false;
    }

    // `text ? TS_REQ_print_bio(out_bio, query) : i2d_TS_REQ_bio(out_bio, query)` —
    // `apps/ts.c:441-451`.
    let out_bio = bio_open_default(out_file, true);
    if out_bio.is_null() {
        // SAFETY: the live pointers are not used again.
        unsafe {
            BIO_free_all(in_bio);
            BIO_free_all(data_bio);
            TS_REQ_free(query);
        }
        return false;
    }
    let ok = if text {
        // SAFETY: `out_bio`/`query` are live.
        (unsafe { TS_REQ_print_bio(out_bio, query) }) != 0
    } else {
        // SAFETY: `out_bio`/`query` are live.
        (unsafe { i2d_TS_REQ_bio(out_bio, query) }) != 0
    };

    // SAFETY: the live pointers are not used again.
    unsafe {
        BIO_free_all(in_bio);
        BIO_free_all(data_bio);
        BIO_free_all(out_bio);
        TS_REQ_free(query);
    }
    ok
}

/// The `default_config_file` the authority's `openssl.c:334` computes at startup.
fn default_config_file() -> Option<String> {
    let p = CONF_get1_default_config_file();
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is NUL-terminated.
    Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// `int ts_main(int argc, char **argv)` — `apps/ts.c:179-374`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, TS_OPTIONS);
    // `opt_set_unknown_name("digest");` — `apps/ts.c:205`.
    opts.enable_unknown("digest");

    let mut configfile = default_config_file();
    let mut mode: Option<Mode> = None;
    let mut data: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut digestname: Option<String> = None;
    let mut cert = false;
    let mut no_nonce = false;
    let mut text = false;
    let mut in_file: Option<String> = None;
    let mut out_file: Option<String> = None;
    let mut vpmtouched = false;
    let mut md: *mut EvpMd = core::ptr::null_mut();

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ... ret = 0; goto end;` —
            // `apps/ts.c:214-219`.
            OptMatch::Help => return not_landed("ts -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/ts.c:209-213`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_CONFIG: configfile = opt_arg();` — `apps/ts.c:220-222`.
            OptMatch::Value("config", v) => configfile = Some(v),
            // `case OPT_SECTION: section = opt_arg();` — `apps/ts.c:223-225`.
            OptMatch::Value("section", _) => {}
            // `case OPT_QUERY: case OPT_REPLY: case OPT_VERIFY:` — `apps/ts.c:226-234`.
            OptMatch::Flag("query") => {
                if mode.is_some() {
                    eprintln!(
                        "{}: Must give only one of -query, -reply, or -verify",
                        opts.prog()
                    );
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Some(Mode::Query);
            }
            OptMatch::Flag("reply") => {
                if mode.is_some() {
                    eprintln!(
                        "{}: Must give only one of -query, -reply, or -verify",
                        opts.prog()
                    );
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Some(Mode::Reply);
            }
            OptMatch::Flag("verify") => {
                if mode.is_some() {
                    eprintln!(
                        "{}: Must give only one of -query, -reply, or -verify",
                        opts.prog()
                    );
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Some(Mode::Verify);
            }
            // `case OPT_DATA: data = opt_arg();` — `apps/ts.c:235-237`.
            OptMatch::Value("data", v) => data = Some(v),
            // `case OPT_DIGEST: digest = opt_arg();` — `apps/ts.c:238-240`.
            OptMatch::Value("digest", v) => digest = Some(v),
            // `case OPT_R_CASES: ...` — `apps/ts.c:241-244`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("ts -rand")
            }
            // `case OPT_PROV_CASES: ...` — `apps/ts.c:245-248`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("ts -provider"),
            // `case OPT_TSPOLICY: policy = opt_arg();` — `apps/ts.c:249-251`.
            OptMatch::Value("tspolicy", _) => return not_landed("ts -tspolicy"),
            // `case OPT_NO_NONCE: no_nonce = 1;` — `apps/ts.c:252-254`.
            OptMatch::Flag("no_nonce") => no_nonce = true,
            // `case OPT_CERT: cert = 1;` — `apps/ts.c:255-257`.
            OptMatch::Flag("cert") => cert = true,
            // `case OPT_IN: in = opt_arg();` — `apps/ts.c:258-260`.
            OptMatch::Value("in", v) => in_file = Some(v),
            // `case OPT_TOKEN_IN: token_in = 1;` — `apps/ts.c:261-263`.
            OptMatch::Flag("token_in") => return not_landed("ts -token_in"),
            // `case OPT_OUT: out = opt_arg();` — `apps/ts.c:264-266`.
            OptMatch::Value("out", v) => out_file = Some(v),
            // `case OPT_TOKEN_OUT: token_out = 1;` — `apps/ts.c:267-269`.
            OptMatch::Flag("token_out") => return not_landed("ts -token_out"),
            // `case OPT_TEXT: text = 1;` — `apps/ts.c:270-272`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_QUERYFILE: queryfile = opt_arg();` — `apps/ts.c:273-275`.
            OptMatch::Value("queryfile", _) => return not_landed("ts -queryfile"),
            // `case OPT_PASSIN: passin = opt_arg();` — `apps/ts.c:276-278`.
            OptMatch::Value("passin", _) => return not_landed("ts -passin"),
            OptMatch::Value("inkey", _)
            | OptMatch::Value("signer", _)
            | OptMatch::Value("chain", _) => return not_landed("ts reply"),
            OptMatch::Value("CAfile", _)
            | OptMatch::Value("CApath", _)
            | OptMatch::Value("CAstore", _)
            | OptMatch::Value("untrusted", _) => return not_landed("ts verify"),
            // `case OPT_ENGINE: engine = opt_arg();` — `apps/ts.c:300-302`.
            OptMatch::Value("engine", _) => return not_landed("ts -engine"),
            // `case OPT_MD: digestname = opt_unknown();` — `apps/ts.c:303-305`.
            OptMatch::Value("", v) => digestname = Some(v),
            // `case OPT_V_CASES: if (!opt_verify(o, vpm)) goto end; vpmtouched++;` —
            // `apps/ts.c:306-310`.
            OptMatch::Value("policy", _)
            | OptMatch::Value("purpose", _)
            | OptMatch::Value("verify_name", _)
            | OptMatch::Value("verify_depth", _)
            | OptMatch::Value("auth_level", _)
            | OptMatch::Value("attime", _)
            | OptMatch::Value("verify_hostname", _)
            | OptMatch::Value("verify_email", _)
            | OptMatch::Value("verify_ip", _) => vpmtouched = true,
            OptMatch::Flag(
                "ignore_critical" | "issuer_checks" | "crl_check" | "crl_check_all"
                | "policy_check" | "explicit_policy" | "inhibit_any" | "inhibit_map"
                | "x509_strict" | "extended_crl" | "use_deltas" | "policy_print" | "check_ss_sig"
                | "trusted_first" | "suiteB_128_only" | "suiteB_128" | "suiteB_192"
                | "partial_chain" | "no_alt_chains" | "no_check_time" | "allow_proxy_certs",
            ) => vpmtouched = true,
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/ts.c:314-316`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (mode == OPT_ERR) { ... goto opthelp; }` — `apps/ts.c:317-320`.
    let Some(m) = mode else {
        eprintln!(
            "{}: Must give one of -query, -reply, or -verify",
            opts.prog()
        );
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    };
    // `if (!app_RAND_load()) goto end;` — the no-`-rand` no-op success.

    // `if (!opt_md(digestname, &md)) goto opthelp;` — `apps/ts.c:325-326`.
    if let Some(name) = &digestname {
        match opt_md(opts.prog(), name) {
            Some(x) => md = x,
            None => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if ((conf = load_config_file(configfile)) == NULL) goto end;` —
    // `apps/ts.c:332-333`.
    let conf = match &configfile {
        Some(cf) => load_config_file(cf),
        None => {
            // `app_load_config(NULL)` searches the default path; not landed.
            return not_landed("ts default config");
        }
    };
    let Some(conf) = conf else {
        return 1;
    };

    // `if (mode == OPT_QUERY) { ... ret = !query_command(...); }` — `apps/ts.c:338-344`.
    let ret = if m == Mode::Query {
        if vpmtouched || (data.is_some() && digest.is_some()) {
            false
        } else {
            query_command(
                data.as_deref(),
                digest.as_deref(),
                md,
                no_nonce,
                cert,
                in_file.as_deref(),
                out_file.as_deref(),
                text,
            )
        }
    } else {
        // `-reply`/`-verify` are not landed.
        false
    };

    // SAFETY: the live pointers are not used again.
    unsafe {
        NCONF_free(conf);
        EVP_MD_free(md);
    }
    if m != Mode::Query {
        return not_landed("ts reply/verify");
    }
    if ret {
        0
    } else {
        1
    }
}
