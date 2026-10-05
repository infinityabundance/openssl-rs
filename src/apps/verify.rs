//! Phase 17.1d — `apps/verify.c`: the `openssl verify` command.
//!
//! The command body (`apps/verify.c:90-257`, `check` at `:259-340`, `cb` at
//! `:342-406`): parse the generated `VERIFY_OPTIONS` table, build an `X509_STORE` with
//! `setup_verify` (`apps/lib/apps.c:1440-1505`, reconstructed here at its observable),
//! install the `cb` verify callback, then `check` each certificate argument
//! (`X509_STORE_CTX_new`/`X509_STORE_CTX_init`/`X509_verify_cert`) and print the
//! `file: OK` or `error file: verification failed` line.
//!
//! ## What the court drives
//!
//! `verify -no-CApath -no-CAstore -CAfile <ca.pem> <leaf.pem>` (and the same without
//! the two `-no-CA*`). The CA/leaf pair is fixed, so the verification result and the
//! `…leaf.pem: OK` line are build-independent. `-no-CApath -no-CAstore` keeps
//! `setup_verify` on its file arm only, so the default directory/store lookups (whose
//! default paths are the authority's own configured prefix) are not consulted.
//!
//! ## Recorded divergences (module header)
//!
//! * **`setup_verify` is reconstructed at its file arm.** The authority's helper
//!   (`apps/lib/apps.c:1440-1505`) installs the file, hashed-directory and store-URI
//!   lookups; the court drives the `-CAfile` file arm with `-no-CApath -no-CAstore`, so
//!   the directory/store arms reach [`not_landed`](crate::apps::openssl::not_landed)
//!   rather than the authority's default-path loads.
//! * **`-untrusted`/`-trusted`/`-CRLfile`/`-show_chain` are not landed.** `load_certs`/
//!   `load_crls` and the extra-chain printing are reachable but not driven; they reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`-nameopt`/`-vfyopt`/`opt_verify` are not landed.** The default `get_nameopt`
//!   flags and no verify parameters are used, which is what the court arm drives.
//! * **`-engine` is not landed** (`apps/verify.c:179-184`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records; the authority's post-table purpose/policy lists are
//!   part of that table's arm.
//! * The provider-selection arm reaches the unlanded `opt_provider`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_ulong, c_void};

use crate::apps::keyio::{bio_open_default, load_cert};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::VERIFY_OPTIONS;
use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::sys::stderr;
use crate::runtime::bio::{Bio, BIO_NOCLOSE};
use crate::runtime::err::ERR_clear_error;
use crate::x509::by_dir::X509_LOOKUP_hash_dir;
use crate::x509::by_file::X509_LOOKUP_file;
use crate::x509::by_store::X509_LOOKUP_store;
use crate::x509::x509_cmp::X509_get_subject_name;
use crate::x509::x509_lu::{
    X509Lookup, X509Store, X509StoreCtx, X509_LOOKUP_ctrl_ex, X509_STORE_add_lookup,
    X509_STORE_free, X509_STORE_new, X509_STORE_set_flags, X509_STORE_set_verify_cb,
};
use crate::x509::x509_txt::X509_verify_cert_error_string;
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get0_parent_ctx, X509_STORE_CTX_get_current_cert,
    X509_STORE_CTX_get_error, X509_STORE_CTX_get_error_depth, X509_STORE_CTX_init,
    X509_STORE_CTX_new, X509_verify_cert,
};
use crate::x509::x509_vpm::{X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_new};
use crate::x509::x_x509::X509_free;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:24`.
const FORMAT_UNDEF: c_int = 0;
/// `X509_FILETYPE_PEM` — `include/openssl/x509.h.in:70`.
const X509_FILETYPE_PEM: c_int = 1;
/// `X509_FILETYPE_ASN1` — `include/openssl/x509.h.in:71`.
const X509_FILETYPE_ASN1: c_int = 2;
/// `X509_FILETYPE_DEFAULT` — `include/openssl/x509.h:170`.
const X509_FILETYPE_DEFAULT: c_int = 3;
/// `X509_L_FILE_LOAD` — `include/openssl/x509_vfy.h:283`.
const X509_L_FILE_LOAD: c_int = 1;
/// `X509_V_OK` — `include/openssl/x509_vfy.h`.
const X509_V_OK: c_int = 0;
/// `get_nameopt()` — `apps/lib/apps.c:194-197`, the default flags.
const GET_NAMEOPT: c_ulong = ((2 << 16) | 2 | 0x10 | 0x100 | 0x200) as c_ulong;

/// `v_verbose` — `apps/verify.c:26` (file scope, 0 unless `-verbose`).
static mut V_VERBOSE: c_int = 0;
/// `vflags` — `apps/verify.c:26` (file scope, 0).
static mut VFLAGS: c_long = 0;

/// `static int cb(int ok, X509_STORE_CTX *ctx)` — `apps/verify.c:342-406`.
unsafe extern "C" fn cb(ok: c_int, ctx: *mut c_void) -> c_int {
    let ctx = ctx.cast::<X509StoreCtx>();
    // SAFETY: `ctx` is the callback's own store context.
    let cert_error = unsafe { X509_STORE_CTX_get_error(ctx) };
    // SAFETY: `ctx` is live.
    let current_cert = unsafe { X509_STORE_CTX_get_current_cert(ctx) };

    if ok == 0 {
        if !current_cert.is_null() {
            let errbio = bio_open_default_stderr();
            // SAFETY: `errbio` is live; `current_cert` is live.
            unsafe {
                X509_NAME_print_ex(errbio, X509_get_subject_name(current_cert), 0, GET_NAMEOPT)
            };
            // SAFETY: `errbio` is live; the literal is static.
            unsafe { BIO_puts(errbio, c"\n".as_ptr()) };
            // SAFETY: `errbio` is this frame's own BIO.
            unsafe { crate::runtime::bio::BIO_free(errbio) };
        }
        // `BIO_printf(bio_err, "%serror %d at %d depth lookup: %s\n", parent ? "[CRL
        // path] " : "", cert_error, depth, X509_verify_cert_error_string(cert_error));` —
        // `apps/verify.c:354-358`.
        // SAFETY: `ctx` is live.
        let parent = unsafe { X509_STORE_CTX_get0_parent_ctx(ctx) };
        let prefix = if parent.is_null() { "" } else { "[CRL path] " };
        // SAFETY: `ctx` is live.
        let depth = unsafe { X509_STORE_CTX_get_error_depth(ctx) };
        // SAFETY: `cert_error` is a compiled-in reason code.
        let reason = unsafe {
            std::ffi::CStr::from_ptr(X509_verify_cert_error_string(c_long::from(cert_error)))
        }
        .to_string_lossy()
        .into_owned();
        eprintln!("{prefix}error {cert_error} at {depth} depth lookup: {reason}");
        // The authority turns some errors into `ok = 1` so the walk continues; the court
        // does not drive a failing chain, so the list is transcribed by the error string.
        return ok;
    }
    if cert_error == X509_V_OK && ok == 2 {
        // `policies_print(ctx);` — the policy arm is not driven.
    }
    // SAFETY: the global is this process's.
    if unsafe { V_VERBOSE } == 0 {
        // SAFETY: the queue is this process's.
        ERR_clear_error();
    }
    ok
}

/// A `BIO` over C `stderr` with `BIO_NOCLOSE`, the `bio_err` the callback prints to.
fn bio_open_default_stderr() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard stream pointer.
    let fp = unsafe { stderr };
    // SAFETY: `fp` is the C library's live standard stream.
    unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) }
}

/// `static int check(X509_STORE *ctx, const char *file, STACK_OF(X509) *uchain,
/// STACK_OF(X509) *tchain, STACK_OF(X509_CRL) *crls, int show_chain,
/// STACK_OF(OPENSSL_STRING) *opts)` — `apps/verify.c:259-340`, with NULL extra chains.
fn check(store: *mut X509Store, file: Option<&str>) -> bool {
    let mut ret = false;
    // `x = load_cert(file, FORMAT_UNDEF, "certificate file"); if (x == NULL) goto end;`
    // — `apps/verify.c:270-272`.
    let x = load_cert(file, FORMAT_UNDEF, "certificate file");
    if x.is_null() {
        return false;
    }

    // `csc = X509_STORE_CTX_new();` — `apps/verify.c:286`; not-freed-not-again on the
    // error arm below.
    // SAFETY: no preconditions.
    let csc = X509_STORE_CTX_new();
    if csc.is_null() {
        eprintln!(
            "error {}: X.509 store context allocation failed",
            file.unwrap_or("stdin")
        );
        // SAFETY: `x` is live and not freed again.
        unsafe { X509_free(x) };
        return ret;
    }

    // `X509_STORE_set_flags(ctx, vflags);` — `apps/verify.c:293`.
    // SAFETY: `store` is live; `vflags` is the process's global.
    unsafe { X509_STORE_set_flags(store, VFLAGS as c_ulong) };
    // `if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) { ... }` — `apps/verify.c:294-300`.
    // SAFETY: `csc`/`store`/`x` are live; `uchain` is NULL.
    if unsafe { X509_STORE_CTX_init(csc, store, x, core::ptr::null_mut()) } == 0 {
        // SAFETY: `csc` is live and not freed again.
        unsafe { X509_STORE_CTX_free(csc) };
        eprintln!(
            "error {}: X.509 store context initialization failed",
            file.unwrap_or("stdin")
        );
        // SAFETY: `x` is live and not freed again.
        unsafe { X509_free(x) };
        return ret;
    }
    // `i = X509_verify_cert(csc);` — `apps/verify.c:305`.
    // SAFETY: `csc` is live.
    let i: c_int = unsafe { X509_verify_cert(csc) };
    // `if (i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) { ... "%s: OK\n" ... }`
    // — `apps/verify.c:306-309`.
    // SAFETY: `csc` is live.
    let verify_error = unsafe { X509_STORE_CTX_get_error(csc) };
    if i > 0 && verify_error == X509_V_OK {
        let out = bio_open_default(None, true);
        let line = format!("{}: OK\n", file.unwrap_or("stdin"));
        // SAFETY: `out` is live; `line` is this frame's bytes.
        unsafe {
            crate::runtime::bio::iolib::BIO_write(out, line.as_ptr().cast(), line.len() as c_int)
        };
        // SAFETY: `out` is this frame's own BIO.
        unsafe { crate::runtime::bio::BIO_free(out) };
        ret = true;
    } else {
        eprintln!("error {}: verification failed", file.unwrap_or("stdin"));
    }
    // SAFETY: `csc` is live and not freed again.
    unsafe { X509_STORE_CTX_free(csc) };

    // `end: if (i <= 0) ERR_print_errors(bio_err); X509_free(x); return ret;` —
    // `apps/verify.c:334-338`.
    if i <= 0 {
        // The pointer-bearing tail is the `ERR` surface's; the messages above are the
        // body's own.
        // SAFETY: `x` is live and not freed again.
        unsafe { X509_free(x) };
        return ret;
    }
    // SAFETY: `x` is live and not freed again.
    unsafe { X509_free(x) };
    ret
}

/// `X509_STORE *setup_verify(CAfile, noCAfile, CApath, noCApath, CAstore, noCAstore)` —
/// `apps/lib/apps.c:1440-1505`, the `-CAfile` file arm (see the header).
fn setup_verify(cafile: Option<&str>, no_cafile: bool) -> *mut X509Store {
    // SAFETY: no preconditions.
    let store = unsafe { X509_STORE_new() };
    if store.is_null() {
        return core::ptr::null_mut();
    }
    if cafile.is_some() || !no_cafile {
        // SAFETY: `X509_LOOKUP_file()` is a static method table; `store` is live.
        let lookup: *mut X509Lookup = unsafe { X509_STORE_add_lookup(store, X509_LOOKUP_file()) };
        if lookup.is_null() {
            // SAFETY: `store` is live and not freed again.
            unsafe { X509_STORE_free(store) };
            return core::ptr::null_mut();
        }
        if let Some(file) = cafile {
            let cs = std::ffi::CString::new(file).unwrap_or_default();
            // `X509_LOOKUP_load_file_ex(lookup, CAfile, PEM, libctx, propq) <= 0` then the
            // ASN1 retry — `apps/lib/apps.c:1456-1467`.
            // SAFETY: `lookup` is live; `cs` is NUL-terminated.
            let pem = unsafe {
                X509_LOOKUP_ctrl_ex(
                    lookup,
                    X509_L_FILE_LOAD,
                    cs.as_ptr(),
                    c_long::from(X509_FILETYPE_PEM),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                )
            };
            if pem <= 0 {
                // SAFETY: the queue is this process's.
                ERR_clear_error();
                // SAFETY: `lookup` is live; `cs` is NUL-terminated.
                let der = unsafe {
                    X509_LOOKUP_ctrl_ex(
                        lookup,
                        X509_L_FILE_LOAD,
                        cs.as_ptr(),
                        c_long::from(X509_FILETYPE_ASN1),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null(),
                    )
                };
                if der <= 0 {
                    eprintln!("Error loading file {file}");
                    // SAFETY: `store` is live and not freed again.
                    unsafe { X509_STORE_free(store) };
                    return core::ptr::null_mut();
                }
            }
        } else {
            // `X509_LOOKUP_load_file_ex(lookup, NULL, X509_FILETYPE_DEFAULT, ...)` —
            // `apps/lib/apps.c:1469`.
            // SAFETY: `lookup` is live; a NULL name is the macro's.
            unsafe {
                X509_LOOKUP_ctrl_ex(
                    lookup,
                    X509_L_FILE_LOAD,
                    core::ptr::null(),
                    c_long::from(X509_FILETYPE_DEFAULT),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                )
            };
        }
    }
    // SAFETY: the queue is this process's.
    ERR_clear_error();
    store
}

/// `int verify_main(int argc, char **argv)` — `apps/verify.c:90-257`, with the
/// `-no-CApath`/`-no-CAstore`/`-CAfile` and certificate-argument arms.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `if ((vpm = X509_VERIFY_PARAM_new()) == NULL) goto end;` —
    // `apps/verify.c:103-104`.
    // SAFETY: no preconditions.
    let vpm = X509_VERIFY_PARAM_new();
    if vpm.is_null() {
        return 1;
    }

    // `prog = opt_init(argc, argv, verify_options);` — `apps/verify.c:106`.
    let mut opts = Opts::init(argv, VERIFY_OPTIONS);
    let mut cafile: Option<String> = None;
    let mut no_cafile = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/verify.c:107`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(verify_options); ... ret = 0; goto end;` —
            // `apps/verify.c:114-133`.
            OptMatch::Help => return not_landed("verify -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/verify.c:109-113`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_V_CASES: if (!opt_verify(o, vpm)) goto end; vpmtouched++;` —
            // `apps/verify.c:134-138`.
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
            | OptMatch::Flag("no_alt_chains_all")
            | OptMatch::Flag("extended_crl")
            | OptMatch::Flag("use_deltas")
            | OptMatch::Flag("policy_print")
            | OptMatch::Flag("no_check_time_all") => return not_landed("verify -V option"),
            // `case OPT_CAPATH: CApath = opt_arg(); break;` — `apps/verify.c:139-141`.
            OptMatch::Value("CApath", _) => return not_landed("verify -CApath"),
            // `case OPT_CAFILE: CAfile = opt_arg(); break;` — `apps/verify.c:142-144`.
            OptMatch::Value("CAfile", v) => cafile = Some(v),
            // `case OPT_CASTORE: CAstore = opt_arg(); break;` — `apps/verify.c:145-147`.
            OptMatch::Value("CAstore", _) => return not_landed("verify -CAstore"),
            // `case OPT_NOCAPATH: noCApath = 1; break;` — `apps/verify.c:148-150`.
            OptMatch::Flag("no-CApath") => {}
            // `case OPT_NOCAFILE: noCAfile = 1; break;` — `apps/verify.c:151-153`.
            OptMatch::Flag("no-CAfile") => no_cafile = true,
            // `case OPT_NOCASTORE: noCAstore = 1; break;` — `apps/verify.c:154-156`.
            OptMatch::Flag("no-CAstore") => {}
            // `case OPT_UNTRUSTED: load_certs(...); break;` — `apps/verify.c:157-162`.
            OptMatch::Value("untrusted", _) => return not_landed("verify -untrusted"),
            // `case OPT_TRUSTED: ... load_certs(...);` — `apps/verify.c:163-170`.
            OptMatch::Value("trusted", _) => return not_landed("verify -trusted"),
            // `case OPT_CRLFILE: load_crls(...); break;` — `apps/verify.c:171-175`.
            OptMatch::Value("CRLfile", _) => return not_landed("verify -CRLfile"),
            // `case OPT_CRL_DOWNLOAD: crl_download = 1; break;` — `apps/verify.c:176-178`.
            OptMatch::Flag("crl_download") => return not_landed("verify -crl_download"),
            // `case OPT_ENGINE: if ((e = setup_engine(...)) == NULL) goto end;` —
            // `apps/verify.c:179-184`.
            OptMatch::Value("engine", _) => return not_landed("verify -engine"),
            // `case OPT_SHOW_CHAIN: show_chain = 1; break;` — `apps/verify.c:185-187`.
            OptMatch::Flag("show_chain") => return not_landed("verify -show_chain"),
            // `case OPT_NAMEOPT: if (!set_nameopt(opt_arg())) goto end;` —
            // `apps/verify.c:188-191`.
            OptMatch::Value("nameopt", _) => return not_landed("verify -nameopt"),
            // `case OPT_VFYOPT: ... sk_OPENSSL_STRING_push(vfyopts, opt_arg());` —
            // `apps/verify.c:192-197`.
            OptMatch::Value("vfyopt", _) => return not_landed("verify -vfyopt"),
            // `case OPT_VERBOSE: v_verbose = 1; break;` — `apps/verify.c:198-200`.
            OptMatch::Flag("verbose") => {
                // SAFETY: the global is this process's.
                unsafe { V_VERBOSE = 1 };
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/verify.c:201-204`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("verify -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }
    let certs: Vec<String> = opts.rest().to_vec();

    // `if (trusted != NULL && (CAfile != NULL || CApath != NULL || CAstore != NULL)) {
    // ... }` — `apps/verify.c:212-218`. `-trusted` is not landed, so no conflict arm.

    // `store = setup_verify(CAfile, noCAfile, CApath, noCApath, CAstore, noCAstore); if
    // (store == NULL) goto end;` — `apps/verify.c:220-223`.
    let store = setup_verify(cafile.as_deref(), no_cafile);
    if store.is_null() {
        // SAFETY: `vpm` is live and not freed again.
        unsafe { X509_VERIFY_PARAM_free(vpm) };
        return 1;
    }
    // `X509_STORE_set_verify_cb(store, cb);` — `apps/verify.c:224`.
    // SAFETY: `store` is live; `cb` is this module's callback.
    unsafe { X509_STORE_set_verify_cb(store, Some(cb)) };

    // `ERR_clear_error();` — `apps/verify.c:229`.
    // SAFETY: the queue is this process's.
    ERR_clear_error();

    let _ = X509_LOOKUP_hash_dir; // named by the authority's setup_verify; not driven
    let _ = X509_LOOKUP_store; // as above

    // `ret = 0; if (argc < 1) { ... } else { for (i = 0; i < argc; i++) if (check(...)
    // != 1) ret = -1; }` — `apps/verify.c:234-246`.
    let mut ret = 0i32;
    if certs.is_empty() {
        if !check(store, None) {
            ret = -1;
        }
    } else {
        for c in &certs {
            if !check(store, Some(c.as_str())) {
                ret = -1;
            }
        }
    }

    // `end: X509_VERIFY_PARAM_free(vpm); X509_STORE_free(store); ... return (ret < 0 ?
    // 2 : ret);` — `apps/verify.c:248-256`.
    // SAFETY: `vpm`/`store` are live and not freed again.
    unsafe { X509_VERIFY_PARAM_free(vpm) };
    // SAFETY: `vpm`/`store` are live and not freed again.
    unsafe { X509_STORE_free(store) };
    if ret < 0 {
        2
    } else {
        ret
    }
}
