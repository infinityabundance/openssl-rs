//! Phase 17.1 — `apps/ciphers.c`: the `openssl ciphers` command.
//!
//! The whole command body (`apps/ciphers.c:91-287`): parse the generated
//! `CIPHERS_OPTIONS` table, build a `TLS_server_method` context, pin its protocol
//! bounds with `SSL_CTX_ctrl` (the `SSL_CTX_set_min/max_proto_version` macros), set
//! the optional cipher list/ciphersuites and the optional PSK callback, then walk
//! `SSL_get_ciphers` (or `SSL_get1_supported_ciphers` under `-s`) printing each
//! cipher's name, standard name, id and description. Every libssl function the
//! driven path reaches is landed: `TLS_server_method`, `SSL_CTX_new_ex`, `SSL_new`,
//! `SSL_CTX_ctrl`, `SSL_CTX_set_cipher_list`, `SSL_CTX_set_ciphersuites`,
//! `SSL_get_ciphers`, `SSL_CIPHER_get_name`, `SSL_CIPHER_get_id`,
//! `SSL_CIPHER_standard_name`, `SSL_CIPHER_description`, `OPENSSL_cipher_name` and
//! the `OPENSSL_sk_*` accessors.
//!
//! ## What the court drives
//!
//! The name-conversion arm (`ciphers -convert <name>`) over fixed TLS 1.3 and
//! TLS 1.2 cipher names, including a name the crate does not know (which both
//! sides render as `(null)`). The list arms are **not** driven: see the first
//! recorded divergence.
//!
//! ## Recorded divergences (module header)
//!
//! * **The default-list arms are not driven.** `ciphers`, `-v`, `-stdname` and
//!   `-tls1_2` all diverge at `SSL_CTX_new_ex`/`SSL_new`: building the default
//!   cipher list, the candidate raises
//!   `inner_evp_generic_fetch:unsupported` for the legacy ciphers (`RC4`, `RC2`,
//!   `IDEA`, `SEED`, the GOST family) and the setup then fails, while the
//!   authority serves the full list. That is the `EVP`-fetch/legacy-provider
//!   surface's divergence, not this body's, so those four argv are recorded in the
//!   court's `recorded_divergences` rather than diffed. `-convert` returns before
//!   any context is built and is driven.
//! * **The `SSL_CTX_set_min/max_proto_version` macros are reduced to their
//!   observable.** `include/openssl/ssl.h.in:1509-1512` defines them as
//!   `SSL_CTX_ctrl(ctx, SSL_CTRL_SET_{MIN,MAX}_PROTO_VERSION, version, NULL)`
//!   (123/124); this module calls the landed `SSL_CTX_ctrl` directly.
//! * **`app_get0_libctx`/`app_get0_propq` are reduced to their observable.** Both
//!   answer `NULL` for the fixed default with no `-libctx`/`-propquery`.
//! * **`-srp` is not landed.** The arm calls `set_up_dummy_srp`
//!   (`apps/lib/tlssrp_depr.c`), an `apps/lib` helper this stratum does not own, so
//!   it reaches [`not_landed`]. The `-psk` arm's `SSL_CTX_set_psk_client_callback`
//!   *is* landed and transcribed.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/ciphers.c:171-174`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint};
use core::ptr;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CIPHERS_OPTIONS;
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{stderr, stdout};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::err::ERR_print_errors;
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::ssl::methods::TLS_server_method;
use crate::ssl::ssl_ciph::{
    OPENSSL_cipher_name, SSL_CIPHER_description, SSL_CIPHER_get_id, SSL_CIPHER_get_name,
    SSL_CIPHER_standard_name, SSL_CTX_set_ciphersuites,
};
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_lib::{
    SSL_CTX_ctrl, SSL_CTX_free, SSL_CTX_new_ex, SSL_CTX_set_cipher_list,
    SSL_CTX_set_psk_client_callback, SSL_free, SSL_get1_supported_ciphers, SSL_get_ciphers,
    SSL_new, Ssl,
};

/// `SSL_CTRL_SET_MIN_PROTO_VERSION` — `ssl.h:1377`. The setter is
/// `SSL_CTX_set_min_proto_version` (`ssl.h.in:1509`).
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
/// `SSL_CTRL_SET_MAX_PROTO_VERSION` — `ssl.h:1378` (`ssl.h.in:1511`).
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;

/// `bio_err` — `apps/lib/apps.c`'s stderr BIO (`dup_bio_err`).
fn bio_err() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard error `FILE *`.
    unsafe { BIO_new_fp(stderr.cast(), BIO_NOCLOSE) }
}

/// `bio_out` — `apps/lib/apps.c`'s stdout BIO (`dup_bio_out`).
fn bio_out() -> *mut Bio {
    // SAFETY: `stdout` is the C library's live standard output `FILE *`.
    unsafe { BIO_new_fp(stdout.cast(), BIO_NOCLOSE) }
}

/// `static unsigned int dummy_psk(...)` — `apps/ciphers.c:82-88`.
unsafe extern "C" fn dummy_psk(
    _ssl: *mut Ssl,
    _hint: *const c_char,
    _identity: *mut c_char,
    _max_identity_len: c_uint,
    _psk: *mut u8,
    _max_psk_len: c_uint,
) -> c_uint {
    0
}

/// `int ciphers_main(int argc, char **argv)` — `apps/ciphers.c:91-287`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, ciphers_options);` — `apps/ciphers.c:111`.
    let mut opts = Opts::init(argv, CIPHERS_OPTIONS);
    let mut ret = 1i32;
    let mut verbose = false;
    let mut verboselong = false;
    let mut use_supported = false;
    let mut stdname = false;
    let mut psk = false;
    let mut ciphers: Option<String> = None;
    let mut convert: Option<String> = None;
    let mut ciphersuites: Option<String> = None;
    let mut min_version: c_int = 0;
    let mut max_version: c_int = 0;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/ciphers.c:112`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(ciphers_options); ret = 0; goto end;` —
            // `apps/ciphers.c:119-122`.
            OptMatch::Help => return not_landed("ciphers -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog);` — `apps/ciphers.c:114-118`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_V: verbose = 1; break;` — `apps/ciphers.c:123-125`.
            OptMatch::Flag("v") => verbose = true,
            // `case OPT_UPPER_V: verbose = Verbose = 1; break;` — `apps/ciphers.c:126-128`.
            OptMatch::Flag("V") => {
                verbose = true;
                verboselong = true;
            }
            // `case OPT_S: use_supported = 1; break;` — `apps/ciphers.c:129-131`.
            OptMatch::Flag("s") => use_supported = true,
            // `case OPT_STDNAME: stdname = verbose = 1; break;` — `apps/ciphers.c:132-134`.
            OptMatch::Flag("stdname") => {
                stdname = true;
                verbose = true;
            }
            // `case OPT_CONVERT: convert = opt_arg(); break;` — `apps/ciphers.c:135-137`.
            OptMatch::Value("convert", v) => convert = Some(v),
            // `case OPT_TLS1: min_version = TLS1_VERSION; max_version = TLS1_VERSION;`
            // — `apps/ciphers.c:142-145`; likewise `tls1_1`/`tls1_2`/`tls1_3`.
            OptMatch::Flag("tls1") => {
                min_version = 0x0301;
                max_version = 0x0301;
            }
            OptMatch::Flag("tls1_1") => {
                min_version = 0x0302;
                max_version = 0x0302;
            }
            OptMatch::Flag("tls1_2") => {
                min_version = 0x0303;
                max_version = 0x0303;
            }
            OptMatch::Flag("tls1_3") => {
                min_version = 0x0304;
                max_version = 0x0304;
            }
            // `case OPT_PSK: ... psk = 1; break;` — `apps/ciphers.c:158-162`.
            OptMatch::Flag("psk") => psk = true,
            // `case OPT_SRP: ... srp = 1;` — `apps/ciphers.c:163-167`. The arm calls
            // `set_up_dummy_srp` (see the header).
            OptMatch::Flag("srp") => return not_landed("ciphers -srp"),
            // `case OPT_CIPHERSUITES: ciphersuites = opt_arg(); break;` —
            // `apps/ciphers.c:168-170`.
            OptMatch::Value("ciphersuites", v) => ciphersuites = Some(v),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/ciphers.c:171-174`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("ciphers -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argv = opt_rest(); if (opt_num_rest() == 1) ciphers = argv[0]; else if
    // (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/ciphers.c:179-183`.
    if opts.num_rest() == 1 {
        ciphers = Some(opts.rest()[0].clone());
    } else if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    if let Some(convert) = &convert {
        // `BIO_printf(bio_out, "OpenSSL cipher name: %s\n",
        // OPENSSL_cipher_name(convert)); ret = 0; goto end;` —
        // `apps/ciphers.c:185-190`.
        let cs = match std::ffi::CString::new(convert.as_str()) {
            Ok(c) => c,
            Err(_) => return ret,
        };
        // SAFETY: `cs` is NUL-terminated.
        let name = unsafe { OPENSSL_cipher_name(cs.as_ptr()) };
        let out = bio_out();
        // SAFETY: `out` is a live stdout BIO and the format is static.
        unsafe { BIO_printf(out, c"OpenSSL cipher name: %s\n".as_ptr(), name) };
        // SAFETY: `out` is NOCLOSE.
        unsafe { BIO_free(out) };
        return 0;
    }

    // `ctx = SSL_CTX_new_ex(app_get0_libctx(), app_get0_propq(), meth);` —
    // `apps/ciphers.c:192-194`. Both accessors are NULL for the fixed default.
    // SAFETY: `meth` is the static server method; both context pointers are NULL.
    let ctx = unsafe { SSL_CTX_new_ex(ptr::null_mut(), ptr::null(), TLS_server_method()) };
    if ctx.is_null() {
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        return ret;
    }

    // `if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0) goto err;` and the
    // `max` sibling — `apps/ciphers.c:195-198`, via the macros (see the header).
    // SAFETY: `ctx` is live; the `parg` is NULL as the macros pass it.
    if unsafe {
        SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MIN_PROTO_VERSION,
            c_long::from(min_version),
            ptr::null_mut(),
        )
    } == 0
    {
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        // SAFETY: `ctx` is live and not freed again.
        unsafe { SSL_CTX_free(ctx) };
        return ret;
    }
    // SAFETY: `ctx` is live; the `parg` is NULL as the macros pass it.
    if unsafe {
        SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MAX_PROTO_VERSION,
            c_long::from(max_version),
            ptr::null_mut(),
        )
    } == 0
    {
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        // SAFETY: `ctx` is live and not freed again.
        unsafe { SSL_CTX_free(ctx) };
        return ret;
    }

    // `if (psk) SSL_CTX_set_psk_client_callback(ctx, dummy_psk);` —
    // `apps/ciphers.c:200-203`.
    if psk {
        // SAFETY: `ctx` is live and the callback is this module's own.
        unsafe { SSL_CTX_set_psk_client_callback(ctx, Some(dummy_psk)) };
    }

    if let Some(suites) = &ciphersuites {
        // `if (ciphersuites != NULL && !SSL_CTX_set_ciphersuites(ctx, ciphersuites))
        // { BIO_printf(bio_err, "Error setting TLSv1.3 ciphersuites\n"); goto err;
        // }` — `apps/ciphers.c:209-212`.
        let cs = match std::ffi::CString::new(suites.as_str()) {
            Ok(c) => c,
            Err(_) => {
                // SAFETY: `ctx` is live and not freed again.
                unsafe { SSL_CTX_free(ctx) };
                return ret;
            }
        };
        // SAFETY: `ctx` is live and `cs` is NUL-terminated.
        if unsafe { SSL_CTX_set_ciphersuites(ctx, cs.as_ptr()) } == 0 {
            eprintln!("Error setting TLSv1.3 ciphersuites");
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { BIO_free(err) };
            // SAFETY: `ctx` is live and not freed again.
            unsafe { SSL_CTX_free(ctx) };
            return ret;
        }
    }

    if let Some(list) = &ciphers {
        // `if (ciphers != NULL) { if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
        // BIO_printf(bio_err, "Error in cipher list\n"); goto err; } }` —
        // `apps/ciphers.c:214-219`.
        let cs = match std::ffi::CString::new(list.as_str()) {
            Ok(c) => c,
            Err(_) => {
                // SAFETY: `ctx` is live and not freed again.
                unsafe { SSL_CTX_free(ctx) };
                return ret;
            }
        };
        // SAFETY: `ctx` is live and `cs` is NUL-terminated.
        if unsafe { SSL_CTX_set_cipher_list(ctx, cs.as_ptr()) } == 0 {
            eprintln!("Error in cipher list");
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { BIO_free(err) };
            // SAFETY: `ctx` is live and not freed again.
            unsafe { SSL_CTX_free(ctx) };
            return ret;
        }
    }

    // `ssl = SSL_new(ctx); if (ssl == NULL) goto err;` — `apps/ciphers.c:220-222`.
    // SAFETY: `ctx` is live.
    let ssl = unsafe { SSL_new(ctx) };
    if ssl.is_null() {
        let err = bio_err();
        // SAFETY: `err` is a live stderr BIO.
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE.
        unsafe { BIO_free(err) };
        // SAFETY: `ctx` is live and not freed again.
        unsafe { SSL_CTX_free(ctx) };
        return ret;
    }

    // `if (use_supported) sk = SSL_get1_supported_ciphers(ssl); else sk =
    // SSL_get_ciphers(ssl);` — `apps/ciphers.c:224-227`.
    let sk: *mut OpenSslStack = if use_supported {
        // SAFETY: `ssl` is live.
        unsafe { SSL_get1_supported_ciphers(ssl) }
    } else {
        // SAFETY: `ssl` is live.
        unsafe { SSL_get_ciphers(ssl) }
    };

    let out = bio_out();
    if !verbose {
        // `for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) { c =
        // sk_SSL_CIPHER_value(sk, i); p = SSL_CIPHER_get_name(c); if (p == NULL)
        // break; if (i != 0) BIO_printf(bio_out, ":"); BIO_printf(bio_out, "%s",
        // p); } BIO_printf(bio_out, "\n");` — `apps/ciphers.c:229-243`.
        // SAFETY: `sk` is a live cipher stack.
        let n = unsafe { OPENSSL_sk_num(sk) };
        for i in 0..n {
            // SAFETY: `sk` is live and `i` is in bounds.
            let c = unsafe { OPENSSL_sk_value(sk, i) }.cast::<SslCipher>();
            // SAFETY: `c` is a live cipher.
            let p = unsafe { SSL_CIPHER_get_name(c) };
            if p.is_null() {
                break;
            }
            if i != 0 {
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_printf(out, c":".as_ptr()) };
            }
            // SAFETY: `out` is live and `p` is NUL-terminated.
            unsafe { BIO_printf(out, c"%s".as_ptr(), p) };
        }
        // SAFETY: `out` is live and the literal is static.
        unsafe { BIO_printf(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `sk` is a live cipher stack.
        let n = unsafe { OPENSSL_sk_num(sk) };
        for i in 0..n {
            // SAFETY: `sk` is live and `i` is in bounds.
            let c = unsafe { OPENSSL_sk_value(sk, i) }.cast::<SslCipher>();
            if verboselong {
                // `unsigned long id = SSL_CIPHER_get_id(c); ...` —
                // `apps/ciphers.c:254-266`.
                // SAFETY: `c` is a live cipher.
                let id = unsafe { SSL_CIPHER_get_id(c) };
                let id0 = (id >> 24) as c_int;
                let id1 = ((id >> 16) & 0xff) as c_int;
                let id2 = ((id >> 8) & 0xff) as c_int;
                let id3 = (id & 0xff) as c_int;
                if (id & 0xff00_0000) == 0x0300_0000 {
                    // SAFETY: `out` is live and the format is static.
                    unsafe { BIO_printf(out, c"          0x%02X,0x%02X - ".as_ptr(), id2, id3) };
                } else {
                    // SAFETY: `out` is live and the format is static.
                    unsafe {
                        BIO_printf(
                            out,
                            c"0x%02X,0x%02X,0x%02X,0x%02X - ".as_ptr(),
                            id0,
                            id1,
                            id2,
                            id3,
                        )
                    };
                }
            }
            if stdname {
                // `const char *nm = SSL_CIPHER_standard_name(c); if (nm == NULL) nm
                // = "UNKNOWN"; BIO_printf(bio_out, "%-45s - ", nm);` —
                // `apps/ciphers.c:267-272`.
                // SAFETY: `c` is a live cipher.
                let nm = unsafe { SSL_CIPHER_standard_name(c) };
                let nm = if nm.is_null() {
                    c"UNKNOWN".as_ptr()
                } else {
                    nm
                };
                // SAFETY: `out` is live and `nm` is NUL-terminated.
                unsafe { BIO_printf(out, c"%-45s - ".as_ptr(), nm) };
            }
            // `BIO_puts(bio_out, SSL_CIPHER_description(c, buf, sizeof(buf)));` —
            // `apps/ciphers.c:273`.
            let mut buf = [0 as c_char; 512];
            // SAFETY: `c` is live and `buf` is 512 writable bytes.
            let desc = unsafe { SSL_CIPHER_description(c, buf.as_mut_ptr(), 512) };
            if !desc.is_null() {
                // SAFETY: `out` is live and `desc` is NUL-terminated.
                unsafe { crate::runtime::bio::iolib::BIO_puts(out, desc) };
            }
        }
    }
    // SAFETY: `out` is NOCLOSE.
    unsafe { BIO_free(out) };

    // `ret = 0;` — `apps/ciphers.c:277`.
    ret = 0;

    // `end: if (use_supported) sk_SSL_CIPHER_free(sk); SSL_CTX_free(ctx);
    // SSL_free(ssl);` — `apps/ciphers.c:282-286`. `sk_SSL_CIPHER_free` is the
    // stack free; the supported-cipher stack is the only owned one.
    if use_supported {
        // SAFETY: `sk` is the stack from `SSL_get1_supported_ciphers`, or NULL.
        unsafe { OPENSSL_sk_free(sk) };
    }
    // SAFETY: `ctx` is live and not freed again.
    unsafe { SSL_CTX_free(ctx) };
    // SAFETY: `ssl` is live and not freed again.
    unsafe { SSL_free(ssl) };
    ret
}
