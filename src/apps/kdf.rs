//! Phase 17.1 — `apps/kdf.c`: the `openssl kdf` command.
//!
//! The whole command body (`apps/kdf.c:75-216`): parse the generated
//! `KDF_OPTIONS` table, fetch the named `EVP_KDF` and build its context, apply the
//! `-kdfopt`/`-cipher`/`-digest`/`-mac` parameters, derive `-keylen` bytes and
//! print them as hex (or raw with `-binary`). Every libcrypto function the body
//! reaches is landed: `EVP_KDF_fetch`, `EVP_KDF_CTX_new`,
//! `EVP_KDF_settable_ctx_params`, `EVP_KDF_CTX_set_params`, `EVP_KDF_derive`,
//! `EVP_KDF_free`, `EVP_KDF_CTX_free`, `OSSL_PARAM_allocate_from_text` and
//! `OPENSSL_buf2hexstr`.
//!
//! ## What the court drives
//!
//! `kdf PBKDF2` over fixed `-kdfopt` pairs (`pass`, `salt`, `iter`, `digest`) and
//! a fixed `-keylen`, plus the deterministic refusal
//! arms: no KDF name, a non-positive `-keylen` (`Invalid derived key length.`) and
//! `kdf` with no name. The derived key is a pure function of the fixed parameters.
//! The `-binary` arm was verified byte-identical too but is not in the probe: the
//! transcript harness decodes each side's output as UTF-8 text, so a binary arm
//! cannot be diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **An unknown KDF name is not diffed.** `kdf nonexistent` prints the same
//!   `Invalid KDF name nonexistent` and summary lines on both sides, but the
//!   authority's `EVP_KDF_fetch` raises `inner_evp_generic_fetch:unsupported` and
//!   its `err:`-label `ERR_print_errors` emits that line, while the crate's fetch
//!   returns NULL without raising, so the candidate's queue is empty. The line
//!   begins with a per-run pointer anyway. Recorded in the court's
//!   `recorded_divergences` rather than diffed.
//! * **`app_params_new_from_opts` is reduced to its observable.** The authority
//!   converts the option stack through `apps/lib/apps.c:3477-3523`; this module
//!   transcribes that function inline against the landed `OSSL_PARAM_allocate_from_text`
//!   so a malformed `-kdfopt` renders the same `Parameter error/unknown '<opt>'`
//!   text. The `ERR_print_errors` tail is not reproduced (it renders
//!   pointer-bearing lines), and such an arm is not driven.
//! * **`app_get0_libctx`/`app_get0_propq` are reduced to their observable.** The
//!   two `apps/lib` accessors answer `NULL`/`NULL` when no `-libctx`/`-propquery`
//!   is given, which is the fixed default this module passes.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::configutl`]'s header for the same shape).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/kdf.c:133-136`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::KDF_OPTIONS;
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch,
    EVP_KDF_free, EVP_KDF_settable_ctx_params,
};
use crate::params::from_text::OSSL_PARAM_allocate_from_text;
use crate::params::{OSSL_PARAM_construct_end, OsslParam};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_buf2hexstr;

/// `atoi(s)` — the `stdlib.h` decimal conversion `-keylen` uses
/// (`apps/kdf.c:104`). Leading whitespace and an optional sign are skipped, the
/// run of decimal digits is converted, and no digit yields 0.
fn atoi(s: &str) -> c_int {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: c_int = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add(c_int::from(b[i] - b'0'));
        i += 1;
    }
    if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

/// `app_malloc(num, ...)` — `apps/lib/apps.c`, reduced to the allocation the body
/// observes.
fn app_malloc(num: usize) -> *mut c_void {
    // SAFETY: a non-zero size and a static file/line label.
    CRYPTO_malloc(num, c"apps/kdf.c".as_ptr(), 182)
}

/// `app_params_new_from_opts(opts, paramdefs)` — `apps/lib/apps.c:3477-3523`,
/// transcribed inline (see the header). Returns a `key`-terminated `OSSL_PARAM`
/// array allocated with the crate's allocator, or NULL on a malformed option.
fn app_params_new_from_opts(opts: &[String], paramdefs: *const OsslParam) -> *mut OsslParam {
    if opts.is_empty() {
        // `if (opts == NULL) return NULL;` — `apps/lib/apps.c:3486-3487`.
        return ptr::null_mut();
    }
    let sz = opts.len();
    // `params = OPENSSL_calloc(sz + 1, sizeof(OSSL_PARAM));` —
    // `apps/lib/apps.c:3489-3491`.
    let params = CRYPTO_zalloc(
        (sz + 1) * core::mem::size_of::<OsslParam>(),
        c"apps/lib/apps.c".as_ptr(),
        3489,
    )
    .cast::<OsslParam>();
    if params.is_null() {
        return ptr::null_mut();
    }

    for (i, opt) in opts.iter().enumerate() {
        // `if ((stmp = OPENSSL_strdup(opt)) == NULL || (vtmp = strchr(stmp, ':'))
        // == NULL) goto err; *vtmp = 0; vtmp++;` — `apps/lib/apps.c:3494-3499`.
        let (key, value) = match opt.split_once(':') {
            Some(kv) => kv,
            None => {
                // `BIO_printf(bio_err, "Parameter %s '%s'\n", found ? "error" :
                // "unknown", opt); ERR_print_errors(bio_err); app_params_free(params);`
                // — `apps/lib/apps.c:3512-3516`. Not driven.
                eprintln!("Parameter error '{opt}'");
                app_params_free(params);
                return ptr::null_mut();
            }
        };
        let Ok(key_c) = std::ffi::CString::new(key) else {
            eprintln!("Parameter error '{opt}'");
            app_params_free(params);
            return ptr::null_mut();
        };
        let Ok(value_c) = std::ffi::CString::new(value) else {
            eprintln!("Parameter error '{opt}'");
            app_params_free(params);
            return ptr::null_mut();
        };
        // `if (!OSSL_PARAM_allocate_from_text(&params[params_n], paramdefs, stmp,
        // vtmp, strlen(vtmp), &found)) goto err;` — `apps/lib/apps.c:3500-3502`.
        let mut found: c_int = 1;
        // SAFETY: `params` has `sz + 1` entries and `i < sz`; `key_c`/`value_c` are
        // NUL-terminated; `paramdefs` is the provider's live definition table.
        let ok = unsafe {
            OSSL_PARAM_allocate_from_text(
                params.add(i),
                paramdefs,
                key_c.as_ptr(),
                value_c.as_ptr(),
                value.len(),
                &mut found,
            )
        };
        if ok == 0 {
            // `BIO_printf(bio_err, "Parameter %s '%s'\n", found ? "error" :
            // "unknown", opt);` — `apps/lib/apps.c:3512-3514`. The label follows
            // `found`: non-zero means the value was unusable (`error`), zero means
            // no such parameter (`unknown`).
            let label = if found != 0 { "error" } else { "unknown" };
            eprintln!("Parameter {label} '{opt}'");
            app_params_free(params);
            return ptr::null_mut();
        }
    }
    // `params[params_n] = OSSL_PARAM_construct_end();` — `apps/lib/apps.c:3505`.
    // SAFETY: the array has `sz + 1` entries; the last is the terminator.
    unsafe { *params.add(sz) = OSSL_PARAM_construct_end() };
    params
}

/// `app_params_free(params)` — `apps/lib/apps.c:3525-3532`.
fn app_params_free(params: *mut OsslParam) {
    if params.is_null() {
        return;
    }
    let mut i = 0usize;
    loop {
        // SAFETY: `params` is a `key`-terminated array allocated for this call.
        let entry = unsafe { &*params.add(i) };
        if entry.key.is_null() {
            break;
        }
        // SAFETY: `entry.data` was allocated by `OSSL_PARAM_allocate_from_text`.
        unsafe { CRYPTO_free(entry.data, c"apps/lib/apps.c".as_ptr(), 3529) };
        i += 1;
    }
    // SAFETY: `params` is the block from `app_params_new_from_opts`.
    unsafe { CRYPTO_free(params.cast(), c"apps/lib/apps.c".as_ptr(), 3531) };
}

/// `bio_open_default(filename, mode, format)` — the stdio/file split.
fn bio_open(filename: Option<&str>, writing: bool) -> *mut Bio {
    match filename {
        None | Some("-") => {
            // SAFETY: `stdout`/`stdin` are the C library's live standard stream pointers.
            let fp = unsafe {
                if writing {
                    stdout
                } else {
                    stdin
                }
            };
            // SAFETY: `fp` is one of the C library's live standard streams.
            unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) }
        }
        Some(path) => {
            let cs = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return ptr::null_mut(),
            };
            let mode = if writing { c"w" } else { c"r" };
            // SAFETY: `cs` is NUL-terminated and outlives the call.
            unsafe { BIO_new_file(cs.as_ptr(), mode.as_ptr()) }
        }
    }
}

/// `int kdf_main(int argc, char **argv)` — `apps/kdf.c:75-216`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, kdf_options);` — `apps/kdf.c:89`.
    let mut opts = Opts::init(argv, KDF_OPTIONS);
    let mut ret = 1i32;
    let mut out_bin = false;
    let mut dkm_len: c_int = 0;
    let mut outfile: Option<String> = None;
    // `STACK_OF(OPENSSL_STRING) *opts = NULL;` — `apps/kdf.c:79`; the pushed
    // `-kdfopt` and synthesized `-cipher`/`-digest`/`-mac` values.
    let mut optstack: Vec<String> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/kdf.c:90`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(kdf_options); ret = 0; goto err;` —
            // `apps/kdf.c:96-99`.
            OptMatch::Help => return not_landed("kdf -help"),
            // `default: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog); goto err;` — `apps/kdf.c:92-95`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_BIN: out_bin = 1; break;` — `apps/kdf.c:100-102`.
            OptMatch::Flag("binary") => out_bin = true,
            // `case OPT_KEYLEN: dkm_len = atoi(opt_arg()); break;` —
            // `apps/kdf.c:103-105`. The authority's `opt_next` does not
            // syntax-check `s` values, and `-keylen` is `s` in the generated table
            // (`apps/kdf.c:42`), so `atoi` sees the raw string.
            OptMatch::Value("keylen", v) => dkm_len = atoi(&v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/kdf.c:106-108`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_KDFOPT: ... sk_OPENSSL_STRING_push(opts, opt_arg());` —
            // `apps/kdf.c:109-114`.
            OptMatch::Value("kdfopt", v) => optstack.push(v),
            // `case OPT_CIPHER: ... cipher = alloc_kdf_algorithm_name(&opts,
            // "cipher", opt_arg());` — `apps/kdf.c:115-120`.
            OptMatch::Value("cipher", v) => optstack.push(format!("cipher:{v}")),
            // `case OPT_DIGEST: ... digest = alloc_kdf_algorithm_name(&opts,
            // "digest", opt_arg());` — `apps/kdf.c:121-126`.
            OptMatch::Value("digest", v) => optstack.push(format!("digest:{v}")),
            // `case OPT_MAC: ... mac = alloc_kdf_algorithm_name(&opts, "mac",
            // opt_arg());` — `apps/kdf.c:127-132`.
            OptMatch::Value("mac", v) => optstack.push(format!("mac:{v}")),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto err;` —
            // `apps/kdf.c:133-136`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("kdf -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (argc != 1) goto opthelp;` —
    // `apps/kdf.c:141-144`. `opthelp` prints the summary line and goes to `err`.
    if opts.num_rest() != 1 {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return ret;
    }
    let kdf_name = opts.rest()[0].clone();

    // `if ((kdf = EVP_KDF_fetch(app_get0_libctx(), argv[0], app_get0_propq())) ==
    // NULL) { BIO_printf(bio_err, "Invalid KDF name %s\n", argv[0]); goto opthelp;
    // }` — `apps/kdf.c:146-151`. The two accessors answer NULL for the fixed
    // default (see the header).
    let Ok(name_c) = std::ffi::CString::new(kdf_name.as_str()) else {
        eprintln!("Invalid KDF name {kdf_name}");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return ret;
    };
    // SAFETY: `name_c` is NUL-terminated; both context pointers are NULL.
    let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), name_c.as_ptr(), ptr::null()) };
    if kdf.is_null() {
        eprintln!("Invalid KDF name {kdf_name}");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return ret;
    }

    // `ctx = EVP_KDF_CTX_new(kdf); if (ctx == NULL) goto err;` —
    // `apps/kdf.c:153-155`.
    // SAFETY: `kdf` is live.
    let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
    if ctx.is_null() {
        // SAFETY: `kdf` is live and not freed again.
        unsafe { EVP_KDF_free(kdf) };
        return ret;
    }

    if !optstack.is_empty() {
        // `OSSL_PARAM *params = app_params_new_from_opts(opts,
        // EVP_KDF_settable_ctx_params(kdf)); if (params == NULL) goto err;` —
        // `apps/kdf.c:157-162`.
        // SAFETY: `kdf` is live.
        let paramdefs = unsafe { EVP_KDF_settable_ctx_params(kdf) };
        let params = app_params_new_from_opts(&optstack, paramdefs);
        if params.is_null() {
            // SAFETY: `ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_CTX_free(ctx) };
            // SAFETY: `ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_free(kdf) };
            return ret;
        }
        // `if (!EVP_KDF_CTX_set_params(ctx, params)) { BIO_printf(bio_err, "KDF
        // parameter error\n"); ERR_print_errors(bio_err); ok = 0; }` —
        // `apps/kdf.c:164-169`.
        // SAFETY: `ctx` is live and `params` is the terminated array.
        if unsafe { EVP_KDF_CTX_set_params(ctx, params) } == 0 {
            // Not driven: `ERR_print_errors` renders pointer-bearing lines.
            eprintln!("KDF parameter error");
            app_params_free(params);
            // SAFETY: `ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_CTX_free(ctx) };
            // SAFETY: `ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_free(kdf) };
            return ret;
        }
        app_params_free(params);
    }

    // `out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY :
    // FORMAT_TEXT); if (out == NULL) goto err;` — `apps/kdf.c:174-176`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_CTX_free(ctx) };
        // SAFETY: `ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_free(kdf) };
        return not_landed("kdf -out (unopenable)");
    }

    // `if (dkm_len <= 0) { BIO_printf(bio_err, "Invalid derived key length.\n");
    // goto err; }` — `apps/kdf.c:178-181`.
    if dkm_len <= 0 {
        eprintln!("Invalid derived key length.");
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { BIO_free(out) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_CTX_free(ctx) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_free(kdf) };
        return ret;
    }

    // `dkm_bytes = app_malloc(dkm_len, "out buffer"); if (dkm_bytes == NULL) goto
    // err;` — `apps/kdf.c:182-184`.
    let dkm_bytes = app_malloc(dkm_len as usize).cast::<u8>();
    if dkm_bytes.is_null() {
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { BIO_free(out) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_CTX_free(ctx) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_free(kdf) };
        return ret;
    }

    // `if (!EVP_KDF_derive(ctx, dkm_bytes, dkm_len, NULL)) { BIO_printf(bio_err,
    // "EVP_KDF_derive failed\n"); goto err; }` — `apps/kdf.c:186-189`.
    // SAFETY: `ctx` is live and `dkm_bytes` is `dkm_len` writable bytes.
    if unsafe { EVP_KDF_derive(ctx, dkm_bytes, dkm_len as usize, ptr::null()) } == 0 {
        eprintln!("EVP_KDF_derive failed");
        // SAFETY: `dkm_bytes` is the block from `app_malloc`; freed under
        // `OPENSSL_clear_free`.
        unsafe { CRYPTO_free(dkm_bytes.cast(), c"apps/kdf.c".as_ptr(), 206) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { BIO_free(out) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_CTX_free(ctx) };
        // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
        unsafe { EVP_KDF_free(kdf) };
        return ret;
    }

    if out_bin {
        // `BIO_write(out, dkm_bytes, dkm_len);` — `apps/kdf.c:192`.
        // SAFETY: `out` is live and `dkm_bytes` is `dkm_len` readable bytes.
        unsafe { crate::runtime::bio::iolib::BIO_write(out, dkm_bytes.cast(), dkm_len) };
    } else {
        // `hexout = OPENSSL_buf2hexstr(dkm_bytes, dkm_len); ... BIO_printf(out,
        // "%s\n\n", hexout);` — `apps/kdf.c:194-199`.
        // SAFETY: `dkm_bytes` is `dkm_len` readable bytes.
        let hexout = unsafe { OPENSSL_buf2hexstr(dkm_bytes, dkm_len as c_long) };
        if hexout.is_null() {
            eprintln!("Memory allocation failure");
            // SAFETY: `dkm_bytes` is the block from `app_malloc`.
            unsafe { CRYPTO_free(dkm_bytes.cast(), c"apps/kdf.c".as_ptr(), 206) };
            // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
            unsafe { BIO_free(out) };
            // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_CTX_free(ctx) };
            // SAFETY: `out`/`ctx`/`kdf` are live and not freed again.
            unsafe { EVP_KDF_free(kdf) };
            return ret;
        }
        // `BIO_printf(out, "%s\n\n", hexout);` — `apps/kdf.c:199`.
        // SAFETY: `out` is live and `hexout` is NUL-terminated.
        unsafe { BIO_printf(out, c"%s\n\n".as_ptr(), hexout.cast_const()) };
        // SAFETY: `hexout` is the block from `OPENSSL_buf2hexstr`.
        unsafe { CRYPTO_free(hexout.cast(), c"apps/kdf.c".as_ptr(), 211) };
    }

    // `ret = 0;` — `apps/kdf.c:202`.
    ret = 0;

    // `err: if (ret != 0) ERR_print_errors(bio_err); OPENSSL_clear_free(dkm_bytes,
    // dkm_len); ... BIO_free(out); ...` — `apps/kdf.c:203-214`.
    // SAFETY: `dkm_bytes` is the block from `app_malloc`.
    unsafe { CRYPTO_free(dkm_bytes.cast(), c"apps/kdf.c".as_ptr(), 206) };
    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free(out) };
    // SAFETY: `ctx` is live and not freed again.
    unsafe { EVP_KDF_CTX_free(ctx) };
    // SAFETY: `kdf` is live and not freed again.
    unsafe { EVP_KDF_free(kdf) };
    ret
}
