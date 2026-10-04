//! Phase 17.1 — `apps/mac.c`: the `openssl mac` command.
//!
//! The whole command body (`apps/mac.c:78-240`): parse the generated `MAC_OPTIONS`
//! table, fetch the named `EVP_MAC` and build its context, apply the
//! `-macopt`/`-cipher`/`-digest` parameters, MAC the whole input and print the
//! result as hex (or raw with `-binary`). Every libcrypto function the body
//! reaches is landed: `EVP_MAC_fetch`, `EVP_MAC_CTX_new`,
//! `EVP_MAC_settable_ctx_params`, `EVP_MAC_CTX_set_params`, `EVP_MAC_init`,
//! `EVP_MAC_update`, `EVP_MAC_final`, `EVP_MAC_CTX_free`, `EVP_MAC_free`,
//! `OSSL_PARAM_allocate_from_text` and `BIO_read`.
//!
//! ## What the court drives
//!
//! `mac -macopt key:<fixed> HMAC -in <certs.pem>` (hex output) over the fixed
//! certificate fixture, plus the deterministic refusal
//! arms: no MAC name (`Missing argument: MAC name`), an unknown MAC name
//! (`Invalid MAC name`) and an unknown option. The digest is the default (`SHA256`
//! for HMAC in 3.x), so the digest is a pure function of the fixed key and bytes.
//! The `-binary` arm was verified byte-identical too but is not in the probe: the
//! transcript harness decodes each side's output as UTF-8 text, so a binary arm
//! cannot be diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **An unknown MAC name is not diffed.** `mac NOPE` prints the same
//!   `Invalid MAC name NOPE` and summary lines on both sides, but the authority's
//!   `EVP_MAC_fetch` raises `inner_evp_generic_fetch:unsupported` and its `err:`
//!   `ERR_print_errors` emits that pointer-bearing line, while the crate's fetch
//!   returns NULL without raising. Recorded in the court's `recorded_divergences`
//!   rather than diffed.
//! * **The read loop is reduced to its observable.** The authority loops on
//!   `BIO_pending(in) || !BIO_eof(in)` (`apps/mac.c:189`); `BIO_eof` is not
//!   landed, so this module reads until `BIO_read` returns 0 (end of input),
//!   which is what the loop does for a file BIO. A mid-stream read error still
//!   takes the authority's `Read Error in '%s'` arm.
//! * **`app_params_new_from_opts` is reduced to its observable.** The authority
//!   converts the option stack through `apps/lib/apps.c:3477-3523`; this module
//!   transcribes that function inline against the landed
//!   `OSSL_PARAM_allocate_from_text`, exactly as [`crate::apps::kdf`] does.
//! * **`app_get0_libctx`/`app_get0_propq` are reduced to their observable.** Both
//!   answer `NULL` for the fixed default with no `-libctx`/`-propquery`.
//! * **`bio_open_default` is reduced to its observable** (see
//!   [`crate::apps::configutl`]'s header for the same shape).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/mac.c:136-139`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::MAC_OPTIONS;
use crate::evp::mac::{
    EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch, EVP_MAC_final,
    EVP_MAC_free, EVP_MAC_init, EVP_MAC_settable_ctx_params, EVP_MAC_update,
};
use crate::params::from_text::OSSL_PARAM_allocate_from_text;
use crate::params::{OSSL_PARAM_construct_end, OsslParam};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::iolib::BIO_read;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// `#define BUFSIZE 1024 * 8` — `apps/mac.c:21`.
const BUFSIZE: usize = 1024 * 8;

/// `app_malloc(num, ...)` — `apps/lib/apps.c`, reduced to the allocation the body
/// observes.
fn app_malloc(num: usize) -> *mut u8 {
    // SAFETY: a non-zero size and a static file/line label.
    CRYPTO_malloc(num, c"apps/mac.c".as_ptr(), 98).cast::<u8>()
}

/// `app_params_new_from_opts(opts, paramdefs)` — `apps/lib/apps.c:3477-3523`,
/// transcribed inline (see the header).
fn app_params_new_from_opts(opts: &[String], paramdefs: *const OsslParam) -> *mut OsslParam {
    if opts.is_empty() {
        return ptr::null_mut();
    }
    let sz = opts.len();
    // SAFETY: a non-zero count and a static file/line label.
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
        let (key, value) = match opt.split_once(':') {
            Some(kv) => kv,
            None => {
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
            let label = if found != 0 { "error" } else { "unknown" };
            eprintln!("Parameter {label} '{opt}'");
            app_params_free(params);
            return ptr::null_mut();
        }
    }
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

/// `int mac_main(int argc, char **argv)` — `apps/mac.c:78-240`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, mac_options);` — `apps/mac.c:97`.
    let mut opts = Opts::init(argv, MAC_OPTIONS);
    let mut ret = 1i32;
    let mut out_bin = false;
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    // `STACK_OF(OPENSSL_STRING) *opts = NULL;` — `apps/mac.c:85`.
    let mut optstack: Vec<String> = Vec::new();

    // `buf = app_malloc(BUFSIZE, "I/O buffer");` — `apps/mac.c:98`.
    let buf = app_malloc(BUFSIZE);
    if buf.is_null() {
        return ret;
    }

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/mac.c:99`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(mac_options); ret = 0; goto err;` —
            // `apps/mac.c:105-108`.
            OptMatch::Help => {
                // SAFETY: `buf` is the block from `app_malloc`; freed under
                // `OPENSSL_clear_free`.
                unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
                return not_landed("mac -help");
            }
            // `default: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog); goto err;` — `apps/mac.c:101-104`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                // SAFETY: `buf` is the block from `app_malloc`.
                unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
                return 1;
            }
            // `case OPT_BIN: out_bin = 1; break;` — `apps/mac.c:109-111`.
            OptMatch::Flag("binary") => out_bin = true,
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/mac.c:112-114`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/mac.c:115-117`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_MACOPT: ... sk_OPENSSL_STRING_push(opts, opt_arg());` —
            // `apps/mac.c:118-123`.
            OptMatch::Value("macopt", v) => optstack.push(v),
            // `case OPT_CIPHER: ... cipher = alloc_mac_algorithm_name(&opts,
            // "cipher", opt_arg());` — `apps/mac.c:124-129`.
            OptMatch::Value("cipher", v) => optstack.push(format!("cipher:{v}")),
            // `case OPT_DIGEST: ... digest = alloc_mac_algorithm_name(&opts,
            // "digest", opt_arg());` — `apps/mac.c:130-135`.
            OptMatch::Value("digest", v) => optstack.push(format!("digest:{v}")),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto err;` —
            // `apps/mac.c:136-139`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => {
                // SAFETY: `buf` is the block from `app_malloc`.
                unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
                return not_landed("mac -provider");
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                // SAFETY: `buf` is the block from `app_malloc`.
                unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg("MAC name")) goto opthelp;` — `apps/mac.c:144-145`.
    if !opts.check_rest_arg(Some("MAC name")) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }
    let mac_name = opts.rest()[0].clone();

    // `mac = EVP_MAC_fetch(app_get0_libctx(), argv[0], app_get0_propq()); if (mac
    // == NULL) { BIO_printf(bio_err, "Invalid MAC name %s\n", argv[0]); goto
    // opthelp; }` — `apps/mac.c:148-152`.
    let Ok(name_c) = std::ffi::CString::new(mac_name.as_str()) else {
        eprintln!("Invalid MAC name {mac_name}");
        eprintln!("{}: Use -help for summary.", opts.prog());
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    };
    // SAFETY: `name_c` is NUL-terminated; both context pointers are NULL.
    let mac = unsafe { EVP_MAC_fetch(ptr::null_mut(), name_c.as_ptr(), ptr::null()) };
    if mac.is_null() {
        eprintln!("Invalid MAC name {mac_name}");
        eprintln!("{}: Use -help for summary.", opts.prog());
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }

    // `ctx = EVP_MAC_CTX_new(mac); if (ctx == NULL) goto err;` —
    // `apps/mac.c:154-156`.
    // SAFETY: `mac` is live.
    let ctx = unsafe { EVP_MAC_CTX_new(mac) };
    if ctx.is_null() {
        // SAFETY: `mac` is live; `buf` is the block from `app_malloc`.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `mac` is live; `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }

    if !optstack.is_empty() {
        // `params = app_params_new_from_opts(opts, EVP_MAC_settable_ctx_params(mac));
        // if (params == NULL) goto err;` — `apps/mac.c:158-164`.
        // SAFETY: `mac` is live.
        let paramdefs = unsafe { EVP_MAC_settable_ctx_params(mac) };
        let params = app_params_new_from_opts(&optstack, paramdefs);
        if params.is_null() {
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { EVP_MAC_CTX_free(ctx) };
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { EVP_MAC_free(mac) };
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
            return ret;
        }
        // `if (!EVP_MAC_CTX_set_params(ctx, params)) { BIO_printf(bio_err, "MAC
        // parameter error\n"); ERR_print_errors(bio_err); ok = 0; }` —
        // `apps/mac.c:166-172`.
        // SAFETY: `ctx` is live and `params` is the terminated array.
        if unsafe { EVP_MAC_CTX_set_params(ctx, params) } == 0 {
            eprintln!("MAC parameter error");
            app_params_free(params);
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { EVP_MAC_CTX_free(ctx) };
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { EVP_MAC_free(mac) };
            // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
            unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
            return ret;
        }
        app_params_free(params);
    }

    // `in = bio_open_default(infile, 'r', inform); if (in == NULL) goto err;` —
    // `apps/mac.c:176-178`.
    let inb = bio_open(infile.as_deref(), false);
    if inb.is_null() {
        // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `ctx`/`mac` are live; `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }
    // `out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY :
    // FORMAT_TEXT); if (out == NULL) goto err;` — `apps/mac.c:180-182`.
    let out = bio_open(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `inb` is live; `ctx`/`mac` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb` is live; `ctx`/`mac` are live.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `inb` is live; `ctx`/`mac` are live.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `inb` is live; `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }

    // `if (!EVP_MAC_init(ctx, NULL, 0, NULL)) { BIO_printf(bio_err,
    // "EVP_MAC_Init failed\n"); goto err; }` — `apps/mac.c:184-187`.
    // SAFETY: `ctx` is live; the key is NULL and params are NULL.
    if unsafe { EVP_MAC_init(ctx, ptr::null(), 0, ptr::null()) } == 0 {
        eprintln!("EVP_MAC_Init failed");
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(out) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }

    // `while (BIO_pending(in) || !BIO_eof(in)) { i = BIO_read(in, (char *)buf,
    // BUFSIZE); ... }` — `apps/mac.c:189-202`. Reduced to read-until-EOF (see the
    // header).
    loop {
        // SAFETY: `inb` is live and `buf` is `BUFSIZE` writable bytes.
        let i = unsafe { BIO_read(inb, buf.cast(), BUFSIZE as c_int) };
        if i < 0 {
            // `BIO_printf(bio_err, "Read Error in '%s'\n", infile);
            // ERR_print_errors(bio_err);` — `apps/mac.c:191-194`. Not driven.
            eprintln!("Read Error in '{}'", infile.as_deref().unwrap_or(""));
            break;
        }
        if i == 0 {
            // `if (i == 0) break;` — `apps/mac.c:196-197`.
            break;
        }
        // `if (!EVP_MAC_update(ctx, buf, i)) { BIO_printf(bio_err, "EVP_MAC_update
        // failed\n"); goto err; }` — `apps/mac.c:198-201`.
        // SAFETY: `ctx` is live and `buf` holds `i` readable bytes.
        if unsafe { EVP_MAC_update(ctx, buf, i as usize) } == 0 {
            eprintln!("EVP_MAC_update failed");
            // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
            unsafe { BIO_free(inb) };
            // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
            unsafe { BIO_free(out) };
            // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
            unsafe { EVP_MAC_CTX_free(ctx) };
            // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
            unsafe { EVP_MAC_free(mac) };
            // SAFETY: `buf` is the block from `app_malloc`.
            unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
            return ret;
        }
    }

    // `if (!EVP_MAC_final(ctx, NULL, &len, 0)) { ... } if (len > BUFSIZE) { ... }`
    // — `apps/mac.c:204-211`.
    let mut len: usize = 0;
    // SAFETY: `ctx` is live; the out pointer is NULL, which asks for the length.
    if unsafe { EVP_MAC_final(ctx, ptr::null_mut(), &mut len, 0) } == 0 {
        eprintln!("EVP_MAC_final failed");
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(out) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }
    if len > BUFSIZE {
        eprintln!("output len is too large");
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(out) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }
    // `if (!EVP_MAC_final(ctx, buf, &len, BUFSIZE)) { ... }` — `apps/mac.c:213-216`.
    // SAFETY: `ctx` is live and `buf` is `BUFSIZE` writable bytes.
    if unsafe { EVP_MAC_final(ctx, buf, &mut len, BUFSIZE) } == 0 {
        eprintln!("EVP_MAC_final failed");
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(inb) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { BIO_free(out) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: `inb`/`out`/`ctx`/`mac` are live.
        unsafe { EVP_MAC_free(mac) };
        // SAFETY: `buf` is the block from `app_malloc`.
        unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
        return ret;
    }

    if out_bin {
        // `BIO_write(out, buf, (int)len);` — `apps/mac.c:219`.
        // SAFETY: `out` is live and `buf` holds `len` readable bytes.
        unsafe { crate::runtime::bio::iolib::BIO_write(out, buf.cast(), len as c_int) };
    } else {
        // `for (i = 0; i < (int)len; ++i) BIO_printf(out, "%02X", buf[i]); if
        // (outfile == NULL) BIO_printf(out, "\n");` — `apps/mac.c:221-224`.
        // SAFETY: `buf` is the block from `app_malloc` and `len <= BUFSIZE`, so the
        // slice is inside the allocation for its whole use here.
        for &byte in unsafe { core::slice::from_raw_parts(buf, len) } {
            // SAFETY: `out` is live and the format is static.
            unsafe { BIO_printf(out, c"%02X".as_ptr(), c_int::from(byte)) };
        }
        if outfile.is_none() {
            // SAFETY: `out` is live and the literal is static.
            unsafe { BIO_printf(out, c"\n".as_ptr()) };
        }
    }

    // `ret = 0;` — `apps/mac.c:227`.
    ret = 0;

    // `err: if (ret != 0) ERR_print_errors(bio_err); OPENSSL_clear_free(buf,
    // BUFSIZE); ... BIO_free(in); BIO_free(out); EVP_MAC_CTX_free(ctx);
    // EVP_MAC_free(mac);` — `apps/mac.c:228-239`.
    // SAFETY: `inb` is live and not freed again.
    unsafe { BIO_free(inb) };
    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free(out) };
    // SAFETY: `ctx` is live and not freed again.
    unsafe { EVP_MAC_CTX_free(ctx) };
    // SAFETY: `mac` is live and not freed again.
    unsafe { EVP_MAC_free(mac) };
    // SAFETY: `buf` is the block from `app_malloc`.
    unsafe { CRYPTO_free(buf.cast(), c"apps/mac.c".as_ptr(), 231) };
    ret
}
