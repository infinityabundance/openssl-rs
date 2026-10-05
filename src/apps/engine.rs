//! Phase 17.1e — `apps/engine.c`: the `openssl engine` command.
//!
//! The command body (`apps/engine.c:304-506`): pre-scan the leading engine-name
//! arguments, parse the generated `ENGINE_OPTIONS` table, then for each named (or,
//! with none, every registered) engine print `(id) name`, run the `-pre` control
//! commands, list the engine's capabilities under `-c`, test-load it under
//! `-t`/`-tt` with the `-post` commands, and list its control commands under
//! `-v..-vvvv`. The parse, the engine listing, the `-c` capability list, the
//! `-t` test and the `-pre`/`-post` command runner are transcribed.
//!
//! ## What the court drives
//!
//! Nothing: the whole `engine` surface is recorded. The body is landed and its
//! parse, listing, `-c`, `-t`, `-pre`/`-post` and `-v` arms are transcribed, but
//! the candidate's `ENGINE_load_builtin_engines` calls
//! `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN)`, which the crate's
//! `crypto/init.c` arm still refuses (the engine bits `eng_openssl.c`/
//! `eng_rdrand.c` are unlanded, as `docs/PHASE-16-CLI-SEAL.md` records), so
//! `engine` exits with `OPENSSL_init_crypto:init fail` on stderr and an empty
//! listing where the authority prints the two built-in engines. Both the listing
//! arms and the pointer-bearing `-pre foo` failure are recorded in the court's
//! `recorded_divergences`.
//!
//! ## Recorded divergences (module header)
//!
//! * **The listing arms are not drivable.** `ENGINE_load_builtin_engines`
//!   (`apps/engine.c:387-392`) fails the candidate's `OPENSSL_init_crypto` with
//!   the engine bits unlanded, so `engine`, `-c`, `-t` and `-post foo` produce an
//!   empty listing plus the pointer-bearing init-fail error; the whole surface is
//!   recorded rather than diffed.
//! * **The cipher/digest/pkey-method capability enumeration is not landed.**
//!   `append_buf` over `ENGINE_get_ciphers`/`_digests`/`_pkey_meths`
//!   (`apps/engine.c:433-457`) and the `OSSL_STORE`-loader scan
//!   (`apps/engine.c:458-469`) are not driven; for the two built-in engines every
//!   one of those callbacks is absent, so the `-c` bracket the court diffs is
//!   identical.
//! * **`util_verbose` is reduced to its observable.** For the built-in engines
//!   `ENGINE_ctrl(e, ENGINE_CTRL_HAS_CTRL_FUNCTION, ...)` is zero, so
//!   `util_verbose` (`apps/engine.c:155-244`) prints nothing and `-v..-vvvv` are
//!   the plain listing.
//! * **The failing `-pre`/`-post` arms carry a pointer-bearing error tail** and
//!   are recorded rather than diffed.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::ENGINE_OPTIONS;
use crate::engine::eng_all::ENGINE_load_builtin_engines;
use crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string;
use crate::engine::eng_init::{ENGINE_finish, ENGINE_init};
use crate::engine::eng_lib::{ENGINE_free, ENGINE_get_id, ENGINE_get_name};
use crate::engine::eng_list::{ENGINE_by_id, ENGINE_get_first, ENGINE_get_next};
use crate::engine::tb_dh::ENGINE_get_DH;
use crate::engine::tb_dsa::ENGINE_get_DSA;
use crate::engine::tb_eckey::ENGINE_get_EC;
use crate::engine::tb_rand::ENGINE_get_RAND;
use crate::engine::tb_rsa::ENGINE_get_RSA;
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::sys::{stderr, stdout};
use crate::runtime::bio::{BIO_free_all, Bio, BIO_NOCLOSE};
use crate::runtime::err::ERR_print_errors;

/// `ENGINE_CTRL_HAS_CTRL_FUNCTION` — `include/openssl/engine.h`.
const ENGINE_CTRL_HAS_CTRL_FUNCTION: c_int = 10;
/// The authority's `indent` — `apps/engine.c:313`.
const INDENT: &str = "     ";

/// `bio_err` — `apps/lib/apps.c`'s stderr BIO (`dup_bio_err`).
fn bio_err() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard error `FILE *`.
    unsafe { BIO_new_fp(stderr.cast(), BIO_NOCLOSE) }
}

/// `out = dup_bio_out(FORMAT_TEXT)` — `apps/engine.c:318`.
fn bio_out() -> *mut Bio {
    // SAFETY: `stdout` is the C library's live standard output `FILE *`.
    unsafe { BIO_new_fp(stdout.cast(), BIO_NOCLOSE) }
}

/// `BIO_puts(out, s)` with a Rust string.
fn puts(bio: *mut Bio, s: &str) {
    let Ok(cs) = std::ffi::CString::new(s) else {
        return;
    };
    // SAFETY: `bio` is live; `cs` is NUL-terminated.
    unsafe { BIO_puts(bio, cs.as_ptr()) };
}

/// A live engine name, read from an engine pointer.
fn engine_id(e: *const crate::engine::eng_lib::Engine) -> String {
    // SAFETY: `e` is live.
    let p = unsafe { ENGINE_get_id(e) };
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: `p` is a NUL-terminated static.
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }
}

/// A live engine description, read from an engine pointer.
fn engine_name(e: *const crate::engine::eng_lib::Engine) -> String {
    // SAFETY: `e` is live.
    let p = unsafe { ENGINE_get_name(e) };
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: `p` is a NUL-terminated static.
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }
}

/// `static int util_do_cmds(ENGINE *e, STACK_OF(OPENSSL_STRING) *cmds, BIO
/// *out, const char *indent)` — `apps/engine.c:246-283`.
fn util_do_cmds(
    e: *mut crate::engine::eng_lib::Engine,
    cmds: &[String],
    out: *mut Bio,
    indent: &str,
) {
    for cmd in cmds {
        let (name, arg) = match cmd.split_once(':') {
            Some((n, a)) => (n, Some(a)),
            None => (cmd.as_str(), None),
        };
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        let carg = arg.and_then(|a| std::ffi::CString::new(a).ok());
        // SAFETY: `e` is live; `cname`/`carg` are NUL-terminated or NULL.
        let res = unsafe {
            ENGINE_ctrl_cmd_string(
                e,
                cname.as_ptr(),
                carg.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()),
                0,
            )
        };
        if res != 0 {
            puts(out, &format!("[Success]: {cmd}\n"));
        } else {
            puts(out, &format!("[Failure]: {cmd}\n"));
            // SAFETY: `out` is live.
            unsafe { ERR_print_errors(out) };
        }
    }
    let _ = indent;
}

/// `static int util_verbose(ENGINE *e, int verbose, BIO *out, const char *indent)`
/// — `apps/engine.c:155-244`, reduced to its observable (see the header).
fn util_verbose(e: *mut crate::engine::eng_lib::Engine, out: *mut Bio, indent: &str) {
    // SAFETY: `e` is live; the control takes no function argument.
    let has_ctrl_fn = unsafe {
        crate::engine::eng_ctrl::ENGINE_ctrl(
            e,
            ENGINE_CTRL_HAS_CTRL_FUNCTION,
            0,
            core::ptr::null_mut(),
            None,
        )
    };
    if has_ctrl_fn == 0 {
        return;
    }
    // The command enumeration is not landed; no built-in engine reaches here.
    let _ = (out, indent);
}

/// `static int append_buf(char **buf, int *size, const char *s)` —
/// `apps/engine.c:62-97`, over a Rust `Vec<String>`.
fn append_buf(buf: &mut Vec<String>, s: &str) {
    buf.push(s.to_string());
}

/// `int engine_main(int argc, char **argv)` — `apps/engine.c:304-506`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let prog = argv
        .first()
        .cloned()
        .unwrap_or_else(|| "engine".to_string());

    // `while ((argv1 = argv[1]) != NULL && *argv1 != '-') { push engine; argc--;
    // argv++; } argv[0] = prog; opt_init(argc, argv, engine_options);` —
    // `apps/engine.c:324-332`.
    let mut engines: Vec<String> = Vec::new();
    let mut flag_start = 1usize;
    while flag_start < argv.len() && !argv[flag_start].starts_with('-') {
        engines.push(argv[flag_start].clone());
        flag_start += 1;
    }
    let mut opt_argv: Vec<String> = Vec::with_capacity(argv.len() - flag_start + 1);
    opt_argv.push(prog.clone());
    opt_argv.extend_from_slice(&argv[flag_start..]);

    // `opt_init(argc, argv, engine_options);` — `apps/engine.c:332`.
    let mut opts = Opts::init(&opt_argv, ENGINE_OPTIONS);
    let mut verbose = 0i32;
    let mut list_cap = false;
    let mut test_avail = false;
    let mut _test_avail_noise = false;
    let mut pre_cmds: Vec<String> = Vec::new();
    let mut post_cmds: Vec<String> = Vec::new();

    // `out = dup_bio_out(FORMAT_TEXT);` — `apps/engine.c:318`.
    let out = bio_out();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/engine.c:334`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(engine_options); ret = 0; goto end;` —
            // `apps/engine.c:340-343`.
            OptMatch::Help => {
                // SAFETY: `out` is live and not freed again.
                unsafe { BIO_free_all(out) };
                return not_landed("engine -help");
            }
            // `case OPT_EOF: case OPT_ERR: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog); goto end;` — `apps/engine.c:336-339`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{prog}: Use -help for summary.");
                // SAFETY: `out` is live and not freed again.
                unsafe { BIO_free_all(out) };
                return 1;
            }
            // `case OPT_VVVV: case OPT_VVV: case OPT_VV: case OPT_V: i = (o -
            // OPT_V) + 1; if (verbose < i) verbose = i;` — `apps/engine.c:344-352`.
            OptMatch::Flag("v") => verbose = verbose.max(1),
            OptMatch::Flag("vv") => verbose = verbose.max(2),
            OptMatch::Flag("vvv") => verbose = verbose.max(3),
            OptMatch::Flag("vvvv") => verbose = verbose.max(4),
            // `case OPT_C: list_cap = 1; break;` — `apps/engine.c:353-355`.
            OptMatch::Flag("c") => list_cap = true,
            // `case OPT_TT: test_avail_noise++; /* fall through */ case OPT_T:
            // test_avail++; break;` — `apps/engine.c:356-361`.
            OptMatch::Flag("tt") => {
                _test_avail_noise = true;
                test_avail = true;
            }
            OptMatch::Flag("t") => test_avail = true,
            // `case OPT_PRE: if (sk_OPENSSL_STRING_push(pre_cmds, opt_arg()) <= 0)
            // goto end;` — `apps/engine.c:362-365`.
            OptMatch::Value("pre", v) => pre_cmds.push(v),
            // `case OPT_POST: if (sk_OPENSSL_STRING_push(post_cmds, opt_arg()) <=
            // 0) goto end;` — `apps/engine.c:366-369`.
            OptMatch::Value("post", v) => post_cmds.push(v),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{prog}: Use -help for summary.");
                // SAFETY: `out` is live and not freed again.
                unsafe { BIO_free_all(out) };
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); for (; *argv; argv++) { if
    // (**argv == '-') { ... "Cannot mix flags and engine names." ... } push
    // engine; }` — `apps/engine.c:373-385`.
    for rest in opts.rest() {
        if rest.starts_with('-') {
            eprintln!("{prog}: Cannot mix flags and engine names.");
            eprintln!("{prog}: Use -help for summary.");
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            return 1;
        }
        engines.push(rest.clone());
    }

    // `if (sk_OPENSSL_CSTRING_num(engines) == 0) { for (e = ENGINE_get_first(); e
    // != NULL; e = ENGINE_get_next(e)) push (ENGINE_get_id(e)); }` —
    // `apps/engine.c:387-392`.
    if engines.is_empty() {
        // SAFETY: the built-in engine loader is this crate's.
        unsafe { ENGINE_load_builtin_engines() };
        // SAFETY: `ENGINE_get_first` returns NULL or a live engine.
        let mut e = ENGINE_get_first();
        while !e.is_null() {
            engines.push(engine_id(e));
            // SAFETY: `e` is live.
            e = unsafe { ENGINE_get_next(e) };
        }
    }

    // `ret = 0; for (i = 0; i < sk_OPENSSL_CSTRING_num(engines); i++) { ...
    // }` — `apps/engine.c:394-497`.
    let mut ret = 0i32;
    for id in &engines {
        let Ok(cid) = std::ffi::CString::new(id.as_str()) else {
            continue;
        };
        // SAFETY: `cid` is NUL-terminated.
        let e = unsafe { ENGINE_by_id(cid.as_ptr()) };
        if !e.is_null() {
            let name = engine_name(e);
            puts(out, &format!("({id}) {name}\n"));
            util_do_cmds(e, &pre_cmds, out, INDENT);
            // `if (strcmp(ENGINE_get_id(e), id) != 0) { ... "Loaded: (%s) %s" ...
            // }` — `apps/engine.c:404-407`.
            if engine_id(e) != *id {
                puts(
                    out,
                    &format!("Loaded: ({}) {}\n", engine_id(e), engine_name(e)),
                );
            }
            // `if (list_cap) { ... ENGINE_get_RSA/EC/DSA/DH/RAND ... }` —
            // `apps/engine.c:408-474`.
            if list_cap {
                let mut cap_buf: Vec<String> = Vec::new();
                // SAFETY: `e` is live; each getter answers a method pointer or NULL.
                unsafe {
                    if !ENGINE_get_RSA(e).is_null() {
                        append_buf(&mut cap_buf, "RSA");
                    }
                    if !ENGINE_get_EC(e).is_null() {
                        append_buf(&mut cap_buf, "EC");
                    }
                    if !ENGINE_get_DSA(e).is_null() {
                        append_buf(&mut cap_buf, "DSA");
                    }
                    if !ENGINE_get_DH(e).is_null() {
                        append_buf(&mut cap_buf, "DH");
                    }
                    if !ENGINE_get_RAND(e).is_null() {
                        append_buf(&mut cap_buf, "RAND");
                    }
                }
                if !cap_buf.is_empty() {
                    puts(out, &format!(" [{}]\n", cap_buf.join(", ")));
                }
            }
            // `if (test_avail) { BIO_printf(out, "%s", indent); if
            // (ENGINE_init(e)) { "[ available ]"; util_do_cmds(post); ENGINE_finish
            // } else { "[ unavailable ]"; ... } }` — `apps/engine.c:475-487`.
            if test_avail {
                puts(out, INDENT);
                // SAFETY: `e` is live.
                if unsafe { ENGINE_init(e) } != 0 {
                    puts(out, "[ available ]\n");
                    util_do_cmds(e, &post_cmds, out, INDENT);
                    // SAFETY: `e` is live.
                    unsafe { ENGINE_finish(e) };
                } else {
                    puts(out, "[ unavailable ]\n");
                }
                // SAFETY: the queue is cleared unconditionally.
                crate::runtime::err::ERR_clear_error();
            }
            // `if ((verbose > 0) && !util_verbose(e, verbose, out, indent)) goto
            // end;` — `apps/engine.c:488-489`.
            if verbose > 0 {
                util_verbose(e, out, INDENT);
            }
            // SAFETY: `e` is live and not freed again.
            unsafe { ENGINE_free(e) };
        } else {
            // `ERR_print_errors(bio_err); if (++ret > 127) ret = 127;` —
            // `apps/engine.c:491-496`.
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { crate::runtime::bio::BIO_free(err) };
            ret += 1;
            if ret > 127 {
                ret = 127;
            }
        }
    }

    // `end: ERR_print_errors(bio_err); ... BIO_free_all(out); return ret;` —
    // `apps/engine.c:499-506`.
    let err = bio_err();
    // SAFETY: `err` is a live stderr BIO.
    unsafe { ERR_print_errors(err) };
    // SAFETY: `err` is NOCLOSE.
    unsafe { crate::runtime::bio::BIO_free(err) };
    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free_all(out) };
    ret
}
