//! Phase 17.1 — `apps/configutl.c`: the `openssl configutl` command.
//!
//! The whole command body (`apps/configutl.c:109-202`): parse the generated
//! `CONFIGUTL_OPTIONS` table, load the named (or default) configuration through
//! `NCONF_load`, and re-emit it in canonical linear form — the `[default]`
//! section first without a header, then every other section in the order
//! `NCONF_get_section_names` yields — with `print_escaped_value`
//! (`apps/configutl.c:20-68`) escaping the value bytes exactly. Every libcrypto
//! function it reaches (`NCONF_new`, `NCONF_load`, `NCONF_get_section_names`,
//! `NCONF_get_section`, `CONF_get1_default_config_file`) is landed.
//!
//! ## What the court drives
//!
//! A fixed configuration fixture and the empty-default arms. The output is
//! deterministic once `OPENSSL_CONF` is fixed (the court sets it to `/dev/null`),
//! so `-config <fixture>` (with and without `-noheader`) and `-out <temp>` are
//! driven; the section order is `NCONF_get_section_names`'s, measured on both
//! sides rather than assumed.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * **The `bio_open_default` helper is reduced to its observable.** The
//!   authority opens `bio_out` through `apps/lib/apps.c`'s `bio_open_default`;
//!   this stratum has no `apps/lib` helper, so the file/stdout distinction is
//!   made with `std::io`/`std::fs` directly. The byte stream is identical, but
//!   the authority's failure text (`Can't open "..." for ...`) is the `apps/lib`
//!   arm's and is not reproduced here; a `-out` that cannot be opened reaches
//!   [`not_landed`].
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CONFIGUTL_OPTIONS;
use crate::runtime::conf::lib::{
    NCONF_free, NCONF_get_section, NCONF_get_section_names, NCONF_load, NCONF_new,
};
use crate::runtime::conf::modparse::CONF_get1_default_config_file;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

/// `static void print_escaped_value(BIO *out, const char *value)` —
/// `apps/configutl.c:20-68`.
fn print_escaped_value(out: &mut String, value: &[u8]) {
    for (i, &b) in value.iter().enumerate() {
        match b {
            b'"' | b'\'' | b'#' | b'\\' | b'$' => {
                out.push('\\');
                out.push(b as char);
            }
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\x08' => out.push_str("\\b"),
            b'\t' => out.push_str("\\t"),
            b' ' => {
                // `if (p == value || p[1] == '\0')` — the first or last byte.
                if i == 0 || i + 1 == value.len() {
                    out.push_str("\" \"");
                } else {
                    out.push(' ');
                }
            }
            _ => out.push(b as char),
        }
    }
}

/// A C string field as bytes without its NUL; NULL is empty (the authority reads
/// it as a `%s` and would fault, but no section entry has a NULL name/value).
fn bytes(p: *mut c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: a `CONF_VALUE` name/value is NUL-terminated for the configuration's life.
    unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// `static void print_section(BIO *out, const CONF *cnf, OPENSSL_CSTRING
/// section_name)` — `apps/configutl.c:73-85`.
fn print_section(out: &mut String, cnf: *const Conf, section_name: *const c_char) {
    // SAFETY: `cnf` is live and `section_name` is NUL-terminated.
    let values = unsafe { NCONF_get_section(cnf, section_name) };
    if values.is_null() {
        return;
    }
    // `for (idx = 0; idx < sk_CONF_VALUE_num(values); idx++)` — `apps/configutl.c:78`.
    // SAFETY: `values` is a live stack.
    let n = unsafe { OPENSSL_sk_num(values) };
    for idx in 0..n {
        // SAFETY: `values` is live and `idx` is in bounds.
        let value = unsafe { OPENSSL_sk_value(values, idx) }.cast::<ConfValue>();
        // SAFETY: a stack element is a live `CONF_VALUE`.
        let (name, val) = unsafe { ((*value).name, (*value).value) };
        out.push_str(&String::from_utf8_lossy(&bytes(name)));
        out.push_str(" = ");
        print_escaped_value(out, &bytes(val));
        out.push('\n');
    }
}

/// `int configutl_main(int argc, char *argv[])` — `apps/configutl.c:109-202`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, configutl_options);` — `apps/configutl.c:122`.
    let mut opts = Opts::init(argv, CONFIGUTL_OPTIONS);
    let mut ret = 1i32;
    let mut configfile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut no_header = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/configutl.c:123`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(configutl_options); ret = 0; goto end;` —
            // `apps/configutl.c:125-128`.
            OptMatch::Help => return not_landed("configutl -help"),
            // `case OPT_NOHEADER: no_header = 1; break;` — `apps/configutl.c:130-132`.
            OptMatch::Flag("noheader") => no_header = true,
            // `case OPT_CONFIG: OPENSSL_free(configfile); configfile =
            // OPENSSL_strdup(opt_arg());` — `apps/configutl.c:133-140`.
            OptMatch::Value("config", v) => configfile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/configutl.c:141-143`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_ERR: default: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog); goto end;` — `apps/configutl.c:144-151`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // Only stdout is driven; a named `-out` writes a file. The authority's
    // `bio_open_default` failure arm is an `apps/lib` helper (see the header).
    let write_to_stdout = outfile.is_none() || outfile.as_deref() == Some("-");

    // `if (configfile == NULL) configfile = CONF_get1_default_config_file();` —
    // `apps/configutl.c:158-159`.
    let owned_default;
    let configfile: &str = match &configfile {
        Some(c) => c.as_str(),
        None => {
            // SAFETY: `CONF_get1_default_config_file` returns an owned NUL-terminated
            // string or NULL; it is freed below.
            let p = CONF_get1_default_config_file();
            if p.is_null() {
                // `if (configfile == NULL) goto end;` — `apps/configutl.c:161-162`.
                return ret;
            }
            // SAFETY: `p` is a NUL-terminated block; it is freed below.
            owned_default = unsafe { core::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `p` is the block just copied and not freed again.
            unsafe { CRYPTO_free(p.cast(), core::ptr::null(), 0) };
            &owned_default
        }
    };

    // `if ((cnf = NCONF_new(NULL)) == NULL) goto end;` — `apps/configutl.c:164-165`.
    // SAFETY: the NULL method selects the default method.
    let cnf = unsafe { NCONF_new(core::ptr::null_mut()) };
    if cnf.is_null() {
        return ret;
    }

    // `if (NCONF_load(cnf, configfile, &eline) == 0) { BIO_printf(bio_err,
    // "Error on line %ld of configuration file\n", eline + 1); goto end; }` —
    // `apps/configutl.c:167-170`.
    let mut eline: c_long = 0;
    let cfile = match std::ffi::CString::new(configfile) {
        Ok(c) => c,
        Err(_) => return ret,
    };
    // SAFETY: `cnf` is live, `cfile` is NUL-terminated and outlives the call.
    if unsafe { NCONF_load(cnf, cfile.as_ptr(), &mut eline) } == 0 {
        eprintln!("Error on line {} of configuration file", eline + 1);
        // SAFETY: `cnf` is live.
        unsafe { NCONF_free(cnf) };
        return ret;
    }

    // `if ((sections = NCONF_get_section_names(cnf)) == NULL) goto end;` —
    // `apps/configutl.c:172-173`.
    // SAFETY: `cnf` is live.
    let sections = unsafe { NCONF_get_section_names(cnf) };
    if sections.is_null() {
        // SAFETY: `cnf` is live.
        unsafe { NCONF_free(cnf) };
        return ret;
    }

    let mut out = String::new();
    // `if (no_header == 0) BIO_printf(out, "# This configuration file was
    // linearized and expanded from %s\n", configfile);` — `apps/configutl.c:175-177`.
    if !no_header {
        out.push_str(&format!(
            "# This configuration file was linearized and expanded from {configfile}\n"
        ));
    }

    // `default_section_idx = sk_OPENSSL_CSTRING_find(sections, "default");` —
    // `apps/configutl.c:179`.
    // SAFETY: `sections` is a live stack of C strings.
    let count = unsafe { OPENSSL_sk_num(sections) };
    let mut default_section_idx: c_int = -1;
    for idx in 0..count {
        // SAFETY: `idx` is in bounds.
        let name = unsafe { OPENSSL_sk_value(sections, idx) }
            .cast::<c_char>()
            .cast_const();
        if !name.is_null() {
            // SAFETY: `name` is NUL-terminated.
            let s = unsafe { core::ffi::CStr::from_ptr(name) };
            if s.to_bytes() == b"default" {
                default_section_idx = idx;
                break;
            }
        }
    }
    // `if (default_section_idx != -1) print_section(out, cnf, "default");` —
    // `apps/configutl.c:180-181`.
    if default_section_idx != -1 {
        print_section(&mut out, cnf, c"default".as_ptr());
    }

    // `for (idx = 0; idx < sk_OPENSSL_CSTRING_num(sections); idx++) { ... if (idx
    // == default_section_idx) continue; BIO_printf(out, "\n[%s]\n", name);
    // print_section(out, cnf, name); }` — `apps/configutl.c:183-191`.
    for idx in 0..count {
        if idx == default_section_idx {
            continue;
        }
        // SAFETY: `idx` is in bounds.
        let name = unsafe { OPENSSL_sk_value(sections, idx) }
            .cast::<c_char>()
            .cast_const();
        // SAFETY: a section name is NUL-terminated.
        let name_str = unsafe { core::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        out.push_str(&format!("\n[{name_str}]\n"));
        print_section(&mut out, cnf, name);
    }

    // `ret = 0;` — `apps/configutl.c:193`.
    ret = 0;

    // `end: ERR_print_errors(bio_err); ...` — `apps/configutl.c:195-201`. The
    // queue is empty on the driven paths, so `ERR_print_errors` is a no-op.
    if write_to_stdout {
        print!("{out}");
    } else if let Some(path) = outfile.as_deref() {
        if std::fs::write(path, out.as_bytes()).is_err() {
            // The authority's `bio_open_default` failure text is the `apps/lib`
            // arm's; see the header. Recorded rather than fabricated.
            // SAFETY: `cnf`/`sections` are live here.
            unsafe { NCONF_free(cnf) };
            return not_landed("configutl -out (unopenable)");
        }
    }

    // SAFETY: `cnf` and `sections` are live and not used again.
    unsafe { NCONF_free(cnf) };
    ret
}
