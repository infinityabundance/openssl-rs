//! Phase 17.1 — `apps/info.c`: the `openssl info` command.
//!
//! The whole command body (`apps/info.c:46-117`): parse the item selector from
//! the generated `INFO_OPTIONS` table, require exactly one, then print
//! `OPENSSL_info(type)`'s answer (or `Undefined` when it is NULL). No item and
//! two items are the two refusal arms, whose text the authority prints to
//! stderr before the shared `Use -help for summary.` line.
//!
//! ## Which arms the court drives, and which are recorded
//!
//! `OPENSSL_info` is landed (`src/runtime/init.rs:1261`) and answers four of the
//! nine selectors with build-independent strings: the DSO extension (`.so`), the
//! directory-filename separator (`/`), the list separator (`:`) and the Windows
//! install context (`Undefined` on this profile). Those four arms, plus the
//! no-item and two-item refusal arms, are driven.
//!
//! Five selectors name build- or subsystem-specific state and **diverge**, so the
//! `RT-CLI-BODIES` court records the input rather than diffing it:
//!
//! * `-configdir`/`-enginesdir`/`-modulesdir` (`OPENSSL_INFO_CONFIG_DIR`/
//!   `ENGINES_DIR`/`MODULES_DIR`, codes 1001-1003): the authority answers its own
//!   configured prefix (`/work/.../openssl-3.6.4-production/ssl` and its `lib/`
//!   siblings); this candidate's `crypto/defaults.c` answers its build's own
//!   `OPENSSLDIR`, which is a different path, and NULL for the two directories
//!   when no prefix was configured. `src/runtime/init.rs` records the same
//!   divergence for the `version` command's `OPENSSLDIR`.
//! * `-seeds` (`OPENSSL_INFO_SEED_SOURCE`, 1007): the authority answers
//!   `os-specific`; the candidate's RAND is a later stratum and answers NULL, so
//!   the body prints `Undefined` (`src/runtime/init.rs:394-400`).
//! * `-cpusettings` (`OPENSSL_INFO_CPU_SETTINGS`, 1008): the authority answers its
//!   captured `OPENSSL_ia32cap=...` line; the candidate's CPU-dispatch string is
//!   Phase 19 and answers NULL (`src/runtime/init.rs:394-400`).
//!
//! * **`-help` is not landed.** `opt_help(info_options)` (`apps/info.c:61`)
//!   formats the option table; `opt_help` is the boundary [`crate::apps::opt`]
//!   records, so `-help` reaches [`not_landed`].
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::INFO_OPTIONS;

/// `OPENSSL_INFO_CONFIG_DIR` — `openssl/crypto.h` (`apps/info.c:65`).
const OPENSSL_INFO_CONFIG_DIR: c_int = 1001;
/// `OPENSSL_INFO_ENGINES_DIR` — `openssl/crypto.h` (`apps/info.c:69`).
const OPENSSL_INFO_ENGINES_DIR: c_int = 1002;
/// `OPENSSL_INFO_MODULES_DIR` — `openssl/crypto.h` (`apps/info.c:73`).
const OPENSSL_INFO_MODULES_DIR: c_int = 1003;
/// `OPENSSL_INFO_DSO_EXTENSION` — `openssl/crypto.h` (`apps/info.c:77`).
const OPENSSL_INFO_DSO_EXTENSION: c_int = 1004;
/// `OPENSSL_INFO_DIR_FILENAME_SEPARATOR` — `openssl/crypto.h` (`apps/info.c:81`).
const OPENSSL_INFO_DIR_FILENAME_SEPARATOR: c_int = 1005;
/// `OPENSSL_INFO_LIST_SEPARATOR` — `openssl/crypto.h` (`apps/info.c:85`).
const OPENSSL_INFO_LIST_SEPARATOR: c_int = 1006;
/// `OPENSSL_INFO_SEED_SOURCE` — `openssl/crypto.h` (`apps/info.c:89`).
const OPENSSL_INFO_SEED_SOURCE: c_int = 1007;
/// `OPENSSL_INFO_CPU_SETTINGS` — `openssl/crypto.h` (`apps/info.c:93`).
const OPENSSL_INFO_CPU_SETTINGS: c_int = 1008;
/// `OPENSSL_INFO_WINDOWS_CONTEXT` — `openssl/crypto.h` (`apps/info.c:97`).
const OPENSSL_INFO_WINDOWS_CONTEXT: c_int = 1009;

/// `int info_main(int argc, char **argv)` — `apps/info.c:46-117`.
#[allow(clippy::never_loop)] // every arm breaks or returns; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, info_options);` — `apps/info.c:53`.
    let mut opts = Opts::init(argv, INFO_OPTIONS);
    let mut type_ = 0 as c_int;
    let mut dirty = 0u32;
    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/info.c:54`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(info_options); ret = 0; goto end;` —
            // `apps/info.c:60-63`. `opt_help` is unlanded; see the module header.
            OptMatch::Help => return not_landed("info -help"),
            // `default: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/info.c:56-59`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_CONFIGDIR: type = OPENSSL_INFO_CONFIG_DIR; dirty++;` and
            // its eight siblings — `apps/info.c:64-99`.
            OptMatch::Flag("configdir") => {
                type_ = OPENSSL_INFO_CONFIG_DIR;
                dirty += 1;
            }
            OptMatch::Flag("enginesdir") => {
                type_ = OPENSSL_INFO_ENGINES_DIR;
                dirty += 1;
            }
            OptMatch::Flag("modulesdir") => {
                type_ = OPENSSL_INFO_MODULES_DIR;
                dirty += 1;
            }
            OptMatch::Flag("dsoext") => {
                type_ = OPENSSL_INFO_DSO_EXTENSION;
                dirty += 1;
            }
            OptMatch::Flag("dirnamesep") => {
                type_ = OPENSSL_INFO_DIR_FILENAME_SEPARATOR;
                dirty += 1;
            }
            OptMatch::Flag("listsep") => {
                type_ = OPENSSL_INFO_LIST_SEPARATOR;
                dirty += 1;
            }
            OptMatch::Flag("seeds") => {
                type_ = OPENSSL_INFO_SEED_SOURCE;
                dirty += 1;
            }
            OptMatch::Flag("cpusettings") => {
                type_ = OPENSSL_INFO_CPU_SETTINGS;
                dirty += 1;
            }
            OptMatch::Flag("windowscontext") => {
                type_ = OPENSSL_INFO_WINDOWS_CONTEXT;
                dirty += 1;
            }
            // `info_options` declares no value-taking option; the authority's
            // `default`/`OPT_ERR` arms are the only reach for anything else.
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/info.c:102-103`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (dirty > 1) { BIO_printf(bio_err, "%s: Only one item allowed\n", prog);
    // goto opthelp; }` — `apps/info.c:104-107`.
    if dirty > 1 {
        eprintln!("{}: Only one item allowed", opts.prog());
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (dirty == 0) { BIO_printf(bio_err, "%s: No items chosen\n", prog);
    // goto opthelp; }` — `apps/info.c:108-111`.
    if dirty == 0 {
        eprintln!("{}: No items chosen", opts.prog());
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `typedata = OPENSSL_info(type); BIO_printf(bio_out, "%s\n", typedata == NULL
    // ? "Undefined" : typedata);` — `apps/info.c:113-114`.
    let typedata = crate::runtime::init::OPENSSL_info(type_);
    let text = if typedata.is_null() {
        "Undefined".to_string()
    } else {
        // SAFETY: a non-NULL `OPENSSL_info` answer is a NUL-terminated `'static`
        // string (`src/runtime/init.rs:1261`).
        unsafe { core::ffi::CStr::from_ptr(typedata as *const c_char) }
            .to_string_lossy()
            .into_owned()
    };
    println!("{text}");
    // `ret = 0; end: return ret;` — `apps/info.c:115-117`.
    0
}
