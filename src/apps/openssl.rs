//! Phase 16.4 — `apps/openssl.c`: the `openssl` command dispatcher.
//!
//! This module transcribes the program's `main`, its `functions[]` dispatch
//! (`do_cmd`), its `help` command and its deprecated-command warning. The
//! `functions[]` table itself and every command's `OPTIONS[]` table are generated
//! from the authority's own C into [`crate::apps::tables`]; the option parser is
//! [`crate::apps::opt`].
//!
//! ## What is landed, and where the dispatcher stops
//!
//! `main`'s global `-help`/`-version` arm, `prog_init`'s table sort, `do_cmd`'s
//! table lookup, its `no-` "is this feature unsupported" arm, its
//! `Invalid command` arm and its deprecated-command warning are transcribed
//! whole. Four command bodies are landed: `help` (this module), `list`
//! ([`crate::apps::list`]) and `version` ([`crate::apps::version`]) from Phase
//! 16.4, whose output is build-independent, and `errstr` ([`crate::apps::errstr`])
//! from Phase 17.1, the first of the 52 command bodies that stratum lands. **Every
//! other command name is present in the table and dispatches, but its body
//! (`apps/<name>.c`) is a unit this stratum does not own**, so it reaches
//! [`not_landed`] rather than printing a wrong body.
//!
//! ## Recorded divergences (module header)
//!
//! * **The command bodies are the boundary.** `apps/req.c`, `apps/x509.c` and
//!   their 52 siblings are separate authority translation units; 16.4 owns the
//!   CLI (`apps/openssl.c`) and the config-loading surface, not the commands. A
//!   landed CLI says a command exists, not that its output is the authority's
//!   (`docs/PHASE-16-SUBPHASES.md` §3.4).
//! * **`app_RAND_write`/`app_providers_cleanup` are not called.** The authority's
//!   exit path writes the deferred randomness and tears the providers down; those
//!   subsystems are other strata's, and no landed command seeds the RNG, so the
//!   divergence is unobservable for the dispatched arms.
//! * **`opt_help` is not landed** (`src/apps/opt.rs` header), so `-help` on the
//!   three landed commands reaches `not_landed`.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::errstr;
use crate::apps::list;
use crate::apps::opt::{progname, OptMatch, Opts};
use crate::apps::tables::{Func, FuncKind, FUNCTIONS, HELP_OPTIONS};
use crate::apps::version;

/// A command body this stratum does not own, reached rather than fabricated.
///
/// The authority's dispatcher calls `fp->func`; this candidate has no `apps/*.c`
/// body for every name, so the arm is recorded. Returns the failing exit class
/// the authority's body would have to answer for.
pub fn not_landed(name: &str) -> i32 {
    eprintln!(
        "openssl-rs: command '{name}' is a Phase 16 boundary: its apps/{name}.c body is not landed."
    );
    1
}

/// `lh_FUNCTION_retrieve(...)` over the `prog_init`-sorted table.
fn find(name: &str) -> Option<&'static Func> {
    FUNCTIONS.iter().find(|f| f.name == name)
}

/// `static void warn_deprecated(const FUNCTION *fp)` — `apps/openssl.c:48-58`.
fn warn_deprecated(fp: &Func) {
    match fp.deprecated_version {
        Some(v) => eprintln!("The command {} was deprecated in version {}.", fp.name, v),
        None => eprintln!("The command {} is deprecated.", fp.name),
    }
    if let Some(alt) = fp.deprecated_alternative {
        if alt != "unknown" {
            eprintln!(" Use '{alt}' instead.");
        }
    }
    eprintln!();
}

/// `int help_main(int argc, char **argv)` — `apps/openssl.c:402-465`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
fn help_main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, HELP_OPTIONS);
    loop {
        match opts.next() {
            OptMatch::End => break,
            OptMatch::Help => return not_landed("help -help"),
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
    if opts.num_rest() == 1 {
        let dispatch = vec![opts.rest()[0].clone(), "--help".to_string()];
        return do_cmd(&dispatch);
    }
    if !opts.check_rest_arg(None) {
        eprintln!("Usage: {}", opts.prog());
        return 1;
    }

    // `apps/openssl.c:437-464`, with `calculate_columns` (`apps/lib/columns.c:14-26`):
    // no terminal query, so the column count is a pure function of the table.
    let width = FUNCTIONS
        .iter()
        .filter(|f| matches!(f.kind, FuncKind::General | FuncKind::Md | FuncKind::Cipher))
        .map(|f| f.name.len())
        .max()
        .unwrap_or(0)
        + 2;
    let columns = 79 / width;
    let mut out = String::new();
    out.push_str(&format!("{}:\n\nStandard commands", opts.prog()));
    let mut i = 0usize;
    let mut tp: Option<FuncKind> = None;
    for fp in FUNCTIONS {
        let mut nl = false;
        if i.is_multiple_of(columns) {
            out.push('\n');
            nl = true;
        }
        i += 1;
        if tp != Some(fp.kind) {
            tp = Some(fp.kind);
            if !nl {
                out.push('\n');
            }
            if fp.kind == FuncKind::Md {
                i = 1;
                out.push_str(
                    "\nMessage Digest commands (see the `dgst' command for more details)\n",
                );
            } else if fp.kind == FuncKind::Cipher {
                i = 1;
                out.push_str("\nCipher commands (see the `enc' command for more details)\n");
            }
        }
        out.push_str(&format!("{:<width$}", fp.name, width = width));
    }
    out.push_str("\n\n");
    eprint!("{out}");
    0
}

/// `static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[])` —
/// `apps/openssl.c:467-509`.
fn do_cmd(argv: &[String]) -> i32 {
    if argv.is_empty() {
        return 0;
    }
    let name = argv[0].as_str();
    if let Some(fp) = find(name) {
        if fp.deprecated_alternative.is_some() {
            warn_deprecated(fp);
        }
        return match fp.name {
            "errstr" => errstr::main(argv),
            "help" => help_main(argv),
            "list" => list::main(argv),
            "version" => version::main(argv),
            _ => not_landed(fp.name),
        };
    }
    if let Some(stripped) = name.strip_prefix("no-") {
        if find(stripped).is_none() {
            println!("{name}");
            return 0;
        }
        println!("{stripped}");
        return 1;
    }
    eprintln!("Invalid command '{name}'; type \"help\" for a list.");
    1
}

/// `int main(int argc, char *argv[])` — `apps/openssl.c:241-383`, the dispatch
/// path. The crate's `build.rs` binds the authority identity, so the optional
/// `OPENSSL_SEC_MEM`/trace/libctx entry work is not reproduced.
pub fn run(args: &[String]) -> i32 {
    let pname = progname(args.first().map(|s| s.as_str()).unwrap_or("openssl"));

    if find(&pname).is_some() {
        // Invoked under a command name: the authority keeps `argv` and replaces
        // `argv[0]` (`apps/openssl.c:354-356`).
        let mut a = args.to_vec();
        if !a.is_empty() {
            a[0] = pname;
        }
        return do_cmd(&a);
    }

    let a1 = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let global_help = matches!(a1, "-help" | "--help" | "-h" | "--h");
    let global_version = matches!(a1, "-version" | "--version" | "-v" | "--v");
    let rest: Vec<String> = args.iter().skip(1).cloned().collect();

    if rest.is_empty() || global_help {
        do_cmd(&["help".to_string()])
    } else if global_version {
        do_cmd(&["version".to_string()])
    } else {
        do_cmd(&rest)
    }
}

/// The `openssl` executable's entry, reading the process arguments.
pub fn main_from_env() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    run(&args)
}
