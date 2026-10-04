//! Phase 16.4 — `apps/list.c`: the `openssl list` command, reduced to the arms
//! 16.4's court drives.
//!
//! `list -options <cmd>` is the option-*list* surface: it reads the command's own
//! `OPTIONS[]` table (`apps/list.c:1134-1166`) and prints `name type` rows, which
//! is exactly the fixed option tables the regenerated Phase-1 capture structures.
//! `list -commands -1` prints the `functions[]` table's standard commands
//! (`apps/list.c:1202-1231`). Both are deterministic and build-independent.
//!
//! ## Recorded divergence (module header)
//!
//! **`list`'s algorithm enumerations are not landed.** The authority's other
//! `list -<selector>` arms reach the provider inventory, the encoders/decoders,
//! the random and MAC/KDF enumerations and the `EVP_*` fetch machinery. This
//! stratum lands the two arms its court drives (`-commands`, `-options`) and
//! reaches a `not landed` boundary for the rest rather than printing a wrong
//! body. `apps/list.c` is a pulled-forward dependency: 16.4 owns the CLI
//! (`apps/openssl.c`), and `list` is the command whose option-list arm the
//! regenerated capture measures. See `docs/PHASE-16-SUBPHASES.md` §4.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::{FuncKind, FUNCTIONS, LIST_OPTIONS};

/// `static void list_options_for_command(const char *command)` — `apps/list.c:1134-1166`.
///
/// Prints `name type` for each row of the command's table and the trailing
/// `- -` marker. An unknown command prints the authority's message to stderr and
/// returns, which is why `list -options bogus` still exits 0.
fn options_for_command(command: &str) {
    let Some(fp) = FUNCTIONS.iter().find(|f| f.name == command) else {
        eprintln!("Invalid command '{command}'; type \"help\" for a list.");
        return;
    };
    let Some(opts) = fp.options else {
        return;
    };
    for o in opts {
        let valtype = if o.valtype == 0 { b'-' } else { o.valtype };
        println!("{} {}", o.name, valtype as char);
    }
    println!("- -");
}

/// `static void list_type(FUNC_TYPE ft, int one)` — `apps/list.c:1202-1231`, the
/// one-column arm and the `FT_general` filter.
fn list_general_commands() {
    for f in FUNCTIONS {
        if f.kind == FuncKind::General {
            println!("{}", f.name);
        }
    }
}

/// `int list_main(int argc, char **argv)` — `apps/list.c:1796-1980`, the arms
/// 16.4 drives.
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, LIST_OPTIONS);
    let (mut one, mut commands, mut any) = (false, false, false);
    loop {
        match opts.next() {
            OptMatch::End => break,
            OptMatch::Help => return not_landed("list -help"),
            OptMatch::Flag("1") => one = true,
            OptMatch::Flag("commands") | OptMatch::Flag("standard-commands") => {
                commands = true;
                any = true;
            }
            OptMatch::Value("options", cmd) => {
                options_for_command(&cmd);
                any = true;
            }
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                return not_landed("list -<selector> (provider enumeration)");
            }
        }
    }
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    if !any {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    if commands {
        if one {
            list_general_commands();
        } else {
            return not_landed("list -commands (columnar)");
        }
    }
    0
}
