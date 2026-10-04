//! Phase 17.1f — `apps/srp.c`: the `openssl srp` command.
//!
//! The command's option parse (`apps/srp.c:257-317`) and its four pre-work
//! refusals (`apps/srp.c:326-347`) are transcribed: two mutually exclusive
//! actions, no action, `-add` without a user, and `-srpvfile` with
//! `-configfile`. The rest of the body — the config lookup, `load_index` and the
//! verifier-file database — reaches `apps/lib` helpers this stratum does not own,
//! so every arm that gets past the refusals stops at [`not_landed`].
//!
//! ## What the court drives
//!
//! `srp`, `srp -list -add`, `srp -add`, `srp -srpvfile <f> -config <f>` and
//! `srp -bogus`: five refusals decided by the parse and printed verbatim. The
//! action-request arms (`-list`, `-add <user>`) need `load_index`
//! (`apps/lib/apps.c`) and are recorded rather than driven.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-list`/`-add`/`-delete`/`-modify` past the refusals are not landed.**
//!   They load a verifier-file index through `load_index`/`index_index` and the
//!   `CA_DB` type (`apps/lib/apps.c`), which this stratum does not own; the
//!   fixture-bearing `-list` arm reaches [`not_landed`].
//! * **`app_load_config`/`default_config_file` are not reconstructed.** The
//!   default config path is the `apps/lib` config surface; an action request with
//!   no `-srpvfile` reaches [`not_landed`] rather than loading a config.
//! * **`app_passwd` is reduced to its no-argument observable**; no `-passin`/
//!   `-passout` is driven.
//! * **`-engine`, `-rand`/`-writerand` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SRP_OPTIONS;

/// `apps/srp.c:191-208`'s action selector, reduced to the mutually exclusive
/// `-add`/`-delete`/`-modify`/`-list` arms.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Add,
    Delete,
    Modify,
    List,
}

/// `int srp_main(int argc, char **argv)` — `apps/srp.c:243-633`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, SRP_OPTIONS);
    let mut mode: Option<Mode> = None;
    let mut configfile: Option<String> = None;
    let mut srpvfile: Option<String> = None;
    let mut passin_seen = false;
    let mut passout_seen = false;

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ret = 0; goto end;` — `apps/srp.c:265-268`.
            OptMatch::Help => return not_landed("srp -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/srp.c:260-264`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_VERBOSE: verbose++;` — `apps/srp.c:269-271`.
            OptMatch::Flag("verbose") => {}
            // `case OPT_CONFIG: configfile = opt_arg();` — `apps/srp.c:272-274`.
            OptMatch::Value("config", v) => configfile = Some(v),
            // `case OPT_NAME: section = opt_arg();` — `apps/srp.c:275-277`.
            OptMatch::Value("name", _) => {}
            // `case OPT_SRPVFILE: srpvfile = opt_arg();` — `apps/srp.c:278-280`.
            OptMatch::Value("srpvfile", v) => srpvfile = Some(v),
            // `case OPT_ADD: case OPT_DELETE: case OPT_MODIFY: case OPT_LIST:` —
            // `apps/srp.c:281-292`.
            OptMatch::Flag("add") => {
                if mode.is_some() {
                    return only_one(opts.prog());
                }
                mode = Some(Mode::Add);
            }
            OptMatch::Flag("delete") => {
                if mode.is_some() {
                    return only_one(opts.prog());
                }
                mode = Some(Mode::Delete);
            }
            OptMatch::Flag("modify") => {
                if mode.is_some() {
                    return only_one(opts.prog());
                }
                mode = Some(Mode::Modify);
            }
            OptMatch::Flag("list") => {
                if mode.is_some() {
                    return only_one(opts.prog());
                }
                mode = Some(Mode::List);
            }
            // `case OPT_GN: gN = opt_arg();` — `apps/srp.c:293-295`.
            OptMatch::Value("gn", _) => {}
            // `case OPT_USERINFO: userinfo = opt_arg();` — `apps/srp.c:296-298`.
            OptMatch::Value("userinfo", _) => {}
            // `case OPT_PASSIN: passinarg = opt_arg();` — `apps/srp.c:299-301`.
            OptMatch::Value("passin", _) => passin_seen = true,
            // `case OPT_PASSOUT: passoutarg = opt_arg();` — `apps/srp.c:302-304`.
            OptMatch::Value("passout", _) => passout_seen = true,
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0);` — `apps/srp.c:305-307`.
            OptMatch::Value("engine", _) => return not_landed("srp -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/srp.c:308-311`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("srp -rand")
            }
            // `case OPT_PROV_CASES: ...` — `apps/srp.c:312-315`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("srp -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest();` — `apps/srp.c:319-321`.
    let rest = opts.rest().to_vec();
    // `if (!app_RAND_load()) goto end;` — the no-`-rand` no-op success.

    // `if (srpvfile != NULL && configfile != NULL) { ... goto end; }` —
    // `apps/srp.c:326-330`.
    if srpvfile.is_some() && configfile.is_some() {
        eprintln!("-srpvfile and -configfile cannot be specified together.");
        return 1;
    }
    // `if (mode == OPT_ERR) { ... goto opthelp; }` — `apps/srp.c:331-335`.
    let Some(m) = mode else {
        eprintln!("Exactly one of the options -add, -delete, -modify -list must be specified.");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    };
    // `if (mode == OPT_DELETE || mode == OPT_MODIFY || mode == OPT_ADD) { if (argc == 0) ... }` —
    // `apps/srp.c:336-342`.
    if matches!(m, Mode::Delete | Mode::Modify | Mode::Add) && rest.is_empty() {
        eprintln!("Need at least one user.");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if ((passinarg != NULL || passoutarg != NULL) && argc != 1) { ... goto opthelp; }` —
    // `apps/srp.c:343-347`.
    if (passin_seen || passout_seen) && rest.len() != 1 {
        eprintln!("-passin, -passout arguments only valid with one user.");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (srpvfile == NULL) { ... app_load_config_verbose ... }` — `apps/srp.c:354-386`.
    // The config path and `load_index` are `apps/lib`'s.
    not_landed("srp action (index file)")
}

/// `BIO_printf(bio_err, "%s: Only one of -add/-delete/-modify/-list\n", prog);` then
/// `goto opthelp;` — `apps/srp.c:285-289`.
fn only_one(prog: &str) -> i32 {
    eprintln!("{prog}: Only one of -add/-delete/-modify/-list");
    eprintln!("{prog}: Use -help for summary.");
    1
}
