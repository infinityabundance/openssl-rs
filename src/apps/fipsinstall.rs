//! Phase 17.1f — `apps/fipsinstall.c`: the `openssl fipsinstall` command.
//!
//! The command's option parse (`apps/fipsinstall.c:642-806`) and its pre-work
//! refusals (`apps/fipsinstall.c:808-828`) are transcribed: `-verify` without
//! `-in`, a missing `-module` (with no `-config`), and the option parser's own
//! refusals. The module's MAC (`do_mac`), the self-test provider load
//! (`load_fips_prov_and_run_self_test`) and the config writer
//! (`write_config_fips_section`) are other strata's, so every arm that reaches
//! them stops at [`not_landed`].
//!
//! ## What the court drives
//!
//! `fipsinstall`, `fipsinstall -verify` and `fipsinstall -bogus`: the three
//! refusals, all of which are decided by the parse and print the authority's
//! exact text. No module is loaded and no FIPS provider is fetched.
//!
//! ## Recorded divergences (module header)
//!
//! * **The module MAC and the self-test load are not landed.** `do_mac`
//!   (`apps/fipsinstall.c:896`) over the module BIO, `EVP_MAC_fetch`,
//!   `load_fips_prov_and_run_self_test` and the config writer are the FIPS
//!   module's and the provider surface's. Every arm that reaches them (a real
//!   `-module`, `-config`, `-verify -in`, `-macopt`, `-self_test_*`) reaches
//!   [`not_landed`].
//! * **`check_non_pedantic_fips` is transcribed** (`apps/fipsinstall.c:270-277`),
//!   so `-no_conditional_errors` after `-pedantic` is the authority's refusal.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::FIPSINSTALL_OPTIONS;

/// `static int check_non_pedantic_fips(int pedantic, const char *name)` —
/// `apps/fipsinstall.c:270-277`.
fn check_non_pedantic_fips(pedantic: bool, name: &str) -> bool {
    if pedantic {
        eprintln!("Cannot specify -{name} after -pedantic");
        return false;
    }
    true
}

/// `int fipsinstall_main(int argc, char **argv)` — `apps/fipsinstall.c:617-971`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, FIPSINSTALL_OPTIONS);
    let mut verify = false;
    let mut pedantic = false;
    let mut in_fname: Option<String> = None;
    let mut parent_config: Option<String> = None;
    let mut module_fname: Option<String> = None;

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ret = 0; goto end;` —
            // `apps/fipsinstall.c:650-653`.
            OptMatch::Help => return not_landed("fipsinstall -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/fipsinstall.c:645-649`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: in_fname = opt_arg();` — `apps/fipsinstall.c:654-656`.
            OptMatch::Value("in", v) => in_fname = Some(v),
            // `case OPT_OUT: out_fname = opt_arg();` — ignored by the refusals.
            OptMatch::Value("out", _) => {}
            // `case OPT_PEDANTIC: fips_opts = pedantic_opts; pedantic = 1;` —
            // `apps/fipsinstall.c:660-663`.
            OptMatch::Flag("pedantic") => pedantic = true,
            // `case OPT_NO_CONDITIONAL_ERRORS: if (!check_non_pedantic_fips(...)) goto end;` —
            // `apps/fipsinstall.c:664-668`.
            OptMatch::Flag("no_conditional_errors") => {
                if !check_non_pedantic_fips(pedantic, "no_conditional_errors") {
                    return 1;
                }
            }
            // `case OPT_NO_SECURITY_CHECKS: ...` — `apps/fipsinstall.c:669-673`.
            OptMatch::Flag("no_security_checks") => {
                if !check_non_pedantic_fips(pedantic, "no_security_checks") {
                    return 1;
                }
            }
            // `case OPT_NO_PBKDF2_LOWER_BOUND_CHECK: ...` — `apps/fipsinstall.c:749-753`.
            OptMatch::Flag("no_pbkdf2_lower_bound_check") => {
                if !check_non_pedantic_fips(pedantic, "no_pbkdf2_lower_bound_check") {
                    return 1;
                }
            }
            // `case OPT_SELF_TEST_ONINSTALL: ...` — `apps/fipsinstall.c:799-804`.
            OptMatch::Flag("self_test_oninstall") => {
                if !check_non_pedantic_fips(pedantic, "self_test_oninstall") {
                    return 1;
                }
            }
            // `case OPT_VERIFY: verify = 1;` — `apps/fipsinstall.c:792-794`.
            OptMatch::Flag("verify") => verify = true,
            // `case OPT_MODULE: module_fname = opt_arg();` — `apps/fipsinstall.c:772-774`.
            OptMatch::Value("module", v) => module_fname = Some(v),
            // `case OPT_CONFIG: parent_config = opt_arg();` — `apps/fipsinstall.c:781-783`.
            OptMatch::Value("config", v) => parent_config = Some(v),
            // `case OPT_MACOPT: ...` — `apps/fipsinstall.c:784-791`.
            OptMatch::Value("macopt", _) => {}
            // The remaining flags/values only set `fips_opts`, which the refusals
            // never read; they parse successfully and are ignored.
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/fipsinstall.c:808-810`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (verify && in_fname == NULL) { BIO_printf(...); goto opthelp; }` —
    // `apps/fipsinstall.c:811-814`.
    if verify && in_fname.is_none() {
        eprintln!("Missing -in option for -verify");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (parent_config != NULL) { verify_module_load(...); ... goto end; }` —
    // `apps/fipsinstall.c:816-826`.
    if parent_config.is_some() {
        return not_landed("fipsinstall -config");
    }

    // `if (module_fname == NULL) goto opthelp;` — `apps/fipsinstall.c:827-828`.
    if module_fname.is_none() {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // The module MAC, the self-test load and the config writer are not landed.
    not_landed("fipsinstall -module")
}
