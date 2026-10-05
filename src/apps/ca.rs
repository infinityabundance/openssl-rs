//! Phase 17.1g — `apps/ca.c`: the `openssl ca` command.
//!
//! The command body (`apps/ca.c:311-…`): parse the generated `CA_OPTIONS` table,
//! load the CA configuration (`app_load_config_verbose`), the index database and
//! the serial file, then issue a certificate per `certreq` argument (or generate a
//! CRL / update the database / print the database). That whole surface is the
//! `apps/lib` `CA_DB` machinery this stratum does not own.
//!
//! ## What the court drives
//!
//! `ca -bogus` (the parser's unknown-option refusal) and `ca -status` (the
//! parser's missing-value refusal). Both are decided by the option parser before
//! any configuration is read, so they are build-independent and identical on both
//! sides.
//!
//! ## Recorded divergences (module header)
//!
//! * **Nothing past the option parser is landed.** `ca` with a config (the default
//!   `/dev/null` under the court's `OPENSSL_CONF`, or a fixed `demoCA` config) reads
//!   the `ca` section, loads the index database, and its failure path carries a
//!   pointer-bearing `NCONF_get_string` `ERR_print_errors` tail; the issuance,
//!   `-gencrl`, `-updatedb`, `-revoke` and `-status` operations are the `apps/lib`
//!   `CA_DB` and `X509V3` surfaces. They reach
//!   [`not_landed`](crate::apps::openssl::not_landed) after the parse.
//! * **`-config`/`-section` and the whole configuration surface are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CA_OPTIONS;

/// `int ca_main(int argc, char **argv)` — `apps/ca.c:311-…`.
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, ca_options);` — `apps/ca.c:356`.
    let mut opts = Opts::init(argv, CA_OPTIONS);
    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/ca.c:357`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(ca_options); ret = 0; goto end;` —
            // `apps/ca.c:364-367`.
            OptMatch::Help => return not_landed("ca -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/ca.c:359-363`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // Every known option is accepted by the parser; the configuration and
            // `CA_DB` work that consumes it is not landed (see the header).
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }
    not_landed("ca")
}
