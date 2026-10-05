//! Phase 17.1g — `apps/s_time.c`: the `openssl s_time` command.
//!
//! The command body (`apps/s_time.c:…`): parse the generated `S_TIME_OPTIONS`
//! table, connect to the host, and time repeated TLS handshakes. The connection and
//! the wall-clock benchmark are the libssl/network surface this stratum does not
//! own.
//!
//! ## What the court drives
//!
//! `s_time -bogus` (the parser's unknown-option refusal) and `s_time -connect` (the
//! parser's missing-value refusal). Both are decided by the option parser before
//! any connection is attempted.
//!
//! ## Recorded divergences (module header)
//!
//! * **The network and wall-clock surface is not landed.** The default
//!   `localhost:4433` connection, the handshake loop and the timing output are a
//!   function of the network and the machine and reach
//!   [`not_landed`](crate::apps::openssl::not_landed) after the parse.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::S_TIME_OPTIONS;

/// `int s_time_main(int argc, char **argv)` — `apps/s_time.c`.
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, s_time_options);`.
    let mut opts = Opts::init(argv, S_TIME_OPTIONS);
    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(s_time_options); goto end;`.
            OptMatch::Help => return not_landed("s_time -help"),
            // `case OPT_ERR: opthelp:` — the parser's refusal.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // Every known option is accepted by the parser; the connection and
            // timing loop is not landed (see the header).
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }
    not_landed("s_time")
}
