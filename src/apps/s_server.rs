//! Phase 17.1g — `apps/s_server.c`: the `openssl s_server` command.
//!
//! The command body (`apps/s_server.c:…`): parse the generated `S_SERVER_OPTIONS`
//! table, load the server certificate/key, build an `SSL_CTX` and a listening
//! `BIO`, accept connections and run the handshake and the read/write loop. The
//! transport, handshake, session cache and I/O loop are the libssl/network surface
//! this stratum does not own.
//!
//! ## What the court drives
//!
//! `s_server -bogus` (the parser's unknown-option refusal) and `s_server -accept`
//! (the parser's missing-value refusal). Both are decided by the option parser
//! before any key is loaded or socket opened.
//!
//! ## Recorded divergences (module header)
//!
//! * **The network/TLS surface is not landed.** The default `server.pem` key load,
//!   the `-accept`/`-port`/`-unix` listener, the handshake, the session cache and
//!   the I/O loop reach [`not_landed`](crate::apps::openssl::not_landed) after the
//!   parse.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::S_SERVER_OPTIONS;

/// `int s_server_main(int argc, char **argv)` — `apps/s_server.c`.
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, s_server_options);`.
    let mut opts = Opts::init(argv, S_SERVER_OPTIONS);
    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(s_server_options); ret = 0; goto end;`.
            OptMatch::Help => return not_landed("s_server -help"),
            // `opthelp:`/`case OPT_ERR:` — the parser's refusal.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // Every known option is accepted by the parser; the listener and
            // handshake it configures is not landed (see the header).
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }
    not_landed("s_server")
}
