//! Phase 17.1g — `apps/s_client.c`: the `openssl s_client` command.
//!
//! The command body (`apps/s_client.c:943-…`): parse the generated
//! `S_CLIENT_OPTIONS` table, build an `SSL_CTX`/`SSL` and a `BIO` connection to the
//! `-connect` host, run the TLS handshake and then the read/write loop. The
//! transport, handshake and I/O loop are the libssl/network surface this stratum
//! does not own.
//!
//! ## What the court drives
//!
//! `s_client -bogus` (the parser's unknown-option refusal) and `s_client -connect`
//! (the parser's missing-value refusal). Both are decided by the option parser
//! before any connection is attempted.
//!
//! ## Recorded divergences (module header)
//!
//! * **The network/TLS surface is not landed.** The default connection
//!   (`localhost:4433`), the `-connect`/`-host`/`-port`/`-unix` transport, the
//!   handshake, the `-tls1_3`/`-servername`/`-cert`/`-key` options and the
//!   application-data loop reach
//!   [`not_landed`](crate::apps::openssl::not_landed) after the parse.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::S_CLIENT_OPTIONS;

/// `int s_client_main(int argc, char **argv)` — `apps/s_client.c:943-…`.
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, s_client_options);` — `apps/s_client.c:1094`.
    let mut opts = Opts::init(argv, S_CLIENT_OPTIONS);
    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/s_client.c:1095`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(s_client_options); ret = 0; goto end;` —
            // `apps/s_client.c:1098-1101`.
            OptMatch::Help => return not_landed("s_client -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/s_client.c:1096-1099`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // Every known option is accepted by the parser; the transport and
            // handshake it configures is not landed (see the header).
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }
    not_landed("s_client")
}
