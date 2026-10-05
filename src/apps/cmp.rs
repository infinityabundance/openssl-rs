//! Phase 17.1g — `apps/cmp.c`: the `openssl cmp` command.
//!
//! The command body (`apps/cmp.c:3673-…`): a pre-scan (`handle_opts_upfront`) reads
//! `-config`/`-section`/`-verbosity`, the default CMP configuration is loaded and
//! logged, then the generated `CMP_OPTIONS` table is parsed and the RFC 4210 CMP
//! client/server exchange runs over `OSSL_CMP_CTX`. The whole exchange is the
//! `OSSL_CMP`/HTTP/network surface this stratum does not own.
//!
//! ## What the court drives
//!
//! Nothing. `cmp`'s parser refusals (`cmp -bogus`, `cmp -server`) are preceded by
//! the CMP logging preamble (`cmp_main:<authority path>/apps/cmp.c:3695:CMP info:
//! using section(s) 'cmp' …`), which names the authority's own source path and
//! cannot be reproduced by the candidate; its no-operation arm calls `opt_help`.
//! Both are recorded rather than diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **The whole CMP surface is not landed.** The pre-parse logging, the config
//!   section reads, the `OSSL_CMP_CTX` construction, the RFC 4210 message exchange
//!   and the `-server`/`-tls_*`/HTTP transport reach
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **The refusal/usage arms are recorded due to the logging preamble** (see
//!   above); the option parser is transcribed, but the arms cannot be diffed.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::CMP_OPTIONS;

/// `int cmp_main(int argc, char **argv)` — `apps/cmp.c:3673-…`.
pub fn main(argv: &[String]) -> i32 {
    // `handle_opts_upfront(argc, argv)` reads -config/-section/-verbosity, then the
    // CMP config/`OSSL_CMP_CTX` setup runs before `get_opts`. None of that surface
    // is landed, so the whole body stops here (see the header).
    let mut opts = Opts::init(argv, CMP_OPTIONS);
    loop {
        // `ret = get_opts(argc, argv);` — `apps/cmp.c:3733`.
        match opts.next() {
            OptMatch::End => break,
            OptMatch::Help => return not_landed("cmp -help"),
            // `case OPT_ERR: …` — the parser's refusal.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }
    not_landed("cmp")
}
