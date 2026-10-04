//! Phase 17.1e — `apps/gendsa.c`: the `openssl gendsa` command.
//!
//! The command body (`apps/gendsa.c:60-178`): parse the generated
//! `GENDSA_OPTIONS` table, read the one required `dsaparam-file` argument, then
//! load the RNG, load the DSA parameters through `load_keyparams`, build a DSA
//! keygen context and write the generated private key. The parse and the
//! argument check are transcribed; the generation path reaches [`not_landed`] at
//! `app_RAND_load`.
//!
//! ## What the court drives
//!
//! Only the argument check, which finishes before any randomness:
//! `gendsa` (the missing-argument refusal). The parameter-load and generation
//! arms are random or draw pointer-bearing error tails and are recorded.
//!
//! ## Recorded divergences (module header)
//!
//! * **Key generation is not landed.** `app_RAND_load` (`apps/gendsa.c:120-121`),
//!   `opt_cipher`, `app_passwd`, `bio_open_owner`, `load_keyparams`,
//!   `app_keygen` and `PEM_write_bio_PrivateKey` are `apps/lib` helpers this
//!   stratum does not own, and the generated key is random besides, so
//!   `gendsa <params>` reaches [`not_landed`]. `gendsa <missing-file>` pairs that
//!   with the authority's `load_keyparams` "Could not open …" text and its
//!   pointer-bearing `ERR_print_errors` tail, which is not diffed.
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/gendsa.c:72`); an
//!   otherwise-unknown option is the parser's `Unknown option` refusal. Not
//!   driven.
//! * **`-engine`, `-rand`/`-writerand` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::GENDSA_OPTIONS;

/// `FORMAT_UNDEF` — `apps/include/fmt.h:27` (the `load_keyparams` format).
const FORMAT_UNDEF: c_int = 0;

/// `int gendsa_main(int argc, char **argv)` — `apps/gendsa.c:60-178`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, gendsa_options);`
    // — `apps/gendsa.c:72-73`.
    let mut opts = Opts::init(argv, GENDSA_OPTIONS);
    let mut _outfile: Option<String> = None;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/gendsa.c:74`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: ret = 0; opt_help(gendsa_options); goto end;` —
            // `apps/gendsa.c:81-84`.
            OptMatch::Help => return not_landed("gendsa -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/gendsa.c:76-80`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/gendsa.c:85-87`.
            OptMatch::Value("out", v) => _outfile = Some(v),
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` —
            // `apps/gendsa.c:88-90`.
            OptMatch::Value("passout", _) => return not_landed("gendsa -passout"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/gendsa.c:91-93`.
            OptMatch::Value("engine", _) => return not_landed("gendsa -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/gendsa.c:94-97`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("gendsa -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/gendsa.c:98-101`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("gendsa -provider"),
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/gendsa.c:102-104`.
            OptMatch::Value("", _) => {}
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/gendsa.c:105-107`.
            OptMatch::Flag("verbose") => {}
            // `case OPT_QUIET: verbose = 0; break;` — `apps/gendsa.c:108-110`.
            OptMatch::Flag("quiet") => {}
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg("params file")) goto opthelp; argv = opt_rest();
    // dsaparams = argv[0];` — `apps/gendsa.c:114-118`.
    if !opts.check_rest_arg(Some("params file")) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_RAND_load()) goto end;` — `apps/gendsa.c:120-121`. The RNG load
    // and every step after it are `apps/lib` helpers this stratum does not own
    // (see the header).
    let _ = FORMAT_UNDEF;
    not_landed("gendsa key generation (app_RAND_load absent)")
}
