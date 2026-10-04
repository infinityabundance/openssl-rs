//! Phase 17.1e — `apps/genpkey.c`: the `openssl genpkey` command.
//!
//! The command body (`apps/genpkey.c:124-342`): parse the generated
//! `GENPKEY_OPTIONS` table, build a keygen/paramgen context from `-paramfile`
//! (`init_keygen_file`) or `-algorithm` (`init_gen_str`), apply the `-pkeyopt`
//! controls, generate the key or parameters (`app_keygen`/`app_paramgen`) and
//! write it. The parse is transcribed; the generation path reaches [`not_landed`]
//! at `app_RAND_load`.
//!
//! ## What the court drives
//!
//! `genpkey` with neither `-paramfile` nor `-algorithm`: the authority
//! `app_RAND_load`s, finds no context and reaches `opthelp`
//! (`apps/genpkey.c:233-234`), which is the same fixed refusal this body prints.
//! Every generation arm is random or draws a pointer-bearing error tail.
//!
//! ## Recorded divergences (module header)
//!
//! * **Key/parameter generation is not landed.** `app_RAND_load`
//!   (`apps/genpkey.c:221-222`), `init_keygen_file`, `init_gen_str`,
//!   `app_keygen`/`app_paramgen`, `opt_cipher`, `app_passwd` and
//!   `mem_bio_to_file` are `apps/lib` helpers this stratum does not own, and the
//!   generated key is random besides, so an `-algorithm`/`-paramfile` arm reaches
//!   [`not_landed`]. `genpkey -algorithm <unknown>` pairs that with the
//!   authority's `Error initializing <alg> context` and its pointer-bearing
//!   `ERR_print_errors` tail, which is not diffed.
//! * **`opt_set_unknown_name("cipher")` is not landed** (`apps/genpkey.c:141`).
//! * **`-engine`, `-config`, `-rand`/`-writerand` and the provider arms are not
//!   landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records; the authority also prints the
//!   `show_gen_pkeyopt` table after help.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::GENPKEY_OPTIONS;

/// `FORMAT_PEM` — `apps/include/fmt.h:32`.
const FORMAT_PEM: c_int = 5 | 0x8000;
/// `FORMAT_ASN1` — `apps/include/fmt.h:31`.
const FORMAT_ASN1: c_int = 4;

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms of
/// `apps/lib/opt.c:277-365`.
fn opt_format(prog: &str, s: &str, result: &mut c_int) -> bool {
    match s.as_bytes().first().copied() {
        Some(b'P') | Some(b'p') if s.len() == 1 || s == "PEM" || s == "pem" => {
            *result = FORMAT_PEM;
            true
        }
        Some(b'D') | Some(b'd') => {
            *result = FORMAT_ASN1;
            true
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

/// `int genpkey_main(int argc, char **argv)` — `apps/genpkey.c:124-342`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv,
    // genpkey_options);` — `apps/genpkey.c:141-142`.
    let mut opts = Opts::init(argv, GENPKEY_OPTIONS);
    let mut _outfile: Option<String> = None;
    let mut _outpubkeyfile: Option<String> = None;
    let mut _passarg: Option<String> = None;
    let mut outformat = FORMAT_PEM;
    let mut text = false;
    let mut _do_param = false;
    let mut _algname: Option<String> = None;
    let mut _paramfile: Option<String> = None;
    let mut pkeyopts: Vec<String> = Vec::new();
    let mut _verbose = true;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/genpkey.c:146`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: ret = 0; opt_help(genpkey_options);
            // show_gen_pkeyopt(...); goto end;` — `apps/genpkey.c:153-157`.
            OptMatch::Help => return not_landed("genpkey -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/genpkey.c:148-152`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &outformat)) goto opthelp;` — `apps/genpkey.c:158-161`.
            OptMatch::Value("outform", v) => {
                if !opt_format(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/genpkey.c:162-164`.
            OptMatch::Value("out", v) => _outfile = Some(v),
            // `case OPT_OUTPUBKEY: outpubkeyfile = opt_arg(); break;` —
            // `apps/genpkey.c:165-167`.
            OptMatch::Value("outpubkey", v) => _outpubkeyfile = Some(v),
            // `case OPT_PASS: passarg = opt_arg(); break;` — `apps/genpkey.c:168-170`.
            OptMatch::Value("pass", v) => _passarg = Some(v),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/genpkey.c:171-173`.
            OptMatch::Value("engine", _) => return not_landed("genpkey -engine"),
            // `case OPT_PARAMFILE: if (do_param == 1) goto opthelp; paramfile =
            // opt_arg();` — `apps/genpkey.c:174-178`.
            OptMatch::Value("paramfile", v) => {
                if _do_param {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                _paramfile = Some(v);
            }
            // `case OPT_ALGORITHM: algname = opt_arg(); break;` —
            // `apps/genpkey.c:179-181`.
            OptMatch::Value("algorithm", v) => _algname = Some(v),
            // `case OPT_PKEYOPT: ... push ...` — `apps/genpkey.c:182-185`.
            OptMatch::Value("pkeyopt", v) => pkeyopts.push(v),
            // `case OPT_QUIET: verbose = 0; break;` — `apps/genpkey.c:186-188`.
            OptMatch::Flag("quiet") => _verbose = false,
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/genpkey.c:189-191`.
            OptMatch::Flag("verbose") => _verbose = true,
            // `case OPT_GENPARAM: do_param = 1; break;` — `apps/genpkey.c:192-194`.
            OptMatch::Flag("genparam") => _do_param = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/genpkey.c:195-197`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/genpkey.c:198-200`.
            OptMatch::Value("", _) => {}
            // `case OPT_CONFIG: conf = app_load_config_modules(opt_arg());` —
            // `apps/genpkey.c:201-205`.
            OptMatch::Value("config", _) => return not_landed("genpkey -config"),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/genpkey.c:206-209`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("genpkey -provider"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/genpkey.c:210-213`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("genpkey -rand")
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/genpkey.c:217-219`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (!app_RAND_load()) goto end;` — `apps/genpkey.c:221-222`. Skipped (see
    // the header).

    // `if (paramfile != NULL) { if (!init_keygen_file(&ctx, paramfile, ...))
    // goto end; } if (algname != NULL) { if (!init_gen_str(&ctx, algname, ...))
    // goto end; } if (ctx == NULL) goto opthelp;` — `apps/genpkey.c:224-234`.
    let _ = (outformat, text, pkeyopts);
    if _algname.is_none() && _paramfile.is_none() {
        // No context to build: the authority's `ctx == NULL` reaches `opthelp`.
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // The context build and generation are `apps/lib`'s (see the header).
    not_landed("genpkey key/parameter generation (app_keygen absent)")
}
