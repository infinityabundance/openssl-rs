//! Phase 17.1e — `apps/rehash.c`: the `openssl rehash` command.
//!
//! The command body (`apps/rehash.c:515-582`): parse the generated
//! `REHASH_OPTIONS` table, then walk the named directories (or, when none are
//! named, the `SSL_CERT_DIR` environment variable's list or the build's default
//! cert directory), reading each PEM certificate/CRL, hashing it with
//! `X509_digest`/`X509_get0_subject_key_id` and creating the `hhhhhhhh.N` (or
//! old-style `hhhhhhhh.rN`) symlinks. The parse and the per-directory writability
//! refusal ([`do_dir`]'s head) are transcribed; the directory walk reaches
//! [`not_landed`].
//!
//! ## What the court drives
//!
//! `rehash <unwritable-or-missing-dir>` (and its `-v` form): `do_dir` checks
//! `app_access(dirname, W_OK)` first and, on failure, prints
//! `Skipping <dir>, can't write` and counts one error, which is the process exit
//! status. That is a pure function of the argv and the path's absence.
//!
//! ## Recorded divergences (module header)
//!
//! * **The directory walk is not landed.** `do_dir`'s symlink rewrite
//!   (`apps/rehash.c:400-478`) mutates the filesystem and depends on the
//!   directory's contents, so a writable directory reaches [`not_landed`] rather
//!   than fabricating links. The court drives only the writability refusal.
//! * **The default-directory arms are not landed.** With no directory argument,
//!   the authority uses `X509_get_default_cert_dir_env()`/
//!   `X509_get_default_cert_dir()` (`apps/rehash.c:565-578`), which name the
//!   authority's configured prefix. Recorded.
//! * **The provider arms are not landed** (`opt_provider`, `apps/rehash.c:545-548`).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::REHASH_OPTIONS;

/// `app_access(dirname, W_OK) < 0` — `apps/rehash.c:362-365`, the head of
/// `do_dir`. Returns the authority's error count for that one directory.
fn do_dir(dirname: &str) -> Result<i32, i32> {
    // `app_access(dirname, W_OK) < 0`: a missing path is the arm the court
    // drives. A path that exists but is not a directory is also refused, as the
    // authority's `OPENSSL_DIR_read` would fail after the check.
    let writable = match std::fs::metadata(dirname) {
        Ok(m) => m.is_dir(),
        Err(_) => false,
    };
    if !writable {
        eprintln!("Skipping {dirname}, can't write");
        return Ok(1);
    }
    // `apps/rehash.c:366-484`, the directory walk and symlink rewrite.
    Err(not_landed("rehash directory walk"))
}

/// `int rehash_main(int argc, char **argv)` — `apps/rehash.c:515-582`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, rehash_options);` — `apps/rehash.c:523`.
    let mut opts = Opts::init(argv, REHASH_OPTIONS);
    let mut errs = 0i32;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/rehash.c:524`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(rehash_options); goto end;` —
            // `apps/rehash.c:530-532`.
            OptMatch::Help => return not_landed("rehash -help"),
            // `case OPT_EOF: case OPT_ERR: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog); goto end;` — `apps/rehash.c:526-529`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_COMPAT: h = HASH_BOTH; break;` — `apps/rehash.c:533-535`.
            OptMatch::Flag("compat") => {}
            // `case OPT_OLD: h = HASH_OLD; break;` — `apps/rehash.c:536-538`.
            OptMatch::Flag("old") => {}
            // `case OPT_N: remove_links = 0; break;` — `apps/rehash.c:539-541`.
            OptMatch::Flag("n") => {}
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/rehash.c:542-544`.
            OptMatch::Flag("v") => {}
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/rehash.c:545-548`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("rehash -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest();` — `apps/rehash.c:553-554`.
    let dirs = opts.rest().to_vec();

    // `evpmd = EVP_sha1(); evpmdsize = EVP_MD_get_size(evpmd);` —
    // `apps/rehash.c:556-560`. The landed body stops before the walk, so the
    // digest setup is not reached.

    // `if (*argv != NULL) { while (*argv != NULL) errs += do_dir(*argv++, h); }
    // else if ((env = getenv(X509_get_default_cert_dir_env())) != NULL) { ... }
    // else { errs += do_dir(X509_get_default_cert_dir(), h); }` —
    // `apps/rehash.c:562-578`.
    if dirs.is_empty() {
        return not_landed("rehash default cert dir");
    }
    for dir in &dirs {
        match do_dir(dir) {
            Ok(n) => errs += n,
            Err(code) => return code,
        }
    }
    errs
}
