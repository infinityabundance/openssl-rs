//! Phase 17.1 — `apps/skeyutl.c`: the `openssl skeyutl` command.
//!
//! The whole command body (`apps/skeyutl.c:40-135`): parse the generated
//! `SKEYUTL_OPTIONS` table, then require a `-skeymgmt` or `-cipher` selector.
//! With no selector it prints `Either -skeymgmt -or -cipher option should be
//! specified`; with a selector but no `-genkey` it prints `Key generation is the
//! only supported operation as of now`; with `-genkey` it fetches an
//! `EVP_SKEYMGMT` and generates an opaque key. The `EVP_SKEY` API is landed
//! (`src/evp/skeymgmt.rs`), so the body is transcribed against it.
//!
//! ## What the court drives
//!
//! * The two no-selector refusals (`skeyutl`, `skeyutl -genkey`) and the
//!   selector-without-`-genkey` refusal (`skeyutl -skeymgmt foo`): all three have
//!   fixed text, an empty error queue and exit 1.
//! * `-genkey` *generation* is not driven: `EVP_SKEY_generate` is random, and a
//!   failing `EVP_SKEYMGMT_fetch` would render `ERR_print_errors`' pointer-bearing
//!   lines, which are not deterministic.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-cipher` is not landed.** `opt_cipher_any` (`apps/lib/opt.c:430-438`)
//!   fetches the cipher through `app_get0_libctx`/`app_get0_propq` and the legacy
//!   `EVP_get_cipherbyname` fallback, all `apps/lib` helpers this stratum does not
//!   own. A named `-cipher` therefore reaches [`not_landed`] rather than a
//!   fabricated fetch; the no-selector and `-skeymgmt` arms do not need it.
//! * **`-skeyopt` with `-genkey` is not landed.** `app_params_new_from_opts`
//!   (`apps/lib/app_params.c`) converts the `-skeyopt opt:value` stack into
//!   `OSSL_PARAM`s; that helper is unlanded. An empty option stack (the only
//!   `-genkey` shape this stratum can drive) passes NULL, exactly as the authority
//!   does for a NULL stack.
//! * **`-help` is not landed.** `opt_help` is the boundary [`crate::apps::opt`]
//!   records.
//! * The provider-selection arms (`-provider` etc.) reach the unlanded
//!   `opt_provider` (`apps/skeyutl.c:79-82`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_char;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SKEYUTL_OPTIONS;
use crate::evp::cipher::EVP_CIPHER_free;
use crate::evp::skeymgmt::{
    EVP_SKEYMGMT_fetch, EVP_SKEYMGMT_free, EVP_SKEY_free, EVP_SKEY_generate, EVP_SKEY_get0_key_id,
    EVP_SKEY_get0_provider_name, EVP_SKEY_get0_skeymgmt_name,
};
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::sys::stderr;
use crate::runtime::bio::{Bio, BIO_NOCLOSE};
use crate::runtime::err::ERR_print_errors;

/// `bio_err` — `apps/lib/apps.c`'s stderr BIO (`dup_bio_err`).
fn bio_err() -> *mut Bio {
    // SAFETY: `stderr` is the C library's live standard error `FILE *`.
    unsafe { BIO_new_fp(stderr.cast(), BIO_NOCLOSE) }
}

/// Read a NUL-terminated `*const c_char` into a Rust `String`; NULL is `None`.
fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        // SAFETY: a non-NULL OpenSSL string is NUL-terminated and `'static` or
        // owned for the caller's use.
        Some(
            unsafe { core::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// `int skeyutl_main(int argc, char **argv)` — `apps/skeyutl.c:40-135`.
#[allow(clippy::never_loop)] // every arm breaks or returns; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, skeyutl_options);` — `apps/skeyutl.c:52`.
    let mut opts = Opts::init(argv, SKEYUTL_OPTIONS);
    let mut ret = 1i32;
    let mut genkey = false;
    let mut ciphername: Option<String> = None;
    let mut skeymgmt: Option<String> = None;
    // `sk_OPENSSL_STRING_new_null()` — `apps/skeyutl.c:47`; the pushed `-skeyopt`
    // values. Kept as a Rust `Vec` because the body only counts/iterates them.
    let mut skeyopts: Vec<String> = Vec::new();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/skeyutl.c:53`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(skeyutl_options); ret = 0; goto end;` —
            // `apps/skeyutl.c:60-63`.
            OptMatch::Help => return not_landed("skeyutl -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/skeyutl.c:55-59`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_GENKEY: genkey = 1; break;` — `apps/skeyutl.c:64-66`.
            OptMatch::Flag("genkey") => genkey = true,
            // `case OPT_CIPHER: ciphername = opt_arg(); break;` — `apps/skeyutl.c:67-69`.
            OptMatch::Value("cipher", v) => ciphername = Some(v),
            // `case OPT_SKEYOPT: ... sk_OPENSSL_STRING_push(skeyopts, opt_arg());`
            // — `apps/skeyutl.c:70-75`. The stack's allocation failure is
            // unreachable here, so the authority's `out of memory` arm is not
            // reached.
            OptMatch::Value("skeyopt", v) => skeyopts.push(v),
            // `case OPT_SKEYMGMT: skeymgmt = opt_arg(); break;` — `apps/skeyutl.c:76-78`.
            OptMatch::Value("skeymgmt", v) => skeymgmt = Some(v),
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/skeyutl.c:79-82`. `opt_provider` is unlanded.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("skeyutl -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_cipher_any(ciphername, &cipher)) goto opthelp;` —
    // `apps/skeyutl.c:87-88`. `opt_cipher_any(NULL, ...)` answers 1 with `cipher`
    // left NULL; a named cipher needs the unlanded `apps/lib` fetch (see header).
    if ciphername.is_some() {
        return not_landed("skeyutl -cipher");
    }
    let cipher: *mut crate::evp::cipher::EvpCipher = core::ptr::null_mut();

    // `if (cipher == NULL && skeymgmt == NULL) { BIO_printf(bio_err, "Either
    // -skeymgmt -or -cipher option should be specified\n"); goto end; }` —
    // `apps/skeyutl.c:90-93`.
    if cipher.is_null() && skeymgmt.is_none() {
        let err = bio_err();
        eprintln!("Either -skeymgmt -or -cipher option should be specified");
        // SAFETY: `err` is a live stderr BIO; the queue is empty, so this is a
        // no-op, exactly as in the authority (`apps/skeyutl.c:129`).
        unsafe { ERR_print_errors(err) };
        // SAFETY: `err` is NOCLOSE, so `stderr` stays open.
        unsafe { crate::runtime::bio::BIO_free(err) };
        return ret;
    }

    if genkey {
        // `if (skeyopts != NULL) ... app_params_new_from_opts(skeyopts, ...)` —
        // `apps/skeyutl.c:103-104`. `app_params_new_from_opts` is unlanded; with
        // an empty stack the authority passes NULL, which is what this arm does.
        if !skeyopts.is_empty() {
            return not_landed("skeyutl -genkey -skeyopt");
        }
        let mgmt_name = skeymgmt.clone().unwrap_or_default();
        // `mgmt = EVP_SKEYMGMT_fetch(app_get0_libctx(), skeymgmt ? skeymgmt :
        // EVP_CIPHER_name(cipher), app_get0_propq());` — `apps/skeyutl.c:98-100`.
        // The two `app_get0_*` helpers are NULL here (no `-libctx`/`-propquery`
        // given), the no-context default.
        let cs = std::ffi::CString::new(mgmt_name.as_str()).unwrap_or_default();
        // SAFETY: `cs` is NUL-terminated; both context/property pointers are NULL.
        let mgmt =
            unsafe { EVP_SKEYMGMT_fetch(core::ptr::null_mut(), cs.as_ptr(), core::ptr::null()) };
        if mgmt.is_null() {
            // `goto end;` — `apps/skeyutl.c:102`. `ERR_print_errors` renders the
            // fetch failure; not driven (see the header).
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { crate::runtime::bio::BIO_free(err) };
            return ret;
        }

        // `skey = EVP_SKEY_generate(app_get0_libctx(), skeymgmt ? skeymgmt :
        // EVP_CIPHER_name(cipher), app_get0_propq(), params);` —
        // `apps/skeyutl.c:106-108`. Random; transcribed, not driven.
        // SAFETY: `cs` is NUL-terminated; the pointers are NULL and `params` NULL.
        let skey = unsafe {
            EVP_SKEY_generate(
                core::ptr::null_mut(),
                cs.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if skey.is_null() {
            // `BIO_printf(bio_err, "Error creating opaque key for skeymgmt %s\n",
            // ...); ERR_print_errors(bio_err);` — `apps/skeyutl.c:110-113`.
            eprintln!("Error creating opaque key for skeymgmt {mgmt_name}");
            let err = bio_err();
            // SAFETY: `err` is a live stderr BIO.
            unsafe { ERR_print_errors(err) };
            // SAFETY: `err` is NOCLOSE.
            unsafe { crate::runtime::bio::BIO_free(err) };
        } else {
            // `BIO_printf(bio_out, "An opaque key identified by %s is created\n",
            // key_name ? key_name : "<unknown>");` and its two siblings —
            // `apps/skeyutl.c:117-120`.
            // SAFETY: `skey` is live.
            let key_name = unsafe { EVP_SKEY_get0_key_id(skey) };
            let key_name = cstr(key_name).unwrap_or_else(|| "<unknown>".to_string());
            // SAFETY: `skey` is live.
            let provider = cstr(unsafe { EVP_SKEY_get0_provider_name(skey) });
            // SAFETY: `skey` is live.
            let mgmt0 = cstr(unsafe { EVP_SKEY_get0_skeymgmt_name(skey) });
            println!("An opaque key identified by {key_name} is created");
            // `BIO_printf(bio_out, "Provider: %s\n", ...)` renders `<NULL>` for a
            // NULL answer, matching `crypto/err/err.c`'s `_dopr`.
            println!(
                "Provider: {}",
                provider.unwrap_or_else(|| "<NULL>".to_string())
            );
            println!(
                "Key management: {}",
                mgmt0.unwrap_or_else(|| "<NULL>".to_string())
            );
            ret = 0;
        }
        // SAFETY: `skey` is NULL or live and not freed again; `mgmt` is live.
        unsafe { EVP_SKEY_free(skey) };
        // SAFETY: `mgmt` is live and not freed again.
        unsafe { EVP_SKEYMGMT_free(mgmt) };
        return ret;
    }

    // `else { BIO_printf(bio_err, "Key generation is the only supported operation
    // as of now\n"); }` — `apps/skeyutl.c:124-126`.
    let err = bio_err();
    eprintln!("Key generation is the only supported operation as of now");
    // `end: ERR_print_errors(bio_err); ...` — `apps/skeyutl.c:128-129`.
    // SAFETY: `err` is a live stderr BIO; the queue is empty for the driven arm.
    unsafe { ERR_print_errors(err) };
    // SAFETY: `err` is NOCLOSE.
    unsafe { crate::runtime::bio::BIO_free(err) };
    // `EVP_CIPHER_free(cipher);` — `apps/skeyutl.c:133`.
    // SAFETY: `cipher` is NULL here.
    unsafe { EVP_CIPHER_free(cipher) };
    ret
}
