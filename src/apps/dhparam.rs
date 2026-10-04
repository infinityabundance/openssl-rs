//! Phase 17.1e — `apps/dhparam.c`: the `openssl dhparam` command.
//!
//! The command body (`apps/dhparam.c:94-381`): parse the generated
//! `DHPARAM_OPTIONS` table, read the optional `numbits`, then either generate DH
//! (or DSA) parameters or read a fixed `DH PARAMETERS` PEM through the decoder,
//! optionally print its text (`EVP_PKEY_print_params`) and check it
//! (`EVP_PKEY_param_check`), and re-encode it through the provider encoder unless
//! `-noout`. The parse, the read path, the text/check arms and the encoder arm
//! are transcribed.
//!
//! ## What the court drives
//!
//! `dhparam -in <dhparams.pem> -text -noout`, `-noout` and `-check` over the
//! fixed `DH PARAMETERS` fixture. The parameter text, the check message and the
//! re-encoded PEM are a pure function of the fixture. `dhparam 8` (generation) is
//! random and recorded.
//!
//! ## Recorded divergences (module header)
//!
//! * **Parameter generation is not landed.** `app_RAND_load`
//!   (`apps/dhparam.c:182-183`), `app_paramgen` and the progress callback are
//!   `apps/lib` helpers this stratum does not own, and the generated parameters
//!   are random besides, so a numeric `numbits` reaches [`not_landed`].
//! * **The read path uses [`crate::apps::keyio::load_keyparams`], not
//!   `OSSL_DECODER`.** The authority builds an `OSSL_DECODER_CTX` and tries
//!   `DH`/`DHX` (`apps/dhparam.c:258-313`); this module reads the same PEM
//!   through `PEM_read_bio_Parameters_ex`. For a single well-formed `DH
//!   PARAMETERS` PEM the object is identical; the load-failure text is keyio's
//!   and is not diffed.
//! * **`dsa_to_dh` and the `-dsaparam` conversion are not driven.**
//! * **`-engine`, `-rand`/`-writerand` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_keyparams, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::DHPARAM_OPTIONS;
use crate::encoder_lib::OSSL_ENCODER_to_bio;
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_is_a, EVP_PKEY_print_params};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::pmeth_check::EVP_PKEY_param_check;

/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS` — `include/openssl/core_dispatch.h:644`.
const SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
/// `DEFBITS` — `apps/dhparam.c:31`.
const DEFBITS: c_int = 2048;

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms of
/// `apps/lib/opt.c:277-365`.
fn opt_format(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'P') | Some(b'p') if b.len() == 1 || s == "PEM" || s == "pem" => {
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

/// `strtol(value, &endp, 0)` — `apps/lib/opt.c:590-616`.
fn strtol_base0(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let (radix, mut j) = if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] | 0x20) == b'x' {
        (16u32, i + 2)
    } else if i < b.len() && b[i] == b'0' {
        (8u32, i)
    } else {
        (10u32, i)
    };
    let digits_start = j;
    let mut acc: i128 = 0;
    let mut overflow = false;
    while j < b.len() {
        let d = match b[j] {
            b'0'..=b'9' => u32::from(b[j] - b'0'),
            b'a'..=b'f' if radix == 16 => u32::from(b[j] - b'a') + 10,
            b'A'..=b'F' if radix == 16 => u32::from(b[j] - b'A') + 10,
            _ => break,
        };
        if d >= radix {
            break;
        }
        acc = acc * i128::from(radix) + i128::from(d);
        if acc > i128::from(i64::MAX) + 1 {
            overflow = true;
            acc = 0;
        }
        j += 1;
    }
    if j == digits_start || j != b.len() {
        return None;
    }
    let mag = if overflow {
        i128::from(i64::MAX) + 1
    } else {
        acc
    };
    let signed = if neg { -mag } else { mag };
    if signed < i128::from(i64::MIN) || signed > i128::from(i64::MAX) {
        return None;
    }
    Some(signed as i64)
}

/// `static void opt_number_error(const char *v)` — `apps/lib/opt.c:568-587`.
fn opt_number_error(prog: &str, v: &str) {
    if v.starts_with("0x") || v.starts_with("0X") {
        eprintln!("{prog}: Can't parse \"{v}\" as a hexadecimal number");
    } else if v.starts_with('0') {
        eprintln!("{prog}: Can't parse \"{v}\" as an octal number");
    } else {
        eprintln!("{prog}: Can't parse \"{v}\" as a number");
    }
}

/// `int opt_int(const char *value, int *result)` — `apps/lib/opt.c:542-556`.
fn opt_int(prog: &str, value: &str) -> Option<c_int> {
    let l = match strtol_base0(value) {
        Some(l) => l,
        None => {
            opt_number_error(prog, value);
            return None;
        }
    };
    let r = l as c_int;
    if i64::from(r) != l {
        eprintln!("{prog}: Value \"{value}\" outside integer range");
        return None;
    }
    Some(r)
}

/// `int dhparam_main(int argc, char **argv)` — `apps/dhparam.c:94-381`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, dhparam_options);` — `apps/dhparam.c:106`.
    let mut opts = Opts::init(argv, DHPARAM_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut informat = FORMAT_PEM;
    let mut outformat = FORMAT_PEM;
    let mut dsaparam = false;
    let mut text = false;
    let mut check = false;
    let mut noout = false;
    let mut num: c_int = 0;
    let mut g: c_int = 0;
    let mut verbose = true;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/dhparam.c:107`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(dhparam_options); ret = 0; goto end;` —
            // `apps/dhparam.c:114-117`.
            OptMatch::Help => return not_landed("dhparam -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/dhparam.c:109-113`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &informat)) goto opthelp;` — `apps/dhparam.c:118-121`.
            OptMatch::Value("inform", v) => {
                if !opt_format(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &outformat)) goto opthelp;` — `apps/dhparam.c:122-125`.
            OptMatch::Value("outform", v) => {
                if !opt_format(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/dhparam.c:126-128`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/dhparam.c:129-131`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/dhparam.c:132-134`.
            OptMatch::Value("engine", _) => return not_landed("dhparam -engine"),
            // `case OPT_CHECK: check = 1; break;` — `apps/dhparam.c:135-137`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_TEXT: text = 1; break;` — `apps/dhparam.c:138-140`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_DSAPARAM: dsaparam = 1; break;` — `apps/dhparam.c:141-143`.
            OptMatch::Flag("dsaparam") => dsaparam = true,
            // `case OPT_2: g = 2; break;` — `apps/dhparam.c:144-146`.
            OptMatch::Flag("2") => g = 2,
            // `case OPT_3: g = 3; break;` — `apps/dhparam.c:147-149`.
            OptMatch::Flag("3") => g = 3,
            // `case OPT_5: g = 5; break;` — `apps/dhparam.c:150-152`.
            OptMatch::Flag("5") => g = 5,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/dhparam.c:153-155`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/dhparam.c:156-158`.
            OptMatch::Flag("verbose") => verbose = true,
            // `case OPT_QUIET: verbose = 0; break;` — `apps/dhparam.c:159-161`.
            OptMatch::Flag("quiet") => verbose = false,
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/dhparam.c:162-165`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("dhparam -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/dhparam.c:166-169`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("dhparam -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (argc == 1) { if
    // (!opt_int(argv[0], &num) || num <= 0) goto opthelp; } else if
    // (!opt_check_rest_arg(NULL)) { goto opthelp; }` — `apps/dhparam.c:173-181`.
    if opts.num_rest() == 1 {
        match opt_int(opts.prog(), opts.rest()[0].as_str()) {
            Some(n) if n > 0 => num = n,
            _ => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    } else if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_RAND_load()) goto end;` — `apps/dhparam.c:182-183`. Skipped
    // (see the header); unobservable for the read/text/check arms.

    // `if (g && !num) num = DEFBITS;` — `apps/dhparam.c:185-186`.
    if g != 0 && num == 0 {
        num = DEFBITS;
    }
    // `if (dsaparam && g) { BIO_printf(bio_err, "Error, generator may not be
    // chosen for DSA parameters\n"); goto end; }` — `apps/dhparam.c:188-192`.
    if dsaparam && g != 0 {
        eprintln!("Error, generator may not be chosen for DSA parameters");
        return 1;
    }
    // `if (num && !g) g = 2;` — `apps/dhparam.c:194-196`.
    if num != 0 && g == 0 {
        g = 2;
    }

    if num != 0 {
        // `if (infile != NULL) BIO_printf(bio_err, "Warning, input file %s
        // ignored\n", infile);` — `apps/dhparam.c:201-203`.
        if let Some(f) = &infile {
            eprintln!("Warning, input file {f} ignored");
        }
        // `ctx = EVP_PKEY_CTX_new_from_name(...); ... app_paramgen(ctx, alg);` —
        // `apps/dhparam.c:205-245`. `app_paramgen` is `apps/lib`'s, and the
        // generated parameters are random (see the header).
        let _ = (verbose, g);
        return not_landed("dhparam parameter generation (app_paramgen absent)");
    }

    // The read path: `keytype = "DH"; in = bio_open_default(infile, 'r',
    // informat); ... OSSL_DECODER_CTX_new_for_pkey(...)` —
    // `apps/dhparam.c:257-333`, reduced to keyio's `load_keyparams`.
    if infile.is_none() {
        // The authority reads stdin; the court does not drive it.
        return not_landed("dhparam (no -in)");
    }
    let tmppkey = load_keyparams(infile.as_deref(), informat, "DH", "DH parameters");
    if tmppkey.is_null() {
        return 1;
    }
    // `if (!EVP_PKEY_is_a(tmppkey, "DH") && !EVP_PKEY_is_a(tmppkey, "DHX")) {
    // BIO_printf(bio_err, "Error, unable to load DH parameters\n"); goto end; }`
    // — `apps/dhparam.c:325-329`.
    // SAFETY: `tmppkey` is live; the names are static literals.
    let is_dh = unsafe { EVP_PKEY_is_a(tmppkey, c"DH".as_ptr()) };
    // SAFETY: as above.
    let is_dhx = unsafe { EVP_PKEY_is_a(tmppkey, c"DHX".as_ptr()) };
    if is_dh == 0 && is_dhx == 0 {
        eprintln!("Error, unable to load DH parameters");
        // SAFETY: `tmppkey` is live and not freed again.
        unsafe { EVP_PKEY_free(tmppkey) };
        return 1;
    }
    let pkey = tmppkey;

    // `out = bio_open_default(outfile, 'w', outformat); if (out == NULL) goto
    // end;` — `apps/dhparam.c:335-337`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `pkey` is live and not freed again.
        unsafe { EVP_PKEY_free(pkey) };
        return 1;
    }
    let mut ret = 1i32;

    // `if (text) EVP_PKEY_print_params(out, pkey, 4, NULL);` —
    // `apps/dhparam.c:339-340`.
    if text {
        // SAFETY: `out`/`pkey` are live; indent 4 and a NULL print context.
        unsafe { EVP_PKEY_print_params(out, pkey, 4, core::ptr::null_mut()) };
    }

    // `if (check) { ctx = EVP_PKEY_CTX_new_from_pkey(...); ... EVP_PKEY_param_check
    // ... }` — `apps/dhparam.c:342-353`.
    if check {
        // SAFETY: `pkey` is live; both context/property pointers are NULL.
        let ctx =
            unsafe { EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null()) };
        if ctx.is_null() {
            eprintln!("Error, failed to check DH parameters");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: as above.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ctx` is live.
        let ok = unsafe { EVP_PKEY_param_check(ctx) };
        // SAFETY: `ctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        if ok <= 0 {
            eprintln!("Error, invalid parameters generated");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: as above.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        eprintln!("DH parameters appear to be ok.");
    }

    // `if (!noout) { OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,
    // OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, outformat == FORMAT_ASN1 ? "DER" :
    // "PEM", NULL, NULL); ... }` — `apps/dhparam.c:355-369`.
    if !noout {
        let output_type = if outformat == FORMAT_ASN1 {
            "DER"
        } else {
            "PEM"
        };
        let out_type_c = std::ffi::CString::new(output_type).unwrap_or_default();
        // SAFETY: `pkey` is live; the type string is NUL-terminated; propq NULL.
        let ectx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey,
                SELECT_DOMAIN_PARAMETERS,
                out_type_c.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if ectx.is_null() {
            eprintln!("Error, unable to write DH parameters");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: as above.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ectx`/`out` are live.
        let ok = unsafe { OSSL_ENCODER_to_bio(ectx, out) };
        // SAFETY: `ectx` is live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
        if ok == 0 {
            eprintln!("Error, unable to write DH parameters");
            // SAFETY: `pkey`/`out` are live and not freed again.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: as above.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }
    ret = 0;

    // `end: ... BIO_free_all(out); EVP_PKEY_free(pkey); ...` —
    // `apps/dhparam.c:371-380`.
    // SAFETY: `pkey`/`out` are live and not freed again.
    unsafe { EVP_PKEY_free(pkey) };
    // SAFETY: as above.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
