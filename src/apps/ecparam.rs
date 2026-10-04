//! Phase 17.1d — `apps/ecparam.c`: the `openssl ecparam` command.
//!
//! The command body (`apps/ecparam.c:105-372`): parse the generated `ECPARAM_OPTIONS`
//! table, then list the built-in curves (`-list_curves`), generate parameters from a
//! `-name` or load them from `-in`, optionally `-check`/`-check_named` them, print them
//! (`-text`) and re-encode them through `OSSL_ENCODER_CTX_new_for_pkey`/
//! `OSSL_ENCODER_to_bio`. `list_builtin_curves` (`apps/ecparam.c:81-103`) is
//! transcribed whole.
//!
//! ## What the court drives
//!
//! `ecparam -list_curves` (the built-in curve table, fully build-independent), the
//! `-name prime256v1 -noout -text` parameter generation and the parser/`opt_format`
//! refusals. `app_RAND_load()` with no `-rand` is a no-op success in the authority
//! (`apps/lib/app_rand.c:66-79` iterates an empty `randfiles` stack), so the command's
//! own arms are reached without an RNG.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-engine` is not landed** (`apps/ecparam.c:191-193`).
//! * **`opt_format(OPT_FMT_PEMDER)` is reduced to its PEM/DER bodies**.
//! * **`opt_string`'s `point_format_options`/`asn1_encoding_options` vocabulary check is
//!   not landed**; a `-conv_form`/`-param_enc` value is carried to
//!   `EVP_PKEY_set_utf8_string_param`, which performs the same rejection at the provider
//!   boundary. Not driven by the court.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-rand`/`-writerand` and provider-selection arms reach unlanded `apps/lib`
//!   helpers (`opt_rand`, `opt_provider`); `app_RAND_load` with no `-rand` is the no-op
//!   success transcribed above.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::apps::keyio::{bio_open_default, load_keyparams, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::ECPARAM_OPTIONS;
use crate::ec::curve::{EC_get_builtin_curves, EcBuiltinCurve};
use crate::encoder_lib::OSSL_ENCODER_to_bio;
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pkey::{EVP_PKEY_print_params, EVP_PKEY_set_utf8_string_param};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
    EVP_PKEY_CTX_set_params,
};
use crate::evp::pmeth_check::EVP_PKEY_param_check;
use crate::evp::pmeth_gn::{EVP_PKEY_keygen, EVP_PKEY_keygen_init};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OsslParam};
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::Bio;
use crate::runtime::obj::OBJ_nid2sn;

/// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-651`.
const SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
const SELECT_ALL: c_int = 0x87;

/// `static int list_builtin_curves(BIO *out)` — `apps/ecparam.c:81-103`.
fn list_builtin_curves(out: *mut Bio) -> bool {
    // `crv_len = EC_get_builtin_curves(NULL, 0);` — `apps/ecparam.c:84`.
    // SAFETY: a NULL receiver asks for the count only.
    let crv_len = unsafe { EC_get_builtin_curves(core::ptr::null_mut(), 0) };
    let mut curves: Vec<EcBuiltinCurve> = Vec::with_capacity(crv_len);
    // SAFETY: the vector has room for `crv_len` rows; the receiver is its data pointer.
    let filled = unsafe { EC_get_builtin_curves(curves.as_mut_ptr(), crv_len) };
    // SAFETY: `filled` rows were initialised.
    unsafe { curves.set_len(filled) };

    for row in &curves {
        // `comment = curves[n].comment; sname = OBJ_nid2sn(curves[n].nid);` —
        // `apps/ecparam.c:90-91`.
        let sname = if row.comment.is_null() {
            String::from("CURVE DESCRIPTION NOT AVAILABLE")
        } else {
            // SAFETY: `row.comment` is a `'static` NUL-terminated string.
            unsafe { std::ffi::CStr::from_ptr(row.comment) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: `OBJ_nid2sn` answers NULL or a `'static` NUL-terminated name.
        let sn_ptr = OBJ_nid2sn(row.nid);
        let sn = if sn_ptr.is_null() {
            String::new()
        } else {
            // SAFETY: `sn_ptr` is NUL-terminated.
            unsafe { std::ffi::CStr::from_ptr(sn_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        // `BIO_printf(out, "  %-10s: ", sname); ... BIO_printf(out, "%s\n", comment);`
        // — `apps/ecparam.c:98-99`.
        let line = format!("  {sn:<10}: {sname}\n");
        // SAFETY: `out` is live; `line` is this frame's bytes.
        unsafe { BIO_write(out, line.as_ptr().cast(), line.len() as c_int) };
    }
    true
}

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`/`D`/`default` arms of
/// `apps/lib/opt.c:277-365` for `-inform`/`-outform`.
fn opt_format_pemder(prog: &str, s: &str, result: &mut c_int) -> bool {
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

/// `int ecparam_main(int argc, char **argv)` — `apps/ecparam.c:105-372`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, ecparam_options);` — `apps/ecparam.c:123`.
    let mut opts = Opts::init(argv, ECPARAM_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut curve_name: Option<String> = None;
    let mut asn1_encoding: Option<String> = None;
    let mut point_format: Option<String> = None;
    let mut informat = FORMAT_PEM;
    let mut outformat = FORMAT_PEM;
    let mut noout = false;
    let mut no_seed = false;
    let mut check = false;
    let mut check_named = false;
    let mut text = false;
    let mut genkey = false;
    let mut list_curves = false;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/ecparam.c:124`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(ecparam_options); ret = 0; goto end;` —
            // `apps/ecparam.c:131-134`.
            OptMatch::Help => return not_landed("ecparam -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/ecparam.c:126-130`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
            // goto opthelp;` — `apps/ecparam.c:135-138`.
            OptMatch::Value("inform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/ecparam.c:139-141`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
            // goto opthelp;` — `apps/ecparam.c:142-145`.
            OptMatch::Value("outform", v) => {
                if !opt_format_pemder(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/ecparam.c:146-148`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_TEXT: text = 1; break;` — `apps/ecparam.c:149-151`.
            OptMatch::Flag("text") => text = true,
            // `case OPT_CHECK: check = 1; break;` — `apps/ecparam.c:152-154`.
            OptMatch::Flag("check") => check = true,
            // `case OPT_CHECK_NAMED: check_named = 1; break;` — `apps/ecparam.c:155-157`.
            OptMatch::Flag("check_named") => check_named = true,
            // `case OPT_LIST_CURVES: list_curves = 1; break;` — `apps/ecparam.c:158-160`.
            OptMatch::Flag("list_curves") => list_curves = true,
            // `case OPT_NO_SEED: no_seed = 1; break;` — `apps/ecparam.c:161-163`.
            OptMatch::Flag("no_seed") => no_seed = true,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/ecparam.c:164-166`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_NAME: curve_name = opt_arg(); break;` — `apps/ecparam.c:167-169`.
            OptMatch::Value("name", v) => curve_name = Some(v),
            // `case OPT_CONV_FORM: point_format = opt_arg(); ...` —
            // `apps/ecparam.c:170-174`.
            OptMatch::Value("conv_form", v) => point_format = Some(v),
            // `case OPT_PARAM_ENC: asn1_encoding = opt_arg(); ...` —
            // `apps/ecparam.c:175-179`.
            OptMatch::Value("param_enc", v) => asn1_encoding = Some(v),
            // `case OPT_GENKEY: genkey = 1; break;` — `apps/ecparam.c:180-182`.
            OptMatch::Flag("genkey") => genkey = true,
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/ecparam.c:183-186`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("ecparam -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/ecparam.c:187-190`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("ecparam -provider"),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/ecparam.c:191-193`.
            OptMatch::Value("engine", _) => return not_landed("ecparam -engine"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/ecparam.c:197-199`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_RAND_load()) goto end;` — with no `-rand` the authority's `app_RAND_load`
    // iterates an empty stack and returns 1 (the no-op success transcribed above).

    if list_curves {
        // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
        // — `apps/ecparam.c:205-207`.
        let out = bio_open_default(outfile.as_deref(), true);
        if out.is_null() {
            return not_landed("ecparam -out (unopenable)");
        }
        // `if (list_builtin_curves(out)) ret = 0; goto end;` —
        // `apps/ecparam.c:209-211`.
        let ok = list_builtin_curves(out);
        // SAFETY: `out` is this frame's own BIO.
        unsafe { crate::runtime::bio::BIO_free_all(out) };
        return if ok { 0 } else { 1 };
    }

    // `private = genkey ? 1 : 0;` — `apps/ecparam.c:214`.
    let private = genkey;
    let mut ret = 1i32;

    // The parameters key: from `-name` (keygen) or `-in` (decoder).
    let params_key: *mut crate::evp::pkey::EvpPkey;
    if let Some(name) = curve_name.as_deref() {
        let mut curve = name.to_string();
        if curve == "secp192r1" {
            eprintln!("using curve name prime192v1 instead of secp192r1");
            curve = String::from("prime192v1");
        } else if curve == "secp256r1" {
            eprintln!("using curve name prime256v1 instead of secp256r1");
            curve = String::from("prime256v1");
        }
        // `OPENSSL_strcasecmp(curve_name, "SM2")` — `apps/ecparam.c:240`.
        let is_sm2 = curve.eq_ignore_ascii_case("SM2");
        let curve_c = std::ffi::CString::new(curve).unwrap_or_default();
        let mut params: [OsslParam; 4] = core::array::from_fn(|_| OSSL_PARAM_construct_end());
        let mut n = 0usize;
        // SAFETY: the key/buffer strings outlive the call.
        params[n] = unsafe {
            OSSL_PARAM_construct_utf8_string(c"group".as_ptr(), curve_c.as_ptr().cast_mut(), 0)
        };
        n += 1;
        let enc_owned = asn1_encoding
            .as_deref()
            .map(|s| std::ffi::CString::new(s).unwrap_or_default());
        if let Some(c) = &enc_owned {
            // SAFETY: the key/buffer strings outlive the call.
            params[n] = unsafe {
                OSSL_PARAM_construct_utf8_string(c"encoding".as_ptr(), c.as_ptr().cast_mut(), 0)
            };
            n += 1;
        }
        let pf_owned = point_format
            .as_deref()
            .map(|s| std::ffi::CString::new(s).unwrap_or_default());
        if let Some(c) = &pf_owned {
            // SAFETY: the key/buffer strings outlive the call.
            params[n] = unsafe {
                OSSL_PARAM_construct_utf8_string(c"point-format".as_ptr(), c.as_ptr().cast_mut(), 0)
            };
            n += 1;
        }
        params[n] = OSSL_PARAM_construct_end();

        // `if (OPENSSL_strcasecmp(curve_name, "SM2") == 0) "sm2" else "ec";` —
        // `apps/ecparam.c:240-245`.
        let alg = if is_sm2 { c"sm2" } else { c"ec" };
        // SAFETY: both context/property pointers are NULL.
        let gctx_params = unsafe {
            EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), alg.as_ptr(), core::ptr::null())
        };
        let mut pk: *mut crate::evp::pkey::EvpPkey = core::ptr::null_mut();
        // `if (gctx_params == NULL || keygen_init <= 0 || set_params <= 0 || keygen <= 0)
        // { "unable to generate key"; goto end; }` — `apps/ecparam.c:246-252`.
        // SAFETY: `gctx_params` is live or NULL; the guards short-circuit.
        let ok = !gctx_params.is_null()
            && unsafe { EVP_PKEY_keygen_init(gctx_params) } > 0
            && unsafe { EVP_PKEY_CTX_set_params(gctx_params, params.as_ptr()) } > 0
            && unsafe { EVP_PKEY_keygen(gctx_params, &mut pk) } > 0;
        // SAFETY: `gctx_params` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(gctx_params) };
        if !ok {
            eprintln!("unable to generate key");
            return ret;
        }
        params_key = pk;
    } else {
        // `params_key = load_keyparams_suppress(infile, informat, 1, "EC", ...); if NULL
        // try "SM2"; if NULL { "Unable to load parameters from %s"; goto end; }` —
        // `apps/ecparam.c:254-263`.
        let mut pk = load_keyparams(infile.as_deref(), informat, "EC", "EC parameters");
        if pk.is_null() {
            pk = load_keyparams(infile.as_deref(), informat, "SM2", "SM2 parameters");
        }
        if pk.is_null() {
            eprintln!(
                "Unable to load parameters from {}",
                infile.as_deref().unwrap_or("")
            );
            return ret;
        }
        // `if (point_format && !EVP_PKEY_set_utf8_string_param(...)) {...}` /
        // `if (asn1_encoding != NULL && !EVP_PKEY_set_utf8_string_param(...)) {...}` —
        // `apps/ecparam.c:265-278`.
        if let Some(pf) = point_format.as_deref() {
            let cs = std::ffi::CString::new(pf).unwrap_or_default();
            // SAFETY: `pk` is live; the strings are NUL-terminated.
            if unsafe { EVP_PKEY_set_utf8_string_param(pk, c"point-format".as_ptr(), cs.as_ptr()) }
                == 0
            {
                eprintln!("unable to set point conversion format");
                // SAFETY: `pk` is live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pk) };
                return ret;
            }
        }
        if let Some(enc) = asn1_encoding.as_deref() {
            let cs = std::ffi::CString::new(enc).unwrap_or_default();
            // SAFETY: `pk` is live; the strings are NUL-terminated.
            if unsafe { EVP_PKEY_set_utf8_string_param(pk, c"encoding".as_ptr(), cs.as_ptr()) } == 0
            {
                eprintln!("unable to set asn1 encoding format");
                // SAFETY: `pk` is live and not freed again.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pk) };
                return ret;
            }
        }
        params_key = pk;
    }

    // `if (no_seed && !EVP_PKEY_set_octet_string_param(params_key,
    // OSSL_PKEY_PARAM_EC_SEED, NULL, 0)) { "unable to clear seed"; goto end; }` —
    // `apps/ecparam.c:281-286`. Not reconstructed: the seed-clearing octet param is not
    // driven by the court.
    if no_seed {
        // SAFETY: `params_key` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
        return not_landed("ecparam -no_seed");
    }

    // `out = bio_open_owner(outfile, outformat, private); if (out == NULL) goto end;`
    // — `apps/ecparam.c:288-290`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        // SAFETY: `params_key` is live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
        return not_landed("ecparam -out (unopenable)");
    }

    // `if (text && EVP_PKEY_print_params(out, params_key, 0, NULL) <= 0) {
    // "unable to print params"; goto end; }` — `apps/ecparam.c:292-296`.
    if text {
        // SAFETY: `out`/`params_key` are live; indent 0 and a NULL print context.
        if unsafe { EVP_PKEY_print_params(out, params_key, 0, core::ptr::null_mut()) } <= 0 {
            eprintln!("unable to print params");
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
    }

    // `if (check || check_named) { "checking elliptic curve parameters: "; ... }` —
    // `apps/ecparam.c:298-315`.
    if check || check_named {
        // `BIO_printf(bio_err, "checking elliptic curve parameters: ");` — the space is
        // the authority's, with no newline before the answer.
        eprint!("checking elliptic curve parameters: ");
        if check_named {
            // The `OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE` set-to-named arm is not
            // reconstructed; the plain `-check` arm is.
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return not_landed("ecparam -check_named");
        }
        // SAFETY: `params_key` is live; both context/property pointers are NULL.
        let pctx = unsafe {
            EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), params_key, core::ptr::null())
        };
        // SAFETY: `pctx` is live or NULL.
        let ok = !pctx.is_null() && unsafe { EVP_PKEY_param_check(pctx) } > 0;
        // SAFETY: `pctx` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        if !ok {
            eprintln!("failed");
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        eprintln!("ok");
    }

    // `if (outformat == FORMAT_ASN1 && genkey) noout = 1;` — `apps/ecparam.c:317-318`.
    let noout = noout || (outformat == FORMAT_ASN1 && genkey);

    // `if (!noout) { ectx_params = OSSL_ENCODER_CTX_new_for_pkey(params_key,
    // SELECT_DOMAIN_PARAMETERS, DER/PEM, NULL, NULL); if (!to_bio) {...} }` —
    // `apps/ecparam.c:320-328`.
    if !noout {
        let otype = if outformat == FORMAT_ASN1 {
            c"DER"
        } else {
            c"PEM"
        };
        // SAFETY: `params_key` is live; the type string is NUL-terminated; propq NULL.
        let ectx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                params_key,
                SELECT_DOMAIN_PARAMETERS,
                otype.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        // SAFETY: `ectx`/`out` are live.
        if unsafe { OSSL_ENCODER_to_bio(ectx, out) } == 0 {
            eprintln!("unable to write elliptic curve parameters");
            // SAFETY: `ectx`/`params_key`/`out` are live and not freed again.
            unsafe { OSSL_ENCODER_CTX_free(ectx) };
            // SAFETY: `ectx`/`params_key`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: `ectx`/`params_key`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ectx` is live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx) };
    }

    // `if (genkey) { gctx_key = EVP_PKEY_CTX_new_from_pkey(...); keygen_init; keygen;
    // ectx_key = OSSL_ENCODER_CTX_new_for_pkey(key, SELECT_ALL, DER/PEM, NULL, NULL);
    // to_bio; }` — `apps/ecparam.c:330-355`.
    if genkey {
        // SAFETY: `params_key` is live; both context/property pointers are NULL.
        let gctx_key = unsafe {
            EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), params_key, core::ptr::null())
        };
        let mut key: *mut crate::evp::pkey::EvpPkey = core::ptr::null_mut();
        // SAFETY: `gctx_key` is live or NULL.
        let ok = !gctx_key.is_null()
            && unsafe { EVP_PKEY_keygen_init(gctx_key) } > 0
            && unsafe { EVP_PKEY_keygen(gctx_key, &mut key) } > 0;
        // SAFETY: `gctx_key` is live and not freed again.
        unsafe { EVP_PKEY_CTX_free(gctx_key) };
        if !ok {
            eprintln!("unable to generate key");
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: `params_key`/`out` are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        let otype = if outformat == FORMAT_ASN1 {
            c"DER"
        } else {
            c"PEM"
        };
        // SAFETY: `key` is live; the type string is NUL-terminated; propq NULL.
        let ectx_key = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                key,
                SELECT_ALL,
                otype.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        // SAFETY: `ectx_key`/`out` are live.
        if unsafe { OSSL_ENCODER_to_bio(ectx_key, out) } == 0 {
            eprintln!("unable to write elliptic curve parameters");
            // SAFETY: all four are live and not freed again.
            unsafe { OSSL_ENCODER_CTX_free(ectx_key) };
            // SAFETY: all four are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
            // SAFETY: all four are live and not freed again.
            unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
            // SAFETY: all four are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free_all(out) };
            return ret;
        }
        // SAFETY: `ectx_key`/`key` are live and not freed again.
        unsafe { OSSL_ENCODER_CTX_free(ectx_key) };
        // SAFETY: `ectx_key`/`key` are live and not freed again.
        unsafe { crate::evp::pkey::EVP_PKEY_free(key) };
    }

    ret = 0;
    let _ = private;

    // `end: ... EVP_PKEY_free(params_key); EVP_PKEY_free(key); ... BIO_free_all(out);`
    // — `apps/ecparam.c:358-371`.
    // SAFETY: `params_key`/`out` are live and not freed again.
    unsafe { crate::evp::pkey::EVP_PKEY_free(params_key) };
    // SAFETY: `params_key`/`out` are live and not freed again.
    unsafe { crate::runtime::bio::BIO_free_all(out) };
    ret
}
