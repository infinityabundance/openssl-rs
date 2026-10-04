//! Phase 17.1f — `apps/dgst.c`: the `openssl dgst` command.
//!
//! The command body (`apps/dgst.c:114-519`): parse the generated `DGST_OPTIONS`
//! table, resolve the digest named by `-<name>` (the table's empty-name sentinel,
//! rebuilt by [`crate::apps::opt::Opts::enable_unknown`]), then run one `do_fp`
//! per input file over a `BIO_f_md` filter and print the result. The digest,
//! `-hex`/`-binary`, `-c`/`-r`, `-hmac`, `-sign`/`-verify` and `-signature` arms
//! are transcribed whole.
//!
//! ## What the court drives
//!
//! `dgst -sha256 <small.bin>` and its `-hex`/`-binary`/`-c`/`-r` spellings,
//! `dgst -hmac <key> <small.bin>`, `dgst -sha256 -sign <rsa-key.pem> <small.bin>`
//! and `dgst -sha256 -verify <rsa-pub.pem> -signature <dgst.sig> <small.bin>` over
//! the fixed fixtures. `EVP_sha256`/`EVP_MD_fetch("sha256")` name a digest whose
//! bytes are fixed, RSA PKCS#1 v1.5 signing is deterministic and HMAC has no
//! nonce, so every driven arm is a pure function of the fixture.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-list` is not driven.** `show_digests` (`apps/dgst.c:521-549`) walks
//!   `OBJ_NAME_do_all_sorted` and fetches each name through `EVP_MD_fetch`; the
//!   candidate's fetch surface is the same one `ciphers` records, so the listing
//!   is a recorded divergence rather than a diffed arm. It reaches [`not_landed`].
//! * **`-mac`/`-macopt` are not landed.** They build a MAC through
//!   `init_gen_str`/`app_keygen`, whose EVP-`MAC` generation path is other
//!   strata's.
//! * **`-xoflen`, `-sigopt`, `-engine`/`-engine_impl`, `-debug`, `-rand`/
//!   `-writerand` and the provider arms reach [`not_landed`]** (XOF length,
//!   signature parameter strings, `setup_engine`, the BIO debug callback, and the
//!   `opt_rand`/`opt_provider` helpers).
//! * **`app_passwd` is reduced to its no-argument observable**; no `-passin` is
//!   driven and `-passin` reaches [`not_landed`].
//! * **`opt_format(s, OPT_FMT_ANY, ...)` is reduced to PEM/DER** (see
//!   [`crate::apps::pkeyutl`]'s header for the same shape).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;

use crate::apps::keyio::{bio_open_default, load_key, load_pubkey, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::DGST_OPTIONS;
use crate::evp::bio_enc::BIO_f_md;
use crate::evp::digest::{
    EVP_DigestInit_ex, EVP_DigestSignFinal, EVP_DigestSignInit_ex, EVP_DigestVerifyFinal,
    EVP_DigestVerifyInit_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get0_name, EvpMd, EvpMdCtx,
};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha256;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get0_type_name, EVP_PKEY_get_default_digest_name, EVP_PKEY_get_size,
    EVP_PKEY_new_raw_private_key, EvpPkey,
};
use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::iolib::{BIO_gets, BIO_read, BIO_write};
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_new, BIO_push, Bio, BIO_CTRL_EOF, BIO_CTRL_PENDING,
    BIO_C_GET_MD_CTX,
};
use crate::runtime::obj::NID_hmac;

/// `BUFSIZE` — `apps/dgst.c:25`.
const BUFSIZE: usize = 8192;

/// `int opt_md_silent(const char *name, EVP_MD **mdp)` — `apps/lib/opt.c:470-489`.
/// Returns the fetched-or-legacy method, or `None` when neither resolves.
fn opt_md_silent(name: &str) -> Option<*mut EvpMd> {
    let cs = CString::new(name).ok()?;
    // SAFETY: `cs` is NUL-terminated; the context and property query are the
    // authority's unconfigured defaults.
    let fetched = unsafe { EVP_MD_fetch(core::ptr::null_mut(), cs.as_ptr(), core::ptr::null()) };
    if !fetched.is_null() {
        return Some(fetched);
    }
    // `opt_legacy_okay() && (md = EVP_get_digestbyname(name))` — the legacy arm.
    // SAFETY: `cs` is NUL-terminated.
    let legacy = unsafe { EVP_get_digestbyname(cs.as_ptr()) };
    if legacy.is_null() {
        None
    } else {
        Some(legacy.cast_mut())
    }
}

/// `int opt_md(const char *name, EVP_MD **mdp)` — `apps/lib/opt.c:491-501`.
fn opt_md(prog: &str, name: &str) -> Option<*mut EvpMd> {
    match opt_md_silent(name) {
        Some(md) => Some(md),
        None => {
            eprintln!("{prog}: Unknown option or message digest: {name}");
            None
        }
    }
}

/// `opt_format(s, OPT_FMT_ANY, result)` — the `P`/`D` and `default` arms of
/// `apps/lib/opt.c:277-365`, reduced to the PEM/DER bodies (see the header).
fn opt_format_any(prog: &str, s: &str, result: &mut c_int) -> bool {
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

/// `BIO_write` of a whole buffer, ignoring the returned count (as the authority's
/// `BIO_puts`/`BIO_printf` callers do).
fn bio_write_all(out: *mut Bio, data: &[u8]) {
    // SAFETY: `out` is live; `data` is readable for its length.
    unsafe { BIO_write(out, data.as_ptr().cast(), data.len() as c_int) };
}

/// `static void print_out(BIO *out, unsigned char *buf, size_t len, int sep, int
/// binout, const char *sig_name, const char *md_name, const char *file)` —
/// `apps/dgst.c:589-626`.
fn print_out(
    out: *mut Bio,
    buf: &[u8],
    sep: c_int,
    binout: bool,
    sig_name: Option<&str>,
    md_name: Option<&str>,
    file: &str,
) {
    if binout {
        bio_write_all(out, buf);
        return;
    }
    if sep == 2 {
        // `newline_escape_filename` — `apps/dgst.c:561-587`.
        let mut escaped = String::new();
        let mut backslash = false;
        for c in file.chars() {
            if c == '\n' {
                escaped.push('\\');
                escaped.push('n');
                backslash = true;
            } else {
                escaped.push(c);
            }
        }
        if backslash {
            bio_write_all(out, b"\\");
        }
        let mut line = String::new();
        for b in buf {
            line.push_str(&format!("{b:02x}"));
        }
        line.push_str(&format!(" *{escaped}\n"));
        bio_write_all(out, line.as_bytes());
        return;
    }
    let head = match (sig_name, md_name) {
        (Some(sn), Some(mn)) => format!("{sn}-{mn}({file})= "),
        (Some(sn), None) => format!("{sn}({file})= "),
        (None, Some(mn)) => format!("{mn}({file})= "),
        (None, None) => format!("({file})= "),
    };
    bio_write_all(out, head.as_bytes());
    let mut line = String::new();
    for (i, b) in buf.iter().enumerate() {
        if sep != 0 && i != 0 {
            line.push(':');
        }
        line.push_str(&format!("{b:02x}"));
    }
    line.push('\n');
    bio_write_all(out, line.as_bytes());
}

/// `static void print_verify_result(BIO *out, int i)` — `apps/dgst.c:628-636`.
fn print_verify_result(out: *mut Bio, i: c_int) {
    if i > 0 {
        bio_write_all(out, b"Verified OK\n");
    } else if i == 0 {
        bio_write_all(out, b"Verification failure\n");
    } else {
        eprintln!("Error verifying data");
    }
}

/// `BIO_get_md_ctx(b, &ctx)` — `BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, &ctx)`.
fn bio_get_md_ctx(b: *mut Bio) -> *mut EvpMdCtx {
    let mut ctx: *mut EvpMdCtx = core::ptr::null_mut();
    // SAFETY: `b` is live; `ctx` is a live local writable for the control call's
    // pointer.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_GET_MD_CTX,
            0,
            core::ptr::addr_of_mut!(ctx).cast::<c_void>(),
        );
    }
    ctx
}

/// `int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout, int
/// xoflen, EVP_PKEY *key, unsigned char *sigin, int siglen, const char *sig_name,
/// const char *md_name, const char *file)` — `apps/dgst.c:638-710`. The `xoflen`
/// arm is not driven (see the header); the oneshot arm is not reached for the
/// driven algorithms (their default digest is not `UNDEF`).
#[allow(clippy::too_many_arguments)]
fn do_fp(
    out: *mut Bio,
    buf: &mut [u8],
    bp: *mut Bio,
    sep: c_int,
    binout: bool,
    key: *mut EvpPkey,
    sigin: Option<&[u8]>,
    sig_name: Option<&str>,
    md_name: Option<&str>,
    file: &str,
) -> i32 {
    // `while (BIO_pending(bp) || !BIO_eof(bp)) { i = BIO_read(bp, buf, BUFSIZE); ... }`
    // — `apps/dgst.c:647-655`.
    loop {
        // SAFETY: `bp` is live; each control takes no pointer.
        let pending = unsafe { BIO_ctrl(bp, BIO_CTRL_PENDING, 0, core::ptr::null_mut()) };
        // SAFETY: as above.
        let eof = unsafe { BIO_ctrl(bp, BIO_CTRL_EOF, 0, core::ptr::null_mut()) };
        if pending == 0 && eof != 0 {
            break;
        }
        // SAFETY: `bp` is live; `buf` is writable for its length.
        let i = unsafe { BIO_read(bp, buf.as_mut_ptr().cast(), BUFSIZE as c_int) };
        if i < 0 {
            eprintln!("Read error in {file}");
            return 1;
        }
        if i == 0 {
            break;
        }
    }
    if let Some(sig) = sigin {
        let ctx = bio_get_md_ctx(bp);
        // SAFETY: `ctx` is live; `sig` is readable for its length.
        let i = unsafe { EVP_DigestVerifyFinal(ctx, sig.as_ptr(), sig.len()) };
        print_verify_result(out, i);
        return if i > 0 { 0 } else { 1 };
    }
    if !key.is_null() {
        let ctx = bio_get_md_ctx(bp);
        let mut tmplen: usize = 0;
        // SAFETY: `ctx` is live; the NULL sigret is the length query.
        if unsafe { EVP_DigestSignFinal(ctx, core::ptr::null_mut(), &mut tmplen) } == 0 {
            eprintln!("Error getting maximum length of signed data");
            return 1;
        }
        let mut sig = vec![0u8; tmplen];
        let mut len = tmplen;
        // SAFETY: `ctx` is live; `sig` is writable for `len` bytes.
        if unsafe { EVP_DigestSignFinal(ctx, sig.as_mut_ptr(), &mut len) } == 0 {
            eprintln!("Error signing data");
            return 1;
        }
        print_out(out, &sig[..len], sep, binout, sig_name, md_name, file);
        return 0;
    }
    // SAFETY: `bp` is live; `buf` is writable for its length.
    let len = unsafe { BIO_gets(bp, buf.as_mut_ptr().cast(), BUFSIZE as c_int) };
    if len < 0 {
        return 1;
    }
    print_out(
        out,
        &buf[..len as usize],
        sep,
        binout,
        sig_name,
        md_name,
        file,
    );
    0
}

/// `int dgst_main(int argc, char **argv)` — `apps/dgst.c:114-519`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, DGST_OPTIONS);
    // `opt_set_unknown_name("digest");` — `apps/dgst.c:142`.
    opts.enable_unknown("digest");

    let mut outfile: Option<String> = None;
    let mut keyfile: Option<String> = None;
    let mut sigfile: Option<String> = None;
    let mut hmac_key: Option<String> = None;
    let mut digestname: Option<String> = None;
    let mut keyform: c_int = 0;
    let mut separator: c_int = 0;
    let mut out_bin: Option<bool> = None;
    let mut want_pub = false;
    let mut do_verify = false;

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ret = EXIT_SUCCESS; goto end;` —
            // `apps/dgst.c:151-154`.
            OptMatch::Help => return not_landed("dgst -help"),
            // `case OPT_ERR: opthelp: ...` — `apps/dgst.c:146-150`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_LIST: ... show_digests ...` — `apps/dgst.c:155-163`.
            OptMatch::Flag("list") => return not_landed("dgst -list"),
            // `case OPT_C: separator = 1;` — `apps/dgst.c:164-166`.
            OptMatch::Flag("c") => separator = 1,
            // `case OPT_R: separator = 2;` — `apps/dgst.c:167-169`.
            OptMatch::Flag("r") => separator = 2,
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/dgst.c:170-173`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("dgst -rand")
            }
            // `case OPT_OUT: outfile = opt_arg();` — `apps/dgst.c:174-176`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_SIGN: keyfile = opt_arg();` — `apps/dgst.c:177-179`.
            OptMatch::Value("sign", v) => keyfile = Some(v),
            // `case OPT_PASSIN: passinarg = opt_arg();` — `apps/dgst.c:180-182`.
            OptMatch::Value("passin", _) => return not_landed("dgst -passin"),
            // `case OPT_VERIFY: keyfile = opt_arg(); want_pub = do_verify = 1;` —
            // `apps/dgst.c:183-186`.
            OptMatch::Value("verify", v) => {
                keyfile = Some(v);
                want_pub = true;
                do_verify = true;
            }
            // `case OPT_PRVERIFY: keyfile = opt_arg(); do_verify = 1;` —
            // `apps/dgst.c:187-190`.
            OptMatch::Value("prverify", v) => {
                keyfile = Some(v);
                do_verify = true;
            }
            // `case OPT_SIGNATURE: sigfile = opt_arg();` — `apps/dgst.c:191-193`.
            OptMatch::Value("signature", v) => sigfile = Some(v),
            // `case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform)) ...` —
            // `apps/dgst.c:194-197`.
            OptMatch::Value("keyform", v) => {
                if !opt_format_any(opts.prog(), &v, &mut keyform) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0);` — `apps/dgst.c:198-200`.
            OptMatch::Value("engine", _) => return not_landed("dgst -engine"),
            // `case OPT_ENGINE_IMPL: engine_impl = 1;` — `apps/dgst.c:201-203`.
            OptMatch::Flag("engine_impl") => return not_landed("dgst -engine_impl"),
            // `case OPT_HEX: out_bin = 0;` — `apps/dgst.c:204-206`.
            OptMatch::Flag("hex") => out_bin = Some(false),
            // `case OPT_BINARY: out_bin = 1;` — `apps/dgst.c:207-209`.
            OptMatch::Flag("binary") => out_bin = Some(true),
            // `case OPT_XOFLEN: xoflen = atoi(opt_arg());` — `apps/dgst.c:210-212`.
            OptMatch::Value("xoflen", _) => return not_landed("dgst -xoflen"),
            // `case OPT_DEBUG: debug = 1;` — `apps/dgst.c:213-215`.
            OptMatch::Flag("d") | OptMatch::Flag("debug") => return not_landed("dgst -debug"),
            // `case OPT_FIPS_FINGERPRINT: hmac_key = "etaonrishdlcupfm";` —
            // `apps/dgst.c:216-218`.
            OptMatch::Flag("fips-fingerprint") => hmac_key = Some("etaonrishdlcupfm".to_string()),
            // `case OPT_HMAC: hmac_key = opt_arg();` — `apps/dgst.c:219-221`.
            OptMatch::Value("hmac", v) => hmac_key = Some(v),
            // `case OPT_MAC: mac_name = opt_arg();` — `apps/dgst.c:222-224`.
            OptMatch::Value("mac", _) => return not_landed("dgst -mac"),
            // `case OPT_SIGOPT: ...` — `apps/dgst.c:225-230`.
            OptMatch::Value("sigopt", _) => return not_landed("dgst -sigopt"),
            // `case OPT_MACOPT: ...` — `apps/dgst.c:231-236`.
            OptMatch::Value("macopt", _) => return not_landed("dgst -macopt"),
            // `case OPT_DIGEST: digestname = opt_unknown();` — `apps/dgst.c:237-239`.
            OptMatch::Value("", v) => digestname = Some(v),
            // `case OPT_PROV_CASES: ...` — `apps/dgst.c:240-243`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("dgst -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest();` — `apps/dgst.c:248-249`.
    let files: Vec<String> = opts.rest().to_vec();
    // `if (keyfile != NULL && argc > 1) { ... }` — `apps/dgst.c:250-253`.
    if keyfile.is_some() && files.len() > 1 {
        eprintln!("{}: Can only sign or verify one file.", opts.prog());
        return 1;
    }
    // `if (!app_RAND_load()) goto end;` — the no-`-rand` no-op success.

    // `md = (EVP_MD *)EVP_get_digestbyname(argv[0]);` — `apps/dgst.c:138-140`. The
    // dispatcher's `argv[0]` is `dgst`, not a digest name.
    let mut md: *mut EvpMd = core::ptr::null_mut();
    if let Some(name) = &digestname {
        // `if (!opt_md(digestname, &md)) goto opthelp;` — `apps/dgst.c:257-260`.
        match opt_md(opts.prog(), name) {
            Some(m) => md = m,
            None => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (do_verify && sigfile == NULL) { ... }` — `apps/dgst.c:262-266`.
    if do_verify && sigfile.is_none() {
        eprintln!("No signature to verify: use the -signature option");
        return 1;
    }

    // `in = BIO_new(BIO_s_file()); bmd = BIO_new(BIO_f_md());` —
    // `apps/dgst.c:270-273`.
    // SAFETY: `BIO_s_file`/`BIO_f_md` are the module's own method tables.
    let inb = unsafe { BIO_new(crate::runtime::bio::bss_file::BIO_s_file()) };
    // SAFETY: as above.
    let bmd = unsafe { BIO_new(BIO_f_md()) };
    if inb.is_null() || bmd.is_null() {
        return 1;
    }

    // `if (out_bin == -1) { if (keyfile != NULL) out_bin = 1; else out_bin = 0; }` —
    // `apps/dgst.c:286-291`.
    let binout = out_bin.unwrap_or(keyfile.is_some());

    // `out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY : FORMAT_TEXT);` —
    // `apps/dgst.c:293-295`.
    let out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        return 1;
    }

    // `if ((!(mac_name == NULL) + !(keyfile == NULL) + !(hmac_key == NULL)) > 1) ...` —
    // `apps/dgst.c:297-300`. `mac_name` is always NULL here (its arm is not landed).
    if keyfile.is_some() && hmac_key.is_some() {
        eprintln!("MAC and signing key cannot both be specified");
        return 1;
    }

    // `if (keyfile != NULL) { ... load_[pub]key ... signctx = EVP_MD_CTX_new(); }` —
    // `apps/dgst.c:302-325`.
    let mut sigkey: *mut EvpPkey = core::ptr::null_mut();
    let mut oneshot_sign = false;
    let mut signctx: *mut EvpMdCtx = core::ptr::null_mut();
    if let Some(kf) = &keyfile {
        sigkey = if want_pub {
            load_pubkey(Some(kf), keyform, "public key")
        } else {
            load_key(Some(kf), keyform, "private key")
        };
        if sigkey.is_null() {
            return 1;
        }
        // `if (EVP_PKEY_get_default_digest_name(sigkey, def_md, sizeof(def_md)) == 2
        // && strcmp(def_md, "UNDEF") == 0) oneshot_sign = 1;` — `apps/dgst.c:314-320`.
        let mut def_md = [0 as c_char; 80];
        // SAFETY: `sigkey` is live; `def_md` is writable for its length.
        if unsafe { EVP_PKEY_get_default_digest_name(sigkey, def_md.as_mut_ptr(), def_md.len()) }
            == 2
        {
            // SAFETY: `def_md` is NUL-terminated by the call.
            let name = unsafe { std::ffi::CStr::from_ptr(def_md.as_ptr()) };
            oneshot_sign = name.to_bytes() == b"UNDEF";
        }
        // SAFETY: `EVP_MD_CTX_new` has no argument.
        signctx = EVP_MD_CTX_new();
        if signctx.is_null() {
            return 1;
        }
    }

    // `if (hmac_key != NULL) { if (md == NULL) md = EVP_sha256(); ... }` —
    // `apps/dgst.c:351-361`.
    if let Some(key) = &hmac_key {
        if md.is_null() {
            md = EVP_sha256() as *mut EvpMd;
            digestname = Some("SHA256".to_string());
        }
        // SAFETY: `key` is readable for its length; the engine is NULL.
        sigkey = unsafe {
            EVP_PKEY_new_raw_private_key(NID_hmac, core::ptr::null_mut(), key.as_ptr(), key.len())
        };
        if sigkey.is_null() {
            return 1;
        }
    }

    // `if (sigkey != NULL) { ... EVP_Digest[Sign|Verify]Init[_ex] ... }` —
    // `apps/dgst.c:363-402`. The `impl` (engine) arm is unreachable (no engine).
    if !sigkey.is_null() {
        if oneshot_sign {
            return not_landed("dgst oneshot sign");
        }
        let mctx = bio_get_md_ctx(bmd);
        // `digestname` is the authority's string; NULL lets the key choose.
        let digcs = digestname.as_deref().and_then(|s| CString::new(s).ok());
        let digptr = digcs.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
        // SAFETY: `mctx`/`sigkey` are live; `digptr` is NULL or NUL-terminated.
        let res = unsafe {
            if do_verify {
                EVP_DigestVerifyInit_ex(
                    mctx,
                    core::ptr::null_mut(),
                    digptr,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    sigkey,
                    core::ptr::null(),
                )
            } else {
                EVP_DigestSignInit_ex(
                    mctx,
                    core::ptr::null_mut(),
                    digptr,
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    sigkey,
                    core::ptr::null(),
                )
            }
        };
        if res == 0 {
            eprintln!("Error setting context");
            return 1;
        }
    } else {
        // `if (md == NULL) md = EVP_sha256(); EVP_DigestInit_ex(mctx, md, impl);` —
        // `apps/dgst.c:404-421`.
        if oneshot_sign {
            eprintln!("Oneshot algorithms don't use a digest");
            return 1;
        }
        let mctx = bio_get_md_ctx(bmd);
        if md.is_null() {
            md = EVP_sha256() as *mut EvpMd;
        }
        // SAFETY: `mctx`/`md` are live; the engine is NULL.
        if unsafe { EVP_DigestInit_ex(mctx, md, core::ptr::null_mut()) } == 0 {
            eprintln!("Error setting digest");
            return 1;
        }
    }

    // `if (sigfile != NULL && sigkey != NULL) { ... read the signature ... }` —
    // `apps/dgst.c:423-438`.
    let sigbuf: Option<Vec<u8>> = if let (Some(sf), false) = (&sigfile, sigkey.is_null()) {
        let cs = match CString::new(sf.as_str()) {
            Ok(c) => c,
            Err(_) => return 1,
        };
        // SAFETY: `cs` is NUL-terminated.
        let sigbio = unsafe { BIO_new_file(cs.as_ptr(), c"rb".as_ptr()) };
        if sigbio.is_null() {
            eprintln!("Error opening signature file {sf}");
            return 1;
        }
        // SAFETY: `sigkey` is live.
        let siglen = unsafe { EVP_PKEY_get_size(sigkey) };
        let mut buf = vec![0u8; siglen as usize];
        // SAFETY: `sigbio` is live; `buf` is writable for its length.
        let n = unsafe { BIO_read(sigbio, buf.as_mut_ptr().cast(), siglen) };
        // SAFETY: `sigbio` is live and not freed again.
        unsafe { BIO_free(sigbio) };
        if n <= 0 {
            eprintln!("Error reading signature file {sf}");
            return 1;
        }
        buf.truncate(n as usize);
        Some(buf)
    } else {
        None
    };

    // `inp = BIO_push(bmd, in);` and `md_name = EVP_MD_get0_name(md);` —
    // `apps/dgst.c:439-450`.
    // SAFETY: `bmd`/`inb` are live BIOs and `BIO_push` adopts `inb`.
    let inp = unsafe { BIO_push(bmd, inb) };
    let md_name: Option<&str> = if md.is_null() {
        None
    } else {
        // SAFETY: `md` is live; the name is a static string owned by the method.
        let p = unsafe { EVP_MD_get0_name(md) };
        if p.is_null() {
            None
        } else {
            // SAFETY: `p` is NUL-terminated.
            Some(
                unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_str()
                    .unwrap_or(""),
            )
        }
    };
    // `if (out_bin == 0) { if (sigkey != NULL) sig_name = EVP_PKEY_get0_type_name(sigkey); }` —
    // `apps/dgst.c:478-481`.
    let sig_name: Option<&str> = if !binout && !sigkey.is_null() {
        // SAFETY: `sigkey` is live.
        let p = unsafe { EVP_PKEY_get0_type_name(sigkey) };
        if p.is_null() {
            None
        } else {
            // SAFETY: `p` is NUL-terminated.
            Some(
                unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_str()
                    .unwrap_or(""),
            )
        }
    } else {
        None
    };

    let mut buf = vec![0u8; BUFSIZE];
    let mut ret = 0;
    if files.is_empty() {
        // `BIO_set_fp(in, stdin, BIO_NOCLOSE);` — `apps/dgst.c:467-474`. The empty
        // input is not driven; it reaches the same do_fp with stdin.
        return not_landed("dgst (stdin)");
    } else {
        for file in &files {
            // `if (BIO_read_filename(in, argv[i]) <= 0) { perror(argv[i]); ... }` —
            // `apps/dgst.c:483-487`.
            let cs = match CString::new(file.as_str()) {
                Ok(c) => c,
                Err(_) => {
                    ret = 1;
                    continue;
                }
            };
            // SAFETY: `inb` is live; `cs` is NUL-terminated.
            let ok = unsafe {
                BIO_ctrl(
                    inb,
                    crate::runtime::bio::BIO_C_SET_FILENAME,
                    (crate::runtime::bio::BIO_CLOSE | crate::runtime::bio::BIO_FP_READ) as i64,
                    cs.as_ptr().cast_mut().cast::<c_void>(),
                )
            };
            if ok <= 0 {
                eprintln!("{file}: No such file or directory");
                ret = 1;
                continue;
            }
            // SAFETY: `out`/`inp`/`buf` are live.
            let r = do_fp(
                out,
                &mut buf,
                inp,
                separator,
                binout,
                sigkey,
                sigbuf.as_deref(),
                sig_name,
                md_name,
                file,
            );
            if r != 0 {
                ret = 1;
            }
        }
    }

    // `if (ret != EXIT_SUCCESS) ERR_print_errors(bio_err);` — `apps/dgst.c:503-505`.
    // SAFETY: the pointers are live and not used again.
    unsafe {
        BIO_free(inb);
        BIO_free_all(out);
        EVP_MD_free(md);
        EVP_PKEY_free(sigkey);
        EVP_MD_CTX_free(signctx);
        BIO_free(bmd);
    }
    ret
}
