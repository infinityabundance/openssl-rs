//! Phase 17.1e — `apps/enc.c`: the `openssl enc` command.
//!
//! The command body (`apps/enc.c:144-822`): parse the generated `ENC_OPTIONS`
//! table (with the `base64` command-name alias), fetch the selected cipher, take
//! the raw key/IV, wrap the output in the cipher BIO (and base64 BIO when
//! `-a`/`-A`), then stream the input through the BIO chain. The parse, the raw
//! `-K`/`-iv` path, `-a`/`-A`, `-nopad`, `-e`/`-d` and the `-p`/`-P` print arms are
//! transcribed. The passphrase/PBKDF2 derivation, the opaque symmetric key
//! (`-skeyopt`/`-skeymgmt`) path and the compression arms reach [`not_landed`].
//!
//! ## What the court drives
//!
//! `enc -aes-128-cbc -K <hex> -iv <hex> -in <fixture>` in the plain, `-d`, `-a`,
//! `-a -A`, `-nopad` and `-P -nosalt` shapes over fixed key/IV/input. Each is a
//! pure function of the fixed bytes, so the ciphertext, the base64 wrapping and
//! the printed key/IV are byte-identical on both sides.
//!
//! ## Recorded divergences (module header)
//!
//! * **The passphrase arms are not landed.** `EVP_BytesToKey`/`PKCS5_PBKDF2_HMAC`
//!   and `app_passwd` (`apps/enc.c:428-465, 600-640`) are the passphrase surface;
//!   the court always supplies a raw `-K`, so those paths are not driven.
//! * **`opt_set_unknown_name("cipher")` is reduced to its observable.** The
//!   authority treats an otherwise-unknown option as a cipher name
//!   (`apps/enc.c:205, 325-327`); this module recognises the parser's
//!   `Unknown option: -<name>` refusal and takes `<name>` as the cipher, which is
//!   the same observable for the court's `-aes-128-cbc`.
//! * **The opaque symmetric key path is not landed.** `EVP_SKEY_*`/
//!   `EVP_SKEYMGMT_*` (`apps/enc.c:675-733`) and `-skeyopt`/`-skeymgmt` reach
//!   `not_landed`; the raw-key path is the court's.
//! * **`-engine`, `-rand`/`-writerand` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::apps::keyio::bio_open_default;
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::ENC_OPTIONS;
use crate::evp::bio_enc::{BIO_f_base64, BIO_f_cipher};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_iv_length,
    EVP_CIPHER_get_key_length, EVP_CIPHER_get_mode, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_set_flags, EVP_CIPHER_CTX_set_padding, EVP_CipherInit_ex,
};
use crate::runtime::bio::iolib::{BIO_read, BIO_write};
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_new, BIO_push, BIO_set_flags, Bio, BIO_CTRL_EOF,
    BIO_CTRL_FLUSH, BIO_CTRL_PENDING, BIO_C_GET_CIPHER_CTX, BIO_FLAGS_BASE64_NO_NL,
};

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `PKCS5_SALT_LEN` — `include/openssl/evp.h`.
const PKCS5_SALT_LEN: usize = 8;
/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:529`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` — `include/openssl/evp.h`.
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x1;
/// `BSIZE` — `apps/enc.c:31`.
const BSIZE: usize = 8 * 1024;
/// `PBKDF2_ITER_DEFAULT` — `apps/enc.c:33`.
const PBKDF2_ITER_DEFAULT: i64 = 10000;

/// `static int set_hex(const char *in, unsigned char *out, int size)` —
/// `apps/enc.c:848-876`.
fn set_hex(input: &str, out: &mut [u8]) -> bool {
    let size = out.len();
    let max = size * 2;
    let n = if input.len() > max {
        eprintln!("hex string is too long, ignoring excess");
        max
    } else {
        if input.len() < max {
            eprintln!("hex string is too short, padding with zero bytes to length");
        }
        input.len()
    };
    out.fill(0);
    for (i, ch) in input.bytes().take(n).enumerate() {
        let j = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => ch - b'a' + 10,
            b'A'..=b'F' => ch - b'A' + 10,
            _ => {
                eprintln!("non-hex digit");
                return false;
            }
        };
        if i & 1 != 0 {
            out[i / 2] |= j;
        } else {
            out[i / 2] = j << 4;
        }
    }
    true
}

/// `opt_cipher(name, &cipher)` — the `OPT_CIPHER_NONE` arm of `apps/lib/opt.c`'s
/// `opt_cipher_any`.
fn opt_cipher(prog: &str, name: &str) -> *mut EvpCipher {
    let Ok(cs) = std::ffi::CString::new(name) else {
        eprintln!("{prog}: Unknown cipher");
        return core::ptr::null_mut();
    };
    // SAFETY: `cs` is NUL-terminated; NULL libctx/props are the default.
    let cipher = unsafe { EVP_CIPHER_fetch(core::ptr::null_mut(), cs.as_ptr(), core::ptr::null()) };
    if cipher.is_null() {
        eprintln!("{prog}: Unknown cipher");
    }
    cipher
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

/// `int opt_long(const char *value, long *result)` — `apps/lib/opt.c:590-616`.
fn opt_long(prog: &str, value: &str) -> Option<i64> {
    match strtol_base0(value) {
        Some(l) => Some(l),
        None => {
            opt_number_error(prog, value);
            None
        }
    }
}

/// `int opt_int(const char *value, int *result)` — `apps/lib/opt.c:542-556`.
fn opt_int(prog: &str, value: &str) -> Option<c_int> {
    let l = opt_long(prog, value)?;
    let r = l as c_int;
    if i64::from(r) != l {
        eprintln!("{prog}: Value \"{value}\" outside integer range");
        return None;
    }
    Some(r)
}

/// `BIO_eof(b)` — `BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL)`.
fn bio_eof(b: *mut Bio) -> bool {
    // SAFETY: `b` is live.
    unsafe { BIO_ctrl(b, BIO_CTRL_EOF, 0, core::ptr::null_mut()) > 0 }
}

/// `BIO_pending(b)` — `BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL)`.
fn bio_pending(b: *mut Bio) -> usize {
    // SAFETY: `b` is live.
    let r = unsafe { BIO_ctrl(b, BIO_CTRL_PENDING, 0, core::ptr::null_mut()) };
    if r < 0 {
        0
    } else {
        r as usize
    }
}

/// The `printkey` rendering (`apps/enc.c:743-766`), as the authority's `printf`s
/// produce it.
fn render_printkey(salt: &[u8], nosalt: bool, key: &[u8], ivlen: usize, iv: &[u8]) -> String {
    let mut s = String::new();
    if !nosalt {
        s.push_str("salt=");
        for b in salt {
            s.push_str(&format!("{b:02X}"));
        }
        s.push('\n');
    }
    if !key.is_empty() {
        s.push_str("key=");
        for b in key {
            s.push_str(&format!("{b:02X}"));
        }
        s.push('\n');
    }
    if ivlen > 0 {
        s.push_str("iv =");
        for b in &iv[..ivlen] {
            s.push_str(&format!("{b:02X}"));
        }
        s.push('\n');
    }
    s
}

/// `int enc_main(int argc, char **argv)` — `apps/enc.c:144-822`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let prog_name = argv.first().cloned().unwrap_or_else(|| "enc".to_string());

    // `if (strcmp(argv[0], "base64") == 0) base64 = 1; ... else if
    // (strcmp(argv[0], "enc") != 0) ciphername = argv[0];` — `apps/enc.c:187-203`.
    let mut base64 = prog_name == "base64";
    let mut ciphername: Option<String> = if prog_name != "base64" && prog_name != "enc" {
        Some(prog_name.clone())
    } else {
        None
    };

    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv, enc_options);`
    // — `apps/enc.c:205-206`.
    let mut opts = Opts::init(argv, ENC_OPTIONS);
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut passarg: Option<String> = None;
    let mut enc = true;
    let mut printkey = 0i32;
    let mut verbose = false;
    let mut nopad = false;
    let mut nosalt = false;
    let mut olb64 = false;
    let mut bsize = BSIZE;
    let mut hkey: Option<String> = None;
    let mut hiv: Option<String> = None;
    let mut _hsalt: Option<String> = None;
    let mut _digestname: Option<String> = None;
    let mut iter = 0i64;
    let mut pbkdf2 = false;
    let mut saltlen = 0i32;
    let mut skeyopts_present = false;
    let mut _skeymgmt: Option<String> = None;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/enc.c:207`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(enc_options); ret = 0; goto end;` —
            // `apps/enc.c:214-217`.
            OptMatch::Help => return not_landed("enc -help"),
            OptMatch::Error(e) => {
                // `opt_set_unknown_name("cipher")` (`apps/enc.c:205`): an
                // otherwise-unknown option is the cipher name (`opt_unknown`).
                if let Some(name) = e.strip_prefix(&format!("{}: Unknown option: -", opts.prog())) {
                    ciphername = Some(name.to_string());
                    continue;
                }
                // `opthelp: BIO_printf(bio_err, "%s: Use -help for summary.\n",
                // prog); goto end;` — `apps/enc.c:209-213`.
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_LIST: ... OBJ_NAME_do_all_sorted(...); ret = 0; goto end;`
            // — `apps/enc.c:218-226`. The `OBJ_NAME` enumeration is not landed.
            OptMatch::Flag("list") | OptMatch::Flag("ciphers") => return not_landed("enc -list"),
            // `case OPT_E: enc = 1; break;` — `apps/enc.c:227-229`.
            OptMatch::Flag("e") => enc = true,
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/enc.c:230-232`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/enc.c:233-235`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_PASS: passarg = opt_arg(); break;` — `apps/enc.c:236-238`.
            OptMatch::Value("pass", v) => passarg = Some(v),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/enc.c:239-241`.
            OptMatch::Value("engine", _) => return not_landed("enc -engine"),
            // `case OPT_D: enc = 0; break;` — `apps/enc.c:242-244`.
            OptMatch::Flag("d") => enc = false,
            // `case OPT_P: printkey = 1; break;` — `apps/enc.c:245-247`.
            OptMatch::Flag("p") => printkey = 1,
            // `case OPT_V: verbose = 1; break;` — `apps/enc.c:248-250`.
            OptMatch::Flag("v") => verbose = true,
            // `case OPT_NOPAD: nopad = 1; break;` — `apps/enc.c:251-253`.
            OptMatch::Flag("nopad") => nopad = true,
            // `case OPT_SALT: nosalt = 0; break;` — `apps/enc.c:254-256`.
            OptMatch::Flag("salt") => nosalt = false,
            // `case OPT_NOSALT: nosalt = 1; break;` — `apps/enc.c:257-259`.
            OptMatch::Flag("nosalt") => nosalt = true,
            // `case OPT_DEBUG: debug = 1; break;` — `apps/enc.c:260-262`. The debug
            // callback arm is not driven.
            OptMatch::Flag("debug") => {}
            // `case OPT_UPPER_P: printkey = 2; break;` — `apps/enc.c:263-265`.
            OptMatch::Flag("P") => printkey = 2,
            // `case OPT_UPPER_A: olb64 = 1; break;` — `apps/enc.c:266-268`.
            OptMatch::Flag("A") => olb64 = true,
            // `case OPT_A: base64 = 1; break;` — `apps/enc.c:269-271`.
            OptMatch::Flag("a") | OptMatch::Flag("base64") => base64 = true,
            // `case OPT_BUFSIZE: ... opt_long ... bsize = (int)n;` —
            // `apps/enc.c:277-289`.
            OptMatch::Value("bufsize", v) => {
                let k = v.len() >= 2 && v.ends_with('k');
                let p = if k { &v[..v.len() - 1] } else { &v };
                match opt_long(opts.prog(), p) {
                    Some(n) if n >= 0 && !(k && n >= i64::MAX / 1024) => {
                        bsize = (if k { n * 1024 } else { n }) as usize;
                    }
                    _ => {
                        eprintln!("{}: Use -help for summary.", opts.prog());
                        return 1;
                    }
                }
            }
            // `case OPT_K: str = opt_arg(); break;` — `apps/enc.c:290-292`.
            OptMatch::Value("k", _) => return not_landed("enc -k (passphrase)"),
            // `case OPT_KFILE: ... str = buf;` — `apps/enc.c:293-312`.
            OptMatch::Value("kfile", _) => return not_landed("enc -kfile"),
            // `case OPT_UPPER_K: hkey = opt_arg(); break;` — `apps/enc.c:313-315`.
            OptMatch::Value("K", v) => hkey = Some(v),
            // `case OPT_UPPER_S: hsalt = opt_arg(); break;` — `apps/enc.c:316-318`.
            OptMatch::Value("S", v) => _hsalt = Some(v),
            // `case OPT_IV: hiv = opt_arg(); break;` — `apps/enc.c:319-321`.
            OptMatch::Value("iv", v) => hiv = Some(v),
            // `case OPT_MD: digestname = opt_arg(); break;` — `apps/enc.c:322-324`.
            OptMatch::Value("md", v) => _digestname = Some(v),
            // `case OPT_ITER: iter = opt_int_arg(); pbkdf2 = 1; break;` —
            // `apps/enc.c:328-331`.
            OptMatch::Value("iter", v) => match opt_int(opts.prog(), &v) {
                Some(n) => {
                    iter = i64::from(n);
                    pbkdf2 = true;
                }
                None => {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            },
            // `case OPT_SALTLEN: if (!opt_int(opt_arg(), &saltlen)) goto opthelp;
            // ...` — `apps/enc.c:332-337`.
            OptMatch::Value("saltlen", v) => match opt_int(opts.prog(), &v) {
                Some(n) => saltlen = n,
                None => {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            },
            // `case OPT_PBKDF2: pbkdf2 = 1; if (iter == 0) iter =
            // PBKDF2_ITER_DEFAULT;` — `apps/enc.c:338-342`.
            OptMatch::Flag("pbkdf2") => {
                pbkdf2 = true;
                if iter == 0 {
                    iter = PBKDF2_ITER_DEFAULT;
                }
            }
            // `case OPT_NONE: cipher = NULL; break;` — `apps/enc.c:343-345`.
            OptMatch::Flag("none") => ciphername = None,
            // `case OPT_SKEYOPT: ... sk_OPENSSL_STRING_push(skeyopts, opt_arg());`
            // — `apps/enc.c:346-351`.
            OptMatch::Value("skeyopt", _) => skeyopts_present = true,
            // `case OPT_SKEYMGMT: skeymgmt = opt_arg(); break;` —
            // `apps/enc.c:352-354`.
            OptMatch::Value("skeymgmt", v) => _skeymgmt = Some(v),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/enc.c:355-358`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("enc -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/enc.c:359-362`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("enc -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/enc.c:366-368`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `if (!app_RAND_load()) goto end;` — `apps/enc.c:369-370`. Skipped (see the
    // header); unobservable for the raw-key arms.
    let _ = (verbose, skeyopts_present, _skeymgmt, _hsalt, _digestname);

    // `if (saltlen == 0 || pbkdf2 == 0) saltlen = PKCS5_SALT_LEN;` —
    // `apps/enc.c:371-372`.
    let saltlen = if saltlen == 0 || !pbkdf2 {
        PKCS5_SALT_LEN
    } else {
        core::cmp::min(saltlen as usize, EVP_MAX_IV_LENGTH)
    };

    // `if (!opt_cipher(ciphername, &cipher)) goto opthelp;` —
    // `apps/enc.c:374-376`. `ciphername == NULL` leaves `cipher` NULL.
    let cipher = match &ciphername {
        Some(name) => {
            let c = opt_cipher(opts.prog(), name);
            if c.is_null() {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            c
        }
        None => core::ptr::null_mut(),
    };

    // `if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_WRAP_MODE)) { wrap = 1;
    // streamable = 0; }` — `apps/enc.c:377-380`.
    let mut wrap = false;
    let mut streamable = true;
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        if unsafe { EVP_CIPHER_get_mode(cipher) } == EVP_CIPH_WRAP_MODE {
            wrap = true;
            streamable = false;
        }
    }
    let _ = iter;

    // `if (base64 && bsize < 80) bsize = 80;` — `apps/enc.c:391-393`.
    if base64 && bsize < 80 {
        bsize = 80;
    }

    // `if (infile == NULL) { if (!streamable && printkey != 2) { ... } in =
    // dup_bio_in(informat); } else { in = bio_open_default(infile, 'r',
    // informat); }` — `apps/enc.c:416-426`.
    if infile.is_none() && !streamable && printkey != 2 {
        eprintln!("Unstreamable cipher mode");
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and not freed again.
            unsafe { EVP_CIPHER_free(cipher) };
        }
        return 1;
    }
    let in_tail = bio_open_default(infile.as_deref(), false);
    if in_tail.is_null() {
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and not freed again.
            unsafe { EVP_CIPHER_free(cipher) };
        }
        return 1;
    }

    // `if (str == NULL && passarg != NULL) { ... str = pass; }` —
    // `apps/enc.c:428-434`.
    if passarg.is_some() {
        // SAFETY: `in_tail` is live and not freed again.
        unsafe { BIO_free(in_tail) };
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and not freed again.
            unsafe { EVP_CIPHER_free(cipher) };
        }
        return not_landed("enc -pass");
    }
    // `if ((str == NULL) && (cipher != NULL) && (hkey == NULL) &&
    // (skeyopts == NULL)) { ... prompt ... }` — `apps/enc.c:436-465`.
    if !cipher.is_null() && hkey.is_none() && !skeyopts_present {
        // SAFETY: `in_tail` is live and not freed again.
        unsafe { BIO_free(in_tail) };
        // SAFETY: `cipher` is live and not freed again.
        unsafe { EVP_CIPHER_free(cipher) };
        return not_landed("enc passphrase prompt");
    }

    // `out = bio_open_default(outfile, 'w', outformat); if (out == NULL) goto
    // end;` — `apps/enc.c:467-469`.
    let out_tail = bio_open_default(outfile.as_deref(), true);
    if out_tail.is_null() {
        // SAFETY: `in_tail` is live and not freed again.
        unsafe { BIO_free(in_tail) };
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and not freed again.
            unsafe { EVP_CIPHER_free(cipher) };
        }
        return 1;
    }

    let mut rbio = in_tail;
    let mut wbio = out_tail;

    // `if (base64) { b64 = BIO_new(BIO_f_base64()); ... if (olb64)
    // BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); if (enc) wbio = BIO_push(b64,
    // wbio); else rbio = BIO_push(b64, rbio); }` — `apps/enc.c:524-537`.
    let mut b64: *mut Bio = core::ptr::null_mut();
    if base64 {
        // SAFETY: `BIO_f_base64` is this crate's method table.
        b64 = unsafe { BIO_new(BIO_f_base64()) };
        if b64.is_null() {
            // SAFETY: all are live and not freed again.
            unsafe { BIO_free(in_tail) };
            // SAFETY: as above.
            unsafe { BIO_free_all(out_tail) };
            if !cipher.is_null() {
                // SAFETY: `cipher` is live and not freed again.
                unsafe { EVP_CIPHER_free(cipher) };
            }
            return 1;
        }
        if olb64 {
            // SAFETY: `b64` is live.
            unsafe { BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL) };
        }
        if enc {
            // SAFETY: `b64`/`wbio` are live.
            wbio = unsafe { BIO_push(b64, wbio) };
        } else {
            // SAFETY: `b64`/`rbio` are live.
            rbio = unsafe { BIO_push(b64, rbio) };
        }
    }

    // `if (cipher != NULL) { ... }` — `apps/enc.c:539-767`.
    let mut key = [0u8; EVP_MAX_KEY_LENGTH];
    let mut iv = [0u8; EVP_MAX_IV_LENGTH];
    let salt = [0u8; EVP_MAX_IV_LENGTH];
    let mut benc: *mut Bio = core::ptr::null_mut();
    let mut go_out = false;
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        let ivlen = unsafe { EVP_CIPHER_get_iv_length(cipher) };
        // SAFETY: `cipher` is live.
        let keylen = unsafe { EVP_CIPHER_get_key_length(cipher) };

        // `if (hiv != NULL) { int siz = EVP_CIPHER_get_iv_length(cipher); ... }`
        // — `apps/enc.c:641-650`.
        if let Some(h) = &hiv {
            if ivlen == 0 {
                eprintln!("warning: iv not used by this cipher");
            } else if !set_hex(h, &mut iv[..ivlen as usize]) {
                eprintln!("invalid hex iv value");
                go_out = true;
            }
        }
        // `if ((hiv == NULL) && (str == NULL) && EVP_CIPHER_get_iv_length(cipher)
        // != 0 && wrap == 0) { ... "iv undefined" ... }` — `apps/enc.c:651-660`.
        if !go_out && hiv.is_none() && ivlen != 0 && !wrap {
            eprintln!("iv undefined");
            go_out = true;
        }
        // `if (hkey != NULL) { if (!set_hex(hkey, key,
        // EVP_CIPHER_get_key_length(cipher))) { ... } ... }` —
        // `apps/enc.c:661-669`.
        if !go_out {
            if let Some(h) = &hkey {
                if !set_hex(h, &mut key[..keylen as usize]) {
                    eprintln!("invalid hex key value");
                    go_out = true;
                }
            }
        }

        // `benc = BIO_new(BIO_f_cipher()); ... BIO_get_cipher_ctx(benc, &ctx);`
        // — `apps/enc.c:680-688`.
        if !go_out {
            // SAFETY: `BIO_f_cipher` is this crate's method table.
            benc = unsafe { BIO_new(BIO_f_cipher()) };
            if benc.is_null() {
                go_out = true;
            }
        }
        let mut ctx: *mut c_void = core::ptr::null_mut();
        if !go_out {
            // SAFETY: `benc` is live; the control writes the live context.
            unsafe {
                BIO_ctrl(
                    benc,
                    BIO_C_GET_CIPHER_CTX,
                    0,
                    core::ptr::addr_of_mut!(ctx).cast(),
                )
            };
        }
        // `if (wrap == 1) EVP_CIPHER_CTX_set_flags(ctx,
        // EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);` — `apps/enc.c:690-691`.
        if !go_out && wrap {
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_set_flags(ctx.cast(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
        }
        // `if (rawkey_set) { if (!EVP_CipherInit_ex(ctx, cipher, e, key, iv, enc))
        // { ... } }` — `apps/enc.c:693-700`.
        if !go_out {
            let ivp: *const u8 = if hiv.is_none() && wrap {
                core::ptr::null()
            } else {
                iv.as_ptr()
            };
            // SAFETY: `ctx`/`cipher` are live; `key` is `keylen` bytes; engine NULL.
            let ok = unsafe {
                EVP_CipherInit_ex(
                    ctx.cast(),
                    cipher,
                    core::ptr::null_mut(),
                    key.as_ptr(),
                    ivp,
                    c_int::from(enc),
                )
            };
            if ok == 0 {
                // SAFETY: `cipher` is live.
                let name = unsafe { EVP_CIPHER_get0_name(cipher) };
                let name = if name.is_null() {
                    String::new()
                } else {
                    // SAFETY: `name` is a NUL-terminated static.
                    unsafe { std::ffi::CStr::from_ptr(name) }
                        .to_string_lossy()
                        .into_owned()
                };
                eprintln!("Error setting cipher {name}");
                go_out = true;
            }
        }
        // `if (nopad) EVP_CIPHER_CTX_set_padding(ctx, 0);` — `apps/enc.c:735-736`.
        if !go_out && nopad {
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_set_padding(ctx.cast(), 0) };
        }
        // `if (printkey) { ... printf ... if (printkey == 2) { ret = 0; goto end;
        // } }` — `apps/enc.c:743-766`.
        if !go_out && printkey != 0 {
            print!(
                "{}",
                render_printkey(
                    &salt[..saltlen],
                    nosalt,
                    &key[..keylen as usize],
                    ivlen as usize,
                    &iv
                )
            );
            if printkey == 2 {
                // SAFETY: all are live and not freed again.
                unsafe { BIO_free(in_tail) };
                // SAFETY: as above.
                unsafe { BIO_free_all(out_tail) };
                // SAFETY: as above.
                unsafe { BIO_free(benc) };
                // SAFETY: as above.
                unsafe { BIO_free(b64) };
                if !cipher.is_null() {
                    // SAFETY: `cipher` is live and not freed again.
                    unsafe { EVP_CIPHER_free(cipher) };
                }
                return 0;
            }
        }
    }
    if go_out {
        // SAFETY: all are live and not freed again.
        unsafe { BIO_free(in_tail) };
        // SAFETY: as above.
        unsafe { BIO_free_all(out_tail) };
        // SAFETY: as above.
        unsafe { BIO_free(benc) };
        // SAFETY: as above.
        unsafe { BIO_free(b64) };
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and not freed again.
            unsafe { EVP_CIPHER_free(cipher) };
        }
        return 1;
    }

    // `if (benc != NULL) wbio = BIO_push(benc, wbio);` — `apps/enc.c:770-771`.
    if !benc.is_null() {
        // SAFETY: both are live.
        wbio = unsafe { BIO_push(benc, wbio) };
    }

    // `while (BIO_pending(rbio) || !BIO_eof(rbio)) { ... }` —
    // `apps/enc.c:773-787`.
    let mut buff = vec![0u8; bsize];
    let mut ret = 1i32;
    loop {
        if !(bio_pending(rbio) > 0 || !bio_eof(rbio)) {
            break;
        }
        // SAFETY: `rbio` is live; `buff` is writable for `bsize` bytes.
        let inl = unsafe { BIO_read(rbio, buff.as_mut_ptr().cast(), bsize as c_int) };
        if inl <= 0 {
            break;
        }
        if !streamable && !bio_eof(rbio) {
            eprintln!("Unstreamable cipher mode");
            ret = 2;
            break;
        }
        // SAFETY: `wbio` is live; `buff[..inl]` is readable.
        let w = unsafe { BIO_write(wbio, buff.as_ptr().cast(), inl) };
        if w != inl {
            eprintln!("error writing output file");
            ret = 2;
            break;
        }
        if !streamable {
            break;
        }
    }
    if ret == 1 {
        // `if (!BIO_flush(wbio)) { if (enc) "bad encrypt" else "bad decrypt"; goto
        // end; }` — `apps/enc.c:788-794`.
        // SAFETY: `wbio` is live.
        let flushed = unsafe { BIO_ctrl(wbio, BIO_CTRL_FLUSH, 0, core::ptr::null_mut()) };
        if flushed == 0 {
            if enc {
                eprintln!("bad encrypt");
            } else {
                eprintln!("bad decrypt");
            }
        } else {
            ret = 0;
        }
    }

    // `end: ... BIO_free(in); BIO_free_all(out); BIO_free(benc); BIO_free(b64);
    // ... EVP_CIPHER_free(cipher);` — `apps/enc.c:801-821`.
    // SAFETY: all are live and not freed again.
    unsafe { BIO_free(in_tail) };
    // SAFETY: as above.
    unsafe { BIO_free_all(out_tail) };
    // SAFETY: as above.
    unsafe { BIO_free(benc) };
    // SAFETY: as above.
    unsafe { BIO_free(b64) };
    if !cipher.is_null() {
        // SAFETY: `cipher` is live and not freed again.
        unsafe { EVP_CIPHER_free(cipher) };
    }
    ret
}
