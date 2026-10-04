//! Phase 17.1e — `apps/passwd.c`: the `openssl passwd` command.
//!
//! The command body (`apps/passwd.c:103-311`): parse the generated
//! `PASSWD_OPTIONS` table, read the password(s) from the positional arguments or
//! `-in`/`-stdin`, then hash each through `md5crypt`/`shacrypt` (or the AIX MD5
//! variant). The parse, the source selection and the crypt algorithms are
//! transcribed whole, including the `cov_2char` alphabet and the output
//! permutation.
//!
//! ## What the court drives
//!
//! `passwd -1/-5/-6 -salt <fixed> <password>` and the same via
//! `-in <pwfile.txt>`, plus the `-table`/`-reverse` output shapes. Each is a
//! pure function of the fixed salt and password.
//!
//! ## Recorded divergences (module header)
//!
//! * **The random-salt arm is not driven.** With no `-salt`, `do_passwd`
//!   (`apps/passwd.c:792-816`) draws an 8- or 16-byte salt through
//!   `RAND_bytes`, so `passwd <password>` emits a fresh hash and is recorded.
//! * **`app_RAND_load` is not called.** The authority's `app_RAND_load()`
//!   (`apps/passwd.c:208-209`) is an `apps/lib` helper this stratum does not own;
//!   it is unobservable for the fixed-salt arms.
//! * **The interactive arms are not landed.** With neither a password argument
//!   nor `-in`/`-stdin`, the authority prompts through `EVP_read_pw_string`
//!   (`apps/passwd.c:239-263`); the court passes a password or `-in`.
//! * **`-in` line reading is reduced to its observable.** The authority reads
//!   through `BIO_gets` (`apps/passwd.c:280-299`); this module reads the same
//!   newline-delimited lines with the same truncation to `pw_maxlen`.
//! * **`-rand`/`-writerand` and the provider arms are not landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_void;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PASSWD_OPTIONS;
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::evp::legacy_md5::EVP_md5;
use crate::evp::legacy_sha::{EVP_sha256, EVP_sha512};

/// `cov_2char[64]` — `apps/passwd.c:25-35`, "from crypto/des/fcrypt.c".
const COV_2CHAR: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `passwd_modes` — `apps/passwd.c:39-46`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unset,
    Md5,
    Apr1,
    Sha256,
    Sha512,
    Aixmd5,
}

/// A digest context wrapper over the crate's `EVP_MD_CTX_*` for the crypt bodies.
struct Md {
    ctx: *mut c_void,
}

impl Md {
    /// `EVP_MD_CTX_new()` + `EVP_DigestInit_ex(ctx, md, NULL)`.
    fn new(md: *const c_void) -> Option<Md> {
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            return None;
        }
        // SAFETY: `ctx` is a fresh, live context; `md` is a static method table.
        if unsafe { EVP_DigestInit_ex(ctx.cast(), md.cast(), core::ptr::null_mut()) } <= 0 {
            // SAFETY: `ctx` is live and not freed again.
            unsafe { EVP_MD_CTX_free(ctx.cast()) };
            return None;
        }
        Some(Md { ctx: ctx.cast() })
    }

    /// `EVP_DigestUpdate(md, data, len)`.
    fn update(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        // SAFETY: `ctx` is live; `data` is readable for its length.
        (unsafe { EVP_DigestUpdate(self.ctx.cast(), data.as_ptr().cast(), data.len()) }) > 0
    }

    /// `EVP_DigestFinal_ex(md, out, NULL)`.
    fn final_into(&mut self, out: &mut [u8]) -> bool {
        // SAFETY: `ctx` is live; `out` is writable for the digest size.
        (unsafe { EVP_DigestFinal_ex(self.ctx.cast(), out.as_mut_ptr(), core::ptr::null_mut()) })
            > 0
    }
}

impl Drop for Md {
    fn drop(&mut self) {
        // SAFETY: `ctx` is live and freed exactly once, here.
        unsafe { EVP_MD_CTX_free(self.ctx.cast()) };
    }
}

/// `static char *md5crypt(const char *passwd, const char *magic, const char *salt)`
/// — `apps/passwd.c:322-494`.
fn md5crypt(passwd: &[u8], magic: &str, salt: &str) -> Option<String> {
    let ascii_salt: String = salt.chars().take(8).collect();
    let salt_bytes = ascii_salt.as_bytes();
    let magic_bytes = magic.as_bytes();

    let mut out = String::new();
    if !magic.is_empty() {
        out.push('$');
        out.push_str(magic);
        out.push('$');
    }
    out.push_str(&ascii_salt);
    if out.len() > 6 + 8 {
        return None;
    }

    let mut buf = [0u8; 16];
    let mut md = Md::new(EVP_md5().cast())?;
    if !md.update(passwd) {
        return None;
    }
    if !magic.is_empty() && (!md.update(b"$") || !md.update(magic_bytes) || !md.update(b"$")) {
        return None;
    }
    if !md.update(salt_bytes) {
        return None;
    }

    let mut md2 = Md::new(EVP_md5().cast())?;
    if !md2.update(passwd) || !md2.update(salt_bytes) || !md2.update(passwd) {
        return None;
    }
    if !md2.final_into(&mut buf) {
        return None;
    }

    let mut i = passwd.len();
    while i > 16 {
        if !md.update(&buf) {
            return None;
        }
        i -= 16;
    }
    if !md.update(&buf[..i]) {
        return None;
    }

    let mut n = passwd.len();
    while n != 0 {
        let one: &[u8] = if n & 1 != 0 { b"\0" } else { &passwd[..1] };
        if !md.update(one) {
            return None;
        }
        n >>= 1;
    }
    if !md.final_into(&mut buf) {
        return None;
    }

    for idx in 0..1000u32 {
        let mut ctx = Md::new(EVP_md5().cast())?;
        let first: &[u8] = if idx & 1 != 0 { passwd } else { &buf };
        if !ctx.update(first) {
            return None;
        }
        if idx % 3 != 0 && !ctx.update(salt_bytes) {
            return None;
        }
        if idx % 7 != 0 && !ctx.update(passwd) {
            return None;
        }
        let last: &[u8] = if idx & 1 != 0 { &buf } else { passwd };
        if !ctx.update(last) {
            return None;
        }
        if !ctx.final_into(&mut buf) {
            return None;
        }
    }

    // `silly output permutation` — `apps/passwd.c:449-480`.
    let mut buf_perm = [0u8; 16];
    let mut source = 0usize;
    for slot in buf_perm.iter_mut().take(14) {
        *slot = buf[source];
        source = (source + 6) % 17;
    }
    buf_perm[14] = buf[5];
    buf_perm[15] = buf[11];

    out.push('$');
    let mut idx = 0usize;
    while idx < 15 {
        out.push(COV_2CHAR[(buf_perm[idx + 2] & 0x3f) as usize] as char);
        out.push(
            COV_2CHAR[(((buf_perm[idx + 1] & 0xf) << 2) | (buf_perm[idx + 2] >> 6)) as usize]
                as char,
        );
        out.push(
            COV_2CHAR[(((buf_perm[idx] & 3) << 4) | (buf_perm[idx + 1] >> 4)) as usize] as char,
        );
        out.push(COV_2CHAR[(buf_perm[idx] >> 2) as usize] as char);
        idx += 3;
    }
    out.push(COV_2CHAR[(buf_perm[15] & 0x3f) as usize] as char);
    out.push(COV_2CHAR[(buf_perm[15] >> 6) as usize] as char);
    Some(out)
}

/// `static char *shacrypt(const char *passwd, const char *magic, const char *salt)`
/// — `apps/passwd.c:501-780`.
fn shacrypt(passwd: &[u8], magic: &str, salt: &str) -> Option<String> {
    const ROUNDS_DEFAULT: u32 = 5000;
    const ROUNDS_MIN: u32 = 1000;
    const ROUNDS_MAX: u32 = 999_999_999;

    let magic_bytes = magic.as_bytes();
    if magic_bytes.len() != 1 {
        return None;
    }
    let (sha, buf_size): (*const c_void, usize) = match magic_bytes[0] {
        b'5' => (EVP_sha256().cast(), 32),
        b'6' => (EVP_sha512().cast(), 64),
        _ => return None,
    };

    let mut rounds = ROUNDS_DEFAULT;
    let mut rounds_custom = false;
    let mut salt = salt;
    if let Some(rest) = salt.strip_prefix("rounds=") {
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let endp = &rest[num.len()..];
        let stripped = endp.strip_prefix('$')?;
        salt = stripped;
        let srounds: u64 = num.parse().unwrap_or(0);
        rounds = if srounds > ROUNDS_MAX as u64 {
            ROUNDS_MAX
        } else if srounds < ROUNDS_MIN as u64 {
            ROUNDS_MIN
        } else {
            srounds as u32
        };
        rounds_custom = true;
    }

    let ascii_salt: String = salt.chars().take(16).collect();
    let salt_bytes = ascii_salt.as_bytes();

    let mut out = String::new();
    out.push('$');
    out.push_str(magic);
    out.push('$');
    if rounds_custom {
        out.push_str(&format!("rounds={rounds}$"));
    }
    out.push_str(&ascii_salt);
    if out.len() > 3 + 17 * usize::from(rounds_custom) + salt_bytes.len() {
        return None;
    }

    let mut buf = [0u8; 64];
    let mut temp_buf = [0u8; 64];

    let mut md = Md::new(sha)?;
    if !md.update(passwd) || !md.update(salt_bytes) {
        return None;
    }

    let mut md2 = Md::new(sha)?;
    if !md2.update(passwd) || !md2.update(salt_bytes) || !md2.update(passwd) {
        return None;
    }
    if !md2.final_into(&mut buf) {
        return None;
    }

    let mut n = passwd.len();
    while n > buf_size {
        if !md.update(&buf[..buf_size]) {
            return None;
        }
        n -= buf_size;
    }
    if !md.update(&buf[..n]) {
        return None;
    }

    n = passwd.len();
    while n != 0 {
        let chunk: &[u8] = if n & 1 != 0 { &buf[..buf_size] } else { passwd };
        if !md.update(chunk) {
            return None;
        }
        n >>= 1;
    }
    if !md.final_into(&mut buf) {
        return None;
    }

    // `P sequence` — `apps/passwd.c:647-662`.
    let mut p_bytes = vec![0u8; passwd.len()];
    {
        let mut ctx = Md::new(sha)?;
        for _ in 0..passwd.len() {
            if !ctx.update(passwd) {
                return None;
            }
        }
        if !ctx.final_into(&mut temp_buf) {
            return None;
        }
    }
    {
        let mut cp = p_bytes.as_mut_slice();
        let mut n = passwd.len();
        while n > buf_size {
            let (dst, rest) = cp.split_at_mut(buf_size);
            dst.copy_from_slice(&temp_buf[..buf_size]);
            cp = rest;
            n -= buf_size;
        }
        cp[..n].copy_from_slice(&temp_buf[..n]);
    }

    // `S sequence` — `apps/passwd.c:664-679`.
    let mut s_bytes = vec![0u8; salt_bytes.len()];
    {
        let mut ctx = Md::new(sha)?;
        let mut cnt = 16 + buf[0] as usize;
        while cnt > 0 {
            if !ctx.update(salt_bytes) {
                return None;
            }
            cnt -= 1;
        }
        if !ctx.final_into(&mut temp_buf) {
            return None;
        }
    }
    {
        let mut cp = s_bytes.as_mut_slice();
        let mut n = salt_bytes.len();
        while n > buf_size {
            let (dst, rest) = cp.split_at_mut(buf_size);
            dst.copy_from_slice(&temp_buf[..buf_size]);
            cp = rest;
            n -= buf_size;
        }
        cp[..n].copy_from_slice(&temp_buf[..n]);
    }

    for idx in 0..rounds {
        let mut ctx = Md::new(sha)?;
        let first: &[u8] = if idx & 1 != 0 {
            &p_bytes
        } else {
            &buf[..buf_size]
        };
        if !ctx.update(first) {
            return None;
        }
        if idx % 3 != 0 && !ctx.update(&s_bytes) {
            return None;
        }
        if idx % 7 != 0 && !ctx.update(&p_bytes) {
            return None;
        }
        let last: &[u8] = if idx & 1 != 0 {
            &buf[..buf_size]
        } else {
            &p_bytes
        };
        if !ctx.update(last) {
            return None;
        }
        if !ctx.final_into(&mut buf) {
            return None;
        }
    }

    out.push('$');
    let mut push24 = |b2: u8, b1: u8, b0: u8, n: i32| {
        let mut w: u32 = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
        let mut i = n;
        while i > 0 {
            out.push(COV_2CHAR[(w & 0x3f) as usize] as char);
            w >>= 6;
            i -= 1;
        }
    };

    match magic_bytes[0] {
        b'5' => {
            push24(buf[0], buf[10], buf[20], 4);
            push24(buf[21], buf[1], buf[11], 4);
            push24(buf[12], buf[22], buf[2], 4);
            push24(buf[3], buf[13], buf[23], 4);
            push24(buf[24], buf[4], buf[14], 4);
            push24(buf[15], buf[25], buf[5], 4);
            push24(buf[6], buf[16], buf[26], 4);
            push24(buf[27], buf[7], buf[17], 4);
            push24(buf[18], buf[28], buf[8], 4);
            push24(buf[9], buf[19], buf[29], 4);
            push24(0, buf[31], buf[30], 3);
        }
        b'6' => {
            push24(buf[0], buf[21], buf[42], 4);
            push24(buf[22], buf[43], buf[1], 4);
            push24(buf[44], buf[2], buf[23], 4);
            push24(buf[3], buf[24], buf[45], 4);
            push24(buf[25], buf[46], buf[4], 4);
            push24(buf[47], buf[5], buf[26], 4);
            push24(buf[6], buf[27], buf[48], 4);
            push24(buf[28], buf[49], buf[7], 4);
            push24(buf[50], buf[8], buf[29], 4);
            push24(buf[9], buf[30], buf[51], 4);
            push24(buf[31], buf[52], buf[10], 4);
            push24(buf[53], buf[11], buf[32], 4);
            push24(buf[12], buf[33], buf[54], 4);
            push24(buf[34], buf[55], buf[13], 4);
            push24(buf[56], buf[14], buf[35], 4);
            push24(buf[15], buf[36], buf[57], 4);
            push24(buf[37], buf[58], buf[16], 4);
            push24(buf[59], buf[17], buf[38], 4);
            push24(buf[18], buf[39], buf[60], 4);
            push24(buf[40], buf[61], buf[19], 4);
            push24(buf[62], buf[20], buf[41], 4);
            push24(0, 0, buf[63], 2);
        }
        _ => return None,
    }
    Some(out)
}

/// `static int do_passwd(...)` — `apps/passwd.c:782-852`. The random-salt arm
/// (`!passed_salt`) is not landed (see the header); the court always passes salt.
#[allow(clippy::too_many_arguments)] // the authority's `do_passwd` takes the same eight
fn do_passwd(
    passed_salt: bool,
    salt: &str,
    passwd: &str,
    quiet: bool,
    table: bool,
    reverse: bool,
    pw_maxlen: usize,
    mode: Mode,
) -> bool {
    if !passed_salt {
        // `apps/passwd.c:792-816` draws the salt through `RAND_bytes`; not landed.
        return false;
    }

    // `if ((strlen(passwd) > pw_maxlen)) { ... truncate ... }` —
    // `apps/passwd.c:820-831`.
    let mut owned = passwd.to_string();
    if owned.len() > pw_maxlen {
        if !quiet {
            eprintln!("Warning: truncating password to {pw_maxlen} characters");
        }
        owned.truncate(pw_maxlen);
    }
    let pw = owned.as_bytes();

    // `apps/passwd.c:833-840`.
    let hash = match mode {
        Mode::Md5 => md5crypt(pw, "1", salt),
        Mode::Apr1 => md5crypt(pw, "apr1", salt),
        Mode::Aixmd5 => md5crypt(pw, "", salt),
        Mode::Sha256 => shacrypt(pw, "5", salt),
        Mode::Sha512 => shacrypt(pw, "6", salt),
        Mode::Unset => None,
    };
    let Some(hash) = hash else {
        return false;
    };

    // `apps/passwd.c:842-847`.
    if table && !reverse {
        println!("{}\t{}", owned, hash);
    } else if table && reverse {
        println!("{}\t{}", hash, owned);
    } else {
        println!("{hash}");
    }
    true
}

/// `int passwd_main(int argc, char **argv)` — `apps/passwd.c:103-311`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, passwd_options);` — `apps/passwd.c:120`.
    let mut opts = Opts::init(argv, PASSWD_OPTIONS);
    let mut infile: Option<String> = None;
    let mut in_stdin = false;
    let mut pw_source_defined = false;
    let mut passed_salt = false;
    let mut salt = String::new();
    let mut quiet = false;
    let mut table = false;
    let mut reverse = false;
    let mut mode = Mode::Unset;
    let pw_maxlen = 256usize;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/passwd.c:121`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(passwd_options); ret = 0; goto end;` —
            // `apps/passwd.c:128-131`.
            OptMatch::Help => return not_landed("passwd -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/passwd.c:123-127`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_IN: if (pw_source_defined) goto opthelp; infile = opt_arg();
            // pw_source_defined = 1;` — `apps/passwd.c:132-137`.
            OptMatch::Value("in", v) => {
                if pw_source_defined {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                infile = Some(v);
                pw_source_defined = true;
            }
            // `case OPT_NOVERIFY: in_noverify = 1; break;` — `apps/passwd.c:138-142`.
            OptMatch::Flag("noverify") => {}
            // `case OPT_QUIET: quiet = 1; break;` — `apps/passwd.c:143-145`.
            OptMatch::Flag("quiet") => quiet = true,
            // `case OPT_TABLE: table = 1; break;` — `apps/passwd.c:146-148`.
            OptMatch::Flag("table") => table = true,
            // `case OPT_REVERSE: reverse = 1; break;` — `apps/passwd.c:149-151`.
            OptMatch::Flag("reverse") => reverse = true,
            // `case OPT_1: if (mode != passwd_unset) goto opthelp; mode = passwd_md5;`
            // — `apps/passwd.c:152-156`.
            OptMatch::Flag("1") => {
                if mode != Mode::Unset {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Mode::Md5;
            }
            // `case OPT_5: ... mode = passwd_sha256;` — `apps/passwd.c:157-161`.
            OptMatch::Flag("5") => {
                if mode != Mode::Unset {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Mode::Sha256;
            }
            // `case OPT_6: ... mode = passwd_sha512;` — `apps/passwd.c:162-166`.
            OptMatch::Flag("6") => {
                if mode != Mode::Unset {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Mode::Sha512;
            }
            // `case OPT_APR1: ... mode = passwd_apr1;` — `apps/passwd.c:167-171`.
            OptMatch::Flag("apr1") => {
                if mode != Mode::Unset {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Mode::Apr1;
            }
            // `case OPT_AIXMD5: ... mode = passwd_aixmd5;` — `apps/passwd.c:172-176`.
            OptMatch::Flag("aixmd5") => {
                if mode != Mode::Unset {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                mode = Mode::Aixmd5;
            }
            // `case OPT_SALT: passed_salt = 1; salt = opt_arg(); break;` —
            // `apps/passwd.c:177-180`.
            OptMatch::Value("salt", v) => {
                passed_salt = true;
                salt = v;
            }
            // `case OPT_STDIN: if (pw_source_defined) goto opthelp; in_stdin = 1;
            // pw_source_defined = 1;` — `apps/passwd.c:181-186`.
            OptMatch::Flag("stdin") => {
                if pw_source_defined {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                in_stdin = true;
                pw_source_defined = true;
            }
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/passwd.c:187-190`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("passwd -rand")
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/passwd.c:191-194`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("passwd -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (*argv != NULL) { if
    // (pw_source_defined) goto opthelp; pw_source_defined = 1; passwds = argv; }`
    // — `apps/passwd.c:198-206`.
    let mut passwds: Vec<String> = Vec::new();
    if !opts.rest().is_empty() {
        if pw_source_defined {
            eprintln!("{}: Use -help for summary.", opts.prog());
            return 1;
        }
        passwds = opts.rest().to_vec();
    }

    // `if (!app_RAND_load()) goto end;` — `apps/passwd.c:208-209`. Skipped (see
    // the header); unobservable for the fixed-salt arms.

    // `if (mode == passwd_unset) mode = passwd_md5;` — `apps/passwd.c:211-214`.
    if mode == Mode::Unset {
        mode = Mode::Md5;
    }

    // `if (infile != NULL && in_stdin) { BIO_printf(bio_err, "%s: Can't combine
    // -in and -stdin\n", prog); goto end; }` — `apps/passwd.c:216-219`.
    if infile.is_some() && in_stdin {
        eprintln!("{}: Can't combine -in and -stdin", opts.prog());
        return 1;
    }

    let ret;
    if !passwds.is_empty() {
        ret = 0;
        for pw in &passwds {
            if !do_passwd(
                passed_salt,
                &salt,
                pw,
                quiet,
                table,
                reverse,
                pw_maxlen,
                mode,
            ) {
                return 1;
            }
        }
    } else if let Some(file) = &infile {
        // `in = bio_open_default(infile, 'r', FORMAT_TEXT);` — `apps/passwd.c:221-229`.
        let content = match std::fs::read(file) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Could not open file or uri for loading of {file}");
                return 1;
            }
        };
        ret = 0;
        for line in content.split_inclusive(|&b| b == b'\n') {
            let raw = if line.ends_with(b"\n") {
                &line[..line.len() - 1]
            } else {
                line
            };
            if raw.is_empty() && line.is_empty() {
                continue;
            }
            let pw = String::from_utf8_lossy(raw).into_owned();
            if !do_passwd(
                passed_salt,
                &salt,
                &pw,
                quiet,
                table,
                reverse,
                pw_maxlen,
                mode,
            ) {
                return 1;
            }
        }
    } else {
        // Neither a password argument nor `-in`/`-stdin`: the authority prompts
        // through `EVP_read_pw_string` (`apps/passwd.c:239-263`).
        return not_landed("passwd interactive");
    }

    ret
}
