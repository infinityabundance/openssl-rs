//! Phase 4 — the `BIO_snprintf`/`BIO_printf` formatting engine.
//!
//! `BIO_snprintf`, `BIO_vsnprintf`, `BIO_printf` and `BIO_vprintf` do **not**
//! format with the C library. The authority carries its own engine (`_dopr` in
//! `crypto/bio/bio_print.c`, descended from Patrick Powell's 1995 `snprintf`),
//! and its dialect is observable:
//!
//! * `%s` of a NULL pointer prints `<NULL>` where glibc prints `(null)`;
//! * `%p` of NULL prints `0` where glibc prints `(nil)`;
//! * an unknown conversion is skipped and produces nothing, where glibc fails
//!   the whole call;
//! * `%e` of `10.0` prints `10.000000e+00`, because the exponent loop steps only
//!   while the mantissa is **strictly** greater than ten — a different
//!   normalisation rule, not a rounding difference;
//! * at most nine fraction digits are ever produced (`if (max > 9) max = 9`).
//!
//! Every one of those was measured against the authority's DSO before this
//! module existed; the previous implementation delegated to `vsnprintf` and was
//! wrong on all five. `RT-BIO-PRINT` is the court that pins them.
//!
//! This module is written from the observable contract rather than transliterated
//! from the authority's C, but the contract *is* a printf dialect, so the
//! structure necessarily matches: a format state machine, three value
//! formatters, and a sink that either truncates into the caller's buffer or
//! grows.
//!
//! ## Why the arguments arrive through callbacks
//!
//! A C-variadic function cannot be **defined** in stable Rust, and `va_arg`
//! requires the un-erased argument list. The C shim (`src/runtime/bio/bio_va.c`)
//! therefore does the one thing Rust cannot — pull the next argument of a
//! requested ABI class off the `va_list` — and this module does everything else,
//! including the *decision* of which class to pull. Keeping the parse
//! single-sourced in Rust is what stops the shim from becoming a second format
//! parser that could disagree with this one.
//!
//! On x86-64 SysV the general-purpose and floating-point arguments advance
//! independent cursors in the `va_list`, so pulling "the next integer-class
//! argument" and "the next floating-point argument" preserves order exactly as
//! the real `va_arg` sequence would. Integer arguments narrower than a register
//! are read at register width and narrowed here, which is why the `cflags`
//! handling below is contract rather than detail. `long double` is `double` in
//! this build — `HAVE_LONG_DOUBLE` is undefined, so the authority's `LDOUBLE` is
//! `double` — which is why there is no third argument class.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use super::Bio;

// ---------------------------------------------------------------------------
// The flags and conversion modifiers, from the authority's source
// ---------------------------------------------------------------------------

const DP_F_MINUS: i32 = 1 << 0;
const DP_F_PLUS: i32 = 1 << 1;
const DP_F_SPACE: i32 = 1 << 2;
const DP_F_NUM: i32 = 1 << 3;
const DP_F_ZERO: i32 = 1 << 4;
const DP_F_UP: i32 = 1 << 5;
const DP_F_UNSIGNED: i32 = 1 << 6;

const DP_C_CHAR: i32 = 1;
const DP_C_SHORT: i32 = 2;
const DP_C_LONG: i32 = 3;
const DP_C_LDOUBLE: i32 = 4;
const DP_C_LLONG: i32 = 5;
const DP_C_SIZE: i32 = 6;
const DP_C_PTRDIFF: i32 = 7;

const F_FORMAT: i32 = 0;
const E_FORMAT: i32 = 1;
const G_FORMAT: i32 = 2;

/// `decimal_size(int64) + 3` from the authority — the digit scratch size.
const CONVERT_SIZE: usize = 26;

/// The integer-class and floating-point-class argument sources.
///
/// The trait exists so the engine can be unit-tested without a real `va_list`;
/// see the `VecArgs` tests at the bottom of this file.
pub(crate) trait Args {
    /// The next general-purpose argument, read at register width.
    fn gp(&mut self) -> u64;
    /// The next floating-point argument.
    fn fp(&mut self) -> f64;
}

extern "C" {
    /// Pull one general-purpose argument. Defined in `bio_va.c`.
    fn openssl_rs_va_gp(ap: *mut c_void) -> u64;
    /// Pull one floating-point argument. Defined in `bio_va.c`.
    fn openssl_rs_va_fp(ap: *mut c_void) -> f64;
}

/// The real argument source: the caller's `va_list`.
struct VaArgs(*mut c_void);

impl Args for VaArgs {
    fn gp(&mut self) -> u64 {
        // SAFETY: `self.0` is the live `va_list` the C shim was called with, and
        // the shim only reads it.
        unsafe { openssl_rs_va_gp(self.0) }
    }

    fn fp(&mut self) -> f64 {
        // SAFETY: as above.
        unsafe { openssl_rs_va_fp(self.0) }
    }
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

/// Where the engine writes.
///
/// The authority has one descriptor with both a static and an optional dynamic
/// buffer, and switches from the first to the second when the static one fills
/// (`BIO_vprintf` passes a 2048-byte stack buffer, `BIO_vsnprintf` passes none).
/// The observable consequences are reproduced here: a fixed sink *truncates* and
/// reports it, a growing sink does not, and both advance `pos` even for bytes
/// that were not stored — which is what `%n` reports.
struct Dopr<'a> {
    /// The caller's buffer, or NULL when the sink grows.
    fixed: *mut c_char,
    maxlen: usize,
    /// Bytes committed, including the terminating NUL.
    cur: usize,
    /// The growing buffer, when the sink is not fixed.
    grow: Option<&'a mut Vec<u8>>,
    args: &'a mut dyn Args,
    /// The `%n` write position. `long long` in the authority.
    pos: i64,
}

impl Dopr<'_> {
    /// `doapr_outch`.
    fn outch(&mut self, c: u8) -> bool {
        if let Some(v) = self.grow.as_mut() {
            v.push(c);
            self.cur += 1;
        } else if self.cur < self.maxlen {
            // SAFETY: the caller supplied a buffer of `maxlen` bytes.
            unsafe { *self.fixed.add(self.cur) = c as c_char };
            self.cur += 1;
        }
        if self.pos < i64::MAX {
            self.pos += 1;
        }
        true
    }

    /// `eob_ok` — the short-circuit that stops a long padding loop at the end of
    /// a fixed buffer while still advancing `pos` by the bytes it did not write.
    fn eob_ok(&mut self, left: i64) -> bool {
        if self.grow.is_some() {
            return true;
        }
        if self.cur >= self.maxlen {
            if left > 0 {
                if self.pos < i64::MAX - left {
                    self.pos += left;
                } else {
                    self.pos = i64::MAX;
                }
            }
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// fmtint
// ---------------------------------------------------------------------------

/// The octal alternative-form prefix. The authority compares the `prefix`
/// pointer against this literal to detect the octal case, so the identity of the
/// slice is meaningful here too.
const OCT_PREFIX: &[u8] = b"0";

fn fmtint(d: &mut Dopr, value: i64, base: u32, min: i32, max: i32, flags: i32) -> bool {
    let mut flags = flags;
    let mut max = max;
    let mut signvalue = 0u8;
    let mut prefix: &[u8] = b"";
    let mut uvalue = value as u64;
    let mut convert = [0u8; CONVERT_SIZE];
    let mut place = 0usize;

    if max < 0 {
        // A negative precision is taken as if the precision were omitted.
        max = 1;
    } else {
        // If a precision is given with an integer conversion, the 0 flag is
        // ignored.
        flags &= !DP_F_ZERO;
    }

    if flags & DP_F_UNSIGNED == 0 {
        if value < 0 {
            signvalue = b'-';
            uvalue = 0u64.wrapping_sub(value as u64);
        } else if flags & DP_F_PLUS != 0 {
            signvalue = b'+';
        } else if flags & DP_F_SPACE != 0 {
            signvalue = b' ';
        }
    }
    if flags & DP_F_NUM != 0 {
        if base == 8 {
            prefix = OCT_PREFIX;
        }
        if value != 0 && base == 16 {
            prefix = if flags & DP_F_UP != 0 { b"0X" } else { b"0x" };
        }
    }
    let caps = flags & DP_F_UP != 0;
    let digits: &[u8] = if caps {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };

    // When 0 is printed with an explicit precision 0, the output is empty.
    while uvalue != 0 && place < CONVERT_SIZE {
        convert[place] = digits[(uvalue % base as u64) as usize];
        place += 1;
        uvalue /= base as u64;
    }
    if place == CONVERT_SIZE {
        place -= 1;
    }

    let octal_prefix = prefix.as_ptr() == OCT_PREFIX.as_ptr();
    let mut zpadlen = max - place as i32 - i32::from(octal_prefix);
    if zpadlen < 0 {
        zpadlen = 0;
    }
    let mut spadlen = min
        - core::cmp::max(
            max,
            place as i32 + zpadlen + i32::from(signvalue != 0) + prefix.len() as i32,
        );
    if spadlen < 0 {
        spadlen = 0;
    }
    if flags & DP_F_MINUS != 0 {
        spadlen = -spadlen;
    } else if flags & DP_F_ZERO != 0 {
        zpadlen += spadlen;
        spadlen = 0;
    }

    // spaces
    while spadlen > 0 && d.eob_ok(spadlen as i64) {
        if !d.outch(b' ') {
            return false;
        }
        spadlen -= 1;
    }
    // sign
    if signvalue != 0 && !d.outch(signvalue) {
        return false;
    }
    // prefix
    for &b in prefix {
        if !d.outch(b) {
            return false;
        }
    }
    // zeros
    while zpadlen > 0 && d.eob_ok(zpadlen as i64) {
        if !d.outch(b'0') {
            return false;
        }
        zpadlen -= 1;
    }
    // digits, least-significant first
    while place > 0 {
        place -= 1;
        if !d.outch(convert[place]) {
            return false;
        }
    }
    // left-justified spaces
    if spadlen < 0 {
        spadlen = -spadlen;
        while spadlen > 0 && d.eob_ok(spadlen as i64) {
            if !d.outch(b' ') {
                return false;
            }
            spadlen -= 1;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// fmtstr
// ---------------------------------------------------------------------------

/// `OPENSSL_strnlen` — a bounded `strlen`.
///
/// # Safety
/// `p` must be NUL-terminated within `limit` bytes.
unsafe fn strnlen(p: *const c_char, limit: usize) -> usize {
    let mut n = 0usize;
    while n < limit {
        // SAFETY: the caller guarantees `limit` readable bytes.
        if unsafe { *p.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    n
}

/// The authority's `%s`, including the `<NULL>` substitution and the two-sided
/// padding rules.
///
/// # Safety
/// `value` must be NULL or a NUL-terminated C string.
unsafe fn fmtstr(d: &mut Dopr, value: *const c_char, flags: i32, min: i32, max: i32) -> bool {
    let value = if value.is_null() {
        c"<NULL>".as_ptr()
    } else {
        value
    };
    let mut max = max;
    let limit = if max < 0 { usize::MAX } else { max as usize };
    // SAFETY: `value` is NUL-terminated, so a bounded scan is valid.
    let mut strln = unsafe { strnlen(value, limit) };

    let mut padlen = 0i32;
    if min >= 0 && strln < c_int::MAX as usize {
        padlen = min - strln as i32;
        if padlen < 0 {
            padlen = 0;
        }
    }
    if max >= 0 {
        if max < c_int::MAX - padlen {
            max += padlen;
        } else {
            max = c_int::MAX;
        }
    }

    let mut cnt = 0i32;
    if flags & DP_F_MINUS == 0 && padlen > 0 {
        if max >= 0 {
            if padlen > max {
                padlen = max;
            }
            cnt = padlen;
        }
        while padlen > 0 && d.eob_ok(padlen as i64) {
            if !d.outch(b' ') {
                return false;
            }
            padlen -= 1;
        }
    }
    if max >= 0 {
        // The authority computes `max - cnt` in `int`. It is never negative here
        // because `cnt` is capped to `max` above, but the comparison is kept in
        // the same width so the rule cannot drift.
        let cap = max - cnt;
        if strln > c_int::MAX as usize || strln as i32 > cap {
            strln = cap as usize;
        }
        cnt += strln as i32;
    }
    let mut off = 0usize;
    let mut left = strln;
    while left > 0 && d.eob_ok(left as i64) {
        // SAFETY: the scan above proved these bytes readable.
        let b = unsafe { *value.add(off) } as u8;
        if !d.outch(b) {
            return false;
        }
        off += 1;
        left -= 1;
    }
    if flags & DP_F_MINUS != 0 && padlen > 0 {
        if max >= 0 && padlen > max - cnt {
            padlen = max - cnt;
        }
        while padlen > 0 && d.eob_ok(padlen as i64) {
            if !d.outch(b' ') {
                return false;
            }
            padlen -= 1;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// fmtfp
// ---------------------------------------------------------------------------

/// `abs_val` — including the two sentinel cases: an infinity becomes zero and a
/// NaN becomes zero, with the `?` sign applied by the caller.
fn abs_val(value: f64) -> f64 {
    let mut result = value;
    if value < 0.0 {
        result = -value;
    }
    if result > 0.0 && result / 2.0 == result {
        result = 0.0;
    } else if result != result {
        result = 0.0;
    }
    result
}

fn pow_10(in_exp: i32) -> f64 {
    let mut result = 1.0f64;
    let mut e = in_exp;
    while e != 0 {
        result *= 10.0;
        e -= 1;
    }
    result
}

fn roundv(value: f64) -> i64 {
    let mut intpart = value as i64;
    let frac = value - intpart as f64;
    if frac >= 0.5 {
        intpart += 1;
    }
    intpart
}

/// The authority's floating-point formatter, `F`/`E`/`G` styles.
fn fmtfp(d: &mut Dopr, fvalue: f64, min: i32, max: i32, flags: i32, style: i32) -> bool {
    let mut max = max;
    let mut signvalue = 0u8;
    let mut iplace = 0usize;
    let mut fplace = 0usize;
    let mut eplace = 0usize;
    let mut exp: i64 = 0;
    let mut iconvert = [0u8; 20];
    let mut fconvert = [0u8; 20];
    let mut econvert = [0u8; 20];

    if max < 0 {
        max = 6;
    }

    if fvalue < 0.0 {
        signvalue = b'-';
    } else if flags & DP_F_PLUS != 0 {
        signvalue = b'+';
    } else if flags & DP_F_SPACE != 0 {
        signvalue = b' ';
    }
    let mut ufvalue = abs_val(fvalue);
    if ufvalue == 0.0 && fvalue != 0.0 {
        // INF or NAN.
        signvalue = b'?';
    }

    // G sometimes prints like E and sometimes like F, depending on the value.
    let realstyle = if style == G_FORMAT {
        if ufvalue == 0.0 {
            F_FORMAT
        } else if ufvalue < 0.0001 {
            E_FORMAT
        } else if (max == 0 && ufvalue >= 10.0) || (max > 0 && ufvalue >= pow_10(max)) {
            E_FORMAT
        } else {
            F_FORMAT
        }
    } else {
        style
    };

    if style != F_FORMAT {
        let mut tmpvalue = ufvalue;
        // Calculate the exponent. The comparisons are strict: a mantissa of
        // exactly ten is left alone, which is why `%e` of 10.0 prints
        // `10.000000e+00` rather than `1.000000e+01`.
        if ufvalue != 0.0 {
            while tmpvalue < 1.0 {
                tmpvalue *= 10.0;
                exp -= 1;
            }
            while tmpvalue > 10.0 {
                tmpvalue /= 10.0;
                exp += 1;
            }
        }
        if style == G_FORMAT {
            // In G the precision is significant digits; there is always at least
            // one.
            if max == 0 {
                max = 1;
            }
            if realstyle == F_FORMAT {
                max -= (exp + 1) as i32;
                if max < 0 {
                    // Should not happen; the authority emits a NUL and fails.
                    d.outch(0);
                    return false;
                }
            } else {
                // In E there is always one significant digit before the point.
                max -= 1;
            }
        }
        if realstyle == E_FORMAT {
            ufvalue = tmpvalue;
        }
    }

    // Subtract 65535 (2^16-1) so the low 15 bits of ULONG_MAX cancel and the
    // comparison does not rest on imprecise floating point values.
    if ufvalue >= (u64::MAX - 65535) as f64 + 65536.0 {
        // Number too big.
        d.outch(0);
        return false;
    }
    let mut intpart = ufvalue as u64;

    // The conversion method supports at most nine digits past the decimal.
    if max > 9 {
        max = 9;
    }

    let max10 = roundv(pow_10(max)) as u64;
    let mut fracpart = roundv(pow_10(max) * (ufvalue - intpart as f64)) as u64;
    if fracpart >= max10 {
        intpart += 1;
        fracpart -= max10;
    }

    // Integer part, least-significant digit first.
    let mut ip = intpart;
    loop {
        iconvert[iplace] = b"0123456789"[(ip % 10) as usize];
        iplace += 1;
        ip /= 10;
        if ip == 0 || iplace >= iconvert.len() {
            break;
        }
    }
    if iplace == iconvert.len() {
        iplace -= 1;
    }

    // Fractional part, again least-significant first. In G the trailing zeros are
    // stripped by shrinking `max`.
    while fplace < max as usize {
        if style == G_FORMAT && fplace == 0 && fracpart % 10 == 0 {
            max -= 1;
            fracpart /= 10;
            if fplace < max as usize {
                continue;
            }
            break;
        }
        fconvert[fplace] = b"0123456789"[(fracpart % 10) as usize];
        fplace += 1;
        fracpart /= 10;
    }

    if realstyle == E_FORMAT {
        let mut tmpexp: i64 = if exp < 0 { -exp } else { exp };
        loop {
            econvert[eplace] = b"0123456789"[(tmpexp % 10) as usize];
            eplace += 1;
            tmpexp /= 10;
            if tmpexp == 0 || eplace >= econvert.len() {
                break;
            }
        }
        if tmpexp > 0 {
            // Exponent too large to print.
            d.outch(0);
            return false;
        }
        if eplace == 1 {
            econvert[eplace] = b'0';
            eplace += 1;
        }
    }

    // One for the decimal point when there is one, one for the sign.
    let mut padlen = min - iplace as i32 - max - i32::from(max > 0) - i32::from(signvalue != 0);
    if realstyle == E_FORMAT {
        padlen -= 2 + eplace as i32;
    }
    let mut zpadlen = max - fplace as i32;
    if zpadlen < 0 {
        zpadlen = 0;
    }
    if padlen < 0 {
        padlen = 0;
    }
    if flags & DP_F_MINUS != 0 {
        padlen = -padlen;
    }

    if flags & DP_F_ZERO != 0 && padlen > 0 {
        if signvalue != 0 {
            if !d.outch(signvalue) {
                return false;
            }
            padlen -= 1;
            signvalue = 0;
        }
        while padlen > 0 && d.eob_ok(padlen as i64) {
            if !d.outch(b'0') {
                return false;
            }
            padlen -= 1;
        }
        padlen = 0;
    }
    while padlen > 0 && d.eob_ok(padlen as i64) {
        if !d.outch(b' ') {
            return false;
        }
        padlen -= 1;
    }
    padlen = 0;
    if signvalue != 0 && !d.outch(signvalue) {
        return false;
    }
    while iplace > 0 {
        iplace -= 1;
        if !d.outch(iconvert[iplace]) {
            return false;
        }
    }
    if max > 0 || flags & DP_F_NUM != 0 {
        if !d.outch(b'.') {
            return false;
        }
        while fplace > 0 {
            fplace -= 1;
            if !d.outch(fconvert[fplace]) {
                return false;
            }
        }
    }
    while zpadlen > 0 && d.eob_ok(zpadlen as i64) {
        if !d.outch(b'0') {
            return false;
        }
        zpadlen -= 1;
    }
    if realstyle == E_FORMAT {
        let ech = if flags & DP_F_UP == 0 { b'e' } else { b'E' };
        if !d.outch(ech) {
            return false;
        }
        if !d.outch(if exp < 0 { b'-' } else { b'+' }) {
            return false;
        }
        while eplace > 0 {
            eplace -= 1;
            if !d.outch(econvert[eplace]) {
                return false;
            }
        }
    }
    if padlen < 0 {
        padlen = -padlen;
        while padlen > 0 && d.eob_ok(padlen as i64) {
            if !d.outch(b' ') {
                return false;
            }
            padlen -= 1;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum St {
    Default,
    Flags,
    Min,
    Dot,
    Max,
    Mod,
    Conv,
    Done,
}

/// `_dopr`. Returns `(ok, truncated, retlen)`.
///
/// # Safety
/// `format` must be NUL-terminated. When `grow` is `None`, `fixed` must be
/// writable for `maxlen` bytes.
unsafe fn dopr(
    fixed: *mut c_char,
    maxlen: usize,
    grow: Option<&mut Vec<u8>>,
    format: *const c_char,
    args: &mut dyn Args,
) -> (bool, bool, usize) {
    let mut d = Dopr {
        fixed,
        maxlen,
        cur: 0,
        grow,
        args,
        pos: 0,
    };
    let mut ok = true;

    // SAFETY: `format` is NUL-terminated, so this scan is valid.
    let bytes = unsafe { core::ffi::CStr::from_ptr(format) }.to_bytes();
    let peek = |i: usize| -> u8 {
        if i < bytes.len() {
            bytes[i]
        } else {
            0
        }
    };

    let mut state = St::Default;
    let mut flags = 0i32;
    let mut cflags = 0i32;
    let mut min = 0i32;
    let mut max = -1i32;

    let mut i = 0usize;
    let mut ch = peek(i);
    i += 1;

    'outer: while state != St::Done {
        if ch == 0 {
            state = St::Done;
        }
        match state {
            St::Default => {
                if ch == b'%' {
                    state = St::Flags;
                } else if !d.outch(ch) {
                    ok = false;
                    break 'outer;
                }
                ch = peek(i);
                i += 1;
            }
            St::Flags => match ch {
                b'-' => {
                    flags |= DP_F_MINUS;
                    ch = peek(i);
                    i += 1;
                }
                b'+' => {
                    flags |= DP_F_PLUS;
                    ch = peek(i);
                    i += 1;
                }
                b' ' => {
                    flags |= DP_F_SPACE;
                    ch = peek(i);
                    i += 1;
                }
                b'#' => {
                    flags |= DP_F_NUM;
                    ch = peek(i);
                    i += 1;
                }
                b'0' => {
                    flags |= DP_F_ZERO;
                    ch = peek(i);
                    i += 1;
                }
                _ => state = St::Min,
            },
            St::Min => {
                if ch.is_ascii_digit() {
                    // The authority caps the width at INT_MAX/10 and fails beyond.
                    if min < c_int::MAX / 10 {
                        min = 10 * min + (ch - b'0') as i32;
                    } else {
                        ok = false;
                        break 'outer;
                    }
                    ch = peek(i);
                    i += 1;
                } else if ch == b'*' {
                    min = d.args.gp() as i32;
                    if min < 0 {
                        flags |= DP_F_MINUS;
                        min = -min;
                    }
                    ch = peek(i);
                    i += 1;
                    state = St::Dot;
                } else {
                    state = St::Dot;
                }
            }
            St::Dot => {
                if ch == b'.' {
                    state = St::Max;
                    ch = peek(i);
                    i += 1;
                } else {
                    state = St::Mod;
                }
            }
            St::Max => {
                if ch.is_ascii_digit() {
                    if max < 0 {
                        max = 0;
                    }
                    if max < c_int::MAX / 10 {
                        max = 10 * max + (ch - b'0') as i32;
                    } else {
                        ok = false;
                        break 'outer;
                    }
                    ch = peek(i);
                    i += 1;
                } else if ch == b'*' {
                    max = d.args.gp() as i32;
                    ch = peek(i);
                    i += 1;
                    state = St::Mod;
                } else {
                    if max < 0 {
                        max = 0;
                    }
                    state = St::Mod;
                }
            }
            St::Mod => {
                match ch {
                    b'h' => {
                        if peek(i) == b'h' {
                            cflags = DP_C_CHAR;
                            i += 1;
                        } else {
                            cflags = DP_C_SHORT;
                        }
                        ch = peek(i);
                        i += 1;
                    }
                    b'l' => {
                        if peek(i) == b'l' {
                            cflags = DP_C_LLONG;
                            i += 1;
                        } else {
                            cflags = DP_C_LONG;
                        }
                        ch = peek(i);
                        i += 1;
                    }
                    b'q' | b'j' => {
                        cflags = DP_C_LLONG;
                        ch = peek(i);
                        i += 1;
                    }
                    b'L' => {
                        cflags = DP_C_LDOUBLE;
                        ch = peek(i);
                        i += 1;
                    }
                    b'z' => {
                        cflags = DP_C_SIZE;
                        ch = peek(i);
                        i += 1;
                    }
                    b't' => {
                        cflags = DP_C_PTRDIFF;
                        ch = peek(i);
                        i += 1;
                    }
                    _ => {}
                }
                state = St::Conv;
            }
            St::Conv => {
                match ch {
                    b'd' | b'i' => {
                        let value: i64 = match cflags {
                            DP_C_CHAR => (d.args.gp() as u8) as i8 as i64,
                            DP_C_SHORT => (d.args.gp() as u16) as i16 as i64,
                            DP_C_LONG | DP_C_LLONG | DP_C_SIZE | DP_C_PTRDIFF => d.args.gp() as i64,
                            _ => (d.args.gp() as u32) as i32 as i64,
                        };
                        if !fmtint(&mut d, value, 10, min, max, flags) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'X' | b'x' | b'o' | b'u' => {
                        let value: i64 = match cflags {
                            DP_C_CHAR => (d.args.gp() as u8) as i64,
                            DP_C_SHORT => (d.args.gp() as u16) as i64,
                            DP_C_LONG | DP_C_LLONG | DP_C_SIZE | DP_C_PTRDIFF => d.args.gp() as i64,
                            _ => (d.args.gp() as u32) as i64,
                        };
                        let mut f = flags | DP_F_UNSIGNED;
                        if ch == b'X' {
                            f |= DP_F_UP;
                        }
                        let base = match ch {
                            b'o' => 8,
                            b'u' => 10,
                            _ => 16,
                        };
                        if !fmtint(&mut d, value, base, min, max, f) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'f' => {
                        let v = d.args.fp();
                        if !fmtfp(&mut d, v, min, max, flags, F_FORMAT) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'E' | b'e' => {
                        let v = d.args.fp();
                        let f = if ch == b'E' { flags | DP_F_UP } else { flags };
                        if !fmtfp(&mut d, v, min, max, f, E_FORMAT) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'G' | b'g' => {
                        let v = d.args.fp();
                        let f = if ch == b'G' { flags | DP_F_UP } else { flags };
                        if !fmtfp(&mut d, v, min, max, f, G_FORMAT) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'c' => {
                        let c = d.args.gp() as u8;
                        if !d.outch(c) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b's' => {
                        let p = d.args.gp() as *const c_char;
                        // SAFETY: the conversion's type is the caller's contract,
                        // exactly as `va_arg` would be.
                        if !(unsafe { fmtstr(&mut d, p, flags, min, max) }) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'p' => {
                        let value = d.args.gp() as i64;
                        if !fmtint(&mut d, value, 16, min, max, flags | DP_F_NUM) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'n' => {
                        let p = d.args.gp() as *mut c_void;
                        if !p.is_null() {
                            // SAFETY: the conversion's type is the caller's
                            // contract, exactly as `va_arg` would be.
                            unsafe {
                                match cflags {
                                    DP_C_CHAR => *(p as *mut i8) = d.pos as i8,
                                    DP_C_SHORT => *(p as *mut i16) = d.pos as i16,
                                    DP_C_LONG | DP_C_LLONG | DP_C_SIZE | DP_C_PTRDIFF => {
                                        *(p as *mut i64) = d.pos
                                    }
                                    _ => *(p as *mut i32) = d.pos as i32,
                                }
                            }
                        }
                    }
                    b'%' => {
                        if !d.outch(ch) {
                            ok = false;
                            break 'outer;
                        }
                    }
                    b'w' => {
                        // Not supported yet: treat the next character as skipped.
                        i += 1;
                    }
                    _ => {
                        // Unknown conversion: skip it, producing nothing.
                    }
                }
                ch = peek(i);
                i += 1;
                state = St::Default;
                flags = 0;
                cflags = 0;
                min = 0;
                max = -1;
            }
            St::Done => {}
        }
    }

    let truncated = if d.grow.is_none() {
        let t = d.cur > d.maxlen.wrapping_sub(1);
        if t {
            d.cur = d.maxlen.wrapping_sub(1);
        }
        t
    } else {
        false
    };
    if !d.outch(0) {
        ok = false;
    }
    let retlen = d.cur.wrapping_sub(1);
    (ok, truncated, retlen)
}

// ---------------------------------------------------------------------------
// The entry points the C shim calls
// ---------------------------------------------------------------------------

/// The engine half of `BIO_vsnprintf`.
///
/// # Safety
/// `buf` must be writable for `n` bytes and `format` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_dopr_snprintf(
    buf: *mut c_char,
    n: usize,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if format.is_null() {
        // The authority dereferences the format and faults; total by policy
        // (docs/SECURITY_DIVERGENCE_POLICY.md).
        return -1;
    }
    if buf.is_null() && n != 0 {
        // Likewise: the authority's `doapr_outch` only asserts.
        return -1;
    }
    let mut args = VaArgs(ap);
    // SAFETY: `buf`/`n` and `format` follow the caller's contract.
    let (ok, truncated, retlen) = unsafe { dopr(buf, n, None, format, &mut args) };
    if !ok {
        return -1;
    }
    if truncated {
        return -1;
    }
    if retlen <= c_int::MAX as usize {
        retlen as c_int
    } else {
        -1
    }
}

/// The engine half of `BIO_vprintf`.
///
/// The authority formats into a 2048-byte stack buffer and switches to a heap
/// buffer only if that fills. The switch is invisible in the result — the bytes
/// written and the reported length are the same either way — so this uses the
/// growing form directly.
///
/// # Safety
/// `bio` must be a live BIO and `format` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_dopr_vprintf(
    bio: *mut Bio,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if format.is_null() {
        // As above: the authority faults, this is total by policy.
        return -1;
    }
    let mut args = VaArgs(ap);
    let mut out: Vec<u8> = Vec::new();
    // SAFETY: `format` is NUL-terminated; `out` grows as needed.
    let (ok, _truncated, retlen) =
        unsafe { dopr(ptr::null_mut(), 0, Some(&mut out), format, &mut args) };
    if !ok {
        return -1;
    }
    // SAFETY: `out` holds at least the terminator, and `bio` is live.
    unsafe { super::BIO_write(bio, out.as_ptr().cast(), retlen as c_int) }
}

// ---------------------------------------------------------------------------
// Unit tests — the engine without a `va_list`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted argument source, so the engine can be exercised directly.
    struct VecArgs {
        gp: Vec<u64>,
        fp: Vec<f64>,
        gi: usize,
        fi: usize,
    }

    impl VecArgs {
        fn new() -> Self {
            VecArgs {
                gp: Vec::new(),
                fp: Vec::new(),
                gi: 0,
                fi: 0,
            }
        }

        fn int(mut self, v: i64) -> Self {
            self.gp.push(v as u64);
            self
        }

        fn ptr(mut self, v: *const c_char) -> Self {
            self.gp.push(v as u64);
            self
        }

        fn dbl(mut self, v: f64) -> Self {
            self.fp.push(v);
            self
        }
    }

    impl Args for VecArgs {
        fn gp(&mut self) -> u64 {
            let v = self.gp[self.gi];
            self.gi += 1;
            v
        }

        fn fp(&mut self) -> f64 {
            let v = self.fp[self.fi];
            self.fi += 1;
            v
        }
    }

    /// Run the engine with a scripted argument source rather than a `va_list`.
    fn engine(n: usize, format: &str, args: &mut VecArgs) -> (i32, String) {
        let fmt = std::ffi::CString::new(format).unwrap();
        let mut buf = vec![0i8; n.max(1)];
        let (ok, truncated, retlen) = unsafe {
            dopr(
                buf.as_mut_ptr(),
                n,
                None,
                fmt.as_ptr(),
                args as &mut dyn Args,
            )
        };
        let s: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let r = if !ok || truncated || retlen > i32::MAX as usize {
            -1
        } else {
            retlen as i32
        };
        (r, String::from_utf8_lossy(&s).into_owned())
    }

    #[test]
    fn null_string_is_substituted_not_printed_as_glibc() {
        let mut a = VecArgs::new().ptr(ptr::null());
        let (r, s) = engine(64, "[%s]", &mut a);
        assert_eq!((r, s.as_str()), (8, "[<NULL>]"));
    }

    #[test]
    fn null_pointer_prints_zero_not_nil() {
        let mut a = VecArgs::new().ptr(ptr::null());
        let (r, s) = engine(64, "[%p]", &mut a);
        assert_eq!((r, s.as_str()), (3, "[0]"));
    }

    #[test]
    fn unknown_conversion_is_skipped() {
        let (r, s) = engine(64, "%q", &mut VecArgs::new());
        assert_eq!((r, s.as_str()), (0, ""));
    }

    #[test]
    fn integer_and_widths() {
        let mut a = VecArgs::new().int(42);
        assert_eq!(engine(64, "%d", &mut a).1, "42");
        let mut a = VecArgs::new().int(-1);
        assert_eq!(engine(64, "%d", &mut a).1, "-1");
        let mut a = VecArgs::new().int(255);
        assert_eq!(engine(64, "%#x", &mut a).1, "0xff");
        let mut a = VecArgs::new().int(0);
        assert_eq!(engine(64, "%#x", &mut a).1, "0");
        let mut a = VecArgs::new().int(0);
        assert_eq!(engine(64, "%#o", &mut a).1, "0");
        let mut a = VecArgs::new().int(5);
        assert_eq!(engine(64, "%05d", &mut a).1, "00005");
        let mut a = VecArgs::new().int(5);
        assert_eq!(engine(64, "%-5d|", &mut a).1, "5    |");
        let mut a = VecArgs::new().int(5);
        assert_eq!(engine(64, "%.3d", &mut a).1, "005");
        let mut a = VecArgs::new().int(0);
        // Explicit precision zero with a zero value prints nothing.
        assert_eq!(engine(64, "%.0d", &mut a).1, "");
    }

    #[test]
    fn floats_follow_the_authority_rules() {
        let mut a = VecArgs::new().dbl(10.0);
        // The strict `> 10` exponent loop leaves a mantissa of exactly ten alone.
        assert_eq!(engine(64, "%e", &mut a).1, "10.000000e+00");
        let mut a = VecArgs::new().dbl(1.5);
        assert_eq!(engine(64, "%f", &mut a).1, "1.500000");
        let mut a = VecArgs::new().dbl(1.5);
        assert_eq!(engine(64, "%.2f", &mut a).1, "1.50");
        let mut a = VecArgs::new().dbl(1.5);
        assert_eq!(engine(64, "%g", &mut a).1, "1.5");
        let mut a = VecArgs::new().dbl(f64::INFINITY);
        // Infinity collapses to zero with the `?` sign marker.
        assert_eq!(engine(64, "%f", &mut a).1, "?0.000000");
    }

    #[test]
    fn n_reports_the_position() {
        // `%n` with no length modifier writes an `int`, so the destination is an
        // `i32`, not the engine's internal `i64` position.
        let mut pos: i32 = -1;
        let mut a = VecArgs::new();
        a.gp.push((&mut pos as *mut i32) as u64);
        let (r, s) = engine(64, "ab%ncd", &mut a);
        assert_eq!((r, s.as_str(), pos), (4, "abcd", 2));
    }

    #[test]
    fn truncation_is_reported_as_failure() {
        let mut a = VecArgs::new().int(12345);
        let (r, s) = engine(4, "%d", &mut a);
        assert_eq!(r, -1);
        assert_eq!(s, "123");
    }
}
