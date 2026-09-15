//! Phase 6.7b — `crypto/property/property_parse.c`, the property grammars.
//!
//! Two grammars live here. A **definition** is what an algorithm declares —
//! `provider=default`, `fips=yes`, or a bare name meaning `=yes`. A **query** is what
//! a fetch asks — `provider=default`, `fips!=yes`, `?optional`, or `-negated`. Both
//! parse into the same shape, an `OSSL_PROPERTY_LIST`, which is why
//! `ossl_property_match_count` can walk one against the other.
//!
//! ## The list is sorted, and the sort is what makes matching a merge-walk
//!
//! `stack_to_property_list` sorts the parsed definitions by `name_idx` and copies
//! them into one allocation. `ossl_property_match_count` then walks the query and the
//! definition together, advancing whichever has the smaller index — a merge join, not
//! a nested loop. Two consequences follow, and both are load-bearing:
//!
//!   * **the sort comparison is `pd_compare`, which compares `name_idx` only.** Two
//!     definitions of the same name are therefore adjacent, which is how the
//!     duplicate check (`r->properties[i].name_idx == prev_name_idx`) sees them.
//!   * **a duplicated name is an error, not a last-one-wins.** `parse_property`
//!     refuses `a=1,a=2` with `PROP_R_PARSE_FAILED` and names the duplicated name.
//!
//! ## Negation, omission and the three-way answer
//!
//! `match_count` answers the number of clauses matched, or **-1** if a *mandatory*
//! clause is false. An optional clause that is false is simply not counted, which is
//! how `?` makes a query tolerant. The two cases that are easy to get wrong are both
//! in the tail of the walk:
//!
//!   * a **missing value** (`PROP_R_NO_VALUE` produced `TYPE_VALUE_UNDEFINED`): an
//!     inequality is satisfied by absence, an equality is not;
//!   * a query clause with **no definition to compare against**: the authority treats
//!     it as a comparison against the Boolean false, and the test is written as a
//!     four-way condition on `type`, `oper` and `v.str_val` rather than as a nested
//!     if — reproduced as written, because the arms overlap in a way that a
//!     restructured version would not preserve.
//!
//! ## What is reproduced literally, and why
//!
//! Three details look like mistakes and are not:
//!
//!   * `ossl_property_list_to_string` walks the definitions **backwards**. The array
//!     is sorted ascending, so the string it produces is in *descending* index order.
//!     Reproduced, because it is observable and because re-parsing it yields the same
//!     sorted list either way.
//!   * `parse_oct`'s loop condition is `ossl_isdigit(*++s) && *s != '9' && *s != '8'`
//!     — the `'8'`/`'9'` tests come *after* the increment, so a `'9'` at the first
//!     position is refused by the loop body and a `'9'` later ends the number and is
//!     then refused by the terminator test as `PROP_R_NOT_AN_OCTAL_DIGIT`.
//!   * `parse_hex`'s `PROP_R_NOT_AN_HEXADECIMAL_DIGIT` message has **no `HERE-->`
//!     prefix** while every sibling raise in the same function has one.
//!
//! ## `%s` on a cursor is the *entry* position, not the failure position
//!
//! `ERR_raise_data(..., "HERE-->%s", *t)` reads `*t`, and `*t` is only assigned at
//! the end of each parser, so every raise inside one uses the position the parser was
//! *called* with. The two exceptions are the trailing-character raises in
//! `ossl_parse_property` and `ossl_parse_query`, which pass the local cursor `s`
//! because by then the parse has consumed the whole input and `*t` would be the same
//! position anyway — but they pass `s` and the code says `s`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::property::list::{
    num_properties, properties_ptr, OsslPropertyDefinition, OsslPropertyIdx, OsslPropertyList,
    PropertyValue, OSSL_PROPERTY_OPER_EQ, OSSL_PROPERTY_OPER_NE, OSSL_PROPERTY_OVERRIDE,
    OSSL_PROPERTY_TYPE_NUMBER, OSSL_PROPERTY_TYPE_STRING, OSSL_PROPERTY_TYPE_VALUE_UNDEFINED,
};
use crate::property::strings::{ossl_property_name, ossl_property_name_str, ossl_property_value};
use crate::runtime::ctype::{
    ossl_isalnum, ossl_isalpha, ossl_isdigit, ossl_isprint, ossl_isspace, ossl_isxdigit,
    ossl_tolower,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::stack::{
    OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strncasecmp;

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property_parse.c".as_ptr();

/// `pd_free`'s `OPENSSL_free(pd)`.
const LINE_FREE_PD: c_int = 302;
/// `stack_to_property_list`'s `OPENSSL_malloc`.
const LINE_MALLOC_LIST: c_int = 320;
/// `stack_to_property_list`'s `OPENSSL_free(r)` on a duplicated name.
const LINE_FREE_LIST_DUP: c_int = 332;
/// `ossl_parse_property`'s `OPENSSL_malloc(sizeof(*prop))`.
const LINE_MALLOC_PROP: c_int = 361;
/// `ossl_parse_property`'s `OPENSSL_free(prop)`.
const LINE_FREE_PROP: c_int = 399;
/// `ossl_parse_query`'s `OPENSSL_malloc(sizeof(*prop))`.
const LINE_MALLOC_QPROP: c_int = 418;
/// `ossl_parse_query`'s `OPENSSL_free(prop)`.
const LINE_FREE_QPROP: c_int = 462;
/// `ossl_property_free`'s `OPENSSL_free(p)`.
const LINE_FREE_LIST: c_int = 531;
/// `ossl_property_merge`'s `OPENSSL_malloc`.
const LINE_MALLOC_MERGED: c_int = 548;

/// `OSSL_PROPERTY_TRUE` is 1 and `OSSL_PROPERTY_FALSE` is 2 — `property_local.h`.
///
/// They are the *indices* the string table gives `"yes"` and `"no"`, which is why
/// `ossl_property_parse_init` asserts them at start up.
pub(crate) const OSSL_PROPERTY_TRUE: c_int = 1;
pub(crate) const OSSL_PROPERTY_FALSE: c_int = 2;

/// A read position in a NUL-terminated string: what `const char **t` is in C.
///
/// `*t` in the authority is the *shared* cursor, so a parser that fails leaves it
/// where the caller left it and a parser that succeeds advances it past the token.
/// A `Copy` struct carried by value through the parser reproduces that: the caller's
/// variable is only assigned where the C assigns `*t`.
#[derive(Clone, Copy)]
struct Cur {
    p: *const c_char,
}

impl Cur {
    /// The byte at `i` from the cursor, sign-extended as C promotes a `char`.
    ///
    /// # Safety
    /// The position must be inside the string, or at its terminating NUL.
    unsafe fn at(self, i: isize) -> c_int {
        // SAFETY: the caller's contract.
        c_int::from(unsafe { *self.p.offset(i) })
    }

    /// The byte at the cursor.
    ///
    /// # Safety
    /// As [`Cur::at`].
    unsafe fn ch(self) -> c_int {
        // SAFETY: forwarded to `at`, whose contract is the caller's.
        unsafe { self.at(0) }
    }

    /// The cursor `i` bytes further on.
    ///
    /// # Safety
    /// As [`Cur::at`]; the result may be past the terminator if `i` is.
    unsafe fn advance(self, i: isize) -> Cur {
        Cur {
            // SAFETY: the caller guarantees the position is inside the string
            // or at its terminator.
            p: unsafe { self.p.offset(i) },
        }
    }
}

/// `static const char *skip_space(const char *s)` — over the cursor's position.
///
/// # Safety
/// `c` must point into a NUL-terminated string.
unsafe fn skip_space(mut c: Cur) -> Cur {
    // SAFETY: the byte read is the cursor's own, and the walk stops at the
    // terminator because `ossl_isspace('\0')` is false.
    unsafe {
        while ossl_isspace(c.ch()) {
            c = c.advance(1);
        }
    }
    c
}

/// `static int match_ch(const char *t[], char m)` — consume `m` and following space.
///
/// # Safety
/// `c` must point into a NUL-terminated string.
unsafe fn match_ch(c: &mut Cur, m: u8) -> bool {
    // SAFETY: the cursor's byte is readable.
    if unsafe { (*c).ch() } == c_int::from(m) {
        // SAFETY: the cursor is not at the terminator, so advancing and skipping is
        // in range.
        *c = unsafe { skip_space((*c).advance(1)) };
        true
    } else {
        false
    }
}

/// `static int match(const char *t[], const char m[], size_t m_len)`
///
/// The comparison is `OPENSSL_strncasecmp`, so the literal is matched
/// case-insensitively — which is why `!=` is matched with a two-byte literal and a
/// `!` in a query does not need to be uppercase.
///
/// # Safety
/// `c` must point into a NUL-terminated string and `lit` must be `NUL`-free.
unsafe fn matches(c: &mut Cur, lit: &core::ffi::CStr) -> bool {
    let m = lit.as_ptr();
    let len = lit.to_bytes().len();
    // SAFETY: `c` is inside its string and `m` has at least `len` readable bytes, so
    // `strncasecmp` stops at either NUL or `len` bytes.
    if unsafe { OPENSSL_strncasecmp(c.p, m, len) } == 0 {
        // SAFETY: the match consumed `len` bytes of a string at least that long.
        *c = unsafe { skip_space((*c).advance(len as isize)) };
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// The four raise shapes, each with its message built as the authority's
// `ERR_raise_data` builds it
// ---------------------------------------------------------------------------

/// `ERR_raise_data(lib, reason, "HERE-->%s", p)` — the shape most of this file uses.
///
/// # Safety
/// `p` must be NUL-terminated and `site` a compile-time constant.
unsafe fn raise_here(site: &err_sites::ErrSite, p: *const c_char) {
    let mut m = b"HERE-->".to_vec();
    // SAFETY: `p` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_bytes(p) });
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call; the site is `'static`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `ERR_raise_data(lib, reason, "HERE-->%c%s", delim, p)` — `parse_string`'s.
///
/// # Safety
/// As [`raise_here`].
unsafe fn raise_here_c(site: &err_sites::ErrSite, delim: u8, p: *const c_char) {
    let mut m = b"HERE-->".to_vec();
    m.push(delim);
    // SAFETY: `p` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_bytes(p) });
    m.push(0);
    // SAFETY: as `raise_here`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `ERR_raise_data(lib, reason, "Property %s overflows", p)` — the three overflow
/// refusals, in all three bases.
///
/// # Safety
/// As [`raise_here`].
unsafe fn raise_overflows(site: &err_sites::ErrSite, p: *const c_char) {
    let mut m = b"Property ".to_vec();
    // SAFETY: `p` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_bytes(p) });
    m.extend_from_slice(b" overflows");
    m.push(0);
    // SAFETY: as `raise_here`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `ERR_raise_data(lib, reason, "%s", p)` — `parse_hex`'s, which is the one raise in
/// this file with no `HERE-->` prefix.
///
/// # Safety
/// As [`raise_here`].
unsafe fn raise_bare(site: &err_sites::ErrSite, p: *const c_char) {
    // SAFETY: `p` is NUL-terminated per the contract.
    let mut m = unsafe { c_bytes(p) }.to_vec();
    m.push(0);
    // SAFETY: as `raise_here`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `ERR_raise_data(lib, reason, "Duplicated name \`%s'", name)`.
///
/// # Safety
/// `name` must be NULL or NUL-terminated.
unsafe fn raise_duplicated(site: &err_sites::ErrSite, name: *const c_char) {
    let mut m = b"Duplicated name `".to_vec();
    if !name.is_null() {
        // SAFETY: `name` is NUL-terminated per the contract.
        m.extend_from_slice(unsafe { c_bytes(name) });
    }
    m.push(b'\'');
    m.push(0);
    // SAFETY: as `raise_here`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// `ERR_raise_data(lib, reason, "Unknown name HERE-->%s", p)`.
///
/// # Safety
/// As [`raise_here`].
unsafe fn raise_unknown_name(site: &err_sites::ErrSite, p: *const c_char) {
    let mut m = b"Unknown name HERE-->".to_vec();
    // SAFETY: `p` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_bytes(p) });
    m.push(0);
    // SAFETY: as `raise_here`.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// The bytes of a NUL-terminated C string, without the terminator.
///
/// # Safety
/// `p` must be NUL-terminated.
unsafe fn c_bytes<'a>(p: *const c_char) -> &'a [u8] {
    let mut n = 0usize;
    // SAFETY: the caller guarantees a terminator, so the walk stops.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p.cast::<u8>(), n)
    }
}

// ---------------------------------------------------------------------------
// The leaf parsers
// ---------------------------------------------------------------------------

/// `static int parse_name(OSSL_LIB_CTX *ctx, const char *t[], int create,
/// OSSL_PROPERTY_IDX *idx)`
///
/// An identifier is `alpha (alnum | '_')*`, optionally dotted:
/// `[alpha (alnum|'_')* '.']* alpha (alnum|'_')*`. A `.` makes it a **user** name,
/// and `user_name && create` is what decides whether the name is interned — so a
/// dotted name in a query is *not* created, while a plain one is. That asymmetry is
/// the authority's and is why `ossl_parse_query` can refuse an unknown name later
/// rather than inventing a number for it.
///
/// The 100-byte buffer caps a name; overflowing it sets `err` and the name is
/// refused with `PROP_R_NAME_TOO_LONG` **after** the whole name is scanned, so a long
/// tail is still consumed before the refusal.
///
/// # Safety
/// `c` must point into a NUL-terminated string and `ctx` must be NULL or live.
unsafe fn parse_name(
    ctx: *mut c_void,
    c: &mut Cur,
    create: c_int,
    idx: *mut OsslPropertyIdx,
) -> bool {
    let entry = *c;
    let mut name = [0u8; 100];
    let mut err = false;
    let mut i = 0usize;
    let mut user_name = false;

    loop {
        // SAFETY: the cursor is inside the string.
        if !ossl_isalpha(unsafe { (*c).ch() }) {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_here(&err_sites::PROPERTY_PARSE_67, entry.p) };
            return false;
        }
        loop {
            // SAFETY: the cursor is inside the string.
            if i < name.len() - 1 {
                // SAFETY: the cursor is inside the string.
                name[i] = unsafe { ossl_tolower(c.ch()) } as u8;
                i += 1;
            } else {
                err = true;
            }
            // The do-while: advance, then continue while the byte is `_` or alnum.
            // SAFETY: advancing to the terminator is the loop's own exit.
            unsafe {
                *c = (*c).advance(1);
                let b = (*c).ch();
                if b != c_int::from(b'_') && !ossl_isalnum(b) {
                    break;
                }
            }
        }
        // SAFETY: the cursor is at a byte of the string.
        if unsafe { (*c).ch() } != c_int::from(b'.') {
            break;
        }
        user_name = true;
        if i < name.len() - 1 {
            name[i] = b'.';
            i += 1;
        } else {
            err = true;
        }
        // SAFETY: the byte read is a `.` inside the string.
        *c = unsafe { (*c).advance(1) };
    }
    // The authority writes `name[i] = '\0'` into a 100-byte buffer, so `i` is at
    // most 99 and the terminator always fits.
    if err {
        // SAFETY: `entry.p` is the caller's string.
        unsafe { raise_here(&err_sites::PROPERTY_PARSE_88, entry.p) };
        return false;
    }
    // SAFETY: the cursor is at a byte of the string.
    *c = unsafe { skip_space(*c) };
    let create_now = if user_name { create } else { 0 };
    // SAFETY: `name` is NUL-terminated at `i`, which is at most 99, and `idx` is the
    // caller's live output for this call.
    unsafe { *idx = ossl_property_name(ctx, name.as_ptr().cast::<c_char>(), create_now) };
    true
}

/// `static int parse_number(const char *t[], OSSL_PROPERTY_DEFINITION *res)`
///
/// # Safety
/// `c` must point into a NUL-terminated string and `res` must be live.
unsafe fn parse_number(c: &mut Cur, res: *mut OsslPropertyDefinition) -> bool {
    let entry = *c;
    let mut v: i64 = 0;
    loop {
        // SAFETY: the cursor is inside the string.
        let b = unsafe { (*c).ch() };
        if !ossl_isdigit(b) {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_here(&err_sites::PROPERTY_PARSE_103, entry.p) };
            return false;
        }
        if v > (i64::MAX - (b - c_int::from(b'0')) as i64) / 10 {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_overflows(&err_sites::PROPERTY_PARSE_109, entry.p) };
            return false;
        }
        v = v * 10 + (b - c_int::from(b'0')) as i64;
        // SAFETY: the byte read is inside the string.
        *c = unsafe { (*c).advance(1) };
        // SAFETY: the cursor is at a byte of the string.
        if !ossl_isdigit(unsafe { (*c).ch() }) {
            break;
        }
    }
    // SAFETY: the cursor is at a byte of the string.
    let b = unsafe { (*c).ch() };
    if !ossl_isspace(b) && b != 0 && b != c_int::from(b',') {
        // SAFETY: `entry.p` is the caller's string.
        unsafe { raise_here(&err_sites::PROPERTY_PARSE_116, entry.p) };
        return false;
    }
    // SAFETY: the cursor is at a byte of the string.
    *c = unsafe { skip_space(*c) };
    // SAFETY: `res` is live per the contract.
    unsafe {
        (*res).type_ = OSSL_PROPERTY_TYPE_NUMBER;
        (*res).v.int_val = v;
    }
    true
}

/// `static int parse_hex(const char *t[], OSSL_PROPERTY_DEFINITION *res)`
///
/// # Safety
/// As [`parse_number`].
unsafe fn parse_hex(c: &mut Cur, res: *mut OsslPropertyDefinition) -> bool {
    let entry = *c;
    let mut v: i64 = 0;
    loop {
        // SAFETY: the cursor is inside the string.
        let b = unsafe { (*c).ch() };
        let sval: i32 = if ossl_isdigit(b) {
            b - c_int::from(b'0')
        } else if ossl_isxdigit(b) {
            ossl_tolower(b) - c_int::from(b'a') + 10
        } else {
            // SAFETY: `entry.p` is the caller's string. Note the message carries no
            // `HERE-->` prefix, unlike every sibling in this function.
            unsafe { raise_bare(&err_sites::PROPERTY_PARSE_138, entry.p) };
            return false;
        };
        if v > (i64::MAX - sval as i64) / 16 {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_overflows(&err_sites::PROPERTY_PARSE_144, entry.p) };
            return false;
        }
        v <<= 4;
        v += sval as i64;
        // SAFETY: the byte read is inside the string.
        *c = unsafe { (*c).advance(1) };
        // SAFETY: the cursor is at a byte of the string.
        if !ossl_isxdigit(unsafe { (*c).ch() }) {
            break;
        }
    }
    // SAFETY: the cursor is at a byte of the string.
    let b = unsafe { (*c).ch() };
    if !ossl_isspace(b) && b != 0 && b != c_int::from(b',') {
        // SAFETY: `entry.p` is the caller's string.
        unsafe { raise_here(&err_sites::PROPERTY_PARSE_153, entry.p) };
        return false;
    }
    // SAFETY: the cursor is at a byte of the string.
    *c = unsafe { skip_space(*c) };
    // SAFETY: `res` is live.
    unsafe {
        (*res).type_ = OSSL_PROPERTY_TYPE_NUMBER;
        (*res).v.int_val = v;
    }
    true
}

/// `static int parse_oct(const char *t[], OSSL_PROPERTY_DEFINITION *res)`
///
/// The loop's `'8'`/`'9'` tests come **after** the increment, which is why the first
/// digit's refusal comes from the body and a later one's from the terminator test;
/// both raise `PROP_R_NOT_AN_OCTAL_DIGIT`, from different lines.
///
/// # Safety
/// As [`parse_number`].
unsafe fn parse_oct(c: &mut Cur, res: *mut OsslPropertyDefinition) -> bool {
    let entry = *c;
    let mut v: i64 = 0;
    loop {
        // SAFETY: the cursor is inside the string.
        let b = unsafe { (*c).ch() };
        if b == c_int::from(b'9') || b == c_int::from(b'8') || !ossl_isdigit(b) {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_here(&err_sites::PROPERTY_PARSE_170, entry.p) };
            return false;
        }
        if v > (i64::MAX - (b - c_int::from(b'0')) as i64) / 8 {
            // SAFETY: `entry.p` is the caller's string.
            unsafe { raise_overflows(&err_sites::PROPERTY_PARSE_175, entry.p) };
            return false;
        }
        v = (v << 3) + (b - c_int::from(b'0')) as i64;
        // SAFETY: the byte read is inside the string.
        *c = unsafe { (*c).advance(1) };
        // SAFETY: the cursor is at a byte of the string.
        let n = unsafe { (*c).ch() };
        if !(ossl_isdigit(n) && n != c_int::from(b'9') && n != c_int::from(b'8')) {
            break;
        }
    }
    // SAFETY: the cursor is at a byte of the string.
    let b = unsafe { (*c).ch() };
    if !ossl_isspace(b) && b != 0 && b != c_int::from(b',') {
        // SAFETY: `entry.p` is the caller's string.
        unsafe { raise_here(&err_sites::PROPERTY_PARSE_183, entry.p) };
        return false;
    }
    // SAFETY: the cursor is at a byte of the string.
    *c = unsafe { skip_space(*c) };
    // SAFETY: `res` is live.
    unsafe {
        (*res).type_ = OSSL_PROPERTY_TYPE_NUMBER;
        (*res).v.int_val = v;
    }
    true
}

/// `static int parse_string(OSSL_LIB_CTX *ctx, const char *t[], char delim,
/// OSSL_PROPERTY_DEFINITION *res, const int create)`
///
/// A quoted value runs to its closing delimiter **or to the end of the input**, and
/// the two are different refusals: an unterminated string raises
/// `PROP_R_NO_MATCHING_STRING_DELIMITER` and returns 0 *without* setting `type`,
/// while an over-long one sets `type` and returns `!err`. The cursor is advanced in
/// both cases — before the length check, which is why the message's `%s` is the
/// entry position rather than the failure position.
///
/// # Safety
/// As [`parse_number`], plus `ctx` NULL or live.
unsafe fn parse_string(
    ctx: *mut c_void,
    c: &mut Cur,
    delim: u8,
    res: *mut OsslPropertyDefinition,
    create: c_int,
) -> bool {
    let entry = *c;
    let mut v = [0u8; 1000];
    let mut i = 0usize;
    let mut err = false;

    // SAFETY: every read is a byte of the caller's string, and the walk stops at the
    // terminator or the delimiter.
    unsafe {
        while (*c).ch() != 0 && (*c).ch() != c_int::from(delim) {
            if i < v.len() - 1 {
                v[i] = (*c).ch() as u8;
                i += 1;
            } else {
                err = true;
            }
            *c = (*c).advance(1);
        }
        if (*c).ch() == 0 {
            raise_here_c(&err_sites::PROPERTY_PARSE_209, delim, entry.p);
            return false;
        }
        if err {
            raise_here(&err_sites::PROPERTY_PARSE_215, entry.p);
        } else {
            (*res).v.str_val = ossl_property_value(ctx, v.as_ptr().cast::<c_char>(), create);
        }
        *c = skip_space((*c).advance(1));
        (*res).type_ = OSSL_PROPERTY_TYPE_STRING;
    }
    !err
}

/// `static int parse_unquoted(OSSL_LIB_CTX *ctx, const char *t[],
/// OSSL_PROPERTY_DEFINITION *res, const int create)`
///
/// An unquoted value is lower-cased as it is collected, so `FIPS=YES` and `fips=yes`
/// intern the same value. Unlike `parse_string`, a value that fails to intern
/// (`ossl_property_value` answering 0) sets `err`, so a `create == 0` query that
/// names an unknown value is refused rather than silently mismatching.
///
/// # Safety
/// As [`parse_string`].
unsafe fn parse_unquoted(
    ctx: *mut c_void,
    c: &mut Cur,
    res: *mut OsslPropertyDefinition,
    create: c_int,
) -> bool {
    let entry = *c;
    let mut v = [0u8; 1000];
    let mut i = 0usize;
    let mut err = false;

    // SAFETY: the cursor is at a byte of the string.
    let first = unsafe { (*c).ch() };
    if first == 0 || first == c_int::from(b',') {
        return false;
    }
    // SAFETY: every read is a byte of the caller's string.
    unsafe {
        while ossl_isprint((*c).ch()) && !ossl_isspace((*c).ch()) && (*c).ch() != c_int::from(b',')
        {
            if i < v.len() - 1 {
                v[i] = ossl_tolower((*c).ch()) as u8;
                i += 1;
            } else {
                err = true;
            }
            *c = (*c).advance(1);
        }
        let b = (*c).ch();
        if !ossl_isspace(b) && b != 0 && b != c_int::from(b',') {
            raise_here(&err_sites::PROPERTY_PARSE_242, c.p);
            return false;
        }
        v[i] = 0;
        if err {
            raise_here(&err_sites::PROPERTY_PARSE_248, entry.p);
        } else {
            // The intern. A `create == 0` query naming a value the table does not
            // hold answers 0, which is "no such value" rather than a valid index, and
            // the authority turns that into the same failure an over-long value gets.
            (*res).v.str_val = ossl_property_value(ctx, v.as_ptr().cast::<c_char>(), create);
            if (*res).v.str_val == 0 {
                err = true;
            }
        }
        *c = skip_space(*c);
        (*res).type_ = OSSL_PROPERTY_TYPE_STRING;
    }
    !err
}

/// `static int parse_value(OSSL_LIB_CTX *ctx, const char *t[],
/// OSSL_PROPERTY_DEFINITION *res, int create)`
///
/// The dispatch on the first character. Note the two arms that do **not** use the
/// local cursor: a bare decimal and a bare identifier are parsed with `t` itself, so
/// their failure leaves the caller's cursor where it was and any message they raise
/// uses the same position as this function's own.
///
/// # Safety
/// As [`parse_string`].
unsafe fn parse_value(
    ctx: *mut c_void,
    c: &mut Cur,
    res: *mut OsslPropertyDefinition,
    create: c_int,
) -> bool {
    // SAFETY: one block, because the justification is identical for every operation
    // in it — each reads a byte of the caller's NUL-terminated string or writes the
    // parser's own live output, and each callee's contract is this function's.
    unsafe {
        let mut s = *c;
        let mut r = false;
        let first = s.ch();
        if first == c_int::from(b'"') || first == c_int::from(b'\'') {
            s = s.advance(1);
            r = parse_string(ctx, &mut s, first as u8, res, create);
        } else if first == c_int::from(b'+') {
            s = s.advance(1);
            r = parse_number(&mut s, res);
        } else if first == c_int::from(b'-') {
            s = s.advance(1);
            r = parse_number(&mut s, res);
            (*res).v.int_val = -(*res).v.int_val;
        } else if first == c_int::from(b'0') && s.at(1) == c_int::from(b'x') {
            s = s.advance(2);
            r = parse_hex(&mut s, res);
        } else if first == c_int::from(b'0') && ossl_isdigit(s.at(1)) {
            s = s.advance(1);
            r = parse_oct(&mut s, res);
        } else if ossl_isdigit(first) {
            return parse_number(c, res);
        } else if ossl_isalpha(first) {
            return parse_unquoted(ctx, c, res, create);
        }
        if r {
            *c = s;
        }
        r
    }
}

// ---------------------------------------------------------------------------
// The list assembly
// ---------------------------------------------------------------------------

/// `static int pd_compare(const OSSL_PROPERTY_DEFINITION *const *p1,
/// const OSSL_PROPERTY_DEFINITION *const *p2)`
///
/// The stack stores *pointers*, so the comparator receives the addresses of two
/// slots and dereferences each once. It compares `name_idx` only.
///
/// # Safety
/// Both arguments must be addresses of live element pointers.
unsafe extern "C" fn pd_compare(p1: *const c_void, p2: *const c_void) -> c_int {
    // SAFETY: the stack passes the addresses of its own slots, each holding a live
    // definition.
    unsafe {
        let d1 = *p1.cast::<*const OsslPropertyDefinition>();
        let d2 = *p2.cast::<*const OsslPropertyDefinition>();
        let a = (*d1).name_idx;
        let b = (*d2).name_idx;
        if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }
    }
}

/// The stack's element destructor: `pd_free`, which is `OPENSSL_free(pd)`.
///
/// # Safety
/// `pd` must be an element of a stack built with this module's comparator.
unsafe extern "C" fn pd_free(pd: *mut c_void) {
    // SAFETY: the element came from `CRYPTO_malloc`.
    unsafe { CRYPTO_free(pd, FILE, LINE_FREE_PD) };
}

/// `static OSSL_PROPERTY_LIST *stack_to_property_list(OSSL_LIB_CTX *ctx,
/// STACK_OF(OSSL_PROPERTY_DEFINITION) *sk)`
///
/// Sorts the stack, copies the definitions into one allocation, and refuses a
/// duplicated name. The allocation is `sizeof(*r) + (n - 1) * sizeof(properties[0])`
/// for `n > 0`, and `sizeof(*r)` for `n <= 0` — which is the header plus the one
/// element the flexible member already accounts for, so an empty list allocates a
/// header with room for one definition it never uses. Reproduced, because it is what
/// `ossl_property_merge` also does and because the two must agree about an
/// allocation they hand to the same releaser.
///
/// # Safety
/// `ctx` must be NULL or live and `sk` a live stack of definitions.
unsafe fn stack_to_property_list(ctx: *mut c_void, sk: *mut OpenSslStack) -> *mut OsslPropertyList {
    // SAFETY: `sk` is live.
    let n = unsafe { OPENSSL_sk_num(sk) };
    let defn_size = core::mem::size_of::<OsslPropertyDefinition>();
    let tail = if n <= 0 {
        0
    } else {
        (n - 1) as usize * defn_size
    };
    let r = CRYPTO_malloc(
        core::mem::size_of::<OsslPropertyList>() + tail,
        FILE,
        LINE_MALLOC_LIST,
    )
    .cast::<OsslPropertyList>();
    if r.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `sk` is a stack built with `pd_compare`, the authority's own sort.
    unsafe { OPENSSL_sk_sort(sk) };
    // SAFETY: `r` is a fresh allocation of the header plus `n - 1` definitions, so
    // the tail has exactly `n` slots, and `sk`'s elements are live definitions.
    unsafe {
        (*r).has_optional = 0;
        let mut prev_name_idx: OsslPropertyIdx = 0;
        for i in 0..n {
            let src = OPENSSL_sk_value(sk, i).cast::<OsslPropertyDefinition>();
            let dst = properties_ptr(r).add(i as usize).cast_mut();
            *dst = *src;
            (*r).has_optional |= (*dst).optional;
            if i > 0 && (*dst).name_idx == prev_name_idx {
                CRYPTO_free(r.cast::<c_void>(), FILE, LINE_FREE_LIST_DUP);
                let name = ossl_property_name_str(ctx, prev_name_idx);
                raise_duplicated(&err_sites::PROPERTY_PARSE_333, name);
                return ptr::null_mut();
            }
            prev_name_idx = (*dst).name_idx;
        }
        (*r).num_properties = n;
    }
    r
}

/// `OSSL_PROPERTY_LIST *ossl_parse_property(OSSL_LIB_CTX *ctx, const char *defn)`
///
/// # Safety
/// `ctx` must be NULL or live and `defn` NULL or NUL-terminated.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_parse_property(
    ctx: *mut c_void,
    defn: *const c_char,
) -> *mut OsslPropertyList {
    if defn.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pd_compare` is this module's comparator and the stack starts empty.
    let sk = OPENSSL_sk_new(Some(pd_compare));
    if sk.is_null() {
        return ptr::null_mut();
    }
    let mut prop: *mut OsslPropertyDefinition = ptr::null_mut();
    let mut res: *mut OsslPropertyList = ptr::null_mut();
    let mut s = Cur { p: defn };

    // SAFETY: `s` is the caller's NUL-terminated string.
    unsafe {
        s = skip_space(s);
        let mut done = s.ch() == 0;
        while !done {
            let start = s;
            prop = CRYPTO_malloc(
                core::mem::size_of::<OsslPropertyDefinition>(),
                FILE,
                LINE_MALLOC_PROP,
            )
            .cast::<OsslPropertyDefinition>();
            if prop.is_null() {
                break;
            }
            (*prop).v = PropertyValue { int_val: 0 };
            (*prop).optional = 0;
            if !parse_name(ctx, &mut s, 1, ptr::addr_of_mut!((*prop).name_idx)) {
                break;
            }
            (*prop).oper = OSSL_PROPERTY_OPER_EQ;
            if (*prop).name_idx == 0 {
                raise_unknown_name(&err_sites::PROPERTY_PARSE_370, start.p);
                break;
            }
            if match_ch(&mut s, b'=') {
                if !parse_value(ctx, &mut s, prop, 1) {
                    raise_here(&err_sites::PROPERTY_PARSE_376, start.p);
                    break;
                }
            } else {
                // A name alone means a true Boolean.
                (*prop).type_ = OSSL_PROPERTY_TYPE_STRING;
                (*prop).v.str_val = OSSL_PROPERTY_TRUE;
            }
            if OPENSSL_sk_push(sk, prop.cast::<c_void>()) <= 0 {
                break;
            }
            prop = ptr::null_mut();
            done = !match_ch(&mut s, b',');
        }
        if s.ch() != 0 {
            raise_here(&err_sites::PROPERTY_PARSE_392, s.p);
        } else {
            res = stack_to_property_list(ctx, sk);
        }
        // The `err:` block, which runs in both the loop-exit and the success case and
        // is a no-op for the NULL `prop` a successful parse leaves.
        if !prop.is_null() {
            CRYPTO_free(prop.cast::<c_void>(), FILE, LINE_FREE_PROP);
        }
        OPENSSL_sk_pop_free(sk, Some(pd_free));
    }
    res
}

/// `OSSL_PROPERTY_LIST *ossl_parse_query(OSSL_LIB_CTX *ctx, const char *s,
/// int create_values)`
///
/// # Safety
/// As [`ossl_parse_property`].
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_parse_query(
    ctx: *mut c_void,
    s: *const c_char,
    create_values: c_int,
) -> *mut OsslPropertyList {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: as `ossl_parse_property`.
    let sk = OPENSSL_sk_new(Some(pd_compare));
    if sk.is_null() {
        return ptr::null_mut();
    }
    let mut prop: *mut OsslPropertyDefinition = ptr::null_mut();
    let mut res: *mut OsslPropertyList = ptr::null_mut();
    let mut c = Cur { p: s };

    // SAFETY: `c` is the caller's NUL-terminated string.
    unsafe {
        c = skip_space(c);
        let mut done = c.ch() == 0;
        while !done {
            prop = CRYPTO_malloc(
                core::mem::size_of::<OsslPropertyDefinition>(),
                FILE,
                LINE_MALLOC_QPROP,
            )
            .cast::<OsslPropertyDefinition>();
            if prop.is_null() {
                break;
            }
            (*prop).v = PropertyValue { int_val: 0 };

            if match_ch(&mut c, b'-') {
                (*prop).oper = OSSL_PROPERTY_OVERRIDE;
                (*prop).optional = 0;
                if !parse_name(ctx, &mut c, 1, ptr::addr_of_mut!((*prop).name_idx)) {
                    break;
                }
                // `goto skip_value` — the push is the only thing after it.
                if OPENSSL_sk_push(sk, prop.cast::<c_void>()) <= 0 {
                    break;
                }
                prop = ptr::null_mut();
                done = !match_ch(&mut c, b',');
                continue;
            }
            (*prop).optional = u32::from(match_ch(&mut c, b'?'));
            if !parse_name(ctx, &mut c, 1, ptr::addr_of_mut!((*prop).name_idx)) {
                break;
            }
            let mut skip_value = false;
            if match_ch(&mut c, b'=') {
                (*prop).oper = OSSL_PROPERTY_OPER_EQ;
            } else if matches(&mut c, c"!=") {
                (*prop).oper = OSSL_PROPERTY_OPER_NE;
            } else {
                // A name alone is a Boolean comparison for true.
                (*prop).oper = OSSL_PROPERTY_OPER_EQ;
                (*prop).type_ = OSSL_PROPERTY_TYPE_STRING;
                (*prop).v.str_val = OSSL_PROPERTY_TRUE;
                skip_value = true;
            }
            if !skip_value && !parse_value(ctx, &mut c, prop, create_values) {
                // The authority does not fail here: it records that the value could
                // not be produced and lets the comparison answer against absence.
                (*prop).type_ = OSSL_PROPERTY_TYPE_VALUE_UNDEFINED;
            }
            if OPENSSL_sk_push(sk, prop.cast::<c_void>()) <= 0 {
                break;
            }
            prop = ptr::null_mut();
            done = !match_ch(&mut c, b',');
        }
        if c.ch() != 0 {
            raise_here(&err_sites::PROPERTY_PARSE_455, c.p);
        } else {
            res = stack_to_property_list(ctx, sk);
        }
        if !prop.is_null() {
            CRYPTO_free(prop.cast::<c_void>(), FILE, LINE_FREE_QPROP);
        }
        OPENSSL_sk_pop_free(sk, Some(pd_free));
    }
    res
}

/// `int ossl_property_parse_init(OSSL_LIB_CTX *ctx)`
///
/// The six predefined names, then the two Boolean values, in that order and with
/// `create` set. Answers 1, or 0 at the first failure — which is what the authority
/// answers too, because its `err:` label is a bare `return 0`.
///
/// This is the last step of `context_init`, and it is a **start-up assertion** rather
/// than an optimisation: `OSSL_PROPERTY_TRUE` is 1 and `OSSL_PROPERTY_FALSE` is 2, and
/// the value table's counter is separate from the name table's, so the six names take
/// 1..6 in their own space while `"yes"` and `"no"` are the first two *values*. A
/// table numbered in another order fails the authority's own check here.
///
/// The `||` short-circuits, and that is reproduced by two `if`s rather than by one
/// tuple comparison: when `"yes"` is not 1, `"no"` is never interned at all, and that
/// state is part of what the authority's failure path reaches.
///
/// # Safety
/// `ctx` must be NULL or a live context whose slot 3 has been constructed.
pub(crate) unsafe fn ossl_property_parse_init(ctx: *mut c_void) -> c_int {
    /// The authority's `predefined_names`, verbatim and in its order.
    static PREDEFINED_NAMES: [&core::ffi::CStr; 6] = [
        c"provider",  // Name of provider (default, legacy, fips)
        c"version",   // Version number of this provider
        c"fips",      // FIPS validated or FIPS supporting algorithm
        c"output",    // Output type for encoders
        c"input",     // Input type for decoders
        c"structure", // Structure name for encoders and decoders
    ];

    for n in PREDEFINED_NAMES {
        // SAFETY: `ctx` is live per the contract and `n` is a `'static` string.
        if unsafe { ossl_property_name(ctx, n.as_ptr(), 1) } == 0 {
            return 0;
        }
    }

    // SAFETY: as above.
    unsafe {
        if ossl_property_value(ctx, c"yes".as_ptr(), 1) != OSSL_PROPERTY_TRUE
            || ossl_property_value(ctx, c"no".as_ptr(), 1) != OSSL_PROPERTY_FALSE
        {
            return 0;
        }
    }

    1
}

/// `void ossl_property_free(OSSL_PROPERTY_LIST *p)` — one `OPENSSL_free`.
///
/// # Safety
/// `p` must be NULL or a list this crate allocated and has not released.
pub(crate) unsafe fn ossl_property_free(p: *mut OsslPropertyList) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` came from this crate's allocator; the block is the whole list.
    unsafe { CRYPTO_free(p.cast::<c_void>(), FILE, LINE_FREE_LIST) };
}

/// `int ossl_property_match_count(const OSSL_PROPERTY_LIST *query,
/// const OSSL_PROPERTY_LIST *defn)`
///
/// The merge join. Returns the number of clauses matched, or -1 when a mandatory
/// clause is false.
///
/// The equality test between a query clause and a definition is
/// `q[i].type == d[j].type && memcmp(&q[i].v, &d[j].v, sizeof(q[i].v)) == 0` — a
/// **byte** comparison of the eight-byte union, not a field comparison. That is why
/// both parsers zero the union before filling it: the four bytes above a `str_val`
/// take part in equality, and a definition built with a different zeroing would
/// answer differently.
///
/// # Safety
/// Both lists must be live.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_match_count(
    query: *const OsslPropertyList,
    defn: *const OsslPropertyList,
) -> c_int {
    // SAFETY: both lists are live, so each tail holds `num_properties` definitions.
    let (q, d) = unsafe {
        (
            core::slice::from_raw_parts(properties_ptr(query), num_properties(query) as usize),
            core::slice::from_raw_parts(properties_ptr(defn), num_properties(defn) as usize),
        )
    };
    let (mut i, mut j, mut matched): (usize, usize, c_int) = (0, 0, 0);

    while i < q.len() {
        let oper = q[i].oper;
        if oper == OSSL_PROPERTY_OVERRIDE {
            i += 1;
            continue;
        }
        if j < d.len() {
            if q[i].name_idx > d[j].name_idx {
                // Skip the definition: it is not in the query.
                j += 1;
                continue;
            }
            if q[i].name_idx == d[j].name_idx {
                let eq = q[i].type_ == d[j].type_ && union_bytes(&q[i].v) == union_bytes(&d[j].v);
                if (eq && oper == OSSL_PROPERTY_OPER_EQ) || (!eq && oper == OSSL_PROPERTY_OPER_NE) {
                    matched += 1;
                } else if q[i].optional == 0 {
                    return -1;
                }
                i += 1;
                j += 1;
                continue;
            }
        }
        // No definition to compare against, or a value the query could not produce.
        // The authority writes the next two cases as one four-way `else if`, whose
        // arms overlap: it is written here as the two cases it actually distinguishes,
        // because the union may only be read once the type says which arm is live.
        if q[i].type_ == OSSL_PROPERTY_TYPE_VALUE_UNDEFINED {
            if oper == OSSL_PROPERTY_OPER_NE {
                matched += 1;
            } else if q[i].optional == 0 {
                return -1;
            }
        } else if q[i].type_ != OSSL_PROPERTY_TYPE_STRING {
            // A non-string, non-missing value with nothing to compare against is a
            // comparison against the Boolean false, which an equality fails and an
            // inequality satisfies.
            if q[i].optional == 0 {
                return -1;
            }
        } else {
            // SAFETY: the guard above established that the type is `STRING`, so the
            // string arm of the union is the live one.
            let str_val = unsafe { q[i].v.str_val };
            let false_by_eq = oper == OSSL_PROPERTY_OPER_EQ && str_val != OSSL_PROPERTY_FALSE;
            let false_by_ne = oper == OSSL_PROPERTY_OPER_NE && str_val == OSSL_PROPERTY_FALSE;
            if false_by_eq || false_by_ne {
                if q[i].optional == 0 {
                    return -1;
                }
            } else {
                matched += 1;
            }
        }
        i += 1;
    }
    matched
}

/// The bytes of the `v` union, which is what the authority's `memcmp` covers.
fn union_bytes(v: &PropertyValue) -> [u8; core::mem::size_of::<PropertyValue>()] {
    // SAFETY: `PropertyValue` is `#[repr(C)]`, `Copy` and all-bits-valid, so reading
    // its bytes is defined.
    unsafe { core::mem::transmute_copy(v) }
}

/// `OSSL_PROPERTY_LIST *ossl_property_merge(const OSSL_PROPERTY_LIST *a,
/// const OSSL_PROPERTY_LIST *b)`
///
/// Merges two lists, **the first list winning a shared name**. The allocation is
/// `sizeof(*r) + (t - 1) * sizeof(properties[0])` where `t` is the *sum* of the two
/// counts, so an empty merge allocates a bare header.
///
/// # Safety
/// Both lists must be live.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_merge(
    a: *const OsslPropertyList,
    b: *const OsslPropertyList,
) -> *mut OsslPropertyList {
    // SAFETY: both lists are live.
    let (ap, bp, na, nb) = unsafe {
        (
            properties_ptr(a),
            properties_ptr(b),
            num_properties(a) as usize,
            num_properties(b) as usize,
        )
    };
    let t = na + nb;
    let defn_size = core::mem::size_of::<OsslPropertyDefinition>();
    let tail = if t == 0 { 0 } else { (t - 1) * defn_size };
    let r = CRYPTO_malloc(
        core::mem::size_of::<OsslPropertyList>() + tail,
        FILE,
        LINE_MALLOC_MERGED,
    )
    .cast::<OsslPropertyList>();
    if r.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `r` is a fresh allocation with room for `t` definitions.
    unsafe {
        (*r).has_optional = 0;
        let (mut i, mut j, mut n) = (0usize, 0usize, 0usize);
        while i < na || j < nb {
            // The merge step, as one expression: which element advances is the whole
            // of the algorithm, and the equal-name case is where the first list wins.
            let copy: *const OsslPropertyDefinition = if i >= na {
                let c = bp.add(j);
                j += 1;
                c
            } else if j >= nb {
                let c = ap.add(i);
                i += 1;
                c
            } else if (*ap.add(i)).name_idx <= (*bp.add(j)).name_idx {
                // A name in both lists keeps the **first** list's clause, so the
                // second list's copy of it is skipped rather than merged.
                if (*ap.add(i)).name_idx == (*bp.add(j)).name_idx {
                    j += 1;
                }
                let c = ap.add(i);
                i += 1;
                c
            } else {
                let c = bp.add(j);
                j += 1;
                c
            };
            let dst = properties_ptr(r).add(n).cast_mut();
            *dst = *copy;
            (*r).has_optional |= (*dst).optional;
            n += 1;
        }
        (*r).num_properties = n as c_int;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use crate::property::query::ossl_property_has_optional;

    /// A live context with the string table pre-initialised.
    fn ctx() -> *mut c_void {
        let c = OSSL_LIB_CTX_new();
        assert!(!c.is_null());
        // SAFETY: `c` is live and its slot 3 was built by `context_init`.
        assert_eq!(unsafe { crate::property::ossl_property_parse_init(c) }, 1);
        c
    }

    /// Parse a definition and answer `(count, first name_idx, first type, first
    /// oper, first optional)` — enough to see the shape without a printer.
    unsafe fn shape(l: *const OsslPropertyList) -> (usize, i32, i32, i32, u32) {
        // SAFETY: `l` is a live list per the caller's contract.
        unsafe {
            let n = num_properties(l) as usize;
            if n == 0 {
                return (0, 0, 0, 0, 0);
            }
            let p = &*properties_ptr(l);
            (n, p.name_idx, p.type_, p.oper, p.optional)
        }
    }

    #[test]
    fn a_definition_parses_to_a_sorted_list_and_a_bare_name_is_true() {
        let c = ctx();
        // SAFETY: `c` is live and every literal is NUL-terminated.
        unsafe {
            // SAFETY: as above; `ossl_property_free` releases the list.
            let one = ossl_parse_property(c, c"fips".as_ptr());
            assert!(!one.is_null());
            let (n, _idx, ty, oper, opt) = shape(one);
            assert_eq!(n, 1);
            assert_eq!(ty, OSSL_PROPERTY_TYPE_STRING);
            assert_eq!(oper, OSSL_PROPERTY_OPER_EQ);
            assert_eq!(opt, 0);
            // A bare name means `=yes`: the value is the index of "yes", which is 1.
            assert_eq!((*properties_ptr(one)).v.str_val, OSSL_PROPERTY_TRUE);
            ossl_property_free(one);

            let two = ossl_parse_property(c, c"output=certificate,input=certificate".as_ptr());
            assert!(!two.is_null(), "a two-clause definition parses");
            assert_eq!(num_properties(two), 2);
            // Sorted by name_idx, not by source order: `input` precedes `output` in
            // the name table only if it was interned first, so assert the order the
            // sort produced is non-decreasing.
            let a = (*properties_ptr(two)).name_idx;
            let b = (*properties_ptr(two).add(1)).name_idx;
            assert!(a <= b, "the list is sorted by name_idx: {a} then {b}");
            ossl_property_free(two);

            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn a_duplicated_name_is_refused_and_the_list_is_not_returned() {
        let c = ctx();
        // SAFETY: `c` is live and the literal is NUL-terminated.
        unsafe {
            let l = ossl_parse_property(c, c"fips=yes,fips=no".as_ptr());
            assert!(
                l.is_null(),
                "a duplicated name is an error, not last-one-wins"
            );
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn an_unterminated_string_is_refused_with_its_own_reason() {
        let c = ctx();
        // SAFETY: `c` is live and the literals are NUL-terminated.
        unsafe {
            assert!(ossl_parse_property(c, c"fips='unterminated".as_ptr()).is_null());
            assert!(ossl_parse_query(c, c"fips='unterminated".as_ptr(), 1).is_null());
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn a_query_records_negation_override_and_optionality() {
        let c = ctx();
        // SAFETY: `c` is live and the literals are NUL-terminated.
        unsafe {
            let q = ossl_parse_query(c, c"?fips!=yes,-provider".as_ptr(), 1);
            assert!(!q.is_null());
            assert_eq!(num_properties(q), 2);
            // The list is sorted, so the two clauses are in name_idx order; find the
            // override by its oper rather than by position.
            let mut saw_override = false;
            let mut saw_optional_ne = false;
            for i in 0..num_properties(q) as usize {
                let p = &*properties_ptr(q).add(i);
                if p.oper == OSSL_PROPERTY_OVERRIDE {
                    saw_override = true;
                }
                if p.oper == OSSL_PROPERTY_OPER_NE && p.optional == 1 {
                    saw_optional_ne = true;
                }
            }
            assert!(saw_override, "`-provider` is an override clause");
            assert!(saw_optional_ne, "`?fips!=yes` is an optional inequality");
            assert_eq!(ossl_property_has_optional(q), 1);
            ossl_property_free(q);
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn match_count_counts_equalities_and_refuses_a_false_mandatory_clause() {
        let c = ctx();
        // SAFETY: `c` is live and the literals are NUL-terminated.
        unsafe {
            let defn = ossl_parse_property(c, c"fips=yes,provider=default".as_ptr());
            let hits = ossl_parse_query(c, c"fips=yes,provider=default".as_ptr(), 0);
            let miss = ossl_parse_query(c, c"fips=no".as_ptr(), 1);
            let neg = ossl_parse_query(c, c"fips!=yes".as_ptr(), 0);
            let opt = ossl_parse_query(c, c"?fips=no".as_ptr(), 1);
            assert!(!defn.is_null() && !hits.is_null() && !miss.is_null());
            assert!(!neg.is_null() && !opt.is_null());
            assert_eq!(
                ossl_property_match_count(hits, defn),
                2,
                "two clauses match"
            );
            assert_eq!(
                ossl_property_match_count(miss, defn),
                -1,
                "a false mandatory clause"
            );
            assert_eq!(
                ossl_property_match_count(neg, defn),
                -1,
                "fips IS yes, so != fails"
            );
            assert_eq!(
                ossl_property_match_count(opt, defn),
                0,
                "an optional clause is not counted"
            );
            for l in [defn, hits, miss, neg, opt] {
                ossl_property_free(l);
            }
            OSSL_LIB_CTX_free(c);
        }
    }

    #[test]
    fn merge_keeps_the_first_list_and_is_sorted() {
        let c = ctx();
        // SAFETY: `c` is live and the literals are NUL-terminated.
        unsafe {
            let a = ossl_parse_property(c, c"fips=yes".as_ptr());
            let b = ossl_parse_property(c, c"fips=no,provider=default".as_ptr());
            let m = ossl_property_merge(a, b);
            assert!(!m.is_null());
            // `a` wins the shared name and `b`'s second clause is kept.
            assert_eq!(num_properties(m), 2);
            let mut de = 0;
            for i in 0..2usize {
                let p = &*properties_ptr(m).add(i);
                if p.type_ == OSSL_PROPERTY_TYPE_STRING && p.v.str_val == OSSL_PROPERTY_TRUE {
                    de += 1;
                }
            }
            assert_eq!(de, 1, "the merged list carries `a`'s true, not `b`'s false");
            ossl_property_free(m);
            ossl_property_free(a);
            ossl_property_free(b);
            OSSL_LIB_CTX_free(c);
        }
    }
}
