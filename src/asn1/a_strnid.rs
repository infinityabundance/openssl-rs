//! Phase 5 — `crypto/asn1/a_strnid.c`: the string-type policy table.
//!
//! Every directory-name attribute has a set of string types it is allowed to be
//! written in and a length range, and this module is were that policy lives. Seven
//! exports: the table accessors, the two ends of the global mask, and the
//! `ASN1_STRING_set_by_NID` constructor that applies a row to a buffer.
//!
//! ## Two tables, and the one that shadows
//!
//! `tbl_standard` is a compile-time table of 28 rows, in NID order, searched with
//! the authority's `OBJ_bsearch_`. `stable` is a runtime stack that
//! `ASN1_STRING_TABLE_add` grows. A `get` looks in the stack **first** and falls
//! back to the standard table, so an added row shadows the built-in one for its
//! NID; `stable_get` is what implements "modify this row" as "make a private copy
//! of it, mark the copy owned, and modify the copy".
//!
//! The ownership flag is the whole reason `STABLE_FLAGS_CLEAR` exists as a name
//! for `STABLE_FLAGS_MALLOC`: `ASN1_STRING_TABLE_cleanup` releases only rows that
//! carry it, so `st_free` on a standard-table row — which no pointer to the table
//! ever reaches — would be a free of static storage. The flag is not a hint.
//!
//! ## The mask has two halves and they only combine one way
//!
//! `global_mask` exists because "certain software (e.g. Netscape) has problems
//! with" `BMPString` and `UTF8String`, so a caller can exclude types process-wide.
//! A row's own mask is always intersected with it *unless* the row sets
//! `STABLE_NO_MASK` — which is why every standard row that names a single type
//! sets that flag, and every row that names a multi-type set does not. Reproducing
//! the mask application without the flag would make `NID_friendlyName`, whose mask
//! is `BMPString` alone, refuse every UTF8 string the moment a caller narrowed the
//! global mask.
//!
//! ## `ASN1_STRING_TABLE_get` loads the config
//!
//! The `OPENSSL_NO_AUTOLOAD_CONFIG` guard is not present on the admitted profile,
//! so the call is made: a `get` can run the config file's `stbl_section` before
//! answering, which is what makes `ASN1_STRING_TABLE_add` visible to a program
//! that configured it in a file rather than in code. The call is reproduced for
//! exactly that reason, even though on a build with no config file it does
//! nothing.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};

use crate::asn1::a_mbstr::{ASN1_mbstring_copy, ASN1_mbstring_ncopy};
use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::OBJ_bsearch_;
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};

extern "C" {
    /// `unsigned long strtoul(const char *, char **, int)`.
    fn strtoul(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulong;
    /// `int strcmp(const char *, const char *)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// The authority translation unit for the string table.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_strnid.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

// ---------------------------------------------------------------------------
// `tbl_standard[]` — `crypto/asn1/tbl_standard.h`
//
// Derived from the authority's own header, in its own order, with the bounds and
// masks it names. The header's comment — "This table must be kept in NID order" —
// is load-bearing: `ASN1_STRING_TABLE_get` falls back to a binary search over it.
// ---------------------------------------------------------------------------

/// The compile-time rows, in NID order.
pub(crate) static TBL_STANDARD: [Asn1StringTable; 28] = [
    row(13, 1, 64, DIRSTRING_TYPE, 0),                     // commonName
    row(14, 2, 2, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK), // countryName
    row(15, 1, 128, DIRSTRING_TYPE, 0),                    // localityName
    row(16, 1, 128, DIRSTRING_TYPE, 0),                    // stateOrProvinceName
    row(17, 1, 64, DIRSTRING_TYPE, 0),                     // organizationName
    row(18, 1, 64, DIRSTRING_TYPE, 0),                     // organizationalUnitName
    row(48, 1, 128, B_ASN1_IA5STRING, STABLE_NO_MASK),     // pkcs9_emailAddress
    row(49, 1, -1, PKCS9STRING_TYPE, 0),                   // pkcs9_unstructuredName
    row(54, 1, -1, PKCS9STRING_TYPE, 0),                   // pkcs9_challengePassword
    row(55, 1, -1, DIRSTRING_TYPE, 0),                     // pkcs9_unstructuredAddress
    row(99, 1, 32768, DIRSTRING_TYPE, 0),                  // givenName
    row(100, 1, 32768, DIRSTRING_TYPE, 0),                 // surname
    row(101, 1, 32768, DIRSTRING_TYPE, 0),                 // initials
    row(105, 1, 64, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK), // serialNumber
    row(156, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK),    // friendlyName
    row(173, 1, 32768, DIRSTRING_TYPE, 0),                 // name
    row(174, -1, -1, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK), // dnQualifier
    row(391, 1, -1, B_ASN1_IA5STRING, STABLE_NO_MASK),     // domainComponent
    row(417, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK),    // ms_csp_name
    row(460, 1, 256, B_ASN1_IA5STRING, STABLE_NO_MASK),    // rfc822Mailbox
    row(957, 2, 2, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK), // jurisdictionCountryName
    row(1004, 1, 12, B_ASN1_NUMERICSTRING, STABLE_NO_MASK), // INN
    row(1005, 1, 13, B_ASN1_NUMERICSTRING, STABLE_NO_MASK), // OGRN
    row(1006, 1, 11, B_ASN1_NUMERICSTRING, STABLE_NO_MASK), // SNILS
    row(1090, 3, 3, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK), // countryCode3c
    row(1091, 3, 3, B_ASN1_NUMERICSTRING, STABLE_NO_MASK), // countryCode3n
    row(1092, 0, -1, B_ASN1_UTF8STRING, STABLE_NO_MASK),   // dnsName
    row(1208, 1, 128, B_ASN1_UTF8STRING, STABLE_NO_MASK),  // id_on_SmtpUTF8Mailbox
];

/// One `tbl_standard` row, as a `const fn` so the table above stays a table.
const fn row(
    nid: c_int,
    minsize: c_long,
    maxsize: c_long,
    mask: c_ulong,
    flags: c_ulong,
) -> Asn1StringTable {
    Asn1StringTable {
        nid,
        minsize,
        maxsize,
        mask,
        flags,
    }
}

// ---------------------------------------------------------------------------
// The two pieces of process state
// ---------------------------------------------------------------------------

/// `static unsigned long global_mask = B_ASN1_UTF8STRING;`
///
/// A plain integer, so the accessors need no synchronisation to be *atomic*; the
/// authority does not synchronise them either (its own comment on the stack says
/// "Ideally, this would be done under lock").
static GLOBAL_MASK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(B_ASN1_UTF8STRING);

/// `static STACK_OF(ASN1_STRING_TABLE) *stable = NULL;`
///
/// The stack pointer, as an `AtomicPtr` rather than a `static mut` so that reading
/// it never forms a reference to mutable static storage. The authority uses a bare
/// pointer and documents that the sort is unsynchronised; the *observable* contract
/// is the same.
static STABLE: core::sync::atomic::AtomicPtr<OpenSslStack> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// The current stack, or null.
fn stable_get_ptr() -> *mut OpenSslStack {
    STABLE.load(core::sync::atomic::Ordering::Relaxed)
}

/// `static int sk_table_cmp(const ASN1_STRING_TABLE *const *a,
/// const ASN1_STRING_TABLE *const *b)`
///
/// The typed-stack comparator's arguments are the *addresses of the slots*, which
/// is why it dereferences twice — the same shape `qsort` and `bsearch` require and
/// the crate's `OPENSSL_sk_sort`/`OPENSSL_sk_find` reproduce.
///
/// # Safety
///
/// `a` and `b` must be addresses of live slots holding `ASN1_STRING_TABLE *`.
unsafe extern "C" fn table_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the caller's contract is the typed-stack comparator's.
    let (x, y) = unsafe {
        (
            *(a as *mut *const Asn1StringTable),
            *(b as *mut *const Asn1StringTable),
        )
    };
    if x.is_null() || y.is_null() {
        return 0;
    }
    // SAFETY: both are live rows.
    unsafe { (*x).nid - (*y).nid }
}

/// `void ASN1_STRING_set_default_mask(unsigned long mask)`
#[no_mangle]
pub extern "C" fn ASN1_STRING_set_default_mask(mask: c_ulong) {
    GLOBAL_MASK.store(mask, core::sync::atomic::Ordering::Relaxed);
}

/// `unsigned long ASN1_STRING_get_default_mask(void)`
#[no_mangle]
pub extern "C" fn ASN1_STRING_get_default_mask() -> c_ulong {
    GLOBAL_MASK.load(core::sync::atomic::Ordering::Relaxed)
}

/// `int ASN1_STRING_set_default_mask_asc(const char *p)`
///
/// Five spellings: a `MASK:` prefix with a number in any base, and the four names.
/// `strtoul` is used rather than a Rust parse because the authority accepts a
/// leading sign and any C base prefix, and because the `*end` test means trailing
/// junk is a failure rather than a partial parse.
///
/// The `MASK:` prefix is consumed through `CHECK_AND_SKIP_PREFIX`, which is a
/// `strncmp` over the literal, so a shorter string does not match and falls
/// through to the names.
///
/// # Safety
///
/// `p` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_set_default_mask_asc(p: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract makes `p` NUL-terminated.
        let s = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
        // The four names, each an exact `strcmp`, and the `MASK:` prefix which is a
        // `strncmp` over the literal so that a shorter string cannot match it.
        // SAFETY: `p` is NUL-terminated per the caller's contract, and each literal
        // is a `'static` C string.
        let is = |lit: &'static core::ffi::CStr| unsafe { strcmp(p, lit.as_ptr()) } == 0;
        let mask: c_ulong = if s.starts_with(b"MASK:") {
            // `if (*p == '\0') return 0;` — an empty remainder is an argument
            // error even though `strtoul` would accept it as zero.
            if s.len() == 5 {
                return 0;
            }
            // SAFETY: the remainder is a NUL-terminated string; `end` is a live
            // local.
            let mut end: *mut c_char = core::ptr::null_mut();
            // SAFETY: `p` is NUL-terminated and `p + 5` is inside it.
            let v = unsafe { strtoul(p.add(5), &mut end, 0) };
            // SAFETY: `end` was written by `strtoul`.
            if unsafe { *end } != 0 {
                return 0;
            }
            v
        } else if is(c"nombstr") {
            !(B_ASN1_BMPSTRING | B_ASN1_UTF8STRING)
        } else if is(c"pkix") {
            !B_ASN1_T61STRING
        } else if is(c"utf8only") {
            B_ASN1_UTF8STRING
        } else if is(c"default") {
            0xFFFFFFFF
        } else {
            return 0;
        };
        ASN1_STRING_set_default_mask(mask);
        1
    })
}

/// `ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)`
///
/// A non-positive NID is an argument error, not a miss. The config load runs
/// before the search, and the stack shadows the standard table — see the module
/// documentation for why both matter.
#[no_mangle]
pub extern "C" fn ASN1_STRING_TABLE_get(nid: c_int) -> *mut Asn1StringTable {
    guard_ffi(core::ptr::null_mut(), || {
        if nid <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_STRNID_133) };
            return core::ptr::null_mut();
        }

        // `#ifndef OPENSSL_NO_AUTOLOAD_CONFIG`, which is not defined on this
        // profile: the config file is loaded before the table is consulted, so a
        // `stbl_section` entry is visible to this call.
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, core::ptr::null());

        let fnd = Asn1StringTable {
            nid,
            minsize: 0,
            maxsize: 0,
            mask: 0,
            flags: 0,
        };
        let st = stable_get_ptr();
        if !st.is_null() {
            // SAFETY: `st` is a live stack of rows with `table_cmp`.
            unsafe { OPENSSL_sk_sort(st) };
            // SAFETY: `st` is live and `fnd` is a live local; the comparator
            // receives its address, as the typed-stack form requires.
            let idx = unsafe { OPENSSL_sk_find(st, (&raw const fnd).cast::<c_void>()) };
            if idx >= 0 {
                // SAFETY: `idx` is a valid index of `st`.
                return unsafe { OPENSSL_sk_value(st, idx) }.cast::<Asn1StringTable>();
            }
        }
        // SAFETY: the key and both tables are live; the comparison function is the
        // generated `table_cmp` and the table is in NID order.
        unsafe {
            OBJ_bsearch_(
                (&raw const fnd).cast::<c_void>(),
                TBL_STANDARD.as_ptr().cast::<c_void>(),
                TBL_STANDARD.len() as c_int,
                core::mem::size_of::<Asn1StringTable>() as c_int,
                Some(bsearch_table_cmp),
            )
            .cast::<Asn1StringTable>()
            .cast_mut()
        }
    })
}

/// The bytes of a table row a `bsearch` comparison must read.
///
/// The authority's `IMPLEMENT_OBJ_BSEARCH_CMP_FN` casts the raw element pointers
/// to the element type and calls the typed comparison; this is the same two lines.
///
/// # Safety
///
/// `a` and `b` must each point at a live `ASN1_STRING_TABLE`.
unsafe extern "C" fn bsearch_table_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the caller's contract.
    let (x, y) = unsafe { (&*a.cast::<Asn1StringTable>(), &*b.cast::<Asn1StringTable>()) };
    x.nid - y.nid
}

/// `static ASN1_STRING_TABLE *stable_get(int nid)`
///
/// "Either directly from table or a copy of an internal value added to the table."
/// A row already on the stack and marked owned is returned as it is; anything else
/// gets a fresh owned row, copied from the standard table if there is one and
/// otherwise defaulted to no bounds and no mask.
fn stable_get(nid: c_int) -> *mut Asn1StringTable {
    if stable_get_ptr().is_null() {
        // SAFETY: `OPENSSL_sk_new` takes an optional comparator and answers null
        // or a fresh empty stack.
        let st = OPENSSL_sk_new(Some(table_cmp));
        if st.is_null() {
            return core::ptr::null_mut();
        }
        STABLE.store(st, core::sync::atomic::Ordering::Relaxed);
    }
    let st = stable_get_ptr();
    let tmp = ASN1_STRING_TABLE_get(nid);
    // SAFETY: `tmp` is null or a live row.
    if !tmp.is_null() && unsafe { (*tmp).flags } & STABLE_FLAGS_MALLOC != 0 {
        return tmp;
    }
    // SAFETY: `CRYPTO_zalloc` answers null or a zeroed row.
    let rv = CRYPTO_zalloc(core::mem::size_of::<Asn1StringTable>(), FILE.as_ptr(), LINE)
        .cast::<Asn1StringTable>();
    if rv.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `st` is live and `rv` is not owned elsewhere.
    if unsafe { OPENSSL_sk_push(st, rv.cast::<c_void>()) } == 0 {
        // SAFETY: `rv` came from this allocator and was refused by the stack.
        unsafe { CRYPTO_free(rv.cast::<c_void>(), FILE.as_ptr(), LINE) };
        return core::ptr::null_mut();
    }
    if !tmp.is_null() {
        // SAFETY: `tmp` and `rv` are live rows.
        unsafe {
            (*rv).nid = (*tmp).nid;
            (*rv).minsize = (*tmp).minsize;
            (*rv).maxsize = (*tmp).maxsize;
            (*rv).mask = (*tmp).mask;
            (*rv).flags = (*tmp).flags | STABLE_FLAGS_MALLOC;
        }
    } else {
        // SAFETY: `rv` is a live row.
        unsafe {
            (*rv).nid = nid;
            (*rv).minsize = -1;
            (*rv).maxsize = -1;
            (*rv).flags = STABLE_FLAGS_MALLOC;
        }
    }
    rv
}

/// `int ASN1_STRING_TABLE_add(int nid, long minsize, long maxsize,
/// unsigned long mask, unsigned long flags)`
///
/// A negative bound means "do not change this field", which is why the three
/// assignments below are guarded. `flags` of zero likewise leaves the existing
/// flags alone — and a non-zero `flags` *replaces* them with the owned bit plus
/// what was asked for, which is how `STABLE_FLAGS_CLEAR` clears `STABLE_NO_MASK`.
#[no_mangle]
pub extern "C" fn ASN1_STRING_TABLE_add(
    nid: c_int,
    minsize: c_long,
    maxsize: c_long,
    mask: c_ulong,
    flags: c_ulong,
) -> c_int {
    guard_ffi(0, || {
        if nid <= 0 || (minsize >= 0 && maxsize >= 0 && minsize > maxsize) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_STRNID_199) };
            return 0;
        }
        let tmp = stable_get(nid);
        if tmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_STRNID_205) };
            return 0;
        }
        // SAFETY: `tmp` is a live, owned row.
        unsafe {
            if minsize >= 0 {
                (*tmp).minsize = minsize;
            }
            if maxsize >= 0 {
                (*tmp).maxsize = maxsize;
            }
            if mask != 0 {
                (*tmp).mask = mask;
            }
            if flags != 0 {
                (*tmp).flags = STABLE_FLAGS_MALLOC | flags;
            }
        }
        1
    })
}

/// `void ASN1_STRING_TABLE_cleanup(void)`
///
/// Releases only the rows that carry `STABLE_FLAGS_MALLOC`, which no standard-table
/// row does. The stack pointer is cleared *before* the rows are released, so a
/// reentrant call from a destructor would see an empty table rather than a freed
/// stack.
#[no_mangle]
pub extern "C" fn ASN1_STRING_TABLE_cleanup() {
    guard_ffi((), || {
        let tmp = stable_get_ptr();
        if tmp.is_null() {
            return;
        }
        STABLE.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
        // SAFETY: `tmp` is a live stack whose elements are rows this module
        // allocated; the stack itself is released by `OPENSSL_sk_pop_free`.
        unsafe { OPENSSL_sk_pop_free(tmp, Some(st_free)) };
    })
}

/// `static void st_free(ASN1_STRING_TABLE *tbl)`
///
/// # Safety
///
/// `tbl` must be null or a live row.
unsafe extern "C" fn st_free(tbl: *mut c_void) {
    // SAFETY: the caller's contract.
    let Some(r) = (unsafe { (tbl as *const Asn1StringTable).as_ref() }) else {
        return;
    };
    if r.flags & STABLE_FLAGS_MALLOC != 0 {
        // SAFETY: the flag says this row came from `CRYPTO_zalloc` in
        // `stable_get`, and the stack is being released.
        unsafe { CRYPTO_free(tbl, FILE.as_ptr(), LINE) };
    }
}

/// `ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
/// const unsigned char *in, int inlen, int inform, int nid)`
///
/// Picks the row for the NID and hands the job to `ASN1_mbstring_ncopy` with its
/// bounds; with no row, the input is classified against `DIRSTRING_TYPE`
/// intersected with the global mask. That fallback is the observable difference
/// between a known NID and an unknown one: an unknown NID still gets a string, but
/// without a length limit.
///
/// A null `out` is redirected to a local, because the function always has a
/// destination to answer.
///
/// # Safety
///
/// `out` must be null or point at a writable `ASN1_STRING *`; `in` must be
/// readable for `inlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_set_by_NID(
    out: *mut *mut Asn1String,
    in_: *const c_uchar,
    inlen: c_int,
    inform: c_int,
    nid: c_int,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        let mut str_: *mut Asn1String = core::ptr::null_mut();
        let out = if out.is_null() { &raw mut str_ } else { out };
        let tbl = ASN1_STRING_TABLE_get(nid);
        let ret = if !tbl.is_null() {
            // SAFETY: `tbl` is a live row.
            let (mask, minsize, maxsize) = unsafe { ((*tbl).mask, (*tbl).minsize, (*tbl).maxsize) };
            // SAFETY: `tbl` is live.
            let mask = if unsafe { (*tbl).flags } & STABLE_NO_MASK == 0 {
                mask & ASN1_STRING_get_default_mask()
            } else {
                mask
            };
            // SAFETY: the caller's contract is `ASN1_mbstring_ncopy`'s.
            unsafe { ASN1_mbstring_ncopy(out, in_, inlen, inform, mask, minsize, maxsize) }
        } else {
            // SAFETY: the caller's contract is `ASN1_mbstring_copy`'s.
            unsafe {
                ASN1_mbstring_copy(
                    out,
                    in_,
                    inlen,
                    inform,
                    DIRSTRING_TYPE & ASN1_STRING_get_default_mask(),
                )
            }
        };
        if ret <= 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: `out` is the caller's slot or the local, both writable.
        unsafe { *out }
    })
}
