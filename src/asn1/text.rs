//! Phase 5 — the text conversions: the `i2a_*` writers a BIO receives and the
//! `a2i_*` readers.
//!
//! ## Uppercase hex, and a two-digit group per octet
//!
//! Every one of these writers spells an octet with `ossl_to_hex`, whose digit
//! table is `"0123456789ABCDEF"` — **uppercase**. That is not cosmetic: a caller
//! that compares the text a BIO received would see a difference, and the
//! differential court compares exactly that text. The group separator is a
//! backslash-newline every 35 octets, which is why the writers count characters
//! rather than trusting the BIO's return value.
//!
//! ## The integer writer prints the *stored magnitude*, not the DER content
//!
//! `i2a_ASN1_INTEGER` writes a leading `-` when `V_ASN1_NEG` is set, then the
//! magnitude bytes as hex. An integer whose length is zero prints `00`, not the
//! empty string: the encoding would be a single zero octet and the text says so.
//! The bytes are the internal magnitude, so a negative prints the magnitude with a
//! `-` in front rather than its two's-complement form — the reading is not
//! `openssl asn1parse`'s.
//!
//! ## `i2a_ASN1_OBJECT` has three answers
//!
//! A null object, or one with no `data`, writes the four octets `NULL`. An object
//! whose text does not fit an 80-byte buffer is re-rendered into a heap buffer and
//! the buffer is written. An object whose text is *empty* writes `<INVALID>`
//! followed by `BIO_dump` of its raw content — so a caller that parses the output
//! sees the content bytes, not a diagnostic string.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::bio::{BIO_dump, BIO_gets, BIO_write};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_realloc, CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc};
use crate::runtime::obj::{Asn1Object, OBJ_obj2txt};
use crate::runtime::str::OPENSSL_hexchar2int;

/// The authority translation unit for the integer text conversion.
pub(crate) const INT_FILE: &core::ffi::CStr = c"crypto/asn1/f_int.c";
/// The authority translation unit for the string text conversion.
pub(crate) const STRING_FILE: &core::ffi::CStr = c"crypto/asn1/f_string.c";
/// The authority translation unit for `i2a_ASN1_OBJECT`.
pub(crate) const OBJECT_FILE: &core::ffi::CStr = c"crypto/asn1/a_object.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ossl_to_hex`'s digit table. Uppercase, as the authority's is.
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// The size of the stack buffer `i2a_ASN1_OBJECT` renders into.
const OBJ_BUF: usize = 80;

// ---------------------------------------------------------------------------------------------
// Ownership of a scratch buffer
// ---------------------------------------------------------------------------------------------

/// An owned scratch buffer grown and released through the crate's allocator seam.
///
/// The block stays a `CRYPTO_malloc`/`CRYPTO_realloc` at the authority's exact size/`file`/`line` --
/// a Rust `Vec` would hide both the growth and its release from a caller-installed
/// `CRYPTO_set_mem_functions` hook -- and only its *ownership* is this type: `new` allocates the
/// fixed `i2a_ASN1_OBJECT` render buffer, `empty` starts an `a2i_*` reader with no block at all,
/// [`Self::clear_realloc`]/[`Self::realloc`] grow a reader's buffer exactly as the authority's
/// `OPENSSL_clear_realloc`/`OPENSSL_realloc` do, `Drop` is its single release, and
/// [`Self::into_raw`] hands a reader's finished value to the `ASN1_STRING` that takes it over. A
/// NULL pointer is a valid, empty block whose release is the authority's own no-op `free(NULL)`.
struct OwnedBuf {
    ptr: *mut u8,
    file: *const c_char,
    line: c_int,
}

impl OwnedBuf {
    /// `CRYPTO_malloc(len, file, line)` for the fixed render buffer, or `None` when the allocator
    /// answers NULL.
    fn new(len: usize, file: *const c_char, line: c_int) -> Option<OwnedBuf> {
        let raw = CRYPTO_malloc(len, file, line).cast::<u8>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            file,
            line,
        })
    }

    /// A reader's empty scratch buffer, before its first growth.
    fn empty(file: *const c_char, line: c_int) -> OwnedBuf {
        OwnedBuf {
            ptr: core::ptr::null_mut(),
            file,
            line,
        }
    }

    /// `CRYPTO_clear_realloc(ptr, old, new, file, line)` — `a2i_ASN1_INTEGER`'s growth, whose
    /// cleared tail the shift-and-or reads. `None` when the allocator answers NULL; the block, if
    /// any, is left for `Drop` exactly as the authority leaves it for its error tail.
    ///
    /// # Safety
    ///
    /// `self.ptr` is NULL or a live block of at least `old` bytes that this handle owns.
    unsafe fn clear_realloc(&mut self, old: usize, new: usize) -> Option<()> {
        // SAFETY: per this method's contract, the block is NULL or this handle's own of `old`
        // bytes; `CRYPTO_clear_realloc` clears the tail it discards.
        let raw = unsafe {
            CRYPTO_clear_realloc(self.ptr.cast::<c_void>(), old, new, self.file, self.line)
        }
        .cast::<u8>();
        if raw.is_null() {
            return None;
        }
        self.ptr = raw;
        Some(())
    }

    /// `CRYPTO_realloc(ptr, new, file, line)` — `a2i_ASN1_STRING`'s growth. `None` when the
    /// allocator answers NULL; the block, if any, is left for `Drop`.
    ///
    /// # Safety
    ///
    /// `self.ptr` is NULL or a live block that this handle owns.
    unsafe fn realloc(&mut self, new: usize) -> Option<()> {
        // SAFETY: per this method's contract, the block is NULL or this handle's own.
        let raw = unsafe { CRYPTO_realloc(self.ptr.cast::<c_void>(), new, self.file, self.line) }
            .cast::<u8>();
        if raw.is_null() {
            return None;
        }
        self.ptr = raw;
        Some(())
    }

    /// The start of the block.
    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Give up ownership of the block to a consumer that takes it over.
    fn into_raw(self) -> *mut u8 {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBuf {
    /// The block's single release, through the same seam the authority uses.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released; the authority's
        // own `CRYPTO_free` accepts NULL, which the readers' `err:` tails pass it.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file, self.line) };
    }
}

/// Write one octet as two uppercase hex digits. Returns 2, the count the callers
/// add to their own.
/// `ossl_to_hex`'s digit table. Uppercase, as the authority's is.
#[inline]
pub(crate) fn to_hex(out: &mut [u8; 2], n: u8) {
    out[0] = HEX_DIGITS[(n >> 4) as usize];
    out[1] = HEX_DIGITS[(n & 0x0f) as usize];
}

/// `i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a)`
///
/// # Safety
///
/// `buf` must be writable for `buf_len` bytes, or `buf_len` may be 0 with `buf`
/// null; `a` must be null or a live object.
#[no_mangle]
pub unsafe extern "C" fn i2t_ASN1_OBJECT(
    buf: *mut c_char,
    buf_len: c_int,
    a: *const Asn1Object,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-valid per this function's `# Safety` section. `no_name`
        // is 0, which is what the authority passes here.
        unsafe { OBJ_obj2txt(buf, buf_len, a, 0) }
    })
}

/// `int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a)`
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live object.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_OBJECT(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1Object,
) -> c_int {
    guard_ffi(0, || {
        if a.is_null() {
            // SAFETY: `bp` is null or live.
            return unsafe { BIO_write(bp, c"NULL".as_ptr().cast(), 4) };
        }
        // SAFETY: `a` is live.
        let obj = unsafe { &*a };
        if obj.data.is_null() {
            // SAFETY: `bp` is null or live.
            return unsafe { BIO_write(bp, c"NULL".as_ptr().cast(), 4) };
        }
        let mut buf = [0 as c_char; OBJ_BUF];
        // SAFETY: `buf` is `OBJ_BUF` writable bytes; `a` is live.
        let i = unsafe { i2t_ASN1_OBJECT(buf.as_mut_ptr(), OBJ_BUF as c_int, a) };
        let mut heap: Option<OwnedBuf> = None;
        if i > (OBJ_BUF - 1) as c_int {
            if i > c_int::MAX - 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::A_OBJECT_198) };
                return -1;
            }
            let Some(h) = OwnedBuf::new(i as usize + 1, OBJECT_FILE.as_ptr(), LINE) else {
                return -1;
            };
            let p = h.as_ptr().cast::<c_char>();
            // SAFETY: `p` is `i + 1` bytes.
            unsafe { i2t_ASN1_OBJECT(p, i + 1, a) };
            heap = Some(h);
        }
        let p = heap
            .as_ref()
            .map_or(buf.as_mut_ptr(), |h| h.as_ptr().cast::<c_char>());
        if i <= 0 {
            // SAFETY: `bp` is null or live.
            let mut n = unsafe { BIO_write(bp, c"<INVALID>".as_ptr().cast(), 9) };
            if n > 0 {
                // SAFETY: `obj.data` is readable for `obj.length` bytes; `bp` is
                // null or live.
                n += unsafe { BIO_dump(bp, obj.data.cast::<c_void>(), obj.length) };
            }
            return n;
        }
        // SAFETY: `p` holds at least `i` readable bytes; `bp` is null or live.
        let n = unsafe { BIO_write(bp, p.cast::<c_void>(), i) };
        // The authority ignores `BIO_write`'s answer here and returns `i`. That is
        // observable when the BIO is short, so it is reproduced.
        let _ = n;
        i
    })
}

/// `int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type)`
///
/// The `type` argument is accepted and unused, as it is in the authority.
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live string.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_STRING(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        let _ = type_;
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is live.
        let s = unsafe { &*a };
        let mut n: c_int = 0;
        if s.length == 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"0".as_ptr().cast(), 1) } != 1 {
                return -1;
            }
            return 1;
        }
        let mut i = 0i32;
        while i < s.length {
            if i != 0 && i % 35 == 0 {
                // SAFETY: `bp` is null or live.
                if unsafe { BIO_write(bp, c"\\\n".as_ptr().cast(), 2) } != 2 {
                    return -1;
                }
                n += 2;
            }
            let mut pair = [0u8; 2];
            // SAFETY: `s.data` is readable for `s.length` bytes.
            to_hex(&mut pair, unsafe { *s.data.add(i as usize) });
            // SAFETY: `pair` is two readable bytes; `bp` is null or live.
            if unsafe { BIO_write(bp, pair.as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            n += 2;
            i += 1;
        }
        let _ = STRING_FILE;
        n
    })
}

/// `int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a)`
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live integer.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_INTEGER(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
) -> c_int {
    guard_ffi(0, || {
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is live.
        let s = unsafe { &*a };
        let mut n: c_int = 0;
        if s.type_ & V_ASN1_NEG != 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"-".as_ptr().cast(), 1) } != 1 {
                return -1;
            }
            n = 1;
        }
        if s.length == 0 {
            // SAFETY: `bp` is null or live.
            if unsafe { BIO_write(bp, c"00".as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            return n + 2;
        }
        let mut i = 0i32;
        while i < s.length {
            if i != 0 && i % 35 == 0 {
                // SAFETY: `bp` is null or live.
                if unsafe { BIO_write(bp, c"\\\n".as_ptr().cast(), 2) } != 2 {
                    return -1;
                }
                n += 2;
            }
            let mut pair = [0u8; 2];
            // SAFETY: `s.data` is readable for `s.length` bytes.
            to_hex(&mut pair, unsafe { *s.data.add(i as usize) });
            // SAFETY: `pair` is two readable bytes; `bp` is null or live.
            if unsafe { BIO_write(bp, pair.as_ptr().cast(), 2) } != 2 {
                return -1;
            }
            n += 2;
            i += 1;
        }
        let _ = INT_FILE;
        n
    })
}

/// `int i2a_ASN1_ENUMERATED(BIO *bp, const ASN1_ENUMERATED *a)`
///
/// Exactly `i2a_ASN1_INTEGER`: the authority's body is a one-line forwarding call,
/// because the stored magnitude and the sign bit are laid out the same way.
///
/// # Safety
///
/// `bp` must be null or a live BIO; `a` must be null or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_ENUMERATED(
    bp: *mut crate::runtime::bio::Bio,
    a: *const Asn1String,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per this function's `# Safety` section.
        unsafe { i2a_ASN1_INTEGER(bp, a) }
    })
}

// ---------------------------------------------------------------------------
// The `f_int.c` and `f_string.c` line readers — `a2i_ASN1_*`
// ---------------------------------------------------------------------------

/// The `f_int.c` translation unit, for the allocator's file/line record.
const F_INT_FILE: &core::ffi::CStr = c"crypto/asn1/f_int.c";
/// The `f_string.c` translation unit.
const F_STRING_FILE: &core::ffi::CStr = c"crypto/asn1/f_string.c";

/// `int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size)`
///
/// Reads one ASN.1 INTEGER from a BIO in the textual hex form the authority writes with
/// `i2a_ASN1_INTEGER`: one line per 35 octets, continued lines ending in a backslash, and
/// the whole value prefixed with `00` on the first line only.
///
/// The caller supplies the line buffer, which is why `buf` and `size` are parameters
/// rather than locals — a caller looping over many integers reuses one buffer, and that is
/// the documented reason the signature has them.
///
/// Four behaviours are worth naming because none is obvious from the signature:
///
/// * the `00` prefix is stripped **only** on the first line, and only when the line is at
///   least two characters of hex. A later line starting with `00` contributes those two
///   octets to the value;
/// * the hex scan stops at the first non-hex character, so trailing text is silently
///   discarded rather than refused — the line's remainder after that point is not read;
/// * a continued line has its backslash removed **before** the odd-length check, so a
///   backslash can make an otherwise odd line even;
/// * the buffer grows with `OPENSSL_clear_realloc`, which matters because the destination
///   octet is read-modify-written (`<<= 4` then `|=`) and the clear is what makes the new
///   region start at zero rather than at whatever the allocator had.
///
/// # Safety
///
/// `bp` must be a live BIO; `bs` must be a live `ASN1_INTEGER`; `buf` must be writable for
/// `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn a2i_ASN1_INTEGER(
    bp: *mut crate::runtime::bio::Bio,
    bs: *mut Asn1String,
    buf: *mut c_char,
    size: c_int,
) -> c_int {
    guard_ffi(0, || {
        let mut s = OwnedBuf::empty(F_INT_FILE.as_ptr(), LINE);
        let mut slen: c_int = 0;
        let mut num: c_int = 0;
        let mut first = true;

        // SAFETY: `bs` is the caller's live string.
        unsafe { (*bs).type_ = V_ASN1_INTEGER };
        // SAFETY: `bp` is a live BIO and `buf` is writable for `size` bytes.
        let mut bufsize = unsafe { BIO_gets(bp, buf, size) };

        let outcome: c_int = 'outer: loop {
            if bufsize < 1 {
                // The `err:` tail, which raises `SHORT_LINE`.
                break 'outer 0;
            }
            let mut i = bufsize;
            // SAFETY: `buf` holds `bufsize` bytes, so the last one is readable.
            if unsafe { *buf.add((i - 1) as usize) } == b'\n' as c_char {
                i -= 1;
                // SAFETY: the same byte, overwritten.
                unsafe { *buf.add(i as usize) = 0 };
            }
            if i == 0 {
                break 'outer 0;
            }
            // SAFETY: `i >= 1`, so the last byte is readable.
            if unsafe { *buf.add((i - 1) as usize) } == b'\r' as c_char {
                i -= 1;
                // SAFETY: as above.
                unsafe { *buf.add(i as usize) = 0 };
            }
            if i == 0 {
                break 'outer 0;
            }
            // The backslash is removed from the count *before* the parity test below.
            // SAFETY: `i >= 1`.
            let again = unsafe { *buf.add((i - 1) as usize) } == b'\\' as c_char;

            // Scan for the first non-hex character; the line ends there.
            let mut j: c_int = 0;
            while j < i {
                // SAFETY: `j < i <= bufsize`, so the byte is readable.
                let ch = unsafe { *buf.add(j as usize) } as core::ffi::c_uchar;
                if !crate::runtime::ctype::ossl_isxdigit(c_int::from(ch)) {
                    i = j;
                    break;
                }
                j += 1;
            }
            // SAFETY: `i <= bufsize` and `BIO_gets` leaves the byte at `bufsize` as its
            // NUL terminator, so this write is inside the caller's buffer.
            unsafe { *buf.add(i as usize) = 0 };

            if i < 2 {
                break 'outer 0;
            }

            let mut bufp = buf as *const u8;
            if first {
                first = false;
                // SAFETY: `i >= 2`, so two bytes are readable.
                if unsafe { *bufp } == b'0' && unsafe { *bufp.add(1) } == b'0' {
                    // SAFETY: as above.
                    bufp = unsafe { bufp.add(2) };
                    i -= 2;
                }
            }
            let mut k: c_int = 0;
            i -= c_int::from(again);
            if i % 2 != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::F_INT_100) };
                return 0;
            }
            i /= 2;
            if num + i > slen {
                // The clear matters: the destination octet is shifted into below.
                // SAFETY: `s` is this call's buffer of `slen` bytes, or null with `slen`
                // 0, which is exactly `OwnedBuf::clear_realloc`'s contract.
                if unsafe { s.clear_realloc(slen.max(0) as usize, (num + i * 2) as usize) }
                    .is_none()
                {
                    return 0;
                }
                slen = num + i * 2;
            }
            let mut jj: c_int = 0;
            while jj < i {
                let mut n: c_int = 0;
                while n < 2 {
                    // SAFETY: `k + n < i * 2` and `bufp` is readable for that many bytes
                    // by the parity test above.
                    let m = OPENSSL_hexchar2int(unsafe { *bufp.add((k + n) as usize) });
                    if m < 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::F_INT_118) };
                        break 'outer 0;
                    }
                    // SAFETY: `num + jj < slen` by the growth above.
                    let cell = unsafe { s.as_ptr().add((num + jj) as usize) };
                    // SAFETY: `cell` is a live octet.
                    unsafe { *cell = (*cell << 4) | (m as u8) };
                    n += 1;
                }
                jj += 1;
                k += 2;
            }
            num += i;
            if again {
                // SAFETY: `bp` is a live BIO and `buf` is writable for `size` bytes.
                bufsize = unsafe { BIO_gets(bp, buf, size) };
            } else {
                break 'outer 1;
            }
        };

        if outcome == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::F_INT_135) };
            return 0;
        }
        // SAFETY: `bs` is the caller's live string and takes the buffer.
        unsafe {
            (*bs).length = num;
            (*bs).data = s.into_raw();
        }
        1
    })
}

/// `int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size)`
///
/// The integer reader with the type stamped afterwards, keeping only the sign bit — an
/// `ENUMERATED` and an `INTEGER` are the same bytes and the item is what says which one
/// this is. That is the same masking the decoder's content codec does.
///
/// # Safety
///
/// As [`a2i_ASN1_INTEGER`].
#[no_mangle]
pub unsafe extern "C" fn a2i_ASN1_ENUMERATED(
    bp: *mut crate::runtime::bio::Bio,
    bs: *mut Asn1String,
    buf: *mut c_char,
    size: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract passes through unchanged.
        let rv = unsafe { a2i_ASN1_INTEGER(bp, bs, buf, size) };
        if rv == 1 {
            // SAFETY: `bs` is the caller's live string.
            unsafe { (*bs).type_ = V_ASN1_INTEGER | ((*bs).type_ & V_ASN1_NEG) };
        }
        rv
    })
}

/// `int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size)`
///
/// The same reader for the string types, and it differs from the INTEGER one in four ways
/// that are all observable:
///
/// * an **empty** input is a success with a zero-length value, not a failure. `first`
///   tracks that: a `BIO_gets` failure on the first line breaks out and answers 1 with
///   `length == 0` and `data == NULL`, which is how a caller can read "no value" without
///   an error on the queue;
/// * the hex scan runs **backwards** from the end of the line, so it stops at the last
///   non-hex character rather than the first. A line whose *middle* is non-hex therefore
///   keeps everything up to the end rather than up to the offender — the opposite of the
///   INTEGER reader;
/// * there is no `00` prefix strip;
/// * the buffer grows with `OPENSSL_realloc` where the INTEGER reader uses
///   `OPENSSL_clear_realloc`. That difference is the authority's and is reproduced; the
///   *content* the two produce is the same, because each octet is written by a shift-and-or
///   whose second pass shifts the previous value out of the byte.
///
/// # Safety
///
/// `bp` must be a live BIO; `bs` must be a live `ASN1_STRING`; `buf` must be writable for
/// `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn a2i_ASN1_STRING(
    bp: *mut crate::runtime::bio::Bio,
    bs: *mut Asn1String,
    buf: *mut c_char,
    size: c_int,
) -> c_int {
    guard_ffi(0, || {
        let mut s = OwnedBuf::empty(F_STRING_FILE.as_ptr(), LINE);
        let mut slen: c_int = 0;
        let mut num: c_int = 0;
        let mut first = true;

        // SAFETY: `bp` is a live BIO and `buf` is writable for `size` bytes.
        let mut bufsize = unsafe { BIO_gets(bp, buf, size) };

        let outcome: c_int = 'outer: loop {
            if bufsize < 1 {
                if first {
                    // Nothing at all: a zero-length value, and no raise.
                    break 'outer 1;
                }
                break 'outer 0;
            }
            first = false;

            let mut i = bufsize;
            // SAFETY: `buf` holds `bufsize` bytes.
            if unsafe { *buf.add((i - 1) as usize) } == b'\n' as c_char {
                i -= 1;
                // SAFETY: the same byte, overwritten.
                unsafe { *buf.add(i as usize) = 0 };
            }
            if i == 0 {
                break 'outer 0;
            }
            // SAFETY: `i >= 1`.
            if unsafe { *buf.add((i - 1) as usize) } == b'\r' as c_char {
                i -= 1;
                // SAFETY: as above.
                unsafe { *buf.add(i as usize) = 0 };
            }
            if i == 0 {
                break 'outer 0;
            }
            // SAFETY: `i >= 1`.
            let again = unsafe { *buf.add((i - 1) as usize) } == b'\\' as c_char;

            // Backwards, so the scan stops at the last non-hex character. `j > 0` means a
            // line that is non-hex from its first byte keeps `i` unchanged.
            let mut j: c_int = i - 1;
            while j > 0 {
                // SAFETY: `j < i <= bufsize`.
                let ch = unsafe { *buf.add(j as usize) } as core::ffi::c_uchar;
                if !crate::runtime::ctype::ossl_isxdigit(c_int::from(ch)) {
                    i = j;
                    break;
                }
                j -= 1;
            }
            // SAFETY: `i <= bufsize`, inside the caller's buffer.
            unsafe { *buf.add(i as usize) = 0 };

            if i < 2 {
                break 'outer 0;
            }
            let bufp = buf as *const u8;

            let mut k: c_int = 0;
            i -= c_int::from(again);
            if i % 2 != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::F_STRING_92) };
                return 0;
            }
            i /= 2;
            if num + i > slen {
                // SAFETY: `s` is this call's buffer or null, which `OwnedBuf::realloc` accepts.
                if unsafe { s.realloc((num + i * 2) as usize) }.is_none() {
                    return 0;
                }
                slen = num + i * 2;
            }
            let mut jj: c_int = 0;
            while jj < i {
                let mut n: c_int = 0;
                while n < 2 {
                    // SAFETY: `k + n < i * 2` and `bufp` is readable for that many.
                    let m = OPENSSL_hexchar2int(unsafe { *bufp.add((k + n) as usize) });
                    if m < 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::F_STRING_110) };
                        return 0;
                    }
                    // Shift-and-or, exactly as the INTEGER reader does and as the
                    // authority's own `s[num + j] <<= 4; s[num + j] |= m;` spells it. The
                    // first pass reads whatever the allocation held and shifts it into the
                    // high nibble; the second pass shifts it out of the octet entirely, so
                    // the result is the two digits and nothing else. Writing the digit
                    // instead of or-ing it produced `01` where the authority produces `41`
                    // for the text `414243`, which `RT-ASN1` caught.
                    // SAFETY: `num + jj < slen` by the growth above.
                    let cell = unsafe { s.as_ptr().add((num + jj) as usize) };
                    // SAFETY: `cell` is a live octet.
                    unsafe { *cell = (*cell << 4) | (m as u8) };
                    n += 1;
                }
                jj += 1;
                k += 2;
            }
            num += i;
            if again {
                // SAFETY: `bp` is a live BIO and `buf` is writable for `size` bytes.
                bufsize = unsafe { BIO_gets(bp, buf, size) };
            } else {
                break 'outer 1;
            }
        };

        if outcome == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::F_STRING_129) };
            return 0;
        }
        // SAFETY: `bs` is the caller's live string and takes the buffer.
        unsafe {
            (*bs).length = num;
            (*bs).data = s.into_raw();
        }
        1
    })
}
