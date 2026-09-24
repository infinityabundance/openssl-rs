//! Phase 5 — `ASN1_BIT_STRING`: the bit-level operations and the two content
//! codecs, from `crypto/asn1/a_bitstr.c` and `crypto/asn1/t_bitst.c`.
//!
//! A bit string is an `ASN1_STRING` whose content is a **big-endian bit
//! sequence** with a count of unused bits left in the last octet. Two facts about
//! that representation drive everything here:
//!
//! * The unused-bit count lives in the low three bits of `flags`, alongside
//!   `ASN1_STRING_FLAG_BITS_LEFT` (`0x08`). When that flag is clear the count is
//!   *derived* on output by scanning back over trailing zero octets — which is
//!   why setting a bit clears the flag and lets the count be recomputed.
//! * Consequently `ASN1_BIT_STRING_set_bit` **truncates** the string: after
//!   writing, it walks `length` down over trailing zero octets, so setting then
//!   clearing a bit does not leave the string its original length.
//!
//! ## The content codec's two asymmetries
//!
//! `ossl_i2c_ASN1_BIT_STRING` returns `1 + len` where `len` is the length *after*
//! the trailing-zero scan, and the count byte it writes is the number of bits
//! unused in the last surviving octet. It also masks that octet with
//! `0xff << bits`, discarding the bits the count says are not part of the value.
//! Both are observable: the mask is why a caller can hand it arbitrary low bits
//! and get the same bytes back.
//!
//! `ossl_c2i_ASN1_BIT_STRING` sets the string's length to `declared - 1` — the
//! count byte is consumed first — and `len == 1` therefore produces a *zero-length*
//! string rather than a one-octet one. It also reuses a caller-supplied string
//! rather than allocating, and on failure frees only what it allocated itself.
//!
//! ## The authority's own bug, reproduced
//!
//! On the allocation-failure path `ossl_c2i_ASN1_BIT_STRING` reaches `err` with
//! `i` still holding the **unused-bit count** it just read, and raises that as an
//! ASN1 reason code — so a failing decode of a bit string whose count byte was,
//! say, 3 puts reason 3 in the queue. It is defined behaviour and a caller can see
//! it, so it is reproduced rather than tidied. `i` is tracked as one variable
//! through this file for exactly that reason.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};

use crate::asn1::layout::*;
use crate::asn1::string::{
    as_str, as_str_mut, string_type_new, ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_set0,
};
use crate::ffi::guard_ffi;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_reasons;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site_dynamic;
use crate::runtime::mem::{CRYPTO_clear_realloc, CRYPTO_malloc};

extern "C" {
    /// `int strcmp(const char *, const char *)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// `int BIO_puts(BIO *, const char *)`.
    fn BIO_puts(bio: *mut Bio, buf: *const c_char) -> c_int;
}

/// The authority translation unit for the bit-string primitives.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_bitstr.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ossl_asn1_string_set_bits_left` — record the unused-bit count, from
/// `asn1_lib.c`.
///
/// The authority's own function is `str->flags &= ~0x07; str->flags |=
/// ASN1_STRING_FLAG_BITS_LEFT | (num & 0x07);` — note that it sets the flag and
/// never clears it, and that the count is masked rather than range-checked. A
/// caller is expected to have validated the count already, which is what
/// `ossl_c2i_ASN1_BIT_STRING` does before calling this.
///
/// # Safety
///
/// `a` must be a live `ASN1_STRING`.
pub(crate) unsafe fn set_bits_left(a: *mut Asn1String, num: c_int) {
    // SAFETY: the caller guarantees `a` is live and uniquely owned here.
    if let Some(s) = unsafe { as_str_mut(a) } {
        s.flags &= !0x07;
        s.flags |= ASN1_STRING_FLAG_BITS_LEFT | c_long::from(num & 0x07);
    }
}

/// `int ASN1_BIT_STRING_set(ASN1_BIT_STRING *x, unsigned char *d, int len)`
///
/// One line in the authority: it is `ASN1_STRING_set` with the bit string's own
/// name, and it deliberately does **not** touch `flags`. A caller that sets new
/// content therefore leaves the old unused-bit count in place until something
/// clears `BITS_LEFT` — which is what `ASN1_BIT_STRING_set_bit` does.
///
/// # Safety
///
/// `x` must be a live, uniquely-owned `ASN1_BIT_STRING`; `d` readable for `len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_set(
    x: *mut Asn1String,
    d: *mut c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: the caller's contract is `ASN1_STRING_set`'s.
    unsafe { ASN1_STRING_set(x, d.cast::<c_void>(), len) }
}

/// `int ossl_i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **pp)`
///
/// Answers the content length — the count byte plus the octets that survive the
/// trailing-zero scan — and writes the content when `pp` is non-null. The caller's
/// pointer is advanced past what was written.
///
/// # Safety
///
/// `a` must be null or a live bit string whose `data` holds `length` readable
/// bytes. `pp` must be null or point to a slot holding null or a pointer with room
/// for the content.
// The name is the authority's, and `ABI-PROTOTYPE` resolves implemented
// exports by it, so it is kept verbatim rather than snake-cased.
#[allow(non_snake_case)]
pub(crate) unsafe fn ossl_i2c_ASN1_BIT_STRING(a: *mut Asn1String, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: null-or-live per this function's `# Safety` section.
    let Some(s) = (unsafe { as_str(a) }) else {
        return 0;
    };
    // The authority reads `a->data` with only `a` checked for null, so a caller
    // that hand-filled the public struct with a positive `length` and a null
    // `data` faults on the first scan octet. Reporting empty content instead is
    // the documented divergence (docs/SECURITY_DIVERGENCE_POLICY.md).
    let mut len = if s.data.is_null() { 0 } else { s.length };
    let bits: c_int;
    if len > 0 {
        if s.flags & ASN1_STRING_FLAG_BITS_LEFT != 0 {
            bits = (s.flags & 0x07) as c_int;
        } else {
            // `for (; len > 0; len--)`: the scan leaves `len` holding the number of
            // octets that survive, and every later use — the returned length and
            // the copy — reads that decremented value.
            while len > 0 {
                // SAFETY: `len > 0 <= s.length`, so this octet is readable.
                if unsafe { *s.data.add((len - 1) as usize) } != 0 {
                    break;
                }
                len -= 1;
            }
            if len == 0 {
                bits = 0;
            } else {
                // SAFETY: `len > 0 <= s.length`, so this octet is readable.
                let j = unsafe { *s.data.add((len - 1) as usize) };
                // The count is the number of low-order zero bits in the last
                // surviving octet: a set bit 0x01 means no unused bits, 0x80 means
                // seven.
                bits = if j & 0x01 != 0 {
                    0
                } else if j & 0x02 != 0 {
                    1
                } else if j & 0x04 != 0 {
                    2
                } else if j & 0x08 != 0 {
                    3
                } else if j & 0x10 != 0 {
                    4
                } else if j & 0x20 != 0 {
                    5
                } else if j & 0x40 != 0 {
                    6
                } else if j & 0x80 != 0 {
                    7
                } else {
                    // Unreachable: the scan stopped on a non-zero octet.
                    0
                };
            }
        }
    } else {
        bits = 0;
    }

    let ret = 1 + len;
    if pp.is_null() {
        return ret;
    }
    // SAFETY: the caller offers a live slot.
    let mut p = unsafe { *pp };
    // SAFETY: the caller guarantees room for `ret` bytes at `p`.
    unsafe {
        *p = bits as c_uchar;
        p = p.add(1);
    }
    if len > 0 {
        // SAFETY: `s.data` holds the `len` octets the scan left, and the caller's
        // buffer holds `len` more writable bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(s.data, p, len as usize);
            p = p.add(len as usize);
            // The count says the low `bits` bits of the last octet are not part of
            // the value; `0xff << bits` clears them and keeps the rest.
            *p.sub(1) &= (0xffu16 << bits) as c_uchar;
        }
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *pp = p };
    ret
}

/// The authority's shared `err:` tail of `ossl_c2i_ASN1_BIT_STRING`: raise the
/// reason accumulated in `i`, release the value unless the caller already owned
/// it, and answer null.
///
/// # Safety
///
/// `a` must be null or a live slot holding null or a live bit string. `ret` must
/// be null or a live bit string that this call may release.
unsafe fn c2i_err(a: *mut *mut Asn1String, i: c_int, ret: *mut Asn1String) -> *mut Asn1String {
    if i != 0 {
        // SAFETY: a compile-time-constant site whose reason the authority computes
        // at run time; the generated table marks it `dynamic_reason`.
        unsafe { raise_site_dynamic(&err_sites::A_BITSTR_139, i) };
    }
    // The authority's rule is `if ((a == NULL) || (*a != ret)) free(ret)`: a value
    // the caller already held is the caller's to keep, and one this call allocated
    // is not.
    // SAFETY: `a` is null or a live slot, per the caller's contract.
    let caller_owns = !a.is_null() && unsafe { *a } == ret;
    if !caller_owns {
        // SAFETY: `ret` is null or a bit string this call allocated.
        unsafe { ASN1_STRING_free(ret) };
    }
    core::ptr::null_mut()
}

/// `ASN1_BIT_STRING *ossl_c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
/// const unsigned char **pp, long len)`
///
/// `len` is the declared content length, so the string it builds is `len - 1`
/// octets long: the first octet is the unused-bit count. `*pp` is advanced past
/// the whole declared content.
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must
/// be null or point to a slot holding null or a live bit string.
// The name is the authority's, and `ABI-PROTOTYPE` resolves implemented
// exports by it, so it is kept verbatim rather than snake-cased.
#[allow(non_snake_case)]
pub(crate) unsafe fn ossl_c2i_ASN1_BIT_STRING(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1String {
    if len < 1 {
        // SAFETY: the caller's contract is `c2i_err`'s; `a` is null or live.
        return unsafe {
            c2i_err(
                a,
                err_reasons::ASN1_R_STRING_TOO_SHORT,
                core::ptr::null_mut(),
            )
        };
    }
    if len > c_long::from(c_int::MAX) {
        // SAFETY: the caller's contract is `c2i_err`'s; `a` is null or live.
        return unsafe {
            c2i_err(
                a,
                err_reasons::ASN1_R_STRING_TOO_LONG,
                core::ptr::null_mut(),
            )
        };
    }

    // SAFETY: the caller's slot is readable.
    let existing = if a.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the caller's slot is readable, and `a` is non-null here.
        unsafe { *a }
    };
    let ret = if existing.is_null() {
        let fresh = string_type_new(V_ASN1_BIT_STRING);
        if fresh.is_null() {
            return core::ptr::null_mut();
        }
        fresh
    } else {
        existing
    };

    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *pp };
    // `i` is the authority's accumulator: it holds the count byte after this read
    // and is what the allocation-failure arm raises.
    // SAFETY: `p` is readable for the `len >= 1` bytes the check above proved.
    let mut i = c_int::from(unsafe { *p });
    // SAFETY: as above.
    p = unsafe { p.add(1) };
    if i > 7 {
        i = err_reasons::ASN1_R_INVALID_BIT_STRING_BITS_LEFT;
        // SAFETY: `ret` is live and this call may release it.
        return unsafe { c2i_err(a, i, ret) };
    }
    // The count is recorded before the content is copied, so the flag is set even
    // on the allocation failure below — which is why that arm has to free the
    // string rather than hand back a half-built one.
    // SAFETY: `ret` is live.
    unsafe { set_bits_left(ret, i) };

    let mut len = len;
    let s: *mut u8;
    if len > 1 {
        // The count byte is already consumed, so the content is `len - 1` octets.
        len -= 1;
        // SAFETY: `len` is the new allocation's size, and it is at least 1 here.
        let buf = CRYPTO_malloc(len as usize, FILE.as_ptr(), LINE) as *mut u8;
        if buf.is_null() {
            // Reaches `err` with `i` still holding the count byte, which the
            // authority then raises as a reason code. Reproduced; see the module
            // doc.
            // SAFETY: `ret` is live and this call may release it.
            return unsafe { c2i_err(a, i, ret) };
        }
        // SAFETY: `buf` holds `len` writable bytes and `p` is readable for the
        // same `len` bytes of content.
        unsafe {
            core::ptr::copy_nonoverlapping(p, buf, len as usize);
            *buf.add(len as usize - 1) &= (0xffu16 << i) as c_uchar;
        }
        // SAFETY: `p` is readable for those `len` bytes.
        p = unsafe { p.add(len as usize) };
        s = buf;
    } else {
        // The authority's `if (len-- > 1)` post-decrements, so a declared length of
        // exactly 1 leaves a length of 0 and no buffer at all.
        len -= 1;
        s = core::ptr::null_mut();
    }

    // SAFETY: `ret` is live and uniquely owned; `s` is a fresh allocation or null,
    // and ownership of it moves to the string.
    unsafe { ASN1_STRING_set0(ret, s.cast::<c_void>(), len as c_int) };
    // SAFETY: `ret` is live.
    unsafe { (*ret).type_ = V_ASN1_BIT_STRING };
    if !a.is_null() {
        // SAFETY: the caller's slot is writable.
        unsafe { *a = ret };
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *pp = p };
    ret
}

/// `int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value)`
///
/// Bit `n` is the `n & 7`-th bit *counting from the most significant end* of octet
/// `n / 8`, which is what makes the representation big-endian.
///
/// Clearing the flag and then re-deriving the count is what makes the truncation
/// below correct: after the write, trailing zero octets are dropped from `length`,
/// so the count that a later encode derives can never contradict the content.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned bit string.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_set_bit(
    a: *mut Asn1String,
    n: c_int,
    value: c_int,
) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        let w = n / 8;
        let mut v = 1i32 << (7 - (n & 0x07));
        let iv = !v;
        if value == 0 {
            v = 0;
        }
        // SAFETY: the caller's contract is null-or-live.
        let Some(s) = (unsafe { as_str_mut(a) }) else {
            return 0;
        };
        // Clearing the count is the point of this call, not incidental: a stale
        // count would describe the old content.
        s.flags &= !(ASN1_STRING_FLAG_BITS_LEFT | 0x07);

        if s.length < w + 1 || s.data.is_null() {
            if value == 0 {
                // Nothing to clear, and the authority does not grow a string just
                // to clear a bit past its end.
                return 1;
            }
            // `OPENSSL_clear_realloc` zeroes the bytes past the old end and cleanses
            // the old buffer. `old_len` is passed as the authority passes it — the
            // string's length — with a negative length clamped to 0 rather than
            // converted to a `size_t`, which is a divergence only for a struct a
            // caller filled in by hand (docs/SECURITY_DIVERGENCE_POLICY.md).
            // SAFETY: `s.data` came from this allocator or is null; the new size is
            // `w + 1`.
            let c = unsafe {
                CRYPTO_clear_realloc(
                    s.data.cast::<c_void>(),
                    s.length.max(0) as usize,
                    (w + 1) as usize,
                    FILE.as_ptr(),
                    LINE,
                )
            } as *mut u8;
            if c.is_null() {
                return 0;
            }
            if w + 1 - s.length > 0 {
                // SAFETY: `c` holds `w + 1` bytes, of which the first `s.length` are
                // the old content; the rest are zeroed.
                unsafe {
                    core::ptr::write_bytes(
                        c.add(s.length.max(0) as usize),
                        0,
                        (w + 1 - s.length.max(0)) as usize,
                    )
                };
            }
            s.data = c;
            s.length = w + 1;
        }
        // SAFETY: `s.length >= w + 1` and `s.data` is non-null, so octet `w` is
        // readable and writable.
        unsafe {
            let slot = s.data.add(w as usize);
            *slot = (*slot & iv as u8) | v as u8;
        }
        // SAFETY: `length > 0 <= top` keeps the read in range.
        while s.length > 0 && unsafe { *s.data.add((s.length - 1) as usize) } == 0 {
            s.length -= 1;
        }
        1
    })
}

/// `int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n)`
///
/// # Safety
///
/// `a` must be null or a live bit string.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_get_bit(a: *const Asn1String, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        let w = n / 8;
        let v = 1u8 << (7 - (n & 0x07));
        // SAFETY: the caller's contract is null-or-live.
        let Some(s) = (unsafe { as_str(a) }) else {
            return 0;
        };
        if s.length < w + 1 || s.data.is_null() {
            return 0;
        }
        // SAFETY: `s.length >= w + 1`, so octet `w` is readable.
        c_int::from(unsafe { *s.data.add(w as usize) } & v != 0)
    })
}

/// `int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a,
/// const unsigned char *flags, int flags_len)`
///
/// Answers 1 when no bit is set outside the ones `flags` allows: `flags[i]` names
/// the bits *permitted* in octet `i`, and octets past `flags_len` permit none.
/// A null or empty bit string answers 1 — there is no unneeded bit in nothing.
///
/// # Safety
///
/// `a` must be null or a live bit string; `flags` must be readable for
/// `flags_len` bytes when `flags_len` is positive.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_check(
    a: *const Asn1String,
    flags: *const c_uchar,
    flags_len: c_int,
) -> c_int {
    guard_ffi(1, || {
        // SAFETY: the caller's contract is null-or-live.
        let Some(s) = (unsafe { as_str(a) }) else {
            return 1;
        };
        if s.data.is_null() {
            return 1;
        }
        let mut ok = 1;
        let mut i: c_int = 0;
        while i < s.length && ok != 0 {
            // A null `flags` with a positive `flags_len` is a caller error the
            // authority dereferences through; treating it as "no bit permitted" is
            // the documented divergence (docs/SECURITY_DIVERGENCE_POLICY.md).
            let mask: u8 = if i < flags_len && !flags.is_null() {
                // SAFETY: `i < flags_len` and `flags` is readable for that many.
                !unsafe { *flags.add(i as usize) }
            } else {
                0xff
            };
            // SAFETY: `i < s.length`, so octet `i` is readable.
            ok = c_int::from(unsafe { *s.data.add(i as usize) } & mask == 0);
            i += 1;
        }
        ok
    })
}

/// `int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
/// BIT_STRING_BITNAME *tbl, int indent)`
///
/// Writes the long name of every bit `bs` has set that `tbl` names, separated by
/// `", "`. Two rules are easy to miss:
///
/// * the table is terminated by a **null `lname`**, not by a count;
/// * a row whose `bitnum` repeats the previous row's is skipped, so a bit that has
///   both a long and a short name is printed once, under whichever spelling the
///   table lists first.
///
/// The indentation is `BIO_printf(out, "%*s", indent, "")`, and the newline is
/// written whether or not anything matched — so a bit string with no named bits
/// set still produces a line containing only the indentation.
///
/// # Safety
///
/// `out` must be a live BIO; `bs` must be null or a live bit string; `tbl` must be
/// a live array whose first null `lname` terminates it.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_name_print(
    out: *mut Bio,
    bs: *mut Asn1String,
    tbl: *mut BitStringBitname,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BIO_printf`'s contract; `out` is live per the caller's.
        unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
        let mut first = true;
        let mut last_seen_bit: c_int = -1;
        let mut bnam = tbl;
        loop {
            // The authority's `for` condition dereferences `bnam->lname` before it
            // tests it, so a null table faults; stopping instead is the documented
            // divergence (docs/SECURITY_DIVERGENCE_POLICY.md).
            if bnam.is_null() {
                break;
            }
            // SAFETY: `bnam` points into the caller's table, which is `lname`-terminated.
            let row = unsafe { &*bnam };
            if row.lname.is_null() {
                break;
            }
            if last_seen_bit == row.bitnum {
                // An alias for the bit just printed: the first spelling wins.
                // SAFETY: still inside the caller's table.
                bnam = unsafe { bnam.add(1) };
                continue;
            }
            last_seen_bit = row.bitnum;
            // SAFETY: `bs` is null or live and the row's `bitnum` is the caller's.
            if unsafe { ASN1_BIT_STRING_get_bit(bs, row.bitnum) } != 0 {
                if !first {
                    // SAFETY: `out` is a live BIO.
                    unsafe { BIO_puts(out, c", ".as_ptr()) };
                }
                // SAFETY: `out` is live; `lname` is non-null by the check above.
                unsafe { BIO_puts(out, row.lname) };
                first = false;
            }
            // SAFETY: still inside the caller's table.
            bnam = unsafe { bnam.add(1) };
        }
        // SAFETY: `out` is a live BIO.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
        1
    })
}

/// `int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, const char *name,
/// int value, BIT_STRING_BITNAME *tbl)`
///
/// Answers 0 when the name is not in the table; otherwise sets (or clears) the
/// named bit and answers 1. Note the direction: a *successful* lookup that fails
/// to set the bit answers 0 too, so a caller cannot tell "no such name" from
/// "could not grow the string" except through the error queue.
///
/// # Safety
///
/// As [`ASN1_BIT_STRING_name_print`], and `name` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_set_asc(
    bs: *mut Asn1String,
    name: *const c_char,
    value: c_int,
    tbl: *mut BitStringBitname,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `name` is NUL-terminated and `tbl` is the caller's, per the
        // caller's contract.
        let bitnum = unsafe { ASN1_BIT_STRING_num_asc(name, tbl) };
        if bitnum < 0 {
            return 0;
        }
        if !bs.is_null() {
            // SAFETY: `bs` is null or a live, uniquely-owned bit string.
            if unsafe { ASN1_BIT_STRING_set_bit(bs, bitnum, value) } == 0 {
                return 0;
            }
        }
        1
    })
}

/// `int ASN1_BIT_STRING_num_asc(const char *name, BIT_STRING_BITNAME *tbl)`
///
/// The bit number a name maps to, or -1. Both the short and the long spelling are
/// accepted, so `tbl` rows whose `sname` and `lname` differ make the name set a
/// superset of the printed names.
///
/// # Safety
///
/// `tbl` must be a live array whose first null `lname` terminates it; `name` must
/// be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ASN1_BIT_STRING_num_asc(
    name: *const c_char,
    tbl: *mut BitStringBitname,
) -> c_int {
    guard_ffi(-1, || {
        // The authority passes `name` straight to `strcmp`; a null `name` faults
        // there, and reporting "not named" instead is the documented divergence
        // (docs/SECURITY_DIVERGENCE_POLICY.md).
        if name.is_null() {
            return -1;
        }
        let mut bnam = tbl;
        loop {
            // SAFETY: same null-table divergence as `name_print`.
            if bnam.is_null() {
                break;
            }
            // SAFETY: `bnam` points into the caller's `lname`-terminated table.
            let row = unsafe { &*bnam };
            if row.lname.is_null() {
                break;
            }
            // SAFETY: `row.sname` and `row.lname` are non-null by the table's own
            // contract, and `name` is NUL-terminated per the caller's.
            if (!row.sname.is_null() && unsafe { strcmp(row.sname, name) } == 0)
                // SAFETY: `row.lname` is non-null by the check above; `name` is NUL-terminated.
                || unsafe { strcmp(row.lname, name) } == 0
            {
                return row.bitnum;
            }
            // SAFETY: still inside the caller's table.
            bnam = unsafe { bnam.add(1) };
        }
        -1
    })
}
