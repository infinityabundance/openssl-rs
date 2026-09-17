//! Phase 5 — `x_long.c`: the `LONG` and `ZLONG` primitives.
//!
//! These two are the odd ones out among the numeric items, and the oddity is the whole
//! content of the file: **the value is stored in the value slot itself**, not behind it.
//! `long_new` is `memcpy(pval, &it->size, sizeof(long))` — it writes the item's `size`
//! field into the eight bytes of the slot and calls that the initial value. `long_i2c`
//! reads eight bytes *from the slot*, `long_c2i` writes eight bytes back into it, and
//! `long_free` restores the sentinel.
//!
//! The consequence is that a caller never dereferences a `LONG *`. It passes an
//! `ASN1_VALUE *` whose eight bytes are the number, exactly as a `BOOLEAN`'s four bytes
//! are its value. That is why `prim_new` here allocates nothing and `prim_free` releases
//! nothing: there is no pointer, only a slot.
//!
//! ## `size` is the undefined-value sentinel
//!
//! `LONG_it`'s `size` is `ASN1_LONG_UNDEF` (`0x7fffffff`) and `ZLONG_it`'s is `0`. A value
//! equal to it encodes as **nothing** — the encoder's "omit" — and decodes as
//! `ASN1_R_INTEGER_TOO_LARGE_FOR_LONG`, because that number is reserved and cannot be
//! represented. So `ZLONG` treats zero as absent and `LONG` treats `0x7fffffff` as absent,
//! which is the only difference between the two items.
//!
//! ## The negative encoding subtracts one
//!
//! A negative value is turned positive by `0 - (unsigned long)ltmp - 1` and then encoded
//! under an `0xff` mask, so the padding decision and the two's-complement are one
//! arithmetic step rather than two. That is the authority's own comment, and it is why the
//! decode side's `ltmp = -ltmp - 1` is the mirror rather than a sign flip.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};

use crate::asn1::items::funcs_item;
use crate::asn1::layout::*;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `ASN1_LONG_UNDEF` — the value `LONG_it` reserves as "no value here".
///
/// `include/openssl/asn1.h.in` defines it as `0x7fffffffL`, which is why it is exactly
/// representable in a `long` and why a caller can never distinguish "unset" from "set to
/// `0x7fffffff`" by looking at the slot.
const ASN1_LONG_UNDEF: c_long = 0x7fff_ffff;

/// `num_bits_ulong` — how many significant bits a `unsigned long` has.
///
/// Written as the authority's constant-counter loop rather than as
/// `64 - leading_zeros()`, so that the "averaged over a real workload" argument in its
/// comment stays attached to the same code. The two answer the same number; this one says
/// why it is shaped that way.
fn num_bits_ulong(mut value: c_ulong) -> c_int {
    let mut ret: c_int = 0;
    for _ in 0..(core::mem::size_of::<c_ulong>() * 8) {
        if value != 0 {
            ret += 1;
        }
        value >>= 1;
    }
    ret
}

/// `int long_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// The slot's eight bytes become the item's `size` field. `memcpy` of `COPY_SIZE(*pval,
/// it->size)`, which is 8 on this target, is what stores the sentinel.
///
/// # Safety
///
/// `pval` must be a live slot at least `size_of::<c_long>()` bytes wide; `it` must be live.
unsafe extern "C" fn long_new(pval: *mut *mut c_void, it: *const Asn1Item) -> c_int {
    // SAFETY: `it` is a live item.
    let sentinel = unsafe { (*it).size };
    // SAFETY: `pval` is a live slot wide enough to hold a `long`, per the caller.
    unsafe { core::ptr::write_unaligned(pval.cast::<c_long>(), sentinel) };
    1
}

/// `void long_free(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// Releases nothing: the value is in the slot, so putting the sentinel back *is* the
/// release. It is also this hook that `prim_clear` uses, because clearing a `LONG` back to
/// its initial value and freeing it are the same operation.
///
/// # Safety
///
/// As [`long_new`].
unsafe extern "C" fn long_free(pval: *mut *mut c_void, it: *const Asn1Item) {
    // SAFETY: `it` is a live item.
    let sentinel = unsafe { (*it).size };
    // SAFETY: as in `long_new`.
    unsafe { core::ptr::write_unaligned(pval.cast::<c_long>(), sentinel) };
}

/// `int long_i2c(const ASN1_VALUE **pval, unsigned char *cont, int *putype,
/// const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must point to a live slot at least `size_of::<c_long>()` bytes wide;
/// `cont` must be null or writable for the length this answers; `it` must be live.
unsafe extern "C" fn long_i2c(
    pval: *mut *const c_void,
    cont: *mut c_uchar,
    _putype: *mut c_int,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract is a slot holding the value.
    let ltmp = unsafe { core::ptr::read_unaligned(pval.cast::<c_long>()) };
    // SAFETY: `it` is a live item.
    let sentinel = unsafe { (*it).size };
    if ltmp == sentinel {
        // The reserved value: the encoder's "omit this type".
        return -1;
    }
    let utmp: c_ulong;
    let sign: c_ulong;
    if ltmp < 0 {
        sign = 0xff;
        // One is subtracted so the padding decision below and the two's complement are
        // one step: the authority's comment gives that as the reason.
        utmp = (0 as c_ulong).wrapping_sub(ltmp as c_ulong).wrapping_sub(1);
    } else {
        sign = 0;
        utmp = ltmp as c_ulong;
    }
    let mut bits = num_bits_ulong(utmp);
    // A leading octet whose top bit is set needs a padding octet to keep it positive.
    let pad: c_int = if bits & 0x7 == 0 { 1 } else { 0 };
    bits = (bits + 7) >> 3;

    if !cont.is_null() {
        let mut cursor = cont;
        if pad != 0 {
            // SAFETY: `cursor` is writable per the caller's contract.
            unsafe { *cursor = sign as c_uchar };
            // SAFETY: as above.
            cursor = unsafe { cursor.add(1) };
        }
        let mut v = utmp;
        // Written back to front, which is why the authority's loop counts down: the
        // least significant octet is taken first but lands last.
        let mut i = bits - 1;
        while i >= 0 {
            // SAFETY: `cursor` is writable for `bits` octets.
            unsafe { *cursor.add(i as usize) = (v ^ sign) as c_uchar };
            v >>= 8;
            i -= 1;
        }
    }
    bits + pad
}

/// `int long_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
/// char *free_cont, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot at least `size_of::<c_long>()` bytes wide; `cont` must be
/// readable for `len` bytes; `it` must be live.
unsafe extern "C" fn long_c2i(
    pval: *mut *mut c_void,
    cont: *const c_uchar,
    len_in: c_int,
    _utype: c_int,
    _free_cont: *mut core::ffi::c_char,
    it: *const Asn1Item,
) -> c_int {
    let mut len = len_in;
    let mut cont = cont;
    // `0x100` is not a byte value: it is the "not yet decided" marker the sign starts at,
    // and it is why the padding check below can tell "no padding byte" from "a zero pad".
    let mut sign: c_ulong = 0x100;

    if len > 1 {
        // The worst case here is skipping a real octet, which the sign handling below
        // makes harmless; the authority's comment says so.
        // SAFETY: `len > 1` means the first octet is readable.
        match unsafe { *cont } {
            0xff => {
                // SAFETY: advancing within the readable extent.
                cont = unsafe { cont.add(1) };
                len -= 1;
                sign = 0xff;
            }
            0 => {
                // SAFETY: as above.
                cont = unsafe { cont.add(1) };
                len -= 1;
                sign = 0;
            }
            _ => {}
        }
    }
    if len > core::mem::size_of::<c_long>() as c_int {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X_LONG_154) };
        return 0;
    }

    if sign == 0x100 {
        // No padding octet was consumed, so the sign comes from the content itself.
        let negative = len != 0
            // SAFETY: `len != 0` means the first octet is readable.
            && (unsafe { *cont } & 0x80) != 0;
        sign = if negative { 0xff } else { 0 };
    } else {
        // A padding octet was consumed, so the octet now at the front must *disagree* with
        // its sign bit: an all-zero pad followed by a byte whose top bit is clear is a
        // number that should have been shorter.
        // SAFETY: the argument above bounds the read by `len`, and the padding path left
        // at least one octet.
        let same = ((sign ^ c_ulong::from(unsafe { *cont })) & 0x80) == 0;
        if same {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X_LONG_165) };
            return 0;
        }
    }

    let mut utmp: c_ulong = 0;
    let mut i: c_int = 0;
    while i < len {
        utmp <<= 8;
        // SAFETY: `i < len` and `cont` is readable for `len` octets.
        utmp |= c_ulong::from(unsafe { *cont.add(i as usize) ^ sign as c_uchar });
        i += 1;
    }
    let mut ltmp = utmp as c_long;
    if ltmp < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X_LONG_175) };
        return 0;
    }
    if sign != 0 {
        ltmp = -ltmp - 1;
    }
    // SAFETY: `it` is a live item.
    if ltmp == unsafe { (*it).size } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X_LONG_181) };
        return 0;
    }
    // SAFETY: `pval` is a live slot wide enough for a `long`.
    unsafe { core::ptr::write_unaligned(pval.cast::<c_long>(), ltmp) };
    1
}

/// `int long_print(BIO *out, const ASN1_VALUE **pval, const ASN1_ITEM *it, int indent,
/// const ASN1_PCTX *pctx)`
///
/// # Safety
///
/// `out` must be a live BIO; `pval` must point to a live slot holding a `long`.
unsafe extern "C" fn long_print(
    out: *mut crate::runtime::bio::Bio,
    pval: *mut *const c_void,
    _it: *const Asn1Item,
    _indent: c_int,
    _pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: the caller's contract is a slot holding the value.
    let l = unsafe { core::ptr::read_unaligned(pval.cast::<c_long>()) };
    // SAFETY: `out` is a live BIO and the format matches the argument.
    unsafe { BIO_printf(out, c"%ld\n".as_ptr(), l) }
}

/// The hooks both items share. `prim_clear` is `long_free`, as the authority's own comment
/// on that line says: clearing a `LONG` back to its initial value *is* putting the
/// sentinel back.
static LONG_PF: Asn1PrimitiveFuncs = Asn1PrimitiveFuncs {
    app_data: core::ptr::null_mut(),
    flags: 0,
    prim_new: Some(long_new),
    prim_free: Some(long_free),
    prim_clear: Some(long_free),
    prim_c2i: Some(long_c2i),
    prim_i2c: Some(long_i2c),
    prim_print: Some(long_print),
};

funcs_item!(
    LONG_ITEM,
    LONG_it,
    LONG_PF,
    ASN1_LONG_UNDEF,
    c"LONG",
    "`const ASN1_ITEM *LONG_it(void)` — `x_long.c`'s `ASN1_ITEM_start(LONG)`. `size` is \
     `ASN1_LONG_UNDEF`, so `0x7fffffff` is the absent value and can never be encoded."
);
funcs_item!(
    ZLONG_ITEM,
    ZLONG_it,
    LONG_PF,
    0,
    c"ZLONG",
    "`const ASN1_ITEM *ZLONG_it(void)` — the same hooks with `size` 0, so **zero** is the \
     absent value. That is the only difference between the two items."
);
