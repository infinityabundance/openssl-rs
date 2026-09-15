//! Phase 5 — `x_int64.c`: the eight fixed-width integer primitives.
//!
//! These exist because `LONG` and `ZLONG` are only as wide as `long`, and the authority
//! wanted `int32_t`/`uint32_t`/`int64_t`/`uint64_t` to round-trip through an `ASN1_INTEGER`
//! exactly. The file's own comment says so, and adds that this is "preferred to using the
//! LONG / ZLONG primitives".
//!
//! ## `size` is a flags word
//!
//! Every item here writes `INTxx_FLAG_*` into the item's `size` field and its hooks read
//! it back. Two flags exist:
//!
//! * `ZERO_DEFAULT` — a zero encodes as **nothing at all** (`-1` from `prim_i2c`, the
//!   "omit this type" answer), which is how `DEFAULT 0` is spelled in a template.
//! * `SIGNED` — the value is read back as a signed integer of its own width, so a
//!   negative value encodes with a sign and a magnitude outside the signed range is
//!   refused at decode time.
//!
//! ## The three encodes that look like special cases
//!
//! * A magnitude of zero with `ZERO_DEFAULT` set returns `-1`. That is not a failure: it
//!   is the encoder's "omit".
//! * A negative value is encoded as its magnitude with `neg` set, because
//!   `ossl_i2c_uint64_int` assumes a positive input and applies the sign itself.
//! * A **zero-length** content decodes as zero. The authority's comment calls this
//!   strictly malformed and keeps it anyway, because `x_long.c` encodes zero as a
//!   zero-length `INTEGER` — wrongly, its own words — and refusing it here would break
//!   values written by that encoder.
//!
//! The `memcpy` in and out of the value is deliberate and is not an alignment dodge: the
//! value is a pointer-sized slot that may hold a four-byte integer, so the read and the
//! write must both take exactly the integer's own width and not the slot's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};

use crate::asn1::items::funcs_item;
use crate::asn1::layout::*;
use crate::asn1::prim::{ossl_c2i_uint64_int, ossl_i2c_uint64_int};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// A zero value encodes as an absent field.
const INTXX_FLAG_ZERO_DEFAULT: c_long = 1 << 0;
/// The value is signed at its own width.
const INTXX_FLAG_SIGNED: c_long = 1 << 1;

/// `ABS_INT32_MIN` — the absolute value of `INT32_MIN`, which cannot be written as
/// `-INT32_MIN` without overflowing.
const ABS_INT32_MIN: u64 = i32::MAX as u64 + 1;

/// `int uint64_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot.
unsafe extern "C" fn uint64_new(pval: *mut *mut c_void, _it: *const Asn1Item) -> c_int {
    // SAFETY: `pval` is the caller's slot; a zeroed eight-byte allocation is the value.
    let v = CRYPTO_zalloc(8, FILE.as_ptr(), LINE);
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = v };
    if v.is_null() {
        0
    } else {
        1
    }
}

/// `void uint64_free(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot holding null or a value this module allocated.
unsafe extern "C" fn uint64_free(pval: *mut *mut c_void, _it: *const Asn1Item) {
    // SAFETY: `pval` is a live slot.
    let v = unsafe { *pval };
    // SAFETY: `v` came from this allocator or is null, which `CRYPTO_free` accepts.
    unsafe { CRYPTO_free(v, FILE.as_ptr(), LINE) };
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = core::ptr::null_mut() };
}

/// `void uint64_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot holding a live eight-byte value.
unsafe extern "C" fn uint64_clear(pval: *mut *mut c_void, _it: *const Asn1Item) {
    // SAFETY: the caller's contract is a live eight-byte value behind the slot.
    unsafe { *(*pval).cast::<u64>() = 0 };
}

/// `int uint64_i2c(const ASN1_VALUE **pval, unsigned char *cont, int *putype,
/// const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must point to a live slot holding a live eight-byte value; `cont` must be null
/// or writable for the length this answers.
unsafe extern "C" fn uint64_i2c(
    pval: *const *const c_void,
    cont: *mut c_uchar,
    _putype: *mut c_int,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract.
    let mut utmp = unsafe { core::ptr::read_unaligned((*pval).cast::<u64>()) };
    let mut neg = 0;
    // SAFETY: `it` is a live item.
    let flags = unsafe { (*it).size };

    if flags & INTXX_FLAG_ZERO_DEFAULT == INTXX_FLAG_ZERO_DEFAULT && utmp == 0 {
        // The encoder's "omit this type" answer, not a failure.
        return -1;
    }
    if flags & INTXX_FLAG_SIGNED == INTXX_FLAG_SIGNED && (utmp as i64) < 0 {
        // The codec assumes a positive magnitude and is told the sign separately.
        utmp = 0u64.wrapping_sub(utmp);
        neg = 1;
    }

    // SAFETY: `cont` is null or the caller's destination.
    unsafe { ossl_i2c_uint64_int(cont, utmp, neg) }
}

/// `int uint64_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
/// char *free_cont, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot; `cont` must be readable for `len` bytes; `it` must be live.
unsafe extern "C" fn uint64_c2i(
    pval: *mut *mut c_void,
    cont: *const c_uchar,
    len: c_int,
    _utype: c_int,
    _free_cont: *mut c_char,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: `pval` is a live slot.
    let mut utmp: u64 = 0;
    let mut neg: c_int = 0;
    // SAFETY: `pval` is a live slot and `it` is the caller's item.
    if unsafe { *pval }.is_null() && unsafe { uint64_new(pval, it) } == 0 {
        return 0;
    }
    // SAFETY: `pval` is a live slot holding this module's value.
    let cp = unsafe { *pval }.cast::<u64>();
    // SAFETY: `it` is a live item.
    let flags = unsafe { (*it).size };

    // A zero-length content is malformed in the specification and accepted here for
    // `x_long.c`'s sake: see the module documentation.
    if len != 0 {
        let mut cursor = cont;
        // SAFETY: `cursor` is readable for `len` bytes and the outputs are local slots.
        if unsafe { ossl_c2i_uint64_int(&mut utmp, &mut neg, &mut cursor, c_long::from(len)) } == 0
        {
            return 0;
        }
        if flags & INTXX_FLAG_SIGNED == 0 && neg != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X_INT64_95) };
            return 0;
        }
        if flags & INTXX_FLAG_SIGNED == INTXX_FLAG_SIGNED && neg == 0 && utmp > i64::MAX as u64 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X_INT64_100) };
            return 0;
        }
        if neg != 0 {
            // The codec answers positive magnitudes.
            utmp = 0u64.wrapping_sub(utmp);
        }
    }
    // SAFETY: `cp` is a live eight-byte value.
    unsafe { core::ptr::write_unaligned(cp, utmp) };
    1
}

/// `int uint64_print(BIO *out, const ASN1_VALUE **pval, const ASN1_ITEM *it, int indent,
/// const ASN1_PCTX *pctx)`
///
/// # Safety
///
/// `out` must be a live BIO; `pval` must point to a live slot holding a live eight-byte
/// value; `it` must be live.
unsafe extern "C" fn uint64_print(
    out: *mut crate::runtime::bio::Bio,
    pval: *const *const c_void,
    it: *const Asn1Item,
    _indent: c_int,
    _pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: `pval` is a live slot holding this module's value.
    let v = unsafe { core::ptr::read_unaligned((*pval).cast::<u64>()) };
    // SAFETY: `it` is a live item.
    let signed = unsafe { (*it).size } & INTXX_FLAG_SIGNED == INTXX_FLAG_SIGNED;
    if signed {
        // SAFETY: `out` is a live BIO and the format matches the argument.
        unsafe { BIO_printf(out, c"%jd\n".as_ptr(), v as i64) }
    } else {
        // SAFETY: as above.
        unsafe { BIO_printf(out, c"%ju\n".as_ptr(), v) }
    }
}

/// `int uint32_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot.
unsafe extern "C" fn uint32_new(pval: *mut *mut c_void, _it: *const Asn1Item) -> c_int {
    // SAFETY: `pval` is the caller's slot.
    let v = CRYPTO_zalloc(4, FILE.as_ptr(), LINE);
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = v };
    if v.is_null() {
        0
    } else {
        1
    }
}

/// `void uint32_free(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot holding null or a value this module allocated.
unsafe extern "C" fn uint32_free(pval: *mut *mut c_void, _it: *const Asn1Item) {
    // SAFETY: `pval` is a live slot.
    let v = unsafe { *pval };
    // SAFETY: `v` came from this allocator or is null.
    unsafe { CRYPTO_free(v, FILE.as_ptr(), LINE) };
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = core::ptr::null_mut() };
}

/// `void uint32_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot holding a live four-byte value.
unsafe extern "C" fn uint32_clear(pval: *mut *mut c_void, _it: *const Asn1Item) {
    // SAFETY: the caller's contract is a live four-byte value behind the slot.
    unsafe { *(*pval).cast::<u32>() = 0 };
}

/// `int uint32_i2c(const ASN1_VALUE **pval, unsigned char *cont, int *putype,
/// const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must point to a live slot holding a live four-byte value; `cont` must be null or
/// writable for the length this answers.
unsafe extern "C" fn uint32_i2c(
    pval: *const *const c_void,
    cont: *mut c_uchar,
    _putype: *mut c_int,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract.
    let mut utmp = unsafe { core::ptr::read_unaligned((*pval).cast::<u32>()) };
    let mut neg = 0;
    // SAFETY: `it` is a live item.
    let flags = unsafe { (*it).size };

    if flags & INTXX_FLAG_ZERO_DEFAULT == INTXX_FLAG_ZERO_DEFAULT && utmp == 0 {
        return -1;
    }
    if flags & INTXX_FLAG_SIGNED == INTXX_FLAG_SIGNED && (utmp as i32) < 0 {
        // The negation is at **32-bit** width, which is the whole point of this hook
        // existing beside the 64-bit one: `0 - 0xfffffffb` is 5 in a `uint32_t` and
        // 0xffffffff00000005 in a `uint64_t`. Widening first and negating second produced
        // the second, which encoded `-5` as nine octets instead of one. `RT-ASN1-TEMPLATE`
        // is what found it.
        utmp = 0u32.wrapping_sub(utmp);
        neg = 1;
    }

    // SAFETY: `cont` is null or the caller's destination.
    unsafe { ossl_i2c_uint64_int(cont, u64::from(utmp), neg) }
}

/// `int uint32_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
/// char *free_cont, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot; `cont` must be readable for `len` bytes; `it` must be live.
unsafe extern "C" fn uint32_c2i(
    pval: *mut *mut c_void,
    cont: *const c_uchar,
    len: c_int,
    _utype: c_int,
    _free_cont: *mut c_char,
    it: *const Asn1Item,
) -> c_int {
    let mut utmp: u64 = 0;
    let mut neg: c_int = 0;
    // SAFETY: `pval` is a live slot and `it` is the caller's item. The authority calls
    // `uint64_new` here, not `uint32_new` — an eight-byte value for a four-byte type,
    // which is a real property of the authority and is reproduced rather than tidied.
    if unsafe { *pval }.is_null() && unsafe { uint64_new(pval, it) } == 0 {
        return 0;
    }
    // SAFETY: `pval` is a live slot holding this module's value.
    let cp = unsafe { *pval }.cast::<u32>();
    // SAFETY: `it` is a live item.
    let flags = unsafe { (*it).size };

    if len != 0 {
        let mut cursor = cont;
        // SAFETY: `cursor` is readable for `len` bytes and the outputs are local slots.
        if unsafe { ossl_c2i_uint64_int(&mut utmp, &mut neg, &mut cursor, c_long::from(len)) } == 0
        {
            return 0;
        }
        if flags & INTXX_FLAG_SIGNED == 0 && neg != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X_INT64_196) };
            return 0;
        }
        if neg != 0 {
            if utmp > ABS_INT32_MIN {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::X_INT64_201) };
                return 0;
            }
            utmp = 0u64.wrapping_sub(utmp);
        } else if (flags & INTXX_FLAG_SIGNED != 0 && utmp > i32::MAX as u64)
            || (flags & INTXX_FLAG_SIGNED == 0 && utmp > u32::MAX as u64)
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X_INT64_208) };
            return 0;
        }
    }
    // The value is stored as four bytes whatever the eight-byte allocation: the
    // authority's `utmp2 = (uint32_t)utmp` is this truncation, and the upper four bytes of
    // the allocation are left zeroed by `uint64_new`.
    // SAFETY: `cp` is a live four-byte value.
    unsafe { core::ptr::write_unaligned(cp, utmp as u32) };
    1
}

/// `int uint32_print(BIO *out, const ASN1_VALUE **pval, const ASN1_ITEM *it, int indent,
/// const ASN1_PCTX *pctx)`
///
/// # Safety
///
/// `out` must be a live BIO; `pval` must point to a live slot holding a live four-byte
/// value; `it` must be live.
unsafe extern "C" fn uint32_print(
    out: *mut crate::runtime::bio::Bio,
    pval: *const *const c_void,
    it: *const Asn1Item,
    _indent: c_int,
    _pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: `pval` is a live slot holding this module's value.
    let v = unsafe { core::ptr::read_unaligned((*pval).cast::<u32>()) };
    // SAFETY: `it` is a live item.
    let signed = unsafe { (*it).size } & INTXX_FLAG_SIGNED == INTXX_FLAG_SIGNED;
    if signed {
        // SAFETY: `out` is a live BIO and the format matches the argument.
        unsafe { BIO_printf(out, c"%d\n".as_ptr(), v as i32) }
    } else {
        // SAFETY: as above.
        unsafe { BIO_printf(out, c"%u\n".as_ptr(), v) }
    }
}

/// `x_int64.c`'s translation unit, for the allocator's file/line record.
const FILE: &core::ffi::CStr = c"crypto/asn1/x_int64.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// The `uint32_t` hooks, shared by the four 32-bit items.
static UINT32_PF: Asn1PrimitiveFuncs = Asn1PrimitiveFuncs {
    app_data: core::ptr::null_mut(),
    flags: 0,
    prim_new: Some(uint32_new),
    prim_free: Some(uint32_free),
    prim_clear: Some(uint32_clear),
    prim_c2i: Some(uint32_c2i),
    prim_i2c: Some(uint32_i2c),
    prim_print: Some(uint32_print),
};

/// The `uint64_t` hooks, shared by the four 64-bit items.
static UINT64_PF: Asn1PrimitiveFuncs = Asn1PrimitiveFuncs {
    app_data: core::ptr::null_mut(),
    flags: 0,
    prim_new: Some(uint64_new),
    prim_free: Some(uint64_free),
    prim_clear: Some(uint64_clear),
    prim_c2i: Some(uint64_c2i),
    prim_i2c: Some(uint64_i2c),
    prim_print: Some(uint64_print),
};

funcs_item!(
    INT32_ITEM,
    INT32_it,
    UINT32_PF,
    INTXX_FLAG_SIGNED,
    c"INT32",
    "`const ASN1_ITEM *INT32_it(void)` — `x_int64.c`'s `ASN1_ITEM_start(INT32)`, whose \
     only flag is `SIGNED`. The value is a `int32_t` in a four-byte allocation."
);
funcs_item!(
    UINT32_ITEM,
    UINT32_it,
    UINT32_PF,
    0,
    c"UINT32",
    "`const ASN1_ITEM *UINT32_it(void)` — the unsigned counterpart, with no flags at all, \
     so a zero encodes as a zero rather than as an absent field."
);
funcs_item!(
    INT64_ITEM,
    INT64_it,
    UINT64_PF,
    INTXX_FLAG_SIGNED,
    c"INT64",
    "`const ASN1_ITEM *INT64_it(void)` — `SIGNED` over the eight-byte hooks, so a value \
     outside the signed 64-bit range is refused at decode time rather than truncated."
);
funcs_item!(
    UINT64_ITEM,
    UINT64_it,
    UINT64_PF,
    0,
    c"UINT64",
    "`const ASN1_ITEM *UINT64_it(void)` — the unsigned eight-byte item."
);
funcs_item!(
    ZINT32_ITEM,
    ZINT32_it,
    UINT32_PF,
    INTXX_FLAG_ZERO_DEFAULT | INTXX_FLAG_SIGNED,
    c"ZINT32",
    "`const ASN1_ITEM *ZINT32_it(void)` — signed with `ZERO_DEFAULT`, so a zero encodes as \
     nothing. That is how a template spells `DEFAULT 0`, and it is the only difference from \
     `INT32` at the byte level."
);
funcs_item!(
    ZUINT32_ITEM,
    ZUINT32_it,
    UINT32_PF,
    INTXX_FLAG_ZERO_DEFAULT,
    c"ZUINT32",
    "`const ASN1_ITEM *ZUINT32_it(void)` — unsigned with `ZERO_DEFAULT`."
);
funcs_item!(
    ZINT64_ITEM,
    ZINT64_it,
    UINT64_PF,
    INTXX_FLAG_ZERO_DEFAULT | INTXX_FLAG_SIGNED,
    c"ZINT64",
    "`const ASN1_ITEM *ZINT64_it(void)` — signed eight-byte with `ZERO_DEFAULT`."
);
funcs_item!(
    ZUINT64_ITEM,
    ZUINT64_it,
    UINT64_PF,
    INTXX_FLAG_ZERO_DEFAULT,
    c"ZUINT64",
    "`const ASN1_ITEM *ZUINT64_it(void)` — unsigned eight-byte with `ZERO_DEFAULT`."
);
