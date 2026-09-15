//! Phase 5 — `x_bignum.c`: the `BIGNUM` and `CBIGNUM` primitives.
//!
//! These read an `ASN1_INTEGER`'s content straight into a `BIGNUM`, without the
//! intermediate `ASN1_STRING` the generic codec would build. The file's own comment notes
//! that it **ignores the sign**, and gives the reason: every `BIGNUM` the authority
//! encodes is non-negative, so a negative-looking encoding is an encoding error rather
//! than a value to represent. `BN_bin2bn` is called on the raw content, so a content whose
//! top bit is set decodes to its unsigned magnitude rather than to a negative number.
//!
//! ## `CBIGNUM` is the same item plus two things
//!
//! "C" is for constant-time. The differences are that its `prim_new` is `BN_secure_new`
//! rather than `BN_new` — so the limbs come from the secure heap — that its `prim_c2i`
//! sets `BN_FLG_CONSTTIME` on the result, and that its `size` field is `BN_SENSITIVE`,
//! which is what `bn_free` reads to decide between `BN_clear_free` and `BN_free`. A freed
//! sensitive `BIGNUM` is therefore wiped and an ordinary one is not, and *that* is why the
//! flag has to survive in the item rather than being passed to the free hook.
//!
//! `prim_clear` is null for both, which is not an omission: the authority leaves the slot
//! empty, and a cleared `BIGNUM` field is an absent one.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::items::funcs_item;
use crate::asn1::layout::*;
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2bin, BN_clear_free, BN_free, BN_new, BN_num_bits, BN_print, BN_secure_new,
    BN_set_flags, BigNum,
};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::Bio;

/// `BN_SENSITIVE` — the bit `bn_free` reads to decide the wipe.
const BN_SENSITIVE: c_long = 1;

/// `BN_FLG_CONSTTIME`, as the authority's `bn.h` defines it.
///
/// Declared here rather than imported because the crate's other users of it each carry
/// their own copy beside the comment that justifies it, and because this one is not a
/// promise about a multiplication but a property stamped on a freshly decoded value.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `BN_num_bytes(a)` — the number of octets a magnitude needs.
///
/// The macro is `(BN_num_bits(a) + 7) / 8`, which is what `bn_i2c` measures its content
/// with, so it is spelled out here rather than reimplemented against the limb array.
///
/// # Safety
///
/// `a` must be a live `BIGNUM`.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: the caller's contract.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// `int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot.
unsafe extern "C" fn bn_new(pval: *mut *mut c_void, _it: *const Asn1Item) -> c_int {
    // SAFETY: `BN_new` allocates a zeroed `BIGNUM`.
    let bn = unsafe { BN_new() };
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = bn.cast::<c_void>() };
    if bn.is_null() {
        0
    } else {
        1
    }
}

/// `int bn_secure_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot.
unsafe extern "C" fn bn_secure_new(pval: *mut *mut c_void, _it: *const Asn1Item) -> c_int {
    // SAFETY: `BN_secure_new` allocates from the secure heap.
    let bn = unsafe { BN_secure_new() };
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = bn.cast::<c_void>() };
    if bn.is_null() {
        0
    } else {
        1
    }
}

/// `void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// The sensitivity bit is read from the *item*, not from the algorithm, so an item built
/// by a caller with the bit set wipes its values however it was declared.
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live `BIGNUM`; `it` must be live.
unsafe extern "C" fn bn_free(pval: *mut *mut c_void, it: *const Asn1Item) {
    // SAFETY: `pval` is a live slot.
    let v = unsafe { *pval };
    if v.is_null() {
        return;
    }
    // SAFETY: `it` is a live item.
    let sensitive = unsafe { (*it).size } & BN_SENSITIVE != 0;
    if sensitive {
        // SAFETY: `v` is the live `BIGNUM` the slot holds.
        unsafe { BN_clear_free(v.cast::<BigNum>()) };
    } else {
        // SAFETY: as above.
        unsafe { BN_free(v.cast::<BigNum>()) };
    }
    // SAFETY: `pval` is a live slot.
    unsafe { *pval = core::ptr::null_mut() };
}

/// `int bn_i2c(const ASN1_VALUE **pval, unsigned char *cont, int *putype,
/// const ASN1_ITEM *it)`
///
/// A null value answers `-1`, which is the encoder's "omit this type" rather than a
/// failure.
///
/// # Safety
///
/// `pval` must point to a live slot holding null or a live `BIGNUM`; `cont` must be null or
/// writable for the length this answers.
unsafe extern "C" fn bn_i2c(
    pval: *const *const c_void,
    cont: *mut c_uchar,
    _putype: *mut c_int,
    _it: *const Asn1Item,
) -> c_int {
    // SAFETY: `pval` is a live slot.
    let v = unsafe { *pval };
    if v.is_null() {
        return -1;
    }
    let bn = v.cast::<BigNum>();
    // A magnitude whose top bit is set needs a leading zero octet to stay positive.
    // SAFETY: `bn` is a live `BIGNUM`.
    let pad: c_int = if unsafe { BN_num_bits(bn) } & 0x7 != 0 {
        0
    } else {
        1
    };
    if !cont.is_null() {
        let mut cursor = cont;
        if pad != 0 {
            // SAFETY: `cursor` is writable per the caller's contract.
            unsafe { *cursor = 0 };
            // SAFETY: as above.
            cursor = unsafe { cursor.add(1) };
        }
        // SAFETY: `cursor` is writable for the magnitude's octets and `bn` is live.
        unsafe { BN_bn2bin(bn, cursor) };
    }
    // SAFETY: `bn` is live.
    pad + unsafe { bn_num_bytes(bn) }
}

/// `int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
/// char *free_cont, const ASN1_ITEM *it)`
///
/// The value is *replaced*, not accumulated: `BN_bin2bn` with a non-null destination
/// overwrites it. On failure the value this call allocated is freed and the caller's slot
/// is nulled, which is what makes a failed decode leave nothing behind.
///
/// # Safety
///
/// `pval` must be a live slot; `cont` must be readable for `len` bytes; `it` must be live.
unsafe extern "C" fn bn_c2i(
    pval: *mut *mut c_void,
    cont: *const c_uchar,
    len: c_int,
    _utype: c_int,
    _free_cont: *mut core::ffi::c_char,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: `pval` is a live slot and `it` is the caller's item.
    if unsafe { *pval }.is_null() && unsafe { bn_new(pval, it) } == 0 {
        return 0;
    }
    // SAFETY: `pval` holds a live `BIGNUM` by the line above.
    let bn = unsafe { *pval }.cast::<BigNum>();
    // SAFETY: `cont` is readable for `len` bytes and `bn` is a live destination.
    if unsafe { BN_bin2bn(cont.cast::<u8>(), len, bn) }.is_null() {
        // SAFETY: `bn` is the value this path owns and `it` is the caller's item.
        unsafe { bn_free(pval, it) };
        return 0;
    }
    1
}

/// `int bn_secure_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
/// char *free_cont, const ASN1_ITEM *it)`
///
/// # Safety
///
/// As [`bn_c2i`].
unsafe extern "C" fn bn_secure_c2i(
    pval: *mut *mut c_void,
    cont: *const c_uchar,
    len: c_int,
    utype: c_int,
    free_cont: *mut core::ffi::c_char,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: `pval` is a live slot and `it` is the caller's item.
    if unsafe { *pval }.is_null() && unsafe { bn_secure_new(pval, it) } == 0 {
        return 0;
    }
    // SAFETY: the caller's contract passes through unchanged.
    let ret = unsafe { bn_c2i(pval, cont, len, utype, free_cont, it) };
    if ret == 0 {
        return 0;
    }
    // SAFETY: `pval` holds a live `BIGNUM` by the line above.
    let bn = unsafe { *pval }.cast::<BigNum>();
    // SAFETY: `bn` is live.
    unsafe { BN_set_flags(bn, BN_FLG_CONSTTIME) };
    ret
}

/// `int bn_print(BIO *out, const ASN1_VALUE **pval, const ASN1_ITEM *it, int indent,
/// const ASN1_PCTX *pctx)`
///
/// # Safety
///
/// `out` must be a live BIO; `pval` must point to a live slot holding a live `BIGNUM`.
unsafe extern "C" fn bn_print(
    out: *mut Bio,
    pval: *const *const c_void,
    _it: *const Asn1Item,
    _indent: c_int,
    _pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: `pval` is a live slot holding a live `BIGNUM`.
    let bn = unsafe { *pval }.cast::<BigNum>();
    // SAFETY: `out` is a live BIO and `bn` is live.
    if unsafe { BN_print(out, bn) } == 0 {
        return 0;
    }
    // SAFETY: `out` is a live BIO and the literal is NUL-terminated.
    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    1
}

/// The ordinary `BIGNUM` hooks. `prim_clear` is null: a cleared `BIGNUM` field is an
/// absent one, and the authority leaves the slot empty rather than allocating.
static BIGNUM_PF: Asn1PrimitiveFuncs = Asn1PrimitiveFuncs {
    app_data: core::ptr::null_mut(),
    flags: 0,
    prim_new: Some(bn_new),
    prim_free: Some(bn_free),
    prim_clear: None,
    prim_c2i: Some(bn_c2i),
    prim_i2c: Some(bn_i2c),
    prim_print: Some(bn_print),
};

/// The constant-time hooks: secure allocation, and `BN_FLG_CONSTTIME` on every decoded
/// value.
static CBIGNUM_PF: Asn1PrimitiveFuncs = Asn1PrimitiveFuncs {
    app_data: core::ptr::null_mut(),
    flags: 0,
    prim_new: Some(bn_secure_new),
    prim_free: Some(bn_free),
    prim_clear: None,
    prim_c2i: Some(bn_secure_c2i),
    prim_i2c: Some(bn_i2c),
    prim_print: Some(bn_print),
};

funcs_item!(
    BIGNUM_ITEM,
    BIGNUM_it,
    BIGNUM_PF,
    0,
    c"BIGNUM",
    "`const ASN1_ITEM *BIGNUM_it(void)` — `x_bignum.c`'s `ASN1_ITEM_start(BIGNUM)`, whose \
     `size` is 0 and whose value is an ordinary heap `BIGNUM`."
);
funcs_item!(
    CBIGNUM_ITEM,
    CBIGNUM_it,
    CBIGNUM_PF,
    BN_SENSITIVE,
    c"CBIGNUM",
    "`const ASN1_ITEM *CBIGNUM_it(void)` — the constant-time variant. `size` is \
     `BN_SENSITIVE`, which is what makes `bn_free` wipe the value instead of releasing it."
);
