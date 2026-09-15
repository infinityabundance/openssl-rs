//! Phase 5 — `evp_asn1.c`: the `ASN1_TYPE` octet-string accessors.
//!
//! Only four of this file's symbols are Phase 5's; the rest belong to `EVP_PKEY` and are
//! declared in `evp.h`. All four are declared in `asn1.h`, which is what puts them here.
//!
//! ## Two of the four need a template
//!
//! `ASN1_TYPE_set_int_octetstring` and `ASN1_TYPE_get_int_octetstring` carry a *pair* — a
//! 32-bit integer and an octet string — inside one `ASN1_TYPE` of type `SEQUENCE`. The
//! authority builds that pair with two file-local template items, and so does this module,
//! which makes it the first place in the stratum where a **caller-invisible** item is
//! built from `ASN1_SEQUENCE` rather than from `ASN1_ITEM_start` with a hand-written
//! descriptor. The item is `static` in the authority and private here for the same reason:
//! nothing outside the file can name it.
//!
//! Two properties of those items are load-bearing and are stated rather than implied:
//!
//! * the integer field is `ASN1_EMBED`, so it lives *inline* in the structure rather than
//!   behind a pointer. `ASN1_TFLG_EMBED` is what makes the decoder hand the field's own
//!   address to the item machinery, and it is why `Asn1IntOct`'s `num` is a plain `i32`
//!   and not a `*mut i32`;
//! * the structures differ only in field order, and the order is observable: the integer
//!   comes first in `asn1_int_oct` and the octet string first in `asn1_oct_int`. The two
//!   therefore produce different encodings of the same pair, which is why both exist.
//!
//! ## The octet string is borrowed, not owned
//!
//! `asn1_type_init_oct` points an octet string at the **caller's** buffer and gives it the
//! caller's length, without copying. The encoder then copies out of it, and the string is
//! a local that is never freed. So a caller keeps ownership of `data` throughout, and the
//! `1` this answers means "the pair was packed", not "the bytes were taken".
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::a_type::{ASN1_TYPE_pack_sequence, ASN1_TYPE_set, ASN1_TYPE_unpack_sequence};
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::*;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::x_int64::INT32_it;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `asn1_int_oct` — the integer-then-octet-string pair.
///
/// `#[repr(C)]` because the template machinery reaches the fields by *offset*: the
/// offsets below are asserted against this declaration rather than assumed from it.
#[repr(C)]
struct Asn1IntOct {
    /// `ASN1_EMBED(..., num, INT32)`: inline, at offset 0.
    num: i32,
    /// `ASN1_SIMPLE(..., oct, ASN1_OCTET_STRING)`: a pointer, at offset 8.
    oct: *mut Asn1String,
}

/// `asn1_oct_int` — the same pair with the fields the other way round.
#[repr(C)]
struct Asn1OctInt {
    /// `ASN1_SIMPLE(..., oct, ASN1_OCTET_STRING)`, at offset 0.
    oct: *mut Asn1String,
    /// `ASN1_EMBED(..., num, INT32)`, at offset 8.
    num: i32,
}

// The offsets the two template arrays below name. Asserted rather than written twice: if a
// field order or a padding rule ever changed, the template would name the wrong field and
// the symptom would be a decode into the wrong member of the structure.
const _: () = {
    assert!(core::mem::size_of::<Asn1IntOct>() == 16);
    assert!(core::mem::offset_of!(Asn1IntOct, num) == 0);
    assert!(core::mem::offset_of!(Asn1IntOct, oct) == 8);
    assert!(core::mem::size_of::<Asn1OctInt>() == 16);
    assert!(core::mem::offset_of!(Asn1OctInt, oct) == 0);
    assert!(core::mem::offset_of!(Asn1OctInt, num) == 8);
};

/// `asn1_int_oct_seq_tt` — `ASN1_EMBED(num, INT32)` then `ASN1_SIMPLE(oct, ...)`.
static ASN1_INT_OCT_TT: [Asn1Template; 2] = [
    Asn1Template {
        // `ASN1_TFLG_EMBED`: the field's own address is the value.
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"num".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"oct".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `asn1_oct_int_seq_tt` — the same two fields in the other order.
static ASN1_OCT_INT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"oct".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"num".as_ptr(),
        item: INT32_it as *mut c_void,
    },
];

/// `asn1_int_oct_it` — the `static_ASN1_SEQUENCE_END` accessor, which has internal linkage
/// in the authority and is private here.
///
/// `size` is derived from the Rust structure rather than written as 16, so the assertion
/// block above and the item cannot disagree.
fn asn1_int_oct_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: ASN1_INT_OCT_TT.as_ptr(),
        tcount: 2,
        funcs: core::ptr::null(),
        size: core::mem::size_of::<Asn1IntOct>() as c_long,
        sname: c"asn1_int_oct".as_ptr(),
    };
    &IT
}

/// `asn1_oct_int_it` — as above, for the other field order.
fn asn1_oct_int_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: ASN1_OCT_INT_TT.as_ptr(),
        tcount: 2,
        funcs: core::ptr::null(),
        size: core::mem::size_of::<Asn1OctInt>() as c_long,
        sname: c"asn1_oct_int".as_ptr(),
    };
    &IT
}

/// `asn1_type_init_oct` — point a local octet string at the caller's buffer.
///
/// No copy and no ownership: `data` stays the caller's, which is why the string must be a
/// local that is never freed.
///
/// # Safety
///
/// `oct` must be a live slot; `data` must be null or readable for `len` bytes.
unsafe fn asn1_type_init_oct(oct: *mut Asn1String, data: *mut c_uchar, len: c_int) {
    // SAFETY: `oct` is the caller's live slot.
    unsafe {
        (*oct).data = data;
        (*oct).type_ = V_ASN1_OCTET_STRING;
        (*oct).length = len;
        (*oct).flags = 0;
    }
}

/// `asn1_type_get_int_oct` — copy out the integer and up to `max_len` octets.
///
/// The return is the string's **full** length whatever was copied, which is what lets a
/// caller tell "all of it fit" from "only the first `max_len` bytes did" by comparing.
///
/// # Safety
///
/// `oct` must be a live `ASN1_OCTET_STRING`; `num` must be null or writable; `data` must
/// be null or writable for `max_len` bytes.
unsafe fn asn1_type_get_int_oct(
    oct: *const Asn1String,
    anum: i32,
    num: *mut c_long,
    data: *mut c_uchar,
    max_len: c_int,
) -> c_int {
    // SAFETY: `oct` is the caller's live string.
    let ret = unsafe { (*oct).length };
    if !num.is_null() {
        // SAFETY: `num` is writable per the caller's contract. The widening is the
        // authority's own `*num = anum`.
        unsafe { *num = c_long::from(anum) };
    }
    let n = if max_len > ret { ret } else { max_len };
    if !data.is_null() && n > 0 {
        // SAFETY: `data` is writable for `n <= max_len` bytes and `oct`'s data is
        // readable for `ret >= n`.
        unsafe {
            core::ptr::copy_nonoverlapping((*oct).data, data, n as usize);
        }
    }
    ret
}

/// `int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len)`
///
/// Allocates an octet string, fills it with a **copy** of `data`, and puts it in `a` as an
/// `OCTET STRING`. The copy is the difference from the `int_octetstring` pair below, which
/// borrows: here the caller may free `data` as soon as this returns.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`; `data` must be null or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_set_octetstring(
    a: *mut Asn1Type,
    data: *mut c_uchar,
    len: c_int,
) -> c_int {
    guard_ffi(0, || {
        let os = ASN1_OCTET_STRING_new();
        if os.is_null() {
            return 0;
        }
        // SAFETY: `os` is a fresh string and `data` is readable for `len` bytes.
        if unsafe { ASN1_OCTET_STRING_set(os, data, len) } == 0 {
            // SAFETY: `os` was made by this call and is not yet owned by `a`.
            unsafe { ASN1_OCTET_STRING_free(os) };
            return 0;
        }
        // SAFETY: `a` is the caller's live type and takes ownership of `os`.
        unsafe { ASN1_TYPE_set(a, V_ASN1_OCTET_STRING, os.cast::<c_void>()) };
        1
    })
}

/// `int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len)`
///
/// Answers the string's full length, copying at most `max_len` bytes into `data`; a null
/// `data` asks only for the length. A type that is not an `OCTET STRING`, or one whose
/// value is null, is `ASN1_R_DATA_IS_WRONG` and `-1`.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`; `data` must be null or writable for `max_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_get_octetstring(
    a: *const Asn1Type,
    data: *mut c_uchar,
    max_len: c_int,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `a` is the caller's live type.
        let (type_, value) = unsafe { ((*a).type_, (*a).value.ptr) };
        if type_ != V_ASN1_OCTET_STRING || value.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_40) };
            return -1;
        }
        let os = value.cast::<Asn1String>();
        // SAFETY: `os` is a live octet string.
        let ret = unsafe { (*os).length };
        let num = if ret < max_len { ret } else { max_len };
        if num > 0 && !data.is_null() {
            // SAFETY: `data` is writable for `num` bytes and the string's data is
            // readable for `ret >= num`.
            unsafe { core::ptr::copy_nonoverlapping((*os).data, data, num as usize) };
        }
        ret
    })
}

/// `int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num, unsigned char *data,
/// int len)`
///
/// Packs a `(num, data)` pair as a `SEQUENCE` into `a` as a `V_ASN1_SEQUENCE` value.
///
/// The 32-bit field is filled from a `long` with a truncation, which is the authority's
/// own assignment rather than a deliberate narrowing here: a caller passing a number wider
/// than 32 bits loses the upper ones silently.
///
/// The third argument to the pack is the address of this function's **own** `a` parameter,
/// so when `a` is non-null the caller's type is reused and nothing is written back. That
/// is the authority's shape and it is reproduced because a caller that passes a fresh type
/// sees the difference.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`; `data` must be null or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_set_int_octetstring(
    a: *mut Asn1Type,
    num: c_long,
    data: *mut c_uchar,
    len: c_int,
) -> c_int {
    guard_ffi(0, || {
        // The octet string is a local pointing at the caller's buffer: no copy, no
        // ownership, and it must not be freed.
        let mut oct = Asn1String {
            length: 0,
            type_: 0,
            data: core::ptr::null_mut(),
            flags: 0,
        };
        // SAFETY: `oct` is a live local and `data` is readable for `len` bytes.
        unsafe { asn1_type_init_oct(&mut oct, data, len) };

        let mut atmp = Asn1IntOct {
            num: num as i32,
            oct: &mut oct,
        };
        // The pack is handed the address of this frame's copy of `a`, exactly as the
        // authority hands it `&a`: with a non-null `a` the existing type is reused and
        // nothing comes back through the slot.
        let mut slot: *mut Asn1Type = a;
        // SAFETY: `atmp` is this frame's live structure; the pack reads it through the
        // template without retaining it.
        let rt = unsafe {
            ASN1_TYPE_pack_sequence(
                asn1_int_oct_it(),
                (&mut atmp as *mut Asn1IntOct).cast::<c_void>(),
                &mut slot,
            )
        };
        if rt.is_null() {
            0
        } else {
            1
        }
    })
}

/// `int ASN1_TYPE_get_int_octetstring(const ASN1_TYPE *a, long *num, unsigned char *data,
/// int max_len)`
///
/// The inverse of [`ASN1_TYPE_set_int_octetstring`], unpacking through the same private
/// item.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`; `num` must be null or writable; `data` must be null or
/// writable for `max_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_get_int_octetstring(
    a: *const Asn1Type,
    num: *mut c_long,
    data: *mut c_uchar,
    max_len: c_int,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `a` is the caller's live type.
        let (type_, value) = unsafe { ((*a).type_, (*a).value.ptr) };
        if type_ != V_ASN1_SEQUENCE || value.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_141) };
            return -1;
        }
        // SAFETY: `a` is a live type of type `SEQUENCE`, which is what the unpack checks.
        let atmp = unsafe { ASN1_TYPE_unpack_sequence(asn1_int_oct_it(), a) };
        if atmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_141) };
            return -1;
        }
        let atmp = atmp.cast::<Asn1IntOct>();
        // SAFETY: `atmp` is the structure the unpack just built from this item's template.
        let ret = unsafe { asn1_type_get_int_oct((*atmp).oct, (*atmp).num, num, data, max_len) };
        if ret == -1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_141) };
        }
        // SAFETY: `atmp` is this call's value and its lifetime ends here.
        unsafe { ASN1_item_free(atmp.cast::<c_void>(), asn1_int_oct_it()) };
        ret
    })
}

/// `int ossl_asn1_type_set_octetstring_int(ASN1_TYPE *a, long num, unsigned char *data,
/// int len)`
///
/// The RFC 5084 ordering: an octet string followed by an integer, for the
/// content-authenticated encryption parameters. It is the same pack as
/// [`ASN1_TYPE_set_int_octetstring`] over the other structure.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`; `data` must be null or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_asn1_type_set_octetstring_int(
    a: *mut Asn1Type,
    num: c_long,
    data: *mut c_uchar,
    len: c_int,
) -> c_int {
    guard_ffi(0, || {
        let mut oct = Asn1String {
            length: 0,
            type_: 0,
            data: core::ptr::null_mut(),
            flags: 0,
        };
        // SAFETY: `oct` is a live local and `data` is readable for `len` bytes.
        unsafe { asn1_type_init_oct(&mut oct, data, len) };

        let mut atmp = Asn1OctInt {
            oct: &mut oct,
            num: num as i32,
        };
        // As `ASN1_TYPE_set_int_octetstring`: this frame's copy of `a` is what is handed
        // over.
        let mut slot: *mut Asn1Type = a;
        // SAFETY: as `ASN1_TYPE_set_int_octetstring`.
        let rt = unsafe {
            ASN1_TYPE_pack_sequence(
                asn1_oct_int_it(),
                (&mut atmp as *mut Asn1OctInt).cast::<c_void>(),
                &mut slot,
            )
        };
        if rt.is_null() {
            0
        } else {
            1
        }
    })
}

/// `int ossl_asn1_type_get_octetstring_int(const ASN1_TYPE *a, long *num,
/// unsigned char *data, int max_len)`
///
/// # Safety
///
/// As [`ASN1_TYPE_get_int_octetstring`].
#[no_mangle]
pub unsafe extern "C" fn ossl_asn1_type_get_octetstring_int(
    a: *const Asn1Type,
    num: *mut c_long,
    data: *mut c_uchar,
    max_len: c_int,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `a` is the caller's live type.
        let (type_, value) = unsafe { ((*a).type_, (*a).value.ptr) };
        if type_ != V_ASN1_SEQUENCE || value.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_203) };
            return -1;
        }
        // SAFETY: `a` is a live type of type `SEQUENCE`.
        let atmp = unsafe { ASN1_TYPE_unpack_sequence(asn1_oct_int_it(), a) };
        if atmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_203) };
            return -1;
        }
        let atmp = atmp.cast::<Asn1OctInt>();
        // SAFETY: `atmp` is the structure the unpack just built from this item's template.
        let ret = unsafe { asn1_type_get_int_oct((*atmp).oct, (*atmp).num, num, data, max_len) };
        if ret == -1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ASN1_203) };
        }
        // SAFETY: `atmp` is this call's value and its lifetime ends here.
        unsafe { ASN1_item_free(atmp.cast::<c_void>(), asn1_oct_int_it()) };
        ret
    })
}
