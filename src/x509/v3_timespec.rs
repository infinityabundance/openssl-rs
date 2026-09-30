//! `crypto/x509/v3_timespec.c` — the ITU-T X.509 (2019) time-specification items and their table
//! row. Phase 10.13 landed the item groups; this slice (10.14's second batch) lands the row and
//! the twelve printers.
//!
//! `crypto/x509/v3_timespec.c` is 599 lines and transcribes whole:
//!
//! * the eleven `ASN1_SEQUENCE`/`ASN1_CHOICE` templates (`:49-113`) and the
//!   `IMPLEMENT_ASN1_FUNCTIONS` group over them (`:115-125`) land. Every `*_it`/`*_new`/`*_free`/
//!   `d2i_*`/`i2d_*` is a public export (`x509v3.h:1299-1309`), so the differential plane can
//!   build each value, encode it and decode the bytes back.
//! * the twelve printers land: `i2r_OSSL_TIME_SPEC_ABSOLUTE` (`:127-156`), `i2r_OSSL_DAY_TIME`
//!   (`:158-175`), `i2r_OSSL_DAY_TIME_BAND` (`:177-196`), the seven `print_*` helpers (`:198-336`),
//!   `i2r_OSSL_PERIOD` (`:338-535`), `i2r_OSSL_TIME_SPEC_TIME` (`:537-566`) and `i2r_OSSL_TIME_SPEC`
//!   (`:568-587`).
//! * the row [`ossl_v3_time_specification`] (`:589-599`) lands: `ext_nid` is
//!   `NID_time_specification`, `ext_flags` is `X509V3_EXT_MULTILINE`, `it` is
//!   `ASN1_ITEM_ref(OSSL_TIME_SPEC)` and `i2r` is `i2r_OSSL_TIME_SPEC`.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456), so the array is the last thing to land, not the first; this unit contributes one of the
//! 63 tables. The row is internal data the admitted DSO does not export (`nm -D` shows no
//! `ossl_v3_*`), so no court can name it; the item groups are the drivable surface.
//!
//! Nothing is stubbed: the generated lifecycle functions are written out one by one rather than
//! produced by a `macro_rules!` group: `prototype_court.py` refuses a macro that fills a *type*
//! position (the `X` in `X_new`/`d2i_X`/`i2d_X`), so the ABI of each would be uncheckable. That is
//! why this file is explicit where `src/x509/v3_pcia.rs` and `v3_pku.rs` are.
//!
//! ## The union member is one pointer
//!
//! Every `ASN1_CHOICE` here carries an `int type` selector at offset 0 and a union of pointers at
//! offset 8. The union is modelled as a single `*mut c_void`, as `src/ec/asn1.rs`'s
//! `ECPKPARAMETERS` does: every arm is pointer-width, the templates reach it through `offset_of!`
//! alone, and the selector is what says which arm is live. The `CHOICE` item's `utype` is the
//! selector's offset (0), which is what `ASN1_CHOICE_END_selector` passes.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms drive the leaf items with non-trivial values -- `OSSL_DAY_TIME` with
//! all three fields, `OSSL_DAY_TIME_BAND`, `OSSL_NAMED_DAY`, `OSSL_TIME_SPEC_X_DAY_OF`,
//! `OSSL_TIME_SPEC_DAY`, `OSSL_TIME_SPEC_WEEKS`, `OSSL_TIME_SPEC_MONTH`, `OSSL_TIME_SPEC_ABSOLUTE`,
//! `OSSL_TIME_PERIOD` and `OSSL_TIME_SPEC` -- through their public `_new` and structure fields,
//! encode, decode and re-encode, comparing byte for byte on both sides.
//!
//! ## No raise
//!
//! The unit raises nothing, so it is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::bitstr::ASN1_BIT_STRING_get_bit;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it,
    ASN1_INTEGER_it, ASN1_NULL_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_INTEGER_get_int64;
use crate::asn1::time::ossl_asn1_time_print_ex;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_time_specification;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};

// ---------------------------------------------------------------------------------------------
// The structures — `include/openssl/x509v3.h:1134-1297`. Every union arm is a pointer, so each
// union is one `*mut c_void` at offset 8 (see the module doc).
// ---------------------------------------------------------------------------------------------

/// `OSSL_TIME_SPEC_ABSOLUTE` — `include/openssl/x509v3.h:1134-1137`.
#[repr(C)]
pub struct OsslTimeSpecAbsolute {
    pub(crate) startTime: *mut Asn1String,
    pub(crate) endTime: *mut Asn1String,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecAbsolute>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecAbsolute, startTime) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecAbsolute, endTime) == 8);
};

/// `OSSL_DAY_TIME` — `include/openssl/x509v3.h:1139-1143`.
#[repr(C)]
pub struct OsslDayTime {
    pub(crate) hour: *mut Asn1String,
    pub(crate) minute: *mut Asn1String,
    pub(crate) second: *mut Asn1String,
}
const _: () = {
    assert!(core::mem::size_of::<OsslDayTime>() == 24);
    assert!(core::mem::offset_of!(OsslDayTime, hour) == 0);
    assert!(core::mem::offset_of!(OsslDayTime, minute) == 8);
    assert!(core::mem::offset_of!(OsslDayTime, second) == 16);
};

/// `OSSL_DAY_TIME_BAND` — `include/openssl/x509v3.h:1145-1148`.
#[repr(C)]
pub struct OsslDayTimeBand {
    pub(crate) startDayTime: *mut OsslDayTime,
    pub(crate) endDayTime: *mut OsslDayTime,
}
const _: () = {
    assert!(core::mem::size_of::<OsslDayTimeBand>() == 16);
    assert!(core::mem::offset_of!(OsslDayTimeBand, startDayTime) == 0);
    assert!(core::mem::offset_of!(OsslDayTimeBand, endDayTime) == 8);
};

/// `OSSL_NAMED_DAY` — `include/openssl/x509v3.h:1167-1173`. `type_` is the CHOICE selector.
#[repr(C)]
pub struct OsslNamedDay {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslNamedDay>() == 16);
    assert!(core::mem::offset_of!(OsslNamedDay, type_) == 0);
    assert!(core::mem::offset_of!(OsslNamedDay, choice) == 8);
};

/// `OSSL_TIME_SPEC_X_DAY_OF` — `include/openssl/x509v3.h:1181-1190`.
#[repr(C)]
pub struct OsslTimeSpecXDayOf {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecXDayOf>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecXDayOf, type_) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecXDayOf, choice) == 8);
};

/// `OSSL_TIME_SPEC_DAY` — `include/openssl/x509v3.h:1210-1217`.
#[repr(C)]
pub struct OsslTimeSpecDay {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecDay>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecDay, type_) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecDay, choice) == 8);
};

/// `OSSL_TIME_SPEC_WEEKS` — `include/openssl/x509v3.h:1228-1235`.
#[repr(C)]
pub struct OsslTimeSpecWeeks {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecWeeks>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecWeeks, type_) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecWeeks, choice) == 8);
};

/// `OSSL_TIME_SPEC_MONTH` — `include/openssl/x509v3.h:1265-1272`.
#[repr(C)]
pub struct OsslTimeSpecMonth {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecMonth>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecMonth, type_) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecMonth, choice) == 8);
};

/// `OSSL_TIME_PERIOD` — `include/openssl/x509v3.h:1274-1280`.
#[repr(C)]
pub struct OsslTimePeriod {
    pub(crate) timesOfDay: *mut OpenSslStack,
    pub(crate) days: *mut OsslTimeSpecDay,
    pub(crate) weeks: *mut OsslTimeSpecWeeks,
    pub(crate) months: *mut OsslTimeSpecMonth,
    pub(crate) years: *mut OpenSslStack,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimePeriod>() == 40);
    assert!(core::mem::offset_of!(OsslTimePeriod, timesOfDay) == 0);
    assert!(core::mem::offset_of!(OsslTimePeriod, days) == 8);
    assert!(core::mem::offset_of!(OsslTimePeriod, weeks) == 16);
    assert!(core::mem::offset_of!(OsslTimePeriod, months) == 24);
    assert!(core::mem::offset_of!(OsslTimePeriod, years) == 32);
};

/// `OSSL_TIME_SPEC_TIME` — `include/openssl/x509v3.h:1285-1291`.
#[repr(C)]
pub struct OsslTimeSpecTime {
    pub(crate) type_: c_int,
    pub(crate) choice: *mut c_void,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpecTime>() == 16);
    assert!(core::mem::offset_of!(OsslTimeSpecTime, type_) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpecTime, choice) == 8);
};

/// `OSSL_TIME_SPEC` — `include/openssl/x509v3.h:1293-1297`.
#[repr(C)]
pub struct OsslTimeSpec {
    pub(crate) time: *mut OsslTimeSpecTime,
    pub(crate) notThisTime: c_int,
    pub(crate) timeZone: *mut Asn1String,
}
const _: () = {
    assert!(core::mem::size_of::<OsslTimeSpec>() == 24);
    assert!(core::mem::offset_of!(OsslTimeSpec, time) == 0);
    assert!(core::mem::offset_of!(OsslTimeSpec, notThisTime) == 8);
    assert!(core::mem::offset_of!(OsslTimeSpec, timeZone) == 16);
};

/// Declare one `_it`/`_new`/`_free`/`d2i_`/`i2d_` group, written out because the generated
/// lifecycle functions put the type in a signature position and `prototype_court.py` refuses a
/// macro that does (the ABI would be uncheckable). `$ty` is the Rust structure, `$item` its
/// `ASN1_ITEM` static, and the five function names are spelled by the caller.
macro_rules! asn1_functions {
    ($ty:ty, $item:ident, $it:ident, $new:ident, $free:ident, $d2i:ident, $i2d:ident) => {
        #[doc = concat!("`const ASN1_ITEM *", stringify!($it),
            "(void)` — the item accessor, from `DECLARE_ASN1_FUNCTIONS` (`crypto/x509/v3_timespec.c:115-125`).")]
        #[no_mangle]
        pub extern "C" fn $it() -> *const Asn1Item {
            &$item
        }
    };
}

// NOTE: the `_new`/`_free`/`d2i_`/`i2d_` halves of each group below are written out explicitly
// rather than through a macro, because a macro that fills the type position is reported by
// `prototype_court.py` as an unreadable declaration.

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_ABSOLUTE — ASN1_SEQUENCE (:49-52)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_ABSOLUTE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"startTime".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"endTime".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_ABSOLUTE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_TIME_SPEC_ABSOLUTE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecAbsolute>() as c_long,
    sname: c"OSSL_TIME_SPEC_ABSOLUTE".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecAbsolute,
    OSSL_TIME_SPEC_ABSOLUTE_ITEM,
    OSSL_TIME_SPEC_ABSOLUTE_it,
    OSSL_TIME_SPEC_ABSOLUTE_new,
    OSSL_TIME_SPEC_ABSOLUTE_free,
    d2i_OSSL_TIME_SPEC_ABSOLUTE,
    i2d_OSSL_TIME_SPEC_ABSOLUTE
);
/// `OSSL_TIME_SPEC_ABSOLUTE *OSSL_TIME_SPEC_ABSOLUTE_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_ABSOLUTE_new() -> *mut OsslTimeSpecAbsolute {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_ABSOLUTE_it()).cast::<OsslTimeSpecAbsolute>() }
}
/// `void OSSL_TIME_SPEC_ABSOLUTE_free(OSSL_TIME_SPEC_ABSOLUTE *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_ABSOLUTE_free(a: *mut OsslTimeSpecAbsolute) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_ABSOLUTE_it()) }
}
/// `OSSL_TIME_SPEC_ABSOLUTE *d2i_OSSL_TIME_SPEC_ABSOLUTE(OSSL_TIME_SPEC_ABSOLUTE **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_ABSOLUTE(
    a: *mut *mut OsslTimeSpecAbsolute,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecAbsolute {
    // SAFETY: the caller's contract for the three pointers.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_ABSOLUTE_it())
            .cast::<OsslTimeSpecAbsolute>()
    }
}
/// `int i2d_OSSL_TIME_SPEC_ABSOLUTE(const OSSL_TIME_SPEC_ABSOLUTE *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_ABSOLUTE(
    a: *const OsslTimeSpecAbsolute,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_ABSOLUTE_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_DAY_TIME — ASN1_SEQUENCE (:54-58)
// ---------------------------------------------------------------------------------------------

static OSSL_DAY_TIME_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"hour".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"minute".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"second".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];
static OSSL_DAY_TIME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_DAY_TIME_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslDayTime>() as c_long,
    sname: c"OSSL_DAY_TIME".as_ptr(),
};
asn1_functions!(
    OsslDayTime,
    OSSL_DAY_TIME_ITEM,
    OSSL_DAY_TIME_it,
    OSSL_DAY_TIME_new,
    OSSL_DAY_TIME_free,
    d2i_OSSL_DAY_TIME,
    i2d_OSSL_DAY_TIME
);
/// `OSSL_DAY_TIME *OSSL_DAY_TIME_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_DAY_TIME_new() -> *mut OsslDayTime {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_DAY_TIME_it()).cast::<OsslDayTime>() }
}
/// `void OSSL_DAY_TIME_free(OSSL_DAY_TIME *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DAY_TIME_free(a: *mut OsslDayTime) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_DAY_TIME_it()) }
}
/// `OSSL_DAY_TIME *d2i_OSSL_DAY_TIME(OSSL_DAY_TIME **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_DAY_TIME(
    a: *mut *mut OsslDayTime,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslDayTime {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_DAY_TIME_it()).cast::<OsslDayTime>() }
}
/// `int i2d_OSSL_DAY_TIME(const OSSL_DAY_TIME *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_DAY_TIME(a: *const OsslDayTime, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_DAY_TIME_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_DAY_TIME_BAND — ASN1_SEQUENCE (:60-63)
// ---------------------------------------------------------------------------------------------

static OSSL_DAY_TIME_BAND_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"startDayTime".as_ptr(),
        item: OSSL_DAY_TIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"endDayTime".as_ptr(),
        item: OSSL_DAY_TIME_it as *mut c_void,
    },
];
static OSSL_DAY_TIME_BAND_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_DAY_TIME_BAND_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslDayTimeBand>() as c_long,
    sname: c"OSSL_DAY_TIME_BAND".as_ptr(),
};
asn1_functions!(
    OsslDayTimeBand,
    OSSL_DAY_TIME_BAND_ITEM,
    OSSL_DAY_TIME_BAND_it,
    OSSL_DAY_TIME_BAND_new,
    OSSL_DAY_TIME_BAND_free,
    d2i_OSSL_DAY_TIME_BAND,
    i2d_OSSL_DAY_TIME_BAND
);
/// `OSSL_DAY_TIME_BAND *OSSL_DAY_TIME_BAND_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_DAY_TIME_BAND_new() -> *mut OsslDayTimeBand {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_DAY_TIME_BAND_it()).cast::<OsslDayTimeBand>() }
}
/// `void OSSL_DAY_TIME_BAND_free(OSSL_DAY_TIME_BAND *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DAY_TIME_BAND_free(a: *mut OsslDayTimeBand) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_DAY_TIME_BAND_it()) }
}
/// `OSSL_DAY_TIME_BAND *d2i_OSSL_DAY_TIME_BAND(OSSL_DAY_TIME_BAND **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_DAY_TIME_BAND(
    a: *mut *mut OsslDayTimeBand,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslDayTimeBand {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_DAY_TIME_BAND_it()).cast::<OsslDayTimeBand>() }
}
/// `int i2d_OSSL_DAY_TIME_BAND(const OSSL_DAY_TIME_BAND *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_DAY_TIME_BAND(
    a: *const OsslDayTimeBand,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_DAY_TIME_BAND_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_NAMED_DAY — ASN1_CHOICE (:65-68)
// ---------------------------------------------------------------------------------------------

static OSSL_NAMED_DAY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"choice.intNamedDays".as_ptr(),
        item: ASN1_ENUMERATED_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.bitNamedDays".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];
static OSSL_NAMED_DAY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_NAMED_DAY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslNamedDay>() as c_long,
    sname: c"OSSL_NAMED_DAY".as_ptr(),
};
asn1_functions!(
    OsslNamedDay,
    OSSL_NAMED_DAY_ITEM,
    OSSL_NAMED_DAY_it,
    OSSL_NAMED_DAY_new,
    OSSL_NAMED_DAY_free,
    d2i_OSSL_NAMED_DAY,
    i2d_OSSL_NAMED_DAY
);
/// `OSSL_NAMED_DAY *OSSL_NAMED_DAY_new(void)` — the allocator half (selector −1).
#[no_mangle]
pub extern "C" fn OSSL_NAMED_DAY_new() -> *mut OsslNamedDay {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_NAMED_DAY_it()).cast::<OsslNamedDay>() }
}
/// `void OSSL_NAMED_DAY_free(OSSL_NAMED_DAY *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_NAMED_DAY_free(a: *mut OsslNamedDay) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_NAMED_DAY_it()) }
}
/// `OSSL_NAMED_DAY *d2i_OSSL_NAMED_DAY(OSSL_NAMED_DAY **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_NAMED_DAY(
    a: *mut *mut OsslNamedDay,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslNamedDay {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_NAMED_DAY_it()).cast::<OsslNamedDay>() }
}
/// `int i2d_OSSL_NAMED_DAY(const OSSL_NAMED_DAY *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_NAMED_DAY(
    a: *const OsslNamedDay,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_NAMED_DAY_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_X_DAY_OF — ASN1_CHOICE (:70-76)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_X_DAY_OF_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"choice.first".as_ptr(),
        item: OSSL_NAMED_DAY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"choice.second".as_ptr(),
        item: OSSL_NAMED_DAY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 3,
        offset: 8,
        field_name: c"choice.third".as_ptr(),
        item: OSSL_NAMED_DAY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 4,
        offset: 8,
        field_name: c"choice.fourth".as_ptr(),
        item: OSSL_NAMED_DAY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 5,
        offset: 8,
        field_name: c"choice.fifth".as_ptr(),
        item: OSSL_NAMED_DAY_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_X_DAY_OF_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_TIME_SPEC_X_DAY_OF_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecXDayOf>() as c_long,
    sname: c"OSSL_TIME_SPEC_X_DAY_OF".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecXDayOf,
    OSSL_TIME_SPEC_X_DAY_OF_ITEM,
    OSSL_TIME_SPEC_X_DAY_OF_it,
    OSSL_TIME_SPEC_X_DAY_OF_new,
    OSSL_TIME_SPEC_X_DAY_OF_free,
    d2i_OSSL_TIME_SPEC_X_DAY_OF,
    i2d_OSSL_TIME_SPEC_X_DAY_OF
);
/// `OSSL_TIME_SPEC_X_DAY_OF *OSSL_TIME_SPEC_X_DAY_OF_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_X_DAY_OF_new() -> *mut OsslTimeSpecXDayOf {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_X_DAY_OF_it()).cast::<OsslTimeSpecXDayOf>() }
}
/// `void OSSL_TIME_SPEC_X_DAY_OF_free(OSSL_TIME_SPEC_X_DAY_OF *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_X_DAY_OF_free(a: *mut OsslTimeSpecXDayOf) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_X_DAY_OF_it()) }
}
/// `OSSL_TIME_SPEC_X_DAY_OF *d2i_OSSL_TIME_SPEC_X_DAY_OF(OSSL_TIME_SPEC_X_DAY_OF **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_X_DAY_OF(
    a: *mut *mut OsslTimeSpecXDayOf,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecXDayOf {
    // SAFETY: the caller's contract for the three pointers.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_X_DAY_OF_it()).cast::<OsslTimeSpecXDayOf>()
    }
}
/// `int i2d_OSSL_TIME_SPEC_X_DAY_OF(const OSSL_TIME_SPEC_X_DAY_OF *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_X_DAY_OF(
    a: *const OsslTimeSpecXDayOf,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_X_DAY_OF_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_DAY — ASN1_CHOICE (:78-82)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_DAY_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"choice.intDay".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.bitDay".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.dayOf".as_ptr(),
        item: OSSL_TIME_SPEC_X_DAY_OF_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_DAY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_TIME_SPEC_DAY_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecDay>() as c_long,
    sname: c"OSSL_TIME_SPEC_DAY".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecDay,
    OSSL_TIME_SPEC_DAY_ITEM,
    OSSL_TIME_SPEC_DAY_it,
    OSSL_TIME_SPEC_DAY_new,
    OSSL_TIME_SPEC_DAY_free,
    d2i_OSSL_TIME_SPEC_DAY,
    i2d_OSSL_TIME_SPEC_DAY
);
/// `OSSL_TIME_SPEC_DAY *OSSL_TIME_SPEC_DAY_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_DAY_new() -> *mut OsslTimeSpecDay {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_DAY_it()).cast::<OsslTimeSpecDay>() }
}
/// `void OSSL_TIME_SPEC_DAY_free(OSSL_TIME_SPEC_DAY *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_DAY_free(a: *mut OsslTimeSpecDay) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_DAY_it()) }
}
/// `OSSL_TIME_SPEC_DAY *d2i_OSSL_TIME_SPEC_DAY(OSSL_TIME_SPEC_DAY **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_DAY(
    a: *mut *mut OsslTimeSpecDay,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecDay {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_DAY_it()).cast::<OsslTimeSpecDay>() }
}
/// `int i2d_OSSL_TIME_SPEC_DAY(const OSSL_TIME_SPEC_DAY *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_DAY(
    a: *const OsslTimeSpecDay,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_DAY_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_WEEKS — ASN1_CHOICE (:84-88)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_WEEKS_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.allWeeks".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"choice.intWeek".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.bitWeek".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_WEEKS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_TIME_SPEC_WEEKS_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecWeeks>() as c_long,
    sname: c"OSSL_TIME_SPEC_WEEKS".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecWeeks,
    OSSL_TIME_SPEC_WEEKS_ITEM,
    OSSL_TIME_SPEC_WEEKS_it,
    OSSL_TIME_SPEC_WEEKS_new,
    OSSL_TIME_SPEC_WEEKS_free,
    d2i_OSSL_TIME_SPEC_WEEKS,
    i2d_OSSL_TIME_SPEC_WEEKS
);
/// `OSSL_TIME_SPEC_WEEKS *OSSL_TIME_SPEC_WEEKS_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_WEEKS_new() -> *mut OsslTimeSpecWeeks {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_WEEKS_it()).cast::<OsslTimeSpecWeeks>() }
}
/// `void OSSL_TIME_SPEC_WEEKS_free(OSSL_TIME_SPEC_WEEKS *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_WEEKS_free(a: *mut OsslTimeSpecWeeks) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_WEEKS_it()) }
}
/// `OSSL_TIME_SPEC_WEEKS *d2i_OSSL_TIME_SPEC_WEEKS(OSSL_TIME_SPEC_WEEKS **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_WEEKS(
    a: *mut *mut OsslTimeSpecWeeks,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecWeeks {
    // SAFETY: the caller's contract for the three pointers.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_WEEKS_it()).cast::<OsslTimeSpecWeeks>()
    }
}
/// `int i2d_OSSL_TIME_SPEC_WEEKS(const OSSL_TIME_SPEC_WEEKS *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_WEEKS(
    a: *const OsslTimeSpecWeeks,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_WEEKS_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_MONTH — ASN1_CHOICE (:90-94)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_MONTH_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.allMonths".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"choice.intMonth".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.bitMonth".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_MONTH_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_TIME_SPEC_MONTH_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecMonth>() as c_long,
    sname: c"OSSL_TIME_SPEC_MONTH".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecMonth,
    OSSL_TIME_SPEC_MONTH_ITEM,
    OSSL_TIME_SPEC_MONTH_it,
    OSSL_TIME_SPEC_MONTH_new,
    OSSL_TIME_SPEC_MONTH_free,
    d2i_OSSL_TIME_SPEC_MONTH,
    i2d_OSSL_TIME_SPEC_MONTH
);
/// `OSSL_TIME_SPEC_MONTH *OSSL_TIME_SPEC_MONTH_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_MONTH_new() -> *mut OsslTimeSpecMonth {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_MONTH_it()).cast::<OsslTimeSpecMonth>() }
}
/// `void OSSL_TIME_SPEC_MONTH_free(OSSL_TIME_SPEC_MONTH *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_MONTH_free(a: *mut OsslTimeSpecMonth) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_MONTH_it()) }
}
/// `OSSL_TIME_SPEC_MONTH *d2i_OSSL_TIME_SPEC_MONTH(OSSL_TIME_SPEC_MONTH **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_MONTH(
    a: *mut *mut OsslTimeSpecMonth,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecMonth {
    // SAFETY: the caller's contract for the three pointers.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_MONTH_it()).cast::<OsslTimeSpecMonth>()
    }
}
/// `int i2d_OSSL_TIME_SPEC_MONTH(const OSSL_TIME_SPEC_MONTH *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_MONTH(
    a: *const OsslTimeSpecMonth,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_MONTH_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_PERIOD — ASN1_SEQUENCE (:96-102)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_PERIOD_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_SET_OF | ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"timesOfDay".as_ptr(),
        item: OSSL_DAY_TIME_BAND_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"days".as_ptr(),
        item: OSSL_TIME_SPEC_DAY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"weeks".as_ptr(),
        item: OSSL_TIME_SPEC_WEEKS_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 24,
        field_name: c"months".as_ptr(),
        item: OSSL_TIME_SPEC_MONTH_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF | ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 32,
        field_name: c"years".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];
static OSSL_TIME_PERIOD_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_TIME_PERIOD_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimePeriod>() as c_long,
    sname: c"OSSL_TIME_PERIOD".as_ptr(),
};
asn1_functions!(
    OsslTimePeriod,
    OSSL_TIME_PERIOD_ITEM,
    OSSL_TIME_PERIOD_it,
    OSSL_TIME_PERIOD_new,
    OSSL_TIME_PERIOD_free,
    d2i_OSSL_TIME_PERIOD,
    i2d_OSSL_TIME_PERIOD
);
/// `OSSL_TIME_PERIOD *OSSL_TIME_PERIOD_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_PERIOD_new() -> *mut OsslTimePeriod {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_PERIOD_it()).cast::<OsslTimePeriod>() }
}
/// `void OSSL_TIME_PERIOD_free(OSSL_TIME_PERIOD *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_PERIOD_free(a: *mut OsslTimePeriod) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_PERIOD_it()) }
}
/// `OSSL_TIME_PERIOD *d2i_OSSL_TIME_PERIOD(OSSL_TIME_PERIOD **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_PERIOD(
    a: *mut *mut OsslTimePeriod,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimePeriod {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_PERIOD_it()).cast::<OsslTimePeriod>() }
}
/// `int i2d_OSSL_TIME_PERIOD(const OSSL_TIME_PERIOD *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_PERIOD(
    a: *const OsslTimePeriod,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_PERIOD_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC_TIME — ASN1_CHOICE (:104-107)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_TIME_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.absolute".as_ptr(),
        item: OSSL_TIME_SPEC_ABSOLUTE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"choice.periodic".as_ptr(),
        item: OSSL_TIME_PERIOD_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_TIME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_TIME_SPEC_TIME_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpecTime>() as c_long,
    sname: c"OSSL_TIME_SPEC_TIME".as_ptr(),
};
asn1_functions!(
    OsslTimeSpecTime,
    OSSL_TIME_SPEC_TIME_ITEM,
    OSSL_TIME_SPEC_TIME_it,
    OSSL_TIME_SPEC_TIME_new,
    OSSL_TIME_SPEC_TIME_free,
    d2i_OSSL_TIME_SPEC_TIME,
    i2d_OSSL_TIME_SPEC_TIME
);
/// `OSSL_TIME_SPEC_TIME *OSSL_TIME_SPEC_TIME_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_TIME_new() -> *mut OsslTimeSpecTime {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_TIME_it()).cast::<OsslTimeSpecTime>() }
}
/// `void OSSL_TIME_SPEC_TIME_free(OSSL_TIME_SPEC_TIME *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_TIME_free(a: *mut OsslTimeSpecTime) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_TIME_it()) }
}
/// `OSSL_TIME_SPEC_TIME *d2i_OSSL_TIME_SPEC_TIME(OSSL_TIME_SPEC_TIME **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_TIME(
    a: *mut *mut OsslTimeSpecTime,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpecTime {
    // SAFETY: the caller's contract for the three pointers.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_TIME_it()).cast::<OsslTimeSpecTime>()
    }
}
/// `int i2d_OSSL_TIME_SPEC_TIME(const OSSL_TIME_SPEC_TIME *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_TIME(
    a: *const OsslTimeSpecTime,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_TIME_it()) }
}

// ---------------------------------------------------------------------------------------------
// OSSL_TIME_SPEC — ASN1_SEQUENCE (:109-113)
// ---------------------------------------------------------------------------------------------

static OSSL_TIME_SPEC_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"time".as_ptr(),
        item: OSSL_TIME_SPEC_TIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"notThisTime".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"timeZone".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];
static OSSL_TIME_SPEC_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_TIME_SPEC_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTimeSpec>() as c_long,
    sname: c"OSSL_TIME_SPEC".as_ptr(),
};
asn1_functions!(
    OsslTimeSpec,
    OSSL_TIME_SPEC_ITEM,
    OSSL_TIME_SPEC_it,
    OSSL_TIME_SPEC_new,
    OSSL_TIME_SPEC_free,
    d2i_OSSL_TIME_SPEC,
    i2d_OSSL_TIME_SPEC
);
/// `OSSL_TIME_SPEC *OSSL_TIME_SPEC_new(void)` — the allocator half.
#[no_mangle]
pub extern "C" fn OSSL_TIME_SPEC_new() -> *mut OsslTimeSpec {
    // SAFETY: the item is the crate's own static.
    unsafe { ASN1_item_new(OSSL_TIME_SPEC_it()).cast::<OsslTimeSpec>() }
}
/// `void OSSL_TIME_SPEC_free(OSSL_TIME_SPEC *a)` — the free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TIME_SPEC_free(a: *mut OsslTimeSpec) {
    // SAFETY: `a` is NULL or live.
    unsafe { ASN1_item_free(a.cast(), OSSL_TIME_SPEC_it()) }
}
/// `OSSL_TIME_SPEC *d2i_OSSL_TIME_SPEC(OSSL_TIME_SPEC **a, const unsigned char **in, long len)` — the decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC(
    a: *mut *mut OsslTimeSpec,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTimeSpec {
    // SAFETY: the caller's contract for the three pointers.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_TIME_SPEC_it()).cast::<OsslTimeSpec>() }
}
/// `int i2d_OSSL_TIME_SPEC(const OSSL_TIME_SPEC *a, unsigned char **out)` — the encoder.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC(
    a: *const OsslTimeSpec,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: `a` is NULL or live; `out` is NULL or a writable cursor.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TIME_SPEC_it()) }
}

// ---------------------------------------------------------------------------------------------
// The printers — `crypto/x509/v3_timespec.c:127-587`.
// ---------------------------------------------------------------------------------------------

// The `#define`s the printers switch on, read from `include/openssl/x509v3.h`. The selector and bit
// numbers are `c_int` (they compare against `type_` fields and index bit strings); the day/month
// numbers compared against the `int64_t` that `ASN1_INTEGER_get_int64` yields are `i64`.

/// `#define OSSL_NAMED_DAY_TYPE_INT 0` — `include/openssl/x509v3.h:1150`.
const OSSL_NAMED_DAY_TYPE_INT: c_int = 0;
/// `#define OSSL_NAMED_DAY_TYPE_BIT 1` — `include/openssl/x509v3.h:1151`.
const OSSL_NAMED_DAY_TYPE_BIT: c_int = 1;
/// `#define OSSL_TIME_SPEC_X_DAY_OF_FIRST 0` — `include/openssl/x509v3.h:1175`.
const OSSL_TIME_SPEC_X_DAY_OF_FIRST: c_int = 0;
/// `#define OSSL_TIME_SPEC_X_DAY_OF_SECOND 1` — `include/openssl/x509v3.h:1176`.
const OSSL_TIME_SPEC_X_DAY_OF_SECOND: c_int = 1;
/// `#define OSSL_TIME_SPEC_X_DAY_OF_THIRD 2` — `include/openssl/x509v3.h:1177`.
const OSSL_TIME_SPEC_X_DAY_OF_THIRD: c_int = 2;
/// `#define OSSL_TIME_SPEC_X_DAY_OF_FOURTH 3` — `include/openssl/x509v3.h:1178`.
const OSSL_TIME_SPEC_X_DAY_OF_FOURTH: c_int = 3;
/// `#define OSSL_TIME_SPEC_X_DAY_OF_FIFTH 4` — `include/openssl/x509v3.h:1179`.
const OSSL_TIME_SPEC_X_DAY_OF_FIFTH: c_int = 4;
/// `#define OSSL_TIME_SPEC_DAY_TYPE_INT 0` — `include/openssl/x509v3.h:1192`.
const OSSL_TIME_SPEC_DAY_TYPE_INT: c_int = 0;
/// `#define OSSL_TIME_SPEC_DAY_TYPE_BIT 1` — `include/openssl/x509v3.h:1193`.
const OSSL_TIME_SPEC_DAY_TYPE_BIT: c_int = 1;
/// `#define OSSL_TIME_SPEC_DAY_TYPE_DAY_OF 2` — `include/openssl/x509v3.h:1194`.
const OSSL_TIME_SPEC_DAY_TYPE_DAY_OF: c_int = 2;
/// `#define OSSL_TIME_SPEC_DAY_BIT_SUN 0` — `include/openssl/x509v3.h:1195`.
const OSSL_TIME_SPEC_DAY_BIT_SUN: c_int = 0;
/// `#define OSSL_TIME_SPEC_DAY_BIT_SAT 6` — `include/openssl/x509v3.h:1201`.
const OSSL_TIME_SPEC_DAY_BIT_SAT: c_int = 6;
/// `#define OSSL_TIME_SPEC_WEEKS_TYPE_ALL 0` — `include/openssl/x509v3.h:1219`.
const OSSL_TIME_SPEC_WEEKS_TYPE_ALL: c_int = 0;
/// `#define OSSL_TIME_SPEC_WEEKS_TYPE_INT 1` — `include/openssl/x509v3.h:1220`.
const OSSL_TIME_SPEC_WEEKS_TYPE_INT: c_int = 1;
/// `#define OSSL_TIME_SPEC_WEEKS_TYPE_BIT 2` — `include/openssl/x509v3.h:1221`.
const OSSL_TIME_SPEC_WEEKS_TYPE_BIT: c_int = 2;
/// `#define OSSL_TIME_SPEC_BIT_WEEKS_1 0` — `include/openssl/x509v3.h:1222`.
const OSSL_TIME_SPEC_BIT_WEEKS_1: c_int = 0;
/// `#define OSSL_TIME_SPEC_BIT_WEEKS_5 4` — `include/openssl/x509v3.h:1226`.
const OSSL_TIME_SPEC_BIT_WEEKS_5: c_int = 4;
/// `#define OSSL_TIME_SPEC_MONTH_TYPE_ALL 0` — `include/openssl/x509v3.h:1237`.
const OSSL_TIME_SPEC_MONTH_TYPE_ALL: c_int = 0;
/// `#define OSSL_TIME_SPEC_MONTH_TYPE_INT 1` — `include/openssl/x509v3.h:1238`.
const OSSL_TIME_SPEC_MONTH_TYPE_INT: c_int = 1;
/// `#define OSSL_TIME_SPEC_MONTH_TYPE_BIT 2` — `include/openssl/x509v3.h:1239`.
const OSSL_TIME_SPEC_MONTH_TYPE_BIT: c_int = 2;
/// `#define OSSL_TIME_SPEC_BIT_MONTH_JAN 0` — `include/openssl/x509v3.h:1252`.
const OSSL_TIME_SPEC_BIT_MONTH_JAN: c_int = 0;
/// `#define OSSL_TIME_SPEC_BIT_MONTH_DEC 11` — `include/openssl/x509v3.h:1263`.
const OSSL_TIME_SPEC_BIT_MONTH_DEC: c_int = 11;
/// `#define OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE 0` — `include/openssl/x509v3.h:1282`.
const OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE: c_int = 0;
/// `#define OSSL_TIME_SPEC_TIME_TYPE_PERIODIC 1` — `include/openssl/x509v3.h:1283`.
const OSSL_TIME_SPEC_TIME_TYPE_PERIODIC: c_int = 1;

/// `#define OSSL_TIME_SPEC_INT_MONTH_JAN 1` — `include/openssl/x509v3.h:1240`.
const OSSL_TIME_SPEC_INT_MONTH_JAN: i64 = 1;
/// `#define OSSL_TIME_SPEC_INT_MONTH_FEB 2` — `include/openssl/x509v3.h:1241`.
const OSSL_TIME_SPEC_INT_MONTH_FEB: i64 = 2;
/// `#define OSSL_TIME_SPEC_INT_MONTH_MAR 3` — `include/openssl/x509v3.h:1242`.
const OSSL_TIME_SPEC_INT_MONTH_MAR: i64 = 3;
/// `#define OSSL_TIME_SPEC_INT_MONTH_APR 4` — `include/openssl/x509v3.h:1243`.
const OSSL_TIME_SPEC_INT_MONTH_APR: i64 = 4;
/// `#define OSSL_TIME_SPEC_INT_MONTH_MAY 5` — `include/openssl/x509v3.h:1244`.
const OSSL_TIME_SPEC_INT_MONTH_MAY: i64 = 5;
/// `#define OSSL_TIME_SPEC_INT_MONTH_JUN 6` — `include/openssl/x509v3.h:1245`.
const OSSL_TIME_SPEC_INT_MONTH_JUN: i64 = 6;
/// `#define OSSL_TIME_SPEC_INT_MONTH_JUL 7` — `include/openssl/x509v3.h:1246`.
const OSSL_TIME_SPEC_INT_MONTH_JUL: i64 = 7;
/// `#define OSSL_TIME_SPEC_INT_MONTH_AUG 8` — `include/openssl/x509v3.h:1247`.
const OSSL_TIME_SPEC_INT_MONTH_AUG: i64 = 8;
/// `#define OSSL_TIME_SPEC_INT_MONTH_SEP 9` — `include/openssl/x509v3.h:1248`.
const OSSL_TIME_SPEC_INT_MONTH_SEP: i64 = 9;
/// `#define OSSL_TIME_SPEC_INT_MONTH_OCT 10` — `include/openssl/x509v3.h:1249`.
const OSSL_TIME_SPEC_INT_MONTH_OCT: i64 = 10;
/// `#define OSSL_TIME_SPEC_INT_MONTH_NOV 11` — `include/openssl/x509v3.h:1250`.
const OSSL_TIME_SPEC_INT_MONTH_NOV: i64 = 11;
/// `#define OSSL_TIME_SPEC_INT_MONTH_DEC 12` — `include/openssl/x509v3.h:1251`.
const OSSL_TIME_SPEC_INT_MONTH_DEC: i64 = 12;

/// `#define OSSL_TIME_SPEC_DAY_INT_SUN 1` — `include/openssl/x509v3.h:1202`.
const OSSL_TIME_SPEC_DAY_INT_SUN: i64 = 1;
/// `#define OSSL_TIME_SPEC_DAY_INT_MON 2` — `include/openssl/x509v3.h:1203`.
const OSSL_TIME_SPEC_DAY_INT_MON: i64 = 2;
/// `#define OSSL_TIME_SPEC_DAY_INT_TUE 3` — `include/openssl/x509v3.h:1204`.
const OSSL_TIME_SPEC_DAY_INT_TUE: i64 = 3;
/// `#define OSSL_TIME_SPEC_DAY_INT_WED 4` — `include/openssl/x509v3.h:1205`.
const OSSL_TIME_SPEC_DAY_INT_WED: i64 = 4;
/// `#define OSSL_TIME_SPEC_DAY_INT_THU 5` — `include/openssl/x509v3.h:1206`.
const OSSL_TIME_SPEC_DAY_INT_THU: i64 = 5;
/// `#define OSSL_TIME_SPEC_DAY_INT_FRI 6` — `include/openssl/x509v3.h:1207`.
const OSSL_TIME_SPEC_DAY_INT_FRI: i64 = 6;
/// `#define OSSL_TIME_SPEC_DAY_INT_SAT 7` — `include/openssl/x509v3.h:1208`.
const OSSL_TIME_SPEC_DAY_INT_SAT: i64 = 7;

/// `#define OSSL_NAMED_DAY_INT_SUN 1` — `include/openssl/x509v3.h:1152`.
const OSSL_NAMED_DAY_INT_SUN: i64 = 1;
/// `#define OSSL_NAMED_DAY_INT_MON 2` — `include/openssl/x509v3.h:1153`.
const OSSL_NAMED_DAY_INT_MON: i64 = 2;
/// `#define OSSL_NAMED_DAY_INT_TUE 3` — `include/openssl/x509v3.h:1154`.
const OSSL_NAMED_DAY_INT_TUE: i64 = 3;
/// `#define OSSL_NAMED_DAY_INT_WED 4` — `include/openssl/x509v3.h:1155`.
const OSSL_NAMED_DAY_INT_WED: i64 = 4;
/// `#define OSSL_NAMED_DAY_INT_THU 5` — `include/openssl/x509v3.h:1156`.
const OSSL_NAMED_DAY_INT_THU: i64 = 5;
/// `#define OSSL_NAMED_DAY_INT_FRI 6` — `include/openssl/x509v3.h:1157`.
const OSSL_NAMED_DAY_INT_FRI: i64 = 6;
/// `#define OSSL_NAMED_DAY_INT_SAT 7` — `include/openssl/x509v3.h:1158`.
const OSSL_NAMED_DAY_INT_SAT: i64 = 7;

/// `static const char *WEEKDAY_NAMES[7]` — `crypto/x509/v3_timespec.c:16-24`.
static WEEKDAY_NAMES: [&core::ffi::CStr; 7] =
    [c"SUN", c"MON", c"TUE", c"WED", c"THU", c"FRI", c"SAT"];

/// `static const char *WEEK_NAMES[5]` — `crypto/x509/v3_timespec.c:26-32`.
static WEEK_NAMES: [&core::ffi::CStr; 5] = [c"first", c"second", c"third", c"fourth", c"final"];

/// `static const char *MONTH_NAMES[12]` — `crypto/x509/v3_timespec.c:34-47`. Note `SEPT`, which
/// differs from the `SEP` `print_int_month` spells.
static MONTH_NAMES: [&core::ffi::CStr; 12] = [
    c"JAN", c"FEB", c"MAR", c"APR", c"MAY", c"JUN", c"JUL", c"AUG", c"SEPT", c"OCT", c"NOV", c"DEC",
];

/// `static int i2r_OSSL_TIME_SPEC_ABSOLUTE(X509V3_EXT_METHOD *method, OSSL_TIME_SPEC_ABSOLUTE
/// *time, BIO *out, int indent)` — `crypto/x509/v3_timespec.c:127-156`.
unsafe fn i2r_OSSL_TIME_SPEC_ABSOLUTE(
    _method: *const X509V3ExtMethod,
    time: *mut OsslTimeSpecAbsolute,
    out: *mut Bio,
    _indent: c_int,
) -> c_int {
    // SAFETY: `time` is live per the caller's contract.
    let (start, end) = unsafe { ((*time).startTime, (*time).endTime) };
    if !start.is_null() && !end.is_null() {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"Any time between ".as_ptr()) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; `start` is live.
        if unsafe { ossl_asn1_time_print_ex(out, start, 0) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c" and ".as_ptr()) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; `end` is live.
        if unsafe { ossl_asn1_time_print_ex(out, end, 0) } == 0 {
            return 0;
        }
    } else if !start.is_null() {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"Any time after ".as_ptr()) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; `start` is live.
        if unsafe { ossl_asn1_time_print_ex(out, start, 0) } == 0 {
            return 0;
        }
        // SAFETY: `start` is live; `length`/`data` describe its bytes; the format matches.
        if unsafe { BIO_printf(out, c"%.*s".as_ptr(), (*start).length, (*start).data) } <= 0 {
            return 0;
        }
    } else if !end.is_null() {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"Any time until ".as_ptr()) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; `end` is live.
        if unsafe { ossl_asn1_time_print_ex(out, end, 0) } == 0 {
            return 0;
        }
    } else {
        // SAFETY: `out` is live; the literal is static.
        return unsafe { BIO_puts(out, c"INVALID (EMPTY)".as_ptr()) };
    }
    1
}

/// `static int i2r_OSSL_DAY_TIME(X509V3_EXT_METHOD *method, OSSL_DAY_TIME *dt, BIO *out, int
/// indent)` — `crypto/x509/v3_timespec.c:158-175`.
unsafe fn i2r_OSSL_DAY_TIME(
    _method: *const X509V3ExtMethod,
    dt: *mut OsslDayTime,
    out: *mut Bio,
    _indent: c_int,
) -> c_int {
    let mut h: i64 = 0;
    let mut m: i64 = 0;
    let mut s: i64 = 0;
    // SAFETY: `dt` is live per the caller's contract.
    let (hour, minute, second) = unsafe { ((*dt).hour, (*dt).minute, (*dt).second) };
    // SAFETY: `hour` is live;
    if hour.is_null() || unsafe { ASN1_INTEGER_get_int64(&raw mut h, hour) } == 0 {
        return 0;
    }
    // SAFETY: `minute` is live.
    if !minute.is_null() && unsafe { ASN1_INTEGER_get_int64(&raw mut m, minute) } == 0 {
        return 0;
    }
    // SAFETY: `second` is live.
    if !second.is_null() && unsafe { ASN1_INTEGER_get_int64(&raw mut s, second) } == 0 {
        return 0;
    }
    // SAFETY: `out` is live; the format and arguments are as declared.
    c_int::from(unsafe { BIO_printf(out, c"%02lld:%02lld:%02lld".as_ptr(), h, m, s) } > 0)
}

/// `static int i2r_OSSL_DAY_TIME_BAND(X509V3_EXT_METHOD *method, OSSL_DAY_TIME_BAND *band, BIO
/// *out, int indent)` — `crypto/x509/v3_timespec.c:177-196`.
unsafe fn i2r_OSSL_DAY_TIME_BAND(
    method: *const X509V3ExtMethod,
    band: *mut OsslDayTimeBand,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `band` is live per the caller's contract.
    let (start, end) = unsafe { ((*band).startDayTime, (*band).endDayTime) };
    if !start.is_null() {
        // SAFETY: `start` is live; `out` is live.
        if unsafe { i2r_OSSL_DAY_TIME(method, start, out, indent) } == 0 {
            return 0;
        }
    // SAFETY: `out` is live; the literal is static.
    } else if unsafe { BIO_puts(out, c"00:00:00".as_ptr()) } == 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_puts(out, c" - ".as_ptr()) } == 0 {
        return 0;
    }
    if !end.is_null() {
        // SAFETY: `end` is live; `out` is live.
        if unsafe { i2r_OSSL_DAY_TIME(method, end, out, indent) } == 0 {
            return 0;
        }
    // SAFETY: `out` is live; the literal is static.
    } else if unsafe { BIO_puts(out, c"23:59:59".as_ptr()) } == 0 {
        return 0;
    }
    1
}

/// `static int print_int_month(BIO *out, int64_t month)` — `crypto/x509/v3_timespec.c:198-229`.
/// `SEP`, not the `SEPT` of [`MONTH_NAMES`].
unsafe fn print_int_month(out: *mut Bio, month: i64) -> c_int {
    // SAFETY: `out` is live per the caller's contract; each literal is static.
    unsafe {
        match month {
            OSSL_TIME_SPEC_INT_MONTH_JAN => BIO_puts(out, c"JAN".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_FEB => BIO_puts(out, c"FEB".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_MAR => BIO_puts(out, c"MAR".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_APR => BIO_puts(out, c"APR".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_MAY => BIO_puts(out, c"MAY".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_JUN => BIO_puts(out, c"JUN".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_JUL => BIO_puts(out, c"JUL".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_AUG => BIO_puts(out, c"AUG".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_SEP => BIO_puts(out, c"SEP".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_OCT => BIO_puts(out, c"OCT".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_NOV => BIO_puts(out, c"NOV".as_ptr()),
            OSSL_TIME_SPEC_INT_MONTH_DEC => BIO_puts(out, c"DEC".as_ptr()),
            _ => 0,
        }
    }
}

/// `static int print_bit_month(BIO *out, ASN1_BIT_STRING *bs)` — `crypto/x509/v3_timespec.c:231-246`.
unsafe fn print_bit_month(out: *mut Bio, bs: *mut Asn1String) -> c_int {
    let mut i = OSSL_TIME_SPEC_BIT_MONTH_JAN;
    let mut j = 0;
    while i <= OSSL_TIME_SPEC_BIT_MONTH_DEC {
        // SAFETY: `bs` is live per the caller's contract.
        if unsafe { ASN1_BIT_STRING_get_bit(bs, i) } != 0 {
            // SAFETY: `out` is live; the literal is static.
            if j > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                return 0;
            }
            j += 1;
            // SAFETY: `out` is live; the name is a static literal.
            if unsafe { BIO_puts(out, MONTH_NAMES[i as usize].as_ptr()) } == 0 {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// `static int print_bit_week(BIO *out, ASN1_BIT_STRING *bs)` — `crypto/x509/v3_timespec.c:253-268`.
/// The fifth bit means "the final week", hence [`WEEK_NAMES`] rather than a numeric render.
unsafe fn print_bit_week(out: *mut Bio, bs: *mut Asn1String) -> c_int {
    let mut i = OSSL_TIME_SPEC_BIT_WEEKS_1;
    let mut j = 0;
    while i <= OSSL_TIME_SPEC_BIT_WEEKS_5 {
        // SAFETY: `bs` is live per the caller's contract.
        if unsafe { ASN1_BIT_STRING_get_bit(bs, i) } != 0 {
            // SAFETY: `out` is live; the literal is static.
            if j > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                return 0;
            }
            j += 1;
            // SAFETY: `out` is live; the name is a static literal.
            if unsafe { BIO_puts(out, WEEK_NAMES[i as usize].as_ptr()) } == 0 {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// `static int print_day_of_week(BIO *out, ASN1_BIT_STRING *bs)` —
/// `crypto/x509/v3_timespec.c:270-285`.
unsafe fn print_day_of_week(out: *mut Bio, bs: *mut Asn1String) -> c_int {
    let mut i = OSSL_TIME_SPEC_DAY_BIT_SUN;
    let mut j = 0;
    while i <= OSSL_TIME_SPEC_DAY_BIT_SAT {
        // SAFETY: `bs` is live per the caller's contract.
        if unsafe { ASN1_BIT_STRING_get_bit(bs, i) } != 0 {
            // SAFETY: `out` is live; the literal is static.
            if j > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                return 0;
            }
            j += 1;
            // SAFETY: `out` is live; the name is a static literal.
            if unsafe { BIO_puts(out, WEEKDAY_NAMES[i as usize].as_ptr()) } == 0 {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// `static int print_int_day_of_week(BIO *out, int64_t dow)` —
/// `crypto/x509/v3_timespec.c:287-308`.
unsafe fn print_int_day_of_week(out: *mut Bio, dow: i64) -> c_int {
    // SAFETY: `out` is live per the caller's contract; each literal is static.
    unsafe {
        match dow {
            OSSL_TIME_SPEC_DAY_INT_SUN => BIO_puts(out, c"SUN".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_MON => BIO_puts(out, c"MON".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_TUE => BIO_puts(out, c"TUE".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_WED => BIO_puts(out, c"WED".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_THU => BIO_puts(out, c"THU".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_FRI => BIO_puts(out, c"FRI".as_ptr()),
            OSSL_TIME_SPEC_DAY_INT_SAT => BIO_puts(out, c"SAT".as_ptr()),
            _ => 0,
        }
    }
}

/// `static int print_int_named_day(BIO *out, int64_t nd)` — `crypto/x509/v3_timespec.c:310-331`.
unsafe fn print_int_named_day(out: *mut Bio, nd: i64) -> c_int {
    // SAFETY: `out` is live per the caller's contract; each literal is static.
    unsafe {
        match nd {
            OSSL_NAMED_DAY_INT_SUN => BIO_puts(out, c"SUN".as_ptr()),
            OSSL_NAMED_DAY_INT_MON => BIO_puts(out, c"MON".as_ptr()),
            OSSL_NAMED_DAY_INT_TUE => BIO_puts(out, c"TUE".as_ptr()),
            OSSL_NAMED_DAY_INT_WED => BIO_puts(out, c"WED".as_ptr()),
            OSSL_NAMED_DAY_INT_THU => BIO_puts(out, c"THU".as_ptr()),
            OSSL_NAMED_DAY_INT_FRI => BIO_puts(out, c"FRI".as_ptr()),
            OSSL_NAMED_DAY_INT_SAT => BIO_puts(out, c"SAT".as_ptr()),
            _ => 0,
        }
    }
}

/// `static int print_bit_named_day(BIO *out, ASN1_BIT_STRING *bs)` —
/// `crypto/x509/v3_timespec.c:333-336`.
unsafe fn print_bit_named_day(out: *mut Bio, bs: *mut Asn1String) -> c_int {
    // SAFETY: `out` and `bs` are live per the caller's contract.
    unsafe { print_day_of_week(out, bs) }
}

/// `static int i2r_OSSL_PERIOD(X509V3_EXT_METHOD *method, OSSL_TIME_PERIOD *p, BIO *out, int
/// indent)` — `crypto/x509/v3_timespec.c:338-535`.
unsafe fn i2r_OSSL_PERIOD(
    method: *const X509V3ExtMethod,
    p: *mut OsslTimePeriod,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `p` is live per the caller's contract.
    let (times_of_day, days, weeks, months, years) = unsafe {
        (
            (*p).timesOfDay,
            (*p).days,
            (*p).weeks,
            (*p).months,
            (*p).years,
        )
    };
    // SAFETY: `out` is live; the format and arguments are as declared.
    if unsafe { BIO_printf(out, c"%*sPeriod:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    if !times_of_day.is_null() {
        // SAFETY: `out` is live; the format and arguments are as declared.
        if unsafe {
            BIO_printf(
                out,
                c"%*sDaytime bands:\n".as_ptr(),
                indent + 4,
                c"".as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `times_of_day` is a live stack.
        let num = unsafe { OPENSSL_sk_num(times_of_day) };
        let mut i = 0;
        while i < num {
            // SAFETY: `i` is in bounds.
            let band = unsafe { OPENSSL_sk_value(times_of_day, i) }.cast::<OsslDayTimeBand>();
            // SAFETY: `out` is live; the format and arguments are as declared.
            if unsafe { BIO_printf(out, c"%*s".as_ptr(), indent + 8, c"".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: `band` is live; `out` is live.
            if unsafe { i2r_OSSL_DAY_TIME_BAND(method, band, out, indent + 8) } == 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            if unsafe { BIO_puts(out, c"\n".as_ptr()) } == 0 {
                return 0;
            }
            i += 1;
        }
    }
    if !days.is_null() {
        // SAFETY: `days` is live.
        if unsafe { (*days).type_ } == OSSL_TIME_SPEC_DAY_TYPE_INT {
            if !weeks.is_null() {
                // SAFETY: `out` is live; the format and arguments are as declared.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*sDays of the week: ".as_ptr(),
                        indent + 4,
                        c"".as_ptr(),
                    )
                } <= 0
                {
                    return 0;
                }
            } else if !months.is_null() {
                // SAFETY: `out` is live; the format and arguments are as declared.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*sDays of the month: ".as_ptr(),
                        indent + 4,
                        c"".as_ptr(),
                    )
                } <= 0
                {
                    return 0;
                }
            } else if !years.is_null() {
                // SAFETY: `out` is live; the format and arguments are as declared.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*sDays of the year: ".as_ptr(),
                        indent + 4,
                        c"".as_ptr(),
                    )
                } <= 0
                {
                    return 0;
                }
            }
        // SAFETY: `out` is live; the format and arguments are as declared.
        } else if unsafe { BIO_printf(out, c"%*sDays: ".as_ptr(), indent + 4, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `days` is live.
        match unsafe { (*days).type_ } {
            OSSL_TIME_SPEC_DAY_TYPE_INT => {
                // SAFETY: the `intDay` arm is live under this selector.
                let ints = unsafe { (*days).choice.cast::<OpenSslStack>() };
                // SAFETY: `ints` is a live stack.
                let n = unsafe { OPENSSL_sk_num(ints) };
                let mut i = 0;
                while i < n {
                    // SAFETY: `i` is in bounds.
                    let big = unsafe { OPENSSL_sk_value(ints, i) }.cast::<Asn1String>();
                    let mut small: i64 = 0;
                    // SAFETY: `big` is live; `small` is a writable local.
                    if unsafe { ASN1_INTEGER_get_int64(&raw mut small, big) } == 0 {
                        return 0;
                    }
                    // SAFETY: `out` is live; the literal is static.
                    if i > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                        return 0;
                    }
                    if !weeks.is_null() {
                        // SAFETY: `out` is live; `small` is a value.
                        if unsafe { print_int_day_of_week(out, small) } == 0 {
                            return 0;
                        }
                    // SAFETY: `out` is live; the format and argument are as declared.
                    } else if unsafe { BIO_printf(out, c"%lld".as_ptr(), small) } <= 0 {
                        return 0;
                    }
                    i += 1;
                }
            }
            OSSL_TIME_SPEC_DAY_TYPE_BIT => {
                // SAFETY: the `bitDay` arm is live under this selector.
                let bs = unsafe { (*days).choice.cast::<Asn1String>() };
                // SAFETY: `bs` is live; `out` is live.
                if unsafe { print_day_of_week(out, bs) } == 0 {
                    return 0;
                }
            }
            OSSL_TIME_SPEC_DAY_TYPE_DAY_OF => {
                // SAFETY: the `dayOf` arm is live under this selector.
                let day_of = unsafe { (*days).choice.cast::<OsslTimeSpecXDayOf>() };
                // SAFETY: `day_of` is live.
                let nd: *mut OsslNamedDay = match unsafe { (*day_of).type_ } {
                    // SAFETY: `out` is live; each literal is static; the arm is live under its tag.
                    OSSL_TIME_SPEC_X_DAY_OF_FIRST => {
                        // SAFETY: `out` is live; the literal is static.
                        if unsafe { BIO_puts(out, c"FIRST ".as_ptr()) } == 0 {
                            return 0;
                        }
                        // SAFETY: this arm's tag selects the live `OsslNamedDay` in `day_of.choice`.
                        unsafe { (*day_of).choice.cast::<OsslNamedDay>() }
                    }
                    OSSL_TIME_SPEC_X_DAY_OF_SECOND => {
                        // SAFETY: `out` is live; the literal is static.
                        if unsafe { BIO_puts(out, c"SECOND ".as_ptr()) } == 0 {
                            return 0;
                        }
                        // SAFETY: this arm's tag selects the live `OsslNamedDay` in `day_of.choice`.
                        unsafe { (*day_of).choice.cast::<OsslNamedDay>() }
                    }
                    OSSL_TIME_SPEC_X_DAY_OF_THIRD => {
                        // SAFETY: `out` is live; the literal is static.
                        if unsafe { BIO_puts(out, c"THIRD ".as_ptr()) } == 0 {
                            return 0;
                        }
                        // SAFETY: this arm's tag selects the live `OsslNamedDay` in `day_of.choice`.
                        unsafe { (*day_of).choice.cast::<OsslNamedDay>() }
                    }
                    OSSL_TIME_SPEC_X_DAY_OF_FOURTH => {
                        // SAFETY: `out` is live; the literal is static.
                        if unsafe { BIO_puts(out, c"FOURTH ".as_ptr()) } == 0 {
                            return 0;
                        }
                        // SAFETY: this arm's tag selects the live `OsslNamedDay` in `day_of.choice`.
                        unsafe { (*day_of).choice.cast::<OsslNamedDay>() }
                    }
                    OSSL_TIME_SPEC_X_DAY_OF_FIFTH => {
                        // SAFETY: `out` is live; the literal is static.
                        if unsafe { BIO_puts(out, c"FIFTH ".as_ptr()) } == 0 {
                            return 0;
                        }
                        // SAFETY: this arm's tag selects the live `OsslNamedDay` in `day_of.choice`.
                        unsafe { (*day_of).choice.cast::<OsslNamedDay>() }
                    }
                    _ => return 0,
                };
                // SAFETY: `nd` is live.
                match unsafe { (*nd).type_ } {
                    OSSL_NAMED_DAY_TYPE_INT => {
                        // SAFETY: the `intNamedDays` arm is live under this selector.
                        let iv = unsafe { (*nd).choice.cast::<Asn1String>() };
                        let mut small: i64 = 0;
                        // SAFETY: `iv` is live; `small` is a writable local.
                        if unsafe { ASN1_INTEGER_get_int64(&raw mut small, iv) } == 0 {
                            return 0;
                        }
                        // SAFETY: `out` is live; `small` is a value.
                        if unsafe { print_int_named_day(out, small) } == 0 {
                            return 0;
                        }
                    }
                    OSSL_NAMED_DAY_TYPE_BIT => {
                        // SAFETY: the `bitNamedDays` arm is live under this selector.
                        let bs = unsafe { (*nd).choice.cast::<Asn1String>() };
                        // SAFETY: `bs` is live; `out` is live.
                        if unsafe { print_bit_named_day(out, bs) } == 0 {
                            return 0;
                        }
                    }
                    _ => return 0,
                }
            }
            _ => return 0,
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } == 0 {
            return 0;
        }
    }
    if !weeks.is_null() {
        // SAFETY: `weeks` is live.
        if unsafe { (*weeks).type_ } == OSSL_TIME_SPEC_WEEKS_TYPE_INT {
            if !months.is_null() {
                // SAFETY: `out` is live; the format and arguments are as declared.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*sWeeks of the month: ".as_ptr(),
                        indent + 4,
                        c"".as_ptr(),
                    )
                } <= 0
                {
                    return 0;
                }
            } else if !years.is_null() {
                // SAFETY: `out` is live; the format and arguments are as declared.
                if unsafe {
                    BIO_printf(
                        out,
                        c"%*sWeeks of the year: ".as_ptr(),
                        indent + 4,
                        c"".as_ptr(),
                    )
                } <= 0
                {
                    return 0;
                }
            }
        // SAFETY: `out` is live; the format and arguments are as declared.
        } else if unsafe { BIO_printf(out, c"%*sWeeks: ".as_ptr(), indent + 4, c"".as_ptr()) } <= 0
        {
            return 0;
        }
        // SAFETY: `weeks` is live.
        match unsafe { (*weeks).type_ } {
            OSSL_TIME_SPEC_WEEKS_TYPE_ALL => {
                // SAFETY: `out` is live; the literal is static.
                if unsafe { BIO_puts(out, c"ALL".as_ptr()) } == 0 {
                    return 0;
                }
            }
            OSSL_TIME_SPEC_WEEKS_TYPE_INT => {
                // SAFETY: the `intWeek` arm is live under this selector.
                let ints = unsafe { (*weeks).choice.cast::<OpenSslStack>() };
                // SAFETY: `ints` is a live stack.
                let n = unsafe { OPENSSL_sk_num(ints) };
                let mut i = 0;
                while i < n {
                    // SAFETY: `i` is in bounds.
                    let big = unsafe { OPENSSL_sk_value(ints, i) }.cast::<Asn1String>();
                    let mut small: i64 = 0;
                    // SAFETY: `big` is live; `small` is a writable local.
                    if unsafe { ASN1_INTEGER_get_int64(&raw mut small, big) } == 0 {
                        return 0;
                    }
                    // SAFETY: `out` is live; the literal is static.
                    if i > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                        return 0;
                    }
                    // SAFETY: `out` is live; the format and argument are as declared.
                    if unsafe { BIO_printf(out, c"%lld".as_ptr(), small) } == 0 {
                        return 0;
                    }
                    i += 1;
                }
            }
            OSSL_TIME_SPEC_WEEKS_TYPE_BIT => {
                // SAFETY: the `bitWeek` arm is live under this selector.
                let bs = unsafe { (*weeks).choice.cast::<Asn1String>() };
                // SAFETY: `bs` is live; `out` is live.
                if unsafe { print_bit_week(out, bs) } == 0 {
                    return 0;
                }
            }
            _ => return 0,
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } == 0 {
            return 0;
        }
    }
    if !months.is_null() {
        // SAFETY: `out` is live; the format and arguments are as declared.
        if unsafe { BIO_printf(out, c"%*sMonths: ".as_ptr(), indent + 4, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `months` is live.
        match unsafe { (*months).type_ } {
            OSSL_TIME_SPEC_MONTH_TYPE_ALL => {
                // SAFETY: `out` is live; the literal is static.
                if unsafe { BIO_puts(out, c"ALL".as_ptr()) } == 0 {
                    return 0;
                }
            }
            OSSL_TIME_SPEC_MONTH_TYPE_INT => {
                // SAFETY: the `intMonth` arm is live under this selector.
                let ints = unsafe { (*months).choice.cast::<OpenSslStack>() };
                // SAFETY: `ints` is a live stack.
                let n = unsafe { OPENSSL_sk_num(ints) };
                let mut i = 0;
                while i < n {
                    // SAFETY: `i` is in bounds.
                    let big = unsafe { OPENSSL_sk_value(ints, i) }.cast::<Asn1String>();
                    let mut small: i64 = 0;
                    // SAFETY: `big` is live; `small` is a writable local.
                    if unsafe { ASN1_INTEGER_get_int64(&raw mut small, big) } == 0 {
                        return 0;
                    }
                    // SAFETY: `out` is live; the literal is static.
                    if i > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                        return 0;
                    }
                    // SAFETY: `out` is live; `small` is a value.
                    if unsafe { print_int_month(out, small) } == 0 {
                        return 0;
                    }
                    i += 1;
                }
            }
            OSSL_TIME_SPEC_MONTH_TYPE_BIT => {
                // SAFETY: the `bitMonth` arm is live under this selector.
                let bs = unsafe { (*months).choice.cast::<Asn1String>() };
                // SAFETY: `bs` is live; `out` is live.
                if unsafe { print_bit_month(out, bs) } == 0 {
                    return 0;
                }
            }
            _ => return 0,
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } == 0 {
            return 0;
        }
    }
    if !years.is_null() {
        // SAFETY: `out` is live; the format and arguments are as declared.
        if unsafe { BIO_printf(out, c"%*sYears: ".as_ptr(), indent + 4, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `years` is a live stack.
        let n = unsafe { OPENSSL_sk_num(years) };
        let mut i = 0;
        while i < n {
            // SAFETY: `i` is in bounds.
            let big = unsafe { OPENSSL_sk_value(years, i) }.cast::<Asn1String>();
            let mut small: i64 = 0;
            // SAFETY: `big` is live; `small` is a writable local.
            if unsafe { ASN1_INTEGER_get_int64(&raw mut small, big) } == 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            if i > 0 && unsafe { BIO_puts(out, c", ".as_ptr()) } == 0 {
                return 0;
            }
            // SAFETY: `out` is live; the format and argument are as declared.
            if unsafe { BIO_printf(out, c"%04lld".as_ptr(), small) } <= 0 {
                return 0;
            }
            i += 1;
        }
    }
    1
}

/// `static int i2r_OSSL_TIME_SPEC_TIME(X509V3_EXT_METHOD *method, OSSL_TIME_SPEC_TIME *time, BIO
/// *out, int indent)` — `crypto/x509/v3_timespec.c:537-566`.
unsafe fn i2r_OSSL_TIME_SPEC_TIME(
    method: *const X509V3ExtMethod,
    time: *mut OsslTimeSpecTime,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `time` is live per the caller's contract.
    match unsafe { (*time).type_ } {
        OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE => {
            // SAFETY: `out` is live; the format and arguments are as declared.
            if unsafe { BIO_printf(out, c"%*sAbsolute: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: the `absolute` arm is live under this selector.
            let abs = unsafe { (*time).choice.cast::<OsslTimeSpecAbsolute>() };
            // SAFETY: `abs` is live; `out` is live.
            if unsafe { i2r_OSSL_TIME_SPEC_ABSOLUTE(method, abs, out, indent + 4) } <= 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) }
        }
        OSSL_TIME_SPEC_TIME_TYPE_PERIODIC => {
            // SAFETY: `out` is live; the format and arguments are as declared.
            if unsafe { BIO_printf(out, c"%*sPeriodic:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: the `periodic` arm is live under this selector.
            let list = unsafe { (*time).choice.cast::<OpenSslStack>() };
            // SAFETY: `list` is a live stack.
            let n = unsafe { OPENSSL_sk_num(list) };
            let mut i = 0;
            while i < n {
                // SAFETY: `out` is live; the literal is static.
                if i > 0 && unsafe { BIO_puts(out, c"\n".as_ptr()) } == 0 {
                    return 0;
                }
                // SAFETY: `i` is in bounds.
                let tp = unsafe { OPENSSL_sk_value(list, i) }.cast::<OsslTimePeriod>();
                // SAFETY: `tp` is live; `out` is live.
                if unsafe { i2r_OSSL_PERIOD(method, tp, out, indent + 4) } == 0 {
                    return 0;
                }
                i += 1;
            }
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) }
        }
        _ => 0,
    }
}

/// `static int i2r_OSSL_TIME_SPEC(X509V3_EXT_METHOD *method, OSSL_TIME_SPEC *time, BIO *out, int
/// indent)` — `crypto/x509/v3_timespec.c:568-587`. The row's `i2r` callback.
unsafe extern "C" fn i2r_OSSL_TIME_SPEC(
    method: *const X509V3ExtMethod,
    time: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let ts = time.cast::<OsslTimeSpec>();
    // SAFETY: `ts` is live per the caller's contract.
    let time_zone = unsafe { (*ts).timeZone };
    if !time_zone.is_null() {
        let mut tz: i64 = 0;
        // SAFETY: `time_zone` is live; `tz` is a writable local.
        if unsafe { ASN1_INTEGER_get_int64(&raw mut tz, time_zone) } != 1 {
            return 0;
        }
        // SAFETY: `out` is live; the format and arguments are as declared.
        if unsafe {
            BIO_printf(
                out,
                c"%*sTimezone: UTC%+03lld:00\n".as_ptr(),
                indent,
                c"".as_ptr(),
                tz,
            )
        } <= 0
        {
            return 0;
        }
    }
    // SAFETY: `ts` is live.
    if unsafe { (*ts).notThisTime } > 0 {
        // SAFETY: `out` is live; the format and arguments are as declared.
        if unsafe { BIO_printf(out, c"%*sNOT this time:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
    // SAFETY: `out` is live; the format and arguments are as declared.
    } else if unsafe { BIO_printf(out, c"%*sTime:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `ts` is live; its `time` is a live value; `out` is live.
    unsafe { i2r_OSSL_TIME_SPEC_TIME(method, (*ts).time, out, indent + 4) }
}

/// `const X509V3_EXT_METHOD ossl_v3_time_specification` — `crypto/x509/v3_timespec.c:589-599`.
///
/// `ext_nid` is `NID_time_specification`, `ext_flags` is `X509V3_EXT_MULTILINE`, `it` is
/// `ASN1_ITEM_ref(OSSL_TIME_SPEC)` and `i2r` is `i2r_OSSL_TIME_SPEC`; every other slot is zero.
pub static ossl_v3_time_specification: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_time_specification,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(OSSL_TIME_SPEC_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_OSSL_TIME_SPEC),
    r2i: None,
    usr_data: ptr::null_mut(),
};
