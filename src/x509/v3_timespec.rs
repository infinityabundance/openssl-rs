//! `crypto/x509/v3_timespec.c` — the ITU-T X.509 (2019) time-specification items. Phase 10.13.
//!
//! `crypto/x509/v3_timespec.c` is 599 lines. **The twelve ASN.1 item groups and their generated
//! lifecycles land; the extension method and its twelve `static` printers are withheld by name**:
//!
//! * the eleven `ASN1_SEQUENCE`/`ASN1_CHOICE` templates (`:49-113`) and the
//!   `IMPLEMENT_ASN1_FUNCTIONS` group over them (`:115-125`) land. Every `*_it`/`_new`/`_free`/
//!   `d2i_*`/`i2d_*` is a public export (`x509v3.h`), so the differential plane can build each
//!   value, encode it and decode the bytes back.
//! * `ossl_v3_time_specification` (`:589-599`) is **withheld by name**: internal, and the admitted
//!   DSO exports no `ossl_v3_*` symbol (`nm -D`). Its only authority caller is
//!   `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`), which lands in
//!   [`crate::x509::v3_lib`]. The dispatch that could reach it by NID -- `X509V3_EXT_get_nid` --
//!   is withheld there because it searches `standard_exts[]` (`standard_exts.h:15-95`), which
//!   names ~63 `ossl_v3_*` tables from units this subphase does not own. See
//!   [`crate::x509::v3_lib`].
//! * the twelve printers -- `i2r_OSSL_TIME_SPEC_ABSOLUTE` (`:127-156`), `i2r_OSSL_DAY_TIME`
//!   (`:158-175`), `i2r_OSSL_DAY_TIME_BAND` (`:177-196`), the seven `print_*` helpers
//!   (`:198-336`), `i2r_OSSL_PERIOD` (`:338-535`), `i2r_OSSL_TIME_SPEC_TIME` (`:537-566`) and
//!   `i2r_OSSL_TIME_SPEC` (`:568-587`) -- are **withheld by name**: `static` functions reached
//!   only through the withheld table, so landing them would be dead code with no court.
//!
//! Nothing is stubbed: the withheld names are named rather than declared. The generated
//! lifecycle functions are written out one by one rather than produced by a `macro_rules!`
//! group: `prototype_court.py` refuses a macro that fills a *type* position (the `X` in
//! `X_new`/`d2i_X`/`i2d_X`), so the ABI of each would be uncheckable. That is why this file is
//! explicit where `src/x509/v3_pcia.rs` and `v3_pku.rs` are.
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

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it,
    ASN1_INTEGER_it, ASN1_NULL_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::stack::OpenSslStack;

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
