//! `crypto/ts/ts_asn1.c` — the RFC 3161 item groups. Phase 12.5.
//!
//! Every struct is the authority's `ts_local.h` spelling in its order; every template is its
//! `ASN1_SEQUENCE` macro expanded by hand, with the offsets taken from the struct so a layout
//! drift is a compile error rather than a silent re-reading. `TS_RESP` carries the authority's
//! `ts_resp_cb`, which owns the `tst_info` member the encoding does not describe.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
//! **Why the dead-code lint is off for this module.** As `asn1/layout.rs` and `cms/cms_asn1.rs`
//! record, this file is a projection of the authority's `ts_asn1.c`: the templates and helpers
//! the exported surface does not yet reach are the part of the contract the later subphases read,
//! not dead code.
#![allow(dead_code, non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::{ASN1_item_d2i_bio, ASN1_item_d2i_fp};
use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_i2d_fp::{ASN1_item_i2d_bio, ASN1_item_i2d_fp};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_FBOOLEAN_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::pkcs7::pk7_asn1::{PKCS7_it, Pkcs7};
use crate::pkcs7::pk7_lib::{pkcs7_get_detached, pkcs7_type_is_signed};
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_id_smime_ct_TSTInfo};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::x_exten::X509_EXTENSION_it;

use super::raise_ts;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_asn1.c";

/// `ASN1_ITEM_ref(type)` as a template's `item` slot: the item's accessor function cast to the
/// untyped `item` pointer the engine calls. `const` so a template's `static` initialiser may name
/// it.
const fn item_ref(f: extern "C" fn() -> *const Asn1Item) -> *mut c_void {
    f as *mut c_void
}

/// `TS_R_TOKEN_PRESENT` — `include/openssl/tserr.h`.
const TS_R_TOKEN_PRESENT: c_int = 131;
/// `TS_R_PKCS7_TO_TS_TST_INFO_FAILED` — `include/openssl/tserr.h`.
const TS_R_PKCS7_TO_TS_TST_INFO_FAILED: c_int = 129;
/// `TS_R_TOKEN_NOT_PRESENT` — `include/openssl/tserr.h`.
const TS_R_TOKEN_NOT_PRESENT: c_int = 130;
/// `TS_R_BAD_PKCS7_TYPE` — `include/openssl/tserr.h`.
const TS_R_BAD_PKCS7_TYPE: c_int = 132;
/// `TS_R_DETACHED_CONTENT` — `include/openssl/tserr.h`.
const TS_R_DETACHED_CONTENT: c_int = 134;
/// `TS_R_BAD_TYPE` — `include/openssl/tserr.h`.
const TS_R_BAD_TYPE: c_int = 133;

// ---------------------------------------------------------------------------------------------
// The structures — `ts_local.h`
// ---------------------------------------------------------------------------------------------

/// `TS_MSG_IMPRINT` — `ts_local.h:15-18`.
#[repr(C)]
pub(crate) struct TsMsgImprint {
    pub(crate) hash_algo: *mut X509Algor,
    pub(crate) hashed_msg: *mut Asn1String,
}

/// `TS_REQ` — `ts_local.h:42-49`.
#[repr(C)]
pub(crate) struct TsReq {
    pub(crate) version: *mut Asn1String,
    pub(crate) msg_imprint: *mut TsMsgImprint,
    pub(crate) policy_id: *mut Asn1Object,
    pub(crate) nonce: *mut Asn1String,
    pub(crate) cert_req: c_int,
    pub(crate) extensions: *mut OpenSslStack,
}

/// `TS_ACCURACY` — `ts_local.h:57-61`.
#[repr(C)]
pub(crate) struct TsAccuracy {
    pub(crate) seconds: *mut Asn1String,
    pub(crate) millis: *mut Asn1String,
    pub(crate) micros: *mut Asn1String,
}

/// `TS_TST_INFO` — `ts_local.h:82-93`.
#[repr(C)]
pub(crate) struct TsTstInfo {
    pub(crate) version: *mut Asn1String,
    pub(crate) policy_id: *mut Asn1Object,
    pub(crate) msg_imprint: *mut TsMsgImprint,
    pub(crate) serial: *mut Asn1String,
    pub(crate) time: *mut Asn1String,
    pub(crate) accuracy: *mut TsAccuracy,
    pub(crate) ordering: c_int,
    pub(crate) nonce: *mut Asn1String,
    pub(crate) tsa: *mut GeneralName,
    pub(crate) extensions: *mut OpenSslStack,
}

/// `TS_STATUS_INFO` — `ts_local.h:95-99`.
#[repr(C)]
pub(crate) struct TsStatusInfo {
    pub(crate) status: *mut Asn1String,
    pub(crate) text: *mut OpenSslStack,
    pub(crate) failure_info: *mut Asn1String,
}

/// `TS_RESP` — `ts_local.h:25-29`.
#[repr(C)]
pub(crate) struct TsResp {
    pub(crate) status_info: *mut TsStatusInfo,
    pub(crate) token: *mut Pkcs7,
    pub(crate) tst_info: *mut TsTstInfo,
}

// The struct sizes and offsets the templates below depend on, so a layout drift fails the build.
const _: () = {
    assert!(core::mem::offset_of!(TsMsgImprint, hash_algo) == 0);
    assert!(core::mem::offset_of!(TsMsgImprint, hashed_msg) == 8);
    assert!(core::mem::offset_of!(TsReq, version) == 0);
    assert!(core::mem::offset_of!(TsReq, msg_imprint) == 8);
    assert!(core::mem::offset_of!(TsReq, policy_id) == 16);
    assert!(core::mem::offset_of!(TsReq, nonce) == 24);
    assert!(core::mem::offset_of!(TsReq, cert_req) == 32);
    assert!(core::mem::offset_of!(TsReq, extensions) == 40);
    assert!(core::mem::offset_of!(TsAccuracy, seconds) == 0);
    assert!(core::mem::offset_of!(TsAccuracy, millis) == 8);
    assert!(core::mem::offset_of!(TsAccuracy, micros) == 16);
    assert!(core::mem::offset_of!(TsTstInfo, version) == 0);
    assert!(core::mem::offset_of!(TsTstInfo, policy_id) == 8);
    assert!(core::mem::offset_of!(TsTstInfo, msg_imprint) == 16);
    assert!(core::mem::offset_of!(TsTstInfo, serial) == 24);
    assert!(core::mem::offset_of!(TsTstInfo, time) == 32);
    assert!(core::mem::offset_of!(TsTstInfo, accuracy) == 40);
    assert!(core::mem::offset_of!(TsTstInfo, ordering) == 48);
    assert!(core::mem::offset_of!(TsTstInfo, nonce) == 56);
    assert!(core::mem::offset_of!(TsTstInfo, tsa) == 64);
    assert!(core::mem::offset_of!(TsTstInfo, extensions) == 72);
    assert!(core::mem::offset_of!(TsStatusInfo, status) == 0);
    assert!(core::mem::offset_of!(TsStatusInfo, text) == 8);
    assert!(core::mem::offset_of!(TsStatusInfo, failure_info) == 16);
    assert!(core::mem::offset_of!(TsResp, status_info) == 0);
    assert!(core::mem::offset_of!(TsResp, token) == 8);
    assert!(core::mem::offset_of!(TsResp, tst_info) == 16);
};

// ---------------------------------------------------------------------------------------------
// TS_MSG_IMPRINT
// ---------------------------------------------------------------------------------------------

static TS_MSG_IMPRINT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsMsgImprint, hash_algo) as c_ulong,
        field_name: c"hashAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsMsgImprint, hashed_msg) as c_ulong,
        field_name: c"hashedMessage".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static TS_MSG_IMPRINT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_MSG_IMPRINT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<TsMsgImprint>() as c_long,
    sname: c"TS_MSG_IMPRINT".as_ptr(),
};

pub(crate) extern "C" fn ts_msg_imprint_it() -> *const Asn1Item {
    &TS_MSG_IMPRINT_ITEM
}

// ---------------------------------------------------------------------------------------------
// TS_REQ
// ---------------------------------------------------------------------------------------------

static TS_REQ_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, version) as c_ulong,
        field_name: c"version".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, msg_imprint) as c_ulong,
        field_name: c"messageImprint".as_ptr(),
        item: item_ref(ts_msg_imprint_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, policy_id) as c_ulong,
        field_name: c"reqPolicy".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, nonce) as c_ulong,
        field_name: c"nonce".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, cert_req) as c_ulong,
        field_name: c"certReq".as_ptr(),
        item: item_ref(ASN1_FBOOLEAN_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsReq, extensions) as c_ulong,
        field_name: c"extensions".as_ptr(),
        item: item_ref(X509_EXTENSION_it),
    },
];

static TS_REQ_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_REQ_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<TsReq>() as c_long,
    sname: c"TS_REQ".as_ptr(),
};

pub(crate) extern "C" fn ts_req_it() -> *const Asn1Item {
    &TS_REQ_ITEM
}

// ---------------------------------------------------------------------------------------------
// TS_ACCURACY
// ---------------------------------------------------------------------------------------------

static TS_ACCURACY_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsAccuracy, seconds) as c_ulong,
        field_name: c"seconds".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsAccuracy, millis) as c_ulong,
        field_name: c"millis".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: core::mem::offset_of!(TsAccuracy, micros) as c_ulong,
        field_name: c"micros".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
];

static TS_ACCURACY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_ACCURACY_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<TsAccuracy>() as c_long,
    sname: c"TS_ACCURACY".as_ptr(),
};

pub(crate) extern "C" fn ts_accuracy_it() -> *const Asn1Item {
    &TS_ACCURACY_ITEM
}

// ---------------------------------------------------------------------------------------------
// TS_TST_INFO
// ---------------------------------------------------------------------------------------------

static TS_TST_INFO_TT: [Asn1Template; 10] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, version) as c_ulong,
        field_name: c"version".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, policy_id) as c_ulong,
        field_name: c"policy".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, msg_imprint) as c_ulong,
        field_name: c"messageImprint".as_ptr(),
        item: item_ref(ts_msg_imprint_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, serial) as c_ulong,
        field_name: c"serialNumber".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, time) as c_ulong,
        field_name: c"genTime".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_GENERALIZEDTIME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, accuracy) as c_ulong,
        field_name: c"accuracy".as_ptr(),
        item: item_ref(ts_accuracy_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, ordering) as c_ulong,
        field_name: c"ordering".as_ptr(),
        item: item_ref(ASN1_FBOOLEAN_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, nonce) as c_ulong,
        field_name: c"nonce".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsTstInfo, tsa) as c_ulong,
        field_name: c"tsa".as_ptr(),
        item: item_ref(GENERAL_NAME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: core::mem::offset_of!(TsTstInfo, extensions) as c_ulong,
        field_name: c"extensions".as_ptr(),
        item: item_ref(X509_EXTENSION_it),
    },
];

static TS_TST_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_TST_INFO_TT.as_ptr(),
    tcount: 10,
    funcs: ptr::null(),
    size: core::mem::size_of::<TsTstInfo>() as c_long,
    sname: c"TS_TST_INFO".as_ptr(),
};

pub(crate) extern "C" fn ts_tst_info_it() -> *const Asn1Item {
    &TS_TST_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// TS_STATUS_INFO
// ---------------------------------------------------------------------------------------------

static TS_STATUS_INFO_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsStatusInfo, status) as c_ulong,
        field_name: c"status".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsStatusInfo, text) as c_ulong,
        field_name: c"text".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_UTF8STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsStatusInfo, failure_info) as c_ulong,
        field_name: c"failureInfo".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_BIT_STRING_it),
    },
];

static TS_STATUS_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_STATUS_INFO_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<TsStatusInfo>() as c_long,
    sname: c"TS_STATUS_INFO".as_ptr(),
};

pub(crate) extern "C" fn ts_status_info_it() -> *const Asn1Item {
    &TS_STATUS_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// TS_RESP
// ---------------------------------------------------------------------------------------------

/// `ts_resp_set_tst_info(TS_RESP *a)` — `ts_asn1.c:133-156`. Fills `a->tst_info` from `a->token`
/// and enforces the `PKIStatusInfo`/token agreement the RFC describes.
///
/// # Safety
/// `a` is a live `TS_RESP`.
unsafe fn ts_resp_set_tst_info(a: *mut TsResp) -> c_int {
    // SAFETY: `a` is live per this function's contract and the status member is non-null on
    // every object the item layer builds.
    let status = unsafe { crate::asn1::prim::ASN1_INTEGER_get((*(*a).status_info).status) };

    // SAFETY: `a` is live.
    if !unsafe { (*a).token }.is_null() {
        if status != 0 && status != 1 {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 141, c"ts_resp_set_tst_info", TS_R_TOKEN_PRESENT) };
            return 0;
        }
        // SAFETY: `a` is live.
        unsafe {
            crate::ts::ts_asn1::TS_TST_INFO_free((*a).tst_info);
        }
        // SAFETY: `a` is live.
        let tst = unsafe { PKCS7_to_TS_TST_INFO((*a).token) };
        // SAFETY: `a` is live.
        unsafe { (*a).tst_info = tst };
        // SAFETY: `a` is live and `tst` just written.
        if unsafe { (*a).tst_info }.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe {
                raise_ts(
                    FILE,
                    147,
                    c"ts_resp_set_tst_info",
                    TS_R_PKCS7_TO_TS_TST_INFO_FAILED,
                )
            };
            return 0;
        }
    } else if status == 0 || status == 1 {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 151, c"ts_resp_set_tst_info", TS_R_TOKEN_NOT_PRESENT) };
        return 0;
    }

    1
}

/// `ts_resp_cb` — `ts_asn1.c:158-171`.
///
/// # Safety
/// The `ASN1_AUX` callback contract: `pval` is a live value slot.
unsafe extern "C" fn ts_resp_cb(
    op: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if op == ASN1_OP_NEW_POST {
        // SAFETY: `pval` is a live value slot per the callback contract.
        let resp = unsafe { (*pval).cast::<TsResp>() };
        // SAFETY: `resp` is the object just built.
        unsafe { (*resp).tst_info = ptr::null_mut() };
    } else if op == ASN1_OP_FREE_POST {
        // SAFETY: as above.
        let resp = unsafe { (*pval).cast::<TsResp>() };
        // SAFETY: `resp` is the object being freed.
        unsafe { TS_TST_INFO_free((*resp).tst_info) };
    } else if op == ASN1_OP_D2I_POST {
        // SAFETY: as above.
        let resp = unsafe { (*pval).cast::<TsResp>() };
        // SAFETY: `resp` is the decoded object.
        if unsafe { ts_resp_set_tst_info(resp) } == 0 {
            return 0;
        }
    }
    1
}

static TS_RESP_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(ts_resp_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static TS_RESP_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(TsResp, status_info) as c_ulong,
        field_name: c"status".as_ptr(),
        item: item_ref(ts_status_info_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: core::mem::offset_of!(TsResp, token) as c_ulong,
        field_name: c"timeStampToken".as_ptr(),
        item: item_ref(PKCS7_it),
    },
];

static TS_RESP_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: TS_RESP_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::addr_of!(TS_RESP_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<TsResp>() as c_long,
    sname: c"TS_RESP".as_ptr(),
};

pub(crate) extern "C" fn ts_resp_it() -> *const Asn1Item {
    &TS_RESP_ITEM
}

/// `Sync` wrapper for the `ASN1_AUX` static, as `cms_asn1.rs` does.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants, written once by the loader, no interior mutability reachable
// through a shared reference.
unsafe impl Sync for SyncAux {}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` and `IMPLEMENT_ASN1_DUP_FUNCTION` for the six types
// ---------------------------------------------------------------------------------------------

/// `TS_MSG_IMPRINT *TS_MSG_IMPRINT_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_MSG_IMPRINT_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_new() -> *mut TsMsgImprint {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_msg_imprint_it()) }.cast()
}

/// `void TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_free(a: *mut TsMsgImprint) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_msg_imprint_it()) };
}

/// `TS_MSG_IMPRINT *TS_MSG_IMPRINT_dup(const TS_MSG_IMPRINT *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_dup(x: *const TsMsgImprint) -> *mut TsMsgImprint {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_msg_imprint_it(), x.cast()) }.cast()
}

/// `TS_REQ *TS_REQ_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_REQ_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_new() -> *mut TsReq {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_req_it()) }.cast()
}

/// `void TS_REQ_free(TS_REQ *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_free(a: *mut TsReq) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_req_it()) };
}

/// `TS_REQ *TS_REQ_dup(const TS_REQ *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_dup(x: *const TsReq) -> *mut TsReq {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_req_it(), x.cast()) }.cast()
}

/// `TS_ACCURACY *TS_ACCURACY_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_ACCURACY_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_new() -> *mut TsAccuracy {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_accuracy_it()) }.cast()
}

/// `void TS_ACCURACY_free(TS_ACCURACY *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_free(a: *mut TsAccuracy) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_accuracy_it()) };
}

/// `TS_ACCURACY *TS_ACCURACY_dup(const TS_ACCURACY *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_dup(x: *const TsAccuracy) -> *mut TsAccuracy {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_accuracy_it(), x.cast()) }.cast()
}

/// `TS_TST_INFO *TS_TST_INFO_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_TST_INFO_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_new() -> *mut TsTstInfo {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_tst_info_it()) }.cast()
}

/// `void TS_TST_INFO_free(TS_TST_INFO *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_free(a: *mut TsTstInfo) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_tst_info_it()) };
}

/// `TS_TST_INFO *TS_TST_INFO_dup(const TS_TST_INFO *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_dup(x: *const TsTstInfo) -> *mut TsTstInfo {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_tst_info_it(), x.cast()) }.cast()
}

/// `TS_STATUS_INFO *TS_STATUS_INFO_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_STATUS_INFO_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_new() -> *mut TsStatusInfo {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_status_info_it()) }.cast()
}

/// `void TS_STATUS_INFO_free(TS_STATUS_INFO *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_free(a: *mut TsStatusInfo) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_status_info_it()) };
}

/// `TS_STATUS_INFO *TS_STATUS_INFO_dup(const TS_STATUS_INFO *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_dup(x: *const TsStatusInfo) -> *mut TsStatusInfo {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_status_info_it(), x.cast()) }.cast()
}

/// `TS_RESP *TS_RESP_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` in `ts_asn1.c`.
///
/// # Safety
/// The returned pointer must be released with `TS_RESP_free`.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_new() -> *mut TsResp {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(ts_resp_it()) }.cast()
}

/// `void TS_RESP_free(TS_RESP *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_free(a: *mut TsResp) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), ts_resp_it()) };
}

/// `TS_RESP *TS_RESP_dup(const TS_RESP *x)` — `IMPLEMENT_ASN1_DUP_FUNCTION`.
///
/// # Safety
/// `x` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_dup(x: *const TsResp) -> *mut TsResp {
    // SAFETY: `x` is NULL or live.
    unsafe { ASN1_item_dup(ts_resp_it(), x.cast()) }.cast()
}

/// `TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_MSG_IMPRINT(
    a: *mut *mut TsMsgImprint,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsMsgImprint {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_msg_imprint_it()) }.cast()
}

/// `int i2d_TS_MSG_IMPRINT(const TS_MSG_IMPRINT *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_MSG_IMPRINT(
    a: *const TsMsgImprint,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_msg_imprint_it()) }
}

/// `TS_REQ *d2i_TS_REQ(TS_REQ **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_REQ(
    a: *mut *mut TsReq,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsReq {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_req_it()) }.cast()
}

/// `int i2d_TS_REQ(const TS_REQ *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_REQ(a: *const TsReq, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_req_it()) }
}

/// `TS_ACCURACY *d2i_TS_ACCURACY(TS_ACCURACY **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_ACCURACY(
    a: *mut *mut TsAccuracy,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsAccuracy {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_accuracy_it()) }.cast()
}

/// `int i2d_TS_ACCURACY(const TS_ACCURACY *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_ACCURACY(
    a: *const TsAccuracy,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_accuracy_it()) }
}

/// `TS_TST_INFO *d2i_TS_TST_INFO(TS_TST_INFO **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_TST_INFO(
    a: *mut *mut TsTstInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsTstInfo {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_tst_info_it()) }.cast()
}

/// `int i2d_TS_TST_INFO(const TS_TST_INFO *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_TST_INFO(
    a: *const TsTstInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_tst_info_it()) }
}

/// `TS_STATUS_INFO *d2i_TS_STATUS_INFO(TS_STATUS_INFO **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_STATUS_INFO(
    a: *mut *mut TsStatusInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsStatusInfo {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_status_info_it()) }.cast()
}

/// `int i2d_TS_STATUS_INFO(const TS_STATUS_INFO *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_STATUS_INFO(
    a: *const TsStatusInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_status_info_it()) }
}

/// `TS_RESP *d2i_TS_RESP(TS_RESP **a, const unsigned char **in, long len)` —
/// `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_RESP(
    a: *mut *mut TsResp,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut TsResp {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ts_resp_it()) }.cast()
}

/// `int i2d_TS_RESP(const TS_RESP *a, unsigned char **out)` — `IMPLEMENT_ASN1_ENCODE_FUNCTIONS`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_RESP(a: *const TsResp, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d(a.cast(), out, ts_resp_it()) }
}

/// `TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT **a)` — `ts_asn1.c`'s `ASN1_d2i_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_MSG_IMPRINT_bio(
    bp: *mut Bio,
    a: *mut *mut TsMsgImprint,
) -> *mut TsMsgImprint {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(ts_msg_imprint_it(), bp, a.cast()) }.cast()
}

/// `int i2d_TS_MSG_IMPRINT_bio(BIO *bp, const TS_MSG_IMPRINT *a)` — `ts_asn1.c`'s `ASN1_i2d_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_MSG_IMPRINT_bio(
    bp: *mut Bio,
    a: *const TsMsgImprint,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(ts_msg_imprint_it(), bp, a.cast()) }
}

/// `TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a)` — `ts_asn1.c`'s `ASN1_d2i_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_MSG_IMPRINT_fp(
    fp: *mut FILE,
    a: *mut *mut TsMsgImprint,
) -> *mut TsMsgImprint {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(ts_msg_imprint_it(), fp, a.cast()) }.cast()
}

/// `int i2d_TS_MSG_IMPRINT_fp(FILE *fp, const TS_MSG_IMPRINT *a)` — `ts_asn1.c`'s `ASN1_i2d_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_MSG_IMPRINT_fp(
    fp: *mut FILE,
    a: *const TsMsgImprint,
) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(ts_msg_imprint_it(), fp, a.cast()) }
}

/// `TS_REQ *d2i_TS_REQ_bio(BIO *bp, TS_REQ **a)` — `ts_asn1.c`'s `ASN1_d2i_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_REQ_bio(bp: *mut Bio, a: *mut *mut TsReq) -> *mut TsReq {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(ts_req_it(), bp, a.cast()) }.cast()
}

/// `int i2d_TS_REQ_bio(BIO *bp, const TS_REQ *a)` — `ts_asn1.c`'s `ASN1_i2d_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_REQ_bio(bp: *mut Bio, a: *const TsReq) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(ts_req_it(), bp, a.cast()) }
}

/// `TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a)` — `ts_asn1.c`'s `ASN1_d2i_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_REQ_fp(fp: *mut FILE, a: *mut *mut TsReq) -> *mut TsReq {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(ts_req_it(), fp, a.cast()) }.cast()
}

/// `int i2d_TS_REQ_fp(FILE *fp, const TS_REQ *a)` — `ts_asn1.c`'s `ASN1_i2d_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_REQ_fp(fp: *mut FILE, a: *const TsReq) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(ts_req_it(), fp, a.cast()) }
}

/// `TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO **a)` — `ts_asn1.c`'s `ASN1_d2i_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_TST_INFO_bio(
    bp: *mut Bio,
    a: *mut *mut TsTstInfo,
) -> *mut TsTstInfo {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(ts_tst_info_it(), bp, a.cast()) }.cast()
}

/// `int i2d_TS_TST_INFO_bio(BIO *bp, const TS_TST_INFO *a)` — `ts_asn1.c`'s `ASN1_i2d_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_TST_INFO_bio(bp: *mut Bio, a: *const TsTstInfo) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(ts_tst_info_it(), bp, a.cast()) }
}

/// `TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a)` — `ts_asn1.c`'s `ASN1_d2i_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_TST_INFO_fp(
    fp: *mut FILE,
    a: *mut *mut TsTstInfo,
) -> *mut TsTstInfo {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(ts_tst_info_it(), fp, a.cast()) }.cast()
}

/// `int i2d_TS_TST_INFO_fp(FILE *fp, const TS_TST_INFO *a)` — `ts_asn1.c`'s `ASN1_i2d_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_TST_INFO_fp(fp: *mut FILE, a: *const TsTstInfo) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(ts_tst_info_it(), fp, a.cast()) }
}

/// `TS_RESP *d2i_TS_RESP_bio(BIO *bp, TS_RESP **a)` — `ts_asn1.c`'s `ASN1_d2i_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_RESP_bio(bp: *mut Bio, a: *mut *mut TsResp) -> *mut TsResp {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_bio(ts_resp_it(), bp, a.cast()) }.cast()
}

/// `int i2d_TS_RESP_bio(BIO *bp, const TS_RESP *a)` — `ts_asn1.c`'s `ASN1_i2d_bio_of`.
///
/// # Safety
/// `bp` is a live BIO; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_RESP_bio(bp: *mut Bio, a: *const TsResp) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_bio(ts_resp_it(), bp, a.cast()) }
}

/// `TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a)` — `ts_asn1.c`'s `ASN1_d2i_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or a writable slot.
#[no_mangle]
pub(crate) unsafe extern "C" fn d2i_TS_RESP_fp(fp: *mut FILE, a: *mut *mut TsResp) -> *mut TsResp {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_d2i_fp(ts_resp_it(), fp, a.cast()) }.cast()
}

/// `int i2d_TS_RESP_fp(FILE *fp, const TS_RESP *a)` — `ts_asn1.c`'s `ASN1_i2d_fp_of`.
///
/// # Safety
/// `fp` is a live `FILE *`; `a` NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn i2d_TS_RESP_fp(fp: *mut FILE, a: *const TsResp) -> c_int {
    // SAFETY: the caller's contract, forwarded.
    unsafe { ASN1_item_i2d_fp(ts_resp_it(), fp, a.cast()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_to_TS_TST_INFO
// ---------------------------------------------------------------------------------------------

/// `PKCS7_to_TS_TST_INFO(PKCS7 *token)` — `ts_asn1.c:204-234`.
///
/// # Safety
/// `token` is NULL or a live `PKCS7`.
#[no_mangle]
pub(crate) unsafe extern "C" fn PKCS7_to_TS_TST_INFO(token: *mut Pkcs7) -> *mut TsTstInfo {
    if token.is_null() {
        // The authority dereferences without a null check; the guard is the caller's contract.
        return ptr::null_mut();
    }
    // SAFETY: `token` is live.
    if !pkcs7_type_is_signed(token) {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 213, c"PKCS7_to_TS_TST_INFO", TS_R_BAD_PKCS7_TYPE) };
        return ptr::null_mut();
    }
    // SAFETY: `token` is live.
    if pkcs7_get_detached(token) {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 217, c"PKCS7_to_TS_TST_INFO", TS_R_DETACHED_CONTENT) };
        return ptr::null_mut();
    }
    // SAFETY: `token` is a signed PKCS7, so `d.sign` is live.
    let pkcs7_signed = unsafe { (*token).d.sign };
    // SAFETY: `pkcs7_signed` is live.
    let enveloped = unsafe { (*pkcs7_signed).contents };
    // SAFETY: `enveloped` is live.
    if unsafe { crate::runtime::obj::OBJ_obj2nid((*enveloped).type_) } != NID_id_smime_ct_TSTInfo {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 222, c"PKCS7_to_TS_TST_INFO", TS_R_BAD_PKCS7_TYPE) };
        return ptr::null_mut();
    }
    // SAFETY: `enveloped` is live.
    let tst_info_wrapper = unsafe { (*enveloped).d.other };
    // SAFETY: `tst_info_wrapper` is live.
    if unsafe { (*tst_info_wrapper).type_ } != V_ASN1_OCTET_STRING {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 227, c"PKCS7_to_TS_TST_INFO", TS_R_BAD_TYPE) };
        return ptr::null_mut();
    }
    // The `ASN1_TYPE` value union's `octet_string` arm.
    // SAFETY: the union holds an `ASN1_OCTET_STRING` per the type tag just checked.
    let tst_info_der = unsafe { (*tst_info_wrapper).value.ptr }.cast::<Asn1String>();
    // SAFETY: `tst_info_der` is live.
    let mut p: *const c_uchar = unsafe { (*tst_info_der).data };
    // SAFETY: `tst_info_der` is live.
    let length = unsafe { (*tst_info_der).length } as c_long;
    // SAFETY: `p` points at `length` bytes of DER.
    unsafe { d2i_TS_TST_INFO(ptr::null_mut(), &mut p, length) }
}
