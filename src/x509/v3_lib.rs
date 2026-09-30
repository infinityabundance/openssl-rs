//! `crypto/x509/v3_lib.c` — the extension registration surface and the `standard_exts[]` dispatch.
//! Phase 10.15, the endgame slice.
//!
//! `crypto/x509/v3_lib.c` is 308 lines and now lands whole. Its **registration** half was Phase
//! 10.13's:
//!
//! * the `X509V3_EXT_METHOD` structure ([`X509V3ExtMethod`], `include/openssl/x509v3.h:65-85`),
//!   with every field at the offset the header gives;
//! * `ext_cmp` (`:39-43`) and `ext_list_free` (`:116-120`), the two `static` helpers;
//! * `X509V3_EXT_add` (`:25-37`), `X509V3_EXT_add_list` (`:81-87`) and `X509V3_EXT_cleanup`
//!   (`:110-114`), the process-global `ext_list` and its lifecycle;
//! * `X509V3_add_standard_extensions` (`:127-130`), which returns 1 by design.
//!
//! This slice lands the **lookup** half that D455/D456 withheld until every table it names existed:
//!
//! * [`STANDARD_EXTS`] — `standard_exts[]` (`standard_exts.h:15-95`) transcribed entry for entry, in
//!   order: **73 entries** over 63 distinct `ossl_v3_*` tables (`ossl_v3_ns_ia5_list[0..6]`,
//!   `ossl_v3_alt[0..2]` and `ossl_v3_ct_scts[0..2]` are the array-backed ones). The array must stay
//!   in `ext_nid` order, because [`X509V3_EXT_get_nid`] binary-searches it exactly as the authority's
//!   `OBJ_bsearch_ext` does. It is held in a `Sync` newtype because a `static` array of raw pointers
//!   is not `Sync`; every element is the address of a crate-owned, immutable row.
//! * `X509V3_EXT_get_nid` (`:52-71`) — the binary search over [`STANDARD_EXTS`], with the dynamic
//!   `ext_list` as a sorted fallback.
//! * `X509V3_EXT_get` (`:73-79`), `X509V3_EXT_add_alias` (`:89-108`), `X509V3_EXT_d2i` (`:134-149`),
//!   `X509V3_get_d2i` (`:167-215`) and `X509V3_add1_i2d` (`:223-308`).
//! * `X509V3_EXT_i2d` (`crypto/x509/v3_conf.c:191-200`), which `X509V3_add1_i2d` calls, lands in
//!   `src/x509/v3_conf.rs` together with the `do_ext_i2d` helper it wraps.
//!
//! The four table-only leaves 10.13 withheld (`ossl_v3_utf8_list`, `ossl_v3_no_rev_avail`,
//! `ossl_v3_single_use`, `ossl_v3_soa_identifier`) and every other `standard_exts[]` row now exist,
//! so nothing is withheld from this unit any more.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_lib.c` is in `gen_err_raise_sites.py`'s covered set, so the registration raise
//! sites are the generated `V3_LIB_29`/`V3_LIB_33` (`X509V3_EXT_add`) and the lookup raise sites the
//! now-landed half makes reachable are `V3_LIB_95` (`X509V3_EXT_add_alias`),
//! `V3_LIB_274` (`X509V3_add1_i2d`) and `V3_LIB_306` (`X509V3_add1_i2d`'s run-time reason).
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms call `X509V3_add_standard_extensions` (the legacy no-op), then
//! `X509V3_EXT_add`/`_add_list` over a probe-declared method and `X509V3_EXT_cleanup`, observing the
//! return values and the error queue (each arm pops first). `X509V3_EXT_get_nid`/`_get` are still not
//! driven by the probe, so no arm names them.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::layout::Asn1Item;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_undef, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null,
    OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_conf::X509V3_EXT_i2d;
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
    X509v3_get_ext_by_NID,
};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};

/// `OPENSSL_FILE` for this unit's `OPENSSL_free`/`OPENSSL_malloc` expansions — `crypto/x509/v3_lib.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_lib.c";
/// `ext_list_free`'s `OPENSSL_free(ext)` (`crypto/x509/v3_lib.c:119`).
const LINE_FREE: c_int = 119;
/// `X509V3_EXT_add_alias`'s `OPENSSL_malloc(sizeof(*tmpext))` (`crypto/x509/v3_lib.c:98`).
const LINE_MALLOC_ALIAS: c_int = 98;
/// `X509V3_EXT_add_alias`'s `OPENSSL_free(tmpext)` (`crypto/x509/v3_lib.c:104`).
const LINE_FREE_ALIAS: c_int = 104;

/// `X509V3_EXT_NEW` — `include/openssl/x509v3.h:45`.
pub type X509V3ExtNew = Option<unsafe extern "C" fn() -> *mut c_void>;
/// `X509V3_EXT_FREE` — `include/openssl/x509v3.h:46`.
pub type X509V3ExtFree = Option<unsafe extern "C" fn(*mut c_void)>;
/// `X509V3_EXT_D2I` — `include/openssl/x509v3.h:47`.
pub type X509V3ExtD2i =
    Option<unsafe extern "C" fn(*mut c_void, *mut *const c_uchar, c_long) -> *mut c_void>;
/// `X509V3_EXT_I2D` — `include/openssl/x509v3.h:48`.
pub type X509V3ExtI2d = Option<unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int>;
/// `X509V3_EXT_I2V` — `include/openssl/x509v3.h:49-50`.
pub type X509V3ExtI2v = Option<
    unsafe extern "C" fn(
        *const X509V3ExtMethod,
        *mut c_void,
        *mut OpenSslStack,
    ) -> *mut OpenSslStack,
>;
/// `X509V3_EXT_V2I` — `include/openssl/x509v3.h:51-53`.
pub type X509V3ExtV2i = Option<
    unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void, *mut OpenSslStack) -> *mut c_void,
>;
/// `X509V3_EXT_I2S` — `include/openssl/x509v3.h:54-55`.
pub type X509V3ExtI2s =
    Option<unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void) -> *mut c_char>;
/// `X509V3_EXT_S2I` — `include/openssl/x509v3.h:56-57`.
pub type X509V3ExtS2i =
    Option<unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void, *const c_char) -> *mut c_void>;
/// `X509V3_EXT_I2R` — `include/openssl/x509v3.h:58-59`.
pub type X509V3ExtI2r =
    Option<unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void, *mut Bio, c_int) -> c_int>;
/// `X509V3_EXT_R2I` — `include/openssl/x509v3.h:60-61`. Same shape as [`X509V3ExtS2i`]; kept
/// distinct because the structure holds them in distinct slots.
pub type X509V3ExtR2i = X509V3ExtS2i;

/// `struct v3_ext_method` — `include/openssl/x509v3.h:65-85`.
///
/// The ABI order is the header's: the two `int`s, the item expression, the four old-style codec
/// hooks, the string pair, the multi-value pair, the raw pair and the caller's `usr_data`.
#[repr(C)]
pub struct X509V3ExtMethod {
    /// `int ext_nid`.
    pub ext_nid: c_int,
    /// `int ext_flags` — `X509V3_EXT_DYNAMIC` / `_CTX_DEP` / `_MULTILINE`.
    pub ext_flags: c_int,
    /// `ASN1_ITEM_EXP *it` — when set the four old-style hooks are ignored.
    ///
    /// `include/openssl/asn1.h.in:378` defines `typedef const ASN1_ITEM *ASN1_ITEM_EXP(void)`, a
    /// **function** type, so `ASN1_ITEM_ref(iptr)` (`asn1.h.in:384`, `(iptr##_it)`) is the function
    /// designator `i##_it`, not its result; the read site `ASN1_ITEM_ptr(method->it)`
    /// (`ASN1_ITEM_ptr(iptr)` = `((iptr)())`) *calls* it. The field is therefore the function
    /// pointer the authority's header declares. D456's first cut typed it `*const Asn1Item`, a
    /// placeholder the table layer is the first writer to falsify; the field is pointer-sized
    /// either way and no landed code read it, so this is a representation correction, not a
    /// behaviour change.
    pub it: Option<unsafe extern "C" fn() -> *const Asn1Item>,
    /// `X509V3_EXT_NEW ext_new`.
    pub ext_new: X509V3ExtNew,
    /// `X509V3_EXT_FREE ext_free`.
    pub ext_free: X509V3ExtFree,
    /// `X509V3_EXT_D2I d2i`.
    pub d2i: X509V3ExtD2i,
    /// `X509V3_EXT_I2D i2d`.
    pub i2d: X509V3ExtI2d,
    /// `X509V3_EXT_I2S i2s`.
    pub i2s: X509V3ExtI2s,
    /// `X509V3_EXT_S2I s2i`.
    pub s2i: X509V3ExtS2i,
    /// `X509V3_EXT_I2V i2v`.
    pub i2v: X509V3ExtI2v,
    /// `X509V3_EXT_V2I v2i`.
    pub v2i: X509V3ExtV2i,
    /// `X509V3_EXT_I2R i2r`.
    pub i2r: X509V3ExtI2r,
    /// `X509V3_EXT_R2I r2i`.
    pub r2i: X509V3ExtR2i,
    /// `void *usr_data`.
    pub usr_data: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<X509V3ExtMethod>() == 104);
    assert!(core::mem::offset_of!(X509V3ExtMethod, ext_nid) == 0);
    assert!(core::mem::offset_of!(X509V3ExtMethod, ext_flags) == 4);
    assert!(core::mem::offset_of!(X509V3ExtMethod, it) == 8);
    assert!(core::mem::offset_of!(X509V3ExtMethod, ext_new) == 16);
    assert!(core::mem::offset_of!(X509V3ExtMethod, ext_free) == 24);
    assert!(core::mem::offset_of!(X509V3ExtMethod, d2i) == 32);
    assert!(core::mem::offset_of!(X509V3ExtMethod, i2d) == 40);
    assert!(core::mem::offset_of!(X509V3ExtMethod, i2s) == 48);
    assert!(core::mem::offset_of!(X509V3ExtMethod, s2i) == 56);
    assert!(core::mem::offset_of!(X509V3ExtMethod, i2v) == 64);
    assert!(core::mem::offset_of!(X509V3ExtMethod, v2i) == 72);
    assert!(core::mem::offset_of!(X509V3ExtMethod, i2r) == 80);
    assert!(core::mem::offset_of!(X509V3ExtMethod, r2i) == 88);
    assert!(core::mem::offset_of!(X509V3ExtMethod, usr_data) == 96);
};

// SAFETY: a method row is fully initialised at compile time and never written. Its pointer fields
// borrow the crate's own static items, function addresses and caller `usr_data`; the authority's
// `standard_exts[]` is exactly this -- an immutable table of immutable rows. Claiming `Sync` is
// what lets those rows be `static` so the dispatch can hold their addresses, the same reason
// `Asn1Item` and `Asn1Template` claim it in `src/asn1/layout.rs`.
unsafe impl Sync for X509V3ExtMethod {}

/// `#define X509V3_EXT_DYNAMIC 0x1` — `include/openssl/x509v3.h:121`.
pub(crate) const X509V3_EXT_DYNAMIC: c_int = 0x1;

/// `#define X509V3_EXT_MULTILINE 0x4` — `include/openssl/x509v3.h:123`.
pub(crate) const X509V3_EXT_MULTILINE: c_int = 0x4;

/// `X509V3_ADD_OP_MASK` — `include/openssl/x509v3.h:794`.
const X509V3_ADD_OP_MASK: c_ulong = 0xf;
/// `X509V3_ADD_DEFAULT` — `include/openssl/x509v3.h:795`.
const X509V3_ADD_DEFAULT: c_ulong = 0;
/// `X509V3_ADD_APPEND` — `include/openssl/x509v3.h:796`.
const X509V3_ADD_APPEND: c_ulong = 1;
/// `X509V3_ADD_REPLACE_EXISTING` — `include/openssl/x509v3.h:798`.
const X509V3_ADD_REPLACE_EXISTING: c_ulong = 3;
/// `X509V3_ADD_KEEP_EXISTING` — `include/openssl/x509v3.h:799`.
const X509V3_ADD_KEEP_EXISTING: c_ulong = 4;
/// `X509V3_ADD_DELETE` — `include/openssl/x509v3.h:800`.
const X509V3_ADD_DELETE: c_ulong = 5;
/// `X509V3_ADD_SILENT` — `include/openssl/x509v3.h:801`.
const X509V3_ADD_SILENT: c_ulong = 0x10;
/// `X509V3_R_EXTENSION_EXISTS` — `include/openssl/x509v3err.h:36`.
const X509V3_R_EXTENSION_EXISTS: c_int = 145;
/// `X509V3_R_EXTENSION_NOT_FOUND` — `include/openssl/x509v3err.h:38`.
const X509V3_R_EXTENSION_NOT_FOUND: c_int = 102;

/// `#define STANDARD_EXTENSION_COUNT OSSL_NELEM(standard_exts)` — `standard_exts.h:99`.
const STANDARD_EXTENSION_COUNT: usize = 73;

/// `standard_exts[]` (`crypto/x509/standard_exts.h:15-95`) in a `Sync` newtype.
///
/// A `static` array of raw pointers is not `Sync` (the same reason [`X509V3ExtMethod`] claims
/// `Sync`), so the table is wrapped. Every element is the address of a crate-owned, immutable
/// `static` row or one element of such an array, so sharing the whole table between threads is
/// sound: the authority's own `standard_exts[]` is `static const` and read-only.
struct StandardExts([*const X509V3ExtMethod; STANDARD_EXTENSION_COUNT]);

// SAFETY: the sole field is 73 pointers to immutable crate-owned rows (see the type doc); no writer
// exists and no interior mutability is reachable through them.
unsafe impl Sync for StandardExts {}

/// `static const X509V3_EXT_METHOD *standard_exts[]` — `crypto/x509/standard_exts.h:15-95`.
///
/// Transcribed entry for entry, in order. The order is `ext_nid`-ascending because that is the
/// invariant the authority's `OBJ_bsearch_ext` relies on and [`X509V3_EXT_get_nid`] preserves.
#[rustfmt::skip]
static STANDARD_EXTS: StandardExts = StandardExts([
    &crate::x509::v3_bitst::ossl_v3_nscert,
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[0],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[1],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[2],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[3],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[4],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[5],
    &crate::x509::v3_ia5::ossl_v3_ns_ia5_list[6],
    &crate::x509::v3_skid::ossl_v3_skey_id,
    &crate::x509::v3_bitst::ossl_v3_key_usage,
    &crate::x509::v3_pku::ossl_v3_pkey_usage_period,
    &crate::x509::v3_san::ossl_v3_alt[0],
    &crate::x509::v3_san::ossl_v3_alt[1],
    &crate::x509::v3_bcons::ossl_v3_bcons,
    &crate::x509::v3_int::ossl_v3_crl_num,
    &crate::x509::v3_cpols::ossl_v3_cpols,
    &crate::x509::v3_akid::ossl_v3_akey_id,
    &crate::x509::v3_crld::ossl_v3_crld,
    &crate::x509::v3_extku::ossl_v3_ext_ku,
    &crate::x509::v3_int::ossl_v3_delta_crl,
    &crate::x509::v3_enum::ossl_v3_crl_reason,
    &crate::x509::v3_crld::ossl_v3_crl_invdate,
    &crate::x509::v3_sxnet::ossl_v3_sxnet,
    &crate::x509::v3_info::ossl_v3_info,
    &crate::x509::v3_audit_id::ossl_v3_audit_identity,
    &crate::x509::v3_addr::ossl_v3_addr,
    &crate::x509::v3_asid::ossl_v3_asid,
    &crate::ocsp::v3_ocsp::ossl_v3_ocsp_nonce,
    &crate::ocsp::v3_ocsp::ossl_v3_ocsp_crlid,
    &crate::x509::v3_extku::ossl_v3_ocsp_accresp,
    &crate::ocsp::v3_ocsp::ossl_v3_ocsp_nocheck,
    &crate::ocsp::v3_ocsp::ossl_v3_ocsp_acutoff,
    &crate::ocsp::v3_ocsp::ossl_v3_ocsp_serviceloc,
    &crate::x509::v3_info::ossl_v3_sinfo,
    &crate::x509::v3_pcons::ossl_v3_policy_constraints,
    &crate::x509::v3_ac_tgt::ossl_v3_targeting_information,
    &crate::x509::v3_no_rev_avail::ossl_v3_no_rev_avail,
    &crate::x509::v3_crld::ossl_v3_crl_hold,
    &crate::x509::v3_pci::ossl_v3_pci,
    &crate::x509::v3_ncons::ossl_v3_name_constraints,
    &crate::x509::v3_pmaps::ossl_v3_policy_mappings,
    &crate::x509::v3_int::ossl_v3_inhibit_anyp,
    &crate::x509::v3_sda::ossl_v3_subj_dir_attrs,
    &crate::x509::v3_crld::ossl_v3_idp,
    &crate::x509::v3_san::ossl_v3_alt[2],
    &crate::x509::v3_crld::ossl_v3_freshest_crl,
    &crate::ct::ct_x509v3::ossl_v3_ct_scts[0],
    &crate::ct::ct_x509v3::ossl_v3_ct_scts[1],
    &crate::ct::ct_x509v3::ossl_v3_ct_scts[2],
    &crate::x509::v3_utf8::ossl_v3_utf8_list[0],
    &crate::x509::v3_ist::ossl_v3_issuer_sign_tool,
    &crate::x509::v3_tlsf::ossl_v3_tls_feature,
    &crate::x509::v3_admis::ossl_v3_ext_admission,
    &crate::x509::v3_authattid::ossl_v3_authority_attribute_identifier,
    &crate::x509::v3_rolespec::ossl_v3_role_spec_cert_identifier,
    &crate::x509::v3_battcons::ossl_v3_battcons,
    &crate::x509::v3_ncons::ossl_v3_delegated_name_constraints,
    &crate::x509::v3_timespec::ossl_v3_time_specification,
    &crate::x509::v3_attrdesc::ossl_v3_attribute_descriptor,
    &crate::x509::v3_usernotice::ossl_v3_user_notice,
    &crate::x509::v3_soa_id::ossl_v3_soa_identifier,
    &crate::x509::v3_extku::ossl_v3_acc_cert_policies,
    &crate::x509::v3_extku::ossl_v3_acc_priv_policies,
    &crate::x509::v3_ind_iss::ossl_v3_indirect_issuer,
    &crate::x509::v3_no_ass::ossl_v3_no_assertion,
    &crate::x509::v3_crld::ossl_v3_aa_issuing_dist_point,
    &crate::x509::v3_iobo::ossl_v3_issued_on_behalf_of,
    &crate::x509::v3_single_use::ossl_v3_single_use,
    &crate::x509::v3_group_ac::ossl_v3_group_ac,
    &crate::x509::v3_aaa::ossl_v3_allowed_attribute_assignments,
    &crate::x509::v3_attrmap::ossl_v3_attribute_mappings,
    &crate::x509::v3_ncons::ossl_v3_holder_name_constraints,
    &crate::x509::v3_sda::ossl_v3_associated_info,
]);

/// `static STACK_OF(X509V3_EXT_METHOD) *ext_list = NULL` — `crypto/x509/v3_lib.c:19`.
///
/// The authority's plain static; held as an atomic pointer only so a `static` in Rust is sound.
/// The list is process-global and unlocked in the authority too (its `X509V3_EXT_get_nid`
/// comments "Ideally, this would be done under a lock"), so this is the same contract.
static EXT_LIST: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static int ext_cmp(const X509V3_EXT_METHOD *const *a, const X509V3_EXT_METHOD *const *b)`
/// — `crypto/x509/v3_lib.c:39-43`.
///
/// The stack comparator receives pointers to element slots, each holding a `X509V3_EXT_METHOD *`.
unsafe extern "C" fn ext_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack layer passes element slots for a comparator installed on this list.
    let (x, y) = unsafe {
        (
            *a.cast::<*const X509V3ExtMethod>(),
            *b.cast::<*const X509V3ExtMethod>(),
        )
    };
    // SAFETY: both are non-null method pointers the caller pushed.
    unsafe { (*x).ext_nid - (*y).ext_nid }
}

/// `static void ext_list_free(X509V3_EXT_METHOD *ext)` — `crypto/x509/v3_lib.c:116-120`.
///
/// Frees only a `X509V3_EXT_DYNAMIC` row, i.e. one `X509V3_EXT_add_alias` allocated; a caller's
/// static table row is the caller's.
unsafe extern "C" fn ext_list_free(ext: *mut c_void) {
    let method = ext.cast::<X509V3ExtMethod>();
    if !method.is_null() {
        // SAFETY: the slot holds a method pointer per the stack contract.
        if unsafe { (*method).ext_flags } & X509V3_EXT_DYNAMIC != 0 {
            // SAFETY: a DYNAMIC row was `OPENSSL_malloc`ed by `X509V3_EXT_add_alias`.
            unsafe { CRYPTO_free(ext, FILE.as_ptr(), LINE_FREE) };
        }
    }
}

/// `int X509V3_EXT_add(X509V3_EXT_METHOD *ext)` — `crypto/x509/v3_lib.c:25-37`.
///
/// Lazily creates the list with [`ext_cmp`], then pushes the caller's row (the list does not own
/// it unless it is `X509V3_EXT_DYNAMIC`).
///
/// # Safety
///
/// `ext` is a live `X509V3_EXT_METHOD` that outlives the list or is `X509V3_EXT_DYNAMIC`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add(ext: *mut X509V3ExtMethod) -> c_int {
    if EXT_LIST.load(Ordering::Acquire).is_null() {
        // `OPENSSL_sk_new` is a safe function; `ext_cmp` is the list's comparator.
        let list = OPENSSL_sk_new(Some(ext_cmp));
        if list.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&err_sites::V3_LIB_29) };
            return 0;
        }
        EXT_LIST.store(list, Ordering::Release);
    }
    let list = EXT_LIST.load(Ordering::Acquire);
    // SAFETY: `list` is live and `ext` is the caller's live row.
    if unsafe { OPENSSL_sk_push(list, ext.cast::<c_void>()) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_LIB_33) };
        return 0;
    }
    1
}

/// `int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist)` — `crypto/x509/v3_lib.c:81-87`.
///
/// Walks a caller's table until the `ext_nid == -1` terminator, adding each row.
///
/// # Safety
///
/// `extlist` points at a `-1`-terminated array of live methods.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_list(extlist: *mut X509V3ExtMethod) -> c_int {
    let mut p = extlist;
    // SAFETY: the caller's contract is a `-1`-terminated array.
    while unsafe { (*p).ext_nid } != -1 {
        // SAFETY: `p` is a live row of the array.
        if unsafe { X509V3_EXT_add(p) } == 0 {
            return 0;
        }
        // SAFETY: advancing within the caller's array.
        p = unsafe { p.add(1) };
    }
    1
}

/// `void X509V3_EXT_cleanup(void)` — `crypto/x509/v3_lib.c:110-114`.
///
/// Pops and frees the list; a NULL list is a no-op, as the typed `sk_*_pop_free` is in the
/// authority.
///
/// # Safety
///
/// Must not race another `X509V3_EXT_add`/`_cleanup`; the authority's list is unlocked, so this
/// is the same single-threaded contract the authority documents.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_cleanup() {
    let list = EXT_LIST.swap(ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: `list` is NULL or the list this module built; `ext_list_free` is its destructor.
    unsafe { OPENSSL_sk_pop_free(list, Some(ext_list_free)) };
}

/// `int X509V3_add_standard_extensions(void)` — `crypto/x509/v3_lib.c:127-130`.
///
/// The authority's own comment: "Legacy function: we don't need to add standard extensions any
/// more because they are now kept in `ext_dat.h`." It answers 1 and adds nothing.
#[no_mangle]
pub extern "C" fn X509V3_add_standard_extensions() -> c_int {
    1
}

/// The `OBJ_bsearch_ext` equivalent over [`STANDARD_EXTS`]: the row whose `ext_nid == nid`.
///
/// The array is `ext_nid`-ascending, so a binary search is exactly the authority's
/// `IMPLEMENT_OBJ_BSEARCH_CMP_FN` over the same table. Returns NULL when no row matches.
fn standard_ext_lookup(nid: c_int) -> *const X509V3ExtMethod {
    let exts = &STANDARD_EXTS.0;
    let mut lo: usize = 0;
    let mut hi: usize = exts.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let m = exts[mid];
        // SAFETY: every entry is the address of a crate-owned static row.
        let cmp = unsafe { (*m).ext_nid } - nid;
        if cmp == 0 {
            return m;
        } else if cmp < 0 {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    ptr::null()
}

/// `const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid)` — `crypto/x509/v3_lib.c:52-71`.
///
/// A negative `nid` answers NULL; otherwise the ordered `standard_exts[]` search answers first, and
/// failing that the dynamic `ext_list` is sorted and binary-searched. A miss answers NULL.
///
/// # Safety
///
/// No pointer arguments. As in the authority, the dynamic `ext_list` fallback is not locked, so
/// concurrent callers must not race a `X509V3_EXT_add`/`X509V3_EXT_cleanup`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3ExtMethod {
    if nid < 0 {
        return ptr::null();
    }
    let found = standard_ext_lookup(nid);
    if !found.is_null() {
        return found;
    }
    let list = EXT_LIST.load(Ordering::Acquire);
    if list.is_null() {
        return ptr::null();
    }
    // SAFETY: `list` is the live global this module built.
    unsafe { OPENSSL_sk_sort(list) };
    // The comparator's key: a method whose only read field is `ext_nid`.
    // SAFETY: an all-zero `X509V3ExtMethod` is a valid starting value (`ext_nid` 0, the rest
    // null/None); `ext_nid` is set below.
    let mut tmp: X509V3ExtMethod = unsafe { core::mem::zeroed() };
    tmp.ext_nid = nid;
    // SAFETY: `list` is live; `&tmp` is the key `ext_cmp` reads `ext_nid` from.
    let idx = unsafe { OPENSSL_sk_find(list, (&raw const tmp).cast::<c_void>()) };
    // SAFETY: `list` is live; an out-of-range `idx` (the miss) answers NULL.
    unsafe { OPENSSL_sk_value(list, idx) }.cast::<X509V3ExtMethod>() as *const X509V3ExtMethod
}

/// `const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext)` — `crypto/x509/v3_lib.c:73-79`.
///
/// # Safety
///
/// `ext` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_get(ext: *mut X509Extension) -> *const X509V3ExtMethod {
    // SAFETY: `ext` is live per the contract.
    let nid = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(ext)) };
    if nid == NID_undef {
        return ptr::null();
    }
    // SAFETY: no preconditions; `X509V3_EXT_get_nid` takes an integer NID.
    unsafe { X509V3_EXT_get_nid(nid) }
}

/// `int X509V3_EXT_add_alias(int nid_to, int nid_from)` — `crypto/x509/v3_lib.c:89-108`.
///
/// Copies the `nid_from` row into a fresh `X509V3_EXT_DYNAMIC` allocation retagged `nid_to` and
/// registers it. A missing `nid_from` raises `X509V3_R_EXTENSION_NOT_FOUND`; a failed `_add` frees
/// the copy.
///
/// # Safety
///
/// No pointer arguments. As in the authority the global `ext_list` is not locked, so this must not
/// race another `X509V3_EXT_add`/`X509V3_EXT_cleanup`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_alias(nid_to: c_int, nid_from: c_int) -> c_int {
    // SAFETY: no preconditions; `nid_from` is an integer NID.
    let ext = unsafe { X509V3_EXT_get_nid(nid_from) };
    if ext.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_LIB_95) };
        return 0;
    }
    // SAFETY: the allocator answers NULL or one `X509V3ExtMethod`-sized block.
    let tmpext = CRYPTO_malloc(
        core::mem::size_of::<X509V3ExtMethod>(),
        FILE.as_ptr(),
        LINE_MALLOC_ALIAS,
    )
    .cast::<X509V3ExtMethod>();
    if tmpext.is_null() {
        return 0;
    }
    // SAFETY: `tmpext` is a fresh, unaliased allocation of one row; `ext` is a live row.
    unsafe {
        ptr::write(tmpext, ptr::read(ext));
        (*tmpext).ext_nid = nid_to;
        (*tmpext).ext_flags |= X509V3_EXT_DYNAMIC;
    }
    // SAFETY: `tmpext` is this call's own row, so `X509V3_EXT_add`'s contract holds.
    if unsafe { X509V3_EXT_add(tmpext) } == 0 {
        // SAFETY: `tmpext` is this call's own allocation, not owned by the list on this path.
        unsafe { CRYPTO_free(tmpext.cast(), FILE.as_ptr(), LINE_FREE_ALIAS) };
        return 0;
    }
    1
}

/// `void *X509V3_EXT_d2i(X509_EXTENSION *ext)` — `crypto/x509/v3_lib.c:134-149`.
///
/// Decodes the extension's octet-string value through the method's `it` (an `ASN1_item_d2i`) when
/// it is set, else through the method's old-style `d2i`.
///
/// # Safety
///
/// `ext` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_d2i(ext: *mut X509Extension) -> *mut c_void {
    // SAFETY: `ext` is live per the contract.
    let method = unsafe { X509V3_EXT_get(ext) };
    if method.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ext` is live.
    let extvalue = unsafe { X509_EXTENSION_get_data(ext) };
    // SAFETY: `extvalue` is the extension's embedded `ASN1_OCTET_STRING`.
    let mut p = unsafe { ASN1_STRING_get0_data(extvalue) };
    // SAFETY: `extvalue` is live.
    let extlen = unsafe { ASN1_STRING_length(extvalue) };
    // SAFETY: `method` is live.
    if let Some(it) = unsafe { (*method).it } {
        // SAFETY: `p` borrows the extension's value for `extlen` bytes; `it()` answers the item the
        // `ASN1_ITEM_ref` macro names.
        return unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, extlen as c_long, it()) };
    }
    // SAFETY: `method` is live.
    let d2i = unsafe { (*method).d2i };
    if let Some(f) = d2i {
        // SAFETY: `f` is the live old-style decoder; `p` borrows the value for `extlen` bytes.
        return unsafe { f(ptr::null_mut(), &raw mut p, extlen as c_long) };
    }
    ptr::null_mut()
}

/// `void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x, int nid, int *crit, int *idx)` —
/// `crypto/x509/v3_lib.c:167-215`.
///
/// Searches `x` from `idx + 1` for the `nid` extension. `crit` reports `-1` for "not found", `-2`
/// for "occurs more than once", else the found extension's critical value; a NULL `x` answers NULL
/// with both out-parameters set to `-1`.
///
/// # Safety
///
/// `x` is NULL or a live extension stack; `crit`/`idx` are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_d2i(
    x: *const OpenSslStack,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    let mut found_ex: *mut X509Extension = ptr::null_mut();
    if x.is_null() {
        if !idx.is_null() {
            // SAFETY: `idx` is writable per the contract.
            unsafe { *idx = -1 };
        }
        if !crit.is_null() {
            // SAFETY: `crit` is writable per the contract.
            unsafe { *crit = -1 };
        }
        return ptr::null_mut();
    }
    let mut lastpos = if !idx.is_null() {
        // SAFETY: `idx` is writable/readable per the contract.
        (unsafe { *idx }) + 1
    } else {
        0
    };
    if lastpos < 0 {
        lastpos = 0;
    }
    // SAFETY: `x` is live per the guard above.
    let num = unsafe { OPENSSL_sk_num(x) };
    let mut i = lastpos;
    while i < num {
        // SAFETY: `x` is live and `i` is within `0..num`.
        let ex = unsafe { OPENSSL_sk_value(x, i) }.cast::<X509Extension>();
        // SAFETY: `ex` is a live extension.
        if unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(ex)) } == nid {
            if !idx.is_null() {
                // SAFETY: `idx` is writable per the contract.
                unsafe { *idx = i };
                found_ex = ex;
                break;
            } else if !found_ex.is_null() {
                /* Found more than one. */
                if !crit.is_null() {
                    // SAFETY: `crit` is writable per the contract.
                    unsafe { *crit = -2 };
                }
                return ptr::null_mut();
            }
            found_ex = ex;
        }
        i += 1;
    }
    if !found_ex.is_null() {
        /* Found it. */
        if !crit.is_null() {
            // SAFETY: `found_ex` is a live extension.
            unsafe { *crit = X509_EXTENSION_get_critical(found_ex) };
        }
        // SAFETY: `found_ex` is a live extension.
        return unsafe { X509V3_EXT_d2i(found_ex) };
    }
    /* Extension not found. */
    if !idx.is_null() {
        // SAFETY: `idx` is writable per the contract.
        unsafe { *idx = -1 };
    }
    if !crit.is_null() {
        // SAFETY: `crit` is writable per the contract.
        unsafe { *crit = -1 };
    }
    ptr::null_mut()
}

/// `int X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x, int nid, void *value, int crit,
/// unsigned long flags)` — `crypto/x509/v3_lib.c:223-308`.
///
/// The append/replace/delete utility: the low nibble of `flags` is the operation, `X509V3_ADD_SILENT`
/// suppresses the two operation refusals' raises, and `value` is the internal structure
/// [`X509V3_EXT_i2d`] encodes.
///
/// # Safety
///
/// `x` is a writable slot holding NULL or a live extension stack; `value` is the internal structure
/// the `nid` method's `i2d` expects.
#[no_mangle]
pub unsafe extern "C" fn X509V3_add1_i2d(
    x: *mut *mut OpenSslStack,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: c_ulong,
) -> c_int {
    let ext_op = flags & X509V3_ADD_OP_MASK;
    let mut extidx: c_int = -1;

    /* If appending we don't care if it exists, otherwise look for existing extension. */
    if ext_op != X509V3_ADD_APPEND {
        // SAFETY: `x` is a writable slot; `*x` is NULL or a live stack.
        extidx = unsafe { X509v3_get_ext_by_NID(*x, nid, -1) };
    }

    if extidx >= 0 {
        /* If keep existing, nothing to do. */
        if ext_op == X509V3_ADD_KEEP_EXISTING {
            return 1;
        }
        /* If default then its an error. */
        if ext_op == X509V3_ADD_DEFAULT {
            if flags & X509V3_ADD_SILENT == 0 {
                // SAFETY: the site is a compiled-in constant; the reason is the run-time `errcode`.
                unsafe { raise_site_dynamic(&err_sites::V3_LIB_306, X509V3_R_EXTENSION_EXISTS) };
            }
            return 0;
        }
        /* If delete, just delete it. */
        if ext_op == X509V3_ADD_DELETE {
            // SAFETY: `*x` is a live stack and `extidx` is in bounds.
            let extmp = unsafe { OPENSSL_sk_delete(*x, extidx) }.cast::<X509Extension>();
            if extmp.is_null() {
                return -1;
            }
            // SAFETY: `extmp` is the removed extension, now this call's own.
            unsafe { X509_EXTENSION_free(extmp) };
            return 1;
        }
    } else if ext_op == X509V3_ADD_REPLACE_EXISTING || ext_op == X509V3_ADD_DELETE {
        /*
         * If replace existing or delete, error since extension must exist.
         */
        if flags & X509V3_ADD_SILENT == 0 {
            // SAFETY: the site is a compiled-in constant; the reason is the run-time `errcode`.
            unsafe { raise_site_dynamic(&err_sites::V3_LIB_306, X509V3_R_EXTENSION_NOT_FOUND) };
        }
        return 0;
    }

    /*
     * If we get this far then we have to create an extension.
     */
    // SAFETY: `nid` names the method and `value` is the caller's internal structure.
    let ext = unsafe { X509V3_EXT_i2d(nid, crit, value) };
    if ext.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_LIB_274) };
        return 0;
    }

    /* If extension exists replace it. */
    if extidx >= 0 {
        // SAFETY: `*x` is a live stack and `extidx` is in bounds.
        let extmp = unsafe { OPENSSL_sk_value(*x, extidx) }.cast::<X509Extension>();
        // SAFETY: `extmp` is the extension being replaced, this call's own.
        unsafe { X509_EXTENSION_free(extmp) };
        // SAFETY: `*x` is live, `extidx` is in bounds, and `ext` is this call's own extension.
        if unsafe { OPENSSL_sk_set(*x, extidx, ext.cast::<c_void>()) }.is_null() {
            return -1;
        }
        return 1;
    }

    // SAFETY: `x` is a writable slot; `*x` is NULL or a live stack.
    let mut ret = unsafe { *x };
    if ret.is_null() {
        ret = OPENSSL_sk_new_null();
        if ret.is_null() {
            // `m_fail:` with `ret == *x` (both NULL): only `ext` is released.
            // SAFETY: `ext` is this call's own extension.
            unsafe { X509_EXTENSION_free(ext) };
            return -1;
        }
    }
    // SAFETY: `ret` is a live stack and `ext` is this call's own extension.
    if unsafe { OPENSSL_sk_push(ret, ext.cast::<c_void>()) } == 0 {
        // SAFETY: `x` is a writable slot per the contract.
        if ret != unsafe { *x } {
            // SAFETY: `ret` is the fresh stack this call built.
            unsafe { OPENSSL_sk_free(ret) };
        }
        // SAFETY: `ext` is this call's own extension.
        unsafe { X509_EXTENSION_free(ext) };
        return -1;
    }

    // SAFETY: `x` is a writable slot per the contract.
    unsafe { *x = ret };
    1
}
