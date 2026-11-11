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
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::layout::Asn1Item;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx, RawCtx};
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::obj::{NID_undef, OBJ_obj2nid};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null,
    OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_run_once, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
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
/// `X509V3_EXT_I2S` — `include/openssl/x509v3.h.in:54-55`.
///
/// # ABI contract for an application-supplied `i2s`
///
/// On a non-NULL return the callback must hand over the **base pointer of one
/// whole allocation from the process's active OpenSSL allocator seam**:
/// `OPENSSL_malloc`/`CRYPTO_malloc`, `CRYPTO_strdup`, or an authority helper that
/// allocates through one of them. The block must be NUL-terminated within its
/// allocated extent and contain a C string of `strlen + 1` bytes (exactly the
/// allocation extent when produced by `CRYPTO_strdup`; a larger `CRYPTO_malloc`
/// block is valid when the terminator is inside it).
///
/// Ownership transfers to the extension machinery: `X509V3_EXT_print` consumes
/// the result as a C string and releases it exactly once with
/// `OPENSSL_free(value)` at `crypto/x509/v3_prn.c:130`. The callback must not
/// free, retain, cache, or otherwise reuse the block, and must not return a
/// pointer to static, stack, borrowed, or non-seam storage. Returning NULL
/// transfers nothing and is reported by `X509V3_EXT_print` as a print failure.
///
/// Authority: `X509V3_EXT_print` assigns `method->i2s(method, ext_str)` to
/// `char *value` and its `err:` label runs `OPENSSL_free(value)`
/// (`crypto/x509/v3_prn.c:96,130`); the public `i2s_ASN1_*` family documents
/// "It is the caller's responsibility to free the returned string"
/// (`doc/man3/s2i_ASN1_IA5STRING.pod`). Registration through
/// [`X509V3_EXT_add`] accepts rows whose `i2s` slot carries this contract.
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
///
/// # Slot contracts
///
/// A row is dispatched by `X509V3_EXT_print` (`crypto/x509/v3_prn.c:69-136`) and by
/// `do_ext_nconf` (`crypto/x509/v3_conf.c:79-134`). Both first obtain `ext_struc`, the value of
/// the ASN.1 type the row names: `it` when set (`ASN1_item_d2i`/`ASN1_item_i2d`), otherwise the
/// old-style `d2i`/`i2d`/`ext_new`/`ext_free` quartet (`v3_prn.c:86-89,131-135`;
/// `v3_conf.c:127-134`). `usr_data` is **not** the decoded extension: it is the row's own
/// immutable auxiliary table, read only by the bit-string and enumerated printers
/// (`crypto/x509/v3_bitst.c:52,81`; `crypto/x509/v3_enum.c:48`).
///
/// Every slot is optional; the dispatcher tests each slot before calling it and reports
/// "unsupported" when the applicable print or set path has no arm (`v3_prn.c:95-127`;
/// `v3_conf.c:96-126`). Precedence is fixed: printing uses `i2s`, else `i2v`, else `i2r`
/// (`v3_prn.c:95-127`); configuration uses `v2i`, else `s2i`, else `r2i`
/// (`v3_conf.c:96-126`).
///
/// The `i2s` contract is on [`X509V3ExtI2s`]. The remaining four are:
///
/// ## `i2r`
///
/// `int (*)(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent)`
/// (`include/openssl/x509v3.h.in:58-59`). `ext` is the dispatcher's freshly decoded,
/// exclusively owned `ext_struc`; it is non-NULL at the call (`v3_prn.c:90-92`) and the
/// dispatcher frees it afterwards (`v3_prn.c:131-135`), so the callback must not free,
/// retain or replace it. `out` is a live caller BIO the callback may write to but must not
/// free. `method` is the row itself, so `usr_data` is its table. Return nonzero on success
/// and zero on failure; the dispatcher maps zero to a print failure but still reaches its
/// cleanup (`v3_prn.c:122-127`). A callback that writes conditionally must therefore return
/// zero from every arm that did not complete.
///
/// ## `i2v`
///
/// `STACK_OF(CONF_VALUE) *(*)(const X509V3_EXT_METHOD *method, void *ext,
/// STACK_OF(CONF_VALUE) *extlist)` (`include/openssl/x509v3.h.in:49-50`). `ext` carries the
/// same dispatcher-owned, non-NULL, must-not-free contract as `i2r`. `extlist` is an
/// optional sink: `X509V3_EXT_print` passes NULL (`v3_prn.c:116`), while other callbacks
/// pass an existing stack they are extending (`crypto/x509/v3_info.c:65-70`, forwarding
/// `tret`). The callback appends `CONF_VALUE`s and returns the possibly newly allocated
/// stack. On success ownership of the returned stack and its members transfers to the
/// caller, which releases the members with `X509V3_conf_free` and the stack with
/// `sk_CONF_VALUE_pop_free` (`v3_prn.c:129`); the callback must not free the returned stack
/// or its members, and must not retain `ext`. Returning NULL reports failure; when the
/// caller supplied a non-NULL `extlist`, the callback must not free that caller-owned stack.
///
/// ## `v2i`
///
/// `void *(*)(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *values)` (`include/openssl/x509v3.h.in:51-53`). `values` is
/// **borrowed**: the dispatcher builds it from `X509V3_parse_list(value)` (an owning list it
/// frees after the call) or from `NCONF_get_section(conf, ...)` (a section owned by the
/// config database), distinguishing the two by `*value == '@'` (`v3_conf.c:96-112`). The
/// callback must consume it read-only and must neither free it or its members nor retain
/// them. `ctx` is the caller's `X509V3_CTX`, borrowed for the call; the `v2i` arm does not
/// check it (`v3_conf.c:96-112`), so an implementation that reads it relies on the
/// authority's `X509V3_EXT_nconf*` callers to supply one. On success the callback returns a
/// new `ext_struc` of the row's ASN.1 item type; ownership transfers to the dispatcher,
/// which encodes it and then frees it with `ASN1_item_free`/`ext_free`
/// (`v3_conf.c:127-134`). On failure it returns NULL and releases any partial value it
/// built. Input it cannot fully consume must be rejected, not partially encoded.
///
/// ## `s2i`
///
/// `void *(*)(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)`
/// (`include/openssl/x509v3.h.in:56-57`). `do_ext_nconf` reaches this arm only when the row has
/// no `v2i` (`crypto/x509/v3_conf.c:113-116`), so `str` is the configuration value itself, not
/// a parsed `STACK_OF(CONF_VALUE)`. `str` is borrowed for the call: the callback may read it as
/// a NUL-terminated C string but must not free or retain it. `ctx` is the caller's
/// `X509V3_CTX`, borrowed for the call; the `s2i` arm does not check it
/// (`crypto/x509/v3_conf.c:113-116`), so an implementation that reads it relies on the
/// authority's `X509V3_EXT_nconf*` callers to supply one. On success the callback returns a
/// new `ext_struc` of the row's ASN.1 item type; ownership transfers to the dispatcher, which
/// encodes it and then frees it with `ASN1_item_free`/`ext_free`
/// (`crypto/x509/v3_conf.c:127-134`). On failure it returns NULL and releases any partial value
/// it built.
///
/// ## `r2i`
///
/// `void *(*)(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)`
/// (`include/openssl/x509v3.h.in:60-61`). Before the call the dispatcher requires `ctx`,
/// `ctx->db` and `ctx->db_meth` to be non-NULL (`v3_conf.c:117-121`). `str` is the config
/// value, borrowed for the call: the callback may parse it (the policy arm builds and frees
/// its own `X509V3_parse_list`, `crypto/x509/v3_cpols.c:96-101`) but must not free or retain
/// it. Return and ownership are `v2i`'s: a fresh `ext_struc` owned by the dispatcher on
/// success, NULL on failure, partial values released by the callback.
///
/// # Registration
///
/// [`X509V3_EXT_add`] stores the row without inspecting its codec slots
/// (`crypto/x509/v3_lib.c:25-37`), so a registered row may populate any of the five slots;
/// each callback is responsible for the contract of the slot it fills.
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

// ---------------------------------------------------------------------------------------------
// Ownership of the dynamic `X509V3_EXT_DYNAMIC` rows
// ---------------------------------------------------------------------------------------------

/// The authority's `ext_list_free` body, without the block release [`OwnedCtx`]'s `Drop` performs:
/// a copied row owns nothing itself, so only the block release is left.
// SAFETY: (a) holds: `destroy_body` is the authority's no-op `ext_list_free` body -- the row owns
// no releasable members -- and it never releases the enclosing block, which `OwnedCtx`'s `Drop`
// owns. (b) holds: `X509V3ExtMethod` is a `#[repr(C)]` record of integers,
// `Option<unsafe extern "C" fn>` callback slots and one raw pointer, so an all-zero block is a valid
// value and the empty body is sound on it.
unsafe impl CtxDestroy for X509V3ExtMethod {
    unsafe fn destroy_body(_ptr: *mut X509V3ExtMethod) {}
}

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
/// The authority leaves the list unlocked (its `X509V3_EXT_get_nid` comments "Ideally, this
/// would be done under a lock"); this candidate adds [`REGISTRY_LOCK`] so that a row resolved by
/// the dispatcher cannot be released by a concurrent `X509V3_EXT_cleanup` (B49-R10).
static EXT_LIST: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static CRYPTO_ONCE registry_init = CRYPTO_ONCE_STATIC_INIT` — this module's run-once.
static REGISTRY_ONCE: AtomicI32 = AtomicI32::new(0);
/// `static CRYPTO_RWLOCK *registry_lock` — the reader/writer lock over [`EXT_LIST`].
static REGISTRY_LOCK: AtomicPtr<CryptoRwlock> = AtomicPtr::new(ptr::null_mut());

/// The run-once body: create the registry lock.
///
/// It reaches only `CRYPTO_THREAD_lock_new` (the allocator seam), never a registry entry point,
/// so a constructor that calls [`ensure_registry`] cannot deadlock against its own run-once.
extern "C" fn do_registry_init() {
    // `CRYPTO_THREAD_lock_new` is a safe function; the store is the publication.
    REGISTRY_LOCK.store(CRYPTO_THREAD_lock_new(), Ordering::Release);
}

/// `RUN_ONCE` for the registry lock: true when the lock exists.
fn ensure_registry() -> bool {
    // SAFETY: `REGISTRY_ONCE` is this module's own `CRYPTO_ONCE` storage, and
    // `do_registry_init` is a valid `extern "C"` initialiser with no parameters.
    if unsafe { CRYPTO_THREAD_run_once(REGISTRY_ONCE.as_ptr(), Some(do_registry_init)) } == 0 {
        return false;
    }
    !REGISTRY_LOCK.load(Ordering::Acquire).is_null()
}

/// A held registry **read** hold; dropping it unlocks.
///
/// The guard is `!Send` (it holds a raw pointer), so it cannot be moved to another thread. A
/// read taken while this thread already holds a read is a reader-count increment in the crate's
/// `CryptoRwlock`; that is what lets [`crate::x509::v3_prn::X509V3_EXT_print`] hold this guard and
/// still call the public [`X509V3_EXT_get`], which takes its own short read hold.
pub(crate) struct RegistryReadGuard {
    lock: *mut CryptoRwlock,
}

impl RegistryReadGuard {
    /// Take the read hold, or `None` when the lock could not be created or acquired.
    pub(crate) fn acquire() -> Option<Self> {
        if !ensure_registry() {
            return None;
        }
        let lock = REGISTRY_LOCK.load(Ordering::Acquire);
        // SAFETY: `lock` is the live registry lock published by `ensure_registry`.
        if unsafe { CRYPTO_THREAD_read_lock(lock) } == 0 {
            return None;
        }
        #[cfg(test)]
        read_hold_probe::enter();
        Some(Self { lock })
    }
}

impl Drop for RegistryReadGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        read_hold_probe::leave();
        // SAFETY: this guard acquired the read hold and releases it exactly once.
        unsafe { CRYPTO_THREAD_unlock(self.lock) };
    }
}

/// Test-only observation of the registry **read** holds the calling thread holds.
///
/// `CRYPTO_THREAD_unlock` does not attribute reader ownership to a thread, so this counter is not
/// a locking primitive: it exists so a unit test can observe that a dispatcher's hold is the
/// calling thread's hold at the moment a slot accessor or callback runs. It is thread-local, so a
/// test on another thread cannot satisfy the assertion, and it is compiled out of every non-test
/// build.
#[cfg(test)]
mod read_hold_probe {
    use core::cell::Cell;

    std::thread_local! {
        static DEPTH: Cell<usize> = const { Cell::new(0) };
    }

    /// Record one read hold taken on this thread.
    pub(super) fn enter() {
        DEPTH.with(|d| d.set(d.get() + 1));
    }

    /// Record one read hold released on this thread.
    pub(super) fn leave() {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }

    /// Whether this thread holds at least one registry read hold.
    pub(super) fn held() -> bool {
        DEPTH.with(|d| d.get() > 0)
    }
}

/// Test-only: whether the calling thread currently holds the extension registry's read hold.
///
/// A dispatcher that must keep a resolved row live across a slot callback takes
/// [`RegistryReadGuard`]; a test-only slot accessor asserts this probe, so removing the guard makes
/// the assertion fail rather than merely documenting the duty.
#[cfg(test)]
pub(crate) fn registry_read_held_on_this_thread() -> bool {
    read_hold_probe::held()
}

/// Test-only: the number of rows currently in the dynamic extension registry.
///
/// The count is taken under the registry **read** hold, so it cannot observe a
/// concurrent mutation half-way. A caller that holds a read on this thread may
/// call it (a nested read is a count increment); a caller that is the writer may
/// not, because `read_lock` refuses a read while the write lock is held.
#[cfg(test)]
pub(crate) fn registry_row_count() -> usize {
    let Some(_registry) = RegistryReadGuard::acquire() else {
        return 0;
    };
    let list = EXT_LIST.load(Ordering::Acquire);
    if list.is_null() {
        return 0;
    }
    // SAFETY: `list` is the registry list this module built, and the read hold is
    // held for this read.
    usize::try_from(unsafe { OPENSSL_sk_num(list) }).unwrap_or(0)
}

/// A held registry **write** hold; dropping it unlocks. Private because every writer is here.
struct RegistryWriteGuard {
    lock: *mut CryptoRwlock,
}

impl RegistryWriteGuard {
    fn acquire() -> Option<Self> {
        if !ensure_registry() {
            return None;
        }
        let lock = REGISTRY_LOCK.load(Ordering::Acquire);
        // SAFETY: `lock` is the live registry lock published by `ensure_registry`.
        if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
            return None;
        }
        Some(Self { lock })
    }
}

impl Drop for RegistryWriteGuard {
    fn drop(&mut self) {
        // SAFETY: this guard acquired the write hold and releases it exactly once.
        unsafe { CRYPTO_THREAD_unlock(self.lock) };
    }
}

/// `static int ext_cmp(const X509V3_EXT_METHOD *const *a, const X509V3_EXT_METHOD *const *b)`
/// — `crypto/x509/v3_lib.c:39-43`.
///
/// The stack comparator receives pointers to element slots, each holding a `X509V3_EXT_METHOD *`.
///
/// # Safety
/// `a` and `b` are pointers to element slots of this list, each live and readable for one
/// pointer-sized value, and each slot holds a non-NULL `*const X509V3ExtMethod` that outlives
/// the call. The stack layer installs and calls this comparator, so the obligation is the
/// stack's, not a caller-supplied arbitrary pointer.
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
///
/// # Safety
///
/// `ext` is NULL or the element the registry's own `ext_list` holds: the stack is created by
/// `X509V3_EXT_add`'s list constructor with `ext_cmp` as its comparator, and every element pushed
/// into it is a row pointer (this module's only writer). A NULL element is ignored; a DYNAMIC row
/// is the single `CRYPTO_malloc` block `X509V3_EXT_add_alias` made and is released here exactly
/// once, and a non-DYNAMIC row is left untouched because its storage belongs to the caller.
unsafe extern "C" fn ext_list_free(ext: *mut c_void) {
    let method = ext.cast::<X509V3ExtMethod>();
    if !method.is_null() {
        // SAFETY: the slot holds a method pointer per the stack contract.
        if unsafe { (*method).ext_flags } & X509V3_EXT_DYNAMIC != 0 {
            // A DYNAMIC row was `CRYPTO_malloc`ed by `X509V3_EXT_add_alias`; reclaiming it runs the
            // row's single block release at the authority's own `:119` site.
            // SAFETY: `method` is a live DYNAMIC row this module allocated and has not released.
            drop(unsafe {
                OwnedCtx::<X509V3ExtMethod>::from_raw_at(method, SeamFile::new(FILE), LINE_FREE)
            });
        }
    }
}

/// [`X509V3_EXT_add`]'s body, with the registry write hold already held.
///
/// # Safety
///
/// `ext` must satisfy [`X509V3_EXT_add`]'s contract, and the caller must hold the registry
/// **write** hold for the whole call.
unsafe fn ext_add_locked(ext: *mut X509V3ExtMethod) -> c_int {
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
    // SAFETY: `list` is live (write hold) and `ext` is the caller's live row.
    if unsafe { OPENSSL_sk_push(list, ext.cast::<c_void>()) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_LIB_33) };
        return 0;
    }
    // The authority sorts on the first lookup (`X509V3_EXT_get_nid`). Sorting here, under the
    // write hold, keeps every read-side lookup free of a mutation, which is what lets a read
    // hold span the dispatcher's use of the row. A stable sort preserves the order of equal-NID
    // rows, so the lookup result is unchanged.
    // SAFETY: `list` is live and `ext_cmp` is its comparator.
    unsafe { OPENSSL_sk_sort(list) };
    1
}

/// `int X509V3_EXT_add(X509V3_EXT_METHOD *ext)` — `crypto/x509/v3_lib.c:25-37`.
///
/// Lazily creates the list with [`ext_cmp`], then pushes the caller's row (the list does not own
/// it unless it is `X509V3_EXT_DYNAMIC`). The authority's body is only the list creation and
/// `sk_X509V3_EXT_METHOD_push` (`crypto/x509/v3_lib.c:25-37`); it does not inspect or take over
/// the row's callbacks.
///
/// The whole mutation runs under the registry write hold, so no print can be using a row while
/// the list changes.
///
/// # Safety
///
/// `ext` is a live `X509V3_EXT_METHOD` that outlives the list or is `X509V3_EXT_DYNAMIC`.
///
/// In addition, when `ext.i2s` is `Some`, the callback must satisfy the ownership contract on
/// [`X509V3ExtI2s`]: every non-NULL result is the base of a whole `OPENSSL_malloc`/
/// `CRYPTO_strdup` block, NUL-terminated within its `strlen + 1`-byte C-string extent, whose
/// ownership transfers to `X509V3_EXT_print` and is released once there. Registering a callback
/// that returns borrowed or static storage makes the later `OPENSSL_free` invalid; this function
/// cannot verify the callback.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add(ext: *mut X509V3ExtMethod) -> c_int {
    let Some(_registry) = RegistryWriteGuard::acquire() else {
        return 0;
    };
    // SAFETY: `ext` is the caller's row and the write hold is held for the whole call.
    unsafe { ext_add_locked(ext) }
}

/// `int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist)` — `crypto/x509/v3_lib.c:81-87`.
///
/// Walks a caller's table until the `ext_nid == -1` terminator, adding each row. The write hold
/// is taken once for the whole walk, so the list is never observable half-updated.
///
/// # Safety
///
/// `extlist` points at a `-1`-terminated array of live methods that outlive the list (unless a
/// row is `X509V3_EXT_DYNAMIC`, which the list then owns).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_list(extlist: *mut X509V3ExtMethod) -> c_int {
    let Some(_registry) = RegistryWriteGuard::acquire() else {
        return 0;
    };
    let mut p = extlist;
    // SAFETY: the caller's contract is a `-1`-terminated array.
    while unsafe { (*p).ext_nid } != -1 {
        // SAFETY: `p` is a live row of the array and the write hold is held.
        if unsafe { ext_add_locked(p) } == 0 {
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
/// authority. The write hold excludes every read, so a print that has resolved a DYNAMIC row is
/// using it only while this function waits.
///
/// # Safety
///
/// No pointer arguments. A pointer previously returned by [`X509V3_EXT_get_nid`]/[`X509V3_EXT_get`]
/// is a borrowed view (the C ABI cannot extend its lifetime), so a caller that keeps using such a
/// pointer across its own `X509V3_EXT_cleanup` is still responsible for excluding that call. The
/// crate's own dispatchers do not rely on that: `X509V3_EXT_print` holds the read hold.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_cleanup() {
    let Some(_registry) = RegistryWriteGuard::acquire() else {
        return;
    };
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

/// [`X509V3_EXT_get_nid`]'s body, with the registry hold already taken.
///
/// The dynamic list is maintained in `ext_nid` order by [`ext_add_locked`], so this lookup does
/// not mutate it: a read hold is sufficient for the whole search.
///
/// # Safety
///
/// The caller must hold the registry read or write hold for the whole call.
unsafe fn ext_get_nid_locked(nid: c_int) -> *const X509V3ExtMethod {
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
    // The comparator's key: a method whose only read field is `ext_nid`.
    // SAFETY: an all-zero `X509V3ExtMethod` is a valid starting value (`ext_nid` 0, the rest
    // null/None); `ext_nid` is set below.
    let mut tmp: X509V3ExtMethod = unsafe { core::mem::zeroed() };
    tmp.ext_nid = nid;
    // SAFETY: `list` is live under the hold; `&tmp` is the key `ext_cmp` reads `ext_nid` from.
    let idx = unsafe { OPENSSL_sk_find(list, (&raw const tmp).cast::<c_void>()) };
    // SAFETY: `list` is live; an out-of-range `idx` (the miss) answers NULL.
    unsafe { OPENSSL_sk_value(list, idx) }.cast::<X509V3ExtMethod>() as *const X509V3ExtMethod
}

/// `const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid)` — `crypto/x509/v3_lib.c:52-71`.
///
/// A negative `nid` answers NULL; otherwise the ordered `standard_exts[]` search answers first, and
/// failing that the dynamic `ext_list` is binary-searched. A miss answers NULL. The search runs
/// under the registry read hold.
///
/// # Safety
///
/// No pointer arguments. The answer is a **borrowed** row, exactly the authority's C contract: a
/// DYNAMIC row may be released by a later `X509V3_EXT_cleanup`, and the ABI cannot carry the read
/// hold past this return. A caller that uses the pointer after this function returns must exclude
/// a concurrent `_cleanup` itself; `X509V3_EXT_print` does not rely on that contract (it holds the
/// read hold across resolution and use, B49-R10).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3ExtMethod {
    let Some(_registry) = RegistryReadGuard::acquire() else {
        return ptr::null();
    };
    // SAFETY: the read hold is held for the whole lookup.
    unsafe { ext_get_nid_locked(nid) }
}

/// `const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext)` — `crypto/x509/v3_lib.c:73-79`.
///
/// # Safety
///
/// `ext` must be a live `X509_EXTENSION`. The returned row is borrowed on the same terms as
/// [`X509V3_EXT_get_nid`].
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_get(ext: *mut X509Extension) -> *const X509V3ExtMethod {
    let Some(_registry) = RegistryReadGuard::acquire() else {
        return ptr::null();
    };
    // SAFETY: `ext` is live per the contract.
    let nid = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(ext)) };
    if nid == NID_undef {
        return ptr::null();
    }
    // SAFETY: the read hold is held for the whole lookup.
    unsafe { ext_get_nid_locked(nid) }
}

/// `int X509V3_EXT_add_alias(int nid_to, int nid_from)` — `crypto/x509/v3_lib.c:89-108`.
///
/// Copies the `nid_from` row into a fresh `X509V3_EXT_DYNAMIC` allocation retagged `nid_to` and
/// registers it. A missing `nid_from` raises `X509V3_R_EXTENSION_NOT_FOUND`; a failed `_add` frees
/// the copy.
///
/// # Safety
///
/// No pointer arguments. One write hold covers the lookup, the copy and the insert: the source
/// row may itself be a DYNAMIC row, and `X509V3_EXT_cleanup` must not release it between the
/// lookup and the `ptr::read` below.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_alias(nid_to: c_int, nid_from: c_int) -> c_int {
    let Some(_registry) = RegistryWriteGuard::acquire() else {
        return 0;
    };
    // SAFETY: the write hold excludes every mutation for the whole call.
    let ext = unsafe { ext_get_nid_locked(nid_from) };
    if ext.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_LIB_95) };
        return 0;
    }
    // `tmpext` owns the fresh copy; a failed `ext_add_locked` releases it at the authority's own
    // `:104` site, and a successful one gives the block up to the `ext_list`.
    // SAFETY: the allocator answers NULL or one `X509V3ExtMethod`-sized block.
    let Some(raw) = RawCtx::<X509V3ExtMethod>::malloc_at(
        SeamFile::new(FILE),
        LINE_MALLOC_ALIAS,
        SeamFile::new(FILE),
        LINE_FREE_ALIAS,
    ) else {
        return 0;
    };
    let p = raw.as_ptr();
    // SAFETY: `p` is a fresh, unaliased allocation of one row; `ext` is a live row under the hold.
    unsafe {
        ptr::write(p, ptr::read(ext));
        (*p).ext_nid = nid_to;
        (*p).ext_flags |= X509V3_EXT_DYNAMIC;
    }
    // SAFETY: every field of the row has been written above.
    let tmpext = unsafe { raw.assume_init() };
    // SAFETY: `tmpext.as_ptr()` is this call's own row and the write hold is held.
    if unsafe { ext_add_locked(tmpext.as_ptr()) } == 0 {
        // `tmpext` drops here, at the authority's `:104` site.
        return 0;
    }
    // The `ext_list` owns the row now.
    let _ = tmpext.into_raw();
    1
}

/// `void *X509V3_EXT_d2i(X509_EXTENSION *ext)` — `crypto/x509/v3_lib.c:134-149`.
///
/// Decodes the extension's octet-string value through the method's `it` (an `ASN1_item_d2i`) when
/// it is set, else through the method's old-style `d2i`.
///
/// # Safety
///
/// `ext` must be a live `X509_EXTENSION`. The method row this resolves is protected for the whole
/// call by the registry read hold: `X509V3_EXT_add`/`_add_list`/`_add_alias`/`_cleanup` take the
/// write hold, so a DYNAMIC alias row cannot be released between the resolution and the `it`/`d2i`
/// slot read below (B51).
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_d2i(ext: *mut X509Extension) -> *mut c_void {
    // Hold the registry read lock across the row resolution **and** the slot read below. Without
    // it, a concurrent `X509V3_EXT_cleanup` could release a DYNAMIC row returned by
    // `X509V3_EXT_get` before `(*method).it`/`(*method).d2i` are read (B51). The nested read
    // inside `X509V3_EXT_get` is a reader/reader acquisition, not a self-deadlock. A failure to
    // take the hold answers NULL exactly as the nested lookup's own failure would.
    let Some(_registry) = RegistryReadGuard::acquire() else {
        return ptr::null_mut();
    };
    // SAFETY: `ext` is live per the contract, and the read hold taken above protects the row.
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

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(X509V3ExtMethod => zero_state_sweep_x509_v3_ext_method);
