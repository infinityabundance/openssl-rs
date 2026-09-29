//! `crypto/x509/v3_lib.c` — the extension registration surface. Phase 10.13, **partial**.
//!
//! This unit is the deliberate scope increase of 10.13: D455 withheld the four `ossl_v3_*`
//! table-only leaves because their only caller, `X509V3_add_standard_extensions`, was unlanded,
//! and recorded the plan's expectation that pulling `v3_lib.c` in would make them drivable. The
//! measurement below shows that expectation is **wrong**, and says exactly where the wall is.
//!
//! ## What lands, and what the wall is
//!
//! The authority's `v3_lib.c` is 308 lines. Its **registration** half lands whole:
//!
//! * the `X509V3_EXT_METHOD` structure ([`X509V3ExtMethod`], `include/openssl/x509v3.h:65-85`),
//!   with every field at the offset the header gives;
//! * `ext_cmp` (`:39-43`) and `ext_list_free` (`:116-120`), the two `static` helpers;
//! * `X509V3_EXT_add` (`:25-37`), `X509V3_EXT_add_list` (`:81-87`) and `X509V3_EXT_cleanup`
//!   (`:110-114`), the process-global `ext_list` and its lifecycle;
//! * `X509V3_add_standard_extensions` (`:127-130`), which returns 1 by design.
//!
//! Its **lookup** half is withheld **by name**, and the blocker is not any one unit's:
//!
//! * `X509V3_EXT_get_nid` (`:52-71`) — the whole function is a search over
//!   `standard_exts[]` (`standard_exts.h:15-95`, `#include`d at `v3_lib.c:50`) with the dynamic
//!   `ext_list` as a fallback. `standard_exts[]` names **63 `ossl_v3_*` tables**, of which this
//!   subphase lands five (`ossl_v3_utf8_list`, `ossl_v3_pkey_usage_period`, `ossl_v3_time_specification`,
//!   `ossl_v3_no_rev_avail`, `ossl_v3_single_use`, and `ossl_v3_soa_identifier` is the sixth) and
//!   **the other ~57 belong to units this subphase does not own** (`v3_bcons.c`, `v3_key_usage.c`,
//!   `v3_alt.c`, `v3_cpols.c`, `v3_addr.c`, `v3_asid.c`, the `crypto/ocsp/` rows, `v3_ncons.c`,
//!   `v3_pmaps.c`, `v3_pcons.c`, `v3_crld.c`, `pcy_*`, …). A partial `standard_exts[]` would
//!   change `OBJ_bsearch_ext`'s answers for every missing NID — a silent divergence, not a
//!   frontier — so the whole function is withheld rather than half-landed. This is the measured
//!   answer to D455's open question, and it is *sharper* than D455's: the four table-only leaves
//!   are not merely unnameable, they sit behind a table whose dependency is the 10.14 SCC.
//! * `X509V3_EXT_get` (`:73-79`) — calls the withheld `X509V3_EXT_get_nid`.
//! * `X509V3_EXT_add_alias` (`:89-108`) — calls the withheld `X509V3_EXT_get_nid`.
//! * `X509V3_EXT_d2i` (`:134-149`) — calls the withheld `X509V3_EXT_get`.
//! * `X509V3_get_d2i` (`:167-215`) — calls the withheld `X509V3_EXT_d2i`.
//! * `X509V3_add1_i2d` (`:223-308`) — calls `X509V3_EXT_i2d`, which lives in `v3_conf.c`
//!   (`:191-200`) and is itself unlanded, and it calls `X509V3_EXT_get_nid` through it.
//!
//! No stub is written: the six names above are named, not declared, so the crate's surface is
//! only what the registration half defines.
//!
//! ## Ownership and the four leaves
//!
//! Because `X509V3_EXT_get_nid` is withheld, the four table-only leaves 10.13 was asked to land
//! (`ossl_v3_utf8_list`'s table, `ossl_v3_no_rev_avail`, `ossl_v3_single_use`,
//! `ossl_v3_soa_identifier`) remain withheld by name — but with this precise blocker instead of
//! D455's vaguer two-part one. `src/x509/v3_no_rev_avail.rs`, `v3_single_use.rs` and `v3_soa_id.rs`
//! record it; `v3_utf8.rs` lands the unit's two public helpers and withholds only its table. This
//! is the reverse of "land what you can": the *caller* landed, the *dispatch* did not.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_lib.c` joins `gen_err_raise_sites.py`'s covered set with this subphase, so the
//! four reachable raises -- `X509V3_EXT_add`'s two `ERR_R_CRYPTO_LIB` sites (`:29`, `:33`) -- are
//! the generated `V3_LIB_*` constants. The withheld functions' sites are generated too, unused
//! until they land.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms call `X509V3_add_standard_extensions` (the legacy no-op), then
//! `X509V3_EXT_add`/`_add_list` over a probe-declared method and `X509V3_EXT_cleanup`, observing
//! the return values and the error queue (each arm pops first). `X509V3_EXT_get_nid`/`_get` are
//! not driven -- they are withheld, so no arm names them.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::asn1::layout::Asn1Item;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::stack::{OPENSSL_sk_new, OPENSSL_sk_pop_free, OPENSSL_sk_push, OpenSslStack};

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansion — `crypto/x509/v3_lib.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_lib.c";
/// `ext_list_free`'s `OPENSSL_free(ext)` (`crypto/x509/v3_lib.c:119`).
const LINE_FREE: c_int = 119;

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
