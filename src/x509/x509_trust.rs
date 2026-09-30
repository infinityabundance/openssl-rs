//! `crypto/x509/x509_trust.c` — the trust/reject table and the trust checkers. **This slice lands
//! the unit whole**: all eleven of its open exports and the six `static` helpers they are built on.
//!
//! `crypto/x509/x509_trust.c` is 298 lines and publishes a table of trust-checking functions —
//! the eight reserved rows (`trstandard[]`, `:31-46`) plus the dynamic rows an application adds
//! through [`X509_TRUST_add`] — and the checkers that decide whether a certificate is trusted for
//! a purpose. Nothing here waits on a later stratum: this unit's closure is the landed `X509`,
//! `X509_CERT_AUX`, `X509_check_purpose` (`v3_purp.rs`, 10.14), `OBJ_obj2nid`
//! (`runtime/obj.rs`), the `OPENSSL_sk_*` stack and the `CRYPTO_*` allocator, which is why it is
//! the one unit of 11.1b that lands without a withheld name (see the module doc of
//! [`crate::x509::by_file`] and [`crate::x509::by_dir`] for the two that cannot).
//!
//! ## The layout, and the standard table
//!
//! `struct x509_trust_st` (`X509_TRUST`) — `include/openssl/x509_vfy.h:188-195`:
//!
//! ```text
//! typedef struct x509_trust_st {
//!     int trust;                                   /* the reserved or dynamic id      */
//!     int flags;                                   /* X509_TRUST_DYNAMIC{,_NAME}      */
//!     int (*check_trust)(struct x509_trust_st *, X509 *, int);
//!     char *name;
//!     int arg1;                                    /* the purpose OID for the checkers */
//!     void *arg2;
//! } X509_TRUST;
//! ```
//!
//! That is 4 + 4 + 8 + 8 + 4 + (4 pad) + 8 = **40** bytes on the target, asserted below. The
//! standard table is writable — [`X509_TRUST_add`] overwrites a reserved row in place when its id
//! names one — so it is held in an [`UnsafeCell`] behind a `Sync` wrapper carrying that claim,
//! exactly as `v3_purp.rs` holds `xstandard[]`.
//!
//! ## The raise sites
//!
//! `crypto/x509/x509_trust.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! three coordinates are **declared locally** in the `err_sites::ErrSite` shape (as `v3_purp.rs`
//! does). Two are [`X509_TRUST_add`]'s failed `sk_X509_TRUST_new`/`_push` (`:168`/`:172`,
//! `ERR_R_CRYPTO_LIB` = `15 | ERR_RFLAG_COMMON`, `include/openssl/err.h.in:330`/`:241`/`:89`) and
//! one is [`X509_TRUST_set`]'s rejected id (`:120`, `X509_R_INVALID_TRUST` = 123,
//! `include/openssl/x509err.h:40`), both raised against `ERR_LIB_X509` = 11
//! (`include/openssl/err.h.in:85`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::runtime::err::err_reasons::X509_R_INVALID_TRUST;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::obj::{
    Asn1Object, NID_OCSP_sign, NID_ad_OCSP, NID_anyExtendedKeyUsage, NID_client_auth,
    NID_code_sign, NID_email_protect, NID_server_auth, NID_time_stamp, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x_x509::X509;
use crate::x509::x_x509a::X509CertAux;

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `15 | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;

/// `X509_TRUST_DEFAULT` — `include/openssl/x509_vfy.h:195`, only valid in purpose settings.
const X509_TRUST_DEFAULT: c_int = 0;
/// `X509_TRUST_COMPAT` — `include/openssl/x509_vfy.h:196`.
const X509_TRUST_COMPAT: c_int = 1;
/// `X509_TRUST_SSL_CLIENT` — `include/openssl/x509_vfy.h:197`.
const X509_TRUST_SSL_CLIENT: c_int = 2;
/// `X509_TRUST_SSL_SERVER` — `include/openssl/x509_vfy.h:198`.
const X509_TRUST_SSL_SERVER: c_int = 3;
/// `X509_TRUST_EMAIL` — `include/openssl/x509_vfy.h:199`.
const X509_TRUST_EMAIL: c_int = 4;
/// `X509_TRUST_OBJECT_SIGN` — `include/openssl/x509_vfy.h:200`.
const X509_TRUST_OBJECT_SIGN: c_int = 5;
/// `X509_TRUST_OCSP_SIGN` — `include/openssl/x509_vfy.h:201`.
const X509_TRUST_OCSP_SIGN: c_int = 6;
/// `X509_TRUST_OCSP_REQUEST` — `include/openssl/x509_vfy.h:202`.
const X509_TRUST_OCSP_REQUEST: c_int = 7;
/// `X509_TRUST_TSA` — `include/openssl/x509_vfy.h:203`.
const X509_TRUST_TSA: c_int = 8;
/// `X509_TRUST_MIN` — `include/openssl/x509_vfy.h:205`.
const X509_TRUST_MIN: c_int = 1;
/// `X509_TRUST_MAX` — `include/openssl/x509_vfy.h:206`.
const X509_TRUST_MAX: c_int = 8;

/// `X509_TRUST_DYNAMIC` — `include/openssl/x509_vfy.h:209`, `1U << 0`.
const X509_TRUST_DYNAMIC: c_int = 1 << 0;
/// `X509_TRUST_DYNAMIC_NAME` — `include/openssl/x509_vfy.h:210`, `1U << 1`.
const X509_TRUST_DYNAMIC_NAME: c_int = 1 << 1;
/// `X509_TRUST_NO_SS_COMPAT` — `include/openssl/x509_vfy.h:212`, `1U << 2`.
const X509_TRUST_NO_SS_COMPAT: c_int = 1 << 2;
/// `X509_TRUST_DO_SS_COMPAT` — `include/openssl/x509_vfy.h:214`, `1U << 3`.
const X509_TRUST_DO_SS_COMPAT: c_int = 1 << 3;
/// `X509_TRUST_OK_ANY_EKU` — `include/openssl/x509_vfy.h:216`, `1U << 4`.
const X509_TRUST_OK_ANY_EKU: c_int = 1 << 4;

/// `X509_TRUST_TRUSTED` — `include/openssl/x509_vfy.h:219`, a `check_trust` return code.
const X509_TRUST_TRUSTED: c_int = 1;
/// `X509_TRUST_REJECTED` — `include/openssl/x509_vfy.h:220`, a `check_trust` return code.
const X509_TRUST_REJECTED: c_int = 2;
/// `X509_TRUST_UNTRUSTED` — `include/openssl/x509_vfy.h:221`, a `check_trust` return code.
const X509_TRUST_UNTRUSTED: c_int = 3;

/// `X509_TRUST_COUNT` — `crypto/x509/x509_trust.c:48`, `OSSL_NELEM(trstandard)`: the eight reserved
/// rows, kept in trust order and without gaps so `id - X509_TRUST_MIN` indexes the table.
const X509_TRUST_COUNT: c_int = 8;

/// `EXFLAG_SS` — `include/openssl/x509v3.h:684`, the self-signed bit [`trust_compat`] tests.
const EXFLAG_SS: c_uint = 0x2000;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_malloc`/`OPENSSL_strdup`/`OPENSSL_free`
/// expansions.
const FILE: &CStr = c"crypto/x509/x509_trust.c";
/// `X509_TRUST_add`'s `OPENSSL_malloc(sizeof(*trtmp))` (`:142`).
const LINE_MALLOC_TRTMP: c_int = 142;
/// `X509_TRUST_add`'s `OPENSSL_free(trtmp->name)` (`:150`).
const LINE_FREE_STD_NAME: c_int = 150;
/// `X509_TRUST_add`'s `OPENSSL_strdup(name)` (`:152`).
const LINE_STRDUP_TRTMP_NAME: c_int = 152;
/// `X509_TRUST_add`'s error-path `OPENSSL_free(trtmp->name)` (`:179`).
const LINE_FREE_ERR_NAME: c_int = 179;
/// `X509_TRUST_add`'s error-path `OPENSSL_free(trtmp)` (`:180`).
const LINE_FREE_ERR_TRTMP: c_int = 180;
/// `trtable_free`'s `OPENSSL_free(p->name)` (`:191`).
const LINE_FREE_DYN_NAME: c_int = 191;
/// `trtable_free`'s `OPENSSL_free(p)` (`:192`).
const LINE_FREE_DYN_P: c_int = 192;

/// One `x509_trust.c` raise coordinate, declared locally (see the module doc).
const fn x509_trust_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_trust.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_TRUST_set`'s rejected id at `x509_trust.c:120`.
const X509_TRUST_120: ErrSite = x509_trust_site(120, c"X509_TRUST_set", X509_R_INVALID_TRUST);
/// `X509_TRUST_add`'s failed `sk_X509_TRUST_new` at `x509_trust.c:168`.
const X509_TRUST_168: ErrSite = x509_trust_site(168, c"X509_TRUST_add", ERR_R_CRYPTO_LIB);
/// `X509_TRUST_add`'s failed `sk_X509_TRUST_push` at `x509_trust.c:172`.
const X509_TRUST_172: ErrSite = x509_trust_site(172, c"X509_TRUST_add", ERR_R_CRYPTO_LIB);

// ---------------------------------------------------------------------------------------------
// The trust type and the two tables — `x509_trust.c:15-50`
// ---------------------------------------------------------------------------------------------

/// `struct x509_trust_st` — `X509_TRUST`, from `include/openssl/x509_vfy.h:188-195`.
///
/// One row of a trust table: the reserved or dynamic id, the `X509_TRUST_*` flags, the checker, the
/// name, the purpose OID the `trust_1oid*` checkers consult, and the application's opaque argument.
#[repr(C)]
pub struct X509Trust {
    /// `int trust` — the id, unique among all rows.
    pub(crate) trust: c_int,
    /// `int flags` — `X509_TRUST_DYNAMIC`/`X509_TRUST_DYNAMIC_NAME`.
    pub(crate) flags: c_int,
    /// `int (*check_trust)(X509_TRUST *, X509 *, int)` — the checker.
    pub(crate) check_trust: Option<CheckTrust>,
    /// `char *name` — the name, owned when `X509_TRUST_DYNAMIC_NAME` is set.
    pub(crate) name: *mut c_char,
    /// `int arg1` — the purpose OID for the `trust_1oid*` checkers.
    pub(crate) arg1: c_int,
    /// `void *arg2` — the application's argument.
    pub(crate) arg2: *mut c_void,
}

/// The `check_trust` callback the `X509_TRUST` struct carries.
type CheckTrust = unsafe extern "C" fn(*mut X509Trust, *mut X509, c_int) -> c_int;

/// The `default_trust` slot's own type — `int (*)(int id, X509 *x, int flags)`.
type DefaultTrustFn = unsafe extern "C" fn(c_int, *mut X509, c_int) -> c_int;

const _: () = {
    assert!(core::mem::size_of::<X509Trust>() == 40);
    assert!(core::mem::offset_of!(X509Trust, trust) == 0);
    assert!(core::mem::offset_of!(X509Trust, flags) == 4);
    assert!(core::mem::offset_of!(X509Trust, check_trust) == 8);
    assert!(core::mem::offset_of!(X509Trust, name) == 16);
    assert!(core::mem::offset_of!(X509Trust, arg1) == 24);
    assert!(core::mem::offset_of!(X509Trust, arg2) == 32);
};

/// `static X509_TRUST trstandard[]` — `x509_trust.c:31-46`.
///
/// The eight reserved rows, in trust order so `idx` indexes directly, wrapped in an `UnsafeCell`
/// because [`X509_TRUST_add`] may modify a reserved row in place. The wrapper carries the `Sync`
/// claim for that writable storage.
#[repr(transparent)]
struct TrstandardTable(UnsafeCell<[X509Trust; 8]>);

// SAFETY: the table is read and written only through this module's unlocked, single-threaded trust
// table discipline, exactly as the authority's plain `trstandard[]` is.
unsafe impl Sync for TrstandardTable {}

static TRSTANDARD: TrstandardTable = TrstandardTable(UnsafeCell::new([
    X509Trust {
        trust: X509_TRUST_COMPAT,
        flags: 0,
        check_trust: Some(trust_compat),
        name: c"compatible".as_ptr().cast_mut(),
        arg1: 0,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_SSL_CLIENT,
        flags: 0,
        check_trust: Some(trust_1oidany),
        name: c"SSL Client".as_ptr().cast_mut(),
        arg1: NID_client_auth,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_SSL_SERVER,
        flags: 0,
        check_trust: Some(trust_1oidany),
        name: c"SSL Server".as_ptr().cast_mut(),
        arg1: NID_server_auth,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_EMAIL,
        flags: 0,
        check_trust: Some(trust_1oidany),
        name: c"S/MIME email".as_ptr().cast_mut(),
        arg1: NID_email_protect,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_OBJECT_SIGN,
        flags: 0,
        check_trust: Some(trust_1oidany),
        name: c"Object Signer".as_ptr().cast_mut(),
        arg1: NID_code_sign,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_OCSP_SIGN,
        flags: 0,
        check_trust: Some(trust_1oid),
        name: c"OCSP responder".as_ptr().cast_mut(),
        arg1: NID_OCSP_sign,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_OCSP_REQUEST,
        flags: 0,
        check_trust: Some(trust_1oid),
        name: c"OCSP request".as_ptr().cast_mut(),
        arg1: NID_ad_OCSP,
        arg2: ptr::null_mut(),
    },
    X509Trust {
        trust: X509_TRUST_TSA,
        flags: 0,
        check_trust: Some(trust_1oidany),
        name: c"TSA server".as_ptr().cast_mut(),
        arg1: NID_time_stamp,
        arg2: ptr::null_mut(),
    },
]));

/// `static STACK_OF(X509_TRUST) *trtable` — `x509_trust.c:50`.
///
/// The dynamic rows an application adds. The authority stores a bare pointer and never locks it, so
/// this models the same single-threaded slot as an `AtomicPtr`, as `v3_purp.rs` models `xptable`.
static TRTABLE: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static int (*default_trust)(int id, X509 *x, int flags) = obj_trust` — `x509_trust.c:23`.
///
/// The checker [`X509_check_trust`] falls back to for an id no table row claims. The authority
/// keeps a plain function-pointer static and [`X509_TRUST_set_default`] reassigns it, so this
/// models the same single-threaded slot in an `UnsafeCell`.
#[repr(transparent)]
struct DefaultTrustCell(UnsafeCell<Option<DefaultTrustFn>>);

// SAFETY: the slot is read and written only through `X509_TRUST_set_default` and
// `X509_check_trust`, the same unlocked single-threaded discipline the authority's plain
// function-pointer static has.
unsafe impl Sync for DefaultTrustCell {}

static DEFAULT_TRUST: DefaultTrustCell = DefaultTrustCell(UnsafeCell::new(Some(obj_trust)));

// ---------------------------------------------------------------------------------------------
// The table helpers — `x509_trust.c:52-55`, `:185-194`
// ---------------------------------------------------------------------------------------------

/// `static int tr_cmp(const X509_TRUST *const *a, const X509_TRUST *const *b)` —
/// `x509_trust.c:52-55`.
///
/// The `STACK` comparator receives pointers to the element pointers, so both arguments are cast to
/// `*const *const X509Trust` before the id is read.
///
/// # Safety
///
/// `a` and `b` must each point at a live `X509_TRUST *` slot.
unsafe extern "C" fn tr_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: both arguments are pointer-to-element-pointer slots per the stack's contract.
    unsafe { (**a.cast::<*const X509Trust>()).trust - (**b.cast::<*const X509Trust>()).trust }
}

/// `static void trtable_free(X509_TRUST *p)` — `x509_trust.c:185-194`.
///
/// Frees a dynamic row's owned name and then the row; a reserved row (no `X509_TRUST_DYNAMIC`) and
/// NULL are left alone, so the reserved table's string literals are never released.
///
/// # Safety
///
/// `p` must be NULL or a row this module allocated through [`X509_TRUST_add`].
unsafe fn trtable_free(p: *mut X509Trust) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is non-NULL and live per the contract.
    if (unsafe { (*p).flags } & X509_TRUST_DYNAMIC) == 0 {
        return;
    }
    // SAFETY: `p` is a dynamic row and its fields are live.
    if (unsafe { (*p).flags } & X509_TRUST_DYNAMIC_NAME) != 0 {
        // SAFETY: `name` is the dynamic row's own owned string.
        unsafe {
            CRYPTO_free(
                (*p).name.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_DYN_NAME,
            );
        }
    }
    // SAFETY: `p` is the row this function frees.
    unsafe { CRYPTO_free(p.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_DYN_P) };
}

/// The `X509_TRUST` destructor [`X509_TRUST_cleanup`] passes to `OPENSSL_sk_pop_free`.
///
/// # Safety
///
/// `elem` must be NULL or an `X509_TRUST` this module allocated.
unsafe extern "C" fn trtable_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a row per the contract; `trtable_free` accepts NULL.
    unsafe { trtable_free(elem.cast::<X509Trust>()) };
}

// ---------------------------------------------------------------------------------------------
// The table accessors and the entry points — `x509_trust.c:57-215`
// ---------------------------------------------------------------------------------------------

/// `int (*X509_TRUST_set_default(int (*trust)(int, X509 *, int)))(int, X509 *, int)` —
/// `x509_trust.c:57-64`.
///
/// Stores `trust` as the fallback checker and answers the one it replaced.
///
/// # Safety
///
/// `trust` must be NULL or a valid `int (*)(int, X509 *, int)` checker.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_set_default(
    trust: Option<DefaultTrustFn>,
) -> Option<DefaultTrustFn> {
    // SAFETY: the slot is this module's own static.
    let slot = DEFAULT_TRUST.0.get();
    // SAFETY: `slot` is live per the above.
    let old = unsafe { *slot };
    // SAFETY: `slot` is live and writable.
    unsafe { *slot = trust };
    old
}

/// `int X509_check_trust(X509 *x, int id, int flags)` — `x509_trust.c:67-81`.
///
/// Returns `X509_TRUST_TRUSTED`, `X509_TRUST_REJECTED` or `X509_TRUST_UNTRUSTED`. The default id
/// asks [`obj_trust`] for `anyExtendedKeyUsage` with `X509_TRUST_DO_SS_COMPAT` forced on; a
/// reserved or dynamic id dispatches to its row's checker, and an unknown id to the fallback.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_trust(x: *mut X509, id: c_int, flags: c_int) -> c_int {
    if id == X509_TRUST_DEFAULT {
        // SAFETY: `x` is live per the contract.
        return unsafe { obj_trust(NID_anyExtendedKeyUsage, x, flags | X509_TRUST_DO_SS_COMPAT) };
    }
    // SAFETY: the table, if present, is this module's own.
    let idx = unsafe { X509_TRUST_get_by_id(id) };
    if idx < 0 {
        // SAFETY: the slot is this module's own static; the contract guarantees the fallback is a
        // valid checker (it is initialised to `obj_trust` and only `X509_TRUST_set_default` moves
        // it). A NULL slot is the authority's own undefined call.
        return match unsafe { *DEFAULT_TRUST.0.get() } {
            Some(default_trust) => {
                // SAFETY: `default_trust` is the live checker the slot names; `id`/`x`/`flags` are
                // the caller's.
                unsafe { default_trust(id, x, flags) }
            }
            None => 0,
        };
    }
    // SAFETY: `idx` is a valid index per `X509_TRUST_get_by_id`.
    let pt = unsafe { X509_TRUST_get0(idx) };
    // SAFETY: `pt` is a live row and its checker is set.
    match unsafe { (*pt).check_trust } {
        Some(check_trust) => {
            // SAFETY: `check_trust` is the row's own live checker; `pt`/`x`/`flags` are the
            // caller's.
            unsafe { check_trust(pt, x, flags) }
        }
        None => 0,
    }
}

/// `int X509_TRUST_get_count(void)` — `x509_trust.c:83-88`.
///
/// The reserved row count, plus the dynamic table's length when it exists.
///
/// # Safety
///
/// The dynamic table, if present, is this module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get_count() -> c_int {
    let table = TRTABLE.load(Ordering::Acquire);
    if table.is_null() {
        return X509_TRUST_COUNT;
    }
    // SAFETY: `table` is this module's own list; `OPENSSL_sk_num` accepts any pointer.
    unsafe { OPENSSL_sk_num(table) + X509_TRUST_COUNT }
}

/// `X509_TRUST *X509_TRUST_get0(int idx)` — `x509_trust.c:90-97`.
///
/// A reserved row for `idx < X509_TRUST_COUNT`, otherwise the dynamic table's
/// `idx - X509_TRUST_COUNT` entry. A negative index answers NULL, as does an out-of-range dynamic
/// index (through `OPENSSL_sk_value`).
///
/// # Safety
///
/// The dynamic table, if present, is this module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get0(idx: c_int) -> *mut X509Trust {
    if idx < 0 {
        return ptr::null_mut();
    }
    if idx < X509_TRUST_COUNT {
        // SAFETY: `idx` is within the reserved table, whose storage is this module's own.
        return unsafe { TRSTANDARD.0.get().cast::<X509Trust>().add(idx as usize) };
    }
    let table = TRTABLE.load(Ordering::Acquire);
    // SAFETY: `table` is this module's own list; `OPENSSL_sk_value` accepts NULL and any index.
    unsafe { OPENSSL_sk_value(table, idx - X509_TRUST_COUNT) }.cast::<X509Trust>()
}

/// `int X509_TRUST_get_by_id(int id)` — `x509_trust.c:99-115`.
///
/// The reserved range answers its index directly; otherwise the dynamic table is sorted and
/// searched by id, and a hit is offset by `X509_TRUST_COUNT`. A miss answers -1.
///
/// # Safety
///
/// The dynamic table, if present, is this module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get_by_id(id: c_int) -> c_int {
    if (X509_TRUST_MIN..=X509_TRUST_MAX).contains(&id) {
        return id - X509_TRUST_MIN;
    }
    let table = TRTABLE.load(Ordering::Acquire);
    if table.is_null() {
        return -1;
    }
    // Only `trust` is read from the key, so the zeroed remainder is never observed.
    let tmp = X509Trust {
        trust: id,
        flags: 0,
        check_trust: None,
        name: ptr::null_mut(),
        arg1: 0,
        arg2: ptr::null_mut(),
    };
    // SAFETY: `table` is this module's own list; the authority sorts before the search.
    unsafe { OPENSSL_sk_sort(table) };
    // SAFETY: `table` is this module's own list and `&tmp` is a live key its comparator reads.
    let idx = unsafe { OPENSSL_sk_find(table, (&raw const tmp).cast::<c_void>()) };
    if idx < 0 {
        return -1;
    }
    idx + X509_TRUST_COUNT
}

/// `int X509_TRUST_set(int *t, int trust)` — `x509_trust.c:117-125`.
///
/// Stores `trust` in `*t` if [`X509_TRUST_get_by_id`] recognises it; an unknown id raises
/// `X509_R_INVALID_TRUST` and answers 0.
///
/// # Safety
///
/// `t` must be a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_set(t: *mut c_int, trust: c_int) -> c_int {
    // SAFETY: the table, if present, is this module's own.
    if unsafe { X509_TRUST_get_by_id(trust) } < 0 {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_TRUST_120) };
        return 0;
    }
    // SAFETY: `t` is writable per the contract.
    unsafe { *t = trust };
    1
}

/// `int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int), const char *name,
/// int arg1, void *arg2)` — `x509_trust.c:127-183`.
///
/// Adds a dynamic row, or modifies an existing row in place (a reserved one included). The name is
/// copied; the flags word's `X509_TRUST_DYNAMIC` bit is application-controlled off and the
/// `X509_TRUST_DYNAMIC_NAME` bit is forced on. A failed allocation or push raises
/// `ERR_R_CRYPTO_LIB` and answers 0.
///
/// # Safety
///
/// `name` must be a NUL-terminated C string; `ck` must be a valid checker; the dynamic table must
/// not be raced.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_add(
    id: c_int,
    flags: c_int,
    ck: Option<CheckTrust>,
    name: *const c_char,
    arg1: c_int,
    arg2: *mut c_void,
) -> c_int {
    // This is set according to what we change: application can't set it.
    // This will always be set for application modified trust entries.
    let flags = (flags & !X509_TRUST_DYNAMIC) | X509_TRUST_DYNAMIC_NAME;

    // SAFETY: the table, if present, is this module's own.
    let idx = unsafe { X509_TRUST_get_by_id(id) };
    let trtmp: *mut X509Trust;
    if idx < 0 {
        // SAFETY: the allocator takes the file/line for its mdbg record only.
        let p = CRYPTO_malloc(
            core::mem::size_of::<X509Trust>(),
            FILE.as_ptr(),
            LINE_MALLOC_TRTMP,
        )
        .cast::<X509Trust>();
        if p.is_null() {
            return 0;
        }
        trtmp = p;
        // SAFETY: `trtmp` is this call's own fresh row.
        unsafe { (*trtmp).flags = X509_TRUST_DYNAMIC };
    } else {
        // SAFETY: `idx` is a valid index per `X509_TRUST_get_by_id`.
        trtmp = unsafe { X509_TRUST_get0(idx) };
    }

    // SAFETY: `trtmp` is a live row per the above.
    if (unsafe { (*trtmp).flags } & X509_TRUST_DYNAMIC_NAME) != 0 {
        // SAFETY: the row owns its name when the dynamic-name bit is set.
        unsafe {
            CRYPTO_free(
                (*trtmp).name.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_STD_NAME,
            )
        };
    }
    // SAFETY: `name` is NUL-terminated per the contract; the allocator takes file/line only.
    let dup = unsafe { CRYPTO_strdup(name, FILE.as_ptr(), LINE_STRDUP_TRTMP_NAME) };
    // SAFETY: `trtmp` is live and writable.
    unsafe { (*trtmp).name = dup };
    if dup.is_null() {
        // SAFETY: `trtmp` is this call's live row; `idx < 0` releases it, `idx >= 0` leaves it.
        return unsafe { x509_trust_add_err(idx, trtmp) };
    }
    // SAFETY: `trtmp` is live and writable.
    unsafe {
        // Keep the dynamic flag of existing entry, then set all other flags.
        (*trtmp).flags &= X509_TRUST_DYNAMIC;
        (*trtmp).flags |= flags;
        (*trtmp).trust = id;
        (*trtmp).check_trust = ck;
        (*trtmp).arg1 = arg1;
        (*trtmp).arg2 = arg2;
    }

    // If it is a new entry, manage the dynamic table.
    if idx < 0 {
        let mut table = TRTABLE.load(Ordering::Acquire);
        if table.is_null() {
            // SAFETY: `tr_cmp` is this module's comparator and `OPENSSL_sk_new` accepts NULL.
            table = OPENSSL_sk_new(Some(tr_cmp));
            if table.is_null() {
                // SAFETY: the site's pointers are static.
                unsafe { raise_site(&X509_TRUST_168) };
                // SAFETY: `trtmp` is this call's live row; `idx < 0` releases it.
                return unsafe { x509_trust_add_err(idx, trtmp) };
            }
            TRTABLE.store(table, Ordering::Release);
        }
        // SAFETY: `table` is this module's own list; `trtmp` is the row to push.
        if unsafe { OPENSSL_sk_push(table, trtmp.cast::<c_void>()) } == 0 {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&X509_TRUST_172) };
            // SAFETY: `trtmp` is this call's live row; `idx < 0` releases it.
            return unsafe { x509_trust_add_err(idx, trtmp) };
        }
    }
    1
}

/// The `err:` label of [`X509_TRUST_add`] — `x509_trust.c:177-182`.
///
/// A dynamic row that failed to install is released whole; a reserved row that failed is left in
/// place (the authority only frees when `idx < 0`).
///
/// # Safety
///
/// `trtmp` must be live; `idx` is `X509_TRUST_get_by_id`'s answer.
unsafe fn x509_trust_add_err(idx: c_int, trtmp: *mut X509Trust) -> c_int {
    if idx < 0 {
        // SAFETY: `trtmp` is this call's own uninstalled row and its name field.
        unsafe {
            CRYPTO_free(
                (*trtmp).name.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_ERR_NAME,
            );
            CRYPTO_free(trtmp.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_ERR_TRTMP);
        }
    }
    0
}

/// `void X509_TRUST_cleanup(void)` — `x509_trust.c:196-200`.
///
/// Releases every dynamic row and clears the table.
///
/// # Safety
///
/// The dynamic table, if present, is this module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_cleanup() {
    let table = TRTABLE.swap(ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: `table` is NULL or the list this module built; `trtable_free_thunk` handles NULL.
    unsafe { OPENSSL_sk_pop_free(table, Some(trtable_free_thunk)) };
}

/// `int X509_TRUST_get_flags(const X509_TRUST *xp)` — `x509_trust.c:202-205`.
///
/// # Safety
///
/// `xp` must be a live `X509_TRUST`.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get_flags(xp: *const X509Trust) -> c_int {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).flags }
}

/// `char *X509_TRUST_get0_name(const X509_TRUST *xp)` — `x509_trust.c:207-210`.
///
/// # Safety
///
/// `xp` must be a live `X509_TRUST`; the answer is borrowed.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get0_name(xp: *const X509Trust) -> *mut c_char {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).name }
}

/// `int X509_TRUST_get_trust(const X509_TRUST *xp)` — `x509_trust.c:212-215`.
///
/// # Safety
///
/// `xp` must be a live `X509_TRUST`.
#[no_mangle]
pub unsafe extern "C" fn X509_TRUST_get_trust(xp: *const X509Trust) -> c_int {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).trust }
}

// ---------------------------------------------------------------------------------------------
// The checkers — `x509_trust.c:217-298`
// ---------------------------------------------------------------------------------------------

/// `static int trust_1oidany(X509_TRUST *trust, X509 *x, int flags)` — `x509_trust.c:217-227`.
///
/// Declares the chain verified if the desired trust OID is not rejected in any auxiliary trust
/// info for the certificate, and the OID is either expressly trusted, or else `anyEKU` is trusted,
/// or the certificate is self-signed and `X509_TRUST_NO_SS_COMPAT` is not set.
///
/// # Safety
///
/// `trust` must be a live row with a purpose OID in `arg1`; `x` must be a live `X509`.
unsafe extern "C" fn trust_1oidany(trust: *mut X509Trust, x: *mut X509, flags: c_int) -> c_int {
    // SAFETY: `trust` is live per the contract.
    let arg1 = unsafe { (*trust).arg1 };
    // SAFETY: `x` is live per the contract.
    unsafe {
        obj_trust(
            arg1,
            x,
            flags | X509_TRUST_DO_SS_COMPAT | X509_TRUST_OK_ANY_EKU,
        )
    }
}

/// `static int trust_1oid(X509_TRUST *trust, X509 *x, int flags)` — `x509_trust.c:229-238`.
///
/// Declares the chain verified only if the desired trust OID is not rejected and is expressly
/// trusted. Neither `anyEKU` nor the self-signed compatibility rule applies.
///
/// # Safety
///
/// `trust` must be a live row with a purpose OID in `arg1`; `x` must be a live `X509`.
unsafe extern "C" fn trust_1oid(trust: *mut X509Trust, x: *mut X509, flags: c_int) -> c_int {
    // SAFETY: `trust` is live per the contract.
    let arg1 = unsafe { (*trust).arg1 };
    // SAFETY: `x` is live per the contract.
    unsafe {
        obj_trust(
            arg1,
            x,
            flags & !(X509_TRUST_DO_SS_COMPAT | X509_TRUST_OK_ANY_EKU),
        )
    }
}

/// `static int trust_compat(X509_TRUST *trust, X509 *x, int flags)` — `x509_trust.c:240-249`.
///
/// The `X509_TRUST_COMPAT` checker: it calls [`X509_check_purpose`] for the side effect of setting
/// `EXFLAG_SS` on a self-signed certificate, then trusts the certificate when the
/// `X509_TRUST_NO_SS_COMPAT` flag is clear and the self-signed bit is set. The `trust` argument is
/// unused by the authority, which is why [`obj_trust`] passes NULL.
///
/// # Safety
///
/// `x` must be a live, unlocked `X509`.
unsafe extern "C" fn trust_compat(_trust: *mut X509Trust, x: *mut X509, flags: c_int) -> c_int {
    // SAFETY: `x` is live per the contract; -1 asks only for the extension cache.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return X509_TRUST_UNTRUSTED;
    }
    // SAFETY: `x` is live; the cache has released its write lock, matching the authority's own
    // unlocked read of `ex_flags`.
    if (flags & X509_TRUST_NO_SS_COMPAT) == 0 && (unsafe { (*x).ex_flags } & EXFLAG_SS) != 0 {
        X509_TRUST_TRUSTED
    } else {
        X509_TRUST_UNTRUSTED
    }
}

/// `static int obj_trust(int id, X509 *x, int flags)` — `x509_trust.c:251-298`.
///
/// The auxiliary-trust decision: a rejected OID answers [`X509_TRUST_REJECTED`], a trusted OID
/// answers [`X509_TRUST_TRUSTED`], an explicit trust list with no match answers
/// [`X509_TRUST_REJECTED`], and otherwise the self-signed compatibility rule decides (or
/// [`X509_TRUST_UNTRUSTED`] when `X509_TRUST_DO_SS_COMPAT` is clear).
///
/// # Safety
///
/// `x` must be a live `X509`; its `aux` member, when non-NULL, must be a live `X509_CERT_AUX`.
unsafe extern "C" fn obj_trust(id: c_int, x: *mut X509, flags: c_int) -> c_int {
    // SAFETY: `x` is live per the contract; `aux` is its own field.
    let ax = unsafe { (*x).aux }.cast::<X509CertAux>();

    if !ax.is_null() {
        // SAFETY: `ax` is live per the contract.
        let reject = unsafe { (*ax).reject };
        if !reject.is_null() {
            // SAFETY: `reject` is the row's own list; `OPENSSL_sk_num` accepts any pointer.
            for i in 0..unsafe { OPENSSL_sk_num(reject) } {
                // SAFETY: `reject` is live and `i` is in range.
                let obj = unsafe { OPENSSL_sk_value(reject, i) }.cast::<Asn1Object>();
                // SAFETY: `obj` is a live `ASN1_OBJECT`.
                let nid = unsafe { OBJ_obj2nid(obj) };
                if nid == id
                    || (nid == NID_anyExtendedKeyUsage && (flags & X509_TRUST_OK_ANY_EKU) != 0)
                {
                    return X509_TRUST_REJECTED;
                }
            }
        }
        // SAFETY: `ax` is live per the contract.
        let trust = unsafe { (*ax).trust };
        if !trust.is_null() {
            // SAFETY: `trust` is the row's own list; `OPENSSL_sk_num` accepts any pointer.
            for i in 0..unsafe { OPENSSL_sk_num(trust) } {
                // SAFETY: `trust` is live and `i` is in range.
                let obj = unsafe { OPENSSL_sk_value(trust, i) }.cast::<Asn1Object>();
                // SAFETY: `obj` is a live `ASN1_OBJECT`.
                let nid = unsafe { OBJ_obj2nid(obj) };
                if nid == id
                    || (nid == NID_anyExtendedKeyUsage && (flags & X509_TRUST_OK_ANY_EKU) != 0)
                {
                    return X509_TRUST_TRUSTED;
                }
            }
            /*
             * Reject when explicit trust EKU are set and none match.
             *
             * Returning untrusted is enough for full chains that end in self-signed roots, because
             * when explicit trust is specified it suppresses the default blanket trust of
             * self-signed objects. For partial chains, failure to match any trusted purpose must
             * trigger an explicit reject.
             */
            return X509_TRUST_REJECTED;
        }
    }

    if (flags & X509_TRUST_DO_SS_COMPAT) == 0 {
        return X509_TRUST_UNTRUSTED;
    }

    // Not rejected, and there is no list of accepted uses, try compat.
    // SAFETY: `x` is live per the contract; `trust_compat` ignores its first argument.
    unsafe { trust_compat(ptr::null_mut(), x, flags) }
}
