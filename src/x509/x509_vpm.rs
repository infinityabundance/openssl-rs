//! `crypto/x509/x509_vpm.c` — the `X509_VERIFY_PARAM` object, the parameters table and the
//! whole `X509_VERIFY_PARAM_*` accessor surface. Phase 11.2's second unit, **landed whole**.
//!
//! `crypto/x509/x509_vpm.c` is 648 lines and publishes **39 open exports**. This slice lands all
//! of them plus the nine `static` helpers they are built on. Nothing in the unit waits on a later
//! stratum: its closure is the `X509_TRUST` table ([`X509_TRUST_set`], `x509_trust.rs`, 11.1b), the
//! purpose table ([`X509_PURPOSE_set`], `v3_purp.rs`, 10.14), `OBJ_dup`/`ASN1_OBJECT_free`
//! (`runtime/obj.rs`, `asn1/prim.rs`), the `OPENSSL_sk_*` stack and the `CRYPTO_*` allocator, and
//! the two IP helpers [`ossl_ipaddr_to_asc`]/[`ossl_a2i_ipadd`] (`v3_utl.rs`, 11.5).
//!
//! ## What lands, and its shape
//!
//! * The object and its lifecycle: [`X509_VERIFY_PARAM_new`] (`:81-93`, `trust` defaulted to
//!   `X509_TRUST_DEFAULT`, `depth` and `auth_level` to `-1`) and [`X509_VERIFY_PARAM_free`]
//!   (`:95-105`).
//! * The inheritance engine [`X509_VERIFY_PARAM_inherit`] (`:150-215`) and its two drivers
//!   [`X509_VERIFY_PARAM_set1`] (`:217-232`) and [`X509_VERIFY_PARAM_set1_name`] (`:259-264`).
//! * Every flag/purpose/trust/depth/auth-level accessor (`:266-332`).
//! * The policy set (`:334-381`), the host/peername set (`:36-79`, `:383-414`, `:421-432`), the
//!   email set (`:434-444`) and the IP set (`:446-484`).
//! * The parameters table (`:501-648`): the six-row `default_table[]`, the writable `param_table`,
//!   [`X509_VERIFY_PARAM_add0_table`], [`X509_VERIFY_PARAM_get_count`], [`X509_VERIFY_PARAM_get0`],
//!   [`X509_VERIFY_PARAM_lookup`] and [`X509_VERIFY_PARAM_table_cleanup`].
//!
//! ## The two transcribes-of-the-authority's-own-shape
//!
//! **`X509_VERIFY_PARAM_free` does not release `param->name`.** The authority frees `policies`,
//! `hosts`, `peername`, `email`, `ip` and then the `param` itself; the `name` a
//! [`X509_VERIFY_PARAM_set1_name`] allocated is not in that list. This is transcribed as written
//! rather than corrected: it is the authority's observable leak, and a court that measures the
//! allocator would see it. The default-table rows' `name` members point into static storage and
//! are likewise not freed, which is exactly why freeing them would be wrong.
//!
//! **The inheritance macros are transcribed as an inline test.** `test_x509_verify_param_copy`
//! (`:141-142`) is `to_overwrite || (src->field != def && (to_default || dest->field == def))`;
//! [`inherit_copy`] reproduces it as a closure-taking helper so each `x509_verify_param_copy`
//! expansion reads as the authority's line does.
//!
//! ## The raise sites
//!
//! `crypto/x509/x509_vpm.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its four
//! coordinates are **declared locally** in the `err_sites::ErrSite` shape (as `v3_purp.rs` does):
//! [`X509_VERIFY_PARAM_set1`]'s NULL `to` (`:224`), [`X509_VERIFY_PARAM_set1_policies`]'s NULL
//! `param` (`:355`), the IP getter's NULL `param`/`ip` (`:449`) and [`X509_VERIFY_PARAM_set1_ip`]'s
//! invalid length (`:469`). Their reasons are read from `include/openssl/err.h.in`:
//! `ERR_LIB_X509` = 11 (`:85`), `ERR_R_PASSED_NULL_PARAMETER` = `258 | ERR_R_FATAL` = 786690
//! (`:356`, `:353`, `:240-241`) and `ERR_R_PASSED_INVALID_ARGUMENT` = `262 | ERR_RFLAG_COMMON`
//! = 524550 (`:360`, `:241`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_strndup, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_delete, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new,
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::time::TimeT;
use crate::x509::v3_purp::X509_PURPOSE_set;
use crate::x509::v3_utl::{ossl_a2i_ipadd, ossl_ipaddr_to_asc};
use crate::x509::x509_trust::X509_TRUST_set;

// ---------------------------------------------------------------------------------------------
// Constants, the layout and the raise coordinates — see the module doc.
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// `X509_TRUST_DEFAULT` — `include/openssl/x509_vfy.h:195`, the `trust` default.
const X509_TRUST_DEFAULT: c_int = 0;
/// `X509_TRUST_SSL_CLIENT` — `include/openssl/x509_vfy.h:197`, the `ssl_client` row's trust.
const X509_TRUST_SSL_CLIENT: c_int = 2;
/// `X509_TRUST_SSL_SERVER` — `include/openssl/x509_vfy.h:198`, the `ssl_server` row's trust.
const X509_TRUST_SSL_SERVER: c_int = 3;
/// `X509_TRUST_EMAIL` — `include/openssl/x509_vfy.h:199`, the `pkcs7`/`smime_sign` rows' trust.
const X509_TRUST_EMAIL: c_int = 4;
/// `X509_TRUST_OBJECT_SIGN` — `include/openssl/x509_vfy.h:200`, the `code_sign` row's trust.
const X509_TRUST_OBJECT_SIGN: c_int = 5;

/// `X509_PURPOSE_SSL_CLIENT` — `include/openssl/x509v3.h.in:502`, the `ssl_client` row's purpose.
const X509_PURPOSE_SSL_CLIENT: c_int = 1;
/// `X509_PURPOSE_SSL_SERVER` — `include/openssl/x509v3.h.in:503`, the `ssl_server` row's purpose.
const X509_PURPOSE_SSL_SERVER: c_int = 2;
/// `X509_PURPOSE_SMIME_SIGN` — `include/openssl/x509v3.h.in:505`, the `pkcs7`/`smime_sign` purpose.
const X509_PURPOSE_SMIME_SIGN: c_int = 4;
/// `X509_PURPOSE_CODE_SIGN` — `include/openssl/x509v3.h.in:511`, the `code_sign` row's purpose.
const X509_PURPOSE_CODE_SIGN: c_int = 10;

/// `X509_V_FLAG_USE_CHECK_TIME` — `include/openssl/x509_vfy.h.in:341`, `0x2`.
const X509_V_FLAG_USE_CHECK_TIME: c_ulong = 0x2;
/// `X509_V_FLAG_POLICY_CHECK` — `include/openssl/x509_vfy.h.in:353`, `0x80`.
const X509_V_FLAG_POLICY_CHECK: c_ulong = 0x80;
/// `X509_V_FLAG_EXPLICIT_POLICY` — `include/openssl/x509_vfy.h.in:355`, `0x100`; one of the four
/// bits in `X509_V_FLAG_POLICY_MASK`.
const X509_V_FLAG_EXPLICIT_POLICY: c_ulong = 0x100;
/// `X509_V_FLAG_INHIBIT_ANY` — `include/openssl/x509_vfy.h.in:357`, `0x200`.
const X509_V_FLAG_INHIBIT_ANY: c_ulong = 0x200;
/// `X509_V_FLAG_INHIBIT_MAP` — `include/openssl/x509_vfy.h.in:359`, `0x400`.
const X509_V_FLAG_INHIBIT_MAP: c_ulong = 0x400;
/// `X509_V_FLAG_TRUSTED_FIRST` — `include/openssl/x509_vfy.h.in:369`, `0x8000`.
const X509_V_FLAG_TRUSTED_FIRST: c_ulong = 0x8000;
/// `X509_V_FLAG_POLICY_MASK` — `include/openssl/x509_vfy.h.in:399-402`, the four policy bits.
const X509_V_FLAG_POLICY_MASK: c_ulong = X509_V_FLAG_POLICY_CHECK
    | X509_V_FLAG_EXPLICIT_POLICY
    | X509_V_FLAG_INHIBIT_ANY
    | X509_V_FLAG_INHIBIT_MAP;

/// `X509_VP_FLAG_DEFAULT` — `include/openssl/x509_vfy.h.in:392`, `0x1`.
const X509_VP_FLAG_DEFAULT: c_uint = 0x1;
/// `X509_VP_FLAG_OVERWRITE` — `include/openssl/x509_vfy.h.in:393`, `0x2`.
const X509_VP_FLAG_OVERWRITE: c_uint = 0x2;
/// `X509_VP_FLAG_RESET_FLAGS` — `include/openssl/x509_vfy.h.in:394`, `0x4`.
const X509_VP_FLAG_RESET_FLAGS: c_uint = 0x4;
/// `X509_VP_FLAG_LOCKED` — `include/openssl/x509_vfy.h.in:395`, `0x8`.
const X509_VP_FLAG_LOCKED: c_uint = 0x8;
/// `X509_VP_FLAG_ONCE` — `include/openssl/x509_vfy.h.in:396`, `0x10`.
const X509_VP_FLAG_ONCE: c_uint = 0x10;

/// `SET_HOST` — `crypto/x509/x509_vpm.c:23`, the "replace the set" mode of [`int_x509_param_set_hosts`].
const SET_HOST: c_int = 0;
/// `ADD_HOST` — `crypto/x509/x509_vpm.c:24`, the "append to the set" mode.
const ADD_HOST: c_int = 1;

/// `OPENSSL_FILE` for this unit's `OPENSSL_zalloc`/`OPENSSL_strdup`/`OPENSSL_strndup` expansions.
const FILE: &CStr = c"crypto/x509/x509_vpm.c";
/// `X509_VERIFY_PARAM_new`'s `OPENSSL_zalloc(sizeof(*param))` (`:85`).
const LINE_ZALLOC_PARAM: c_int = 85;
/// `X509_VERIFY_PARAM_free`'s `OPENSSL_free(param)` (`:104`).
const LINE_FREE_PARAM: c_int = 104;

/// One `x509_vpm.c` raise coordinate, declared locally (see the module doc).
const fn vpm_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_vpm.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_VERIFY_PARAM_set1`'s NULL `to` — `x509_vpm.c:224`.
const X509_VPM_224: ErrSite = vpm_site(224, c"X509_VERIFY_PARAM_set1", ERR_R_PASSED_NULL_PARAMETER);
/// `X509_VERIFY_PARAM_set1_policies`'s NULL `param` — `x509_vpm.c:355`.
const X509_VPM_355: ErrSite = vpm_site(
    355,
    c"X509_VERIFY_PARAM_set1_policies",
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `int_X509_VERIFY_PARAM_get0_ip`'s NULL `param`/`ip` — `x509_vpm.c:449`.
const X509_VPM_449: ErrSite = vpm_site(
    449,
    c"int_X509_VERIFY_PARAM_get0_ip",
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `X509_VERIFY_PARAM_set1_ip`'s invalid length — `x509_vpm.c:469`.
const X509_VPM_469: ErrSite = vpm_site(
    469,
    c"X509_VERIFY_PARAM_set1_ip",
    ERR_R_PASSED_INVALID_ARGUMENT,
);

/// `struct X509_VERIFY_PARAM_st` — `crypto/x509/x509_local.h:21-39`.
///
/// The verify parameters a chain check reads: the check time, the inheritance and verify flags, the
/// purpose/trust/depth/auth-level words, the permissible-policy set and the peer-identity members.
/// `time_t` is `c_long` on the target, so `check_time` sits at offset 8 and the whole is 112 bytes.
#[repr(C)]
pub struct X509VerifyParam {
    /// `char *name` — the table key, owned (but not released by [`X509_VERIFY_PARAM_free`]).
    pub(crate) name: *mut c_char,
    /// `time_t check_time` — the time [`X509_VERIFY_PARAM_set_time`] installs.
    pub(crate) check_time: TimeT,
    /// `uint32_t inh_flags` — the `X509_VP_FLAG_*` word.
    pub(crate) inh_flags: c_uint,
    /// `unsigned long flags` — the `X509_V_FLAG_*` word.
    pub(crate) flags: c_ulong,
    /// `int purpose` — the purpose to check untrusted certificates.
    pub(crate) purpose: c_int,
    /// `int trust` — the trust setting to check.
    pub(crate) trust: c_int,
    /// `int depth` — the verify depth.
    pub(crate) depth: c_int,
    /// `int auth_level` — the security level for chain verification.
    pub(crate) auth_level: c_int,
    /// `STACK_OF(ASN1_OBJECT) *policies` — the permissible policies, or null.
    pub(crate) policies: *mut OpenSslStack,
    /// `STACK_OF(OPENSSL_STRING) *hosts` — the acceptable names, or null.
    pub(crate) hosts: *mut OpenSslStack,
    /// `unsigned int hostflags` — the name-matching flags.
    pub(crate) hostflags: c_uint,
    /// `char *peername` — the name matched in the peer certificate, or null.
    pub(crate) peername: *mut c_char,
    /// `char *email` — the address to match, or null.
    pub(crate) email: *mut c_char,
    /// `size_t emaillen` — the length of `email`.
    pub(crate) emaillen: usize,
    /// `unsigned char *ip` — the address to match, or null.
    pub(crate) ip: *mut c_uchar,
    /// `size_t iplen` — the length of `ip`.
    pub(crate) iplen: usize,
}

const _: () = {
    assert!(core::mem::size_of::<X509VerifyParam>() == 112);
    assert!(core::mem::offset_of!(X509VerifyParam, name) == 0);
    assert!(core::mem::offset_of!(X509VerifyParam, check_time) == 8);
    assert!(core::mem::offset_of!(X509VerifyParam, inh_flags) == 16);
    assert!(core::mem::offset_of!(X509VerifyParam, flags) == 24);
    assert!(core::mem::offset_of!(X509VerifyParam, purpose) == 32);
    assert!(core::mem::offset_of!(X509VerifyParam, trust) == 36);
    assert!(core::mem::offset_of!(X509VerifyParam, depth) == 40);
    assert!(core::mem::offset_of!(X509VerifyParam, auth_level) == 44);
    assert!(core::mem::offset_of!(X509VerifyParam, policies) == 48);
    assert!(core::mem::offset_of!(X509VerifyParam, hosts) == 56);
    assert!(core::mem::offset_of!(X509VerifyParam, hostflags) == 64);
    assert!(core::mem::offset_of!(X509VerifyParam, peername) == 72);
    assert!(core::mem::offset_of!(X509VerifyParam, email) == 80);
    assert!(core::mem::offset_of!(X509VerifyParam, emaillen) == 88);
    assert!(core::mem::offset_of!(X509VerifyParam, ip) == 96);
    assert!(core::mem::offset_of!(X509VerifyParam, iplen) == 104);
};

// ---------------------------------------------------------------------------------------------
// The `str_copy`/`str_free` adapters and the two stack element destructors — `x509_vpm.c:26-34`.
// ---------------------------------------------------------------------------------------------

/// `static char *str_copy(const char *s)` — `x509_vpm.c:26-29`, `OPENSSL_strdup`.
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe extern "C" fn str_copy(s: *const c_void) -> *mut c_void {
    // SAFETY: `s` is NULL or NUL-terminated per the contract.
    unsafe { CRYPTO_strdup(s.cast(), FILE.as_ptr(), 0).cast() }
}

/// `static void str_free(char *s)` — `x509_vpm.c:31-34`, `OPENSSL_free`.
///
/// # Safety
///
/// `s` must be NULL or a `str_copy`/`CRYPTO_strndup` block.
unsafe extern "C" fn str_free(s: *mut c_void) {
    // SAFETY: `s` is NULL or an owned block per the contract.
    unsafe { CRYPTO_free(s, FILE.as_ptr(), 0) };
}

/// The `ASN1_OBJECT_free` element thunk for `sk_ASN1_OBJECT_pop_free`.
///
/// # Safety
///
/// `a` must be NULL or a live `ASN1_OBJECT`.
unsafe extern "C" fn asn1_object_free_void(a: *mut c_void) {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe { ASN1_OBJECT_free(a.cast()) };
}

// ---------------------------------------------------------------------------------------------
// `X509_VERIFY_PARAM` lifecycle — `x509_vpm.c:81-105`.
// ---------------------------------------------------------------------------------------------

/// `X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void)` — `crypto/x509/x509_vpm.c:81-93`.
///
/// A zeroed parameter with `trust = X509_TRUST_DEFAULT`, `depth = -1` and `auth_level = -1`.
#[no_mangle]
pub extern "C" fn X509_VERIFY_PARAM_new() -> *mut X509VerifyParam {
    let param = CRYPTO_zalloc(
        core::mem::size_of::<X509VerifyParam>(),
        FILE.as_ptr(),
        LINE_ZALLOC_PARAM,
    );
    if param.is_null() {
        return ptr::null_mut();
    }
    let param = param.cast::<X509VerifyParam>();
    // SAFETY: `param` is a fresh zeroed block.
    unsafe {
        (*param).trust = X509_TRUST_DEFAULT;
        // (*param).inh_flags = X509_VP_FLAG_DEFAULT; -- commented out in the authority (`:89`).
        (*param).depth = -1;
        (*param).auth_level = -1; // -1 means unset, 0 is explicit (`:91`).
    }
    param
}

/// `void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param)` — `crypto/x509/x509_vpm.c:95-105`.
///
/// Releases the policy set, the host set, the peername, the email and the IP, then the parameter
/// itself. **`name` is deliberately not released** — the authority's own text omits it (see the
/// module doc).
///
/// # Safety
///
/// `param` must be NULL or a live parameter not already freed.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_free(param: *mut X509VerifyParam) {
    if param.is_null() {
        return;
    }
    // SAFETY: `param` is live per the contract; each member is NULL or owned by it.
    unsafe {
        // SAFETY: the same contract.
        OPENSSL_sk_pop_free((*param).policies, Some(asn1_object_free_void));
        // SAFETY: the same contract.
        OPENSSL_sk_pop_free((*param).hosts, Some(str_free));
        // SAFETY: each pointer is NULL or an owned block.
        CRYPTO_free((*param).peername.cast(), FILE.as_ptr(), 0);
        // SAFETY: the same contract.
        CRYPTO_free((*param).email.cast(), FILE.as_ptr(), 0);
        // SAFETY: the same contract.
        CRYPTO_free((*param).ip.cast(), FILE.as_ptr(), 0);
        // SAFETY: the same contract.
        CRYPTO_free(param.cast(), FILE.as_ptr(), LINE_FREE_PARAM);
    }
}

// ---------------------------------------------------------------------------------------------
// Inheritance — `x509_vpm.c:139-232`.
// ---------------------------------------------------------------------------------------------

/// The expansion of `x509_verify_param_copy(field, def)` — `x509_vpm.c:141-148`.
///
/// It copies `src.field` into `dest.field` when
/// `to_overwrite || (src.field != def && (to_default || dest.field == def))`.
///
/// # Safety
///
/// `dest`/`src` must be live parameters and `field` a pointer- or scalar-typed member.
macro_rules! inherit_copy {
    ($dest:expr, $src:expr, $to_default:expr, $to_overwrite:expr, $field:ident, $zero:expr) => {{
        let src_val = (*$src).$field;
        let dest_val = (*$dest).$field;
        if $to_overwrite || (src_val != $zero && ($to_default || dest_val == $zero)) {
            (*$dest).$field = src_val;
        }
    }};
}

/// `int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *dest, const X509_VERIFY_PARAM *src)` —
/// `crypto/x509/x509_vpm.c:150-215`.
///
/// # Safety
///
/// `dest` must be live; `src` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_inherit(
    dest: *mut X509VerifyParam,
    src: *const X509VerifyParam,
) -> c_int {
    if src.is_null() {
        return 1;
    }
    // SAFETY: `dest` is live and `src` non-NULL per the contract.
    unsafe {
        let inh_flags = (*dest).inh_flags | (*src).inh_flags;

        if (inh_flags & X509_VP_FLAG_ONCE) != 0 {
            (*dest).inh_flags = 0;
        }
        if (inh_flags & X509_VP_FLAG_LOCKED) != 0 {
            return 1;
        }

        let to_default = (inh_flags & X509_VP_FLAG_DEFAULT) != 0;
        let to_overwrite = (inh_flags & X509_VP_FLAG_OVERWRITE) != 0;

        inherit_copy!(dest, src, to_default, to_overwrite, purpose, 0);
        inherit_copy!(
            dest,
            src,
            to_default,
            to_overwrite,
            trust,
            X509_TRUST_DEFAULT
        );
        inherit_copy!(dest, src, to_default, to_overwrite, depth, -1);
        inherit_copy!(dest, src, to_default, to_overwrite, auth_level, -1);

        // If overwrite or check time not set, copy across (`:176-180`).
        if to_overwrite || ((*dest).flags & X509_V_FLAG_USE_CHECK_TIME) == 0 {
            (*dest).check_time = (*src).check_time;
            (*dest).flags &= !X509_V_FLAG_USE_CHECK_TIME;
        }

        if (inh_flags & X509_VP_FLAG_RESET_FLAGS) != 0 {
            (*dest).flags = 0;
        }
        (*dest).flags |= (*src).flags;

        // `test_x509_verify_param_copy(policies, NULL)` (`:187-190`).
        {
            let src_val = (*src).policies;
            let dest_val = (*dest).policies;
            if (to_overwrite || (!src_val.is_null() && (to_default || dest_val.is_null())))
                && X509_VERIFY_PARAM_set1_policies(dest, src_val) == 0
            {
                return 0;
            }
        }

        inherit_copy!(dest, src, to_default, to_overwrite, hostflags, 0);

        // `test_x509_verify_param_copy(hosts, NULL)` (`:194-202`).
        {
            let src_val = (*src).hosts;
            let dest_val = (*dest).hosts;
            if to_overwrite || (!src_val.is_null() && (to_default || dest_val.is_null())) {
                OPENSSL_sk_pop_free((*dest).hosts, Some(str_free));
                (*dest).hosts = ptr::null_mut();
                if !src_val.is_null() {
                    (*dest).hosts = OPENSSL_sk_deep_copy(src_val, Some(str_copy), Some(str_free));
                    if (*dest).hosts.is_null() {
                        return 0;
                    }
                }
            }
        }

        // `test_x509_verify_param_copy(email, NULL)` (`:204-207`).
        {
            let src_val = (*src).email;
            let dest_val = (*dest).email;
            if (to_overwrite || (!src_val.is_null() && (to_default || dest_val.is_null())))
                && X509_VERIFY_PARAM_set1_email(dest, src_val, (*src).emaillen) == 0
            {
                return 0;
            }
        }

        // `test_x509_verify_param_copy(ip, NULL)` (`:209-212`).
        {
            let src_val = (*src).ip;
            let dest_val = (*dest).ip;
            if (to_overwrite || (!src_val.is_null() && (to_default || dest_val.is_null())))
                && X509_VERIFY_PARAM_set1_ip(dest, src_val, (*src).iplen) == 0
            {
                return 0;
            }
        }
    }
    1
}

/// `int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to, const X509_VERIFY_PARAM *from)` —
/// `crypto/x509/x509_vpm.c:217-232`.
///
/// # Safety
///
/// `to` must be NULL or live; `from` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1(
    to: *mut X509VerifyParam,
    from: *const X509VerifyParam,
) -> c_int {
    if to.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VPM_224) };
        return 0;
    }
    // SAFETY: `to` is live per the contract.
    unsafe {
        let save_flags = (*to).inh_flags;
        (*to).inh_flags |= X509_VP_FLAG_DEFAULT;
        let ret = X509_VERIFY_PARAM_inherit(to, from);
        (*to).inh_flags = save_flags;
        ret
    }
}

/// `static int int_x509_param_set1(char **pdest, size_t *pdestlen, const char *src,
/// size_t srclen)` — `crypto/x509/x509_vpm.c:234-257`.
///
/// # Safety
///
/// `pdest` must be live and own `*pdest`; `pdestlen` is NULL or live; `src` is NULL or readable
/// over `srclen` bytes.
unsafe fn int_x509_param_set1(
    pdest: *mut *mut c_char,
    pdestlen: *mut usize,
    src: *const c_char,
    mut srclen: usize,
) -> c_int {
    let tmp: *mut c_char;
    if !src.is_null() {
        if srclen == 0 {
            // SAFETY: `src` is NUL-terminated per the contract.
            srclen = unsafe { libc_strlen(src) };
        }
        // SAFETY: the block is `srclen + 1` writable bytes.
        let raw = CRYPTO_zalloc(srclen + 1, FILE.as_ptr(), 0);
        if raw.is_null() {
            return 0;
        }
        tmp = raw.cast::<c_char>();
        // SAFETY: `tmp` is `srclen + 1` bytes, `src` is `srclen` readable bytes.
        unsafe {
            ptr::copy_nonoverlapping(src, tmp, srclen);
            *tmp.add(srclen) = 0; // enforce NUL termination (`:247`).
        }
    } else {
        tmp = ptr::null_mut();
        srclen = 0;
    }
    // SAFETY: `pdest` is live and `*pdest` is the old owned block.
    unsafe {
        CRYPTO_free((*pdest).cast(), FILE.as_ptr(), 0);
        *pdest = tmp;
        if !pdestlen.is_null() {
            *pdestlen = srclen;
        }
    }
    1
}

/// `int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name)` —
/// `crypto/x509/x509_vpm.c:259-264`.
///
/// # Safety
///
/// `param` must be live; `name` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_name(
    param: *mut X509VerifyParam,
    name: *const c_char,
) -> c_int {
    // SAFETY: `param` is live; `name` is NULL or NUL-terminated.
    unsafe {
        CRYPTO_free((*param).name.cast(), FILE.as_ptr(), 0);
        (*param).name = CRYPTO_strdup(name, FILE.as_ptr(), 0);
        (!(*param).name.is_null()) as c_int
    }
}

// ---------------------------------------------------------------------------------------------
// Flag/purpose/trust/depth/auth-level accessors — `x509_vpm.c:266-332`.
// ---------------------------------------------------------------------------------------------

/// `int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags)` —
/// `crypto/x509/x509_vpm.c:266-272`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_flags(
    param: *mut X509VerifyParam,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe {
        (*param).flags |= flags;
        if (flags & X509_V_FLAG_POLICY_MASK) != 0 {
            (*param).flags |= X509_V_FLAG_POLICY_CHECK;
        }
    }
    1
}

/// `int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param, unsigned long flags)` —
/// `crypto/x509/x509_vpm.c:274-279`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_clear_flags(
    param: *mut X509VerifyParam,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).flags &= !flags };
    1
}

/// `unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:281-284`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_flags(param: *const X509VerifyParam) -> c_ulong {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).flags }
}

/// `uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:286-289`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_inh_flags(param: *const X509VerifyParam) -> u32 {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).inh_flags }
}

/// `int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param, uint32_t flags)` —
/// `crypto/x509/x509_vpm.c:291-295`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_inh_flags(
    param: *mut X509VerifyParam,
    flags: u32,
) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).inh_flags = flags };
    1
}

/// `int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose)` —
/// `crypto/x509/x509_vpm.c:298-301`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_purpose(
    param: *mut X509VerifyParam,
    purpose: c_int,
) -> c_int {
    // SAFETY: `param` is live; its `purpose` field is live.
    unsafe { X509_PURPOSE_set(ptr::addr_of_mut!((*param).purpose), purpose) }
}

/// `int X509_VERIFY_PARAM_get_purpose(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:303-306`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_purpose(param: *const X509VerifyParam) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).purpose }
}

/// `int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust)` —
/// `crypto/x509/x509_vpm.c:308-311`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_trust(
    param: *mut X509VerifyParam,
    trust: c_int,
) -> c_int {
    // SAFETY: `param` is live; its `trust` field is live.
    unsafe { X509_TRUST_set(ptr::addr_of_mut!((*param).trust), trust) }
}

/// `void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth)` —
/// `crypto/x509/x509_vpm.c:313-316`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_depth(param: *mut X509VerifyParam, depth: c_int) {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).depth = depth };
}

/// `void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level)` —
/// `crypto/x509/x509_vpm.c:318-321`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_auth_level(
    param: *mut X509VerifyParam,
    auth_level: c_int,
) {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).auth_level = auth_level };
}

/// `time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:323-326`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_time(param: *const X509VerifyParam) -> TimeT {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).check_time }
}

/// `void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t)` —
/// `crypto/x509/x509_vpm.c:328-332`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_time(param: *mut X509VerifyParam, t: TimeT) {
    // SAFETY: `param` is live per the contract.
    unsafe {
        (*param).check_time = t;
        (*param).flags |= X509_V_FLAG_USE_CHECK_TIME;
    }
}

// ---------------------------------------------------------------------------------------------
// The policy set — `x509_vpm.c:334-381`.
// ---------------------------------------------------------------------------------------------

/// `int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param, ASN1_OBJECT *policy)` —
/// `crypto/x509/x509_vpm.c:334-346`.
///
/// # Safety
///
/// `param` must be live; `policy` must be a live `ASN1_OBJECT` whose ownership transfers.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_add0_policy(
    param: *mut X509VerifyParam,
    policy: *mut Asn1Object,
) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe {
        if (*param).policies.is_null() {
            (*param).policies = OPENSSL_sk_new_null();
            if (*param).policies.is_null() {
                return 0;
            }
        }
        if OPENSSL_sk_push((*param).policies, policy.cast()) <= 0 {
            return 0;
        }
    }
    1
}

/// `int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param, STACK_OF(ASN1_OBJECT)
/// *policies)` — `crypto/x509/x509_vpm.c:348-381`.
///
/// # Safety
///
/// `param` must be NULL or live; `policies` must be NULL or a live stack of `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_policies(
    param: *mut X509VerifyParam,
    policies: *mut OpenSslStack,
) -> c_int {
    if param.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VPM_355) };
        return 0;
    }
    // SAFETY: `param` is live per the contract.
    unsafe {
        OPENSSL_sk_pop_free((*param).policies, Some(asn1_object_free_void));

        if policies.is_null() {
            (*param).policies = ptr::null_mut();
            return 1;
        }

        (*param).policies = OPENSSL_sk_new_null();
        if (*param).policies.is_null() {
            return 0;
        }

        for i in 0..OPENSSL_sk_num(policies) {
            let oid = OPENSSL_sk_value(policies, i).cast::<Asn1Object>();
            // SAFETY: `oid` is a live `ASN1_OBJECT`; `OBJ_dup` returns a fresh one.
            let doid = OBJ_dup(oid);
            if doid.is_null() {
                return 0;
            }
            if OPENSSL_sk_push((*param).policies, doid.cast()) == 0 {
                // SAFETY: `doid` is a fresh live object we own.
                ASN1_OBJECT_free(doid);
                return 0;
            }
        }
        (*param).flags |= X509_V_FLAG_POLICY_CHECK;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The host/peername set — `x509_vpm.c:36-79`, `:383-414`, `:421-432`.
// ---------------------------------------------------------------------------------------------

/// `static int int_x509_param_set_hosts(X509_VERIFY_PARAM *vpm, int mode, const char *name,
/// size_t namelen)` — `crypto/x509/x509_vpm.c:36-79`.
///
/// # Safety
///
/// `vpm` must be live; `name` must be NULL or readable over `namelen` bytes (or NUL-terminated
/// when `namelen` is 0).
unsafe fn int_x509_param_set_hosts(
    vpm: *mut X509VerifyParam,
    mode: c_int,
    name: *const c_char,
    mut namelen: usize,
) -> c_int {
    // SAFETY: `vpm` is live per the contract.
    unsafe {
        // Refuse names with embedded NUL bytes, except perhaps as final byte (`:41-49`).
        if namelen == 0 || name.is_null() {
            namelen = if name.is_null() { 0 } else { libc_strlen(name) };
        } else if !name.is_null()
            && !libc_memchr(
                name.cast(),
                0,
                if namelen > 1 { namelen - 1 } else { namelen },
            )
            .is_null()
        {
            return 0;
        }
        if namelen > 0 && *name.add(namelen - 1) == 0 {
            namelen -= 1;
        }

        if mode == SET_HOST {
            OPENSSL_sk_pop_free((*vpm).hosts, Some(str_free));
            (*vpm).hosts = ptr::null_mut();
        }
        if name.is_null() || namelen == 0 {
            return 1;
        }

        let copy = CRYPTO_strndup(name, namelen, FILE.as_ptr(), 0);
        if copy.is_null() {
            return 0;
        }

        if (*vpm).hosts.is_null() {
            (*vpm).hosts = OPENSSL_sk_new_null();
            if (*vpm).hosts.is_null() {
                // SAFETY: `copy` is an owned block.
                CRYPTO_free(copy.cast(), FILE.as_ptr(), 0);
                return 0;
            }
        }

        if OPENSSL_sk_push((*vpm).hosts, copy.cast()) == 0 {
            // SAFETY: `copy` is an owned block.
            CRYPTO_free(copy.cast(), FILE.as_ptr(), 0);
            if OPENSSL_sk_num((*vpm).hosts) == 0 {
                OPENSSL_sk_free((*vpm).hosts);
                (*vpm).hosts = ptr::null_mut();
            }
            return 0;
        }
    }
    1
}

/// `char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx)` —
/// `crypto/x509/x509_vpm.c:383-386`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_host(
    param: *mut X509VerifyParam,
    idx: c_int,
) -> *mut c_char {
    // SAFETY: `param` is live per the contract.
    unsafe { OPENSSL_sk_value((*param).hosts, idx).cast::<c_char>() }
}

/// `int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param, const char *name,
/// size_t namelen)` — `crypto/x509/x509_vpm.c:388-392`.
///
/// # Safety
///
/// As [`int_x509_param_set_hosts`].
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_host(
    param: *mut X509VerifyParam,
    name: *const c_char,
    namelen: usize,
) -> c_int {
    // SAFETY: the caller's contract is `int_x509_param_set_hosts`'s.
    unsafe { int_x509_param_set_hosts(param, SET_HOST, name, namelen) }
}

/// `int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param, const char *name,
/// size_t namelen)` — `crypto/x509/x509_vpm.c:394-398`.
///
/// # Safety
///
/// As [`int_x509_param_set_hosts`].
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_add1_host(
    param: *mut X509VerifyParam,
    name: *const c_char,
    namelen: usize,
) -> c_int {
    // SAFETY: the caller's contract is `int_x509_param_set_hosts`'s.
    unsafe { int_x509_param_set_hosts(param, ADD_HOST, name, namelen) }
}

/// `void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param, unsigned int flags)` —
/// `crypto/x509/x509_vpm.c:400-404`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_hostflags(
    param: *mut X509VerifyParam,
    flags: c_uint,
) {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).hostflags = flags };
}

/// `unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:406-409`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_hostflags(param: *const X509VerifyParam) -> c_uint {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).hostflags }
}

/// `char *X509_VERIFY_PARAM_get0_peername(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:411-414`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_peername(
    param: *const X509VerifyParam,
) -> *mut c_char {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).peername }
}

/// `void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *to, X509_VERIFY_PARAM *from)` —
/// `crypto/x509/x509_vpm.c:421-432`.
///
/// # Safety
///
/// `to` must be live; `from` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_move_peername(
    to: *mut X509VerifyParam,
    from: *mut X509VerifyParam,
) {
    // SAFETY: `to` is live; `from` is NULL or live per the contract.
    unsafe {
        let peername = if from.is_null() {
            ptr::null_mut()
        } else {
            (*from).peername
        };
        if (*to).peername != peername {
            CRYPTO_free((*to).peername.cast(), FILE.as_ptr(), 0);
            (*to).peername = peername;
        }
        if !from.is_null() {
            (*from).peername = ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The email set — `x509_vpm.c:434-444`.
// ---------------------------------------------------------------------------------------------

/// `char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:434-437`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_email(param: *mut X509VerifyParam) -> *mut c_char {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).email }
}

/// `int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param, const char *email,
/// size_t emaillen)` — `crypto/x509/x509_vpm.c:439-444`.
///
/// # Safety
///
/// `param` must be live; `email` must be NULL or readable over `emaillen` bytes (or
/// NUL-terminated when `emaillen` is 0).
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_email(
    param: *mut X509VerifyParam,
    email: *const c_char,
    emaillen: usize,
) -> c_int {
    // SAFETY: `param` is live; its `email` field owns the old block per the contract.
    unsafe {
        int_x509_param_set1(
            ptr::addr_of_mut!((*param).email),
            ptr::addr_of_mut!((*param).emaillen),
            email,
            emaillen,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The IP set — `x509_vpm.c:446-484`.
// ---------------------------------------------------------------------------------------------

/// `static unsigned char *int_X509_VERIFY_PARAM_get0_ip(X509_VERIFY_PARAM *param,
/// size_t *plen)` — `crypto/x509/x509_vpm.c:446-455`.
///
/// # Safety
///
/// `param` must be NULL or live; `plen` must be NULL or live.
unsafe fn int_x509_verify_param_get0_ip(
    param: *mut X509VerifyParam,
    plen: *mut usize,
) -> *mut c_uchar {
    // SAFETY: `param` is NULL or live per the contract; the NULL case is short-circuited first.
    if param.is_null() || unsafe { (*param).ip }.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VPM_449) };
        return ptr::null_mut();
    }
    // SAFETY: `param` is live per the contract.
    unsafe {
        if !plen.is_null() {
            *plen = (*param).iplen;
        }
        (*param).ip
    }
}

/// `char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:457-463`.
///
/// # Safety
///
/// `param` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get1_ip_asc(param: *mut X509VerifyParam) -> *mut c_char {
    let mut iplen: usize = 0;
    // SAFETY: `param` is NULL or live; `iplen` is live.
    let ip = unsafe { int_x509_verify_param_get0_ip(param, &mut iplen) };
    if ip.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ip` is a live `iplen`-byte address; the helper returns an owned string.
    unsafe { ossl_ipaddr_to_asc(ip, iplen as c_int) }
}

/// `int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param, const unsigned char *ip,
/// size_t iplen)` — `crypto/x509/x509_vpm.c:465-474`.
///
/// # Safety
///
/// `param` must be live; `ip` must be NULL or readable over `iplen` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip(
    param: *mut X509VerifyParam,
    ip: *const c_uchar,
    iplen: usize,
) -> c_int {
    if iplen != 0 && iplen != 4 && iplen != 16 {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VPM_469) };
        return 0;
    }
    // SAFETY: `param` is live; its `ip` field owns the old block per the contract.
    unsafe {
        int_x509_param_set1(
            ptr::addr_of_mut!((*param).ip).cast::<*mut c_char>(),
            ptr::addr_of_mut!((*param).iplen),
            ip.cast::<c_char>(),
            iplen,
        )
    }
}

/// `int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param, const char *ipasc)` —
/// `crypto/x509/x509_vpm.c:476-484`.
///
/// # Safety
///
/// `param` must be live; `ipasc` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip_asc(
    param: *mut X509VerifyParam,
    ipasc: *const c_char,
) -> c_int {
    let mut ipout = [0 as c_uchar; 16];
    // SAFETY: `ipout` is 16 writable bytes; `ipasc` is NUL-terminated.
    let iplen = unsafe { ossl_a2i_ipadd(ipout.as_mut_ptr(), ipasc) } as usize;
    if iplen == 0 {
        return 0;
    }
    // SAFETY: `param` is live; `ipout` is `iplen` readable bytes.
    unsafe { X509_VERIFY_PARAM_set1_ip(param, ipout.as_ptr(), iplen) }
}

/// `int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:486-489`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_depth(param: *const X509VerifyParam) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).depth }
}

/// `int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:491-494`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_auth_level(param: *const X509VerifyParam) -> c_int {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).auth_level }
}

/// `const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:496-499`.
///
/// # Safety
///
/// `param` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get0_name(
    param: *const X509VerifyParam,
) -> *const c_char {
    // SAFETY: `param` is live per the contract.
    unsafe { (*param).name }
}

// ---------------------------------------------------------------------------------------------
// The parameters table — `x509_vpm.c:501-648`.
// ---------------------------------------------------------------------------------------------

/// The value of `vpm_empty_id` (`x509_vpm.c:501`) for one default-table row: the seven trailing
/// initializers `policies`, `hosts`, `hostflags`, `peername`, `email`, `emaillen`, `iplen`.
///
/// # Safety
///
/// The result is a template row; the caller must fill the named fields.
const fn vpm_empty_id(param: X509VerifyParam) -> X509VerifyParam {
    param
}

/// A `default_table[]` row with the `vpm_empty_id` tail — `x509_vpm.c:509-570`.
const fn vpm_row(
    name: *mut c_char,
    check_time: TimeT,
    inh_flags: c_uint,
    flags: c_ulong,
    purpose: c_int,
    trust: c_int,
    depth: c_int,
) -> X509VerifyParam {
    vpm_empty_id(X509VerifyParam {
        name,
        check_time,
        inh_flags,
        flags,
        purpose,
        trust,
        depth,
        auth_level: -1,
        policies: ptr::null_mut(),
        hosts: ptr::null_mut(),
        hostflags: 0,
        peername: ptr::null_mut(),
        email: ptr::null_mut(),
        emaillen: 0,
        ip: ptr::null_mut(),
        iplen: 0,
    })
}

/// `static const X509_VERIFY_PARAM default_table[]` — `crypto/x509/x509_vpm.c:509-570`.
///
/// Six rows in `name` order: `code_sign`, `default`, `pkcs7`, `smime_sign`, `ssl_client`,
/// `ssl_server`. The `default` row carries `X509_V_FLAG_TRUSTED_FIRST` and `depth = 100`; the
/// others default `depth`/`auth_level` to `-1`.
struct DefaultTable(UnsafeCell<[X509VerifyParam; 6]>);
// SAFETY: the table is written once at load and read-only thereafter; the authority's own table is
// `static const`.
unsafe impl Sync for DefaultTable {}

static DEFAULT_TABLE: DefaultTable = DefaultTable(UnsafeCell::new([
    vpm_row(
        c"code_sign".as_ptr() as *mut c_char,
        0,
        0,
        0,
        X509_PURPOSE_CODE_SIGN,
        X509_TRUST_OBJECT_SIGN,
        -1,
    ),
    vpm_row(
        c"default".as_ptr() as *mut c_char,
        0,
        0,
        X509_V_FLAG_TRUSTED_FIRST,
        0,
        0,
        100,
    ),
    vpm_row(
        c"pkcs7".as_ptr() as *mut c_char,
        0,
        0,
        0,
        X509_PURPOSE_SMIME_SIGN,
        X509_TRUST_EMAIL,
        -1,
    ),
    vpm_row(
        c"smime_sign".as_ptr() as *mut c_char,
        0,
        0,
        0,
        X509_PURPOSE_SMIME_SIGN,
        X509_TRUST_EMAIL,
        -1,
    ),
    vpm_row(
        c"ssl_client".as_ptr() as *mut c_char,
        0,
        0,
        0,
        X509_PURPOSE_SSL_CLIENT,
        X509_TRUST_SSL_CLIENT,
        -1,
    ),
    vpm_row(
        c"ssl_server".as_ptr() as *mut c_char,
        0,
        0,
        0,
        X509_PURPOSE_SSL_SERVER,
        X509_TRUST_SSL_SERVER,
        -1,
    ),
]));

/// `OSSL_NELEM(default_table)` — `x509_vpm.c:612`.
const DEFAULT_TABLE_LEN: usize = 6;

/// The `default_table[]` base pointer.
fn default_table_ptr() -> *const X509VerifyParam {
    DEFAULT_TABLE.0.get().cast::<X509VerifyParam>()
}

/// `static int table_cmp(const X509_VERIFY_PARAM *a, const X509_VERIFY_PARAM *b)` —
/// `crypto/x509/x509_vpm.c:574-577`, `strcmp(a->name, b->name)`.
///
/// # Safety
///
/// `a`/`b` must be live parameters with NUL-terminated `name`s.
unsafe fn table_cmp(a: *const X509VerifyParam, b: *const X509VerifyParam) -> c_int {
    // SAFETY: `a`/`b` are live per the contract.
    unsafe { libc_strcmp((*a).name, (*b).name) }
}

/// `static int param_cmp(const X509_VERIFY_PARAM *const *a, const X509_VERIFY_PARAM *const *b)` —
/// `crypto/x509/x509_vpm.c:582-586`, the stack comparator form of [`table_cmp`].
///
/// # Safety
///
/// The arguments are pointers-to-slots holding live parameters.
unsafe extern "C" fn param_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack passes pointers to element slots per its contract.
    // SAFETY: the stack passes pointers to element slots per its contract.
    let a = unsafe { *a.cast::<*const X509VerifyParam>() };
    // SAFETY: the same contract.
    let b = unsafe { *b.cast::<*const X509VerifyParam>() };
    // SAFETY: `a`/`b` are live parameters per the stack's contract.
    unsafe { table_cmp(a, b) }
}

/// `static STACK_OF(X509_VERIFY_PARAM) *param_table` — `crypto/x509/x509_vpm.c:572`.
static PARAM_TABLE: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_vpm.c:588-608`.
///
/// # Safety
///
/// `param` must be a live parameter whose ownership transfers to the table.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_add0_table(param: *mut X509VerifyParam) -> c_int {
    let table = PARAM_TABLE.load(Ordering::SeqCst);
    if table.is_null() {
        // SAFETY: none needed; `OPENSSL_sk_new` is a safe constructor taking the comparator;
        // `param_cmp` matches the element type.
        let table = OPENSSL_sk_new(Some(param_cmp));
        if table.is_null() {
            return 0;
        }
        PARAM_TABLE.store(table, Ordering::SeqCst);
    } else {
        // SAFETY: `table` is the live registry; `param` is live per the contract.
        let idx = unsafe { OPENSSL_sk_find(table, param.cast()) };
        if idx >= 0 {
            // SAFETY: the registry is live and `idx` names one of its rows.
            let ptmp = unsafe { OPENSSL_sk_delete(table, idx) }.cast::<X509VerifyParam>();
            // SAFETY: `ptmp` was owned by the table and is not aliased.
            unsafe { X509_VERIFY_PARAM_free(ptmp) };
        }
    }

    let table = PARAM_TABLE.load(Ordering::SeqCst);
    // SAFETY: `table` is live; `param` is live per the contract.
    if unsafe { OPENSSL_sk_push(table, param.cast()) } <= 0 {
        return 0;
    }
    1
}

/// `int X509_VERIFY_PARAM_get_count(void)` — `crypto/x509/x509_vpm.c:610-617`.
#[no_mangle]
pub extern "C" fn X509_VERIFY_PARAM_get_count() -> c_int {
    let mut num = DEFAULT_TABLE_LEN as c_int;
    let table = PARAM_TABLE.load(Ordering::SeqCst);
    if !table.is_null() {
        // SAFETY: `table` is the live registry.
        num += unsafe { OPENSSL_sk_num(table) };
    }
    num
}

/// `const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id)` — `crypto/x509/x509_vpm.c:619-626`.
#[no_mangle]
pub extern "C" fn X509_VERIFY_PARAM_get0(id: c_int) -> *const X509VerifyParam {
    let num = DEFAULT_TABLE_LEN as c_int;
    if id < num {
        // SAFETY: `id` names a row of the static table.
        return unsafe { default_table_ptr().add(id as usize) };
    }
    let table = PARAM_TABLE.load(Ordering::SeqCst);
    // SAFETY: `table` is NULL or live; `OPENSSL_sk_value` handles NULL.
    unsafe { OPENSSL_sk_value(table, id - num).cast::<X509VerifyParam>() }
}

/// `const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name)` —
/// `crypto/x509/x509_vpm.c:628-642`.
///
/// Searches the writable registry first (sorted by name), then binary-searches the static
/// `default_table[]` through `OBJ_bsearch_table`.
///
/// # Safety
///
/// `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_lookup(name: *const c_char) -> *const X509VerifyParam {
    // A stack-shaped query row, as the authority's local `X509_VERIFY_PARAM pm` (`:631`).
    let pm = X509VerifyParam {
        name: name as *mut c_char,
        check_time: 0,
        inh_flags: 0,
        flags: 0,
        purpose: 0,
        trust: 0,
        depth: 0,
        auth_level: 0,
        policies: ptr::null_mut(),
        hosts: ptr::null_mut(),
        hostflags: 0,
        peername: ptr::null_mut(),
        email: ptr::null_mut(),
        emaillen: 0,
        ip: ptr::null_mut(),
        iplen: 0,
    };

    let table = PARAM_TABLE.load(Ordering::SeqCst);
    if !table.is_null() {
        // SAFETY: `table` is the live registry; sorting is the authority's `:636`.
        unsafe { OPENSSL_sk_sort(table) };
        // SAFETY: `table` is live; the comparator orders by name.
        let idx = unsafe { OPENSSL_sk_find(table, ptr::from_ref(&pm).cast()) };
        if idx >= 0 {
            // SAFETY: `table` is live.
            return unsafe { OPENSSL_sk_value(table, idx) }.cast::<X509VerifyParam>();
        }
    }
    // SAFETY: the static table is live; the query `pm` is live.
    unsafe { obj_bsearch_table(ptr::from_ref(&pm), default_table_ptr(), DEFAULT_TABLE_LEN) }
}

/// `OBJ_bsearch_table` over the `default_table[]` — the generated binary search the authority's
/// `DECLARE_OBJ_BSEARCH_CMP_FN(X509_VERIFY_PARAM, X509_VERIFY_PARAM, table)`
/// (`x509_vpm.c:579`) expands to.
///
/// # Safety
///
/// `key` must be live and comparable by `table_cmp`; `base` must point at `len` live rows.
unsafe fn obj_bsearch_table(
    key: *const X509VerifyParam,
    base: *const X509VerifyParam,
    len: usize,
) -> *const X509VerifyParam {
    let mut lo = 0usize;
    let mut hi = len;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        // SAFETY: `mid < len` by the loop bounds; `key` is live.
        let cmp = unsafe { table_cmp(key, base.add(mid)) };
        if cmp == 0 {
            // SAFETY: `mid < len`.
            return unsafe { base.add(mid) };
        } else if cmp < 0 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    ptr::null()
}

/// `void X509_VERIFY_PARAM_table_cleanup(void)` — `crypto/x509/x509_vpm.c:644-648`.
#[no_mangle]
pub extern "C" fn X509_VERIFY_PARAM_table_cleanup() {
    let table = PARAM_TABLE.swap(ptr::null_mut(), Ordering::SeqCst);
    // SAFETY: `table` is the live registry (or NULL); its rows are heap parameters.
    unsafe { OPENSSL_sk_pop_free(table, Some(verify_param_free_void)) };
}

/// The `X509_VERIFY_PARAM_free` element thunk for `sk_X509_VERIFY_PARAM_pop_free`.
///
/// # Safety
///
/// `p` must be NULL or a live parameter.
unsafe extern "C" fn verify_param_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or live per the contract.
    unsafe { X509_VERIFY_PARAM_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// `strlen`/`strcmp`/`memchr` — the byte-oriented libc helpers the authority calls directly.
// ---------------------------------------------------------------------------------------------

/// `strlen(s)` — `x509_vpm.c:46`, `:240`.
///
/// # Safety
///
/// `s` must be NUL-terminated.
unsafe fn libc_strlen(s: *const c_char) -> usize {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { CStr::from_ptr(s) }.to_bytes().len()
}

/// `strcmp(a, b)` — `x509_vpm.c:576`, `:585`. Compares the unsigned bytes as C does.
///
/// # Safety
///
/// `a`/`b` must be NUL-terminated.
unsafe fn libc_strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: `a`/`b` are NUL-terminated per the contract.
    let a = unsafe { CStr::from_ptr(a) }.to_bytes();
    // SAFETY: the same contract.
    let b = unsafe { CStr::from_ptr(b) }.to_bytes();
    match a.cmp(b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `memchr(s, c, n)` — `x509_vpm.c:48`. Returns the first occurrence or a NULL pointer.
///
/// # Safety
///
/// `s` must be readable over `n` bytes.
unsafe fn libc_memchr(s: *const c_void, c: c_int, n: usize) -> *const c_void {
    let bytes = s.cast::<u8>();
    let needle = c as u8;
    for i in 0..n {
        // SAFETY: `i < n` and `s` is readable over `n` bytes per the contract.
        if unsafe { *bytes.add(i) } == needle {
            // SAFETY: the same contract.
            return unsafe { bytes.add(i).cast() };
        }
    }
    ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh parameter carries the authority's three field defaults.
    #[test]
    fn the_new_parameter_has_the_authoritys_defaults() {
        let p = X509_VERIFY_PARAM_new();
        assert!(!p.is_null());
        // SAFETY: `p` is the live block `X509_VERIFY_PARAM_new` just returned.
        unsafe {
            assert_eq!((*p).trust, 0);
            assert_eq!((*p).depth, -1);
            assert_eq!((*p).auth_level, -1);
            assert_eq!((*p).flags, 0);
            assert!((*p).name.is_null());
            X509_VERIFY_PARAM_free(p);
        }
    }

    /// `X509_VERIFY_PARAM_set_time` installs both the time and the `USE_CHECK_TIME` flag.
    #[test]
    fn set_time_installs_the_use_check_time_flag() {
        let p = X509_VERIFY_PARAM_new();
        // SAFETY: `p` is live; its fields are readable.
        unsafe {
            X509_VERIFY_PARAM_set_time(p, 1704067200);
            assert_eq!(X509_VERIFY_PARAM_get_time(p), 1704067200);
            assert_eq!(
                X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_USE_CHECK_TIME,
                X509_V_FLAG_USE_CHECK_TIME
            );
            X509_VERIFY_PARAM_free(p);
        }
    }

    /// A policy-related bit implies `X509_V_FLAG_POLICY_CHECK` (`x509_vpm.c:269-270`).
    #[test]
    fn a_policy_bit_implies_policy_check() {
        let p = X509_VERIFY_PARAM_new();
        // SAFETY: `p` is live; its fields are readable.
        unsafe {
            X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_EXPLICIT_POLICY);
            assert_eq!(
                X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_POLICY_CHECK,
                X509_V_FLAG_POLICY_CHECK
            );
            X509_VERIFY_PARAM_free(p);
        }
    }

    /// `set1_host` replaces the set and `add1_host` appends to it (`x509_vpm.c:53-56`).
    #[test]
    fn set1_host_replaces_and_add1_host_appends() {
        let p = X509_VERIFY_PARAM_new();
        // SAFETY: `p` is live; every pointer handed in is a `'static` C literal.
        unsafe {
            assert_eq!(X509_VERIFY_PARAM_set1_host(p, c"a.example".as_ptr(), 0), 1);
            assert_eq!(X509_VERIFY_PARAM_add1_host(p, c"b.example".as_ptr(), 0), 1);
            let h0 = X509_VERIFY_PARAM_get0_host(p, 0);
            let h1 = X509_VERIFY_PARAM_get0_host(p, 1);
            assert_eq!(CStr::from_ptr(h0).to_bytes(), b"a.example");
            assert_eq!(CStr::from_ptr(h1).to_bytes(), b"b.example");
            // A `SET_HOST` call drops both.
            assert_eq!(X509_VERIFY_PARAM_set1_host(p, c"c.example".as_ptr(), 0), 1);
            let h0 = X509_VERIFY_PARAM_get0_host(p, 0);
            assert_eq!(CStr::from_ptr(h0).to_bytes(), b"c.example");
            assert!(X509_VERIFY_PARAM_get0_host(p, 1).is_null());
            X509_VERIFY_PARAM_free(p);
        }
    }

    /// The static table has six rows and `lookup` binary-searches it.
    #[test]
    fn the_default_table_has_six_rows() {
        let _guard = crate::test_support::lock_global_state();
        assert_eq!(X509_VERIFY_PARAM_get_count(), 6);
        // SAFETY: `lookup` reads the static table only; the query name is a `'static` literal.
        unsafe {
            let d = X509_VERIFY_PARAM_lookup(c"default".as_ptr());
            assert!(!d.is_null());
            assert_eq!(X509_VERIFY_PARAM_get_depth(d), 100);
            assert!(X509_VERIFY_PARAM_lookup(c"no.such.row".as_ptr()).is_null());
        }
    }
}
