//! Phase 11.7 — `crypto/asn1/asn_mstbl.c`: the `stbl_section` configuration module.
//!
//! One export, `ASN1_add_stable_module`, registers `stbl_section` with the module registry so that
//! a configuration file can change an OID's string table:
//!
//! ```text
//! [openssl_init]
//! stbl_section = new_stbl
//! [new_stbl]
//! someName = min:1,max:64,mask:... ,flags:nomask
//! ```
//!
//! `stbl_module_init` reads the section the registry entry names, and for each entry `do_tcreate`
//! resolves the key to a NID (`OBJ_sn2nid`, then `OBJ_ln2nid`), parses the value as
//! `X509V3_parse_list`'s `name:value, name:value, ...` and calls `ASN1_STRING_TABLE_add`. The
//! parse's three shapes -- `min`, `max`, `mask`/`flags` -- and its refusals are the authority's:
//! an unknown field name, an unparsable number with trailing input, a `mask:` that is empty or
//! zero, and a `flags:` that is neither `nomask` nor `none`. `stbl_module_finish` is
//! `ASN1_STRING_TABLE_cleanup`.
//!
//! The module was handed to this stratum by Phase 5 (`forensics/tools/phase5_obligations.py`
//! records the deferral) because its initialiser reaches `X509V3_parse_list`, which `v3_utl.c`
//! lands with 11.5. Every callee is landed now, so the unit lands whole and
//! `OPENSSL_load_builtin_modules` calls it beside `ASN1_add_oid_module`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_strnid::{ASN1_STRING_TABLE_add, ASN1_STRING_TABLE_cleanup};
use crate::asn1::asn1_gen::ASN1_str2mask;
use crate::asn1::layout::{STABLE_FLAGS_CLEAR, STABLE_NO_MASK};
use crate::ffi::guard_ffi;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::conf::lib::NCONF_get_section;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{
    CONF_imodule_get_value, CONF_module_add, ConfFinishFn, ConfImodule, ConfInitFn,
};
use crate::runtime::err::err_sites::{
    ASN_MSTBL_102, ASN_MSTBL_107, ASN_MSTBL_113, ASN_MSTBL_29, ASN_MSTBL_35,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::obj::{OBJ_ln2nid, OBJ_sn2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_utl::{X509V3_conf_free, X509V3_parse_list};

/// `#define NID_undef 0` — `openssl/objects.h`. Declared locally because the crate keeps its copy
/// private to `src/runtime/obj.rs`; `do_tcreate` compares against it in both lookups.
#[allow(non_upper_case_globals)] // the authority's own spelling, `#define NID_undef 0`
const NID_undef: c_int = 0;

extern "C" {
    /// `unsigned long strtoul(const char *, char **, int)`.
    fn strtoul(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulong;
    /// `int strcmp(const char *, const char *)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(lst, X509V3_conf_free)` installs.
///
/// # Safety
/// `p` must be NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `static int do_tcreate(const char *value, const char *name)` — `crypto/asn1/asn_mstbl.c:57-117`.
///
/// See the module doc for the grammar and the refusals. `cnf` is deliberately kept outside the
/// loop: the authority's `err:` label distinguishes "a field failed" (raise the field's own name
/// and value) from "nothing was looked at yet" (raise the section entry's name and value), and
/// that is exactly the last value `cnf` holds when the loop breaks.
///
/// # Safety
/// `value` and `name` must be NUL-terminated, and `name` non-NULL — the authority passes the
/// `CONF_VALUE`'s key, which a section entry always has.
unsafe fn do_tcreate(value: *const c_char, name: *const c_char) -> c_int {
    let mut tbl_min: c_long = -1;
    let mut tbl_max: c_long = -1;
    let mut tbl_mask: c_ulong = 0;
    let mut tbl_flags: c_ulong = 0;
    let mut lst: *mut OpenSslStack = ptr::null_mut();
    let mut cnf: *mut ConfValue = ptr::null_mut();

    // SAFETY: `name` is NUL-terminated per the contract.
    let mut nid = unsafe { OBJ_sn2nid(name) };
    if nid == NID_undef {
        // SAFETY: as above.
        nid = unsafe { OBJ_ln2nid(name) };
    }
    if nid == NID_undef {
        // SAFETY: `lst` is NULL and `cnf` is NULL; the strings are NUL-terminated.
        return unsafe { do_tcreate_err(lst, cnf, value, name) };
    }

    // SAFETY: `value` is NUL-terminated per the contract.
    lst = unsafe { X509V3_parse_list(value) };
    if lst.is_null() {
        // SAFETY: `lst` is NULL and `cnf` is NULL; the strings are NUL-terminated.
        return unsafe { do_tcreate_err(lst, cnf, value, name) };
    }

    // SAFETY: `lst` is the list `X509V3_parse_list` answered.
    let count = unsafe { OPENSSL_sk_num(lst) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of the list's own entries.
        cnf = unsafe { OPENSSL_sk_value(lst, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live and its `value`/`name` are NUL-terminated strings.
        if unsafe { (*cnf).value }.is_null() {
            // SAFETY: `lst` is this frame's list and `cnf` is one of its entries.
            return unsafe { do_tcreate_err(lst, cnf, value, name) };
        }
        /* SAFETY: `cnf`'s two strings are NUL-terminated, and the literals are static. */
        let refused = unsafe {
            if strcmp((*cnf).name, c"min".as_ptr()) == 0 {
                let mut eptr: *mut c_char = ptr::null_mut();
                tbl_min = strtoul((*cnf).value, &mut eptr, 0) as c_long;
                *eptr != 0
            } else if strcmp((*cnf).name, c"max".as_ptr()) == 0 {
                let mut eptr: *mut c_char = ptr::null_mut();
                tbl_max = strtoul((*cnf).value, &mut eptr, 0) as c_long;
                *eptr != 0
            } else if strcmp((*cnf).name, c"mask".as_ptr()) == 0 {
                ASN1_str2mask((*cnf).value, &mut tbl_mask) == 0 || tbl_mask == 0
            } else if strcmp((*cnf).name, c"flags".as_ptr()) == 0 {
                if strcmp((*cnf).value, c"nomask".as_ptr()) == 0 {
                    tbl_flags = STABLE_NO_MASK;
                    false
                } else if strcmp((*cnf).value, c"none".as_ptr()) == 0 {
                    tbl_flags = STABLE_FLAGS_CLEAR;
                    false
                } else {
                    true
                }
            } else {
                true
            }
        };
        if refused {
            // SAFETY: `lst` is this frame's list and `cnf` is one of its entries.
            return unsafe { do_tcreate_err(lst, cnf, value, name) };
        }
        i += 1;
    }

    /* The authority's `rv == 1` arm: add the row and raise `ERR_R_ASN1_LIB` if it refuses. */
    let added = ASN1_STRING_TABLE_add(nid, tbl_min, tbl_max, tbl_mask, tbl_flags);
    if added == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&ASN_MSTBL_113) };
    }
    // SAFETY: `lst` is this frame's own or NULL; its elements are `CONF_VALUE`s.
    unsafe { OPENSSL_sk_pop_free(lst, Some(conf_value_free_thunk)) };
    added
}

/// The authority's `err:` label of [`do_tcreate`]: raise the field-shaped or the name-shaped
/// record, release the parsed list the way the authority's label does, and answer 0. Factored so
/// every refusal carries its own `// SAFETY:` comment.
///
/// # Safety
/// `cnf` is NULL or live; `value`/`name` are NUL-terminated; `lst` is NULL or the parsed list.
unsafe fn do_tcreate_err(
    lst: *mut OpenSslStack,
    cnf: *mut ConfValue,
    value: *const c_char,
    name: *const c_char,
) -> c_int {
    let mut msg = [0 as c_char; 256];
    if !cnf.is_null() {
        /* `ERR_raise_data(..., "field=%s, value=%s", cnf->name, cnf->value != NULL ? cnf->value
         * : value)`. */
        // SAFETY: `cnf` is live and both strings are NUL-terminated; `msg` is this frame's and its
        // length is passed with it.
        let valuep = unsafe {
            if (*cnf).value.is_null() {
                value
            } else {
                (*cnf).value
            }
        };
        // SAFETY: `cnf` is live, its `name` is NUL-terminated, and `msg` is writable.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"field=%s, value=%s".as_ptr(),
                (*cnf).name,
                valuep,
            );
        }
        // SAFETY: a compile-time-constant site with this frame's formatted data.
        unsafe { raise_site_data(&ASN_MSTBL_102, msg.as_ptr()) };
    } else {
        // SAFETY: `name`/`value` are NUL-terminated and `msg` is writable.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s, value=%s".as_ptr(),
                name,
                value,
            );
        }
        // SAFETY: a compile-time-constant site with this frame's formatted data.
        unsafe { raise_site_data(&ASN_MSTBL_107, msg.as_ptr()) };
    }
    // SAFETY: `lst` is NULL or this frame's own parsed list; its elements are `CONF_VALUE`s.
    unsafe { OPENSSL_sk_pop_free(lst, Some(conf_value_free_thunk)) };
    0
}

/// `static int stbl_module_init(CONF_IMODULE *md, const CONF *cnf)` —
/// `crypto/asn1/asn_mstbl.c:20-40`.
///
/// Reads the section the registry entry names and creates one string-table row per entry. Two
/// failures are raised rather than skipped: a section that does not exist
/// (`ASN1_R_ERROR_LOADING_SECTION`) and any single entry that `do_tcreate` refuses
/// (`ASN1_R_INVALID_VALUE`).
///
/// # Safety
/// `md` must be a live initialisation and `cnf` the configuration it was loaded from.
unsafe extern "C" fn stbl_module_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // SAFETY: `md` is live per the callback's contract; its value is the section name.
    let stbl_section = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `stbl_section` is a NUL-terminated string owned by `md`.
    let sktmp = unsafe { NCONF_get_section(cnf, stbl_section) };
    if sktmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&ASN_MSTBL_29) };
        return 0;
    }

    // SAFETY: `sktmp` is the section's own stack, live for the duration of this call.
    let count = unsafe { OPENSSL_sk_num(sktmp) };
    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of the section's own entries.
        let mval = unsafe { OPENSSL_sk_value(sktmp, i) }.cast::<ConfValue>();
        // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated; the authority passes
        // them in the order `do_tcreate(mval->value, mval->name)`.
        let (value, name) = unsafe { ((*mval).value, (*mval).name) };
        // SAFETY: both are NUL-terminated and `name` is non-NULL for a section entry.
        if unsafe { do_tcreate(value, name) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ASN_MSTBL_35) };
            return 0;
        }
        i += 1;
    }

    1
}

/// `static void stbl_module_finish(CONF_IMODULE *md)` — `crypto/asn1/asn_mstbl.c:42-45`: the whole
/// body is `ASN1_STRING_TABLE_cleanup()`.
unsafe extern "C" fn stbl_module_finish(_md: *mut ConfImodule) {
    ASN1_STRING_TABLE_cleanup();
}

/// `void ASN1_add_stable_module(void)` — `crypto/asn1/asn_mstbl.c:47-50`.
///
/// One `CONF_module_add` under the name `stbl_section`, with the two callbacks above. The
/// registry's answer is discarded, as the authority discards it.
#[no_mangle]
pub extern "C" fn ASN1_add_stable_module() {
    guard_ffi((), || {
        // SAFETY: the name is a static NUL-terminated string and the two callbacks have the
        // registry's declared types.
        unsafe {
            CONF_module_add(
                c"stbl_section".as_ptr(),
                Some(stbl_module_init as ConfInitFn),
                Some(stbl_module_finish as ConfFinishFn),
            )
        };
    })
}
